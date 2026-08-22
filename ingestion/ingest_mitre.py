"""
ingestion/ingest_mitre.py
Ingests all MITRE ATT&CK Enterprise technique STIX objects into ChromaDB.

Usage:
    python -m ingestion.ingest_mitre
    # or directly:
    python ingestion/ingest_mitre.py

Prerequisites:
    data/knowledge_base/mitre_stix/enterprise-attack/  (STIX FileSystem bundle)
    ChromaDB persisted at the path in .env (CHROMA_PERSIST_DIR)
"""

import logging
import sys
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer
from stix2 import FileSystemSource, Filter

# ── Paths & constants ─────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).resolve().parent.parent
STIX_PATH   = REPO_ROOT / "data" / "knowledge_base" / "mitre_stix" / "enterprise-attack"
CHROMA_DIR  = REPO_ROOT / "data" / "chroma_db"
COLLECTION  = "cybersentinel_kb"
EMBED_MODEL = "all-MiniLM-L6-v2"
BATCH_SIZE  = 64          # embed this many docs per model.encode() call

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger("ingest_mitre")


def _format_tactics(kill_chain_phases) -> str:
    """Turn a list of KillChainPhase objects into a readable string."""
    if not kill_chain_phases:
        return "unknown"
    return ", ".join(
        f"{p.kill_chain_name}:{p.phase_name}" for p in kill_chain_phases
    )


def ingest_mitre(
    stix_path: Path = STIX_PATH,
    chroma_dir: Path = CHROMA_DIR,
    collection_name: str = COLLECTION,
    embed_model_name: str = EMBED_MODEL,
    batch_size: int = BATCH_SIZE,
) -> int:
    """
    Load all attack-pattern objects from the STIX FileSystem source,
    embed them with SentenceTransformer, and upsert into ChromaDB.

    Returns the total number of techniques indexed.
    """
    if not stix_path.exists():
        log.error("STIX path not found: %s", stix_path)
        sys.exit(1)

    # ── Load STIX data ────────────────────────────────────────────────────────
    log.info("Loading STIX data from %s", stix_path)
    src = FileSystemSource(str(stix_path))
    techniques: list = src.query([Filter("type", "=", "attack-pattern")])
    log.info("Found %d attack-pattern objects in STIX bundle", len(techniques))

    # ── Filter out deprecated / revoked objects ───────────────────────────────
    active = [
        t for t in techniques
        if not getattr(t, "revoked", False) and not getattr(t, "x_mitre_deprecated", False)
    ]
    log.info("%d active (non-revoked, non-deprecated) techniques", len(active))

    # ── Build document lists ──────────────────────────────────────────────────
    docs, ids, metas = [], [], []
    for t in active:
        technique_id = t.get("external_references", [{}])[0].get("external_id", t.id)
        description  = getattr(t, "description", "") or ""
        tactics      = _format_tactics(getattr(t, "kill_chain_phases", []))

        # Rich text for embedding quality
        text = (
            f"MITRE ATT&CK Technique: {t.name} ({technique_id})\n"
            f"Tactics: {tactics}\n"
            f"Description: {description[:600]}"
        )
        docs.append(text)
        ids.append(t.id)   # STIX ID is guaranteed unique
        metas.append({
            "type":         "mitre_technique",
            "technique_id": technique_id,
            "name":         t.name,
            "tactics":      tactics,
            "stix_id":      t.id,
        })

    # ── Embed in batches ──────────────────────────────────────────────────────
    log.info("Loading embedding model: %s", embed_model_name)
    model = SentenceTransformer(embed_model_name)

    all_embeddings = []
    for start in range(0, len(docs), batch_size):
        batch = docs[start : start + batch_size]
        vecs  = model.encode(batch, show_progress_bar=False).tolist()
        all_embeddings.extend(vecs)
        log.info(
            "Embedded batch %d/%d  (%d techniques so far)",
            start // batch_size + 1,
            (len(docs) + batch_size - 1) // batch_size,
            start + len(batch),
        )

    # ── Upsert into ChromaDB ──────────────────────────────────────────────────
    log.info("Connecting to ChromaDB at %s", chroma_dir)
    chroma_dir.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(chroma_dir))
    col    = client.get_or_create_collection(
        name=collection_name,
        metadata={"hnsw:space": "cosine"},
    )

    # Upsert in batches (ChromaDB has a per-call limit)
    for start in range(0, len(docs), batch_size):
        col.upsert(
            documents=docs[start : start + batch_size],
            embeddings=all_embeddings[start : start + batch_size],
            ids=ids[start : start + batch_size],
            metadatas=metas[start : start + batch_size],
        )

    final_count = col.count()
    log.info(
        "Ingestion complete — collection '%s' now contains %d documents "
        "(%d MITRE techniques upserted this run)",
        collection_name,
        final_count,
        len(docs),
    )
    return len(docs)


if __name__ == "__main__":
    total = ingest_mitre()
    print(f"\n[OK] MITRE ingestion done — {total} techniques indexed.")
