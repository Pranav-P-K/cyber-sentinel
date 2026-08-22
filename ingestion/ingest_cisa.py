"""
ingestion/ingest_cisa.py
Ingests the CISA Known Exploited Vulnerabilities (KEV) catalog into ChromaDB.

Every KEV entry gets  cisa_hit=True  in its metadata — this flag is used by
the PFGL Stage 1 exact-match verifier to check if a CVE is actively exploited.

Usage:
    python -m ingestion.ingest_cisa
    python ingestion/ingest_cisa.py
"""

import json
import logging
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

# ── Paths & constants ─────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).resolve().parent.parent
KEV_PATH    = REPO_ROOT / "data" / "knowledge_base" / "cisa_kev" / "known_exploited_vulnerabilities.json"
CHROMA_DIR  = REPO_ROOT / "data" / "chroma_db"
COLLECTION  = "cybersentinel_kb"
EMBED_MODEL = "all-MiniLM-L6-v2"
BATCH_SIZE  = 256

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger("ingest_cisa")


def ingest_cisa(
    kev_path: Path   = KEV_PATH,
    chroma_dir: Path = CHROMA_DIR,
    collection_name: str = COLLECTION,
) -> int:
    """
    Load the CISA KEV JSON catalog, embed each vulnerability entry, and
    upsert into ChromaDB with cisa_hit=True in metadata.

    Returns the number of entries ingested.
    """
    if not kev_path.exists():
        log.error("CISA KEV file not found: %s", kev_path)
        return 0

    log.info("Loading CISA KEV catalog: %s", kev_path.name)
    with open(kev_path, encoding="utf-8") as f:
        data = json.load(f)

    vulnerabilities = data.get("vulnerabilities", [])
    log.info("Found %d KEV entries", len(vulnerabilities))

    docs, ids, metas = [], [], []
    for entry in vulnerabilities:
        cve_id      = entry.get("cveID", "")
        vendor      = entry.get("vendorProject", "")
        product     = entry.get("product", "")
        vuln_name   = entry.get("vulnerabilityName", "")
        short_desc  = entry.get("shortDescription", "")[:400]
        req_action  = entry.get("requiredAction", "")[:200]
        due_date    = entry.get("dueDate", "")
        date_added  = entry.get("dateAdded", "")

        if not cve_id:
            continue

        text = (
            f"CISA KEV Entry: {cve_id}\n"
            f"Vulnerability: {vuln_name}\n"
            f"Vendor/Product: {vendor} — {product}\n"
            f"Description: {short_desc}\n"
            f"Required Action: {req_action}\n"
            f"Due Date: {due_date}"
        )
        docs.append(text)
        ids.append(f"cisa-kev-{cve_id}")
        metas.append({
            "type":         "cisa_kev",
            "cve_id":       cve_id,
            "cisa_hit":     True,          # ← PFGL exact-match flag
            "vendor":       vendor,
            "product":      product,
            "vuln_name":    vuln_name,
            "date_added":   date_added,
            "due_date":     due_date,
        })

    # Embed
    log.info("Loading embedding model: %s", EMBED_MODEL)
    model = SentenceTransformer(EMBED_MODEL)

    log.info("Embedding %d CISA KEV entries …", len(docs))
    all_embeddings = []
    for start in range(0, len(docs), BATCH_SIZE):
        batch = docs[start: start + BATCH_SIZE]
        all_embeddings.extend(model.encode(batch, show_progress_bar=False).tolist())

    # Upsert into shared ChromaDB collection
    chroma_dir.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(chroma_dir))
    col    = client.get_or_create_collection(
        name=collection_name,
        metadata={"hnsw:space": "cosine"},
    )

    CHROMA_BATCH = 2000
    for start in range(0, len(docs), CHROMA_BATCH):
        col.upsert(
            documents=docs[start: start + CHROMA_BATCH],
            embeddings=all_embeddings[start: start + CHROMA_BATCH],
            ids=ids[start: start + CHROMA_BATCH],
            metadatas=metas[start: start + CHROMA_BATCH],
        )

    final_count = col.count()
    log.info(
        "CISA KEV ingestion complete — %d entries added. Collection total: %d",
        len(docs), final_count,
    )
    return len(docs)


if __name__ == "__main__":
    ingest_cisa()
