"""
ingestion/ingest_nvd.py
Ingests NVD 2.0 CVE JSON feeds into ChromaDB.

Supports both 2023 and 2024 feed files.

Usage:
    python -m ingestion.ingest_nvd
    python ingestion/ingest_nvd.py
"""

import json
import logging
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

# ── Paths & constants ─────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).resolve().parent.parent
NVD_DIR     = REPO_ROOT / "data" / "knowledge_base" / "nvd_feeds"
CHROMA_DIR  = REPO_ROOT / "data" / "chroma_db"
COLLECTION  = "cybersentinel_kb"
EMBED_MODEL = "all-MiniLM-L6-v2"
BATCH_SIZE  = 128
MAX_CVES    = 10_000   # cap per file

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger("ingest_nvd")


def ingest_nvd(
    json_path: Path,
    collection: chromadb.Collection,
    model: SentenceTransformer,
    year: str,
    max_cves: int = MAX_CVES,
    batch_size: int = BATCH_SIZE,
) -> int:
    """
    Parse one NVD 2.0 JSON feed, embed CVE descriptions, and upsert into
    the given ChromaDB collection.

    Returns the number of CVEs ingested.
    """
    log.info("Loading NVD feed: %s", json_path.name)
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities", [])[:max_cves]
    log.info("  %d CVEs found in feed (cap=%d)", len(data.get("vulnerabilities", [])), max_cves)

    docs, embeddings, ids, metas = [], [], [], []

    for item in tqdm(vulns, desc=f"NVD {year}", unit="cve"):
        cve     = item.get("cve", {})
        cve_id  = cve.get("id", "")
        if not cve_id:
            continue

        # English description
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )[:500]
        if not desc:
            continue

        # CVSS score (prefer v3.1 > v3.0 > v2)
        cvss_score = ""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_score = str(entries[0].get("cvssData", {}).get("baseScore", ""))
                break

        severity = ""
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                severity = entries[0].get("cvssData", {}).get("baseSeverity", "")
                break

        text = (
            f"CVE: {cve_id}\n"
            f"Severity: {severity or 'N/A'}  CVSS: {cvss_score or 'N/A'}\n"
            f"Description: {desc}"
        )
        docs.append(text)
        ids.append(f"nvd-{year}-{cve_id}")
        metas.append({
            "type":       "nvd",
            "cve_id":     cve_id,
            "year":       year,
            "cvss_score": cvss_score,
            "severity":   severity,
        })

    # Embed in batches
    log.info("  Embedding %d CVE descriptions …", len(docs))
    all_embeddings = []
    for start in range(0, len(docs), batch_size):
        batch = docs[start: start + batch_size]
        all_embeddings.extend(model.encode(batch, show_progress_bar=False).tolist())

    # Upsert in batches (ChromaDB hard limit ~5000/call)
    CHROMA_BATCH = 2000
    for start in range(0, len(docs), CHROMA_BATCH):
        collection.upsert(
            documents=docs[start: start + CHROMA_BATCH],
            embeddings=all_embeddings[start: start + CHROMA_BATCH],
            ids=ids[start: start + CHROMA_BATCH],
            metadatas=metas[start: start + CHROMA_BATCH],
        )

    log.info("  Ingested %d CVEs from NVD %s", len(docs), year)
    return len(docs)


def run_all(
    nvd_dir: Path    = NVD_DIR,
    chroma_dir: Path = CHROMA_DIR,
    collection_name: str = COLLECTION,
) -> None:
    """Ingest all NVD feed files found in nvd_dir."""
    feed_files = sorted(nvd_dir.glob("nvdcve-*.json"))
    if not feed_files:
        log.error("No NVD feed files found in %s", nvd_dir)
        return

    log.info("Loading embedding model: %s", EMBED_MODEL)
    model = SentenceTransformer(EMBED_MODEL)

    chroma_dir.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(chroma_dir))
    col    = client.get_or_create_collection(
        name=collection_name,
        metadata={"hnsw:space": "cosine"},
    )

    total = 0
    for feed in feed_files:
        # Extract year from filename: nvdcve-2023.json → "2023"
        year = feed.stem.replace("nvdcve-", "")
        total += ingest_nvd(feed, col, model, year)

    final_count = col.count()
    log.info(
        "\nNVD ingestion complete — %d CVEs added this run. "
        "Collection total: %d documents",
        total, final_count,
    )


if __name__ == "__main__":
    run_all()
