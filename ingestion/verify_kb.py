"""
ingestion/verify_kb.py
Sanity-check the ChromaDB knowledge base after all ingestion is complete.

Runs 5 semantic queries and prints the top-3 results for each.
Checks that total document count is 50K+.

Usage:
    python -m ingestion.verify_kb
    python ingestion/verify_kb.py
"""

import logging
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).resolve().parent.parent
CHROMA_DIR  = REPO_ROOT / "data" / "chroma_db"
COLLECTION  = "cybersentinel_kb"
EMBED_MODEL = "all-MiniLM-L6-v2"

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger("verify_kb")

# 5 mandatory verification queries
QUERIES = [
    ("SSH brute force",                  "TA0006 — Credential Access expected"),
    ("CVE-2021-44228",                   "Log4Shell — NVD/CISA KEV hit expected"),
    ("ransomware lateral movement",      "TA0008 Lateral Movement / TA0040 Impact expected"),
    ("port scan reconnaissance",         "TA0043 Reconnaissance expected"),
    ("C2 beacon command and control",    "TA0011 C2 expected"),
]


def verify(
    chroma_dir: Path = CHROMA_DIR,
    collection_name: str = COLLECTION,
    n_results: int = 3,
) -> bool:
    """
    Run semantic verification queries. Returns True if KB has 50K+ documents,
    False otherwise.
    """
    client = chromadb.PersistentClient(path=str(chroma_dir))
    try:
        col = client.get_collection(collection_name)
    except Exception:
        log.error("Collection '%s' not found — run ingestion scripts first.", collection_name)
        return False

    total = col.count()
    log.info("=" * 60)
    log.info("Collection: '%s' | Total documents: %d", collection_name, total)
    log.info("=" * 60)

    model = SentenceTransformer(EMBED_MODEL)

    all_pass = True
    for query, expected_note in QUERIES:
        emb     = model.encode(query).tolist()
        results = col.query(
            query_embeddings=[emb],
            n_results=n_results,
            include=["documents", "metadatas", "distances"],
        )

        print(f"\n{'-'*60}")
        print(f"  QUERY: \"{query}\"")
        print(f"  NOTE:   {expected_note}")
        print(f"{'-'*60}")
        for rank, (doc, meta, dist) in enumerate(
            zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0],
            ),
            start=1,
        ):
            doc_type = meta.get("type", "unknown")
            name     = meta.get("name") or meta.get("cve_id") or meta.get("vuln_name", "")
            score    = 1.0 - dist   # cosine: distance → similarity
            print(f"  [{rank}] type={doc_type:<15} name={name:<35} sim={score:.4f}")
            print(f"       {doc[:120].strip()} …")

    print(f"\n{'='*60}")
    if total >= 50_000:
        print(f"  [PASS] Knowledge base contains {total:,} documents (>= 50,000 target)")
    else:
        print(f"  [WARN] KB contains only {total:,} docs (target: 50,000+) -- run more ingestion")
        all_pass = False
    print(f"{'='*60}\n")

    return all_pass


if __name__ == "__main__":
    ok = verify()
    exit(0 if ok else 1)
