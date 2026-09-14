"""
backend/core/rag/knowledge_base.py
ChromaDB wrapper with semantic search and MMR re-ranking.
"""

import logging
from pathlib import Path

import numpy as np
import chromadb
from chromadb.utils import embedding_functions
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

from backend.config import get_settings

log = logging.getLogger("rag.knowledge_base")


class KnowledgeBase:
    """
    Wraps a ChromaDB persistent collection and provides:
      - search()     : top-k cosine similarity
      - search_mmr() : Maximal Marginal Relevance (diversity-aware retrieval)
      - get_doc_count(): number of indexed documents
    """

    def __init__(
        self,
        persist_dir: str | None = None,
        collection_name: str | None = None,
        model_name: str | None = None,
    ):
        settings = get_settings()
        _persist  = persist_dir     or settings.chroma_persist_dir
        _col_name = collection_name or settings.chroma_collection_name
        _model    = model_name      or settings.embedding_model

        # Resolve relative path to absolute
        _persist = str(Path(_persist).resolve())

        self.client = chromadb.PersistentClient(path=_persist)
        ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=_model
        )
        self.col = self.client.get_or_create_collection(
            name=_col_name,
            embedding_function=ef,
            metadata={"hnsw:space": "cosine"},
        )
        # Keep a raw SentenceTransformer for MMR re-ranking embeddings
        self._model = SentenceTransformer(_model)
        log.info(
            "KnowledgeBase ready — collection='%s' docs=%d",
            _col_name, self.col.count(),
        )

    def search(self, query: str, k: int = 5) -> list[dict]:
        """
        Top-k cosine similarity search.

        Returns list of {"text": str, "metadata": dict, "distance": float}
        """
        k = min(k, self.col.count())
        if k == 0:
            return []
        results = self.col.query(
            query_texts=[query],
            n_results=k,
            include=["documents", "metadatas", "distances"],
        )
        return [
            {"text": doc, "metadata": meta, "distance": dist}
            for doc, meta, dist in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0],
            )
        ]

    def search_mmr(
        self,
        query: str,
        k: int = 5,
        fetch_k: int = 20,
        lambda_mult: float = 0.6,
    ) -> list[dict]:
        """
        Maximal Marginal Relevance retrieval.

        Retrieves fetch_k candidates then greedily selects k documents
        that balance relevance (lambda_mult) vs. diversity (1 - lambda_mult).

        MMR score = lambda * relevance - (1 - lambda) * max_redundancy
        Default lambda=0.6 favours relevance slightly over diversity.
        """
        fetch_k = min(fetch_k, self.col.count())
        k = min(k, fetch_k)
        if fetch_k == 0:
            return []

        results = self.col.query(
            query_texts=[query],
            n_results=fetch_k,
            include=["documents", "metadatas", "distances"],
        )
        docs   = results["documents"][0]
        metas  = results["metadatas"][0]
        dists  = results["distances"][0]

        if not docs:
            return []

        # Embed all candidates + query
        q_emb   = self._model.encode([query])                # (1, D)
        d_embs  = self._model.encode(docs)                   # (fetch_k, D)

        selected: list[dict] = []
        selected_embs: list[np.ndarray] = []
        remaining = list(range(len(docs)))

        while len(selected) < k and remaining:
            rel_scores = cosine_similarity(q_emb, d_embs)[0]   # (fetch_k,)

            if not selected_embs:
                # First pick: purely by relevance
                idx = int(np.argmax([rel_scores[i] for i in remaining]))
                chosen = remaining[idx]
            else:
                stacked = np.array(selected_embs)               # (sel, D)
                red_scores = cosine_similarity(d_embs, stacked).max(axis=1)  # (fetch_k,)
                mmr = lambda_mult * rel_scores - (1 - lambda_mult) * red_scores
                # Mask out already-selected
                masked = {i: mmr[i] for i in remaining}
                chosen = max(masked, key=masked.get)

            selected.append({
                "text":     docs[chosen],
                "metadata": metas[chosen],
                "distance": dists[chosen],
            })
            selected_embs.append(d_embs[chosen])
            remaining.remove(chosen)

        return selected

    def get_doc_count(self) -> int:
        return self.col.count()

    def search_by_cve(self, cve_id: str) -> list[dict]:
        """
        Exact metadata filter for a specific CVE ID.
        Used by PFGL claim verification.
        """
        try:
            results = self.col.get(
                where={"cve_id": cve_id},
                include=["documents", "metadatas"],
            )
            return [
                {"text": doc, "metadata": meta}
                for doc, meta in zip(results["documents"], results["metadatas"])
            ]
        except Exception:
            return []

    def search_cisa_hit(self, cve_id: str) -> bool:
        """Check if a CVE is in the CISA KEV catalog (cisa_hit=True in metadata)."""
        results = self.search_by_cve(cve_id)
        return any(r["metadata"].get("cisa_hit") for r in results)
