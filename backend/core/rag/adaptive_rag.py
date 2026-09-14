"""
backend/core/rag/adaptive_rag.py
Novelty 1: CGAR — Confidence-Guided Adaptive Retrieval

Pipeline per alert:
  Round 1:
    1. Build query from alert entities
    2. Retrieve top-k docs (MMR)
    3. Compute HRSS: Hybrid Retrieval Sufficiency Score
       HRSS = 0.4 * c_sem + 0.35 * c_entity + 0.25 * c_llm
    4. If HRSS >= CONFIDENCE_THRESHOLD → done
  Round 2 (triggered when HRSS < threshold):
    5. Refine query using LLM (entity-enriched)
    6. Retrieve again with refined query
    7. Merge Round 1 + Round 2 docs (deduplicated)
"""

import logging
from dataclasses import dataclass, field

from backend.config import get_settings
from backend.core.llm.client import LLMClient
from backend.core.llm.output_parsers import extract_float, safe_str
from backend.core.llm.prompts import (
    CONFIDENCE_SYSTEM,
    CONFIDENCE_PROMPT,
    QUERY_REFINEMENT_SYSTEM,
    QUERY_REFINEMENT_PROMPT,
)
from backend.core.rag.knowledge_base import KnowledgeBase
from nlp.ner.entity_extractor import AlertEntityExtractor

log = logging.getLogger("rag.adaptive_rag")


@dataclass
class RetrievalResult:
    docs: list[dict] = field(default_factory=list)
    hrss: float = 0.0
    round2_triggered: bool = False
    round1_query: str = ""
    round2_query: str = ""
    c_sem: float = 0.0
    c_entity: float = 0.0
    c_llm: float = 0.0


class HybridRetrievalSufficiencyScorer:
    """
    HRSS = 0.40 * c_sem + 0.35 * c_entity + 0.25 * c_llm

    c_sem    : best cosine similarity score from top-k docs (1 - distance)
    c_entity : fraction of alert entity strings found in retrieved doc texts
    c_llm    : LLM self-reported confidence score from CONFIDENCE_PROMPT
    """

    SEM_WEIGHT    = 0.40
    ENTITY_WEIGHT = 0.35
    LLM_WEIGHT    = 0.25

    def compute_c_sem(self, docs: list[dict]) -> float:
        if not docs:
            return 0.0
        # distance is cosine distance; similarity = 1 - distance
        sims = [1.0 - d.get("distance", 1.0) for d in docs]
        return float(max(sims))

    def compute_c_entity(self, entity_strings: list[str], docs: list[dict]) -> float:
        if not entity_strings or not docs:
            return 0.0
        combined_text = " ".join(d["text"].lower() for d in docs)
        found = sum(1 for e in entity_strings if e.lower() in combined_text)
        return found / len(entity_strings)

    async def compute_c_llm(
        self,
        alert_text: str,
        docs: list[dict],
        llm: LLMClient,
    ) -> tuple[float, str]:
        """Returns (c_llm score, missing_info string)."""
        context = _format_context(docs[:3])  # top-3 to keep prompt short
        prompt = CONFIDENCE_PROMPT.format(alert_text=alert_text, context=context)
        try:
            raw = await llm.generate(CONFIDENCE_SYSTEM, prompt)
            score = extract_float(raw, key="score", default=0.5)
            # Try to also get the 'missing' field
            from backend.core.llm.output_parsers import extract_json
            try:
                data = extract_json(raw)
                missing = data.get("missing", "")
            except ValueError:
                missing = ""
            return score, missing
        except Exception as exc:
            log.warning("c_llm computation failed: %s — using 0.5", exc)
            return 0.5, ""

    def compute_hrss(self, c_sem: float, c_entity: float, c_llm: float) -> float:
        return (
            self.SEM_WEIGHT    * c_sem +
            self.ENTITY_WEIGHT * c_entity +
            self.LLM_WEIGHT    * c_llm
        )


class AdaptiveRAG:
    """
    Full CGAR loop.

    Usage:
        rag = AdaptiveRAG()
        result = await rag.retrieve(alert)
        # result.docs → list of retrieved context dicts
        # result.hrss → final HRSS score
        # result.round2_triggered → True if second pass ran
    """

    def __init__(
        self,
        kb: KnowledgeBase | None = None,
        llm: LLMClient | None = None,
        top_k: int | None = None,
    ):
        settings = get_settings()
        self.kb         = kb  or KnowledgeBase()
        self.llm        = llm or LLMClient()
        self.top_k      = top_k or settings.rag_top_k
        self.threshold  = settings.confidence_threshold
        self.scorer     = HybridRetrievalSufficiencyScorer()
        self.extractor  = AlertEntityExtractor()

    async def retrieve(self, alert: dict) -> RetrievalResult:
        """
        Run CGAR for a single alert dict.
        Returns RetrievalResult with docs, HRSS, and diagnostics.
        """
        result = RetrievalResult()

        # Build Round 1 query
        entities   = self.extractor.extract(alert)
        query_r1   = self.extractor.build_query_text(alert, entities)
        result.round1_query = query_r1

        # Round 1: MMR retrieval
        docs_r1 = self.kb.search_mmr(query_r1, k=self.top_k, fetch_k=self.top_k * 4)
        log.debug("Round 1 query: %r → %d docs", query_r1, len(docs_r1))

        # HRSS scoring
        entity_strings = self.extractor.entity_strings(entities)
        alert_text     = _alert_to_text(alert)

        c_sem    = self.scorer.compute_c_sem(docs_r1)
        c_entity = self.scorer.compute_c_entity(entity_strings, docs_r1)
        c_llm, missing = await self.scorer.compute_c_llm(alert_text, docs_r1, self.llm)
        hrss     = self.scorer.compute_hrss(c_sem, c_entity, c_llm)

        result.c_sem    = c_sem
        result.c_entity = c_entity
        result.c_llm    = c_llm
        result.hrss     = hrss

        log.info(
            "HRSS=%.3f  c_sem=%.3f  c_entity=%.3f  c_llm=%.3f  threshold=%.2f",
            hrss, c_sem, c_entity, c_llm, self.threshold,
        )

        if hrss >= self.threshold:
            result.docs = docs_r1
            log.info("CGAR: sufficient context — skipping Round 2")
            return result

        # Round 2: query refinement
        result.round2_triggered = True
        log.info("CGAR: HRSS below threshold (%.3f < %.2f) — triggering Round 2", hrss, self.threshold)

        query_r2 = await self._refine_query(alert, entities, missing)
        result.round2_query = query_r2

        docs_r2 = self.kb.search_mmr(query_r2, k=self.top_k, fetch_k=self.top_k * 4)
        log.debug("Round 2 query: %r → %d docs", query_r2, len(docs_r2))

        # Merge and deduplicate by text
        merged = _merge_docs(docs_r1, docs_r2, max_docs=self.top_k + 2)
        result.docs = merged
        log.info("CGAR Round 2 complete — merged %d docs", len(merged))

        return result

    async def _refine_query(self, alert: dict, entities, missing: str) -> str:
        """Use the LLM to generate a more specific Round 2 query."""
        prompt = QUERY_REFINEMENT_PROMPT.format(
            alert_text=_alert_to_text(alert),
            missing=missing or "insufficient specificity",
            attack_type=safe_str(alert.get("attack_type", "Unknown")),
            src_ip=safe_str(alert.get("src_ip", "")),
            dst_port=safe_str(alert.get("dst_port", "")),
            protocol=safe_str(alert.get("protocol", "TCP")),
            cves=", ".join(entities.cves) if entities.cves else "none",
        )
        try:
            refined = await self.llm.generate(QUERY_REFINEMENT_SYSTEM, prompt)
            refined = refined.strip().splitlines()[0].strip()  # first line only
            return refined if refined else _alert_to_text(alert)
        except Exception as exc:
            log.warning("Query refinement failed: %s — using original", exc)
            return _alert_to_text(alert)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _alert_to_text(alert: dict) -> str:
    """Convert alert dict to a natural-language query string."""
    attack  = alert.get("attack_type", "network attack")
    proto   = alert.get("protocol", "TCP")
    port    = alert.get("dst_port", "")
    src_ip  = alert.get("src_ip", "")
    port_s  = f"port {port}" if port else ""
    return f"{attack} {proto} {port_s} from {src_ip}".strip()


def _format_context(docs: list[dict]) -> str:
    """Format retrieved docs into a numbered context block for prompts."""
    lines = []
    for i, doc in enumerate(docs, 1):
        lines.append(f"[{i}] {doc['text'][:400]}")
    return "\n\n".join(lines)


def _merge_docs(r1: list[dict], r2: list[dict], max_docs: int = 7) -> list[dict]:
    """Merge two doc lists, deduplicate by first 80 chars of text, sort by distance."""
    seen: set[str] = set()
    merged = []
    for doc in r1 + r2:
        key = doc["text"][:80]
        if key not in seen:
            seen.add(key)
            merged.append(doc)
    # Sort by cosine distance ascending (most similar first)
    merged.sort(key=lambda d: d.get("distance", 1.0))
    return merged[:max_docs]
