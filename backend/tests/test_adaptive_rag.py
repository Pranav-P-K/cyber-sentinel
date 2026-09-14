"""
backend/tests/test_adaptive_rag.py
Unit tests for CGAR / HRSS.

All tests use mocked LLM and KnowledgeBase — no Ollama or ChromaDB needed.
Run with: pytest backend/tests/test_adaptive_rag.py -v
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.core.rag.adaptive_rag import (
    AdaptiveRAG,
    HybridRetrievalSufficiencyScorer,
    RetrievalResult,
    _merge_docs,
    _alert_to_text,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_ALERT = {
    "alert_id": "test-001",
    "src_ip": "10.0.0.5",
    "dst_ip": "192.168.1.10",
    "dst_port": 22,
    "protocol": "TCP",
    "attack_type": "SSH-Patator",
    "timestamp": "2017-07-04T09:00:00",
}

SAMPLE_DOCS = [
    {"text": "MITRE T1110.001 Brute Force Password Guessing SSH credential attack", "metadata": {"type": "mitre_technique"}, "distance": 0.25},
    {"text": "CVE-2023-25136 OpenSSH vulnerability", "metadata": {"type": "nvd", "cve_id": "CVE-2023-25136"}, "distance": 0.40},
    {"text": "CISA KEV CVE-2023-25136 Required action: patch immediately", "metadata": {"type": "cisa_kev", "cisa_hit": True}, "distance": 0.55},
]

LOW_CONF_DOCS = [
    {"text": "Unrelated document about network topology", "metadata": {"type": "nvd"}, "distance": 0.85},
    {"text": "Another unrelated document about cloud services", "metadata": {"type": "nvd"}, "distance": 0.90},
]


def make_mock_kb(docs=SAMPLE_DOCS):
    kb = MagicMock()
    kb.search_mmr.return_value = docs
    kb.search.return_value = docs
    kb.get_doc_count.return_value = 22287
    return kb


def make_mock_llm(confidence=0.75, missing=""):
    llm = MagicMock()
    # generate returns JSON string with score
    import json
    llm.generate = AsyncMock(return_value=json.dumps({"score": confidence, "reason": "test", "missing": missing}))
    return llm


# ── HRSS unit tests ───────────────────────────────────────────────────────────

class TestHybridRetrievalSufficiencyScorer:

    def test_c_sem_high_similarity(self):
        scorer = HybridRetrievalSufficiencyScorer()
        docs = [{"distance": 0.1}, {"distance": 0.3}]
        assert scorer.compute_c_sem(docs) == pytest.approx(0.9)

    def test_c_sem_empty_docs(self):
        scorer = HybridRetrievalSufficiencyScorer()
        assert scorer.compute_c_sem([]) == 0.0

    def test_c_entity_full_coverage(self):
        scorer = HybridRetrievalSufficiencyScorer()
        entity_strings = ["SSH-Patator", "10.0.0.5"]
        docs = [{"text": "SSH-Patator attack from 10.0.0.5 on port 22"}]
        score = scorer.compute_c_entity(entity_strings, docs)
        assert score == 1.0

    def test_c_entity_no_coverage(self):
        scorer = HybridRetrievalSufficiencyScorer()
        entity_strings = ["DDoS", "192.168.100.1"]
        docs = [{"text": "Unrelated document about cloud services"}]
        score = scorer.compute_c_entity(entity_strings, docs)
        assert score == 0.0

    def test_c_entity_partial(self):
        scorer = HybridRetrievalSufficiencyScorer()
        entity_strings = ["SSH-Patator", "10.0.0.5", "22"]
        docs = [{"text": "SSH-Patator attack credentials"}]
        score = scorer.compute_c_entity(entity_strings, docs)
        assert 0.0 < score < 1.0

    def test_hrss_formula(self):
        scorer = HybridRetrievalSufficiencyScorer()
        hrss = scorer.compute_hrss(c_sem=0.8, c_entity=0.7, c_llm=0.6)
        expected = 0.40 * 0.8 + 0.35 * 0.7 + 0.25 * 0.6
        assert hrss == pytest.approx(expected, abs=1e-6)

    def test_hrss_low_triggers_round2(self):
        """When c_llm=0.4, c_sem=0.3 → HRSS should be below 0.70 threshold."""
        scorer = HybridRetrievalSufficiencyScorer()
        hrss = scorer.compute_hrss(c_sem=0.3, c_entity=0.2, c_llm=0.4)
        # 0.4*0.3 + 0.35*0.2 + 0.25*0.4 = 0.12 + 0.07 + 0.10 = 0.29
        assert hrss < 0.70, f"Expected HRSS < 0.70, got {hrss}"


# ── AdaptiveRAG integration tests (mocked) ────────────────────────────────────

class TestAdaptiveRAG:

    def test_high_confidence_no_round2(self):
        """
        When c_llm=0.85, c_sem=0.75, c_entity=1.0 (mocked) →
        HRSS = 0.4*0.75 + 0.35*1.0 + 0.25*0.85 = 0.3 + 0.35 + 0.2125 = 0.8625 > 0.70
        → Round 2 must NOT fire.
        """
        from unittest.mock import patch as mock_patch
        kb  = make_mock_kb(SAMPLE_DOCS)
        llm = make_mock_llm(confidence=0.85)
        rag = AdaptiveRAG(kb=kb, llm=llm, top_k=5)
        with mock_patch.object(rag.scorer, "compute_c_entity", return_value=1.0):
            result = asyncio.run(rag.retrieve(SAMPLE_ALERT))
        assert result.round2_triggered is False, (
            f"Round 2 should NOT fire when HRSS is high. HRSS={result.hrss:.4f}"
        )
        assert len(result.docs) > 0

    def test_low_confidence_triggers_round2(self):
        """
        Core CGAR test: c_llm=0.35, low-quality docs → HRSS < 0.70 → Round 2.
        """
        kb  = make_mock_kb(LOW_CONF_DOCS)
        llm = MagicMock()
        llm.generate = AsyncMock(side_effect=[
            '{"score": 0.35, "reason": "low", "missing": "No SSH technique"}',
            "SSH brute force credential access T1110.001 CVE-2023-25136",
        ])
        rag = AdaptiveRAG(kb=kb, llm=llm, top_k=5)
        result = asyncio.run(rag.retrieve(SAMPLE_ALERT))
        assert result.round2_triggered is True, "Round 2 should have been triggered"
        assert result.round2_query != "", "Round 2 query should be set"
        assert rag.kb.search_mmr.call_count == 2

    def test_result_docs_not_empty(self):
        kb  = make_mock_kb(SAMPLE_DOCS)
        llm = make_mock_llm(confidence=0.85)
        rag = AdaptiveRAG(kb=kb, llm=llm, top_k=5)
        result = asyncio.run(rag.retrieve(SAMPLE_ALERT))
        assert len(result.docs) > 0

    def test_hrss_components_recorded(self):
        kb  = make_mock_kb(SAMPLE_DOCS)
        llm = make_mock_llm(confidence=0.85)
        rag = AdaptiveRAG(kb=kb, llm=llm, top_k=5)
        result = asyncio.run(rag.retrieve(SAMPLE_ALERT))
        assert 0.0 <= result.c_sem    <= 1.0
        assert 0.0 <= result.c_entity <= 1.0
        assert 0.0 <= result.c_llm    <= 1.0


# ── Helper function tests ─────────────────────────────────────────────────────

def test_merge_docs_deduplication():
    r1 = [{"text": "Document about SSH attack", "distance": 0.2}]
    r2 = [{"text": "Document about SSH attack", "distance": 0.3}]  # duplicate
    merged = _merge_docs(r1, r2)
    assert len(merged) == 1  # deduped


def test_merge_docs_max_cap():
    r1 = [{"text": f"Doc {i}", "distance": float(i) / 10} for i in range(5)]
    r2 = [{"text": f"Doc {i+10}", "distance": float(i) / 10} for i in range(5)]
    merged = _merge_docs(r1, r2, max_docs=7)
    assert len(merged) <= 7


def test_alert_to_text():
    text = _alert_to_text(SAMPLE_ALERT)
    assert "SSH-Patator" in text
    assert "TCP" in text
