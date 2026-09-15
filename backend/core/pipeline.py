"""
backend/core/pipeline.py
CyberSentinel 6-layer pipeline orchestrator.

Layer order (Day 3–5):
  1. NLP     : entity extraction + MITRE tactic classification
  2. CGAR    : Confidence-Guided Adaptive Retrieval (Novelty 1)
  3. TKCI    : Temporal Kill Chain Inference / DBASC (Novelty 2)
  4. Narrative: LLM chain narrative generation
  5. PFGL    : Post-Generation Factual Grounding (Novelty 3) — wired Day 5
  6. Storage : async persist to SQLite
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime

from backend.config import get_settings
from backend.core.chain.reconstructor import AttackSession, KillChainReconstructor, ReconstructionResult
from backend.core.llm.client import LLMClient
from backend.core.llm.prompts import (
    CHAIN_NARRATIVE_SYSTEM,
    CHAIN_NARRATIVE_PROMPT,
)
from backend.core.rag.adaptive_rag import AdaptiveRAG, RetrievalResult
from backend.core.rag.knowledge_base import KnowledgeBase
from nlp.classifier.mitre_classifier import MITREClassifier
from nlp.ner.entity_extractor import AlertEntityExtractor

log = logging.getLogger("pipeline")


class CyberSentinelPipeline:
    """
    Singleton orchestrator. Initialised once at startup via FastAPI lifespan.
    All heavy objects (models, ChromaDB client) are shared across requests.
    """

    def __init__(
        self,
        kb:   KnowledgeBase       | None = None,
        llm:  LLMClient           | None = None,
        clf:  MITREClassifier     | None = None,
        recon: KillChainReconstructor | None = None,
    ):
        self.kb    = kb    or KnowledgeBase()
        self.llm   = llm   or LLMClient()
        self.clf   = clf   or MITREClassifier()
        self.recon = recon or KillChainReconstructor(classifier=self.clf)
        self.rag   = AdaptiveRAG(kb=self.kb, llm=self.llm)
        self.ner   = AlertEntityExtractor()
        log.info("CyberSentinelPipeline ready.")

    async def analyze(self, alerts: list[dict]) -> dict:
        """
        Run the full pipeline on a batch of alert dicts.

        Returns a structured dict matching AnalyzeResponse schema.
        """
        t0 = time.monotonic()
        analysis_id = str(uuid.uuid4())
        log.info("Analysis %s starting — %d alerts", analysis_id, len(alerts))

        # ── Layer 1: NLP — entity extraction + MITRE classification ──────────
        tactic_assignments: list[str] = []
        tactic_confidences: list[float] = []
        for alert in alerts:
            tactic_id, confidence = self.clf.classify_alert(alert)
            alert["mitre_tactic"]       = tactic_id
            alert["tactic_confidence"]  = confidence
            tactic_assignments.append(tactic_id)
            tactic_confidences.append(confidence)

        log.info("Layer 1 NLP done — tactics: %s", tactic_assignments)

        # ── Layer 2: TKCI — DBASC session clustering ──────────────────────────
        recon_result: ReconstructionResult = self.recon.reconstruct(alerts, tactic_assignments)
        log.info(
            "Layer 2 TKCI done — %d sessions, %d noise",
            recon_result.session_count, len(recon_result.noise_alert_indices)
        )

        # ── Layers 3 + 4: CGAR retrieval + LLM narrative (parallel per session) ─
        session_reports = await asyncio.gather(*[
            self._process_session(session)
            for session in recon_result.sessions
        ])

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        log.info("Analysis %s complete in %dms", analysis_id, elapsed_ms)

        return {
            "analysis_id":   analysis_id,
            "total_alerts":  len(alerts),
            "session_count": recon_result.session_count,
            "noise_alerts":  len(recon_result.noise_alert_indices),
            "sessions":      session_reports,
            "processing_ms": elapsed_ms,
        }

    async def _process_session(self, session: AttackSession) -> dict:
        """
        CGAR + Narrative for a single session.
        Returns a dict matching SessionReport schema.
        """
        # Build a synthetic "aggregate alert" for retrieval query
        aggregate_alert = {
            "attack_type": _dominant_attack_type(session.alert_details),
            "src_ip":      session.attacker_ips[0] if session.attacker_ips else "",
            "dst_port":    _dominant_port(session.alert_details),
            "protocol":    "TCP",
            "mitre_tactic": session.ordered_tactics[-1] if session.ordered_tactics else "TA0001",
        }

        # Layer 3: CGAR adaptive retrieval
        retrieval: RetrievalResult = await self.rag.retrieve(aggregate_alert)

        # Layer 4: LLM chain narrative
        narrative = await self._generate_narrative(session, retrieval)

        return {
            "session_id":       session.session_id,
            "attacker_ips":     session.attacker_ips,
            "victim_ips":       session.victim_ips,
            "time_start":       session.time_start.isoformat() if session.time_start else None,
            "time_end":         session.time_end.isoformat()   if session.time_end   else None,
            "ordered_chain":    session.ordered_tactics,
            "chain_labels":     session.tactic_labels,
            "kcv":              session.kcv,
            "kcv_label":        KillChainReconstructor.kcv_label(session.kcv),
            "severity_index":   session.severity_index,
            "hrss":             retrieval.hrss,
            "round2_triggered": retrieval.round2_triggered,
            "narrative":        narrative,
            "alert_count":      len(session.alert_details),
        }

    async def _generate_narrative(
        self,
        session: AttackSession,
        retrieval: RetrievalResult,
    ) -> str:
        """Generate grounded LLM narrative for a session using CHAIN_NARRATIVE_PROMPT."""
        context = _format_context(retrieval.docs)

        chain_str = " → ".join(
            f"{t} ({l})" for t, l in zip(session.ordered_tactics, session.tactic_labels)
        )

        t_window = "unknown"
        if session.time_start and session.time_end:
            t_window = f"{session.time_start.isoformat()} → {session.time_end.isoformat()}"

        alert_details_str = "\n".join(
            f"  [{i+1}] {a.get('attack_type','?')}  src={a.get('src_ip','?')}  "
            f"dst_port={a.get('dst_port','?')}  ts={a.get('timestamp','?')}"
            for i, a in enumerate(session.alert_details[:10])  # cap at 10 in prompt
        )

        prompt = CHAIN_NARRATIVE_PROMPT.format(
            attacker_ips=", ".join(session.attacker_ips) or "Unknown",
            time_window=t_window,
            kill_chain=chain_str,
            kcv=session.kcv,
            kcv_label=KillChainReconstructor.kcv_label(session.kcv),
            severity_index=session.severity_index,
            context=context or "No specific threat intelligence retrieved.",
            alert_details=alert_details_str,
        )

        try:
            narrative = await self.llm.generate(CHAIN_NARRATIVE_SYSTEM, prompt)
            return narrative.strip()
        except Exception as exc:
            log.warning("Narrative generation failed: %s", exc)
            return (
                f"[Narrative unavailable — LLM error: {exc}]\n\n"
                f"Attack chain: {chain_str}\n"
                f"SI={session.severity_index:.1f}  KCV={session.kcv:.2f} ph/hr"
            )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _dominant_attack_type(alerts: list[dict]) -> str:
    """Return the most common attack_type in a session."""
    from collections import Counter
    types = [a.get("attack_type", "") for a in alerts if a.get("attack_type")]
    if not types:
        return "Unknown"
    return Counter(types).most_common(1)[0][0]


def _dominant_port(alerts: list[dict]) -> int | None:
    """Return the most common destination port."""
    from collections import Counter
    ports = [a.get("dst_port") for a in alerts if a.get("dst_port")]
    if not ports:
        return None
    return Counter(ports).most_common(1)[0][0]


def _format_context(docs: list[dict], max_chars: int = 3000) -> str:
    """Format retrieved docs into a numbered context block."""
    lines = []
    total = 0
    for i, doc in enumerate(docs, 1):
        text = doc.get("text", "")[:500]
        lines.append(f"[{i}] {text}")
        total += len(text)
        if total > max_chars:
            break
    return "\n\n".join(lines)


# ── Module-level singleton (lazily initialised) ───────────────────────────────
_pipeline_instance: CyberSentinelPipeline | None = None


def get_pipeline() -> CyberSentinelPipeline:
    """FastAPI dependency: returns the shared pipeline instance."""
    global _pipeline_instance
    if _pipeline_instance is None:
        _pipeline_instance = CyberSentinelPipeline()
    return _pipeline_instance
