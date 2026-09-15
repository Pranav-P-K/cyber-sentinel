"""
backend/core/chain/reconstructor.py
Novelty 2: TKCI — Temporal Kill Chain Inference with DBASC

Pipeline per alert batch:
  1. DBASC: cluster alerts into sessions using DBSCAN on
     d = 0.7 * IP_mismatch + 0.3 * |Δt| / T_max
  2. TKCI: for each session, sort tactics by canonical kill-chain order
  3. KCV  = distinct_phases / time_window_hours
  4. SI   = (chain_depth + cisa_fraction + norm_kcv) / 3 * 100
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import numpy as np
from sklearn.cluster import DBSCAN

from nlp.classifier.mitre_classifier import MITREClassifier, TACTIC_ORDER, TACTIC_NAMES

log = logging.getLogger("chain.reconstructor")

# DBASC hyper-parameters (tuned on CICIDS 2017)
DBSCAN_EPS        = 0.35    # neighbourhood radius in the distance metric
DBSCAN_MIN_SAMPLES = 2       # minimum alerts to form a session core

# KCV normalisation cap — velocities above this are capped at 1.0 in SI
KCV_CAP = 10.0


@dataclass
class AttackSession:
    session_id: str
    alert_indices: list[int]
    attacker_ips: list[str]
    victim_ips: list[str]
    time_start: Optional[datetime]
    time_end: Optional[datetime]
    ordered_tactics: list[str]          # e.g. ["TA0043", "TA0006", "TA0010"]
    tactic_labels: list[str]            # human-readable
    kcv: float                          # phases / hour
    severity_index: float               # 0–100
    cisa_fraction: float                # fraction of alerts with CISA KEV hit
    alert_details: list[dict] = field(default_factory=list)


@dataclass
class ReconstructionResult:
    sessions: list[AttackSession]
    noise_alert_indices: list[int]      # DBSCAN noise (label == -1)
    total_alerts: int
    session_count: int


class KillChainReconstructor:
    """
    DBASC + TKCI implementation.

    Usage:
        clf = MITREClassifier()
        recon = KillChainReconstructor(clf)
        result = recon.reconstruct(alerts, tactic_assignments)
    """

    def __init__(
        self,
        classifier: MITREClassifier | None = None,
        eps: float = DBSCAN_EPS,
        min_samples: int = DBSCAN_MIN_SAMPLES,
    ):
        self.clf         = classifier or MITREClassifier()
        self.eps         = eps
        self.min_samples = min_samples

    # ── Public API ────────────────────────────────────────────────────────────

    def reconstruct(
        self,
        alerts: list[dict],
        tactic_assignments: list[str] | None = None,
    ) -> ReconstructionResult:
        """
        Full DBASC + TKCI reconstruction.

        Args:
            alerts:             list of alert dicts (from CSV/JSON input)
            tactic_assignments: pre-computed tactic IDs per alert (from NLP layer).
                                If None, classify on-the-fly.

        Returns:
            ReconstructionResult with per-session kill chains, KCV, and SI.
        """
        if not alerts:
            return ReconstructionResult(sessions=[], noise_alert_indices=[], total_alerts=0, session_count=0)

        # Assign tactics if not provided
        if tactic_assignments is None:
            tactic_assignments = [
                self.clf.classify_alert(a)[0] for a in alerts
            ]

        # Step 1: DBASC clustering
        labels = self.cluster_sessions(alerts)

        # Separate sessions from noise
        session_ids = set(l for l in labels if l != -1)
        noise_indices = [i for i, l in enumerate(labels) if l == -1]

        sessions: list[AttackSession] = []
        for sid in sorted(session_ids):
            indices = [i for i, l in enumerate(labels) if l == sid]
            session_alerts = [alerts[i] for i in indices]
            session_tactics = [tactic_assignments[i] for i in indices]

            session = self._build_session(
                session_id=f"session-{sid:02d}",
                alert_indices=indices,
                alerts=session_alerts,
                tactics=session_tactics,
            )
            sessions.append(session)

        # Sort sessions by severity (highest first)
        sessions.sort(key=lambda s: s.severity_index, reverse=True)

        log.info(
            "Reconstruction complete: %d sessions, %d noise alerts",
            len(sessions), len(noise_indices),
        )
        return ReconstructionResult(
            sessions=sessions,
            noise_alert_indices=noise_indices,
            total_alerts=len(alerts),
            session_count=len(sessions),
        )

    def cluster_sessions(self, alerts: list[dict]) -> np.ndarray:
        """
        DBASC: Build pairwise distance matrix then run DBSCAN.

        Distance metric:
            d(i, j) = 0.7 * IP_mismatch + 0.3 * |Δt| / T_max

        Returns array of cluster labels (int), -1 = noise.
        """
        n = len(alerts)
        if n == 1:
            return np.array([0])

        timestamps = [_parse_ts(a.get("timestamp", "")) for a in alerts]
        t_values   = np.array([t.timestamp() if t else 0.0 for t in timestamps])
        t_max      = float(np.ptp(t_values)) or 1.0   # range (avoid div-by-zero)

        dist_matrix = np.zeros((n, n), dtype=float)
        for i in range(n):
            for j in range(i + 1, n):
                d = _alert_distance(alerts[i], alerts[j], t_values[i], t_values[j], t_max)
                dist_matrix[i, j] = d
                dist_matrix[j, i] = d

        db = DBSCAN(eps=self.eps, min_samples=self.min_samples, metric="precomputed")
        labels = db.fit_predict(dist_matrix)
        log.debug("DBSCAN labels: %s", labels.tolist())
        return labels

    # ── Session building ──────────────────────────────────────────────────────

    def _build_session(
        self,
        session_id: str,
        alert_indices: list[int],
        alerts: list[dict],
        tactics: list[str],
    ) -> AttackSession:
        """Build a fully-scored AttackSession from a cluster of alerts."""
        # Extract IPs
        attacker_ips = list(dict.fromkeys(
            a.get("src_ip", "") for a in alerts if a.get("src_ip")
        ))
        victim_ips = list(dict.fromkeys(
            a.get("dst_ip", "") for a in alerts if a.get("dst_ip")
        ))

        # Time window
        timestamps = [_parse_ts(a.get("timestamp", "")) for a in alerts]
        valid_ts   = [t for t in timestamps if t is not None]
        t_start    = min(valid_ts) if valid_ts else None
        t_end      = max(valid_ts) if valid_ts else None

        # TKCI: order tactics by canonical kill-chain phase
        ordered_tactics = self._order_tactics(tactics)
        tactic_labels   = [TACTIC_NAMES.get(t, t) for t in ordered_tactics]

        # KCV
        kcv = self.compute_kcv(ordered_tactics, t_start, t_end)

        # CISA fraction (fraction of alerts that are CISA KEV hits)
        cisa_hits = sum(1 for a in alerts if a.get("cisa_hit") or a.get("is_cisa_kev"))
        cisa_fraction = cisa_hits / len(alerts) if alerts else 0.0

        # Severity Index
        si = self.compute_si(ordered_tactics, cisa_fraction, kcv)

        return AttackSession(
            session_id=session_id,
            alert_indices=alert_indices,
            attacker_ips=attacker_ips,
            victim_ips=victim_ips,
            time_start=t_start,
            time_end=t_end,
            ordered_tactics=ordered_tactics,
            tactic_labels=tactic_labels,
            kcv=kcv,
            severity_index=si,
            cisa_fraction=cisa_fraction,
            alert_details=alerts,
        )

    def _order_tactics(self, tactics: list[str]) -> list[str]:
        """
        TKCI: deduplicate and sort tactics by canonical kill-chain phase order.
        Preserves temporal narrative flow.
        """
        seen: set[str] = set()
        unique: list[str] = []
        for t in tactics:
            if t and t not in seen:
                seen.add(t)
                unique.append(t)
        # Sort by TACTIC_ORDER index
        unique.sort(key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99)
        return unique

    # ── Metric formulae ───────────────────────────────────────────────────────

    @staticmethod
    def compute_kcv(
        ordered_tactics: list[str],
        t_start: Optional[datetime],
        t_end: Optional[datetime],
    ) -> float:
        """
        Kill Chain Velocity = distinct_phases / time_window_hours

        High KCV (> 5) → automated/scripted attack.
        Low KCV (< 2)  → manual / APT-patterned.
        Returns 0.0 if time window is zero or unknownork.
        """
        phases = len(set(ordered_tactics))
        if not t_start or not t_end or t_start == t_end:
            return float(phases)   # unknown window → return phase count as raw

        delta_hours = (t_end - t_start).total_seconds() / 3600.0
        if delta_hours < 1 / 3600:   # < 1 second window
            return float(phases)
        return round(phases / delta_hours, 4)

    @staticmethod
    def compute_si(
        ordered_tactics: list[str],
        cisa_fraction: float,
        kcv: float,
    ) -> float:
        """
        Severity Index (0–100):
            SI = (chain_depth + cisa_fraction + norm_kcv) / 3 * 100

        chain_depth   = len(unique_tactics) / 14   (14 = max MITRE tactics)
        cisa_fraction = CVEs with cisa_hit / total alerts  (already 0–1)
        norm_kcv      = min(kcv, KCV_CAP) / KCV_CAP        (caps at 10 ph/hr)
        """
        chain_depth  = min(len(set(ordered_tactics)), 14) / 14.0
        norm_kcv     = min(kcv, KCV_CAP) / KCV_CAP
        si_raw       = (chain_depth + cisa_fraction + norm_kcv) / 3.0
        return round(si_raw * 100.0, 2)

    @staticmethod
    def kcv_label(kcv: float) -> str:
        """Human-readable KCV interpretation."""
        if kcv > 5:
            return "automated/scripted"
        elif kcv > 2:
            return "semi-automated"
        else:
            return "manual/APT-patterned"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_ts(ts_str: str) -> Optional[datetime]:
    """Parse ISO 8601 timestamp string. Returns None on failure."""
    if not ts_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(str(ts_str).strip(), fmt)
        except ValueError:
            continue
    return None


def _alert_distance(
    a: dict, b: dict,
    t_a: float, t_b: float,
    t_max: float,
) -> float:
    """
    DBASC pairwise distance:
        d = 0.7 * IP_mismatch + 0.3 * |Δt| / T_max

    IP_mismatch = 0 if same src_ip, 1 if different (primary clustering signal).
    Temporal distance normalised to [0, 1].
    """
    ip_a = a.get("src_ip", "")
    ip_b = b.get("src_ip", "")
    ip_mismatch = 0.0 if ip_a == ip_b else 1.0

    t_dist = abs(t_a - t_b) / t_max if t_max > 0 else 0.0
    t_dist = min(t_dist, 1.0)

    return 0.7 * ip_mismatch + 0.3 * t_dist
