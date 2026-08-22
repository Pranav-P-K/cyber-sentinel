"""
nlp/classifier/mitre_classifier.py
Classifies a network alert's text into a MITRE ATT&CK tactic using cosine
similarity against pre-embedded tactic descriptions.

This is the semantic NLP layer (Layer 2) of the CyberSentinel pipeline.
"""

import json
import logging
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

log = logging.getLogger("mitre_classifier")

# Canonical MITRE tactic order (used to compute chain ordering)
TACTIC_ORDER = [
    "TA0043",  # Reconnaissance
    "TA0042",  # Resource Development
    "TA0001",  # Initial Access
    "TA0002",  # Execution
    "TA0003",  # Persistence
    "TA0004",  # Privilege Escalation
    "TA0005",  # Defense Evasion
    "TA0006",  # Credential Access
    "TA0007",  # Discovery
    "TA0008",  # Lateral Movement
    "TA0009",  # Collection
    "TA0010",  # Exfiltration
    "TA0011",  # Command and Control
    "TA0040",  # Impact
]

TACTIC_NAMES = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

_DEFAULT_DESCRIPTIONS_PATH = (
    Path(__file__).resolve().parent / "tactic_descriptions.json"
)


class MITREClassifier:
    """
    Assigns a MITRE ATT&CK tactic to an alert by embedding the alert text and
    computing cosine similarity against pre-computed tactic description embeddings.

    Usage:
        clf = MITREClassifier()
        tactic_id, score = clf.classify("SSH-Patator brute force on port 22")
        print(tactic_id, score)  # TA0006, 0.87
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        descriptions_path: Path = _DEFAULT_DESCRIPTIONS_PATH,
    ):
        self.model = SentenceTransformer(model_name)

        with open(descriptions_path, encoding="utf-8") as f:
            self.tactics: dict[str, str] = json.load(f)

        # Pre-compute tactic embeddings once at init
        log.info("Pre-computing %d tactic embeddings …", len(self.tactics))
        self.tactic_embs: dict[str, np.ndarray] = {
            tid: self.model.encode(desc)
            for tid, desc in self.tactics.items()
        }
        log.info("MITREClassifier ready.")

    def classify(self, alert_text: str) -> tuple[str, float]:
        """
        Classify a single alert text.

        Returns:
            (tactic_id, cosine_similarity_score) — e.g. ("TA0006", 0.874)
        """
        emb = self.model.encode(alert_text)
        scores = {
            tid: float(cosine_similarity([emb], [e])[0][0])
            for tid, e in self.tactic_embs.items()
        }
        best_id    = max(scores, key=scores.get)
        best_score = scores[best_id]
        return best_id, best_score

    def classify_top_k(self, alert_text: str, k: int = 3) -> list[tuple[str, float]]:
        """
        Return top-k (tactic_id, score) sorted by similarity descending.
        Useful for ambiguous alerts (e.g., DoS can be TA0040 or TA0011).
        """
        emb = self.model.encode(alert_text)
        scores = {
            tid: float(cosine_similarity([emb], [e])[0][0])
            for tid, e in self.tactic_embs.items()
        }
        return sorted(scores.items(), key=lambda x: x[1], reverse=True)[:k]

    def classify_alert(self, alert: dict) -> tuple[str, float]:
        """
        Convenience wrapper: build query text from an alert dict and classify.
        Uses attack_type + protocol + dst_port as the query.
        """
        attack = alert.get("attack_type", "")
        proto  = alert.get("protocol", "TCP")
        port   = alert.get("dst_port", "")
        query  = f"{attack} {proto} port {port}".strip()
        return self.classify(query)

    def get_phase_order(self, tactic_id: str) -> int:
        """
        Return the canonical kill-chain order index for a tactic.
        Used by TKCI to sort assigned tactics chronologically.
        Unknown tactics return 99.
        """
        try:
            return TACTIC_ORDER.index(tactic_id)
        except ValueError:
            return 99

    def get_tactic_name(self, tactic_id: str) -> str:
        """Return human-readable tactic name for a given tactic ID."""
        return TACTIC_NAMES.get(tactic_id, tactic_id)


# ── Smoke test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    clf = MITREClassifier()

    test_cases = [
        ("SSH-Patator brute force 450 attempts port 22",    "TA0006"),
        ("PortScan 55 ports per second network mapping",    "TA0043"),
        ("DDoS SYN flood 950000 bytes per second port 80",  "TA0040"),
        ("Bot C2 beacon HTTPS regular interval outbound",   "TA0011"),
        ("Infiltration large outbound data transfer HTTPS",  "TA0010"),
    ]

    print("\nMITRE Classifier — Smoke Test")
    print("=" * 70)
    all_pass = True
    for text, expected in test_cases:
        pred_id, score = clf.classify(text)
        pred_name  = clf.get_tactic_name(pred_id)
        exp_name   = clf.get_tactic_name(expected)
        status     = "PASS" if pred_id == expected else "FAIL"
        if pred_id != expected:
            all_pass = False
        print(
            f"[{status}]  Expected: {expected} ({exp_name})\n"
            f"        Got:      {pred_id} ({pred_name})  sim={score:.4f}\n"
            f"        Query:    {text!r}\n"
        )

    top3_q = "FTP login attempt brute force credentials"
    print(f"Top-3 for: {top3_q!r}")
    for tid, sc in clf.classify_top_k(top3_q, k=3):
        print(f"  {tid} {clf.get_tactic_name(tid):<25}  {sc:.4f}")

    print("=" * 70)
    print("All tests passed!" if all_pass else "Some tests failed — review tactic_descriptions.json")
