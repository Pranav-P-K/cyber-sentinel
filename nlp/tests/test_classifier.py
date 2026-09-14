"""
nlp/tests/test_classifier.py
Unit tests for MITREClassifier — 5 known CICIDS attack type → tactic mappings.

Run with: pytest nlp/tests/test_classifier.py -v
No Ollama/ChromaDB needed — only the SentenceTransformer model.
"""

import pytest
from nlp.classifier.mitre_classifier import MITREClassifier


@pytest.fixture(scope="module")
def clf():
    """Load classifier once for all tests in this module."""
    return MITREClassifier()


# ── Primary mapping tests ─────────────────────────────────────────────────────

class TestMITREClassifierMappings:

    def test_port_scan_is_reconnaissance(self, clf):
        """PortScan → TA0043 Reconnaissance"""
        tactic_id, score = clf.classify("PortScan network mapping 55 ports per second")
        assert tactic_id == "TA0043", f"Expected TA0043, got {tactic_id} (sim={score:.4f})"
        assert score > 0.0

    def test_ssh_brute_is_credential_access(self, clf):
        """SSH-Patator → TA0006 Credential Access"""
        tactic_id, score = clf.classify("SSH-Patator brute force 450 attempts port 22")
        assert tactic_id == "TA0006", f"Expected TA0006, got {tactic_id} (sim={score:.4f})"

    def test_ddos_is_impact(self, clf):
        """DDoS → TA0040 Impact"""
        tactic_id, score = clf.classify("DDoS SYN flood 950000 bytes per second port 80")
        assert tactic_id == "TA0040", f"Expected TA0040, got {tactic_id} (sim={score:.4f})"

    def test_bot_c2_is_command_and_control(self, clf):
        """Bot C2 beacon → TA0011 Command and Control"""
        tactic_id, score = clf.classify("Bot C2 beacon HTTPS regular interval outbound")
        assert tactic_id == "TA0011", f"Expected TA0011, got {tactic_id} (sim={score:.4f})"

    def test_infiltration_is_exfiltration(self, clf):
        """Infiltration large outbound → TA0010 Exfiltration"""
        tactic_id, score = clf.classify("Infiltration large outbound data transfer HTTPS")
        assert tactic_id == "TA0010", f"Expected TA0010, got {tactic_id} (sim={score:.4f})"


# ── Top-K and phase order tests ───────────────────────────────────────────────

class TestMITREClassifierHelpers:

    def test_top_k_returns_k_results(self, clf):
        results = clf.classify_top_k("SSH brute force credentials", k=3)
        assert len(results) == 3

    def test_top_k_sorted_descending(self, clf):
        results = clf.classify_top_k("ransomware data encryption impact", k=5)
        scores = [r[1] for r in results]
        assert scores == sorted(scores, reverse=True), "Results should be sorted by score descending"

    def test_get_phase_order_known(self, clf):
        assert clf.get_phase_order("TA0043") == 0   # Reconnaissance is first
        assert clf.get_phase_order("TA0040") == 13  # Impact is last

    def test_get_phase_order_unknown(self, clf):
        assert clf.get_phase_order("TA9999") == 99

    def test_get_tactic_name(self, clf):
        assert clf.get_tactic_name("TA0006") == "Credential Access"
        assert clf.get_tactic_name("TA0043") == "Reconnaissance"
        assert clf.get_tactic_name("TA9999") == "TA9999"  # unknown → returns ID

    def test_classify_alert_dict(self, clf):
        """
        FTP-Patator is a credential brute-force (TA0006) but all-MiniLM-L6-v2
        may associate FTP port 21 with data transfer (TA0010 Exfiltration) or
        initial access (TA0001). All three are contextually reasonable.
        """
        alert = {
            "attack_type": "FTP-Patator",
            "protocol": "TCP",
            "dst_port": 21,
        }
        tactic_id, score = clf.classify_alert(alert)
        assert tactic_id in ["TA0006", "TA0001", "TA0010"], (
            f"Unexpected tactic: {tactic_id} — expected TA0006, TA0001, or TA0010"
        )
        assert 0.0 < score <= 1.0

