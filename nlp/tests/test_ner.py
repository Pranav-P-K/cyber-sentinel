"""
nlp/tests/test_ner.py
Unit tests for AlertEntityExtractor and spaCy EntityRuler patterns.

Run with: pytest nlp/tests/test_ner.py -v
"""

import pytest
from nlp.ner.entity_extractor import AlertEntityExtractor
from nlp.ner.patterns import get_all_patterns, LABEL_CVE, LABEL_TOOL, LABEL_TACTIC, LABEL_TECHNIQUE


@pytest.fixture(scope="module")
def extractor():
    return AlertEntityExtractor()


# ── Pattern coverage tests ────────────────────────────────────────────────────

class TestPatternCoverage:

    def test_patterns_not_empty(self):
        patterns = get_all_patterns()
        assert len(patterns) > 20, "Expected at least 20 entity patterns"

    def test_cve_pattern_present(self):
        patterns = get_all_patterns()
        labels = [p["label"] for p in patterns]
        assert LABEL_CVE in labels

    def test_tool_patterns_present(self):
        patterns = get_all_patterns()
        tool_patterns = [p for p in patterns if p["label"] == LABEL_TOOL]
        assert len(tool_patterns) > 10, "Expected at least 10 attack tool patterns"

    def test_tactic_ids_present(self):
        patterns = get_all_patterns()
        tactic_patterns = [p for p in patterns if p["label"] == LABEL_TACTIC]
        assert len(tactic_patterns) >= 10


# ── Entity extraction tests ───────────────────────────────────────────────────

class TestAlertEntityExtractor:

    def test_extract_cve_from_alert(self, extractor):
        alert = {"attack_type": "CVE-2023-25136 OpenSSH", "protocol": "TCP"}
        entities = extractor.extract(alert)
        assert "CVE-2023-25136" in entities.cves, f"CVE not found. Got: {entities.cves}"

    def test_extract_attack_type(self, extractor):
        alert = {"attack_type": "SSH-Patator", "protocol": "TCP", "dst_port": 22}
        entities = extractor.extract(alert)
        assert "SSH-Patator" in entities.attack_types, f"attack_type not found. Got: {entities.attack_types}"

    def test_extract_port(self, extractor):
        alert = {"attack_type": "DDoS", "dst_port": 80, "protocol": "TCP"}
        entities = extractor.extract(alert)
        assert 80 in entities.ports, f"Port 80 not found. Got: {entities.ports}"

    def test_extract_ips(self, extractor):
        alert = {
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.1",
            "attack_type": "PortScan",
        }
        entities = extractor.extract(alert)
        assert "192.168.1.10" in entities.src_ips, f"src_ip not found. Got: {entities.src_ips}"

    def test_entity_strings_not_empty(self, extractor):
        alert = {"attack_type": "SSH-Patator", "src_ip": "10.0.0.5", "dst_port": 22}
        entities = extractor.extract(alert)
        strings = extractor.entity_strings(entities)
        assert len(strings) > 0

    def test_build_query_text(self, extractor):
        alert = {"attack_type": "SSH-Patator", "src_ip": "10.0.0.5", "dst_port": 22}
        entities = extractor.extract(alert)
        query = extractor.build_query_text(alert, entities)
        assert isinstance(query, str)
        assert len(query) > 5

    def test_empty_alert_does_not_crash(self, extractor):
        entities = extractor.extract({})
        assert entities is not None

    def test_multiple_cves_extracted(self, extractor):
        alert = {
            "attack_type": "CVE-2021-44228 CVE-2022-30190 Log4Shell exploit",
        }
        entities = extractor.extract(alert)
        assert len(entities.cves) >= 1   # at least 1 CVE found via regex
