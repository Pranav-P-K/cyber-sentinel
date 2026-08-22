"""
nlp/ner/entity_extractor.py
Surface NLP layer — extracts typed entities from raw IDS alert dicts.

The entity_strings() output is used by the CGAR HRSS computation to calculate
Semantic Coverage Score (what fraction of alert entities appear in retrieved docs).
"""

import re
from dataclasses import dataclass, field

import spacy


@dataclass
class AlertEntities:
    src_ips:      list[str] = field(default_factory=list)
    dst_ips:      list[str] = field(default_factory=list)
    ports:        list[int] = field(default_factory=list)
    protocols:    list[str] = field(default_factory=list)
    attack_types: list[str] = field(default_factory=list)
    cves:         list[str] = field(default_factory=list)
    timestamps:   list[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"AlertEntities("
            f"src_ips={self.src_ips}, dst_ips={self.dst_ips}, "
            f"ports={self.ports}, protocols={self.protocols}, "
            f"attack_types={self.attack_types}, cves={self.cves})"
        )


class AlertEntityExtractor:
    """
    Extracts structured entities from a CyberSentinel alert dict.

    Regex patterns handle the structured fields (IP, CVE, port) which spaCy's
    general NER model misses. spaCy is reserved for free-text enrichment when
    additional context is appended to alerts in later pipeline stages.
    """

    IP_RE  = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
    CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    PORT_RE = re.compile(r"\b(\d{1,5})\b")

    def __init__(self, spacy_model: str = "en_core_web_sm"):
        try:
            self.nlp = spacy.load(spacy_model)
        except OSError:
            # Graceful fallback — model not yet installed
            self.nlp = None

    def extract(self, alert: dict) -> AlertEntities:
        """
        Extract entities from a single alert dict.
        Primary source is the structured fields; regex also scans the
        serialised dict for any embedded CVE references in string values.
        """
        alert_str = str(alert)

        # IPs: prefer structured fields, also scan full text
        src_ips = list({alert.get("src_ip", "")}.union(set(self.IP_RE.findall(alert_str))))
        src_ips = [ip for ip in src_ips if ip and ip != "0.0.0.0"]

        # Only keep the known dst_ip from structured field (avoids scanning embedded IPs)
        dst_ip = alert.get("dst_ip", "")
        dst_ips = [dst_ip] if dst_ip and dst_ip != "0.0.0.0" else []

        # Port
        port = alert.get("dst_port", 0)
        ports = [int(port)] if port else []

        # Protocol
        proto = alert.get("protocol", "TCP")
        protocols = [str(proto)] if proto else ["TCP"]

        # Attack type
        at = alert.get("attack_type", "")
        attack_types = [at] if at and at != "Unknown" else []

        # CVEs in any string value in the alert
        cves = list(set(self.CVE_RE.findall(alert_str)))

        # Timestamp
        ts = alert.get("timestamp", "")
        timestamps = [str(ts)] if ts else []

        return AlertEntities(
            src_ips=src_ips,
            dst_ips=dst_ips,
            ports=ports,
            protocols=protocols,
            attack_types=attack_types,
            cves=cves,
            timestamps=timestamps,
        )

    def extract_batch(self, alerts: list[dict]) -> list[AlertEntities]:
        """Extract entities from a list of alerts."""
        return [self.extract(a) for a in alerts]

    def entity_strings(self, entities: AlertEntities) -> list[str]:
        """
        Returns a flat list of entity strings used by CGAR HRSS to compute
        Semantic Coverage Score:
            c_semantic = |entity_strings found in retrieved docs| / |entity_strings|

        We include: IPs, attack type keywords, CVEs.
        Ports and timestamps are excluded (too noisy for semantic matching).
        """
        strings: list[str] = []
        strings.extend(ip for ip in entities.src_ips if ip)
        strings.extend(ip for ip in entities.dst_ips if ip)
        strings.extend(entities.attack_types)
        strings.extend(entities.cves)
        return strings

    def build_query_text(self, alert: dict, entities: AlertEntities) -> str:
        """
        Construct the first-round CGAR query string from a single alert.
        Used by the RAG engine as the initial ChromaDB query.
        """
        attack = entities.attack_types[0] if entities.attack_types else "network attack"
        proto  = entities.protocols[0] if entities.protocols else "TCP"
        port   = f"port {entities.ports[0]}" if entities.ports else ""
        cves   = " ".join(entities.cves)

        parts  = [attack, proto, port, cves]
        return " ".join(p for p in parts if p).strip()


# ── Quick smoke test ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    extractor = AlertEntityExtractor()

    sample_alerts = [
        {
            "alert_id": "test-001",
            "timestamp": "2017-07-04T09:00:00",
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "dst_port": 22,
            "protocol": "TCP",
            "attack_type": "SSH-Patator",
            "flow_bytes_per_sec": 4200.5,
            "packet_count": 450,
        },
        {
            "alert_id": "test-002",
            "timestamp": "2017-07-05T10:00:00",
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.0",
            "dst_port": 0,
            "protocol": "TCP",
            "attack_type": "PortScan",
            "flow_bytes_per_sec": 12000.0,
            "packet_count": 1100,
        },
        {
            "alert_id": "test-003",
            "timestamp": "2017-07-07T14:00:00",
            "src_ip": "192.168.100.4",
            "dst_ip": "192.168.1.25",
            "dst_port": 80,
            "protocol": "TCP",
            "attack_type": "DDoS",
            "note": "Related to CVE-2021-44228",
        },
    ]

    print("AlertEntityExtractor — Smoke Test")
    print("=" * 60)
    for alert in sample_alerts:
        ents  = extractor.extract(alert)
        query = extractor.build_query_text(alert, ents)
        estrs = extractor.entity_strings(ents)
        print(f"\nAlert: {alert['alert_id']}")
        print(f"  Entities : {ents}")
        print(f"  Query    : {query!r}")
        print(f"  E-strings: {estrs}")
