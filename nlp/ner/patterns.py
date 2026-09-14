"""
nlp/ner/patterns.py
spaCy EntityRuler patterns for cybersecurity-specific entities.

These patterns extend spaCy's default NER with domain-specific rules for:
  - CVE identifiers
  - Port numbers in context
  - Known attack tool names (from CICIDS dataset)
  - MITRE tactic/technique IDs
  - Common vulnerability keywords

Usage:
    from nlp.ner.patterns import add_patterns_to_nlp
    nlp = spacy.load("en_core_web_sm")
    nlp = add_patterns_to_nlp(nlp)
"""

import spacy
from spacy.language import Language


# ── Entity label constants ────────────────────────────────────────────────────
LABEL_CVE       = "CVE_ID"
LABEL_TOOL      = "ATTACK_TOOL"
LABEL_TACTIC    = "MITRE_TACTIC"
LABEL_TECHNIQUE = "MITRE_TECHNIQUE"
LABEL_PORT      = "NETWORK_PORT"
LABEL_PROTOCOL  = "PROTOCOL"


def _build_patterns() -> list[dict]:
    """Return all EntityRuler patterns."""
    patterns: list[dict] = []

    # ── CVE IDs ───────────────────────────────────────────────────────────────
    # Pattern: CVE-YYYY-NNNNN (4-7 digit ID)
    patterns.append({
        "label": LABEL_CVE,
        "pattern": [
            {"TEXT": {"REGEX": r"CVE-\d{4}-\d{4,7}"}},
        ],
    })

    # ── Known attack tools from CICIDS 2017 ───────────────────────────────────
    cicids_tools = [
        "SSH-Patator", "FTP-Patator", "Patator",
        "Slowloris", "Slowhttptest", "GoldenEye", "Hulk", "RUDY",
        "LOIC", "HOIC",
        "Ares", "Infiltration",
        "nmap", "Nmap", "Masscan",
        "Metasploit", "msfvenom",
        "Hydra", "Medusa", "THC-Hydra",
        "sqlmap", "SQLmap",
        "XSStrike", "BeEF",
    ]
    for tool in cicids_tools:
        patterns.append({
            "label": LABEL_TOOL,
            "pattern": tool,
        })

    # ── MITRE Tactic IDs (TA0001–TA0043) ─────────────────────────────────────
    tactic_ids = [
        "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
        "TA0006", "TA0007", "TA0008", "TA0009", "TA0010",
        "TA0011", "TA0040", "TA0042", "TA0043",
    ]
    for tid in tactic_ids:
        patterns.append({"label": LABEL_TACTIC, "pattern": tid})

    # ── MITRE Technique IDs (Txxxx or Txxxx.xxx) ─────────────────────────────
    patterns.append({
        "label": LABEL_TECHNIQUE,
        "pattern": [
            {"TEXT": {"REGEX": r"T\d{4}(?:\.\d{3})?"}},
        ],
    })

    # ── Well-known vulnerable ports (as standalone tokens) ───────────────────
    vuln_ports = {
        "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
        "53": "DNS", "80": "HTTP", "443": "HTTPS", "445": "SMB",
        "3389": "RDP", "8080": "HTTP-Alt", "3306": "MySQL",
        "1433": "MSSQL", "5432": "PostgreSQL", "6379": "Redis",
    }
    for port_num in vuln_ports:
        patterns.append({
            "label": LABEL_PORT,
            "pattern": [
                {"LOWER": "port"},
                {"TEXT": port_num},
            ],
        })

    # ── Network protocols ─────────────────────────────────────────────────────
    for proto in ["TCP", "UDP", "ICMP", "HOPOPT", "HTTP", "HTTPS", "FTP", "SSH", "SMB", "DNS", "RDP"]:
        patterns.append({"label": LABEL_PROTOCOL, "pattern": proto})

    return patterns


def add_patterns_to_nlp(nlp: Language) -> Language:
    """
    Add the CyberSentinel EntityRuler to a spaCy pipeline.
    The ruler runs before the default NER to set high-priority domain rules.
    """
    if "entity_ruler" not in nlp.pipe_names:
        ruler = nlp.add_pipe("entity_ruler", before="ner")
    else:
        ruler = nlp.get_pipe("entity_ruler")

    ruler.add_patterns(_build_patterns())
    return nlp


def get_all_patterns() -> list[dict]:
    """Return patterns for inspection or testing."""
    return _build_patterns()
