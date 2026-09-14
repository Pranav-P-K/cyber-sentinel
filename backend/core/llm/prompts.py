"""
backend/core/llm/prompts.py
All prompt templates for the CyberSentinel pipeline.

  CONFIDENCE_PROMPT      → CGAR Round 1: LLM self-reports retrieval confidence
  CHAIN_NARRATIVE_PROMPT → TKCI: generates grounded incident narrative
  CLAIM_EXTRACTION_PROMPT→ PFGL: extracts atomic verifiable claims
  QUERY_REFINEMENT_PROMPT→ CGAR Round 2: refines query using entity context
"""

# ── CGAR: Round 1 confidence assessment ──────────────────────────────────────

CONFIDENCE_SYSTEM = """You are a cybersecurity threat intelligence expert.
You are given an IDS alert and a set of retrieved knowledge base documents.
Your task is to assess how well the retrieved documents cover the alert.
Be concise and precise."""

CONFIDENCE_PROMPT = """
Alert:
{alert_text}

Retrieved Documents:
{context}

Rate the quality of the retrieved context for answering this alert on a scale of 0.0 to 1.0:
- 1.0: Documents directly address the attack type, technique, or CVEs mentioned
- 0.7: Documents are partially relevant — cover the tactic but not the specific technique
- 0.4: Documents are tangentially related
- 0.0: Documents are irrelevant to this alert

Respond ONLY with valid JSON:
{{
  "score": <float 0.0-1.0>,
  "reason": "<one sentence explaining the score>",
  "missing": "<what key information is absent from the retrieved docs>"
}}
"""

# ── TKCI: Grounded incident narrative generation ──────────────────────────────

CHAIN_NARRATIVE_SYSTEM = """You are a senior threat intelligence analyst at a Security Operations Center.
Your job is to write clear, grounded, actionable incident narratives for security teams.
CRITICAL RULE: Only cite CVEs, TTPs, and threat actor names that explicitly appear in the provided context.
Do not invent or hallucinate any security identifiers."""

CHAIN_NARRATIVE_PROMPT = """
ATTACK SESSION SUMMARY
======================
Attacker IPs: {attacker_ips}
Time Window: {time_window}
Kill Chain (MITRE ATT&CK, chronological): {kill_chain}
Kill Chain Velocity: {kcv:.2f} phases/hour — {kcv_label}
Severity Index: {severity_index:.1f}/100

THREAT INTELLIGENCE CONTEXT (from verified knowledge base)
==========================================================
{context}

ALERT DETAILS
=============
{alert_details}

Write a grounded incident narrative with exactly 3 paragraphs:
1. ATTACK PROGRESSION: What happened, in chronological order, mapped to the kill chain above.
2. ACTOR PROFILE: Likely threat actor characteristics based on TTPs and timing.
3. RECOMMENDED RESPONSE: Specific containment and remediation steps.

Rules:
- Only cite CVEs and TTPs that appear in the THREAT INTELLIGENCE CONTEXT above.
- Use MITRE tactic/technique IDs (e.g., T1110.001) when referencing techniques.
- Be specific — include IP addresses, ports, and timestamps from ALERT DETAILS.
- Do NOT say "based on the context" or "according to documents". Write as a professional analyst.
"""

# ── PFGL: Atomic claim extraction for verification ────────────────────────────

CLAIM_EXTRACTION_SYSTEM = """You are a fact-checker for cybersecurity incident reports.
Extract all verifiable factual claims from the given narrative.
Focus on: CVE IDs, MITRE technique IDs, IP addresses, threat actor names, attack tools."""

CLAIM_EXTRACTION_PROMPT = """
Incident Narrative:
{narrative}

Extract all verifiable claims into the following JSON format:
{{
  "claims": [
    {{
      "text": "<exact quote from narrative>",
      "type": "<cve|ttp|ip|actor|tool|other>",
      "identifier": "<CVE-XXXX-XXXX or TXXXX.XXX or IP or name>",
      "verifiable": <true|false>
    }}
  ]
}}

Only include claims that can be checked against a security knowledge base.
Respond ONLY with valid JSON.
"""

# ── CGAR: Round 2 query refinement ───────────────────────────────────────────

QUERY_REFINEMENT_SYSTEM = """You are a cybersecurity search query expert.
Given an alert and why the first retrieval failed, generate a better search query."""

QUERY_REFINEMENT_PROMPT = """
Original Alert: {alert_text}

First Retrieval Failure Reason: {missing}

Extracted Entities:
- Attack type: {attack_type}
- Source IP: {src_ip}
- Destination port: {dst_port}
- Protocol: {protocol}
- CVEs mentioned: {cves}

Generate an improved search query (1-2 sentences) that will retrieve more specific
MITRE ATT&CK techniques or CVEs relevant to this attack.

Respond ONLY with the query string, no explanation.
"""

# ── Confidence thresholds (mirrors .env defaults) ─────────────────────────────
CONFIDENCE_THRESHOLD = 0.70    # below this → trigger Round 2
HIGH_CONFIDENCE      = 0.85    # above this → skip Round 2 entirely
