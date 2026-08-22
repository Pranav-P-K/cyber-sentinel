"""
frontend/app.py
CyberSentinel — Streamlit dashboard skeleton.
Each page is a placeholder that will be fleshed out as pipeline
layers (CGAR, TKCI, PFGL) are implemented.
"""

import streamlit as st

st.set_page_config(
    page_title="CyberSentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Sidebar navigation ────────────────────────────────────────────────────────
st.sidebar.image(
    "https://img.shields.io/badge/CyberSentinel-v0.1-blue?style=for-the-badge",
    use_column_width=True,
)
st.sidebar.title("🛡️ CyberSentinel")
st.sidebar.caption("Explainable IDS Alert Triage")
st.sidebar.divider()

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Dashboard",
        "📥 Upload Alerts",
        "🔗 Kill Chain Viewer",
        "✅ Trust Score Report",
        "⚙️ Settings",
    ],
)

st.sidebar.divider()
st.sidebar.info(
    "**Status** · Day 1 Skeleton\n\n"
    "Pipeline layers will be connected here as each module is implemented."
)

# ── Pages ─────────────────────────────────────────────────────────────────────

if page == "🏠 Dashboard":
    st.title("🛡️ CyberSentinel — Threat Intelligence Dashboard")
    st.caption("Confidence-Guided Adaptive Retrieval · Temporal Kill Chain Inference · Hallucination Verification")
    st.divider()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Alerts Processed",      "—", help="Total IDS alerts ingested this session")
    col2.metric("Attack Sessions Found", "—", help="Distinct attacker sessions identified by DBASC")
    col3.metric("Avg. Trust Score",      "—", help="Mean Weighted Trust Score (WTS) across all reports")
    col4.metric("Hallucination Rate",    "—", help="Fraction of claims flagged as unverifiable or contradicted")

    st.divider()
    st.info(
        "⏳ **Pipeline not yet connected.** "
        "Upload alerts on the '📥 Upload Alerts' page once the backend is running."
    )

elif page == "📥 Upload Alerts":
    st.title("📥 Upload IDS Alerts")
    st.caption("Upload a JSON file of IDS alerts or paste raw alert records")
    st.divider()

    upload_method = st.radio("Input method", ["Upload JSON file", "Paste JSON text"], horizontal=True)

    if upload_method == "Upload JSON file":
        uploaded = st.file_uploader("Choose an alert JSON file", type=["json"])
        if uploaded:
            st.success(f"File received: **{uploaded.name}** ({uploaded.size / 1024:.1f} KB)")
            st.info("🔧 Backend pipeline not yet connected — processing will be enabled in Day 3.")
    else:
        raw = st.text_area("Paste alert JSON array here", height=250, placeholder='[{"alert_id": "...", ...}]')
        if st.button("Submit Alerts") and raw.strip():
            st.info("🔧 Backend pipeline not yet connected — processing will be enabled in Day 3.")

elif page == "🔗 Kill Chain Viewer":
    st.title("🔗 Attack Kill Chain Viewer")
    st.caption("Visualises the reconstructed MITRE ATT&CK kill chain per attacker session")
    st.divider()
    st.info("🔧 TKCI module not yet implemented — available from Day 5 onwards.")

    # Preview of the expected output format
    st.subheader("Expected Output (Preview)")
    st.code(
        """
Session: 10.0.0.5  |  Kill Chain Velocity: 5.1 phases/hr  |  Severity: 78/100
─────────────────────────────────────────────────────────────────────────────
[TA0043] Reconnaissance → [TA0006] Credential Access →
[TA0001] Initial Access → [TA0010] Exfiltration
        """,
        language="text",
    )

elif page == "✅ Trust Score Report":
    st.title("✅ Factual Verification Report")
    st.caption("Per-claim verification results and Weighted Trust Score (WTS)")
    st.divider()
    st.info("🔧 PFGL module not yet implemented — available from Day 6 onwards.")

    st.subheader("Expected Output (Preview)")
    st.code(
        """
Claim                    Type   Status          Weight
─────────────────────────────────────────────────────
CVE-2021-44228           CVE    ✅ Verified      1.5
T1110 (Brute Force)      TTP    ✅ Verified      1.3
APT28 attributed         Actor  ⚠️ Unverifiable  0.7
─────────────────────────────────────────────────────
Weighted Trust Score:  76 / 100
        """,
        language="text",
    )

elif page == "⚙️ Settings":
    st.title("⚙️ Settings")
    st.divider()

    import os, requests

    backend_url = os.environ.get("BACKEND_URL", "http://localhost:8000")

    with st.expander("Backend Connection", expanded=True):
        st.text_input("Backend URL", value=backend_url, disabled=True)
        if st.button("Test /health"):
            try:
                resp = requests.get(f"{backend_url}/health", timeout=5)
                if resp.ok:
                    st.success("Backend is reachable!")
                    st.json(resp.json())
                else:
                    st.error(f"Backend returned HTTP {resp.status_code}")
            except Exception as e:
                st.error(f"Cannot reach backend: {e}")

    with st.expander("Pipeline Configuration (read-only — edit .env to change)"):
        st.code(
            f"""
OLLAMA_BASE_URL  = {os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434')}
LLM_MODEL        = {os.environ.get('LLM_MODEL', 'llama3')}
EMBEDDING_MODEL  = {os.environ.get('EMBEDDING_MODEL', 'all-MiniLM-L6-v2')}
CONFIDENCE_THRESHOLD = {os.environ.get('CONFIDENCE_THRESHOLD', '0.70')}
MAX_RETRIEVAL_ROUNDS = {os.environ.get('MAX_RETRIEVAL_ROUNDS', '2')}
            """,
            language="bash",
        )
