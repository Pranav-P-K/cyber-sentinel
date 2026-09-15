"""
frontend/pages/dashboard.py
CyberSentinel — Main analysis dashboard page.

Flow:
  1. User enters/pastes IDS alerts (via alert_input.py component)
  2. POST /api/v1/analyze
  3. Render per-session: attack chain timeline + SI gauge + narrative + metadata
"""

import json
import streamlit as st

from frontend.components.alert_input import render_alert_input
from frontend.components.attack_chain import render_attack_chain, render_chain_badge_row
from frontend.components.severity_gauge import render_severity_gauge
from frontend.utils.api_client import sync_analyze, sync_health, BACKEND_URL as DEFAULT_BACKEND_URL



# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="CyberSentinel — SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #0f172a;
    color: #e2e8f0;
}
.stApp { background-color: #0f172a; }
.metric-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 16px 20px;
    margin: 8px 0;
}
.session-header {
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 16px;
    margin: 16px 0;
}
.narrative-box {
    background: #1e293b;
    border-left: 4px solid #6366f1;
    border-radius: 0 8px 8px 0;
    padding: 16px;
    margin: 12px 0;
    font-size: 14px;
    line-height: 1.7;
    color: #cbd5e1;
}
.stMetric label { color: #94a3b8 !important; }
.stMetric [data-testid="metric-container"] > div:first-child { font-size: 13px; }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.image("https://via.placeholder.com/180x50/6366f1/FFFFFF?text=CyberSentinel", width=180)
    st.markdown("---")
    api_url = st.text_input(
        "Backend URL",
        value=DEFAULT_BACKEND_URL,
        help="FastAPI backend URL",
    )
    st.markdown("---")
    st.markdown("**About**")
    st.markdown(
        "CyberSentinel uses **CGAR** + **TKCI** + **PFGL** novelties "
        "to turn raw IDS alerts into grounded, MITRE ATT&CK-mapped incident narratives.",
        unsafe_allow_html=False,
    )
    st.markdown("---")
    st.markdown(
        "<small style='color:#64748b'>v0.1.0 · CICIDS 2017 · 22K+ KB docs</small>",
        unsafe_allow_html=True,
    )


# ── Main content ──────────────────────────────────────────────────────────────

st.markdown("## 🛡️ CyberSentinel SOC Copilot")
st.markdown(
    "<p style='color:#94a3b8;margin-top:-8px'>Explainable threat analysis with MITRE ATT&CK mapping</p>",
    unsafe_allow_html=True,
)
st.markdown("---")


# ── Alert input ───────────────────────────────────────────────────────────────

with st.container():
    alerts, submitted = render_alert_input()


# ── Analysis ─────────────────────────────────────────────────────────────────

if submitted and alerts:

    with st.spinner("🔍 Analysing alerts — CGAR retrieval + TKCI clustering + LLM narrative…"):
        try:
            import os
            os.environ["BACKEND_URL"] = api_url
            response = sync_analyze(alerts)
        except Exception as exc:
            st.error(f"❌ Backend error: {exc}")
            st.stop()

    if "error" in response:
        st.error(f"API error: {response['error']}")
        st.stop()

    # ── Summary metrics bar ───────────────────────────────────────────────────
    st.markdown("---")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Alerts",   response.get("total_alerts", 0))
    m2.metric("Attack Sessions", response.get("session_count", 0))
    m3.metric("Noise Alerts",   response.get("noise_alerts", 0))
    m4.metric("Processing",     f"{response.get('processing_ms', 0)} ms")

    sessions = response.get("sessions", [])
    if not sessions:
        st.info("No attack sessions detected. Alerts may be noise or too sparse to cluster.")
        st.stop()

    # ── Per-session panels ────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 🔥 Attack Sessions")

    for i, session in enumerate(sessions):
        si  = session.get("severity_index", 0.0)
        kcv = session.get("kcv", 0.0)

        with st.expander(
            f"**{session['session_id'].upper()}** — "
            f"SI: {si:.0f}/100 · {session['alert_count']} alerts · "
            f"{', '.join(session['attacker_ips'][:2]) or 'Unknown IPs'}",
            expanded=(i == 0),
        ):
            left, right = st.columns([1, 1])

            # Left: SI gauge + KCV metric
            with left:
                render_severity_gauge(
                    si=si,
                    kcv=kcv,
                    session_id=session["session_id"],
                    key=f"gauge_{i}",
                )
                c1, c2 = st.columns(2)
                c1.metric("Attacker IPs",  ", ".join(session["attacker_ips"][:2]) or "—")
                c2.metric("Victim IPs",    ", ".join(session["victim_ips"][:2]) or "—")
                c1.metric("CGAR HRSS",     f"{session.get('hrss', 0):.3f}")
                c2.metric("Round 2",       "✓ Triggered" if session.get("round2_triggered") else "✗ Not needed")

            # Right: Attack chain timeline
            with right:
                render_attack_chain(
                    session_id=session["session_id"],
                    ordered_tactics=session.get("ordered_chain", []),
                    chain_labels=session.get("chain_labels", []),
                    kcv=kcv,
                    severity_index=si,
                    time_start=session.get("time_start"),
                    time_end=session.get("time_end"),
                    key=f"chain_{i}",
                )

            # Narrative
            st.markdown("#### 📝 Incident Narrative")
            narrative = session.get("narrative", "Narrative unavailable.")
            st.markdown(
                f"<div class='narrative-box'>{narrative.replace(chr(10), '<br>')}</div>",
                unsafe_allow_html=True,
            )

            # Raw JSON toggle
            with st.expander("🔧 Raw session JSON", expanded=False):
                st.json(session)

    # ── Download report ───────────────────────────────────────────────────────
    st.markdown("---")
    st.download_button(
        label="⬇️ Download Full Report (JSON)",
        data=json.dumps(response, indent=2),
        file_name=f"cybersentinel_{response.get('analysis_id', 'report')}.json",
        mime="application/json",
    )

elif not submitted:
    # Landing state
    st.markdown("""
    <div style='text-align:center;padding:60px 20px;'>
        <div style='font-size:64px'>🛡️</div>
        <h3 style='color:#e2e8f0;margin:12px 0'>Paste IDS alerts to begin</h3>
        <p style='color:#64748b'>
            Supports JSON arrays or CSV rows from CICIDS 2017, Suricata, Zeek, or custom formats.
        </p>
    </div>
    """, unsafe_allow_html=True)
