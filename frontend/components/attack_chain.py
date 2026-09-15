"""
frontend/components/attack_chain.py
Plotly timeline for TKCI attack chain with KCV annotation.

Visualises the ordered kill-chain phases for a session as a horizontal
timeline with colour-coded tactic blocks and a KCV banner.
"""

from datetime import datetime
from typing import Optional

import plotly.graph_objects as go
import streamlit as st

# MITRE tactic colour palette (reconnaissance → impact)
TACTIC_COLORS: dict[str, str] = {
    "TA0043": "#6366f1",   # Reconnaissance        — indigo
    "TA0042": "#8b5cf6",   # Resource Development  — violet
    "TA0001": "#ec4899",   # Initial Access        — pink
    "TA0002": "#f43f5e",   # Execution             — rose
    "TA0003": "#f97316",   # Persistence           — orange
    "TA0004": "#eab308",   # Privilege Escalation  — yellow
    "TA0005": "#84cc16",   # Defense Evasion       — lime
    "TA0006": "#22c55e",   # Credential Access     — green
    "TA0007": "#14b8a6",   # Discovery             — teal
    "TA0008": "#06b6d4",   # Lateral Movement      — cyan
    "TA0009": "#3b82f6",   # Collection            — blue
    "TA0011": "#a855f7",   # Command and Control   — purple
    "TA0010": "#f59e0b",   # Exfiltration          — amber
    "TA0040": "#ef4444",   # Impact                — red
}
DEFAULT_COLOR = "#6b7280"  # grey for unknown tactics


def render_attack_chain(
    session_id:     str,
    ordered_tactics: list[str],
    chain_labels:   list[str],
    kcv:            float,
    severity_index: float,
    time_start:     Optional[str] = None,
    time_end:       Optional[str] = None,
    key:            str = "chain",
) -> None:
    """
    Render the TKCI kill-chain timeline in Streamlit.

    Args:
        session_id:      e.g. "session-00"
        ordered_tactics: ["TA0043", "TA0006", "TA0010"]
        chain_labels:    ["Reconnaissance", "Credential Access", "Exfiltration"]
        kcv:             Kill Chain Velocity (phases/hour)
        severity_index:  0–100
        time_start/end:  ISO 8601 strings (optional)
        key:             Unique Streamlit key prefix
    """
    if not ordered_tactics:
        st.info("No kill chain phases identified for this session.")
        return

    kcv_label = _kcv_label(kcv)
    kcv_color = "#ef4444" if kcv > 5 else "#eab308" if kcv > 2 else "#22c55e"

    # ── Header row ────────────────────────────────────────────────────────────
    col1, col2, col3 = st.columns([3, 1, 1])
    col1.markdown(f"**{session_id.upper()}** — Kill Chain Timeline")
    col2.markdown(
        f"<span style='color:{kcv_color};font-weight:700'>"
        f"KCV: {kcv:.2f} ph/hr</span><br>"
        f"<span style='color:#9ca3af;font-size:11px'>{kcv_label}</span>",
        unsafe_allow_html=True,
    )
    col3.markdown(
        f"<span style='color:#e5e7eb;font-size:13px'>SI: "
        f"<b style='color:{_si_color(severity_index)}'>{severity_index:.0f}</b>/100</span>",
        unsafe_allow_html=True,
    )

    # ── Plotly chain timeline ─────────────────────────────────────────────────
    n = len(ordered_tactics)
    fig = go.Figure()

    for i, (tactic, label) in enumerate(zip(ordered_tactics, chain_labels)):
        color = TACTIC_COLORS.get(tactic, DEFAULT_COLOR)

        # Block bar
        fig.add_trace(go.Bar(
            x=[1],
            y=[label],
            orientation="h",
            marker_color=color,
            marker_line=dict(color="#111827", width=1),
            hovertemplate=(
                f"<b>{label}</b><br>"
                f"ID: {tactic}<br>"
                f"Phase {i+1} of {n}<extra></extra>"
            ),
            name=label,
            showlegend=False,
        ))

    # Arrow connectors between phases using shapes
    shapes = []
    for i in range(n - 1):
        shapes.append(dict(
            type="line",
            x0=1.02, y0=i, x1=1.02, y1=i + 1,
            line=dict(color="#4b5563", width=2, dash="dot"),
            xref="x", yref="y",
        ))

    fig.update_layout(
        paper_bgcolor="#111827",
        plot_bgcolor="#1f2937",
        barmode="stack",
        xaxis=dict(visible=False, range=[0, 1.1]),
        yaxis=dict(
            autorange="reversed",
            tickfont=dict(color="#e5e7eb", size=12),
            gridcolor="#374151",
        ),
        font=dict(color="#e5e7eb", family="Inter, sans-serif"),
        margin=dict(l=10, r=10, t=30, b=10),
        height=max(120, n * 42),
        shapes=shapes,
        title=dict(
            text=(
                f"📡 Attack Chain — {n} phases"
                + (f" | {time_start[:10]} → {time_end[:10]}" if time_start and time_end else "")
            ),
            font=dict(size=13, color="#9ca3af"),
        ),
    )

    st.plotly_chart(fig, use_container_width=True, key=f"{key}_chain")


def render_chain_badge_row(ordered_tactics: list[str], chain_labels: list[str]) -> None:
    """
    Compact inline badge row for attack phases.
    Useful in tables and summaries.
    """
    badges = []
    for tactic, label in zip(ordered_tactics, chain_labels):
        color = TACTIC_COLORS.get(tactic, DEFAULT_COLOR)
        badges.append(
            f"<span style='background:{color};color:white;padding:2px 8px;"
            f"border-radius:10px;font-size:11px;margin:2px;display:inline-block'>"
            f"{label}</span>"
        )
    st.markdown("&nbsp;→&nbsp;".join(badges), unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _kcv_label(kcv: float) -> str:
    if kcv > 5:
        return "Automated / Scripted"
    elif kcv > 2:
        return "Semi-Automated"
    return "Manual / APT-Patterned"


def _si_color(si: float) -> str:
    if si < 30:   return "#22c55e"
    if si < 60:   return "#eab308"
    if si < 85:   return "#f97316"
    return "#ef4444"
