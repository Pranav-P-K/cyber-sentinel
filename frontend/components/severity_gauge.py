"""
frontend/components/severity_gauge.py
Plotly gauge chart for displaying the Severity Index (0–100).

Colour bands:
  0–30   → green   (Low)
  30–60  → yellow  (Medium)
  60–85  → orange  (High)
  85–100 → red     (Critical)
"""

import plotly.graph_objects as go
import streamlit as st


def severity_band_label(si: float) -> tuple[str, str]:
    """Returns (band_label, color_hex) for a given SI value."""
    if si < 30:
        return "LOW", "#22c55e"
    elif si < 60:
        return "MEDIUM", "#eab308"
    elif si < 85:
        return "HIGH", "#f97316"
    else:
        return "CRITICAL", "#ef4444"


def render_severity_gauge(
    si: float,
    wts: float | None = None,
    kcv: float | None = None,
    session_id: str = "Session",
    key: str = "gauge",
) -> None:
    """
    Render a full Plotly gauge + optional WTS/KCV sub-metrics in Streamlit.

    Args:
        si:         Severity Index (0–100)
        wts:        Weighted Trust Score (0.0–1.0, shown as %)
        kcv:        Kill Chain Velocity (phases/hour)
        session_id: Label shown above the gauge
        key:        Unique Streamlit key
    """
    band_label, band_color = severity_band_label(si)

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=si,
        number={
            "suffix": "",
            "font": {"size": 36, "color": band_color},
        },
        title={
            "text": f"<b>{session_id}</b><br><span style='color:{band_color};font-size:14px'>{band_label}</span>",
            "font": {"size": 16},
        },
        gauge={
            "axis": {
                "range": [0, 100],
                "tickwidth": 1,
                "tickcolor": "#374151",
                "tickvals": [0, 30, 60, 85, 100],
                "ticktext": ["0", "30", "60", "85", "100"],
            },
            "bar": {"color": band_color, "thickness": 0.25},
            "bgcolor": "#1f2937",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 30],   "color": "#14532d"},   # dark green
                {"range": [30, 60],  "color": "#713f12"},   # dark yellow
                {"range": [60, 85],  "color": "#7c2d12"},   # dark orange
                {"range": [85, 100], "color": "#450a0a"},   # dark red
            ],
            "threshold": {
                "line": {"color": "#ffffff", "width": 3},
                "thickness": 0.8,
                "value": si,
            },
        },
    ))

    fig.update_layout(
        paper_bgcolor="#111827",
        font={"color": "#e5e7eb", "family": "Inter, sans-serif"},
        height=280,
        margin={"l": 20, "r": 20, "t": 60, "b": 20},
    )

    st.plotly_chart(fig, use_container_width=True, key=f"{key}_gauge")

    # Sub-metrics row
    if wts is not None or kcv is not None:
        cols = st.columns(2)
        if wts is not None:
            wts_pct = wts * 100
            wts_color = "#22c55e" if wts >= 0.85 else "#eab308" if wts >= 0.70 else "#ef4444"
            cols[0].metric(
                label="Weighted Trust Score",
                value=f"{wts_pct:.1f}%",
                delta=None,
                help="PFGL claim verification score. >85% = high trust.",
            )
        if kcv is not None:
            kcv_label = "Scripted/Automated" if kcv > 5 else "Manual/APT"
            cols[1].metric(
                label="Kill Chain Velocity",
                value=f"{kcv:.2f} ph/hr",
                delta=kcv_label,
                help="Phases per hour. High KCV = fast scripted attack.",
            )


def render_severity_badge(si: float) -> None:
    """
    Compact inline severity badge (no gauge) for use in alert tables.
    """
    band_label, band_color = severity_band_label(si)
    st.markdown(
        f"<span style='background:{band_color};color:white;padding:2px 10px;"
        f"border-radius:12px;font-weight:700;font-size:13px'>{band_label} {si:.0f}</span>",
        unsafe_allow_html=True,
    )
