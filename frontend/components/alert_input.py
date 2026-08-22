"""
frontend/components/alert_input.py
Streamlit widget for JSON alert input — file upload or paste.

Returns a list of alert dicts or None if nothing is provided yet.
"""

import json
import streamlit as st


def render_alert_input() -> list[dict] | None:
    """
    Renders the alert input widget.
    Returns a list of alert dicts if valid input is provided, else None.
    """
    st.subheader("📥 Input IDS Alerts")

    method = st.radio(
        "Input method",
        ["Upload JSON file", "Paste JSON text", "Use sample alerts"],
        horizontal=True,
        key="alert_input_method",
    )

    alerts: list[dict] | None = None

    if method == "Upload JSON file":
        uploaded = st.file_uploader(
            "Upload alert JSON file",
            type=["json"],
            help="Expected format: array of alert objects. See evaluation/ground_truth/scenarios.json for examples.",
            key="alert_file_upload",
        )
        if uploaded:
            try:
                content = uploaded.read().decode("utf-8")
                parsed  = json.loads(content)
                # Support both a raw array and a scenarios.json-style wrapper
                if isinstance(parsed, list):
                    if parsed and "alerts" in parsed[0]:
                        # scenarios.json format — flatten all alerts
                        alerts = [a for scenario in parsed for a in scenario.get("alerts", [])]
                    else:
                        alerts = parsed
                elif isinstance(parsed, dict) and "alerts" in parsed:
                    alerts = parsed["alerts"]
                else:
                    st.error("Unrecognised JSON structure. Expected an array of alert objects.")
                    return None

                st.success(f"Loaded **{len(alerts)} alerts** from `{uploaded.name}`")
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON: {e}")
                return None

    elif method == "Paste JSON text":
        raw = st.text_area(
            "Paste alert JSON array",
            height=220,
            placeholder='[{"alert_id": "...", "src_ip": "...", "attack_type": "..."}]',
            key="alert_paste_box",
        )
        if raw.strip():
            try:
                parsed = json.loads(raw.strip())
                alerts = parsed if isinstance(parsed, list) else [parsed]
                st.success(f"Parsed **{len(alerts)} alerts** from pasted text.")
            except json.JSONDecodeError as e:
                st.error(f"JSON parse error: {e}")
                return None

    else:  # Use sample alerts
        alerts = _sample_alerts()
        st.info(f"Using **{len(alerts)} built-in sample alerts** (SSH brute-force + port scan scenario).")

    if alerts:
        with st.expander(f"Preview — first {min(3, len(alerts))} alerts"):
            for a in alerts[: min(3, len(alerts))]:
                st.json(a)
        if len(alerts) > 3:
            st.caption(f"… and {len(alerts) - 3} more alerts")

    return alerts


def _sample_alerts() -> list[dict]:
    """Built-in demo alerts for testing without a data file."""
    return [
        {
            "alert_id": "demo-001",
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
            "alert_id": "demo-002",
            "timestamp": "2017-07-04T09:05:00",
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "dst_port": 22,
            "protocol": "TCP",
            "attack_type": "SSH-Patator",
            "flow_bytes_per_sec": 3950.0,
            "packet_count": 420,
        },
        {
            "alert_id": "demo-003",
            "timestamp": "2017-07-04T09:11:00",
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.0",
            "dst_port": 0,
            "protocol": "TCP",
            "attack_type": "PortScan",
            "flow_bytes_per_sec": 12000.0,
            "packet_count": 1100,
        },
    ]
