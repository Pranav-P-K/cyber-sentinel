"""
frontend/components/alert_input.py
Streamlit widget for JSON alert input — file upload or paste.

Returns a list of alert dicts or None if nothing is provided yet.
"""

import json
import streamlit as st


def render_alert_input() -> tuple[list[dict] | None, bool]:
    """
    Renders the alert input widget.
    Returns (alerts, submitted) tuple.
    """
    st.subheader("📥 Input IDS Alerts")

    method = st.radio(
        "Input method",
        ["🎯 Review Demo Presets", "Upload JSON file", "Paste JSON text"],
        horizontal=True,
        key="alert_input_method",
    )

    alerts: list[dict] | None = None

    if method == "🎯 Review Demo Presets":
        preset_choice = st.selectbox(
            "Select Review Demo Scenario",
            [
                "Scenario 1: Multi-Attacker Campaign (Showcases Novelty 2 DBASC Clustering)",
                "Scenario 2: Progressive APT Attack Chain (Showcases Novelty 1 CGAR + KCV/SI)",
            ],
            key="preset_scenario_select",
        )

        if "Multi-Attacker" in preset_choice:
            alerts = _multi_attacker_preset()
            st.info(
                "💡 **Scenario 1 Focus (Novelty 2 DBASC)**: Contains 5 alerts interleaved from 2 distinct attacker IPs "
                "(`192.168.1.100` and `10.10.50.200`). Watch DBASC automatically separate them into **2 distinct attack sessions** "
                "instead of creating a false single chain."
            )
        else:
            alerts = _progressive_apt_preset()
            st.info(
                "💡 **Scenario 2 Focus (Novelty 1 CGAR + KCV/SI)**: Progressive 4-phase campaign from a single actor "
                "(`172.16.0.5`). Demonstrates ChromaDB adaptive retrieval (HRSS), Kill Chain Velocity (KCV), "
                "and Composite Severity Index (SI)."
            )

    elif method == "Upload JSON file":
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
                if isinstance(parsed, list):
                    if parsed and "alerts" in parsed[0]:
                        alerts = [a for scenario in parsed for a in scenario.get("alerts", [])]
                    else:
                        alerts = parsed
                elif isinstance(parsed, dict) and "alerts" in parsed:
                    alerts = parsed["alerts"]
                else:
                    st.error("Unrecognised JSON structure. Expected an array of alert objects.")
                    return None, False

                st.success(f"Loaded **{len(alerts)} alerts** from `{uploaded.name}`")
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON: {e}")
                return None, False

    else:  # Paste JSON text
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
                return None, False

    submitted = False
    if alerts:
        with st.expander(f"Preview — {len(alerts)} alerts loaded (click to inspect JSON)"):
            st.json(alerts)
        submitted = st.button("🚀 Analyze Alerts with CyberSentinel", type="primary", use_container_width=True)

    return alerts, submitted


def _multi_attacker_preset() -> list[dict]:
    """
    Two concurrent attackers interleaved in time.
    Attacker A (192.168.1.100): PortScan -> SSH-Patator -> DoS Hulk
    Attacker B (10.10.50.200): Infiltration / WebAttack -> Bot C2
    DBASC must cluster these into 2 separate sessions.
    """
    return [
        {
            "alert_id": "alert-A1",
            "timestamp": "2017-07-04T09:00:00",
            "src_ip": "192.168.1.100",
            "dst_ip": "172.16.0.10",
            "dst_port": 80,
            "protocol": "TCP",
            "attack_type": "PortScan",
            "flow_bytes_per_sec": 12500.0,
            "packet_count": 820,
        },
        {
            "alert_id": "alert-B1",
            "timestamp": "2017-07-04T09:05:00",
            "src_ip": "10.10.50.200",
            "dst_ip": "172.16.0.25",
            "dst_port": 443,
            "protocol": "TCP",
            "attack_type": "Infiltration",
            "flow_bytes_per_sec": 4800.0,
            "packet_count": 190,
        },
        {
            "alert_id": "alert-A2",
            "timestamp": "2017-07-04T09:12:00",
            "src_ip": "192.168.1.100",
            "dst_ip": "172.16.0.10",
            "dst_port": 22,
            "protocol": "TCP",
            "attack_type": "SSH-Patator",
            "flow_bytes_per_sec": 3400.0,
            "packet_count": 450,
        },
        {
            "alert_id": "alert-B2",
            "timestamp": "2017-07-04T09:18:00",
            "src_ip": "10.10.50.200",
            "dst_ip": "172.16.0.25",
            "dst_port": 8080,
            "protocol": "TCP",
            "attack_type": "Bot",
            "flow_bytes_per_sec": 8900.0,
            "packet_count": 620,
        },
        {
            "alert_id": "alert-A3",
            "timestamp": "2017-07-04T09:25:00",
            "src_ip": "192.168.1.100",
            "dst_ip": "172.16.0.10",
            "dst_port": 80,
            "protocol": "TCP",
            "attack_type": "DoS Hulk",
            "flow_bytes_per_sec": 95000.0,
            "packet_count": 4200,
        },
    ]


def _progressive_apt_preset() -> list[dict]:
    """
    Single attacker moving systematically across MITRE phases:
    Recon (PortScan) -> Credential Access (SSH) -> Exfiltration -> Impact (DDoS)
    """
    return [
        {
            "alert_id": "apt-001",
            "timestamp": "2017-07-07T10:00:00",
            "src_ip": "172.16.0.5",
            "dst_ip": "192.168.10.50",
            "dst_port": 0,
            "protocol": "TCP",
            "attack_type": "PortScan",
            "flow_bytes_per_sec": 15000.0,
            "packet_count": 1200,
        },
        {
            "alert_id": "apt-002",
            "timestamp": "2017-07-07T10:25:00",
            "src_ip": "172.16.0.5",
            "dst_ip": "192.168.10.50",
            "dst_port": 22,
            "protocol": "TCP",
            "attack_type": "SSH-Patator",
            "flow_bytes_per_sec": 4100.0,
            "packet_count": 520,
        },
        {
            "alert_id": "apt-003",
            "timestamp": "2017-07-07T11:00:00",
            "src_ip": "172.16.0.5",
            "dst_ip": "192.168.10.50",
            "dst_port": 80,
            "protocol": "TCP",
            "attack_type": "Heartbleed",
            "flow_bytes_per_sec": 6200.0,
            "packet_count": 310,
        },
        {
            "alert_id": "apt-004",
            "timestamp": "2017-07-07T11:30:00",
            "src_ip": "172.16.0.5",
            "dst_ip": "192.168.10.50",
            "dst_port": 80,
            "protocol": "TCP",
            "attack_type": "DDoS",
            "flow_bytes_per_sec": 120000.0,
            "packet_count": 6800,
        },
    ]

