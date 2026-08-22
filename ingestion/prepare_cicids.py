"""
ingestion/prepare_cicids.py
Converts CICIDS 2017 CSV flow files → CyberSentinel Alert JSON format.

Usage:
    python -m ingestion.prepare_cicids            # process all 8 CSVs
    python ingestion/prepare_cicids.py            # same

Each CSV produces one JSON file in  data/processed/alerts/
e.g.  Tuesday-WorkingHours.pcap_ISCX.csv  →  Tuesday-WorkingHours.pcap_ISCX.json

Only malicious flows (Label != 'BENIGN') are kept.
"""

import json
import logging
import uuid
from pathlib import Path

import pandas as pd

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).resolve().parent.parent
RAW_DIR     = REPO_ROOT / "data" / "raw" / "cicids2017"
OUTPUT_DIR  = REPO_ROOT / "data" / "processed" / "alerts"
MAX_ALERTS  = 5000   # cap per file to keep memory manageable during dev

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger("prepare_cicids")


# Column name aliases — CICIDS files have leading/trailing spaces in headers
_COL = {
    "label":          " Label",
    "timestamp":      "Timestamp",
    "src_ip":         " Source IP",
    "dst_ip":         " Destination IP",
    "dst_port":       " Destination Port",
    "protocol":       " Protocol",
    "flow_bytes_s":   " Flow Bytes/s",
    "fwd_packets":    " Total Fwd Packets",
    "flow_duration":  " Flow Duration",
    "flow_packets_s": " Flow Packets/s",
    "fwd_pkt_len_mean": " Fwd Packet Length Mean",
}

# Map CICIDS protocol numbers to human-readable strings
_PROTO_MAP = {6: "TCP", 17: "UDP", 0: "HOPOPT", 1: "ICMP"}


def _safe_float(val, default: float = 0.0) -> float:
    try:
        v = float(val)
        return v if v == v else default   # NaN check
    except (ValueError, TypeError):
        return default


def _safe_int(val, default: int = 0) -> int:
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return default


def _resolve_protocol(raw_proto) -> str:
    try:
        return _PROTO_MAP.get(int(float(raw_proto)), str(raw_proto))
    except (ValueError, TypeError):
        return str(raw_proto)


def convert_cicids_to_alerts(
    csv_path: Path,
    output_dir: Path = OUTPUT_DIR,
    max_alerts: int = MAX_ALERTS,
) -> int:
    """
    Read one CICIDS CSV, keep only malicious rows, and write an Alert JSON.

    Returns the number of alerts written.
    """
    log.info("Processing: %s", csv_path.name)
    df = pd.read_csv(csv_path, encoding="latin-1", low_memory=False)
    df.columns = df.columns.str.strip()   # strip ALL column names once

    # Normalise label column (might be 'Label' or ' Label' after strip)
    label_col = "Label"
    if label_col not in df.columns:
        log.error("Label column not found in %s — columns: %s", csv_path.name, list(df.columns[:10]))
        return 0

    malicious = df[df[label_col] != "BENIGN"].head(max_alerts).copy()
    log.info(
        "  %s → %d total rows, %d malicious (capped at %d)",
        csv_path.name, len(df), len(df[df[label_col] != "BENIGN"]), max_alerts,
    )

    if malicious.empty:
        log.warning("  No malicious rows found in %s — skipping.", csv_path.name)
        return 0

    alerts = []
    for _, row in malicious.iterrows():
        alerts.append({
            "alert_id":          str(uuid.uuid4()),
            "timestamp":         str(row.get("Timestamp", "")),
            "src_ip":            str(row.get("Source IP",         "0.0.0.0")),
            "dst_ip":            str(row.get("Destination IP",    "0.0.0.0")),
            "dst_port":          _safe_int(row.get("Destination Port", 0)),
            "protocol":          _resolve_protocol(row.get("Protocol", "TCP")),
            "attack_type":       str(row.get(label_col, "Unknown")),
            "flow_bytes_per_sec":_safe_float(row.get("Flow Bytes/s", 0)),
            "packet_count":      _safe_int(row.get("Total Fwd Packets", 0)),
            "flow_duration_us":  _safe_int(row.get("Flow Duration", 0)),
            "flow_packets_s":    _safe_float(row.get("Flow Packets/s", 0)),
            "fwd_pkt_len_mean":  _safe_float(row.get("Fwd Packet Length Mean", 0)),
        })

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / (csv_path.stem + ".json")
    out_path.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    log.info("  Written: %s  (%d alerts)", out_path.name, len(alerts))
    return len(alerts)


def process_all(raw_dir: Path = RAW_DIR, output_dir: Path = OUTPUT_DIR) -> None:
    """Process all 8 CICIDS CSV files found in raw_dir."""
    csv_files = sorted(raw_dir.glob("*.csv"))
    if not csv_files:
        log.error("No CSV files found in %s", raw_dir)
        return

    total = 0
    for csv in csv_files:
        total += convert_cicids_to_alerts(csv, output_dir)

    log.info("\nAll files processed. Total malicious alerts written: %d", total)
    log.info("Output directory: %s", output_dir)


if __name__ == "__main__":
    process_all()
