"""
backend/tests/test_chain_reconstructor.py
Unit tests for TKCI / DBASC.

Key test: 2-attacker scenario clusters correctly into 2 separate sessions.
Run with: pytest backend/tests/test_chain_reconstructor.py -v
"""

import pytest
from datetime import datetime

from backend.core.chain.reconstructor import (
    KillChainReconstructor,
    _alert_distance,
    _parse_ts,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_alert(src_ip, attack_type, timestamp, dst_port=80, dst_ip="10.0.0.1"):
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": "TCP",
        "attack_type": attack_type,
        "timestamp": timestamp,
        "cisa_hit": False,
    }


# Attacker A: 192.168.1.10 — SSH brute force then exfiltration
ATTACKER_A_ALERTS = [
    make_alert("192.168.1.10", "PortScan",    "2017-07-04T09:00:00", dst_port=80),
    make_alert("192.168.1.10", "SSH-Patator", "2017-07-04T09:05:00", dst_port=22),
    make_alert("192.168.1.10", "Infiltration","2017-07-04T09:20:00", dst_port=443),
]

# Attacker B: 10.10.0.50 — DDoS flood (different IP, simultaneous)
ATTACKER_B_ALERTS = [
    make_alert("10.10.0.50",   "DDoS-SYN",   "2017-07-04T09:02:00", dst_port=80),
    make_alert("10.10.0.50",   "DDoS-SYN",   "2017-07-04T09:03:00", dst_port=80),
]


# ── Distance metric tests ─────────────────────────────────────────────────────

class TestAlertDistance:

    def test_same_ip_same_time(self):
        a = make_alert("10.0.0.1", "SSH-Patator", "2017-07-04T09:00:00")
        b = make_alert("10.0.0.1", "SSH-Patator", "2017-07-04T09:00:00")
        d = _alert_distance(a, b, 0.0, 0.0, 1.0)
        assert d == 0.0, f"Same IP, same time → distance should be 0.0, got {d}"

    def test_different_ip_zero_time_delta(self):
        a = make_alert("10.0.0.1", "X", "2017-07-04T09:00:00")
        b = make_alert("10.0.0.2", "X", "2017-07-04T09:00:00")
        d = _alert_distance(a, b, 0.0, 0.0, 1.0)
        assert d == pytest.approx(0.7), f"Different IPs, same time → d=0.7, got {d}"

    def test_same_ip_max_time_delta(self):
        a = make_alert("10.0.0.1", "X", "2017-07-04T09:00:00")
        b = make_alert("10.0.0.1", "X", "2017-07-04T09:00:00")
        d = _alert_distance(a, b, 0.0, 1.0, 1.0)  # t_max=1, delta=1
        assert d == pytest.approx(0.3), f"Same IP, max time → d=0.3, got {d}"

    def test_distance_bounded(self):
        a = make_alert("10.0.0.1", "X", "2017-07-04T09:00:00")
        b = make_alert("10.0.0.2", "X", "2017-07-04T10:00:00")
        d = _alert_distance(a, b, 0.0, 3600.0, 3600.0)
        assert 0.0 <= d <= 1.0, f"Distance should be in [0, 1], got {d}"


# ── DBASC clustering tests ────────────────────────────────────────────────────

class TestDBASCClustering:

    @pytest.fixture(scope="class")
    def recon(self):
        return KillChainReconstructor()

    def test_two_attacker_scenario_clusters_into_2_sessions(self, recon):
        """
        Core DBASC test:
        192.168.1.10 (3 alerts) and 10.10.0.50 (2 alerts) should form 2 separate clusters
        since IP_mismatch=1 gives distance=0.7 > eps=0.35.
        """
        all_alerts = ATTACKER_A_ALERTS + ATTACKER_B_ALERTS
        labels = recon.cluster_sessions(all_alerts)

        unique_sessions = set(l for l in labels if l != -1)
        assert len(unique_sessions) == 2, (
            f"Expected 2 sessions (one per attacker IP), got {len(unique_sessions)}. "
            f"Labels: {labels.tolist()}"
        )

    def test_same_attacker_clusters_together(self, recon):
        """3 alerts from same IP should form 1 cluster."""
        labels = recon.cluster_sessions(ATTACKER_A_ALERTS)
        unique_sessions = set(l for l in labels if l != -1)
        assert len(unique_sessions) == 1, (
            f"Expected 1 session, got {len(unique_sessions)}. Labels: {labels.tolist()}"
        )

    def test_single_alert_handled(self, recon):
        """Single alert should not crash (returns label [0])."""
        labels = recon.cluster_sessions([ATTACKER_A_ALERTS[0]])
        assert len(labels) == 1


# ── TKCI tactic ordering tests ────────────────────────────────────────────────

class TestTKCIOrdering:

    @pytest.fixture(scope="class")
    def recon(self):
        return KillChainReconstructor()

    def test_tactics_ordered_by_kill_chain_phase(self, recon):
        """TA0040 (Impact) before TA0043 (Reconnaissance) should be reordered."""
        disordered = ["TA0040", "TA0043", "TA0006"]
        ordered = recon._order_tactics(disordered)
        assert ordered.index("TA0043") < ordered.index("TA0006") < ordered.index("TA0040"), (
            f"Expected Recon < CredAccess < Impact, got: {ordered}"
        )

    def test_duplicate_tactics_deduplicated(self, recon):
        tactics = ["TA0006", "TA0006", "TA0043"]
        ordered = recon._order_tactics(tactics)
        assert len(ordered) == 2
        assert ordered.count("TA0006") == 1


# ── Metric formulae tests ─────────────────────────────────────────────────────

class TestMetricFormulae:

    def test_kcv_formula(self):
        """3 phases in 1.5 hours → KCV = 2.0 ph/hr"""
        t_start = datetime(2017, 7, 4, 9, 0, 0)
        t_end   = datetime(2017, 7, 4, 10, 30, 0)   # 1.5 hours
        tactics = ["TA0043", "TA0006", "TA0010"]
        kcv = KillChainReconstructor.compute_kcv(tactics, t_start, t_end)
        assert kcv == pytest.approx(2.0, abs=0.01)

    def test_kcv_high_means_scripted(self):
        """6 phases in 0.5 hours → KCV=12 → scripted"""
        t_start = datetime(2017, 7, 4, 9, 0, 0)
        t_end   = datetime(2017, 7, 4, 9, 30, 0)  # 0.5 hours
        tactics = ["TA0043", "TA0001", "TA0002", "TA0006", "TA0010", "TA0040"]
        kcv = KillChainReconstructor.compute_kcv(tactics, t_start, t_end)
        assert kcv > 5
        assert KillChainReconstructor.kcv_label(kcv) == "automated/scripted"

    def test_si_formula(self):
        """SI = (chain_depth + cisa_fraction + norm_kcv) / 3 * 100"""
        # chain_depth = 2/14, cisa_fraction = 0.5, norm_kcv = 4/10
        tactics = ["TA0043", "TA0006"]  # 2 phases
        si = KillChainReconstructor.compute_si(tactics, cisa_fraction=0.5, kcv=4.0)
        expected = (2/14 + 0.5 + 4/10) / 3 * 100
        assert si == pytest.approx(expected, abs=0.5)

    def test_si_max_capped(self):
        """Maximum possible SI should not exceed 100."""
        tactics = [f"TA{str(i).zfill(4)}" for i in range(14)]
        si = KillChainReconstructor.compute_si(tactics, cisa_fraction=1.0, kcv=10.0)
        assert si <= 100.0

    def test_si_zero_scenario(self):
        si = KillChainReconstructor.compute_si([], cisa_fraction=0.0, kcv=0.0)
        assert si == 0.0


# ── Full reconstruct() integration test ──────────────────────────────────────

class TestFullReconstruct:

    @pytest.fixture(scope="class")
    def recon(self):
        return KillChainReconstructor()

    def test_reconstruct_two_attackers(self, recon):
        all_alerts = ATTACKER_A_ALERTS + ATTACKER_B_ALERTS
        tactics = ["TA0043", "TA0006", "TA0010", "TA0040", "TA0040"]
        result = recon.reconstruct(all_alerts, tactic_assignments=tactics)

        assert result.session_count == 2, f"Expected 2 sessions, got {result.session_count}"
        assert result.total_alerts == 5
        for session in result.sessions:
            assert session.severity_index >= 0.0
            assert session.kcv >= 0.0
            assert len(session.ordered_tactics) > 0

    def test_empty_alerts(self, recon):
        result = recon.reconstruct([])
        assert result.session_count == 0
        assert result.total_alerts == 0


# ── Timestamp parser ──────────────────────────────────────────────────────────

def test_parse_ts_iso():
    dt = _parse_ts("2017-07-04T09:00:00")
    assert dt is not None
    assert dt.year == 2017

def test_parse_ts_space_sep():
    dt = _parse_ts("2017-07-04 09:00:00")
    assert dt is not None

def test_parse_ts_empty():
    assert _parse_ts("") is None
    assert _parse_ts(None) is None
