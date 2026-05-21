"""Unit tests for response_engine.py — no external dependencies."""
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from response_engine import (
    infer_anomaly_type, get_recommendation, format_response_block,
    SYN_FLOOD, UDP_FLOOD, ICMP_FLOOD, PORT_SCAN,
    SSH_BRUTE_FORCE, FTP_BRUTE_FORCE, HTTP_SLOWLORIS, WEB_ATTACK,
    DNS_AMPLIFICATION, GENERIC_TCP, GENERIC_UDP, GENERIC_ICMP, UNKNOWN,
    ALL_TYPES,
)


# ─────────────────────────────────────────────────────────────
# Minimal FlowStats stub — only the attributes the engine reads
# ─────────────────────────────────────────────────────────────
class _Flow:
    def __init__(
        self,
        fwd_pkts=10, bwd_pkts=10,
        fwd_bytes=None, bwd_bytes=None,
        syn=0, ack=0,
        duration=5.0,
    ):
        self.fwd_pkts  = fwd_pkts
        self.bwd_pkts  = bwd_pkts
        self.fwd_bytes = fwd_bytes or [100] * fwd_pkts
        self.bwd_bytes = bwd_bytes or [100] * bwd_pkts
        self.syn       = syn
        self.ack       = ack
        now = time.time()
        self.start_ts  = now - duration
        self.last_ts   = now


def _key(src_port=12345, dst_port=80, proto=6):
    """Build the normalized 5-tuple shape expected by infer_anomaly_type()."""
    return ("1.2.3.4", "5.6.7.8", src_port, dst_port, proto)


# ─────────────────────────────────────────────────────────────
# infer_anomaly_type — rule coverage
# ─────────────────────────────────────────────────────────────
def test_icmp_flood():
    # 200 ICMP pkts in 2 s = 100 pkt/s > threshold (50)
    flow = _Flow(fwd_pkts=200, bwd_pkts=0, duration=2.0)
    assert infer_anomaly_type(flow, _key(proto=1)) == ICMP_FLOOD

def test_icmp_generic():
    flow = _Flow(fwd_pkts=5, bwd_pkts=0, duration=2.0)
    assert infer_anomaly_type(flow, _key(proto=1)) == GENERIC_ICMP

def test_udp_flood():
    # 500 pkts in 2 s = 250 pkt/s > 100
    flow = _Flow(fwd_pkts=500, bwd_pkts=0, duration=2.0)
    assert infer_anomaly_type(flow, _key(proto=17, dst_port=9999)) == UDP_FLOOD

def test_dns_amplification_by_dst_port():
    # small request (100 B), large response (2000 B) on port 53
    flow = _Flow(fwd_pkts=1, bwd_pkts=1,
                 fwd_bytes=[100], bwd_bytes=[2000], duration=0.1)
    assert infer_anomaly_type(flow, _key(proto=17, dst_port=53)) == DNS_AMPLIFICATION

def test_dns_amplification_by_src_port():
    flow = _Flow(fwd_pkts=1, bwd_pkts=1,
                 fwd_bytes=[50], bwd_bytes=[500], duration=0.1)
    assert infer_anomaly_type(flow, _key(proto=17, src_port=53, dst_port=9999)) == DNS_AMPLIFICATION

def test_udp_generic():
    flow = _Flow(fwd_pkts=5, bwd_pkts=5, duration=10.0)
    assert infer_anomaly_type(flow, _key(proto=17, dst_port=9999)) == GENERIC_UDP

def test_syn_flood():
    flow = _Flow(fwd_pkts=50, bwd_pkts=0, syn=20, ack=0, duration=1.0)
    assert infer_anomaly_type(flow, _key(proto=6, dst_port=80)) == SYN_FLOOD

def test_syn_flood_ack_ratio():
    # syn=15, ack=2 → syn >= ack * 3 (15 >= 6) → SYN flood
    flow = _Flow(fwd_pkts=20, bwd_pkts=5, syn=15, ack=2, duration=2.0)
    assert infer_anomaly_type(flow, _key(proto=6, dst_port=443)) == SYN_FLOOD

def test_ssh_brute_force_dst():
    flow = _Flow(fwd_pkts=30, bwd_pkts=30, syn=1, ack=20, duration=15.0)
    assert infer_anomaly_type(flow, _key(proto=6, dst_port=22)) == SSH_BRUTE_FORCE

def test_ssh_brute_force_src():
    # normalised key has 22 as src_port
    flow = _Flow(fwd_pkts=30, bwd_pkts=30, syn=1, ack=20, duration=15.0)
    assert infer_anomaly_type(flow, _key(proto=6, src_port=22, dst_port=55000)) == SSH_BRUTE_FORCE

def test_ftp_brute_force():
    flow = _Flow(fwd_pkts=20, bwd_pkts=20, syn=1, ack=15, duration=10.0)
    assert infer_anomaly_type(flow, _key(proto=6, dst_port=21)) == FTP_BRUTE_FORCE

def test_http_slowloris():
    # long duration (60 s), very low pkt rate
    flow = _Flow(fwd_pkts=10, bwd_pkts=5, syn=1, ack=5, duration=60.0)
    assert infer_anomaly_type(flow, _key(proto=6, dst_port=80)) == HTTP_SLOWLORIS

def test_web_attack_http():
    flow = _Flow(fwd_pkts=50, bwd_pkts=50, syn=1, ack=40, duration=5.0)
    assert infer_anomaly_type(flow, _key(proto=6, dst_port=443)) == WEB_ATTACK

def test_web_attack_8080():
    flow = _Flow(fwd_pkts=20, bwd_pkts=20, syn=1, ack=15, duration=3.0)
    assert infer_anomaly_type(flow, _key(proto=6, dst_port=8080)) == WEB_ATTACK

def test_port_scan():
    # very short, one-sided, few packets
    flow = _Flow(fwd_pkts=2, bwd_pkts=0, syn=1, ack=0, duration=0.5)
    assert infer_anomaly_type(flow, _key(proto=6, dst_port=9999)) == PORT_SCAN

def test_generic_tcp():
    flow = _Flow(fwd_pkts=20, bwd_pkts=20, syn=1, ack=15, duration=10.0)
    assert infer_anomaly_type(flow, _key(proto=6, dst_port=9999)) == GENERIC_TCP

def test_unknown_protocol():
    flow = _Flow(fwd_pkts=10, bwd_pkts=5, duration=5.0)
    assert infer_anomaly_type(flow, _key(proto=99)) == UNKNOWN


# ─────────────────────────────────────────────────────────────
# get_recommendation — knowledge base coverage
# ─────────────────────────────────────────────────────────────
def test_all_types_have_recommendations():
    for t in ALL_TYPES:
        rec = get_recommendation(t, "High")
        assert rec.anomaly_type == t
        assert rec.description
        assert rec.summary
        assert len(rec.actions) > 0

def test_escalate_false_for_medium():
    rec = get_recommendation(SYN_FLOOD, "Medium")
    assert rec.escalate is False

def test_escalate_true_for_high():
    rec = get_recommendation(SYN_FLOOD, "High")
    assert rec.escalate is True

def test_escalate_true_for_critical():
    rec = get_recommendation(SSH_BRUTE_FORCE, "Critical")
    assert rec.escalate is True

def test_critical_summary_contains_escalate():
    rec = get_recommendation(SYN_FLOOD, "Critical")
    assert "ESCALATE" in rec.summary

def test_unknown_anomaly_type_falls_back():
    rec = get_recommendation("TOTALLY_MADE_UP", "High")
    assert rec.anomaly_type == "TOTALLY_MADE_UP"
    assert rec.description   # falls back to UNKNOWN entry

def test_low_risk_handled_gracefully():
    rec = get_recommendation(PORT_SCAN, "Low")
    assert rec.summary  # defaults to Medium summary


# ─────────────────────────────────────────────────────────────
# format_response_block
# ─────────────────────────────────────────────────────────────
def test_format_contains_src_ip():
    rec = get_recommendation(SYN_FLOOD, "Critical")
    block = format_response_block(rec, "10.0.0.1")
    assert "10.0.0.1" in block

def test_format_replaces_placeholder():
    rec = get_recommendation(SYN_FLOOD, "High")
    block = format_response_block(rec, "192.168.1.50")
    assert "<SRC_IP>" not in block
    assert "192.168.1.50" in block

def test_format_contains_all_steps():
    rec = get_recommendation(SSH_BRUTE_FORCE, "High")
    block = format_response_block(rec, "1.1.1.1")
    for i in range(1, len(rec.actions) + 1):
        assert f"{i}." in block


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(failed)
