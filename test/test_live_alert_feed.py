"""Unit tests for live_alert_feed.py without Streamlit or packet capture."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from live_alert_feed import append_live_alert, clear_live_alerts, read_live_alerts


def _sample_alert(**overrides):
    alert = {
        "timestamp": "2026-05-14 12:00:00",
        "risk": "High",
        "risk_label": "!! High",
        "src_ip": "10.0.0.5",
        "src_port": 44321,
        "dst_ip": "10.0.0.10",
        "dst_port": 443,
        "protocol": "TCP",
        "packets": 12,
        "bytes": 4096,
        "error": 512.1234567,
        "type": "Web Attack",
        "recommendation": "Investigate the flow.",
    }
    alert.update(overrides)
    return alert


def test_append_and_read_recent_first():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "live_alerts.jsonl")

        append_live_alert(_sample_alert(timestamp="2026-05-14 12:00:00", risk="Medium"), path=path)
        append_live_alert(_sample_alert(timestamp="2026-05-14 12:00:02", risk="Critical"), path=path)

        alerts = read_live_alerts(path=path)

    assert len(alerts) == 2
    assert alerts[0]["risk"] == "Critical"
    assert alerts[1]["risk"] == "Medium"


def test_read_limit_keeps_latest_records():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "live_alerts.jsonl")

        for idx in range(5):
            append_live_alert(_sample_alert(timestamp=f"2026-05-14 12:00:0{idx}", src_port=1000 + idx), path=path)

        alerts = read_live_alerts(limit=3, path=path)

    assert [alert["src_port"] for alert in alerts] == [1004, 1003, 1002]


def test_clear_live_alerts_removes_feed_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "live_alerts.jsonl")
        append_live_alert(_sample_alert(), path=path)

        clear_live_alerts(path=path)

        assert read_live_alerts(path=path) == []
        assert not os.path.exists(path)


def test_malformed_lines_are_ignored():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "live_alerts.jsonl")

        with open(path, "w", encoding="utf-8") as f:
            f.write("not json\n")

        append_live_alert(_sample_alert(), path=path)
        alerts = read_live_alerts(path=path)

    assert len(alerts) == 1
    assert alerts[0]["src_ip"] == "10.0.0.5"


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS  {test.__name__}")
            passed += 1
        except AssertionError as exc:
            print(f"  FAIL  {test.__name__}: {exc}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(failed)
