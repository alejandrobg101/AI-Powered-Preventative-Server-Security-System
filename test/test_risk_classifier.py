"""Unit tests for risk_classifier.py — no external artifacts required."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from risk_classifier import classify, LOW, MEDIUM, HIGH, CRITICAL

_T = {"medium": 1.0, "high": 2.5, "critical": 6.0}


def test_low_at_zero():
    assert classify(0.0, _T) is LOW

def test_low_at_threshold():
    assert classify(1.0, _T) is LOW

def test_medium_just_above_threshold():
    assert classify(1.001, _T) is MEDIUM

def test_medium_at_high_boundary():
    assert classify(2.5, _T) is MEDIUM

def test_high_just_above_medium():
    assert classify(2.501, _T) is HIGH

def test_high_at_critical_boundary():
    assert classify(6.0, _T) is HIGH

def test_critical_just_above_high():
    assert classify(6.001, _T) is CRITICAL

def test_critical_extreme():
    assert classify(1_000.0, _T) is CRITICAL

def test_risk_codes_are_ordered():
    assert LOW.code < MEDIUM.code < HIGH.code < CRITICAL.code

def test_all_levels_have_nonempty_fields():
    for level in (LOW, MEDIUM, HIGH, CRITICAL):
        assert level.name
        assert level.label
        assert level.suggested_response


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
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(failed)
