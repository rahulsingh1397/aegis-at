"""Core tests for sweep.verify_deterministic — determinism gate."""
import pytest
from sweep import verify_deterministic, _FIXED_TS


def test_b2_b3_pass_under_fixed_clock():
    """B2 (no defects) and B3 (JWT path) must be deterministic."""
    assert verify_deterministic("B2", k=3) is True
    assert verify_deterministic("B3", k=3) is True


def test_fault_injection_catches_divergent_records():
    """If a drifting clock produces divergent records,
    verify_deterministic must raise AssertionError naming the field."""
    counter = [0]
    def drifting_clock():
        counter[0] += 1
        return _FIXED_TS + (0.001 if counter[0] > 1 else 0.0)
    with pytest.raises(AssertionError, match="B2 run 1.*timestamp"):
        verify_deterministic("B2", k=2, now_fn=drifting_clock)