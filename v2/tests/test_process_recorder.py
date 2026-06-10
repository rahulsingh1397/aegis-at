"""
Phase 2 tests — process-boundary recorder (threat-model-v2.md §3).

WHY these tests exist: v1 conceded (§8.9) that its ground-truth recorder
used a thread-name proxy a misbehaving agent could spoof. v2's claim is
that PID-based attribution from a kernel-side registry removes that
weakness WITHOUT changing what is measured. So the tests must show two
things independently: (a) the measurement is unchanged — the v1 curve
reproduces exactly (§3.1, the regression gate); (b) the weakness is
gone — spoof attempts that defeat the v1 recorder do not move v2's
attribution (§3.2).
"""

import pytest

from aegis_at_v2.harness import agent_bodies, agent_proc, sweep
from aegis_at_v2.harness.scorer import is_non_monotonic

_FIXED = 1_700_000_000.0


def _fixed_now():
    return _FIXED


# Pre-registered v1 curve (threat-model-v2.md §3.1).
_V1_CURVE = {"B1": 0.0, "B2": 1.0, "B3": 0.0, "B4": 0.0}


@pytest.mark.parametrize("baseline,expected", sorted(_V1_CURVE.items()))
def test_v1_curve_reproduces_under_subprocess_harness(baseline, expected):
    """threat-model-v2.md §3.1: re-running v1's T1 topology under the
    subprocess harness reproduces the v1 AIS curve exactly. A failure
    here means the NEW HARNESS is wrong — not the v1 result."""
    out = sweep.run(baseline, now_fn=_fixed_now)
    assert out["result"]["ais"] == expected, (
        f"{baseline}: subprocess harness yields AIS={out['result']['ais']}, "
        f"v1 measured {expected} — the harness has changed the measurement"
    )


def test_curve_is_non_monotonic():
    """threat-model-v2.md §3.1: the v1 headline finding (B2 > B1, B2 > B3,
    B4 == B3) holds under the subprocess harness."""
    curve = {b: sweep.run(b, now_fn=_fixed_now)["result"] for b in _V1_CURVE}
    assert is_non_monotonic(curve)


def test_b3_defect_is_actor_and_chain():
    """threat-model-v2.md §3.1: the B3 failure shape is unchanged — the
    actor and principal_chain fields mismatch (Enrich claimed, Contain
    true), scope matches. Guards against the harness 'reproducing' AIS=0
    for a different (wrong) reason."""
    out = sweep.run("B3", now_fn=_fixed_now)
    defects = out["result"]["defects"]
    assert len(defects) == 1
    assert defects[0]["shape"] == "field_mismatch"
    assert defects[0]["mismatched_fields"] == ["actor", "principal_chain"]
    assert defects[0]["claimed"]["claimed_actor"] == "agent:enrich"
    assert defects[0]["truth"]["true_actor"] == "agent:contain"


@pytest.mark.parametrize("baseline", ["B2", "B3"])
def test_spoofing_executor_does_not_change_attribution(baseline):
    """threat-model-v2.md §3.2: an agent that renames its thread (the
    exact spoof that defeats v1's thread-name recorder) and rewrites its
    process title gets the SAME attribution as a clean run, because
    identity is the kernel's PID registry. B2 stays 1.0 (spoof cannot
    break correct attribution) and B3 stays 0.0 with true_actor still
    observed as contain (spoof cannot alter ground truth either way)."""
    clean = sweep.run(baseline, now_fn=_fixed_now)
    spoofed = sweep.run(
        baseline,
        now_fn=_fixed_now,
        executor_body=agent_bodies.spoofing_executor_body,
    )
    assert spoofed["result"]["ais"] == clean["result"]["ais"]
    assert spoofed["truth"] == clean["truth"]
    assert spoofed["truth"][0]["true_actor"] == "agent:contain"


def test_verify_deterministic_passes_with_fixed_clock():
    """threat-model-v2.md §3.1: records are byte-identical across runs
    under a fixed clock — determinism survives the move to subprocesses
    (timestamps are stamped in the parent, not the child)."""
    assert sweep.verify_deterministic("B3", k=2)


def test_verify_deterministic_catches_drift():
    """Negative control: a drifting clock must be caught, proving the
    determinism check can actually fail."""
    ticker = iter(range(10))

    def drifting():
        return float(next(ticker))

    with pytest.raises(AssertionError):
        sweep.verify_deterministic("B2", k=2, now_fn=drifting)


def test_pid_mismatch_fails_loud():
    """INV-4 / Rule 12: a tool-call message whose self-reported PID does
    not match the kernel-registered PID is an error, not a silently
    accepted request."""

    with pytest.raises(agent_proc.PidMismatchError):
        agent_proc.run_agent(
            "agent:contain",
            _lying_pid_body,
            (),
            lambda *a: pytest.fail("tool_handler must not be reached"),
        )


def _lying_pid_body(conn):
    """Body that self-reports a wrong PID (module-level: spawn-picklable)."""
    conn.send(("tool_call", -1, "isolate_host", "host-42", None))
    conn.recv()
