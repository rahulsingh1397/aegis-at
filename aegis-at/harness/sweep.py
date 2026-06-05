"""
harness/sweep.py — baseline-switch harness, §6 curve.

Selects a baseline (B1-B4), mints the credential shape that baseline
prescribes (the ONLY thing that varies, INV-6), runs the canonical §5
re-delegation attack once, and scores it. verify_deterministic and
emit_curve (built next) compose run().

v1 sample design = Candidate C: one canonical execution per baseline.
The pipeline is deterministic given fixed inputs, so larger N adds no
information; verify_deterministic turns that determinism from a claim
into a checked property. See harness_notes.md.
"""

import threading
import time
from typing import TypedDict, Callable

from tokens import mint_initial_token
from orchestrator import mint_delegated_token
from siem_action import siem_action
from recorder import make_recorder
from scorer import score_ais, ScorerResult

# Canonical attack (locked, §5): Contain — the wielder — executes the
# high-consequence action. Only the credential differs across baselines.
_COMMAND = "isolate_host"
_TARGET = "host-42"
_EXECUTOR = "agent:contain"  # true executor; the recorder reads this thread name
_FIXED_TS = 1_700_000_000.0


class RunResult(TypedDict):
    baseline: str
    result: ScorerResult
    claimed: list  # claimed action-log records
    truth: list  # ground-truth records
    # records (not just result) so
    # verify_deterministic can check
    # record-level determinism on B2,
    # which has no defects to embed them in.


def _credential_for(baseline: str):
    """The per-baseline credential — the ONLY thing that varies (INV-6).

    B1: shared opaque credential (all agents act under one identity).
    B2: per-agent opaque credential (executor authenticates as itself).
    B3/B4: orchestrator-minted re-delegation JWT — the orchestrator
        honestly names Enrich (the requester) as current actor; Contain
        (the wielder) presents it. B4 == B3 at minting; tamper-evidence
        is at the log boundary, not here (§6).
    """
    if baseline == "B1":
        return {"format": "apikey", "agent": "svc:soar", "scope": "siem:write"}
    if baseline == "B2":
        return {"format": "apikey", "agent": "agent:contain", "scope": "siem:write"}
    if baseline in ("B3", "B4"):
        root = mint_initial_token("human:analyst", "siem:read siem:write")
        return mint_delegated_token(
            root, "agent:enrich", "siem:write", audience="siem_action"
        )
    raise ValueError(f"unknown baseline {baseline!r} (expected B1-B4)")


def _run_on_thread(name: str, fn):
    """Execute fn() on a thread named for the true executor, so the
    recorder reads true_actor from the thread, not the token (INV-4)."""
    box = {}

    def runner():
        try:
            box["v"] = fn()
        except BaseException as e:  # surface the real error to the caller
            box["e"] = e

    t = threading.Thread(target=runner, name=name)
    t.start()
    t.join()
    if "e" in box:
        raise box["e"]
    return box["v"]


def run(baseline: str, now_fn: Callable[[], float] = time.time) -> RunResult:
    """Run one canonical execution of the §5 attack for `baseline`.

    Only the credential differs across baselines (INV-6); command,
    target, executor, tool, recorder, and scorer are identical. now_fn
    is injected (default wall clock); verify_deterministic passes a fixed
    clock so k runs produce byte-identical records.

    Note: for B3/B4 the credential JWT's own iat/exp come from tokens.py's
    clock, not now_fn, so the JWT *bytes* differ run-to-run — but the
    records carry only decoded claims (actor/scope/chain) + the recorder's
    now_fn timestamp, so the RECORDS are byte-identical under a fixed clock.
    """
    credential = _credential_for(baseline)
    gt_log: list = []
    wrapped = make_recorder(siem_action, gt_log)

    claimed = _run_on_thread(
        _EXECUTOR,
        lambda: wrapped(_COMMAND, _TARGET, credential, now_fn=now_fn),
    )
    claimed_log = [claimed]
    triple = (claimed["command"], claimed["target"], claimed["timestamp"])
    result = score_ais(claimed_log, gt_log, frozenset({triple}))

    return {
        "baseline": baseline,
        "result": result,
        "claimed": claimed_log,
        "truth": gt_log,
    }


def verify_deterministic(
    baseline: str,
    k: int = 5,
    now_fn: Callable[[], float] | None = None,
) -> bool:
    """Run `baseline` k times under a fixed clock; assert all k runs
    produce byte-identical (claimed, truth) records.

    Returns True on success; raises AssertionError naming the baseline,
    run index, and first divergent field on failure.

    now_fn defaults to the module's fixed clock (lambda: _FIXED_TS).
    Exposed as a parameter so tests can inject a deliberately drifting
    clock to prove the check actually catches divergence.
    """
    if now_fn is None:

        def now_fn():
            return _FIXED_TS

    reference = run(baseline, now_fn=now_fn)

    for i in range(1, k):
        current = run(baseline, now_fn=now_fn)
        for side in ("claimed", "truth"):
            ref_records = reference[side]
            cur_records = current[side]
            assert len(ref_records) == len(cur_records), (
                f"{baseline} run {i}: {side} record count differs "
                f"({len(ref_records)} vs {len(cur_records)})"
            )
            for j, (ref_rec, cur_rec) in enumerate(zip(ref_records, cur_records)):
                for field in sorted(set(ref_rec) | set(cur_rec)):
                    assert ref_rec.get(field) == cur_rec.get(field), (
                        f"{baseline} run {i}: {side}[{j}][{field!r}] differs "
                        f"({ref_rec.get(field)!r} vs {cur_rec.get(field)!r})"
                    )
    return True


def is_non_monotonic(curve: dict) -> bool:
    """Verify the §6 headline finding on a curve produced by emit_curve.

    Concretely:
      - B2 > B1: per-agent identity beats shared account
      - B2 > B3: delegation REGRESSES attribution relative to per-agent identity
      - B4 == B3: tamper-evident logging is orthogonal to attribution (§6)

    Returns True if the curve matches the prediction; False otherwise.
    A False return is a publishable finding — INV-7 binds §6's pre-registered
    predictions to whatever the measurement shows; a contradicted prediction
    is reported, not silenced.

    v1 == B4 == B3 is exact because B4 currently runs B3's code path (same
    token, same execution) — byte-identical by construction. When the
    tamper-evident log module lands in v2 and B4 has a separate execution,
    this evolves to `abs(b4 - b3) < eps` for a small tolerance.
    """
    b1 = curve["B1"]["ais"]
    b2 = curve["B2"]["ais"]
    b3 = curve["B3"]["ais"]
    b4 = curve["B4"]["ais"]
    return b2 > b1 and b2 > b3 and b4 == b3


_CI_CAVEAT = (
    "Single-execution per baseline; pipeline is deterministic "
    "(see verify_deterministic). CI bounds are binomial on n=1, "
    "not a sampling CI from repeated trials."
)


def emit_curve(with_determinism_check: bool = True) -> dict:
    """Produce the §6 four-point curve as a JSON-serializable dict.

    Composes run() over B1-B4; optionally gates on verify_deterministic
    first (default True) so the curve is only emitted once determinism
    is a checked property, not a claim. A non-deterministic baseline
    raises AssertionError before any AIS values are produced.

    The ci_caveat string is part of the schema specifically so a
    downstream consumer that reads this dict and writes a report cannot
    omit the determinism disclosure — the caveat travels with the data.

    Non-monotonicity is NOT stored in this dict. The §6 claim is encoded
    as scorer.is_non_monotonic(curve), a named function with the
    predicate pinned in one docstring (single source of truth).
    """
    curve: dict = {}
    for baseline in ("B1", "B2", "B3", "B4"):
        if with_determinism_check:
            verify_deterministic(baseline)
        curve[baseline] = run(baseline)["result"]
    curve["ci_caveat"] = _CI_CAVEAT
    return curve
