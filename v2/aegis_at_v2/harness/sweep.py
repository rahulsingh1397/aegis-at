"""
harness/sweep.py — baseline-switch harness, §6 curve (ported from v1).

v2 change from v1: the executor runs in a SUBPROCESS via the agent-process
kernel (`_run_in_subprocess` replaces v1's `_run_on_thread`); the recorder
resolves true_actor from the kernel's PID registry, not a thread name
(threat-model-v2.md §3). Everything else — credential shapes, command,
target, scorer — is the v1 design unchanged (INV-6: baselines are config
flags over one codebase).

Regression contract (threat-model-v2.md §3.1): the v1 curve B1=0, B2=1.0,
B3=0, B4=0 must reproduce under this harness. If it does not, the harness
is wrong — not the v1 result.
"""

import time
from typing import TypedDict, Callable

from aegis_at_v2.auth import dpop
from aegis_at_v2.auth.tokens import mint_initial_token
from aegis_at_v2.orchestrator.orchestrator import mint_delegated_token
from aegis_at_v2.tools.siem_action import siem_action
from aegis_at_v2.harness.recorder import make_recorder
from aegis_at_v2.harness.scorer import score_ais, score_lis, ScorerResult, LisResult
from aegis_at_v2.harness.tamper_log import TamperEvidentLog
from aegis_at_v2.harness import agent_proc
from aegis_at_v2.harness import agent_bodies
from aegis_at_v2.topologies import get_topology, TOPOLOGY_NAMES

# Only Baseline 4 ships a hash-chained, tamper-evident log (§6.1). Every
# other baseline writes a plain append-only log with no integrity artifact,
# so a post-hoc rewrite is undetectable (LIS = 0.0 by definition, §4.2).
_HASH_CHAINED_BASELINES = frozenset({"B4"})

# Canonical attack (locked, §5): Contain — the wielder — executes the
# high-consequence action. Only the credential differs across baselines.
_COMMAND = "isolate_host"
_TARGET = "host-42"
_EXECUTOR = "agent:contain"  # true executor; the kernel binds this to the child PID
_FIXED_TS = 1_700_000_000.0


class RunResult(TypedDict):
    baseline: str
    topology: str  # "T1" / "T2" — which re-delegation depth this run used
    result: ScorerResult
    claimed: list  # claimed action-log records
    truth: list  # ground-truth records
    # records (not just result) so
    # verify_deterministic can check
    # record-level determinism on B2,
    # which has no defects to embed them in.


def _delegated_chain(topology: str) -> str:
    """Build the unbound re-delegation token Contain presents under B3/B4.

    The chain DEPTH is data, declared by the topology (threat-model-v2.md
    §7); this function just mints one nested re-delegation per declared
    requester hop. The deepest requester becomes the current actor
    (RFC 8693 §4.1) and therefore the claimed actor:

      T1 (v1): [enrich] -> chain [enrich, analyst], claimed actor = enrich.
      T2:      [enrich, investigator] -> chain [investigator, enrich,
               analyst], claimed actor = investigator.

    In every topology the claimed actor is a REQUESTER, never the executor
    (Contain) — the gap does not heal with depth (§7.2). Adding a topology
    is adding a hop list under topologies/, not branching here (INV-6).
    """
    topo = get_topology(topology)
    token = mint_initial_token("human:analyst", "siem:read siem:write")
    for actor in topo.redelegation_chain:
        token = mint_delegated_token(
            token, actor, "siem:write", audience="siem_action"
        )
    return token


def _credential_for(baseline: str, now: float, replay_cache=None, topology: str = "T1"):
    """The per-baseline credential — the ONLY thing that varies (INV-6).

    Returns (credential, executor_body, body_extra_args):
    everything the executor subprocess needs to present a call.

    B1: shared opaque credential (all agents act under one identity).
    B2: per-agent opaque credential (executor authenticates as itself).
    B3/B4: orchestrator-minted re-delegation JWT — the orchestrator
        honestly names the deepest REQUESTER as current actor; Contain
        (the wielder) presents an UNBOUND token. Chain depth is set by
        `topology` (see _delegated_chain). B4 == B3 at minting;
        tamper-evidence is at the log boundary, not here (§6).
    B5: sender-constrained. The unbound chain cannot be wielded by Contain
        (the lift is rejected, §5.2), so Contain obtains its OWN token —
        bound to Contain's key, naming Contain, rooted directly at the
        analyst (its LEGITIMATE 2-hop chain, independent of the attack
        path's depth — so B5 is topology-independent, §7.2). The executor
        signs a DPoP proof at call time; claimed actor tracks the executor.
    """
    if baseline == "B1":
        cred = {"format": "apikey", "agent": "svc:soar", "scope": "siem:write"}
        return cred, agent_bodies.executor_body, ()
    if baseline == "B2":
        cred = {"format": "apikey", "agent": "agent:contain", "scope": "siem:write"}
        return cred, agent_bodies.executor_body, ()
    if baseline in ("B3", "B4"):
        cred = _delegated_chain(topology)
        return cred, agent_bodies.executor_body, ()
    if baseline == "B5":
        # The executor (Contain) holds its own DPoP key. It obtains a
        # token bound to that key by presenting a possession proof to the
        # orchestrator's token endpoint — so the orchestrator names
        # Contain (the requester of THIS exchange) as current actor.
        contain_key = dpop.DPoPKey()
        root = mint_initial_token("human:analyst", "siem:read siem:write")
        mint_proof = contain_key.create_proof(
            dpop.RESOURCE_HTM, dpop.TOKEN_ENDPOINT_HTU, now
        )
        cred = mint_delegated_token(
            root,
            "agent:contain",
            "siem:write",
            audience="siem_action",
            cnf=contain_key.jkt,
            proof=mint_proof,
            replay_cache=replay_cache,
            now=now,
        )
        # The executor subprocess rebuilds the key and signs the
        # call-time proof itself (its runtime possession evidence).
        return cred, agent_bodies.dpop_executor_body, (contain_key.private_pem, now)
    raise ValueError(f"unknown baseline {baseline!r} (expected B1-B5)")


def _run_in_subprocess(name: str, body, args: tuple, tool_handler) -> None:
    """Execute an agent body in a subprocess registered as `name`, so the
    recorder reads true_actor from the kernel's PID registry, not the
    token (INV-4). Replaces v1's _run_on_thread."""
    agent_proc.run_agent(name, body, args, tool_handler)


def run(
    baseline: str,
    now_fn: Callable[[], float] = time.time,
    executor_body=None,
    topology: str = "T1",
) -> RunResult:
    """Run one canonical execution of the §5 attack for `baseline`.

    Only the credential differs across baselines (INV-6); command,
    target, executor, tool, recorder, and scorer are identical. now_fn
    is injected (default wall clock) and stays in the PARENT process —
    the recorder stamps the timestamp at the harness, so determinism is
    independent of subprocess scheduling.

    topology (threat-model-v2.md §7) sets the re-delegation chain depth
    for B3/B4 (T1 = v1's 2-agent chain, T2 = 3-agent linear chain). B1,
    B2, and B5 are topology-independent by construction, so passing a
    topology changes only the B3/B4 claimed actor/chain — not the curve
    shape (§7.2). Default T1 keeps every v1-era caller unchanged.

    executor_body overrides the per-baseline default body (e.g. the §3.2
    spoof test swaps in the spoofing body); when None, the body chosen by
    _credential_for is used so each baseline runs the body it needs (B5
    must sign a DPoP proof, B1-B4 must not).

    Note: for B3/B4/B5 the credential JWT's own iat/exp come from
    tokens.py's clock, not now_fn, so the JWT *bytes* differ run-to-run —
    but the records carry only decoded claims (actor/scope/chain) + the
    recorder's now_fn timestamp, so the RECORDS are byte-identical under a
    fixed clock. The DPoP proof bytes also vary (random jti) but never
    enter a record either.
    """
    now = now_fn()
    # Per-run replay cache: B5 proofs are single-use; a fresh cache per run
    # means independent runs never collide, and a within-run replay (the
    # §5.4 test) is still caught. Held in the parent harness only.
    replay_cache = dpop.ReplayCache()

    credential, default_body, body_extra = _credential_for(
        baseline, now, replay_cache=replay_cache, topology=topology
    )
    body = executor_body if executor_body is not None else default_body

    gt_log: list = []
    recorder = make_recorder(siem_action, gt_log)
    claimed_log: list = []

    def tool_handler(true_actor, command, target, token, proof):
        record = recorder(
            true_actor,
            command,
            target,
            token,
            now_fn=now_fn,
            proof=proof,
            replay_cache=replay_cache,
        )
        claimed_log.append(record)
        return record

    _run_in_subprocess(
        _EXECUTOR,
        body,
        (_COMMAND, _TARGET, credential, *body_extra),
        tool_handler,
    )

    claimed = claimed_log[0]
    triple = (claimed["command"], claimed["target"], claimed["timestamp"])
    result = score_ais(claimed_log, gt_log, frozenset({triple}))

    return {
        "baseline": baseline,
        "topology": topology,
        "result": result,
        "claimed": claimed_log,
        "truth": gt_log,
    }


def _tamper_entry(entry: dict) -> dict:
    """Return a copy of `entry` with its claimed_actor flipped — a
    plausible post-hoc rewrite (an adversary hiding who acted). Used to
    inject a tamper the chain must catch. Pure: does not mutate input."""
    rewritten = dict(entry)
    rewritten["claimed_actor"] = "agent:enrich-rewritten"
    return rewritten


def measure_lis(
    baseline: str,
    entries: list[dict],
    tamper_indices: list[int] | None = None,
) -> LisResult:
    """Measure the Log Integrity Score for `baseline` (threat-model-v2.md
    §4.2 / §6.2).

    The harness writes `entries` to the baseline's log, then rewrites the
    entries at `tamper_indices` (default: the first entry) AFTER commit,
    and asks the log whether it can detect the rewrite.

    - Hash-chained baselines (B4): each entry is chained; the rewrite
      breaks the link at its index, so verify() flags it. LIS = 1.0.
    - All other baselines: a plain append-only log with no chain; the
      rewrite is silent. detected = [], LIS = 0.0 by definition (§4.2).

    The logger key (B4) is generated inside the log object, held only here
    in the parent harness — no agent or the orchestrator can sign a
    replacement head (§6.1).
    """
    if not entries:
        raise ValueError("measure_lis requires at least one entry to tamper")
    if tamper_indices is None:
        tamper_indices = [0]

    if baseline not in _HASH_CHAINED_BASELINES:
        # No integrity artifact: the rewrite happens and nothing notices.
        return score_lis(tamper_indices, detected_indices=[])

    log = TamperEvidentLog()
    for entry in entries:
        log.append(entry)
    head_sig = log.sign_head()

    # Post-hoc tamper: rewrite committed entries in place WITHOUT updating
    # their stored chain hash (an attacker editing the log file cannot
    # recompute the chain without breaking it — that is the whole point).
    for i in tamper_indices:
        log.entries[i] = _tamper_entry(log.entries[i])

    detected = log.verify(head_signature=head_sig)
    return score_lis(tamper_indices, detected_indices=detected)


def verify_deterministic(
    baseline: str,
    k: int = 5,
    now_fn: Callable[[], float] | None = None,
    topology: str = "T1",
) -> bool:
    """Run `baseline` k times under a fixed clock; assert all k runs
    produce byte-identical (claimed, truth) records.

    Returns True on success; raises AssertionError naming the baseline,
    run index, and first divergent field on failure.

    now_fn defaults to the module's fixed clock (lambda: _FIXED_TS).
    Exposed as a parameter so tests can inject a deliberately drifting
    clock to prove the check actually catches divergence. topology is
    threaded through so determinism is a checked property of T2 as well
    as T1 (the stochastic sweep, §8, relies on it for both).
    """
    if now_fn is None:

        def now_fn():
            return _FIXED_TS

    reference = run(baseline, now_fn=now_fn, topology=topology)

    for i in range(1, k):
        current = run(baseline, now_fn=now_fn, topology=topology)
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


_CI_CAVEAT = (
    "Single-execution per baseline; pipeline is deterministic "
    "(see verify_deterministic). CI bounds are binomial on n=1, "
    "not a sampling CI from repeated trials."
)


def emit_curve(with_determinism_check: bool = True, topology: str = "T1") -> dict:
    """Produce the five-point curve (B1-B5) for one topology as a
    JSON-serializable dict.

    Composes run() over B1-B5; optionally gates on verify_deterministic
    first (default True) so the curve is only emitted once determinism
    is a checked property, not a claim. A non-deterministic baseline
    raises AssertionError before any AIS values are produced.

    B5 (threat-model-v2.md §5) extends the v1 four-point curve: the
    sender-constraint layer hypothesized to recover attribution. topology
    (§7) selects the re-delegation depth; the predicted curve is identical
    across topologies (§7.2), which emit_curves() lets a caller verify.

    The ci_caveat string is part of the schema specifically so a
    downstream consumer that reads this dict and writes a report cannot
    omit the determinism disclosure — the caveat travels with the data.

    Non-monotonicity is NOT stored in this dict. The §6 claim is encoded
    as scorer.is_non_monotonic(curve), a named function with the
    predicate pinned in one docstring (single source of truth).
    """
    curve: dict = {"topology": topology}
    for baseline in ("B1", "B2", "B3", "B4", "B5"):
        if with_determinism_check:
            verify_deterministic(baseline, topology=topology)
        curve[baseline] = run(baseline, topology=topology)["result"]
    curve["ci_caveat"] = _CI_CAVEAT
    return curve


def emit_curves(with_determinism_check: bool = True) -> dict:
    """Produce the B1-B5 curve for every registered topology (T1, T2).

    Returns {topology_name: curve}. The §7.2 prediction is that all
    topologies yield the same curve shape (B1=0, B2=1.0, B3=0, B4=0,
    B5=1.0) — the gap does not heal with chain depth. A caller compares
    the curves; a divergence is a finding (INV-7), not something to
    reconcile silently.
    """
    return {
        name: emit_curve(with_determinism_check=with_determinism_check, topology=name)
        for name in TOPOLOGY_NAMES
    }


def emit_lis_curve(n_entries: int = 5) -> dict:
    """Produce the LIS curve across B1-B5 (threat-model-v2.md §6.2).

    Each baseline logs `n_entries` synthetic action records, one entry is
    rewritten post-commit, and LIS reports whether the rewrite is caught.
    Prediction: only B4 (hash-chained) detects it (LIS = 1.0); B1-B3, B5
    have no integrity artifact (LIS = 0.0).

    The synthetic entries differ per index (distinct target) so a rewrite
    is a genuine change, not a no-op that hashes identically.
    """
    entries = [
        {
            "claimed_actor": "agent:enrich",
            "claimed_scope": "siem:write",
            "command": "isolate_host",
            "target": f"host-{i}",
            "timestamp": _FIXED_TS + i,
        }
        for i in range(n_entries)
    ]
    return {b: measure_lis(b, entries) for b in ("B1", "B2", "B3", "B4", "B5")}
