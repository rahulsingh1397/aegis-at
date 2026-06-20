"""
harness/completion_sweep.py — the B8/B9 completion-attestation sweep
(threat-model-v3.md §5, §7.1). EXTENDS the v2 sweep by IMPORT (INV-6): it reuses
v2's process kernel, recorder, tool, and scorer byte-for-byte and adds ONLY the
completion-record audit layer.

The measurement (one action, two defenses, a swappable seat):
  1. EXECUTE  Contain runs the canonical action under an OPAQUE per-agent
     credential (B2-shaped), via the v2 process kernel. The recorder writes
     ground truth from the OS PID registry (INV-4) — never a token or completion
     field. The opaque credential is a deliberate control: ground truth carries
     `principal_chain = None` and `scope` is observed, so the ONLY field the
     attestation source can move is the executor identity (`claimed_actor`).
  2. ATTEST   the adversary adapter (adversary.py) emits a signed completion
     record naming the executor (honest: Contain; colluding [Slice B]: Enrich).
  3. RESOLVE  the audit's `claimed_actor` is read by attestation source:
       B8 self_reported -> the completion's asserted_executor (trust self-report)
       B9 tool_verified -> the independent verifier's observation (the recorder)
  4. SCORE    score_ais(audit, ground_truth) — reused byte-for-byte.

Non-circularity (§5.3/§8.4): B9's verifier observation and ground truth share the
independent process-boundary observation point, but neither reads a token or
agent-supplied field. B9's 1.0 is shown to be EARNED (not vacuous) by the
Slice C control. Production B9 FAILS LOUD if the verifier observation is absent —
it never silently degrades into B8 (Rule 12).

Slice A (this commit): the HONEST seat + the load-bearing checkpoint (§7.5).
"""

from __future__ import annotations

from aegis_at_v2.harness import agent_bodies, agent_proc
from aegis_at_v2.harness.recorder import make_recorder
from aegis_at_v2.harness.scorer import score_ais
from aegis_at_v2.policy.scope_map import scope_for_command
from aegis_at_v2.tools.siem_action import siem_action

from aegis_at_v3.completion.completion_record import (
    SELF_REPORTED,
    TOOL_VERIFIED,
    verify_signature,
)
from aegis_at_v3.harness import adversary

# Canonical action (matches the v2 sweep; only the audit path is new).
_COMMAND = "isolate_host"
_TARGET = "host-42"
_EXECUTOR = adversary.CONTAIN  # the true executor; the kernel binds it to the PID
_FIXED_TS = 1_700_000_000.0
# The id of the single scripted action a completion attests. The audit binds the
# completion to THIS action (a completion for another action must not be paired in
# by timestamp); a mismatch fails loud (Slice B adds the negative test).
_ACTION_ID = "act-isolate-host-42"


class VerifierUnavailableError(Exception):
    """B9 (tool_verified) was asked to resolve an executor with no independent
    verifier observation. Fail loud (Rule 12): a real B9 audit MUST consult the
    verifier; silently falling back to the self-report would degrade B9 into B8
    and make its 1.0 vacuous (threat-model-v3.md §5.3/§8.4)."""


class CompletionBindingError(Exception):
    """A completion record does not attest the executed action (its action_id
    differs). Fail loud: an unbound completion must never be scored as this
    action's attestation."""


class InvalidCompletionSignatureError(Exception):
    """A completion's signature does not verify under the attester's key. In the
    scripted core every seat signs with Contain's own valid key, so this is a
    harness bug, not an adversary capability (§4.2 forbids cross-key forgery)."""


def attestation_source_for(baseline: str) -> str:
    """B8 -> self_reported, B9 -> tool_verified (threat-model-v3.md §3.1)."""
    if baseline == "B8":
        return SELF_REPORTED
    if baseline == "B9":
        return TOOL_VERIFIED
    raise ValueError(f"unknown completion baseline {baseline!r} (expected B8/B9)")


def resolve_claimed_actor(
    attestation_source: str,
    asserted_executor: str,
    verifier_observed_actor: str | None,
) -> str:
    """Resolve the audit record's claimed executor by attestation source (§3.1).

    B8 (self_reported): trust the executor's self-asserted completion.
    B9 (tool_verified): use the INDEPENDENT verifier's observation; FAIL LOUD if
    it is absent (VerifierUnavailableError) — never silently fall back to the
    self-report (Rule 12; the non-circularity guard, §5.3/§8.4). The Slice C
    control exercises the degraded fallback explicitly to prove B9's 1.0 is
    earned, not vacuous.
    """
    if attestation_source == TOOL_VERIFIED:
        if verifier_observed_actor is None:
            raise VerifierUnavailableError(
                "B9 (tool_verified) requires an independent verifier observation; "
                "none was supplied (threat-model-v3.md §5.3/§8.4)"
            )
        return verifier_observed_actor
    return asserted_executor  # SELF_REPORTED (B8)


def _execute(now_fn) -> list:
    """Run the canonical action as Contain under an opaque per-agent credential,
    reusing the v2 kernel + recorder. Returns the ground-truth log; ground truth
    is written from the OS PID registry (INV-4), never from the credential."""
    cred = {"format": "apikey", "agent": _EXECUTOR, "scope": "siem:write"}
    gt_log: list = []
    recorder = make_recorder(siem_action, gt_log)

    def tool_handler(true_actor, command, target, token, proof):
        return recorder(true_actor, command, target, token, now_fn=now_fn, proof=proof)

    agent_proc.run_agent(
        _EXECUTOR, agent_bodies.executor_body, (_COMMAND, _TARGET, cred), tool_handler
    )
    return gt_log


def _build_audit_record(
    claimed_actor: str, command: str, target: str, timestamp: float
) -> dict:
    """Build the audit record scored against ground truth, mirroring the GT shape
    EXACTLY so the only field the attestation source can move is the actor:
      - claimed_scope: from the OBSERVED command (the verifier's own observation,
        not an agent-supplied field) — always matches true_scope.
      - claimed_principal_chain: None — the opaque-credential audit carries no
        delegation chain (matches the recorder's None for apikey credentials).
    """
    return {
        "claimed_actor": claimed_actor,
        "claimed_scope": scope_for_command(command),
        "claimed_principal_chain": None,
        "command": command,
        "target": target,
        "timestamp": timestamp,
    }


def run_cell(
    baseline: str,
    seat: str = "honest",
    topology: str = "T1",
    now_fn=None,
    verifier_enabled: bool = True,
) -> dict:
    """Run one B8/B9 cell for one adversary `seat`; return its AIS result + records.

    baseline in {"B8", "B9"}; seat in {"honest"} (Slice A; "colluding" in Slice B).
    `topology` is threaded as a LABEL only: the opaque-credential audit path is
    topology-independent by construction (no re-delegation chain), so B8/B9 are
    identical on T1 and T2 (§7.1) — the grid test asserts this. `verifier_enabled`
    and the fixed clock support the Slice C control and §8.6 determinism.
    """
    if now_fn is None:

        def now_fn():
            return _FIXED_TS

    # 1. EXECUTE (reuse v2; ground truth from the PID registry, INV-4).
    gt_log = _execute(now_fn)
    gt = gt_log[0]

    # 2. ATTEST (Slice A: honest seat only).
    source = attestation_source_for(baseline)
    completion = adversary.make_completion(seat, source, _ACTION_ID)

    # The completion must attest THE executed action, and its signature must
    # verify under the attester's own key — both fail loud otherwise.
    if completion.action_id != _ACTION_ID:
        raise CompletionBindingError(
            f"completion attests {completion.action_id!r}, not the executed "
            f"action {_ACTION_ID!r}"
        )
    if not verify_signature(completion, adversary.contain_public_key()):
        raise InvalidCompletionSignatureError(
            "completion signature does not verify under Contain's key"
        )

    # 3. RESOLVE the audit actor by attestation source. The verifier observation
    #    is the recorder's independent process-boundary observation (INV-4-clean);
    #    verifier_enabled=False models a disabled verifier (the Slice C control).
    verifier_observed_actor = gt["true_actor"] if verifier_enabled else None
    claimed_actor = resolve_claimed_actor(
        source, completion.asserted_executor, verifier_observed_actor
    )

    # 4. SCORE (reuse the v2 scorer byte-for-byte).
    audit = _build_audit_record(
        claimed_actor, gt["command"], gt["target"], gt["timestamp"]
    )
    triple = (audit["command"], audit["target"], audit["timestamp"])
    result = score_ais([audit], gt_log, frozenset({triple}))

    return {
        "baseline": baseline,
        "seat": seat,
        "topology": topology,
        "result": result,
        "audit": [audit],
        "truth": gt_log,
        "completion": completion,
    }
