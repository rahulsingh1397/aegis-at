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

Slice B adds the colluding seat, the locked grid (§7.1), determinism (§8.6), and
the action_id binding guard. (Slice A: the honest checkpoint, §7.5.)
"""

from __future__ import annotations

from aegis_at_v2.auth.tokens import mint_initial_token
from aegis_at_v2.harness import agent_bodies, agent_proc
from aegis_at_v2.harness.recorder import make_recorder
from aegis_at_v2.harness.scorer import score_ais
from aegis_at_v2.orchestrator.orchestrator import mint_delegated_token
from aegis_at_v2.policy.scope_map import scope_for_command
from aegis_at_v2.tools.siem_action import siem_action
from aegis_at_v2.topologies import TOPOLOGY_NAMES

from aegis_at_v3.auth import mtls
from aegis_at_v3.completion.completion_record import (
    SELF_REPORTED,
    TOOL_VERIFIED,
    VALID_SOURCES,
    sign_completion,
    verify_signature,
)
from aegis_at_v3.completion import execution_assertion
from aegis_at_v3.harness import adversary

# Canonical action (matches the v2 sweep; only the audit path is new).
_COMMAND = "isolate_host"
_TARGET = "host-42"
_EXECUTOR = adversary.CONTAIN  # the true executor; the kernel binds it to the PID
_ROOT = "human:analyst"  # the root principal (the JWT base credential's chain root)
_FIXED_TS = 1_700_000_000.0
# The id of the single scripted action a completion attests. The audit binds the
# completion to THIS action (a completion for another action must not be paired in
# by timestamp); a mismatch fails loud (Slice B adds the negative test).
_ACTION_ID = "act-isolate-host-42"
# Baselines run_cell knows (fail loud on any other — Rule 12). B8/B9 are the locked
# completion-attestation core; B6 (mTLS, §A1) and B7 (A-JWT execution assertion,
# §A2) are the P3 comparative-breadth additions.
_KNOWN_BASELINES = ("B6", "B7", "B8", "B9")


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


class VerifiedEvidenceUnavailableError(Exception):
    """B6/B7 (verified-evidence baselines) were asked to resolve an executor with
    no cert/assertion observation. Fail loud (Rule 12): silently falling back to
    the self-report would make their 1.0 vacuous — the same non-circularity guard
    as B9 (threat-model-v3.0.1.md §A1/§A2 caveats; §8.4)."""


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
    if attestation_source == SELF_REPORTED:
        return asserted_executor  # B8: trust the self-report
    raise ValueError(
        f"unknown attestation_source {attestation_source!r}; "
        f"must be one of {sorted(VALID_SOURCES)} (no silent default)"
    )


def resolve_via_verified_evidence(
    verified_observed_actor: str | None,
    asserted_executor: str,
) -> str:
    """B6/B7: resolve the audit's claimed executor from INDEPENDENTLY VERIFIED
    evidence — the cert subject (B6) or the verified execution assertion (B7) — NOT
    from the recorder (that is B9) and NOT from the self-report (that is B8). FAIL
    LOUD if the verification is absent. The non-circularity control injects a
    degraded resolver that falls back to ``asserted_executor``, proving the 1.0 is
    EARNED by the verification (mirrors B9's Slice-C control)."""
    if verified_observed_actor is None:
        raise VerifiedEvidenceUnavailableError(
            "B6/B7 require an independent verified-evidence observation "
            "(cert/assertion); none was supplied (threat-model-v3.0.1.md §A1/§A2)"
        )
    return verified_observed_actor


def _base_credential(base_credential: str):
    """The execution (access-control) credential Contain presents — the ONLY thing
    Slice E varies. "apikey" is the opaque per-agent credential of the locked B8/B9
    core (GT chain = None); "jwt" is a delegated token naming Contain (GT chain =
    [contain, root]), used by the Slice E sensitivity check to show the actor
    finding survives a chain-bearing credential. Either way the executor is Contain
    and the action genuinely runs; the audit path is unchanged."""
    if base_credential == "apikey":
        return {"format": "apikey", "agent": _EXECUTOR, "scope": "siem:write"}
    if base_credential == "jwt":
        root = mint_initial_token(_ROOT, "siem:read siem:write")
        return mint_delegated_token(
            root, _EXECUTOR, "siem:write", audience="siem_action"
        )
    raise ValueError(
        f"unknown base_credential {base_credential!r} (expected 'apikey'/'jwt')"
    )


def _execute(now_fn, base_credential: str) -> list:
    """Run the canonical action as Contain, reusing the v2 kernel + recorder.
    Returns the ground-truth log; ground truth is written from the OS PID registry
    (INV-4), never from the credential — for either base credential."""
    cred = _base_credential(base_credential)
    gt_log: list = []
    recorder = make_recorder(siem_action, gt_log)

    def tool_handler(true_actor, command, target, token, proof):
        return recorder(true_actor, command, target, token, now_fn=now_fn, proof=proof)

    agent_proc.run_agent(
        _EXECUTOR, agent_bodies.executor_body, (_COMMAND, _TARGET, cred), tool_handler
    )
    return gt_log


def _build_audit_record(
    claimed_actor: str,
    command: str,
    target: str,
    timestamp: float,
    principal_chain,
) -> dict:
    """Build the audit record scored against ground truth, mirroring the GT shape
    EXACTLY so the only field the attestation source can move is the actor:
      - claimed_scope: from the OBSERVED command (the verifier's own observation,
        not an agent-supplied field) — always matches true_scope.
      - claimed_principal_chain: mirrors the GT chain SHAPE for the resolved actor —
        None under the opaque credential (the locked core), or [claimed_actor, root]
        under the JWT base (Slice E), so honest cells match and a colluder's false
        executor also implies a false chain.
    """
    return {
        "claimed_actor": claimed_actor,
        "claimed_scope": scope_for_command(command),
        "claimed_principal_chain": principal_chain,
        "command": command,
        "target": target,
        "timestamp": timestamp,
    }


def run_cell(
    baseline: str,
    *,
    seat: str = "honest",
    topology: str = "T1",
    now_fn=None,
    verifier_enabled: bool = True,
    completion_action_id: str | None = None,
    audit_resolver=resolve_claimed_actor,
    evidence_resolver=resolve_via_verified_evidence,
    base_credential: str = "apikey",
    asserted_executor_override: str | None = None,
) -> dict:
    """Run one baseline cell for one adversary `seat`; return its AIS result + records.

    baseline in {"B6", "B7", "B8", "B9"}; seat in {"honest", "colluding"}.
    `topology` is threaded as a LABEL only: the opaque-credential audit path is
    topology-independent by construction (no re-delegation chain), so B8/B9 are
    identical on T1 and T2 (§7.1) — the grid test asserts this. `verifier_enabled`
    and the fixed clock support the Slice C control and §8.6 determinism.
    `completion_action_id` is a test hook for the wrong-action_id negative test;
    production callers leave it None so the completion binds to the executed action.
    `audit_resolver` is the B8/B9 non-circularity test seam (Slice C): production
    uses `resolve_claimed_actor`; the §8.4 control injects a degraded resolver that
    falls back to `asserted_executor` to prove B9's 1.0 is earned by the verifier.
    `evidence_resolver` is the analogous seam for B6 (and B7): production uses
    `resolve_via_verified_evidence`; the degraded control falls back to the
    self-report to prove B6's 1.0 is earned by the cert verification.
    `base_credential` selects Contain's execution credential — "apikey" (the locked
    B8/B9 core, GT chain None) or "jwt" (Slice E sensitivity, GT chain-bearing).
    `asserted_executor_override` (B8/B9 only; raises otherwise) replaces the scripted
    seat's asserted_executor with an externally supplied value — the Tier-2 LLM seat
    (Harness_Notes/llm_seat_v3.md); None keeps the scripted path byte-for-byte.
    """
    if topology not in TOPOLOGY_NAMES:
        raise ValueError(
            f"unknown topology {topology!r}; must be one of "
            f"{sorted(TOPOLOGY_NAMES)} — the opaque-credential path is "
            "topology-inert, but the label must name a real registered topology "
            "(§7.1 'identical on T1 and T2')"
        )
    if baseline not in _KNOWN_BASELINES:
        raise ValueError(
            f"unknown baseline {baseline!r}; expected one of {_KNOWN_BASELINES} "
            "(B8/B9 = completion attestation source; B6 = mTLS cert-bound, §A1; "
            "B7 = A-JWT execution assertion, §A2)"
        )
    if now_fn is None:

        def now_fn():
            return _FIXED_TS

    # 1. EXECUTE (reuse v2; ground truth from the PID registry, INV-4).
    gt_log = _execute(now_fn, base_credential)
    gt = gt_log[0]

    # 2. ATTEST. B8/B9 carry the baseline's own attestation source; B6/B7 face the
    #    SAME self-reported lie B8 does (the colluder self-reports Enrich) but read
    #    identity from independently VERIFIED evidence, so the lie is inert (§A1/§A4).
    source = (
        attestation_source_for(baseline) if baseline in ("B8", "B9") else SELF_REPORTED
    )
    if asserted_executor_override is not None:
        if baseline not in ("B8", "B9"):
            raise ValueError(
                f"asserted_executor_override is B8/B9-only (the Tier-2 LLM seat); "
                f"got baseline {baseline!r}"
            )
        completion = sign_completion(
            completion_action_id or _ACTION_ID,
            asserted_executor_override,
            source,
            adversary.CONTAIN,
            adversary.contain_private_key(),
        )
    else:
        completion = adversary.make_completion(
            seat, source, completion_action_id or _ACTION_ID
        )

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

    # 3. RESOLVE the audit actor by baseline. B8 reads the self-report; B9 reads the
    #    recorder's process-boundary observation; B6 reads the INDEPENDENTLY VERIFIED
    #    cert subject — never the recorder (that is B9) and never the self-report
    #    (that is B8) — so the colluder's lie is inert (§A1/§A4). verifier_enabled=
    #    False models disabled verification (the non-circularity control).
    if baseline in ("B8", "B9"):
        verifier_observed_actor = gt["true_actor"] if verifier_enabled else None
        claimed_actor = audit_resolver(
            source, completion.asserted_executor, verifier_observed_actor
        )
    elif baseline == "B6":  # mTLS, RFC 8705: the executor presents its OWN cert;
        # the token is bound to that cert's x5t#S256. verify_cert_binding does the
        # §3 match AND returns the verified subject. The colluder cannot present
        # another agent's cert (§4.2), so the verified identity is the true executor.
        cert_observed_actor = (
            mtls.verify_cert_binding(
                mtls.agent_certificate_der(_EXECUTOR),
                mtls.token_cnf_for(_EXECUTOR),
            )
            if verifier_enabled
            else None
        )
        claimed_actor = evidence_resolver(
            cert_observed_actor, completion.asserted_executor
        )
    else:  # B7 (A-JWT): the executor emits an execution assertion signed by its OWN
        # PoP key; verify_execution_assertion checks the signature against the key
        # REGISTERED for executed_by and returns it (A6). The colluder cannot sign as
        # another agent (§4.2), so the verified executed_by is the true executor.
        assertion_observed_actor = (
            execution_assertion.verify_execution_assertion(
                execution_assertion.sign_execution_assertion(
                    _ACTION_ID, _EXECUTOR, _EXECUTOR
                )
            )
            if verifier_enabled
            else None
        )
        claimed_actor = evidence_resolver(
            assertion_observed_actor, completion.asserted_executor
        )

    # 4. SCORE (reuse the v2 scorer byte-for-byte). The audit chain mirrors the GT
    #    chain SHAPE for the resolved actor: None for the opaque credential, or
    #    [claimed_actor, root] for the JWT base (Slice E) — so the only field the
    #    attestation source moves under the opaque core is still the actor.
    audit_chain = None if base_credential == "apikey" else [claimed_actor, _ROOT]
    audit = _build_audit_record(
        claimed_actor, gt["command"], gt["target"], gt["timestamp"], audit_chain
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


def emit_b8_b9_grid(topology: str = "T1", now_fn=None) -> dict:
    """The B8/B9 AIS grid for one topology (threat-model-v3.md §7.1).

    Returns {"topology": t,
             "B8": {"honest": ais, "colluding": ais},
             "B9": {"honest": ais, "colluding": ais}}.

    Composes run_cell over the 2x2 (baseline x seat) grid. The gate asserts this
    equals the LOCKED prediction (B8 = 1.0/0.0, B9 = 1.0/1.0) on T1 and T2; a
    contradiction is a FINDING (INV-7), never coded around.
    """
    grid: dict = {"topology": topology}
    for baseline in ("B8", "B9"):
        grid[baseline] = {
            seat: run_cell(baseline, seat=seat, topology=topology, now_fn=now_fn)[
                "result"
            ]["ais"]
            for seat in ("honest", "colluding")
        }
    return grid


def emit_b6_grid(topology: str = "T1", now_fn=None) -> dict:
    """The B6 (mTLS, RFC 8705) AIS grid for one topology.

    Returns {"topology": t, "B6": {"honest": ais, "colluding": ais}}.

    The gate asserts this == the LOCKED prediction (B6 = 1.0 / 1.0,
    threat-model-v3.0.1.md §A1/§A5) on T1 and T2; a contradiction is a FINDING
    (INV-7), never coded around. B6 is inert under the colluder: the cert-verified
    identity overrides the self-reported lie.
    """
    return {
        "topology": topology,
        "B6": {
            seat: run_cell("B6", seat=seat, topology=topology, now_fn=now_fn)["result"][
                "ais"
            ]
            for seat in ("honest", "colluding")
        },
    }


def emit_b7_grid(topology: str = "T1", now_fn=None) -> dict:
    """The B7 (A-JWT execution assertion) AIS grid for one topology.

    Returns {"topology": t, "B7": {"honest": ais, "colluding": ais}}.

    The gate asserts this == the LOCKED prediction (B7 = 1.0 / 1.0,
    threat-model-v3.0.1.md §A2/§A5) on T1 and T2; a contradiction is a FINDING
    (INV-7), never coded around. B7 is inert under the colluder: the verified
    execution assertion (PoP-bound executed_by) overrides the self-reported lie.
    """
    return {
        "topology": topology,
        "B7": {
            seat: run_cell("B7", seat=seat, topology=topology, now_fn=now_fn)["result"][
                "ais"
            ]
            for seat in ("honest", "colluding")
        },
    }
