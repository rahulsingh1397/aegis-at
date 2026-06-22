"""B7 — A-JWT execution-assertion baseline (threat-model-v3.0.1.md §A2,
draft-goswami-agentic-jwt-00 / arXiv:2509.13597).

P3 comparative-breadth slice 2. B7 reads the executor identity from a signed
execution assertion (`executed_by` + a per-agent PoP key) VERIFIED AT EXECUTION
(A-JWT Anchor A6): the signature must verify under the key REGISTERED for the named
agent. A colluding executor self-reports a false completion (Enrich) exactly as in
B8, but B7 ignores it and reads the verified `executed_by` — the colluder cannot
sign an assertion as another agent (§4.2; A-JWT's T1 checksum-copy attack is
defeated by A6 PoP + A3, not the checksum). So B7 is INERT under the colluder:
predicted 1.0 / 1.0, locked in v3.0.1.

Why these encode intent (Rule 9):
  - the locked grid (1.0/1.0 on T1+T2) is the pre-registered prediction (INV-7);
  - the A6 ACTIVE REJECTION — an assertion naming a different agent than its signer
    is rejected — is the load-bearing fidelity test (the colluder cannot assert
    Enrich); this is why B7 recovers;
  - B7's 1.0 is EARNED by the assertion verification, not structural (the
    non-circularity controls), and it reads the verified assertion NOT ground truth
    (so it does not collapse into B9);
  - the locked B8/B9 grid AND the B6 grid stay byte-identical (purely additive).
"""

import pytest

from aegis_at_v3.completion import execution_assertion as ea
from aegis_at_v3.completion.completion_record import verify_signature
from aegis_at_v3.harness import adversary
from aegis_at_v3.harness.completion_sweep import (
    VerifiedEvidenceUnavailableError,
    emit_b6_grid,
    emit_b7_grid,
    emit_b8_b9_grid,
    run_cell,
)

_TOPOLOGIES = ("T1", "T2")
_CONTAIN = "agent:contain"
_ENRICH = "agent:enrich"
_ACTION = "act-isolate-host-42"


# --- The execution-assertion primitive (completion/execution_assertion.py) ---


def test_assertion_is_deterministic():
    """§8.6: fixed PoP key + Ed25519 (RFC 8032) → byte-identical signature."""
    a = ea.sign_execution_assertion(_ACTION, _CONTAIN, _CONTAIN)
    b = ea.sign_execution_assertion(_ACTION, _CONTAIN, _CONTAIN)
    assert a == b


def test_honest_assertion_verifies_to_its_executor():
    """A6: an assertion signed by its named agent's PoP key verifies, returning
    that agent — `executed_by` is VERIFIED, not self-asserted."""
    assertion = ea.sign_execution_assertion(_ACTION, _CONTAIN, _CONTAIN)
    assert ea.verify_execution_assertion(assertion) == _CONTAIN


def test_cross_agent_assertion_is_rejected():
    """A6 active rejection (the load-bearing fidelity test): an assertion naming
    ENRICH but signed with Contain's key does NOT verify — the colluder cannot
    assert another agent because it lacks that agent's PoP key (§4.2). This is the
    mechanism by which B7 recovers."""
    forged = ea.sign_execution_assertion(_ACTION, _ENRICH, _CONTAIN)
    with pytest.raises(ea.AssertionVerificationError):
        ea.verify_execution_assertion(forged)


def test_enrich_pop_key_is_distinct_from_contain():
    """The colluder (Contain) does not hold Enrich's registered PoP key — so it
    cannot mint a verifiable Enrich assertion (the basis of the §4.2 constraint)."""
    assert ea.registered_pop_public_key(_CONTAIN) != ea.registered_pop_public_key(
        _ENRICH
    )


def test_unknown_agent_fails_loud():
    """No registered PoP key for an unknown agent — raise, never default."""
    with pytest.raises(ea.UnknownAgentError):
        ea.sign_execution_assertion(_ACTION, "agent:ghost", "agent:ghost")


# --- B7 in the sweep --------------------------------------------------------


@pytest.mark.parametrize("topology", _TOPOLOGIES)
@pytest.mark.parametrize("seat", ("honest", "colluding"))
def test_b7_is_one_on_both_seats(seat, topology):
    """§A2/§A5 GATE: B7 = 1.0 on honest AND colluding, on T1 and T2. Inert under
    the colluder — the verified `executed_by` overrides the self-report."""
    cell = run_cell("B7", seat=seat, topology=topology)
    assert cell["result"]["ais"] == 1.0, (
        f"B7/{seat}/{topology}: AIS {cell['result']['ais']} != 1.0 locked (§A2) "
        "— a contradiction is a FINDING (INV-7)"
    )
    assert cell["result"]["defects"] == []
    assert cell["audit"][0]["claimed_actor"] == _CONTAIN


@pytest.mark.parametrize("topology", _TOPOLOGIES)
def test_b7_grid_matches_locked_prediction(topology):
    """§A5 GATE: the measured B7 grid == the locked prediction (1.0 / 1.0) on T1
    and T2. A contradiction is a FINDING (INV-7), never coded around."""
    grid = emit_b7_grid(topology=topology)
    assert grid["B7"] == {
        "honest": 1.0,
        "colluding": 1.0,
    }, f"B7/{topology}: {grid['B7']} != locked 1.0/1.0 (threat-model-v3.0.1.md §A5)"


def test_b7_colluding_completion_is_a_valid_lie_but_inert():
    """INV-5 + inertness (§A4): the completion validly self-reports Enrich (signed
    under Contain's own key), yet B7 records Contain — it reads the verified
    assertion, not the completion. No component misbehaves."""
    cell = run_cell("B7", seat="colluding")
    completion = cell["completion"]
    assert verify_signature(completion, adversary.contain_public_key()) is True
    assert completion.asserted_executor == _ENRICH  # the lie is real...
    assert cell["audit"][0]["claimed_actor"] == _CONTAIN  # ...but B7 ignored it
    assert cell["truth"][0]["true_actor"] == _CONTAIN


def test_b7_fails_loud_when_verification_disabled():
    """Non-circularity (mirrors B9 §8.4): with the assertion verification disabled,
    B7 must FAIL LOUD — never silently fall back to the self-report."""
    with pytest.raises(VerifiedEvidenceUnavailableError):
        run_cell("B7", seat="colluding", verifier_enabled=False)


def test_b7_degraded_fallback_to_self_report_is_zero():
    """Non-circularity (mirrors B9 §8.4): if B7 fell back to the self-report when
    the assertion verification is unavailable, the colluder's lie would win (AIS
    0.0). Proves B7's 1.0 is EARNED by the assertion verification. Injected
    control — production fails loud."""

    def degraded(verified_observed_actor, asserted_executor):
        return (
            asserted_executor
            if verified_observed_actor is None
            else verified_observed_actor
        )

    cell = run_cell(
        "B7", seat="colluding", verifier_enabled=False, evidence_resolver=degraded
    )
    assert cell["result"]["ais"] == 0.0
    assert cell["audit"][0]["claimed_actor"] == _ENRICH


def test_b7_is_byte_identical_across_runs():
    """§8.6 determinism: byte-identical (audit, truth, completion) across runs,
    including the colluding cell and the assertion it verifies."""
    a = run_cell("B7", seat="colluding")
    b = run_cell("B7", seat="colluding")
    assert a["audit"] == b["audit"]
    assert a["truth"] == b["truth"]
    assert a["completion"] == b["completion"]


@pytest.mark.parametrize("topology", _TOPOLOGIES)
def test_b7_addition_leaves_locked_grids_byte_identical(topology):
    """Purely ADDITIVE: B7 must not perturb the locked B8/B9 grid OR the B6 grid.
    A change here is a regression, not a finding."""
    b8b9 = emit_b8_b9_grid(topology=topology)
    assert b8b9["B8"] == {"honest": 1.0, "colluding": 0.0}
    assert b8b9["B9"] == {"honest": 1.0, "colluding": 1.0}
    assert emit_b6_grid(topology=topology)["B6"] == {"honest": 1.0, "colluding": 1.0}
