"""
JWT sensitivity check — Slice E (threat-model-v3.md §7.4, §9 L14).

NON-LOCKED. The locked B8/B9 core runs Contain under an OPAQUE per-agent credential,
so ground truth carries `principal_chain = None` and the only field the attestation
source can move is the executor. A reviewer can object that this isolation
manufactures the result. This check rebuts that with data: re-run the SAME colluder
over a JWT base credential (which carries a real delegation chain) and show the
actor finding survives — B8 colluding still fails, B9 still recovers.

Reported, not locked: under the JWT base the colluder's false executor ALSO implies
a false chain, so B8 defects on actor AND principal_chain. The ACTOR remains the
load-bearing field — the opaque-cred result (actor-only) is the conservative core,
not a rigged simplification.

Determinism: the JWT's iat/exp use the wall clock, so the JWT *bytes* vary
run-to-run — but the SCORED records (actor/scope/chain) are deterministic. E is
non-locked, so this is intentional and never asserted byte-identical (the locked
determinism, §8.6, lives in the opaque-cred core).
"""

import pytest

from aegis_at_v3.harness.completion_sweep import run_cell

_JWT = {"base_credential": "jwt"}
_CONTAIN_CHAIN = ["agent:contain", "human:analyst"]


@pytest.mark.parametrize("baseline", ("B8", "B9"))
def test_jwt_honest_checkpoint(baseline):
    """Sanity (a §7.5 analogue for the JWT base): the honest column is still 1.0, so
    the JWT harness is correct before we read the colluding result — and the JWT base
    genuinely carries a delegation chain, unlike the opaque core."""
    cell = run_cell(baseline, seat="honest", **_JWT)
    assert cell["result"]["ais"] == 1.0
    assert cell["truth"][0]["true_principal_chain"] == _CONTAIN_CHAIN


def test_jwt_b8_colluding_finding_survives():
    """The rebuttal: under a chain-bearing JWT base, B8 colluding STILL fails — the
    actor finding is not an artifact of the opaque-credential `chain = None`
    isolation. GT carries a real chain here, and the actor is among the mismatches."""
    cell = run_cell("B8", seat="colluding", **_JWT)
    result = cell["result"]
    assert result["ais"] == 0.0
    # B8 read the completion's false executor, NOT the JWT's act.sub (which is contain)
    assert cell["audit"][0]["claimed_actor"] == "agent:enrich"
    assert "actor" in result["defects"][0]["mismatched_fields"]
    # INV-4 under JWT: GT still names the true executor, carries a real chain (not
    # None), and the false identity appears nowhere in it
    truth = cell["truth"][0]
    assert truth["true_actor"] == "agent:contain"
    assert truth["true_principal_chain"] == _CONTAIN_CHAIN
    assert "agent:enrich" not in str(list(truth.values()))


def test_jwt_b9_colluding_recovers():
    """Under the same JWT base, B9 still recovers to 1.0 — the verifier wins
    regardless of credential shape."""
    cell = run_cell("B9", seat="colluding", **_JWT)
    assert cell["result"]["ais"] == 1.0
    assert cell["audit"][0]["claimed_actor"] == "agent:contain"


def test_jwt_colluder_also_defects_on_chain_but_actor_is_load_bearing():
    """Reported, not locked: under JWT the false executor also implies a false chain,
    so the defect spans actor AND principal_chain — but the finding holds on the
    ACTOR alone, so the opaque-cred (actor-only) core is conservative, not rigged.
    Scope never moves: it is observed, never an agent claim."""
    mismatched = run_cell("B8", seat="colluding", **_JWT)["result"]["defects"][0][
        "mismatched_fields"
    ]
    # exact set: actor AND chain move under JWT; scope never does (it is observed).
    # The finding holds on the actor alone, so the opaque-cred core is conservative.
    assert mismatched == ["actor", "principal_chain"]
