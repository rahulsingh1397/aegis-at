"""B6 — mTLS certificate-bound baseline (threat-model-v3.0.1.md §A1, RFC 8705).

P3 comparative-breadth slice 1. B6 reads the executor identity from a per-agent
X.509 certificate bound to the token (`cnf.x5t#S256`) and VERIFIED AT ACCESS
(RFC 8705 §3). A colluding executor self-reports a false completion (Enrich)
exactly as in B8, but B6 ignores it and reads the cert-verified subject — the
colluder cannot present another agent's cert (§4.2). So B6 is INERT under the
colluder: predicted 1.0 / 1.0 (honest / colluding), locked in v3.0.1.

Why these encode intent (Rule 9):
  - the locked grid (1.0/1.0 on T1+T2) is the pre-registered prediction (INV-7);
  - B6's 1.0 must be EARNED by the cert verification, not structural — proven by
    the non-circularity controls (verification disabled → fail loud; degraded
    fallback to the self-report → 0.0), mirroring B9's §8.4 control;
  - the thumbprint is the REAL DER-cert x5t#S256 (RFC 8705 §3.1), not a JWK
    surrogate (the 4-agent review's fidelity correction);
  - the B8/B9 grid must stay byte-identical (the change is purely additive).
"""

import base64
import hashlib

import pytest

from cryptography import x509

from aegis_at_v3.auth import mtls
from aegis_at_v3.completion.completion_record import verify_signature
from aegis_at_v3.harness import adversary
from aegis_at_v3.harness.completion_sweep import (
    VerifiedEvidenceUnavailableError,
    emit_b6_grid,
    emit_b8_b9_grid,
    run_cell,
)

_TOPOLOGIES = ("T1", "T2")
_CONTAIN = "agent:contain"
_ENRICH = "agent:enrich"


# --- The mTLS primitive (auth/mtls.py) -------------------------------------


def test_certificate_is_deterministic():
    """§8.6: a fixed key + fixed serial + fixed validity + Ed25519 (RFC 8032)
    yield byte-identical DER run-to-run — so the x5t#S256 reproduces exactly."""
    assert mtls.agent_certificate_der(_CONTAIN) == mtls.agent_certificate_der(_CONTAIN)


def test_certificates_are_per_agent():
    """Each agent has a distinct cert and therefore a distinct thumbprint — the
    binding can actually distinguish executors (else B6 would be vacuous)."""
    der_c = mtls.agent_certificate_der(_CONTAIN)
    der_e = mtls.agent_certificate_der(_ENRICH)
    assert der_c != der_e
    assert mtls.x5t_s256(der_c) != mtls.x5t_s256(der_e)


def test_x5t_s256_is_the_real_der_thumbprint():
    """RFC 8705 §3.1: the thumbprint is base64url(SHA-256(DER cert)) — over the
    ACTUAL X.509 DER bytes, NOT a JWK surrogate (the review's fidelity fix). The
    DER parses as a real certificate, and the thumbprint matches a recompute."""
    der = mtls.agent_certificate_der(_CONTAIN)
    x509.load_der_x509_certificate(der)  # parses as a real X.509 cert (no raise)
    expected = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=")
    assert mtls.x5t_s256(der) == expected.decode("ascii")


def test_cert_subject_is_the_agent_identity():
    """The verified cert's subject CN is the L20 cert -> executor identity mapping."""
    assert mtls.cert_subject_agent(mtls.agent_certificate_der(_CONTAIN)) == _CONTAIN


def test_verify_cert_binding_accepts_matching_cert():
    """RFC 8705 §3 match: presenting the cert the token is bound to yields the
    verified subject identity."""
    der = mtls.agent_certificate_der(_CONTAIN)
    assert mtls.verify_cert_binding(der, mtls.token_cnf_for(_CONTAIN)) == _CONTAIN


def test_verify_cert_binding_rejects_mismatched_cert():
    """Active rejection (review Q6): presenting a DIFFERENT cert against a token
    bound to Contain fails the §3 match — the cert-layer analog of B5's DPoP lift
    rejection. The colluder cannot wield Contain's token with Enrich's cert."""
    der_enrich = mtls.agent_certificate_der(_ENRICH)
    with pytest.raises(mtls.CertBindingError):
        mtls.verify_cert_binding(der_enrich, mtls.token_cnf_for(_CONTAIN))


def test_unknown_agent_fails_loud():
    """No registered cert key for an unknown agent — raise, never default."""
    with pytest.raises(mtls.UnknownAgentError):
        mtls.agent_certificate_der("agent:ghost")


# --- B6 in the sweep --------------------------------------------------------


@pytest.mark.parametrize("topology", _TOPOLOGIES)
@pytest.mark.parametrize("seat", ("honest", "colluding"))
def test_b6_is_one_on_both_seats(seat, topology):
    """§A1/§A5 GATE: B6 = 1.0 on honest AND colluding, on T1 and T2. Inert under
    the colluder — the cert-verified identity overrides the self-report."""
    cell = run_cell("B6", seat=seat, topology=topology)
    assert cell["result"]["ais"] == 1.0, (
        f"B6/{seat}/{topology}: AIS {cell['result']['ais']} != 1.0 locked (§A1) "
        "— a contradiction is a FINDING (INV-7)"
    )
    assert cell["result"]["defects"] == []
    assert cell["audit"][0]["claimed_actor"] == _CONTAIN


@pytest.mark.parametrize("topology", _TOPOLOGIES)
def test_b6_grid_matches_locked_prediction(topology):
    """§A5 GATE: the measured B6 grid == the locked prediction (1.0 / 1.0) on T1
    and T2. A contradiction is a FINDING (INV-7), never coded around."""
    grid = emit_b6_grid(topology=topology)
    assert grid["B6"] == {
        "honest": 1.0,
        "colluding": 1.0,
    }, f"B6/{topology}: {grid['B6']} != locked 1.0/1.0 (threat-model-v3.0.1.md §A5)"


def test_b6_colluding_completion_is_a_valid_lie_but_inert():
    """INV-5 + inertness (§A4): under collusion the completion is a VALID
    self-report naming Enrich (signed under Contain's own key), yet B6 records
    Contain — because it reads the cert, not the completion. No component
    misbehaves; the lie is simply not the attribution source B6 uses."""
    cell = run_cell("B6", seat="colluding")
    completion = cell["completion"]
    assert verify_signature(completion, adversary.contain_public_key()) is True
    assert completion.asserted_executor == _ENRICH  # the lie is real...
    assert cell["audit"][0]["claimed_actor"] == _CONTAIN  # ...but B6 ignored it
    assert cell["truth"][0]["true_actor"] == _CONTAIN


def test_b6_fails_loud_when_verification_disabled():
    """Non-circularity (mirrors B9 §8.4): with the cert verification disabled,
    B6 must FAIL LOUD — never silently fall back to the self-report (which would
    make its 1.0 vacuous)."""
    with pytest.raises(VerifiedEvidenceUnavailableError):
        run_cell("B6", seat="colluding", verifier_enabled=False)


def test_b6_degraded_fallback_to_self_report_is_zero():
    """Non-circularity (mirrors B9 §8.4): if B6 silently fell back to the
    self-report when the cert verification is unavailable, the colluder's lie
    would win (AIS 0.0). This proves B6's 1.0 is EARNED by the cert verification,
    not structural. The degraded resolver is injected — production fails loud."""

    def degraded(verified_observed_actor, asserted_executor):
        # The dangerous silent fallback the production resolver REFUSES to do.
        return (
            asserted_executor
            if verified_observed_actor is None
            else verified_observed_actor
        )

    cell = run_cell(
        "B6", seat="colluding", verifier_enabled=False, evidence_resolver=degraded
    )
    assert cell["result"]["ais"] == 0.0
    assert cell["audit"][0]["claimed_actor"] == _ENRICH


def test_b6_is_byte_identical_across_runs():
    """§8.6 determinism: fixed clock + fixed keys → byte-identical (audit, truth,
    completion) across runs, including the colluding cell and the cert it binds."""
    a = run_cell("B6", seat="colluding")
    b = run_cell("B6", seat="colluding")
    assert a["audit"] == b["audit"]
    assert a["truth"] == b["truth"]
    assert a["completion"] == b["completion"]


@pytest.mark.parametrize("topology", _TOPOLOGIES)
def test_b6_addition_leaves_b8_b9_grid_byte_identical(topology):
    """The B6 addition is purely ADDITIVE (Agent 2): the locked B8/B9 grid must be
    unchanged. If this fails, B6 perturbed the locked core — a regression, not a
    finding."""
    grid = emit_b8_b9_grid(topology=topology)
    assert grid["B8"] == {"honest": 1.0, "colluding": 0.0}
    assert grid["B9"] == {"honest": 1.0, "colluding": 1.0}


def test_unknown_baseline_fails_loud():
    """run_cell rejects a baseline it does not know — no silent default (Rule 12)."""
    with pytest.raises(ValueError, match="unknown baseline"):
        run_cell("B99", seat="honest")
