"""
B9 non-circularity proof — Slice C (threat-model-v3.md §5.3, §8.4; review #5).

B9 reads its executor from the independent verifier, which shares the
process-boundary observation point with ground truth. §5.3 flags the risk that
this makes B9 = 1.0 *vacuous* — true by construction rather than because
verification works. §8.4 therefore REQUIRES a dedicated control: B9 must fail
(AIS < 1.0) if the verifier is disabled, or if the audit path falls back to the
self-reported `asserted_executor`.

This file is that control, exercised END-TO-END through the full colluding sweep
(not a unit test of the resolver `if`). The trio together proves B9's 1.0 is
EARNED by the verifier:
  - real verifier            -> AIS = 1.0 (audit names the TRUE executor)
  - verifier disabled        -> FAILS LOUD (never silently degrades to B8)
  - audit falls back to self -> AIS = 0.0 (the colluder wins)
"""

import pytest

from aegis_at_v3.harness.completion_sweep import VerifierUnavailableError, run_cell


def _degraded_resolver(attestation_source, asserted_executor, verifier_observed_actor):
    """The misimplementation §8.4 warns about: the audit falls back to the
    self-reported executor even though a verifier observation IS available. Used
    ONLY here, as the adversarial negative control — never in production."""
    return asserted_executor


def test_b9_earns_its_one_via_the_verifier():
    """Positive control: the SAME colluding completion, resolved by the real
    verifier, yields 1.0 with the audit naming the TRUE executor. The contrast
    with the two failures below is what makes B9's 1.0 non-vacuous (§5.3)."""
    cell = run_cell("B9", seat="colluding")
    assert cell["result"]["ais"] == 1.0
    assert cell["audit"][0]["claimed_actor"] == "agent:contain"


def test_b9_fails_loud_when_verifier_disabled():
    """§8.4 clause 1: with no verifier observation, production B9 RAISES — it does
    not silently fall back to the self-report (Rule 12). A silent fallback is the
    exact failure that would make B9 vacuous."""
    with pytest.raises(VerifierUnavailableError):
        run_cell("B9", seat="colluding", verifier_enabled=False)


def test_b9_fails_if_audit_falls_back_to_self_report():
    """§8.4 clause 2: if B9's audit path falls back to `asserted_executor` (even
    with a verifier present), the colluder wins — AIS drops to 0.0 on the actor
    alone. This proves B9's 1.0 comes from CONSULTING the verifier, not from the
    label or from sharing an observation source with ground truth."""
    cell = run_cell("B9", seat="colluding", audit_resolver=_degraded_resolver)
    result = cell["result"]
    assert result["ais"] == 0.0
    assert result["denominator"] == 1  # the action WAS scored (not missing)
    assert len(result["defects"]) == 1
    defect = result["defects"][0]
    assert defect["shape"] == "field_mismatch"
    assert defect["mismatched_fields"] == ["actor"]
    assert defect["claimed"]["claimed_actor"] == "agent:enrich"
    assert defect["truth"]["true_actor"] == "agent:contain"
