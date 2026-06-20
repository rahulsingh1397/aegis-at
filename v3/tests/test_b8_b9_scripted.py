"""
B8/B9 scripted core — Slice A: the honest checkpoint
(threat-model-v3.md §7.5, §8.1).

INV-7 load-bearing checkpoint: BEFORE any colluder exists, the honest column must
read 1.0 on both baselines and both topologies. If it does not, the harness is
wrong, not the finding (§7.5). The colluder (B8 = 0.0), the full grid,
determinism, non-circularity (§8.4), and INV-4 (§8.5) land in Slices B-E.

Why these encode intent (Rule 9): honest B8 = 1.0 proves a self-reported
completion naming the TRUE executor is recorded correctly; honest B9 = 1.0 proves
the independent verifier agrees when there is nothing to lie about. Only against
this baseline is the colluder's B8 = 0.0 (Slice B) attributable to the
attestation source rather than a broken harness.
"""

import pytest

from aegis_at_v3.completion.completion_record import verify_signature
from aegis_at_v3.harness import adversary
from aegis_at_v3.harness.completion_sweep import run_cell

_TOPOLOGIES = ("T1", "T2")


@pytest.mark.parametrize("topology", _TOPOLOGIES)
@pytest.mark.parametrize("baseline", ("B8", "B9"))
def test_honest_checkpoint_is_one(baseline, topology):
    """§7.5/§8.1 HARD GATE: honest B8 AND honest B9 == 1.0 on T1 and T2."""
    cell = run_cell(baseline, seat="honest", topology=topology)
    assert cell["result"]["ais"] == 1.0, (
        f"{baseline} honest/{topology}: AIS {cell['result']['ais']} != 1.0 "
        "(harness is wrong, not the finding — §7.5)"
    )
    assert cell["result"]["defects"] == []


def test_audit_record_mirrors_ground_truth_shape():
    """The audit record mirrors the GT shape EXACTLY, so the only field the
    attestation source can move is the actor (the opaque-credential control,
    Agent-review #3). An invented chain or a different scope would make honest
    B8/B9 fail for the WRONG reason."""
    cell = run_cell("B8", seat="honest")
    audit = cell["audit"][0]
    truth = cell["truth"][0]
    assert audit["claimed_scope"] == truth["true_scope"]
    assert audit["claimed_principal_chain"] is None
    assert truth["true_principal_chain"] is None
    assert audit["claimed_actor"] == truth["true_actor"] == "agent:contain"


def test_honest_completion_signature_is_valid():
    """The honest completion verifies under Contain's own key — the crypto path
    is sound before the colluder (which will also sign validly, §4.2) arrives."""
    cell = run_cell("B8", seat="honest")
    completion = cell["completion"]
    assert verify_signature(completion, adversary.contain_public_key()) is True
    assert completion.asserted_executor == completion.attester_id == "agent:contain"
