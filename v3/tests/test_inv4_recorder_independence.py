"""
INV-4 — ground-truth independence, end-to-end (threat-model-v3.md §8.5; review #5).

INV-4: the ground-truth recorder observes the executing PROCESS and must NEVER
read identity from a token, an `act` claim, or any agent-supplied field. v3 adds a
completion record carrying a (possibly false) `asserted_executor`; the strongest
test of INV-4 is that this field — even under collusion, where it names
`agent:enrich` — never reaches ground truth.

End-to-end across every cell (baseline x seat x topology): the recorder names the
TRUE executor and each ground-truth record carries EXACTLY the recorder's own
schema — no completion field, no `act` claim, no agent-supplied identity.
"""

import itertools

import pytest

from aegis_at_v3.harness.completion_sweep import run_cell

# The recorder's own ground-truth schema (v2 harness/recorder.py) — the ONLY keys
# a ground-truth record may carry. Anything else (a completion field, an `act`
# claim, an agent-supplied identity under any key) is an INV-4 violation. If the
# recorder schema legitimately changes, do NOT blindly extend this set — audit the
# new field for INV-4 first (it must not carry agent-supplied identity).
_GT_KEYS = frozenset(
    {
        "true_actor",
        "true_scope",
        "true_principal_chain",
        "command",
        "target",
        "timestamp",
    }
)

_CELLS = list(itertools.product(("B8", "B9"), ("honest", "colluding"), ("T1", "T2")))


@pytest.mark.parametrize("baseline,seat,topology", _CELLS)
def test_recorder_independent_of_completion(baseline, seat, topology):
    """§8.5/INV-4 on every cell: the recorder observes the TRUE executor and the
    ground-truth record carries no completion field — even under collusion, where
    the completion asserts `agent:enrich`."""
    cell = run_cell(baseline, seat=seat, topology=topology)
    truth = cell["truth"]
    assert len(truth) == 1
    record = truth[0]
    # the recorder observed the executing PROCESS, not the (possibly false) claim
    assert record["true_actor"] == "agent:contain"
    # ground truth is EXACTLY the recorder's own schema: no completion field
    # (asserted_executor / attester_id / attestation_source / signature), no `act`
    # claim, no agent-supplied identity under any key — §8.5's three exclusions
    assert set(record) == _GT_KEYS
    # and the colluder's false executor appears nowhere in ground truth — scanned
    # via str() so it is caught even if smuggled into a populated field (e.g. the
    # principal chain a JWT base credential carries in Slice E), not just top-level
    assert not any("agent:enrich" in str(v) for v in record.values())


def test_collusion_diverges_audit_from_ground_truth():
    """The sharpest INV-4 statement: in ONE B8 colluding cell, the audit names the
    false executor (`agent:enrich`, trusted by B8) while ground truth
    independently names the true one (`agent:contain`). The completion cannot move
    the recorder."""
    cell = run_cell("B8", seat="colluding")
    assert cell["audit"][0]["claimed_actor"] == "agent:enrich"  # the lie B8 trusts
    assert cell["truth"][0]["true_actor"] == "agent:contain"  # the independent truth


def test_inv4_assertion_catches_a_leak():
    """Non-vacuity guard: prove the parametrized test's checks would catch a real
    INV-4 regression, using the SAME checks (schema pin + `str()` value scan). Two
    leak shapes — a new completion key, and the lie smuggled into the EXISTING
    `true_actor` field — so neither the schema pin nor the value scan is vacuous."""
    real = run_cell("B8", seat="colluding")["truth"][0]

    # Shape 1 — a new completion field key: the exact-schema check rejects it.
    new_key = {**real, "asserted_executor": "agent:enrich"}
    assert set(new_key) != _GT_KEYS
    assert any("agent:enrich" in str(v) for v in new_key.values())

    # Shape 2 — the lie smuggled into an EXISTING key: the schema pin passes, but
    # the true_actor pin and the value scan still catch it.
    same_key = {**real, "true_actor": "agent:enrich"}
    assert set(same_key) == _GT_KEYS
    assert same_key["true_actor"] != "agent:contain"
    assert any("agent:enrich" in str(v) for v in same_key.values())
