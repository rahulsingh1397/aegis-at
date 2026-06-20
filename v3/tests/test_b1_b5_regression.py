"""
B1-B5 regression + MCP-transparency gate (MASTER_PLAN_v3 P1; mirrors
threat-model-v2.md §3.1 and threat-model-v3.md §7.1 B1-B5 / §7.4 inertness).

Two INDEPENDENT properties (note: test 1 does NOT route the v2 sweep through
MCPBoundary — it reproduces the inherited curve via import; test 2 separately
checks the MCP envelope is transparent to a credential):

1. CURVE REPRODUCTION (INV-6). The inherited v1/v2 curve reproduces when
   driven from v3 via import — B1=0, B2=1, B3=0, B4=0, B5=1 on every
   topology. v3 reuses v2's B1-B5 path byte-for-byte (it imports it), so the
   curve cannot move; if it does, the reuse wiring is wrong, not the result.

2. MCP TRANSPARENCY (§6.2/§6.3). The MCP transport envelope (slice 3) does
   not alter a B1-B5 credential: an audience-bound BoundToken returns its
   payload unchanged and carries no executor field. So the boundary cannot
   shift the curve — it only models the envelope the call crosses.
"""

from aegis_at_v2.harness.scorer import is_non_monotonic
from aegis_at_v2.harness.sweep import emit_curves
from aegis_at_v3.transport.mcp_adapter import BoundToken, MCPBoundary

# Locked B1-B5 prediction — threat-model-v2.md §3.1/§7.2; carried into
# threat-model-v3.md §7.1 (the "locked (v1/v2)" rows).
EXPECTED = {"B1": 0.0, "B2": 1.0, "B3": 0.0, "B4": 0.0, "B5": 1.0}


def test_inherited_curve_reproduces_on_every_topology():
    """B1-B5 reproduce the locked v2 curve when driven from v3 (regression).

    Determinism is v2's own gate (verify_deterministic); here we only assert
    the curve REPRODUCES, so with_determinism_check=False keeps the v3 gate
    fast (one run per baseline, not five).
    """
    curves = emit_curves(with_determinism_check=False)
    assert curves, "emit_curves returned no topologies"
    for topology, curve in curves.items():
        for baseline, expected in EXPECTED.items():
            ais = curve[baseline]["ais"]
            assert ais == expected, (
                f"{topology}/{baseline}: AIS {ais} != locked {expected} "
                "(regression: v3 reuse changed the v1/v2 curve)"
            )
        assert is_non_monotonic(curve), f"{topology}: non-monotonic shape lost"


def test_mcp_boundary_is_transparent_to_credentials():
    """The MCP envelope returns a wrapped credential unchanged and carries no
    executor identity (§6.2/§6.3) — so B1-B5 cannot move because of it.

    Note: accept_inbound returns the BoundToken (not a bool), so we check the
    returned token's payload is unchanged and that BoundToken carries no
    executor field.
    """
    siem = "siem_action"  # the audience B3/B4/B5 tokens are minted for
    boundary = MCPBoundary(siem)
    cred = "opaque-baseline-credential"
    accepted = boundary.accept_inbound(BoundToken(audience=siem, value=cred))
    assert accepted.value == cred
    assert set(BoundToken.__dataclass_fields__) == {"audience", "value"}
