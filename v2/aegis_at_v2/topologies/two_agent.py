"""
topologies/two_agent.py — T1, the v1 2-agent topology (kept for regression).

Enrich requests, Contain executes: a single re-delegation hop. This is the
topology v1 measured; v2 keeps it unchanged as the §3.1 / §7.3 regression
anchor — the v1 curve B1=0, B2=1.0, B3=0, B4=0 must reproduce on T1 under
the v2 substrate, or the substrate (not the v1 result) is wrong.
"""

from aegis_at_v2.topologies.base import Topology

TWO_AGENT = Topology(
    name="T1",
    redelegation_chain=("agent:enrich",),
    description=(
        "v1 baseline: Enrich (the requester) re-delegates containment; "
        "Contain (the executor) wields the token. One re-delegation hop; "
        "claimed actor = enrich, true actor = contain."
    ),
)
