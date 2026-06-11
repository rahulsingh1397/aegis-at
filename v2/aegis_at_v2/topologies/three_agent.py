"""
topologies/three_agent.py — T2, the v2 3-agent linear chain (§7).

Enrich -> Investigator -> Contain: two re-delegation hops. Investigator is
a mid-chain agent that receives Enrich's escalation, makes its own (correct)
judgment, and re-delegates containment onward; Contain still executes.

Why linear, not fan-in (§7.1): linear isolates the chain-DEPTH question —
does the attribution gap compound past one hop? Fan-in (two agents both
re-delegating into Contain) would add concurrent-write log-ordering
confounds outside the question v2 asks; deferred to v3.

The locked prediction (§7.2): the curve SHAPE is identical to T1
(B1=0, B2=1.0, B3=0, B4=0, B5=1.0). At B3/B4 the claimed actor is the
DEEPEST requester (Investigator) — still not the executor (Contain) — so
the gap PERSISTS at depth 2; it does not heal with depth, and the claimed
principal chain simply grows a hop ([investigator, enrich, analyst]). B5 is
topology-independent: Contain's own bound token is rooted directly at the
analyst regardless of the attack path's depth.
"""

from aegis_at_v2.topologies.base import Topology

THREE_AGENT = Topology(
    name="T2",
    redelegation_chain=("agent:enrich", "agent:investigator"),
    description=(
        "3-agent linear chain: Enrich -> Investigator -> Contain. Two "
        "re-delegation hops; claimed actor = investigator (deepest "
        "requester), true actor = contain. Tests whether the gap compounds "
        "at chain depth >= 2."
    ),
)
