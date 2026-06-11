"""
topologies/ — experimental topologies for the v2 sweep (threat-model-v2.md §7).

A topology declares the re-delegation chain depth for a sweep run; the sweep
builds tokens from the declaration (see harness/sweep.py:_delegated_chain).
T1 is v1's 2-agent chain (regression anchor); T2 is the 3-agent linear chain.

Public API:
    get_topology(name) -> Topology       resolve "T1"/"T2" (fail loud on unknown)
    all_topologies()  -> list[Topology]  every registered topology, name order
    TOPOLOGY_NAMES                        the registered names, for sweeps/params
"""

from aegis_at_v2.topologies.base import Topology
from aegis_at_v2.topologies.two_agent import TWO_AGENT
from aegis_at_v2.topologies.three_agent import THREE_AGENT

_REGISTRY: dict[str, Topology] = {
    TWO_AGENT.name: TWO_AGENT,
    THREE_AGENT.name: THREE_AGENT,
}

TOPOLOGY_NAMES: tuple[str, ...] = tuple(_REGISTRY)


def get_topology(name: str) -> Topology:
    """Resolve a topology by name. Raises ValueError on an unknown name
    (Rule 12: an unknown topology is an error, not a silent default)."""
    if name not in _REGISTRY:
        raise ValueError(
            f"unknown topology {name!r}; registered: {sorted(_REGISTRY)}"
        )
    return _REGISTRY[name]


def all_topologies() -> list[Topology]:
    """Every registered topology, in name order."""
    return [_REGISTRY[n] for n in sorted(_REGISTRY)]


__all__ = [
    "Topology",
    "TWO_AGENT",
    "THREE_AGENT",
    "get_topology",
    "all_topologies",
    "TOPOLOGY_NAMES",
]
