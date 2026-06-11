"""
topologies/base.py — the Topology value object (threat-model-v2.md §7).

A Topology is DATA, not code: it declares the re-delegation chain depth for
one experimental configuration. The sweep builds the actual tokens from
this declaration, so adding a topology is adding data (a hop list), never a
forked codebase (INV-6: baselines/topologies are config over one codebase).

The ONLY axis a topology varies is the re-delegation chain the orchestrator
mints for Baselines 3-4 — i.e. how many requesters sit between the human
principal and the executor. Baselines 1, 2, and 5 are topology-independent
by construction (opaque per-agent credential, or the executor's own bound
token rooted directly at the analyst), so the curve SHAPE is predicted
identical across topologies; only the B3/B4 claimed actor moves deeper
(§7.2).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Topology:
    """One experimental topology.

    Attributes:
        name: short id used in results and predictions ("T1", "T2").
        redelegation_chain: the actors the orchestrator nests, in request
            order from FIRST requester to DEEPEST requester. The deepest
            requester becomes the token's current actor (RFC 8693 §4.1) and
            therefore the claimed actor under B3/B4. The executor (Contain)
            is NOT in this list — it wields the token, it does not request
            it; that requester/executor divergence is the whole finding.
        description: human-readable note for the paper/results.
    """

    name: str
    redelegation_chain: tuple[str, ...]
    description: str

    def __post_init__(self) -> None:
        if not self.redelegation_chain:
            raise ValueError(
                f"topology {self.name!r}: redelegation_chain must have at "
                "least one requester hop"
            )

    @property
    def claimed_actor(self) -> str:
        """The current actor under B3/B4: the deepest (most-recent)
        requester (RFC 8693 §4.1). Never the executor (§7.2)."""
        return self.redelegation_chain[-1]

    @property
    def expected_claimed_chain(self) -> list[str]:
        """The claimed principal chain a B3/B4 token yields under this
        topology: current-actor first, root principal last. Equals
        actor_chain() of the minted token — exposed here so a test can
        assert the chain WITHOUT minting (a second source of truth for
        the §7.2 depth prediction)."""
        return [*reversed(self.redelegation_chain), "human:analyst"]
