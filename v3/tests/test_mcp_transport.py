"""
MCP-shaped transport boundary tests (threat-model-v3.md §6).

These pin the two rules the v3 result depends on — RFC 8707 audience binding and
token-passthrough-forbidden (source-lock-v3.md §A4) — and document that the
transport conveys no executor identity, which is why attribution must ride on a
completion record (B8/B9), not the transport (§6.3).
"""

import pytest

from aegis_at_v3.transport.mcp_adapter import (
    AudienceMismatchError,
    BoundToken,
    MCPBoundary,
    TokenPassthroughError,
)

SIEM = "https://siem.example/mcp"
UPSTREAM = "https://upstream.example/mcp"


def test_accept_inbound_audience_match():
    """A token bound to this resource is accepted (RFC 8707)."""
    b = MCPBoundary(SIEM)
    tok = BoundToken(audience=SIEM, value="tok-client")
    assert b.accept_inbound(tok) is tok


def test_accept_inbound_audience_mismatch_rejected():
    """A token issued for a different resource is rejected (RFC 8707)."""
    b = MCPBoundary(SIEM)
    wrong = BoundToken(audience="https://other.example/mcp", value="tok-x")
    with pytest.raises(AudienceMismatchError, match="audience"):
        b.accept_inbound(wrong)


def test_passthrough_token_rejected():
    """THE §6 rule: reusing the client's inbound token upstream is forbidden.

    This is the token-passthrough-forbidden rule (source-lock-v3.md §A4) that
    grounds v3 in MCP: because the client's token cannot cross the hop, the
    upstream sees the server's identity, not the originating agent's — so
    executor attribution must come from a completion record, not the transport.
    """
    b = MCPBoundary(SIEM)
    inbound = BoundToken(audience=SIEM, value="tok-client")
    with pytest.raises(TokenPassthroughError, match="pass the client's token"):
        b.forward_upstream(inbound, UPSTREAM, server_token=inbound)


def test_server_minted_token_forwards():
    """A distinct server token bound to the upstream audience forwards fine."""
    b = MCPBoundary(SIEM)
    inbound = BoundToken(audience=SIEM, value="tok-client")
    server = BoundToken(audience=UPSTREAM, value="tok-server")
    assert b.forward_upstream(inbound, UPSTREAM, server_token=server) is server


def test_server_token_wrong_audience_rejected():
    """A server token not bound to the upstream resource is rejected (RFC 8707)."""
    b = MCPBoundary(SIEM)
    inbound = BoundToken(audience=SIEM, value="tok-client")
    misbound = BoundToken(audience="https://elsewhere.example/mcp", value="tok-srv")
    with pytest.raises(AudienceMismatchError, match="upstream"):
        b.forward_upstream(inbound, UPSTREAM, server_token=misbound)


def test_bound_token_carries_no_executor_identity():
    """The transport token has no executor/act/delegation field (§6.3): who
    executed cannot be read from the transport, only from a completion record."""
    fields = set(BoundToken.__dataclass_fields__)
    assert fields == {"audience", "value"}
    assert not (fields & {"executor", "act", "asserted_executor", "delegation"})
