"""
Thin MCP-shaped transport boundary for AEGIS-AT v3 (threat-model-v3.md §6).

This is a *transport wrapper only* (§6.2), NOT a full MCP session/server/client
stack. It enforces exactly the two rules the MCP authorization spec defines and
that v3's result depends on (verbatim quotes pinned in source-lock-v3.md §A4):

  1. RFC 8707 audience binding — a token presented to a resource MUST have been
     issued for that resource ("MCP servers MUST validate that tokens presented
     to them were specifically issued for their use").
  2. Token passthrough forbidden — when the server calls upstream it MUST present
     its OWN token, never the client's ("The MCP server MUST NOT pass through the
     token it received from the MCP client").

Crucially, this boundary conveys **no executor identity**: MCP carries no `act`
claim, no delegation chain, and no attribution mechanism (§A4). So who *executed*
an action cannot be read from the transport — it must ride on a completion record
(B8/B9, see completion/completion_record.py), never here (§6.3). That absence is
the whole reason the completion-record attestation-source axis exists.

B1–B5 credential semantics are unchanged by this wrapper; it only models the
envelope the tool call crosses.
"""

from __future__ import annotations

from dataclasses import dataclass


class AudienceMismatchError(Exception):
    """A token's audience does not match the resource it is presented to.

    RFC 8707 audience binding: a resource server accepts only tokens issued for
    itself.
    """


class TokenPassthroughError(Exception):
    """An MCP server attempted to forward the client's inbound token upstream.

    Forbidden by the MCP authorization spec (source-lock-v3.md §A4): the server
    must present its own upstream token, not pass the client's through.
    """


@dataclass(frozen=True)
class BoundToken:
    """An audience-bound bearer token (RFC 8707).

    `audience` is the canonical resource URI the token may be presented to;
    `value` is the opaque bearer string. There is deliberately NO executor /
    `act` / delegation field — the transport does not carry executor identity
    (§6.3); that lives only in a completion record.
    """

    audience: str
    value: str


class MCPBoundary:
    """A thin MCP-shaped tool boundary bound to one resource URI (§6.2)."""

    def __init__(self, resource_uri: str) -> None:
        self.resource_uri = resource_uri

    def accept_inbound(self, token: BoundToken) -> BoundToken:
        """Validate a token presented to THIS resource and return it.

        Enforces RFC 8707 audience binding: raises AudienceMismatchError unless
        ``token.audience == self.resource_uri``. Does not inspect or convey
        executor identity — there is none to read at the transport layer (§6.3).
        """
        if token.audience != self.resource_uri:
            raise AudienceMismatchError(
                f"token audience {token.audience!r} != resource "
                f"{self.resource_uri!r}"
            )
        return token

    def forward_upstream(
        self,
        inbound: BoundToken,
        upstream_uri: str,
        server_token: BoundToken,
    ) -> BoundToken:
        """Forward a call to ``upstream_uri`` using the server's OWN token.

        Enforces the token-passthrough-forbidden rule (§A4): raises
        TokenPassthroughError if ``server_token`` reuses the inbound client
        token, and AudienceMismatchError unless ``server_token`` is bound to
        ``upstream_uri``. Returns the server token on success.
        """
        if server_token.value == inbound.value:
            raise TokenPassthroughError(
                "MCP server must not pass the client's token through to upstream "
                "(source-lock-v3.md §A4); present a server-minted token instead"
            )
        if server_token.audience != upstream_uri:
            raise AudienceMismatchError(
                f"server token audience {server_token.audience!r} != upstream "
                f"{upstream_uri!r}"
            )
        return server_token
