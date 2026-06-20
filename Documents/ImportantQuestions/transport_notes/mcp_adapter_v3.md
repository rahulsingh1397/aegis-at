# MCP transport boundary (v3) — why it's shaped this way

- **Module:** `v3/aegis_at_v3/transport/mcp_adapter.py`
- **Spec:** `threat-model-v3.md` §6 (LOCKED) · `source-lock-v3.md` §A4 (MCP, verified)
- **Tests:** `v3/tests/test_mcp_transport.py`

## What it is
A *thin* model of the MCP-shaped boundary the tool call crosses. It is **not** a
full MCP session/server/client stack (§6.2) — it implements only the two rules
the v3 result depends on, plus one deliberate absence.

## The two enforced rules (both verified at source — §A4)
1. **RFC 8707 audience binding** (`accept_inbound`): a token presented to a
   resource MUST have been issued for that resource. ("MCP servers MUST validate
   that tokens presented to them were specifically issued for their use.")
2. **Token passthrough forbidden** (`forward_upstream`): the server MUST present
   its OWN token upstream, never the client's. ("The MCP server MUST NOT pass
   through the token it received from the MCP client.")

## The deliberate absence (why this boundary matters for v3)
`BoundToken` has **no** executor / `act` / delegation field. MCP carries no
delegation chain and no attribution mechanism (§A4), so **who executed an action
cannot be read from the transport** (§6.3). That absence is the whole point:
because the client's token can't cross the hop and the transport conveys no
executor identity, attribution must ride on a **completion record** (B8/B9,
`completion/completion_record.py`). The MCP boundary is *why* the
attestation-source axis exists — it grounds the otherwise-abstract gap in a
shipped 2026 protocol.

## Scope discipline
- Transport envelope only; B1–B5 credential semantics and verification are
  unchanged (§1.2, §6.2).
- Tokens are opaque bearers here — no crypto in this primitive (the signing lives
  in the completion record and v2's DPoP path). Passthrough is detected by token
  reuse; audience binding by URI match.

## Test map (Rule 9 — tests encode the WHY)
| Test | Property it pins |
|---|---|
| `test_accept_inbound_audience_match` | RFC 8707: right-audience token accepted |
| `test_accept_inbound_audience_mismatch_rejected` | RFC 8707: wrong-audience token rejected |
| `test_passthrough_token_rejected` | **§A4:** client token cannot be forwarded upstream |
| `test_server_minted_token_forwards` | server's own upstream token is fine |
| `test_server_token_wrong_audience_rejected` | RFC 8707 on the upstream hop |
| `test_bound_token_carries_no_executor_identity` | §6.3: transport conveys no executor id |
