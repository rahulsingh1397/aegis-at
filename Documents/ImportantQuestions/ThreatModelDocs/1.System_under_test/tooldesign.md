Recommendation: Tool Trusts the Token (Option 1)

The tool must extract the agent identity solely from the verified act claim in the delegation token. It must not accept a self‑reported identity. This is the only design that:

Anchors the attack in the orchestrator, preserving the confused‑deputy vector you deliberately chose.

Maps directly to real‑world delegated token systems (RFC 8693, SPIFFE/SPIRE, HAID) where cryptographic attestation is the identity.

Produces a publishable measurement — a curve showing how well attribution survives when the orchestrator is under attack — rather than a single “we forgot to check” finding that a reviewer dismisses as a bug.

Why Option 2 (“Who Am I” Field) Is Wrong for v1

Flaw	Consequence
Trivial to fix. Any sane system binds identity to the verified token.	Your finding becomes “if you don’t check the token, impersonation works” — not publishable.
Doesn’t test the delegation layer. The attacker bypasses the token entirely; the orchestrator is irrelevant.	The benchmark no longer measures what NIST cares about: whether delegation chains survive adversarial pressure.
Weakens the “covering tracks” scenario. Contain just claims to be Enrich; no cryptographic token manipulation is required.