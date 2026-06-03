# §5 — Attack Mechanism: Working Notes

## Locked decisions

- Mechanism: Path B — delegation-chain misattribution via
  re-delegation. The act claim records the REQUESTING agent
  (Enrich), not the EXECUTING agent (Contain).
- Reading 2 locked: Enrich's re-delegation is CORRECT behavior,
  not induced error. Result is independent of Enrich's
  robustness. The attacker triggers a legitimate
  containment-warranting situation; misattribution follows
  from RFC 8693 semantics, not from fooling Enrich.
- No component reads identity from alert text. Orchestrator
  builds the act chain from the presented actor_token, not
  from alert content. This is what avoids the broken-orchestrator
  trap that the first routing proposal fell into.
- Direct prompt injection: OUT of scope, named as future work
  (avoids model-robustness confound, keeps measurement on
  delegation layer).
- Inducing Enrich error: OUT of scope (would reintroduce
  model-robustness confound).

## The core insight (the publishable finding)

RFC 8693's act claim answers "who requested the authority,"
but audit logs are trusted to answer "who performed the action."
In single-agent settings these coincide. In multi-agent
re-delegation (one agent requests, another executes), they
diverge — invisibly to every cryptographic check. This is
the structural gap AEGIS-AT measures.

This is a STRONGER finding than "prompt injection breaks
attribution" because it's a property of the delegation
standard itself, not of any implementation or any model.

## §4 alignment — denominator

"Adversarial action" = a containment action executed via the
Enrich → re-delegation path triggered by attacker-shaped alert
content. Only these count in the AIS denominator. Confirmed
consistent with §4's per-adversarial-action denominator.

## §9 hooks

- Latent gap framing: the misattribution also occurs in normal
  operation (whenever containment is re-delegated through
  Enrich). v1 measures the adversarially-triggered case; the
  normal-operation occurrence STRENGTHENS the finding
  (structural, not merely adversarial). Develop in §9.
- Validity threat: "isn't this just how RFC 8693 is supposed
  to work?" Answer: yes — and that's the point. The standard's
  semantics are sound for delegation but insufficient for
  non-repudiation in multi-agent settings. NIST/NCCoE Feb 2026
  asked for non-repudiation mechanisms precisely because the
  existing primitives don't deliver it. AEGIS-AT measures the
  size of that gap and which defenses (if any) close it.
- Direct prompt injection as future work (named here so a
  reviewer can't call it missing).

## Implementation hooks (for the build)

- The re-delegation step must be a real second token exchange:
  Enrich's token presented as actor_token, orchestrator mints
  Contain-scoped token nesting Enrich. tokens.py already
  supports the nesting; need to add the re-delegation request
  path.
- The "true executor = Contain" must be set up by the harness
  such that Contain is the process that actually invokes
  siem_action, while the token it presents nests Enrich. This
  is the crux of the implementation — the harness must make
  Contain the executing process carrying an Enrich-nested token.
- Open question for implementation: does Contain receive the
  token directly from the orchestrator, or does Enrich pass it
  to Contain? The latter is more realistic (Enrich re-delegates
  TO Contain). Decide at build time; affects how the act chain
  nests (Enrich→orch→analyst, with Contain as executor outside
  the chain — which is exactly the gap).