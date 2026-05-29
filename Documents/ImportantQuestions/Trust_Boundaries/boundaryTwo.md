# Boundary 2 — Working Notes & Forward Hooks

Scratchpad for Boundary 2 of the threat model. Locked decisions live in
threat-model.md §2; this file is for forward-pointing reminders and
deferred questions so they aren't lost.

## Locked decisions (recorded here for context)

- Boundary 2 is the attack boundary. Boundaries 1, 3, 4, 5 are described
  so the reviewer can see they are verified properly.
- The split that makes the boundary work: cryptographic verification is
  sound; decisional verification is the slack. The cryptography is sound;
  the decision the cryptography commits to is corrupted.
- Attacker cannot forge a token. Attacker can manipulate the orchestrator
  into honestly issuing a token that names the wrong sibling as the actor.
- The architecture has no direct A↔B communication path. All impersonation
  must go through a token minted with the wrong `act` claim at Boundary 2.

## §5 hook — structural reason the attack is plausible

(paste into §5's adversary-capability or attack-mechanism subsection
when writing it)

In a realistic SOC, the orchestrator routinely mints tokens for BOTH
Enrich and Contain based on the same alert's fields — one alert often
triggers multiple workflow steps (enrich the indicator AND respond to it).
The orchestrator's routing logic decides which agent to invoke based on
parsed alert fields. The adversarial alert content (via Enrich's output,
per Boundary 1's locked path) manipulates this routing logic so that the
orchestrator embeds Enrich's identity in the `act` claim of a token
carrying Contain's scope (or vice versa). This matches actual SOAR
orchestrator behavior; the attack is a design tension, not a one-off bug.

## §9 hook — validity-threat the reviewer will raise

A reviewer will ask: "If your cryptography is sound, isn't your attack
just a logic bug? Wouldn't a careful orchestrator implementation fix it?"

Pre-empt this in §9 with three points:
  1. The confused-deputy lineage (Hardy, 1988) shows this class of
     bug is architectural, not implementation-specific. Any orchestrator
     that takes adversarial input and makes identity-affecting decisions
     based on it has this surface.
  2. The benchmark's point is to MEASURE how much each defense layer
     (per-agent identity → act claims → tamper-evident logs) closes
     the gap. The result is the curve across baselines, not the claim
     "no orchestrator could ever get this right."
  3. NIST/NCCoE Feb 2026 explicitly identifies auditing and non-repudiation
     as an unsolved area precisely because "verified mechanism" alone
     doesn't deliver "correct attribution." This boundary is the gap they
     are asking the community to measure.

## Open questions deferred to later sections

- How exactly does Enrich's output influence the orchestrator's routing
  decision? Field extraction? Summarization? Direct field substitution
  into a tool call? Decide in §5 (attack mechanism). For now, the
  threat model is agnostic about the precise plumbing — what matters
  here in §2 is that the influence path exists.
- Does the orchestrator log its own minting decisions? If so, that log
  is a candidate signal for detection in defenses (Baseline 4 territory).
  Note for the defenses/baselines section.