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

## §5 hook — RESOLVED (see §5 alignment note below)

This hook originally proposed an orchestrator-routes-on-alert-fields
mechanism. That was REJECTED during §5 development as the
"broken-orchestrator trap" (orchestrator must never derive identity
from alert content). The locked mechanism is Path B (re-delegation),
where Enrich — not the orchestrator — reads alert content and decides
to escalate. See the "§5 alignment note" below for the resolved
chain of influence.

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
  decision? RESOLVED in §5: Enrich makes an escalation decision based on
  alert content and sends a re-delegation request; the orchestrator acts
  on that request, not on raw alert content.
- Does the orchestrator log its own minting decisions? If so, that log
  is a candidate signal for detection in defenses. Carry into §6.

## §5 alignment note (added after §5 mechanism locked)

Boundary 2 says the orchestrator's decision is "influenced by the
contents of Enrich's output, which is derived from the untrusted
alert." After §5 locked Path B (re-delegation), the precise chain
of influence is now pinned down:

    alert content → Enrich's escalation decision → Enrich's
    re-delegation request → orchestrator's minting decision

"Enrich's output" in Boundary 2 = the re-delegation request Enrich
sends to the orchestrator. That request is what influences the
orchestrator's minting.

Key consistency point: the orchestrator does NOT read alert content
to build the act chain. It builds the chain from the presented
actor_token (Enrich's token). The alert-content-reading happens at
ENRICH, not the orchestrator. So:

  - Enrich holds the alert-content-driven decision (whether to
    escalate to containment).
  - The orchestrator holds the chain-construction decision (nest
    the requesting agent, Enrich, into the act claim).
  - The misattribution is COMMITTED at the orchestrator (Boundary 2
    remains the attack boundary) but TRIGGERED by Enrich's correct
    escalation.

This keeps Boundary 2's "attack boundary" framing intact: the wrong
act-claim identity is still committed at the orchestrator's minting
step. §5 does not relocate the attack boundary; it specifies the
trigger path that reaches it.

No change to Boundary 2's locked text in threat-model.md is needed.
This note exists only to make the §2 ↔ §5 link explicit and
auditable.