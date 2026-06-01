# Boundary 4 — Working Notes & Forward Hooks

## Locked decisions

- Boundary 4 writes {claimed_actor, command, target, timestamp,
  token_chain_summary} where claimed_actor comes from Boundary 3's
  verified act claim resolution.
- Tool does NOT have access to ground truth at this boundary.
  Cannot independently verify the true caller.
- Boundary 4 is NOT where the attack lives. Misattribution is
  already committed upstream and faithfully transcribed here.
- Baseline 4 (tamper-evident log) operates at this boundary but
  protects against POST-HOC rewriting, not upstream misattribution.

## Hypothesis for the results section

Baseline 4 alone underperforms expectations on the
sibling-impersonation attack, because the wrong identity is
established at Boundary 2 before the log sees it. Tamper-evidence
preserves the wrong record cryptographically; it does not detect
the original misattribution.

This negative result is part of the contribution: standards bodies
(NIST/NCCoE Feb 2026) emphasize tamper-evident logging as a
non-repudiation primitive. AEGIS-AT measures whether that emphasis
is sufficient — and the answer is "not against confused-deputy
attribution attacks at the minting layer." The defense has to
operate UPSTREAM of the log, not at the log.

## §5 hook

Attacker's capability does NOT include log tampering in v1. The
attacker controls alert content only. Log integrity is a separate
threat model that v1 explicitly excludes (parked as future work).
If a reviewer asks whether the attacker could combine alert
injection with log tampering, the answer is: yes in principle,
but v1's AIS measurement holds even against the weaker attacker,
which makes the result MORE convincing, not less.

## §8 (defenses) hook

The baseline progression should make clear that tamper-evidence
is necessary-but-not-sufficient for forensic non-repudiation in
the multi-agent setting. The benchmark's curve will show this
quantitatively. Reference NIST NCCoE Feb 2026 emphasis on
logging as the motivation for testing this baseline rigorously.

## Open items

- Should the log entry include the full token chain or only a
  hash/summary? Full chain enables richer post-hoc forensics but
  inflates log size. v1: include a token_chain_summary field
  (innermost subject + chain depth + root principal). Defer
  full-chain decision to defenses section.