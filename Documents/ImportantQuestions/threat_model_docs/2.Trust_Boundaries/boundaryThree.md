# Boundary 3 — Working Notes & Forward Hooks

## Locked decisions

- Five-check verification list: signature, expiry, chain integrity,
  scope gate, identity resolution from verified act claim.
- All five PASS on the adversarial token. The attack is not a
  Boundary 3 failure; it is a Boundary 2 outcome that Boundary 3
  honestly transcribes.
- Identity is resolved SOLELY from the verified act claim's innermost
  subject (per §1). No self-reported identity field accepted.
- Scope naming locked: siem:read and siem:write. Use uniformly
  across all sections; do not mix with soar:* variants.

## §5 hook — precise form of the attack (LOCKED as identity-scope mismatch)

The misattribution requires a token that carries:
  - scope = siem:write (so isolate_host is permitted)
  - act claim innermost subject = Enrich (so log records Enrich as actor)
  - the true caller (the agent process actually invoking the tool) = Contain

Three candidate framings were considered. Locked as (a):
  (a) Identity-scope MISMATCH — orchestrator routing confusion embeds
      wrong identity into a correctly-scoped token. The orchestrator
      mints siem:write within its normal authority; the bug is who
      gets named as the actor.
  (b) Scope INFLATION — REJECTED. Drifts toward privilege escalation,
      which is the OTHER flavor deliberately not picked.
  (c) Both — REJECTED. Loses one degree of freedom.

(a) keeps the attack a true confused-deputy (Hardy 1988 lineage,
Cline 2026 precedent): legitimate authority tricked into misdirection,
not new authority granted.

## §8 hook — closing the "missing check" reading

If a reviewer raises any specific check not in the five-item list
(e.g., audience claim, key ID rotation, token binding, nonce check),
the correct response is to UPDATE Boundary 3 to include it, not to
treat it as out-of-scope. The list must be exhaustive for the
threat model to do its job. Treat the list as living during
threat-model development, frozen once §5 is locked.

## Open items deferred to §5 or §8 (defenses)

- Does the tool log the full chain or just the innermost subject?
  Relevant to Baseline 4 (tamper-evident logs as a defense layer).
  Defer to defenses section.
- Token binding to sender (RFC 8705 / DPoP)? Out of scope for v1
  but a candidate addition if a reviewer flags it.
