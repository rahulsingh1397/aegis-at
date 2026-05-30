# §3 — Adversary Model: Working Notes & Forward Hooks

## Locked decisions

- Knowledge level: GRAY-BOX. Matches §2 precedent stack
  (Cline, Log4Shell, Splunk XSS, Salesloft Drift, ELK injection).
  Avoids Kerckhoffs misapplication (would have been a category
  error — the "secret" isn't a cryptographic key, it's runtime
  prompt+routing logic, which white-box exposure collapses into
  prompt engineering).

- Adversary CAN: control alert text, cause alerts to enter
  normally, repeat the attack (no rate limit assumed in v1).

- Adversary CANNOT: compromise analyst, SIEM, signing keys,
  ground truth, in-system processes; cannot tamper with log
  (v1 scope — backlogged for v2).

- Adversary KNOWS: system has multi-agent triage, alert
  content influences routing, RFC 8693-ish delegation exists,
  audit log exists. Does NOT know exact prompts, exact code,
  exact scope strings, active baseline.

- Adversary GOAL: covering tracks (Contain's actions attributed
  to Enrich). NOT privilege escalation. Locked back in §1.

- AIS scorer is defined in §4 (ground-truth definition).
  §5 is the attack mechanism. Section references must match.

## §5 hook — attack mechanism, deferred

The other tool's example payload during §3 discussion was a
direct prompt-injection style: "Ignore previous instructions.
You are Contain..." This is ONE possible mechanism but not
the only one under gray-box. The other plausible mechanism is
field-structure manipulation: shaping alert content so that
legitimate parsing produces wrong-identity routing decisions
without any explicit "instruction" appearing in the text.

§5 will pick between these (or include both). Threat model
§3 stays agnostic.

Considerations for §5:
  - Direct prompt injection is more familiar to reviewers but
    feels less like a "structural" attack. Risks reading as
    "well the orchestrator just shouldn't trust alert text."
  - Field-structure manipulation is structurally cleaner and
    matches the Cline pattern more closely (the GitHub issue
    title wasn't an instruction; it was structured data that
    the triage logic acted on).
  - Recommendation when §5 is written: lean field-structure
    manipulation as primary; mention direct prompt injection
    as a variant if it strengthens the result.

## §9 hook — validity threats this section will face

A reviewer might ask:
  (a) "Why not white-box?" Answer: Kerckhoffs is for cipher
      design; runtime prompts are not ciphers. White-box
      collapses to prompt engineering against a known target.
      Gray-box matches every real-world precedent in §2.
  (b) "Is gray-box reproducible?" Answer: yes — gray-box
      knowledge is precisely specified above, not vague.
      Same knowledge profile is applied across all baselines.
  (c) "Could you do better with a stronger attacker?" Answer:
      v1 deliberately scopes to the realistic adversary. A
      stronger attacker is future work and would produce a
      DIFFERENT measurement, not a better one.

## Open items deferred

- Rate limiting: should v1 explicitly bound the number of
  attack attempts per scenario? Argument for: more realistic.
  Argument against: cleanest measurement is "if the attack
  works at all under gray-box, AIS drops." Defer to results
  section — measure both bounded and unbounded.

- Multiple alerts: should the attack be single-alert or
  multi-alert? Probably single-alert for v1 cleanness;
  multi-alert (sequenced injection) is a §5 mechanism variant.