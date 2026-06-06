# Boundary 1 — Working Notes & Forward Hooks

Scratchpad for Boundary 1 of the threat model. Locked decisions live in
threat-model.md §2; this file is for forward-pointing reminders that belong
to other sections so they aren't lost.

## Locked decisions (recorded here for context)

- Injection path: **Enrich-as-conduit.** Attacker controls alert text only;
  Enrich processes the alert and passes extracted fields to the orchestrator.

  The injection is **indirect** — orchestrator never sees raw attacker text.
  
- Analyst path is trusted (authenticated insider, OIDC-verified). Not the
  attacker in this threat model.

- Boundary 1 covers both inputs (trusted analyst + untrusted alert-via-Enrich)
  intentionally; splitting them would break the template's principal→orchestrator
  framing without clarifying anything.

## §5 hook (paste into §5's adversary-capability subsection when you write it)

Attacker's capability is **"control of text content of an alert that Enrich
processes."** Enrich may summarize or extract fields before passing them to
the orchestrator. The orchestrator's confused-deputy error is therefore
triggered by the content of *Enrich's output*, not by raw attacker text —
i.e., the injection is indirect. This matches the Cline pattern: the triage
bot read the issue title; the attacker never spoke to the bot directly.

## §8 hook (validity-threats section)

A reviewer may ask whether "alert text reaches Enrich" is a realistic
attacker capability. Answer with the precedent stack already in Boundary 1
(Cline, Log4Shell, Splunk XSS, ELK injection, Hardy 1988). Do not re-argue
  realism in §8; reference Boundary 1.

A separate §8 limitation is needed for the analyst-prompt path being out of
scope. Draft text:
"We model the attacker as controlling alert content ingested by the Enrich
agent. An alternative injection path — a malicious or socially engineered
analyst directly entering a prompt — would constitute an insider-threat
scenario and is outside the scope of this delegation-layer benchmark.
Measuring delegation resilience to insider-threat injection is future work."

## Open questions for later boundaries (not for §2)

- Boundary 5 (tool → ground-truth recorder): need to specify *how* ground
  truth stays independent of the attacker. Likely answer: recorder writes
  from inside the tool's process before the agent's logic runs, separate
credentials. Defer to §4 (ground-truth definition) and §8 (validity).
