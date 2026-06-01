# §7 — Scope Discipline: Working Notes

## Locked decisions

- IN SCOPE (v1): ONE failure mode — sibling misattribution via
  re-delegation (Path B, §5). Measured end-to-end: real RFC 8693
  exchange, 4 baselines, independent ground-truth recorder, AIS
  metric with pre-registered hypotheses.

- OUT OF SCOPE (each named deliberately, not omitted):
  1. Direct prompt injection — conflates delegation layer with LLM
     robustness; isolating the delegation layer is the whole point.
  2. Inducing Enrich into a wrong decision — v1 relies on Enrich
     being CORRECT, so result is model-robustness-independent.
  3. Delegation forgery / token replay — signing key out of reach (§3).
  4. Scope-attenuation bypass — v1 holds scope enforcement sound;
     measures attribution, not authorization.
  5. Audit-log tampering — adversary can't tamper in v1; B4 measures
     tamper-EVIDENCE only.
  6. Principal laundering — principal held correctly rooted; attack
     hits actor position only.
  7. may_act enforcement (§4.4) — governs AUTHORIZATION not
     attribution; Contain is legitimately authorized, so may_act
     doesn't prevent the attack. Defense-in-depth note for future.

## The "why one mode" answer (the template's required question)

A benchmark's value is in the trustworthiness of its measurement,
not breadth of coverage. One mode measured end-to-end (independent
ground truth, spec-compliant exchange, 4 real baselines, pre-
registered hypotheses) gives a result a reviewer can verify and a
practitioner can act on. Five modes gestured at multiplies the
"did you really measure that?" surface without deepening any one
answer. Out-of-scope list = v2 roadmap, not excuses.

## may_act note (added because the other tool raised it)

Including may_act in the out-of-scope list pre-empts the reviewer
question "what about may_act?" Answer: it's authorization, not
attribution, and Contain is authorized — so it doesn't stop the
attack. Naming it closes the question the same way the rest of the
list does.