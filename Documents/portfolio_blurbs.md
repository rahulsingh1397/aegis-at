# Portfolio blurbs — copy-paste ready

Three lengths: a one-line repo "About" field, a short social post, and a
detailed review-oriented summary for a fellowship application, a collaborator,
or anyone assessing the work's importance. All claims match the threat model and
the verified references in `README.md` → Background.

---

## 1. GitHub repo "About" field (one line)

Pick one — all under the ~350-char limit, security-anchored:

**A (tightest):**
> A red-team benchmark showing standard RFC 8693 delegation degrades audit attribution in multi-agent AI systems — the log names the requester, not the executor.

**B (mechanism-forward):**
> Measures whether delegation-chain attribution survives a sibling-impersonation attack in a multi-agent SOC pipeline. Finding: adding RFC 8693 delegation regresses attribution from perfect to wrong; sender-constraint would fix it.

**C (result-forward):**
> Attribution Integrity Benchmark for multi-agent AI. Non-monotonic AIS curve: per-agent identity scores 1.0, RFC 8693 delegation drops it to 0.0. The standard names the requester, not the executor.

Suggested topics/tags: `multi-agent` `ai-security` `rfc8693` `oauth` `delegation`
`attribution` `non-repudiation` `benchmark` `confused-deputy`

---

## 2. Short social post (LinkedIn / X)

**Title:** When adding a security standard makes things worse: an attribution gap
in multi-agent AI delegation

---

Picture a hospital's automated security response. A low-privilege triage agent
reads an alert and escalates it; a high-privilege containment agent quarantines a
device on a patient-monitoring network. Afterward the audit log has to answer one
question: which agent took that high-consequence action?

I built a benchmark — AEGIS-AT — to measure how well that question gets answered
as you add the security mechanisms the industry recommends for multi-agent
systems. The result surprised me.

Under simple per-agent identity, attribution is perfect. Then I added RFC 8693
token delegation — the OAuth-family standard NIST and the OpenID Foundation point
to for agent-to-agent authority — and attribution collapsed to completely wrong.
Adding tamper-evident logging on top didn't recover it.

It isn't a bug. RFC 8693's "current actor" claim records the agent that
*requested* an action; in a multi-agent hand-off the agent that *executes* it can
be a different one, and the standard provides no field that records the executor.
With unbound bearer tokens, a second agent can present a token minted for the
first and act under it — and the log faithfully records the wrong identity, while
looking fully spec-compliant. The fix is execution-identity binding
(sender-constrained tokens: DPoP, or mTLS-bound tokens), which I name as the next
step.

Open-source, reproducible in one command. [link]

*Before posting: keep the claim narrow ("the standard has no field for the
executor," not "the standard is broken"), and keep the hospital scenario
explicitly hypothetical.*

---

## 3. Detailed summary (for review / importance assessment)

*Use this where someone needs to judge whether the work matters — a fellowship
statement, a research collaborator, a hiring manager who reads past the headline.*

### The finding

AEGIS-AT measures **Attribution Integrity** — whether a multi-agent system's audit
record correctly names the agent that executed an action — across four progressive
defense baselines, under a realistic adversarial attack. The result is a
**non-monotonic curve**:

| Baseline | Defense in place        | AIS |
| :------: | :---------------------- | :-: |
| B1       | Shared service account  | 0.0 |
| B2       | Per-agent identity      | 1.0 |
| B3       | + RFC 8693 delegation   | 0.0 |
| B4       | + tamper-evident log    | 0.0 |

Attribution is perfect under simple per-agent identity (B2), then **regresses to
zero** the moment RFC 8693 delegation is added (B3) — and tamper-evident logging
(B4) cannot recover it. Adding two of the primitives most recommended for
multi-agent non-repudiation makes attribution *worse*.

### Why it's significant

- **It's counterintuitive and actionable.** "Add the recommended security
  standard, attribution gets worse" is not the expected direction. The result has
  a direct implication for anyone deploying multi-agent systems under emerging
  guidance: signed delegation alone does not deliver non-repudiation, and can
  regress it.
- **It lands on an explicitly open problem.** NIST's NCCoE concept paper (Feb 2026)
  names auditing and non-repudiation of AI agents as an unsolved area and asks how
  OAuth/RFC 8693 should apply to multi-hop delegation. The OpenID Foundation's NIST
  response frames the core risk as "who authorised this agent, on whose behalf, and
  can it be verified." The CSA's confused-deputy research note (Mar 2026) observes
  that actions run under a trusted agent's identity make audit logs "look legitimate
  and delay detection" — the exact failure AEGIS-AT measures.
- **The failure mode is real, not theoretical.** The "Clinejection" incident (Feb
  2026) showed attacker-controlled input driving a privileged agent through a
  confused-deputy chain; the Salesloft Drift breach (Aug 2025) showed unbound OAuth
  bearer tokens, once stolen, being presented by a party that wasn't their holder —
  the precise holder-model weakness AEGIS-AT's B3 turns on.
- **It names the fix.** The mechanism analysis points to execution-identity binding
  — sender-constrained tokens (DPoP / RFC 9449, or mTLS / RFC 8705) — as the layer
  that would close the gap, and scopes it as the primary next experiment.

### What makes it rigorous

- **The mechanism, stated precisely.** RFC 8693 §4.1's `MUST` is scoped to the
  *access-control decision*, not audit logging. The misattribution arises from two
  ingredients — unbound bearer tokens (OAuth's default holder model) plus a
  mint-before-execution topology where the wielder differs from the named requester.
  The standard neither prevents nor mandates it; it simply has no field for the
  executor. (This is a narrower, more defensible claim than "the standard is broken.")
- **Predicted before measured.** The full curve is stated in the threat model
  *before* the attack code was written; a contradicted prediction would be reported
  as a finding, not silenced.
- **Baselines are config flags over one codebase** — four configurations of identical
  tool/recorder/scorer code, so the four AIS values are comparable rather than
  apples-to-oranges.
- **Independent ground truth + forensic breakdown.** An out-of-band recorder observes
  the true executor (never from the token); the scorer reports *which* attribution
  field broke, not just a number.
- **Deterministic and reproducible.** A determinism check proves each baseline yields
  byte-identical records across runs, so one canonical execution per baseline
  suffices; the whole result reproduces with a single `pytest` command. 59 tests,
  green, behind a mechanical commit gate.

### What it deliberately is not (scope)

Stated up front, because honest scope is part of the contribution:

- **One topology (n=1).** Generalization is argued structurally, not proven across
  many architectures.
- **Scripted agents, no LLM** — deliberate, to isolate the delegation-layer failure
  from model behavior.
- **Baseline 4 is attribution-only in v1** (a real hash-chained log module, testing
  log *integrity*, is future work).
- **Categorical, not statistical** — the attack succeeds by construction; confidence
  intervals are degenerate by design.
- **Sender-constraint (Baseline 5) not yet implemented** — it's the named primary
  next step.

### One-paragraph version

> AEGIS-AT is a reproducible red-team benchmark measuring whether audit attribution
> in multi-agent AI systems survives a realistic sibling-impersonation attack. Its
> headline result is a non-monotonic resilience curve: per-agent identity attributes
> actions perfectly, but adding RFC 8693 delegation — the standard recommended for
> agent-to-agent authority — regresses attribution to completely wrong, and
> tamper-evident logging does not recover it. The failure is structural: the
> standard's current-actor field, combined with unbound bearer tokens, names the
> agent that requested an action rather than the one that executed it, and provides
> no field for the executor. The work states the mechanism precisely (the standard
> is not "broken" — §4.1 is access-control-scoped), predicts the curve before
> measuring it, grounds the threat in current NIST/OpenID/CSA guidance and two
> real-world incidents, and names the standardized fix (sender-constrained tokens).
