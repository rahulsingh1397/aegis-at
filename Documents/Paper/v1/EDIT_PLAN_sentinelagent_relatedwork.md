# EDIT PLAN — Position AEGIS-AT against SentinelAgent / Agentic JWT / Red Hat / Okta

**For:** an LLM running in the IDE, editing the paper.
**Targets (edit BOTH, keep in sync):**
- `Documents/Paper/aegis-at.md`  (GitHub companion; numeric refs `[12]`, anchors `<a id="ref12">`)
- `Documents/Paper/aegis-at.tex` (canonical artifact; named cite keys `\cite{sentinelagent}`, `\bibitem{...}`)

**Do not touch any other file.** Source material already updated for you:
`Documents/References/References.md` (entries 8–11) and `Documents/ThreatModel/threat-model.md`
(§8 item 11 + §8.10 Agentic JWT). The §8 item 11 text there is liftable almost verbatim for Edit 1.

There are **5 edits**. Apply all. Then run the verification checklist at the bottom.

---

## HARD RULES — these are corrections from two prior reviews; violating them reintroduces known errors

1. **Never write "AEGIS-AT falsifies P4."** Always: *"bounds the audit-attribution interpretation of P4
   under transferable, non-sender-constrained bearer tokens."* P4 reconstructs the lineage of the token
   *presented*, i.e. who was *authorized* — not who *wielded/executed*. A walkable chain ≠ executor identity.
2. **Category count = 7 attack categories** (A,B,C,D,F,G,H) + 3 benign (E,I,J) = **516 scenarios
   (150 attacks / 366 benign)**. Do **not** write "8 categories" or "10 attack categories" (SentinelAgent's
   abstract says "10" but its own taxonomy table contradicts that — cite the table).
3. **No global "only/nobody" claims.** Scope every superiority claim to *"among the works we compare"*.
4. **Adversary asymmetry is a strength, not parity.** SentinelAgent models a *compromised agent* (its A2);
   AEGIS-AT succeeds under a *strictly weaker* adversary (alert-text control only). Do **not** write
   "same threat envelope."
5. **Drop CSA from the pro-delegation narrative grouping.** Cite Red Hat + Okta as the "delegation beats
   impersonation" foil. The CSA ref already in the paper (`\cite{csa2026}` / `[6]`) is a *confused-deputy*
   note — do not repurpose it.
6. **Agentic JWT = solution proposal/prototype** ("eval forthcoming"), a candidate **Baseline 5**, NOT a
   rival measurement. It is complementary.
7. **SentinelAgent tokens = HMAC-signed bearer, no PoP/mTLS** — this is the load-bearing fact behind Edit 1.
8. Match each file's existing voice, indentation, and dash style (`.tex` uses `---`/`~`; `.md` uses `—`).

---

## NEW REFERENCES (add in Edit 5; keys/numbers used by Edits 1–3)

| # (.md) | key (.tex) | Citation |
|--|--|--|
| 12 | `sentinelagent` | K. S. R. Patil, *SentinelAgent: Intent-Verified Delegation Chains for Securing Federal Multi-Agent AI Systems.* arXiv:2604.02767, April 2026. |
| 13 | `agenticjwt` | A. Goswami, *Agentic JWT: Secure Delegation for Agentic AI.* arXiv:2509.13597, September 2025. |
| 14 | `redhat2026` | Red Hat, *Zero Trust for AI Agents: Why Delegation Beats Impersonation.* Red Hat Emerging Tech, May 21, 2026. |
| 15 | `okta2026` | Okta, *Agent Security: Securing the Delegation Chain.* Okta AI Security Blog, 2026. |

URLs:
- https://arxiv.org/abs/2604.02767
- https://arxiv.org/abs/2509.13597
- https://next.redhat.com/2026/05/21/zero-trust-for-ai-agents-why-delegation-beats-impersonation/
- https://www.okta.com/blog/ai/agent-security-delegation-chain/

---

## EDIT 1 — Add SentinelAgent to Related Work (§2.4 "Closest prior academic work")

**Why:** A reviewer Googles SentinelAgent first; the current §2.4 only discusses The Misattribution Gap.
This is the single most important edit.

### 1a. `aegis-at.md`
**Location:** in §2.4, immediately AFTER the paragraph that ends
`...the problem space is *defensibly underexplored* rather than untouched.`
**Insert this new paragraph:**

> The closest adjacent framework is **SentinelAgent / DelegationBench v4** [[12]](#ref12): a Delegation
> Chain Calculus, a non-LLM Delegation Authority Service (DAS), and a 516-scenario benchmark (150
> adversarial actions across seven attack categories; 366 benign), reporting 100% attack detection at 0%
> false-positive rate with TLA+ verification of its deterministic properties — including *forensic
> reconstructibility* (P4): given any action, the hash-linked delegation chain that authorized it is
> reconstructible in O(n). SentinelAgent and AEGIS-AT measure different quantities. SentinelAgent measures
> *detection* — does the DAS block a policy-violating delegation? AEGIS-AT measures *attribution integrity*
> — does the logged actor equal the true executor? — on actions that violate no policy. The two meet at one
> point: P4 reconstructs the lineage of the token *presented at the proxy*, which establishes who was
> *authorized*, not who *wielded* the token at the resource, unless the token is sender-constrained.
> SentinelAgent's tokens are HMAC-signed bearer credentials with no proof-of-possession; under the
> re-delegation hand-off we study (§5), a sibling presents a token whose chain names another agent, so
> hash-chain reconstruction succeeds while executor attribution fails. AEGIS-AT therefore does not refute
> reconstructibility — it *bounds the audit-attribution interpretation of P4*: a walkable chain certifies
> who was authorized, not who acted. A DAS could close this by binding the token to its holder (DPoP / mTLS)
> or authenticating the caller independently, but that is an added sender-constraint, not a consequence of
> reconstruction. The attack also needs none of SentinelAgent's stronger adversaries (e.g. its
> compromised-agent case): it succeeds with alert-text control alone, no component misbehaving. Among the
> works we compare, AEGIS-AT is the only one that treats attribution correctness as a *measured* dependent
> variable rather than a design guarantee.

### 1b. `aegis-at.tex`
**Location:** in `\subsection{Closest prior academic work}` (after line ~267), immediately after the
sentence ending `\emph{defensibly underexplored} rather than untouched.` and before the
`\section{Threat Model}` block.
**Insert the same paragraph in LaTeX**, converting:
`[[12]](#ref12)` → `\cite{sentinelagent}`; `*forensic reconstructibility*` → `\emph{forensic
reconstructibility}`; em-dashes `—` → `---`; `O(n)` → `$O(n)$`; `*bounds...*` → `\emph{bounds...}`.
Optionally wrap it in a new `\paragraph{SentinelAgent / DelegationBench v4.}` lead-in if that matches the
local style.

---

## EDIT 2 — Add Agentic JWT to Baseline 5 (Future Work, §12)

### 2a. `aegis-at.md`
**Location:** §12, the bullet starting `- **Baseline 5 — sender-constrained tokens.**`, immediately AFTER
the sentence ending `...the primary defensive item of future work.`
**Append to that bullet:**

> Agentic JWT [[13]](#ref13) is one concrete design in this direction — per-agent proof-of-possession keys
> plus intent/delegation claims binding an API call to a registered agent and workflow step. In AEGIS-AT
> terms it is a plausible Baseline 5 instantiation: it proposes the sender-constraint but does not measure
> the attribution-integrity regression that motivates it. Pairing such a protocol with the AIS metric —
> *does sender-constraint recover the curve at B5?* — is the natural next experiment.

### 2b. `aegis-at.tex`
**Location:** in `\section{Future Work}`, the `\item \textbf{Baseline 5 --- sender-constrained tokens.}`
bullet, after `...effectively a Baseline~5.`
**Append the same text**, `[[13]](#ref13)` → `\cite{agenticjwt}`, em-dashes → `---`, `*...*` → `\emph{...}`.

---

## EDIT 3 — Qualify the industry narrative (Discussion, §10)

### 3a. `aegis-at.md`
**Location:** §10, AFTER the paragraph `**The gap is structural, not merely adversarial.**` (ends
`...would measure the structural property more faithfully.`) and BEFORE
`**Tamper-evident logging protects a wrong answer.**`
**Insert new paragraph:**

> **Delegation's auditability benefit is conditional.** This result *qualifies* rather than rejects the
> emerging industry narrative that delegation beats impersonation for accountability [[14]](#ref14),
> [[15]](#ref15). Delegation does beat shared service accounts (B1) on lineage and least privilege; what
> AEGIS-AT shows is that delegation's *audit-attribution* advantage is conditional — absent sender-constraint,
> B3 attributes worse than the simpler per-agent identity of B2, even while every delegation check passes.
> We are not arguing impersonation is preferable; we are bounding when delegation actually delivers the
> accountability it is promoted for.

### 3b. `aegis-at.tex`
**Location:** in the Discussion section, before `\paragraph{Tamper-evident logging protects a wrong answer.}`.
**Insert the same as** `\paragraph{Delegation's auditability benefit is conditional.}` followed by the text,
with `[[14]](#ref14), [[15]](#ref15)` → `\cite{redhat2026, okta2026}` and dash/emph conversions.

---

## EDIT 4 — One-sentence "moat" framing (Introduction, §1)

### 4a. `aegis-at.md`
**Location:** §1, AFTER the "Why it regresses (a one-paragraph preview)" paragraph (ends
`...it simply has no place to put the executor.`) and BEFORE `**Contributions.**`
**Insert as its own short paragraph:**

> **What sets this apart.** Unlike delegation frameworks that report detection rates (can an attack be
> blocked?), AEGIS-AT treats attribution correctness itself — does the logged actor equal the true
> executor? — as the measured dependent variable.

### 4b. `aegis-at.tex`
**Location:** same logical spot in `\section{Introduction}`, before the `\textbf{Contributions.}` block.
**Insert** the same as a `\paragraph{What sets this apart.}` (or a plain sentence), dash/emph converted.

---

## EDIT 5 — Reference / bibliography entries

### 5a. `aegis-at.md`
**Location:** end of `## References`, AFTER entry `[11]` (Hardy). **Append:**

```markdown
<a id="ref12"></a>[12] K. S. R. Patil. *SentinelAgent: Intent-Verified Delegation Chains for Securing
Federal Multi-Agent AI Systems.* arXiv:2604.02767, April 2026. <https://arxiv.org/abs/2604.02767>

<a id="ref13"></a>[13] A. Goswami. *Agentic JWT: Secure Delegation for Agentic AI.* arXiv:2509.13597,
September 2025. <https://arxiv.org/abs/2509.13597>

<a id="ref14"></a>[14] Red Hat. *Zero Trust for AI Agents: Why Delegation Beats Impersonation.* Red Hat
Emerging Tech, May 21, 2026.
<https://next.redhat.com/2026/05/21/zero-trust-for-ai-agents-why-delegation-beats-impersonation/>

<a id="ref15"></a>[15] Okta. *Agent Security: Securing the Delegation Chain.* Okta AI Security Blog, 2026.
<https://www.okta.com/blog/ai/agent-security-delegation-chain/>
```

### 5b. `aegis-at.tex`
**Location:** in `\begin{thebibliography}{99}`, AFTER `\bibitem{hardy1988}...`. **Append:**

```latex
\bibitem{sentinelagent} K.~S.~R.~Patil, \emph{SentinelAgent: Intent-Verified Delegation Chains for
Securing Federal Multi-Agent AI Systems}, arXiv:2604.02767, April 2026.
\url{https://arxiv.org/abs/2604.02767}

\bibitem{agenticjwt} A.~Goswami, \emph{Agentic JWT: Secure Delegation for Agentic AI},
arXiv:2509.13597, September 2025. \url{https://arxiv.org/abs/2509.13597}

\bibitem{redhat2026} Red Hat, \emph{Zero Trust for AI Agents: Why Delegation Beats Impersonation},
Red Hat Emerging Tech, May~21, 2026.
\url{https://next.redhat.com/2026/05/21/zero-trust-for-ai-agents-why-delegation-beats-impersonation/}

\bibitem{okta2026} Okta, \emph{Agent Security: Securing the Delegation Chain}, Okta AI Security Blog, 2026.
\url{https://www.okta.com/blog/ai/agent-security-delegation-chain/}
```
(If the `.tex` preamble lacks `\usepackage{url}`/`hyperref`, replace `\url{...}` with `\texttt{...}`.)

---

## VERIFICATION CHECKLIST (run after all edits)

- [ ] Both files cite all four new refs; every in-text `[12]`/`[13]`/`[14]`/`[15]` (`.md`) and
      `\cite{sentinelagent|agenticjwt|redhat2026|okta2026}` (`.tex`) resolves to a bibliography entry.
- [ ] No occurrence of "falsif" near P4; the phrase "bounds the audit-attribution interpretation of P4"
      appears once in each file. (`grep -i "falsif" aegis-at.*` → expect none about P4.)
- [ ] "seven attack categories" appears; **no** "eight"/"8 attack categories"/"10 attack categories".
- [ ] No "same threat envelope"; the weaker-adversary point is present.
- [ ] CSA is NOT grouped with Red Hat/Okta in the new narrative paragraph.
- [ ] `.tex` compiles (`pdflatex aegis-at.tex` twice); no undefined-citation warnings for the 4 new keys.
- [ ] `.md` renders: anchors `#ref12..#ref15` exist and links jump correctly.
- [ ] Diff is additive only — no existing sentence deleted or renumbered; existing refs [1]–[11] unchanged.
- [ ] Voice/indent/dash style matches surroundings in each file.
