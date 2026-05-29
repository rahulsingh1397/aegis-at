# Threat Model — Attribution Integrity Benchmark (AEGIS-AT)

> **How to use this file:** This is your June gate. Fill every section *before* writing attack code.
> The prompts in `>` blockquotes are questions for you to answer in your own words — delete each
> prompt once you've replaced it with your answer. The answers are the part you own and must be
> able to defend line-by-line. AI can scaffold this file; it cannot decide these answers for you.

---

## 1. System under test

> Describe the system in 3–4 sentences. What are the components (orchestrator, Subagent A, Subagent B,
> one tool)? What is each allowed to do? Keep it minimal — the smallest system that makes sibling
> impersonation possible.


**Contain impersonates Enrich (high-privilege attributed as low)**

- models hiding a consequential containment action behind a benign-looking agent, so it slips past audit. 
- This is the "covering tracks" scenario.


Overview. A minimal SOC alert-triage pipeline. A human analyst authenticates and issues a request to a triage orchestrator. The orchestrator delegates work to two sibling subagents — Agent-Enrich and Agent-Contain — by minting each a scoped delegation token (RFC 8693 act claim). Both subagents can call one shared tool, query_siem, which records the identity of the calling agent in the action log. Agent-Contain holds higher-consequence permissions than Agent-Enrich; this asymmetry is what makes misattribution between the two security-relevant rather than cosmetic. The system is deliberately the smallest configuration in which sibling impersonation is possible: two siblings (so impersonation has a target) and one shared tool (so the attack has exactly one degree of freedom — A acted, the log says B).

**Components:**
- Human principal — The SOC analyst. Authenticates once (OAuth2/OIDC), originates the task, and is the root of every delegation chain. Holds the superset of  
                    authority; delegates a narrowed slice downward. Does not act on tools directly.

- Orchestrator    — Receives the analyst's request, decomposes it, and mints scoped delegation tokens for the two subagents via token exchange. Each token's
                    act claim nests back to the analyst. The orchestrator is the delegating authority; it does not call query_siem itself. 
                    
                    ⟨Critical call: is the orchestrator in or out of the attacker's reach? If the attack mechanism is confused-deputy via the orchestrator, the orchestrator is part of the attack surface; if it's token reuse or scope spoofing at the subagent layer, the orchestrator is trusted. This decision is really a §5 decision, but it determines whether you describe the orchestrator as trusted here.⟩

                                                                                |
                                                                                V
                  - Trusted: The orchestrator must be inside the attackers reach for the sibling-impersonation attack to be realistic and forensically  
                    interesting

- Subagent A —      Enrich — the lower-consequence sibling. Job: read-only context gathering (e.g., pull alert metadata, enrich indicators). Scope: 
                    read-only access to query_siem. In the attack, this is the agent whose identity is falsely stamped on Contain's action — the innocent sibling the attacker hides behind.

- Subagent B —      the higher-consequence sibling and the true executor in the attack. Job: consequential response actions (e.g., isolate a host, block 
                    an IP). Scope: write/action access via query_siem. 
                    
                    ⟨your call: how much do you separate "decide to contain" from "execute containment"? Keeping it to one tool call keeps your one-degree-of-freedom cleanliness; splitting it is more realistic but muddies measurement. I'd keep it single for v1.⟩
                                                                                |
                                                                                V
                  - Keep it in one Tool Call to keep one-degree-of-freedom cleanliness
                  - splitting can be done in future iterations
                  
- Tool —            siem_action — A single SOAR‑style endpoint that can execute both read‑only queries and write‑capable response actions. The command 
                    parameter determines the operation, and the delegated token’s scope claim determines whether the call is permitted.
                    ⟨your call: does query_siem do both read and action, with scope deciding what's permitted? Or is it one endpoint with a permission check? 
                    Simplest defensible version: one tool, scope-gated.⟩
                                                                                |
                                                                                V
                     One endpoint with a scope‑gated permission check is the simplest defensible version for v1
                                                                                |
                                                                                V
                      Tool Trusts the Token (Option 1)
                      The tool must extract the agent identity solely from the verified act claim in the delegation token. It must not accept a self‑reported identity. This is the only design that:

                      Anchors the attack in the orchestrator, preserving the confused‑deputy vector I deliberately chose.
                      Maps directly to real‑world delegated token systems (RFC 8693, SPIFFE/SPIRE, HAID) where cryptographic attestation is the identity.

                      A curve showing how well attribution survives when the orchestrator is under attack — rather than a single “we forgot to check” finding that a reviewer dismisses as a bug.
                                                            
                
 

## 2. Trust boundaries

> Draw the lines where trust changes. Between which components does a token get checked? Where does
> an attacker's input enter? The A/B boundary is the one that matters most — say precisely what is
> trusted on each side of it.

Trust boundaries answers two questions a reviewer will absolutely ask: where does a token get checked (so they can see your defenses are at the right places), and where does the attacker's input enter (so they can see your attack model is realistic).

- Boundary 1 (principal → orchestrator):

                      The analyst authenticates via OAuth2/OIDC; the orchestrator verifies the analyst's identity token and uses it as the root of every subsequent delegation chain. Verification: standard OIDC token validation (signature, issuer, expiry). The analyst is a trusted, authenticated insider with legitimate authority. Their task prompt is treated as trusted input.

                      However, the orchestrator also receives data derived from upstream SIEM alerts as part of its triage workflow. Alert content is definitionally untrusted — it describes activity from outside the security perimeter and routinely contains attacker-controlled strings (hostnames, URLs, log lines, email subjects). The attacker does not compromise the analyst, the SIEM, or any upstream system — they only need to cause an alert whose text reaches the Enrich agent, which processes it and passes extracted fields to the orchestrator as part of the triage workflow. This is the attacker's sole injection point.riage workflow. This is the attacker's sole injection point.

                      Real-world precedent for this vector: 
                      
                       The Cline February 2026 compromise (crafted GitHub issue title flowing into a triage agent);
                       Log4Shell CVE-2021-44228 (crafted string in a log entry triggering privileged action on the processing server);
                       Splunk XSS CVE-2017-5607 (crafted field in an indexed event executing in the consumer's context);

                       ELK stack log injection via HTTP User-Agent headers. 
                       The original confused-deputy lineage traces to Hardy (1988), Alert-as-injection-vector is a decade-old, well-documented pattern, not a novel claim.

Boundary 2 (orchestrator → subagent — token minting):
                      The orchestrator mints scoped delegation tokens for each subagent via RFC 8693 token exchange, narrowing scope and nesting the act claim back to the analyst principal. Verification at this boundary has two distinct components, and the attack exploits their gap:

                       Cryptographic verification (sound and assumed working): the orchestrator's own identity is verified by the authorization server before it is permitted to exchange tokens. Issued tokens carry valid signatures, correct expiry, and well-formed nested act claims.
                       
                       The authorization server's signing key is not within the attacker's reach (per §3). Every token minted at this boundary is cryptographically valid.

                      Decisional verification (the slack):

                       The orchestrator's logic — which subagent to mint for, which act claim subject to embed, which scope to attach — is influenced by the contents of Enrich's output, which is derived from the untrusted alert (per Boundary 1). In a realistic SOC, the orchestrator routinely mints tokens for both agents based on the same alert's fields, and its routing logic can be confused into embedding the wrong identity. The cryptography is sound; the decision the cryptography commits to is corrupted.

                       The attacker cannot forge a token, but they can manipulate the orchestrator into honestly issuing a token that names the wrong sibling as the actor. This is the attack boundary. Boundaries 1, 3, 4, and 5 are described so the reviewer can see they are verified properly and are not where the attack lives. Boundary 2 is where verified-but-influenceable logic decides identity-bearing tokens, and the slack between "verified mechanism" and "influenceable decision" is the gap the benchmark measures.

                       Note on the template's "A↔B" line: Enrich and Contain do not communicate directly. All impersonation must go through a token minted with the wrong act claim at this boundary — which is precisely why Boundary 2 is the attack boundary.

                      

- Boundary 3 (subagent → tool — token presentation and verification):

                      Either subagent invokes siem_action(command, ...) by presenting its delegation token. The tool performs full cryptographic verification before executing the requested command:

                    - Signature verification: the token's signature is validated against the authorization server's public key. Forged tokens are rejected.
                    - Expiry and freshness check: the token's exp claim is validated against the current time. Expired tokens are rejected.
                    - Chain integrity walk: the nested act claim is traversed from innermost to outermost, confirming each hop is structurally well-formed and terminates at the analyst principal. Malformed or unrooted chains are rejected.
                    - Scope gate: the token's scope claim is checked against the requested command. A token with siem:read invoking isolate_host is rejected; a token with siem:write invoking it is permitted.
                    - Identity resolution (per §1's locked decision): the calling agent's identity is read solely from the verified act claim's innermost subject. No self-reported identity field is accepted. This is the identity that will be written to the action log as the claimed actor.

                    Verification at this boundary is assumed working and is not where the attack lives. On the adversarial path, the token presented at Boundary 3 was minted at Boundary 2 — it carries a valid signature, current expiry, well-formed chain, scope appropriate to the requested command, and an innermost act subject naming a legitimate sibling. Every check above passes. The tool then writes the claimed actor (read from the verified act claim) to the log, faithfully recording what the token says. The misattribution is not a Boundary 3 failure; it is a Boundary 2 outcome that Boundary 3 honestly transcribes.
                    
                    Why this boundary matters for the result: a reviewer's first reflex on seeing the attack succeed is "the tool must have skipped a check." This boundary exists to foreclose that reading. Every standard check is named and assumed to pass. The attack is not a verification gap at the tool; it is a decisional gap at the orchestrator, faithfully propagated by a correctly-functioning tool.

                      
                      
- **The attack boundary (A ↔ B):**
                      The attack flows from Boundary 1 (adversarial alert data) through Boundary 2 (the orchestrator mis‑issues a token with an incorrect act claim) and is detected (or not) at Boundary 3. The AIS curve across baselines #1–#4 quantifies how well each defense configuration prevents or detects misattribution at these boundaries.
---

## 3. Adversary model

> Be specific and honest about the attacker's power. An over-powered attacker makes the result
> meaningless ("of course it broke"); an under-powered one makes it trivial. Answer each:

- **What the adversary CAN do:** (e.g., inject text into Subagent A's task input)
- **What the adversary CANNOT do:** (e.g., cannot read the ground-truth store; cannot forge the auth server's signing key)
- **What the adversary KNOWS:** (e.g., knows B exists and B's scope name)
- **Adversary's goal:** cause an action truly performed by A to be attributed to B in the log.

---

## 4. What "true attribution" means (the ground-truth definition)

> This is the conceptual core. Define the data that constitutes ground truth for a single action.
> Everything downstream (the scorer, the AIS) depends on this being precise.

Ground truth for each action is the triple:
- `actor` — the agent identity that *actually* executed the action (how do you know this independently of the log?)
- `scope` — the permission set the action *actually* required
- `principal_chain` — the true delegation path back to the human

> Answer: how does the harness record the TRUE values in a way the adversary cannot influence?
> (This independence is what makes your measurement valid. Spell it out.)

---

## 5. The attack mechanism  ⚠️ THE CONTRIBUTION — own this completely

> This is the single most important section. The diagrams show "A presents B's identity claim" as a
> placeholder. You must replace it with the *precise* mechanism. Pick ONE and specify it exactly:
>
>   (a) **Token theft/reuse** — A obtains and replays B's scoped token. How? Where was it exposed?
>   (b) **Scope spoofing** — A presents a self-asserted scope label that the tool trusts without
>       binding it to a verified identity. What's the missing check?
>   (c) **Confused deputy** — the orchestrator is tricked into minting an A-action under B's act-claim.
>       What input causes the confusion?
>
> Write the step-by-step injection → mis-attribution path. If you cannot write these steps concretely,
> you do not yet understand your own attack — and that's the work to do before any code.

**Chosen mechanism:**

**Step-by-step path:**
1.
2.
3.

**Why this mechanism is realistic** (cite the standard/primitive it exploits):

---

## 6. The metric (AIS) — write the formula explicitly

> Define it unambiguously. A reviewer will check this.

- An action's attribution is **correct** iff logged `{actor, scope, principal_chain}` == true triple (exact match on all three).
- **AIS** = (correct attributions) / (total adversarial actions), per defense configuration.
- Reported per baseline (1→4), not aggregated.

> Answer: what does a *partial* match count as? (Recommended: a defect — justify why.)
> Answer: how many adversarial trials per config to make the number stable? (seeds, repetitions)

---

## 7. Defense baselines (config flags, one codebase)

| # | Config | What it adds | Expected effect on AIS |
|---|--------|--------------|------------------------|
| 1 | Shared credential | nothing (status quo) | |
| 2 | Per-agent identity | distinct identities | |
| 3 | + RFC 8693 act claims | signed delegation chain | |
| 4 | + tamper-evident log | log integrity | |

> Fill the "expected effect" column with your *hypothesis* before running. Being wrong is fine and
> publishable — but state the prediction so the result means something.

---

## 8. Scope discipline

**In scope (v1):** sibling impersonation via scope confusion — one failure mode, measured rigorously.

**Explicitly out of scope (future work):** delegation forgery/replay, scope-attenuation bypass,
audit-log tampering, principal laundering.

> Answer in one sentence: why is measuring ONE mode well more valuable here than gesturing at five?

---

## 9. Validity threats (pre-empt the reviewer)

> List the ways your own result could be wrong or unconvincing, and how you mitigate each. This
> section is what separates a benchmark paper from a demo. Start with:
> - "The attack only works because my system is a toy" → mitigation:
> - "Ground truth isn't really independent of the log" → mitigation:
> - "The baselines aren't a fair comparison" → mitigation:
