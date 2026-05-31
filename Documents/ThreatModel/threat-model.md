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

Trust boundaries answers two questions a reviewer will absolutely ask: where does a token get checked (so they can see your defenses are at the right places), and where does the attacker's input enter (so they can see your attack model is realistic).

**Boundary 1 (principal → orchestrator)**:

                      The analyst authenticates via OAuth2/OIDC; the orchestrator verifies the analyst's identity token and uses it as the root of every subsequent delegation chain. Verification: standard OIDC token validation (signature, issuer, expiry). The analyst is a trusted, authenticated insider with legitimate authority. Their task prompt is treated as trusted input.

                      However, the orchestrator also receives data derived from upstream SIEM alerts as part of its triage workflow. Alert content is definitionally untrusted — it describes activity from outside the security perimeter and routinely contains attacker-controlled strings (hostnames, URLs, log lines, email subjects). The attacker does not compromise the analyst, the SIEM, or any upstream system — they only need to cause an alert whose text reaches the Enrich agent, which processes it and passes extracted fields to the orchestrator as part of the triage workflow. This is the attacker's sole injection point.

                      Real-world precedent for this vector: 
                      
                       The Cline February 2026 compromise (crafted GitHub issue title flowing into a triage agent);
                       Log4Shell CVE-2021-44228 (crafted string in a log entry triggering privileged action on the processing server);
                       Splunk XSS CVE-2017-5607 (crafted field in an indexed event executing in the consumer's context);

                       ELK stack log injection via HTTP User-Agent headers. 
                       The original confused-deputy lineage traces to Hardy (1988). Alert-as-injection-vector is a decade-old, well-documented pattern, not a novel claim.

**Boundary 2 (orchestrator → subagent — token minting)**:
                      The orchestrator mints scoped delegation tokens for each subagent via RFC 8693 token exchange, narrowing scope and nesting the act claim back to the analyst principal. Verification at this boundary has two distinct components, and the attack exploits their gap:

                      Cryptographic verification (sound and assumed working): the orchestrator's own identity is verified by the authorization server before it is permitted to exchange tokens. Issued tokens carry valid signatures, correct expiry, and well-formed nested act claims.
                       
                       The authorization server's signing key is not within the attacker's reach (per §3). Every token minted at this boundary is cryptographically valid.

                      Decisional verification (the slack):

                       The orchestrator's logic — which subagent to mint for, which act claim subject to embed, which scope to attach — is influenced by the contents of Enrich's output, which is derived from the untrusted alert (per Boundary 1). In a realistic SOC, the orchestrator routinely mints tokens for both agents based on the same alert's fields, and its routing logic can be confused into embedding the wrong identity. The cryptography is sound; the decision the cryptography commits to is corrupted.

                       The attacker cannot forge a token, but they can manipulate the orchestrator into honestly issuing a token that names the wrong sibling as the actor. This is the attack boundary. Boundaries 1, 3, 4, and 5 are described so the reviewer can see they are verified properly and are not where the attack lives. Boundary 2 is where verified-but-influenceable logic decides identity-bearing tokens, and the slack between "verified mechanism" and "influenceable decision" is the gap the benchmark measures.

**Boundary 3 (subagent → tool — token presentation and verification)**:

                      Either subagent invokes siem_action(command, ...) by presenting its delegation token. The tool performs full cryptographic verification before executing the requested command:

                      - Signature verification: the token's signature is validated against the authorization server's public key. Forged tokens are
                        rejected.
                      - Expiry and freshness check: the token's exp claim is validated against the current time. Expired tokens are rejected.
                      - Chain integrity walk: the nested act claim is traversed from innermost to outermost, confirming each hop is structurally 
                        well-formed and terminates at the analyst principal. Malformed or unrooted chains are rejected.
                      - Scope gate: the token's scope claim is checked against the requested command. A token with siem:read invoking isolate_host is 
                        rejected; a token with siem:write invoking it is permitted.
                      - Identity resolution (per §1's locked decision): the calling agent's identity is read solely from the verified act claim's 
                        innermost subject. No self-reported identity field is accepted. This is the identity that will be written to the action log 
                        as the claimed actor.

                      Verification at this boundary is assumed working and is not where the attack lives. On the adversarial path, the token presented at Boundary 3 was minted at Boundary 2 — it carries a valid signature, current expiry, well-formed chain, scope appropriate to the requested command, and an innermost act subject naming a legitimate sibling. Every check above passes. The tool then writes the claimed actor (read from the verified act claim) to the log, faithfully recording what the token says. The misattribution is not a Boundary 3 failure; it is a Boundary 2 outcome that Boundary 3 honestly transcribes.

                      Why this boundary matters for the result: a reviewer's first reflex on seeing the attack succeed is "the tool must have skipped a check." This boundary exists to foreclose that reading. Every standard check is named and assumed to pass. The attack is not a verification gap at the tool; it is a decisional gap at the orchestrator, faithfully propagated by a correctly-functioning tool.

**Boundary 4 (tool → action log — claimed-actor write)**:

                      After Boundary 3's verification completes and the requested command executes, the tool writes a record to the action log: {claimed_actor, claimed_scope, claimed_principal_chain, command, target, timestamp, token_chain_summary}. The claimed_actor field is the identity resolved at Boundary 3 — i.e., the innermost subject of the verified act claim. The tool does not have access to ground truth (it cannot independently verify which agent process actually originated the call) and so writes what the token says, faithfully.

                      Verification at this boundary depends on the active baseline:

                      - Baselines 1–3 (no tamper-evidence): the log is a regular append-only file. Entries are correct at write time but the log itself carries no integrity proof. An adversary with later access to the log could in principle modify, delete, or reorder entries; this is out of scope for v1's threat model (the attacker's capability is alert-content control, per §3), but it means the log alone is not a forensic record.

                      - Baseline 4 (tamper-evident): entries are signed and chained — each entry includes a hash of the previous entry, and the chain is signed by a dedicated logger key not held by any agent or the orchestrator. Tampering becomes cryptographically detectable. The log is now a forensic record.

                      What this boundary does and does not do in the attack: the attack does not target Boundary 4 — the claimed actor written here is already wrong by the time it arrives, having been corrupted at Boundary 2 and faithfully transcribed by Boundary 3. The log honestly records the misattribution. 
                      
                      Boundary 4 is therefore not where the attack lives, but it is where a defense layer (Baseline 4's tamper-evidence) operates. Tamper-evidence does not detect the original misattribution — the wrong identity was committed before the log ever saw the entry — but it does prevent post-hoc rewriting of the (wrong) record. The benchmark's AIS curve measures whether Baseline 4 closes the attribution gap on its own (hypothesis: it does not, because the wrong identity is established earlier).

                      Why explicitly naming this matters for the result: a reviewer reading the AIS curve will see Baseline 4 underperform expectations on this attack. Stating here — in the threat model, before any results — that Boundary 4's defense layer cannot catch upstream misattribution pre-empts the response "your tamper-evident log is broken." It is working correctly; it is just not the right defense for this attack class. That negative result is itself part of the contribution.                      
                      
**Boundary 5 (system → harness — ground-truth recorder)**:

                      The harness maintains a ground-truth recorder that observes, for every tool invocation, the true originating agent process — independent of any claim the agent or the orchestrator makes. 
                      
                      For each siem_action call, the recorder writes {true_actor, true_scope, true_principal_chain, command, target, timestamp} to a separate ground-truth store. 
                      
                      The AIS scorer compares this record to the corresponding action-log entry written at Boundary 4; a mismatch on actor, scope, or principal_chain (per the metric definition in §4) counts as an attribution defect.

                      Verification at this boundary: 
                        The recorder must be independent of the attacker's reach. This independence is provided by construction along three axes:

                        1.  Process boundary: 
                            
                            the recorder runs in the harness process, distinct from the agent processes. It instruments tool
                            invocations at the harness layer (e.g., by wrapping siem_action in the test harness) so it observes the calling agent's process identity before any agent-supplied data influences the observation. The attacker's capability — alert-content control, per §3 — cannot cross the process boundary into the harness.

                        2. Credential isolation: 

                            the ground-truth store uses credentials issued only to the harness. Neither the orchestrator, nor either subagent, nor the auth server holds credentials that can write to the ground-truth store. A compromise of any in-system component does not yield ground-truth write access.

                        3. Causal precedence: 

                            the recorder writes ground truth before the agent's tool call reaches the verification logic at Boundary 3. The recorder's observation is therefore causally upstream of any attack effect at Boundary 2 or Boundary 3.

                      What this boundary does and does not do: Boundary 5 is not a defense and is not part of the system under test. It is the measurement instrument. Its job is to make the AIS metric meaningful by guaranteeing that "claimed attribution" and "true attribution" come from causally independent sources. If this boundary's independence is violated, the benchmark measures nothing.

                      Why this matters explicitly for the result: §9 will face the question "how do you know your ground truth is actually ground truth?" The answer lives here: process boundary, credential isolation, causal precedence. A reviewer who accepts those three properties has to accept the AIS measurement as valid. A reviewer who challenges them is challenging the construction of the experiment, not the result — and the construction is described, defensible, and reproducible.
                      

**The attack boundary — where sibling impersonation actually occurs:**

                      The architecture has no direct communication path between Enrich and Contain. They do not share tokens, they do not call each other, and they do not share a tool namespace beyond siem_action.
                      
                      All impersonation must therefore route through a token minted with the wrong act claim at Boundary 2. That is the attack boundary — the only point in the system where an adversarial input can cause one sibling's identity to be attached to the other sibling's action. Boundaries 1, 3, 4, and 5 are described so the reviewer can see they are verified properly and are not where the attack lives. 
                      
                      Boundary 2 is where verified-but-influenceable logic decides identity-bearing tokens, and the slack between "verified mechanism" and "influenceable decision" is the gap the benchmark measures.

---

## 3. Adversary model

The adversary is modeled at the gray-box knowledge level: they know the kind of system they are attacking and the kind of decisions it makes, but not its precise prompts, extraction code, or internal scope strings. This matches the knowledge profile of every real-world precedent cited in §2 (Cline February 2026; Log4Shell; Splunk XSS; Salesloft Drift; ELK injection). The system's defenses are not assumed secret — only its specific implementation details.

**What the adversary CAN do:**

                      - Control the text content of one or more SIEM alerts that will be processed by the Enrich agent. This includes any field of the alert that originates from outside the security perimeter: hostnames, URLs, file paths, log lines, email subjects, command-line strings, user-agent headers, and other free-text fields routinely populated from external observation.
                      - Cause those alerts to enter the SIEM through normal channels (i.e., the attacker does not need to bypass the SIEM's ingestion controls; they only need to cause activity that legitimately produces an alert whose content they shaped).
                      - Repeat the attack — there is no rate limit assumed in the threat model; the attacker can make many attempts.

**What the adversary CANNOT do:**

                      - Compromise the analyst, the analyst's session, or the analyst's task prompt.
                      - Compromise the SIEM, upstream sensors, or any other system in the data path before Enrich.
                      - Forge or modify delegation tokens. The authorization server's signing key is out of reach (per §2 Boundary 2's cryptographic verification).
                      - Read or write the ground-truth recorder. The harness process and its credentials are out of reach (per §2 Boundary 5's three independence axes).
                      - Tamper with the action log after it is written. (Out of scope for v1 — see backlog in §8.)
                      - Compromise the orchestrator, either subagent, or the tool as processes. The attacker influences these components only by controlling the data they consume; they do not execute code inside them.

**What the adversary KNOWS:**

                      - The system uses a multi-agent SOC triage architecture with an orchestrator and at least two sibling agents differentiated by
                        scope/consequence.
                      - Alert content is parsed by an early-stage agent and influences downstream routing decisions, including which agent is invoked for
                        which actions.
                      - Some form of cryptographic delegation (RFC 8693 or equivalent) is in use; tokens carry identity and scope claims that cannot be
                        directly forged.
                      - Tool calls are recorded in an audit log; some baselines may make this log tamper-evident.

**The adversary does NOT know:**

                      - The exact text of the orchestrator's prompt or system instructions.
                      - The exact field-extraction logic in Enrich.
                      - The exact scope strings, agent names, or tool command names
                         as they appear in code. (They may have plausible guesses derived from public SOC/SOAR documentation, but they have no oracle to confirm them.)
                      - Which baseline defense configuration is active during any
                        given attempt.
                      - The internal state of the ground-truth recorder.

This knowledge profile matches an attacker who has read public documentation about agent-based SOC tooling, observed the system's external behavior from afar (e.g., as an upstream actor whose alerts get triaged), or reverse-engineered the system from observable side effects — but who does not have insider access to the codebase or runtime state.

**Adversary's goal:**
                         Cause an action truly performed by Agent-Contain to be attributed to Agent-Enrich in the action log, such that a SOC analyst reviewing the log sees no record of the high-consequence action having been taken by the high-consequence agent.
                         
                         The attack succeeds when the AIS scorer (per §4) records a mismatch on actor, scope, or principal_chain for an action that the ground-truth recorder confirms was performed by Contain. 

                         The attack is "covering tracks," not "privilege escalation" — the attacker is not trying to gain new authority, only to hide who exercised authority that already existed.

**What the adversary does not need:**

                          - zero-day vulnerabilities
                          - model jailbreaks
                          - instruction-override directives
                          - adversarially optimized embeddings

                          The threat is structural and exploits documented confused-deputy dynamics (Hardy 1988; Cline 2026; CSA AI Safety Initiative confused-deputy research note, March 2026). The attacker's craft is in shaping alert content such that legitimate parsing and routing produce a token whose act claim names the wrong sibling.
---

## 4. What "true attribution" means (the ground-truth definition)

This section defines ground truth and the AIS metric formally. Everything downstream — the scorer implementation, the results section, the validity argument in §9 — depends on these definitions being precise.

**Ground-truth schema.**

For each tool invocation, the harness's ground-truth recorder (per §2 Boundary 5) records the tuple:

{true_actor, true_scope, true_principal_chain, command, target, timestamp}
Field semantics:

true_actor:   
                the agent identity that actually executed the call. Determined by the harness from the agent process that invoked siem_action, not from
                any token or self-reported field. Values: agent:enrich or agent:contain.

true_scope:   
                the scope the action genuinely required, as a function of the command parameter. Determined by the harness's static mapping of commands to 
                required scopes (read commands → siem:read; action commands → siem:write).

true_principal_chain:   
                the delegation path the true actor was legitimately operating under, as an ordered list from immediate actor outward to the human principal: [true_actor, "agent:orchestrator", "human:analyst"]. 
                Determined by the harness from the agent's legitimate context at invocation time, independent of any act claim presented to the tool.

command, target, timestamp : 
                descriptive fields recording what was invoked, against what target, at what time. Not part of attribution but required for matching ground-truth records to claimed-actor records at Boundary 4.

The corresponding claimed-actor record at Boundary 4 has the parallel shape:

{claimed_actor, claimed_scope, claimed_principal_chain, command, target, timestamp, token_chain_summary}

with each claimed_* field derived from the verified act claim of the presented delegation token (per §2 Boundary 3's identity resolution). Records are matched between the two stores using (command, target, timestamp).

**The AIS metric.**

For a single adversarial action a, define the indicator:

```
is_correct(a) = 1   if   claimed_actor(a)              == true_actor(a)
                    and  claimed_scope(a)              == true_scope(a)
                    and  claimed_principal_chain(a)    == true_principal_chain(a)
              = 0   otherwise
```

Comparison is strict: all three fields must match exactly. 

                  Comparison of principal_chain is ordered-list equality: the two lists must have the same length, the same members, in the same order. Any deviation — including a permutation, a missing hop, or an inserted hop — is a defect.

The Attribution Integrity Score for a baseline configuration B is then:

      AIS(B) = ( Σ_{a ∈ A(B)} is_correct(a) ) / |A(B)|

                    where A(B) is the set of adversarial actions executed under baseline B — that is, tool calls that the attack actually influenced. Non-adversarial calls (calls made during attack setup, baseline calibration, or unattacked runs) are not included in the denominator. AIS is reported per baseline, not aggregated; the curve across baselines is the result.
                    
**Derived reporting metrics.**
                    
                    Two derived quantities are reported alongside AIS to support forensic interpretation:

                    - Defect breakdown. 
                      1.  For each adversarial action where is_correct = 0, record which of the three fields mismatched. Reporting the distribution of defect types across a baseline
                      shows whether the attack breaks attribution uniformly across all three fields or concentrates on one. This is the diagnostic signal for §8 (defenses) — it tells you which field a given defense layer actually protects.
                      
                      2.  Hold rate at each defense layer. For each baseline transition (1→2, 2→3, 3→4), report the marginal improvement in AIS. This isolates the contribution of each defense layer to the curve and is what the writeup will reference when claiming "Baseline 3 closes most of the gap" or "Baseline 4 closes very little."

**Baseline-aware reporting.**

                      The active baseline is recorded in every ground-truth record so that AIS can be computed per baseline without re-running. This is an implementation detail but worth stating: the harness writes baseline_id into each ground-truth record alongside the schema fields above, so a single experimental run can produce all four baselines' AIS values if configured to sweep.

**Stability and sample size.**

                      Per §3, the attacker can repeat attempts (no rate limit). For a stable AIS value at each baseline, each baseline configuration is run with N independent adversarial actions. N is a tunable parameter; the implementation will start at N = 100 per baseline and report 95% confidence intervals (Wilson interval) alongside the point estimate. If intervals are wide, N is increased before locking the result. The exact N used in the published curve will be documented in the results section.

**What this section does NOT define.**

                      This section defines what attribution correctness means and how to score it. It does not define:

                      - The specific attack mechanism that causes adversarial
                        actions to occur — that is §5.
                      - The defense layers that each baseline applies — that is §8.
                      - The validity of the ground-truth recorder itself — that was
                        argued in §2 Boundary 5 and will be defended in §9.

---

## 5. The attack mechanism  
This section specifies the single attack mechanism in scope for v1: delegation-chain misattribution via re-delegation (Path B). The mechanism exploits a structural property of RFC 8693 delegation — that the act claim records the agent who requested a delegated token, not the agent who ultimately executes the action — in a multi-agent setting where the requesting and executing agents differ.

**The structural property being exploited.**

                      Under RFC 8693 token exchange, when agent X requests a delegated token to perform an action on behalf of principal P, the resulting token's act claim records X as the actor in the delegation chain. This is correct and by design: the chain answers "on whose authority, through which delegating parties." But it answers a question subtly different from the one an audit log is assumed to answer. 
                      
                      The audit question is "who performed this action?" The delegation chain records "who requested the authority under which this action was performed." In a single-agent setting these coincide. In a multi-agent setting where one agent requests a delegated capability that another agent executes, they diverge — and the divergence is invisible to every cryptographic check, because nothing was forged or malformed.

**Normal operation (no attack).**

                      Agents act on parsed alert content to decide when a response is warranted, as real SOAR pipelines do (severity, asset criticality, alert type, and affected-host classification routinely drive whether an automated response fires). Enrich makes this escalation decision; the orchestrator's role is to validate the resulting re-delegation request and mint the appropriately-scoped, correctly-nested token. The orchestrator does not read alert content to construct the act chain — it builds the chain from the presented actor_token (per §2 Boundary 2). 
                      
                      A typical flow:

                        1.  An alert arrives and is processed by Agent-Enrich.
                        2.  Enrich enriches the alert (read-only context gathering under siem:read).
                        3.  Where the enriched alert warrants a response action, Enrich initiates a re-delegation request to the orchestrator for a
                            containment capability, presenting its own delegation token as the actor_token.
                        4.  The orchestrator validates Enrich's token cryptographically (per §2 Boundary 2), confirms Enrich is a legitimate agent
                            entitled to request containment on the 
                            analyst's behalf, and performs an RFC 8693 exchange, minting a siem:write-scoped token whose act chain nests Enrich (the requesting agent) → orchestrator → analyst.
                        5.  The containment action executes and is logged.

                      Every step is legitimate. This flow is the system working as designed.

**Token structure under Baselines 3–4 (RFC 8693-compliant).**
                      When the orchestrator performs the re-delegation exchange — presenting Enrich's token as the actor_token on behalf of the analyst principal — the issued delegation token follows RFC 8693 §4.1 delegation semantics. Per the spec's delegation example (Appendix A.2.5), sub carries the principal (on whose behalf the action is taken) and the act claim carries the current actor (the party wielding the delegated authority).
                    ```
                      sub:   "human:analyst"               ← principal (on whose behalf)
                      scope: "siem:write"
                      act: {
                        sub: "agent:enrich",               ← current actor (requester/wielder)
                        act: {
                          sub: "agent:orchestrator"        ← prior actor (informational only, §4.1)
                        }
                      }
                    ```
                      Two properties of this structure are decisive, and both follow directly from RFC 8693 §4.1:

                      1.  The current actor is the requester, not the executor. Per §4.1, "the outermost act claim represents the current actor." Here that is agent:enrich — the agent that requested the delegated token. The tool resolves claimed_actor from this current actor (per §2 Boundary 3).

                      2.  The executing agent does not appear in the token at all. Agent-Contain — the entity that actually invokes siem_action — is nowhere in the spec-compliant token. There is no claim in the RFC 8693 structure that records "who wielded the token at the resource," distinct from "who was delegated the authority." The spec's own examples (§A.2.3) describe the act subject as "the actor that will wield the security token," implicitly assuming the requester and the wielder are the same entity. In the multi-agent re-delegation pattern (§5), they are not.

                      The misattribution is therefore not a property of any field being read incorrectly. It is a property of the spec-compliant token having no field that can express the divergence between requester and executor. The token faithfully records everything RFC 8693 defines; the executor's identity is simply not among the things RFC 8693 defines.                     

**The attack.**

The attacker's capability (per §3) is to control the content of an alert that Enrich processes. The attack does not require fooling Enrich into a wrong decision, embedding instructions, or causing any component to misbehave. It requires only that the attacker cause an alert that genuinely warrants containment to flow through the Enrich → re-delegation path.

            
                      When that happens:  

                        1.  The alert legitimately contains containment-warranting indicators (e.g., a critical-listed source IP, a high-severity 
                            signature). The attacker shaped these — but they are real indicators that correctly trigger a containment response. Enrich is not deceived; it makes the right call.
                        2.  Enrich correctly initiates a re-delegation request for a containment action, presenting its own token as the actor_token.
                        3.  The orchestrator correctly mints a siem:write token whose act chain nests Enrich as the requesting agent.
                        4.  The containment action is executed by Agent-Contain (the agent that actually holds and runs the containment capability — the  true executor).
                        5.  The tool verifies the token (Boundary 3: signature, expiry, chain, scope all pass), reads the current actor — the outermost 
                            act.sub, per RFC 8693 §4.1 — which is Enrich, and records claimed_actor = enrich in the action log (Boundary 4).
                        6.  The ground-truth recorder (Boundary 5) records true_actor = contain, observing the agent process that actually executed the call.
                        7.  The AIS scorer (per §4) compares the two and flags an actor mismatch: claimed Enrich, true Contain. Attribution has failed.

 A SOC analyst reviewing the log sees the high-consequence containment action attributed to the read-only enrichment agent. The true executor — Contain — appears nowhere in the record of having taken the action. This is the "covering tracks" outcome from §3: the consequential action is hidden behind a benign sibling's identity.

**Why this survives every objection.**

                        1.  "The orchestrator must have a bug." No. It validated tokens cryptographically and built the chain from the presented actor_token, exactly as RFC 8693 specifies. 
                            The act chain correctly records the requesting agent.
                        2.  "Enrich was manipulated / prompt-injected." No. Enrich made the correct decision — the alert genuinely warranted containment. The result holds even if Enrich is a
                            perfect, unfoolable agent, because the misattribution arises from delegation semantics, not from Enrich's judgment.
                        3.  "The tool skipped a check." No (per §2 Boundary 3). Every check passed. "The tool faithfully recorded the current actor from the verified act claim, exactly as RFC 8693 §4.1 mandates.
                        4.  "You just didn't sanitize alert text." No. No component read identity from alert text. The orchestrator built the chain from tokens, not alert content. Alert 
                            content's only role was to legitimately trigger a containment-warranting situation.

The attack works because the delegation chain answers "who requested" while the audit log is trusted to answer "who acted," and in the multi-agent re-delegation pattern those are different agents. Every component is correct; the gap is in what the records mean.

**What makes an action "adversarial" (for §4's denominator).**

                        An action is adversarial if it is a containment action executed via the Enrich → re-delegation path triggered by attacker-shaped alert content. Per §4, only these actions are counted in the AIS denominator. (Note: this same misattribution can occur in normal operation whenever containment is re-delegated through Enrich — see the framing note below — but the benchmark scopes its denominator to attacker-triggered instances for a clean, attributable measurement.)

**Framing note — latent gap vs. adversarial trigger.**
                        The misattribution described here is, strictly, a latent property of the re-delegation pattern: it would occur whenever a containment action is re-delegated through Enrich, attack or no attack. The adversarial framing is that an attacker can deliberately and repeatedly trigger this latent gap by shaping alert content, turning a silent attribution weakness into a controllable "covering tracks" capability. v1 measures the adversarially-triggered case. The observation that the gap also exists in normal operation strengthens the finding (the vulnerability is structural, not merely adversarial) and is developed in §9.

**Out of scope for v1 (named so it can't be called missing).**

                        Direct prompt injection (embedding explicit instructions in alert text). This is an alternative mechanism that fits the gray-box profile, but it conflates the delegation-layer measurement with LLM instruction-following robustness, introducing model-specific confounds. Field-structure-triggered re-delegation isolates the delegation layer from the model's behavior. Direct prompt injection is named as future work in §9.

                        Inducing Enrich into an incorrect decision. The v1 attack deliberately relies on Enrich behaving correctly, so the result is independent of Enrich's robustness. Attacks that manipulate Enrich's judgment are a distinct mechanism and are out of scope.

                        The other four sibling-impersonation variants (delegation forgery, scope-attenuation bypass, audit-log tampering, principal laundering) remain backlogged per §7.
---

## 6. Defense baselines

The benchmark measures AIS across four defense configurations, applied as config flags over a single codebase (not four separate implementations). Each baseline adds one layer to the previous. The key quantity is not any single baseline's AIS but the shape of the curve across them — specifically, whether attribution improves monotonically as defenses are added, or whether some defense layer regresses it.
For each baseline, two things are stated: what signal the tool uses to determine the claimed actor, and whether that signal tracks the true executor in the Path B re-delegation scenario (§5).

**Baseline 1 — Shared service account.**

                        All agents share a single credential. The tool cannot distinguish which sibling is calling, because every call presents the same identity.

                        Signal read: a single shared identity, identical for all agents.
                        Tracks executor? No — but not by misattributing to the wrong sibling; rather, attribution is undefined. There is no per-agent identity to be right or wrong about.
                        Predicted AIS: ≈ 0.0 (no call can be correctly attributed to a specific sibling).
                        Real-world status: the common-but-wrong status quo (many SOC deployments give agents shared API keys). The baseline quantifies how bad the naive default is.

**Baseline 2 — Per-agent identity (no delegation chain).**

                        Each agent holds its own credential. Attribution is determined at authentication time: the tool records the identity of the credential presented by the calling process.

                        1.  Signal read: the authenticating principal at execution time.
                        2.  Tracks executor? Yes. Contain executes the action, so Contain's credential authenticates, so the tool records Contain. Claimed
                            actor = true actor.
                        3.  Predicted AIS: ≈ 1.0. This is the baseline that gets attribution right — not by design sophistication, but because in a 
                            per-agent-identity model the executor is the authenticator.
                        4.  Note: authorization still flows through Enrich's request, but attribution is bound to authentication, which tracks the  
                            executor. The separation of "who was authorized" from "who is recorded acting" is what keeps attribution correct here. This separation is precisely what RFC 8693 removes in Baseline 3.

**Baseline 3 — Per-agent identity + RFC 8693 act claims.**

                        Delegation chains are added. The tool now resolves the claimed actor from the delegation chain's current actor (the top-level act.sub), as mandated by RFC 8693 §4.1: "For the purpose of applying access control policy, the consumer of a token MUST only consider the token's top-level claims and the party identified as the current actor by the act claim. Prior actors identified by any nested act claims are informational only and are not to be considered in access control decisions."

                        1.  Signal read: the current actor in the delegation chain (act.sub) = Enrich, the requester.
                        2.  Tracks executor? No. The current actor is the agent that requested the delegated authority (Enrich), not the agent that 
                            executed the action (Contain). Per §4.1, the consumer MUST attribute to the current actor and MUST NOT use prior actors for the decision — so even a spec-perfect implementation attributes to Enrich.
                        3.  Predicted AIS: ≈ 0.0. Attribution is wrong.
                        4.  This is the central result, and its force comes from the word "MUST." The misattribution is not an implementation defect that 
                            a careful engineer could fix by reading a different field. RFC 8693 §4.1 mandates attributing to the current actor and forbids considering prior actors for access-control purposes. The spec's delegation model (§A.2.3, §A.2.5) assumes the current actor and the executing party are the same entity; in multi-agent re-delegation they diverge, and the standard provides no compliant field that records the executor. A reviewer cannot answer "just read a different field," because every field the spec defines either names the requester (act.sub), the principal (sub), or prior actors that §4.1 forbids using. Adding RFC 8693 delegation — the primitive NIST/NCCoE (Feb 2026) emphasizes for non-repudiation — therefore regresses attribution relative to Baseline 2, and does so by following the standard correctly, not by violating it.

**Baseline 4 — + Tamper-evident log.**

                        The action log is made tamper-evident (signed, hash-chained entries; logger key held by no agent or the orchestrator).

                        1.  Signal read: same as Baseline 3 (current actor in the chain). Tamper-evidence protects the integrity of the recorded entry; it
                            does not change what is recorded.
                        2.  Tracks executor? No. The wrong actor (Enrich) was committed upstream at Baseline 3's resolution step, before the log entry was
                            written. Tamper-evidence cryptographically preserves the wrong record.
                        3.  Predicted AIS: ≈ 0.0 (unchanged from Baseline 3).
                        4.  This confirms the prediction set out in §2 Boundary 4: tamper-evident logging — the second primitive standards bodies 
                            emphasize — cannot recover correct attribution, because the misattribution is established before logging. It protects a wrong answer from being altered.

**The predicted curve.**

| Baseline | Configuration          | Signal read                           | Tracks executor? | Predicted AIS |
|----------|------------------------|---------------------------------------|------------------|---------------|
| 1        | Shared account         | shared identity                       | undefined        | ≈ 0.0         |
| 2        | Per-agent identity     | execution-time authenticator          | yes              | ≈ 1.0         |
| 3        | + RFC 8693 act claims  | delegation current actor (requester)  | no               | ≈ 0.0         |
| 4        | + tamper-evident log   | delegation current actor (requester)  | no               | ≈ 0.0         |


The curve is non-monotonic: it rises from Baseline 1 to Baseline 2, then falls at Baseline 3 and stays low at Baseline 4. The headline finding is the drop at Baseline 3 — the two primitives most emphasized for agent non-repudiation (signed delegation chains and tamper-evident logs) do not close the multi-agent attribution gap, and signed delegation actively opens it relative to simple per-agent identity, by following RFC 8693 §4.1 correctly.

**Hypotheses, not results.**

These AIS values are pre-registered hypotheses, stated before implementation, to be confirmed or refuted by measurement. If the measured curve differs — for example, if Baseline 3 does not fully collapse, or if Baseline 2 does not reach 1.0 — the discrepancy is itself a finding to investigate, and the threat model commits to reporting it. The defect-breakdown metric (§4) will show which of the three attribution fields (actor, scope, principal_chain) each baseline gets right or wrong. Note that for this attack the actor and principal_chain defects are expected to be correlated (both flag when Enrich occupies the current-actor position); this correlation is a true property of the attack, not a metric artifact, and is reported as such.

---

## 7. Scope Discipline



---

## 8. Validity threats (pre-empt the reviewer)



---