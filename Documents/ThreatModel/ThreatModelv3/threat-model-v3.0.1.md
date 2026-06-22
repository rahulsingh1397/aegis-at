# Threat Model v3.0.1 — Amendment to v3.0: B6/B7 pre-registered predictions

> **Status: AMENDMENT, hash-locked.** This file is locked by
> `threat-model-v3.0.1.sha256` and the CI test
> `v3/tests/test_threat_model_v3_locked.py`; any edit fails the build. It amends
> `threat-model-v3.md` (v3.0) per that file's §10 change discipline.
> **This amendment ADDS pre-registered predictions for B6 (mTLS, RFC 8705) and
> B7 (A-JWT) — two cells that carried NO locked value in v3.0 (§7.1 "TBD / NOT
> LOCKED (deferred)"; §9 L11) — and changes NO v3.0 locked value.** Every locked
> value in v3.0 (B1–B5; B8 = 1.0 honest / 0.0 colluding; B9 = 1.0 / 1.0; the
> Tier-2 hypotheses H1–H4 as design-only) stands verbatim. v3.0 remains the
> immutable pre-registration of the deterministic core; this file is the
> immutable pre-registration of the B6/B7 comparative-breadth predictions.
>
> **Why v3.0.1 and not v3.1.** B6/B7 are **Tier-1, deterministic** comparative
> breadth (scripted, exact-equality cells), so they belong to the deterministic
> core this point release extends. `v3.1` remains **reserved for the Tier-2 LLM
> ladder** (v3.0 §7.2 / §10) — its model list, N, ε, prompts, and retry policy
> are still unspecified and unlocked. Bumping the patch digit keeps that
> reservation intact.
>
> **Companion artifact:** the primary-source receipts for every B6/B7 spec claim
> below are in `source-lock-v3.0.1.md` (§A, verified 2026-06-21). No claim here
> exceeds what that file records (INV-8). Both files lock together.

---

## §A0. Why this amendment exists

v3.0 listed B6 and B7 in the §7.1 grid "for structure only," with `TBD` values
and the explicit note "**B6/B7 carry no locked values … deferred until RFC 8705 /
A-JWT are read at source**" (§7.1, §9 L11). Both specs have now been read at
primary source — RFC 8705 and `draft-goswami-agentic-jwt-00` (companion
arXiv:2509.13597), verified 2026-06-21 and receipted in `source-lock-v3.0.1.md`
§A. Per v3.0 §10 ("amendments go in `threat-model-v3.1.md` (etc.), each with its
own lock; the original is never edited in place"), the B6/B7 predictions are
pre-registered here and locked.

This is **purely additive**: it resolves the deferred status of two cells. A
measured B6/B7 value could not have contradicted a v3.0 lock because none was
recorded (§7.1). It now becomes a finding against *this* lock instead (§A7).

## §A1. B6 — mTLS-bound token (RFC 8705) — **PREDICTED 1.0 / 1.0** (honest / colluding, T1 + T2)

**Prediction.** Under B6 the system reads executor identity from the
**certificate bound to the access token and verified at the protected resource**,
not from any self-report. On both the honest and the colluding scripted columns,
the claimed actor equals the recorder's process-observed executor → **AIS = 1.0**,
identical on T1 and T2.

**Mechanism (source: `source-lock-v3.0.1.md` §A5 / RFC 8705).** RFC 8705 §3
**MANDATES** that requests to the protected resource "MUST be made over a mutually
authenticated TLS connection using the same certificate that was used for mutual
TLS at the token endpoint," and that "the protected resource MUST obtain, from its
TLS implementation layer, the client certificate used for mutual TLS and MUST
verify that the certificate matches the certificate associated with the access
token." The binding member is the `cnf` claim's `x5t#S256` (the certificate
thumbprint, §3.1). This is a **sender-constraint verified at access** — the same
shape as B5 (DPoP, RFC 9449): possession is checked at execution time, so a lifted
token is useless to a holder who cannot present the bound certificate.

**Reading.** B6 behaves like B5. v3.0 §7.4 already anticipated this informally
("B6 is expected to behave like B5") but asserted nothing; this amendment asserts
it, now that the verifying-at-access requirement is read at source. The §4.2
colluding capability is **inert** on B6: the executor cannot present **another
agent's** certificate (that is key/credential forgery, excluded by §4.2 and §4.3),
so it cannot make the cert-bound identity name a different agent. The colluding
column therefore equals the honest column.

**Caveats (load-bearing; carried as concessions, §A6).**
1. The prediction assumes the AEGIS-AT B6 model uses a **per-executor (per-agent)
   certificate** and **derives the recorded executor identity from the verified
   mTLS certificate**, enforcing the RFC 8705 §3 match — i.e., the resource maps a
   `verified per-agent cert → executor` (parallel to B5's per-agent key). This is
   what the RFC mandates; the benchmark instantiates that mandate. A **shared
   client-app certificate** would identify only the app, not the executor, and is
   not the B6 model.
2. **Executor certificate/key compromise is out of the v3 collusion model**
   (§4.2: the colluder cannot forge or sign under another agent's key, nor defeat
   DPoP/mTLS key possession). B6 is a defense against the *self-attestation* gap,
   not against a fully key-compromised executor.

## §A2. B7 — A-JWT execution assertion (`draft-goswami-agentic-jwt-00`) — **PREDICTED 1.0 / 1.0** (honest / colluding, T1 + T2)

**Prediction.** Under B7 the system reads executor identity from an **execution
assertion that is cryptographically verified at execution** — the per-agent
proof-of-possession key in the token's `cnf`, checked by the Resource Server at
request time — backed by the IDP's runtime checksum check at mint. The asserted
executor (`executed_by`) is therefore **not a bare self-report**. On both columns
the claimed actor equals the recorder's process-observed executor → **AIS = 1.0**,
identical on T1 and T2.

**Mechanism (source: `source-lock-v3.0.1.md` §A6 / A-JWT §3, §5).** A-JWT's
Security Anchor A6 (Proof of Possession): "During registration each agent
generates ephemeral key pair … [the IDP] sends [the public key] in the cnf claim
of the issued token"; "Client performs Ed25519 signature with http request to the
Resource Server. The Resource Server uses agent specific public key in the token
and verifies this signature"; guarantee: "Intercepted or stolen tokens cannot be
replayed without access to the agent specific private key." At mint, the IDP
"compare[s] the provided checksum against the registered checksum … runtime
cryptographic check on agent's identity." Anchor A3 guarantees "Agents cannot
impersonate other agents within the same process space." The intent token carries
`executed_by`; the PoP JWK thumbprint rides in `cnf`. A-JWT's threat model
explicitly targets the attribution gap v3 measures — T7 Cross-Agent Privilege
Escalation, T10 Intent Origin Forgery, T11 Delegation Chain Manipulation — and
frames the problem as "a separation between the actual user (generator of the
intent) and the executing agent (executor of the API call)."

**Reading.** B7 recovers — it is the **opposite of B8 (self-report)**. v3.0 §7.4
made recovery conditional ("B7 to recover **iff** its execution assertion is
independently verified at execution"); A-JWT's design **specifies** the mechanism
that satisfies the condition (PoP verified at the RS at execution; runtime checksum
verified at the IDP at mint), so the prediction is now asserted. **Recovery does
not rest on the checksum.** A-JWT's own threat model **admits T1 (Agent Identity
Spoofing)** — a malicious agent can replicate code to compute an identical checksum
— so the load-bearing anchors are the two that T1 cannot defeat: **A3 (Bridge
Identifier Binding)**, runtime stack/object inspection *at token-request time*
guaranteeing "Agents cannot impersonate other agents within the same process space"
(A3 "Mitigates: T1"), and **A6 (Proof of Possession)**, the per-agent key verified
at the RS at execution. The §4.2 colluding capability is therefore **inert** on B7:
for the colluding executor (Contain) to attribute its action to a different agent
(Enrich) it would need to impersonate Enrich in-process at mint (blocked by **A3**)
**and** sign with Enrich's PoP key at the RS (blocked by **A6** + §4.2, no signing
under another agent's key) — a copied checksum buys neither. Both are outside the
colluder's capability, so the colluding column equals the honest column.

**Caveats (load-bearing; carried as concessions, §A6).**
1. **A-JWT is a design / proof-of-concept, not a validated adversarial
   measurement.** Its own "blocking 100 % of threat requests" is a PoC claim; the
   paper states "A comprehensive performance and security evaluation … will appear
   in our forthcoming journal submission." The B7 = 1.0/1.0 prediction is for the
   **mechanism as specified, graded by AEGIS-AT's own recorder** — it is **not** an
   endorsement of A-JWT's unvalidated 100 % figure.
2. **A-JWT's native independence anchor is weaker/different from v3's.** A-JWT
   verifies identity via an **in-process** Shim (runtime checksum + A3 stack/object
   inspection), whereas v3's INV-4 recorder is independent **by OS-process
   boundary**. A fully process-compromised executor could in principle defeat an
   in-process shim — but that is outside v3's §4.2 colluder model, and A-JWT offers
   an **optional TEE attestation profile** that strengthens its anchor toward v3's
   independence level. Decisively, AEGIS-AT grades B7 with its **own**
   OS-process-boundary recorder (INV-4) regardless of A-JWT's native anchor, so the
   AIS measurement's independence is v3's, not A-JWT's.

## §A3. Where B6/B7 sit — the recover-cluster vs. the isolated failure

With B6/B7 pre-registered, the v3 deterministic narrative is: attribution
**recovers** in every form of "verify the executor at execution" —
**{B5 DPoP, B6 mTLS, B7 A-JWT execution assertion, B9 independent process-boundary
verifier}** all predict 1.0 / 1.0. The attribution failure is **isolated to B8**
(self-reported completion: 1.0 honest / 0.0 colluding). The thesis sharpens:
*verifying the executor at execution wins in every cryptographic form tested;
trusting the executor's self-report is the single cell that fails under collusion.*

## §A4. Inertness, consistent with v3.0 §7.4

B6 and B7 join B1–B5 as honest-component baselines on which the colluding
capability is **inert** (their colluding column equals their honest column),
because neither reads attribution from a self-asserted completion and neither
permits the executor to authenticate or prove key-possession **as another agent**
(§4.2). This is exactly the §7.4 inertness principle, now asserted for B6/B7
rather than left open. The finding remains isolated to B8.

## §A5. The §7.1 grid rows, resolved (additive — supersedes only the two TBD placeholders)

These two rows replace the `TBD / TBD / NOT LOCKED (deferred)` placeholders for
B6/B7 in v3.0 §7.1. **No other row changes.** Column structure is identical to
v3.0 §7.1.

| B | Mechanism | Attribution source the system uses | script-honest | script-colluding | Status |
|---|---|---|---|---|---|
| B6 | + mTLS-bound token (RFC 8705) | cert-bound identity, verified at access | **1.0** | **1.0** | **locked (v3.0.1)** |
| B7 | + A-JWT execution assertion | execution assertion (PoP `cnf` at RS + IDP checksum at mint) | **1.0** | **1.0** | **locked (v3.0.1)** |

Identical on T1 and T2 (as for B1–B5). These are Tier-1 scripted cells, asserted
by **exact equality** (v3.0 §7.1 / §10), byte-identical across runs.

## §A6. Concessions — L11 resolved; new caveats recorded

| ID | Concession / resolution | Status |
|---|---|---|
| L11 | B6 (mTLS) / B7 (A-JWT) carry no locked values | **RESOLVED** — both read at source (`source-lock-v3.0.1.md` §A) and locked here at 1.0 / 1.0 |
| L20 | B6 assumes the resource derives the recorded identity from the verified mTLS cert (RFC 8705 §3); executor cert/key compromise is out of scope | new; defers to §4.2 collusion model |
| L21 | B7 = 1.0/1.0 is for the A-JWT **mechanism graded by AEGIS-AT's recorder**, not an endorsement of A-JWT's unvalidated PoC "100 %"; A-JWT's native in-process anchor is weaker than v3's OS-process recorder (optional TEE profile excepted) | new; the measurement's independence is v3's (INV-4), not A-JWT's |

v3.0's L12–L19 stand unchanged. The remaining `source-lock-v3.md` §B items
(PAuth, Otsuka et al., OWASP ASI03, NIST re-verify, completion-record field
semantics) are **not** resolved by this amendment.

## §A7. Change discipline (unchanged from v3.0 §10)

- This file is committed with its own `threat-model-v3.0.1.sha256` lock;
  `source-lock-v3.0.1.sha256` locks the companion. Both are checked by
  `v3/tests/test_threat_model_v3_locked.py` alongside v3.0.
- B6/B7 are locked as **Tier-1 exact-equality** predictions (1.0 / 1.0). A
  measurement contradicting either is reported as a **finding**, never coded
  around (INV-7, INV-8).
- A further amendment would be `threat-model-v3.0.2.md` (deterministic core) or
  `threat-model-v3.1.md` (the Tier-2 LLM ladder); neither v3.0 nor this file is
  ever edited in place.
