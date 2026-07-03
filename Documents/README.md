# Documents

Index of the project's documentation. Code lives under `../v1/` (frozen),
`../v2/` (active), and `../v3/` (active; v3.0 pre-registration locked).

| Path | What it is | Status |
|---|---|---|
| `ThreatModel/threat-model.md` | v1 threat model — the spec for everything under `v1/`. Pre-registered the B1–B4 AIS curve. | **Frozen** |
| `ThreatModel/threat-model-v2.md` | v2 threat model — pre-registers all v2 predictions (B5 DPoP, LIS, T2, Wilson CIs). | **Locked** (SHA-256 in `threat-model-v2.sha256`, enforced by `v2/tests/test_threat_model_v2_locked.py`; amend via `threat-model-v2.1.md`, never edit) |
| `ThreatModel/ThreatModelv3/threat-model-v3.md` | v3 threat model — merged attestation-source × adversary-realization design. v3.0 locks the scripted B8/B9 core (B8=1.0/0.0, B9=1.0/1.0); B6/B7 locked in v3.0.1, the LLM ladder in v3.1. | **Locked** (SHA-256 in `threat-model-v3.sha256`, enforced by `v3/tests/test_threat_model_v3_locked.py`; amend via a new versioned file, never edit) |
| `ThreatModel/ThreatModelv3/threat-model-v3.0.1.md` | v3.0.1 amendment — pre-registers B6 (mTLS, RFC 8705) and B7 (A-JWT) at 1.0/1.0 (deterministic comparative breadth). | **Locked** (SHA-256 in `threat-model-v3.0.1.sha256`, same lock test) |
| `ThreatModel/ThreatModelv3/threat-model-v3.1.md` | v3.1 — pins the Tier-2 LLM-ladder parameters (4 models, N, ε=0, prompts verbatim, retry policy) and restates H1–H4. | **Locked** (SHA-256 in `threat-model-v3.1.sha256`, same lock test) |
| `ThreatModel/ThreatModelv3/source-lock-v3*.md` | v3 primary-source receipts (INV-8): `-v3` (AIP/PEDIGREE/HDP/MCP), `-v3.0.1` (RFC 8705 + A-JWT, verified), `-v3.1` (model IDs/cutoffs/AA scores). | **Locked** (each with its own `.sha256`, same lock test) |
| `Paper/` | The benchmark papers: v1 `aegis-at.tex` → `.pdf` (+ `aegis-at.md` companion), v2 `aegis-at-v2.tex` → `.pdf`, v3 `aegis-at-v3.tex` → `.pdf`. See [`Paper/README.md`](./Paper/README.md). | v1–v3 shipped |
| `References/References.md` | Citation list. | Maintained |
| `ImportantQuestions/` | Design Q&A notes per module (harness, orchestrator, policy). | Working notes |
| `ResearchPapers/` | Third-party papers (local only, gitignored). | Local |
| `LICENSE-docs` | CC BY 4.0 — applies to documentation; code is Apache-2.0. | — |

Build artifacts (`*.aux`, `*.out`, `*.toc`) and planning notes
(`EDIT_PLAN_*.md`) are gitignored.
