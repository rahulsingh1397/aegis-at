# Documents

Index of the project's documentation. Code lives under `../v1/` (frozen),
`../v2/` (active), and `../v3/` (active; v3.0 pre-registration locked).

| Path | What it is | Status |
|---|---|---|
| `ThreatModel/threat-model.md` | v1 threat model — the spec for everything under `v1/`. Pre-registered the B1–B4 AIS curve. | **Frozen** |
| `ThreatModel/threat-model-v2.md` | v2 threat model — pre-registers all v2 predictions (B5 DPoP, LIS, T2, Wilson CIs). | **Locked** (SHA-256 in `threat-model-v2.sha256`, enforced by `v2/tests/test_threat_model_v2_locked.py`; amend via `threat-model-v2.1.md`, never edit) |
| `ThreatModel/ThreatModelv3/threat-model-v3.md` | v3 threat model — merged attestation-source × adversary-realization design. v3.0 locks the scripted B8/B9 core (B8=1.0/0.0, B9=1.0/1.0); LLM ladder + B6/B7 staged to v3.1. | **Locked** (SHA-256 in `threat-model-v3.sha256`, enforced by `v3/tests/test_threat_model_v3_locked.py`; amend via `threat-model-v3.1.md`, never edit) |
| `ThreatModel/ThreatModelv3/source-lock-v3.md` | v3 primary-source receipts (INV-8): AIP/PEDIGREE/HDP/MCP verified; A-JWT/mTLS/completion-field semantics pending (§B). | **Locked** (SHA-256 in `source-lock-v3.sha256`, same lock test) |
| `Paper/` | The v1 paper: `aegis-at.tex` (canonical) → `aegis-at.pdf`; `aegis-at.md` is the GitHub-rendered companion. v2 paper will land as `aegis-at-v2.tex`. | v1 shipped |
| `References/References.md` | Citation list. | Maintained |
| `ImportantQuestions/` | Design Q&A notes per module (harness, orchestrator, policy). | Working notes |
| `ResearchPapers/` | Third-party papers (local only, gitignored). | Local |
| `LICENSE-docs` | CC BY 4.0 — applies to documentation; code is Apache-2.0. | — |

Build artifacts (`*.aux`, `*.out`, `*.toc`) and planning notes
(`EDIT_PLAN_*.md`) are gitignored.
