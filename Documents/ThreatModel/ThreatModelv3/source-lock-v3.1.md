# AEGIS-AT v3.1 — Source Lock (Tier-2 LLM-ladder receipts)

**Status:** PRE-REGISTERED — 4-agent review complete (2026-06-25); hash-locked by
`source-lock-v3.1.sha256` and `v3/tests/test_threat_model_v3_locked.py`; any edit
fails the build. Companion to `threat-model-v3.1.md`; both lock together. To amend,
add `source-lock-v3.2.md`.
**Verification dates:** 2026-06-23 (§A1, §A2, §B leaderboard, §C, and the §A3
HF-card / cdn-PDF observations) and **2026-06-24** (§A3 gpt-oss cutoff pinned
verbatim at the arXiv model card; §B `llama-3.1-8b` index value pinned). Each row
read at its cited source on the date stated for that row.
**Discipline (INV-8):** verify every model/spec claim against the primary source;
never trust paraphrase. Rows fully verified at primary source are in §A/§B/§C;
items not verbatim-confirmed are flagged in §D and must NOT be cited as verbatim
fact until resolved.

Classification: **VERIFIED-VERBATIM** (exact quote read at the cited primary
source) · **SECONDARY** (reported by a non-primary source; primary verbatim
pending) · **OBSERVED** (a third-party measurement read at its source).

---

## §A. Model identifiers + training cutoffs (parameter #1, #3)

The four models are Groq production-tier, open-weight, served via one API key.

### A1 — `llama-3.1-8b-instant` (Meta) — VERIFIED-VERBATIM
- **Source read:** Meta Llama 3.1 model card,
  https://github.com/meta-llama/llama-models/blob/main/models/llama3_1/MODEL_CARD.md
- **Cutoff (verbatim):** "Knowledge cutoff: December 2023"; "The pretraining data
  has a cutoff of December 2023." — **DESCRIPTIVE** (vendor disclosure). Applies to
  all Llama 3.1 sizes incl. 8B.

### A2 — `llama-3.3-70b-versatile` (Meta) — VERIFIED-VERBATIM
- **Source read:** Meta Llama 3.3 model card,
  https://github.com/meta-llama/llama-models/blob/main/models/llama3_3/MODEL_CARD.md
- **Cutoff (verbatim, Data Freshness):** "The pretraining data has a cutoff of
  December 2023." — **DESCRIPTIVE.** (Re-verified 2026-06-25: the 3.3 card records
  December 2023 in a wide per-model training-data row, not a literal
  "Knowledge cutoff | December 2023" cell; the Data-Freshness sentence above is the
  verbatim form.)

### A3 — `openai/gpt-oss-20b` and `openai/gpt-oss-120b` (OpenAI) — VERIFIED-VERBATIM (cutoff pinned at the arXiv model card)
- **Cutoff (VERIFIED-VERBATIM, read 2026-06-24):** OpenAI gpt-oss model card,
  **arXiv:2508.10925v1** ("gpt-oss-120b & gpt-oss-20b Model Card", OpenAI), §2.4
  Pretraining → Data: **"Our model has a knowledge cutoff of June 2024."** Read from
  the arXiv HTML full text (raw bytes grepped, not a summarizer paraphrase). One
  model card covers both gpt-oss-20b and gpt-oss-120b.
- **Earlier sources (2026-06-23, superseded for the cutoff):** the OpenAI gpt-oss HF
  card (https://huggingface.co/openai/gpt-oss-120b) **states NO knowledge-cutoff
  date** (verified absence); the OpenAI cdn model-card PDF
  (https://cdn.openai.com/pdf/419b6906-9da6-406c-a19d-1bb078ac7637/oai_gpt-oss_model_card.pdf,
  released 2025-08-05) **could not be extracted via automated fetch** (binary PDF).
  The arXiv version is the same model card and supplies the verbatim quote.
- **Effective-cutoff counterpoint (SECONDARY):** an external benchmark, **LLMLagBench**
  (arXiv:2511.12116), estimates the *effective* cutoff is earlier, **~September
  2023**. Retained as a counterpoint; June 2024 is the vendor's declared figure.
- **Architecture (verified, HF card):** mixture-of-experts; gpt-oss-120b ≈ 117B
  total / ~5.1B active; gpt-oss-20b ≈ 21B total / ~3.6B active. (Grounds the §B
  "not by parameter count" point.)

### A4 — No-memorization conclusion
**AEGIS-AT was private until 2026-06-22** (first public push of the repo). Every
cutoff above — Dec 2023 (Meta, verbatim) and ~Sept 2023–June 2024 (gpt-oss, under
every estimate) — precedes that date by **≥18 months**. So no candidate model could
have memorized the AEGIS-AT scenario, and the §7.2 #3 constraint holds *regardless*
of which gpt-oss estimate one uses (declared June 2024, §A3, or effective ~Sept
2023). The generic threat pattern being in
training data is intended (model reasoning, not benchmark memorization).

---

## §B. Capability ordering (parameter #2) — OBSERVED (M1 floor is an AA-published *estimate*)

- **Sources read:** Artificial Analysis Intelligence Index (public multi-benchmark
  composite) — leaderboard https://artificialanalysis.ai/leaderboards/models (read
  2026-06-23) and the per-model page
  https://artificialanalysis.ai/models/llama-3-1-instruct-8b (read 2026-06-24).
- **Scores (OBSERVED):** `gpt-oss-120b` = **24** · `gpt-oss-20b` = **15** ·
  `llama-3.3-70b` (Instruct) = **9** · `llama-3.1-8b` (Instruct) = **6 (estimated)**
  (AA's per-model page: "scores 6 (estimated)"; not on the ranked leaderboard —
  below its listing threshold — but the estimated value is published per-model).
- **Locked ordering (weak → strong):** `llama-3.1-8b` (6, est.) < `llama-3.3-70b`
  (9) < `gpt-oss-20b` (15) < `gpt-oss-120b` (24).
- **Why not parameter count:** `gpt-oss-20b` (MoE, ~3.6B active) **out-scores** the
  70B-dense `llama-3.3-70b` (15 > 9). Param count would mis-order the ladder; the
  benchmark is the defensible axis.
- **Caveat (§D2):** `llama-3.1-8b`'s 6 is AA-*estimated*, not a full measured board
  ranking — but it is strictly below the next rung (9), so the floor placement holds
  under the estimate (the ordering needs only floor < 9, not the exact floor value).
  The 4-agent review (2026-06-25) consensus is to keep M1 (estimate + same-family
  architecture both put it below M2); the keep-vs-substitute call is resolved in
  `threat-model-v3.1.md` §C2 (keep M1).

---

## §C. Groq production tier (parameter #1) — OBSERVED

- **Source read:** Groq models documentation, https://console.groq.com/docs/models
  (read 2026-06-23).
- **Production-tier text models (OBSERVED):** `llama-3.1-8b-instant`,
  `llama-3.3-70b-versatile`, `openai/gpt-oss-20b`, `openai/gpt-oss-120b` are listed
  as **production** ("meet or exceed high standards for speed, quality, and
  reliability"), distinct from preview/deprecated. All open-weight and free-tier
  (L17 honored). `groq/compound*` are agentic systems with built-in tools —
  excluded as not a clean single model in the seat.

---

## §D. Resolved items / open caveats (before the final lock)

1. **gpt-oss exact cutoff — RESOLVED (2026-06-24).** Pinned VERIFIED-VERBATIM at the
   arXiv gpt-oss model card (arXiv:2508.10925v1 §2.4): **"Our model has a knowledge
   cutoff of June 2024."** (§A3). The HF card still omits it and the cdn PDF still
   would not auto-parse, but the arXiv version is the same model card and supplies
   the verbatim quote. LLMLagBench's effective-~Sept-2023 estimate is retained as a
   SECONDARY counterpoint. Was never load-bearing (§A4).
2. **`llama-3.1-8b` capability score — RESOLVED (2026-06-25): keep M1.** AA's
   per-model page publishes an *estimated* Intelligence Index of **6** (§B), which
   supports the floor placement (6 < 9 < 15 < 24). Decision (4-agent review
   consensus): keep `llama-3.1-8b` as M1 — the estimate *and* the same-family
   dense-8B < dense-70B architecture both place it below M2, and substituting a
   measured cross-family model would add a confound (`threat-model-v3.1.md` §C2).
3. **Re-verify before the LLM run — OPEN (inherent; cannot close until run).** Groq's
   lineup and the AA board can change; re-confirm the four IDs are still production
   and the ordering still holds at the moment of the run (the lock fixes the
   *pre-registration*; a lineup change is disclosed, not silently substituted).
