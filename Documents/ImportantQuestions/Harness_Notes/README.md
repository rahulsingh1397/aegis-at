# Harness notes — index

One note per harness component, each answering *why it's shaped this way* (rationale
+ a Rule-9 test map) — not API docs. Grouped by lineage below.

**Convention:** new notes go **flat** in this folder (e.g. `adversary_v3.md`). The
single-file subfolders under "Reused primitives" are legacy — don't add more of them.

## Tier-2 — LLM ladder (v3.1)
- [llm_seat_v3.md](llm_seat_v3.md) — LLM-in-the-executor-seat adapter (Step 2); outcome-only, strict §C7 classification · `harness/llm_seat.py`
- [llm_sweep_v3.md](llm_sweep_v3.md) — adaptive sweep driver (Step 3); batches → Wilson CIs → evasion rates · `harness/llm_sweep.py`

## v3 completion-attestation core (B6–B9)
- [adversary_v3.md](adversary_v3.md) — scripted adversary seats (honest / colluding) · `harness/adversary.py`
- [completion_sweep_v3.md](completion_sweep_v3.md) — B8/B9 completion-attestation sweep (+ B6/B7) · `harness/completion_sweep.py`

## Reused harness primitives (v1/v2 — ground truth, scoring, kernel)
- [agent_proc_v2.md](agent_proc_v2.md) — process kernel + agent bodies (the INV-4 boundary) · `agent_proc.py`, `agent_bodies.py`
- [RecorderNotes/recorder_notes.md](RecorderNotes/recorder_notes.md) — ground-truth recorder (OS PID registry, INV-4) · `recorder.py`
- [scorer_notes/scorer_notes.md](scorer_notes/scorer_notes.md) — AIS scorer + Wilson CI · `scorer.py`
- [SweepNotes/SweepNotes.md](SweepNotes/SweepNotes.md) — baseline sweep (B1–B5) · `sweep.py`
- [tamperlog_notes/tamper_logV2.md](tamperlog_notes/tamper_logV2.md) — tamper-evident log (B4) · `tamper_log.py`
