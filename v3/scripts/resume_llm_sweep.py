"""Step 4b resume runner — re-run only the dead (denominator==0) cells of a prior
sweep, paced to stay under Groq free-tier TPM, CHECKPOINTING after every cell.

Usage (from repo root, GROQ_API_KEY in .env):
    python v3/scripts/resume_llm_sweep.py [path/to/prior_llm_sweep.json]

Writes results/llm_sweep_resumed.json after EACH cell, so an interruption (session end,
crash, sleep) loses at most the one in-progress cell — re-running continues from the
checkpoint. With no arg it prefers that checkpoint, else the latest original sweep.
Cells are independently seeded (§C10); locked params/prompts/RETRY_MAX untouched —
only pacing differs.
"""

from __future__ import annotations

import glob
import json
import os
import pathlib
import sys

from dotenv import load_dotenv

_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path[:0] = [str(_ROOT / "v2"), str(_ROOT / "v3")]

from aegis_at_v3.harness import llm_eval, llm_sweep  # noqa: E402

PACE_S = 4.0  # uniform delay; sized to the tightest TPM (6k/min, llama-3.1-8b)
CHECKPOINT = _ROOT / "results" / "llm_sweep_resumed.json"


def _rehydrate(cd: dict):
    trials = [llm_sweep.TrialResult(**td) for td in cd["trials"]]
    return llm_sweep.CellResult(**{**cd, "trials": trials})


def _select_base() -> pathlib.Path:
    if sys.argv[1:]:
        return pathlib.Path(sys.argv[1])
    if CHECKPOINT.exists():
        return CHECKPOINT  # resume the resume
    originals = sorted(
        p
        for p in glob.glob(str(_ROOT / "results" / "llm_sweep_*.json"))
        if "resumed" not in pathlib.Path(p).name
    )
    if not originals:
        sys.exit("no prior results/llm_sweep_*.json found")
    return pathlib.Path(originals[-1])


def main() -> None:
    base = _select_base()
    data = json.loads(base.read_text(encoding="utf-8"))
    meta = data["meta"]
    rebuilt = {
        (c["model"], c["baseline"], c["condition"]): _rehydrate(c) for c in data["grid"]
    }

    def checkpoint():
        grid = [rebuilt[tuple(k)] for k in meta["grid_order"]]
        CHECKPOINT.parent.mkdir(exist_ok=True)
        llm_sweep.write_results({"grid": grid, "meta": meta}, str(CHECKPOINT))
        return grid

    to_run = [k for k, c in rebuilt.items() if c.denominator == 0]
    if to_run:
        load_dotenv(_ROOT / ".env")
        if not os.environ.get("GROQ_API_KEY"):
            sys.exit(
                "GROQ_API_KEY not set (put it in .env) — aborting before any call."
            )
        print(
            f"resuming {len(to_run)} dead cell(s) from {base.name}, pace={PACE_S}s/call",
            flush=True,
        )
        for key in to_run:
            model, baseline, condition = key
            print(f"  re-running {key} ...", flush=True)
            rebuilt[key] = llm_sweep.adaptive_llm_cell(
                model, baseline, condition, base_seed=meta["base_seed"], pace_s=PACE_S
            )
            checkpoint()  # persist after every cell
            print(f"  done {key}: denom={rebuilt[key].denominator}", flush=True)
    else:
        print(f"no dead cells in {base.name} — already complete.", flush=True)

    grid = checkpoint()
    print(llm_eval.format_verdict(llm_eval.evaluate(grid)), flush=True)
    print(f"\ncheckpointed audit log: {CHECKPOINT}", flush=True)


if __name__ == "__main__":
    main()
