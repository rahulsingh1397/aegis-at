"""Step 4b resume runner — re-run only the dead (denominator==0) cells of a prior
sweep, paced to stay under Groq free-tier TPM, then merge + re-evaluate.

Usage (from repo root, GROQ_API_KEY in .env):
    python v3/scripts/resume_llm_sweep.py [path/to/prior_llm_sweep.json]
Defaults to the most recent results/llm_sweep_*.json. Cells are independently seeded
(§C10), so re-running a dead cell reproduces it exactly; the good cells are rehydrated
unchanged. Locked params/prompts/RETRY_MAX untouched — only pacing differs.
"""

from __future__ import annotations

import glob
import json
import os
import pathlib
import sys
from datetime import datetime

from dotenv import load_dotenv

_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path[:0] = [str(_ROOT / "v2"), str(_ROOT / "v3")]

from aegis_at_v3.harness import llm_eval, llm_sweep  # noqa: E402

PACE_S = 4.0  # uniform delay; sized to the tightest TPM (6k/min, llama-3.1-8b)


def _rehydrate(cd: dict):
    trials = [llm_sweep.TrialResult(**td) for td in cd["trials"]]
    return llm_sweep.CellResult(**{**cd, "trials": trials})


def main() -> None:
    args = sys.argv[1:]
    if args:
        prior = pathlib.Path(args[0])
    else:
        found = sorted(glob.glob(str(_ROOT / "results" / "llm_sweep_*.json")))
        if not found:
            sys.exit("no prior results/llm_sweep_*.json found")
        prior = pathlib.Path(found[-1])

    data = json.loads(prior.read_text(encoding="utf-8"))
    meta = data["meta"]
    dead = [c for c in data["grid"] if c["denominator"] == 0]
    if not dead:
        sys.exit("no dead cells (denominator==0) — nothing to resume.")

    load_dotenv(_ROOT / ".env")
    if not os.environ.get("GROQ_API_KEY"):
        sys.exit("GROQ_API_KEY not set (put it in .env) — aborting before any call.")
    print(f"resuming {len(dead)} dead cell(s) from {prior.name}, pace={PACE_S}s/call")

    rebuilt = {}
    for c in data["grid"]:
        key = (c["model"], c["baseline"], c["condition"])
        if c["denominator"] == 0:
            print(f"  re-running {key} ...")
            rebuilt[key] = llm_sweep.adaptive_llm_cell(
                c["model"],
                c["baseline"],
                c["condition"],
                base_seed=meta["base_seed"],
                pace_s=PACE_S,
            )
        else:
            rebuilt[key] = _rehydrate(c)

    grid = [rebuilt[tuple(k)] for k in meta["grid_order"]]
    out_dir = _ROOT / "results"
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"llm_sweep_resumed_{stamp}.json"
    llm_sweep.write_results({"grid": grid, "meta": meta}, str(path))

    print(llm_eval.format_verdict(llm_eval.evaluate(grid)))
    print(f"\nmerged audit log: {path}")


if __name__ == "__main__":
    main()
