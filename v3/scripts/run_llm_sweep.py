"""Step 4b live runner — execute the Tier-2 sweep against real Groq models.

Thin orchestration only (no logic of its own): load the key, put v2+v3 on the path,
run llm_sweep -> write the raw audit log -> evaluate H1-H4 -> print the verdict.

Usage (from the repo root, with GROQ_API_KEY in .env):
    python v3/scripts/run_llm_sweep.py

INV-7: v3.1 is locked + committed, so live calls are permitted. A finding (incl. any
B9 evasion) is a RESULT, reported in the verdict — not a script error. The key is read
only from the process env via load_dotenv(); this script never opens .env itself.
"""

from __future__ import annotations

import os
import pathlib
import sys
from datetime import datetime

from dotenv import load_dotenv

_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(_ROOT / "v2"),
    str(_ROOT / "v3"),
]  # conftest does this for tests only

from aegis_at_v3.harness import llm_eval, llm_sweep  # noqa: E402


def main() -> None:
    load_dotenv(_ROOT / ".env")
    if not os.environ.get("GROQ_API_KEY"):
        sys.exit("GROQ_API_KEY not set (put it in .env) — aborting before any call.")

    result = llm_sweep.llm_sweep()

    out_dir = _ROOT / "results"
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = out_dir / f"llm_sweep_{stamp}.json"
    llm_sweep.write_results(result, str(log_path))

    verdict = llm_eval.evaluate(result["grid"])
    print(llm_eval.format_verdict(verdict))
    print(f"\nraw audit log: {log_path}")


if __name__ == "__main__":
    main()
