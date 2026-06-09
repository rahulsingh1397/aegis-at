# Agent system (Days 5-7): orchestrator + Subagent A + B + one tool. Each carries a real token from auth/tokens.py
# agents/ — intentionally empty in v1

There is no separate agent package in v1. Agents are scripted, deterministic
wrappers inside [`../harness/sweep.py`](../harness/sweep.py): a worker thread named
for the true executor runs the tool call under the per-baseline credential. This is
deliberate (paper §11.5, "Scripted, not real LLM behavior") — it removes
model-specific confounds so the v1 result speaks to the delegation layer only. A v2
optional LLM adapter would live here; until then this directory is intentionally empty.