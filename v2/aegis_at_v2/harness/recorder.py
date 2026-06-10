"""
harness/recorder.py — ground-truth recorder, §2 Boundary 5 / v2 §3.

v2 change from v1: true_actor comes from the agent-process kernel's
PID registry (agent_proc.run_agent resolves it from the OS-assigned
proc.pid it observed at spawn), not from threading.current_thread().name.
A thread rename or process-title change inside the agent cannot alter it
(threat-model-v2.md §3.2).

INV-4 unchanged: the recorder never reads identity from a token or any
agent-supplied field. It derives true_scope from the OBSERVED command via
the shared scope contract, and writes ground truth BEFORE forwarding the
call to the tool (causal precedence).

Chain shape (§4): true_principal_chain is [true_actor, "human:analyst"]
— a 2-hop chain. The orchestrator does NOT appear: it is a stateless
minting endpoint, not a delegated principal, so it has no place in the
RFC 8693 act chain.
"""

import time
from typing import Callable

from aegis_at_v2.policy.scope_map import scope_for_command


def make_recorder(
    real_siem_action: Callable,
    ground_truth_log: list,
) -> Callable:
    """Build a recorder-wrapped, kernel-facing tool handler.

    Returns a callable with the agent_proc tool_handler signature:
    (true_actor, command, target, token) -> claimed record. true_actor is
    supplied by the kernel from its PID registry — harness-trusted, never
    agent-supplied (INV-4). The recorder writes ground truth, then
    forwards the call; the tool's verification and the tool's own log
    entry are untouched.

    Args:
        real_siem_action: The bare siem_action() callable.
        ground_truth_log: Harness-owned list; the recorder appends to it.
    """

    def wrapped(
        true_actor: str,
        command,
        target,
        token,
        *,
        now_fn: Callable[[], float] = time.time,
    ):
        ts = now_fn()

        true_scope = scope_for_command(command)

        ground_truth_log.append(
            {
                "true_actor": true_actor,
                "true_scope": true_scope,
                # Credential-aware (threat-model.md §6): an opaque per-agent
                # credential (apikey dict, Baselines 1-2) carries no
                # delegation chain -> None. A JWT (Baselines 3+) is a
                # delegation token -> 2-hop [executor, root]. Discrimination
                # is on credential STRUCTURE; true_actor still comes from
                # the kernel's PID registry, so INV-4 (independence from
                # the token) is intact.
                "true_principal_chain": (
                    None if isinstance(token, dict) else [true_actor, "human:analyst"]
                ),
                "command": command,
                "target": target,
                "timestamp": ts,
            }
        )

        return real_siem_action(command, target, token, now_fn=lambda: ts)

    return wrapped
