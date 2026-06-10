"""
harness/recorder.py — ground-truth recorder, §2 Boundary 5.

Wraps siem_action() to independently observe the true executor of every
tool call. INV-4: observes the calling THREAD (v1a proxy for process
identity); never reads identity from a token or any agent-supplied
field. Documented limitation per threat-model.md §8.

The recorder is harness infrastructure, NOT part of the SOC system
under test. It must be unreachable from the attacker's input path.

Chain shape (§4): true_principal_chain is [true_actor, "human:analyst"]
— a 2-hop chain. The orchestrator does NOT appear: it is a stateless
minting endpoint, not a delegated principal holding a token, so it has
no place in the RFC 8693 act chain. This matches what actor_chain()
produces on the claimed side from a spec-compliant single-hop
delegation token. See threat-model.md §4 and §5.
"""

import threading
import time
from typing import Callable
from scope_map import scope_for_command


def make_recorder(
    real_siem_action: Callable,
    ground_truth_log: list,
) -> Callable:
    """Build a recorder-wrapped version of siem_action.

    The wrapper observes the calling thread's name as true_actor BEFORE
    calling the real tool (causal precedence). It derives true_scope
    from the OBSERVED command, never the token (INV-4). It then forwards
    the call; the tool's verification and the tool's own log entry are
    untouched.

    Args:
        real_siem_action: The bare siem_action() callable.
        ground_truth_log: Harness-owned list; the recorder appends to it.

    Returns:
        A callable with the same signature as siem_action.
    """

    def wrapped(command, target, token, *, now_fn: Callable[[], float] = time.time):
        ts = now_fn()

        true_actor = threading.current_thread().name
        true_scope = scope_for_command(command)

        ground_truth_log.append(
            {
                "true_actor": true_actor,
                "true_scope": true_scope,
                # Credential-aware (threat-model.md §6): an opaque per-agent
                # credential (apikey dict, Baselines 1-2) carries no
                # delegation chain -> None. A JWT (Baselines 3-4) is a
                # delegation token -> 2-hop [executor, root]. Discrimination
                # is on credential STRUCTURE; true_actor still comes from the
                # thread, so INV-4 (independence from the token) is intact.
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
