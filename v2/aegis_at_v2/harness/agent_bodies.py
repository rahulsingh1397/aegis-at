"""
harness/agent_bodies.py — code that runs INSIDE agent subprocesses.

Deliberately a leaf module: it imports nothing from auth/tools/harness,
so spawning a child does not regenerate RSA keys or import the parent's
verification stack. The child only ferries opaque credentials over IPC;
all minting, verification, and recording happen in the parent harness.

Bodies must be module-level functions (spawn pickles them by reference).
Each body receives the child end of the kernel's private pipe as its
first argument and uses `request_tool_call` to ask the parent harness to
execute a tool call on its behalf.
"""

import os
import threading


def request_tool_call(conn, command: str, target: str, credential) -> dict:
    """Send a tool-call request to the parent harness; return the claimed
    record (or re-raise the tool's error in this process).

    The message carries os.getpid() so the kernel can cross-check it
    against the PID it observed at spawn (fail loud on mismatch). The
    kernel NEVER uses this self-reported value for identity resolution —
    identity comes from the kernel's own registry (INV-4).
    """
    conn.send(("tool_call", os.getpid(), command, target, credential))
    status, payload = conn.recv()
    if status == "ok":
        return payload
    raise payload  # the tool's exception, surfaced in the agent process


def executor_body(conn, command: str, target: str, credential) -> None:
    """The canonical §5 executor: one tool call, then exit."""
    request_tool_call(conn, command, target, credential)


def spoofing_executor_body(conn, command: str, target: str, credential) -> None:
    """Executor that attempts identity spoofing before the call
    (threat-model-v2.md §3.2).

    It renames its thread (defeats the v1 thread-name recorder) and
    overwrites argv-visible process metadata — the in-Python equivalent
    of prctl(PR_SET_NAME). Neither can move the call into another
    process, so PID-based attribution must be unchanged.
    """
    threading.current_thread().name = "agent:enrich"  # v1-recorder spoof
    try:
        import sys

        sys.argv[0] = "agent:enrich"  # process-title spoof (best effort)
    except Exception:
        pass
    request_tool_call(conn, command, target, credential)
