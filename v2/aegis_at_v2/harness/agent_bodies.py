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


def request_tool_call(conn, command: str, target: str, credential, proof=None) -> dict:
    """Send a tool-call request to the parent harness; return the claimed
    record (or re-raise the tool's error in this process).

    The message carries os.getpid() so the kernel can cross-check it
    against the PID it observed at spawn (fail loud on mismatch). The
    kernel NEVER uses this self-reported value for identity resolution —
    identity comes from the kernel's own registry (INV-4).

    `proof` is an optional DPoP proof JWT (Baseline 5); None for B1-B4.
    The proof is created HERE, in the agent process, using the agent's
    own key — it is the agent's runtime evidence of key possession.
    """
    conn.send(("tool_call", os.getpid(), command, target, credential, proof))
    status, payload = conn.recv()
    if status == "ok":
        return payload
    raise payload  # the tool's exception, surfaced in the agent process


def executor_body(conn, command: str, target: str, credential) -> None:
    """The canonical §5 executor: one tool call, then exit."""
    request_tool_call(conn, command, target, credential)


def dpop_executor_body(
    conn, command: str, target: str, credential, private_pem: bytes, now_value: float
) -> None:
    """Baseline 5 executor (threat-model-v2.md §5).

    Rebuilds its DPoP key from the PEM the harness provisioned, signs a
    fresh proof bound to the tool endpoint at `now_value`, and presents
    (token, proof) to the tool. Importing dpop here is safe: it is a leaf
    module (Ed25519 only) and does NOT pull in the RSA-key-generating
    auth.tokens, so spawning this body stays cheap and isolated.
    """
    from aegis_at_v2.auth import dpop

    key = dpop.DPoPKey.from_private_pem(private_pem)
    proof = key.create_proof(dpop.RESOURCE_HTM, dpop.RESOURCE_HTU, now_value)
    request_tool_call(conn, command, target, credential, proof)


# Note: the §5.2 "lift" stimulus reuses dpop_executor_body — the executor
# signs a proof under its own (Contain's) key but is handed a token bound
# to Enrich's key; the tool rejects the mismatch. The lift is a property of
# the credential/key pairing, not a different agent behaviour, so no
# separate body is needed (INV-5: no component misbehaves).


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
