"""
harness/agent_proc.py — process-boundary agent kernel, §2 Boundary 5 / v2 §3.

Replaces v1's thread-name proxy. Agents run as multiprocessing.Process
children; the kernel (this module, running in the parent harness process)
registers {pid -> agent_name} from the OS-assigned proc.pid BEFORE serving
any request from that agent. Identity resolution is a kernel-side registry
lookup — never an agent-supplied field (INV-4, all three axes):

  1. Process boundary: agent user code runs in a different OS process;
     it cannot reach the registry, the ground-truth log, or the parent's
     signing key (auth.tokens generates a per-process key at import).
  2. Credential isolation: the per-agent Pipe is created by the kernel
     and only its child end crosses the boundary; a request arriving on
     that pipe can only come from that process.
  3. Causal precedence: registration happens at spawn, before the agent's
     user code runs; the kernel cross-checks the message's self-reported
     PID against the registered PID and fails loud on mismatch — but the
     resolved identity always comes from the registry, not the message.
"""

import multiprocessing as mp
from typing import Callable


class PidMismatchError(Exception):
    """A tool-call message self-reported a PID that does not match the
    kernel-registered PID for its pipe. Fail loud (Rule 12)."""


def _bootstrap(child_conn, body: Callable, args: tuple) -> None:
    """Child-process entry point. Runs the agent body, then signals done.

    Any exception in the body is sent to the parent so run_agent can
    re-raise it there (fail loud, not a silent dead child).
    """
    try:
        body(child_conn, *args)
        child_conn.send(("done", None))
    except BaseException as e:  # surface the real error to the parent
        try:
            child_conn.send(("agent_error", e))
        except Exception:
            child_conn.send(("agent_error", RuntimeError(repr(e))))


def run_agent(
    name: str,
    body: Callable,
    args: tuple,
    tool_handler: Callable[[str, str, str, object], dict],
) -> None:
    """Spawn `body` as agent `name` in a subprocess and serve its tool calls.

    Args:
        name: the agent identity the kernel binds to the child's PID.
        body: module-level function (spawn-picklable) taking
            (conn, *args); see harness/agent_bodies.py.
        args: forwarded to body after the pipe connection.
        tool_handler: parent-side callable
            (true_actor, command, target, credential, proof) -> claimed
            record. This is where the recorder + tool live; exceptions it
            raises are sent to the agent AND re-raised here. `proof` is the
            agent-supplied DPoP proof (None for B1-B4); it is verified by
            the tool, never used for identity (INV-4).

    The kernel serves requests until the body signals done, then joins
    the process. Tool-call protocol: see agent_bodies.request_tool_call.
    """
    ctx = mp.get_context("spawn")
    parent_conn, child_conn = ctx.Pipe()
    proc = ctx.Process(target=_bootstrap, args=(child_conn, body, args))
    proc.start()
    # Kernel-side registration: OS-assigned PID -> agent name, recorded
    # before any request from this agent is served (causal precedence).
    registered_pid = proc.pid

    first_error: BaseException | None = None
    try:
        while True:
            msg = parent_conn.recv()
            kind = msg[0]
            if kind == "done":
                break
            if kind == "agent_error":
                first_error = msg[1]
                break
            if kind == "tool_call":
                _, reported_pid, command, target, credential, proof = msg
                if reported_pid != registered_pid:
                    raise PidMismatchError(
                        f"agent {name!r}: message PID {reported_pid} != "
                        f"kernel-registered PID {registered_pid}"
                    )
                # Identity = kernel registry, never the message (INV-4).
                true_actor = name
                try:
                    record = tool_handler(
                        true_actor, command, target, credential, proof
                    )
                except Exception as e:
                    parent_conn.send(("error", e))
                    raise
                parent_conn.send(("ok", record))
                continue
            raise RuntimeError(f"unknown message from agent {name!r}: {kind!r}")
    finally:
        # Closing the parent end unblocks a child waiting in recv() on
        # kernel error paths (EOFError in the child), so join is prompt.
        parent_conn.close()
        proc.join(timeout=10)
        if proc.is_alive():
            proc.terminate()
            proc.join()

    if first_error is not None:
        raise first_error
