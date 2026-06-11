# Agent-Process Kernel Notes — v2/aegis_at_v2/harness/agent_proc.py + agent_bodies.py

Working notes for the v2 process-boundary substrate. This is the Phase 2
change that retires v1's single biggest validity concession (§II.8.9 of
the v1 reference: "your ground-truth recorder uses threads, not
processes"). It is the *why* behind two implementation files:

- `harness/agent_proc.py` — the **kernel**: runs in the parent harness,
  spawns each agent as an OS subprocess, serves its tool calls.
- `harness/agent_bodies.py` — the **bodies**: the code that runs *inside*
  those subprocesses.

Pre-registered in `threat-model-v2.md §3`. This file is the design
rationale; the threat model is the locked prediction.

---

## What changed from v1 and why

v1 identified the true actor with `threading.current_thread().name`
(`recorder_notes.md`, "Process boundary" axis). That was an honest proxy,
but a proxy: an agent that ran `threading.current_thread().name = "..."`
mid-call could have spoofed ground truth. v1 excluded that by INV-5 (no
illegitimate component behavior) and §II.3 (the adversary controls alert
text, not agent code) — a defensible exclusion, but one a reviewer is
entitled to push on.

v2 removes the proxy. The true actor is now the **OS process identity**
the kernel assigned at spawn. A thread rename or a process-title rewrite
inside the agent cannot move the call into a different process, so it
cannot change attribution. The §II.8.9 caveat is retired, not argued
around.

---

## Architecture: kernel in the parent, bodies in children

```
        parent harness process
        ┌──────────────────────────────────────────────┐
        │  agent_proc.run_agent(name, body, args, h)    │
        │    • spawns child, records registered_pid      │
        │    • owns the tool_handler h (recorder+tool)   │
        │    • owns signing key, ground-truth log,       │
        │      replay cache, tamper-evident log          │
        └───────────────┬───────────────────────────────┘
                        │ multiprocessing.Pipe (spawn ctx)
                        ▼
        child process (agent "name")
        ┌──────────────────────────────────────────────┐
        │  agent_bodies.<body>(conn, *args)             │
        │    • holds only opaque credentials             │
        │    • request_tool_call(conn, ...) over the pipe│
        │    • CANNOT reach the registry, log, or key    │
        └──────────────────────────────────────────────┘
```

The split is the whole point: everything that defines ground truth lives
in the parent; the child only ferries an opaque credential (a JWT string
or an apikey dict) and, for B5, a DPoP proof it signs with its own key.

---

## Locked decisions

### `spawn` context, not `fork`

`mp.get_context("spawn")` (agent_proc.py:70). Spawn is the only
cross-platform context (Windows has no `fork`) and it gives a clean
process image — the child re-imports modules rather than inheriting the
parent's memory. That clean re-import is what forces the
`agent_bodies.py` leaf-module discipline below.

### Bodies are a leaf module (imports nothing from auth/tools/harness)

`agent_bodies.py` deliberately imports only `os` and `threading` at
module scope. Reason: under `spawn`, importing the body's module in the
child re-runs that module's imports. If a body imported `auth.tokens`,
every spawned child would regenerate a 2048-bit RSA keypair at import
(tokens.py:37 runs at import time) — slow, and pointless because the
child never mints or verifies. The body only needs to *carry* a
credential, not understand it.

The one exception is `dpop_executor_body`, which imports `dpop` **inside
the function body** (agent_bodies.py:55), not at module scope. `dpop` is
itself a leaf (Ed25519 only, no `auth.tokens` import), so the cost is an
Ed25519 keypair reconstruction from PEM — cheap — and it only happens for
B5 runs.

### Identity = kernel registry, never the message (INV-4)

The tool-call message carries `os.getpid()` (agent_bodies.py:32) so the
kernel can **cross-check** it, but the resolved `true_actor` is always
`name` from the kernel's own registration (agent_proc.py:96). The
self-reported PID is used only to fail loud on mismatch
(`PidMismatchError`, agent_proc.py:90–94), never to decide identity. This
is the INV-4 line: a self-reported field may be *checked*, but it may
never *be* the ground truth.

### Causal precedence is structural here

`registered_pid = proc.pid` is read immediately after `proc.start()`
(agent_proc.py:76), before the receive loop serves any message. The
kernel knows who the agent is before the agent can say anything. v1's
causal precedence was "record before verify"; v2's is "register before
serve" — a stronger ordering because it predates the agent's first
instruction.

### Fail-loud on a dead or confused child (Rule 12)

Three failure paths, all surfaced rather than swallowed:
- body raises → child sends `("agent_error", e)` → parent re-raises it
  after join (agent_proc.py:40–44, 116–117). A dead child is never
  silent.
- tool_handler raises → sent to the agent *and* re-raised in the parent
  (agent_proc.py:101–103), so neither side loses the error.
- PID mismatch → `PidMismatchError`, no record written.

The `finally` block closes the parent pipe end (unblocks a child stuck in
`recv()` via EOFError), joins with a 10 s timeout, and terminates a hung
child (agent_proc.py:107–114) — no orphan processes leaking across the
test suite.

---

## The bodies (agent_bodies.py)

| Body | Role | §-ref |
|---|---|---|
| `request_tool_call` | shared IPC helper; sends `(tool_call, pid, cmd, target, cred, proof)`, returns the claimed record or re-raises the tool's error in-process | protocol |
| `executor_body` | the canonical §5 executor: one tool call, exit. B1–B4. | §5 |
| `dpop_executor_body` | B5 executor: rebuild DPoP key from PEM, sign a fresh proof bound to the tool endpoint at `now_value`, present (token, proof) | §5.1 |
| `spoofing_executor_body` | §3.2 stimulus: renames its thread to `agent:enrich` and rewrites `sys.argv[0]`, then calls. Must NOT change PID-based attribution. | §3.2 |

Note (agent_bodies.py:62–66): the §5.2 "lift" stimulus reuses
`dpop_executor_body` unchanged — the executor signs a proof under its own
key but is handed a token bound to *Enrich's* key; the tool rejects the
mismatch. The lift is a property of the credential/key *pairing*, not a
different agent behavior, so no separate body exists. This keeps INV-5
intact: no component misbehaves; the harness just pairs a key with the
wrong token to construct the stimulus.

---

## INV walkthrough

- **INV-1 (token structure):** N/A — the kernel ferries opaque tokens,
  never constructs or inspects them.
- **INV-2 (current actor resolution):** N/A — identity resolution from
  the token happens in the tool (`siem_action`), downstream of the
  kernel. The kernel resolves the *true* actor (process), which is a
  different axis.
- **INV-3 (siem_action naming):** ✓ — the `tool_handler` wraps
  `siem_action`; no `query_siem`.
- **INV-4 (ground-truth independence):** ✓ — all three axes are now
  *real*, not proxied: process boundary (OS subprocess), credential
  isolation (per-agent Pipe, child end only), causal precedence
  (register before serve). The kernel never reads identity from the
  message.
- **INV-5 (no illegitimate behavior):** ✓ — the spoofing/lift stimuli are
  harness-injected test pressure, not agent misconduct; the bodies
  themselves behave correctly.
- **INV-6 (baselines as config flags):** ✓ — the kernel is
  baseline-agnostic; the only thing that varies per baseline is the
  credential/body the harness hands it.
- **INV-7 (pre-registered):** the §3.1 regression (v1 curve reproduces
  under subprocess) and §3.2 spoof-resistance are both locked
  predictions; the kernel exists to make them measurable.
- **INV-8 (verify against source):** ✓ — spawn semantics, `proc.pid`
  availability after `start()`, and Pipe EOF behavior verified against
  the Python `multiprocessing` docs and exercised in
  `tests/test_process_recorder.py`.

---

## Cross-references

- **threat-model-v2.md §3** — the locked process-boundary predictions.
- **recorder_notes.md** (`==== v2 additions ====`) — how `true_actor`
  now flows from this kernel into the recorder.
- **CLAUDE.md INV-4** — the binding invariant this module makes real.
- **dpop_v2.md** — the B5 proof the `dpop_executor_body` signs.
- **v1 AEGIS-AT_Reference.md §II.8.9** — the thread-name caveat retired
  here.
- **tests/test_process_recorder.py** — §3.1 regression + §3.2 spoof
  resistance.
