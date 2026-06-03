# Recorder Notes — aegis-at/harness/recorder.py

                                        Working notes for the ground-truth recorder. The recorder is the most
                                        INV-sensitive module in the project — INV-4 is its entire reason to
                                        exist — so we lock the design here before writing code.

                                        Implementation will live in `aegis-at/harness/recorder.py`. This file
                                        is the *why*.

---

## What the recorder is for

                                        Per §2 Boundary 5: the recorder produces ground-truth records about *what actually happened* during a tool invocation, independent of what the token claims. The AIS scorer compares these against the tool's Boundary-4 records (claimed records) to compute attribution accuracy.

                                        The recorder is NOT part of the SOC system being measured. It's **harness infrastructure**. The threat model excludes it from the adversary's reach (INV-4: process boundary, credential isolation, causal precedence). If the recorder could be influenced by the agents or the tool, the measurement would be circular.

---

## INV-4 analysis (the binding constraint)

                                        INV-4 (CLAUDE.md): *"The ground-truth recorder observes the executing PROCESS. It must NEVER read identity from a token or any agent-supplied field. If ground-truth code touches the `act` claim, the measurement is circular and INVALID. Hold all three axes: process boundary, credential isolation, causal precedence."*

Three axes, examined for v1:

### Process boundary
                                        The recorder must observe the *true caller* without trusting any caller-supplied label. In v1 (single-process Python), full OS process isolation isn't viable without major harness complexity. We use **thread-naming** as a proxy: each agent runs in its own `threading.Thread` constructed with `name="agent:enrich"` (or similar), and the recorder reads `threading.current_thread().name`.

                                        This is weaker than true process boundary — an agent's code could mutate its thread name mid-call. But INV-5 ("no illegitimate component behavior") excludes that: a well-behaved component never renames its thread. The threat model's adversary controls alert text only, not agent code (per §3). So thread-naming holds *within the threat model the project is testing*, and the v1 limitation is documented in §8.

### Credential isolation
                                        The recorder writes to a list (or file) the agents can't reach. In v1, this is a harness-owned list passed by closure to the recorder; the agents have no reference to it.

### Causal precedence
                                        The recorder records BEFORE the tool's verification runs. If the tool errors (forgery, expired token), ground truth is still written — the attempt happened even if it was rejected. This is what lets the scorer
                                        measure attempted but blocked actions, not just successful ones.

---

## v1 design: a wrapper around siem_action

                                        The recorder is a function factory: it takes the real `siem_action` callable and returns a wrapped version. The wrapper:

                                        1. Reads `threading.current_thread().name` — the **true actor**.
                                        2. Derives `true_scope` from the **observed command** (not the token) by calling `scope_for_command(command)`. The command argument was passed to the wrapper directly; it did not come from a token.
                                        3. Appends the ground-truth record to a harness-owned list.
                                        4. Calls the real `siem_action`. Result (or exception) propagates unchanged.

                                        What the wrapper does NOT do:
                                        1. It does NOT call `verify_token`, `actor_chain`, `resolve_identity`, or any function from `siem_action.py` to
                                           derive ground truth. That would make ground truth read from the token (INV-4 violation).
                                        2. It does NOT inspect the token at all. The token isn't even unpacked.
                                        3. It does NOT decide whether the call succeeds. The real `siem_action` does that. The recorder is independent of
                                           outcome.

### Sketch

                                        ```python
                                        def make_recorder(real_siem_action, ground_truth_log):
                                            def wrapped(command, target, token, **kw):
                                                true_actor = threading.current_thread().name
                                                true_scope = scope_for_command(command)  # raises on unknown
                                                ground_truth_log.append({
                                                    "true_actor": true_actor,
                                                    "true_scope": true_scope,
                                                    "true_principal_chain": [
                                                        true_actor,
                                                        "agent:orchestrator",
                                                        "human:analyst",
                                                    ],
                                                    "command": command,
                                                    "target": target,
                                                    "timestamp": time.time(),
                                                })
                                                return real_siem_action(command, target, token, **kw)
                                            return wrapped
                                        ```

                                        The wrapper preserves the tool's signature and forwards keyword args (including `now_fn`) so it stays a drop-in replacement.

---

## Locked decisions (v1)

### Threading-based observation (v1a)

                                        Chosen over two rejected alternatives:

- **Explicit parameter `true_actor=`** 
                                        (the other tool's proposal).Rejected: makes the recorder read a caller-supplied field, which is INV-4 violation in spirit. The caller "names" the actor - the recorder doesn't observe anything. The §8 caveat for this approach would be much larger than for thread-naming.
- **Multiprocessing with `os.getpid()`**. 

                                        Strongest INV-4 (true process boundary). Rejected for v1 because it forces the harness to use `multiprocessing.Process` instead of `threading.Thread`, complicates inter-process record collection, and slows the test suite. Worth revisiting in v2 as a hardening pass.

### Wrapper pattern, not decorator

                                        The recorder is a factory function `make_recorder(real_siem_action, log)` that returns a wrapped callable. NOT a `@recorder` decorator.

                                        Why: a decorator would have to know where the log lives at module load time (module-level state) or use a context variable (hidden coupling). A factory function is explicit: the harness builds the wrapped tool with the log it wants, and the wrapped tool is just a callable.

### Recorder reads command from the call, not the token

                                        `scope_for_command(command)` is called with the `command` argument passed to the wrapped tool — the command the agent intends to execute.
                                        This is *observed* (the harness sees what's being requested), not *claimed* (the token doesn't carry a command field). INV-4 holds.

### `true_principal_chain` is the §4-schema 3-hop list

                                        Per the threat model's locked §4 schema, the true chain is `[true_actor, "agent:orchestrator", "human:analyst"]` — three hops from immediate actor to root principal. An earlier draft of this
                                        notes file proposed a one-element chain `[true_actor]`; that contradicted §4 and was corrected before the recorder build.

                                        The 3-hop shape matters for the metric. §4 defines principal_chain equality as ordered-list equality (same length, same members, same order). With matching shapes across claimed and true records, a sibling-impersonation defect produces a clean first-element mismatch:

                                                claimed: ["agent:enrich",   "agent:orchestrator", "human:analyst"]
                                                true:    ["agent:contain",  "agent:orchestrator", "human:analyst"]

                                        That's a clean actor defect — the metric flags exactly what it should. A shape-mismatch (different list lengths) would conflate the actor defect with a structural defect, muddying the signal.
---

## INV walkthrough

                                        - **INV-1 (token structure):** N/A — recorder doesn't touch tokens.
                                        - **INV-2 (current actor resolution):** N/A directly; but the recorder
                                        must never call `resolve_identity()` to derive truth. The wrapper
                                        sketch above honors this.
                                        - **INV-3 (siem_action naming):** ✓ — wraps `siem_action`, not
                                        `query_siem`.
                                        - **INV-4 (ground-truth independence):** ✓ — three axes addressed
                                        above. v1a limitation noted in §8 (next).
                                        - **INV-5 (no illegitimate component behavior):** ✓ — the recorder is
                                        not a component of the SOC system; it's harness infrastructure. The
                                        threat model's adversary cannot influence it (it has no path in).
                                        - **INV-6 (baselines as config flags):** the recorder is
                                        baseline-independent — it observes the same way regardless of which
                                        baseline the tool is configured for. This is what lets the scorer
                                        measure differences between baselines as *the only thing that
                                        changed*.
                                        - **INV-7 (pre-registered predictions):** N/A — recorder doesn't
                                        measure AIS; the scorer does.
                                        - **INV-8 (verify against source):** ✓ — `threading.current_thread()`
                                        behavior verified by the Python stdlib docs; will also be verified
                                        by tests (a test constructs two named threads and asserts the
                                        recorder distinguishes them).

---

## §8 (Validity Threats) addition needed in threat-model.md

-                                       Add to threat-model.md §8 (validity threats), as a new bullet: **v1 process-boundary proxy.** The   
                                        ground-truth recorder uses `threading.current_thread().name` as a proxy for OS process identity. A misbehaving agent that renamed its thread mid-call could spoof ground truth. INV-5 (no illegitimate component behavior) excludes this from the threat model — the adversary controls alert text only (§3), not agent code. v2 hardening would use `multiprocessing` with `os.getpid()` for true process boundary.

                                        This caveat is small because the threat model's adversary already cannot touch agent code. The recorder's v1 weakness only matters under adversary models we are explicitly not testing.

---

## Forward hooks

### For the AIS scorer

                                        - Consumes the harness-owned `ground_truth_log` list and the Boundary-4 records produced by `siem_action`.
                                        - Matches records by `(command, target, timestamp)` per §4.
                                        - A scorer test that constructs synthetic record pairs (a matching pair → AIS 1; a mismatched pair → AIS 0)  
                                          confirms the scoring logic before the orchestrator + attack are wired up.

### For the orchestrator + agents

                                        - Each agent must run in its own thread named after its identity:
                                          `Thread(target=enrich_loop, name="agent:enrich")`.
                                        - The orchestrator runs in its own thread:
                                          `Thread(target=orch_loop, name="agent:orchestrator")`.
                                        - The harness verifies thread naming on startup — a non-conformant
                                          agent fails to start, not silently mis-attributed.

### For the harness's tool wiring

                                        - The harness builds the recorder once: `wrapped = make_recorder(siem_action, ground_truth_log)`.
                                        - All agents receive `wrapped` (not the bare `siem_action`) as their tool reference.
                                        - The harness owns both the action log (Boundary-4) and the ground-truth log (Boundary-5); the scorer reads both.

---

## Open questions deferred

- **Should the recorder log even when the tool raises?** 
                                        
    Currently yes (causal precedence: the attempt happened). A failed attempt with no ground-truth record would let an attacker "fail quietly" with no audit trail. Worth a test: forged token → ground-truth record exists, action-log record absent.

- **What if two agents call simultaneously?** 
    v1 is single-threaded per agent flow; concurrency between agents isn't part of the measurement. v2 with `multiprocessing` might need a lock on the log lists.

- **Should the orchestrator hop in the true chain be a constant, or read from harness state?** 
    v1 hardcodes "agent:orchestrator" and "human:analyst" because the harness has only one orchestrator and one analyst. v2 with multiple orchestrators would need to track which one was active for the call.
    
- **Does the recorder need its own scope-map import?** 
    Yes — it derives `true_scope` from the observed command. This is the second consumer of `policy/scope_map.py`, fulfilling its shared-contract purpose.

---

## Cross-references

- **threat-model.md §2 Boundary 5**: defines the recorder's role.
- **threat-model.md §4**: ground-truth record schema.
- **threat-model.md §8**: needs the v1a process-boundary caveat added.
- **CLAUDE.md INV-4**: the binding invariant.
- **policy_notes.md**: the recorder consumes `scope_for_command()`.
- **tools_notes.md**: lists the recorder's INV-4 obligation as a
  forward hook from the tool.