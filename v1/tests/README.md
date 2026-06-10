# AEGIS-AT — Testing Conventions

Testing intent for v1: **core path is tested rigorously; scaffolding is
tested lightly.** This keeps the benchmark's critical claims credible
without slowing down the code that exists only to make the attack run.

## Layout

```
tests/
  core/      <- gating. Run by ./scripts/check.sh. Must pass to commit.
  support/   <- non-gating. Scaffolding tests, run manually as useful.
```

`check.sh` runs **only `tests/core/`**. That is deliberate: the gate
stays fast and the "must pass" bar applies only where correctness is
load-bearing.

## What belongs in tests/core/ (the critical path)

These three are the benchmark's credibility. They get real tests:

1. **Tokens** (`auth/tokens.py`) — minting produces the RFC 8693-compliant
   shape (INV-1); identity resolves to the most-recent actor / top-level
   `act.sub` (INV-2); the five Boundary 3 checks each reject what they
   should and accept what they should; a forged/expired/unrooted token is
   rejected.
2. **Scorer** (AIS, §4) — a matching claimed/true triple scores 1; a
   mismatch on any field scores 0; `principal_chain` comparison is
   ordered-list equality (permutation, missing hop, inserted hop all
   count as defects); the denominator counts adversarial actions only.
3. **Attack** (`harness/attacks/`) — the Path B flow produces the expected
   misattribution (claimed Enrich, true Contain); the no-attack flow
   produces correct attribution (the B2≈1.0 checkpoint).

## What belongs in tests/support/ (scaffolding)

Agent stubs, orchestrator plumbing, config loading, fixtures. Test these
enough to trust them; don't gold-plate them.

## The standard for a core test (Rule 9)

A test must encode **why** the behavior matters, not just what it does.

- Bad: `assert resolve(token) == "agent:enrich"` — passes even if the
  reason is wrong; a future refactor that breaks the invariant for the
  wrong reason still goes green.
- Good: a test named for the invariant
  (`test_identity_resolves_to_most_recent_actor_not_root_principal`) that
  constructs a multi-hop chain and asserts the resolver returns the
  top-level `act.sub` and explicitly NOT the deeply-nested root — so it
  fails loudly if anyone reintroduces the "innermost" error.

If a test cannot fail when the invariant is violated, it is not testing
the invariant. Rewrite it.

## Running

```
pytest tests/core -q        # the gate (also run by check.sh)
pytest tests/support -q     # scaffolding, manual
pytest -q                   # everything
```
