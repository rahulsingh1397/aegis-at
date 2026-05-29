# AEGIS-AT

A red-team benchmark measuring whether delegation-chain attribution in
multi-agent AI systems survives adversarial sibling impersonation.

## What this project does

Modern multi-agent frameworks rely on signed delegation chains (RFC 8693
`act` claims) to attribute actions back to a responsible human principal.
Standards bodies including NIST NCCoE (Feb 2026) have explicitly identified
non-repudiation of agent actions as an open problem with no benchmark.

This project builds the benchmark. A small SOC alert-triage pipeline
(orchestrator + two sibling subagents + one shared SOAR-style tool) is
subjected to an adversarial sibling-impersonation attack: a high-consequence
containment action performed by one agent is recorded under the identity of
its lower-consequence sibling, hiding the true executor from audit.

The result is an **Attribution Integrity Score (AIS)** measured across four
progressive defense baselines (shared credential → per-agent identity →
RFC 8693 act claims → tamper-evident logs). The deliverable is a
reproducible resilience curve — quantifying how much each defense layer
actually closes the attribution gap.

## Status

- [x] Scope and methodology locked (see `docs/scope.md`)
- [ ] Threat model — in progress (see `docs/threat-model.md`)
- [x] RFC 8693 token exchange — working reference implementation (`auth/tokens.py`)
- [ ] Minimal agent system — pending threat model lock
- [ ] Sibling-impersonation attack — pending
- [ ] Baseline sweep and resilience curve — pending
- [ ] Writeup — pending

This is an active research project. Documentation and code evolve together;
the `docs/` folder records the design rationale as decisions are made.

## What lives where

- `docs/threat-model.md` — primary design document
- `docs/Trust_Boundries/` — per-boundary rationale and forward hooks
- `docs/ImportantQuestions/` — decision rationale for system-under-test
  and tool design
- `auth/` — RFC 8693 reference implementation
- `agents/`, `harness/`, `configs/`, `results/` — populated as the
  build progresses

## Why this matters

NIST NCCoE explicitly called for auditing and non-repudiation mechanisms
for AI agent actions in its February 2026 concept paper. The Cline
February 2026 compromise demonstrated that audit trails can be made to
lie about which agent performed an action. No reproducible benchmark
currently exists for measuring whether the defenses being proposed
(per-agent identity, signed delegation, tamper-evident logging) actually
hold under adversarial pressure. This is that benchmark.