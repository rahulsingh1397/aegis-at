# AEGIS-AT — Attribution Integrity Benchmark

A red-team benchmark measuring whether delegation-chain attribution in multi-agent
systems survives an adversarial **sibling-impersonation** attack — and which defenses
restore it. Scored as an **Attribution Integrity Score (AIS)** across four progressive
defense baselines.

## The question
Modern agent frameworks claim every action is traceable to a responsible party
(via RFC 8693 `act`-claim delegation). This benchmark tests whether that attribution
holds under adversarial pressure, rather than assuming it.

## Status
- [x] Threat model — `docs/threat-model.md` (the June gate; fill before building attacks)
- [x] Delegation tokens by hand — `auth/tokens.py` (run it: `python auth/tokens.py`)
- [ ] Minimal agent system — `agents/` (orchestrator + A + B + one tool)
- [ ] Ground-truth recorder + AIS scorer — `harness/`
- [ ] Sibling-impersonation attack — `harness/attacks/`
- [ ] Baseline sweep + resilience curve — `configs/`, `results/`

## Quick start
```bash
pip install -r requirements.txt
python auth/tokens.py          # see the delegation chain nest, scope narrowing, forgery rejection
```

## What is genuinely owned here
The threat model, the AIS metric definition, the attack mechanism, and the validity
analysis (`docs/threat-model.md` §5 and §9). The agent scaffolding and auth plumbing
are assembled with standard tooling; the measurement design is the contribution.

## Scope discipline
One failure mode (sibling impersonation), measured rigorously. Delegation forgery,
scope-attenuation bypass, audit-log tampering, and principal laundering are explicit
future work — see `docs/threat-model.md` §8.
