FINAL PASS (before threat-model.md is considered done):
Reconcile ALL §-cross-references against the locked 8-section map:
  §1 System under test
  §2 Trust boundaries
  §3 Adversary model
  §4 Ground-truth + AIS metric (formula included)
  §5 Attack mechanism
  §6 Defense baselines
  §7 Scope discipline
  §8 Validity threats
Checks:
  - Search for any ninth-section reference → it must not exist; every hit becomes §8.
  - Search "§6" → must mean Defense baselines, not the metric.
  - Search "§7" → must mean Scope discipline, not baselines.
  - Search "§8" → must mean Validity threats, not scope/backlog.
Do this AFTER §8 is locked, in one pass.
