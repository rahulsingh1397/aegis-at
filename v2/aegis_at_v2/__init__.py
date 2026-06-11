"""AEGIS-AT v2 package.

Builds on the frozen v1 substrate (see ../v1/aegis-at/). Phases land here
in dependency order: process-boundary recorder, Baseline 5 (DPoP),
hash-chained log + LIS, topology T2, stochastic policy + Wilson CIs.
Predictions are pre-registered in Documents/ThreatModel/ThreatModelv2/threat-model-v2.md
(plus the threat-model-v2.1.md amendment in the same directory).
"""
