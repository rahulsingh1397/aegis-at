"""AEGIS-AT v3 package.

Builds on the v2 substrate by import (INV-6: B1-B5 stay byte-for-byte the
v1/v2 path; see ../v2/aegis_at_v2/). v3 adds the completion-record model
(B8/B9), the MCP-shaped transport boundary, and the adversary adapter.
Predictions are pre-registered in
Documents/ThreatModel/ThreatModelv3/threat-model-v3.md (+ source-lock-v3.md),
both SHA-256-locked.
"""
