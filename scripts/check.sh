#!/usr/bin/env bash
# AEGIS-AT top-level check gate.
# Run from repo root: ./scripts/check.sh
# Runs BOTH the frozen v1 gate and the v2 gate. Both must exit 0.
#
# Exit codes: 0 = all pass, 1 = a gate failed.
# This script is intentionally noisy on failure (Rule 12: fail loud).

set -uo pipefail
FAIL=0

echo "=== AEGIS-AT top-level gate ==="

echo "--- v1 gate (frozen) ---"
(cd v1 && bash scripts/check.sh) || FAIL=1

echo "--- v2 gate ---"
if [ -f v2/scripts/check_v2.sh ]; then
  (cd v2 && bash scripts/check_v2.sh) || FAIL=1
else
  echo "  WARN: v2/scripts/check_v2.sh not present yet — v2 gate skipped."
fi

echo "=== result ==="
if [ "$FAIL" -ne 0 ]; then
  echo "TOP-LEVEL CHECK FAILED. Fix the above before committing. (Rule 12: fail loud.)"
  exit 1
fi
echo "All gates passed (v1 frozen + v2)."
exit 0
