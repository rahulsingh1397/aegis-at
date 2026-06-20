#!/usr/bin/env bash
# AEGIS-AT v3 mechanical check gate.
# Run from v3/: ./scripts/check_v3.sh
# Enforces the GREPPABLE project invariants (INV-2, INV-3) + lint + v3 tests.
# Mirrors v2/scripts/check_v2.sh; only SRC_DIR / test paths differ. Judgment
# invariants (INV-1, INV-4, INV-5) are NOT checked here — see CHECKLIST.md.
#
# Exit codes: 0 = all pass, 1 = an invariant or check failed.
# Intentionally noisy on failure (Rule 12: fail loud).

set -uo pipefail
# Auto-activate venv if one exists (v3 shares v1/v2's venv; requirements at root).
if [ -f ../v1/aegis-at/venv/Scripts/activate ]; then
  source ../v1/aegis-at/venv/Scripts/activate
elif [ -f ../v1/aegis-at/venv/bin/activate ]; then
  source ../v1/aegis-at/venv/bin/activate
fi

SRC_DIR="aegis_at_v3"
FAIL=0

echo "=== AEGIS-AT v3 check gate ==="

echo "[INV-3] tool name (no query_siem in source)..."
if grep -rn "query_siem" "$SRC_DIR" --include="*.py" 2>/dev/null; then
  echo "  FAIL: 'query_siem' found in source. The tool is 'siem_action' (INV-3)."
  FAIL=1
else
  echo "  ok"
fi

echo "[INV-2] identity resolution (no 'innermost' near identity wording)..."
IDENT_RE='(claimed_actor|resolve.*actor|actor.*resolve|identity.*read|read.*identity|current actor)'
HITS=$(grep -rniE "innermost" "$SRC_DIR" --include="*.py" 2>/dev/null | grep -iE "$IDENT_RE" || true)
if [ -n "$HITS" ]; then
  echo "  FAIL: 'innermost' appears near identity-resolution wording (INV-2)."
  echo "$HITS" | sed 's/^/        > /'
  FAIL=1
else
  echo "  ok"
fi

echo "[lint] ruff..."
if command -v ruff >/dev/null 2>&1; then
  ruff check "$SRC_DIR" || FAIL=1
else
  echo "  WARN: ruff not installed (pip install ruff) — lint skipped."
fi

echo "[format] black --check..."
if command -v black >/dev/null 2>&1; then
  black --check "$SRC_DIR" || FAIL=1
else
  echo "  WARN: black not installed (pip install black) — format check skipped."
fi

echo "[tests] v3..."
if command -v pytest >/dev/null 2>&1; then
  if [ -d "tests" ]; then
    pytest tests -q
    RC=$?
    if [ "$RC" -eq 5 ]; then
      echo "  WARN: no v3 tests collected yet."
    elif [ "$RC" -ne 0 ]; then
      FAIL=1
    fi
  else
    echo "  WARN: tests/ not present yet."
  fi
else
  echo "  WARN: pytest not installed (pip install pytest) — tests skipped."
fi

echo "=== result ==="
if [ "$FAIL" -ne 0 ]; then
  echo "V3 CHECK FAILED. Fix the above before committing. (Rule 12: fail loud.)"
  exit 1
fi
echo "All v3 mechanical checks passed. Remember: CHECKLIST.md covers the"
echo "judgment invariants (INV-1, INV-4, INV-5) that no script can verify."
exit 0
