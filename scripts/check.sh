#!/usr/bin/env bash
# AEGIS-AT mechanical check gate.
# Run from repo root: ./scripts/check.sh
# Enforces the GREPPABLE project invariants (INV-2, INV-3) + lint + core tests.
# Judgment invariants (INV-1, INV-4, INV-5) are NOT checked here — see CHECKLIST.md.
#
# Exit codes: 0 = all pass, 1 = an invariant or check failed.
# This script is intentionally noisy on failure (Rule 12: fail loud).

set -uo pipefail
# Auto-activate venv if one exists (so ruff/black/pytest are found).
# Windows Git Bash uses Scripts/; Linux/macOS uses bin/.
if [ -f aegis-at/venv/Scripts/activate ]; then
  source aegis-at/venv/Scripts/activate
elif [ -f aegis-at/venv/bin/activate ]; then
  source aegis-at/venv/bin/activate
fi

# Scope greps to source only. Adjust if layout changes.
SRC_DIR="aegis-at"
FAIL=0

echo "=== AEGIS-AT check gate ==="

# ---------------------------------------------------------------------------
# INV-3 — tool name must be siem_action, never query_siem (in source).
# ---------------------------------------------------------------------------
echo "[INV-3] tool name (no query_siem in source)..."
if grep -rn "query_siem" "$SRC_DIR" --include="*.py" 2>/dev/null; then
  echo "  FAIL: 'query_siem' found in source. The tool is 'siem_action' (INV-3)."
  FAIL=1
else
  echo "  ok"
fi

# ---------------------------------------------------------------------------
# INV-2 — identity must resolve to the MOST-RECENT actor, never "innermost".
# Heuristic: flag any line that mentions BOTH an identity-resolution word
# AND "innermost". "innermost" alone is allowed (chain-walk direction);
# "innermost" near identity wording is the exact error we shipped once.
# This is a heuristic — false positives are possible and are a feature
# (they force a human glance), not a bug.
# ---------------------------------------------------------------------------
echo "[INV-2] identity resolution (no 'innermost' near identity wording)..."
# identity-resolution signal words
IDENT_RE='(claimed_actor|resolve.*actor|actor.*resolve|identity.*read|read.*identity|current actor)'
HITS=$(grep -rniE "innermost" "$SRC_DIR" --include="*.py" 2>/dev/null | grep -iE "$IDENT_RE" || true)
if [ -n "$HITS" ]; then
  echo "  FAIL: 'innermost' appears near identity-resolution wording (INV-2)."
  echo "        Identity resolves to the MOST-RECENT actor (top-level act.sub),"
  echo "        not the innermost subject (that is the root principal)."
  echo "$HITS" | sed 's/^/        > /'
  FAIL=1
else
  echo "  ok"
fi

# ---------------------------------------------------------------------------
# Lint / format — mechanical, always run. Tools optional: skip-with-warning
# if not installed so the gate still runs in a fresh checkout.
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Core tests — tokens, scorer, attack (Option 2: core-path testing).
# Only runs tests under tests/core/. Other tests are not gating for v1.
# ---------------------------------------------------------------------------
echo "[tests] core path..."
if command -v pytest >/dev/null 2>&1; then
  if [ -d "tests/core" ]; then
    pytest tests/core -q || FAIL=1
  else
    echo "  WARN: tests/core/ not present yet — no core tests to run."
  fi
else
  echo "  WARN: pytest not installed (pip install pytest) — tests skipped."
fi

echo "=== result ==="
if [ "$FAIL" -ne 0 ]; then
  echo "CHECK FAILED. Fix the above before committing. (Rule 12: fail loud.)"
  exit 1
fi
echo "All mechanical checks passed. Remember: CHECKLIST.md covers the"
echo "judgment invariants (INV-1, INV-4, INV-5) that no script can verify."
exit 0
