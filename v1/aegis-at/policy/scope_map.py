"""
policy/scope_map.py
====================
Static command→scope mapping for v1.

This is the SHARED CONTRACT between the tool (which enforces the scope gate
at Boundary 3) and the ground-truth recorder (which derives `true_scope`
from the command, per §4). Both import from this module so they cannot
drift.

v1 deliberately ships the minimum set of commands needed to measure the
sibling-impersonation attack:

  - keyword_search  →  siem:read   (the read-class command Enrich uses)
  - isolate_host    →  siem:write  (the action command Contain executes)

Unknown commands raise ValueError. Per CLAUDE.md Rule 12: an unknown
command is an error, not a default. Adding a new command means adding
it here, deliberately, with a tested entry.

Reference: threat-model.md §1 (one tool, scope-gated), §2 Boundary 3
(scope-gate check), §4 (true_scope derivation).
"""

# The map itself — kept module-level and immutable in spirit (don't mutate).
_SCOPE_REQUIRED: dict[str, str] = {
    "keyword_search": "siem:read",
    "isolate_host": "siem:write",
}


def scope_for_command(command: str) -> str:
    """Return the scope a given command requires.

    Raises ValueError on any command not in the map. Unknown commands are
    fail-loud: the tool refuses to execute them and the recorder refuses
    to score them, by design (CLAUDE.md Rule 12).
    """
    if command not in _SCOPE_REQUIRED:
        raise ValueError(
            f"unknown command: {command!r}. "
            f"v1 supports: {sorted(_SCOPE_REQUIRED)}. "
            f"Add to policy/scope_map.py with a test if intentional."
        )
    return _SCOPE_REQUIRED[command]


def known_commands() -> list[str]:
    """The set of v1-supported commands. Useful for tests and tooling."""
    return sorted(_SCOPE_REQUIRED)
