"""Core tests for policy/scope_map.py — shared scope-gate contract."""
import pytest

from scope_map import scope_for_command, known_commands


def test_keyword_search_requires_read():
    """The read-class command must require siem:read. If this drifts,
    Baseline 2's attribution model breaks and the attack is unmeasurable."""
    assert scope_for_command("keyword_search") == "siem:read"


def test_isolate_host_requires_write():
    """The action command must require siem:write. If this drifts,
    the Path B attack stops being measurable — Enrich could call
    isolate_host on a read token and the scope gate wouldn't catch it."""
    assert scope_for_command("isolate_host") == "siem:write"


def test_unknown_command_raises():
    """Unknown commands MUST fail loud (Rule 12). A silent default
    would let an untested command slip into the attack path."""
    with pytest.raises(ValueError, match="unknown command"):
        scope_for_command("delete_everything")


def test_known_commands_lists_exactly_v1_set():
    """v1 ships exactly two commands. If this test fails, someone added
    a command without updating the threat model and its tests — stop
    and do both before continuing."""
    assert known_commands() == ["isolate_host", "keyword_search"]