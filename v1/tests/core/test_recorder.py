"""Core tests for harness/recorder.py — §2 Boundary 5, INV-4."""
import threading
import pytest

from tokens import mint_initial_token, exchange_token
from siem_action import siem_action
from recorder import make_recorder


# Fixed clock for deterministic timestamps in pairing tests.
_FIXED_TS = 1_700_000_000.0
_fixed_clock = lambda: _FIXED_TS


def _run_in_named_thread(name: str, fn):
    """Run fn() in a thread named `name`. Return its value or raise its error."""
    result = {}

    def runner():
        try:
            result["value"] = fn()
        except BaseException as e:
            result["error"] = e

    t = threading.Thread(target=runner, name=name)
    t.start()
    t.join()
    if "error" in result:
        raise result["error"]
    return result["value"]


def test_recorder_observes_calling_thread_name():
    """The recorder reads true_actor from the calling thread,
    independent of what the token says. This is the load-bearing INV-4
    test: claimed identity (token) and true identity (thread) come
    from causally independent sources.

    Chain is 2-hop [true_actor, "human:analyst"] — the orchestrator is
    a stateless minter, not a delegated principal, so it does not
    appear (threat-model.md §4)."""
    gt_log = []
    wrapped = make_recorder(siem_action, gt_log)

    # Token claims Enrich as current actor.
    root = mint_initial_token("human:analyst", "siem:write")
    enrich = exchange_token(root, "agent:enrich")

    # Contain is the thread actually executing.
    _run_in_named_thread(
        "agent:contain",
        lambda: wrapped("isolate_host", "host-01", enrich, now_fn=_fixed_clock),
    )

    assert len(gt_log) == 1
    record = gt_log[0]
    assert record["true_actor"] == "agent:contain"
    assert record["true_scope"] == "siem:write"
    assert record["true_principal_chain"] == [
        "agent:contain",
        "human:analyst",
    ]
    assert record["command"] == "isolate_host"
    assert record["target"] == "host-01"
    assert record["timestamp"] == _FIXED_TS


def test_recorder_and_tool_share_timestamp_for_pairing():
    """Claimed and true records must share the timestamp, since §4
    pairs them by (command, target, timestamp). Without shared clock,
    AIS pairing fails."""
    gt_log = []
    wrapped = make_recorder(siem_action, gt_log)

    root = mint_initial_token("human:analyst", "siem:write")
    enrich = exchange_token(root, "agent:enrich")

    claimed = _run_in_named_thread(
        "agent:contain",
        lambda: wrapped("isolate_host", "host-01", enrich, now_fn=_fixed_clock),
    )

    assert gt_log[0]["timestamp"] == claimed["timestamp"]
    assert gt_log[0]["command"] == claimed["command"]
    assert gt_log[0]["target"] == claimed["target"]


def test_recorder_distinguishes_two_threads():
    """Two calls from differently-named threads must produce two
    ground-truth records with different true_actor values."""
    gt_log = []
    wrapped = make_recorder(siem_action, gt_log)

    root = mint_initial_token("human:analyst", "siem:read siem:write")
    token = exchange_token(root, "agent:enrich")

    _run_in_named_thread(
        "agent:enrich",
        lambda: wrapped("keyword_search", "src_ip=1.2.3.4", token),
    )
    _run_in_named_thread(
        "agent:contain",
        lambda: wrapped("isolate_host", "host-01", token),
    )

    assert [r["true_actor"] for r in gt_log] == ["agent:enrich", "agent:contain"]


def test_recorder_writes_before_tool_runs():
    """Causal precedence: even when the tool raises (forged token),
    the ground-truth record must already exist. This makes
    failed-attempt attribution measurable."""
    gt_log = []
    wrapped = make_recorder(siem_action, gt_log)

    forged = "this.is.not.a.valid.jwt"

    with pytest.raises(Exception):
        _run_in_named_thread(
            "agent:contain",
            lambda: wrapped("isolate_host", "host-01", forged),
        )

    assert len(gt_log) == 1
    assert gt_log[0]["true_actor"] == "agent:contain"


def test_recorder_derives_true_scope_from_command_not_token():
    """INV-4: true_scope comes from scope_for_command(observed_command),
    NOT from the token's scope claim. This test uses a token whose
    scope is a superset of what the command needs, and verifies the
    recorder records the command-required scope, not the token's
    declared scope."""
    gt_log = []
    wrapped = make_recorder(siem_action, gt_log)

    # Token carries BOTH scopes; command only needs siem:write.
    root = mint_initial_token("human:analyst", "siem:read siem:write")
    token = exchange_token(root, "agent:enrich")

    _run_in_named_thread(
        "agent:contain",
        lambda: wrapped("isolate_host", "host-01", token),
    )

    # true_scope is siem:write (from command), not "siem:read siem:write"
    # (from token).
    assert gt_log[0]["true_scope"] == "siem:write"


def test_recorder_unknown_command_propagates_error():
    """Unknown commands fail-loud at the recorder (scope_for_command
    raises ValueError), BEFORE the tool runs. No ground-truth record
    is written — the call was malformed at the harness layer."""
    gt_log = []
    wrapped = make_recorder(siem_action, gt_log)

    root = mint_initial_token("human:analyst", "siem:write")

    with pytest.raises(ValueError, match="unknown command"):
        _run_in_named_thread(
            "agent:contain",
            lambda: wrapped("delete_everything", "host-01", root),
        )

    assert gt_log == []