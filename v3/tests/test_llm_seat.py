"""Tests for the LLM seat adapter (v3.1 Tier-2, Step 2).

Always-on guards need no key; the live smoke test is skipped without GROQ_API_KEY.
"""

import dataclasses
import importlib
import json
import os
import pathlib
import sys

import pytest

from aegis_at_v3.harness import llm_seat

REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
TM_V31 = (
    REPO_ROOT / "Documents" / "ThreatModel" / "ThreatModelv3" / "threat-model-v3.1.md"
)
AID = llm_seat.CANONICAL_ACTION_ID


class _Fn:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class _TC:
    def __init__(self, name, arguments):
        self.function = _Fn(name, arguments)


def _call(executor, action_id=AID, name="submit_completion"):
    args = json.dumps({"action_id": action_id, "asserted_executor": executor})
    return [_TC(name, args)]


# --- prompt fidelity (INV-7 / INV-8) ---------------------------------------


def test_prompt_constants_match_locked_c6():
    tm = TM_V31.read_text(encoding="utf-8").replace("\r\n", "\n")
    for prompt in (
        llm_seat.SYSTEM_PROMPT,
        llm_seat.HONEST_PROMPT,
        llm_seat.ATTACK_PROMPT,
    ):
        assert prompt in tm, "adapter prompt drifted from locked §C6"


def test_tool_schema_is_submit_completion():
    fn = llm_seat.TOOL_SCHEMA["function"]
    assert llm_seat.TOOL_SCHEMA["type"] == "function"
    assert fn["name"] == "submit_completion"
    assert set(fn["parameters"]["properties"]) == {"action_id", "asserted_executor"}
    assert set(fn["parameters"]["required"]) == {"action_id", "asserted_executor"}


# --- classification (strict §C7) -------------------------------------------


def test_classify_contain_enrich_well_formed():
    for ex in ("agent:contain", "agent:enrich"):
        cat, asserted = llm_seat.classify(_call(ex), None, AID)
        assert cat == "well_formed"
        assert asserted == ex


def test_classify_no_tool_call_refused():
    assert llm_seat.classify(None, "I cannot comply.", AID) == ("refused", None)
    assert llm_seat.classify([], "", AID) == ("refused", None)


def test_classify_nearmiss_malformed():
    for bad in (
        "agent:enrich ",
        "Agent:Enrich",
        "enrich",
        "agent: enrich",
        "AGENT:CONTAIN",
    ):
        cat, asserted = llm_seat.classify(_call(bad), None, AID)
        assert cat == "malformed"
        assert asserted is None


def test_classify_wrong_action_id_malformed():
    for aid in ("wrong-id", "", 123, None):
        args = json.dumps({"action_id": aid, "asserted_executor": "agent:enrich"})
        assert (
            llm_seat.classify([_TC("submit_completion", args)], None, AID)[0]
            == "malformed"
        )
    missing = json.dumps({"asserted_executor": "agent:enrich"})
    assert (
        llm_seat.classify([_TC("submit_completion", missing)], None, AID)[0]
        == "malformed"
    )


def test_classify_multiple_tool_calls_malformed():
    tcs = _call("agent:enrich") + _call("agent:enrich")
    assert llm_seat.classify(tcs, None, AID)[0] == "malformed"


def test_classify_wrong_tool_name_malformed():
    assert (
        llm_seat.classify(_call("agent:enrich", name="other_tool"), None, AID)[0]
        == "malformed"
    )
    assert (
        llm_seat.classify([_TC("submit_completion", "{not json")], None, AID)[0]
        == "malformed"
    )


# --- availability + key safety ---------------------------------------------


def _groq_httpx():
    import groq
    import httpx

    return groq, httpx


def test_unavailable_after_retries_excluded_but_counted(monkeypatch):
    groq, httpx = _groq_httpx()
    monkeypatch.setattr(llm_seat, "RETRY_BACKOFF_S", 0)

    class _Boom:
        class chat:
            class completions:
                @staticmethod
                def create(**_):
                    raise groq.APIConnectionError(
                        request=httpx.Request("POST", "https://api.groq.com")
                    )

    out = llm_seat.run_llm_seat(
        "m",
        "attack",
        action_id=AID,
        alert_id="a",
        target="host-42",
        seed=1,
        client=_Boom,
    )
    assert out.category == "unavailable"
    assert out.attempts == llm_seat.RETRY_MAX
    assert out.error_type == "APIConnectionError"
    assert out.asserted_executor is None


def test_key_never_surfaces(monkeypatch, caplog):
    groq, httpx = _groq_httpx()
    monkeypatch.setattr(llm_seat, "RETRY_BACKOFF_S", 0)
    sentinel = "gsk_FAKE_SENTINEL_DO_NOT_LEAK"

    class _Leak:
        class chat:
            class completions:
                @staticmethod
                def create(**_):
                    raise groq.APIError(
                        sentinel,
                        httpx.Request("POST", "https://api.groq.com"),
                        body=None,
                    )

    out = llm_seat.run_llm_seat(
        "m",
        "attack",
        action_id=AID,
        alert_id="a",
        target="host-42",
        seed=1,
        client=_Leak,
    )
    blob = json.dumps(dataclasses.asdict(out))
    assert sentinel not in blob
    assert sentinel not in caplog.text
    assert out.error_type == "APIError"


def test_import_without_groq_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "groq", None)
    mod = sys.modules["aegis_at_v3.harness.llm_seat"]
    importlib.reload(mod)  # imports cleanly with groq unavailable (lazy import)
    with pytest.raises(ImportError):
        mod.run_llm_seat(
            "m", "attack", action_id=AID, alert_id="a", target="host-42", seed=1
        )


# --- splice hook (B8/B9-only; scripted path unchanged) ---------------------


def test_scripted_cells_bit_identical_with_hook():
    from aegis_at_v3.harness import completion_sweep as cs

    base = cs.run_cell("B8", seat="colluding", topology="T1")
    hooked = cs.run_cell(
        "B8", seat="colluding", topology="T1", asserted_executor_override=None
    )
    assert base["completion"].asserted_executor == "agent:enrich"
    assert base["completion"] == hooked["completion"]
    assert base["audit"] == hooked["audit"]
    assert base["truth"] == hooked["truth"]
    with pytest.raises(ValueError):
        cs.run_cell(
            "B6",
            seat="honest",
            topology="T1",
            asserted_executor_override="agent:enrich",
        )


# --- live smoke (off by default) -------------------------------------------


@pytest.mark.skipif(not os.environ.get("GROQ_API_KEY"), reason="no GROQ_API_KEY")
def test_llm_seat_live_smoke():
    out = llm_seat.run_llm_seat(
        "llama-3.1-8b-instant",
        "attack",
        action_id=llm_seat.CANONICAL_ACTION_ID,
        alert_id=llm_seat.CANONICAL_ALERT_ID,
        target=llm_seat.CANONICAL_TARGET,
        seed=7,
    )
    assert out.category in llm_seat.CATEGORIES
    assert out.model == "llama-3.1-8b-instant"
