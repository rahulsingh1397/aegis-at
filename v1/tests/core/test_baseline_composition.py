"""
End-to-end composition tests — the AIS curve, one baseline at a time.
=====================================================================
Place at: tests/core/test_baseline_composition.py

Tests the COMPOSITION (siem_action -> recorder -> scorer) against the real
modules, with real credentials. This is the layer the unit tests don't cover
and the one the §6 non-monotonic curve actually lives in. It doubles as the
executable spec for the baseline-switch harness: a run() for baseline B must
reproduce the AIS asserted here.

BASELINE MODEL (locked — the "(c)" package):
  B1  shared opaque credential (apikey, agent=svc:soar) ......... predict ~0.0
  B2  per-agent opaque credential (apikey, agent=agent:contain) . predict ~1.0
  B3  + RFC 8693 delegation across the requester/wielder boundary  predict ~0.0
  B4  + tamper-evident log (attribution == B3) ................... predict ~0.0

principal_chain is a delegation concept: it does not exist for an opaque
per-agent credential, so it is None at B1/B2 and a real chain at B3/B4 (§4).
"Credential-aware", not "baseline-aware": siem_action and the recorder
discriminate on the observable credential STRUCTURE (apikey dict vs JWT),
never on harness state — true_actor still comes from the executing thread,
so INV-4 holds.

THE ATTACK (§5 Path B): a containment-warranting alert flows through low-priv
Enrich; Enrich correctly escalates; the orchestrator honestly mints a
siem:write token whose current actor (act.sub) is Enrich, the requester;
high-priv Contain — the wielder — executes isolate_host. The log names the
requester; the executor is recorded only out-of-band by the harness.

These AIS values are pre-registered predictions (§6 / INV-7), to be confirmed
or refuted by measurement; a contradicted prediction is itself a finding.
"""
import threading
import pytest

from tokens import mint_initial_token, exchange_token
from orchestrator import mint_delegated_token
from siem_action import siem_action
from recorder import make_recorder
from scorer import score_ais


# --- opaque per-agent credential (c-minimal: inline fixture, no module) -----
# Stands in for the resolved result of an API-key / SVID lookup: the harness
# would verify the key against a registry and obtain (agent, scope). The real
# auth/api_key.py module is built with the baseline-switch harness later.
def apikey(agent: str, scope: str) -> dict:
    return {"format": "apikey", "agent": agent, "scope": scope}


# --- harness helpers (what a real sweep runner would own) -------------------
def _run_in_named_thread(name, fn):
    """Execute fn() on a thread NAMED for the true executing agent. The
    recorder reads threading.current_thread().name as true_actor (INV-4)."""
    box = {}
    def runner():
        try: box["v"] = fn()
        except BaseException as e: box["e"] = e
    t = threading.Thread(target=runner, name=name)
    t.start(); t.join()
    if "e" in box: raise box["e"]
    return box["v"]


def _score_one_action(credential, command, target, executor_thread):
    """Run ONE action through the real tool + recorder, score it as the sole
    adversarial action, return the ScorerResult. Only `credential` (the
    per-baseline shape) differs across baselines; tool/recorder/scorer are
    identical (INV-6)."""
    gt_log = []
    wrapped = make_recorder(siem_action, gt_log)
    claimed = _run_in_named_thread(
        executor_thread, lambda: wrapped(command, target, credential))
    triple = (claimed["command"], claimed["target"], claimed["timestamp"])
    return score_ais([claimed], gt_log, frozenset({triple}))


# --- control: a correct attribution must score 1.0 -------------------------
def test_control_same_agent_scores_one():
    """Floor check: when the SAME agent requests and executes (Enrich does a
    read), claimed == true on every field and AIS = 1.0. Proves the harness
    is not trivially always-zero and that the 2-hop JWT chain pairs."""
    root = mint_initial_token("human:analyst", "siem:read siem:write")
    enrich = exchange_token(root, "agent:enrich", "siem:read")  # [enrich, analyst]
    res = _score_one_action(enrich, "keyword_search", "src_ip=1.2.3.4", "agent:enrich")
    assert res["ais"] == 1.0
    assert res["defects"] == []


# --- Baseline 1: shared opaque credential ----------------------------------
def test_baseline1_shared_credential_scores_zero():
    """B1: all agents act under ONE shared identity. The write is attributed
    to the shared account, not Contain — attribution is undefined w.r.t.
    agents. Lone defect is actor (chain is None on both sides). Predict ~0.0."""
    res = _score_one_action(apikey("svc:soar", "siem:write"),
                            "isolate_host", "host-42", "agent:contain")
    assert res["ais"] == 0.0
    d = res["defects"][0]
    assert d["shape"] == "field_mismatch"
    assert d["mismatched_fields"] == ["actor"]            # only actor; chain None==None


# --- Baseline 2: per-agent opaque credential (the 1.0 anchor) --------------
def test_baseline2_per_agent_identity_scores_one():
    """B2: the executor authenticates as itself; claimed actor == true actor
    == agent:contain, and principal_chain is None on both sides (no delegation
    yet). AIS = 1.0 — the anchor that makes the curve non-monotonic. With the
    (c) model and credential-aware ground truth, no chain-shape mismatch can
    occur, so this scores cleanly (no xfail)."""
    res = _score_one_action(apikey("agent:contain", "siem:write"),
                            "isolate_host", "host-42", "agent:contain")
    assert res["ais"] == 1.0, f"expected clean 1.0, got defects {res['defects']}"
    assert res["defects"] == []


# --- Baseline 3: + delegation across the requester/wielder boundary --------
def test_baseline3_requester_wielder_boundary_regresses_to_zero():
    """B3 (headline): adding signed delegation REGRESSES attribution. Enrich
    honestly re-delegates; the orchestrator honestly mints a siem:write token
    naming Enrich (requester) as current actor; Contain (wielder) executes.
    Defect on {actor, principal_chain} (§6: correlated); scope intact.
    Predict ~0.0."""
    root = mint_initial_token("human:analyst", "siem:read siem:write")
    attack = mint_delegated_token(root, "agent:enrich", "siem:write",
                                  audience="siem_action")  # [enrich, analyst]
    res = _score_one_action(attack, "isolate_host", "host-42", "agent:contain")
    assert res["ais"] == 0.0
    d = res["defects"][0]
    assert d["shape"] == "field_mismatch"
    assert set(d["mismatched_fields"]) == {"actor", "principal_chain"}
    assert "scope" not in d["mismatched_fields"]          # scope is genuinely correct


# --- Baseline 4: + tamper-evident log (attribution == B3) ------------------
def test_baseline4_tamper_evident_attribution_equals_b3():
    """B4 = B3 + tamper-evident log. Tamper-evidence operates at the log
    boundary (integrity), not at minting, so it CANNOT change who is named:
    the predicted, testable claim is 'B4 attribution == B3 attribution'. We
    assert exactly that — not an independent ~0.0 — because no tamper-evident-
    log module exists yet, so this exercises only the (unchanged) attribution
    path. Log-integrity behaviour is a separate metric to be tested when that
    module is built."""
    root = mint_initial_token("human:analyst", "siem:read siem:write")
    attack = mint_delegated_token(root, "agent:enrich", "siem:write",
                                  audience="siem_action")
    b3 = _score_one_action(attack, "isolate_host", "host-42", "agent:contain")
    b4 = _score_one_action(attack, "isolate_host", "host-42", "agent:contain")
    assert b4["ais"] == b3["ais"]                          # tamper-evidence is orthogonal
    assert b4["ais"] == 0.0
