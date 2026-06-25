"""
Pre-registration lock for the v3 threat model (threat-model-v3.md §10).

Recomputes the SHA-256 of each locked v3 file over LF-normalized bytes
(CRLF -> LF, so Windows and Unix checkouts hash identically) and compares
it to the recorded hash in the matching .sha256. Any drift fails the build.

WHY this test exists (not just what it does): v3's Tier-1 predictions (the
scripted B8/B9 cells: B8 = 1.0 honest / 0.0 colluding; B9 = 1.0 / 1.0) and
the source-lock receipts they rest on only mean something if they provably
predate the code that measures them. This lock is the proof. The originals
(threat-model-v3.md, source-lock-v3.md) are never edited; clarifications and
the Tier-2 LLM parameters go in versioned files (threat-model-v3.1.md, ...),
each with its own lock (threat-model-v3.md §10). This test guards every one,
so the amendment record is as tamper-evident as the original. Mirrors
v2/tests/test_threat_model_v2_locked.py.
"""

import hashlib
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
# v3 threat-model files live under Documents/ThreatModel/ThreatModelv3/ so
# they sit next to each other; v1's threat-model.md stays at the parent
# Documents/ThreatModel/ and v2's under ThreatModelv2/, each unchanged.
TM_DIR = REPO_ROOT / "Documents" / "ThreatModel" / "ThreatModelv3"

# Every locked v3 file: the v3.0 pre-registration, the source-lock receipts,
# and each future amendment. (markdown stem -> lock file). Add a row when a
# new amendment is locked (e.g. threat-model-v3.1.md for the Tier-2 LLM
# parameters); never remove or edit an existing one.
LOCKED = [
    ("threat-model-v3.md", "threat-model-v3.sha256"),
    ("source-lock-v3.md", "source-lock-v3.sha256"),
    # v3.0.1 amendment: B6 (mTLS, RFC 8705) / B7 (A-JWT) predictions, both
    # 1.0/1.0, additive over v3.0 (resolves §9 L11). Companion receipts locked too.
    ("threat-model-v3.0.1.md", "threat-model-v3.0.1.sha256"),
    ("source-lock-v3.0.1.md", "source-lock-v3.0.1.sha256"),
    # v3.1 amendment: Tier-2 LLM-ladder parameters (4 Groq models, prompts,
    # N/stopping rule, ε); 4-agent reviewed 2026-06-25. Companion receipts locked too.
    ("threat-model-v3.1.md", "threat-model-v3.1.sha256"),
    ("source-lock-v3.1.md", "source-lock-v3.1.sha256"),
]


def _lf_normalized_sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


@pytest.mark.parametrize("md_name,lock_name", LOCKED)
def test_threat_model_file_exists(md_name, lock_name):
    """threat-model-v3.md §10: each locked file and its lock must be present."""
    md = TM_DIR / md_name
    lock = TM_DIR / lock_name
    assert md.is_file(), f"missing pre-registration file: {md}"
    assert lock.is_file(), f"missing lock file: {lock}"


@pytest.mark.parametrize("md_name,lock_name", LOCKED)
def test_threat_model_hash_matches_lock(md_name, lock_name):
    """threat-model-v3.md §10: any edit to a locked file fails the build."""
    md = TM_DIR / md_name
    lock = TM_DIR / lock_name
    recorded = lock.read_text(encoding="utf-8").split()[0].strip().lower()
    actual = _lf_normalized_sha256(md)
    if actual != recorded:
        pytest.fail(
            f"{md_name} has drifted from its pre-registration lock.\n"
            f"  recorded: {recorded}\n"
            f"  actual:   {actual}\n"
            "Threat-model files are locked (threat-model-v3.md §10). To amend, "
            "add the next versioned file (threat-model-v3.1.md, ...) with its "
            "own lock — do not edit a locked file."
        )
