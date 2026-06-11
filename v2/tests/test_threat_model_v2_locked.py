"""
Pre-registration lock for the v2 threat model (threat-model-v2.md §10).

Recomputes the SHA-256 of each locked threat-model file over LF-normalized
bytes (CRLF -> LF, so Windows and Unix checkouts hash identically) and
compares it to the recorded hash in the matching .sha256. Any drift fails
the build.

WHY this test exists (not just what it does): v2's predictions (B5 AIS,
B4 LIS, T2 curve, CI cells) only mean something if they provably predate
the code that measures them. This lock is the proof. The original
threat-model-v2.md is never edited; clarifications and amendments go in
versioned files (threat-model-v2.1.md, ...), each with its own lock
(threat-model-v2.md §10). This test guards every one of them, so the
amendment record is as tamper-evident as the original.
"""

import hashlib
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
# v2 threat-model files live under Documents/ThreatModel/ThreatModelv2/ so
# they sit next to each other; v1's threat-model.md stays at the parent
# Documents/ThreatModel/ unchanged.
TM_DIR = REPO_ROOT / "Documents" / "ThreatModel" / "ThreatModelv2"

# Every locked threat-model file: the v2.0 pre-registration and each
# amendment. (markdown stem -> lock file). Add a row when a new amendment
# is locked; never remove or edit an existing one.
LOCKED = [
    ("threat-model-v2.md", "threat-model-v2.sha256"),
    ("threat-model-v2.1.md", "threat-model-v2.1.sha256"),
]


def _lf_normalized_sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


@pytest.mark.parametrize("md_name,lock_name", LOCKED)
def test_threat_model_file_exists(md_name, lock_name):
    """threat-model-v2.md §10: each locked file and its lock must be present."""
    md = TM_DIR / md_name
    lock = TM_DIR / lock_name
    assert md.is_file(), f"missing pre-registration file: {md}"
    assert lock.is_file(), f"missing lock file: {lock}"


@pytest.mark.parametrize("md_name,lock_name", LOCKED)
def test_threat_model_hash_matches_lock(md_name, lock_name):
    """threat-model-v2.md §10: any edit to a locked file fails the build."""
    md = TM_DIR / md_name
    lock = TM_DIR / lock_name
    recorded = lock.read_text(encoding="utf-8").split()[0].strip().lower()
    actual = _lf_normalized_sha256(md)
    if actual != recorded:
        pytest.fail(
            f"{md_name} has drifted from its pre-registration lock.\n"
            f"  recorded: {recorded}\n"
            f"  actual:   {actual}\n"
            "Threat-model files are locked (threat-model-v2.md §10). To amend, "
            "add the next versioned file (threat-model-v2.2.md, ...) with its "
            "own lock — do not edit a locked file."
        )
