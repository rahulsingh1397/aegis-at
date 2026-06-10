"""
Pre-registration lock for the v2 threat model (threat-model-v2.md §10).

Recomputes the SHA-256 of Documents/ThreatModel/threat-model-v2.md over
LF-normalized bytes (CRLF -> LF, so Windows and Unix checkouts hash
identically) and compares it to the recorded hash in
threat-model-v2.sha256. Any drift fails the build.

WHY this test exists (not just what it does): v2's predictions (B5 AIS,
B4 LIS, T2 curve, CI cells) only mean something if they provably predate
the code that measures them. This lock is the proof. To amend a
prediction, add threat-model-v2.1.md with its own lock — never edit the
locked file (INV-7).
"""

import hashlib
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
TM_DIR = REPO_ROOT / "Documents" / "ThreatModel"
TM_FILE = TM_DIR / "threat-model-v2.md"
LOCK_FILE = TM_DIR / "threat-model-v2.sha256"


def _lf_normalized_sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def test_threat_model_v2_exists():
    """threat-model-v2.md §10: the locked file must be present."""
    assert TM_FILE.is_file(), f"missing pre-registration file: {TM_FILE}"
    assert LOCK_FILE.is_file(), f"missing lock file: {LOCK_FILE}"


def test_threat_model_v2_hash_matches_lock():
    """threat-model-v2.md §10: any edit to the locked file fails the build."""
    recorded = LOCK_FILE.read_text(encoding="utf-8").split()[0].strip().lower()
    actual = _lf_normalized_sha256(TM_FILE)
    if actual != recorded:
        pytest.fail(
            "threat-model-v2.md has drifted from its pre-registration lock.\n"
            f"  recorded: {recorded}\n"
            f"  actual:   {actual}\n"
            "Predictions are locked (threat-model-v2.md §10). To amend, add "
            "threat-model-v2.1.md with its own lock — do not edit the "
            "locked file."
        )
