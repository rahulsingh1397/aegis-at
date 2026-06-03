"""
pytest path setup for AEGIS-AT.

Lets tests import from aegis-at/auth/, aegis-at/policy/, etc. regardless
of the working directory pytest is invoked from. Anchors paths off this
file's own location (which is stable) rather than the cwd (which is not).
"""
import sys
import pathlib

REPO_ROOT = pathlib.Path(__file__).parent.parent
AEGIS = REPO_ROOT / "aegis-at"

for subdir in ("auth", "policy","tools","harness"):
    sys.path.insert(0, str(AEGIS / subdir))