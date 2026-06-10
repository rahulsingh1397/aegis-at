"""
pytest path setup for AEGIS-AT v2.

Lets tests import aegis_at_v2 regardless of the working directory pytest
is invoked from. Anchors paths off this file's own location (which is
stable) rather than the cwd (which is not).
"""
import sys
import pathlib

V2_ROOT = pathlib.Path(__file__).parent.parent

sys.path.insert(0, str(V2_ROOT))
