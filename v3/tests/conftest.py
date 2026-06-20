"""
pytest path setup for AEGIS-AT v3.

Lets tests import aegis_at_v3 AND aegis_at_v2 regardless of the working
directory pytest is invoked from. v3 reuses v2's B1-B5 modules by importing
them (INV-6: byte-for-byte the v1/v2 path), so both package roots go on
sys.path. Anchored off this file's own location, not the cwd.
"""
import sys
import pathlib

V3_ROOT = pathlib.Path(__file__).parent.parent       # .../v3
V2_ROOT = V3_ROOT.parent / "v2"                       # .../v2 (sibling)

for root in (V3_ROOT, V2_ROOT):
    sys.path.insert(0, str(root))