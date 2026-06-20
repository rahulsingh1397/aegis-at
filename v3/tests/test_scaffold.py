"""
Scaffold smoke test (MASTER_PLAN_v3 P1): the v3 package exists and the
import-from-v2 reuse path resolves — pinning INV-6 (import v2, do not vendor).
"""


def test_v3_package_importable():
    import aegis_at_v3  # noqa: F401


def test_v2_reuse_path_importable():
    """v3 reuses v2's B1-B5 modules by import; the keystone reuse must resolve."""
    import aegis_at_v2  # noqa: F401
    from aegis_at_v2.harness import recorder  # becomes B9's tool_verified verifier

    assert hasattr(recorder, "__file__")