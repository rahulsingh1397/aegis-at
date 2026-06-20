"""
Completion-record primitive tests (threat-model-v3.md §5.1).

These encode WHY the abstraction is shaped this way (Rule 9), especially the
load-bearing property that a VALID signature does NOT imply `asserted_executor`
is true — exactly why B8 (self_reported) fails under a colluding executor while
B9 (independent recorder) does not.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_at_v3.completion.completion_record import (
    SELF_REPORTED,
    TOOL_VERIFIED,
    CompletionRecord,
    sign_completion,
    verify_signature,
)


def _keypair():
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key()


def test_honest_record_roundtrips():
    """An honest self-report (asserted_executor == signer) verifies."""
    sk, pk = _keypair()
    rec = sign_completion("a1", "agent:contain", SELF_REPORTED, "agent:contain", sk)
    assert verify_signature(rec, pk) is True


def test_signature_is_key_bound():
    """A record does not verify under a different agent's key."""
    sk, _ = _keypair()
    _, other_pk = _keypair()
    rec = sign_completion("a1", "agent:contain", SELF_REPORTED, "agent:contain", sk)
    assert verify_signature(rec, other_pk) is False


def test_tamper_breaks_signature():
    """Editing any signed field after signing fails verification."""
    sk, pk = _keypair()
    rec = sign_completion("a1", "agent:contain", SELF_REPORTED, "agent:contain", sk)
    tampered = CompletionRecord(
        action_id=rec.action_id,
        asserted_executor="agent:enrich",  # changed after signing
        attestation_source=rec.attestation_source,
        attester_id=rec.attester_id,
        signature=rec.signature,
    )
    assert verify_signature(tampered, pk) is False


def test_colluding_record_has_a_valid_signature():
    """THE load-bearing test (§5.1): a colluder signs, with its OWN key, a
    record naming a DIFFERENT executor — and the signature is valid.

    Contain signs but asserts asserted_executor='agent:enrich'. The signature
    verifies under Contain's key, yet asserted_executor != attester_id. This is
    precisely why a self_reported audit (B8) records the wrong actor while every
    cryptographic check passes; only an independent verifier (B9) catches it.
    verify_signature MUST NOT conflate the two.
    """
    sk, pk = _keypair()  # Contain's keypair
    rec = sign_completion("a1", "agent:enrich", SELF_REPORTED, "agent:contain", sk)
    assert verify_signature(rec, pk) is True  # signature is valid...
    assert rec.asserted_executor != rec.attester_id  # ...yet the claim is false


def test_unknown_attestation_source_fails_loud():
    """Unknown attestation_source raises (fail-loud; no silent default)."""
    sk, _ = _keypair()
    with pytest.raises(ValueError, match="unknown attestation_source"):
        sign_completion("a1", "agent:contain", "made_up_tier", "agent:contain", sk)


def test_signing_is_deterministic():
    """Ed25519 is deterministic: identical inputs -> identical signature
    (supports the §8.6 determinism invariant)."""
    sk, _ = _keypair()
    r1 = sign_completion("a1", "agent:contain", TOOL_VERIFIED, "agent:contain", sk)
    r2 = sign_completion("a1", "agent:contain", TOOL_VERIFIED, "agent:contain", sk)
    assert r1.signature == r2.signature
