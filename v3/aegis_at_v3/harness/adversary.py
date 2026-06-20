"""
harness/adversary.py — the adversary adapter (the agent in the "liar seat"),
threat-model-v3.md §3.2 / §4.2a.

v3 expands the adversary model with ONE pre-registered capability: a colluding
executor that emits a false self-reported completion WITHIN ITS OWN KEY (§4.2).
This module produces the signed completion record for each adversary realization
("seat"). Tier-1 (v3.0) is SCRIPTED and injected PARENT-SIDE — the same
construction as v2's token-lift/replay stimuli (threat-model-v2.md §2) — so the
attacker is deterministic and INV-5 holds: the colluding executor is the
adversary's locus, not a miscoded component.

Slice A (this commit) ships the HONEST seat ONLY. The load-bearing checkpoint
(§7.5) must be green before any colluder code exists; the `colluding` seat lands
in Slice B.

Determinism (§8.6): Contain signs under a FIXED Ed25519 key (constant seed), and
Ed25519 is deterministic (RFC 8032), so a completion record is byte-identical
run-to-run under a fixed clock.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aegis_at_v3.completion.completion_record import CompletionRecord, sign_completion

# The true executor and the attester. Contain runs the action and signs the
# completion with its OWN key. (The colluder in Slice B keeps attester_id ==
# Contain while naming a DIFFERENT asserted_executor — a valid signature, a
# false claim; that is the whole capability, §4.2.)
CONTAIN = "agent:contain"

# Fixed seed -> fixed Contain signing key (§8.6 determinism). The value is
# arbitrary but CONSTANT so signatures reproduce byte-for-byte across runs.
_CONTAIN_KEY_SEED = bytes(range(32))


def contain_private_key() -> Ed25519PrivateKey:
    """Contain's fixed Ed25519 signing key (deterministic; §8.6)."""
    return Ed25519PrivateKey.from_private_bytes(_CONTAIN_KEY_SEED)


def contain_public_key() -> Ed25519PublicKey:
    """Contain's public key — what the audit verifies a completion under."""
    return contain_private_key().public_key()


def honest_completion(attestation_source: str, action_id: str) -> CompletionRecord:
    """script-honest (§3.2): a truthful completion naming the TRUE executor.

    asserted_executor == attester_id == Contain — the signature is valid AND the
    claim is true, so an honest B8 records the true executor (AIS = 1.0, §8.1).
    """
    return sign_completion(
        action_id=action_id,
        asserted_executor=CONTAIN,
        attestation_source=attestation_source,
        attester_id=CONTAIN,
        private_key=contain_private_key(),
    )


def make_completion(
    seat: str, attestation_source: str, action_id: str
) -> CompletionRecord:
    """Produce the completion for one adversary `seat`.

    Slice A implements `honest` only; `colluding` lands in Slice B. An unknown
    seat fails loud (project convention: no silent default).
    """
    if seat == "honest":
        return honest_completion(attestation_source, action_id)
    raise ValueError(
        f"unknown adversary seat {seat!r}; Slice A ships 'honest' only "
        "(colluding lands in Slice B)"
    )
