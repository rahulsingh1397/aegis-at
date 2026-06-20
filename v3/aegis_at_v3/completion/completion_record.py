"""
Completion-record primitive for AEGIS-AT v3 (threat-model-v3.md §5.1).

A *minimal benchmark abstraction* of the 2026 "completion block" — NOT a
byte-for-byte AIP/PEDIGREE schema (L14). The load-bearing property it models is
the one verified in source-lock-v3.md: the `self_reported` tier performs **no
independent verification of the asserted executor**. The exact field layout is
secondary; any spec with that property is in scope.

Two fields are deliberately DECOUPLED:
  - `attester_id`        — who SIGNED the record (proven by the signature)
  - `asserted_executor`  — who the record CLAIMS executed the action

A colluding executor can therefore sign a record (validly, with its OWN key)
whose `asserted_executor` names a *different* agent. `verify_signature` below
checks ONLY that `attester_id` signed the record; it does NOT enforce
`asserted_executor == attester_id`. That cross-check is itself an act of
independent verification — exactly what `self_reported` (B8) omits and what
`tool_verified` (B9, the process-boundary recorder) supplies. So the
signer-vs-claim gap is not a bug here: it IS the B8 -> B9 distinction
(threat-model-v3.md §5.1-§5.3).

Crypto: Ed25519 (matches HDP/AIP and v2's auth/dpop.py); signatures are
deterministic (RFC 8032), supporting the v3 determinism invariant (§8.6).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SELF_REPORTED = "self_reported"
TOOL_VERIFIED = "tool_verified"
VALID_SOURCES = frozenset({SELF_REPORTED, TOOL_VERIFIED})


@dataclass(frozen=True)
class CompletionRecord:
    """A signed completion record (the §5.1 benchmark abstraction).

    `signature` is the hex Ed25519 signature over the canonical bytes of the
    other four fields. Frozen so a record cannot be mutated after signing
    without re-verification detecting it.
    """

    action_id: str
    asserted_executor: str
    attestation_source: str
    attester_id: str
    signature: str  # hex


def _signing_payload(
    action_id: str,
    asserted_executor: str,
    attestation_source: str,
    attester_id: str,
) -> bytes:
    """Canonical bytes signed/verified — every field EXCEPT the signature.

    Deterministic serialization (sorted keys, no whitespace) so identical
    inputs always produce identical bytes (§8.6 determinism).
    """
    return json.dumps(
        {
            "action_id": action_id,
            "asserted_executor": asserted_executor,
            "attestation_source": attestation_source,
            "attester_id": attester_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_completion(
    action_id: str,
    asserted_executor: str,
    attestation_source: str,
    attester_id: str,
    private_key: Ed25519PrivateKey,
) -> CompletionRecord:
    """Build and sign a completion record under `attester_id`'s private key.

    Fail-loud on an unknown `attestation_source` (project convention: unknown
    values raise, never default). This does NOT check that
    `asserted_executor == attester_id` — see the module docstring; that omission
    is the self_reported behaviour, and the B8/B9 baselines decide whether to
    trust the self-report.
    """
    if attestation_source not in VALID_SOURCES:
        raise ValueError(
            f"unknown attestation_source {attestation_source!r}; "
            f"must be one of {sorted(VALID_SOURCES)}"
        )
    payload = _signing_payload(
        action_id, asserted_executor, attestation_source, attester_id
    )
    return CompletionRecord(
        action_id=action_id,
        asserted_executor=asserted_executor,
        attestation_source=attestation_source,
        attester_id=attester_id,
        signature=private_key.sign(payload).hex(),
    )


def verify_signature(record: CompletionRecord, public_key: Ed25519PublicKey) -> bool:
    """True iff `record` was signed by the holder of `public_key`.

    Verifies the SIGNATURE ONLY. It does NOT verify that
    `record.asserted_executor` is the true executor, nor that
    `asserted_executor == attester_id`. Establishing the true executor is the
    job of the independent process-boundary recorder (B9 / INV-4) — never this
    function and never the completion record itself.
    """
    payload = _signing_payload(
        record.action_id,
        record.asserted_executor,
        record.attestation_source,
        record.attester_id,
    )
    try:
        public_key.verify(bytes.fromhex(record.signature), payload)
        return True
    except (InvalidSignature, ValueError):
        return False
