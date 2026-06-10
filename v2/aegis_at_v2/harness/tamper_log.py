"""
harness/tamper_log.py — hash-chained tamper-evident log, threat-model-v2.md §6.

This makes Baseline 4 REAL. v1 shipped B4 as an attribution-only stub
(B4 == B3 by construction) and named the hash-chained module as future
work; this is that module.

Mechanism (§6.1): each appended entry carries
    prev_hash = SHA-256(canonical(entry) || prev_hash)
so any change to a committed entry breaks the chain from that point
forward. The chain HEAD (the latest hash) is signed by a dedicated logger
key held only by the parent harness process — no agent, the orchestrator,
or the tool holds it (same isolation pattern as the ground-truth recorder
and the replay cache). Post-hoc tampering is therefore detectable two
ways: the broken link, and a head signature that no longer matches.

What this does and does NOT do (§6.3): tamper-evidence protects the
integrity of the recorded entry; it does not change WHAT is recorded. The
wrong actor under B3/B4 is committed upstream at minting, before the log
sees the entry — so B4 AIS stays 0.0. This module measures a SEPARATE
quantity (LIS, §4.2): whether post-hoc rewrites are detected.

The genesis hash is a fixed constant so an empty-log head is well-defined
and deterministic.
"""

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

# Genesis: the prev_hash seed for the first entry. Fixed so the chain is
# deterministic and an empty log has a well-defined head.
GENESIS_HASH = "0" * 64


def _canonical(entry: dict) -> bytes:
    """Canonical, order-independent serialization of a log entry.

    Sorted keys + tight separators so the same logical entry always
    hashes identically regardless of dict insertion order. Records may
    contain lists (principal_chain); JSON handles those, and tuples are
    coerced to lists, so callers must not rely on tuple/list distinction
    inside an entry.
    """
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _link(entry: dict, prev_hash: str) -> str:
    """The chained hash for one entry: SHA-256(canonical(entry) || prev)."""
    h = hashlib.sha256()
    h.update(_canonical(entry))
    h.update(prev_hash.encode("ascii"))
    return h.hexdigest()


class TamperEvidentLog:
    """Append-only hash-chained log with a logger-signed head.

    The logger key is generated here and held only by the holder of this
    object (the parent harness). `entries` is the list of committed
    records; `hashes[i]` is the chained hash AFTER entry i.
    """

    def __init__(self, logger_key: Ed25519PrivateKey | None = None):
        self._logger_key = logger_key or Ed25519PrivateKey.generate()
        self.entries: list[dict] = []
        self.hashes: list[str] = []

    @property
    def head(self) -> str:
        """The latest chained hash (GENESIS_HASH when empty)."""
        return self.hashes[-1] if self.hashes else GENESIS_HASH

    def append(self, entry: dict) -> None:
        """Commit an entry, extending the chain from the current head."""
        new_hash = _link(entry, self.head)
        self.entries.append(entry)
        self.hashes.append(new_hash)

    def sign_head(self) -> bytes:
        """Sign the current head with the logger key (call after the run).

        The signature binds the entire chain: any rewrite changes the head,
        which invalidates this signature under the logger's public key.
        """
        return self._logger_key.sign(self.head.encode("ascii"))

    def public_key(self) -> Ed25519PublicKey:
        """The logger's public key, for independent head-signature checks."""
        return self._logger_key.public_key()

    def verify(self, head_signature: bytes | None = None) -> list[int]:
        """Recompute the chain and return the indices of broken entries.

        An entry index i is reported broken if recomputing the chain from
        entry 0 yields a hash at position i that differs from the stored
        hashes[i]. Because the chain is cumulative, a single in-place edit
        at index k breaks k and every entry after it; the FIRST broken
        index is the tamper site.

        If `head_signature` is supplied, the head signature is also
        verified; a bad signature with no broken link still flags the log
        as tampered by returning [len(entries)-1] (the head no longer
        attests the chain). An empty list means the log is intact.
        """
        broken: list[int] = []
        prev = GENESIS_HASH
        for i, entry in enumerate(self.entries):
            recomputed = _link(entry, prev)
            if i >= len(self.hashes) or recomputed != self.hashes[i]:
                broken.append(i)
            # Walk using the STORED hash so a single edit reports as one
            # broken link at its site, not a cascade (the stored chain is
            # what a verifier holds; we test each stored link against its
            # recomputed value).
            prev = self.hashes[i] if i < len(self.hashes) else recomputed

        if head_signature is not None and not broken:
            try:
                self.public_key().verify(head_signature, self.head.encode("ascii"))
            except InvalidSignature:
                if self.entries:
                    broken.append(len(self.entries) - 1)
        return broken
