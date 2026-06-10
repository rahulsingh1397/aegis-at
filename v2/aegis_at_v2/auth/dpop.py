"""
auth/dpop.py — DPoP sender-constraint (RFC 9449), threat-model-v2.md §5.

This is the Baseline 5 mechanism: the binding hypothesized in v1 §8.10 to
recover the attribution curve. It is the ONLY new cryptographic primitive
in v2.

What it provides:
  - per-agent proof-of-possession keypair (each agent's private key never
    leaves that agent);
  - a DPoP proof JWT (`htm`, `htu`, `iat`, `jti`) the agent signs at call
    time to prove possession of the key;
  - a JWK thumbprint (`jkt`, RFC 7638) that names the bound key; the
    access token carries `cnf: {"jkt": ...}` (RFC 7800);
  - server-side proof verification: signature under the proof's embedded
    public key, `jkt(proof key) == token.cnf.jkt`, `jti` replay rejection,
    `iat` freshness window.

Why this closes the v1 gap (§5.2): under B1-B4 Contain can present a token
minted naming Enrich because nothing binds the token to a holder. Under
B5 the token's `cnf.jkt` is Enrich's thumbprint; Contain cannot produce a
proof under Enrich's private key, so the lift is rejected and Contain must
obtain its own token — naming itself current actor. Claimed actor then
tracks the executor.

Keys here use Ed25519 for compact, deterministic signatures; RFC 9449
permits any JOSE-registered asymmetric algorithm.
"""

import hashlib
import json
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode

import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# Default proof freshness window (seconds). RFC 9449 §11.1 recommends a
# short window; 60 s matches the threat-model-v2.md §5.1 spec.
DEFAULT_PROOF_WINDOW_S = 60

# Endpoint identifiers a DPoP proof binds to (RFC 9449 htm/htu). A proof is
# scoped to one method+endpoint, so the proof presented to the tool differs
# from the proof presented to the orchestrator's token endpoint. Kept here
# (a child-safe leaf module) so agent subprocesses can import them without
# pulling in the RSA-key-generating auth.tokens module.
RESOURCE_HTM = "POST"
RESOURCE_HTU = "https://siem.local/siem_action"  # the tool endpoint
TOKEN_ENDPOINT_HTU = "https://orchestrator.local/token"  # the mint endpoint


class DPoPError(Exception):
    """Base class for all DPoP verification failures (fail loud, Rule 12)."""


class ProofSignatureError(DPoPError):
    """The proof's signature does not verify under its embedded key."""


class ProofBindingError(DPoPError):
    """jkt(proof key) does not match the token's cnf.jkt."""


class ProofReplayError(DPoPError):
    """The proof's jti has already been seen (replay)."""


class ProofStaleError(DPoPError):
    """The proof's iat is outside the freshness window."""


def _b64url_no_pad(raw: bytes) -> str:
    return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _public_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _jwk_for(pub: Ed25519PublicKey) -> dict:
    """The public JWK for an Ed25519 key (RFC 8037 OKP form)."""
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url_no_pad(_public_raw(pub)),
    }


def jkt_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK SHA-256 thumbprint, base64url (no padding).

    The thumbprint is computed over the REQUIRED members only, in
    lexicographic key order, with no whitespace — so it is canonical and
    independent of dict ordering.
    """
    canonical = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    serialized = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
    return _b64url_no_pad(hashlib.sha256(serialized.encode("utf-8")).digest())


class DPoPKey:
    """An agent's proof-of-possession keypair. The private key never
    leaves the holding agent; in v2's harness each agent owns one and the
    tool only ever sees public material (the embedded JWK in a proof)."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        self._private = private_key or Ed25519PrivateKey.generate()
        self._public = self._private.public_key()
        self.jwk = _jwk_for(self._public)
        self.jkt = jkt_thumbprint(self.jwk)

    @classmethod
    def from_private_pem(cls, pem: bytes) -> "DPoPKey":
        """Reconstruct a key from PKCS8 PEM bytes.

        Used to hand an agent its key across the process boundary: the
        DPoPKey OBJECT is not picklable (the underlying Ed25519 key holds
        a non-picklable handle), so the harness ships the PEM bytes as a
        spawn argument and the agent rebuilds the key in its own process.
        The bytes are provisioned by the harness BEFORE the agent's user
        code runs; the attacker (alert text, §3) never touches them.
        """
        priv = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise TypeError(f"expected Ed25519 private key, got {type(priv).__name__}")
        return cls(priv)

    @property
    def private_pem(self) -> bytes:
        """PKCS8 PEM of the private key (for provisioning a subprocess)."""
        return self._encode_key()

    def create_proof(
        self,
        htm: str,
        htu: str,
        now: float,
        jti: str | None = None,
    ) -> str:
        """Mint a DPoP proof JWT bound to (htm, htu) at time `now`.

        The proof embeds the public JWK in its header (RFC 9449 §4.2) so
        the verifier can check the signature and compute jkt without prior
        key distribution. `jti` defaults to a fresh UUID; tests may pin it
        to exercise replay rejection.
        """
        headers = {"typ": "dpop+jwt", "jwk": self.jwk}
        claims = {
            "htm": htm,
            "htu": htu,
            "iat": int(now),
            "jti": jti or uuid.uuid4().hex,
        }
        return jwt.encode(
            claims, self._encode_key(), algorithm="EdDSA", headers=headers
        )

    def _encode_key(self) -> bytes:
        return self._private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


class ReplayCache:
    """Bounded jti replay cache, held in the parent harness process (no
    agent or the orchestrator holds it). A jti is single-use within the
    proof window; seeing it twice is a replay (§5.4)."""

    def __init__(self):
        self._seen: set[str] = set()

    def check_and_add(self, jti: str) -> None:
        if jti in self._seen:
            raise ProofReplayError(f"jti already seen (replay): {jti!r}")
        self._seen.add(jti)


def verify_proof(
    proof: str,
    expected_htm: str,
    expected_htu: str,
    bound_jkt: str,
    now: float,
    replay_cache: ReplayCache,
    window_s: int = DEFAULT_PROOF_WINDOW_S,
) -> str:
    """Verify a DPoP proof against the token's binding. Returns the
    proof's jkt on success; raises a DPoPError subclass on any failure.

    Checks, in order (threat-model-v2.md §5.1):
      1. signature verifies under the proof's embedded JWK;
      2. htm/htu match the request;
      3. jkt(proof key) == bound_jkt (the token's cnf.jkt);
      4. iat within [now - window, now + window];
      5. jti not previously seen (then recorded).

    The window is symmetric to tolerate small clock skew on both sides;
    the harness uses a fixed clock so the window is effectively exact.
    """
    # 1. Recover the embedded JWK from the unverified header, then verify
    #    the signature under exactly that key (RFC 9449 §4.3 step: the
    #    proof is self-attesting — the key proves possession, the cnf
    #    binding is what ties it to the granted token).
    header = jwt.get_unverified_header(proof)
    if header.get("typ") != "dpop+jwt" or "jwk" not in header:
        raise ProofSignatureError("proof missing dpop+jwt typ or embedded jwk")
    jwk = header["jwk"]
    try:
        pub = Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))
        pub_pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        claims = jwt.decode(proof, pub_pem, algorithms=["EdDSA"])
    except Exception as e:
        raise ProofSignatureError(f"proof signature invalid: {e!r}") from e

    # 2. htm/htu binding.
    if claims.get("htm") != expected_htm or claims.get("htu") != expected_htu:
        raise ProofBindingError(
            f"proof htm/htu {claims.get('htm')!r}/{claims.get('htu')!r} != "
            f"expected {expected_htm!r}/{expected_htu!r}"
        )

    # 3. Possession binding: the proof key must be the token's bound key.
    proof_jkt = jkt_thumbprint(jwk)
    if proof_jkt != bound_jkt:
        raise ProofBindingError(
            f"proof key thumbprint {proof_jkt!r} != token cnf.jkt {bound_jkt!r} "
            "(token presented by an agent other than the bound holder)"
        )

    # 4. Freshness.
    iat = claims.get("iat")
    if iat is None or abs(int(now) - int(iat)) > window_s:
        raise ProofStaleError(
            f"proof iat {iat!r} outside ±{window_s}s window around {int(now)}"
        )

    # 5. Replay.
    replay_cache.check_and_add(claims["jti"])

    return proof_jkt


def _b64url_decode(s: str) -> bytes:
    """Decode base64url without padding (JWK members omit padding)."""
    pad = "=" * (-len(s) % 4)
    return urlsafe_b64decode(s + pad)
