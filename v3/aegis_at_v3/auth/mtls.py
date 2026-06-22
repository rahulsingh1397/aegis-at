"""auth/mtls.py — B6 mTLS certificate-bound evidence (RFC 8705).

The v3 cert-layer analog of v2's DPoP (B5, ``v2/aegis_at_v2/auth/dpop.py``): a
per-agent X.509 certificate whose RFC 8705 §3.1 ``x5t#S256`` thumbprint is bound
into the token's ``cnf`` and VERIFIED AT ACCESS. RFC 8705 §3 MANDATES that the
protected resource obtain the client certificate and "verify that the certificate
matches the certificate associated with the access token." Identity is then the
verified certificate's subject. A colluding executor cannot present ANOTHER
agent's certificate (cross-credential forgery is out of scope, threat-model-v3.md
§4.2), so the cert-verified identity tracks the true executor — B6 recovers
(predicted 1.0 / 1.0, threat-model-v3.0.1.md §A1).

A DETERMINISTIC MODEL, NOT a live TLS stack (threat-model-v3.0.1.md L20): the
prediction is for the MECHANISM graded by AEGIS-AT's own recorder. The cert is a
minimal self-signed X.509 cert over a FIXED validity epoch with a per-agent FIXED
Ed25519 key, so the DER bytes — and thus the ``x5t#S256`` thumbprint — are
byte-identical run-to-run (§8.6). The thumbprint is computed over the ACTUAL DER
certificate bytes, exactly as RFC 8705 §3.1 defines — NOT a JWK surrogate (the
4-agent P3 review's fidelity correction).

Primary sources (read at source, source-lock-v3.0.1.md §A5): RFC 8705 §1, §3, §3.1.
"""

from __future__ import annotations

import base64
import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

# Fixed cert validity + serial => deterministic DER (§8.6). Arbitrary but CONSTANT
# (a real CA uses live validity and a random serial); the value is irrelevant to
# the measurement, only its constancy matters for byte-identical reproduction.
_FIXED_NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
_VALIDITY = datetime.timedelta(days=3650)
_FIXED_SERIAL = 1

# Per-agent fixed key seeds (deterministic). Contain's seed MATCHES the
# adversary's completion-signing seed (``adversary._CONTAIN_KEY_SEED``) so
# "Contain's cert key" and "Contain's completion key" are the SAME agent's keys —
# one identity, two key uses. Enrich has its own seed; nothing in the v3 colluder
# model gives Contain access to Enrich's private key (§4.2).
_AGENT_KEY_SEEDS = {
    "agent:contain": bytes(range(32)),
    "agent:enrich": bytes(range(1, 33)),
}


class CertBindingError(Exception):
    """The presented certificate's ``x5t#S256`` does not match the token's bound
    ``cnf.x5t#S256`` (the RFC 8705 §3 at-access match check). Fail loud (Rule 12):
    a token bound to one cert cannot be wielded by the holder of another — the
    cert-layer analog of B5's DPoP lift rejection (dpop_v2.md)."""


class UnknownAgentError(Exception):
    """No registered cert key for the requested agent (no silent default)."""


def _agent_key(agent: str) -> Ed25519PrivateKey:
    if agent not in _AGENT_KEY_SEEDS:
        raise UnknownAgentError(f"no registered cert key for {agent!r}")
    return Ed25519PrivateKey.from_private_bytes(_AGENT_KEY_SEEDS[agent])


def agent_certificate_der(agent: str) -> bytes:
    """The agent's deterministic minimal self-signed X.509 certificate, DER-encoded.

    Subject CN = the agent name: the cert ASSERTS its subject and a (modelled) CA
    vouches for it, exactly as an mTLS client cert carries the client's identity.
    Deterministic: fixed key + fixed serial + fixed validity, Ed25519 signature
    (RFC 8032 deterministic) → byte-identical DER run-to-run (§8.6).
    """
    key = _agent_key(agent)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(_FIXED_SERIAL)
        .not_valid_before(_FIXED_NOT_BEFORE)
        .not_valid_after(_FIXED_NOT_BEFORE + _VALIDITY)
        .sign(key, None)  # Ed25519: algorithm is None (RFC 8032 deterministic sig)
    )
    return cert.public_bytes(serialization.Encoding.DER)


def x5t_s256(cert_der: bytes) -> str:
    """RFC 8705 §3.1: the base64url-encoded (no padding) SHA-256 hash of the DER
    X.509 certificate — the value carried in the token's ``cnf`` ``x5t#S256``
    member. Computed over the ACTUAL DER cert bytes, not a JWK (the fidelity fix)."""
    digest = hashlib.sha256(cert_der).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def token_cnf_for(executor: str) -> str:
    """The ``cnf.x5t#S256`` the orchestrator/IDP binds into the executor's token:
    bound to the EXECUTOR's OWN registered cert (the requester of the exchange),
    exactly as B5's DPoP binds ``cnf.jkt`` to the requester's key (dpop_v2.md). A
    colluder cannot obtain a token bound to a different agent's cert."""
    return x5t_s256(agent_certificate_der(executor))


def cert_subject_agent(cert_der: bytes) -> str:
    """The identity the resource derives from a verified certificate: its subject
    CN (the L20 ``verified cert -> executor`` mapping). RFC 8705 §3 mandates the
    cert/token match; mapping the verified cert to an identity is the deployment's
    instantiation of that mandate (threat-model-v3.0.1.md §A1 / L20)."""
    cert = x509.load_der_x509_certificate(cert_der)
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cns:
        raise UnknownAgentError("certificate has no subject CN")
    return str(cns[0].value)


def verify_cert_binding(presented_cert_der: bytes, bound_x5t_s256: str) -> str:
    """RFC 8705 §3 at-access check: the presented client cert MUST match the cert
    associated with the token (its ``cnf.x5t#S256``). Returns the verified subject
    identity on success; raises ``CertBindingError`` on mismatch (fail loud).

    This is the cert-layer sender-constraint: a token bound to Contain's cert
    cannot be exercised by presenting another cert, and the colluder cannot present
    another agent's cert (§4.2) — so the verified identity is the true executor.
    """
    presented = x5t_s256(presented_cert_der)
    if presented != bound_x5t_s256:
        raise CertBindingError(
            f"presented cert x5t#S256 {presented!r} != token cnf {bound_x5t_s256!r} "
            "(RFC 8705 §3 cert/token match failed)"
        )
    return cert_subject_agent(presented_cert_der)
