"""completion/execution_assertion.py — B7 A-JWT execution assertion
(draft-goswami-agentic-jwt-00 / arXiv:2509.13597).

The v3 model of A-JWT's VERIFIED execution attribution. The executing agent emits a
signed ``ExecutionAssertion`` (``executed_by`` + a per-agent proof-of-possession
key) that the Resource Server verifies AT EXECUTION (A-JWT Anchor A6). The verifier
checks the signature against the public key REGISTERED for the named agent — so a
colluder cannot produce a *verifiable* assertion naming a DIFFERENT agent: it lacks
that agent's private key (§4.2). A-JWT's own T1 (impersonation by copying code for
an identical checksum) is defeated here by **A6 (PoP) + A3**, NOT by the checksum
(threat-model-v3.0.1.md §A2). So ``executed_by`` is VERIFIED, not self-asserted,
and B7 recovers (predicted 1.0 / 1.0, §A2).

**A3 (no in-process cross-agent impersonation) is provided in AEGIS-AT by the OS
PROCESS BOUNDARY** — the v2 kernel's PID registry (INV-4). Agents run as separate
processes, so one cannot impersonate another in-process; the assertion is produced
inside the executor's own process. This is a STRONGER independence anchor than
A-JWT's in-process software shim (threat-model-v3.0.1.md §A2 caveat 2).

A DETERMINISTIC MODEL, not a live A-JWT shim/TEE (L21): Ed25519 PoP (matches
``v2/aegis_at_v2/auth/dpop.py`` and A-JWT's per-agent keys), deterministic
signatures (RFC 8032), fixed per-agent key seeds → byte-identical assertions
run-to-run (§8.6).

Sources (read at source, source-lock-v3.0.1.md §A6): A-JWT abstract; §5 Anchors
A3/A6; §3 ``executed_by`` / ``cnf``; §4 threats T7/T10/T11.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Per-agent PoP key seeds (deterministic). A-JWT's PoP key is a per-agent ephemeral
# key registered at the IDP — DISTINCT from B6's cert key and the completion key
# (an agent holds several keys for several purposes). Fixed seeds → deterministic
# Ed25519 signatures (§8.6). The colluder (Contain) cannot obtain Enrich's PoP
# private key (cross-key forgery is out of scope, §4.2).
_POP_KEY_SEEDS = {
    "agent:contain": bytes(range(64, 96)),
    "agent:enrich": bytes(range(96, 128)),
}


class AssertionVerificationError(Exception):
    """The execution assertion's signature does not verify under the PoP key
    REGISTERED for its ``executed_by`` agent (A-JWT A6 at-execution check). Fail
    loud (Rule 12): a colluder signing ``executed_by = Enrich`` with Contain's own
    key is rejected here — it cannot sign as Enrich (§4.2). This is the active
    rejection of the cross-agent attribution attempt."""


class UnknownAgentError(Exception):
    """No registered PoP key for the agent (no silent default)."""


def _pop_key(agent: str) -> Ed25519PrivateKey:
    if agent not in _POP_KEY_SEEDS:
        raise UnknownAgentError(f"no registered PoP key for {agent!r}")
    return Ed25519PrivateKey.from_private_bytes(_POP_KEY_SEEDS[agent])


def registered_pop_public_key(agent: str) -> Ed25519PublicKey:
    """The PoP public key the IDP registered for ``agent`` — what the Resource
    Server verifies an assertion's signature against (A-JWT A6)."""
    return _pop_key(agent).public_key()


@dataclass(frozen=True)
class ExecutionAssertion:
    """A signed A-JWT-style execution assertion: "agent ``executed_by`` ran
    ``action_id``", signed by the SIGNER's PoP key. Frozen so it cannot be mutated
    after signing without verification detecting it. Separate from
    ``CompletionRecord`` — B7 is an orthogonal, verified-at-execution axis, and the
    locked completion schema stays untouched (the 4-agent review's requirement)."""

    action_id: str
    executed_by: str
    signature: str  # hex


def _assertion_payload(action_id: str, executed_by: str) -> bytes:
    """Canonical signed bytes — deterministic serialization (sorted keys, no
    whitespace) so identical inputs produce identical bytes (§8.6)."""
    return json.dumps(
        {"action_id": action_id, "executed_by": executed_by},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_execution_assertion(
    action_id: str, executed_by: str, signing_agent: str
) -> ExecutionAssertion:
    """The executor signs "``executed_by`` ran ``action_id``" with
    ``signing_agent``'s PoP key.

    Honest: ``signing_agent == executed_by`` → verifies. A colluder may set
    ``executed_by = Enrich`` but can only sign with its OWN key
    (``signing_agent = Contain``); that assertion will NOT verify against Enrich's
    registered key (§4.2) — see ``verify_execution_assertion``. The signer cannot
    obtain another agent's PoP private key, so it cannot mint a verifiable
    cross-agent assertion."""
    payload = _assertion_payload(action_id, executed_by)
    return ExecutionAssertion(
        action_id=action_id,
        executed_by=executed_by,
        signature=_pop_key(signing_agent).sign(payload).hex(),
    )


def verify_execution_assertion(assertion: ExecutionAssertion) -> str:
    """A-JWT A6 at-execution check: verify the signature against the PoP key
    REGISTERED for ``assertion.executed_by``. Returns ``executed_by`` on success;
    raises ``AssertionVerificationError`` on failure.

    The named agent must hold the key that signed — so a colluder cannot assert a
    DIFFERENT agent (it would have to sign with that agent's key, which it does not
    hold, §4.2). This is what makes ``executed_by`` verified rather than
    self-asserted, and it is independent of the recorder (INV-4): B7 reads THIS, not
    ground truth, so it does not collapse into B9."""
    public_key = registered_pop_public_key(assertion.executed_by)
    payload = _assertion_payload(assertion.action_id, assertion.executed_by)
    try:
        public_key.verify(bytes.fromhex(assertion.signature), payload)
    except (InvalidSignature, ValueError) as exc:
        raise AssertionVerificationError(
            f"execution assertion for action {assertion.action_id!r} naming "
            f"{assertion.executed_by!r} does not verify under that agent's "
            "registered PoP key (A-JWT A6; a cross-agent assertion is rejected)"
        ) from exc
    return assertion.executed_by
