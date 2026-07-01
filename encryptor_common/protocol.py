"""Message envelope parsing and canonical serialization.

The project uses JSON envelopes for readability in a cyber classroom setting.
Security-critical operations use canonical JSON bytes, not Python object
representations, so sender and receiver can reproduce the exact bytes for
signatures and authenticated data.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any

from .errors import ProtocolError


@dataclass(frozen=True)
class MessageEnvelope:
    """Encrypted application message plus metadata required for validation.

    `ephemeral_public_key` is the sender's per-message X25519 public key,
    encoded as base64url raw 32-byte key material. `nonce`, `ciphertext`, and
    `signature` are also base64url encoded for JSON transport.
    """

    version: int
    message_id: str
    timestamp: str
    sender_id: str
    recipient_id: str
    key_id: str
    ephemeral_public_key: str
    nonce: str
    ciphertext: str
    signature: str
    aad: dict[str, Any]


def parse_envelope(raw: bytes) -> MessageEnvelope:
    """Parse a UTF-8 JSON message into a `MessageEnvelope`.

    Raises:
        ProtocolError: If the bytes are not valid UTF-8 JSON or do not contain
            the fields required by `MessageEnvelope`.
    """

    try:
        payload = json.loads(raw.decode("utf-8"))
        return MessageEnvelope(**payload)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise ProtocolError("Invalid message envelope") from exc


def serialize_envelope(envelope: MessageEnvelope) -> bytes:
    """Serialize an envelope as deterministic UTF-8 JSON bytes."""

    return _canonical_json(asdict(envelope))


def get_signed_bytes(envelope: MessageEnvelope) -> bytes:
    """Return deterministic bytes covered by the Ed25519 signature.

    The signature field itself is excluded to avoid circular signing.
    """

    payload = asdict(envelope)
    payload.pop("signature", None)
    return _canonical_json(payload)


def serialize_aad(envelope: MessageEnvelope) -> bytes:
    """Serialize authenticated metadata for AES-GCM verification.

    AES-GCM authenticates these bytes even though it does not encrypt them.
    Binding identity and routing metadata here prevents a valid ciphertext from
    being replayed under a different sender, recipient, key id, or ephemeral
    X25519 public key.
    """

    return _canonical_json(
        {
            "version": envelope.version,
            "message_id": envelope.message_id,
            "timestamp": envelope.timestamp,
            "sender_id": envelope.sender_id,
            "recipient_id": envelope.recipient_id,
            "key_id": envelope.key_id,
            "ephemeral_public_key": envelope.ephemeral_public_key,
            "aad": envelope.aad,
        }
    )


def _canonical_json(payload: dict[str, Any]) -> bytes:
    """Encode JSON with stable key ordering and compact separators."""

    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
