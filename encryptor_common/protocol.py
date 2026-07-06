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

REQUIRED_ENVELOPE_FIELDS = {
    "version",
    "message_id",
    "timestamp",
    "sender_id",
    "recipient_id",
    "key_id",
    "ephemeral_public_key",
    "nonce",
    "ciphertext",
    "signature",
    "aad",
}
MAX_ID_LENGTH = 128
MAX_KEY_ID_LENGTH = 64
MAX_TIMESTAMP_LENGTH = 64
MAX_SMALL_B64_LENGTH = 128
MAX_CIPHERTEXT_LENGTH = 1_400_000
MAX_AAD_JSON_LENGTH = 8_192


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
        _validate_envelope_payload(payload)
        return MessageEnvelope(**payload)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
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


def _validate_envelope_payload(payload: Any) -> None:
    """Validate envelope shape and field sizes before constructing a dataclass."""

    if not isinstance(payload, dict):
        raise ValueError("Envelope must be a JSON object")

    fields = set(payload)
    if fields != REQUIRED_ENVELOPE_FIELDS:
        missing = REQUIRED_ENVELOPE_FIELDS - fields
        extra = fields - REQUIRED_ENVELOPE_FIELDS
        raise ValueError(f"Envelope fields mismatch; missing={missing}, extra={extra}")

    if not isinstance(payload["version"], int) or isinstance(payload["version"], bool):
        raise ValueError("Envelope version must be an integer")

    _require_string(payload, "message_id", MAX_ID_LENGTH)
    _require_string(payload, "timestamp", MAX_TIMESTAMP_LENGTH)
    _require_string(payload, "sender_id", MAX_ID_LENGTH)
    _require_string(payload, "recipient_id", MAX_ID_LENGTH)
    _require_string(payload, "key_id", MAX_KEY_ID_LENGTH)
    _require_string(payload, "ephemeral_public_key", MAX_SMALL_B64_LENGTH)
    _require_string(payload, "nonce", MAX_SMALL_B64_LENGTH)
    _require_string(payload, "ciphertext", MAX_CIPHERTEXT_LENGTH)
    _require_string(payload, "signature", MAX_SMALL_B64_LENGTH)

    aad = payload["aad"]
    if not isinstance(aad, dict):
        raise ValueError("Envelope aad must be an object")
    try:
        aad_json = _canonical_json(aad)
    except (TypeError, ValueError) as exc:
        raise ValueError("Envelope aad must be JSON serializable") from exc
    if len(aad_json) > MAX_AAD_JSON_LENGTH:
        raise ValueError("Envelope aad is too large")


def _require_string(payload: dict[str, Any], key: str, max_length: int) -> None:
    value = payload[key]
    if not isinstance(value, str):
        raise ValueError(f"Envelope {key} must be a string")
    if not value:
        raise ValueError(f"Envelope {key} must not be empty")
    if len(value) > max_length:
        raise ValueError(f"Envelope {key} is too long")
