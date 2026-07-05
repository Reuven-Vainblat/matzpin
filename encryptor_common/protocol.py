"""Shared encrypted-message envelope format."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MessageEnvelope:
    """Encrypted application message plus metadata required for validation."""

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
    aad: dict[str, Any] = field(default_factory=dict)


def parse_envelope(raw: bytes) -> MessageEnvelope:
    """Parse UTF-8 JSON bytes into a ``MessageEnvelope``.

    TODO: decode JSON, validate fields, and normalize errors.
    """

    raise NotImplementedError


def serialize_envelope(envelope: MessageEnvelope) -> bytes:
    """Serialize an envelope as deterministic UTF-8 JSON bytes."""

    raise NotImplementedError


def get_signed_bytes(envelope: MessageEnvelope) -> bytes:
    """Return canonical bytes covered by the Ed25519 signature."""

    raise NotImplementedError


def serialize_aad(envelope: MessageEnvelope) -> bytes:
    """Return canonical bytes used as AES-GCM associated data."""

    raise NotImplementedError
