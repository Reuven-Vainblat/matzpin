"""Validation helpers for Pi-side envelope metadata and plaintext."""

from __future__ import annotations

from datetime import UTC, datetime

from encryptor_common.errors import ProtocolError
from encryptor_common.protocol import MessageEnvelope

from .config import PiConfig

SUPPORTED_VERSION = 1


def validate_envelope_metadata(envelope: MessageEnvelope, config: PiConfig) -> None:
    """Run non-cryptographic envelope validation checks."""

    validate_version(envelope)
    validate_recipient(envelope, config.expected_recipient_id)
    validate_timestamp(envelope, config.max_clock_skew_seconds)


def validate_version(envelope: MessageEnvelope) -> None:
    """Ensure the envelope version is supported by this daemon."""

    if envelope.version != SUPPORTED_VERSION:
        raise ProtocolError(f"Unsupported envelope version: {envelope.version}")


def validate_recipient(envelope: MessageEnvelope, expected_recipient_id: str) -> None:
    """Ensure this Pi is the intended recipient."""

    if envelope.recipient_id != expected_recipient_id:
        raise ProtocolError("Message recipient does not match this daemon")


def validate_timestamp(envelope: MessageEnvelope, max_clock_skew_seconds: int) -> None:
    """Reject messages whose ISO-8601 timestamp is too far from local time."""

    try:
        timestamp = datetime.fromisoformat(envelope.timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("Invalid message timestamp") from exc

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)

    skew = abs((datetime.now(UTC) - timestamp.astimezone(UTC)).total_seconds())
    if skew > max_clock_skew_seconds:
        raise ProtocolError("Message timestamp is outside allowed clock skew")


def validate_plaintext(plaintext: bytes) -> None:
    """Perform basic sanity checks before forwarding plaintext."""

    if not plaintext:
        raise ProtocolError("Plaintext payload is empty")

