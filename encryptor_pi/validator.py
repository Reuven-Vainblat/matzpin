"""Pi-side non-cryptographic validation helpers."""

from __future__ import annotations

from encryptor_common.protocol import MessageEnvelope

from .config import PiConfig


def validate_envelope_metadata(envelope: MessageEnvelope, config: PiConfig) -> None:
    """Validate version, recipient, and timestamp metadata."""

    raise NotImplementedError


def validate_version(envelope: MessageEnvelope) -> None:
    """Ensure the envelope version is supported by this daemon."""

    raise NotImplementedError


def validate_recipient(envelope: MessageEnvelope, expected_recipient_id: str) -> None:
    """Ensure this Pi is the intended recipient."""

    raise NotImplementedError


def validate_timestamp(envelope: MessageEnvelope, max_clock_skew_seconds: int) -> None:
    """Reject messages whose timestamp is too far from local time."""

    raise NotImplementedError


def validate_plaintext(plaintext: bytes) -> None:
    """Perform sanity checks before forwarding plaintext."""

    raise NotImplementedError
