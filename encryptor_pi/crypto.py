"""Pi-side message authentication and decryption."""

from __future__ import annotations

from typing import Any

from encryptor_common.protocol import MessageEnvelope

from .config import PiConfig


def verify_signature(envelope: MessageEnvelope, config: PiConfig) -> None:
    """Verify the envelope's Ed25519 signature with a trusted sender key."""

    raise NotImplementedError


def decrypt_payload(envelope: MessageEnvelope, config: PiConfig) -> bytes:
    """Derive the AES key with X25519/HKDF and decrypt the payload."""

    raise NotImplementedError


def load_x25519_private_key(path: str) -> Any:
    """Load the Pi X25519 private key."""

    raise NotImplementedError


def load_public_key_for_sender(sender_id: str, key_id: str, config: PiConfig) -> Any:
    """Load the sender Ed25519 public key."""

    raise NotImplementedError
