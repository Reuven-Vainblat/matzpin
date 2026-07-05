"""Server-side message encryption and signing."""

from __future__ import annotations

from typing import Any

from encryptor_common.protocol import MessageEnvelope

from .config import ServerConfig


def encrypt_for_pi(envelope: MessageEnvelope, plaintext: bytes, config: ServerConfig) -> MessageEnvelope:
    """Encrypt plaintext to the Pi and sign the final envelope."""

    raise NotImplementedError


def load_pi_x25519_public_key(path: str) -> Any:
    """Load the Pi raw X25519 public key from disk."""

    raise NotImplementedError


def load_signing_private_key(path: str) -> Any:
    """Load the server Ed25519 private signing key."""

    raise NotImplementedError
