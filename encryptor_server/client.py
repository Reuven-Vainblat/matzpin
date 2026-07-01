"""High-level server client API for sending plaintext to the Raspberry Pi."""

from __future__ import annotations

from datetime import UTC, datetime
import uuid

from encryptor_common.protocol import MessageEnvelope, serialize_envelope

from .config import ServerConfig
from .crypto import encrypt_and_sign
from .tls_client import send_envelope


def build_envelope(config: ServerConfig, aad: dict | None = None) -> MessageEnvelope:
    """Build the unsigned envelope metadata for one outbound message.

    Crypto fields are intentionally empty here. `encrypt_and_sign` fills the
    ephemeral X25519 public key, nonce, ciphertext, and signature.
    """

    return MessageEnvelope(
        version=1,
        message_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC).isoformat(),
        sender_id=config.sender_id,
        recipient_id=config.recipient_id,
        key_id=config.key_id,
        ephemeral_public_key="",
        nonce="",
        ciphertext="",
        signature="",
        aad=aad or {},
    )


def send_plaintext(plaintext: bytes, config: ServerConfig, aad: dict | None = None) -> bytes:
    """Encrypt, sign, frame, send one plaintext message, and return response."""

    envelope = build_envelope(config, aad=aad)
    secured = encrypt_and_sign(plaintext, envelope, config)
    return send_envelope(serialize_envelope(secured), config)
