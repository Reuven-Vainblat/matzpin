"""Server-side envelope encryption and signing helpers."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from encryptor_common.errors import AuthenticationError, DecryptionError
from encryptor_common.protocol import MessageEnvelope, get_signed_bytes, serialize_aad

from .config import ServerConfig


def encrypt_and_sign(plaintext: bytes, envelope: MessageEnvelope, config: ServerConfig) -> MessageEnvelope:
    """Encrypt plaintext to the Pi and sign the resulting envelope.

    The input envelope should contain metadata and an empty `ciphertext` and
    `signature`. This function fills both fields.
    """

    pi_public_key = load_pi_x25519_public_key(config.pi_x25519_public_key_path)
    signing_key = load_signing_private_key(config.signing_private_key_path)
    sender_ephemeral_private = X25519PrivateKey.generate()
    sender_ephemeral_public = sender_ephemeral_private.public_key()
    nonce = os.urandom(12)

    envelope = MessageEnvelope(
        version=envelope.version,
        message_id=envelope.message_id,
        timestamp=envelope.timestamp,
        sender_id=envelope.sender_id,
        recipient_id=envelope.recipient_id,
        key_id=envelope.key_id,
        ephemeral_public_key=_b64(sender_ephemeral_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        nonce=_b64(nonce),
        ciphertext="",
        signature="",
        aad=envelope.aad,
    )
    key = derive_message_key(sender_ephemeral_private, pi_public_key, envelope, nonce)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, serialize_aad(envelope))
    unsigned = MessageEnvelope(**{**envelope.__dict__, "ciphertext": _b64(ciphertext)})
    signature = signing_key.sign(get_signed_bytes(unsigned))
    return MessageEnvelope(**{**unsigned.__dict__, "signature": _b64(signature)})


def load_pi_x25519_public_key(path: str) -> X25519PublicKey:
    """Load the Pi raw X25519 public key from disk."""

    key_path = Path(path)
    if not key_path.is_file():
        raise DecryptionError(f"Missing Pi X25519 public key: {path}")
    raw = key_path.read_bytes()
    if len(raw) != 32:
        raise DecryptionError("Pi X25519 public key must be 32 raw bytes")
    try:
        return X25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise DecryptionError("Invalid Pi X25519 public key") from exc


def load_signing_private_key(path: str) -> Ed25519PrivateKey:
    """Load the server Ed25519 private key used to sign envelopes."""

    key_path = Path(path)
    if not key_path.is_file():
        raise AuthenticationError(f"Missing signing private key: {path}")
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except ValueError as exc:
        raise AuthenticationError(f"Invalid signing private key: {path}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AuthenticationError("Signing private key must be Ed25519")
    return key


def derive_message_key(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
    envelope: MessageEnvelope,
    nonce: bytes,
) -> bytes:
    """Derive the AES-256-GCM key with X25519 and HKDF-SHA256."""

    shared_secret = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce,
        info=_kdf_info(envelope),
    ).derive(shared_secret)


def _kdf_info(envelope: MessageEnvelope) -> bytes:
    """Return the same HKDF context used by the Pi daemon."""

    return b"|".join(
        [
            b"encryptor-daemon",
            b"v1",
            b"x25519-hkdf-sha256-aes-256-gcm",
            envelope.sender_id.encode("utf-8"),
            envelope.recipient_id.encode("utf-8"),
            envelope.key_id.encode("utf-8"),
        ]
    )


def _b64(data: bytes) -> str:
    """Return base64url text for binary envelope fields."""

    return base64.urlsafe_b64encode(data).decode("ascii")

