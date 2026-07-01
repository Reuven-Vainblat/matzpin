"""Raspberry Pi message verification and decryption helpers."""

from __future__ import annotations

import base64
import binascii
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from encryptor_common.errors import AuthenticationError, DecryptionError
from encryptor_common.protocol import MessageEnvelope, get_signed_bytes, serialize_aad

from .config import PiConfig


def verify_signature(envelope: MessageEnvelope, config: PiConfig) -> None:
    """Verify the envelope's Ed25519 signature with the trusted sender key."""

    public_key = load_public_key_for_sender(envelope.sender_id, envelope.key_id, config)
    signature = _decode_b64(envelope.signature, AuthenticationError, "Invalid signature encoding")
    try:
        public_key.verify(signature, get_signed_bytes(envelope))
    except InvalidSignature as exc:
        raise AuthenticationError("Invalid message signature") from exc


def decrypt_payload(envelope: MessageEnvelope, config: PiConfig) -> bytes:
    """Derive the message AES key with X25519/HKDF and decrypt the payload."""

    pi_private_key = load_x25519_private_key(config.x25519_private_key_path)
    sender_ephemeral_public_key = load_ephemeral_public_key(envelope.ephemeral_public_key)
    nonce = _decode_b64(envelope.nonce, DecryptionError, "Invalid nonce encoding")
    ciphertext = _decode_b64(envelope.ciphertext, DecryptionError, "Invalid ciphertext encoding")
    if len(nonce) != 12:
        raise DecryptionError("AES-GCM nonce must be 12 bytes")

    key = derive_message_key(pi_private_key, sender_ephemeral_public_key, envelope, nonce)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, serialize_aad(envelope))
    except Exception as exc:
        raise DecryptionError("Payload decryption failed") from exc


def load_x25519_private_key(path: str) -> X25519PrivateKey:
    """Load the Pi X25519 private key from a PEM file."""

    key_path = Path(path)
    if not key_path.is_file():
        raise DecryptionError(f"Missing X25519 private key file: {path}")

    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except ValueError as exc:
        raise DecryptionError(f"Invalid X25519 private key: {path}") from exc

    if not isinstance(key, X25519PrivateKey):
        raise DecryptionError("Configured private key must be X25519")
    return key


def load_ephemeral_public_key(value: str) -> X25519PublicKey:
    """Decode the sender's base64url raw X25519 public key."""

    raw = _decode_b64(value, DecryptionError, "Invalid ephemeral public key encoding")
    if len(raw) != 32:
        raise DecryptionError("X25519 public key must be 32 bytes")
    try:
        return X25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise DecryptionError("Invalid X25519 public key") from exc


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


def load_public_key_for_sender(sender_id: str, key_id: str, config: PiConfig) -> Ed25519PublicKey:
    """Load the sender Ed25519 public key used for signature verification."""

    path = _key_path(config.sender_public_keys_dir, f"{sender_id}_{key_id}", ".pem")
    if not path.is_file():
        raise AuthenticationError(f"Missing sender public key: {path}")

    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except ValueError as exc:
        raise AuthenticationError(f"Invalid sender public key: {path}") from exc

    if not isinstance(key, Ed25519PublicKey):
        raise AuthenticationError("Sender public key must be Ed25519")
    return key


def _kdf_info(envelope: MessageEnvelope) -> bytes:
    """Return HKDF domain-separation context for this protocol."""

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


def _key_path(directory: str, name: str, suffix: str) -> Path:
    """Build a key path after rejecting path separators in key names."""

    if any(char in name for char in ("/", "\\", ":", "\0")):
        raise AuthenticationError("Key identifier contains invalid path characters")
    return Path(directory) / f"{name}{suffix}"


def _decode_b64(value: str, error_type: type[Exception], message: str) -> bytes:
    """Decode padded or unpadded base64url text with a domain-specific error."""

    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise error_type(message) from exc
