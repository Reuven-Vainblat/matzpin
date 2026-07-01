"""Pi-side message processing pipeline."""

from __future__ import annotations

from encryptor_common.errors import ReplayError
from encryptor_common.protocol import parse_envelope

from .config import PiConfig
from .crypto import decrypt_payload, verify_signature
from .forwarder import forward_plaintext_over_tls
from .replay_db import is_replay, mark_seen
from .validator import validate_envelope_metadata, validate_plaintext


def handle_message(raw: bytes, config: PiConfig) -> bytes:
    """Validate, verify, decrypt, forward, and record one envelope message."""

    envelope = parse_envelope(raw)
    validate_envelope_metadata(envelope, config)

    if is_replay(config.replay_db_path, envelope.message_id):
        raise ReplayError("Replay detected")

    verify_signature(envelope, config)
    plaintext = decrypt_payload(envelope, config)
    validate_plaintext(plaintext)

    response = forward_plaintext_over_tls(plaintext, config)
    mark_seen(config.replay_db_path, envelope)
    return response

