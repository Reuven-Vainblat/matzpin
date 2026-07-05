"""Pi-side message processing pipeline."""

from __future__ import annotations

import logging

from encryptor_common.errors import ReplayError
from encryptor_common.protocol import parse_envelope

from .config import PiConfig
from .crypto import decrypt_payload, verify_signature
from .forwarder import forward_plaintext_over_tls
from .replay_db import is_replay, mark_seen
from .validator import validate_envelope_metadata, validate_plaintext

LOGGER = logging.getLogger(__name__)


def handle_message(raw: bytes, config: PiConfig) -> bytes:
    """Validate, verify, decrypt, forward, and record one envelope message."""

    envelope = parse_envelope(raw)
    LOGGER.info(
        "Pi parsed request message_id=%s sender=%s key_id=%s",
        envelope.message_id,
        envelope.sender_id,
        envelope.key_id,
    )
    validate_envelope_metadata(envelope, config)

    if is_replay(config.replay_db_path, envelope.message_id):
        raise ReplayError("Replay detected")
    LOGGER.info("Pi replay check passed for message_id=%s", envelope.message_id)

    verify_signature(envelope, config)
    LOGGER.info("Pi signature verified for message_id=%s", envelope.message_id)
    plaintext = decrypt_payload(envelope, config)
    LOGGER.info("Pi decrypted payload for message_id=%s: %s bytes", envelope.message_id, len(plaintext))
    validate_plaintext(plaintext)

    response = forward_plaintext_over_tls(plaintext, config)
    mark_seen(config.replay_db_path, envelope)
    LOGGER.info("Pi marked message_id=%s as seen", envelope.message_id)
    return response

