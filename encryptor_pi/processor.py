"""Pi-side message processing pipeline."""

from __future__ import annotations

import logging

from encryptor_common.protocol import parse_envelope

from .config import PiConfig
from .crypto import decrypt_payload, verify_signature
from .forwarder import forward_plaintext_over_tls
from .replay_db import claim_message, maybe_cleanup_old_entries, release_message_claim
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

    maybe_cleanup_old_entries(
        config.replay_db_path,
        config.replay_retention_seconds,
        config.replay_cleanup_interval_seconds,
    )
    claim_message(config.replay_db_path, envelope)
    LOGGER.info("Pi replay claim succeeded for message_id=%s", envelope.message_id)

    forwarded = False
    try:
        verify_signature(envelope, config)
        LOGGER.info("Pi signature verified for message_id=%s", envelope.message_id)
        plaintext = decrypt_payload(envelope, config)
        LOGGER.info("Pi decrypted payload for message_id=%s: %s bytes", envelope.message_id, len(plaintext))
        validate_plaintext(plaintext)

        response = forward_plaintext_over_tls(plaintext, config)
        forwarded = True
    except Exception:
        if not forwarded:
            release_message_claim(config.replay_db_path, envelope.message_id)
            LOGGER.info("Pi released replay claim for failed message_id=%s", envelope.message_id)
        raise

    LOGGER.info("Pi kept replay claim for completed message_id=%s", envelope.message_id)
    return response

