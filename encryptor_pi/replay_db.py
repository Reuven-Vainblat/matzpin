"""SQLite replay protection for processed message IDs."""

from __future__ import annotations

from encryptor_common.protocol import MessageEnvelope


def init_replay_db(db_path: str) -> None:
    """Create replay storage if it does not exist."""

    raise NotImplementedError


def is_replay(db_path: str, message_id: str) -> bool:
    """Return true when ``message_id`` has already been marked as seen."""

    raise NotImplementedError


def mark_seen(db_path: str, envelope: MessageEnvelope) -> None:
    """Persist a successfully processed message id for future replay checks."""

    raise NotImplementedError


def cleanup_old_entries(db_path: str, max_age_seconds: int) -> None:
    """Delete replay entries older than ``max_age_seconds``."""

    raise NotImplementedError
