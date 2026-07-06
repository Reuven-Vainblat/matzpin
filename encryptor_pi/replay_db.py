"""SQLite-backed replay protection for processed message ids."""

from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import time

from encryptor_common.errors import ReplayError
from encryptor_common.protocol import MessageEnvelope

_LAST_CLEANUP_BY_DB: dict[str, float] = {}


def init_replay_db(db_path: str) -> None:
    """Create the replay table if it does not already exist."""

    db_parent = Path(db_path).expanduser().parent
    if str(db_parent) not in ("", "."):
        db_parent.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_messages (
                    message_id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    seen_at REAL NOT NULL
                )
                """
            )


def is_replay(db_path: str, message_id: str) -> bool:
    """Return true when `message_id` has already been marked as seen."""

    init_replay_db(db_path)
    with closing(sqlite3.connect(db_path)) as conn:
        row = conn.execute(
            "SELECT 1 FROM seen_messages WHERE message_id = ?",
            (message_id,),
        ).fetchone()
    return row is not None


def claim_message(db_path: str, envelope: MessageEnvelope) -> None:
    """Atomically reserve a message id before forwarding plaintext."""

    init_replay_db(db_path)
    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO seen_messages(message_id, sender_id, seen_at) VALUES (?, ?, ?)",
                (envelope.message_id, envelope.sender_id, time.time()),
            )
    if cursor.rowcount == 0:
        raise ReplayError("Replay detected")


def release_message_claim(db_path: str, message_id: str) -> None:
    """Remove a claim when processing fails before plaintext is forwarded."""

    init_replay_db(db_path)
    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            conn.execute("DELETE FROM seen_messages WHERE message_id = ?", (message_id,))


def mark_seen(db_path: str, envelope: MessageEnvelope) -> None:
    """Persist a successfully processed message id for future replay checks."""

    init_replay_db(db_path)
    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO seen_messages(message_id, sender_id, seen_at) VALUES (?, ?, ?)",
                (envelope.message_id, envelope.sender_id, time.time()),
            )


def cleanup_old_entries(db_path: str, max_age_seconds: int) -> None:
    """Delete replay entries older than `max_age_seconds`."""

    init_replay_db(db_path)
    cutoff = time.time() - max_age_seconds
    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            conn.execute("DELETE FROM seen_messages WHERE seen_at < ?", (cutoff,))


def maybe_cleanup_old_entries(
    db_path: str,
    max_age_seconds: int,
    cleanup_interval_seconds: float,
    now: float | None = None,
) -> bool:
    """Run replay cleanup at most once per configured interval."""

    now = time.time() if now is None else now
    last_cleanup = _LAST_CLEANUP_BY_DB.get(db_path, 0.0)
    if now - last_cleanup < cleanup_interval_seconds:
        return False

    cleanup_old_entries(db_path, max_age_seconds)
    _LAST_CLEANUP_BY_DB[db_path] = now
    return True
