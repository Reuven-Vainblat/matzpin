"""SQLite-backed replay protection for processed message ids."""

from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import time

from encryptor_common.protocol import MessageEnvelope


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
