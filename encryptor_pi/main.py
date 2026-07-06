"""Command-line entry point for the Raspberry Pi daemon."""

from __future__ import annotations

import logging

from .config import load_config
from .replay_db import init_replay_db, maybe_cleanup_old_entries
from .tls_server import run_server


def main() -> None:
    """Load Pi config, prepare replay storage, and start the TLS listener."""

    logging.basicConfig(level=logging.INFO)
    config = load_config()
    init_replay_db(config.replay_db_path)
    maybe_cleanup_old_entries(
        config.replay_db_path,
        config.replay_retention_seconds,
        config.replay_cleanup_interval_seconds,
    )
    run_server(config)


if __name__ == "__main__":
    main()
