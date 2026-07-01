"""Command-line entry point for the Raspberry Pi daemon."""

from __future__ import annotations

from .config import load_config
from .replay_db import init_replay_db
from .tls_server import run_server


def main() -> None:
    """Load Pi config, prepare replay storage, and start the TLS listener."""

    config = load_config()
    init_replay_db(config.replay_db_path)
    run_server(config)


if __name__ == "__main__":
    main()
