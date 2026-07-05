"""Simple downstream TLS service used by system tests."""

from __future__ import annotations

import argparse

from .config import DemiClientConfig, load_config


def main() -> None:
    """Run the downstream demi client from the command line."""

    parser = argparse.ArgumentParser(description="Run the downstream demi client.")
    parser.add_argument("--config")
    args = parser.parse_args()
    run_client(load_config(args.config))


def run_client(config: DemiClientConfig) -> None:
    """Accept one forwarded plaintext message and send the configured response."""

    raise NotImplementedError


if __name__ == "__main__":
    main()
