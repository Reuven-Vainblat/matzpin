"""Development key, certificate, and config generation skeleton."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

MAX_MESSAGE_SIZE = 1_048_576


def main() -> None:
    """Parse arguments and generate the requested development material."""

    parser = argparse.ArgumentParser(description="Generate development certificates and message keys.")
    parser.add_argument("--out", default=".")
    parser.add_argument("--component", choices=("all", "authority", "pi", "server", "trust-server", "trust-pi"), default="all")
    parser.parse_args()
    raise NotImplementedError


def generate_dev_security(root: Path, sender_id: str = "server", key_id: str = "k1") -> None:
    """Generate all development certificates, keys, and peer key copies."""

    raise NotImplementedError


def generate_dev_authority(root: Path) -> tuple[Any, Any]:
    """Create and write the development certificate authority."""

    raise NotImplementedError


def generate_pi_security(root: Path, ca_key: Any, ca_cert: Any, sender_id: str = "server", key_id: str = "k1") -> None:
    """Generate Pi-side TLS and message-decryption material."""

    raise NotImplementedError


def generate_server_security(root: Path, ca_key: Any, ca_cert: Any, sender_id: str = "server", key_id: str = "k1") -> None:
    """Generate server-side TLS and message-signing material."""

    raise NotImplementedError


def build_pi_config(security_root: Path, port: int, forward_port: int, replay_db_path: Path) -> dict[str, object]:
    """Build a Pi config that points at generated development security files."""

    raise NotImplementedError


def build_server_config(server_security_root: Path, port: int, pi_port: int) -> dict[str, object]:
    """Build a server config that points at generated development security files."""

    raise NotImplementedError


def build_demi_client_config(security_root: Path, port: int, response: str, received_output_path: Path) -> dict[str, object]:
    """Build a demi-client config that points at generated development security files."""

    raise NotImplementedError


def write_config_file(path: Path, data: dict[str, object]) -> None:
    """Write a JSON runtime config file."""

    raise NotImplementedError


if __name__ == "__main__":
    main()
