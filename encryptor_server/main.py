"""Command-line entry point for sending one encrypted message to the Pi."""

from __future__ import annotations

import argparse

from .client import send_plaintext
from .config import load_config


def main() -> None:
    """Encrypt, sign, send one plaintext message, and print the response."""

    parser = argparse.ArgumentParser(description="Send one encrypted envelope to the Raspberry Pi daemon.")
    parser.add_argument("message", help="Plaintext message to send.")
    parser.add_argument("--config", help="Optional JSON config file path.")
    args = parser.parse_args()

    config = load_config(args.config)
    response = send_plaintext(args.message.encode("utf-8"), config)
    print(response.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
