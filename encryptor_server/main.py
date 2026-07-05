"""Command-line entry point for sending one encrypted message."""

from __future__ import annotations

import argparse

from encryptor_common.protocol import serialize_envelope

from .client import build_envelope
from .config import load_config
from .crypto import encrypt_for_pi
from .tls_client import send_encrypted_message


def main() -> None:
    """Load config, encrypt/sign one message, send it, and print the response."""

    parser = argparse.ArgumentParser(description="Send one encrypted message to the Pi daemon.")
    parser.add_argument("message")
    parser.add_argument("--config")
    args = parser.parse_args()

    config = load_config(args.config)
    envelope = build_envelope(config)
    encrypted = encrypt_for_pi(envelope, args.message.encode("utf-8"), config)
    response = send_encrypted_message(serialize_envelope(encrypted), config)
    print(response.decode("utf-8"))


if __name__ == "__main__":
    main()
