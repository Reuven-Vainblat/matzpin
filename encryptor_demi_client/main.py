"""Command-line entry point for the downstream demi client."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
import socket
import ssl

from encryptor_common.framing import recv_framed_message, send_framed_message

from .config import DemiClientConfig, load_config

LOGGER = logging.getLogger(__name__)


def main() -> None:
    """Run a one-request downstream TLS service for local/system tests."""

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Run the downstream demi client.")
    parser.add_argument("--config", help="Optional JSON config file path.")
    args = parser.parse_args()

    run_client(load_config(args.config))


def run_client(config: DemiClientConfig) -> None:
    """Accept one forwarded plaintext message and send the configured response."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=config.tls_cert_path, keyfile=config.tls_key_path)

    with socket.create_server((config.host, config.port), reuse_port=False) as listener:
        LOGGER.info("Demi client listening on %s:%s", config.host, config.port)
        raw_sock, address = listener.accept()
        LOGGER.info("Demi client accepted connection from %s", address)
        with raw_sock:
            with context.wrap_socket(raw_sock, server_side=True) as tls_sock:
                plaintext = recv_framed_message(tls_sock, config.max_message_size)
                LOGGER.info("Demi client received forwarded plaintext: %s bytes", len(plaintext))
                if config.received_output_path:
                    Path(config.received_output_path).write_bytes(plaintext)
                    LOGGER.info("Demi client wrote plaintext to %s", config.received_output_path)
                send_framed_message(tls_sock, config.response)
                LOGGER.info("Demi client sent response: %s bytes", len(config.response))


if __name__ == "__main__":
    main()
