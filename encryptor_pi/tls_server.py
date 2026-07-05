"""Pi-side mutual-TLS listener for encrypted envelopes."""

from __future__ import annotations

import logging
import socket
import ssl

from encryptor_common.framing import recv_framed_message, send_framed_message

from .config import PiConfig
from .processor import handle_message

LOGGER = logging.getLogger(__name__)


def create_ssl_context(config: PiConfig) -> ssl.SSLContext:
    """Create a server SSL context that requires client certificates."""

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=config.pi_cert_path, keyfile=config.pi_key_path)
    context.load_verify_locations(cafile=config.ca_cert_path)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def run_server(config: PiConfig) -> None:
    """Run the blocking Pi TLS server loop forever."""

    context = create_ssl_context(config)
    with socket.create_server((config.host, config.port), reuse_port=False) as server_sock:
        while True:
            client_sock, address = server_sock.accept()
            with client_sock:
                client_sock.settimeout(config.request_timeout_seconds)
                try:
                    with context.wrap_socket(client_sock, server_side=True) as tls_sock:
                        tls_sock.settimeout(config.request_timeout_seconds)
                        handle_connection(tls_sock, config)
                except Exception as exc:
                    LOGGER.warning("Rejected Pi client connection from %s: %s", address, exc)


def handle_connection(tls_sock: ssl.SSLSocket, config: PiConfig) -> None:
    """Read one framed envelope, process it, and write one framed response."""

    request = recv_framed_message(tls_sock, config.max_message_size)
    response = handle_message(request, config)
    send_framed_message(tls_sock, response)
