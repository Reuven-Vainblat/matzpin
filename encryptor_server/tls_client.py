"""Server-side mutual-TLS client used to send envelopes to the Pi."""

from __future__ import annotations

import socket
import ssl

from encryptor_common.framing import recv_framed_message, send_framed_message

from .config import ServerConfig


def send_envelope(raw_envelope: bytes, config: ServerConfig) -> bytes:
    """Send one framed envelope to the Pi and return one framed response."""

    context = ssl.create_default_context(cafile=config.ca_cert_path)
    context.load_cert_chain(certfile=config.server_cert_path, keyfile=config.server_key_path)
    source_address = _source_address(config)
    with socket.create_connection(
        (config.pi_host, config.pi_port),
        timeout=config.timeout_seconds,
        source_address=source_address,
    ) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=config.pi_host) as tls_sock:
            send_framed_message(tls_sock, raw_envelope)
            return recv_framed_message(tls_sock, config.max_message_size)


def _source_address(config: ServerConfig) -> tuple[str, int] | None:
    """Return an optional local bind address for deterministic tests."""

    if config.local_host is None and config.local_port == 0:
        return None
    return (config.local_host or "", config.local_port)
