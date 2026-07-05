"""Forward decrypted Pi-side plaintext to a downstream TLS service."""

from __future__ import annotations

import logging
import socket
import ssl

from encryptor_common.errors import ForwardingError
from encryptor_common.framing import recv_framed_message, send_framed_message

from .config import PiConfig

LOGGER = logging.getLogger(__name__)


def forward_plaintext_over_tls(plaintext: bytes, config: PiConfig) -> bytes:
    """Forward plaintext to the configured downstream service over TLS."""

    context = ssl.create_default_context(cafile=config.ca_cert_path)
    try:
        LOGGER.info(
            "Pi forwarding plaintext to downstream %s:%s: %s bytes",
            config.forward_host,
            config.forward_port,
            len(plaintext),
        )
        with socket.create_connection(
            (config.forward_host, config.forward_port),
            timeout=config.forward_timeout_seconds,
        ) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=config.forward_host) as tls_sock:
                send_framed_message(tls_sock, plaintext)
                response = recv_framed_message(tls_sock, config.max_message_size)
                LOGGER.info("Pi received downstream response: %s bytes", len(response))
                return response
    except OSError as exc:
        raise ForwardingError("Failed to forward payload over TLS") from exc

