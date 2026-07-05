"""Pi-side mutual-TLS listener for encrypted envelopes."""

from __future__ import annotations

import socket
import ssl

from .config import PiConfig


def create_ssl_context(config: PiConfig) -> ssl.SSLContext:
    """Create a server SSL context that requires client certificates."""

    raise NotImplementedError


def run_server(config: PiConfig) -> None:
    """Run the Pi TLS server loop."""

    raise NotImplementedError


def handle_connection(tls_sock: ssl.SSLSocket, config: PiConfig) -> None:
    """Read one framed envelope, process it, and write one framed response."""

    raise NotImplementedError
