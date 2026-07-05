"""Server-side mutual-TLS client used to reach the Pi daemon."""

from __future__ import annotations

from .config import ServerConfig


def send_encrypted_message(raw_envelope: bytes, config: ServerConfig) -> bytes:
    """Send one framed envelope to the Pi and return one framed response."""

    raise NotImplementedError
