"""Pi-side forwarding to the downstream real client/service."""

from __future__ import annotations

from .config import PiConfig


def forward_plaintext_over_tls(plaintext: bytes, config: PiConfig) -> bytes:
    """Forward plaintext to the configured downstream service over TLS."""

    raise NotImplementedError
