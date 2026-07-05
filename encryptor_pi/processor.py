"""Pi-side request processing pipeline."""

from __future__ import annotations

from .config import PiConfig


def handle_message(raw: bytes, config: PiConfig) -> bytes:
    """Validate, verify, decrypt, forward, and record one envelope message."""

    raise NotImplementedError
