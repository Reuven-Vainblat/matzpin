"""Server-side envelope construction."""

from __future__ import annotations

from encryptor_common.protocol import MessageEnvelope

from .config import ServerConfig


def build_envelope(config: ServerConfig) -> MessageEnvelope:
    """Create the unsigned metadata envelope for one outgoing message."""

    raise NotImplementedError
