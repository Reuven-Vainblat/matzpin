"""Configuration loading for the server/sender."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ServerConfig:
    """Runtime settings owned by the server/sender."""

    pi_host: str
    pi_port: int
    ca_cert_path: str
    server_cert_path: str
    server_key_path: str
    sender_id: str
    recipient_id: str
    key_id: str
    signing_private_key_path: str
    pi_x25519_public_key_path: str
    max_message_size: int
    timeout_seconds: float
    local_host: str | None
    local_port: int


def load_config(path: str | None = None) -> ServerConfig:
    """Load server configuration from JSON and environment variables."""

    raise NotImplementedError
