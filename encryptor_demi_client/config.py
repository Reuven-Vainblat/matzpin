"""Configuration for the downstream demi client."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DemiClientConfig:
    """Runtime settings for the local downstream test service."""

    host: str
    port: int
    tls_cert_path: str
    tls_key_path: str
    response: bytes
    received_output_path: str | None
    max_message_size: int


def load_config(path: str | None = None) -> DemiClientConfig:
    """Load demi-client configuration from JSON and environment variables."""

    raise NotImplementedError
