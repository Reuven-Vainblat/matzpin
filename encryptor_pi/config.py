"""Configuration loading for the Raspberry Pi daemon."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PiConfig:
    """Runtime settings owned by the Raspberry Pi daemon."""

    host: str
    port: int
    ca_cert_path: str
    pi_cert_path: str
    pi_key_path: str
    expected_recipient_id: str
    sender_public_keys_dir: str
    x25519_private_key_path: str
    replay_db_path: str
    max_message_size: int
    max_clock_skew_seconds: int
    request_timeout_seconds: float
    forward_host: str
    forward_port: int
    forward_timeout_seconds: float


def load_config(path: str | None = None) -> PiConfig:
    """Load Pi daemon configuration from JSON and environment variables."""

    raise NotImplementedError
