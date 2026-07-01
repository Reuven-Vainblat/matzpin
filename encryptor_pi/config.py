"""Configuration loading for the Raspberry Pi daemon."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PiConfig:
    """Runtime settings owned by the Raspberry Pi daemon.

    TLS settings identify the Pi on the network. The sender public-key
    directory verifies Ed25519 message signatures. The X25519 private key lets
    the Pi derive each message's AES key from the sender's ephemeral public key.
    """

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
    forward_host: str
    forward_port: int
    forward_timeout_seconds: float


def load_config(path: str | None = None) -> PiConfig:
    """Load Pi daemon configuration from JSON and environment variables.

    Environment variables override JSON values. If `path` is omitted, the
    function reads `ENCRYPTOR_PI_CONFIG`.
    """

    data: dict[str, Any] = {}
    config_path = path or os.getenv("ENCRYPTOR_PI_CONFIG")
    if config_path:
        data.update(json.loads(Path(config_path).read_text(encoding="utf-8")))

    return PiConfig(
        host=_get(data, "host", "PI_HOST", "0.0.0.0"),
        port=int(_get(data, "port", "PI_PORT", 8443)),
        ca_cert_path=_get(data, "ca_cert_path", "PI_CA_CERT", "pi/certs/ca.crt"),
        pi_cert_path=_get(data, "pi_cert_path", "PI_TLS_CERT", "pi/certs/pi.crt"),
        pi_key_path=_get(data, "pi_key_path", "PI_TLS_KEY", "pi/certs/pi.key"),
        expected_recipient_id=_get(data, "expected_recipient_id", "PI_RECIPIENT_ID", "raspberry-pi"),
        sender_public_keys_dir=_get(data, "sender_public_keys_dir", "PI_SENDER_PUBLIC_KEYS_DIR", "pi/keys/senders"),
        x25519_private_key_path=_get(
            data,
            "x25519_private_key_path",
            "PI_X25519_PRIVATE_KEY",
            "pi/keys/private/pi_x25519.pem",
        ),
        replay_db_path=_get(data, "replay_db_path", "PI_REPLAY_DB", "pi/replay.sqlite3"),
        max_message_size=int(_get(data, "max_message_size", "PI_MAX_MESSAGE_SIZE", 1_048_576)),
        max_clock_skew_seconds=int(_get(data, "max_clock_skew_seconds", "PI_MAX_CLOCK_SKEW", 300)),
        forward_host=_get(data, "forward_host", "PI_FORWARD_HOST", "127.0.0.1"),
        forward_port=int(_get(data, "forward_port", "PI_FORWARD_PORT", 9443)),
        forward_timeout_seconds=float(_get(data, "forward_timeout_seconds", "PI_FORWARD_TIMEOUT", 10.0)),
    )


def _get(data: dict[str, Any], key: str, env_name: str, default: Any) -> Any:
    """Return an environment override, JSON value, or default in that order."""

    return os.getenv(env_name, data.get(key, default))

