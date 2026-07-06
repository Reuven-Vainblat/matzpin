"""Configuration loading for the server/sender side."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any

from encryptor_common.config_validation import (
    require_message_size,
    require_non_empty,
    require_port,
    require_positive_float,
)


@dataclass(frozen=True)
class ServerConfig:
    """Runtime settings owned by the server/sender.

    The server connects to the Pi over mutual TLS, encrypts messages to the Pi
    X25519 public key, and signs envelopes with its Ed25519 private key.
    """

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
    local_host: str | None = None
    local_port: int = 0


def load_config(path: str | None = None) -> ServerConfig:
    """Load server configuration from JSON and environment variables."""

    data: dict[str, Any] = {}
    config_path = path or os.getenv("ENCRYPTOR_SERVER_CONFIG")
    if config_path:
        data.update(json.loads(Path(config_path).read_text(encoding="utf-8")))

    config = ServerConfig(
        pi_host=_get(data, "pi_host", "SERVER_PI_HOST", "127.0.0.1"),
        pi_port=int(_get(data, "pi_port", "SERVER_PI_PORT", 8443)),
        ca_cert_path=_get(data, "ca_cert_path", "SERVER_CA_CERT", "server/certs/ca.crt"),
        server_cert_path=_get(data, "server_cert_path", "SERVER_TLS_CERT", "server/keys/private/server_tls.crt"),
        server_key_path=_get(data, "server_key_path", "SERVER_TLS_KEY", "server/keys/private/server_tls.key"),
        sender_id=_get(data, "sender_id", "SERVER_SENDER_ID", "server"),
        recipient_id=_get(data, "recipient_id", "SERVER_RECIPIENT_ID", "raspberry-pi"),
        key_id=_get(data, "key_id", "SERVER_KEY_ID", "k1"),
        signing_private_key_path=_get(
            data,
            "signing_private_key_path",
            "SERVER_SIGNING_PRIVATE_KEY",
            "server/keys/private/server_k1.pem",
        ),
        pi_x25519_public_key_path=_get(
            data,
            "pi_x25519_public_key_path",
            "SERVER_PI_X25519_PUBLIC_KEY",
            "server/keys/public/pi_x25519.pub",
        ),
        max_message_size=int(_get(data, "max_message_size", "SERVER_MAX_MESSAGE_SIZE", 1_048_576)),
        timeout_seconds=float(_get(data, "timeout_seconds", "SERVER_TIMEOUT", 10.0)),
        local_host=_optional_str(_get(data, "local_host", "SERVER_LOCAL_HOST", None)),
        local_port=int(_get(data, "local_port", "SERVER_LOCAL_PORT", 0)),
    )
    validate_config(config)
    return config


def _get(data: dict[str, Any], key: str, env_name: str, default: Any) -> Any:
    """Return an environment override, JSON value, or default in that order."""

    return os.getenv(env_name, data.get(key, default))


def _optional_str(value: Any) -> str | None:
    """Normalize blank config strings to an unset optional string."""

    if value is None:
        return None
    value = str(value)
    return value or None


def validate_config(config: ServerConfig) -> None:
    """Reject invalid server runtime settings at startup."""

    require_non_empty("pi_host", config.pi_host)
    require_port("pi_port", config.pi_port)
    require_non_empty("ca_cert_path", config.ca_cert_path)
    require_non_empty("server_cert_path", config.server_cert_path)
    require_non_empty("server_key_path", config.server_key_path)
    require_non_empty("sender_id", config.sender_id)
    require_non_empty("recipient_id", config.recipient_id)
    require_non_empty("key_id", config.key_id)
    require_non_empty("signing_private_key_path", config.signing_private_key_path)
    require_non_empty("pi_x25519_public_key_path", config.pi_x25519_public_key_path)
    require_message_size(config.max_message_size)
    require_positive_float("timeout_seconds", config.timeout_seconds)
    if config.local_host is not None:
        require_non_empty("local_host", config.local_host)
    require_port("local_port", config.local_port, allow_zero=True)
