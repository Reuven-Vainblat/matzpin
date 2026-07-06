"""Configuration loading for the demi downstream client."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any

from encryptor_common.config_validation import require_message_size, require_non_empty, require_port


@dataclass(frozen=True)
class DemiClientConfig:
    """Runtime settings for a small downstream TLS service."""

    host: str
    port: int
    tls_cert_path: str
    tls_key_path: str
    response: bytes
    received_output_path: str | None
    max_message_size: int


def load_config(path: str | None = None) -> DemiClientConfig:
    """Load demi client configuration from JSON and environment variables."""

    data: dict[str, Any] = {}
    config_path = path or os.getenv("ENCRYPTOR_DEMI_CLIENT_CONFIG")
    if config_path:
        data.update(json.loads(Path(config_path).read_text(encoding="utf-8")))

    config = DemiClientConfig(
        host=_get(data, "host", "DEMI_CLIENT_HOST", "127.0.0.1"),
        port=int(_get(data, "port", "DEMI_CLIENT_PORT", 9443)),
        tls_cert_path=_get(data, "tls_cert_path", "DEMI_CLIENT_TLS_CERT", "pi/certs/pi.crt"),
        tls_key_path=_get(data, "tls_key_path", "DEMI_CLIENT_TLS_KEY", "pi/certs/pi.key"),
        response=str(_get(data, "response", "DEMI_CLIENT_RESPONSE", "OK")).encode("utf-8"),
        received_output_path=_optional_str(_get(data, "received_output_path", "DEMI_CLIENT_RECEIVED_OUTPUT", None)),
        max_message_size=int(_get(data, "max_message_size", "DEMI_CLIENT_MAX_MESSAGE_SIZE", 1_048_576)),
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


def validate_config(config: DemiClientConfig) -> None:
    """Reject invalid demi-client runtime settings at startup."""

    require_non_empty("host", config.host)
    require_port("port", config.port)
    require_non_empty("tls_cert_path", config.tls_cert_path)
    require_non_empty("tls_key_path", config.tls_key_path)
    if not config.response:
        raise ValueError("response must not be empty")
    if config.received_output_path is not None:
        require_non_empty("received_output_path", config.received_output_path)
    require_message_size(config.max_message_size)
