"""Shared runtime configuration validation helpers."""

from __future__ import annotations


def require_non_empty(name: str, value: str) -> None:
    """Require a non-empty string value."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def require_port(name: str, value: int, allow_zero: bool = False) -> None:
    """Require a TCP/UDP port value, optionally allowing zero for OS assignment."""

    minimum = 0 if allow_zero else 1
    if not minimum <= value <= 65_535:
        if allow_zero:
            raise ValueError(f"{name} must be between 0 and 65535")
        raise ValueError(f"{name} must be between 1 and 65535")


def require_positive_int(name: str, value: int) -> None:
    """Require a positive integer value."""

    if value <= 0:
        raise ValueError(f"{name} must be positive")


def require_positive_float(name: str, value: float) -> None:
    """Require a positive float value."""

    if value <= 0:
        raise ValueError(f"{name} must be positive")


def require_message_size(value: int) -> None:
    """Require a bounded maximum message size."""

    if not 1 <= value <= 16 * 1024 * 1024:
        raise ValueError("max_message_size must be between 1 byte and 16 MiB")
