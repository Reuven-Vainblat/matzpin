"""Focused tests for practical security hardening behavior."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from encryptor_common.errors import AuthenticationError, ForwardingError, ProtocolError, ReplayError
from encryptor_common.protocol import MessageEnvelope, parse_envelope, serialize_envelope
from encryptor_pi.config import PiConfig, validate_config
from encryptor_pi.processor import handle_message
from encryptor_pi.rate_limiter import FixedWindowRateLimiter
from encryptor_pi.replay_db import (
    claim_message,
    cleanup_old_entries,
    is_replay,
    maybe_cleanup_old_entries,
    release_message_claim,
)


class ProtocolHardeningTest(unittest.TestCase):
    def test_parse_envelope_accepts_valid_shape(self) -> None:
        envelope = _envelope()

        parsed = parse_envelope(serialize_envelope(envelope))

        self.assertEqual(parsed.message_id, envelope.message_id)

    def test_parse_envelope_rejects_extra_fields(self) -> None:
        payload = _payload()
        payload["unexpected"] = "nope"

        with self.assertRaises(ProtocolError):
            parse_envelope(json.dumps(payload).encode("utf-8"))

    def test_parse_envelope_rejects_wrong_field_type(self) -> None:
        payload = _payload()
        payload["aad"] = []

        with self.assertRaises(ProtocolError):
            parse_envelope(json.dumps(payload).encode("utf-8"))

    def test_parse_envelope_rejects_oversized_id(self) -> None:
        payload = _payload()
        payload["message_id"] = "x" * 129

        with self.assertRaises(ProtocolError):
            parse_envelope(json.dumps(payload).encode("utf-8"))


class ReplayHardeningTest(unittest.TestCase):
    def test_claim_rejects_duplicate_message_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "replay.sqlite3")
            envelope = _envelope()

            claim_message(db_path, envelope)

            with self.assertRaises(ReplayError):
                claim_message(db_path, envelope)

    def test_release_claim_allows_retry_after_failed_processing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "replay.sqlite3")
            envelope = _envelope()

            claim_message(db_path, envelope)
            release_message_claim(db_path, envelope.message_id)
            claim_message(db_path, envelope)

            self.assertTrue(is_replay(db_path, envelope.message_id))

    def test_cleanup_old_entries_removes_expired_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "replay.sqlite3")
            envelope = _envelope()

            claim_message(db_path, envelope)
            cleanup_old_entries(db_path, max_age_seconds=-1)

            self.assertFalse(is_replay(db_path, envelope.message_id))

    def test_maybe_cleanup_respects_interval(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "replay.sqlite3")

            first = maybe_cleanup_old_entries(db_path, 60, 10, now=100.0)
            second = maybe_cleanup_old_entries(db_path, 60, 10, now=105.0)

            self.assertTrue(first)
            self.assertFalse(second)

    def test_processor_keeps_claim_after_successful_forward(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = _pi_config(
                replay_db_path=str(Path(temp_dir) / "replay.sqlite3"),
                max_clock_skew_seconds=10**9,
            )
            raw = serialize_envelope(_envelope())

            with (
                patch("encryptor_pi.processor.verify_signature"),
                patch("encryptor_pi.processor.decrypt_payload", return_value=b"payload"),
                patch("encryptor_pi.processor.forward_plaintext_over_tls", return_value=b"ok") as forward,
            ):
                self.assertEqual(handle_message(raw, config), b"ok")
                with self.assertRaises(ReplayError):
                    handle_message(raw, config)

            forward.assert_called_once()

    def test_processor_releases_claim_after_signature_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "replay.sqlite3")
            config = _pi_config(replay_db_path=db_path, max_clock_skew_seconds=10**9)
            envelope = _envelope()

            with patch(
                "encryptor_pi.processor.verify_signature",
                side_effect=AuthenticationError("bad signature"),
            ):
                with self.assertRaises(AuthenticationError):
                    handle_message(serialize_envelope(envelope), config)

            self.assertFalse(is_replay(db_path, envelope.message_id))

    def test_processor_releases_claim_after_forwarding_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "replay.sqlite3")
            config = _pi_config(replay_db_path=db_path, max_clock_skew_seconds=10**9)
            envelope = _envelope()

            with (
                patch("encryptor_pi.processor.verify_signature"),
                patch("encryptor_pi.processor.decrypt_payload", return_value=b"payload"),
                patch(
                    "encryptor_pi.processor.forward_plaintext_over_tls",
                    side_effect=ForwardingError("downstream failed"),
                ),
            ):
                with self.assertRaises(ForwardingError):
                    handle_message(serialize_envelope(envelope), config)

            self.assertFalse(is_replay(db_path, envelope.message_id))


class RateLimiterTest(unittest.TestCase):
    def test_rate_limiter_rejects_over_limit_until_window_expires(self) -> None:
        now = 100.0
        limiter = FixedWindowRateLimiter(10.0, 2, now=lambda: now)

        self.assertTrue(limiter.allow("10.0.0.1"))
        self.assertTrue(limiter.allow("10.0.0.1"))
        self.assertFalse(limiter.allow("10.0.0.1"))

        now = 111.0
        self.assertTrue(limiter.allow("10.0.0.1"))


class ConfigValidationTest(unittest.TestCase):
    def test_pi_config_rejects_invalid_ports_and_timeouts(self) -> None:
        config = _pi_config(port=0)

        with self.assertRaises(ValueError):
            validate_config(config)

        config = _pi_config(request_timeout_seconds=0)
        with self.assertRaises(ValueError):
            validate_config(config)


def _payload() -> dict[str, object]:
    return {
        "version": 1,
        "message_id": "message-1",
        "timestamp": "2026-07-06T12:00:00+00:00",
        "sender_id": "server",
        "recipient_id": "raspberry-pi",
        "key_id": "k1",
        "ephemeral_public_key": "abc",
        "nonce": "abc",
        "ciphertext": "abc",
        "signature": "abc",
        "aad": {},
    }


def _envelope() -> MessageEnvelope:
    return MessageEnvelope(**_payload())


def _pi_config(**overrides: object) -> PiConfig:
    data = {
        "host": "127.0.0.1",
        "port": 18443,
        "ca_cert_path": "ca.crt",
        "pi_cert_path": "pi.crt",
        "pi_key_path": "pi.key",
        "expected_recipient_id": "raspberry-pi",
        "sender_public_keys_dir": "senders",
        "x25519_private_key_path": "pi_x25519.pem",
        "replay_db_path": "replay.sqlite3",
        "max_message_size": 1_048_576,
        "max_clock_skew_seconds": 300,
        "request_timeout_seconds": 5.0,
        "rate_limit_window_seconds": 60.0,
        "max_connections_per_window": 60,
        "replay_retention_seconds": 86_400,
        "replay_cleanup_interval_seconds": 3_600.0,
        "forward_host": "127.0.0.1",
        "forward_port": 19443,
        "forward_timeout_seconds": 5.0,
    }
    data.update(overrides)
    return PiConfig(**data)


if __name__ == "__main__":
    unittest.main()
