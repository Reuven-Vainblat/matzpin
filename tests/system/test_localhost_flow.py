"""System-test skeleton for the localhost Pi/server/client flow."""

from __future__ import annotations

import unittest


class LocalhostSystemTest(unittest.TestCase):
    def test_pi_main_then_server_main_round_trip_on_distinct_ports(self) -> None:
        """Run demi client, Pi main, and server main on different localhost ports."""

        raise NotImplementedError

    def test_rejects_server_with_untrusted_tls_certificate(self) -> None:
        """A server certificate from another CA must fail mutual TLS."""

        raise NotImplementedError

    def test_rejects_message_signed_by_unknown_server_key(self) -> None:
        """A valid TLS server still fails if its envelope signature is unknown."""

        raise NotImplementedError

    def test_rejects_message_encrypted_to_wrong_pi_public_key(self) -> None:
        """A signed envelope fails if it was encrypted for another Pi key."""

        raise NotImplementedError


if __name__ == "__main__":
    unittest.main()
