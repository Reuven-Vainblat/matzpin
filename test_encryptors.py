import unittest
from unittest.mock import MagicMock, patch
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from matzpin import Encryptor, DH_BASE, DH_PRIME

class TestEncryptor(unittest.TestCase):

    def setUp(self):
        """Set up a base Encryptor instance with mocked sockets."""
        # Patch the socket.socket call in __init__ so it doesn't try to bind to local ports
        with patch("socket.socket") as mock_sock_cls:
            self.mock_red_socket = MagicMock()
            mock_sock_cls.return_value = self.mock_red_socket
            
            # Instantiate as a client/sender for default test setup
            self.encryptor = Encryptor(
                is_server=False, 
                red_nic="8888", 
                black_ip="127.0.0.1", 
                black_port=9999
            )
            
            # Manually inject a mock for the black TCP connection
            self.encryptor.black_connection = MagicMock()

    @patch("matzpin.secrets.randbits")
    @patch("matzpin.black_side.receive_exact_bytes")
    def test_sync_keys_sender(self, mock_receive, mock_randbits):
        """Validates that Diffie-Hellman key exchange successfully computes the shared secret."""
        # 1. Mock the client's static private key for deterministic test math
        mock_randbits.return_value = 12345
        client_private_key = 12345
        client_public_key = pow(DH_BASE, client_private_key, DH_PRIME)
        
        # 2. Mock a simulated peer public key
        peer_private_key = 67890
        peer_public_key = pow(DH_BASE, peer_private_key, DH_PRIME)
        peer_pub_bytes = peer_public_key.to_bytes(256, byteorder="big")
        mock_receive.return_value = peer_pub_bytes

        # 3. Calculate expected key manually
        expected_shared_secret = pow(peer_public_key, client_private_key, DH_PRIME)
        expected_key = hashlib.sha256(expected_shared_secret.to_bytes(256, byteorder="big")).digest()

        # Run the sync
        self.encryptor.sync_keys()

        # Assertions
        self.assertEqual(self.encryptor.key, expected_key)
        self.encryptor.black_connection.sendall.assert_called_once_with(
            client_public_key.to_bytes(256, byteorder="big")
        )

    @patch("matzpin.black_side.receive_tcp_message")
    def test_black_to_red_loop_success(self, mock_receive_tcp):
        """Tests successful decryption and verification of custom wire protocol packets."""
        # Setup static operational key
        test_key = b"A_VERY_VERY_SECURE_32_BYTE_KEY!!"
        self.encryptor.key = test_key
        self.encryptor.last_red_client = ("127.0.0.1", 5555)

        # 1. Create a mock unencrypted packet payload
        raw_red_payload = b"Hello, Red Side!"
        
        # 2. Encrypt manually using AES-CBC to build valid mock incoming wire data
        iv = os.urandom(16)
        cipher = AES.new(test_key, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(raw_red_payload, AES.block_size))
        
        message_data = iv + ciphertext
        verify_input = test_key + message_data
        verify_hash = hashlib.sha256(verify_input).digest()[:8]
        
        # Mock payload returned by black_side (which excludes the 4-byte header length)
        mock_receive_tcp.return_value = verify_hash + message_data

        # 3. Prevent the while loop from going infinite
        def stop_loop(*args, **kwargs):
            self.encryptor.active = False

        self.mock_red_socket.sendto.side_effect = stop_loop

        # Run one iteration of the loop logic
        self.encryptor.black_to_red_loop()

        # Assertions: Verify packet was properly decrypted and forwarded out the Red NIC
        self.mock_red_socket.sendto.assert_called_once_with(raw_red_payload, ("127.0.0.1", 5555))

    @patch("matzpin.black_side.receive_tcp_message")
    def test_black_to_red_loop_corrupt_hash(self, mock_receive_tcp):
        """Ensures packets with modified or faulty signature hashes are dropped."""
        self.encryptor.key = b"A_VERY_VERY_SECURE_32_BYTE_KEY!!"
        
        # Construct completely bogus payload structure
        bad_hash = b"BAD_HASH"
        fake_message_data = b"A" * 32  # 16B IV + 16B Ciphertext block
        mock_receive_tcp.return_value = bad_hash + fake_message_data

        # Force break the loop immediately after evaluation by treating loop state as conditional
        # (Alternatively, toggle active inside a mocked check or patch)
        with patch.object(Encryptor, 'active', new_callable=unittest.mock.PropertyMock, create=True) as mock_active:
            mock_active.side_effect = [True, False]
            
            self.encryptor.black_to_red_loop()

        # Ensure the packet never got forwarded to red socket due to verification failure
        self.mock_red_socket.sendto.assert_not_called()

    def test_red_to_black_loop_success(self):
        """Validates encryption packaging routine: converts raw payload into framed network buffer."""
        test_key = b"A_VERY_VERY_SECURE_32_BYTE_KEY!!"
        self.encryptor.key = test_key
        
        raw_input_packet = b"Secret Payload"
        mock_sender_addr = ("127.0.0.1", 7777)

        # 1. Mock recvfrom to return our raw data, then kill loop on next spin
        def mock_recvfrom(bufsize):
            self.encryptor.active = False
            return raw_input_packet, mock_sender_addr

        self.mock_red_socket.recvfrom.side_effect = mock_recvfrom

        # Run loop
        self.encryptor.red_to_black_loop()

        # 2. Extract and decode the arguments sent to the pipeline TCP channel
        self.encryptor.black_connection.sendall.assert_called_once()
        sent_wire_packet = self.encryptor.black_connection.sendall.call_args[0][0]

        # 3. Parse and verify protocol framing fields manually
        total_length_header = int.from_bytes(sent_wire_packet[:4], byteorder="big")
        payload_body = sent_wire_packet[4:]
        
        self.assertEqual(total_length_header, len(payload_body))
        
        provided_hash = payload_body[:8]
        message_data = payload_body[8:]
        
        # Verify MAC Check matches
        expected_hash = hashlib.sha256(test_key + message_data).digest()[:8]
        self.assertEqual(provided_hash, expected_hash)

        # Verify underlying ciphertext payload content matches origin
        iv = message_data[:16]
        ciphertext = message_data[16:]
        cipher = AES.new(test_key, AES.MODE_CBC, iv=iv)
        decrypted_payload = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        self.assertEqual(decrypted_payload, raw_input_packet)
        self.assertEqual(self.encryptor.last_red_client, mock_sender_addr)


if __name__ == "__main__":
    unittest.main()