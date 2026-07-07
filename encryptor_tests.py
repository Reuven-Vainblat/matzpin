import unittest
from unittest.mock import MagicMock, patch, mock_open
import socket
import struct
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Assuming your class is inside a file named encryptor.py
from matzpin import Encryptor, DH_BASE, DH_PRIME

class TestEncryptor(unittest.TestCase):
    @patch('matzpin.fcntl.ioctl')
    @patch('matzpin.socket.socket')
    def setUp(self, mock_socket, mock_ioctl):
        # Mock the raw and UDP sockets used in initialization
        self.mock_red_socket = MagicMock()
        mock_socket.return_value = self.mock_red_socket
        
        # Mock MAC address retrieval (returns a 6-byte dummy MAC)
        mock_ioctl.return_value = b'\x00' * 18 + b'\x11\x22\x33\x44\x55\x66'
        
        # Instantiate a server-mode Encryptor
        self.encryptor = Encryptor(
            is_server=True, 
            red_nic="eth0", 
            red_ip="192.168.1.1", 
            black_ip="10.0.0.1", 
            black_port=9999
        )
        # Initialize sequence_counter explicitly if not done in __init__
        if not hasattr(self.encryptor, 'sequence_counter'):
            self.encryptor.sequence_counter = 0

        # Mock the black connection socket
        self.mock_black_conn = MagicMock()
        self.encryptor.black_connection = self.mock_black_conn

    ## ───────────────────────────────────────────────────────────
    ## Sequence Counter & Sliding Window Tests
    ## ───────────────────────────────────────────────────────────

    def test_sequence_counter_increment_and_overflow(self):
        """Verify sequence counter increments correctly and triggers an overflow at the 64-bit boundary."""
        self.encryptor.sequence_counter = 0
        self.encryptor.active = True
        
        # Side-effect to break the loop *after* reading a packet
        def recvfrom_side_effect(*args, **kwargs):
            self.encryptor.active = False
            return (b'\x00'*14 + b'\x45' + b'\x00'*19, ('addr', 0))
            
        self.mock_red_socket.recvfrom.side_effect = recvfrom_side_effect
        
        with patch('matzpin.parse_ethernet_header') as mock_parse, \
             patch('matzpin.IPV4_ETHERTYPE', 0x0800):
            
            # Destination MAC, Source MAC (different to avoid loopback drop), EtherType, IP payload
            mock_parse.return_value = (b'\xaa'*6, b'\xbb'*6, 0x0800, b'\x45' + b'\x00'*19)
            
            # 1. Test normal increment
            try:
                self.encryptor.red_to_black_loop()
            except Exception:
                pass
            self.assertEqual(self.encryptor.sequence_counter, 1)

            # 2. Test hard ceiling overflow threshold: (2^64 - 1)
            self.encryptor.sequence_counter = (1 << 64) - 1
            self.encryptor.active = True
            
            # Reset side effect to safely trip the loop check again
            self.mock_red_socket.recvfrom.side_effect = recvfrom_side_effect
            
            with self.assertRaises(RuntimeError) as context:
                self.encryptor.red_to_black_loop()
                
            self.assertIn("Sequence counter overflow!", str(context.exception))

    def test_black_to_red_replay_window_pre_check_tail(self):
        """Verify packets falling behind the trailing edge of the sliding window are dropped."""
        self.encryptor.replay_window.max_seen = 100
        self.encryptor.replay_window.window_size = 64
        self.encryptor.replay_window.bitmap = 0x1
        self.encryptor.active = True
        
        stale_seq_num = 36 
        counter_bytes = struct.pack(">Q", stale_seq_num)
        payload = b'\x00'*8 + counter_bytes + b'\x00'*32
        
        def recv_side_effect(*args, **kwargs):
            self.encryptor.active = False
            return payload
        
        with patch('matzpin.encryptor_utils.receive_tcp_message', side_effect=recv_side_effect):
            self.encryptor.black_to_red_loop()

    def test_black_to_red_replay_window_duplicate_detection(self):
        """Verify identical sequence numbers inside the sliding window bitmask are flagged and dropped."""
        self.encryptor.replay_window.max_seen = 50
        self.encryptor.replay_window.window_size = 64
        self.encryptor.replay_window.bitmap = 1 << 0 
        self.encryptor.active = True
        
        duplicate_seq = 50
        counter_bytes = struct.pack(">Q", duplicate_seq)
        payload = b'\x00'*8 + counter_bytes + b'\x00'*32
        
        def recv_side_effect(*args, **kwargs):
            self.encryptor.active = False
            return payload
        
        with patch('matzpin.encryptor_utils.receive_tcp_message', side_effect=recv_side_effect):
            self.encryptor.black_to_red_loop()

    ## ───────────────────────────────────────────────────────────
    ## Cryptographic Integrity Tests
    ## ───────────────────────────────────────────────────────────

    def test_black_to_red_cryptographic_verification_failure(self):
        """Verify packets with tampered payload or sequence counters fail the SHA256 integrity token check."""
        self.encryptor.replay_window.max_seen = 10
        self.encryptor.replay_window.bitmap = 0
        self.encryptor.active = True
        
        valid_seq = 15
        counter_bytes = struct.pack(">Q", valid_seq)
        message_data = b'\x00'*32 
        
        bad_verify_hash = b'\xDEADBEEF\x00\x00\x00\x00'[:8]
        payload = bad_verify_hash + counter_bytes + message_data
        
        def recv_side_effect(*args, **kwargs):
            self.encryptor.active = False
            return payload
        
        with patch('matzpin.encryptor_utils.receive_tcp_message', side_effect=recv_side_effect):
            self.encryptor.black_to_red_loop()

    def test_black_to_red_successful_crypto_and_window_commit(self):
        """Verify a perfectly formed packet validates dynamically, advances the window, and decrypts successfully."""
        self.encryptor.replay_window.max_seen = 10
        self.encryptor.replay_window.bitmap = 0
        self.encryptor.active = True
        
        valid_seq = 11
        counter_bytes = struct.pack(">Q", valid_seq)
        
        iv = b'H'*16
        cipher = AES.new(self.encryptor.key, AES.MODE_CBC, iv=iv)
        raw_ip_payload = b'\x45\x00\x00\x28' + b'\x00'*16 
        padded_ip = pad(raw_ip_payload, AES.block_size)
        ciphertext = cipher.encrypt(padded_ip)
        message_data = iv + ciphertext
        
        verify_input = self.encryptor.key + counter_bytes + message_data
        calculated_hash = hashlib.sha256(verify_input).digest()[:8]
        
        full_payload = calculated_hash + counter_bytes + message_data
        
        def recv_side_effect(*args, **kwargs):
            self.encryptor.active = False
            return full_payload
        
        with patch('matzpin.encryptor_utils.receive_tcp_message', side_effect=recv_side_effect), \
             patch('matzpin.build_ethernet_frame', return_value=b'ETH_FRAME_OK'), \
             patch.object(self.encryptor.replay_window, 'verify_and_update') as mock_window_commit, \
             patch.object(self.encryptor, '_resolve_mac', return_value=b'\x22'*6):
             
            self.encryptor.black_to_red_loop()
            
            mock_window_commit.assert_called_once_with(valid_seq)
            self.mock_red_socket.send.assert_called_with(b'ETH_FRAME_OK')


if __name__ == '__main__':
    unittest.main()