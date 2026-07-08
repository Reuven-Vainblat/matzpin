import unittest
from unittest.mock import MagicMock, patch
import socket
import struct
import hashlib
import time
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

# Assuming your class is inside a file named matzpin.py
from matzpin import Encryptor

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
        
        # Explicit initialization parameters
        self.encryptor.key = b"A_VERY_VERY_SECURE_32_BYTE_KEY!!"
        self.encryptor.current_key_id = 1
        self.encryptor.previous_key = None
        self.encryptor.previous_key_id = 0
        self.encryptor.sequence_counter = 0
        
        # Mock the black connection socket
        self.mock_black_conn = MagicMock()
        self.encryptor.black_connection = self.mock_black_conn

    def tearDown(self):
        pass

    ## ───────────────────────────────────────────────────────────
    ## Key Rolling & Derivation Logic Tests
    ## ───────────────────────────────────────────────────────────

    def test_parametric_derive_next_key_single_step(self):
        """Verify that _derive_next_key steps exactly 1 generation correctly."""
        initial_key = b"A_VERY_VERY_SECURE_32_BYTE_KEY!!"
        initial_id = 0
        
        target_key, target_id, prev_key, prev_id = self.encryptor._derive_next_key(
            initial_key, initial_id, n=1
        )
        
        expected_next_key = hashlib.sha256(initial_key).digest()
        self.assertEqual(target_key, expected_next_key)
        self.assertEqual(target_id, 1)
        self.assertEqual(prev_key, initial_key)
        self.assertEqual(prev_id, 0)

    def test_parametric_derive_next_key_multi_step(self):
        """Verify that _derive_next_key advances multiple steps (n=3) correctly."""
        initial_key = b"A_VERY_VERY_SECURE_32_BYTE_KEY!!"
        initial_id = 254 # Test wrap-around boundary logic % 25
        
        target_key, target_id, prev_key, prev_id = self.encryptor._derive_next_key(
            initial_key, initial_id, n=3
        )
        
        # Calculate expected iterations manually to ensure correctness
        key_1 = hashlib.sha256(initial_key).digest()  # ID: 255
        key_2 = hashlib.sha256(key_1).digest()        # ID: 0
        key_3 = hashlib.sha256(key_2).digest()        # ID: 1
        
        self.assertEqual(target_key, key_3)
        self.assertEqual(target_id, 1)
        self.assertEqual(prev_key, key_2)
        self.assertEqual(prev_id, 0)

    def test_local_time_triggered_key_roll(self):
        """Verify checking interval logic forces a stateful key roll after 1 hour."""
        old_key = self.encryptor.key
        old_id = self.encryptor.current_key_id
        
        # Simulate an expired 1-hour interval duration
        self.encryptor.last_roll_time = time.time() - 3601
        self.encryptor._check_and_apply_time_roll()
        
        self.assertNotEqual(self.encryptor.key, old_key)
        self.assertEqual(self.encryptor.current_key_id, old_id + 1)
        self.assertEqual(self.encryptor.previous_key, old_key)
        self.assertEqual(self.encryptor.previous_key_id, old_id)

    ## ───────────────────────────────────────────────────────────
    ## Sequence Counter & Sliding Window Tests
    ## ───────────────────────────────────────────────────────────

    def test_sequence_counter_increment_and_overflow(self):
        """Verify sequence counter increments correctly and triggers an overflow at the 64-bit boundary."""
        self.encryptor.sequence_counter = 0
        self.encryptor.active = True
        
        def recvfrom_side_effect(*args, **kwargs):
            self.encryptor.active = False
            return (b'\x00'*14 + b'\x45' + b'\x00'*19, ('addr', 0))
            
        self.mock_red_socket.recvfrom.side_effect = recvfrom_side_effect
        
        with patch('matzpin.parse_ethernet_header') as mock_parse, \
             patch('matzpin.IPV4_ETHERTYPE', 0x0800):
            
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
            self.mock_red_socket.recvfrom.side_effect = recvfrom_side_effect
            
            with self.assertRaises(RuntimeError) as context:
                self.encryptor.red_to_black_loop()
                
            self.assertIn("Sequence counter overflow!", str(context.exception))

    def test_black_to_red_replay_window_pre_check_tail(self):
        """Verify packets falling behind the trailing edge of the sliding window are dropped."""
        self.encryptor.replay_window.max_seen = 100
        self.encryptor.replay_window.window_size = 64
        self.encryptor.active = True
        
        stale_seq_num = 36 
        key_id_byte = struct.pack(">B", self.encryptor.current_key_id)
        counter_bytes = struct.pack(">Q", stale_seq_num)
        
        # Sliced input expects layout: verify_hash[8] + key_id_byte[1] + counter_bytes[8] + message_data[...]
        payload = b'\x00'*8 + key_id_byte + counter_bytes + b'\x00'*32
        
        def recv_side_effect(*args, **kwargs):
            self.encryptor.active = False
            return payload
        
        with patch('matzpin.encryptor_utils.receive_tcp_message', side_effect=recv_side_effect):
            self.encryptor.black_to_red_loop()

    ## ───────────────────────────────────────────────────────────
    ## Cryptographic Integrity & Dynamic Remote Catch-Up Tests
    ## ───────────────────────────────────────────────────────────

    def test_black_to_red_cryptographic_verification_failure(self):
        """Verify packets with tampered payload or sequence counters fail the integrity check."""
        self.encryptor.replay_window.max_seen = 10
        self.encryptor.active = True
        
        valid_seq = 15
        key_id_byte = struct.pack(">B", self.encryptor.current_key_id)
        counter_bytes = struct.pack(">Q", valid_seq)
        message_data = b'\x00'*32 
        
        bad_verify_hash = b'\xDEADBEEF\x00\x00\x00\x00'[:8]
        payload = bad_verify_hash + key_id_byte + counter_bytes + message_data
        
        def recv_side_effect(*args, **kwargs):
            self.encryptor.active = False
            return payload
        
        with patch('matzpin.encryptor_utils.receive_tcp_message', side_effect=recv_side_effect):
            self.encryptor.black_to_red_loop()

    def test_black_to_red_speculative_remote_catch_up(self):
        """Verify a wire packet showing a higher key_id triggers parametric rollahead calculations."""
        self.encryptor.replay_window.max_seen = 10
        self.encryptor.active = True
        
        # Target a remote loop-ahead distance of 5 key increments
        future_key_id = (self.encryptor.current_key_id + 5) % 256
        valid_seq = 12
        
        # Deriving the verified speculative key to sign valid test packet
        target_key, _, spec_prev, spec_prev_id = self.encryptor._derive_next_key(
            self.encryptor.key, self.encryptor.current_key_id, n=5
        )
        
        key_id_byte = struct.pack(">B", future_key_id)
        counter_bytes = struct.pack(">Q", valid_seq)
        
        iv = b'H'*16
        cipher = AES.new(target_key, AES.MODE_CBC, iv=iv)
        raw_ip_payload = b'\x45\x00\x00\x28' + b'\x00'*16 
        ciphertext = cipher.encrypt(pad(raw_ip_payload, AES.block_size))
        message_data = iv + ciphertext
        
        verify_input = target_key + key_id_byte + counter_bytes + message_data
        calculated_hash = hashlib.sha256(verify_input).digest()[:8]
        full_payload = calculated_hash + key_id_byte + counter_bytes + message_data
        
        def recv_side_effect(*args, **kwargs):
            self.encryptor.active = False
            return full_payload
            
        with patch('matzpin.encryptor_utils.receive_tcp_message', side_effect=recv_side_effect), \
             patch('matzpin.build_ethernet_frame', return_value=b'ETH_FRAME_OK'), \
             patch.object(self.encryptor, '_resolve_mac', return_value=b'\x22'*6):
             
            self.encryptor.black_to_red_loop()
            
            # Assert local active cryptographic parameters caught up statefully
            self.assertEqual(self.encryptor.current_key_id, future_key_id)
            self.assertEqual(self.encryptor.key, target_key)
            self.assertEqual(self.encryptor.previous_key, spec_prev)
            self.assertEqual(self.encryptor.previous_key_id, spec_prev_id)

    def test_black_to_red_successful_crypto_and_window_commit(self):
        """Verify standard synchronized execution paths decrypt and record valid messages correctly."""
        self.encryptor.replay_window.max_seen = 10
        self.encryptor.active = True
        
        valid_seq = 11
        key_id_byte = struct.pack(">B", self.encryptor.current_key_id)
        counter_bytes = struct.pack(">Q", valid_seq)
        
        iv = b'H'*16
        cipher = AES.new(self.encryptor.key, AES.MODE_CBC, iv=iv)
        raw_ip_payload = b'\x45\x00\x00\x28' + b'\x00'*16 
        padded_ip = pad(raw_ip_payload, AES.block_size)
        ciphertext = cipher.encrypt(padded_ip)
        message_data = iv + ciphertext
        
        verify_input = self.encryptor.key + key_id_byte + counter_bytes + message_data
        calculated_hash = hashlib.sha256(verify_input).digest()[:8]
        full_payload = calculated_hash + key_id_byte + counter_bytes + message_data
        
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

    ## ───────────────────────────────────────────────────────────
    ## Full Integration: Real Loop Execution & Verbose Prints
    ## ───────────────────────────────────────────────────────────
    def test_encryption_and_decryption(self):
            """Appended Test: Runs your REAL red_to_black_loop and black_to_red_loop methods 
            end-to-end to verify that instance members and crypto perform successfully."""
            print("\n\n" + "═"*60)
            print("ENCRYPTION-DECRYPTION TEST:")
            print("═"*60)

            # 1. Setup the real plaintext string inside a simulated IP packet
            english_message = "a very secret message!"
            print(f"Message: '{english_message}'")
            
            # Build 20-byte IP header (src: 192.168.1.5, dst: 192.168.1.20)
            ip_header = b'\x45\x00\x00\x28' + b'\x00'*8 + socket.inet_aton("192.168.1.5") + socket.inet_aton("192.168.1.20")
            raw_ip_packet = ip_header + english_message.encode('utf-8')
            mock_incoming_ethernet = b'\x11\x22\x33\x44\x55\x66' + b'\xaa\xbb\xcc\xdd\xee\xff' + b'\x08\x00' + raw_ip_packet

            # Initialize the target object's sequence counter state
            self.encryptor.sequence_counter = 500
            self.encryptor.active = True
            
            print(f"\n---red_to_black_loop ---")
            print(f"initial state: key={self.encryptor.key}, seq={self.encryptor.sequence_counter}")

            # read and send mocks
            intercepted_wire_packets = []
            self.mock_black_conn.sendall.side_effect = lambda data: intercepted_wire_packets.append(data)
            self.encryptor.red_socket = MagicMock()
            
            def safe_red_recv(bufsize):
                self.encryptor.active = False 
                return (mock_incoming_ethernet, ('127.0.0.1', 0))
                
            self.encryptor.red_socket.recvfrom.side_effect = safe_red_recv

            with patch('matzpin.parse_ethernet_header') as mock_parse, \
                patch('matzpin.IPV4_ETHERTYPE', 0x0800), \
                patch('matzpin.ARP_ETHERTYPE', 0x0806):
                
                mock_parse.return_value = (b'\x11\x22\x33\x44\x55\x66', b'\xaa\xbb\xcc\xdd\xee\xff', 0x0800, raw_ip_packet)
                
                # --- CALL THE REAL ENCRYPTION LOOP FUNCTION ---
                self.encryptor.red_to_black_loop()

            # Validate that something came out on the wire
            self.assertEqual(len(intercepted_wire_packets), 1, "The real red_to_black_loop didn't send anything!")
            wire_packet = intercepted_wire_packets[0]

            print(f"post-encryption state: seq={self.encryptor.sequence_counter} (Successfully incremented!)")

            # Parse the raw bytes produced on the wire to print them out
            header_length = struct.unpack(">I", wire_packet[0:4])[0]
            payload_body = wire_packet[4:] # This is exactly what receive_tcp_message returns!
            
            print(f"PACKET ANALYSIS\n")
            print(f"-> 4B TCP Framed Length:        {header_length} bytes")
            print(f"-> Sliced Integrity Hash (8B):  {payload_body[0:8].hex()}")
            print(f"-> Sliced Key ID (1B):          {payload_body[8:9].hex()} ({struct.unpack('>B', payload_body[8:9])[0]})")
            print(f"-> Sliced Sequence Counter(8B): {payload_body[9:17].hex()} ({struct.unpack('>Q', payload_body[9:17])[0]})")
            print(f"-> Raw IV + Ciphertext Block:    {payload_body[17:].hex()}")

            print("\n---black_to_red_loop ---")
            self.encryptor.active = True

            def safe_black_recv(conn):
                self.encryptor.active = False
                return payload_body

            with patch('matzpin.encryptor_utils.receive_tcp_message', side_effect=safe_black_recv):
                captured_decrypted_ip_bytes = []
                
                with patch('matzpin.build_ethernet_frame') as mock_build_eth, \
                    patch.object(self.encryptor, '_resolve_mac', return_value=b'\x11\x22\x33\x44\x55\x66'), \
                    patch('matzpin.IPV4_ETHERTYPE', 0x0800):
                    
                    def spy_build_ethernet(dst_mac, src_mac, ethertype, ip_bytes):
                        captured_decrypted_ip_bytes.append(ip_bytes)
                        return b'MOCK_FINAL_FRAME'
                    
                    mock_build_eth.side_effect = spy_build_ethernet
                    print(f"output packets amount before calling black_to_red_loop: {len(captured_decrypted_ip_bytes)}")
                    # --- CALL THE REAL DECRYPTION LOOP FUNCTION ---
                    self.encryptor.black_to_red_loop()

            # Check results
            self.assertEqual(len(captured_decrypted_ip_bytes), 1, "The real black_to_red_loop failed to output decrypted packet!")
            decrypted_packet = captured_decrypted_ip_bytes[0]

            # Extract the embedded plain text string from the decrypted IP payload array (skipping the 20 byte header)
            decrypted_string = decrypted_packet[20:].decode('utf-8')
            print(f"decrypted output after calling black_to_red_loop: '{decrypted_string}'")

            # Confirm equality!
            self.assertEqual(decrypted_string, english_message)


    def test_the_matzpin_logs(self):
        log_path = "/home/matzpin/matzpin.log"
        
        print("═" * 50)
        print(" [CHECK] STARTING LOG FILE VERIFICATION")
        print("═" * 50)
        
        self.assertEqual(os.path.exists(log_path), True,
                        f"The log file does not exist at: '{log_path}'")
                    
        file_size = os.path.getsize(log_path)
        self.assertNotEqual(file_size, 0,
                        "The log file exists, but it is completely EMPTY")
        
        print(f"SUCCESS: Log file found at '{log_path}' and non-empty (size: {file_size} bytes).")

        print("\n LIVE LOG FILE CONTENTS:\n")
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as log_file:
                contents = log_file.read()
                print(contents)
        except Exception as e:
            print(f"ERROR: Failed to read the file. Reason: {e}")

if __name__ == '__main__':
    unittest.main()