import socket
import struct
import fcntl
import nat
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import encryptor_utils
import secrets
import os
import sys
import json
import time  # For tracking the 1-hour interval

from arp_handler import (
    ArpTable, parse_ethernet_header, build_ethernet_frame,
    parse_arp, build_arp_reply, build_arp_request,
    ARP_ETHERTYPE, IPV4_ETHERTYPE,
    ARP_REQUEST, ARP_REPLY, BROADCAST_MAC,
)

ETH_P_ALL = 3  # read all protocols

DH_BASE = 2
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 
    16
)

class Encryptor:
    def __init__(self, is_server, red_nic, red_ip, black_ip, black_port=9999):
        self.is_server = is_server
        self.red_nic = red_nic
        self.red_ip = red_ip
        self.black_ip = black_ip
        self.black_port = black_port
        self.server_socket = None
        self.black_connection = None

        self.red_socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.red_socket.bind((red_nic, 0))

        self.red_mac = self._get_nic_mac(red_nic)
        self.arp_table = ArpTable()

        # --- Key Rolling Management State ---
        self.current_key_id = 0
        self.key = b"A_VERY_VERY_SECURE_32_BYTE_KEY!!"
        self.previous_key = None              # Kept for grace period compatibility
        self.previous_key_id = None           # Tracks the ID of the fallback key
        self.last_roll_time = time.time()

        self.active = True
        self.replay_window = encryptor_utils.ReplayWindow(window_size=64)
        self.sequence_counter = 0 

        self.red_sent_cnt = 0
        self.red_drop_cnt = 0
        self.black_sent_cnt = 0
        self.black_drop_cnt = 0
        self.bytes_counter = 0

        if sys.platform.startswith('win'):
            self.log_file_path = "matzpin.log"
        else:
            self.log_file_path = "/var/log/matzpin.log"

    # ──────────────────────────────────────
    # N-Step Parametric Key Rolling Logic
    # ──────────────────────────────────────

    def _derive_next_key(self, current_key, current_key_id, n=1):
        """Generic function to roll forward n generations.
        Returns (target_key, target_key_id, intermediate_prev_key, intermediate_prev_key_id).
        """
        check_key = current_key
        temp_id = current_key_id
        temp_prev = None
        temp_prev_id = None
        
        for _ in range(n):
            temp_prev = check_key
            temp_prev_id = temp_id
            check_key = hashlib.sha256(check_key).digest()
            temp_id = (temp_id + 1) % 256
            
        return check_key, temp_id, temp_prev, temp_prev_id

    def _roll_key_local(self):
        """Derives the next scheduled key using the unified n-step roll configuration."""
        old_id = self.current_key_id
        self.key, self.current_key_id, self.previous_key, self.previous_key_id = self._derive_next_key(
            self.key, old_id, n=1
        )
        self.last_roll_time = time.time()
        self._stream_log("KEY_ROLL", f"Key rolled locally from ID {old_id} to {self.current_key_id}")

    def _check_and_apply_time_roll(self):
        """Rolls keys automatically if 1 hour (3600 seconds) has elapsed."""
        if time.time() - self.last_roll_time >= 3600:
            self._roll_key_local()

    # ──────────────────────────────────────
    # Network helpers
    # ──────────────────────────────────────

    def _stream_log(self, category, message):
        """Builds and appends telemetry logs as a single-line JSON locally."""
        try:
            total_red = self.red_sent_cnt + self.red_drop_cnt
            red_drop_pct = (self.red_drop_cnt / total_red * 100) if total_red > 0 else 0.0
            
            total_black = self.black_sent_cnt + self.black_drop_cnt
            black_drop_pct = (self.black_drop_cnt / total_black * 100) if total_black > 0 else 0.0
            
            matzpin_type = "SERVER" if self.is_server else "HOST"

            log_payload = {
                "log_type": matzpin_type,
                "category": category,
                "total_transferred_bytes": self.bytes_counter,
                "red": {
                    "sent": self.red_sent_cnt,
                    "drop": self.red_drop_cnt,
                    "drop_percentage": round(red_drop_pct, 1),
                    "ddos_alert": (red_drop_pct > 30.0 and total_red > 10),
                    "port": self.red_nic,
                    "ip": self.red_ip
                },
                "black": {
                    "sent": self.black_sent_cnt,
                    "drop": self.black_drop_cnt,
                    "drop_percentage": round(black_drop_pct, 1),
                    "ddos_alert": (black_drop_pct > 30.0 and total_black > 10),
                    "port": self.black_port,
                    "ip": self.black_ip
                },
                "log": message
            }
            
            log_line = json.dumps(log_payload)
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
        except Exception:
            pass

    @staticmethod
    def _get_nic_mac(nic_name):
        SIOCGIFHWADDR = 0x8927
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            info = fcntl.ioctl(
                s.fileno(), SIOCGIFHWADDR,
                struct.pack('256s', nic_name.encode()[:15]))
        finally:
            s.close()
        return bytes(info[18:24])

    def connect(self):
        if self.is_server:
            self._setup_receiver()
        else:
            self._setup_sender()

    def _setup_receiver(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.black_ip, self.black_port))
        self.server_socket.listen(1)
        self.black_connection, address = self.server_socket.accept()
        self._stream_log("NEW_MATZPIN", f"New TCP receiver")

    def _setup_sender(self):
        self.black_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.black_connection.connect((self.black_ip, self.black_port))
        self._stream_log("NEW_MATZPIN", f"New TCP sender")

    def sync_keys(self):
        self._stream_log("KEY_SYNC", f"Starting Diffie-Hellman Key Exchange.")

        private_key = secrets.randbits(256)
        public_key = pow(DH_BASE, private_key, DH_PRIME)
        pub_bytes = public_key.to_bytes(256, byteorder="big")
        
        if self.is_server:
            self.black_connection.sendall(pub_bytes)
            peer_pub_bytes = encryptor_utils.receive_exact_bytes(self.black_connection, 256)
        else:
            peer_pub_bytes = encryptor_utils.receive_exact_bytes(self.black_connection, 256)
            self.black_connection.sendall(pub_bytes)
            
        peer_public_key = int.from_bytes(peer_pub_bytes, byteorder="big")
        shared_secret = pow(peer_public_key, private_key, DH_PRIME)
        shared_secret_bytes = shared_secret.to_bytes(256, byteorder="big")

        # Load clean DH handshake context
        self.key = hashlib.sha256(shared_secret_bytes).digest()
        self.current_key_id = 0
        self.previous_key = None
        self.previous_key_id = None
        self.last_roll_time = time.time()
        
        self._stream_log("KEY_SYNC", f"Key exchange successful. Shared initial Key ID 0 loaded.")

    def _handle_arp(self, frame):
        parsed = parse_ethernet_header(frame)
        if parsed is None:
            return None
        _dst_mac, _src_mac, _ethertype, payload = parsed

        arp = parse_arp(payload)
        if arp is None:
            return None

        self.arp_table.update(arp['sender_ip'], arp['sender_mac'])
        
        if arp['opcode'] == ARP_REQUEST:
            self._stream_log("ARP", f"{arp['sender_ip']} is asking: Who has {arp['target_ip']}?")
        elif arp['opcode'] == ARP_REPLY:
            self._stream_log("ARP", f"Learned {arp['sender_ip']} -> {arp['sender_mac'].hex(':')}")

        if arp['opcode'] == ARP_REQUEST:
            if arp['target_ip'] == arp['sender_ip']:
                return None
                
            if arp['target_ip'] == self.red_ip or not self.is_server:
                reply = build_arp_reply(
                    self.red_mac, arp['target_ip'],
                    arp['sender_mac'], arp['sender_ip'])
                self._stream_log("ARP", f"Replying: {arp['target_ip']} is-at {self.red_mac.hex(':')}")
                return reply
        return None

    def _resolve_mac(self, dst_ip):
        mac = self.arp_table.lookup(dst_ip)
        if mac is not None:
            return mac

        arp_req = build_arp_request(self.red_mac, self.red_ip, dst_ip)
        self.red_socket.send(arp_req)
        self._stream_log("ARP", f"Sent who-has for {dst_ip}")
        return BROADCAST_MAC

    # ──────────────────────────────────────
    # Data-plane loops
    # ──────────────────────────────────────

    def red_to_black_loop(self):
        while self.active:
            try:
                packet_data, _address = self.red_socket.recvfrom(65535)

                parsed = parse_ethernet_header(packet_data)
                if parsed is None:
                    continue
                dst_mac, src_mac, ethertype, ip_bytes = parsed

                if src_mac == self.red_mac:
                    continue

                if ethertype == ARP_ETHERTYPE:
                    reply = self._handle_arp(packet_data)
                    if reply:
                        self.red_socket.send(reply)
                    continue

                if ethertype != IPV4_ETHERTYPE:
                    continue

                if len(ip_bytes) >= 20:
                    src_ip = socket.inet_ntoa(ip_bytes[12:16])
                    self.arp_table.update(src_ip, src_mac)

                if not self.is_server:
                    ip_bytes = nat.nat_outbound(ip_bytes)
                    if ip_bytes is None:
                        continue
                
                # Check for hourly timer trigger before encoding outbound wires
                self._check_and_apply_time_roll()
                
                self.sequence_counter += 1
                if self.sequence_counter > (1 << 64) - 1:
                    raise RuntimeError("Sequence counter overflow! Crypto context exhausted.")
                
                counter_bytes = struct.pack(">Q", self.sequence_counter)
                key_id_byte = struct.pack(">B", self.current_key_id)

                # Encrypt with active key variable
                iv = os.urandom(16)
                cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
                padded_data = pad(ip_bytes, AES.block_size)
                ciphertext = cipher.encrypt(padded_data)

                encrypted_message_data = iv + ciphertext

                # Compute integrity hash context matching current key
                verify_input = self.key + key_id_byte + counter_bytes + encrypted_message_data
                verify_hash = hashlib.sha256(verify_input).digest()[:8]

                payload_body = verify_hash + key_id_byte + counter_bytes + encrypted_message_data
                total_payload_length = len(payload_body)
                
                header_length_bytes = total_payload_length.to_bytes(4, byteorder="big")
                wire_packet = header_length_bytes + payload_body

                self.black_connection.sendall(wire_packet)
                
                self.red_sent_cnt += 1
                self.bytes_counter += len(wire_packet)
                self._stream_log("MGMT", f"Successfully delivered packet from red to black. ({len(wire_packet)} encrypted bytes).")
            except RuntimeError:
                # Re-raise fatal crypto exhaustion errors so the thread halts and tests can catch it
                raise
            except Exception as e:
                self.black_drop_cnt += 1
                self._stream_log("PACKET_DROP", f"RED line: Exception while handling package encryption: {str(e)}.")
    
    def black_to_red_loop(self):
        while self.active:
            try:
                payload_received = encryptor_utils.receive_tcp_message(self.black_connection)
                if payload_received is None:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", "BLACK line: Invalid TCP message length")
                    continue

                if len(payload_received) < 49:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", f"BLACK line: Packet size header too small ({len(payload_received)} bytes).")
                    continue

                # --- Slice Fields ---
                provided_verify_hash = payload_received[0:8]
                key_id_byte          = payload_received[8:9]
                counter_bytes        = payload_received[9:17]
                message_data         = payload_received[17:]

                remote_key_id = struct.unpack(">B", key_id_byte)[0]
                seq_num = struct.unpack(">Q", counter_bytes)[0]

                # --- Sliding Window Pre-Check ---
                if seq_num <= self.replay_window.max_seen - self.replay_window.window_size:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", f"BLACK line: REPLAY dropped: outside window tail.")
                    continue
                
                if seq_num <= self.replay_window.max_seen:
                    bit_position = self.replay_window.max_seen - seq_num
                    if (self.replay_window.bitmap & (1 << bit_position)) != 0:
                        self.black_drop_cnt += 1
                        self._stream_log("PACKET_DROP", f"BLACK line: REPLAY dropped: Duplicate.")
                        continue

                # --- Speculative Key Selection / Calculation ---
                target_decryption_key = None
                speculative_previous_key = None
                speculative_previous_key_id = None

                if remote_key_id == self.current_key_id:
                    target_decryption_key = self.key
                elif remote_key_id == self.previous_key_id and self.previous_key is not None:
                    target_decryption_key = self.previous_key
                else:
                    # Look ahead using the flexible parametric roll function
                    distance = (remote_key_id - self.current_key_id) % 256
                    if 0 < distance <= 128:
                        target_decryption_key, _, speculative_previous_key, speculative_previous_key_id = (
                            self._derive_next_key(self.key, self.current_key_id, n=distance)
                        )
                    else:
                        self.black_drop_cnt += 1
                        self._stream_log("PACKET_DROP", f"BLACK line: Unresolvable distant Key ID: {remote_key_id}")
                        continue

                # --- Validate Hash Integrity Prior to Processing Actions ---
                verify_input = target_decryption_key + key_id_byte + counter_bytes + message_data
                calculated_hash = hashlib.sha256(verify_input).digest()[:8]
                
                if calculated_hash != provided_verify_hash:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", f"BLACK line: Verification failed for Key ID {remote_key_id}.")
                    continue

                # --- Cryptographic Proof Obtained: Commit State Variables ---
                if remote_key_id != self.current_key_id and remote_key_id != self.previous_key_id:
                    self.key = target_decryption_key
                    self.previous_key = speculative_previous_key
                    self.previous_key_id = speculative_previous_key_id
                    self.current_key_id = remote_key_id
                    self.last_roll_time = time.time()
                    self._stream_log("KEY_ROLL", f"Caught up to peer verified Key ID: {remote_key_id}")

                # Commit sequence number to sliding anti-replay tracking window
                self.replay_window.verify_and_update(seq_num)

                # --- Decrypt Payload Content ---
                iv = message_data[:16]
                ciphertext = message_data[16:]

                cipher = AES.new(target_decryption_key, AES.MODE_CBC, iv=iv)
                encrypted_padded = cipher.decrypt(ciphertext)
                ip_bytes = unpad(encrypted_padded, AES.block_size)

                if len(ip_bytes) > 1500:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", "BLACK line: Decrypted IP payload exceeds MTU.")
                    continue

                if not self.is_server:
                    ip_bytes = nat.nat_outbound(ip_bytes)
                    if ip_bytes is None:
                        self.black_drop_cnt += 1
                        self._stream_log("PACKET_DROP", "BLACK line: Inbound NAT translation failed.")
                        continue

                if len(ip_bytes) >= 20:
                    dst_ip = socket.inet_ntoa(ip_bytes[16:20])
                    dst_mac = self._resolve_mac(dst_ip)
                else:
                    dst_mac = BROADCAST_MAC

                final_ethernet_frame = build_ethernet_frame(
                    dst_mac, self.red_mac, IPV4_ETHERTYPE, ip_bytes)

                if final_ethernet_frame is None:
                    self.black_drop_cnt += 1
                    continue

                self.red_socket.send(final_ethernet_frame)
                
                self.black_sent_cnt += 1
                self.bytes_counter += len(final_ethernet_frame)
                self._stream_log("MGMT", f"Successfully delivered packet from black to red. ({len(ip_bytes)} decrypted bytes, {len(final_ethernet_frame)} total bytes).")

            except ValueError:
                self.black_drop_cnt += 1
                self._stream_log("ALERT", "BLACK line: Decryption Error: Padding is corrupted or wrong key used.")
            except Exception as e:
                self.black_drop_cnt += 1
                self._stream_log("ALERT", f"BLACK line: Exception while handling package decryption: {str(e)}.")