import socket
import struct
import fcntl
import nat
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import encryptor_utils
import secrets
import hashlib
import os
import sys
import json

from arp_handler import (
    ArpTable, parse_ethernet_header, build_ethernet_frame,
    parse_arp, build_arp_reply, build_arp_request,
    ARP_ETHERTYPE, IPV4_ETHERTYPE,
    ARP_REQUEST, ARP_REPLY, BROADCAST_MAC,
)

ETH_P_ALL = 3  # read all protocols


# Base (Generator)
DH_BASE = 2

# Prime Modulus (p)
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

        # Retrieve our own MAC from the NIC
        self.red_mac = self._get_nic_mac(red_nic)

        # ARP table for red-side MAC resolution
        self.arp_table = ArpTable()

        self.key = b"A_VERY_VERY_SECURE_32_BYTE_KEY!!"  

        self.active = True

        self.replay_window = encryptor_utils.ReplayWindow(window_size=64)
        self.sequence_counter = 0  # Initialize packet counter for sequence numbers

        self.red_sent_cnt = 0
        self.red_drop_cnt = 0
        self.black_sent_cnt = 0
        self.black_drop_cnt = 0
        self.bytes_counter = 0

        # Determine log file path based on OS
        if sys.platform.startswith('win'):
            self.log_file_path = "matzpin.log"
        else:
            self.log_file_path = "/var/log/matzpin.log"

    # ──────────────────────────────────────
    # Network helpers
    # ──────────────────────────────────────

    def _stream_log(self, category, message):
        """Builds and appends telemetry logs as a single-line JSON locally to a platform-specific file."""
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
            
            # Serialize to a single-line JSON string
            log_line = json.dumps(log_payload)
            
            # Append to Local Log File
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")

        except Exception:
            pass # Fail silently to prioritize core encryption throughput

    # ──────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────

    @staticmethod
    def _get_nic_mac(nic_name):
        """Read the hardware (MAC) address of a network interface via ioctl."""
        SIOCGIFHWADDR = 0x8927
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            info = fcntl.ioctl(
                s.fileno(), SIOCGIFHWADDR,
                struct.pack('256s', nic_name.encode()[:15]))
        finally:
            s.close()
        return bytes(info[18:24])

    # ──────────────────────────────────────
    # Black-side connection setup
    # ──────────────────────────────────────

    def connect(self):
        """Establishes the connection based on the mode."""
        if self.is_server:
            self._setup_receiver()
        else:
            self._setup_sender()

    def _setup_receiver(self):
        # Create a TCP/IP socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow immediate reuse of the port to prevent "Address already in use" errors
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.server_socket.bind((self.black_ip, self.black_port))
        self.server_socket.listen(1)

        # Block and wait for incoming connection
        self.black_connection, address = self.server_socket.accept()
        self._stream_log("NEW_MATZPIN", f"New TCP receiver")

    def _setup_sender(self):
        # Create a TCP/IP socket
        self.black_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Attempt to connect to the receiver
        self.black_connection.connect((self.black_ip, self.black_port))
        self._stream_log("NEW_MATZPIN", f"New TCP sender")

    def sync_keys(self):
        self._stream_log("KEY_SYNC", f"Starting Diffie-Hellman Key Exchange.")

        private_key = secrets.randbits(256)

        # pow(base, exponent, modulus)* 
        public_key = pow(DH_BASE, private_key, DH_PRIME)
        pub_bytes = public_key.to_bytes(256, byteorder="big")
        
        if self.is_server:
            self.black_connection.sendall(pub_bytes)
            peer_pub_bytes = encryptor_utils.receive_exact_bytes(self.black_connection, 256)
        else:
            peer_pub_bytes = encryptor_utils.receive_exact_bytes(self.black_connection, 256)
            self.black_connection.sendall(pub_bytes)
            
        peer_public_key = int.from_bytes(peer_pub_bytes, byteorder="big")
        
        # calculate the shared secret (g^ab mod p)
        shared_secret = pow(peer_public_key, private_key, DH_PRIME)
        
        shared_secret_bytes = shared_secret.to_bytes(256, byteorder="big")

        # using sha256 to create a equalized key for encryption
        self.key = hashlib.sha256(shared_secret_bytes).digest()
        
        self._stream_log("KEY_SYNC", f"Key exchange successful")

    # ──────────────────────────────────────
    # ARP handling on the red side
    # ──────────────────────────────────────

    def _handle_arp(self, frame):
        """Process an ARP frame received on the red side.

        * Always learns the sender's MAC.
        * If it is an ARP request for *our* red IP (or we are the host acting as a proxy), sends a reply.

        Returns an ARP reply frame (bytes) to transmit, or None.
        """
        parsed = parse_ethernet_header(frame)
        if parsed is None:
            return None
        _dst_mac, _src_mac, _ethertype, payload = parsed

        arp = parse_arp(payload)
        if arp is None:
            return None

        # Learn the sender
        self.arp_table.update(arp['sender_ip'], arp['sender_mac'])
        
        if arp['opcode'] == ARP_REQUEST:
            self._stream_log("ARP", f"{arp['sender_ip']} is asking: Who has {arp['target_ip']}?")
        elif arp['opcode'] == ARP_REPLY:
            self._stream_log("ARP", f"Learned {arp['sender_ip']} -> {arp['sender_mac'].hex(':')}")

        # Reply if it's asking for our IP, OR if we are the host (Proxy ARP for everything else)
        if arp['opcode'] == ARP_REQUEST:
            # Don't reply if it's gratuitous ARP for its own IP
            if arp['target_ip'] == arp['sender_ip']:
                return None
                
            if arp['target_ip'] == self.red_ip or not self.is_server:
                reply = build_arp_reply(
                    self.red_mac, arp['target_ip'], # Claim to be the requested IP
                    arp['sender_mac'], arp['sender_ip'])
                self._stream_log("ARP", f"Replying: {arp['target_ip']} is-at {self.red_mac.hex(':')}")
                return reply

        return None

    def _resolve_mac(self, dst_ip):
        """Resolve an IP to a MAC via the ARP cache.

        If the mapping is unknown an ARP request is sent and broadcast
        is returned as a temporary fallback (the reply will populate the
        cache for the next packet).
        """
        mac = self.arp_table.lookup(dst_ip)
        if mac is not None:
            return mac

        # Send an ARP who-has for this IP
        arp_req = build_arp_request(self.red_mac, self.red_ip, dst_ip)
        self.red_socket.send(arp_req)
        self._stream_log("ARP", f"Sent who-has for {dst_ip}")

        return BROADCAST_MAC  # fallback until we learn the real MAC

    # ──────────────────────────────────────
    # Data-plane loops
    # ──────────────────────────────────────

    def red_to_black_loop(self):
        """
        Red → Black direction.
        
        1. Receive an Ethernet frame from the red NIC
        2. Handle ARP (respond locally, never tunnel ARP)
        3. Strip the Ethernet header to get clean IP bytes
        4. Host only: apply outbound NAT
        5. Increment sequence counter & encrypt using AES-CBC
        6. Authenticate (Counter + IV + Ciphertext) to prevent replay
        7. Send the packet over the encrypted tunnel
        """
        while self.active:
            try:
                packet_data, _address = self.red_socket.recvfrom(65535)

                # --- Parse Ethernet header ---
                parsed = parse_ethernet_header(packet_data)
                if parsed is None:
                    # Assuming parse_ethernet_header is defined elsewhere
                    continue
                dst_mac, src_mac, ethertype, ip_bytes = parsed

                # Ignore frames that we sent ourselves (loopback)
                if src_mac == self.red_mac:
                    continue

                # --- ARP: handle locally, never tunnel ---
                if ethertype == ARP_ETHERTYPE:
                    reply = self._handle_arp(packet_data)
                    if reply:
                        self.red_socket.send(reply)
                    continue

                # Only forward IPv4
                if ethertype != IPV4_ETHERTYPE:
                    continue

                # Learn the source MAC from this frame while we have it
                if len(ip_bytes) >= 20:
                    src_ip = socket.inet_ntoa(ip_bytes[12:16])
                    self.arp_table.update(src_ip, src_mac)

                # --- Host: outbound NAT on the clean IP bytes ---
                if not self.is_server:
                    ip_bytes = nat.nat_outbound(ip_bytes)
                    if ip_bytes is None:
                        continue
                
                # --- 1. Increment & Protect the Sequence Counter ---
                self.sequence_counter += 1
                # Check for 64-bit overflow (Hard safety ceiling)
                if self.sequence_counter > (1 << 64) - 1:
                    raise RuntimeError("Sequence counter overflow! Crypto context exhausted. Keys must be rotated.")
                
                # Pack counter into 8 bytes (Big-Endian Unsigned Long Long)
                counter_bytes = struct.pack(">Q", self.sequence_counter)

                # 2. Encrypt using AES-CBC (requires padding + dynamic 16-byte IV)
                iv = os.urandom(16)
                cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
                padded_data = pad(ip_bytes, AES.block_size)
                ciphertext = cipher.encrypt(padded_data)

                # 3. Assemble the core message components
                encrypted_message_data = iv + ciphertext

                # 4. Generate verification token
                # CRITICAL: We include counter_bytes in the hash. 
                # This cryptographically locks the sequence number so attackers cannot alter it.
                verify_input = self.key + counter_bytes + encrypted_message_data
                verify_hash = hashlib.sha256(verify_input).digest()[:8]

                # 5. Build Full Protocol Payload
                # The length header must represent ONLY the upcoming payload body size
                payload_body = verify_hash + counter_bytes + encrypted_message_data
                total_payload_length = len(payload_body)
                
                header_length_bytes = total_payload_length.to_bytes(4, byteorder="big")
                
                # Final Wire Combination Assembly: 
                # [4B Length] + [8B Hash] + [8B Counter] + [16B IV] + [Ciphertext]
                wire_packet = header_length_bytes + payload_body

                self.black_connection.sendall(wire_packet)
                
                self.red_sent_cnt += 1
                self.bytes_counter += len(wire_packet)
                self._stream_log("MGMT", f"Successfully delivered packet from red to black. ({len(wire_packet)} encrypted bytes).")

            except Exception as e:
                self.black_drop_cnt += 1
                self._stream_log("PACKET_DROP", f"RED line: Exception while handling package encryption: {str(e)}.")
    
    def black_to_red_loop(self):
        """
        Black → Red direction.

        1. Receive raw protocol payload from the encrypted tunnel
        2. Unpack sequence counter and run sliding window pre-check
        3. Cryptographically verify hash integrity (prevents counter tampering)
        4. Commit sequence number permanently to the sliding window bitmask
        5. Decrypt payload and strip padding securely
        6. Forward clean IP bytes to the Red NIC via Ethernet frame insertion
        """
        while self.active:
            try:
                # receive_tcp_message reads the 4B length header and returns the rest
                payload_received = encryptor_utils.receive_tcp_message(self.black_connection)
                if payload_received is None:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", "BLACK line: Invalid TCP message length")
                    continue

                # Protocol validation boundaries update:
                # 8B Hash + 8B Counter + 16B IV + at least 16B ciphertext block = 48 bytes
                if len(payload_received) < 48:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", f"BLACK line: Packet size header too small ({len(payload_received)} bytes).")
                    continue

                # --- 1. Slice and Parse Protocol Fields ---
                provided_verify_hash = payload_received[0:8]
                counter_bytes        = payload_received[8:16]
                message_data         = payload_received[16:]  # Contains [IV + Ciphertext]

                # Unpack the raw bytes back into an integer
                seq_num = struct.unpack(">Q", counter_bytes)[0]

                # --- 2. Sliding Window Pre-Check ---
                # Drop early if it's explicitly too old or already recorded in the bitmask
                # (We copy the check logic here before running expensive crypto routines)
                if seq_num <= self.replay_window.max_seen - self.replay_window.window_size:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", "BLACK line: REPLAY, Packet #{seq_num} dropped: outside active window tail.")
                    continue
                
                if seq_num <= self.replay_window.max_seen:
                    bit_position = self.replay_window.max_seen - seq_num
                    if (self.replay_window.bitmap & (1 << bit_position)) != 0:
                        self.black_drop_cnt += 1
                        self._stream_log("PACKET_DROP", "BLACK line: REPLAY, Packet #{seq_num} dropped: Duplicate.")
                        continue

                # --- 3. Validate Hash Integrity ---
                # We hash key + counter + message_data to ensure the counter wasn't modified
                verify_input = self.key + counter_bytes + message_data
                calculated_hash = hashlib.sha256(verify_input).digest()[:8]
                
                if calculated_hash != provided_verify_hash:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", "BLACK line: Incorrect certificate.")
                    continue

                # --- 4. Cryptographic Proof Obtained: Commit to Window ---
                # Now that we know the packet is authentic and fresh, safe to update/slide the window
                self.replay_window.verify_and_update(seq_num)

                # --- 5. Decrypt Payload Content ---
                iv = message_data[:16]
                ciphertext = message_data[16:]

                cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
                encrypted_padded = cipher.decrypt(ciphertext)
                
                # Strip PKCS7 padding securely
                ip_bytes = unpad(encrypted_padded, AES.block_size)

                if len(ip_bytes) > 1500:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", "BLACK line: Decrypted IP payload exceeds MTU.")
                    continue

                # --- 6. Host: inbound NAT ---
                if not self.is_server:
                    ip_bytes = nat.nat_inbound(ip_bytes)
                    if ip_bytes is None:
                        self.black_drop_cnt += 1
                        self._stream_log("PACKET_DROP", "BLACK line: Inbound NAT translation failed.")
                        continue

                # --- 7. Resolve destination MAC ---
                if len(ip_bytes) >= 20:
                    dst_ip = socket.inet_ntoa(ip_bytes[16:20])
                    dst_mac = self._resolve_mac(dst_ip)
                else:
                    dst_mac = BROADCAST_MAC

                # --- 8. Rebuild Ethernet frame and inject onto the red NIC ---
                final_ethernet_frame = build_ethernet_frame(
                    dst_mac, self.red_mac, IPV4_ETHERTYPE, ip_bytes)

                if final_ethernet_frame is None:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", "BLACK line: Error building Ethernet frame.")
                    continue

                print(f"[Black-to-Red] Success! Packet #{seq_num} processed cleanly. Forwarding to Red.")
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