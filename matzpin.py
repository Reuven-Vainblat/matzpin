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
        print(f"[Init] Red NIC '{red_nic}' MAC: {self.red_mac.hex(':')}")
        print(f"[Init] Red IP: {red_ip}  |  Mode: {'server' if is_server else 'host'}")

        # ARP table for red-side MAC resolution
        self.arp_table = ArpTable()

        self.key = b"A_VERY_VERY_SECURE_32_BYTE_KEY!!"  

        self.active = True

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
        print(f"[Receiver] Listening on {self.black_ip}:{self.black_port}...")

        # Block and wait for incoming connection
        self.black_connection, address = self.server_socket.accept()
        print(f"[Receiver] Connection established with {address}")

    def _setup_sender(self):
        # Create a TCP/IP socket
        self.black_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[Sender] Connecting to {self.black_ip}:{self.black_port}...")

        # Attempt to connect to the receiver
        self.black_connection.connect((self.black_ip, self.black_port))
        print("[Sender] Connected successfully.")

    def sync_keys(self):
        print("[KeySync] Starting Diffie-Hellman Key Exchange...")

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
        
        print(f"[KeySync] Key exchange successful. Derived Key (Hex): {self.key.hex()}")

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
            print(f"[ARP] {arp['sender_ip']} is asking: Who has {arp['target_ip']}?")
        elif arp['opcode'] == ARP_REPLY:
            print(f"[ARP] Learned {arp['sender_ip']} -> {arp['sender_mac'].hex(':')}")

        # Reply if it's asking for our IP, OR if we are the host (Proxy ARP for everything else)
        if arp['opcode'] == ARP_REQUEST:
            # Don't reply if it's gratuitous ARP for its own IP
            if arp['target_ip'] == arp['sender_ip']:
                return None
                
            if arp['target_ip'] == self.red_ip or not self.is_server:
                reply = build_arp_reply(
                    self.red_mac, arp['target_ip'], # Claim to be the requested IP
                    arp['sender_mac'], arp['sender_ip'])
                print(f"[ARP] Replying: {arp['target_ip']} is-at {self.red_mac.hex(':')}")
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
        print(f"[ARP] Sent who-has for {dst_ip}")

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
        5. Send the IP bytes over the encrypted tunnel
        """
        while self.active:
            packet_data, _address = self.red_socket.recvfrom(65535)

            # --- Parse Ethernet header ---
            parsed = parse_ethernet_header(packet_data)
            if parsed is None:
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

            print(f"\n--- Red→Black | {len(ip_bytes)} bytes IP payload ---")

            # --- Host: outbound NAT on the clean IP bytes ---
            if not self.is_server:
                ip_bytes = nat.nat_outbound(ip_bytes)
                if ip_bytes is None:
                    continue

            print("Encrypting IP Bytes")
            # 1. Encrypt using AES-CBC (requires padding + dynamic 16-byte IV)
            iv = os.urandom(16)
            cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
            padded_data = pad(ip_bytes, AES.block_size)
            ciphertext = cipher.encrypt(padded_data)

            # 2. Assemble into the "Message Data" array block (IV + Ciphertext)
            encrypted_message_data = iv + ciphertext

            # 3. Generate verification token: hash(key + message_data) -> exactly 8 bytes
            verify_input = self.key + encrypted_message_data
            verify_hash = hashlib.sha256(verify_input).digest()[:8]

            print("hash added", verify_hash)

            # 4. Build Full Protocol Payload
            # The length header must represent ONLY the upcoming payload body size
            payload_body = verify_hash + encrypted_message_data
            total_payload_length = len(payload_body)
            
            header_length_bytes = total_payload_length.to_bytes(4, byteorder="big")
            
            # Final Wire Combination Assembly: [4B Length] + [8B Hash] + [IV + Ciphertext]
            wire_packet = header_length_bytes + payload_body

            self.black_connection.sendall(wire_packet)
            print(f"[Red-to-Black] Framed and Sent packet. Hex Hash Prefix: {verify_hash.hex()}")

    def black_to_red_loop(self):
        """
        Black → Red direction.

        1. Receive IP bytes from the encrypted tunnel
        2. Host only: apply inbound NAT
        3. Resolve the destination MAC via ARP cache
        4. Build a new Ethernet frame (our MAC as source)
        5. Inject the frame onto the red NIC
        """
        while self.active:
            try:
                payload_received = encryptor_utils.receive_tcp_message(self.black_connection)
                if payload_received is None:
                    print("Received None. Connection likely dropped or invalid data.")
                    continue

                print(f"\n--- Black→Red | {len(payload_received)} bytes IP payload ---")

                

                if payload_received is None:
                    print("[Black-to-Red] Error: Connection dropped or empty message.")
                    continue

                # 2. Check protocol length boundaries (8 bytes verification + 16 bytes IV + at least 16 bytes ciphertext block)
                if len(payload_received) < 40:
                    print(f"[ALERT] Protocol violation! Packet too small ({len(payload_received)} bytes). Dropping.")
                    continue

                # 3. Parse fields directly from the payload payload
                provided_verify_hash = payload_received[0:8]
                message_data = payload_received[8:]

                # 4. Validate Custom Hash Verification: hash(key + message_data) using first 8 bytes
                verify_input = self.key + message_data
                calculated_hash = hashlib.sha256(verify_input).digest()[:8]
                
                if calculated_hash != provided_verify_hash:
                    print("provided hash", provided_verify_hash)
                    print("[ALERT] Verification Failed! Signature bad. Dropping.")
                    continue

                # 5. Separate IV and Ciphertext out of the remaining message data block
                iv = message_data[:16]
                ciphertext = message_data[16:]

                # 6. Decrypt using AES-CBC
                cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
                encrypted_padded = cipher.decrypt(ciphertext)
                
                # Strip PKCS7 padding securely
                ip_bytes = unpad(encrypted_padded, AES.block_size)

                print(f"[Black-to-Red] Success! Packet verified & decrypted. Forwarding {len(ip_bytes)} bytes to Red. - {message_data} = {ip_bytes}")
                if len(ip_bytes) > 1500:
                    print("IP payload exceeds MTU, dropping")
                    continue

                # --- Host: inbound NAT ---
                if not self.is_server:
                    ip_bytes = nat.nat_inbound(ip_bytes)
                    if ip_bytes is None:
                        continue

                # --- Resolve destination MAC ---
                if len(ip_bytes) >= 20:
                    dst_ip = socket.inet_ntoa(ip_bytes[16:20])
                    dst_mac = self._resolve_mac(dst_ip)
                else:
                    dst_mac = BROADCAST_MAC

            # --- Rebuild Ethernet frame and inject onto the red NIC ---
                to_send_packet = build_ethernet_frame(
                    dst_mac, self.red_mac, IPV4_ETHERTYPE, ip_bytes)
                self.red_socket.send(to_send_packet)

            except ValueError:
                print("[ALERT] Decryption Error: Padding is corrupted or wrong key used.")
            except Exception as e:
                print(f"[Black-to-Red] Unexpected Loop Error: {e}")
