import socket
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import black_side, red_side
import secrets
import hashlib

ETH_P_ALL = 3 #read all protocols

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
    def __init__(self, is_server, red_nic, black_ip, black_port=9999):
        self.is_server = is_server
        self.red_nic = red_nic
        self.black_ip = black_ip
        self.black_port = black_port
        self.server_socket = None
        self.black_connection = None

        # Red side (UDP socket for Windows/Mock testing)
        self.red_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            local_port = int(red_nic)
        except ValueError:
            local_port = 8888  
        
        self.red_socket.bind(("127.0.0.1", local_port))
        # Keep track of the last destination address for forwarding out of the loop
        self.last_red_client = None 

        # 32-byte AES key (256-bit)
        self.key = b"A_VERY_VERY_SECURE_32_BYTE_KEY!!" 
        self.active = True

    def connect(self):
        """Establishes the connection based on the mode."""
        if self.is_server:
            self._setup_receiver()
        else:
            self._setup_sender()

    def _setup_receiver(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.black_ip, self.black_port))
        self.server_socket.listen(1)
        print(f"[Receiver] Listening on {self.black_ip}:{self.black_port}...")
        
        self.black_connection, address = self.server_socket.accept()
        print(f"[Receiver] Connection established with {address}")

    def _setup_sender(self):
        self.black_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[Sender] Connecting to {self.black_ip}:{self.black_port}...")
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
            peer_pub_bytes = black_side.receive_exact_bytes(self.black_connection, 256)
        else:
            peer_pub_bytes = black_side.receive_exact_bytes(self.black_connection, 256)
            self.black_connection.sendall(pub_bytes)
            
        peer_public_key = int.from_bytes(peer_pub_bytes, byteorder="big")
        
        # calculate the shared secret (g^ab mod p)
        shared_secret = pow(peer_public_key, private_key, DH_PRIME)
        
        shared_secret_bytes = shared_secret.to_bytes(256, byteorder="big")

        # using sha256 to create a equalized key for encryption
        self.key = hashlib.sha256(shared_secret_bytes).digest()
        
        print(f"[KeySync] Key exchange successful. Derived Key (Hex): {self.key.hex()}")

    def black_to_red_loop(self):
        """
        Receives according to Custom Wire Protocol:
        [8B Verify Hash] + [Remaining Data (16B IV + Ciphertext)]
        (Note: The 4B length was already read and stripped by black_side.receive_tcp_message)
        """
        while self.active:
            try:
                # 1. Fetch data from TCP buffer via your black_side module
                # This returns ONLY the payload after the 4-byte header!
                payload_received = black_side.receive_tcp_message(self.black_connection)
                
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
                    print("[ALERT] Verification Failed! Signature bad. Dropping.")
                    continue

                # 5. Separate IV and Ciphertext out of the remaining message data block
                iv = message_data[:16]
                ciphertext = message_data[16:]

                # 6. Decrypt using AES-CBC
                cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
                encrypted_padded = cipher.decrypt(ciphertext)
                
                # Strip PKCS7 padding securely
                decrypted_packet = unpad(encrypted_padded, AES.block_size)

                print(f"[Black-to-Red] Success! Packet verified & decrypted. Forwarding {len(decrypted_packet)} bytes to Red. - {message_data} = {decrypted_packet}")
                
                # 7. Forward onto Red Network
                if self.last_red_client:
                    self.red_socket.sendto(decrypted_packet, self.last_red_client)
                else:
                    # If fallback mode hasn't received anything yet, default back to loopback port
                    self.red_socket.sendto(decrypted_packet, ("127.0.0.1", 8888))

            except ValueError:
                print("[ALERT] Decryption Error: Padding is corrupted or wrong key used.")
            except Exception as e:
                print(f"[Black-to-Red] Unexpected Loop Error: {e}")
    
    def red_to_black_loop(self):
        """
        Grabs raw Red traffic, encrypts via CBC, packages into wire framing format, and sends.
        """
        while self.active:
            try:
                packet_data, address = self.red_socket.recvfrom(65535)
                self.last_red_client = address # Capture endpoint destination information
                
                # 1. Encrypt using AES-CBC (requires padding + dynamic 16-byte IV)
                iv = os.urandom(16)
                cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
                padded_data = pad(packet_data, AES.block_size)
                ciphertext = cipher.encrypt(padded_data)

                # 2. Assemble into the "Message Data" array block (IV + Ciphertext)
                encrypted_message_data = iv + ciphertext

                # 3. Generate verification token: hash(key + message_data) -> exactly 8 bytes
                verify_input = self.key + encrypted_message_data
                verify_hash = hashlib.sha256(verify_input).digest()[:8]

                # 4. Build Full Protocol Payload
                # The length header must represent ONLY the upcoming payload body size
                payload_body = verify_hash + encrypted_message_data
                total_payload_length = len(payload_body)
                
                header_length_bytes = total_payload_length.to_bytes(4, byteorder="big")
                
                # Final Wire Combination Assembly: [4B Length] + [8B Hash] + [IV + Ciphertext]
                wire_packet = header_length_bytes + payload_body

                # 5. Pipeline out to TCP channel
                self.black_connection.sendall(wire_packet)
                print(f"[Red-to-Black] Framed and Sent packet. Hex Hash Prefix: {verify_hash.hex()}")

            except Exception as e:
                print(f"[Red-to-Black] Error processing packet: {e}")