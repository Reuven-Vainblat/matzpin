import socket
import os
import sys
import hashlib
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import black_side
import secrets

MESSAGE_LENGTH_SIZE = 4
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
    def __init__(self, is_server, red_nic, black_ip, black_port):
        self.is_server = is_server
        self.red_nic = red_nic
        self.black_ip = black_ip
        self.black_port = black_port

        self.server_socket = None
        self.black_connection = None

        # Red Side Setup
        self.red_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            local_port = int(red_nic)
        except ValueError:
            local_port = 8888  
        self.red_socket.bind(("127.0.0.1", local_port))
        self.last_red_client = None 

        self.key = b"A_VERY_VERY_SECURE_32_BYTE_KEY!!" 
        self.active = True
        
        # Real-time running tally variables used strictly to calculate percentages on the fly
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
                    "port": self.red_nic
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
        try:
            private_key = secrets.randbits(256)
            public_key = pow(DH_BASE, private_key, DH_PRIME)
            pub_bytes = public_key.to_bytes(256, byteorder="big")
            
            if self.is_server:
                self.black_connection.sendall(pub_bytes)
                peer_pub_bytes = black_side.receive_exact_bytes(self.black_connection, 256)
            else:
                peer_pub_bytes = black_side.receive_exact_bytes(self.black_connection, 256)
                self.black_connection.sendall(pub_bytes)
                
            peer_public_key = int.from_bytes(peer_pub_bytes, byteorder="big")
            shared_secret = pow(peer_public_key, private_key, DH_PRIME)
            shared_secret_bytes = shared_secret.to_bytes(256, byteorder="big")

            self.key = hashlib.sha256(shared_secret_bytes).digest() 
            self._stream_log("KEY_SYNC", f"Key Shared / Key Updated occurred.")
        except Exception as e:
            self._stream_log("KEY_SYNC", f"Key exchange protocol failure: {str(e)}")

    def black_to_red_loop(self):
        while self.active:
            try:
                payload_received = black_side.receive_tcp_message(self.black_connection)
                if payload_received is None:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", "BLACK line: Invalid TCP message length")
                    continue

                if len(payload_received) < 40:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", f"BLACK line: Packet size header too small ({len(payload_received)} bytes).")
                    continue

                provided_verify_hash = payload_received[0:8]
                message_data = payload_received[8:]

                verify_input = self.key + message_data
                calculated_hash = hashlib.sha256(verify_input).digest()[:8]
                
                if calculated_hash != provided_verify_hash:
                    self.black_drop_cnt += 1
                    self._stream_log("PACKET_DROP", "BLACK line: Incorrect certificate.")
                    continue

                iv = message_data[:16]
                ciphertext = message_data[16:]

                cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
                encrypted_padded = cipher.decrypt(ciphertext)
                decrypted_packet = unpad(encrypted_padded, AES.block_size)

                if self.last_red_client:
                    self.red_socket.sendto(decrypted_packet, self.last_red_client)
                else:
                    self.red_socket.sendto(decrypted_packet, ("127.0.0.1", 8888))
                
                self.black_sent_cnt += 1
                self.bytes_counter += (len(payload_received) + MESSAGE_LENGTH_SIZE)
                self._stream_log("MGMT", f"Successfully delivered packet from black to red. ({len(decrypted_packet)} cleartext bytes).")

            except Exception as e:
                self.black_drop_cnt += 1
                self._stream_log("PACKET_DROP", f"Exception while handling package decryption: {str(e)}.")
    
    def red_to_black_loop(self):
        while self.active:
            try:
                packet_data, address = self.red_socket.recvfrom(65535)
                self.last_red_client = address 
                
                iv = os.urandom(16)
                cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
                padded_data = pad(packet_data, AES.block_size)
                ciphertext = cipher.encrypt(padded_data)

                encrypted_message_data = iv + ciphertext
                verify_input = self.key + encrypted_message_data
                verify_hash = hashlib.sha256(verify_input).digest()[:8]

                payload_body = verify_hash + encrypted_message_data
                total_payload_length = len(payload_body)
                header_length_bytes = total_payload_length.to_bytes(4, byteorder="big")
                wire_packet = header_length_bytes + payload_body

                self.black_connection.sendall(wire_packet)
                
                self.red_sent_cnt += 1
                self.bytes_counter += len(wire_packet)
                self._stream_log("MGMT", f"Successfully delivered packet from red to black. ({len(wire_packet)} encrypted bytes).")

            except ConnectionResetError:
                pass
            except Exception as e:
                self.red_drop_cnt += 1
                self._stream_log("PACKET_DROP", f"Exception while handling package encryption: {str(e)}.")