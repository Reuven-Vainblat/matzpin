from red_side import red_side_loop
from black_side import black_side_loop

import socket
import struct
import threading, sys


def main():
    if len(sys.argv) < 5 or (sys.argv[1] not in ("server", "host")):
        print("Usage: python script.py [server|host] <red_nic> <black_ip> <black_port>")
        return

    encryptor = Encryptor(sys.argv[1] == "server", sys.argv[2], sys.argv[3], sys.argv[4])

    encryptor.sync_keys()
    
    # # Start red side thread
    # red_thread = threading.Thread(target=red_side_loop, args=(red_socket))

    # # Start black side thread
    # black_thread = threading.Thread(target=black_side_loop, args=(black_socket))

class Encryptor:
    def __init__(self, is_server, red_nic, black_ip, black_port=9999):
        
        self.is_server = is_server
        self.red_nic = red_nic
        self.black_ip = black_ip
        self.black_port = black_port
        self.server_socket = None
        self.black_connection = None

        self.red_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.red_socket.bind((red_nic,0))

        self.key = ""

    def connect(self):
        """Establishes the connection based on the mode."""
        if self.mode == 'server':
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
        print(f"[Receiver] Listening on {self.host}:{self.port}...")
        
        # Block and wait for incoming connection
        self.black_connection, address = self.server_socket.accept()
        print(f"[Receiver] Connection established with {address}")

    def _setup_sender(self):
        # Create a TCP/IP socket
        self.black_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[Sender] Connecting to {self.host}:{self.port}...")
        
        # Attempt to connect to the receiver
        self.black_connection.connect((self.black_ip, self.black_port))
        print("[Sender] Connected successfully.")
    
    def sync_keys(self):
        #TODO
        pass

