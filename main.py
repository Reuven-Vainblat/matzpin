import red_side, black_side

import socket
import struct
import threading, sys

ETH_P_ALL = 3 #read all protocols

def main():
    if len(sys.argv) < 5 or (sys.argv[1] not in ("server", "host")):
        print("Usage: python script.py [server|host] <red_nic> <black_ip> <black_port>")
        return

    encryptor = Encryptor(sys.argv[1] == "server", sys.argv[2], sys.argv[3], sys.argv[4])

    encryptor.connect()

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

        self.red_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.red_socket.bind((red_nic,0))

        self.key = ""

        self.active = True


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


    def black_to_red_loop(self):
        """
        We dont trust the black side
        Get full TCP message
        [:8] is the Hash [9:] is ENC(PKT)
        Verify [:8]==hash(ENC(PKT)+key)
        Decrypt the paket
        Send it over black connection
        """
        
        while True:
            packet_recived = black_side.receive_tcp_message(self.black_connection)
            ## NEED VERIFY AND DECYPTION LOGIC
            self.red_socket.send(packet_recived)
    
    def red_to_black_loop(self):
        """
        We trust the red side
        Take the packet and encrypt it
        Create a verify Hash
        Send over the black connection HASH(ENC(PKT)+key) + ENC(PKT)
        """

        packet_data, address = self.red_socket.recvfrom(65535)
        print(f"\n--- New Packet Received ---")
        print(f"From Address Info: {address}")
        print(f"Raw Byte Length: {len(packet_data)}")
        print(f"Hex Payload Hash: {packet_data[64].hex()}")

        #Verify and decrypt

        self.black_connection.send(packet_data)



if __name__ == "__main__":
    print("Starting Encryptor")
    main()