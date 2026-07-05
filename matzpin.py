import socket
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

        self.red_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.red_socket.bind((red_nic,0))

        self.key = ""

        self.active = True


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
        We dont trust the black side
        Get full TCP message
        [:8] is the Hash [9:] is ENC(PKT)
        Verify [:8]==hash(ENC(PKT)+key)
        Decrypt the paket
        Send it over black connection
        """
        
        while self.active:
            packet_recived = black_side.receive_tcp_message(self.black_connection)
            if packet_recived is None:
                print("Received None. Connection likely dropped or invalid data received.")
                continue
            print("Got Black Message, Forwarding Packet")
            if len(packet_recived) > 1500:
                print("packet too long")
                continue
            ## NEED VERIFY AND DECYPTION LOGIC
            self.red_socket.send(packet_recived)
    
    def red_to_black_loop(self):
        """
        We trust the red side
        Take the packet and encrypt it
        Create a verify Hash
        Send over the black connection HASH(ENC(PKT)+key) + ENC(PKT)
        """
        while self.active:
            packet_data, address = self.red_socket.recvfrom(65535)
            print(f"\n--- New Packet Received On Red Side ---")
            print(f"From Address Info: {address}")
            print(f"Raw Byte Length: {len(packet_data)}")
            print(f"Hex Payload Hash: {packet_data[:64].hex()}")

            #Verify and decrypt

            self.black_connection.send(len(packet_data).to_bytes(4, byteorder="big")+packet_data)

