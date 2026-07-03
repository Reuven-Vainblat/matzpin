import os
import fcntl
import struct
import socket
import subprocess
import utils

# Linux ioctl for TUN/TAP interface creation
TUNSETIFF  = 0x400454ca
IFF_TUN    = 0x0001   # Layer 3 — IP packets, no Ethernet headers
IFF_NO_PI  = 0x1000   # Don't prepend packet info header

TUN_NAME   = "matzpin0"
MTU        = 1500


class Encryptor:
    def __init__(self, is_server, tun_ip, remote_subnet, black_ip, black_port=9999):
        """
        is_server     : True = listen for TCP connection, False = initiate TCP connection
        tun_ip        : IP + prefix for the local TUN interface, e.g. "10.10.0.1/30"
        remote_subnet : Subnet on the other RED network to route through the tunnel,
                        e.g. "192.168.1.0/24"
        black_ip      : For server mode — local IP to bind on. For client mode — remote IP to connect to.
        black_port    : TCP port used for the black (unsafe) connection.
        """
        self.is_server     = is_server
        self.tun_ip        = tun_ip
        self.tun_name      = TUN_NAME
        self.remote_subnet = remote_subnet
        self.black_ip      = black_ip
        self.black_port    = black_port
        self.server_socket = None
        self.black_connection = None
        self.tun_fd        = None
        self.key           = b""
        self.active        = True

        # Create and configure the TUN interface — all done in-process
        self._create_tun()
        self._add_route()


    # -------------------------------------------------------------------------
    # TUN interface management
    # -------------------------------------------------------------------------

    def _create_tun(self):
        """
        Opens /dev/net/tun, creates a TUN interface named matzpin0,
        assigns the given IP, and brings the link up.
        Requires CAP_NET_ADMIN (i.e. run with sudo).
        """
        # Open the TUN kernel interface
        self.tun_fd = os.open("/dev/net/tun", os.O_RDWR)

        # Request a TUN (Layer 3, no packet-info header) interface with our chosen name
        ifr = struct.pack("16sH", self.tun_name.encode()[:15], IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self.tun_fd, TUNSETIFF, ifr)

        # Set MTU, assign IP address with prefix, bring the link up
        subprocess.run(["ip", "link", "set", self.tun_name, "mtu", str(MTU)], check=True)
        subprocess.run(["ip", "addr", "add", self.tun_ip, "dev", self.tun_name], check=True)
        subprocess.run(["ip", "link", "set", self.tun_name, "up"],              check=True)

        print(f"[TUN] Interface '{self.tun_name}' created with IP {self.tun_ip}")

    def _add_route(self):
        """
        Adds a kernel route so that traffic destined for the remote RED subnet
        is sent out via the TUN interface, where the encryptor will pick it up.
        """
        subprocess.run(
            ["ip", "route", "add", self.remote_subnet, "dev", self.tun_name],
            check=True
        )
        print(f"[TUN] Route added: {self.remote_subnet} via {self.tun_name}")

    def teardown(self):
        """
        Graceful shutdown: stop loops, delete TUN interface, close sockets.
        The TUN interface disappears from the OS when this runs.
        """
        self.active = False

        # Delete the TUN interface (this also removes the route we added)
        if self.tun_fd is not None:
            subprocess.run(["ip", "link", "del", self.tun_name], check=False)
            try:
                os.close(self.tun_fd)
            except OSError:
                pass
            self.tun_fd = None
            print(f"[TUN] Interface '{self.tun_name}' deleted")

        if self.black_connection:
            self.black_connection.close()
        if self.server_socket:
            self.server_socket.close()


    # -------------------------------------------------------------------------
    # Black (unsafe) network — TCP connection
    # -------------------------------------------------------------------------

    def connect(self):
        """Establishes the TCP connection over the black (unsafe) network."""
        if self.is_server:
            self._setup_receiver()
        else:
            self._setup_sender()

    def _setup_receiver(self):
        """Listen on the black IP/port and wait for the remote encryptor to connect."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.black_ip, self.black_port))
        self.server_socket.listen(1)
        print(f"[Black] Listening on {self.black_ip}:{self.black_port}...")
        self.black_connection, address = self.server_socket.accept()
        print(f"[Black] Connection established with {address}")

    def _setup_sender(self):
        """Connect to the remote encryptor over the black network."""
        self.black_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[Black] Connecting to {self.black_ip}:{self.black_port}...")
        self.black_connection.connect((self.black_ip, self.black_port))
        print("[Black] Connected successfully.")


    # -------------------------------------------------------------------------
    # Key synchronisation (placeholder)
    # -------------------------------------------------------------------------

    def sync_keys(self):
        # TODO: implement key exchange (e.g. Diffie-Hellman over the black connection)
        pass


    # -------------------------------------------------------------------------
    # Forwarding loops
    # -------------------------------------------------------------------------

    def red_to_black_loop(self):
        """
        RED → BLACK forwarding.
        Reads IP packets that the OS has routed out through the TUN interface
        (i.e. packets destined for the remote RED subnet), then:
          1. [TODO] Encrypt the packet
          2. [TODO] Append HMAC: HASH(ENC(PKT) + key)
          3. Send over the black TCP connection with a 4-byte length header
        """
        print("[Red→Black] Loop started")
        while self.active:
            try:
                packet_data = os.read(self.tun_fd, 65535)
            except OSError as e:
                if self.active:
                    print(f"[Red→Black] TUN read error: {e}")
                break

            print(f"[Red→Black] Captured {len(packet_data)} bytes from RED side")

            # TODO: encrypt packet_data and prepend HMAC before sending
            utils.send_tcp_data(self.black_connection, packet_data)

    def black_to_red_loop(self):
        """
        BLACK → RED forwarding.
        Receives a length-prefixed message from the black TCP connection, then:
          1. [TODO] Verify HMAC: first 8 bytes = HASH(ENC(PKT) + key)
          2. [TODO] Decrypt the payload
          3. Write the plain IP packet into the TUN interface so the OS
             delivers it to the destination on the local RED network
        """
        print("[Black→Red] Loop started")
        while self.active:
            packet_received = utils.receive_tcp_message(self.black_connection)
            if packet_received is None:
                print("[Black→Red] Connection dropped or invalid data — stopping")
                self.active = False
                break

            print(f"[Black→Red] Received {len(packet_received)} bytes, injecting into RED side")

            # TODO: verify HMAC and decrypt before writing
            try:
                os.write(self.tun_fd, packet_received)
            except OSError as e:
                print(f"[Black→Red] TUN write error: {e}")
                self.active = False
                break
