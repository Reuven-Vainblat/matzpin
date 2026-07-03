import signal
import sys
import threading
from matzpin import Encryptor


USAGE = """
Usage:
  sudo python main.py server <tun_ip/prefix> <remote_subnet> <black_bind_ip> <black_port>
  sudo python main.py client <tun_ip/prefix> <remote_subnet> <black_remote_ip> <black_port>

Arguments:
  server|client    : server listens for a TCP connection; client initiates one
  tun_ip/prefix    : IP address and prefix length for the local TUN interface
                     e.g.  10.10.0.1/30  (physical device)
                           10.10.0.2/30  (Azure VM)
  remote_subnet    : Subnet on the other RED network to route through the tunnel
                     e.g.  192.168.1.0/24
  black_ip         : server mode — local IP to bind on (use 0.0.0.0 to accept any)
                     client mode — remote encryptor IP to connect to
  black_port       : TCP port for the black (unsafe) connection

Example (physical device — server):
  sudo python main.py server 10.10.0.1/30 10.0.0.0/24 0.0.0.0 9999

Example (Azure VM — client):
  sudo python main.py client 10.10.0.2/30 192.168.1.0/24 <physical_vpn_ip> 9999
"""


def main():
    if len(sys.argv) < 6 or sys.argv[1] not in ("server", "client"):
        print(USAGE)
        sys.exit(1)

    _, mode, tun_ip, remote_subnet, black_ip, black_port = sys.argv

    encryptor = Encryptor(
        is_server     = (mode == "server"),
        tun_ip        = tun_ip,
        remote_subnet = remote_subnet,
        black_ip      = black_ip,
        black_port    = int(black_port),
    )

    # Graceful shutdown on Ctrl+C or SIGTERM
    def shutdown(sig, frame):
        print("\n[Main] Shutting down...")
        encryptor.teardown()
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Establish black (unsafe) TCP connection
    encryptor.connect()

    # Key exchange (currently a no-op placeholder)
    encryptor.sync_keys()

    # RED→BLACK runs in a background thread; BLACK→RED runs on the main thread
    red_thread = threading.Thread(
        target=encryptor.red_to_black_loop,
        name="red-to-black",
        daemon=True,
    )
    red_thread.start()

    encryptor.black_to_red_loop()


if __name__ == "__main__":
    print("Starting Encryptor")
    main()