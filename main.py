from matzpin import Encryptor
import threading, sys


def main():
    if len(sys.argv) < 6 or (sys.argv[1] not in ("server", "host")):
        print("Usage: python main.py [server|host] <red_nic> <red_ip> <black_ip> <black_port>")
        print("  server  - waits for a host to connect (no NAT)")
        print("  host    - connects to a server (with NAT)")
        print("  red_nic - name of the red-side network interface (e.g. eth0)")
        print("  red_ip  - IP address of the encryptor on the red network")
        return

    mode = sys.argv[1]
    red_nic = sys.argv[2]
    red_ip = sys.argv[3]
    black_ip = sys.argv[4]
    black_port = int(sys.argv[5])

    encryptor = Encryptor(mode == "server", red_nic, red_ip, black_ip, black_port)

    encryptor.connect()

    encryptor.sync_keys()
    
    # Start red side thread
    red_thread = threading.Thread(target=encryptor.red_to_black_loop)
    red_thread.start()

    encryptor.black_to_red_loop()



if __name__ == "__main__":
    print("Starting Encryptor")
    main()