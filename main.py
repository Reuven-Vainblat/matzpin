from matzpin import Encryptor
import threading, sys


def main():
    if len(sys.argv) < 5 or (sys.argv[1] not in ("server", "host")):
        print("Usage: python script.py [server|host] <red_nic> <black_ip> <black_port>")
        return

    encryptor = Encryptor(sys.argv[1] == "server", sys.argv[2], sys.argv[3], int(sys.argv[4]))

    encryptor.connect()

    encryptor.sync_keys()
    
    # Start red side thread
    red_thread = threading.Thread(target=encryptor.red_to_black_loop)
    red_thread.start()

    encryptor.black_to_red_loop()



if __name__ == "__main__":
    print("Starting Encryptor")
    main()