import socket
from time import sleep

# Send unencrypted data to the host's Red side
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    sleep(3)  # Wait for 3 seconds before sending the next message
    sock.sendto(b"Hello World through AES!", ("127.0.0.1", 8002))