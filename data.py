import socket
# Send unencrypted data to the host's Red side
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"Hello World through AES!", ("127.0.0.1", 8002))