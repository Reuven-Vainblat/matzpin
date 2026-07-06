def receive_exact_bytes(sock, num_bytes):
    buffer = b""
    while len(buffer) < num_bytes:
        chunk = sock.recv(num_bytes - len(buffer))
        if not chunk:
            raise ConnectionError("Socket connection closed prematurely by peer.")
        buffer += chunk
    return buffer

def receive_tcp_message(sock):
    MAX_PAYLOAD_SIZE = 10 * 1024 * 1024 
    try:
        header = receive_exact_bytes(sock, 4)
        message_length = int.from_bytes(header, byteorder="big")
        
        if message_length > MAX_PAYLOAD_SIZE or message_length < 0:
            raise ValueError()

        message_payload = receive_exact_bytes(sock, message_length)
        return message_payload
    except Exception:
        return None