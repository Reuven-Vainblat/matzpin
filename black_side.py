
def black_side_loop():
    pass

def receive_exact_bytes(sock, num_bytes):
    """Ensures exactly the requested number of bytes are read from the stream."""
    buffer = b""
    while len(buffer) < num_bytes:
        chunk = sock.recv(num_bytes - len(buffer))
        if not chunk:
            raise ConnectionError("Socket connection closed prematurely by peer.")
        buffer += chunk
    return buffer

def receive_tcp_message(sock):
    """Receives a complete message prefixed with a 4-byte length header."""
    try:
        # 1. Read the 4-byte integer header to find out the payload size
        header = receive_exact_bytes(sock, 4)
        message_length = int.from_bytes(header, byteorder="big")
        
        # 2. Read the actual payload based on the size received
        message_payload = receive_exact_bytes(sock, message_length)
        return message_payload.decode("utf-8")
        
    except ConnectionError as e:
        print(f"Network error: {e}")
        return None