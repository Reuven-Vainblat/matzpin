
def send_tcp_data(sock, data):
    sock.send(len(data).to_bytes(4, byteorder="big")+data)

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
    # Define a reasonable maximum size for your payloads (e.g., 10 MB)
    MAX_PACKET_SIZE = 9000 

    try:
        # 1. Read the 4-byte integer header to find out the payload size
        header = receive_exact_bytes(sock, 4)
        print("RECIVE TCP MSG HEADER", header)
        message_length = int.from_bytes(header, byteorder="big")
        
        # Add a debug print to see what is actually coming over the wire
        print(f"[DEBUG] Parsed message length: {message_length} bytes (Header raw: {header})")

        # 2. Sanity check the size before receiving the payload
        if message_length > MAX_PACKET_SIZE:
            raise ValueError(f"Message length {message_length} exceeds max allowed size of {MAX_PACKET_SIZE}. Sender might be using the wrong protocol.")
        if message_length < 0:
            raise ValueError(f"Invalid message length: {message_length}")

        # 3. Read the actual payload based on the size received
        message_payload = receive_exact_bytes(sock, message_length)
        return message_payload
        
    except ConnectionError as e:
        print(f"Network error: {e}")
        return None
    except ValueError as e:
        print(f"Protocol error: {e}")
        return None