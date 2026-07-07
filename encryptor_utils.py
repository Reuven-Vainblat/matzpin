
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
    MAX_PAYLOAD_SIZE = 10 * 1024 * 1024 

    try:
        # 1. Read the 4-byte integer header to find out the payload size
        header = receive_exact_bytes(sock, 4)
        print("RECIVE TCP MSG HEADER", header)
        message_length = int.from_bytes(header, byteorder="big")
        
        # Add a debug print to see what is actually coming over the wire
        print(f"[DEBUG] Parsed message length: {message_length} bytes (Header raw: {header})")

        # 2. Sanity check the size before receiving the payload
        if message_length > MAX_PAYLOAD_SIZE:
            raise ValueError(f"Message length {message_length} exceeds max allowed size of {MAX_PAYLOAD_SIZE}. Sender might be using the wrong protocol.")
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

class ReplayWindow:
    def __init__(self, window_size: int = 64):
        # Window size must match the bit-width of our mask
        self.window_size = window_size
        self.max_seen = 0
        self.bitmap = 0

    def verify_and_update(self, seq_num: int) -> bool:
        """
        Verifies packet sequence number using a bitmask.
        Returns True if packet is fresh/valid, False if it's a replay or too old.
        """
        if seq_num <= 0:
            return False

        # Packet is too old (outside the right/tail edge of the window)
        if seq_num <= self.max_seen - self.window_size:
            print(f"Rejected: Packet {seq_num} is too old. Window tail is {self.max_seen - self.window_size + 1}")
            return False

        # Packet is within the current window
        if seq_num <= self.max_seen:
            bit_position = self.max_seen - seq_num
            
            # Check if the bit at 'bit_position' is already set to 1
            if (self.bitmap & (1 << bit_position)) != 0:
                print(f"Rejected: Packet {seq_num} is a REPLAY!")
                return False
            
            # Not seen yet! Mark it as received by setting the bit to 1
            self.bitmap |= (1 << bit_position)
            print(f"Accepted: Packet {seq_num} (Out-of-order within window)")
            return True

        # Packet is ahead of the window (New peak sequence number)
        diff = seq_num - self.max_seen
        
        if diff >= self.window_size:
            # The jump is so large it completely clears out the old window
            self.bitmap = 1
        else:
            # Slide the window left by 'diff' spaces to drop old packets,
            # then set the 1st bit (position 0) for the new peak packet
            self.bitmap = (self.bitmap << diff) | 1
            
            # Ensure we mask out any bits that slid past our window size limit
            self.bitmap &= (1 << self.window_size) - 1

        self.max_seen = seq_num
        window_tail = self.max_seen - self.window_size + 1
        print(f"Accepted: Packet {seq_num} (New peak. Window range: [{window_tail} -> {self.max_seen}])")
        return True

    def debug_print_bitmap(self):
        """Helper to visualize the window bits"""
        # Formats the integer as a zero-padded binary string matching window size
        binary_str = f"{self.bitmap:0{self.window_size}b}"
        print(f"   [Bitmap Window State]: {binary_str} (Left=Oldest, Right=Newest/Peak)")