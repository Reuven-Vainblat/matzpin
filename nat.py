import time
import socket
import struct

EXTERNAL_IP = "10.60.44.6"
TIMEOUT = 30  # seconds

# NAT_TABLE: (src_ip, src_port) -> {'port': ext_port, 'last_seen': time.time()}
NAT_TABLE = {}
# REVERSE_TABLE: ext_port -> ((src_ip, src_port), last_seen)
REVERSE_TABLE = {}
NEXT_PORT = 40000


def calculate_checksum(data: bytes) -> int:
    """Calculates the standard 16-bit Internet checksum (RFC 1071)."""
    if len(data) % 2 == 1:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        checksum += word
    while (checksum >> 16) > 0:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF


def cleanup_expired():
    """Removes entries older than TIMEOUT seconds."""
    now = time.time()
    to_delete = [k for k, v in NAT_TABLE.items() if now - v['last_seen'] > TIMEOUT]
    
    for key in to_delete:
        ext_port = NAT_TABLE[key]['port']
        del NAT_TABLE[key]
        if ext_port in REVERSE_TABLE:
            del REVERSE_TABLE[ext_port]


def allocate_port(src_ip, src_port):
    global NEXT_PORT
    cleanup_expired()  # Clean up before allocating
    
    if (src_ip, src_port) not in NAT_TABLE:
        ext_port = NEXT_PORT
        now = time.time()
        NAT_TABLE[(src_ip, src_port)] = {'port': ext_port, 'last_seen': now}
        REVERSE_TABLE[ext_port] = ((src_ip, src_port), now)
        NEXT_PORT = 40000 + ((NEXT_PORT - 40000 + 1) % 20000)
    else:
        NAT_TABLE[(src_ip, src_port)]['last_seen'] = time.time()
        
    return NAT_TABLE[(src_ip, src_port)]['port']


def handle_packet_bytes(packet_bytes: bytes) -> bytes | None:
    # Require at least the minimum IPv4 header length
    if len(packet_bytes) < 20:
        return packet_bytes

    # Parse IP Version and Header Length
    ver_ihl = packet_bytes[0]
    version = ver_ihl >> 4
    if version != 4:  # Drop if not IPv4
        return packet_bytes
    
    ihl = (ver_ihl & 0x0F) * 4
    if len(packet_bytes) < ihl:
        return packet_bytes

    # Protocol check (6 = TCP, 17 = UDP)
    protocol = packet_bytes[9]
    if protocol not in (6, 17):
        return packet_bytes

    # Ensure Layer 4 header is present (8 bytes min for both TCP/UDP)
    l4_offset = ihl
    if len(packet_bytes) < l4_offset + 8:
        return packet_bytes

    # Extract IPs
    src_ip_bytes = packet_bytes[12:16]
    dst_ip_bytes = packet_bytes[16:20]
    src_ip = socket.inet_ntoa(src_ip_bytes)
    dst_ip = socket.inet_ntoa(dst_ip_bytes)

    # Extract Ports
    src_port, dst_port = struct.unpack("!HH", packet_bytes[l4_offset:l4_offset+4])

    # Convert to mutable bytearray to modify the packet
    pkt = bytearray(packet_bytes)

    # Apply NAT Logic based on exactly how your scapy script behaved
    if src_ip.startswith("192.168."):
        # --- OUTBOUND ---
        new_src_port = allocate_port(src_ip, src_port)
        pkt[12:16] = socket.inet_aton(EXTERNAL_IP)
        struct.pack_into("!H", pkt, l4_offset, new_src_port)
        
    elif dst_ip == EXTERNAL_IP:
        # --- INBOUND ---
        cleanup_expired()
        if dst_port in REVERSE_TABLE:
            (internal_ip, internal_port), _ = REVERSE_TABLE[dst_port]
            
            REVERSE_TABLE[dst_port] = ((internal_ip, internal_port), time.time())
            NAT_TABLE[(internal_ip, internal_port)]['last_seen'] = time.time()
            
            pkt[16:20] = socket.inet_aton(internal_ip)
            struct.pack_into("!H", pkt, l4_offset + 2, internal_port)
        else:
            return None  # Drop packet
            
    else:
        # --- FALLBACK (matching your final `else` condition) ---
        new_src_port = allocate_port(src_ip, src_port)
        pkt[12:16] = socket.inet_aton(EXTERNAL_IP)
        struct.pack_into("!H", pkt, l4_offset, new_src_port)


    # ==========================
    # CHECKSUM RECALCULATION
    # ==========================
    
    # 1. IP Checksum
    pkt[10:12] = b'\x00\x00'  # Zero out old checksum
    ip_header = pkt[0:ihl]
    struct.pack_into("!H", pkt, 10, calculate_checksum(ip_header))

    # 2. Layer 4 Checksum
    l4_len = len(pkt) - ihl
    
    if protocol == 6:  # TCP
        csum_offset = l4_offset + 16
    else:              # UDP
        csum_offset = l4_offset + 6

    pkt[csum_offset : csum_offset+2] = b'\x00\x00'  # Zero out old L4 checksum

    # Create IP pseudo-header required for TCP/UDP checksum calculations
    # Src IP (4), Dst IP (4), Zero (1), Protocol (1), L4 Length (2)
    pseudo_header = struct.pack("!4s4sBBH", pkt[12:16], pkt[16:20], 0, protocol, l4_len)
    
    l4_checksum = calculate_checksum(pseudo_header + pkt[l4_offset:])
    
    # UDP specific rule: if calculated checksum is 0, it must be set to 0xFFFF
    if protocol == 17 and l4_checksum == 0:
        l4_checksum = 0xFFFF

    struct.pack_into("!H", pkt, csum_offset, l4_checksum)

    return bytes(pkt)