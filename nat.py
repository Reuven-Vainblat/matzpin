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


def _recalculate_checksums(pkt, ihl, protocol, l4_offset):
    """Recalculate IP and L4 checksums after NAT modifications."""
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


def _parse_ip_l4(ip_bytes):
    """Parse IP header fields needed for NAT.
    
    Returns (version, ihl, protocol, l4_offset, src_ip, dst_ip, src_port, dst_port)
    or None if the packet cannot be NATted (non-IPv4, non-TCP/UDP, too short).
    """
    if len(ip_bytes) < 20:
        return None

    ver_ihl = ip_bytes[0]
    version = ver_ihl >> 4
    if version != 4:
        return None

    ihl = (ver_ihl & 0x0F) * 4
    if len(ip_bytes) < ihl:
        return None

    protocol = ip_bytes[9]
    if protocol not in (6, 17):  # TCP or UDP only
        return None

    l4_offset = ihl
    if len(ip_bytes) < l4_offset + 8:
        return None

    src_ip = socket.inet_ntoa(ip_bytes[12:16])
    dst_ip = socket.inet_ntoa(ip_bytes[16:20])
    src_port, dst_port = struct.unpack("!HH", ip_bytes[l4_offset:l4_offset+4])

    return version, ihl, protocol, l4_offset, src_ip, dst_ip, src_port, dst_port


def nat_outbound(ip_bytes: bytes) -> bytes:
    """Outbound NAT: rewrite source IP/port for packets leaving the red network.
    
    Replaces the internal source IP with EXTERNAL_IP and assigns a mapped port.
    Non-TCP/UDP packets are passed through unchanged.
    """
    parsed = _parse_ip_l4(ip_bytes)
    if parsed is None:
        return ip_bytes  # Pass through non-NATtable packets

    version, ihl, protocol, l4_offset, src_ip, dst_ip, src_port, dst_port = parsed
    print(f"[NAT OUT] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

    pkt = bytearray(ip_bytes)

    new_src_port = allocate_port(src_ip, src_port)
    pkt[12:16] = socket.inet_aton(EXTERNAL_IP)
    struct.pack_into("!H", pkt, l4_offset, new_src_port)

    _recalculate_checksums(pkt, ihl, protocol, l4_offset)
    return bytes(pkt)


def nat_inbound(ip_bytes: bytes) -> bytes | None:
    """Inbound NAT: rewrite destination IP/port for packets returning to the red network.
    
    Looks up the destination port in the reverse table and restores the
    original internal IP/port.  Returns None if no mapping exists (drop).
    Non-TCP/UDP packets are passed through unchanged.
    """
    parsed = _parse_ip_l4(ip_bytes)
    if parsed is None:
        return ip_bytes  # Pass through non-NATtable packets

    version, ihl, protocol, l4_offset, src_ip, dst_ip, src_port, dst_port = parsed
    print(f"[NAT IN] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

    if dst_ip != EXTERNAL_IP:
        return ip_bytes  # Not addressed to us, pass through

    cleanup_expired()

    if dst_port not in REVERSE_TABLE:
        print(f"[NAT IN] No mapping for port {dst_port}, dropping")
        return None  # Drop — no mapping

    (internal_ip, internal_port), _ = REVERSE_TABLE[dst_port]

    # Refresh timestamps
    REVERSE_TABLE[dst_port] = ((internal_ip, internal_port), time.time())
    NAT_TABLE[(internal_ip, internal_port)]['last_seen'] = time.time()

    pkt = bytearray(ip_bytes)
    pkt[16:20] = socket.inet_aton(internal_ip)
    struct.pack_into("!H", pkt, l4_offset + 2, internal_port)

    _recalculate_checksums(pkt, ihl, protocol, l4_offset)
    return bytes(pkt)


def handle_packet_bytes(packet_bytes: bytes) -> bytes | None:
    """Auto-detecting convenience wrapper (used by test harness).
    
    Routes to nat_outbound or nat_inbound based on the destination IP.
    """
    parsed = _parse_ip_l4(packet_bytes)
    if parsed is None:
        return packet_bytes

    _, _, _, _, _, dst_ip, _, dst_port = parsed

    print("Got packet to", dst_ip, dst_port)

    if dst_ip == EXTERNAL_IP:
        return nat_inbound(packet_bytes)
    else:
        return nat_outbound(packet_bytes)