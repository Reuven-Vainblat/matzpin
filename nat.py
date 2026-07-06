import time
import socket
import struct

# This NAT rewrites IPv4 TCP/UDP packets crossing the encryptor.
# The red side uses Linux AF_PACKET sockets, so packets usually arrive as full
# Ethernet frames. The code therefore first finds the IPv4 header, then applies
# NAT relative to that header instead of assuming byte 0 is always IPv4.
EXTERNAL_IP = "10.60.44.6"
TIMEOUT = 30  # seconds

# NAT_TABLE: (src_ip, src_port) -> {'port': ext_port, 'last_seen': time.time()}
NAT_TABLE = {}
# REVERSE_TABLE: ext_port -> ((src_ip, src_port), last_seen)
REVERSE_TABLE = {}
NEXT_PORT = 40000
ETHERNET_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}


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


def _ipv4_lengths_at(packet_bytes: bytes, ip_offset: int) -> tuple[int, int] | None:
    """Return (ihl, total_length) if an IPv4 header starts at ip_offset."""
    # IPv4 has a minimum 20-byte header. IHL tells us the real header length,
    # and total_length tells us how much of the frame belongs to the IP datagram.
    if len(packet_bytes) < ip_offset + 20:
        return None

    ver_ihl = packet_bytes[ip_offset]
    version = ver_ihl >> 4
    if version != 4:
        return None

    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(packet_bytes) < ip_offset + ihl:
        return None

    total_len = struct.unpack("!H", packet_bytes[ip_offset + 2:ip_offset + 4])[0]
    if total_len < ihl or len(packet_bytes) < ip_offset + total_len:
        return None

    return ihl, total_len


def _find_ipv4_header(packet_bytes: bytes) -> tuple[int, int, int] | None:
    """Locate IPv4 in either a raw IP packet or an Ethernet frame."""
    # AF_PACKET gives us Ethernet headers. EtherType 0x0800 means the payload is
    # IPv4, while VLAN tags add 4-byte wrappers before the real EtherType.
    if len(packet_bytes) >= ETHERNET_HEADER_LEN:
        ethertype = struct.unpack("!H", packet_bytes[12:14])[0]
        ip_offset = ETHERNET_HEADER_LEN

        while ethertype in VLAN_ETHERTYPES:
            if len(packet_bytes) < ip_offset + 4:
                return None
            ethertype = struct.unpack("!H", packet_bytes[ip_offset + 2:ip_offset + 4])[0]
            ip_offset += 4

        if ethertype == ETHERTYPE_IPV4:
            lengths = _ipv4_lengths_at(packet_bytes, ip_offset)
            if lengths is not None:
                ihl, total_len = lengths
                return ip_offset, ihl, total_len

    lengths = _ipv4_lengths_at(packet_bytes, 0)
    if lengths is None:
        return None

    # Keep supporting raw IPv4 bytes as well. That makes tests and any future
    # non-Ethernet caller work with the same NAT function.
    ihl, total_len = lengths
    return 0, ihl, total_len


def handle_packet_bytes(packet_bytes: bytes) -> bytes | None:
    # ip_offset is 0 for raw IPv4 packets and 14 or more for Ethernet frames.
    # All IP and TCP/UDP offsets below are calculated relative to this value.
    ip_info = _find_ipv4_header(packet_bytes)
    if ip_info is None:
        return packet_bytes
    ip_offset, ihl, total_len = ip_info
    ip_end = ip_offset + total_len

    # Protocol check (6 = TCP, 17 = UDP)
    protocol = packet_bytes[ip_offset + 9]
    if protocol not in (6, 17):
        return packet_bytes

    # Ensure the full TCP/UDP header is present inside the IP datagram.
    min_l4_len = 20 if protocol == 6 else 8
    if total_len < ihl + min_l4_len:
        return packet_bytes
    l4_offset = ip_offset + ihl

    # Extract IPs
    src_ip_bytes = packet_bytes[ip_offset + 12:ip_offset + 16]
    dst_ip_bytes = packet_bytes[ip_offset + 16:ip_offset + 20]
    src_ip = socket.inet_ntoa(src_ip_bytes)
    dst_ip = socket.inet_ntoa(dst_ip_bytes)

    # Extract Ports
    src_port, dst_port = struct.unpack("!HH", packet_bytes[l4_offset:l4_offset+4])

    # Convert to mutable bytearray to modify the packet
    pkt = bytearray(packet_bytes)

    # Apply NAT Logic based on exactly how your scapy script behaved
    if src_ip.startswith("192.168."):
        # --- OUTBOUND ---
        # Internal red-side clients are hidden behind EXTERNAL_IP, with a
        # per-flow external source port stored in NAT_TABLE/REVERSE_TABLE.
        new_src_port = allocate_port(src_ip, src_port)
        pkt[ip_offset + 12:ip_offset + 16] = socket.inet_aton(EXTERNAL_IP)
        struct.pack_into("!H", pkt, l4_offset, new_src_port)
        
    elif dst_ip == EXTERNAL_IP:
        # --- INBOUND ---
        # Return traffic is accepted only if the destination port matches a
        # previously allocated mapping. Unknown inbound flows are dropped.
        cleanup_expired()
        if dst_port in REVERSE_TABLE:
            (internal_ip, internal_port), _ = REVERSE_TABLE[dst_port]
            
            REVERSE_TABLE[dst_port] = ((internal_ip, internal_port), time.time())
            NAT_TABLE[(internal_ip, internal_port)]['last_seen'] = time.time()
            
            pkt[ip_offset + 16:ip_offset + 20] = socket.inet_aton(internal_ip)
            struct.pack_into("!H", pkt, l4_offset + 2, internal_port)
        else:
            return None  # Drop packet
            
    else:
        # --- FALLBACK (matching your final `else` condition) ---
        new_src_port = allocate_port(src_ip, src_port)
        pkt[ip_offset + 12:ip_offset + 16] = socket.inet_aton(EXTERNAL_IP)
        struct.pack_into("!H", pkt, l4_offset, new_src_port)


    # ==========================
    # CHECKSUM RECALCULATION
    # ==========================
    
    # 1. IP Checksum
    pkt[ip_offset + 10:ip_offset + 12] = b'\x00\x00'  # Zero out old checksum
    ip_header = pkt[ip_offset:ip_offset + ihl]
    struct.pack_into("!H", pkt, ip_offset + 10, calculate_checksum(ip_header))

    # 2. Layer 4 Checksum
    # Use the IPv4 total length, not len(pkt), because Ethernet frames can carry
    # padding/trailing bytes that are not part of the TCP/UDP checksum input.
    l4_len = total_len - ihl
    
    if protocol == 6:  # TCP
        csum_offset = l4_offset + 16
    else:              # UDP
        csum_offset = l4_offset + 6

    pkt[csum_offset : csum_offset+2] = b'\x00\x00'  # Zero out old L4 checksum

    # Create IP pseudo-header required for TCP/UDP checksum calculations
    # Src IP (4), Dst IP (4), Zero (1), Protocol (1), L4 Length (2)
    pseudo_header = struct.pack(
        "!4s4sBBH",
        pkt[ip_offset + 12:ip_offset + 16],
        pkt[ip_offset + 16:ip_offset + 20],
        0,
        protocol,
        l4_len,
    )
    
    l4_checksum = calculate_checksum(pseudo_header + pkt[l4_offset:ip_end])
    
    # UDP specific rule: if calculated checksum is 0, it must be set to 0xFFFF
    if protocol == 17 and l4_checksum == 0:
        l4_checksum = 0xFFFF

    struct.pack_into("!H", pkt, csum_offset, l4_checksum)

    return bytes(pkt)
