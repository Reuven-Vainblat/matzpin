import struct
import socket
import time

# Ethernet constants
ETH_HEADER_LEN = 14
ARP_ETHERTYPE = 0x0806
IPV4_ETHERTYPE = 0x0800
BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'

# ARP opcodes
ARP_REQUEST = 1
ARP_REPLY = 2


class ArpTable:
    """Simple ARP cache mapping IP addresses (str) to MAC addresses (bytes)."""

    def __init__(self, timeout=300):
        self.timeout = timeout
        # ip_str -> {'mac': bytes(6), 'last_seen': float}
        self._table = {}

    def update(self, ip, mac):
        """Add or refresh an ARP entry."""
        self._table[ip] = {'mac': mac, 'last_seen': time.time()}

    def lookup(self, ip):
        """Look up a MAC for an IP.  Returns bytes(6) or None."""
        entry = self._table.get(ip)
        if entry is None:
            return None
        if time.time() - entry['last_seen'] > self.timeout:
            del self._table[ip]
            return None
        return entry['mac']

    def cleanup(self):
        """Remove expired entries."""
        now = time.time()
        expired = [ip for ip, e in self._table.items()
                   if now - e['last_seen'] > self.timeout]
        for ip in expired:
            del self._table[ip]


# ──────────────────────────────────────────────
# Ethernet helpers
# ──────────────────────────────────────────────

def parse_ethernet_header(frame):
    """Parse an Ethernet frame.

    Returns (dst_mac, src_mac, ethertype, payload) or None.
    """
    if len(frame) < ETH_HEADER_LEN:
        return None
    dst_mac = frame[0:6]
    src_mac = frame[6:12]
    ethertype = struct.unpack('!H', frame[12:14])[0]
    payload = frame[ETH_HEADER_LEN:]
    return dst_mac, src_mac, ethertype, payload


def build_ethernet_frame(dst_mac, src_mac, ethertype, payload):
    """Build an Ethernet frame from its components."""
    return dst_mac + src_mac + struct.pack('!H', ethertype) + payload


# ──────────────────────────────────────────────
# ARP packet helpers
# ──────────────────────────────────────────────

def parse_arp(arp_payload):
    """Parse an ARP packet (Ethernet payload, header already stripped).

    Returns a dict with sender_mac, sender_ip, target_mac, target_ip,
    opcode, etc.  Returns None if the payload is too short.
    """
    if len(arp_payload) < 28:
        return None

    hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack(
        '!HHBBH', arp_payload[0:8])

    sender_mac = arp_payload[8:14]
    sender_ip = socket.inet_ntoa(arp_payload[14:18])
    target_mac = arp_payload[18:24]
    target_ip = socket.inet_ntoa(arp_payload[24:28])

    return {
        'hw_type':    hw_type,
        'proto_type': proto_type,
        'hw_size':    hw_size,
        'proto_size': proto_size,
        'opcode':     opcode,
        'sender_mac': sender_mac,
        'sender_ip':  sender_ip,
        'target_mac': target_mac,
        'target_ip':  target_ip,
    }


def build_arp_reply(encryptor_mac, encryptor_ip, target_mac, target_ip):
    """Build a complete ARP reply Ethernet frame.

    "I am <encryptor_ip> and my MAC is <encryptor_mac>."
    """
    arp_payload = struct.pack('!HHBBH',
                              1,          # Hardware type: Ethernet
                              0x0800,     # Protocol type: IPv4
                              6,          # Hardware address size
                              4,          # Protocol address size
                              ARP_REPLY)
    arp_payload += encryptor_mac
    arp_payload += socket.inet_aton(encryptor_ip)
    arp_payload += target_mac
    arp_payload += socket.inet_aton(target_ip)

    return build_ethernet_frame(target_mac, encryptor_mac,
                                ARP_ETHERTYPE, arp_payload)


def build_arp_request(encryptor_mac, encryptor_ip, target_ip):
    """Build a complete ARP request Ethernet frame.

    "Who has <target_ip>?  Tell <encryptor_ip>."
    """
    arp_payload = struct.pack('!HHBBH',
                              1,            # Hardware type: Ethernet
                              0x0800,       # Protocol type: IPv4
                              6,            # Hardware address size
                              4,            # Protocol address size
                              ARP_REQUEST)
    arp_payload += encryptor_mac
    arp_payload += socket.inet_aton(encryptor_ip)
    arp_payload += b'\x00\x00\x00\x00\x00\x00'   # Target MAC (unknown)
    arp_payload += socket.inet_aton(target_ip)

    return build_ethernet_frame(BROADCAST_MAC, encryptor_mac,
                                ARP_ETHERTYPE, arp_payload)
