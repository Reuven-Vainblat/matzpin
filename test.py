import socket
import struct
import unittest

import nat


ETH_HEADER = (
    b"\xaa\xbb\xcc\xdd\xee\xff"
    b"\x11\x22\x33\x44\x55\x66"
    b"\x08\x00"
)


def make_udp_packet(src_ip, dst_ip, src_port, dst_port, payload=b"hello"):
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    udp_len = 8 + len(payload)
    total_len = 20 + udp_len

    packet = bytearray(
        struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 1, 0, 64, 17, 0, src, dst)
        + struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        + payload
    )

    struct.pack_into("!H", packet, 10, nat.calculate_checksum(packet[:20]))
    pseudo_header = struct.pack("!4s4sBBH", src, dst, 0, 17, udp_len)
    udp_checksum = nat.calculate_checksum(pseudo_header + packet[20:])
    if udp_checksum == 0:
        udp_checksum = 0xFFFF
    struct.pack_into("!H", packet, 26, udp_checksum)

    return bytes(packet)


def inet_at(packet, offset):
    return socket.inet_ntoa(packet[offset:offset + 4])


def udp_ports_at(packet, offset):
    return struct.unpack("!HH", packet[offset:offset + 4])


def valid_ip_checksum(packet, ip_offset):
    ihl = (packet[ip_offset] & 0x0F) * 4
    return nat.calculate_checksum(packet[ip_offset:ip_offset + ihl]) == 0


def valid_udp_checksum(packet, ip_offset):
    ihl = (packet[ip_offset] & 0x0F) * 4
    total_len = struct.unpack("!H", packet[ip_offset + 2:ip_offset + 4])[0]
    l4_offset = ip_offset + ihl
    l4_len = total_len - ihl
    pseudo_header = struct.pack(
        "!4s4sBBH",
        packet[ip_offset + 12:ip_offset + 16],
        packet[ip_offset + 16:ip_offset + 20],
        0,
        17,
        l4_len,
    )
    return nat.calculate_checksum(pseudo_header + packet[l4_offset:ip_offset + total_len]) == 0


class NatTests(unittest.TestCase):
    def setUp(self):
        nat.NAT_TABLE.clear()
        nat.REVERSE_TABLE.clear()
        nat.NEXT_PORT = 40000

    def test_outbound_raw_ipv4_packet_is_translated(self):
        packet = make_udp_packet("192.168.1.10", "8.8.8.8", 12345, 53)

        translated = nat.handle_packet_bytes(packet)

        self.assertIsNotNone(translated)
        self.assertEqual(inet_at(translated, 12), nat.EXTERNAL_IP)
        self.assertEqual(udp_ports_at(translated, 20), (40000, 53))
        self.assertTrue(valid_ip_checksum(translated, 0))
        self.assertTrue(valid_udp_checksum(translated, 0))

    def test_outbound_ethernet_ipv4_frame_is_translated(self):
        packet = make_udp_packet("192.168.1.10", "8.8.8.8", 12345, 53)
        frame = ETH_HEADER + packet

        translated = nat.handle_packet_bytes(frame)

        self.assertIsNotNone(translated)
        self.assertEqual(translated[:14], ETH_HEADER)
        self.assertEqual(inet_at(translated, 26), nat.EXTERNAL_IP)
        self.assertEqual(udp_ports_at(translated, 34), (40000, 53))
        self.assertTrue(valid_ip_checksum(translated, 14))
        self.assertTrue(valid_udp_checksum(translated, 14))

    def test_inbound_ethernet_ipv4_frame_uses_reverse_table(self):
        outbound = ETH_HEADER + make_udp_packet("192.168.1.10", "8.8.8.8", 12345, 53)
        nat.handle_packet_bytes(outbound)
        inbound = ETH_HEADER + make_udp_packet("8.8.8.8", nat.EXTERNAL_IP, 53, 40000)

        translated = nat.handle_packet_bytes(inbound)

        self.assertIsNotNone(translated)
        self.assertEqual(translated[:14], ETH_HEADER)
        self.assertEqual(inet_at(translated, 30), "192.168.1.10")
        self.assertEqual(udp_ports_at(translated, 34), (53, 12345))
        self.assertTrue(valid_ip_checksum(translated, 14))
        self.assertTrue(valid_udp_checksum(translated, 14))

    def test_non_ipv4_ethernet_frame_is_unchanged(self):
        arp_frame = (
            b"\xaa\xbb\xcc\xdd\xee\xff"
            b"\x11\x22\x33\x44\x55\x66"
            b"\x08\x06"
            b"\x00" * 28
        )

        translated = nat.handle_packet_bytes(arp_frame)

        self.assertEqual(translated, arp_frame)
        self.assertEqual(nat.NAT_TABLE, {})
        self.assertEqual(nat.REVERSE_TABLE, {})


if __name__ == "__main__":
    unittest.main()
