import time
import socket
import struct
import threading
from unittest.mock import MagicMock, patch

from matzpin import Encryptor, IPV4_ETHERTYPE

# --- Mocking Dependencies ---
import sys
sys.modules['nat'] = MagicMock()
sys.modules['encryptor_utils'] = MagicMock()
sys.modules['arp_handler'] = MagicMock()

import nat
import encryptor_utils
import arp_handler

arp_handler.parse_ethernet_header.return_value = (b'\xaa'*6, b'\xbb'*6, IPV4_ETHERTYPE, b'\x45' + b'\x00'*19)
arp_handler.build_ethernet_frame.return_value = b'\x00' * 60
encryptor_utils.ReplayWindow = MagicMock

# --- ANSI Color Codes ---
class AnsiColor:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def generate_mock_ip_packet(length=100):
    """Generates a dummy IPv4 header and payload safely fitting the length."""
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, length, 0, 0, 64, 0, 0, b'\x01\x02\x03\x04', b'\x05\x06\x07\x08')
    payload = b'X' * max(0, length - len(header))
    return header + payload

def generate_mock_ethernet_frame(ip_packet):
    """Wraps an IP packet in a mock Ethernet Frame."""
    dst_mac = b'\x11\x22\x33\x44\x55\x66'
    src_mac = b'\xaa\xbb\xcc\xdd\xee\xff'
    ethertype = struct.pack('>H', IPV4_ETHERTYPE)
    return dst_mac + src_mac + ethertype + ip_packet

# --- Benchmarking Suite ---
class EncryptorBenchmark:
    def __init__(self):
        with patch('socket.socket'), \
             patch.object(Encryptor, '_get_nic_mac', return_value=b'\xaa'*6), \
             patch.object(Encryptor, '_get_nic_netmask', return_value=b'\xff'*4), \
             patch.object(Encryptor, '_get_default_gateway', return_value='192.168.1.1'):
            
            self.encryptor = Encryptor(
                is_server=False, 
                red_nic="eth0", 
                red_ip="192.168.1.50", 
                black_ip="192.168.1.100"
            )
        
        self.encryptor.black_connection = MagicMock()
        self.encryptor._stream_log = MagicMock()
        nat.nat_outbound = MagicMock(side_effect=lambda x: x)

    def _run_batch_processing(self, packet_size, total_packets, encrypt=True):
        """Processes a continuous stream of a specific packet size to find collective delay."""
        ip_packet = generate_mock_ip_packet(packet_size)
        frame = generate_mock_ethernet_frame(ip_packet)
        
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import pad
        import hashlib

        # Force pre-imports and local lookups to isolate crypto-execution time
        key = self.encryptor.key
        iv = b'\x00' * 16

        start_time = time.perf_counter()
        for _ in range(total_packets):
            parsed = arp_handler.parse_ethernet_header(frame)
            dst_mac, src_mac, ethertype, ip_bytes = parsed
            ip_bytes = nat.nat_outbound(ip_bytes)
            
            if encrypt:
                self.encryptor.sequence_counter += 1
                counter_bytes = struct.pack(">Q", self.encryptor.sequence_counter)
                key_id_byte = struct.pack(">B", self.encryptor.current_key_id)
                
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                padded_data = pad(ip_bytes, AES.block_size)
                ciphertext = cipher.encrypt(padded_data)
                
                encrypted_message_data = iv + ciphertext
                verify_input = key + key_id_byte + counter_bytes + encrypted_message_data
                verify_hash = hashlib.sha256(verify_input).digest()[:8]
                
                payload_body = verify_hash + key_id_byte + counter_bytes + encrypted_message_data
                header_length_bytes = len(payload_body).to_bytes(4, byteorder="big")
                wire_packet = header_length_bytes + payload_body
            else:
                # --- Raw Send Mode ---
                header_length_bytes = len(ip_bytes).to_bytes(4, byteorder="big")
                wire_packet = header_length_bytes + ip_bytes
                
            self.encryptor.black_connection.sendall(wire_packet)
            
        end_time = time.perf_counter()
        return end_time - start_time

    def compare_raw_vs_encrypted(self, packet_size=512, packets_per_step=90000):
        """Compares raw sending speed versus fully encrypted pipelines for a fixed packet size."""
        print(f"\n{AnsiColor.CYAN}{AnsiColor.BOLD}=== Comparative Test: Raw vs Encrypted ({packets_per_step} packets, {packet_size}B) ==={AnsiColor.RESET}")
        
        raw_delay = self._run_batch_processing(packet_size, packets_per_step, encrypt=False)
        enc_delay = self._run_batch_processing(packet_size, packets_per_step, encrypt=True)
        
        diff = enc_delay - raw_delay
        overhead_percent = (diff / raw_delay) * 100 if raw_delay > 0 else 0
        
        print(f"Raw Send Delay      : {AnsiColor.GREEN}{raw_delay:.4f} seconds{AnsiColor.RESET}")
        print(f"Encryptor Send Delay: {AnsiColor.RED}{enc_delay:.4f} seconds{AnsiColor.RESET}")
        print(f"Absolute Overhead    : {AnsiColor.YELLOW}{diff:.4f} seconds{AnsiColor.RESET}")
        print(f"Crypto Penalty       : {AnsiColor.RED}{AnsiColor.BOLD}+{overhead_percent:.2f}%{AnsiColor.RESET}")

    def benchmark_latency_vs_size(self, packets_per_step=50000):
        print(f"\n{AnsiColor.CYAN}{AnsiColor.BOLD}=== Running Latency vs. Packet Size Curve ({packets_per_step} packets per size) ==={AnsiColor.RESET}")
        
        packet_sizes = [64, 128, 256, 512, 768, 1024, 1280, 1500]
        raw_results = []
        enc_results = []

        for size in packet_sizes:
            raw_delay = self._run_batch_processing(size, packets_per_step, encrypt=False)
            enc_delay = self._run_batch_processing(size, packets_per_step, encrypt=True)
            
            raw_results.append((size, raw_delay))
            enc_results.append((size, enc_delay))
            
            print(f"Packet Size: {AnsiColor.BOLD}{size:4d} Bytes{AnsiColor.RESET} | "
                  f"Raw: {AnsiColor.GREEN}{raw_delay:.4f}s{AnsiColor.RESET} | "
                  f"Encrypted: {AnsiColor.RED}{enc_delay:.4f}s{AnsiColor.RESET}")

        self._draw_ascii_plot(raw_results, enc_results, packets_per_step)

    def _draw_ascii_plot(self, raw_data, enc_data, packet_count):
        """Generates an explicit text-based XY scatter graph comparing Raw vs Encrypted."""        
        print(f"\n{AnsiColor.CYAN}{AnsiColor.BOLD}=== Scatter Plot: Latency vs Packet Size ==={AnsiColor.RESET}")
        height = 12
        width = 60
        
        sizes = [point[0] for point in raw_data]
        all_delays = [point[1] for point in raw_data] + [point[1] for point in enc_data]
        
        min_x, max_x = min(sizes), max(sizes)
        min_y, max_y = min(all_delays), max(all_delays)
        
        y_range = (max_y - min_y) if max_y != min_y else 1.0
        x_range = (max_x - min_x) if max_x != min_x else 1.0

        grid = [[" " for _ in range(width)] for _ in range(height)]
        
        # Plot Raw Data (as Asterisks '*')
        for x_val, y_val in raw_data:
            col = int(((x_val - min_x) / x_range) * (width - 1))
            row = int(((y_val - min_y) / y_range) * (height - 1))
            grid[(height - 1) - row][col] = f"{AnsiColor.GREEN}*{AnsiColor.RESET}"

        # Plot Encrypted Data (as Crosses 'x')
        for x_val, y_val in enc_data:
            col = int(((x_val - min_x) / x_range) * (width - 1))
            row = int(((y_val - min_y) / y_range) * (height - 1))
            # If they land on the same character cell, we let Encrypted layer over it
            grid[(height - 1) - row][col] = f"{AnsiColor.RED}x{AnsiColor.RESET}"

        for r in range(height):
            curr_y = max_y - (r * (y_range / (height - 1)))
            row_str = "".join([char if char != " " else " " for char in grid[r]])
            print(f"{AnsiColor.YELLOW}{curr_y:6.3f}s{AnsiColor.RESET} | {row_str}")
            
        print(" " * 8 + "└" + "─" * width)
        x_axis_line = f"{min_x}B".ljust(width) + f"{max_x}B"
        print(" " * 9 + f"{AnsiColor.BOLD}{x_axis_line}{AnsiColor.RESET}")
        print(" " * (9 + width // 4) + f"{AnsiColor.CYAN}PACKET SIZE (BYTES) ──>{AnsiColor.RESET}")
        
        # Legend
        print(f"\n{' ' * 9}{AnsiColor.BOLD}Legend:{AnsiColor.RESET} "
              f"{AnsiColor.GREEN}* Raw Send{AnsiColor.RESET}   "
              f"{AnsiColor.RED}x Encrypted Send{AnsiColor.RESET}\n")


if __name__ == "__main__":
    bench = EncryptorBenchmark()
    
    # 1. Run comparative breakdown test
    bench.compare_raw_vs_encrypted(packet_size=512, packets_per_step=100000)
    
    # 2. Run size curve benchmark
    bench.benchmark_latency_vs_size(packets_per_step=45000)