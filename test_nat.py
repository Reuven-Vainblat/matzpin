import time
import struct
import socket
from scapy.all import rdpcap, wrpcap, IP
import nat
# ==========================================
# 2. SCAPY PCAP HARNESS
# ==========================================
def process_pcap_with_scapy(input_pcap: str, output_pcap: str):
    print(f"Reading '{input_pcap}'...")
    try:
        packets = rdpcap(input_pcap)
    except FileNotFoundError:
        print(f"Error: Could not find '{input_pcap}'")
        return

    output_packets = []
    dropped_count = 0

    for pkt in packets:
        # If it doesn't have an IP layer, pass it through untouched
        if IP not in pkt:
            output_packets.append(pkt)
            continue
            
        # 1. Separate Layer 2 (Ethernet/etc.) from Layer 3 (IP)
        raw_pkt_bytes = bytes(pkt)
        raw_ip_bytes = bytes(pkt[IP])
        
        # Calculate where the IP layer starts to save the L2 header
        l2_offset = len(raw_pkt_bytes) - len(raw_ip_bytes)
        l2_bytes = raw_pkt_bytes[:l2_offset]
        
        # 2. Run the raw IP bytes through your pure-Python logic
        natted_ip_bytes = nat.handle_packet_bytes(raw_ip_bytes)
        
        # 3. Handle the result
        if natted_ip_bytes is not None:
            # Reattach the L2 header to the new IP bytes
            new_pkt_bytes = l2_bytes + natted_ip_bytes
            
            # Parse it back into a Scapy packet using the original packet's base class (e.g., Ether)
            # This allows Scapy to write it out cleanly to the pcap
            new_pkt = pkt.__class__(new_pkt_bytes)
            output_packets.append(new_pkt)
        else:
            # Packet was dropped by NAT logic
            dropped_count += 1

    print(f"Processed {len(packets)} packets.")
    print(f"Dropped {dropped_count} packets (unmapped inbound NAT).")
    print(f"Writing {len(output_packets)} packets to '{output_pcap}'...")
    
    wrpcap(output_pcap, output_packets)
    print("Done! Open the output PCAP in Wireshark to verify.")

if __name__ == "__main__":
    # Create a test input PCAP (e.g., using tcpdump or wireshark), then run this:
    process_pcap_with_scapy("input.pcap", "natted_output.pcap")