from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, L3RawSocket
import json
import sys
import os

# Read interface from argument
iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"

# Path to log file
log_file = os.path.join(os.path.dirname(__file__), "packets_log.json")

# Ensure Layer 3 socket
conf.L3socket = L3RawSocket

# Packet list (in memory)
packets = []

# Packet processing
def process_packet(pkt):
    if pkt.haslayer(IP):
        proto = "Other"
        src_port = dst_port = None
        if pkt.haslayer(TCP):
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        pkt_info = {
            "Protocol": proto,
            "Source IP": pkt[IP].src,
            "Source Port": src_port,
            "Destination IP": pkt[IP].dst,
            "Destination Port": dst_port,
            "Length": len(pkt)
        }
        packets.append(pkt_info)

        # Write last 100 packets to JSON file
        with open(log_file, "w") as f:
            json.dump(packets[-100:], f)

# Start sniffing
sniff(prn=process_packet, store=False, iface=iface)
