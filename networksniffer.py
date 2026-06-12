from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
def process_packet(packet):
    print("\n========================")
    print("New Packet Captured")
    print("========================")
    # Check whether packet contains IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print("Source IP:", ip_layer.src)
        print("Destination IP:", ip_layer.dst)
        # Detect protocol
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print("Protocol: TCP")
            print("Source Port:", tcp_layer.sport)
            print("Destination Port:", tcp_layer.dport)
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print("Protocol: UDP")
            print("Source Port:", udp_layer.sport)
            print("Destination Port:", udp_layer.dport)
        else:
            print("Protocol: Other")
        # Display payload if available
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print("Payload:")
            print(payload)
print("Starting Packet Sniffer...")
sniff(
    prn=process_packet,
    store=False
)