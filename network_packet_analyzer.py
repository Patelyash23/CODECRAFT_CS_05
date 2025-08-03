from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def packet_callback(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = 'Other'
        if packet.haslayer(TCP):
            proto = 'TCP'
        elif packet.haslayer(UDP):
            proto = 'UDP'
        elif packet.haslayer(ICMP):
            proto = 'ICMP'

        payload = bytes(packet.payload)
        payload_len = len(payload)

        print(f"\n[{timestamp}]")
        print(f"Protocol     : {proto}")
        print(f"Source IP    : {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Payload Size : {payload_len} bytes")

def main():
    try:
        count = int(input("Enter the number of packets to capture: "))
        print("\nStarting packet capture... Press Ctrl+C to stop early.")
        sniff(count=count, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
