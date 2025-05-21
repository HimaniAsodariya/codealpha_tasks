import socket
import struct

# Format MAC address
def get_mac_addr(mac_bytes):
    return ':'.join(format(b, '02x') for b in mac_bytes).upper()

# Format IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Parse Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Parse IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Parse TCP segment
def tcp_segment(data):
    src_port, dest_port = struct.unpack('! H H', data[:4])
    return src_port, dest_port

# Main sniffer function
def main():
    # Create raw socket (AF_PACKET works only on Linux)
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("[*] Packet sniffing started... Press Ctrl+C to stop.\n")

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f"\nEthernet Frame:")
        print(f"  Source MAC: {src_mac}, Destination MAC: {dest_mac}, Protocol: {eth_proto}")

        # Process IPv4 packets (protocol 8)
        if eth_proto == 8:
            ip_header_len, ttl, proto, src_ip, dest_ip, data = ipv4_packet(data)
            print(f"  IP Packet:")
            print(f"    Source IP: {src_ip}, Destination IP: {dest_ip}, Protocol: {proto}")

            # Process TCP packets (protocol number 6)
            if proto == 6:
                src_port, dest_port = tcp_segment(data)
                print(f"    TCP Segment:")
                print(f"      Source Port: {src_port}, Destination Port: {dest_port}")

if __name__ == "__main__":
    main()
