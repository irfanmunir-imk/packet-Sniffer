#!/usr/bin/env python3
"""
=============================================================
  PACKET SNIFFER - Educational Network Traffic Analyzer
  Author  : Irfan (Educational Project)
  Purpose : Capture & analyze raw network packets
  Usage   : sudo python3 packet_sniffer.py
=============================================================

WARNING: Use ONLY on networks you own or have permission to monitor.
         Unauthorized packet sniffing is illegal.
"""

import socket
import struct
import textwrap
import sys
import os

# ─────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────
TAB_1 = '\t '
TAB_2 = '\t\t '
TAB_3 = '\t\t\t '
TAB_4 = '\t\t\t\t '
DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


# ─────────────────────────────────────────────
#  HELPER FUNCTIONS
# ─────────────────────────────────────────────

def format_multi_line(prefix, string, size=80):
    """Format data into readable multiline output."""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def get_mac_addr(bytes_addr):
    """Convert raw bytes to readable MAC address (AA:BB:CC:DD:EE:FF)."""
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv4(addr):
    """Convert raw bytes to readable IPv4 address."""
    return '.'.join(map(str, addr))


# ─────────────────────────────────────────────
#  ETHERNET FRAME PARSER
# ─────────────────────────────────────────────

def ethernet_frame(data):
    """
    Parse Ethernet frame.
    Returns: dest_mac, src_mac, protocol, payload
    """
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# ─────────────────────────────────────────────
#  IPv4 PACKET PARSER
# ─────────────────────────────────────────────

def ipv4_packet(data):
    """
    Parse IPv4 packet header.
    Returns: version, header_len, ttl, proto, src, target, payload
    """
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]


# ─────────────────────────────────────────────
#  ICMP PACKET PARSER
# ─────────────────────────────────────────────

def icmp_packet(data):
    """Parse ICMP packet. Returns: type, code, checksum, payload"""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# ─────────────────────────────────────────────
#  TCP SEGMENT PARSER
# ─────────────────────────────────────────────

def tcp_segment(data):
    """
    Parse TCP segment.
    Returns: src_port, dest_port, sequence, acknowledgement, flags, payload
    flags dict keys: URG, ACK, PSH, RST, SYN, FIN
    """
    (src_port, dest_port, sequence,
     acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])

    offset = (offset_reserved_flags >> 12) * 4  # data offset (header length)
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    flags = {
        'URG': flag_urg,
        'ACK': flag_ack,
        'PSH': flag_psh,
        'RST': flag_rst,
        'SYN': flag_syn,
        'FIN': flag_fin
    }

    return src_port, dest_port, sequence, acknowledgement, flags, data[offset:]


# ─────────────────────────────────────────────
#  UDP SEGMENT PARSER
# ─────────────────────────────────────────────

def udp_segment(data):
    """Parse UDP segment. Returns: src_port, dest_port, length, payload"""
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# ─────────────────────────────────────────────
#  DISPLAY FUNCTIONS
# ─────────────────────────────────────────────

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════╗
║          PACKET SNIFFER - Educational Project            ║
║          Capture & Analyze Network Traffic               ║
║   WARNING: Use only on networks you own/have permission  ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_ethernet(dest_mac, src_mac, proto, packet_num):
    print(f"\n{'='*60}")
    print(f"  [PACKET #{packet_num}]")
    print(f"{'='*60}")
    print(f"  [ETHERNET FRAME]")
    print(f"{TAB_1}Destination MAC : {dest_mac}")
    print(f"{TAB_1}Source MAC      : {src_mac}")
    print(f"{TAB_1}Protocol        : {proto}")


def print_ipv4(version, header_len, ttl, proto, src, target):
    print(f"\n{TAB_1}[IPv4 PACKET]")
    print(f"{TAB_2}Version         : {version}")
    print(f"{TAB_2}Header Length   : {header_len}")
    print(f"{TAB_2}TTL             : {ttl}")
    print(f"{TAB_2}Protocol        : {proto}")
    print(f"{TAB_2}Source IP       : {src}")
    print(f"{TAB_2}Target IP       : {target}")


def print_tcp(src_port, dest_port, seq, ack, flags, data):
    active_flags = [k for k, v in flags.items() if v]
    print(f"\n{TAB_2}  [TCP SEGMENT]")
    print(f"{TAB_3}Source Port     : {src_port}")
    print(f"{TAB_3}Dest Port       : {dest_port}")
    print(f"{TAB_3}Sequence        : {seq}")
    print(f"{TAB_3}Acknowledgement : {ack}")
    print(f"{TAB_3}Flags           : {', '.join(active_flags) if active_flags else 'None'}")
    print(f"{TAB_4}  URG={flags['URG']}  ACK={flags['ACK']}  PSH={flags['PSH']}")
    print(f"{TAB_4}  RST={flags['RST']}  SYN={flags['SYN']}  FIN={flags['FIN']}")
    if len(data) > 0:
        print(f"{TAB_3}Data ({len(data)} bytes):")
        print(format_multi_line(DATA_TAB_4, data))


def print_udp(src_port, dest_port, length, data):
    print(f"\n{TAB_2}  [UDP SEGMENT]")
    print(f"{TAB_3}Source Port     : {src_port}")
    print(f"{TAB_3}Dest Port       : {dest_port}")
    print(f"{TAB_3}Length          : {length}")
    if len(data) > 0:
        print(f"{TAB_3}Data ({len(data)} bytes):")
        print(format_multi_line(DATA_TAB_4, data))


def print_icmp(icmp_type, code, checksum, data):
    print(f"\n{TAB_2}  [ICMP PACKET]")
    print(f"{TAB_3}Type            : {icmp_type}")
    print(f"{TAB_3}Code            : {code}")
    print(f"{TAB_3}Checksum        : {checksum}")
    if len(data) > 0:
        print(f"{TAB_3}Data ({len(data)} bytes):")
        print(format_multi_line(DATA_TAB_4, data))


def print_raw(data):
    print(f"\n{TAB_1}  [OTHER / RAW DATA]")
    print(format_multi_line(DATA_TAB_2, data))


# ─────────────────────────────────────────────
#  MAIN SNIFFER LOOP
# ─────────────────────────────────────────────

def main():
    # Check root/admin privilege
    if os.geteuid() != 0:
        print("\n[ERROR] This script requires root privileges.")
        print("        Run with: sudo python3 packet_sniffer.py\n")
        sys.exit(1)

    print_banner()
    print("[*] Starting packet capture... Press Ctrl+C to stop.\n")

    # AF_PACKET = raw socket at device driver level (Linux only)
    # ETH_P_ALL = capture all protocols
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except AttributeError:
        print("[ERROR] AF_PACKET not available. This script requires Linux.")
        sys.exit(1)
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo.")
        sys.exit(1)

    packet_num = 0

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            packet_num += 1

            # ── Layer 2: Ethernet ──────────────────────────────
            dest_mac, src_mac, eth_proto, payload = ethernet_frame(raw_data)
            print_ethernet(dest_mac, src_mac, eth_proto, packet_num)

            # ── Layer 3: IPv4 (protocol 8) ─────────────────────
            if eth_proto == 8:
                version, header_len, ttl, proto, src, target, ip_data = ipv4_packet(payload)
                print_ipv4(version, header_len, ttl, proto, src, target)

                # ── Layer 4: ICMP (protocol 1) ─────────────────
                if proto == 1:
                    icmp_type, code, checksum, icmp_data = icmp_packet(ip_data)
                    print_icmp(icmp_type, code, checksum, icmp_data)

                # ── Layer 4: TCP (protocol 6) ──────────────────
                elif proto == 6:
                    src_port, dest_port, seq, ack, flags, tcp_data = tcp_segment(ip_data)
                    print_tcp(src_port, dest_port, seq, ack, flags, tcp_data)

                # ── Layer 4: UDP (protocol 17) ─────────────────
                elif proto == 17:
                    src_port, dest_port, udp_len, udp_data = udp_segment(ip_data)
                    print_udp(src_port, dest_port, udp_len, udp_data)

                # ── Other IPv4 protocols ───────────────────────
                else:
                    print(f"\n{TAB_1}  [OTHER IPv4 PROTOCOL: {proto}]")
                    print(format_multi_line(DATA_TAB_2, ip_data))

            # ── Non-IPv4 frames ────────────────────────────────
            else:
                print_raw(payload)

    except KeyboardInterrupt:
        print(f"\n\n[*] Capture stopped. Total packets captured: {packet_num}")
        print("[*] Goodbye!\n")


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == '__main__':
    main()
