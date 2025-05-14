#!/usr/bin/env python3

import socket
import struct
import argparse
import logging
import sys
import ipaddress

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ICMPv6 Neighbor Solicitation Message Type
ICMPv6_NS = 135
# ICMPv6 Router Solicitation Message Type
ICMPv6_RS = 133
# ICMPv6 Type for Echo Request (Ping)
ICMPv6_ECHO_REQUEST = 128

# IPv6 All-Nodes Multicast Address
ALL_NODES_MCAST = "ff02::1"

def setup_argparse():
    """
    Sets up the argument parser for the script.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Discovers IPv6 hosts on a local network using ICMPv6 Neighbor Solicitation and Router Solicitation messages.")
    parser.add_argument("-i", "--interface", dest="interface", help="Network interface to use (e.g., eth0)", required=True)
    parser.add_argument("-t", "--target", dest="target", help="Target IPv6 address (optional, scans local network if not provided). Can be a single address or a subnet (e.g., 2001:db8::/64)", required=False)
    parser.add_argument("-r", "--router-solicitation", dest="router_solicitation", action="store_true", help="Send Router Solicitation messages (default: Neighbor Solicitation)", required=False)
    parser.add_argument("-p", "--ping", dest="ping", action="store_true", help="Send ICMPv6 Echo Request (Ping) to discovered hosts", required=False)
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Enable verbose output for debugging.", required=False)
    return parser

def craft_icmpv6_ns(target_ip):
    """
    Crafts an ICMPv6 Neighbor Solicitation message.

    Args:
        target_ip (str): The target IPv6 address.

    Returns:
        bytes: The ICMPv6 Neighbor Solicitation message.
    """
    try:
        # ICMPv6 Header
        icmpv6_type = ICMPv6_NS
        icmpv6_code = 0
        icmpv6_checksum = 0  # Placeholder for checksum calculation
        icmpv6_reserved = 0

        # Neighbor Solicitation Body
        target_address = socket.inet_pton(socket.AF_INET6, target_ip)
        source_link_layer_address_option = b'\x01\x01\x00\x00\x00\x00\x00\x00'  # Type 1 (Source Link-Layer Address), Length 1, MAC address (placeholder)
        
        # Pack the header and body
        icmpv6_packet = struct.pack("!BBHL", icmpv6_type, icmpv6_code, icmpv6_checksum, icmpv6_reserved) + target_address + source_link_layer_address_option

        # Calculate Checksum (pseudo-header is needed for IPv6)
        checksum = calculate_checksum_ipv6(icmpv6_packet, source_ip="::", dest_ip=target_ip, next_header=58) # 58 is ICMPv6

        # Re-pack with the calculated checksum
        icmpv6_packet = struct.pack("!BBHL", icmpv6_type, icmpv6_code, checksum, icmpv6_reserved) + target_address + source_link_layer_address_option

        return icmpv6_packet
    except Exception as e:
        logging.error(f"Error crafting ICMPv6 Neighbor Solicitation: {e}")
        return None

def craft_icmpv6_rs():
    """
    Crafts an ICMPv6 Router Solicitation message.

    Returns:
        bytes: The ICMPv6 Router Solicitation message.
    """
    try:
        # ICMPv6 Header
        icmpv6_type = ICMPv6_RS
        icmpv6_code = 0
        icmpv6_checksum = 0  # Placeholder for checksum calculation
        icmpv6_reserved = 0

        # Router Solicitation Body (no options in this basic implementation)
        icmpv6_packet = struct.pack("!BBHL", icmpv6_type, icmpv6_code, icmpv6_checksum, icmpv6_reserved)
        
        # Calculate Checksum (pseudo-header is needed for IPv6)
        checksum = calculate_checksum_ipv6(icmpv6_packet, source_ip="::", dest_ip=ALL_NODES_MCAST, next_header=58) # 58 is ICMPv6

        # Re-pack with the calculated checksum
        icmpv6_packet = struct.pack("!BBHL", icmpv6_type, icmpv6_code, checksum, icmpv6_reserved)

        return icmpv6_packet
    except Exception as e:
        logging.error(f"Error crafting ICMPv6 Router Solicitation: {e}")
        return None

def craft_icmpv6_echo_request(identifier=12345, sequence_number=1):
    """
    Crafts an ICMPv6 Echo Request (Ping) message.

    Args:
        identifier (int): The identifier for the ping.
        sequence_number (int): The sequence number for the ping.

    Returns:
        bytes: The ICMPv6 Echo Request message.
    """
    try:
        # ICMPv6 Header
        icmpv6_type = ICMPv6_ECHO_REQUEST
        icmpv6_code = 0
        icmpv6_checksum = 0  # Placeholder for checksum calculation

        # ICMPv6 Echo Request Body
        icmpv6_identifier = identifier
        icmpv6_sequence_number = sequence_number
        icmpv6_data = b"Hello, IPv6 World!"

        # Pack the header and body
        icmpv6_packet = struct.pack("!BBH", icmpv6_type, icmpv6_code, icmpv6_checksum) + struct.pack("!HH", icmpv6_identifier, icmpv6_sequence_number) + icmpv6_data

        return icmpv6_packet
    except Exception as e:
        logging.error(f"Error crafting ICMPv6 Echo Request: {e}")
        return None


def calculate_checksum_ipv6(packet, source_ip, dest_ip, next_header):
    """
    Calculates the checksum for an IPv6 ICMPv6 packet.

    Args:
        packet (bytes): The ICMPv6 packet.
        source_ip (str): The source IPv6 address.
        dest_ip (str): The destination IPv6 address.
        next_header (int): The next header field (58 for ICMPv6).

    Returns:
        int: The calculated checksum.
    """
    try:
        src_addr = socket.inet_pton(socket.AF_INET6, source_ip)
        dst_addr = socket.inet_pton(socket.AF_INET6, dest_ip)
        
        # Pseudo-Header
        pseudo_header = src_addr + dst_addr
        pseudo_header += struct.pack("!LL", len(packet), next_header)
        
        # Combine pseudo-header and packet
        combined_data = pseudo_header + packet

        # Pad with a zero byte if the length is odd
        if len(combined_data) % 2 != 0:
            combined_data += b'\x00'

        checksum = 0
        for i in range(0, len(combined_data), 2):
            word = (combined_data[i] << 8) + combined_data[i + 1]
            checksum += word
        
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += (checksum >> 16)
        checksum = ~checksum & 0xffff

        return checksum
    except Exception as e:
        logging.error(f"Error calculating checksum: {e}")
        return 0

def send_icmpv6_message(interface, target_ip, message):
    """
    Sends an ICMPv6 message to the specified target.

    Args:
        interface (str): The network interface to use.
        target_ip (str): The target IPv6 address.
        message (bytes): The ICMPv6 message to send.
    """
    try:
        # Create a raw socket for IPv6 ICMP
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        sock.bind((interface, 0))
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_HOPLIMIT, 255)  # Set Hop Limit

        # Send the message
        sock.sendto(message, (target_ip, 0))  # Port is irrelevant for ICMP

        sock.close()

    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except Exception as e:
        logging.error(f"Error sending ICMPv6 message: {e}")

def scan_network(interface, target, router_solicitation, ping, verbose):
    """
    Scans the network for IPv6 hosts.

    Args:
        interface (str): The network interface to use.
        target (str): The target IPv6 address or subnet. If None, scans the all-nodes multicast address.
        router_solicitation (bool): Whether to send Router Solicitation messages instead of Neighbor Solicitation.
        ping (bool): Whether to send ICMPv6 Echo Requests (Ping) to discovered hosts.
        verbose (bool): Whether to enable verbose output.
    """
    try:
        if target:
            try:
                # Check if the target is a network
                network = ipaddress.ip_network(target, strict=False)
                if verbose:
                    logging.info(f"Scanning network: {network}")

                for ip in network.hosts():
                    target_ip = str(ip)
                    if router_solicitation:
                        message = craft_icmpv6_rs()
                        if message:
                            send_icmpv6_message(interface, ALL_NODES_MCAST, message)
                            logging.info(f"Sent Router Solicitation to {ALL_NODES_MCAST}")
                    else:
                        message = craft_icmpv6_ns(target_ip)
                        if message:
                            send_icmpv6_message(interface, target_ip, message)
                            logging.info(f"Sent Neighbor Solicitation to {target_ip}")
                    
                    if ping:
                        ping_message = craft_icmpv6_echo_request()
                        if ping_message:
                             send_icmpv6_message(interface, target_ip, ping_message)
                             logging.info(f"Sent ICMPv6 Echo Request to {target_ip}")

            except ValueError:
                # Assume the target is a single IP address
                target_ip = target
                if verbose:
                    logging.info(f"Scanning single host: {target_ip}")

                if router_solicitation:
                    message = craft_icmpv6_rs()
                    if message:
                        send_icmpv6_message(interface, ALL_NODES_MCAST, message)
                        logging.info(f"Sent Router Solicitation to {ALL_NODES_MCAST}")
                else:
                    message = craft_icmpv6_ns(target_ip)
                    if message:
                        send_icmpv6_message(interface, target_ip, message)
                        logging.info(f"Sent Neighbor Solicitation to {target_ip}")
                    
                if ping:
                    ping_message = craft_icmpv6_echo_request()
                    if ping_message:
                         send_icmpv6_message(interface, target_ip, ping_message)
                         logging.info(f"Sent ICMPv6 Echo Request to {target_ip}")

        else:
            # Scan the all-nodes multicast address
            if verbose:
                logging.info("Scanning all-nodes multicast address.")

            if router_solicitation:
                message = craft_icmpv6_rs()
                if message:
                    send_icmpv6_message(interface, ALL_NODES_MCAST, message)
                    logging.info(f"Sent Router Solicitation to {ALL_NODES_MCAST}")
            else:
                logging.warning("No target specified.  Neighbor Solicitation requires a target address.  Use Router Solicitation (-r) to discover routers.")
                return

    except Exception as e:
        logging.error(f"Error during network scan: {e}")

def main():
    """
    Main function of the script.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not args.interface:
        logging.error("Interface is required. Use -i or --interface.")
        sys.exit(1)

    scan_network(args.interface, args.target, args.router_solicitation, args.ping, args.verbose)

if __name__ == "__main__":
    main()