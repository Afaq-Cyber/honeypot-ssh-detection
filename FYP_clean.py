"""
================================================================================
  Real-Time SSH Intrusion Detector
  Final Year Project — University of Agriculture Peshawar (2024)
  Authors: Afaq Ali & Yawar Hassan
  Supervisor: Mr. Nisar Ali, Lecturer ICS/IT
================================================================================

Description:
    Monitors live network traffic for SSH connection attempts (TCP port 22).
    On detecting an attempt, resolves the attacker's MAC address via ARP and
    immediately prints a formatted alert with IP, MAC, and timestamp.

Technical stack:
    - PyShark  : Live packet capture (wrapper around Wireshark/tshark)
    - Scapy    : ARP-based MAC address resolution
    - Threading: Non-blocking capture — runs in background thread
    - BPF filter: Restricts capture to TCP port 22 only (SSH)

Network interface:
    Configured for 'ens33' — VMware virtual NIC.
    Change to your active interface (e.g. eth0, wlan0) as needed.

Usage:
    sudo python3 FYP.py   (root required for raw packet capture)

Requirements:
    pip install pyshark scapy
    tshark must be installed: sudo apt install tshark
================================================================================
"""

import threading
import pyshark
from scapy.all import ARP, Ether, srp
from datetime import datetime


# ── MAC Resolution ────────────────────────────────────────────────────────────

def get_mac(ip):
    """
    Resolve a local IP address to its MAC address using ARP.

    Sends an ARP broadcast to the network and waits up to 1 second
    for a reply from the target IP. Returns the MAC address string
    if found, or None if the host does not respond.

    Args:
        ip (str): IPv4 address to resolve (e.g. '192.168.20.128')

    Returns:
        str | None: MAC address in 'xx:xx:xx:xx:xx:xx' format, or None
    """
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None


# ── Timestamp ─────────────────────────────────────────────────────────────────

def get_current_datetime():
    """
    Return the current date and time as a formatted string.

    Returns:
        str: Timestamp in 'YYYY-MM-DD HH:MM:SS' format
    """
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")


# ── Alert Banner ──────────────────────────────────────────────────────────────

def print_banner(ip, mac, timestamp):
    """
    Print a formatted intrusion alert to the terminal.

    Displays a bordered banner with the attacker's IP, MAC address,
    and the time the SSH attempt was detected.

    Args:
        ip        (str): Attacker's source IP address
        mac       (str): Attacker's MAC address (resolved via ARP)
        timestamp (str): Detection timestamp
    """
    banner = f"""


                                      *********************************************
                                      *                                           *
                                      *         Yawar & Afaq Cyber Security       *
                                      *                                           *
                                      *         SSH Access Attempt Detected       *
                                      *                                           *
                                      *********************************************
                                      * Attacker IP   : {ip:<22}*
                                      * Attacker MAC  : {str(mac):<22}*
                                      * Time & Date   : {timestamp:<22}*
                                      *********************************************


"""
    print(banner)


# ── Packet Handler ────────────────────────────────────────────────────────────

def packet_callback(packet):
    """
    Process each captured packet and trigger alert on SSH detection.

    Called automatically by PyShark for every packet that passes the
    BPF filter (tcp port 22). Checks that the packet has an IP layer
    and is destined for port 22, then resolves the source MAC and
    prints the intrusion banner.

    Args:
        packet: PyShark packet object
    """
    if 'IP' in packet:
        ip_src = packet.ip.src

        # Trigger only on TCP traffic targeting SSH port 22
        if 'TCP' in packet and packet.tcp.dstport == '22':
            mac_src = get_mac(ip_src)
            timestamp = get_current_datetime()
            print_banner(ip_src, mac_src, timestamp)


# ── Capture Engine ────────────────────────────────────────────────────────────

def start_packet_capture():
    """
    Start live packet capture on the configured network interface.

    Uses PyShark's LiveCapture with a BPF filter restricting capture
    to TCP port 22 only. Applies packet_callback to every packet.

    Note: 'ens33' is the VMware virtual NIC name. Change to your
    active interface if deploying in a different environment
    (e.g. 'eth0', 'wlan0', 'enp3s0').
    """
    capture = pyshark.LiveCapture(
        interface='ens33',
        bpf_filter='tcp port 22'
    )
    capture.apply_on_packets(packet_callback)


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":

    welcome_message = """

                                    **************************************************
                                    *                                                *
                                    *      Welcome to Yawar & Afaq Cyber World       *
                                    *                                                *
                                    *         Monitoring SSH Access Attempts         *
                                    *                                                *
                                    **************************************************
"""
    print(welcome_message)

    # Launch packet capture in a background thread (non-blocking)
    capture_thread = threading.Thread(target=start_packet_capture)
    capture_thread.daemon = True   # Thread exits cleanly when main process ends
    capture_thread.start()

    print("                                              Packet capturing is running...")
    print("                                                  Honeypot is Activated")

    # Keep main thread alive while capture thread runs
    capture_thread.join()
