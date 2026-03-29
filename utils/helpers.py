# helpers.py

import time
import socket
from functools import lru_cache


# ---------------------------
# Time Utilities
# ---------------------------
def get_current_time():
    return time.strftime("%H:%M:%S")


def get_timestamp():
    return time.time()


# ---------------------------
# Protocol Utilities
# ---------------------------
def get_protocol_name(packet):
    try:
        from scapy.all import TCP, UDP, ICMP

        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        else:
            return "OTHER"
    except:
        return "UNKNOWN"


# ---------------------------
# Application Layer Detection
# ---------------------------
def detect_application(proto, dport):
    if proto == "TCP":
        return {
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            21: "FTP",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            3389: "RDP"
        }.get(dport, "UNKNOWN")

    if proto == "UDP":
        return {
            53: "DNS",
            123: "NTP",
            67: "DHCP",
            68: "DHCP"
        }.get(dport, "UNKNOWN")

    return "UNKNOWN"


# ---------------------------
# IP Utilities
# ---------------------------
def safe_get_ip(packet):
    try:
        from scapy.all import IP

        if packet.haslayer(IP):
            return packet[IP].src, packet[IP].dst
    except:
        pass

    return None, None


def is_private_ip(ip):
    return (
        ip.startswith("192.168.") or
        ip.startswith("10.") or
        ip.startswith("172.")
    )


def get_direction(ip):
    if not ip:
        return "UNKNOWN"

    return "OUTGOING" if is_private_ip(ip) else "INCOMING"


# ---------------------------
# Hostname Resolver (Cached ⚡)
# ---------------------------
@lru_cache(maxsize=500)
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip


# ---------------------------
# Port Utilities
# ---------------------------
def get_ports(packet):
    try:
        from scapy.all import TCP, UDP

        if packet.haslayer(TCP):
            return packet[TCP].sport, packet[TCP].dport
        elif packet.haslayer(UDP):
            return packet[UDP].sport, packet[UDP].dport
    except:
        pass

    return None, None


# ---------------------------
# Packet Safety
# ---------------------------
def safe_packet_length(packet):
    try:
        return len(packet)
    except:
        return 0


def extract_basic_info(packet):
    """
    One-shot fast extractor (used for performance)
    """
    src, dst = safe_get_ip(packet)
    proto = get_protocol_name(packet)
    sport, dport = get_ports(packet)
    length = safe_packet_length(packet)

    return src, dst, proto, sport, dport, length


# ---------------------------
# Formatting Utilities
# ---------------------------
def format_alerts(alerts):
    if not alerts:
        return ""
    return ", ".join(alerts)


def format_stats(stats_dict):
    return "  ".join([f"{k}:{v}" for k, v in stats_dict.items()])


# ---------------------------
# Validation Utilities
# ---------------------------
def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except:
        return False


# ---------------------------
# Rate Calculation
# ---------------------------
def calculate_rate(count, duration):
    if duration <= 0:
        return 0
    return round(count / duration, 2)


# ---------------------------
# Debug Utility
# ---------------------------
def debug_log(message):
    print(f"[DEBUG {get_current_time()}] {message}")


# ---------------------------
# Memory Safety
# ---------------------------
def trim_list(lst, max_size=1000):
    """
    Prevent memory overflow in logs
    """
    if len(lst) > max_size:
        del lst[:len(lst) - max_size]