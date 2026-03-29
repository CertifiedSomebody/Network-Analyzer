from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw
from collections import Counter
import time


class PacketAnalyzer:
    def __init__(self):
        # Stats
        self.protocol_count = Counter()
        self.ip_activity = Counter()

        # Logs
        self.packet_log = []

        # Suspicious tracking
        self.suspicious_ips = set()

        # Thresholds
        self.packet_threshold = 200

        # Suspicious ports (basic threat intel)
        self.suspicious_ports = {4444, 5555, 6666, 1337, 9999}

    # ---------------------------
    # MAIN ANALYSIS
    # ---------------------------
    def analyze(self, packet):
        if not packet.haslayer(IP):
            return None

        try:
            src = packet[IP].src
            dst = packet[IP].dst

            proto = self._get_protocol(packet)
            sport, dport = self._get_ports(packet)
            length = len(packet)

            # Update stats
            self.protocol_count[proto] += 1
            self.ip_activity[src] += 1

            # Deep inspection
            app_proto = self._detect_application(proto, dport)
            info = self._extract_payload_info(packet)

            # Direction
            direction = self._get_direction(src)

            # Alerts
            alerts = []
            suspicious = self._detect_suspicious(src)
            if suspicious:
                alerts.append(suspicious)

            port_alert = self._detect_suspicious_port(dport)
            if port_alert:
                alerts.append(port_alert)

            size_alert = self._detect_large_packet(length, src)
            if size_alert:
                alerts.append(size_alert)

            data = {
                "time": time.strftime("%H:%M:%S"),
                "src": src,
                "dst": dst,
                "protocol": proto,
                "app_proto": app_proto,
                "sport": sport,
                "dport": dport,
                "length": length,
                "direction": direction,
                "info": info,
                "alerts": alerts
            }

            # Maintain log size
            if len(self.packet_log) > 1000:
                self.packet_log.pop(0)

            self.packet_log.append(data)

            return data

        except Exception as e:
            print(f"[Analyzer Error] {e}")
            return None

    # ---------------------------
    # PROTOCOL DETECTION
    # ---------------------------
    def _get_protocol(self, packet):
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        else:
            return "OTHER"

    # ---------------------------
    # PORT EXTRACTION
    # ---------------------------
    def _get_ports(self, packet):
        try:
            if packet.haslayer(TCP):
                return packet[TCP].sport, packet[TCP].dport
            elif packet.haslayer(UDP):
                return packet[UDP].sport, packet[UDP].dport
        except:
            pass

        return None, None

    # ---------------------------
    # APPLICATION LAYER DETECTION
    # ---------------------------
    def _detect_application(self, proto, dport):
        if proto == "TCP":
            if dport == 80:
                return "HTTP"
            elif dport == 443:
                return "HTTPS"
            elif dport == 22:
                return "SSH"
            elif dport == 21:
                return "FTP"
            elif dport == 3389:
                return "RDP"

        if proto == "UDP":
            if dport == 53:
                return "DNS"

        return "UNKNOWN"

    # ---------------------------
    # DEEP PACKET INSPECTION 🔥
    # ---------------------------
    def _extract_payload_info(self, packet):
        try:
            # DNS Query
            if packet.haslayer(DNS) and packet[DNS].qd:
                return f"DNS Query: {packet[DNS].qd.qname.decode(errors='ignore')}"

            # HTTP Host
            if packet.haslayer(Raw):
                payload = packet[Raw].load

                if b"Host:" in payload:
                    host = payload.split(b"Host:")[1].split(b"\r\n")[0]
                    return f"HTTP: {host.decode(errors='ignore')}"

                if b"GET" in payload or b"POST" in payload:
                    return "HTTP Request"

            return None

        except:
            return None

    # ---------------------------
    # DIRECTION DETECTION
    # ---------------------------
    def _get_direction(self, src):
        if (
            src.startswith("192.168.") or
            src.startswith("10.") or
            src.startswith("172.16.")
        ):
            return "OUTGOING"
        return "INCOMING"

    # ---------------------------
    # SUSPICIOUS BEHAVIOR
    # ---------------------------
    def _detect_suspicious(self, src_ip):
        if self.ip_activity[src_ip] > self.packet_threshold:
            self.suspicious_ips.add(src_ip)
            return f"⚠️ High traffic from {src_ip}"
        return None

    # ---------------------------
    # SUSPICIOUS PORT DETECTION 🔥
    # ---------------------------
    def _detect_suspicious_port(self, dport):
        if dport in self.suspicious_ports:
            return f"🚨 Suspicious port access: {dport}"
        return None

    # ---------------------------
    # LARGE PACKET DETECTION
    # ---------------------------
    def _detect_large_packet(self, length, src):
        if length > 1500:
            return f"⚠️ Large packet from {src}"
        return None

    # ---------------------------
    # STATS
    # ---------------------------
    def get_stats(self):
        return dict(self.protocol_count)

    def get_top_ips(self, limit=5):
        return self.ip_activity.most_common(limit)

    # ---------------------------
    # RESET
    # ---------------------------
    def reset(self):
        self.protocol_count.clear()
        self.ip_activity.clear()
        self.packet_log.clear()
        self.suspicious_ips.clear()