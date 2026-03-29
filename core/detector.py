from collections import defaultdict
import time


class ThreatDetector:
    def __init__(self):
        # Activity tracking
        self.ip_timestamps = defaultdict(list)
        self.icmp_timestamps = defaultdict(list)
        self.ip_ports = defaultdict(set)

        # Advanced tracking
        self.packet_sizes = defaultdict(list)
        self.last_seen = defaultdict(float)

        # Cooldown
        self.alert_cooldown = {}

        # ---------------------------
        # THRESHOLDS
        # ---------------------------
        self.TIME_WINDOW = 5
        self.FLOOD_THRESHOLD = 60
        self.PORT_SCAN_THRESHOLD = 15
        self.ICMP_THRESHOLD = 25
        self.COOLDOWN = 5

        # Advanced thresholds
        self.BEACON_INTERVAL_TOLERANCE = 0.5
        self.BEACON_MIN_PACKETS = 6
        self.BURST_THRESHOLD = 40

        # Suspicious ports
        self.SUSPICIOUS_PORTS = {
            21, 22, 23, 445, 3389, 4444, 5555, 6666, 1337
        }

    # ---------------------------
    # MAIN ANALYSIS
    # ---------------------------
    def analyze(self, data):
        try:
            src = data.get("src")
            proto = data.get("protocol")
            dport = data.get("dport")
            length = data.get("length", 0)
            direction = data.get("direction")

            if not src:
                return None

            now = time.time()
            alerts = []

            # ---------------------------
            # CLEAN OLD DATA
            # ---------------------------
            self.ip_timestamps[src] = [
                t for t in self.ip_timestamps[src]
                if now - t <= self.TIME_WINDOW
            ]

            self.icmp_timestamps[src] = [
                t for t in self.icmp_timestamps[src]
                if now - t <= self.TIME_WINDOW
            ]

            # ---------------------------
            # TRACK ACTIVITY
            # ---------------------------
            self.ip_timestamps[src].append(now)
            self.packet_sizes[src].append(length)

            if proto == "ICMP":
                self.icmp_timestamps[src].append(now)

            if dport:
                self.ip_ports[src].add(dport)

            # ---------------------------
            # COOLDOWN CHECK
            # ---------------------------
            last_alert = self.alert_cooldown.get(src, 0)
            if now - last_alert < self.COOLDOWN:
                return None

            # ---------------------------
            # 🔥 DETECTION LOGIC
            # ---------------------------

            # 1. Flood Detection
            if len(self.ip_timestamps[src]) > self.FLOOD_THRESHOLD:
                alerts.append(f"🚨 Flood detected from {src}")

            # 2. Burst Attack (sudden spike)
            if len(self.ip_timestamps[src]) > self.BURST_THRESHOLD:
                alerts.append(f"🚨 Burst traffic spike from {src}")

            # 3. High Request Rate
            if len(self.ip_timestamps[src]) > 30:
                alerts.append(f"⚠️ High request rate from {src}")

            # 4. Port Scan
            if len(self.ip_ports[src]) > self.PORT_SCAN_THRESHOLD:
                alerts.append(f"🚨 Port scan detected from {src}")

            # 5. ICMP Flood
            if len(self.icmp_timestamps[src]) > self.ICMP_THRESHOLD:
                alerts.append(f"🚨 ICMP flood from {src}")

            # 6. Suspicious Port Access
            if dport in self.SUSPICIOUS_PORTS:
                alerts.append(f"⚠️ Suspicious port {dport} accessed by {src}")

            # 7. Large Packet Anomaly
            if length > 1500:
                alerts.append(f"⚠️ Large packet anomaly from {src}")

            # 8. Incoming External Threat
            if direction == "INCOMING":
                alerts.append(f"⚠️ Incoming traffic from external IP {src}")

            # 9. Beaconing Detection (VERY ADVANCED 🔥)
            if self._detect_beaconing(src):
                alerts.append(f"🚨 Beaconing behavior detected from {src}")

            # 10. Repeated Suspicious Port Pattern
            if self._repeated_port_pattern(src):
                alerts.append(f"🚨 Repeated suspicious port access from {src}")

            # ---------------------------
            # SAVE COOLDOWN
            # ---------------------------
            if alerts:
                self.alert_cooldown[src] = now
                return alerts

            return None

        except Exception as e:
            print(f"[Detector Error] {e}")
            return None

    # ---------------------------
    # 🔥 BEACON DETECTION
    # ---------------------------
    def _detect_beaconing(self, src):
        timestamps = self.ip_timestamps[src]

        if len(timestamps) < self.BEACON_MIN_PACKETS:
            return False

        intervals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

        avg = sum(intervals) / len(intervals)

        for interval in intervals:
            if abs(interval - avg) > self.BEACON_INTERVAL_TOLERANCE:
                return False

        return True

    # ---------------------------
    # 🔥 REPEATED PORT PATTERN
    # ---------------------------
    def _repeated_port_pattern(self, src):
        ports = self.ip_ports[src]
        suspicious_hits = ports.intersection(self.SUSPICIOUS_PORTS)

        return len(suspicious_hits) >= 3

    # ---------------------------
    # RESET
    # ---------------------------
    def reset(self):
        self.ip_timestamps.clear()
        self.icmp_timestamps.clear()
        self.ip_ports.clear()
        self.packet_sizes.clear()
        self.last_seen.clear()
        self.alert_cooldown.clear()