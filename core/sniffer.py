from scapy.all import sniff, get_if_list
import threading
import time


class PacketSniffer:
    def __init__(self, analyzer, detector=None, callback=None):
        self.analyzer = analyzer
        self.detector = detector
        self.callback = callback

        self.running = False
        self.paused = False
        self.thread = None

        self.interface = None
        self.packet_filter = None

        # Performance stats
        self.packet_count = 0
        self.start_time = 0
        self.last_rate_check = 0
        self.current_rate = 0

    # ---------------------------
    # Internal Packet Handler
    # ---------------------------
    def _process_packet(self, packet):
        if not self.running or self.paused:
            return

        try:
            self.packet_count += 1

            # 🔥 Calculate live packet rate
            now = time.time()
            if now - self.last_rate_check >= 1:
                duration = now - self.start_time
                self.current_rate = self.packet_count / duration if duration > 0 else 0
                self.last_rate_check = now

                print(f"[RATE] {self.current_rate:.2f} pkt/s")

            data = self.analyzer.analyze(packet)
            if not data:
                return

            alerts = None
            if self.detector:
                alerts = self.detector.analyze(data)

            data["alerts"] = alerts
            data["pps"] = round(self.current_rate, 2)

            if self.callback:
                self.callback(data)

        except Exception as e:
            print(f"[Sniffer Error] {e}")

    # ---------------------------
    # Start Sniffing
    # ---------------------------
    def start(self, interface=None, packet_filter=None):
        if self.running:
            print("[!] Sniffer already running")
            return

        self.running = True
        self.paused = False

        self.interface = interface
        self.packet_filter = packet_filter

        self.packet_count = 0
        self.start_time = time.time()
        self.last_rate_check = self.start_time

        def sniff_loop():
            print(f"[+] Starting sniff on: {self.interface if self.interface else 'AUTO'}")

            while self.running:
                try:
                    sniff(
                        iface=self._get_valid_interface(),
                        prn=self._process_packet,
                        store=False,
                        timeout=1,
                        filter=self.packet_filter
                    )
                except Exception as e:
                    print(f"[Sniffer Thread Error] {e}")
                    time.sleep(1)  # prevent crash loop

        self.thread = threading.Thread(target=sniff_loop)
        self.thread.daemon = True
        self.thread.start()

        print("[+] Sniffer started")

    # ---------------------------
    # Stop Sniffing
    # ---------------------------
    def stop(self):
        if not self.running:
            print("[!] Sniffer is not running")
            return

        self.running = False

        if self.thread:
            self.thread.join(timeout=2)

        duration = time.time() - self.start_time
        rate = self.packet_count / duration if duration > 0 else 0

        print("[+] Sniffer stopped")
        print(f"[STATS] Packets: {self.packet_count}")
        print(f"[STATS] Duration: {duration:.2f}s")
        print(f"[STATS] Avg Rate: {rate:.2f} pkt/s")

    # ---------------------------
    # Pause / Resume (NEW 🔥)
    # ---------------------------
    def pause(self):
        if self.running:
            self.paused = True
            print("[+] Sniffer paused")

    def resume(self):
        if self.running:
            self.paused = False
            print("[+] Sniffer resumed")

    # ---------------------------
    # Restart
    # ---------------------------
    def restart(self, interface=None, packet_filter=None):
        self.stop()
        time.sleep(1)
        self.start(interface, packet_filter)

    # ---------------------------
    # Interface Handling
    # ---------------------------
    def _get_valid_interface(self):
        try:
            if not self.interface:
                return None

            if "NPF" in str(self.interface):
                print("[DEBUG] NPF interface detected → AUTO mode")
                return None

            return self.interface

        except Exception as e:
            print(f"[Interface Fix Error] {e}")
            return None

    # ---------------------------
    # Interfaces List
    # ---------------------------
    @staticmethod
    def get_interfaces():
        try:
            interfaces = get_if_list()
            print("[DEBUG] Interfaces:", interfaces)
            return interfaces
        except Exception as e:
            print(f"[Interface Error] {e}")
            return []

    # ---------------------------
    # Dynamic Filter (NO RESTART 🔥)
    # ---------------------------
    def set_filter(self, filter_str):
        self.packet_filter = filter_str
        print(f"[+] Filter updated: {filter_str}")

    # ---------------------------
    # Stats API (FOR GUI 🔥)
    # ---------------------------
    def get_stats(self):
        duration = time.time() - self.start_time
        return {
            "total_packets": self.packet_count,
            "duration": round(duration, 2),
            "rate": round(self.current_rate, 2)
        }

    # ---------------------------
    # Status
    # ---------------------------
    def is_running(self):
        return self.running

    def is_paused(self):
        return self.paused