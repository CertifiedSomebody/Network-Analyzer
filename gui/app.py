import tkinter as tk
from tkinter import ttk, messagebox
from queue import Queue, Empty

from core.sniffer import PacketSniffer
from core.analyzer import PacketAnalyzer
from core.detector import ThreatDetector


class NetScopeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NetScope - Network Analyzer")
        self.root.geometry("1200x700")

        self.queue = Queue()

        # Core modules
        self.analyzer = PacketAnalyzer()
        self.detector = ThreatDetector()
        self.sniffer = PacketSniffer(
            self.analyzer,
            self.detector,
            self.enqueue_packet
        )

        # Stats
        self.protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self.auto_scroll = True

        self._build_ui()
        self._update_gui_loop()

    # ---------------------------
    # UI BUILD
    # ---------------------------
    def _build_ui(self):
        top_frame = tk.Frame(self.root)
        top_frame.pack(fill="x", pady=5)

        # Buttons
        tk.Button(top_frame, text="Start", command=self.start_sniffing).pack(side="left", padx=5)
        tk.Button(top_frame, text="Stop", command=self.stop_sniffing).pack(side="left", padx=5)
        tk.Button(top_frame, text="Pause", command=self.pause_sniffing).pack(side="left", padx=5)
        tk.Button(top_frame, text="Resume", command=self.resume_sniffing).pack(side="left", padx=5)
        tk.Button(top_frame, text="Reset", command=self.reset_stats).pack(side="left", padx=5)

        # Auto-scroll toggle
        tk.Checkbutton(
            top_frame,
            text="Auto Scroll",
            command=self.toggle_scroll,
        ).pack(side="left", padx=10)

        # Interface dropdown
        self.interface_var = tk.StringVar()
        self.interfaces = PacketSniffer.get_interfaces()
        if self.interfaces:
            self.interface_var.set(self.interfaces[0])

        ttk.Combobox(
            top_frame,
            textvariable=self.interface_var,
            values=self.interfaces,
            width=40,
            state="readonly"
        ).pack(side="right", padx=5)

        # Filter dropdown
        self.filter_var = tk.StringVar(value="ALL")
        ttk.Combobox(
            top_frame,
            textvariable=self.filter_var,
            values=["ALL", "TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS"],
            width=10,
            state="readonly"
        ).pack(side="right", padx=5)

        # Table
        table_frame = tk.Frame(self.root)
        table_frame.pack(fill="both", expand=True)

        columns = ("time", "src", "dst", "protocol", "length", "alerts", "pps")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=120, anchor="center")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Row coloring
        self.tree.tag_configure("danger", background="#5c1a1a")
        self.tree.tag_configure("warning", background="#5c4a1a")

        # Stats panel
        stats_frame = tk.Frame(self.root)
        stats_frame.pack(fill="x")

        self.stats_label = tk.Label(stats_frame, text=self._format_stats(), font=("Arial", 12))
        self.stats_label.pack(side="left", padx=10)

        self.pps_label = tk.Label(stats_frame, text="PPS: 0", fg="green")
        self.pps_label.pack(side="left", padx=20)

        self.status_label = tk.Label(stats_frame, text="STOPPED", fg="red")
        self.status_label.pack(side="left", padx=20)

        self.top_ips_label = tk.Label(stats_frame, text="Top IPs:", fg="blue")
        self.top_ips_label.pack(side="right", padx=10)

        # Alerts panel
        alert_frame = tk.Frame(self.root)
        alert_frame.pack(fill="x")

        tk.Label(alert_frame, text="Alerts:", fg="red").pack(anchor="w")

        self.alert_box = tk.Text(alert_frame, height=6)
        self.alert_box.pack(fill="x")

        tk.Button(alert_frame, text="Clear Alerts", command=self.clear_alerts).pack(anchor="e")

    # ---------------------------
    # CONTROLS
    # ---------------------------
    def start_sniffing(self):
        if self.sniffer.is_running():
            return

        interface = self.interface_var.get()
        packet_filter = self._get_filter()

        if interface and "NPF" in interface:
            interface = None

        self.sniffer.start(interface=interface, packet_filter=packet_filter)
        self.status_label.config(text="RUNNING", fg="green")

    def stop_sniffing(self):
        self.sniffer.stop()
        self.status_label.config(text="STOPPED", fg="red")

    def pause_sniffing(self):
        self.sniffer.pause()
        self.status_label.config(text="PAUSED", fg="orange")

    def resume_sniffing(self):
        self.sniffer.resume()
        self.status_label.config(text="RUNNING", fg="green")

    def reset_stats(self):
        self.analyzer.reset()
        self.detector.reset()

        self.protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}

        self.tree.delete(*self.tree.get_children())
        self.alert_box.delete("1.0", tk.END)

    def clear_alerts(self):
        self.alert_box.delete("1.0", tk.END)

    def toggle_scroll(self):
        self.auto_scroll = not self.auto_scroll

    # ---------------------------
    # FILTER
    # ---------------------------
    def _get_filter(self):
        val = self.filter_var.get()
        return {
            "TCP": "tcp",
            "UDP": "udp",
            "ICMP": "icmp",
            "DNS": "port 53",
            "HTTP": "port 80",
            "HTTPS": "port 443"
        }.get(val, None)

    # ---------------------------
    # QUEUE LOOP
    # ---------------------------
    def enqueue_packet(self, data):
        self.queue.put(data)

    def _update_gui_loop(self):
        try:
            while True:
                data = self.queue.get_nowait()
                self._update_table(data)
                self._update_stats(data)
                self._update_alerts(data)
                self._update_top_ips()
                self._update_pps(data)
        except Empty:
            pass

        self.root.after(100, self._update_gui_loop)

    # ---------------------------
    # UPDATE FUNCTIONS
    # ---------------------------
    def _update_table(self, data):
        alerts_text = ", ".join(data.get("alerts") or [])

        row = self.tree.insert("", "end", values=(
            data.get("time"),
            data.get("src"),
            data.get("dst"),
            data.get("protocol"),
            data.get("length"),
            alerts_text,
            data.get("pps", 0)
        ))

        if "🚨" in alerts_text:
            self.tree.item(row, tags=("danger",))
        elif "⚠️" in alerts_text:
            self.tree.item(row, tags=("warning",))

        if self.auto_scroll:
            self.tree.yview_moveto(1)

        if len(self.tree.get_children()) > 400:
            self.tree.delete(self.tree.get_children()[0])

    def _update_stats(self, data):
        proto = data.get("protocol", "OTHER")
        self.protocol_stats[proto] += 1
        self.stats_label.config(text=self._format_stats())

    def _update_alerts(self, data):
        alerts = data.get("alerts")
        if alerts:
            for alert in alerts:
                self.alert_box.insert(tk.END, alert + "\n")

    def _update_top_ips(self):
        try:
            top_ips = self.analyzer.get_top_ips()
            text = "Top IPs: " + ", ".join([f"{ip}({count})" for ip, count in top_ips])
            self.top_ips_label.config(text=text)
        except:
            pass

    def _update_pps(self, data):
        self.pps_label.config(text=f"PPS: {data.get('pps', 0)}")

    def _format_stats(self):
        return "  ".join([f"{k}:{v}" for k, v in self.protocol_stats.items()])


# ---------------------------
# MAIN
# ---------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = NetScopeApp(root)
    root.mainloop()