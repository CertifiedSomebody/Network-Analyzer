import tkinter as tk
from tkinter import ttk

# ---------------------------
# GLOBAL STYLING
# ---------------------------
BG_COLOR = "#1e1e2f"
FG_COLOR = "#ffffff"
ACCENT = "#00adb5"
WARNING = "#f39c12"
DANGER = "#e74c3c"


# ---------------------------
# Styled Button
# ---------------------------
def create_button(parent, text, command, width=12):
    return tk.Button(
        parent,
        text=text,
        command=command,
        width=width,
        bg=ACCENT,
        fg="black",
        activebackground="#00cfd6",
        relief="flat",
        font=("Arial", 10, "bold"),
        cursor="hand2"
    )


# ---------------------------
# Packet Table Component
# ---------------------------
class PacketTable:
    def __init__(self, parent):
        style = ttk.Style()
        style.theme_use("default")

        style.configure(
            "Treeview",
            background=BG_COLOR,
            foreground=FG_COLOR,
            rowheight=26,
            fieldbackground=BG_COLOR,
            borderwidth=0
        )

        style.map(
            "Treeview",
            background=[("selected", "#34495e")],
            foreground=[("selected", "white")]
        )

        columns = ("time", "src", "dst", "protocol", "length", "alerts")

        self.tree = ttk.Treeview(parent, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=130, anchor="center")

        # Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Configure tags ONCE (performance fix)
        self.tree.tag_configure("danger", background="#5c1a1a")
        self.tree.tag_configure("warning", background="#5c4a1a")

    def insert(self, data):
        alerts = ", ".join(data.get("alerts") or [])

        row_id = self.tree.insert(
            "",
            "end",
            values=(
                data.get("time"),
                data.get("src"),
                data.get("dst"),
                data.get("protocol"),
                data.get("length"),
                alerts
            )
        )

        # 🎯 Color logic
        if alerts:
            if "🚨" in alerts:
                self.tree.item(row_id, tags=("danger",))
            elif "⚠️" in alerts:
                self.tree.item(row_id, tags=("warning",))

        # Limit rows (prevent lag)
        children = self.tree.get_children()
        if len(children) > 300:
            self.tree.delete(children[0])

    def clear(self):
        self.tree.delete(*self.tree.get_children())


# ---------------------------
# Stats Panel
# ---------------------------
class StatsPanel:
    def __init__(self, parent):
        self.frame = tk.Frame(parent, bg=BG_COLOR)

        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}

        self.label = tk.Label(
            self.frame,
            text=self._format_stats(),
            font=("Arial", 12, "bold"),
            fg=ACCENT,
            bg=BG_COLOR
        )

        self.label.pack(anchor="w", padx=10, pady=5)

    def _format_stats(self):
        return "  ".join([f"{k}: {v}" for k, v in self.stats.items()])

    def update(self, protocol):
        self.stats[protocol] = self.stats.get(protocol, 0) + 1
        self.label.config(text=self._format_stats())

    def reset(self):
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self.label.config(text=self._format_stats())


# ---------------------------
# Top IP Panel
# ---------------------------
class TopIPsPanel:
    def __init__(self, parent):
        self.frame = tk.Frame(parent, bg=BG_COLOR)

        tk.Label(
            self.frame,
            text="Top Active IPs",
            fg=ACCENT,
            bg=BG_COLOR,
            font=("Arial", 11, "bold")
        ).pack(anchor="w", padx=10)

        self.text = tk.Text(
            self.frame,
            height=5,
            bg="#12121c",
            fg="white",
            relief="flat"
        )
        self.text.pack(fill="x", padx=10, pady=5)

    def update(self, ip_list):
        self.text.delete("1.0", tk.END)

        for ip, count in ip_list:
            self.text.insert(tk.END, f"{ip} → {count} packets\n")

    def clear(self):
        self.text.delete("1.0", tk.END)


# ---------------------------
# Alerts Panel
# ---------------------------
class AlertsPanel:
    def __init__(self, parent):
        self.frame = tk.Frame(parent, bg=BG_COLOR)

        tk.Label(
            self.frame,
            text="Alerts:",
            fg=DANGER,
            bg=BG_COLOR,
            font=("Arial", 11, "bold")
        ).pack(anchor="w")

        self.text = tk.Text(
            self.frame,
            height=6,
            bg="#12121c",
            fg="white",
            relief="flat"
        )
        self.text.pack(fill="x")

        # Configure tags once
        self.text.tag_config("danger", foreground="#ff4d4d")
        self.text.tag_config("warning", foreground="#f1c40f")

    def add_alerts(self, alerts):
        if not alerts:
            return

        for alert in alerts:
            if "🚨" in alert:
                self.text.insert(tk.END, alert + "\n", "danger")
            elif "⚠️" in alert:
                self.text.insert(tk.END, alert + "\n", "warning")
            else:
                self.text.insert(tk.END, alert + "\n")

        self.text.see(tk.END)

    def clear(self):
        self.text.delete("1.0", tk.END)


# ---------------------------
# Interface Selector
# ---------------------------
class InterfaceSelector:
    def __init__(self, parent, interfaces):
        self.var = tk.StringVar()

        if interfaces:
            self.var.set(interfaces[0])

        self.dropdown = ttk.Combobox(
            parent,
            textvariable=self.var,
            values=interfaces,
            width=45,
            state="readonly"
        )

    def get(self):
        return self.var.get()


# ---------------------------
# Filter Selector
# ---------------------------
class FilterSelector:
    def __init__(self, parent):
        self.var = tk.StringVar(value="ALL")

        options = ["ALL", "TCP", "UDP", "ICMP", "DNS", "HTTP"]

        self.dropdown = ttk.Combobox(
            parent,
            textvariable=self.var,
            values=options,
            width=15,
            state="readonly"
        )

    def get_filter(self):
        val = self.var.get()

        return {
            "TCP": "tcp",
            "UDP": "udp",
            "ICMP": "icmp",
            "DNS": "port 53",
            "HTTP": "port 80"
        }.get(val, None)