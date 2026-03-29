# 🛰️ NetScope – Real-Time Network Traffic Analyzer

## 📌 Overview
**NetScope** is a high-performance, real-time network traffic analyzer and lightweight **Intrusion Detection System (IDS)**. Built using Python and the Scapy library, it bridges the gap between raw packet data and actionable security insights.

This project was developed as a practical implementation for the **Computer Communication Networks (CCN)** course (**EXTC Engineering, Semester VI**).

---

## 🚀 Key Features

### 🔍 Advanced Packet Sniffing
* **Live Capture:** Hooks into network interfaces to intercept traffic in real-time.
* **Deep Metadata Extraction:** Identifies Source/Destination IPs, Protocols (TCP, UDP, ICMP), Ports, and Packet Length.
* **Directional Tracking:** Distinguishes between Incoming and Outgoing traffic.
* **Layer 7 Awareness:** Basic identification of HTTP, DNS, SSH, and HTTPS traffic.

### 📊 Real-Time Analysis Engine
* **Live Stats:** Monitors packet rates and protocol distribution.
* **IP Tracking:** Maintains a "Top Talkers" list to identify the most active devices on the network.
* **Traffic Baselining:** Observes normal flow to help identify deviations.

### 🚨 Intrusion Detection System (IDS)
NetScope identifies malicious patterns using a time-windowed detection logic:
* **Flood Attacks:** Detects ICMP and general packet flooding.
* **Port Scanning:** Flags rapid connection attempts across multiple ports.
* **Anomaly Alerts:** Warns about unusually large packets or suspicious request rates.
* **Smart Cooldown:** Integrated system to prevent alert fatigue and spam.

### 🖥️ Modern GUI (Tkinter)
* **Dark Mode Interface:** Designed for high visibility and a professional "SOC" feel.
* **Interactive Controls:** Start, Stop, and Reset capture with one click.
* **Protocol Filtering:** Quickly isolate TCP, UDP, or ICMP traffic.
* **Visual Alerts:** Color-coded logs (🚨 Danger / ⚠️ Warning) for immediate threat recognition.

---

## 🧠 CCN Concepts Covered
* **OSI & TCP/IP Models:** Practical mapping of data across layers.
* **Packet Encapsulation:** Analysis of headers and payloads.
* **Network Security:** Hands-on application of IDS/IPS logic.
* **Flow Control:** Understanding how packet rates impact network stability.

## 🏗️ Project Structure
NetScope/
├── main.py              # Application Entry Point
├── core/
│   ├── sniffer.py       # Scapy-based capture engine
│   ├── analyzer.py      # Protocol & Traffic logic
│   └── detector.py      # IDS Rule engine
├── gui/
│   ├── app.py           # Main Tkinter Window
│   └── components.py    # Custom UI Widgets
├── utils/
│   ├── helpers.py       # Data formatting
│   └── logger.py        # Thread-safe logging system
└── data/
    └── alerts.log       # Persistent threat history


## ⚙️ Installation & Usage

### 1. Prerequisites
* **Python 3.8+**
* **Npcap (Windows):** Ensure "Install Npcap with WinPcap compatibility mode" is checked during installation.
* **Libpcap (Linux/Mac):** Usually pre-installed or available via \`apt install libpcap-dev\`.

### 2. Setup
```
# Clone the repository
git clone <your-repo-link>
cd NetScope
```

# Install dependencies
```
pip install scapy
```

### 3. Run

Run the app
# Note: Root/Admin privileges are required for packet sniffing


---

## 🎯 Learning Outcomes
1. **Network Literacy:** Deep dive into how packets travel through a Network Interface Card (NIC).
2. **Concurrency:** Handling real-time data streams using Python threading to keep the GUI responsive.
3. **Cybersecurity Foundations:** Understanding signature-based detection and traffic anomalies.

---

## 👨‍💻 Author
**Prabhat Jha** *EXTC Engineering – Xavier Institute of Engineering* *Semester VI*

---
> **Disclaimer:** This tool is for educational purposes only. Always ensure you have permission to monitor traffic on the network you are testing.
