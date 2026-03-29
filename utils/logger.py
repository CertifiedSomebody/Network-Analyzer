# logger.py

import os
import time
import threading
import json
from queue import Queue


class Logger:
    def __init__(self, log_dir="data", max_size_kb=512):
        self.log_dir = log_dir
        self.max_size = max_size_kb * 1024  # convert to bytes

        # Log files
        self.packet_log_file = os.path.join(log_dir, "packets.log")
        self.alert_log_file = os.path.join(log_dir, "alerts.log")
        self.error_log_file = os.path.join(log_dir, "errors.log")

        # Threading
        self.lock = threading.Lock()
        self.queue = Queue()
        self.running = True

        # Prevent spam errors
        self.last_error_time = 0
        self.error_cooldown = 2  # seconds

        os.makedirs(self.log_dir, exist_ok=True)

        # Start background writer thread
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()

    # ---------------------------
    # Background Worker (ASYNC ⚡)
    # ---------------------------
    def _worker(self):
        while self.running:
            try:
                filepath, message = self.queue.get(timeout=1)
                self._safe_write(filepath, message)
            except:
                continue

    # ---------------------------
    # Safe Write + Rotation
    # ---------------------------
    def _safe_write(self, filepath, message):
        try:
            with self.lock:
                # Rotate log if too big
                if os.path.exists(filepath) and os.path.getsize(filepath) > self.max_size:
                    self._rotate_file(filepath)

                with open(filepath, "a", encoding="utf-8") as f:
                    f.write(message + "\n")

        except Exception as e:
            print(f"[Logger Error] {e}")

    def _rotate_file(self, filepath):
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            new_name = f"{filepath}.{timestamp}.bak"
            os.rename(filepath, new_name)
        except Exception as e:
            print(f"[Rotate Error] {e}")

    # ---------------------------
    # Time Utility
    # ---------------------------
    def _timestamp(self):
        return time.strftime("%Y-%m-%d %H:%M:%S")

    # ---------------------------
    # Queue Writer
    # ---------------------------
    def _write(self, filepath, message):
        self.queue.put((filepath, message))

    # ---------------------------
    # Packet Logging
    # ---------------------------
    def log_packet(self, data):
        try:
            msg = (
                f"[{self._timestamp()}] "
                f"{data.get('src')}:{data.get('sport')} -> "
                f"{data.get('dst')}:{data.get('dport')} | "
                f"{data.get('protocol')} ({data.get('app_proto')}) | "
                f"Len:{data.get('length')} | "
                f"{data.get('direction')}"
            )

            self._write(self.packet_log_file, msg)

        except Exception as e:
            self.log_error(f"Packet log failed: {e}")

    # ---------------------------
    # JSON Packet Logging (NEW 🔥)
    # ---------------------------
    def log_packet_json(self, data):
        try:
            data_copy = data.copy()
            data_copy["timestamp"] = self._timestamp()

            msg = json.dumps(data_copy)
            self._write(self.packet_log_file, msg)

        except Exception as e:
            self.log_error(f"JSON log failed: {e}")

    # ---------------------------
    # Alert Logging
    # ---------------------------
    def log_alert(self, alerts):
        try:
            if not alerts:
                return

            for alert in alerts:
                msg = f"[{self._timestamp()}] {alert}"
                self._write(self.alert_log_file, msg)

        except Exception as e:
            self.log_error(f"Alert log failed: {e}")

    # ---------------------------
    # Error Logging (RATE LIMITED ⚡)
    # ---------------------------
    def log_error(self, error_msg):
        now = time.time()

        if now - self.last_error_time < self.error_cooldown:
            return  # prevent spam

        self.last_error_time = now

        msg = f"[{self._timestamp()}] ERROR: {error_msg}"
        self._write(self.error_log_file, msg)

    # ---------------------------
    # Clear Logs
    # ---------------------------
    def clear_logs(self):
        try:
            with self.lock:
                open(self.packet_log_file, "w").close()
                open(self.alert_log_file, "w").close()
                open(self.error_log_file, "w").close()
        except Exception as e:
            print(f"[Logger Error] Failed to clear logs: {e}")

    # ---------------------------
    # Export Logs
    # ---------------------------
    def export_logs(self, export_path="exported_logs.txt"):
        try:
            with open(export_path, "w", encoding="utf-8") as outfile:
                for file in [
                    self.packet_log_file,
                    self.alert_log_file,
                    self.error_log_file
                ]:
                    if os.path.exists(file):
                        with open(file, "r", encoding="utf-8") as infile:
                            outfile.write(f"\n--- {os.path.basename(file)} ---\n")
                            outfile.write(infile.read())

            return True

        except Exception as e:
            self.log_error(f"Export failed: {e}")
            return False

    # ---------------------------
    # Stop Logger
    # ---------------------------
    def shutdown(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)