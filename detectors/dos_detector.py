import socket
import struct
import time
from collections import defaultdict
from detectors.base_detector import BaseDetector

class DosDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__("DosDetector", alert_manager)
        # Dictionary mapping source_ip to list of packet timestamps
        self.ip_history = defaultdict(list)
        self.THRESHOLD = 150 # packets
        self.TIME_WINDOW = 2 # seconds

    def process(self, packet: bytes):
        if len(packet) < 20:
            return

        src_ip = None

        try:
            # 1. Raw IPv4 Packet (Windows Capture)
            if (packet[0] >> 4) == 4:
                src_ip = socket.inet_ntoa(packet[12:16])
            
            # 2. Ethernet Frame containing IPv4 (Linux Capture)
            elif len(packet) > 34 and (packet[14] >> 4) == 4 and struct.unpack("!H", packet[12:14])[0] == 0x0800:
                src_ip = socket.inet_ntoa(packet[26:30])

            if not src_ip:
                return

            current_time = time.time()
            self.ip_history[src_ip].append(current_time)
            
            # Clean up history outside time window
            self.ip_history[src_ip] = [t for t in self.ip_history[src_ip] if current_time - t < self.TIME_WINDOW]
            
            if len(self.ip_history[src_ip]) >= self.THRESHOLD:
                self.alert_manager.add_alert(
                    "CRITICAL",
                    "Denial of Service (DoS) Attack Detected",
                    f"Massive packet flood detected from {src_ip} ({len(self.ip_history[src_ip])} packets in {self.TIME_WINDOW}s).",
                    self.name,
                    attacker_ip=src_ip
                )
                # Clear history to avoid spam
                self.ip_history[src_ip] = []
                
        except Exception:
            pass
