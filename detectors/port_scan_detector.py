import struct
import time
from collections import defaultdict
from detectors.base_detector import BaseDetector

class PortScanDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__("PortScanDetector", alert_manager)
        # Dictionary mapping source_ip to list of timestamps of SYN packets
        self.syn_history = defaultdict(list)
        self.THRESHOLD = 20
        self.TIME_WINDOW = 5 # seconds

    def process(self, packet: bytes):
        # Determine if packet starts with Ethernet or IPv4
        # Windows gives raw IP, Linux gives raw Ethernet
        offset = 0
        if len(packet) > 14:
            # Check if it's IPv4 directly (byte 0 is 0x45 typically)
            if (packet[0] >> 4) == 4:
                offset = 0
            # Check if it's Ethernet containing IPv4
            elif (packet[14] >> 4) == 4 and struct.unpack("!H", packet[12:14])[0] == 0x0800:
                offset = 14
            else:
                return # Not an IPv4 packet
        else:
            return

        ip_header_start = offset
        if len(packet) < ip_header_start + 20:
            return
            
        ip_header = packet[ip_header_start:ip_header_start+20]
        version_ihl = ip_header[0]
        ihl = (version_ihl & 0x0F) * 4
        protocol = ip_header[9]
        
        if protocol != 6: # Protocol 6 is TCP
            return
            
        src_ip = ".".join(str(b) for b in ip_header[12:16])
        
        tcp_header_start = ip_header_start + ihl
        if len(packet) < tcp_header_start + 14:
            return
            
        tcp_header = packet[tcp_header_start:tcp_header_start+14]
        tcp_flags = tcp_header[13]
        
        # Check if SYN flag is set (bit 1)
        is_syn = (tcp_flags & 0x02) != 0
        
        if is_syn:
            current_time = time.time()
            self.syn_history[src_ip].append(current_time)
            
            # Clean up history outside time window
            self.syn_history[src_ip] = [t for t in self.syn_history[src_ip] if current_time - t < self.TIME_WINDOW]
            
            if len(self.syn_history[src_ip]) >= self.THRESHOLD:
                self.alert_manager.add_alert(
                    "MEDIUM",
                    "Port Scanning Detected",
                    f"Possible port scan from {src_ip} ({len(self.syn_history[src_ip])} SYN packets in {self.TIME_WINDOW}s)",
                    self.name,
                    attacker_ip=src_ip
                )
                # Clear history to avoid spam
                self.syn_history[src_ip] = []
