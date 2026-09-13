import socket
import struct
from detectors.base_detector import BaseDetector

class MaliciousIpDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__("MaliciousIpDetector", alert_manager)
        # القائمة السوداء لعناوين الـ IP الخبيثة المعروفة (C2 Servers, Botnets, Scanners)
        # يمكن توسيع هذه القائمة لاحقاً بقراءتها من ملف خارجي.
        self.blacklist = {
            "198.51.100.1",   # Example Malicious IP 1 (TEST-NET-2)
            "203.0.113.5",    # Example Malicious IP 2 (TEST-NET-3)
            "185.15.59.224",  # Fake Botnet C2
            "9.9.9.99",       # Fake malicious server
            "6.6.6.6"         # Test malicious server
        }
        self.alerted_ips = {} # To avoid spamming alerts for the same IP (IP -> Timestamp)

    def process(self, packet: bytes):
        if len(packet) < 20:
            return

        src_ip = None
        dst_ip = None

        try:
            # 1. Raw IPv4 Packet (Windows Capture)
            if (packet[0] >> 4) == 4:
                src_ip = socket.inet_ntoa(packet[12:16])
                dst_ip = socket.inet_ntoa(packet[16:20])
            
            # 2. Ethernet Frame containing IPv4 (Linux Capture)
            elif len(packet) > 34 and (packet[14] >> 4) == 4 and struct.unpack("!H", packet[12:14])[0] == 0x0800:
                src_ip = socket.inet_ntoa(packet[26:30])
                dst_ip = socket.inet_ntoa(packet[30:34])

            if not src_ip or not dst_ip:
                return

            # التحقق من وجود أحد الطرفين في القائمة السوداء
            malicious_ip = None
            direction = ""
            
            if dst_ip in self.blacklist:
                malicious_ip = dst_ip
                direction = "OUTBOUND connection to"
            elif src_ip in self.blacklist:
                malicious_ip = src_ip
                direction = "INBOUND connection from"

            if malicious_ip:
                import time
                current_time = time.time()
                last_alert = self.alerted_ips.get(malicious_ip, 0)
                
                # إرسال تنبيه واحد كل 30 ثانية لنفس الآيبي لمنع الإزعاج (Spam)
                if current_time - last_alert > 30:
                    self.alerted_ips[malicious_ip] = current_time
                    self.alert_manager.add_alert(
                        "CRITICAL",
                        "Malicious Connection Detected",
                        f"{direction} a known malicious server: {malicious_ip}",
                        self.name,
                        attacker_ip=malicious_ip
                    )
        except Exception:
            pass
