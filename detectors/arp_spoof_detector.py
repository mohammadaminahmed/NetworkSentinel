from detectors.base_detector import BaseDetector
from parsers.arp_parser import parse

class ArpSpoofDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__("ArpSpoofDetector", alert_manager)
        self.mac_ip_map = {}

    def process(self, packet: bytes):
        arp_data = parse(packet)
        if not arp_data: return
        
        sender_ip = arp_data.get("sender_ip")
        sender_mac = arp_data.get("sender_mac")
        
        if sender_ip and sender_mac:
            if sender_ip in self.mac_ip_map and self.mac_ip_map[sender_ip] != sender_mac:
                self.alert_manager.add_alert(
                    "CRITICAL",
                    "ARP Spoofing Detected",
                    f"IP {sender_ip} changed MAC from {self.mac_ip_map[sender_ip]} to {sender_mac}. Potential MITM attack!",
                    self.name,
                    attacker_ip=sender_ip
                )
            else:
                self.mac_ip_map[sender_ip] = sender_mac
