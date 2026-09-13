import math
import time
from collections import defaultdict
from detectors.base_detector import BaseDetector
from parsers.dns_parser import parse

def calculate_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy

class DnsTunnelDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__("DnsTunnelDetector", alert_manager)
        self.domain_history = defaultdict(list)
        self.LENGTH_THRESHOLD = 50
        self.ENTROPY_THRESHOLD = 4.0
        self.TIME_WINDOW = 60 # seconds
        self.FREQ_THRESHOLD = 5

    def process(self, packet: bytes):
        dns_data = parse(packet)
        if not dns_data or not dns_data.get("questions"):
            return
            
        current_time = time.time()
        
        for q in dns_data["questions"]:
            domain = q.get("name", "")
            if len(domain) > self.LENGTH_THRESHOLD:
                entropy = calculate_entropy(domain)
                if entropy > self.ENTROPY_THRESHOLD:
                    self.domain_history[domain].append(current_time)
                    
                    # Clean up old history
                    self.domain_history[domain] = [t for t in self.domain_history[domain] if current_time - t < self.TIME_WINDOW]
                    
                    if len(self.domain_history[domain]) >= self.FREQ_THRESHOLD:
                        self.alert_manager.add_alert(
                            "MEDIUM",
                            "DNS Tunneling Detected",
                            f"Suspicious DNS queries for long/high-entropy domain: {domain} (Entropy: {entropy:.2f})",
                            self.name,
                            attacker_ip=dns_data.get("src_ip")
                        )
                        # Clear history to avoid spamming alerts for the same domain
                        self.domain_history[domain] = []
