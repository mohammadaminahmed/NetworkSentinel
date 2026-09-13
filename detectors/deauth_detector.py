import time
from collections import defaultdict
from detectors.base_detector import BaseDetector
from parsers.dot11_parser import parse

class DeauthDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__("DeauthDetector", alert_manager)
        # Dictionary mapping bssid to list of timestamps of deauth frames
        self.deauth_history = defaultdict(list)
        self.THRESHOLD = 10
        self.TIME_WINDOW = 5 # seconds

    def process(self, packet: bytes):
        dot11_data = parse(packet)
        if not dot11_data:
            return
            
        # We only care about Deauth frames (Type 0, Subtype 12)
        if dot11_data.get("type_str") == "Deauth":
            bssid = dot11_data.get("bssid")
            if not bssid:
                return
                
            current_time = time.time()
            self.deauth_history[bssid].append(current_time)
            
            # Clean up history outside the time window
            self.deauth_history[bssid] = [t for t in self.deauth_history[bssid] if current_time - t < self.TIME_WINDOW]
            
            if len(self.deauth_history[bssid]) >= self.THRESHOLD:
                self.alert_manager.add_alert(
                    "HIGH",
                    "Deauthentication Attack Detected",
                    f"Mass deauth frames detected for BSSID {bssid} ({len(self.deauth_history[bssid])} frames in {self.TIME_WINDOW}s). Potential Wi-Fi DoS!",
                    self.name
                )
                # Clear history to avoid spam
                self.deauth_history[bssid] = []
