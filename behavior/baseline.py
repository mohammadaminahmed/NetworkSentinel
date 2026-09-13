import json
import time
import os
from core.logger import log

class Baseline:
    def __init__(self):
        self.known_macs = set()
        self.packet_counts_per_minute = []
        self.mean_packets = 0.0
        self.std_packets = 0.0
        self.is_learned = False
        
        # Runtime variables for learning
        self._current_minute_count = 0
        self._last_minute_time = time.time()

    def update_stats(self, statistics_module):
        """Update mean and standard deviation after collecting data"""
        if self.packet_counts_per_minute:
            self.mean_packets = statistics_module.mean(self.packet_counts_per_minute)
            self.std_packets = statistics_module.std_dev(self.packet_counts_per_minute)

    def process_packet(self, mac_src: str = None):
        """Called for each packet during the learning phase"""
        if mac_src:
            self.known_macs.add(mac_src)
            
        current_time = time.time()
        if current_time - self._last_minute_time >= 60:
            self.packet_counts_per_minute.append(self._current_minute_count)
            self._current_minute_count = 1
            self._last_minute_time = current_time
        else:
            self._current_minute_count += 1

    def save(self, filename: str):
        """Save the learned baseline to a file"""
        data = {
            "known_macs": list(self.known_macs),
            "mean_packets": self.mean_packets,
            "std_packets": self.std_packets,
            "is_learned": self.is_learned
        }
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            log.error(f"Failed to save baseline: {e}")

    def load(self, filename: str):
        """Load the baseline from a file"""
        if not os.path.exists(filename):
            return
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                self.known_macs = set(data.get("known_macs", []))
                self.mean_packets = data.get("mean_packets", 0.0)
                self.std_packets = data.get("std_packets", 0.0)
                self.is_learned = data.get("is_learned", False)
        except Exception as e:
            log.error(f"Failed to load baseline: {e}")
