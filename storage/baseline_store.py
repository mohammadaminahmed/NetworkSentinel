import json
import os
from behavior.baseline import Baseline
from core.logger import log

class BaselineStore:
    @staticmethod
    def save(baseline: Baseline, filename: str):
        """Extracts data from Baseline object and saves it"""
        data = {
            "known_macs": list(baseline.known_macs),
            "mean_packets": baseline.mean_packets,
            "std_packets": baseline.std_packets,
            "is_learned": baseline.is_learned
        }
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            log.error(f"Failed to save baseline store: {e}")

    @staticmethod
    def load(baseline: Baseline, filename: str):
        """Loads data from file and populates the given Baseline object"""
        if not os.path.exists(filename):
            return
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                baseline.known_macs = set(data.get("known_macs", []))
                baseline.mean_packets = data.get("mean_packets", 0.0)
                baseline.std_packets = data.get("std_packets", 0.0)
                baseline.is_learned = data.get("is_learned", False)
        except Exception as e:
            log.error(f"Failed to load baseline store: {e}")
