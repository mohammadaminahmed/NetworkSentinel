import json
import os
from core.logger import log

class AlertStore:
    def __init__(self):
        self.alerts = []

    def save(self, alerts: list, filename: str):
        """Save a list of alerts to a JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(alerts, f, indent=4)
        except Exception as e:
            log.error(f"Failed to save alerts: {e}")

    def load(self, filename: str) -> list:
        """Load alerts from a JSON file"""
        if not os.path.exists(filename):
            return []
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except Exception as e:
            log.error(f"Failed to load alerts: {e}")
            return []
