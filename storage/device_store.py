import json
import os
from dataclasses import dataclass, asdict
from core.logger import log

@dataclass
class Device:
    mac: str
    ip: str
    vendor: str
    device_type: str
    first_seen: str

class DeviceStore:
    def __init__(self):
        self.devices = {} # mac -> Device

    def add_device(self, mac: str, ip: str, vendor: str, device_type: str, first_seen: str):
        self.devices[mac] = Device(mac, ip, vendor, device_type, first_seen)

    def get_device(self, mac: str) -> Device:
        return self.devices.get(mac)

    def get_all_devices(self) -> list:
        return list(self.devices.values())

    def save(self, filename: str):
        try:
            with open(filename, 'w') as f:
                json.dump({mac: asdict(dev) for mac, dev in self.devices.items()}, f, indent=4)
        except Exception as e:
            log.error(f"Failed to save devices: {e}")

    def load(self, filename: str):
        if not os.path.exists(filename):
            return
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                for mac, dev_data in data.items():
                    self.devices[mac] = Device(**dev_data)
        except Exception as e:
            log.error(f"Failed to load devices: {e}")
