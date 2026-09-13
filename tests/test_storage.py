import unittest
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from storage.device_store import DeviceStore
from storage.alert_store import AlertStore
from storage.baseline_store import BaselineStore
from behavior.baseline import Baseline

class TestStorageSystem(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.device_file = os.path.join(self.temp_dir.name, "devices.json")
        self.alert_file = os.path.join(self.temp_dir.name, "alerts.json")
        self.baseline_file = os.path.join(self.temp_dir.name, "baseline.json")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_device_store(self):
        store = DeviceStore()
        store.add_device("00:11:22:33:44:55", "192.168.1.10", "Apple", "Phone", "2023-01-01T12:00:00")
        
        self.assertEqual(len(store.get_all_devices()), 1)
        self.assertEqual(store.get_device("00:11:22:33:44:55").vendor, "Apple")
        
        store.save(self.device_file)
        
        new_store = DeviceStore()
        new_store.load(self.device_file)
        self.assertEqual(len(new_store.get_all_devices()), 1)
        self.assertEqual(new_store.get_device("00:11:22:33:44:55").ip, "192.168.1.10")

    def test_alert_store(self):
        store = AlertStore()
        alerts = [{"severity": "HIGH", "title": "Test Alert", "description": "Test"}]
        
        store.save(alerts, self.alert_file)
        
        loaded_alerts = store.load(self.alert_file)
        self.assertEqual(len(loaded_alerts), 1)
        self.assertEqual(loaded_alerts[0]["title"], "Test Alert")

    def test_baseline_store(self):
        baseline = Baseline()
        baseline.known_macs = {"AA:BB:CC:DD:EE:FF"}
        baseline.mean_packets = 50.0
        baseline.std_packets = 5.0
        baseline.is_learned = True
        
        BaselineStore.save(baseline, self.baseline_file)
        
        new_baseline = Baseline()
        BaselineStore.load(new_baseline, self.baseline_file)
        
        self.assertTrue(new_baseline.is_learned)
        self.assertEqual(new_baseline.mean_packets, 50.0)
        self.assertIn("AA:BB:CC:DD:EE:FF", new_baseline.known_macs)

if __name__ == '__main__':
    unittest.main(verbosity=2)
