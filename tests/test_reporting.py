import unittest
import os
import sys
import tempfile
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from reporting.json_reporter import generate as generate_json
from reporting.html_reporter import generate as generate_html

class TestReportingSystem(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.json_file = os.path.join(self.temp_dir.name, "report.json")
        self.html_file = os.path.join(self.temp_dir.name, "report.html")
        
        self.alerts = [
            {"timestamp": "2023-10-01T12:00", "severity": "CRITICAL", "title": "ARP Spoofing", "description": "Spoof detected"}
        ]
        self.devices = [
            {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.10", "vendor": "TestVendor", "device_type": "Laptop"}
        ]
        self.baseline = {
            "is_learned": True,
            "mean_packets": 100,
            "std_packets": 5
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_json_reporter(self):
        output = generate_json(self.alerts, self.devices, self.baseline, self.json_file)
        self.assertEqual(output, self.json_file)
        self.assertTrue(os.path.exists(self.json_file))
        
        with open(self.json_file, 'r') as f:
            data = json.load(f)
            self.assertEqual(data["summary"]["total_alerts"], 1)
            self.assertEqual(data["alerts"][0]["title"], "ARP Spoofing")

    def test_html_reporter(self):
        output = generate_html(self.alerts, self.devices, self.baseline, self.html_file)
        self.assertEqual(output, self.html_file)
        self.assertTrue(os.path.exists(self.html_file))
        
        with open(self.html_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn("Network Sentinel Security Report", content)
            self.assertIn("ARP Spoofing", content)
            self.assertIn("AA:BB:CC:DD:EE:FF", content)
            self.assertIn("class=\"severity-CRITICAL\"", content)

if __name__ == '__main__':
    unittest.main(verbosity=2)
