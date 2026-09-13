import unittest
import os
import sys
import struct
import socket

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.alert_manager import AlertManager
from detectors.malicious_ip_detector import MaliciousIpDetector

class TestMaliciousIpDetector(unittest.TestCase):
    def setUp(self):
        self.alert_mgr = AlertManager()
        self.detector = MaliciousIpDetector(self.alert_mgr)

    def build_mock_ipv4_packet(self, src_ip, dst_ip):
        # Build a minimal 20-byte IPv4 header
        # Version 4, IHL 5 (0x45), TOS 0, Total Length 20
        # ID 0, Flags/Frag 0, TTL 64, Protocol 6 (TCP), Checksum 0
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton(dst_ip)
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 0, 0, 64, 6, 0, src_bytes, dst_bytes)
        return header

    def test_safe_connection(self):
        # Google DNS to Local IP (Safe)
        packet = self.build_mock_ipv4_packet("8.8.8.8", "192.168.1.10")
        self.detector.process(packet)
        self.assertEqual(len(self.alert_mgr.alerts), 0)

    def test_outbound_malicious_connection(self):
        # Local IP to Malicious IP (Outbound)
        packet = self.build_mock_ipv4_packet("192.168.1.10", "6.6.6.6")
        self.detector.process(packet)
        self.assertEqual(len(self.alert_mgr.alerts), 1)
        alert = self.alert_mgr.alerts[0]
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertIn("OUTBOUND", alert["description"])
        self.assertIn("6.6.6.6", alert["description"])

    def test_inbound_malicious_connection(self):
        # Malicious IP to Local IP (Inbound)
        self.alert_mgr.clear()
        packet = self.build_mock_ipv4_packet("9.9.9.99", "192.168.1.10")
        self.detector.process(packet)
        self.assertEqual(len(self.alert_mgr.alerts), 1)
        alert = self.alert_mgr.alerts[0]
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertIn("INBOUND", alert["description"])
        self.assertIn("9.9.9.99", alert["description"])

if __name__ == '__main__':
    unittest.main()
