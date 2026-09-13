import unittest
import struct
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from parsers.dns_parser import parse
from detectors.dns_tunnel_detector import DnsTunnelDetector
from core.alert_manager import AlertManager

class TestDnsSystem(unittest.TestCase):
    def setUp(self):
        self.alert_manager = AlertManager()
        self.detector = DnsTunnelDetector(self.alert_manager)
        
        # Craft a standard DNS query for "google.com"
        # Transaction ID: 0x1234, Flags: 0x0100 (Standard query), qdcount: 1
        qname_normal = b'\x06google\x03com\x00'
        dns_normal = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname_normal + struct.pack("!HH", 1, 1)
        self.normal_packet = dns_normal
        
        # Craft a suspicious DNS query (long, high entropy)
        # e.g., a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z.evil.com (length > 50)
        suspicious_domain = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f"
        qname_suspicious = bytes([len(suspicious_domain)]) + suspicious_domain.encode('utf-8') + b'\x04evil\x03com\x00'
        dns_suspicious = struct.pack("!HHHHHH", 0x5678, 0x0100, 1, 0, 0, 0) + qname_suspicious + struct.pack("!HH", 1, 1)
        self.suspicious_packet = dns_suspicious

    def test_dns_parser(self):
        """Test parsing of a standard DNS packet"""
        result = parse(self.normal_packet)
        self.assertTrue(bool(result))
        self.assertFalse(result['is_response'])
        self.assertEqual(len(result['questions']), 1)
        self.assertEqual(result['questions'][0]['name'], 'google.com')

    def test_dns_tunnel_detection(self):
        """Test the detection of DNS Tunneling"""
        # Normal packet shouldn't trigger anything
        self.detector.process(self.normal_packet)
        self.assertEqual(len(self.alert_manager.alerts), 0)
        
        # Suspicious packet needs to be seen multiple times (default FREQ_THRESHOLD = 5)
        for i in range(4):
            self.detector.process(self.suspicious_packet)
            self.assertEqual(len(self.alert_manager.alerts), 0) # Below threshold
            
        # 5th packet should trigger alert
        self.detector.process(self.suspicious_packet)
        self.assertEqual(len(self.alert_manager.alerts), 1)
        
        alert = self.alert_manager.alerts[0]
        self.assertEqual(alert['severity'], 'MEDIUM')
        self.assertEqual(alert['title'], 'DNS Tunneling Detected')
        self.assertIn('evil.com', alert['description'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
