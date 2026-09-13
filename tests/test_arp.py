import unittest
import struct
import sys
import os

# Ensure the parent directory is in the path so we can import from core/parsers/detectors
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from parsers.arp_parser import parse
from detectors.arp_spoof_detector import ArpSpoofDetector
from core.alert_manager import AlertManager

class TestArpSystem(unittest.TestCase):
    def setUp(self):
        self.alert_manager = AlertManager()
        self.detector = ArpSpoofDetector(self.alert_manager)
        
        # Craft a valid ARP Request Packet (42 bytes)
        # Ethernet Header
        eth_hdr = struct.pack("!6s6sH", b'\xff'*6, b'\x00\x11\x22\x33\x44\x55', 0x0806)
        # ARP Header
        arp_hdr = struct.pack("!HHBBH6s4s6s4s", 
            1, 0x0800, 6, 4, 1, 
            b'\x00\x11\x22\x33\x44\x55', 
            bytes([192, 168, 1, 100]), 
            b'\x00'*6, 
            bytes([192, 168, 1, 1])
        )
        self.valid_packet = eth_hdr + arp_hdr
        
        # Craft a valid ARP Reply Packet with a spoofed MAC for the same IP
        eth_hdr_spoofed = struct.pack("!6s6sH", b'\xff'*6, b'\xaa\xbb\xcc\xdd\xee\xff', 0x0806)
        arp_hdr_spoofed = struct.pack("!HHBBH6s4s6s4s", 
            1, 0x0800, 6, 4, 2, 
            b'\xaa\xbb\xcc\xdd\xee\xff', 
            bytes([192, 168, 1, 100]), 
            b'\x00'*6, 
            bytes([192, 168, 1, 1])
        )
        self.spoofed_packet = eth_hdr_spoofed + arp_hdr_spoofed

    def test_arp_parser(self):
        """Test parsing of a valid ARP packet"""
        result = parse(self.valid_packet)
        self.assertTrue(bool(result))
        self.assertEqual(result['op'], 'request')
        self.assertEqual(result['sender_mac'], '00:11:22:33:44:55')
        self.assertEqual(result['sender_ip'], '192.168.1.100')
        self.assertEqual(result['target_mac'], '00:00:00:00:00:00')
        self.assertEqual(result['target_ip'], '192.168.1.1')

    def test_arp_spoof_detection(self):
        """Test the detection of an ARP spoofing attack"""
        # First packet: registers the IP and MAC
        self.detector.process(self.valid_packet)
        self.assertEqual(len(self.alert_manager.alerts), 0)
        
        # Second packet: same IP but different MAC -> Should trigger alert
        self.detector.process(self.spoofed_packet)
        self.assertEqual(len(self.alert_manager.alerts), 1)
        
        alert = self.alert_manager.alerts[0]
        self.assertEqual(alert['severity'], 'CRITICAL')
        self.assertEqual(alert['title'], 'ARP Spoofing Detected')
        self.assertIn('192.168.1.100 changed MAC', alert['description'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
