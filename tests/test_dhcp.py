import unittest
import struct
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from parsers.dhcp_parser import parse
from detectors.rogue_dhcp_detector import RogueDhcpDetector
from core.alert_manager import AlertManager

class TestDhcpSystem(unittest.TestCase):
    def setUp(self):
        self.alert_manager = AlertManager()
        self.detector = RogueDhcpDetector(self.alert_manager)
        
        # Craft a valid DHCP Offer from authorized server (192.168.1.1)
        self.auth_offer = self.craft_dhcp_offer("192.168.1.1")
        
        # Craft a valid DHCP Offer from rogue server (192.168.1.100)
        self.rogue_offer = self.craft_dhcp_offer("192.168.1.100")

    def craft_dhcp_offer(self, server_ip: str) -> bytes:
        op = 2 # Reply
        htype = 1
        hlen = 6
        hops = 0
        xid = 0x12345678
        secs = 0
        flags = 0
        ciaddr = b'\x00\x00\x00\x00'
        yiaddr = bytes(map(int, "192.168.1.50".split('.')))
        siaddr = bytes(map(int, server_ip.split('.')))
        giaddr = b'\x00\x00\x00\x00'
        chaddr = b'\x11\x22\x33\x44\x55\x66' + b'\x00'*10
        sname = b'\x00' * 64
        file_ = b'\x00' * 128
        magic_cookie = b'\x63\x82\x53\x63'
        
        header = struct.pack("!BBBBIHH4s4s4s4s16s64s128s4s", 
            op, htype, hlen, hops, xid, secs, flags, 
            ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file_, magic_cookie
        )
        
        # Option 53: Message Type = 2 (Offer)
        opt53 = struct.pack("!BBB", 53, 1, 2)
        # Option 54: Server Identifier
        opt54 = struct.pack("!BB4s", 54, 4, siaddr)
        # End option
        opt_end = struct.pack("!B", 255)
        
        return header + opt53 + opt54 + opt_end

    def test_dhcp_parser(self):
        """Test parsing of a standard DHCP packet"""
        result = parse(self.auth_offer)
        self.assertTrue(bool(result))
        self.assertEqual(result['op'], 'reply')
        self.assertEqual(result['options']['message_type'], 2)
        self.assertEqual(result['options']['server_id'], '192.168.1.1')
        self.assertEqual(result['your_ip'], '192.168.1.50')

    def test_rogue_dhcp_detection(self):
        """Test the detection of a Rogue DHCP Server"""
        # First offer learns the authorized server
        self.detector.process(self.auth_offer)
        self.assertEqual(len(self.alert_manager.alerts), 0)
        
        # Second offer from the SAME server is fine
        self.detector.process(self.auth_offer)
        self.assertEqual(len(self.alert_manager.alerts), 0)
        
        # Offer from a DIFFERENT (Rogue) server triggers alert
        self.detector.process(self.rogue_offer)
        self.assertEqual(len(self.alert_manager.alerts), 1)
        
        alert = self.alert_manager.alerts[0]
        self.assertEqual(alert['severity'], 'CRITICAL')
        self.assertEqual(alert['title'], 'Rogue DHCP Server Detected')
        self.assertIn('192.168.1.100', alert['description'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
