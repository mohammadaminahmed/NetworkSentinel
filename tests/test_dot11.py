import unittest
import struct
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from parsers.dot11_parser import parse
from detectors.deauth_detector import DeauthDetector
from core.alert_manager import AlertManager

class TestDot11System(unittest.TestCase):
    def setUp(self):
        self.alert_manager = AlertManager()
        self.detector = DeauthDetector(self.alert_manager)
        
        # Craft a Beacon Frame (Type 0, Subtype 8 -> Frame control: 0x0080 in little endian)
        # Frame Control (2 bytes) = \x80\x00
        fc_beacon = b'\x80\x00'
        duration = b'\x00\x00'
        addr1 = b'\xff\xff\xff\xff\xff\xff' # Broadcast
        addr2 = b'\x00\x11\x22\x33\x44\x55' # Transmitter
        addr3 = b'\x00\x11\x22\x33\x44\x55' # BSSID
        seq = b'\x00\x00'
        self.beacon_packet = fc_beacon + duration + addr1 + addr2 + addr3 + seq
        
        # Craft a Deauth Frame (Type 0, Subtype 12 -> Frame control: 0x00C0 in little endian)
        fc_deauth = b'\xc0\x00'
        self.deauth_packet = fc_deauth + duration + addr1 + addr2 + addr3 + seq

    def test_dot11_parser(self):
        """Test parsing of an 802.11 beacon frame"""
        result = parse(self.beacon_packet)
        self.assertTrue(bool(result))
        self.assertEqual(result['type_str'], 'Beacon')
        self.assertEqual(result['bssid'], '00:11:22:33:44:55')

    def test_deauth_detection(self):
        """Test the detection of a Deauth Attack"""
        # Beacon frames shouldn't trigger anything
        for _ in range(15):
            self.detector.process(self.beacon_packet)
        self.assertEqual(len(self.alert_manager.alerts), 0)
        
        # Send 9 Deauth frames (below threshold of 10)
        for _ in range(9):
            self.detector.process(self.deauth_packet)
        self.assertEqual(len(self.alert_manager.alerts), 0)
        
        # Send the 10th Deauth frame -> Trigger Alert
        self.detector.process(self.deauth_packet)
        self.assertEqual(len(self.alert_manager.alerts), 1)
        
        alert = self.alert_manager.alerts[0]
        self.assertEqual(alert['severity'], 'HIGH')
        self.assertEqual(alert['title'], 'Deauthentication Attack Detected')
        self.assertIn('00:11:22:33:44:55', alert['description'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
