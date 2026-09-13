import unittest
import struct
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detectors.port_scan_detector import PortScanDetector
from core.alert_manager import AlertManager

class TestPortScanSystem(unittest.TestCase):
    def setUp(self):
        self.alert_manager = AlertManager()
        self.detector = PortScanDetector(self.alert_manager)
        
        # Craft a TCP SYN packet (IPv4 + TCP)
        # IPv4 Header: 20 bytes
        version_ihl = 0x45
        tos = 0
        total_len = 40
        ip_id = 54321
        frag_off = 0
        ttl = 64
        protocol = 6 # TCP
        check = 0
        src_ip = bytes([192, 168, 1, 50])
        dst_ip = bytes([192, 168, 1, 100])
        
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 
            version_ihl, tos, total_len, ip_id, frag_off, 
            ttl, protocol, check, src_ip, dst_ip)
            
        # TCP Header: 20 bytes
        src_port = 12345
        dst_port = 80
        seq = 0
        ack = 0
        data_off_res = 0x50 # 5 * 4 = 20 bytes header
        flags = 0x02 # SYN
        window = 8192
        check_tcp = 0
        urg_ptr = 0
        
        tcp_hdr = struct.pack("!HHIIBBHHH", 
            src_port, dst_port, seq, ack, 
            data_off_res, flags, window, check_tcp, urg_ptr)
            
        self.syn_packet = ip_hdr + tcp_hdr

    def test_port_scan_detection(self):
        """Test the detection of a Port Scan (SYN packets)"""
        # Send 19 SYN packets (below threshold of 20)
        for _ in range(19):
            self.detector.process(self.syn_packet)
        self.assertEqual(len(self.alert_manager.alerts), 0)
        
        # Send the 20th SYN packet -> Trigger Alert
        self.detector.process(self.syn_packet)
        self.assertEqual(len(self.alert_manager.alerts), 1)
        
        alert = self.alert_manager.alerts[0]
        self.assertEqual(alert['severity'], 'MEDIUM')
        self.assertEqual(alert['title'], 'Port Scanning Detected')
        self.assertIn('192.168.1.50', alert['description'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
