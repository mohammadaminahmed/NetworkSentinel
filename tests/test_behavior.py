import unittest
import sys
import os
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from behavior.statistics import mean, std_dev, z_score, moving_average
from behavior.baseline import Baseline
from behavior.anomaly import AnomalyDetector
from core.alert_manager import AlertManager
import behavior.statistics as stats

class TestBehaviorSystem(unittest.TestCase):
    def test_statistics(self):
        values = [10.0, 12.0, 23.0, 23.0, 16.0, 23.0, 21.0, 16.0]
        self.assertAlmostEqual(mean(values), 18.0)
        self.assertAlmostEqual(std_dev(values), 5.2372, places=3)
        self.assertAlmostEqual(z_score(23.0, 18.0, 5.2372), 0.9547, places=3)
        
        m_avg = moving_average(values, window=3)
        self.assertEqual(len(m_avg), 6)
        self.assertAlmostEqual(m_avg[0], 15.0)

    def test_baseline_and_anomaly(self):
        alert_manager = AlertManager()
        anomaly_detector = AnomalyDetector(alert_manager)
        baseline = Baseline()
        
        # Simulate baseline learning
        baseline.known_macs = {"00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"}
        baseline.packet_counts_per_minute = [100, 105, 95, 110, 90]
        baseline.update_stats(stats)
        baseline.is_learned = True
        
        self.assertAlmostEqual(baseline.mean_packets, 100.0)
        self.assertTrue(baseline.std_packets > 0)
        
        # Test 1: Normal behavior (Known MAC, normal traffic)
        current_macs = {"00:11:22:33:44:55"}
        current_count = 102
        anomalies = anomaly_detector.compare(current_macs, current_count, baseline)
        self.assertEqual(len(anomalies), 0)
        self.assertEqual(len(alert_manager.alerts), 0)
        
        # Test 2: Unknown MAC
        current_macs = {"00:11:22:33:44:55", "99:88:77:66:55:44"}
        current_count = 100
        anomalies = anomaly_detector.compare(current_macs, current_count, baseline)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(len(alert_manager.alerts), 1)
        self.assertIn("New Device Detected", alert_manager.alerts[0]['title'])
        
        # Test 3: High traffic anomaly (Z-score > 3)
        alert_manager.clear()
        current_macs = {"00:11:22:33:44:55"}
        # std_dev of [100, 105, 95, 110, 90] is 7.905
        # Mean is 100. Z-score of 3 -> count > 100 + 3*7.905 = 123.7
        current_count = 150 
        anomalies = anomaly_detector.compare(current_macs, current_count, baseline)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(len(alert_manager.alerts), 1)
        self.assertIn("Traffic Anomaly", alert_manager.alerts[0]['title'])

    def test_baseline_save_load(self):
        baseline = Baseline()
        baseline.known_macs = {"11:22:33:44:55:66"}
        baseline.mean_packets = 50.5
        baseline.std_packets = 2.1
        baseline.is_learned = True
        
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_name = tmp.name
            
        try:
            baseline.save(tmp_name)
            
            new_baseline = Baseline()
            new_baseline.load(tmp_name)
            
            self.assertEqual(new_baseline.known_macs, {"11:22:33:44:55:66"})
            self.assertEqual(new_baseline.mean_packets, 50.5)
            self.assertEqual(new_baseline.std_packets, 2.1)
            self.assertTrue(new_baseline.is_learned)
        finally:
            os.remove(tmp_name)

if __name__ == '__main__':
    unittest.main(verbosity=2)
