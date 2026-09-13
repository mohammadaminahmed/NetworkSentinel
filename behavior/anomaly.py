from behavior.statistics import z_score
from behavior.baseline import Baseline

class AnomalyDetector:
    def __init__(self, alert_manager):
        self.alert_manager = alert_manager

    def compare(self, current_macs: set, current_packet_count: int, baseline: Baseline) -> list:
        """
        Compares current network behavior against the learned baseline.
        Returns a list of detected anomalies.
        """
        if not baseline.is_learned:
            return [] # Can't detect anomalies without baseline
            
        anomalies = []
        
        # 1. New device detection
        new_macs = current_macs - baseline.known_macs
        for mac in new_macs:
            anomalies.append(f"Unknown device detected: {mac}")
            self.alert_manager.add_alert(
                "INFO",
                "New Device Detected",
                f"A device not seen in the baseline has connected: {mac}",
                "AnomalyDetector"
            )
            
        # 2. Abnormal traffic volume using Z-Score
        if baseline.std_packets > 0:
            z = z_score(current_packet_count, baseline.mean_packets, baseline.std_packets)
            # Z-score > 3 is generally considered a significant anomaly (99.7% rule)
            if z > 3.0:
                anomalies.append(f"High traffic volume (Z-score: {z:.2f})")
                self.alert_manager.add_alert(
                    "MEDIUM",
                    "Traffic Anomaly",
                    f"Traffic volume is unusually high: {current_packet_count} pkts/min (Z-Score: {z:.2f})",
                    "AnomalyDetector"
                )
            elif z < -3.0:
                anomalies.append(f"Low traffic volume (Z-score: {z:.2f})")
                
        return anomalies
