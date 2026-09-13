import json
import os
from core.logger import log

def generate(alerts: list, devices: list, baseline_info: dict, filename: str) -> str:
    """Generate a JSON report."""
    report_data = {
        "summary": {
            "total_alerts": len(alerts),
            "total_devices": len(devices),
            "baseline_learned": baseline_info.get("is_learned", False)
        },
        "alerts": alerts,
        "devices": devices,
        "baseline": baseline_info
    }
    
    try:
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=4)
        log.info(f"JSON report generated at {filename}")
        return filename
    except Exception as e:
        log.error(f"Failed to generate JSON report: {e}")
        return ""
