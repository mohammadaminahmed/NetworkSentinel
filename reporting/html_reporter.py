import os
from core.logger import log

def generate(alerts: list, devices: list, baseline_info: dict, filename: str) -> str:
    """Generate a self-contained HTML report with CSS."""
    
    # Modern CSS styling for the report
    css = """
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 20px; }
    h1, h2 { color: #2c3e50; }
    .container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    .summary { display: flex; justify-content: space-around; margin-bottom: 30px; }
    .card { background: #ecf0f1; padding: 20px; border-radius: 8px; text-align: center; width: 30%; }
    .card h3 { margin: 0 0 10px 0; color: #7f8c8d; }
    .card p { margin: 0; font-size: 24px; font-weight: bold; color: #2980b9; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background-color: #34495e; color: white; }
    tr:hover { background-color: #f5f5f5; }
    .severity-CRITICAL { color: #c0392b; font-weight: bold; }
    .severity-HIGH { color: #e67e22; font-weight: bold; }
    .severity-MEDIUM { color: #f39c12; font-weight: bold; }
    .severity-INFO { color: #2980b9; font-weight: bold; }
    """
    
    # HTML Header and Summary
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Network Sentinel Report</title>
        <style>{css}</style>
    </head>
    <body>
        <div class="container">
            <h1>Network Sentinel Security Report</h1>
            <div class="summary">
                <div class="card">
                    <h3>Total Alerts</h3>
                    <p>{len(alerts)}</p>
                </div>
                <div class="card">
                    <h3>Discovered Devices</h3>
                    <p>{len(devices)}</p>
                </div>
                <div class="card">
                    <h3>Baseline Status</h3>
                    <p>{'Learned' if baseline_info.get('is_learned') else 'Not Learned'}</p>
                </div>
            </div>
    """
    
    # Alerts Section
    html_content += "<h2>Security Alerts</h2>"
    if alerts:
        html_content += """
        <table>
            <tr><th>Timestamp</th><th>Severity</th><th>Title</th><th>Description</th></tr>
        """
        for a in alerts:
            severity = a.get("severity", "INFO")
            html_content += f"""
            <tr>
                <td>{a.get('timestamp', '')}</td>
                <td class="severity-{severity}">{severity}</td>
                <td>{a.get('title', '')}</td>
                <td>{a.get('description', '')}</td>
            </tr>
            """
        html_content += "</table>"
    else:
        html_content += "<p>No alerts recorded. Your network is safe!</p>"
        
    # Devices Section
    html_content += "<h2>Discovered Devices</h2>"
    if devices:
        html_content += """
        <table>
            <tr><th>MAC Address</th><th>IP Address</th><th>Vendor</th><th>Type</th></tr>
        """
        for d in devices:
            # Handle dictionary vs dataclass seamlessly
            d_dict = d if isinstance(d, dict) else d.__dict__
            html_content += f"""
            <tr>
                <td>{d_dict.get('mac', '')}</td>
                <td>{d_dict.get('ip', '')}</td>
                <td>{d_dict.get('vendor', '')}</td>
                <td>{d_dict.get('device_type', '')}</td>
            </tr>
            """
        html_content += "</table>"
    else:
        html_content += "<p>No devices discovered.</p>"
        
    html_content += """
        </div>
    </body>
    </html>
    """
    
    try:
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        log.info(f"HTML report generated at {filename}")
        return filename
    except Exception as e:
        log.error(f"Failed to generate HTML report: {e}")
        return ""
