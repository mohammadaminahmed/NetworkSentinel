import json
import threading
import time
import os
import ssl
import base64
import subprocess
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from core.config import Config
from core.alert_manager import AlertManager
from core.packet_capture import PacketCapture
from storage.device_store import DeviceStore
from behavior.baseline import Baseline
from behavior.anomaly import AnomalyDetector

# Detectors
from detectors.arp_spoof_detector import ArpSpoofDetector
from detectors.dns_tunnel_detector import DnsTunnelDetector
from detectors.rogue_dhcp_detector import RogueDhcpDetector
from detectors.deauth_detector import DeauthDetector
from detectors.port_scan_detector import PortScanDetector
from detectors.malicious_ip_detector import MaliciousIpDetector
from detectors.dos_detector import DosDetector

# Global state for the web app
class WebState:
    is_monitoring = False
    cap = None
    alert_mgr = None
    device_store = None
    monitor_thread = None
    failed_logins = {} # IP -> {'count': 0, 'locked_until': 0}

class DashboardHandler(BaseHTTPRequestHandler):
    def get_client_ip(self):
        cf_ip = self.headers.get('CF-Connecting-IP')
        if cf_ip: return cf_ip
        xff = self.headers.get('X-Forwarded-For')
        if xff: return xff.split(',')[0].strip()
        return self.client_address[0]

    def is_locked_out(self):
        client_ip = self.get_client_ip()
        if client_ip in WebState.failed_logins:
            record = WebState.failed_logins[client_ip]
            if record['count'] >= 5:
                if time.time() < record['locked_until']:
                    return True
                else:
                    record['count'] = 0
        return False

    def check_auth(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            return False
        
        # Read credentials from config or use default admin:admin
        config = Config()
        config.load("config.json")
        expected_user = config.settings.get('web_user', 'admin')
        expected_pass = config.settings.get('web_pass', 'admin')
        
        encoded_creds = auth_header.split(' ')[1]
        try:
            decoded = base64.b64decode(encoded_creds).decode('utf-8')
            user, pwd = decoded.split(':')
            is_valid = (user == expected_user and pwd == expected_pass)
            
            client_ip = self.get_client_ip()
            if is_valid:
                if client_ip in WebState.failed_logins:
                    WebState.failed_logins[client_ip]['count'] = 0
                return True
            else:
                if client_ip not in WebState.failed_logins:
                    WebState.failed_logins[client_ip] = {'count': 0, 'locked_until': 0}
                WebState.failed_logins[client_ip]['count'] += 1
                
                if WebState.failed_logins[client_ip]['count'] >= 5:
                    WebState.failed_logins[client_ip]['locked_until'] = time.time() + 900 # 15 mins lock
                    print(f"\n[!] SECURITY ALERT: IP {client_ip} locked out for 15 minutes due to Brute Force login attempts!")
                return False
        except:
            return False

    def send_security_headers(self):
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self' 'unsafe-inline';")

    def _send_response(self, status_code, payload):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode('utf-8'))

    def do_GET(self):
        if self.is_locked_out():
            self.send_response(403)
            self.send_header('Content-type', 'text/html')
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(b"<h1>403 Forbidden</h1><p>Your IP has been locked for 15 minutes due to too many failed login attempts.</p>")
            return

        if not self.check_auth():
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Network Sentinel Secure Dashboard"')
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(b"401 Unauthorized Access")
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_security_headers()
            self.end_headers()
            html_path = os.path.join(os.path.dirname(__file__), 'index.html')
            with open(html_path, 'r', encoding='utf-8') as f:
                self.wfile.write(f.read().encode('utf-8'))
                
        elif path == '/api/status':
            self._send_response(200, {'running': WebState.is_monitoring})
            
        elif path == '/api/alerts':
            if WebState.alert_mgr:
                self._send_response(200, WebState.alert_mgr.alerts)
            else:
                self._send_response(200, [])
                
        elif path == '/api/devices':
            if WebState.device_store:
                self._send_response(200, WebState.device_store.devices)
            else:
                self._send_response(200, {})
                
        elif path == '/api/ips_pending':
            if WebState.alert_mgr and not WebState.alert_mgr.block_queue.empty():
                ip = WebState.alert_mgr.block_queue.get_nowait()
                self._send_response(200, {'ip': ip})
            else:
                self._send_response(200, {'ip': None})
                
        elif path == '/api/config':
            config = Config()
            config.load("config.json")
            self._send_response(200, config.settings.get("notifications", {}))
            
        elif path == '/api/test_alert':
            if WebState.alert_mgr:
                WebState.alert_mgr.add_alert(
                    "CRITICAL", 
                    "Simulated Attack (Test)", 
                    "This is a guaranteed test alert to verify the UI.", 
                    "Test API", 
                    attacker_ip="9.9.9.9"
                )
            self._send_response(200, {'status': 'alert_injected'})
            
        else:
            self.send_error(404)

    def do_POST(self):
        if self.is_locked_out():
            self.send_response(403)
            self.send_header('Content-type', 'application/json')
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(b'{"error": "IP locked out due to brute force attempts."}')
            return

        if not self.check_auth():
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Network Sentinel Secure Dashboard"')
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(b"401 Unauthorized Access")
            return

        # CSRF Protection: Ensure content type is JSON for API requests
        content_type = self.headers.get('Content-Type', '')
        if 'application/json' not in content_type:
            self.send_error(403, "Forbidden: Invalid Content-Type (CSRF Protection)")
            return
            
        content_length = int(self.headers.get('Content-Length', 0))
        
        # DoS Protection: Limit payload size to 1MB max
        if content_length > 1024 * 1024:
            self.send_error(413, "Payload Too Large")
            return
            
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode('utf-8')) if post_data else {}

        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/api/start':
            if not WebState.is_monitoring:
                interface = data.get('interface', 'eth0')
                WebState.is_monitoring = True
                WebState.monitor_thread = threading.Thread(target=self._run_monitor_loop, args=(interface,), daemon=True)
                WebState.monitor_thread.start()
            self._send_response(200, {'status': 'started'})
            
        elif path == '/api/stop':
            if WebState.is_monitoring:
                WebState.is_monitoring = False
                if WebState.cap:
                    WebState.cap.stop()
            self._send_response(200, {'status': 'stopped'})
            
        elif path == '/api/ips_action':
            ip = data.get('ip')
            action = data.get('action')
            if WebState.alert_mgr and ip:
                if action == 'block':
                    WebState.alert_mgr.firewall.block_ip(ip)
            self._send_response(200, {'status': 'action_taken'})
            
        elif path == '/api/config':
            config = Config()
            config.load("config.json")
            if "notifications" not in config.settings:
                config.settings["notifications"] = {}
            config.settings["notifications"].update(data)
            config.save("config.json")
            
            if WebState.alert_mgr:
                WebState.alert_mgr.notification_config = config.settings["notifications"]
                
            self._send_response(200, {'status': 'saved'})
            
        else:
            self.send_error(404)

    def _run_monitor_loop(self, interface):
        config = Config()
        config.load("config.json")
        
        WebState.alert_mgr = AlertManager(
            notification_config=config.settings.get("notifications", {}),
            ips_enabled=config.settings.get("ips_enabled", True),
            ui_mode='web'
        )
        WebState.device_store = DeviceStore()
        baseline = Baseline()
        
        detectors = [
            ArpSpoofDetector(WebState.alert_mgr),
            DnsTunnelDetector(WebState.alert_mgr),
            RogueDhcpDetector(WebState.alert_mgr),
            DeauthDetector(WebState.alert_mgr),
            PortScanDetector(WebState.alert_mgr),
            MaliciousIpDetector(WebState.alert_mgr),
            DosDetector(WebState.alert_mgr)
        ]
        
        anomaly_detector = AnomalyDetector(WebState.alert_mgr)
        WebState.cap = PacketCapture(interface)
        last_anomaly_check = time.time()
        
        def process_packet(packet):
            nonlocal last_anomaly_check
            baseline.process_packet()
            for detector in detectors:
                try: detector.process(packet)
                except: pass
                    
            current_time = time.time()
            if current_time - last_anomaly_check >= 60:
                last_anomaly_check = current_time
                if baseline.is_learned:
                    anomaly_detector.compare(set(), baseline._current_minute_count, baseline)
                    
        try:
            WebState.cap.start(process_packet)
        except Exception as e:
            print(f"Capture Error: {e}")
        finally:
            WebState.is_monitoring = False

def run_web_server(port=8080):
    server = ThreadingHTTPServer(('0.0.0.0', port), DashboardHandler)
    protocol = "http"
            
    print(f"==========================================")
    print(f"[*] Secure Web Dashboard running locally on: {protocol}://localhost:{port}/")
    print(f"[*] Default Credentials -> Username: admin | Password: admin")
    print(f"==========================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down web server...")
        if WebState.cap:
            WebState.cap.stop()
        server.server_close()
