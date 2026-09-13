import argparse
import sys
import os
import time
import threading
from datetime import datetime

from core.platform import is_admin, detect
from core.logger import log
from core.config import Config
from cli.menu import run_menu
from core.packet_capture import PacketCapture
from core.alert_manager import AlertManager

# Import Stores
from storage.device_store import DeviceStore
from storage.alert_store import AlertStore
from storage.baseline_store import BaselineStore

# Import Behavior
from behavior.baseline import Baseline
from behavior.anomaly import AnomalyDetector
import behavior.statistics as stats

# Import Detectors
from detectors.arp_spoof_detector import ArpSpoofDetector
from detectors.dns_tunnel_detector import DnsTunnelDetector
from detectors.rogue_dhcp_detector import RogueDhcpDetector
from detectors.deauth_detector import DeauthDetector
from detectors.port_scan_detector import PortScanDetector
from detectors.malicious_ip_detector import MaliciousIpDetector
from detectors.dos_detector import DosDetector

# Import Reporting
from reporting import json_reporter, html_reporter, email_reporter

def welcome_message():
    print("""
=========================================================
    Network Sentinel - Home Network IDS
    [DEFENSIVE TOOL ONLY - Protect Your Network]
=========================================================
    """)

def run_monitor(interface="eth0", learn_mode=False):
    log.info(f"Starting monitor mode on interface '{interface}'...")
    
    # Load configuration
    config = Config()
    config.load("config.json")
    
    # Initialize Core Stores
    alert_mgr = AlertManager(
        notification_config=config.settings.get("notifications", {}),
        ips_enabled=config.settings.get("ips_enabled", True)
    )
    alert_store = AlertStore()
    device_store = DeviceStore()
    baseline = Baseline()
    
    # Load past data
    os.makedirs("data", exist_ok=True)
    if os.path.exists("data/alerts.json"):
        alert_mgr.alerts = alert_store.load("data/alerts.json")
    if os.path.exists("data/devices.json"):
        device_store.load("data/devices.json")
    if os.path.exists("data/baseline.json"):
        BaselineStore.load(baseline, "data/baseline.json")
        
    if learn_mode:
        log.info("Learning mode enabled. Building network baseline...")
        baseline.is_learned = False
        baseline.packet_counts_per_minute = []

    # Initialize Detectors
    detectors = [
        ArpSpoofDetector(alert_mgr),
        DnsTunnelDetector(alert_mgr),
        RogueDhcpDetector(alert_mgr),
        DeauthDetector(alert_mgr),
        PortScanDetector(alert_mgr),
        MaliciousIpDetector(alert_mgr),
        DosDetector(alert_mgr)
    ]
    
    anomaly_detector = AnomalyDetector(alert_mgr)
    cap = PacketCapture(interface)
    last_anomaly_check = time.time()
    
    def process_packet(packet):
        nonlocal last_anomaly_check
        
        # 1. Pass to Baseline for packet counting
        baseline.process_packet()
        
        # 2. Pass to all signature-based detectors
        for detector in detectors:
            try:
                detector.process(packet)
            except Exception as e:
                pass # Fail silently to prevent crashing the capture loop
                
        # 3. Periodically check anomalies and learning state (every 60s)
        current_time = time.time()
        if current_time - last_anomaly_check >= 60:
            last_anomaly_check = current_time
            if baseline.is_learned:
                # Compare current packet count against baseline
                anomaly_detector.compare(set(), baseline._current_minute_count, baseline)
            elif learn_mode and len(baseline.packet_counts_per_minute) >= 5:
                # After 5 minutes of learning, finalize baseline
                baseline.update_stats(stats)
                baseline.is_learned = True
                log.info("Baseline learning complete.")

    def daily_report_worker():
        last_sent_date = None
        while True:
            target_time = config.settings.get("daily_report_time", "23:59")
            current_time = datetime.now().strftime("%H:%M")
            current_date = datetime.now().date()
            if current_time == target_time and last_sent_date != current_date:
                log.info("Generating and sending daily report...")
                os.makedirs("reports", exist_ok=True)
                json_reporter.generate(alert_mgr.alerts, device_store.get_all_devices(), {"is_learned": baseline.is_learned}, "reports/report.json")
                html_reporter.generate(alert_mgr.alerts, device_store.get_all_devices(), {"is_learned": baseline.is_learned}, "reports/report.html")
                email_reporter.send_daily_report(config, "reports/report.html")
                last_sent_date = current_date
            time.sleep(60)

    scheduler_thread = threading.Thread(target=daily_report_worker, daemon=True)
    scheduler_thread.start()

    try:
        cap.start(process_packet)
    except KeyboardInterrupt:
        cap.stop()
        log.info("Monitoring stopped by user. Saving data...")
        
        # Save all data
        os.makedirs("data", exist_ok=True)
        alert_store.save(alert_mgr.alerts, "data/alerts.json")
        device_store.save("data/devices.json")
        
        # Complete learning if stopped early
        if learn_mode and not baseline.is_learned and baseline.packet_counts_per_minute:
            baseline.update_stats(stats)
            baseline.is_learned = True
            
        BaselineStore.save(baseline, "data/baseline.json")
        
        # Generate Reports
        os.makedirs("reports", exist_ok=True)
        json_reporter.generate(alert_mgr.alerts, device_store.get_all_devices(), {"is_learned": baseline.is_learned}, "reports/report.json")
        html_reporter.generate(alert_mgr.alerts, device_store.get_all_devices(), {"is_learned": baseline.is_learned}, "reports/report.html")
        
        log.info("Data saved and reports generated. Goodbye!")

def main():
    parser = argparse.ArgumentParser(description="Network Sentinel - Intelligent IDS")
    parser.add_argument('--version', action='version', version='Network Sentinel 1.0')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO')
    
    subparsers = parser.add_subparsers(dest='command')
    
    # Monitor Command
    monitor_parser = subparsers.add_parser('monitor', help='Start network monitoring')
    monitor_parser.add_argument('-i', '--interface', help='Network interface to monitor (e.g., eth0, Wi-Fi)', default='eth0')
    monitor_parser.add_argument('--learn', action='store_true', help='Force baseline learning mode')
    
    # Other Commands
    subparsers.add_parser('devices', help='List discovered devices')
    subparsers.add_parser('alerts', help='Show recent alerts')
    subparsers.add_parser('menu', help='Interactive menu')
    subparsers.add_parser('gui', help='Launch the Desktop GUI Dashboard')
    web_parser = subparsers.add_parser('web', help='Launch the Web Dashboard')
    web_parser.add_argument('--port', type=int, default=8080, help='Port to run the web server on')

    args = parser.parse_args()

    welcome_message()
    log.set_level(args.log_level)

    if not is_admin():
        log.warning("Not running as Administrator/Root. Packet Capture may fail due to permissions.")

    if args.command == 'menu' or not args.command:
        run_menu()
    elif args.command == 'monitor':
        run_monitor(args.interface, args.learn)
    elif args.command == 'gui':
        from gui.app import run_gui
        run_gui()
    elif args.command == 'web':
        from web.server import run_web_server
        run_web_server(args.port)
    else:
        log.info(f"Command '{args.command}' is not implemented yet. Please use 'monitor' or 'menu'.")

if __name__ == "__main__":
    main()
