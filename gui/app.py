import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import os

from core.config import Config
from core.alert_manager import AlertManager
from core.packet_capture import PacketCapture
from storage.device_store import DeviceStore
from storage.alert_store import AlertStore
from storage.baseline_store import BaselineStore
from behavior.baseline import Baseline
from behavior.anomaly import AnomalyDetector
import behavior.statistics as stats

# Detectors
from detectors.arp_spoof_detector import ArpSpoofDetector
from detectors.dns_tunnel_detector import DnsTunnelDetector
from detectors.rogue_dhcp_detector import RogueDhcpDetector
from detectors.deauth_detector import DeauthDetector
from detectors.port_scan_detector import PortScanDetector
from detectors.malicious_ip_detector import MaliciousIpDetector

class SentinelGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sentinel - Dashboard")
        self.root.geometry("900x600")
        
        # Cyber theme colors
        self.bg_color = "#0d1117"
        self.fg_color = "#c9d1d9"
        self.accent_color = "#2ea043" # Green
        self.alert_color = "#f85149" # Red
        self.warning_color = "#d29922" # Yellow
        
        self.root.configure(bg=self.bg_color)
        
        # State
        self.is_monitoring = False
        self.cap = None
        self.alert_mgr = None
        self.device_store = None
        
        self._setup_styles()
        self._build_ui()
        
        # Check queue periodically
        self.root.after(1000, self._process_ips_queue)
        self.root.after(2000, self._update_tables)
        
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('default')
        style.configure('TFrame', background=self.bg_color)
        style.configure('TLabel', background=self.bg_color, foreground=self.fg_color, font=('Consolas', 11))
        style.configure('Header.TLabel', font=('Consolas', 16, 'bold'), foreground=self.accent_color)
        
        style.configure('TButton', font=('Consolas', 10, 'bold'), background="#21262d", foreground=self.fg_color)
        style.map('TButton', background=[('active', self.accent_color)])
        
        style.configure('Treeview', 
                        background="#161b22", 
                        foreground=self.fg_color, 
                        fieldbackground="#161b22",
                        font=('Consolas', 10))
        style.configure('Treeview.Heading', font=('Consolas', 10, 'bold'), background="#21262d", foreground=self.fg_color)

    def _build_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- Top Control Panel ---
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(control_frame, text="Network Sentinel 🛡️", style='Header.TLabel').pack(side=tk.LEFT, padx=(0, 20))
        
        ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT)
        self.interface_var = tk.StringVar(value="eth0")
        self.interface_entry = ttk.Entry(control_frame, textvariable=self.interface_var, width=15)
        self.interface_entry.pack(side=tk.LEFT, padx=(5, 20))
        
        self.btn_start = tk.Button(control_frame, text="START MONITORING", bg=self.accent_color, fg="white", font=('Consolas', 10, 'bold'), command=self.toggle_monitoring)
        self.btn_start.pack(side=tk.LEFT)
        
        self.status_lbl = ttk.Label(control_frame, text="Status: IDLE", foreground=self.warning_color)
        self.status_lbl.pack(side=tk.RIGHT)
        
        # --- Notebook for Tabs ---
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Tab 1: Alerts
        alerts_frame = ttk.Frame(notebook)
        notebook.add(alerts_frame, text=" 🚨 Alerts ")
        
        columns = ("time", "severity", "title", "source")
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=columns, show="headings")
        self.alerts_tree.heading("time", text="Timestamp")
        self.alerts_tree.heading("severity", text="Severity")
        self.alerts_tree.heading("title", text="Alert Title")
        self.alerts_tree.heading("source", text="Source/Details")
        self.alerts_tree.column("time", width=150)
        self.alerts_tree.column("severity", width=80)
        self.alerts_tree.column("title", width=200)
        self.alerts_tree.column("source", width=300)
        self.alerts_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Colorize severities
        self.alerts_tree.tag_configure('HIGH', foreground=self.alert_color)
        self.alerts_tree.tag_configure('CRITICAL', foreground=self.alert_color, background="#4a0f0f")
        self.alerts_tree.tag_configure('MEDIUM', foreground=self.warning_color)
        self.alerts_tree.tag_configure('LOW', foreground=self.accent_color)

        # Tab 2: Devices
        devices_frame = ttk.Frame(notebook)
        notebook.add(devices_frame, text=" 💻 Devices ")
        
        dev_cols = ("mac", "ip", "vendor", "last_seen")
        self.devices_tree = ttk.Treeview(devices_frame, columns=dev_cols, show="headings")
        self.devices_tree.heading("mac", text="MAC Address")
        self.devices_tree.heading("ip", text="IP Address")
        self.devices_tree.heading("vendor", text="Vendor")
        self.devices_tree.heading("last_seen", text="Last Seen")
        self.devices_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def toggle_monitoring(self):
        if not self.is_monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()
            
    def start_monitoring(self):
        interface = self.interface_var.get().strip()
        if not interface:
            messagebox.showerror("Error", "Please specify a network interface (e.g., eth0, Wi-Fi)")
            return
            
        self.is_monitoring = True
        self.btn_start.config(text="STOP MONITORING", bg=self.alert_color)
        self.status_lbl.config(text="Status: ACTIVE", foreground=self.accent_color)
        
        # Start in background thread
        self.monitor_thread = threading.Thread(target=self._run_monitor_loop, args=(interface,), daemon=True)
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        self.is_monitoring = False
        if self.cap:
            self.cap.stop()
        self.btn_start.config(text="START MONITORING", bg=self.accent_color)
        self.status_lbl.config(text="Status: IDLE", foreground=self.warning_color)
        
    def _run_monitor_loop(self, interface):
        config = Config()
        config.load("config.json")
        
        # Initialize Core with GUI mode
        self.alert_mgr = AlertManager(
            notification_config=config.settings.get("notifications", {}),
            ips_enabled=config.settings.get("ips_enabled", True),
            ui_mode='gui'
        )
        self.device_store = DeviceStore()
        baseline = Baseline()
        
        detectors = [
            ArpSpoofDetector(self.alert_mgr),
            DnsTunnelDetector(self.alert_mgr),
            RogueDhcpDetector(self.alert_mgr),
            DeauthDetector(self.alert_mgr),
            PortScanDetector(self.alert_mgr),
            MaliciousIpDetector(self.alert_mgr)
        ]
        
        anomaly_detector = AnomalyDetector(self.alert_mgr)
        self.cap = PacketCapture(interface)
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
            self.cap.start(process_packet)
        except Exception as e:
            # Let the GUI thread show the error
            self.root.after(0, lambda: messagebox.showerror("Capture Error", str(e)))
            self.root.after(0, self.stop_monitoring)
            
    def _process_ips_queue(self):
        if self.alert_mgr and not self.alert_mgr.block_queue.empty():
            ip = self.alert_mgr.block_queue.get_nowait()
            if ip and ip not in self.alert_mgr.firewall.blocked_ips:
                # Ask user
                ans = messagebox.askyesno("IPS Action Required", f"Critical attack detected!\nDo you want to block the attacker's IP: {ip}?")
                if ans:
                    self.alert_mgr.firewall.block_ip(ip)
        self.root.after(1000, self._process_ips_queue)
        
    def _update_tables(self):
        if self.is_monitoring and self.alert_mgr and self.device_store:
            # Update Alerts
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
            for alert in reversed(self.alert_mgr.alerts[-100:]): # Show last 100
                self.alerts_tree.insert("", "end", values=(
                    alert['timestamp'][:19].replace('T', ' '),
                    alert['severity'],
                    alert['title'],
                    alert['source']
                ), tags=(alert['severity'],))
                
            # Update Devices
            for item in self.devices_tree.get_children():
                self.devices_tree.delete(item)
            for mac, dev in self.device_store.devices.items():
                self.devices_tree.insert("", "end", values=(
                    mac,
                    dev.get('ip', 'Unknown'),
                    dev.get('vendor', 'Unknown'),
                    dev.get('last_seen', '')[:19].replace('T', ' ')
                ))
        self.root.after(2000, self._update_tables)

def run_gui():
    root = tk.Tk()
    app = SentinelGUI(root)
    root.mainloop()

if __name__ == "__main__":
    run_gui()
