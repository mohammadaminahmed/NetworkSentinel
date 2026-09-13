import threading
import queue
from datetime import datetime
from core.logger import log
from core.notifier import notify
from core.firewall import FirewallManager

class AlertManager:
    def __init__(self, max_alerts=1000, notification_config=None, ips_enabled=False, ui_mode='cli'):
        self.max_alerts = max_alerts
        self.alerts = []
        self.notification_config = notification_config or {}
        self.ips_enabled = ips_enabled
        self.ui_mode = ui_mode
        self.firewall = FirewallManager()
        
        # Setup interactive prompt thread for IPS
        self.block_queue = queue.Queue()
        if self.ui_mode not in ['gui', 'web']:
            self.prompt_thread = threading.Thread(target=self._prompt_loop, daemon=True)
            self.prompt_thread.start()

    def _prompt_loop(self):
        while True:
            ip = self.block_queue.get()
            if ip is None: break
            if ip in self.firewall.blocked_ips:
                continue
            
            # Interactive prompt
            print(f"\n[?] IPS ACTION REQUIRED: Do you want to block the attacker's IP ({ip})? (y/n): ", end="", flush=True)
            try:
                ans = input().strip().lower()
                if ans == 'y':
                    self.firewall.block_ip(ip)
                else:
                    log.info(f"IPS ACTION: User ignored blocking for {ip}.")
            except EOFError:
                pass

    def add_alert(self, severity: str, title: str, description: str, source: str, attacker_ip: str = None):
        alert = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "title": title,
            "description": description,
            "source": source,
            "attacker_ip": attacker_ip
        }
        self.alerts.append(alert)
        if len(self.alerts) > self.max_alerts:
            self.alerts.pop(0)
        log.warning(f"ALERT [{severity}]: {title} - {description}")
        
        # Trigger sound and external notifications
        notify(severity, title, description, self.notification_config)
        
        # Trigger IPS blocking (Interactive Mode)
        if self.ips_enabled and attacker_ip and severity in ["HIGH", "CRITICAL"]:
            self.block_queue.put(attacker_ip)

    def get_alerts(self, severity=None, limit=None):
        filtered = [a for a in self.alerts if a['severity'] == severity] if severity else self.alerts
        if limit: return filtered[-limit:]
        return filtered

    def clear(self):
        self.alerts.clear()
