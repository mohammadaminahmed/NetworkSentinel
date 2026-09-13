import subprocess
import threading
from core.logger import log
from core.platform import detect

class FirewallManager:
    def __init__(self):
        self.blocked_ips = set()
        self.os_type = detect()

    def block_ip(self, ip: str):
        """Block an IP address at the OS firewall level asynchronously."""
        if not ip or ip in self.blocked_ips:
            return
            
        self.blocked_ips.add(ip)
        threading.Thread(target=self._execute_block, args=(ip,), daemon=True).start()

    def unblock_ip(self, ip: str):
        """Unblock a previously blocked IP address."""
        if not ip or ip not in self.blocked_ips:
            return
        
        self.blocked_ips.remove(ip)
        threading.Thread(target=self._execute_unblock, args=(ip,), daemon=True).start()

    def _execute_block(self, ip: str):
        try:
            if self.os_type == 'windows':
                # Windows Firewall rule
                rule_name = f"NetworkSentinel_Block_{ip}"
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log.info(f"IPS ACTION: Automatically blocked {ip} in Windows Firewall.")
                
            elif self.os_type == 'android':
                # Android requires root for iptables
                cmd = f'su -c "iptables -A INPUT -s {ip} -j DROP"'
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log.info(f"IPS ACTION: Automatically blocked {ip} in Android (Rooted).")
                
            elif self.os_type == 'linux':
                # Linux iptables rule
                cmd = f'iptables -A INPUT -s {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log.info(f"IPS ACTION: Automatically blocked {ip} in iptables.")
                
            else:
                log.warning(f"IPS ACTION: Automatic blocking not supported on {self.os_type}.")
        except Exception as e:
            log.error(f"IPS ACTION FAILED: Could not block {ip}. {e}")

    def _execute_unblock(self, ip: str):
        try:
            if self.os_type == 'windows':
                rule_name = f"NetworkSentinel_Block_{ip}"
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log.info(f"IPS ACTION: Automatically unblocked {ip} in Windows Firewall.")
                
            elif self.os_type == 'android':
                cmd = f'su -c "iptables -D INPUT -s {ip} -j DROP"'
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log.info(f"IPS ACTION: Automatically unblocked {ip} in Android (Rooted).")
                
            elif self.os_type == 'linux':
                cmd = f'iptables -D INPUT -s {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log.info(f"IPS ACTION: Automatically unblocked {ip} in iptables.")
        except Exception as e:
            log.error(f"IPS ACTION FAILED: Could not unblock {ip}. {e}")
