from detectors.base_detector import BaseDetector
from parsers.dhcp_parser import parse

class RogueDhcpDetector(BaseDetector):
    def __init__(self, alert_manager, allowed_servers=None):
        super().__init__("RogueDhcpDetector", alert_manager)
        self.allowed_servers = allowed_servers or set()
        # If no servers are configured, we "learn" the first one we see
        self.is_learning = not bool(self.allowed_servers)

    def process(self, packet: bytes):
        dhcp_data = parse(packet)
        if not dhcp_data:
            return
            
        # We are looking for DHCP Reply (op=2) and DHCP Offer (message_type=2) or Ack (5)
        options = dhcp_data.get("options", {})
        msg_type = options.get("message_type")
        server_id = options.get("server_id") or dhcp_data.get("server_ip")
        
        # Check only if it is an Offer or Ack from a DHCP Server
        if dhcp_data["op"] == "reply" and msg_type in (2, 5) and server_id:
            if server_id == "0.0.0.0":
                return
                
            if self.is_learning:
                # Trust the first DHCP server we see as the primary/legitimate router
                self.allowed_servers.add(server_id)
                self.is_learning = False
            elif server_id not in self.allowed_servers:
                self.alert_manager.add_alert(
                    "CRITICAL",
                    "Rogue DHCP Server Detected",
                    f"Unauthorized DHCP server spotted offering IPs to clients: {server_id}",
                    self.name,
                    attacker_ip=server_id
                )
