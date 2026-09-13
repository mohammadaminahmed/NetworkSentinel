import socket
from core.platform import detect
from core.logger import log

class PacketCapture:
    def __init__(self, interface: str):
        self.interface = interface
        self.sock = None
        self.running = False
        self.os_type = detect()

    def start(self, callback):
        try:
            if self.os_type == "linux":
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                self.sock.bind((self.interface, 0))
            elif self.os_type == "windows":
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                
                # Check if interface is explicitly an IP
                import re
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", self.interface):
                    host = self.interface
                else:
                    # Auto-detect primary IP using dummy UDP connection (skips VM adapters)
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect(("8.8.8.8", 80))
                        host = s.getsockname()[0]
                        s.close()
                    except Exception:
                        host = socket.gethostbyname(socket.gethostname())
                    log.info(f"Auto-detected primary interface IP: {host}")
                
                self.sock.bind((host, 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            elif self.os_type == "android":
                log.error("Packet capture requires root on Android. Using limited mode.")
                return
            else:
                log.error("Unsupported OS for raw capture.")
                return
            
            self.running = True
            log.info(f"Started packet capture on interface '{self.interface}'")
            self._capture_loop(callback)
        except PermissionError:
            log.error("Permission denied. Run as admin/root.")
        except Exception as e:
            log.error(f"Capture error: {e}")

    def _capture_loop(self, callback):
        while self.running:
            try:
                packet, _ = self.sock.recvfrom(65535)
                callback(packet)
            except socket.timeout: continue
            except Exception as e:
                if self.running: log.error(f"Error: {e}")

    def stop(self):
        self.running = False
        if self.sock:
            if self.os_type == "windows":
                try: self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except: pass
            self.sock.close()
