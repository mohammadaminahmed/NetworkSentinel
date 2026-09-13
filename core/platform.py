import platform
import os
import socket

def detect() -> str:
    system = platform.system().lower()
    if system == "linux":
        if "ANDROID_ROOT" in os.environ: return "android"
        return "linux"
    elif system == "windows": return "windows"
    return "unknown"

def is_linux() -> bool: return detect() == "linux"
def is_windows() -> bool: return detect() == "windows"
def is_android() -> bool: return detect() == "android"

def is_admin() -> bool:
    try:
        if is_windows():
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0
    except Exception:
        return False

def get_default_interface() -> str:
    return "eth0" if is_linux() else "Wi-Fi"

def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def get_network_range() -> str:
    ip = get_local_ip()
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

def get_hostname() -> str:
    return socket.gethostname()
