import socket
import psutil

def get_interfaces():
    print("====================================")
    print("   Available Network Interfaces     ")
    print("====================================")
    for interface_name, interface_addresses in psutil.net_if_addrs().items():
        for address in interface_addresses:
            if address.family == socket.AF_INET:
                print(f"[{interface_name}] IP: {address.address}")
                
if __name__ == "__main__":
    try:
        get_interfaces()
    except Exception as e:
        print(f"Error fetching interfaces: {e}")
        print("Fallback IP:", socket.gethostbyname(socket.gethostname()))
