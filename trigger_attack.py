import socket
import time
import os
import base64

def trigger_malicious_connection():
    target_ip = "6.6.6.6" # Known malicious IP in our blacklist
    print(f"\n[!] Simulating a connection to a known malicious server ({target_ip})...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0) 
        s.connect((target_ip, 80))
        s.close()
    except Exception:
        pass 
    print("✅ Attack sent! (Expected: CRITICAL Alert + IPS Popup)")

def trigger_dns_tunnel():
    print("\n[!] Simulating DNS Tunneling (Data Exfiltration) attack...")
    # Send 6 queries to pass FREQ_THRESHOLD=5
    for i in range(6):
        # Generate high entropy string
        rand_bytes = os.urandom(40)
        # Use base32 to ensure valid domain characters
        domain = base64.b32encode(rand_bytes).decode('utf-8').strip('=').lower() + ".com"
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Minimal DNS query packet
            header = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            qname = b''.join(bytes([len(p)]) + p.encode('utf-8') for p in domain.split('.')) + b'\x00'
            qtype_qclass = b'\x00\x01\x00\x01' # Type A, Class IN
            packet = header + qname + qtype_qclass
            
            s.sendto(packet, ("8.8.8.8", 53))
            s.close()
            print(f"  -> Sent DNS query: {domain[:20]}...")
        except Exception as e:
            pass
        time.sleep(0.1)
    print("✅ Attack sent! (Expected: MEDIUM Alert in the dashboard)")

def trigger_port_scan():
    host = "192.168.1.1" # A common router IP to scan
    print(f"\n[!] Simulating Port Scan against ({host})...")
    for port in range(8000, 8025):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect((host, port))
            s.close()
        except Exception:
            pass
    print("✅ Attack sent! (Expected: MEDIUM Alert in the dashboard)")

def trigger_dos_attack():
    print("\n[!] Simulating Denial of Service (UDP Flood) Attack...")
    target_ip = "127.0.0.1"
    target_port = 9999
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Send 200 packets rapidly to trigger DosDetector (Threshold is 150)
        for i in range(200):
            s.sendto(b"DOS_TEST_PAYLOAD_1234567890", (target_ip, target_port))
        s.close()
        print("✅ DoS Flood sent! (Expected: CRITICAL Alert + IPS Popup)")
    except Exception as e:
        print(f"❌ Attack failed: {e}")

def trigger_ui_test():
    print("\n[!] Sending a direct signal to the Web Dashboard (Bypassing Windows Sockets)...")
    import urllib.request
    try:
        urllib.request.urlopen("http://localhost:8080/api/test_alert", timeout=2)
        print("✅ Alert injected successfully! Check your dashboard now.")
    except Exception as e:
        print(f"❌ Failed to reach dashboard: {e}")

def main():
    print("=========================================")
    print("   Network Sentinel - Attack Simulator   ")
    print("=========================================")
    print("1. Malicious IP Connection (CRITICAL - Triggers IPS)")
    print("2. DNS Tunneling (MEDIUM - Data Exfiltration)")
    print("3. Port Scan (MEDIUM - Reconnaissance)")
    print("4. Denial of Service (DoS) Flood (CRITICAL - Triggers IPS)")
    print("5. Test Web UI Directly (Bypass Windows Raw Sockets) ⭐️ RECOMMENDED")
    print("0. Exit")
    
    choice = input("\nSelect the attack you want to simulate (0-4): ").strip()
    
    if choice == '1':
        trigger_malicious_connection()
    elif choice == '2':
        trigger_dns_tunnel()
    elif choice == '3':
        trigger_port_scan()
    elif choice == '4':
        trigger_dos_attack()
    elif choice == '5':
        trigger_ui_test()
    elif choice == '0':
        print("Goodbye!")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
