import os
import urllib.request

def main():
    print("=========================================")
    print("   Network Sentinel - Remote Access      ")
    print("   (Powered by Cloudflare Tunnels)       ")
    print("=========================================")
    
    cf_url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
    exe_name = "cloudflared.exe"
    
    if not os.path.exists(exe_name):
        print("[*] Downloading Cloudflare Tunnel (First time setup only, please wait...)")
        try:
            urllib.request.urlretrieve(cf_url, exe_name)
            print("[+] Download complete.")
        except Exception as e:
            print(f"❌ Failed to download Cloudflare: {e}")
            return
            
    print("[*] Starting secure tunnel...")
    print("[*] Look for the URL ending in '.trycloudflare.com' below!")
    print("-----------------------------------------\n")
    
    # Run cloudflared
    try:
        os.system(f"{exe_name} tunnel --url http://localhost:8080")
    except KeyboardInterrupt:
        print("\n[*] Tunnel closed.")

if __name__ == "__main__":
    main()
