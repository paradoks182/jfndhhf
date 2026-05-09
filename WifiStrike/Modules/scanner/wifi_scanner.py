DESCRIPTION = "Scan WiFi networks and show BSSID, channel, encryption, signal"
DATE = "2026-05-03"
RANK = "middle"
AUTHOR = "WiFiStrike"

OPTIONS = {
    "interface": {"default": "wlan1", "description": "Wireless interface in monitor mode"},
    "channel": {"default": "", "description": "Channel to scan (empty = all channels)"},
    "time": {"default": "15", "description": "Scan duration in seconds"},
    "output": {"default": "", "description": "Save output to file (optional)"}
}

import subprocess
import os
import time
import signal
import sys

def run(options):
    interface = options.get("interface", "wlan1")
    channel = options.get("channel", "")
    scan_time = int(options.get("time", 15))
    output = options.get("output", "")
    
    if not output:
        output = f"/tmp/wifistrike_scan_{int(time.time())}"
    
    print(f"[*] Starting WiFi scan...")
    print(f"[*] Interface: {interface}")
    print(f"[*] Channel: {channel if channel else 'All'}")
    print(f"[*] Duration: {scan_time} seconds")
    print(f"[*] Press Ctrl+C to stop early")
    print()
    
    cmd = ["sudo", "airodump-ng"]
    
    if channel:
        cmd.extend(["-c", str(channel)])
    
    cmd.extend(["-w", output, "--output-format", "csv", interface])
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(scan_time)
        proc.send_signal(signal.SIGINT)
        proc.wait()
        
        csv_file = f"{output}-01.csv"
        
        if os.path.exists(csv_file):
            print()
            print("[+] Scan complete!")
            print()
            parse_csv(csv_file)
        else:
            print("[!] No output file found. Is monitor mode enabled?")
    
    except KeyboardInterrupt:
        proc.send_signal(signal.SIGINT)
        proc.wait()
        print("\n[*] Scan stopped by user")
    
    except Exception as e:
        print(f"[!] Error: {e}")

def parse_csv(filepath):
    networks = []
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        in_networks = False
        
        for line in lines:
            line = line.strip()
            
            if not line:
                continue
            
            if "BSSID" in line and "ESSID" in line:
                in_networks = True
                continue
            
            if "Station MAC" in line:
                break
            
            if in_networks and "," in line:
                parts = line.split(",")
                if len(parts) >= 14:
                    bssid = parts[0].strip()
                    channel = parts[3].strip()
                    encryption = parts[5].strip()
                    cipher = parts[6].strip()
                    auth = parts[7].strip()
                    power = parts[8].strip()
                    essid = parts[13].strip() if len(parts) > 13 else ""
                    
                    if bssid and ":" in bssid:
                        networks.append({
                            "bssid": bssid,
                            "channel": channel,
                            "encryption": encryption,
                            "cipher": cipher,
                            "auth": auth,
                            "power": power,
                            "essid": essid if essid else "<hidden>"
                        })
    except Exception as e:
        print(f"[!] Parse error: {e}")
        return
    
    if not networks:
        print("[!] No networks found")
        return
    
    networks.sort(key=lambda x: int(x["power"]) if x["power"].lstrip("-").isdigit() else -100, reverse=True)
    
    print(f"  {'#':<3} {'BSSID':<18} {'CH':<4} {'PWR':<5} {'ENC':<8} {'AUTH':<8} {'ESSID'}")
    print(f"  {'-'*3} {'-'*18} {'-'*4} {'-'*5} {'-'*8} {'-'*8} {'-'*20}")
    
    for i, net in enumerate(networks):
        power = net["power"] + "dBm" if net["power"] else "?"
        essid = net["essid"][:25] if len(net["essid"]) > 25 else net["essid"]
        print(f"  {i:<3} {net['bssid']:<18} {net['channel']:<4} {power:<5} {net['encryption']:<8} {net['auth']:<8} {essid}")
    
    print()
    print(f"[+] Total: {len(networks)} networks found")

if __name__ == "__main__":
    run({"interface": "wlan1", "channel": "", "time": "15", "output": ""})
