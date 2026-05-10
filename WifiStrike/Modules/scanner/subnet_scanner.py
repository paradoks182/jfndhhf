"""
WiFiStrike Subnet Scanner
"""

DESCRIPTION = "ARP subnet scanner - discover all devices on local network"
DATE = "2026-05-04"
RANK = "Good"
AUTHOR = "WiFiStrike"

OPTIONS = {
    "interface": {"default": "wlan1", "description": "Network interface"},
    "target": {"default": "", "description": "Target subnet (192.168.1.0/24 or auto)"}
}

import scapy.all as scapy
import socket
import sys
import time
import os

found_devices = []

def get_mac_vendor(mac):
    vendors = {
        "00:1D:0F": "TP-Link", "14:CC:20": "TP-Link", "50:C7:BF": "TP-Link",
        "34:E8:94": "TP-Link", "EC:08:6B": "TP-Link", "00:25:86": "TP-Link",
        "00:14:6C": "Netgear", "20:4E:7F": "Netgear", "30:46:9A": "Netgear",
        "E0:91:F5": "Netgear", "2C:B0:5D": "Netgear", "9C:97:26": "Netgear",
        "00:1C:F0": "D-Link", "1C:7E:E5": "D-Link", "34:08:04": "D-Link",
        "00:23:54": "ASUS", "30:85:A9": "ASUS", "4C:ED:FB": "ASUS",
        "00:15:6D": "Ubiquiti", "24:A4:3C": "Ubiquiti", "78:8A:20": "Ubiquiti",
        "00:0C:41": "Cisco", "00:0F:B5": "Cisco", "00:13:F7": "Cisco",
        "00:13:10": "Cisco", "00:1A:E2": "Cisco", "00:1B:53": "Cisco",
        "00:18:39": "Linksys", "00:1B:2F": "Linksys", "00:1D:7E": "Linksys",
        "08:00:27": "VirtualBox", "00:50:56": "VMware", "00:0C:29": "VMware",
        "D4:6E:0E": "Xiaomi", "F0:B4:29": "Xiaomi", "78:11:DC": "Xiaomi",
        "B0:68:E6": "Samsung", "CC:3A:61": "Samsung", "84:38:35": "Samsung",
        "D8:BB:2C": "Apple", "AC:BC:32": "Apple", "A4:83:E7": "Apple",
        "00:1A:79": "Huawei", "48:DB:50": "Huawei", "30:FB:B8": "Huawei",
        "00:0C:E7": "Hikvision", "4C:EF:C0": "Hikvision", "8C:E7:48": "Hikvision",
        "3C:EF:8C": "Dahua", "A0:BD:1D": "Dahua", "E0:50:8B": "Dahua",
        "00:40:F4": "MikroTik", "4C:5E:0C": "MikroTik", "6C:3B:6B": "MikroTik",
        "00:50:8B": "Zyxel", "CC:5D:4E": "Zyxel", "FC:F5:28": "Zyxel",
    }
    oui = mac[:8].upper()
    return vendors.get(oui, "Unknown")

def get_network(interface):
    try:
        if os.name == "nt":
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except:
        return "192.168.1.0/24"

def find_interface():
    if os.name == "nt":
        return scapy.conf.iface.name if scapy.conf.iface else "Ethernet"
    
    for iface in ["wlan1", "wlan0", "eth0", "eth1"]:
        if os.path.exists(f"/sys/class/net/{iface}"):
            return iface
    
    return scapy.conf.iface.name if scapy.conf.iface else "eth0"

def run(options):
    global found_devices
    found_devices = []

    interface = options.get("interface", "wlan1")
    target = options.get("target", "")

    if not interface or interface == "wlan1":
        interface = find_interface()

    if not target:
        target = get_network(interface)
        print(f"[*] Auto-detected network: {target}")

    print(f"[*] Interface: {interface}")
    print(f"[*] Target: {target}")
    print()
    print("[*] Scanning network with ARP requests...")
    print("[*] Press Ctrl+C to stop early")
    print()

    start_time = time.time()

    try:
        arp = scapy.ARP(pdst=target)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        answered = scapy.srp(packet, timeout=3, iface=interface, verbose=False, retry=2)[0]

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            vendor = get_mac_vendor(mac)
            found_devices.append({"ip": ip, "mac": mac, "vendor": vendor})

    except PermissionError:
        print()
        print("[!] Root privileges required!")
        print("[*] Run with: sudo python3 wifistrike.py")
        return
    except ImportError:
        print()
        print("[!] Scapy not installed!")
        print("[*] Install: sudo pip3 install scapy")
        return
    except OSError as e:
        print()
        print(f"[!] Interface error: {e}")
        print(f"[*] Tried interface: {interface}")
        print(f"[*] Available interfaces:")
        for iface in os.listdir("/sys/class/net"):
            print(f"    - {iface}")
        print(f"[*] Try: set interface:wlan0")
        return
    except KeyboardInterrupt:
        print()
        print("[*] Scan interrupted by user")
    except Exception as e:
        print()
        print(f"[!] Scan failed: {e}")
        return

    elapsed = time.time() - start_time

    found_devices.sort(key=lambda x: tuple(map(int, x['ip'].split('.'))))

    print()
    print()
    print(f"  {'IP':<16} {'MAC':<18} {'Vendor'}")
    print(f"  {'─'*16} {'─'*18} {'─'*20}")

    for device in found_devices:
        print(f"  {device['ip']:<16} {device['mac']:<18} {device['vendor']}")

    print()
    print(f"[+] Scan complete!")
    print(f"[+] Devices found: {len(found_devices)}")
    print(f"[+] Time: {elapsed:.2f} seconds")

    if len(found_devices) == 0:
        print("[*] No devices found")
        print("[*] Try different interface or target")
        print(f"[*] Current interface: {interface}")
        print(f"[*] Current target: {target}")

if __name__ == "__main__":
    run({"interface": "wlan1", "target": ""})