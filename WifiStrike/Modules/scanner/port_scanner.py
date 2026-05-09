DESCRIPTION = "Full TCP port scanner - scans all 65535 ports"
DATE = "2026-05-04"
RANK = "Good"
AUTHOR = "WiFiStrike"

OPTIONS = {
    "target": {"default": "", "description": "Target IP or hostname"},
    "threads": {"default": "500", "description": "Number of threads for scanning"}
}

import socket
import threading
import sys
import time

open_ports = []
lock = threading.Lock()
scanned_count = 0
total_ports = 65535

def scan_port(target, port):
    global scanned_count
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        sock.close()

        with lock:
            scanned_count += 1

        if result == 0:
            service = get_service(port)
            with lock:
                open_ports.append((port, service))
                sys.stdout.write(f"\r[*] Scanned: {scanned_count}/{total_ports} | Found: {len(open_ports)} | Port: {port}/tcp open - {service}")
                sys.stdout.flush()
    except:
        with lock:
            scanned_count += 1

def get_service(port):
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 69: "TFTP", 80: "HTTP", 110: "POP3",
        111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
        161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
        514: "RSH", 554: "RTSP", 587: "SMTP-TLS", 631: "IPP",
        636: "LDAPS", 873: "Rsync", 993: "IMAPS", 995: "POP3S",
        1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
        1883: "MQTT", 2049: "NFS", 2121: "FTP-Alt", 2375: "Docker",
        3128: "Squid", 3306: "MySQL", 3389: "RDP", 4444: "Metasploit",
        5000: "UPnP", 5432: "PostgreSQL", 5555: "Android-ADB",
        5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
        6379: "Redis", 6443: "Kubernetes", 7547: "TR-069",
        8000: "HTTP-Alt", 8009: "AJP", 8080: "HTTP-Proxy",
        8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 9000: "PHP-FPM",
        9090: "Cockpit", 9200: "Elasticsearch", 11211: "Memcached",
        27017: "MongoDB", 27018: "MongoDB-Shard",
        37777: "Dahua-Camera", 44818: "EtherNet/IP",
        47808: "BACnet", 49152: "Windows-RPC",
        50000: "SAP", 50030: "Hadoop", 50070: "Hadoop-Web",
        55553: "Metasploit", 55554: "Metasploit",
        80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt"
    }
    return services.get(port, "Unknown")

def run(options):
    global scanned_count, open_ports
    scanned_count = 0
    open_ports = []

    target = options.get("target", "")
    threads_count = int(options.get("threads", 500))

    if not target:
        print("[!] Target required!")
        return

    print(f"[*] Target: {target}")
    print(f"[*] Scanning: ALL 65535 ports")
    print(f"[*] Threads: {threads_count}")
    print()

    try:
        target_ip = socket.gethostbyname(target)
        if target_ip != target:
            print(f"[*] Resolved: {target} -> {target_ip}")
            print()
    except:
        print(f"[!] Cannot resolve: {target}")
        return

    print("[*] Starting full port scan...")
    print("[*] This may take a few minutes...")
    print("[*] Press Ctrl+C to stop early")
    print()

    start_time = time.time()

    ports = list(range(1, 65536))

    threads = []
    for port in ports:
        while len(threads) >= threads_count:
            for t in threads[:]:
                if not t.is_alive():
                    t.join()
                    threads.remove(t)
            time.sleep(0.0001)

        t = threading.Thread(target=scan_port, args=(target_ip, port))
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        for t in threads:
            while t.is_alive():
                t.join(timeout=0.1)
    except KeyboardInterrupt:
        print()
        print("[*] Scan interrupted by user")

    elapsed = time.time() - start_time

    open_ports.sort(key=lambda x: x[0])

    print()
    print()
    print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE'}")
    print(f"  {'─'*8} {'─'*10} {'─'*20}")

    for port, service in open_ports:
        print(f"  {port:<8} {'open':<10} {service}")

    print()
    print(f"[+] Scan complete!")
    print(f"[+] Open ports: {len(open_ports)}")
    print(f"[+] Scanned: {scanned_count}/{total_ports}")
    print(f"[+] Time: {elapsed:.2f} seconds")

    if len(open_ports) == 0:
        print("[*] No open ports found")
        print("[*] Target may be offline or firewalled")

if __name__ == "__main__":
    run({"target": "127.0.0.1", "threads": "500"})
