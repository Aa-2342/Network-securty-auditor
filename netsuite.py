"""
NetSuite — Network Visibility & Security Platform
Author: Ahmed Al-Ghamdi
Description: Combined pipeline that maps network topology,
             identifies device types, and audits security risks.
"""

import socket
import subprocess
import platform
import json
import datetime
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
# DEVICE SIGNATURES
# ─────────────────────────────────────────────
DEVICE_SIGNATURES = {
    "Router/Firewall": [80, 443, 22, 23, 161],
    "Windows PC":      [135, 139, 445, 3389],
    "Linux Server":    [22, 80, 443],
    "Printer":         [9100, 515, 631],
    "IP Camera":       [554, 8080, 80],
    "Switch":          [22, 23, 161, 80],
    "Database Server": [3306, 1433, 5432],
}

# ─────────────────────────────────────────────
# DANGEROUS PORTS
# ─────────────────────────────────────────────
DANGEROUS_PORTS = {
    21:   {"service": "FTP",      "risk": "HIGH",   "reason": "Plaintext file transfer — credentials exposed"},
    23:   {"service": "Telnet",   "risk": "HIGH",   "reason": "Unencrypted remote access — easily intercepted"},
    445:  {"service": "SMB",      "risk": "HIGH",   "reason": "EternalBlue / ransomware attack vector"},
    3389: {"service": "RDP",      "risk": "HIGH",   "reason": "Remote Desktop exposed — brute force risk"},
    3306: {"service": "MySQL",    "risk": "HIGH",   "reason": "Database exposed to network"},
    1433: {"service": "MSSQL",    "risk": "HIGH",   "reason": "Database exposed to network"},
    5900: {"service": "VNC",      "risk": "HIGH",   "reason": "Remote desktop with weak auth"},
    80:   {"service": "HTTP",     "risk": "MEDIUM", "reason": "Unencrypted web traffic"},
    135:  {"service": "RPC",      "risk": "MEDIUM", "reason": "Common remote exploitation target"},
    139:  {"service": "NetBIOS",  "risk": "MEDIUM", "reason": "Legacy Windows sharing — info disclosure"},
    8080: {"service": "HTTP-Alt", "risk": "LOW",    "reason": "Alternative HTTP — verify if intentional"},
}

SAFE_PORTS = {22: "SSH", 443: "HTTPS", 53: "DNS", 123: "NTP"}

ALL_PORTS = sorted(set(
    list(DANGEROUS_PORTS.keys()) +
    list(SAFE_PORTS.keys()) +
    [9100, 515, 631, 554, 161, 5432, 27017]
))


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def ping_host(ip, timeout=1):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        r = subprocess.run(
            ["ping", param, "1", "-W", str(timeout), str(ip)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 1
        )
        return r.returncode == 0
    except:
        return False


def scan_port(ip, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((str(ip), port)) == 0
    except:
        return False


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"


def detect_device_type(open_ports):
    best, score = "Unknown Device", 0
    for dtype, ports in DEVICE_SIGNATURES.items():
        m = len(set(open_ports) & set(ports))
        if m > score:
            score, best = m, dtype
    return best


def calculate_risk(open_ports):
    findings, score = [], 0
    for port in open_ports:
        if port in DANGEROUS_PORTS:
            info = DANGEROUS_PORTS[port]
            findings.append({"port": port, "service": info["service"],
                             "risk": info["risk"], "reason": info["reason"]})
            score += {"HIGH": 30, "MEDIUM": 15, "LOW": 5}.get(info["risk"], 0)
        elif port in SAFE_PORTS:
            findings.append({"port": port, "service": SAFE_PORTS[port],
                             "risk": "SAFE", "reason": "Encrypted / standard protocol"})

    if score >= 60:   level = "CRITICAL"
    elif score >= 30: level = "HIGH"
    elif score >= 15: level = "MEDIUM"
    elif score > 0:   level = "LOW"
    else:             level = "CLEAN"

    return findings, min(score, 100), level


# ─────────────────────────────────────────────
# FULL HOST SCAN
# ─────────────────────────────────────────────
def scan_host(ip):
    if not ping_host(ip):
        return {"ip": str(ip), "status": "down"}

    open_ports = []
    with ThreadPoolExecutor(max_workers=25) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in ALL_PORTS}
        for f in as_completed(futures):
            if f.result():
                open_ports.append(futures[f])

    open_ports = sorted(open_ports)
    hostname    = get_hostname(ip)
    device_type = detect_device_type(open_ports)
    findings, risk_score, risk_level = calculate_risk(open_ports)

    return {
        "ip":          str(ip),
        "status":      "up",
        "hostname":    hostname,
        "device_type": device_type,
        "open_ports":  open_ports,
        "findings":    findings,
        "risk_score":  risk_score,
        "risk_level":  risk_level,
    }


# ─────────────────────────────────────────────
# NETWORK SCAN
# ─────────────────────────────────────────────
def scan_network(cidr, max_hosts=50):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return {"error": str(e)}

    hosts = list(network.hosts())[:max_hosts]
    results = []

    print(f"\n{'='*55}")
    print(f"  NetSuite — Network Visibility & Security Platform")
    print(f"{'='*55}")
    print(f"  Target : {cidr}")
    print(f"  Hosts  : {len(hosts)}")
    print(f"{'='*55}\n")

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(scan_host, str(ip)): str(ip) for ip in hosts}
        for i, f in enumerate(as_completed(futures), 1):
            r = f.result()
            results.append(r)
            if r["status"] == "up":
                print(f"  [{i:02d}/{len(hosts)}] {r['ip']:15s} | {r['device_type']:20s} | {r['risk_level']}")
            else:
                print(f"  [{i:02d}/{len(hosts)}] {r['ip']:15s} | DOWN")

    up = [r for r in results if r["status"] == "up"]
    risky = [r for r in up if r["risk_level"] in ("CRITICAL", "HIGH")]

    summary = {
        "network":       cidr,
        "scan_time":     datetime.datetime.now().isoformat(),
        "total_scanned": len(results),
        "hosts_up":      len(up),
        "risky_hosts":   len(risky),
        "devices":       sorted(up, key=lambda x: x["risk_score"], reverse=True)
    }

    print(f"\n{'='*55}")
    print(f"  ✓ Hosts Up    : {len(up)}")
    print(f"  ✓ Risky Hosts : {len(risky)}")
    print(f"{'='*55}\n")

    return summary


# ─────────────────────────────────────────────
# SAVE REPORT
# ─────────────────────────────────────────────
def save_report(data, filename=None):
    if not filename:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"netsuite_report_{ts}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  [✓] Report saved: {filename}")
    print(f"  [✓] Open netsuite.html to view results.\n")
    return filename


# ─────────────────────────────────────────────
# ENTRY
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python netsuite.py 192.168.1.0/24")
        print("  python netsuite.py 192.168.1.1")
        sys.exit(1)

    target = sys.argv[1]
    if "/" in target:
        results = scan_network(target)
    else:
        print(f"\n[*] Scanning single host: {target}")
        host = scan_host(target)
        results = {
            "network": target,
            "scan_time": datetime.datetime.now().isoformat(),
            "total_scanned": 1,
            "hosts_up": 1 if host["status"] == "up" else 0,
            "risky_hosts": 1 if host.get("risk_level") in ("CRITICAL", "HIGH") else 0,
            "devices": [host] if host["status"] == "up" else []
        }

    save_report(results)