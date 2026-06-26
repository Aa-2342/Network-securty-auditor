"""
Network Security Auditor
Author: Ahmed Al-Ghamdi
Description: Automated network security scanner that detects open ports,
             weak/insecure protocols, and generates risk reports.
"""

import socket
import subprocess
import platform
import json
import datetime
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
# DANGEROUS PORTS & PROTOCOLS
# ─────────────────────────────────────────────
DANGEROUS_PORTS = {
    21:   {"service": "FTP",        "risk": "HIGH",   "reason": "Transfers data in plaintext — credentials exposed"},
    23:   {"service": "Telnet",     "risk": "HIGH",   "reason": "Unencrypted remote access — easily intercepted"},
    69:   {"service": "TFTP",       "risk": "HIGH",   "reason": "No authentication — allows anonymous file transfer"},
    80:   {"service": "HTTP",       "risk": "MEDIUM", "reason": "Unencrypted web traffic — use HTTPS instead"},
    135:  {"service": "RPC",        "risk": "MEDIUM", "reason": "Common target for remote exploitation"},
    139:  {"service": "NetBIOS",    "risk": "MEDIUM", "reason": "Legacy Windows sharing — information disclosure risk"},
    445:  {"service": "SMB",        "risk": "HIGH",   "reason": "EternalBlue / ransomware attack vector"},
    1433: {"service": "MSSQL",      "risk": "HIGH",   "reason": "Database exposed to network — should be restricted"},
    3306: {"service": "MySQL",      "risk": "HIGH",   "reason": "Database port exposed — brute force risk"},
    3389: {"service": "RDP",        "risk": "HIGH",   "reason": "Remote Desktop exposed — BlueKeep / brute force"},
    5900: {"service": "VNC",        "risk": "HIGH",   "reason": "Remote desktop with weak/no auth by default"},
    8080: {"service": "HTTP-Alt",   "risk": "LOW",    "reason": "Alternative HTTP — verify if intentional"},
    8443: {"service": "HTTPS-Alt",  "risk": "LOW",    "reason": "Alternative HTTPS — verify if intentional"},
}

SAFE_PORTS = {
    22:   "SSH",
    443:  "HTTPS",
    53:   "DNS",
    123:  "NTP",
    161:  "SNMP",
    389:  "LDAP",
    636:  "LDAPS",
}

ALL_SCAN_PORTS = sorted(set(list(DANGEROUS_PORTS.keys()) + list(SAFE_PORTS.keys()) + [22, 443, 53]))


# ─────────────────────────────────────────────
# PING
# ─────────────────────────────────────────────
def ping_host(ip: str, timeout: int = 1) -> bool:
    """Returns True if host responds to ping."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", param, "1", "-W", str(timeout), str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1
        )
        return result.returncode == 0
    except Exception:
        return False


# ─────────────────────────────────────────────
# PORT SCAN
# ─────────────────────────────────────────────
def scan_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Returns True if port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((str(ip), port)) == 0
    except Exception:
        return False


def scan_host(ip: str) -> dict:
    """Full scan of a single host."""
    is_up = ping_host(ip)

    open_ports = []
    findings = []
    risk_score = 0

    if is_up:
        # Scan all ports concurrently
        with ThreadPoolExecutor(max_workers=30) as executor:
            future_to_port = {executor.submit(scan_port, ip, port): port for port in ALL_SCAN_PORTS}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                if future.result():
                    open_ports.append(port)

        # Analyze findings
        for port in open_ports:
            if port in DANGEROUS_PORTS:
                info = DANGEROUS_PORTS[port]
                findings.append({
                    "port": port,
                    "service": info["service"],
                    "risk": info["risk"],
                    "reason": info["reason"]
                })
                risk_score += {"HIGH": 30, "MEDIUM": 15, "LOW": 5}.get(info["risk"], 0)
            elif port in SAFE_PORTS:
                findings.append({
                    "port": port,
                    "service": SAFE_PORTS[port],
                    "risk": "SAFE",
                    "reason": "Encrypted / standard protocol"
                })

    # Determine overall risk level
    if risk_score >= 60:
        overall_risk = "CRITICAL"
    elif risk_score >= 30:
        overall_risk = "HIGH"
    elif risk_score >= 15:
        overall_risk = "MEDIUM"
    elif risk_score > 0:
        overall_risk = "LOW"
    else:
        overall_risk = "CLEAN"

    return {
        "ip": str(ip),
        "status": "up" if is_up else "down",
        "open_ports": sorted(open_ports),
        "findings": findings,
        "risk_score": min(risk_score, 100),
        "overall_risk": overall_risk,
        "scanned_at": datetime.datetime.now().isoformat()
    }


# ─────────────────────────────────────────────
# NETWORK SCAN
# ─────────────────────────────────────────────
def scan_network(cidr: str, max_hosts: int = 50) -> dict:
    """Scan all hosts in a CIDR range."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return {"error": str(e)}

    hosts = list(network.hosts())[:max_hosts]
    results = []

    print(f"\n[*] Scanning {len(hosts)} hosts in {cidr}...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(scan_host, str(ip)): str(ip) for ip in hosts}
        for i, future in enumerate(as_completed(future_to_ip), 1):
            ip = future_to_ip[future]
            result = future.result()
            results.append(result)
            status = result["status"]
            risk = result["overall_risk"] if status == "up" else "-"
            print(f"  [{i}/{len(hosts)}] {ip:15s} — {status.upper():4s}  Risk: {risk}")

    # Summary stats
    up_hosts = [r for r in results if r["status"] == "up"]
    risky = [r for r in up_hosts if r["overall_risk"] in ("CRITICAL", "HIGH")]

    summary = {
        "network": cidr,
        "total_scanned": len(results),
        "hosts_up": len(up_hosts),
        "hosts_down": len(results) - len(up_hosts),
        "risky_hosts": len(risky),
        "scan_time": datetime.datetime.now().isoformat(),
        "hosts": sorted(results, key=lambda x: x["risk_score"], reverse=True)
    }

    return summary


# ─────────────────────────────────────────────
# SAVE REPORT
# ─────────────────────────────────────────────
def save_report(data: dict, filename: str = None) -> str:
    """Save scan results as JSON report."""
    if not filename:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_report_{ts}.json"

    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n[✓] Report saved: {filename}")
    return filename


# ─────────────────────────────────────────────
# CLI ENTRY
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python scanner.py 192.168.1.0/24       # Scan network")
        print("  python scanner.py 192.168.1.1          # Scan single host")
        sys.exit(1)

    target = sys.argv[1]

    if "/" in target:
        results = scan_network(target)
    else:
        print(f"\n[*] Scanning single host: {target}")
        results = {"network": target, "hosts": [scan_host(target)], "scan_time": datetime.datetime.now().isoformat()}

    save_report(results)
    print("\n[✓] Scan complete. Open dashboard.html to view results.")