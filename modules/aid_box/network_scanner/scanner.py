"""
Core logic for the Network Device Scanner tool.

Two capabilities:
1. scan_network() -- discovers live devices on the local /24 subnet via
   a concurrent ping sweep, resolves hostnames, and flags new devices
   against a saved baseline (see below).
2. scan_ports() -- Nmap-style TCP connect port scan against a single
   target: tries each port with a real TCP handshake (socket.connect),
   reports open/closed, maps well-known ports to service names, and
   does lightweight passive banner grabbing (reads what the service
   volunteers on connect, or sends a harmless HTTP HEAD request for
   web ports). This is a "connect scan" -- the same fundamental
   technique Nmap's default TCP scan uses, and the only unprivileged
   scan type available. It is purely observational: no exploitation,
   no payloads beyond a standard HTTP HEAD request.

Only ever touches targets the machine can already reach on the local
network or that the user explicitly provides -- never scans a
range/target the user didn't ask for.
"""
import json
import os
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional

from core.config import DATA_DIR
from core.settings import get_setting

BASELINE_PATH = os.path.join(DATA_DIR, "known_devices.json")
PING_TIMEOUT_MS = 600


@dataclass
class DeviceResult:
    ip: str
    hostname: Optional[str]
    is_new: bool


@dataclass
class ScanSummary:
    subnet: str
    devices: List[DeviceResult] = field(default_factory=list)
    new_devices: List[DeviceResult] = field(default_factory=list)
    first_scan: bool = False
    error: Optional[str] = None


def get_local_ip() -> str:
    """Find this machine's own LAN IP without sending any real traffic
    (UDP 'connect' on a socket just asks the OS to pick a route/interface)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _ping(ip: str) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, PING_TIMEOUT_MS // 1000)), ip]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=(PING_TIMEOUT_MS / 1000) + 1,
        )
        return result.returncode == 0
    except Exception:
        return False


def _resolve_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _load_baseline() -> set:
    if not os.path.exists(BASELINE_PATH):
        return set()
    try:
        with open(BASELINE_PATH, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()


def _save_baseline(ips: set) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(BASELINE_PATH, "w") as f:
        json.dump(sorted(ips), f, indent=2)


def scan_network(progress_callback=None) -> ScanSummary:
    """
    Sweeps the local /24 subnet the machine is currently on.
    progress_callback(str), if provided, is called with short status
    strings as the scan proceeds (safe to connect to a Qt signal).
    """
    local_ip = get_local_ip()
    if local_ip == "127.0.0.1":
        return ScanSummary(subnet="unknown", error="Could not determine local network interface.")

    base = local_ip.rsplit(".", 1)[0]
    subnet = f"{base}.0/24"
    targets = [f"{base}.{i}" for i in range(1, 255)]

    if progress_callback:
        progress_callback(f"Scanning {subnet} ({len(targets)} addresses)...")

    live_ips = []
    max_workers = get_setting("network_scan_thread_workers")
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_ping, ip): ip for ip in targets}
        done = 0
        for future in as_completed(futures):
            done += 1
            ip = futures[future]
            try:
                if future.result():
                    live_ips.append(ip)
            except Exception:
                pass
            if progress_callback and done % 25 == 0:
                progress_callback(f"Checked {done}/{len(targets)} addresses, {len(live_ips)} responding...")

    if progress_callback:
        progress_callback(f"Resolving hostnames for {len(live_ips)} device(s)...")

    baseline = _load_baseline()
    first_scan = len(baseline) == 0

    devices = []
    for ip in sorted(live_ips, key=lambda x: int(x.split(".")[-1])):
        hostname = _resolve_hostname(ip)
        is_new = (ip not in baseline) and not first_scan
        devices.append(DeviceResult(ip=ip, hostname=hostname, is_new=is_new))

    new_devices = [d for d in devices if d.is_new]

    _save_baseline({d.ip for d in devices} | baseline)

    return ScanSummary(
        subnet=subnet,
        devices=devices,
        new_devices=new_devices,
        first_scan=first_scan,
    )


# ==================== Port Scanning (Nmap-style TCP connect scan) ====================

# Well-known ports and their conventional service names -- for display only.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1723: "PPTP", 3000: "Dev-HTTP", 3306: "MySQL",
    3389: "RDP", 5000: "Dev-HTTP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8000: "HTTP-alt", 8080: "HTTP-proxy", 8443: "HTTPS-alt",
    27017: "MongoDB",
}

# The default "quick scan" port set -- mirrors Nmap's most commonly
# scanned ports, kept small so a scan finishes in a few seconds.
QUICK_SCAN_PORTS = sorted(COMMON_PORTS.keys())

PORT_CONNECT_TIMEOUT = 0.6
BANNER_READ_TIMEOUT = 1.0


@dataclass
class PortResult:
    port: int
    state: str              # "open" | "closed" | "filtered"
    service: str
    banner: Optional[str] = None


@dataclass
class PortScanResult:
    target: str
    resolved_ip: Optional[str] = None
    open_ports: List[PortResult] = field(default_factory=list)
    scanned_count: int = 0
    error: Optional[str] = None


def _grab_banner(ip: str, port: int) -> Optional[str]:
    """Best-effort, passive banner grab: read whatever the service volunteers
    on connect (common for FTP/SSH/SMTP), or send a harmless HTTP HEAD
    request for likely-web ports to read the Server header. Never sends
    anything beyond a standard, unmodified protocol handshake."""
    try:
        with socket.create_connection((ip, port), timeout=PORT_CONNECT_TIMEOUT) as sock:
            sock.settimeout(BANNER_READ_TIMEOUT)

            if port in (80, 8080, 8000, 8443, 3000, 5000, 443):
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
                except Exception:
                    pass

            try:
                data = sock.recv(256)
                text = data.decode("utf-8", errors="replace").strip()
                # Collapse to the first line for a compact, readable banner
                first_line = text.splitlines()[0] if text else ""
                return first_line[:120] if first_line else None
            except socket.timeout:
                return None
    except Exception:
        return None


def _scan_one_port(ip: str, port: int, grab_banners: bool) -> Optional[PortResult]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(PORT_CONNECT_TIMEOUT)
    try:
        result = sock.connect_ex((ip, port))
    except Exception:
        result = 1
    finally:
        sock.close()

    if result != 0:
        return None  # closed/filtered -- not reported (matches Nmap's default "show open only")

    service = COMMON_PORTS.get(port, "unknown")
    banner = _grab_banner(ip, port) if grab_banners else None
    return PortResult(port=port, state="open", service=service, banner=banner)


def scan_ports(target: str, ports: Optional[List[int]] = None, grab_banners: bool = True,
                progress_callback=None) -> PortScanResult:
    """
    TCP connect scan against a single target (hostname or IP). Uses a
    real three-way TCP handshake per port (the only scan type possible
    without raw-socket privileges) -- functionally the same technique
    as `nmap -sT`.
    """
    try:
        resolved_ip = socket.gethostbyname(target)
    except Exception as e:
        return PortScanResult(target=target, error=f"Could not resolve target: {e}")

    port_list = ports if ports else QUICK_SCAN_PORTS

    if progress_callback:
        progress_callback(f"Scanning {len(port_list)} port(s) on {resolved_ip}...")

    open_ports = []
    max_workers = min(get_setting("network_scan_thread_workers"), 100)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_one_port, resolved_ip, p, grab_banners): p for p in port_list}
        done = 0
        for future in as_completed(futures):
            done += 1
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
            except Exception:
                pass
            if progress_callback and done % 5 == 0:
                progress_callback(f"Checked {done}/{len(port_list)} ports, {len(open_ports)} open so far...")

    open_ports.sort(key=lambda r: r.port)

    return PortScanResult(
        target=target,
        resolved_ip=resolved_ip,
        open_ports=open_ports,
        scanned_count=len(port_list),
    )
