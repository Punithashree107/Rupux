"""
Core logic for the IDS System (Intrusion Detection System) tool.

Complements DoS Detector (which focuses on floods) with a different
set of signals, in the same spirit as lightweight NIDS tools like
Snort/Suricata's built-in rule categories:

  - ARP spoofing: one IP address claimed by more than one MAC address
    in ARP replies -- the classic sign of an ARP cache-poisoning attack.
  - Known malicious/backdoor ports: connections to ports conventionally
    associated with malware C2, remote-access trojans, or common
    pentest tool defaults (informational awareness, not exploitation).
  - Plaintext credentials in transit: FTP/Telnet login commands or HTTP
    Basic Auth headers observed unencrypted on the wire.
  - DNS anomalies: unusually long or high-entropy query names, a common
    indicator of DNS tunneling used for covert C2 channels.
  - Port scan behavior: one source touching many distinct destination
    ports (shared detection logic with Packet Analyzer's scanner check).
  - Statistical traffic anomaly: a source sending traffic volume far
    outside the norm for this capture (z-score based outlier check).

Purely observational -- reads traffic and reports patterns. Generates
no traffic, sends no packets, and does not decrypt anything (plaintext
findings only apply to traffic that was already unencrypted).
"""
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional


# Ports conventionally associated with malware/backdoors or common
# offensive-tool defaults -- flagged for awareness, not proof of compromise.
SUSPICIOUS_PORTS = {
    4444: "Common Metasploit default handler port",
    31337: "Classic backdoor port (Back Orifice / 'elite')",
    12345: "NetBus trojan default port",
    6667: "IRC — historically common botnet C2 channel",
    1337: "Common backdoor/leet port",
    5555: "Android Debug Bridge — frequently abused if exposed",
    54321: "Back Orifice 2000 default port",
    9001: "Common Tor relay port (unexpected use may indicate covert tunneling)",
}

SCAN_PORT_THRESHOLD = 15
DNS_TUNNELING_LENGTH_THRESHOLD = 50  # query name length considered suspiciously long
ANOMALY_ZSCORE_THRESHOLD = 3.0


@dataclass
class IdsAlert:
    signature: str
    severity: str      # "info" | "low" | "medium" | "high" | "critical"
    source: Optional[str]
    detail: str


@dataclass
class IdsResult:
    total_packets: int = 0
    duration_seconds: float = 0.0
    alerts: List[IdsAlert] = field(default_factory=list)
    error: Optional[str] = None


def _severity_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)


def _detect_arp_spoofing(packets) -> List[IdsAlert]:
    from scapy.all import ARP

    alerts = []
    ip_to_macs = {}
    for pkt in packets:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # is-at (reply)
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            ip_to_macs.setdefault(ip, set()).add(mac)

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            alerts.append(IdsAlert(
                signature="ARP Spoofing", severity="critical", source=ip,
                detail=f"IP {ip} claimed by {len(macs)} different MAC addresses: {', '.join(macs)}",
            ))
    return alerts


def _detect_suspicious_ports(packets) -> List[IdsAlert]:
    from scapy.all import IP, TCP, UDP

    alerts = []
    seen = set()  # dedupe (src, dst, port) triples
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        dport = None
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport
        if dport in SUSPICIOUS_PORTS:
            key = (pkt[IP].src, pkt[IP].dst, dport)
            if key in seen:
                continue
            seen.add(key)
            alerts.append(IdsAlert(
                signature="Suspicious Port", severity="medium", source=pkt[IP].src,
                detail=f"{pkt[IP].src} -> {pkt[IP].dst}:{dport} ({SUSPICIOUS_PORTS[dport]})",
            ))
    return alerts


def _detect_plaintext_credentials(packets) -> List[IdsAlert]:
    from scapy.all import IP, TCP, Raw

    alerts = []
    seen = set()
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            continue

        src = pkt[IP].src
        finding = None

        if payload.startswith(b"USER ") or payload.startswith(b"PASS "):
            finding = "FTP/Telnet-style plaintext login command observed"
        elif b"Authorization: Basic" in payload:
            finding = "HTTP Basic Authentication (base64, not encrypted) observed"
        elif re.search(rb"(?i)\bpassword=", payload) and b"HTTP" not in payload[:20]:
            finding = "Plaintext 'password=' field observed in traffic"

        if finding:
            key = (src, finding)
            if key in seen:
                continue
            seen.add(key)
            alerts.append(IdsAlert(
                signature="Plaintext Credentials", severity="high", source=src, detail=finding,
            ))
    return alerts


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _detect_dns_anomalies(packets) -> List[IdsAlert]:
    from scapy.all import DNS, DNSQR

    alerts = []
    seen = set()
    for pkt in packets:
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            continue
        try:
            qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
        except Exception:
            continue

        if len(qname) >= DNS_TUNNELING_LENGTH_THRESHOLD:
            if qname in seen:
                continue
            seen.add(qname)
            entropy = _shannon_entropy(qname)
            alerts.append(IdsAlert(
                signature="DNS Anomaly", severity="medium", source=None,
                detail=f"Unusually long DNS query ({len(qname)} chars, entropy {entropy:.1f}) — "
                       f"possible DNS tunneling: {qname[:60]}...",
            ))
    return alerts


def _detect_port_scans(packets) -> List[IdsAlert]:
    from scapy.all import IP, TCP, UDP

    src_to_dst_ports = {}
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        dport = None
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport
        if dport is not None:
            src_to_dst_ports.setdefault(pkt[IP].src, set()).add(dport)

    alerts = []
    for src, ports in src_to_dst_ports.items():
        if len(ports) >= SCAN_PORT_THRESHOLD:
            alerts.append(IdsAlert(
                signature="Port Scan", severity="high", source=src,
                detail=f"{src} touched {len(ports)} distinct destination ports",
            ))
    return alerts


def _detect_statistical_anomaly(packets, duration: float) -> List[IdsAlert]:
    from scapy.all import IP

    counts = Counter()
    for pkt in packets:
        if pkt.haslayer(IP):
            counts[pkt[IP].src] += 1

    if len(counts) < 4:
        return []  # not enough sources for a meaningful statistical baseline

    rates = {ip: c / duration for ip, c in counts.items()}
    values = list(rates.values())
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    stddev = math.sqrt(variance)

    if stddev == 0:
        return []

    alerts = []
    for ip, rate in rates.items():
        z = (rate - mean) / stddev
        if z >= ANOMALY_ZSCORE_THRESHOLD:
            alerts.append(IdsAlert(
                signature="Statistical Anomaly", severity="medium", source=ip,
                detail=f"{rate:.1f} pkts/sec is {z:.1f} standard deviations above "
                       f"this capture's average ({mean:.1f} pkts/sec)",
            ))
    return alerts


def analyze_packets_for_ids(packets) -> IdsResult:
    if len(packets) == 0:
        return IdsResult(error="No packets to analyze.")

    timestamps = []
    for p in packets:
        try:
            timestamps.append(float(p.time))
        except Exception:
            pass
    duration = (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0.0
    duration = max(duration, 0.1)

    alerts = []
    alerts += _detect_arp_spoofing(packets)
    alerts += _detect_suspicious_ports(packets)
    alerts += _detect_plaintext_credentials(packets)
    alerts += _detect_dns_anomalies(packets)
    alerts += _detect_port_scans(packets)
    alerts += _detect_statistical_anomaly(packets, duration)

    alerts.sort(key=lambda a: _severity_rank(a.severity))

    return IdsResult(total_packets=len(packets), duration_seconds=round(duration, 2), alerts=alerts)


def analyze_pcap_file(path: str) -> IdsResult:
    try:
        from scapy.all import rdpcap
    except ImportError:
        return IdsResult(error="scapy is not installed. Run: pip install scapy")

    try:
        packets = rdpcap(path)
    except Exception as e:
        return IdsResult(error=f"Could not read capture file: {e}")

    return analyze_packets_for_ids(packets)


def live_monitor(duration_seconds: int = 10, iface: Optional[str] = None,
                  progress_callback=None) -> IdsResult:
    try:
        from scapy.all import sniff
    except ImportError:
        return IdsResult(error="scapy is not installed. Run: pip install scapy")

    if progress_callback:
        progress_callback(f"Monitoring live traffic for {duration_seconds}s for intrusion signatures... "
                           f"(requires admin/root + a capture driver)")

    try:
        kwargs = {"timeout": duration_seconds, "store": True}
        if iface:
            kwargs["iface"] = iface
        packets = sniff(**kwargs)
    except PermissionError:
        return IdsResult(
            error="Permission denied. Live monitoring needs elevated privileges: "
                  "run Rupux as Administrator on Windows (with Npcap from npcap.com "
                  "installed), or with sudo on Linux/macOS."
        )
    except OSError as e:
        return IdsResult(
            error=f"Could not start capture ({e}). On Windows this usually means "
                  f"Npcap isn't installed, or Rupux isn't running as Administrator."
        )
    except Exception as e:
        return IdsResult(error=f"Live monitoring failed: {e}")

    if len(packets) == 0:
        return IdsResult(error="No packets captured in that window.")

    return analyze_packets_for_ids(packets)
