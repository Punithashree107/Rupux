"""
Core logic for the DoS Attack Detector tool.

Analyzes network traffic (from a capture file or a short live capture)
for classic denial-of-service traffic signatures:
  - Volumetric flood: one source sending far more packets/sec than normal
  - SYN flood: many TCP SYN packets from a source with almost no
    completed handshakes (ACKs)
  - ICMP flood: abnormally high rate of ICMP packets from one source
  - UDP flood: abnormally high rate of UDP packets from one source

This is purely observational/analytical -- it reads traffic and reports
patterns. It does not generate, replay, or send any traffic itself.
Reuses the same scapy-based packet handling as the Packet Analyzer tool.
"""
from dataclasses import dataclass, field
from typing import List, Optional

from core.settings import get_setting

# Thresholds -- tuned for short capture windows (seconds), not long-term averages.
# SYN flood minimum and volumetric pps thresholds are user-tunable via Settings;
# the rest are fixed heuristics that rarely need adjusting.
SYN_FLOOD_RATIO_THRESHOLD = 0.85   # SYN-only packets / (SYN + ACK) packets from that source
ICMP_FLOOD_PPS_THRESHOLD = 20
UDP_FLOOD_PPS_THRESHOLD = 50


@dataclass
class SourceStats:
    ip: str
    packet_count: int
    syn_count: int
    ack_count: int
    icmp_count: int
    udp_count: int
    pps: float


@dataclass
class DosFinding:
    source_ip: str
    attack_type: str      # "SYN Flood" | "ICMP Flood" | "UDP Flood" | "Volumetric Flood"
    severity: str          # "medium" | "high" | "critical"
    detail: str


@dataclass
class DosAnalysisResult:
    total_packets: int = 0
    duration_seconds: float = 0.0
    findings: List[DosFinding] = field(default_factory=list)
    source_stats: List[SourceStats] = field(default_factory=list)
    error: Optional[str] = None


def _severity_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(sev, 4)


def analyze_packets_for_dos(packets) -> DosAnalysisResult:
    from scapy.all import IP, TCP, UDP, ICMP

    if len(packets) == 0:
        return DosAnalysisResult(error="No packets to analyze.")

    timestamps = []
    for p in packets:
        try:
            timestamps.append(float(p.time))
        except Exception:
            pass
    duration = (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0.0
    duration = max(duration, 0.1)  # avoid divide-by-zero on very short/instant captures

    stats = {}
    for p in packets:
        if not p.haslayer(IP):
            continue
        src = p[IP].src
        s = stats.setdefault(src, {"total": 0, "syn": 0, "ack": 0, "icmp": 0, "udp": 0})
        s["total"] += 1

        if p.haslayer(TCP):
            flags = int(p[TCP].flags)
            syn_set = bool(flags & 0x02)
            ack_set = bool(flags & 0x10)
            if syn_set and not ack_set:
                s["syn"] += 1
            if ack_set:
                s["ack"] += 1

        if p.haslayer(ICMP):
            s["icmp"] += 1

        if p.haslayer(UDP):
            s["udp"] += 1

    findings = []
    source_stats_list = []
    syn_flood_min_packets = get_setting("dos_syn_flood_min_packets")
    volumetric_pps_threshold = get_setting("dos_volumetric_pps_threshold")

    for ip, s in stats.items():
        pps = s["total"] / duration
        source_stats_list.append(SourceStats(
            ip=ip, packet_count=s["total"], syn_count=s["syn"], ack_count=s["ack"],
            icmp_count=s["icmp"], udp_count=s["udp"], pps=round(pps, 1),
        ))

        # SYN flood: lots of SYNs, almost no completed handshakes
        tcp_handshake_total = s["syn"] + s["ack"]
        syn_ratio = (s["syn"] / tcp_handshake_total) if tcp_handshake_total > 0 else 0.0
        if s["syn"] >= syn_flood_min_packets and syn_ratio >= SYN_FLOOD_RATIO_THRESHOLD:
            findings.append(DosFinding(
                source_ip=ip, attack_type="SYN Flood", severity="high",
                detail=f"{s['syn']} SYN packets with only {s['ack']} ACKs "
                       f"({syn_ratio:.0%} incomplete handshakes)",
            ))

        # ICMP flood
        icmp_pps = s["icmp"] / duration
        if icmp_pps >= ICMP_FLOOD_PPS_THRESHOLD:
            findings.append(DosFinding(
                source_ip=ip, attack_type="ICMP Flood", severity="high",
                detail=f"{s['icmp']} ICMP packets (~{icmp_pps:.0f}/sec)",
            ))

        # UDP flood
        udp_pps = s["udp"] / duration
        if udp_pps >= UDP_FLOOD_PPS_THRESHOLD:
            findings.append(DosFinding(
                source_ip=ip, attack_type="UDP Flood", severity="high",
                detail=f"{s['udp']} UDP packets (~{udp_pps:.0f}/sec)",
            ))

        # General volumetric flood (catches anything not caught by the above)
        if pps >= volumetric_pps_threshold:
            findings.append(DosFinding(
                source_ip=ip, attack_type="Volumetric Flood", severity="medium",
                detail=f"{s['total']} packets total (~{pps:.0f}/sec sustained)",
            ))

    source_stats_list.sort(key=lambda x: x.packet_count, reverse=True)
    findings.sort(key=lambda f: _severity_rank(f.severity))

    return DosAnalysisResult(
        total_packets=len(packets),
        duration_seconds=round(duration, 2),
        findings=findings,
        source_stats=source_stats_list[:10],
    )


def analyze_pcap_file(path: str) -> DosAnalysisResult:
    try:
        from scapy.all import rdpcap
    except ImportError:
        return DosAnalysisResult(error="scapy is not installed. Run: pip install scapy")

    try:
        packets = rdpcap(path)
    except Exception as e:
        return DosAnalysisResult(error=f"Could not read capture file: {e}")

    return analyze_packets_for_dos(packets)


def live_monitor(duration_seconds: int = 10, iface: Optional[str] = None,
                  progress_callback=None) -> DosAnalysisResult:
    try:
        from scapy.all import sniff
    except ImportError:
        return DosAnalysisResult(error="scapy is not installed. Run: pip install scapy")

    if progress_callback:
        progress_callback(f"Monitoring live traffic for {duration_seconds}s for DoS patterns... "
                           f"(requires admin/root + a capture driver)")

    try:
        kwargs = {"timeout": duration_seconds, "store": True}
        if iface:
            kwargs["iface"] = iface
        packets = sniff(**kwargs)
    except PermissionError:
        return DosAnalysisResult(
            error="Permission denied. Live monitoring needs elevated privileges: "
                  "run Rupux as Administrator on Windows (with Npcap from npcap.com "
                  "installed), or with sudo on Linux/macOS."
        )
    except OSError as e:
        return DosAnalysisResult(
            error=f"Could not start capture ({e}). On Windows this usually means "
                  f"Npcap isn't installed, or Rupux isn't running as Administrator."
        )
    except Exception as e:
        return DosAnalysisResult(error=f"Live monitoring failed: {e}")

    if len(packets) == 0:
        return DosAnalysisResult(error="No packets captured in that window.")

    return analyze_packets_for_dos(packets)
