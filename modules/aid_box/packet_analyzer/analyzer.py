"""
Core logic for the Network Packet Analyzer tool.

Two modes:
1. analyze_pcap_file(path) - parses an existing .pcap/.pcapng capture
   file (e.g. exported from Wireshark, or a previous Rupux capture) and
   summarizes it. Works on any OS, needs no special privileges.
2. live_capture(duration_seconds, iface, progress_callback) - attempts
   a short live capture using scapy. This requires elevated privileges
   (Administrator on Windows, root/CAP_NET_RAW on Linux/macOS) and, on
   Windows, the Npcap driver (https://npcap.com) to be installed. If
   those aren't available, it raises a clear, actionable error instead
   of crashing.

Both modes end in the same summarize_packets() so the UI only needs
one rendering path.
"""
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class PacketSummary:
    total_packets: int = 0
    protocol_counts: Counter = field(default_factory=Counter)
    top_src_ips: List[tuple] = field(default_factory=list)
    top_dst_ips: List[tuple] = field(default_factory=list)
    top_dst_ports: List[tuple] = field(default_factory=list)
    suspicious_scanners: List[str] = field(default_factory=list)  # src IPs hitting many distinct dest ports
    error: Optional[str] = None


SCAN_PORT_THRESHOLD = 15  # distinct destination ports from one source = likely a port scan


def _proto_name(pkt) -> str:
    # Import from scapy.all (not targeted submodules) so that scapy's
    # linktype registry (conf.l2types) is fully populated -- otherwise
    # rdpcap can't map Ethernet-linktype captures to the right layers.
    from scapy.all import TCP, UDP, ICMP
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "Other"


def summarize_packets(packets) -> PacketSummary:
    from scapy.all import IP, TCP, UDP

    summary = PacketSummary(total_packets=len(packets))
    src_counter = Counter()
    dst_counter = Counter()
    port_counter = Counter()
    src_to_dst_ports = {}  # src_ip -> set of distinct dest ports touched

    for pkt in packets:
        summary.protocol_counts[_proto_name(pkt)] += 1

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_counter[ip_layer.src] += 1
            dst_counter[ip_layer.dst] += 1

            dport = None
            if pkt.haslayer(TCP):
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                dport = pkt[UDP].dport

            if dport is not None:
                port_counter[dport] += 1
                src_to_dst_ports.setdefault(ip_layer.src, set()).add(dport)

    summary.top_src_ips = src_counter.most_common(10)
    summary.top_dst_ips = dst_counter.most_common(10)
    summary.top_dst_ports = port_counter.most_common(10)

    summary.suspicious_scanners = [
        src for src, ports in src_to_dst_ports.items()
        if len(ports) >= SCAN_PORT_THRESHOLD
    ]

    return summary


def analyze_pcap_file(path: str) -> PacketSummary:
    try:
        from scapy.all import rdpcap
    except ImportError:
        return PacketSummary(error="scapy is not installed. Run: pip install scapy")

    try:
        packets = rdpcap(path)
    except Exception as e:
        return PacketSummary(error=f"Could not read capture file: {e}")

    if len(packets) == 0:
        return PacketSummary(error="Capture file contains no packets.")

    return summarize_packets(packets)


def live_capture(duration_seconds: int = 10, iface: Optional[str] = None,
                  progress_callback=None) -> PacketSummary:
    try:
        from scapy.all import sniff
    except ImportError:
        return PacketSummary(error="scapy is not installed. Run: pip install scapy")

    if progress_callback:
        progress_callback(f"Capturing live traffic for {duration_seconds}s... "
                           f"(requires admin/root + a capture driver)")

    try:
        kwargs = {"timeout": duration_seconds, "store": True}
        if iface:
            kwargs["iface"] = iface
        packets = sniff(**kwargs)
    except PermissionError:
        return PacketSummary(
            error="Permission denied. Live capture needs elevated privileges: "
                  "run Rupux as Administrator on Windows (and make sure Npcap "
                  "from npcap.com is installed), or with sudo on Linux/macOS."
        )
    except OSError as e:
        return PacketSummary(
            error=f"Could not start capture ({e}). On Windows this usually means "
                  f"Npcap (npcap.com) isn't installed, or Rupux isn't running as "
                  f"Administrator."
        )
    except Exception as e:
        return PacketSummary(error=f"Live capture failed: {e}")

    if len(packets) == 0:
        return PacketSummary(error="No packets captured in that window. Try a longer duration.")

    return summarize_packets(packets)
