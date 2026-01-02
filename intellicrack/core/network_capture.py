"""Network packet capture and analysis functionality.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import socket
import time
from typing import Any


logger: logging.Logger = logging.getLogger(__name__)


def capture_with_scapy(interface: str = "any", filter_str: str = "", count: int = 100) -> dict[str, Any]:
    """Capture network packets using Scapy for real-time traffic analysis.

    Performs live packet capture on specified network interface with real-time
    packet processing, license-related traffic identification, DNS query tracking,
    port distribution analysis, and license server detection for binary protection
    analysis and network protocol reverse engineering.

    Args:
        interface: Network interface to capture on. Use 'any' for all interfaces
                   or specific interface name (e.g., 'eth0', 'Wi-Fi').
        filter_str: Berkeley Packet Filter (BPF) string for traffic filtering
                    (e.g., 'tcp port 80', 'udp port 53').
        count: Maximum number of packets to capture before stopping.

    Returns:
        Dictionary with packet capture results including success status,
        total packet count, license-related packet identification, unique
        destination counts, detected license servers (IP/port tuples), DNS
        queries, top destination ports, protocol distribution, captured
        packet details, error information, and dependency suggestions.

    Notes:
        - Automatically detects license-related keywords in packet payloads
        - Requires administrative/root privileges for live capture
        - Uses layered packet parsing for IP, TCP, UDP, and DNS
        - Timeout of 10 seconds between packets before stopping

    """
    try:
        from scapy.all import DNS, IP, TCP, UDP, Raw, sniff
    except ImportError:
        return {"error": "Scapy not available", "suggestion": "Install with: pip install scapy"}

    captured_packets = []
    license_servers = set()
    dns_queries = []

    try:

        def packet_handler(packet: Any) -> None:
            """Process captured packets in real-time.

            Args:
                packet: Scapy packet object to process and analyze.
            """
            packet_info: dict[str, Any] = {
                "timestamp": time.time(),
                "size": len(packet),
                "layers": [],
                "summary": packet.summary() if hasattr(packet, "summary") else "",
            }

            # Extract IP layer information
            if IP in packet:
                packet_info["src_ip"] = packet[IP].src
                packet_info["dst_ip"] = packet[IP].dst
                packet_info["protocol"] = packet[IP].proto
                packet_info["ttl"] = packet[IP].ttl

            # Extract transport layer information
            if TCP in packet:
                packet_info["src_port"] = packet[TCP].sport
                packet_info["dst_port"] = packet[TCP].dport
                packet_info["transport"] = "TCP"
                packet_info["flags"] = str(packet[TCP].flags)
                packet_info["seq"] = packet[TCP].seq
                packet_info["ack"] = packet[TCP].ack
            elif UDP in packet:
                packet_info["src_port"] = packet[UDP].sport
                packet_info["dst_port"] = packet[UDP].dport
                packet_info["transport"] = "UDP"

            # Check for DNS queries
            if DNS in packet and packet.haslayer(DNS) and packet[DNS].qr == 0:
                query_name = packet[DNS].qd.qname.decode() if packet[DNS].qd else None
                if query_name:
                    packet_info["dns_query"] = query_name
                    dns_queries.append(query_name)

            # Check for license-related traffic
            if Raw in packet:
                try:
                    payload = bytes(packet[Raw].load)
                    license_keywords = [
                        b"license",
                        b"activation",
                        b"serial",
                        b"key",
                        b"auth",
                        b"validate",
                        b"register",
                        b"subscription",
                        b"trial",
                        b"flexlm",
                        b"rlm",
                        b"hasp",
                        b"sentinel",
                        b"wibu",
                    ]
                    if any(keyword in payload.lower() for keyword in license_keywords):
                        packet_info["license_related"] = True
                        if "dst_ip" in packet_info:
                            license_servers.add((packet_info["dst_ip"], packet_info.get("dst_port", 0)))

                        license_indicators: list[str] = []
                        for keyword in license_keywords:
                            if keyword in payload.lower():
                                license_indicators.append(keyword.decode())
                        packet_info["license_indicators"] = license_indicators
                except (AttributeError, UnicodeDecodeError, TypeError) as e:
                    logger.debug("Failed to extract license indicators from packet: %s", e)

            captured_packets.append(packet_info)

        logger.info("[Scapy] Starting packet capture on interface: %s", interface)

        # Start packet capture with timeout
        packets = sniff(
            iface=interface if interface != "any" else None,
            filter=filter_str,
            count=count,
            prn=packet_handler,
            timeout=10,
            store=False,  # Don't store packets in memory
        )

        # Log capture completion status
        logger.info("[Scapy] Packet capture completed. Session info: %s", packets)

        # Analyze captured packets
        license_packets = [p for p in captured_packets if p.get("license_related")]
        unique_ips = set()
        port_distribution: dict[Any, int] = {}
        protocol_distribution = {"TCP": 0, "UDP": 0, "Other": 0}

        for p in captured_packets:
            if "dst_ip" in p:
                unique_ips.add(p["dst_ip"])

            # Track port distribution
            if "dst_port" in p:
                port = p["dst_port"]
                port_distribution[port] = port_distribution.get(port, 0) + 1

            transport: str = str(p.get("transport", "Other"))
            protocol_distribution[transport] = protocol_distribution.get(transport, 0) + 1

        # Identify top ports
        top_ports = sorted(port_distribution.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "success": True,
            "total_packets": len(captured_packets),
            "license_packets": len(license_packets),
            "unique_destinations": len(unique_ips),
            "license_servers": list(license_servers),
            "dns_queries": list(set(dns_queries))[:20],  # Top 20 unique DNS queries
            "top_ports": top_ports,
            "protocol_distribution": protocol_distribution,
            "packets": captured_packets[:20],  # Return first 20 packets for analysis
        }

    except Exception as e:
        logger.exception("Scapy capture error: %s", e)
        return {"error": str(e), "success": False}


def analyze_pcap_with_pyshark(pcap_file: str) -> dict[str, Any]:
    """Analyze PCAP file using PyShark for deep packet inspection.

    Performs comprehensive analysis of captured network traffic including protocol
    identification, conversation tracking, DNS queries, HTTP requests, TLS handshakes,
    license server identification, and suspicious port detection.

    Args:
        pcap_file: Path to PCAP file to analyze.

    Returns:
        Dictionary with comprehensive packet analysis including total packet
        count, protocol distribution, source-destination conversations, DNS
        queries, HTTP requests, TLS handshakes, suspicious port activity,
        license-related traffic, unique DNS query count, unique conversation
        count, and top 10 conversation partners.
    """
    try:
        import pyshark
    except ImportError:
        return {"error": "PyShark not available", "suggestion": "Install with: pip install pyshark"}

    try:
        logger.info("[PyShark] Analyzing PCAP file: %s", pcap_file)

        # Open capture file with display filter
        cap = pyshark.FileCapture(
            pcap_file,
            display_filter="tcp or udp",
            use_json=True,
            include_raw=True,
        )

        protocols: dict[str, int] = {}
        conversations: dict[str, int] = {}
        dns_queries_list: list[str] = []
        http_requests: list[dict[str, str]] = []
        tls_handshakes: list[str] = []
        suspicious_ports_list: list[dict[str, Any]] = []
        license_traffic: list[dict[str, Any]] = []
        total_packets: int = 0

        suspicious_ports = [1337, 31337, 4444, 5555, 8080, 8888, 9999]
        license_ports = [1947, 27000, 27001, 5053, 5054, 6200, 7070]  # Common license server ports

        for packet in cap:
            total_packets += 1

            if hasattr(packet, "highest_layer"):
                proto: str = str(packet.highest_layer)
                protocols[proto] = protocols.get(proto, 0) + 1

            if hasattr(packet, "ip"):
                src: str = str(getattr(packet.ip, "src", "unknown"))
                dst: str = str(getattr(packet.ip, "dst", "unknown"))
                conv_key: str = f"{src} -> {dst}"
                conversations[conv_key] = conversations.get(conv_key, 0) + 1

                if hasattr(packet, "tcp"):
                    port: int = int(getattr(packet.tcp, "dstport", 0))
                    if port in license_ports:
                        license_traffic.append(
                            {
                                "src": src,
                                "dst": dst,
                                "port": port,
                                "timestamp": getattr(packet, "sniff_timestamp", "unknown"),
                            },
                        )

            if hasattr(packet, "dns") and hasattr(packet.dns, "qry_name"):
                dns_name: str = str(packet.dns.qry_name)
                dns_queries_list.append(dns_name)

                license_domains: list[str] = [
                    "flexera",
                    "flexlm",
                    "rlm",
                    "reprise",
                    "sentinel",
                    "hasp",
                    "wibu",
                ]
                if any(domain in dns_name.lower() for domain in license_domains):
                    license_traffic.append(
                        {
                            "type": "DNS",
                            "query": dns_name,
                            "timestamp": getattr(packet, "sniff_timestamp", "unknown"),
                        },
                    )

            if hasattr(packet, "http") and hasattr(packet.http, "request_method"):
                http_info: dict[str, str] = {
                    "method": str(packet.http.request_method),
                    "uri": str(getattr(packet.http, "request_uri", "unknown")),
                    "host": str(getattr(packet.http, "host", "unknown")),
                    "user_agent": str(getattr(packet.http, "user_agent", "unknown")),
                }
                http_requests.append(http_info)

                if any(keyword in http_info["uri"].lower() for keyword in ["license", "activate", "validate"]):
                    license_traffic.append(
                        {
                            "type": "HTTP",
                            "details": http_info,
                            "timestamp": getattr(packet, "sniff_timestamp", "unknown"),
                        },
                    )

            if hasattr(packet, "tls") and hasattr(packet.tls, "handshake") and hasattr(packet.tls, "handshake_extensions_server_name"):
                server_name: str = str(packet.tls.handshake_extensions_server_name)
                tls_handshakes.append(server_name)

            if hasattr(packet, "tcp"):
                dstport: int = int(getattr(packet.tcp, "dstport", 0))
                if dstport in suspicious_ports:
                    suspicious_ports_list.append(
                        {
                            "port": dstport,
                            "src": getattr(packet.ip, "src", "unknown") if hasattr(packet, "ip") else "unknown",
                            "dst": getattr(packet.ip, "dst", "unknown") if hasattr(packet, "ip") else "unknown",
                            "flags": str(getattr(packet.tcp, "flags", "unknown")),
                        },
                    )

        cap.close()

        unique_dns_queries: int = len(set(dns_queries_list))
        unique_conversations: int = len(conversations)
        top_talkers: list[tuple[str, int]] = sorted(
            conversations.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        return {
            "total_packets": total_packets,
            "protocols": protocols,
            "conversations": conversations,
            "dns_queries": dns_queries_list,
            "http_requests": http_requests,
            "tls_handshakes": tls_handshakes,
            "suspicious_ports": suspicious_ports_list,
            "license_traffic": license_traffic,
            "unique_dns_queries": unique_dns_queries,
            "unique_conversations": unique_conversations,
            "top_talkers": top_talkers,
        }

    except Exception as e:
        logger.exception("PyShark analysis error: %s", e)
        return {"error": str(e), "success": False}


class NetworkCapture:
    """Network packet capture and analysis class for license-related traffic.

    Provides comprehensive network packet analysis capabilities for identifying
    and intercepting license-related communications including license server
    connections, activation requests, and cloud licensing traffic.
    """

    def __init__(self) -> None:
        """Initialize network capture manager."""
        self.logger: logging.Logger = logging.getLogger(__name__)

    def capture_live_traffic(self, interface: str = "any", filter_str: str = "", count: int = 100) -> dict[str, Any]:
        """Capture live network traffic using Scapy.

        Args:
            interface: Network interface to capture on
            filter_str: BPF filter string
            count: Maximum packets to capture

        Returns:
            Dictionary with capture results and analysis
        """
        return capture_with_scapy(interface, filter_str, count)

    def analyze_pcap_file(self, pcap_file: str) -> dict[str, Any]:
        """Analyze PCAP file using PyShark for deep packet inspection.

        Args:
            pcap_file: Path to PCAP file

        Returns:
            Dictionary with comprehensive packet analysis
        """
        return analyze_pcap_with_pyshark(pcap_file)

    def parse_pcap_binary(self, pcap_file: str) -> dict[str, Any]:
        """Parse PCAP file using dpkt for low-level binary analysis.

        Args:
            pcap_file: Path to PCAP file

        Returns:
            Dictionary with low-level packet statistics
        """
        return parse_pcap_with_dpkt(pcap_file)

    def identify_license_servers(self, pcap_file: str) -> list[dict[str, Any]]:
        """Identify license servers from packet capture.

        Args:
            pcap_file: Path to PCAP file

        Returns:
            List of identified license servers with details
        """
        analysis: dict[str, Any] = analyze_pcap_with_pyshark(pcap_file)
        result: Any = analysis.get("license_traffic", [])
        return list(result) if isinstance(result, list) else []

    def extract_dns_queries(self, pcap_file: str) -> list[str]:
        """Extract DNS queries from packet capture.

        Args:
            pcap_file: Path to PCAP file

        Returns:
            List of unique DNS query names
        """
        analysis: dict[str, Any] = analyze_pcap_with_pyshark(pcap_file)
        result: Any = analysis.get("dns_queries", [])
        return [str(item) for item in result] if isinstance(result, list) else []

    def detect_cloud_licensing_traffic(self, interface: str = "any", duration: int = 60) -> dict[str, Any]:
        """Detect cloud licensing traffic in real-time.

        Args:
            interface: Network interface to monitor
            duration: Monitoring duration in seconds

        Returns:
            Dictionary with detected cloud licensing communications
        """
        result: dict[str, Any] = capture_with_scapy(interface, "", duration)
        license_servers_raw: Any = result.get("license_servers", [])
        dns_queries_raw: Any = result.get("dns_queries", [])
        license_servers_list: list[Any] = list(license_servers_raw) if isinstance(license_servers_raw, list) else []
        dns_queries_result: list[str] = [str(q) for q in dns_queries_raw] if isinstance(dns_queries_raw, list) else []

        return {
            "license_servers_detected": len(license_servers_list),
            "license_servers": license_servers_list,
            "license_related_domains": [
                q
                for q in dns_queries_result
                if any(keyword in q.lower() for keyword in ["license", "activation", "flexlm", "rlm", "hasp", "sentinel"])
            ],
            "total_packets": result.get("total_packets", 0),
            "license_packets": result.get("license_packets", 0),
        }


def parse_pcap_with_dpkt(pcap_file: str) -> dict[str, Any]:
    """Parse PCAP file using dpkt for low-level binary analysis.

    Provides low-level binary packet parsing with detailed connection tracking,
    protocol statistics, port scanning detection, data exfiltration analysis,
    and DNS query extraction using the dpkt library.

    Args:
        pcap_file: Path to PCAP file to parse.

    Returns:
        Dictionary with low-level packet statistics including total packet and
        byte counts, start/end timestamps, IPv4/TCP/UDP/ICMP packet counts,
        unique connection count, port scanning indicators, data exfiltration
        suspects, capture duration, packet and byte rates, and total port scan
        attempt count.
    """
    try:
        import dpkt
    except ImportError:
        return {"error": "dpkt not available", "suggestion": "Install with: pip install dpkt"}

    try:
        logger.info("[dpkt] Parsing PCAP file: %s", pcap_file)

        total_packets: int = 0
        total_bytes: int = 0
        start_time: float | None = None
        end_time: float | None = None
        ip_packets: int = 0
        tcp_packets: int = 0
        udp_packets: int = 0
        icmp_packets: int = 0
        unique_connections: set[tuple[str, int, str, int, str]] = set()
        port_scan_indicators: list[dict[str, Any]] = []
        data_exfiltration_suspects: list[dict[str, Any]] = []

        with open(pcap_file, "rb") as f:
            pcap: Any = dpkt.pcap.Reader(f)

            connection_data: dict[str, dict[str, Any]] = {}

            for timestamp, buf in pcap:
                total_packets += 1
                total_bytes += len(buf)

                if start_time is None:
                    start_time = float(timestamp)
                end_time = float(timestamp)

                try:
                    eth: Any = dpkt.ethernet.Ethernet(buf)

                    # Check for IP packet
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip: Any = eth.data
                        ip_packets += 1

                        # Track unique connections
                        src_ip: str = socket.inet_ntoa(ip.src)
                        dst_ip: str = socket.inet_ntoa(ip.dst)

                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp: Any = ip.data
                            tcp_packets += 1

                            conn_tuple: tuple[str, int, str, int, str] = (
                                src_ip,
                                int(tcp.sport),
                                dst_ip,
                                int(tcp.dport),
                                "TCP",
                            )
                            unique_connections.add(conn_tuple)

                            # Track connection data volume
                            conn_key: str = f"{src_ip}:{tcp.sport}->{dst_ip}:{tcp.dport}"
                            if conn_key not in connection_data:
                                connection_data[conn_key] = {
                                    "bytes": 0,
                                    "packets": 0,
                                    "start_time": timestamp,
                                }
                            connection_data[conn_key]["bytes"] += len(tcp.data)
                            connection_data[conn_key]["packets"] += 1
                            connection_data[conn_key]["end_time"] = timestamp

                            # Check for port scanning (SYN without data)
                            if tcp.flags & dpkt.tcp.TH_SYN and not tcp.data:
                                port_scan_indicators.append(
                                    {
                                        "src": src_ip,
                                        "dst": dst_ip,
                                        "port": int(tcp.dport),
                                        "timestamp": timestamp,
                                    },
                                )

                        elif isinstance(ip.data, dpkt.udp.UDP):
                            udp: Any = ip.data
                            udp_packets += 1

                            conn_tuple_udp: tuple[str, int, str, int, str] = (
                                src_ip,
                                int(udp.sport),
                                dst_ip,
                                int(udp.dport),
                                "UDP",
                            )
                            unique_connections.add(conn_tuple_udp)

                            # Check for DNS (port 53)
                            if udp.dport == 53 or udp.sport == 53:
                                try:
                                    dns: Any = dpkt.dns.DNS(udp.data)
                                    # Log DNS queries for analysis
                                    if dns.qd:  # If there are questions (queries)
                                        for question in dns.qd:
                                            queried_domain: str = str(question.name)
                                            if queried_domain and len(queried_domain) > 1:
                                                logger.debug("DNS query detected: %s", queried_domain)
                                except (
                                    dpkt.dpkt.NeedData,
                                    dpkt.dpkt.UnpackError,
                                    AttributeError,
                                ) as e:
                                    logger.debug("Failed to parse DNS packet: %s", e)

                        elif isinstance(ip.data, dpkt.icmp.ICMP):
                            icmp_packets += 1

                except Exception as e:
                    # Skip malformed packets
                    logger.debug("Skipping malformed packet: %s", e)
                    continue

        duration_seconds: float = 0.0
        packets_per_second: float = 0.0
        bytes_per_second: float = 0.0
        if start_time is not None and end_time is not None:
            duration_seconds = end_time - start_time
            packets_per_second = total_packets / max(duration_seconds, 1.0)
            bytes_per_second = total_bytes / max(duration_seconds, 1.0)

        for conn, data in connection_data.items():
            conn_bytes: int = int(data["bytes"])
            if conn_bytes > 10 * 1024 * 1024:
                conn_start: float = float(data["start_time"])
                conn_end: float = float(data.get("end_time", conn_start))
                conn_duration: float = conn_end - conn_start
                data_exfiltration_suspects.append(
                    {
                        "connection": conn,
                        "bytes": conn_bytes,
                        "duration": conn_duration,
                        "rate_mbps": (conn_bytes * 8 / 1024 / 1024) / max(conn_duration, 1.0),
                    },
                )

        unique_connections_count: int = len(unique_connections)
        total_port_scans: int = len(port_scan_indicators)

        if len(port_scan_indicators) > 100:
            port_scan_indicators = port_scan_indicators[:100]

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "start_time": start_time,
            "end_time": end_time,
            "ip_packets": ip_packets,
            "tcp_packets": tcp_packets,
            "udp_packets": udp_packets,
            "icmp_packets": icmp_packets,
            "unique_connections": unique_connections_count,
            "port_scan_indicators": port_scan_indicators,
            "data_exfiltration_suspects": data_exfiltration_suspects,
            "duration_seconds": duration_seconds,
            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second,
            "total_port_scans": total_port_scans,
        }

    except Exception as e:
        logger.exception("dpkt parsing error: %s", e)
        return {"error": str(e), "success": False}


__all__ = [
    "NetworkCapture",
    "capture_with_scapy",
    "analyze_pcap_with_pyshark",
    "parse_pcap_with_dpkt",
]
