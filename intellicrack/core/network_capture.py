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

logger = logging.getLogger(__name__)


def capture_with_scapy(interface: str = "any", filter_str: str = "", count: int = 100) -> dict[str, Any]:
    """Capture network packets using Scapy for real-time traffic analysis.

    Args:
        interface: Network interface to capture on ('any' for all)
        filter_str: BPF filter string (e.g., 'tcp port 80')
        count: Maximum number of packets to capture

    Returns:
        Dictionary with capture results and statistics

    """
    try:
        from scapy.all import DNS, IP, TCP, UDP, Raw, sniff
    except ImportError:
        return {"error": "Scapy not available", "suggestion": "Install with: pip install scapy"}

    captured_packets = []
    license_servers = set()
    dns_queries = []

    try:

        def packet_handler(packet):
            """Process captured packets in real-time."""
            packet_info = {
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
            if DNS in packet and packet.haslayer(DNS):
                if packet[DNS].qr == 0:  # DNS query
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

                        # Extract potential license data
                        packet_info["license_indicators"] = []
                        for keyword in license_keywords:
                            if keyword in payload.lower():
                                packet_info["license_indicators"].append(keyword.decode())
                except (AttributeError, UnicodeDecodeError, TypeError) as e:
                    logger.debug(f"Failed to extract license indicators from packet: {e}")

            captured_packets.append(packet_info)

        logger.info(f"[Scapy] Starting packet capture on interface: {interface}")

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
        logger.info(f"[Scapy] Packet capture completed. Session info: {packets}")

        # Analyze captured packets
        license_packets = [p for p in captured_packets if p.get("license_related")]
        unique_ips = set()
        port_distribution = {}
        protocol_distribution = {"TCP": 0, "UDP": 0, "Other": 0}

        for p in captured_packets:
            if "dst_ip" in p:
                unique_ips.add(p["dst_ip"])

            # Track port distribution
            if "dst_port" in p:
                port = p["dst_port"]
                port_distribution[port] = port_distribution.get(port, 0) + 1

            # Track protocol distribution
            transport = p.get("transport", "Other")
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
        logger.error(f"Scapy capture error: {e}")
        return {"error": str(e), "success": False}


def analyze_pcap_with_pyshark(pcap_file: str) -> dict[str, Any]:
    """Analyze PCAP file using PyShark for deep packet inspection.

    Args:
        pcap_file: Path to PCAP file to analyze

    Returns:
        Dictionary with analysis results

    """
    try:
        import pyshark
    except ImportError:
        return {"error": "PyShark not available", "suggestion": "Install with: pip install pyshark"}

    try:
        logger.info(f"[PyShark] Analyzing PCAP file: {pcap_file}")

        # Open capture file with display filter
        cap = pyshark.FileCapture(
            pcap_file,
            display_filter="tcp or udp",
            use_json=True,
            include_raw=True,
        )

        packet_summary = {
            "total_packets": 0,
            "protocols": {},
            "conversations": {},
            "dns_queries": [],
            "http_requests": [],
            "tls_handshakes": [],
            "suspicious_ports": [],
            "license_traffic": [],
        }

        suspicious_ports = [1337, 31337, 4444, 5555, 8080, 8888, 9999]
        license_ports = [1947, 27000, 27001, 5053, 5054, 6200, 7070]  # Common license server ports

        for packet in cap:
            packet_summary["total_packets"] += 1

            # Track protocols
            if hasattr(packet, "highest_layer"):
                proto = packet.highest_layer
                packet_summary["protocols"][proto] = packet_summary["protocols"].get(proto, 0) + 1

            # Track conversations
            if hasattr(packet, "ip"):
                src = getattr(packet.ip, "src", "unknown")
                dst = getattr(packet.ip, "dst", "unknown")
                conv_key = f"{src} -> {dst}"
                packet_summary["conversations"][conv_key] = packet_summary["conversations"].get(conv_key, 0) + 1

                # Check for license server communication
                if hasattr(packet, "tcp"):
                    port = int(getattr(packet.tcp, "dstport", 0))
                    if port in license_ports:
                        packet_summary["license_traffic"].append(
                            {
                                "src": src,
                                "dst": dst,
                                "port": port,
                                "timestamp": getattr(packet, "sniff_timestamp", "unknown"),
                            }
                        )

            # Extract DNS queries
            if hasattr(packet, "dns") and hasattr(packet.dns, "qry_name"):
                dns_name = str(packet.dns.qry_name)
                packet_summary["dns_queries"].append(dns_name)

                # Check for license-related domains
                license_domains = [
                    "flexera",
                    "flexlm",
                    "rlm",
                    "reprise",
                    "sentinel",
                    "hasp",
                    "wibu",
                ]
                if any(domain in dns_name.lower() for domain in license_domains):
                    packet_summary["license_traffic"].append(
                        {
                            "type": "DNS",
                            "query": dns_name,
                            "timestamp": getattr(packet, "sniff_timestamp", "unknown"),
                        }
                    )

            # Extract HTTP requests
            if hasattr(packet, "http"):
                if hasattr(packet.http, "request_method"):
                    http_info = {
                        "method": str(packet.http.request_method),
                        "uri": str(getattr(packet.http, "request_uri", "unknown")),
                        "host": str(getattr(packet.http, "host", "unknown")),
                        "user_agent": str(getattr(packet.http, "user_agent", "unknown")),
                    }
                    packet_summary["http_requests"].append(http_info)

                    # Check for license-related HTTP traffic
                    if any(keyword in http_info["uri"].lower() for keyword in ["license", "activate", "validate"]):
                        packet_summary["license_traffic"].append(
                            {
                                "type": "HTTP",
                                "details": http_info,
                                "timestamp": getattr(packet, "sniff_timestamp", "unknown"),
                            }
                        )

            # Extract TLS handshakes
            if hasattr(packet, "tls") and hasattr(packet.tls, "handshake"):
                if hasattr(packet.tls, "handshake_extensions_server_name"):
                    server_name = str(packet.tls.handshake_extensions_server_name)
                    packet_summary["tls_handshakes"].append(server_name)

            # Check for suspicious ports
            if hasattr(packet, "tcp"):
                dstport = int(getattr(packet.tcp, "dstport", 0))
                if dstport in suspicious_ports:
                    packet_summary["suspicious_ports"].append(
                        {
                            "port": dstport,
                            "src": getattr(packet.ip, "src", "unknown") if hasattr(packet, "ip") else "unknown",
                            "dst": getattr(packet.ip, "dst", "unknown") if hasattr(packet, "ip") else "unknown",
                            "flags": str(getattr(packet.tcp, "flags", "unknown")),
                        }
                    )

        cap.close()

        # Post-process results
        packet_summary["unique_dns_queries"] = len(set(packet_summary["dns_queries"]))
        packet_summary["unique_conversations"] = len(packet_summary["conversations"])
        packet_summary["top_talkers"] = sorted(
            packet_summary["conversations"].items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        return packet_summary

    except Exception as e:
        logger.error(f"PyShark analysis error: {e}")
        return {"error": str(e), "success": False}


def parse_pcap_with_dpkt(pcap_file: str) -> dict[str, Any]:
    """Parse PCAP file using dpkt for low-level binary analysis.

    Args:
        pcap_file: Path to PCAP file to parse

    Returns:
        Dictionary with parsing results and statistics

    """
    try:
        import dpkt
    except ImportError:
        return {"error": "dpkt not available", "suggestion": "Install with: pip install dpkt"}

    try:
        logger.info(f"[dpkt] Parsing PCAP file: {pcap_file}")

        packet_stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "start_time": None,
            "end_time": None,
            "ip_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "unique_connections": set(),
            "port_scan_indicators": [],
            "data_exfiltration_suspects": [],
        }

        with open(pcap_file, "rb") as f:
            pcap = dpkt.pcap.Reader(f)

            connection_data = {}  # Track data per connection

            for timestamp, buf in pcap:
                packet_stats["total_packets"] += 1
                packet_stats["total_bytes"] += len(buf)

                if packet_stats["start_time"] is None:
                    packet_stats["start_time"] = timestamp
                packet_stats["end_time"] = timestamp

                try:
                    eth = dpkt.ethernet.Ethernet(buf)

                    # Check for IP packet
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        packet_stats["ip_packets"] += 1

                        # Track unique connections
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)

                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp = ip.data
                            packet_stats["tcp_packets"] += 1

                            conn_tuple = (src_ip, tcp.sport, dst_ip, tcp.dport, "TCP")
                            packet_stats["unique_connections"].add(conn_tuple)

                            # Track connection data volume
                            conn_key = f"{src_ip}:{tcp.sport}->{dst_ip}:{tcp.dport}"
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
                                packet_stats["port_scan_indicators"].append(
                                    {
                                        "src": src_ip,
                                        "dst": dst_ip,
                                        "port": tcp.dport,
                                        "timestamp": timestamp,
                                    }
                                )

                        elif isinstance(ip.data, dpkt.udp.UDP):
                            udp = ip.data
                            packet_stats["udp_packets"] += 1

                            conn_tuple = (src_ip, udp.sport, dst_ip, udp.dport, "UDP")
                            packet_stats["unique_connections"].add(conn_tuple)

                            # Check for DNS (port 53)
                            if udp.dport == 53 or udp.sport == 53:
                                try:
                                    dns = dpkt.dns.DNS(udp.data)
                                    # Log DNS queries for analysis
                                    if dns.qd:  # If there are questions (queries)
                                        for question in dns.qd:
                                            queried_domain = question.name
                                            if queried_domain and len(queried_domain) > 1:
                                                logger.debug(f"DNS query detected: {queried_domain}")
                                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, AttributeError) as e:
                                    logger.debug(f"Failed to parse DNS packet: {e}")

                        elif isinstance(ip.data, dpkt.icmp.ICMP):
                            packet_stats["icmp_packets"] += 1

                except Exception as e:
                    # Skip malformed packets
                    logger.debug(f"Skipping malformed packet: {e}")
                    continue

        # Calculate statistics
        if packet_stats["start_time"] and packet_stats["end_time"]:
            duration = packet_stats["end_time"] - packet_stats["start_time"]
            packet_stats["duration_seconds"] = duration
            packet_stats["packets_per_second"] = packet_stats["total_packets"] / max(duration, 1)
            packet_stats["bytes_per_second"] = packet_stats["total_bytes"] / max(duration, 1)

        # Identify potential data exfiltration
        for conn, data in connection_data.items():
            if data["bytes"] > 10 * 1024 * 1024:  # More than 10MB
                duration = data.get("end_time", data["start_time"]) - data["start_time"]
                packet_stats["data_exfiltration_suspects"].append(
                    {
                        "connection": conn,
                        "bytes": data["bytes"],
                        "duration": duration,
                        "rate_mbps": (data["bytes"] * 8 / 1024 / 1024) / max(duration, 1),
                    }
                )

        # Convert set to count for JSON serialization
        packet_stats["unique_connections"] = len(packet_stats["unique_connections"])
        packet_stats["total_port_scans"] = len(packet_stats["port_scan_indicators"])

        # Limit large lists
        if len(packet_stats["port_scan_indicators"]) > 100:
            packet_stats["port_scan_indicators"] = packet_stats["port_scan_indicators"][:100]

        return packet_stats

    except Exception as e:
        logger.error(f"dpkt parsing error: {e}")
        return {"error": str(e), "success": False}
