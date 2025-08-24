import logging
import socket
import time

import psutil

from intellicrack.utils.log_message import log_message

logger = logging.getLogger(__name__)

class TrafficAnalyzer:
    @staticmethod
    def _init_traffic_analyzer_config(app):
        """Initialize traffic analyzer configuration."""
        if not hasattr(app, "traffic_analyzer_config"):
            app.traffic_analyzer_config = {
                "capture_interface": "any",
                "capture_filter": "",
                "max_packets": 10000,
                "analysis_modes": ["real_time", "batch"],
                "protocols": ["TCP", "UDP", "HTTP", "HTTPS", "DNS"],
                "visualization_types": ["timeline", "flow_graph", "protocol_distribution"],
                "alert_thresholds": {
                    "suspicious_connections": 5,
                    "data_exfiltration_mb": 100,
                    "unusual_ports": [1337, 31337, 4444, 5555],
                },
            }

        if not hasattr(app, "traffic_capture_state"):
            app.traffic_capture_state = {
                "is_capturing": False,
                "packets_captured": 0,
                "bytes_captured": 0,
                "start_time": None,
                "current_session": None,
                "capture_interface": "auto",
            }

        if not hasattr(app, "traffic_analysis_results"):
            app.traffic_analysis_results = {
                "packet_summary": {},
                "protocol_distribution": {},
                "connection_flows": [],
                "suspicious_activities": [],
                "license_traffic": [],
                "dns_queries": [],
                "http_requests": [],
                "encrypted_connections": [],
            }

    @staticmethod
    def _check_capture_libraries(app):
        """Check availability of packet capture libraries."""
        capture_libraries = {
            "scapy": False,
            "pyshark": False,
            "dpkt": False,
            "socket_raw": False,
        }

        try:
            import scapy.all  # noqa: F401 - Checking availability
            capture_libraries["scapy"] = True
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message("[Traffic] Scapy packet manipulation library available")
                )
        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)

        try:
            import pyshark  # noqa: F401 - Checking availability
            capture_libraries["pyshark"] = True
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message("[Traffic] PyShark packet analysis library available")
                )
        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)

        try:
            import dpkt  # noqa: F401 - Checking availability
            capture_libraries["dpkt"] = True
        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)

        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            test_socket.close()
            capture_libraries["socket_raw"] = True
        except (OSError, PermissionError) as e:
            logger.error("(OSError, PermissionError) in main_app.py: %s", e)

        return capture_libraries

    @staticmethod
    def _assign_capture_functions(app, capture_libraries):
        """Import and assign network capture functions if libraries are available."""
        if not any(capture_libraries.values()):
            return

        try:
            from ..core.network_capture import (
                analyze_pcap_with_pyshark,
                capture_with_scapy,
                parse_pcap_with_dpkt,
            )

            if capture_libraries["scapy"]:
                app.capture_with_scapy = capture_with_scapy
                if hasattr(app, "update_output"):
                    app.update_output.emit(
                        log_message("[Traffic] Scapy capture function loaded")
                    )

            if capture_libraries["pyshark"]:
                app.analyze_pcap_with_pyshark = analyze_pcap_with_pyshark
                if hasattr(app, "update_output"):
                    app.update_output.emit(
                        log_message("[Traffic] PyShark analysis function loaded")
                    )

            if capture_libraries["dpkt"]:
                app.parse_pcap_with_dpkt = parse_pcap_with_dpkt
                if hasattr(app, "update_output"):
                    app.update_output.emit(
                        log_message("[Traffic] dpkt parsing function loaded")
                    )

        except ImportError as e:
            logger.error("Failed to import network capture functions: %s", e)

    @staticmethod
    def _detect_network_interfaces(app):
        """Initialize network interface detection."""
        available_interfaces = []
        try:
            network_interfaces = psutil.net_if_addrs()
            for interface_name, addresses in network_interfaces.items():
                interface_info = {
                    "name": interface_name,
                    "addresses": [],
                    "is_up": False,
                    "is_loopback": interface_name.lower().startswith("lo"),
                }

                for addr in addresses:
                    if addr.family.name in ["AF_INET", "AF_INET6"]:
                        interface_info["addresses"].append(
                            {
                                "family": addr.family.name,
                                "address": addr.address,
                                "netmask": getattr(addr, "netmask", None),
                            }
                        )

                try:
                    stats = psutil.net_if_stats()[interface_name]
                    interface_info["is_up"] = stats.isup
                    interface_info["speed"] = stats.speed
                except (KeyError, AttributeError) as e:
                    logger.error("(KeyError, AttributeError) in main_app.py: %s", e)

                available_interfaces.append(interface_info)

            if hasattr(app, "update_output"):
                active_interfaces = [
                    iface
                    for iface in available_interfaces
                    if iface["is_up"] and not iface["is_loopback"]
                ]
                app.update_output.emit(
                    log_message(
                        f"[Traffic] Found {len(active_interfaces)} active network interfaces"
                    )
                )

        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            available_interfaces = [
                {
                    "name": "eth0",
                    "addresses": [{"family": "AF_INET", "address": "192.168.1.100"}],
                    "is_up": True,
                },
                {
                    "name": "wlan0",
                    "addresses": [{"family": "AF_INET", "address": "192.168.1.101"}],
                    "is_up": True,
                },
                {
                    "name": "lo",
                    "addresses": [{"family": "AF_INET", "address": "127.0.0.1"}],
                    "is_up": True,
                    "is_loopback": True,
                },
            ]

        return available_interfaces

    @staticmethod
    def _setup_traffic_results(app, capture_libraries):
        """Set up traffic analysis results based on library availability."""
        if not any(capture_libraries.values()):
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message("[Traffic] No packet capture libraries available")
                )
                app.update_output.emit(
                    log_message(
                        "[Traffic] Install scapy, pyshark, or run as administrator for raw sockets"
                    )
                )

            app.traffic_analysis_results = {
                "packet_summary": {
                    "total_packets": 0,
                    "total_bytes": 0,
                    "license_packets": 0,
                    "capture_duration": 0,
                },
                "protocol_distribution": {},
                "connection_flows": [],
                "suspicious_activities": [],
                "license_traffic": [],
                "dns_queries": [],
                "http_requests": [],
                "encrypted_connections": [],
            }
        else:
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(
                        "[Traffic] No packet capture libraries available - limited analysis mode"
                    )
                )

    @staticmethod
    def _format_traffic_analyzer_results(app, capture_libraries, available_interfaces):
        """Format and display traffic analyzer results."""
        if not hasattr(app, "analyze_results"):
            app.analyze_results = []

        app.analyze_results.append("\n=== VISUAL NETWORK TRAFFIC ANALYZER ===")
        app.analyze_results.append("Available capture libraries:")
        for library, available in capture_libraries.items():
            status = "✓" if available else "✗"
            app.analyze_results.append(f"- {library.capitalize()}: {status}")

        if available_interfaces:
            active_ifaces = [
                iface
                for iface in available_interfaces
                if iface.get("is_up", False) and not iface.get("is_loopback", False)
            ]
            app.analyze_results.append(
                f"\nNetwork interfaces: {len(available_interfaces)} total, {len(active_ifaces)} active"
            )
            for iface in active_ifaces[:3]:
                app.analyze_results.append(
                    f"- {iface['name']}: {len(iface['addresses'])} addresses"
                )

        TrafficAnalyzer._format_traffic_summary(app)
        TrafficAnalyzer._add_traffic_features(app)

    @staticmethod
    def _format_traffic_summary(app):
        """Format traffic analysis summary."""
        if (
            hasattr(app, "traffic_analysis_results")
            and app.traffic_analysis_results["packet_summary"]
        ):
            summary = app.traffic_analysis_results["packet_summary"]
            app.analyze_results.append("\nTraffic analysis summary:")
            app.analyze_results.append(f"- Total packets: {summary['total_packets']}")
            app.analyze_results.append(f"- Total bytes: {summary['total_bytes']:,}")
            app.analyze_results.append(
                f"- License-related packets: {summary['license_packets']}"
            )
            app.analyze_results.append(
                f"- Capture duration: {summary['capture_duration']} seconds"
            )

            if app.traffic_analysis_results["protocol_distribution"]:
                app.analyze_results.append("\nProtocol distribution:")
                for protocol, count in app.traffic_analysis_results[
                    "protocol_distribution"
                ].items():
                    percentage = (count / summary["total_packets"]) * 100
                    app.analyze_results.append(
                        f"- {protocol}: {count} packets ({percentage:.1f}%)"
                    )

            if app.traffic_analysis_results["suspicious_activities"]:
                app.analyze_results.append(
                    f"\nSuspicious activities: {len(app.traffic_analysis_results['suspicious_activities'])}"
                )
                for activity in app.traffic_analysis_results["suspicious_activities"]:
                    severity_indicator = {"low": "🟡", "medium": "🟠", "high": "🔴"}.get(
                        activity["severity"],
                        "⚪",
                    )
                    app.analyze_results.append(
                        f"- {severity_indicator} {activity['description']} ({activity['severity']})"
                    )

            if app.traffic_analysis_results["license_traffic"]:
                app.analyze_results.append(
                    f"\nLicense server connections: {len(app.traffic_analysis_results['license_traffic'])}"
                )
                for flow in app.traffic_analysis_results["license_traffic"][:3]:
                    domain = flow.get("destination_domain", flow["dst_ip"])
                    app.analyze_results.append(
                        f"- {domain}:{flow['dst_port']} ({flow['packet_count']} packets, {flow['total_bytes']} bytes)"
                    )

    @staticmethod
    def _add_traffic_features(app):
        """Add traffic analyzer features list."""
        app.analyze_results.append("\nTraffic analyzer features:")
        app.analyze_results.append("- Real-time packet capture")
        app.analyze_results.append("- Protocol analysis and visualization")
        app.analyze_results.append("- License traffic detection")
        app.analyze_results.append("- Suspicious activity monitoring")
        app.analyze_results.append("- Connection flow analysis")
        app.analyze_results.append("- DNS query tracking")

    def run_visual_network_traffic_analyzer(self, app, *args, **kwargs):
        """Run visual network traffic analyzer when analyzer not available."""
        _ = args, kwargs
        try:
            from ..core.network.traffic_analyzer import NetworkTrafficAnalyzer

            analyzer = NetworkTrafficAnalyzer()

            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message("[Traffic] Starting network traffic analyzer...")
                )

            interface = kwargs.get("interface", None)
            if analyzer.start_capture(interface):
                time.sleep(5)
                analyzer.stop_capture()

                results = analyzer.analyze_traffic()
                if results:
                    return results

            return {
                "total_packets": 0,
                "total_connections": 0,
                "license_connections": 0,
                "license_servers": [],
                "license_conn_details": [],
            }

        except ImportError as e:
            logger.error("Import error in main_app.py: %s", e)
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(
                        "[Traffic] Network traffic analyzer not available, using fallback..."
                    )
                )

            self._init_traffic_analyzer_config(app)
            capture_libraries = self._check_capture_libraries(app)
            app.capture_libraries = capture_libraries
            self._assign_capture_functions(app, capture_libraries)
            available_interfaces = self._detect_network_interfaces(app)
            app.available_interfaces = available_interfaces
            self._setup_traffic_results(app, capture_libraries)
            self._format_traffic_analyzer_results(app, capture_libraries, available_interfaces)

            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(
                        "[Traffic] Visual network traffic analyzer initialized successfully"
                    )
                )

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("(OSError, ValueError, RuntimeError) in main_app.py: %s", e)
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(f"[Traffic] Error running traffic analyzer: {e}")
                )
