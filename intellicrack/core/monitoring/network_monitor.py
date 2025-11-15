"""Network Monitor for packet-level traffic analysis.

Optional deep packet inspection using scapy.
Complements API Monitor's socket hooks with packet-level analysis.

NOTE: Network API hooks (connect, send, recv) are handled by APIMonitor.
This monitor provides OPTIONAL packet-level inspection for deep analysis.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import threading
import time

from intellicrack.core.monitoring.base_monitor import (
    BaseMonitor,
    EventSeverity,
    EventSource,
    EventType,
    MonitorEvent,
    ProcessInfo,
)

try:
    from scapy.all import IP, TCP, UDP, Raw, sniff

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkMonitor(BaseMonitor):
    """Optional packet-level network traffic analysis.

    Provides deep packet inspection to complement APIMonitor's socket hooks.
    Requires scapy and may need admin privileges.

    NOTE: Basic network monitoring (connect, send, recv) is handled by APIMonitor.
    This monitor is OPTIONAL for advanced packet analysis.
    """

    def __init__(self, process_info: ProcessInfo | None = None, target_ports: list | None = None) -> None:
        """Initialize network monitor.

        Args:
            process_info: Process information.
            target_ports: Specific ports to monitor (None for all).

        """
        super().__init__("NetworkMonitor", process_info)
        self.target_ports = target_ports or [80, 443, 8080, 8443]
        self._sniff_thread: threading.Thread | None = None
        self._stop_sniffing = False

        if not SCAPY_AVAILABLE:
            print("[NetworkMonitor] Scapy not available - packet capture disabled")
            print("[NetworkMonitor] Network API monitoring handled by APIMonitor")

    def _start_monitoring(self) -> bool:
        """Start network monitoring.

        Returns:
            True if started successfully.

        """
        if not SCAPY_AVAILABLE:
            print("[NetworkMonitor] Skipping - scapy not available")
            return False

        try:
            self._stop_sniffing = False
            self._sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
            self._sniff_thread.start()
            return True

        except Exception as e:
            return not self._handle_error(e)

    def _stop_monitoring(self) -> None:
        """Stop network monitoring."""
        self._stop_sniffing = True
        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=2.0)

    def _sniff_packets(self) -> None:
        """Packet sniffing loop (runs in thread)."""
        if not SCAPY_AVAILABLE:
            return

        filter_str = f"tcp port {' or '.join(map(str, self.target_ports))}"

        try:
            sniff(filter=filter_str, prn=self._process_packet, store=False, stop_filter=lambda _: self._stop_sniffing)
        except Exception as e:
            self._handle_error(e)

    def _process_packet(self, packet) -> None:
        """Process captured packet.

        Args:
            packet: Scapy packet object.

        """
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport

            if packet.haslayer(Raw):
                payload = packet[Raw].load

                if any(keyword in payload.lower() for keyword in [b"license", b"serial", b"activation", b"key"]):
                    severity = EventSeverity.CRITICAL
                else:
                    severity = EventSeverity.INFO

                event = MonitorEvent(
                    timestamp=time.time(),
                    source=EventSource.NETWORK,
                    event_type=EventType.SEND if src_port > 1024 else EventType.RECEIVE,
                    severity=severity,
                    details={
                        "protocol": "TCP",
                        "src": f"{src_ip}:{src_port}",
                        "dst": f"{dst_ip}:{dst_port}",
                        "payload_size": len(payload),
                        "contains_license_keywords": severity == EventSeverity.CRITICAL,
                    },
                    process_info=self.process_info,
                )

                self._emit_event(event)

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport

            if packet.haslayer(Raw):
                payload = packet[Raw].load

                event = MonitorEvent(
                    timestamp=time.time(),
                    source=EventSource.NETWORK,
                    event_type=EventType.SEND,
                    severity=EventSeverity.INFO,
                    details={"protocol": "UDP", "src": f"{src_ip}:{src_port}", "dst": f"{dst_ip}:{dst_port}", "payload_size": len(payload)},
                    process_info=self.process_info,
                )

                self._emit_event(event)
