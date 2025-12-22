"""Pcapy compatibility layer for packet capture functionality."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from types import ModuleType
from typing import Any

from intellicrack.utils.logger import logger

"""
Compatibility module for pcapy functionality.

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


scapy_module: ModuleType | None
try:
    import scapy.all as scapy_module

    SCAPY_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in pcapy_compat: %s", e)
    SCAPY_AVAILABLE = False
    scapy_module = None


class ScapyPacketReader:
    """Scapy-based packet capture reader that provides pcapy-compatible interface."""

    def __init__(
        self,
        interface: str = "any",
        promisc: bool = True,
        immediate: bool = True,
        timeout_ms: int = 100,
    ) -> None:
        """Initialize Scapy packet reader.

        Args:
            interface (str): Network interface to capture from
            promisc (bool): Enable promiscuous mode
            immediate (bool): Enable immediate mode (ignored, for compatibility)
            timeout_ms (int): Timeout in milliseconds

        """
        self.interface: str | None = None if interface == "any" else interface
        self.promisc: bool = promisc
        self.timeout: float = timeout_ms / 1000.0
        self.filter: str | None = None
        self._running: bool = False

    def setfilter(self, filter_str: str) -> None:
        """Set BPF filter for packet capture.

        Args:
            filter_str (str): BPF filter expression

        """
        self.filter = filter_str

    def loop(self, count: int, callback: Callable[[float, bytes], None]) -> None:
        """Start packet capture loop.

        Args:
            count (int): Number of packets to capture (0 = infinite)
            callback (callable): Function to call for each packet

        """
        if not SCAPY_AVAILABLE or scapy_module is None:
            raise RuntimeError("Scapy not available for packet capture")

        self._running = True

        def packet_handler(packet: Any) -> None:
            if not self._running:
                return
            timestamp: float = float(packet.time) if hasattr(packet, "time") else 0.0
            raw_packet: bytes = bytes(packet)
            callback(timestamp, raw_packet)

        try:
            scapy_module.sniff(
                iface=self.interface,
                filter=self.filter,
                prn=packet_handler,
                count=count,
                timeout=self.timeout if count == 0 else None,
                stop_filter=lambda x: not self._running,
            )
        except Exception as e:
            logger.error("Exception in pcapy_compat: %s", e)
            raise RuntimeError(f"Packet capture failed: {e}")

    def __iter__(self) -> Iterator[tuple[float, bytes]]:
        """Iterator interface for packet capture."""
        if not SCAPY_AVAILABLE or scapy_module is None:
            raise RuntimeError("Scapy not available for packet capture")

        self._running = True

        try:
            for packet in scapy_module.sniff(
                iface=self.interface,
                filter=self.filter,
                stop_filter=lambda x: not self._running,
                timeout=1,
            ):
                if not self._running:
                    break
                timestamp: float = float(packet.time) if hasattr(packet, "time") else 0.0
                raw_packet: bytes = bytes(packet)
                yield timestamp, raw_packet
        except Exception as e:
            logger.error("Exception in pcapy_compat: %s", e)
            raise RuntimeError(f"Packet capture failed: {e}") from e

    def stop(self) -> None:
        """Stop packet capture."""
        self._running = False


def get_packet_capture_interface() -> ModuleType | None:
    """Get a packet capture interface using Scapy.

    Returns:
        module: Scapy module or None if unavailable

    """
    return scapy_module if SCAPY_AVAILABLE else None


def create_pcap_reader(interface: str = "any") -> ScapyPacketReader | None:
    """Create a packet capture reader using Scapy with pcapy-compatible interface.

    Args:
        interface (str): Network interface to capture from

    Returns:
        ScapyPacketReader: Packet capture reader or None if unavailable

    """
    if not SCAPY_AVAILABLE:
        return None

    try:
        return ScapyPacketReader(interface=interface, promisc=True, immediate=True)
    except Exception as e:
        logger.error("Exception in pcapy_compat: %s", e)
        print(f"Warning: Failed to create packet capture reader: {e}")
        return None


pcapy: ModuleType | None = get_packet_capture_interface()
PCAP_AVAILABLE: bool = SCAPY_AVAILABLE

__all__ = [
    "PCAP_AVAILABLE",
    "SCAPY_AVAILABLE",
    "ScapyPacketReader",
    "create_pcap_reader",
    "get_packet_capture_interface",
    "pcapy",
]
