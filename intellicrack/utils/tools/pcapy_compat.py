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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    scapy = None


class ScapyPacketReader:
    """
    Scapy-based packet capture reader that provides pcapy-compatible interface.
    """
    
    def __init__(self, interface="any", promisc=True, immediate=True, timeout_ms=100):
        """
        Initialize Scapy packet reader.
        
        Args:
            interface (str): Network interface to capture from
            promisc (bool): Enable promiscuous mode
            immediate (bool): Enable immediate mode (ignored, for compatibility)
            timeout_ms (int): Timeout in milliseconds
        """
        self.interface = None if interface == "any" else interface
        self.promisc = promisc
        self.timeout = timeout_ms / 1000.0  # Convert to seconds
        self.filter = None
        self._running = False
    
    def setfilter(self, filter_str):
        """
        Set BPF filter for packet capture.
        
        Args:
            filter_str (str): BPF filter expression
        """
        self.filter = filter_str
    
    def loop(self, count, callback):
        """
        Start packet capture loop.
        
        Args:
            count (int): Number of packets to capture (0 = infinite)
            callback (callable): Function to call for each packet
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available for packet capture")
        
        self._running = True
        
        def packet_handler(packet):
            if not self._running:
                return
            # Convert scapy packet to raw bytes for compatibility
            timestamp = packet.time if hasattr(packet, 'time') else 0
            raw_packet = bytes(packet)
            callback(timestamp, raw_packet)
        
        try:
            scapy.sniff(
                iface=self.interface,
                filter=self.filter,
                prn=packet_handler,
                count=count,
                timeout=self.timeout if count == 0 else None,
                stop_filter=lambda x: not self._running
            )
        except Exception as e:
            raise RuntimeError(f"Packet capture failed: {e}")
    
    def __iter__(self):
        """
        Iterator interface for packet capture.
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available for packet capture")
        
        self._running = True
        
        try:
            for packet in scapy.sniff(
                iface=self.interface,
                filter=self.filter,
                stop_filter=lambda x: not self._running,
                timeout=1  # Short timeout for responsiveness
            ):
                if not self._running:
                    break
                timestamp = packet.time if hasattr(packet, 'time') else 0
                raw_packet = bytes(packet)
                yield timestamp, raw_packet
        except Exception as e:
            raise RuntimeError(f"Packet capture failed: {e}")
    
    def stop(self):
        """
        Stop packet capture.
        """
        self._running = False


def get_packet_capture_interface():
    """
    Get a packet capture interface using Scapy.

    Returns:
        module: Scapy module or None if unavailable
    """
    if SCAPY_AVAILABLE:
        return scapy
    return None

def create_pcap_reader(interface="any"):
    """
    Create a packet capture reader using Scapy with pcapy-compatible interface.

    Args:
        interface (str): Network interface to capture from

    Returns:
        ScapyPacketReader: Packet capture reader or None if unavailable
    """
    if not SCAPY_AVAILABLE:
        return None

    try:
        reader = ScapyPacketReader(interface=interface, promisc=True, immediate=True)
        return reader
    except Exception as e:
        print(f"Warning: Failed to create packet capture reader: {e}")
        return None

# Compatibility aliases for existing pcapy code
pcapy = get_packet_capture_interface()
PCAP_AVAILABLE = SCAPY_AVAILABLE  # For backward compatibility

__all__ = ['get_packet_capture_interface', 'create_pcap_reader', 'pcapy', 'PCAP_AVAILABLE', 'ScapyPacketReader', 'SCAPY_AVAILABLE']
