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
    import pcap as pypcap_module
    PCAP_AVAILABLE = True
except ImportError:
    PCAP_AVAILABLE = False
    pypcap_module = None

def get_packet_capture_interface():
    """
    Get a packet capture interface, preferring pypcap over pcapy.

    Returns:
        object: Packet capture interface or None if unavailable
    """
    if PCAP_AVAILABLE:
        return pypcap_module
    return None

def create_pcap_reader(interface="any"):
    """
    Create a packet capture reader compatible with pcapy interface.

    Args:
        interface (str): Network interface to capture from

    Returns:
        object: Packet capture reader or None if unavailable
    """
    if not PCAP_AVAILABLE:
        return None

    try:
        # pypcap interface is slightly different from pcapy
        pc = pypcap_module.pcap(name=interface, promisc=True, immediate=True)
        return pc
    except (OSError, ValueError, RuntimeError) as e:
        print(f"Warning: Failed to create packet capture reader: {e}")
        return None

# Compatibility aliases for existing pcapy code
pcapy = get_packet_capture_interface()

__all__ = ['get_packet_capture_interface', 'create_pcap_reader', 'pcapy', 'PCAP_AVAILABLE']
