"""
Compatibility module for pcapy functionality.

Since pcapy is incompatible with Python 3.11+, this module provides
a compatibility layer using pypcap as a replacement.
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
    except Exception as e:
        print(f"Warning: Failed to create packet capture reader: {e}")
        return None

# Compatibility aliases for existing pcapy code
pcapy = get_packet_capture_interface()

__all__ = ['get_packet_capture_interface', 'create_pcap_reader', 'pcapy', 'PCAP_AVAILABLE']