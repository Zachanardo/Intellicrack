"""
Base Network Analyzer Module

Provides common functionality for network analysis components.
"""

import logging
from typing import Any, Callable


class BaseNetworkAnalyzer:
    """
    Base class for network analysis components.
    Provides common packet handling functionality.
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def create_packet_handler(self, scapy_module: Any,
                            is_running_check: Callable[[], bool],
                            process_packet_func: Callable[[Any, Any, Any], None]) -> Callable:
        """
        Create a packet handler function with common functionality.
        
        Args:
            scapy_module: The scapy module instance
            is_running_check: Function to check if capture should continue
            process_packet_func: Function to process valid packets
            
        Returns:
            Packet handler function
        """
        def packet_handler(packet):
            """Process each captured packet."""
            if not is_running_check():
                return

            try:
                # Check if it's a TCP packet with IP layer
                from ...utils.network_api_common import get_scapy_layers

                layers = get_scapy_layers(scapy_module)
                if not layers:
                    # Skip this packet if we can't access IP/TCP
                    return

                IP, TCP = layers

                # Process packet with the provided function
                process_packet_func(packet, IP, TCP)

            except Exception as e:
                self.logger.debug(f"Packet processing error: {e}")

        return packet_handler
