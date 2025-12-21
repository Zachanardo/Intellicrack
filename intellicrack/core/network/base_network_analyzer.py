"""Base network analyzer for Intellicrack core network functionality.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import logging
from collections.abc import Callable
from types import ModuleType


class BaseNetworkAnalyzer:
    """Base class for network analysis components.

    Provides common packet handling functionality.
    """

    def __init__(self) -> None:
        """Initialize the base network analyzer with logging."""
        self.logger = logging.getLogger(self.__class__.__name__)

    def create_packet_handler(
        self,
        scapy_module: ModuleType,
        is_running_check: Callable[[], bool],
        process_packet_func: Callable[[object, object, object], None],
    ) -> Callable[[object], None]:
        """Create a packet handler function with common functionality.

        Args:
            scapy_module: The scapy module instance for layer access.
            is_running_check: Function to check if capture should continue.
            process_packet_func: Function to process valid packets with IP/TCP layers.

        Returns:
            Callable that handles individual network packets and processes them
            if the capture is still running.

        """

        def packet_handler(packet: object) -> None:
            """Process each captured packet."""
            if not is_running_check():
                return

            try:
                # Check if it's a TCP packet with IP layer
                from ...utils.binary.network_api_analysis import get_scapy_layers

                layers = get_scapy_layers(scapy_module)
                if not layers:
                    # Skip this packet if we can't access IP/TCP
                    return

                IP, TCP = layers

                # Process packet with the provided function
                process_packet_func(packet, IP, TCP)

            except Exception as e:
                self.logger.debug("Packet processing error: %s", e)

        return packet_handler
