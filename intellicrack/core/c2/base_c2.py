"""This file is part of Intellicrack.
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
import time
from typing import Any

from intellicrack.utils.service_utils import get_service_url

"""
Base C2 Module

Provides common functionality for C2 client and server components.
"""


class BaseC2:
    """Base class for C2 components.
    Provides common protocol initialization functionality.
    """

    def __init__(self):
        """Initialize the base C2 framework with logging and protocol management."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.protocols = []
        self.running = False
        self.stats = {"start_time": None}

    def initialize_protocols(self, protocols_config: list[dict[str, Any]], encryption_manager: Any) -> None:
        """Initialize communication protocols with error handling.

        Args:
            protocols_config: List of protocol configurations
            encryption_manager: Encryption manager instance

        """
        try:
            for proto_config in protocols_config:
                protocol_type = proto_config["type"]

                if protocol_type == "https":
                    from .communication_protocols import HttpsProtocol

                    server_url = proto_config.get("server_url")
                    if not server_url:
                        server_url = get_service_url("c2_server")

                    protocol = HttpsProtocol(
                        encryption_manager,
                        server_url,
                        proto_config.get("headers", {}),
                    )
                elif protocol_type == "dns":
                    from .communication_protocols import DnsProtocol

                    domain = proto_config.get("domain")
                    if not domain:
                        c2_url = get_service_url("c2_server")
                        domain = c2_url.replace("http://", "").replace("https://", "").split(":")[0]

                    protocol = DnsProtocol(
                        encryption_manager,
                        domain,
                        proto_config.get("dns_server", "8.8.8.8"),
                    )
                elif protocol_type == "tcp":
                    from .communication_protocols import TcpProtocol

                    c2_url = get_service_url("c2_server")
                    host = c2_url.replace("http://", "").replace("https://", "").split(":")[0]
                    port = int(c2_url.split(":")[-1].replace("/", "")) if ":" in c2_url else 9999

                    protocol = TcpProtocol(
                        encryption_manager,
                        proto_config.get("host", host),
                        proto_config.get("port", port),
                    )
                else:
                    self.logger.warning(f"Unknown protocol type: {protocol_type}")
                    continue

                self.protocols.append(
                    {
                        "type": protocol_type,
                        "handler": protocol,
                        "priority": proto_config.get("priority", 99),
                    }
                )

            # Sort by priority
            self.protocols.sort(key=lambda x: x["priority"])

            self.logger.info(f"Initialized {len(self.protocols)} communication protocols")

        except Exception as e:
            self.logger.error(f"Failed to initialize protocols: {e}")
            raise

    def prepare_start(self, component_name: str) -> bool:
        """Common start preparation for C2 components.

        Args:
            component_name: Name of the component (e.g., "C2 client", "C2 server")

        Returns:
            True if start should proceed, False if already running

        """
        if self.running:
            self.logger.warning(f"{component_name} already running")
            return False

        self.logger.info(f"Starting {component_name}...")
        self.running = True
        self.stats["start_time"] = time.time()
        return True
