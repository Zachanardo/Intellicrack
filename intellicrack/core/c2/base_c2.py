"""
Base C2 Module

Provides common functionality for C2 client and server components.
"""

import logging
import time
from typing import Any, Dict, List


class BaseC2:
    """
    Base class for C2 components.
    Provides common protocol initialization functionality.
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.protocols = []
        self.running = False
        self.stats = {'start_time': None}

    def initialize_protocols(self, protocols_config: List[Dict[str, Any]],
                           encryption_manager: Any) -> None:
        """
        Initialize communication protocols with error handling.

        Args:
            protocols_config: List of protocol configurations
            encryption_manager: Encryption manager instance
        """
        try:
            for proto_config in protocols_config:
                protocol_type = proto_config['type']

                if protocol_type == 'https':
                    from .communication_protocols import HttpsProtocol
                    protocol = HttpsProtocol(
                        encryption_manager,
                        proto_config.get('server_url', 'https://localhost:8443'),
                        proto_config.get('headers', {})
                    )
                elif protocol_type == 'dns':
                    from .communication_protocols import DnsProtocol
                    protocol = DnsProtocol(
                        encryption_manager,
                        proto_config.get('domain', 'localhost'),
                        proto_config.get('dns_server', '8.8.8.8')
                    )
                elif protocol_type == 'tcp':
                    from .communication_protocols import TcpProtocol
                    protocol = TcpProtocol(
                        encryption_manager,
                        proto_config.get('host', 'localhost'),
                        proto_config.get('port', 9999)
                    )
                else:
                    self.logger.warning(f"Unknown protocol type: {protocol_type}")
                    continue

                self.protocols.append({
                    'type': protocol_type,
                    'handler': protocol,
                    'priority': proto_config.get('priority', 99)
                })

            # Sort by priority
            self.protocols.sort(key=lambda x: x['priority'])

            self.logger.info(f"Initialized {len(self.protocols)} communication protocols")

        except Exception as e:
            self.logger.error(f"Failed to initialize protocols: {e}")
            raise

    def prepare_start(self, component_name: str) -> bool:
        """
        Common start preparation for C2 components.

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
        self.stats['start_time'] = time.time()
        return True
