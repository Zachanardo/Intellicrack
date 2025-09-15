"""Command and Control (C2) Infrastructure for Intellicrack.

This module provides advanced C2 capabilities including:
- Multi-protocol communication (HTTP/S, DNS, TCP, custom)
- AES-256 encryption with secure key exchange
- Beacon management and session handling
- Proxy/redirector support for infrastructure isolation
- Resilient communication with failover mechanisms

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

from .beacon_manager import BeaconManager
from .c2_client import C2Client
from .c2_manager import C2Manager
from .c2_server import C2Server
from .communication_protocols import DnsProtocol, HttpsProtocol, TcpProtocol
from .encryption_manager import EncryptionManager
from .session_manager import SessionManager

__all__ = [
    "BeaconManager",
    "C2Client",
    "C2Manager",
    "C2Server",
    "DnsProtocol",
    "EncryptionManager",
    "HttpsProtocol",
    "SessionManager",
    "TcpProtocol",
]
