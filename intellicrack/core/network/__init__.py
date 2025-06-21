"""
Network analysis and protocol handling for Intellicrack.

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
    from .traffic_analyzer import NetworkTrafficAnalyzer as TrafficAnalyzer
except ImportError:
    TrafficAnalyzer = None

try:
    from .ssl_interceptor import SSLTLSInterceptor as SSLInterceptor
except ImportError:
    SSLInterceptor = None

try:
    from .protocol_fingerprinter import ProtocolFingerprinter
except ImportError:
    ProtocolFingerprinter = None

try:
    from .license_server_emulator import NetworkLicenseServerEmulator as LicenseServerEmulator
except ImportError:
    LicenseServerEmulator = None

try:
    from .cloud_license_hooker import CloudLicenseResponseGenerator as CloudLicenseHooker
except ImportError:
    CloudLicenseHooker = None

__all__ = [
    'TrafficAnalyzer',
    'SSLInterceptor',
    'ProtocolFingerprinter',
    'LicenseServerEmulator',
    'CloudLicenseHooker'
]
