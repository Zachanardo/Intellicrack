"""
Network analysis and protocol handling for Intellicrack.

This package provides network-related analysis capabilities:
- Network traffic capture and analysis
- Protocol fingerprinting and identification
- SSL/TLS interception and analysis
- License server emulation
- Cloud license verification interception

Modules:
    traffic_analyzer: Network traffic capture and analysis
    ssl_interceptor: SSL/TLS interception and analysis
    protocol_fingerprinter: Protocol identification and fingerprinting
    license_server_emulator: License server emulation
    cloud_license_hooker: Cloud license verification interception
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
