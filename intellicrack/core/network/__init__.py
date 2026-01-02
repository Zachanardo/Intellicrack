"""Network package for Intellicrack.

This package contains networking components for communication protocols,
C2 infrastructure, and network-based analysis capabilities.
"""

from typing import TYPE_CHECKING, Any

from intellicrack.utils.logger import logger

from .cloud_license_hooker import CloudLicenseResponseGenerator
from .protocol_fingerprinter import ProtocolFingerprinter as ProtocolFingerprinterType
from .ssl_interceptor import SSLTLSInterceptor
from .traffic_analyzer import NetworkTrafficAnalyzer


if TYPE_CHECKING:
    from intellicrack.plugins.custom_modules.license_server_emulator import LicenseServerEmulator as NetworkLicenseServerEmulator


logger.debug("Network core module loaded")

TrafficAnalyzer: type[Any] | None = None
"""Network traffic analyzer for capturing and analyzing network communications."""

SSLInterceptor: type[Any] | None = None
"""SSL/TLS interceptor for analyzing and intercepting encrypted network traffic."""

ProtocolFingerprinter: type[Any] | None = None
"""Protocol fingerprinter for identifying network protocol implementations."""

LicenseServerEmulator: type[Any] | None = None
"""License server emulator for generating and validating license server responses."""

CloudLicenseHooker: type[Any] | None = None
"""Cloud license hooker for intercepting and modifying cloud-based license validation."""

try:
    from .traffic_analyzer import NetworkTrafficAnalyzer as TrafficAnalyzer
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    TrafficAnalyzer = None

try:
    from .ssl_interceptor import SSLTLSInterceptor as SSLInterceptor
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    SSLInterceptor = None

try:
    from .protocol_fingerprinter import ProtocolFingerprinter
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    ProtocolFingerprinter = None

try:
    from intellicrack.plugins.custom_modules.license_server_emulator import LicenseServerEmulator as NetworkLicenseServerEmulator

    LicenseServerEmulator = NetworkLicenseServerEmulator
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    LicenseServerEmulator = None

try:
    from .cloud_license_hooker import CloudLicenseResponseGenerator as CloudLicenseHooker
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    CloudLicenseHooker = None

__all__ = [
    "CloudLicenseHooker",
    "LicenseServerEmulator",
    "ProtocolFingerprinter",
    "SSLInterceptor",
    "TrafficAnalyzer", "CloudLicenseResponseGenerator", "ProtocolFingerprinterType", "SSLTLSInterceptor", "NetworkTrafficAnalyzer",
]
