"""Network package for Intellicrack.

This package contains networking components for communication protocols,
C2 infrastructure, and network-based analysis capabilities.
"""

from typing import TYPE_CHECKING, Any

from intellicrack.utils.logger import logger


if TYPE_CHECKING:
    from intellicrack.plugins.custom_modules.license_server_emulator import LicenseServerEmulator as NetworkLicenseServerEmulator

    from .cloud_license_hooker import CloudLicenseResponseGenerator
    from .protocol_fingerprinter import ProtocolFingerprinter as ProtocolFingerprinterType
    from .ssl_interceptor import SSLTLSInterceptor
    from .traffic_analyzer import NetworkTrafficAnalyzer

logger.debug("Network core module loaded")

TrafficAnalyzer: type[Any] | None
SSLInterceptor: type[Any] | None
ProtocolFingerprinter: type[Any] | None
LicenseServerEmulator: type[Any] | None
CloudLicenseHooker: type[Any] | None

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
    "TrafficAnalyzer",
]
