r"""Certificate pinning detection via static analysis for Windows PE binaries.

CAPABILITIES:
- Windows PE binary pinning detection
- Certificate hash extraction (SHA-256, SHA-1, Base64-encoded)
- Windows API detection (WinHTTP, Schannel, CryptoAPI)
- Cross-reference analysis for hash usage
- Confidence scoring for detections
- Bypass strategy recommendations
- PinningReport generation with detailed findings

LIMITATIONS:
- Static analysis only (no runtime detection)
- May miss obfuscated or encrypted hashes
- Cannot detect dynamically generated pins
- Limited effectiveness on native code obfuscation
- No support for proprietary pinning frameworks
- Requires LIEF for binary parsing

USAGE EXAMPLES:
    from intellicrack.core.certificate.pinning_detector import PinningDetector

    detector = PinningDetector()
    report = detector.generate_pinning_report("app.exe")

    if report.has_pinning:
        print(f"Found {len(report.detected_pins)} pinned certificates")
        for pin in report.detected_pins:
            print(f"  Hash: {pin.hashes[0]}")

        print(f"\\nPinning methods: {report.pinning_methods}")
        print(f"Confidence: {report.confidence:.2f}")
        print(f"\\nBypass recommendations:")
        for rec in report.bypass_recommendations:
            print(f"  - {rec}")

    # Scan for certificate hashes
    hashes = detector.scan_for_certificate_hashes("app.exe")
    print(f"Found {len(hashes)} certificate hashes")

    # Find pinning cross-references
    cross_refs = detector.find_pinning_cross_refs("app.exe")
    for hash_val, addresses in cross_refs.items():
        print(f"Hash {hash_val} used at: {[hex(a) for a in addresses]}")

RELATED MODULES:
- multilayer_bypass.py: Uses pinning detection for comprehensive bypass

DETECTION METHODS:
    String Scanning:
        - Extract all strings from binary
        - Find SHA-256 hashes (64 hex characters)
        - Find SHA-1 hashes (40 hex characters)
        - Find Base64-encoded certificates

    Windows API Analysis:
        - Search for CertGetCertificateChain usage
        - Search for CertVerifyCertificateChainPolicy
        - Search for WinHttpSetOption calls
        - Detect Schannel certificate validation

    Cross-Reference:
        - Find all references to detected certificate hashes
        - Map hash -> function addresses that use it
        - Identify pinning validation functions

PINNING REPORT STRUCTURE:
    - binary_path: Target file path
    - detected_pins: List[PinningInfo] (hashes, method)
    - pinning_locations: List[PinningLocation] (address, function, type)
    - pinning_methods: List[str] (custom, winhttp, etc.)
    - bypass_recommendations: List[str]
    - confidence: float (0.0-1.0)
    - platform: str (windows)

CONFIDENCE SCORING:
    - High (0.8-1.0): API-detected + hashes found + clear validation logic
    - Medium (0.5-0.7): Hashes found + some validation indicators
    - Low (0.3-0.4): Only hashes found, validation unclear
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import lief


logger = logging.getLogger(__name__)


@dataclass
class PinningInfo:
    """Certificate pinning information."""

    location: str
    pin_type: str
    domains: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    confidence: float = 0.0
    additional_info: dict[str, Any] = field(default_factory=dict)


@dataclass
class PinningLocation:
    """Location of pinning logic in binary."""

    address: int
    function_name: str
    pinning_type: str
    confidence: float
    evidence: list[str] = field(default_factory=list)


@dataclass
class PinningReport:
    """Comprehensive pinning detection report."""

    binary_path: str
    detected_pins: list[PinningInfo]
    pinning_locations: list[PinningLocation]
    pinning_methods: list[str]
    bypass_recommendations: list[str]
    confidence: float
    platform: str

    @property
    def has_pinning(self) -> bool:
        """Check if any pinning was detected.

        Returns:
            True if pinning was detected in the binary

        """
        return len(self.detected_pins) > 0 or len(self.pinning_locations) > 0


class PinningDetector:
    """Windows PE certificate pinning detector.

    Analyzes Windows PE binaries to detect certificate pinning implementations
    using static analysis techniques.
    """

    def __init__(self) -> None:
        """Initialize pinning detector."""
        self.binary: lief.PE.Binary | None = None
        self.binary_path: Path | None = None
        self.platform: str = "windows"

    def scan_for_certificate_hashes(self, binary_path: str) -> list[str]:
        """Scan binary for certificate hash strings.

        Detects SHA-256 and SHA-1 hashes that may be pinned certificates.

        Args:
            binary_path: Path to binary file

        Returns:
            List of detected certificate hashes

        Raises:
            FileNotFoundError: If binary file is not found

        """
        self.binary_path = Path(binary_path)

        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        try:
            content = self.binary_path.read_bytes()
            text_content = content.decode("utf-8", errors="ignore")
        except Exception as e:
            logger.exception("Failed to read binary: %s", e, exc_info=True)
            return []

        sha256_pattern = re.compile(r"\b([a-fA-F0-9]{64})\b")
        sha256_matches = sha256_pattern.findall(text_content)
        hashes = [f"SHA-256:{h}" for h in set(sha256_matches)]
        sha1_pattern = re.compile(r"\b([a-fA-F0-9]{40})\b")
        sha1_matches = sha1_pattern.findall(text_content)
        hashes.extend([f"SHA-1:{h}" for h in set(sha1_matches)])

        base64_sha256_pattern = re.compile(r"sha256/([A-Za-z0-9+/]{43}=)")
        base64_matches = base64_sha256_pattern.findall(text_content)
        hashes.extend([f"SHA-256-B64:{h}" for h in set(base64_matches)])

        logger.info("Found %d potential certificate hashes", len(hashes))
        return hashes

    def detect_pinning_logic(self, binary_path: str) -> list[PinningLocation]:
        """Detect certificate pinning logic in Windows PE binary.

        Args:
            binary_path: Path to binary file

        Returns:
            List of detected pinning locations

        """
        self.binary_path = Path(binary_path)

        try:
            parsed = lief.parse(str(self.binary_path))
            if not isinstance(parsed, lief.PE.Binary):
                logger.warning("Not a Windows PE binary: %s", binary_path)
                return []
            self.binary = parsed
        except Exception as e:
            logger.exception("Failed to parse binary with LIEF: %s", e, exc_info=True)
            return []

        locations = self._detect_windows_pinning_logic()

        logger.info("Detected %d pinning logic locations", len(locations))
        return locations

    def _detect_windows_pinning_logic(self) -> list[PinningLocation]:
        """Detect Windows-specific pinning logic.

        Returns:
            List of detected pinning locations

        """
        locations: list[PinningLocation] = []

        if not isinstance(self.binary, lief.PE.Binary):
            return locations

        imports = self._get_imported_functions()

        cert_apis = {
            "CertVerifyCertificateChainPolicy",
            "CertGetCertificateChain",
            "WinHttpSetOption",
            "WinHttpSendRequest",
            "CertOpenStore",
            "CertFindCertificateInStore",
            "CertGetNameStringW",
            "CertGetNameStringA",
        }

        schannel_apis = {
            "AcquireCredentialsHandleW",
            "AcquireCredentialsHandleA",
            "InitializeSecurityContextW",
            "InitializeSecurityContextA",
            "QueryContextAttributesW",
            "QueryContextAttributesA",
        }

        winhttp_apis = {
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "WinHttpSetOption",
            "WinHttpQueryOption",
        }

        found_cert_apis = cert_apis.intersection(imports)
        found_schannel_apis = schannel_apis.intersection(imports)
        found_winhttp_apis = winhttp_apis.intersection(imports)

        if found_cert_apis:
            hashes = self.scan_for_certificate_hashes(str(self.binary_path)) if self.binary_path else []
            if hashes:
                locations.append(
                    PinningLocation(
                        address=0,
                        function_name="crypt32_pinning",
                        pinning_type="crypt32",
                        confidence=0.80,
                        evidence=[f"APIs: {', '.join(found_cert_apis)}", f"Found {len(hashes)} hashes"],
                    ),
                )

        if found_schannel_apis:
            locations.append(
                PinningLocation(
                    address=0,
                    function_name="schannel_validation",
                    pinning_type="schannel",
                    confidence=0.70,
                    evidence=[f"Schannel APIs: {', '.join(found_schannel_apis)}"],
                ),
            )

        if found_winhttp_apis:
            locations.append(
                PinningLocation(
                    address=0,
                    function_name="winhttp_pinning",
                    pinning_type="winhttp",
                    confidence=0.75,
                    evidence=[f"WinHTTP APIs: {', '.join(found_winhttp_apis)}"],
                ),
            )

        return locations

    def find_pinning_cross_refs(self, binary_path: str) -> dict[str, list[int]]:
        """Find cross-references to certificate hashes.

        Args:
            binary_path: Path to binary file

        Returns:
            Dictionary mapping hash -> addresses that reference it

        """
        cross_refs: dict[str, list[int]] = {}

        hashes = self.scan_for_certificate_hashes(binary_path)

        if not hashes:
            return cross_refs

        try:
            content = Path(binary_path).read_bytes()

            for hash_str in hashes:
                hash_value = hash_str.split(":", 1)[1] if ":" in hash_str else hash_str
                hash_bytes = hash_value.encode("utf-8")

                addresses = []
                offset = 0
                while True:
                    pos = content.find(hash_bytes, offset)
                    if pos == -1:
                        break
                    addresses.append(pos)
                    offset = pos + 1

                if addresses:
                    cross_refs[hash_str] = addresses

        except Exception as e:
            logger.exception("Cross-reference analysis failed: %s", e, exc_info=True)

        return cross_refs

    def generate_pinning_report(self, binary_path: str) -> PinningReport:
        """Generate comprehensive pinning detection report.

        Args:
            binary_path: Path to binary file

        Returns:
            Complete pinning report with all detected configurations

        """
        self.binary_path = Path(binary_path)

        try:
            parsed = lief.parse(str(self.binary_path))
            if isinstance(parsed, lief.PE.Binary):
                self.binary = parsed
            else:
                logger.warning("Not a Windows PE binary")
                self.binary = None
        except Exception as e:
            logger.exception("Binary parsing failed: %s", e, exc_info=True)
            self.binary = None

        detected_pins: list[PinningInfo] = []
        pinning_locations = self.detect_pinning_logic(str(self.binary_path))
        pinning_methods = list({loc.pinning_type for loc in pinning_locations})

        hashes = self.scan_for_certificate_hashes(str(self.binary_path))
        if hashes:
            detected_pins.append(
                PinningInfo(
                    location="string_data",
                    pin_type="hash_detected",
                    domains=[],
                    hashes=hashes[:20],
                    confidence=0.50 if not pinning_locations else 0.75,
                    additional_info={"detection_method": "hash_scan"},
                ),
            )

        bypass_recommendations = self._generate_bypass_recommendations(pinning_methods)

        avg_confidence = 0.0
        if detected_pins:
            avg_confidence = sum(p.confidence for p in detected_pins) / len(detected_pins)
        elif pinning_locations:
            avg_confidence = sum(loc.confidence for loc in pinning_locations) / len(pinning_locations)

        report = PinningReport(
            binary_path=str(self.binary_path),
            detected_pins=detected_pins,
            pinning_locations=pinning_locations,
            pinning_methods=pinning_methods,
            bypass_recommendations=bypass_recommendations,
            confidence=avg_confidence,
            platform="windows",
        )

        logger.info(
            "Generated pinning report: %d pins, %d methods, confidence=%.2f",
            len(detected_pins),
            len(pinning_methods),
            avg_confidence,
        )

        return report

    def _generate_bypass_recommendations(self, pinning_methods: list[str]) -> list[str]:
        """Generate bypass recommendations based on detected pinning.

        Args:
            pinning_methods: List of detected pinning method types

        Returns:
            List of bypass recommendations

        """
        recommendations = []

        if "crypt32" in pinning_methods:
            recommendations.append(
                "Crypt32: Hook CertVerifyCertificateChainPolicy to return TRUE, "
                "or hook CertGetCertificateChain to modify chain validation"
            )

        if "schannel" in pinning_methods:
            recommendations.append(
                "Schannel: Hook InitializeSecurityContext to skip certificate validation, "
                "or use Frida schannel_bypass.js"
            )

        if "winhttp" in pinning_methods:
            recommendations.append(
                "WinHTTP: Hook WinHttpSetOption to ignore WINHTTP_OPTION_SECURITY_FLAGS, "
                "or use Frida winhttp_bypass.js"
            )

        if "custom" in pinning_methods:
            recommendations.append(
                "Custom implementation: Identify hash comparison function and patch/hook to always succeed"
            )

        if not recommendations:
            recommendations.append(
                "No specific pinning detected - use general certificate bypass with Frida universal_ssl_bypass.js"
            )

        return recommendations

    def _extract_strings(self) -> set[str]:
        """Extract strings from binary.

        Returns:
            Set of extracted string patterns

        """
        if not self.binary_path:
            return set()

        try:
            content = self.binary_path.read_bytes().decode("utf-8", errors="ignore")

            string_pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")
            return set(string_pattern.findall(content))
        except Exception as e:
            logger.debug("String extraction failed: %s", e, exc_info=True)
            return set()

    def _get_imported_functions(self) -> set[str]:
        """Get list of imported function names from PE binary.

        Returns:
            Set of imported function names

        """
        if not self.binary or not isinstance(self.binary, lief.PE.Binary):
            return set()

        imports: set[str] = set()

        try:
            for import_entry in self.binary.imports:
                for func in import_entry.entries:
                    if func.name:
                        name = func.name if isinstance(func.name, str) else func.name.decode("utf-8", errors="ignore")
                        imports.add(name)

        except Exception as e:
            logger.debug("Import extraction failed: %s", e, exc_info=True)

        return imports
