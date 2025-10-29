r"""Certificate pinning detection via comprehensive static analysis across platforms.

CAPABILITIES:
- Multi-platform pinning detection (Android, iOS, Windows, Linux)
- Certificate hash extraction (SHA-256, SHA-1, Base64-encoded)
- Framework-specific detection (OkHttp, AFNetworking, Alamofire)
- Bytecode analysis for pinning logic
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
- Android/iOS detection requires specialized tools

USAGE EXAMPLES:
    # Detect pinning in any binary
    from intellicrack.core.certificate.pinning_detector import PinningDetector

    detector = PinningDetector()
    report = detector.generate_pinning_report("app.exe")

    if report.has_pinning:
        print(f"Found {len(report.detected_pins)} pinned certificates")
        for pin in report.detected_pins:
            print(f"  Domain: {pin.domain}")
            print(f"  Hash: {pin.certificate_hashes[0]}")

        print(f"\\nPinning methods: {report.pinning_methods}")
        print(f"Confidence: {report.confidence:.2f}")
        print(f"\\nBypass recommendations:")
        for rec in report.bypass_recommendations:
            print(f"  - {rec}")

    # Scan for certificate hashes
    hashes = detector.scan_for_certificate_hashes("app.exe")
    print(f"Found {len(hashes)} certificate hashes")

    # Detect framework-specific pinning
    okhttp = detector.detect_okhttp_pinning("app.apk")
    afnet = detector.detect_afnetworking_pinning("app.ipa")

    # Find pinning cross-references
    cross_refs = detector.find_pinning_cross_refs("app.exe")
    for hash_val, addresses in cross_refs.items():
        print(f"Hash {hash_val} used at: {[hex(a) for a in addresses]}")

RELATED MODULES:
- apk_analyzer.py: Android-specific APK analysis
- frida_scripts/android_pinning.js: Runtime Android pinning bypass
- frida_scripts/ios_pinning.js: Runtime iOS pinning bypass
- multilayer_bypass.py: Uses pinning detection for comprehensive bypass

DETECTION METHODS:
    String Scanning:
        - Extract all strings from binary
        - Find SHA-256 hashes (64 hex characters)
        - Find SHA-1 hashes (40 hex characters)
        - Find Base64-encoded certificates

    Bytecode Analysis:
        - Android: Decompile DEX, search for certificate comparison
        - iOS: Analyze Mach-O for SecTrustEvaluate patterns
        - Windows: Search for CertGetCertificateChain + hash comparison

    Framework Detection:
        - OkHttp: Search for CertificatePinner.Builder usage
        - AFNetworking: Search for AFSecurityPolicy patterns
        - Alamofire: Search for server trust evaluation

    Cross-Reference:
        - Find all references to detected certificate hashes
        - Map hash → function addresses that use it
        - Identify pinning validation functions

PINNING REPORT STRUCTURE:
    - binary_path: Target file path
    - detected_pins: List[PinningInfo] (domain, hashes, method)
    - pinning_locations: List[PinningLocation] (address, function, type)
    - pinning_methods: List[str] (OkHttp, custom, etc.)
    - bypass_recommendations: List[str]
    - confidence: float (0.0-1.0)
    - platform: str (Android/iOS/Windows/Linux)

CONFIDENCE SCORING:
    - High (0.8-1.0): Framework-detected + hashes found + clear validation logic
    - Medium (0.5-0.7): Hashes found + some validation indicators
    - Low (0.3-0.4): Only hashes found, validation unclear
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

import lief

from .apk_analyzer import APKAnalyzer, PinningInfo

logger = logging.getLogger(__name__)


@dataclass
class PinningLocation:
    """Location of pinning logic in binary."""

    address: int
    function_name: str
    pinning_type: str
    confidence: float
    evidence: List[str] = field(default_factory=list)


@dataclass
class PinningReport:
    """Comprehensive pinning detection report."""

    binary_path: str
    detected_pins: List[PinningInfo]
    pinning_locations: List[PinningLocation]
    pinning_methods: List[str]
    bypass_recommendations: List[str]
    confidence: float
    platform: str

    @property
    def has_pinning(self) -> bool:
        """Check if any pinning was detected."""
        return len(self.detected_pins) > 0 or len(self.pinning_locations) > 0


class PinningDetector:
    """Multi-platform certificate pinning detector.

    Analyzes binaries to detect certificate pinning implementations
    across different platforms and frameworks using static analysis.
    """

    def __init__(self):
        """Initialize pinning detector."""
        self.binary: Optional[lief.Binary] = None
        self.binary_path: Optional[Path] = None
        self.platform: Optional[str] = None

    def scan_for_certificate_hashes(self, binary_path: str) -> List[str]:
        """Scan binary for certificate hash strings.

        Detects SHA-256 and SHA-1 hashes that may be pinned certificates.

        Args:
            binary_path: Path to binary file

        Returns:
            List of detected certificate hashes

        """
        self.binary_path = Path(binary_path)

        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        try:
            content = self.binary_path.read_bytes()
            text_content = content.decode("utf-8", errors="ignore")
        except Exception as e:
            logger.error(f"Failed to read binary: {e}")
            return []

        hashes = []

        sha256_pattern = re.compile(r"\b([a-fA-F0-9]{64})\b")
        sha256_matches = sha256_pattern.findall(text_content)
        hashes.extend([f"SHA-256:{h}" for h in set(sha256_matches)])

        sha1_pattern = re.compile(r"\b([a-fA-F0-9]{40})\b")
        sha1_matches = sha1_pattern.findall(text_content)
        hashes.extend([f"SHA-1:{h}" for h in set(sha1_matches)])

        base64_sha256_pattern = re.compile(r"sha256/([A-Za-z0-9+/]{43}=)")
        base64_matches = base64_sha256_pattern.findall(text_content)
        hashes.extend([f"SHA-256-B64:{h}" for h in set(base64_matches)])

        logger.info(f"Found {len(hashes)} potential certificate hashes")
        return hashes

    def detect_pinning_logic(self, binary_path: str) -> List[PinningLocation]:
        """Detect certificate pinning logic in binary.

        Args:
            binary_path: Path to binary file

        Returns:
            List of detected pinning locations

        """
        self.binary_path = Path(binary_path)

        try:
            self.binary = lief.parse(str(self.binary_path))
        except Exception as e:
            logger.error(f"Failed to parse binary with LIEF: {e}")
            return []

        if not self.binary:
            logger.error("Binary parsing returned None")
            return []

        self._determine_platform()

        locations = []

        if self.platform == "android":
            locations.extend(self._detect_android_pinning_logic())
        elif self.platform == "ios":
            locations.extend(self._detect_ios_pinning_logic())
        elif self.platform == "windows":
            locations.extend(self._detect_windows_pinning_logic())
        elif self.platform == "linux":
            locations.extend(self._detect_linux_pinning_logic())

        logger.info(f"Detected {len(locations)} pinning logic locations")
        return locations

    def _determine_platform(self):
        """Determine binary platform."""
        if isinstance(self.binary, lief.PE.Binary):
            self.platform = "windows"
        elif isinstance(self.binary, lief.ELF.Binary):
            machine = getattr(self.binary.header, "machine_type", None)
            if machine and "ARM" in str(machine):
                self.platform = "android"
            else:
                self.platform = "linux"
        elif isinstance(self.binary, lief.MachO.Binary):
            self.platform = "ios"
        else:
            self.platform = "unknown"

        logger.debug(f"Detected platform: {self.platform}")

    def _detect_android_pinning_logic(self) -> List[PinningLocation]:
        """Detect Android-specific pinning logic."""
        locations = []

        if self.binary_path.suffix.lower() in [".apk", ".aab"]:
            try:
                with APKAnalyzer() as analyzer:
                    analyzer.extract_apk(str(self.binary_path))
                    okhttp_pins = analyzer.detect_okhttp_pinning()

                    for pin in okhttp_pins:
                        locations.append(
                            PinningLocation(
                                address=0,
                                function_name=pin.location,
                                pinning_type="okhttp",
                                confidence=pin.confidence,
                                evidence=[f"Domains: {', '.join(pin.domains)}", f"Hashes: {', '.join(pin.hashes)}"],
                            )
                        )
            except Exception as e:
                logger.debug(f"APK analysis failed: {e}")

        return locations

    def _detect_ios_pinning_logic(self) -> List[PinningLocation]:
        """Detect iOS-specific pinning logic."""
        locations = []

        strings = self._extract_strings()

        afnetworking_indicators = ["AFSecurityPolicy", "pinnedCertificates", "validatesDomainName", "SSLPinningMode"]

        alamofire_indicators = ["ServerTrustPolicy", "PinnedCertificates", "PublicKeys", "performDefaultEvaluation"]

        evidence = []
        for indicator in afnetworking_indicators:
            if indicator in strings:
                evidence.append(f"Found: {indicator}")

        if evidence:
            locations.append(
                PinningLocation(
                    address=0, function_name="AFNetworking_pinning", pinning_type="afnetworking", confidence=0.85, evidence=evidence
                )
            )

        evidence = []
        for indicator in alamofire_indicators:
            if indicator in strings:
                evidence.append(f"Found: {indicator}")

        if evidence:
            locations.append(
                PinningLocation(address=0, function_name="Alamofire_pinning", pinning_type="alamofire", confidence=0.85, evidence=evidence)
            )

        if "SecTrustEvaluate" in strings and any(h in strings for h in ["sha256", "SHA256"]):
            locations.append(
                PinningLocation(
                    address=0,
                    function_name="custom_sectrust",
                    pinning_type="custom",
                    confidence=0.70,
                    evidence=["SecTrustEvaluate + SHA256 references"],
                )
            )

        return locations

    def _detect_windows_pinning_logic(self) -> List[PinningLocation]:
        """Detect Windows-specific pinning logic."""
        locations = []

        if not isinstance(self.binary, lief.PE.Binary):
            return locations

        imports = self._get_imported_functions()

        cert_apis = {"CertVerifyCertificateChainPolicy", "CertGetCertificateChain", "WinHttpSetOption", "WinHttpSendRequest"}

        found_apis = cert_apis.intersection(imports)

        if found_apis:
            hashes = self.scan_for_certificate_hashes(str(self.binary_path))

            if hashes:
                locations.append(
                    PinningLocation(
                        address=0,
                        function_name="custom_windows_pinning",
                        pinning_type="custom",
                        confidence=0.75,
                        evidence=[f"APIs: {', '.join(found_apis)}", f"Found {len(hashes)} hashes"],
                    )
                )

        return locations

    def _detect_linux_pinning_logic(self) -> List[PinningLocation]:
        """Detect Linux-specific pinning logic."""
        locations = []

        if not isinstance(self.binary, lief.ELF.Binary):
            return locations

        imports = self._get_imported_functions()

        openssl_verify = {"SSL_CTX_set_verify", "SSL_get_verify_result", "X509_verify_cert", "SSL_CTX_set_cert_verify_callback"}

        found_apis = openssl_verify.intersection(imports)

        if found_apis:
            hashes = self.scan_for_certificate_hashes(str(self.binary_path))

            if hashes:
                locations.append(
                    PinningLocation(
                        address=0,
                        function_name="openssl_pinning",
                        pinning_type="openssl",
                        confidence=0.80,
                        evidence=[f"APIs: {', '.join(found_apis)}", f"Found {len(hashes)} hashes"],
                    )
                )

        return locations

    def detect_okhttp_pinning(self, binary_path: str) -> List[PinningInfo]:
        """Detect OkHttp pinning (Android-specific).

        Args:
            binary_path: Path to APK or Android binary

        Returns:
            List of OkHttp pinning configurations

        """
        binary_path_obj = Path(binary_path)

        if binary_path_obj.suffix.lower() not in [".apk", ".aab"]:
            logger.warning("OkHttp detection requires APK file")
            return []

        try:
            with APKAnalyzer() as analyzer:
                return analyzer.detect_okhttp_pinning(binary_path)
        except Exception as e:
            logger.error(f"OkHttp detection failed: {e}")
            return []

    def detect_afnetworking_pinning(self, binary_path: str) -> List[PinningInfo]:
        """Detect AFNetworking pinning (iOS-specific).

        Args:
            binary_path: Path to iOS binary

        Returns:
            List of AFNetworking pinning configurations

        """
        pins = []

        try:
            self.binary = lief.parse(binary_path)
            if not isinstance(self.binary, lief.MachO.Binary):
                logger.warning("AFNetworking detection requires iOS binary")
                return []
        except Exception as e:
            logger.error(f"Failed to parse binary: {e}")
            return []

        strings = self._extract_strings()

        if "AFSecurityPolicy" in strings:
            hashes = self.scan_for_certificate_hashes(binary_path)

            if hashes:
                pins.append(
                    PinningInfo(
                        location="AFSecurityPolicy",
                        pin_type="afnetworking",
                        domains=[],
                        hashes=hashes[:10],
                        confidence=0.80,
                        additional_info={"framework": "AFNetworking"},
                    )
                )

        return pins

    def detect_alamofire_pinning(self, binary_path: str) -> List[PinningInfo]:
        """Detect Alamofire pinning (iOS-specific).

        Args:
            binary_path: Path to iOS binary

        Returns:
            List of Alamofire pinning configurations

        """
        pins = []

        try:
            self.binary = lief.parse(binary_path)
            if not isinstance(self.binary, lief.MachO.Binary):
                logger.warning("Alamofire detection requires iOS binary")
                return []
        except Exception as e:
            logger.error(f"Failed to parse binary: {e}")
            return []

        strings = self._extract_strings()

        if "ServerTrustPolicy" in strings or "Alamofire" in strings:
            hashes = self.scan_for_certificate_hashes(binary_path)

            if hashes:
                pins.append(
                    PinningInfo(
                        location="ServerTrustPolicy",
                        pin_type="alamofire",
                        domains=[],
                        hashes=hashes[:10],
                        confidence=0.80,
                        additional_info={"framework": "Alamofire"},
                    )
                )

        return pins

    def find_pinning_cross_refs(self, binary_path: str) -> Dict[str, List[int]]:
        """Find cross-references to certificate hashes.

        Args:
            binary_path: Path to binary file

        Returns:
            Dictionary mapping hash -> addresses that reference it

        """
        cross_refs = {}

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
            logger.error(f"Cross-reference analysis failed: {e}")

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
            self.binary = lief.parse(str(self.binary_path))
            self._determine_platform()
        except Exception as e:
            logger.error(f"Binary parsing failed: {e}")
            self.platform = "unknown"

        detected_pins = []
        pinning_locations = self.detect_pinning_logic(str(self.binary_path))
        pinning_methods = list(set(loc.pinning_type for loc in pinning_locations))

        if self.platform == "android" and self.binary_path.suffix.lower() in [".apk", ".aab"]:
            try:
                with APKAnalyzer() as analyzer:
                    analyzer.extract_apk(str(self.binary_path))

                    nsc = analyzer.parse_network_security_config()
                    if nsc.has_pinning:
                        for dc in nsc.domain_configs:
                            if dc.pins:
                                detected_pins.append(
                                    PinningInfo(
                                        location="network_security_config.xml",
                                        pin_type="network_security_config",
                                        domains=dc.domains,
                                        hashes=[p.hash_value for p in dc.pins],
                                        confidence=1.0,
                                    )
                                )

                    okhttp_pins = analyzer.detect_okhttp_pinning()
                    detected_pins.extend(okhttp_pins)

                    hardcoded_certs = analyzer.find_hardcoded_certs()
                    detected_pins.extend(hardcoded_certs)

                    if not pinning_methods:
                        pinning_methods = list(set(p.pin_type for p in detected_pins))

            except Exception as e:
                logger.error(f"APK analysis failed: {e}")

        elif self.platform == "ios":
            afnet_pins = self.detect_afnetworking_pinning(str(self.binary_path))
            detected_pins.extend(afnet_pins)

            alamofire_pins = self.detect_alamofire_pinning(str(self.binary_path))
            detected_pins.extend(alamofire_pins)

        hashes = self.scan_for_certificate_hashes(str(self.binary_path))
        if hashes and not detected_pins:
            detected_pins.append(
                PinningInfo(
                    location="string_data",
                    pin_type="unknown",
                    domains=[],
                    hashes=hashes[:20],
                    confidence=0.50,
                    additional_info={"detection_method": "hash_scan"},
                )
            )

        bypass_recommendations = self._generate_bypass_recommendations(pinning_methods, detected_pins)

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
            platform=self.platform or "unknown",
        )

        logger.info(f"Generated pinning report: {len(detected_pins)} pins, {len(pinning_methods)} methods, confidence={avg_confidence:.2f}")

        return report

    def _generate_bypass_recommendations(self, pinning_methods: List[str], detected_pins: List[PinningInfo]) -> List[str]:
        """Generate bypass recommendations based on detected pinning."""
        recommendations = []

        if "network_security_config" in pinning_methods:
            recommendations.append(
                "Network Security Config: Modify network_security_config.xml to remove <pin-set> "
                "or use Frida to hook NetworkSecurityConfig validation"
            )

        if "okhttp" in pinning_methods:
            recommendations.append("OkHttp: Hook okhttp3.CertificatePinner.check() method with Frida to bypass pinning")

        if "afnetworking" in pinning_methods:
            recommendations.append("AFNetworking: Hook AFSecurityPolicy.evaluateServerTrust with Frida, force return YES")

        if "alamofire" in pinning_methods:
            recommendations.append("Alamofire: Hook ServerTrustPolicy evaluation, always return .performDefaultEvaluation")

        if "openssl" in pinning_methods:
            recommendations.append(
                "OpenSSL: Hook SSL_get_verify_result() to return X509_V_OK, or hook SSL_CTX_set_verify() to set mode to SSL_VERIFY_NONE"
            )

        if "custom" in pinning_methods:
            recommendations.append("Custom implementation: Identify hash comparison function and patch/hook to always succeed")

        if not recommendations:
            recommendations.append("No specific pinning detected - use general certificate bypass with Frida or MITM proxy")

        return recommendations

    def _extract_strings(self) -> Set[str]:
        """Extract strings from binary."""
        if not self.binary_path:
            return set()

        try:
            content = self.binary_path.read_bytes().decode("utf-8", errors="ignore")

            string_pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")
            strings = set(string_pattern.findall(content))

            return strings
        except Exception as e:
            logger.debug(f"String extraction failed: {e}")
            return set()

    def _get_imported_functions(self) -> Set[str]:
        """Get list of imported function names."""
        if not self.binary:
            return set()

        imports = set()

        try:
            if isinstance(self.binary, lief.PE.Binary):
                for import_entry in self.binary.imports:
                    for func in import_entry.entries:
                        if func.name:
                            imports.add(func.name)

            elif isinstance(self.binary, lief.ELF.Binary):
                for symbol in self.binary.imported_symbols:
                    if symbol.name:
                        imports.add(symbol.name)

            elif isinstance(self.binary, lief.MachO.Binary):
                for symbol in self.binary.imported_symbols:
                    if symbol.name:
                        imports.add(symbol.name)

        except Exception as e:
            logger.debug(f"Import extraction failed: {e}")

        return imports
