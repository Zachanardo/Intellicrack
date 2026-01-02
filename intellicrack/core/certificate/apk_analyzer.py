"""Android APK certificate pinning analysis module with comprehensive static analysis.

CAPABILITIES:
- APK extraction and decompilation (via apktool)
- Network Security Config XML parsing (network_security_config.xml)
- OkHttp3 CertificatePinner detection and certificate extraction
- Hardcoded certificate detection (.pem, .crt, .der files in assets/)
- Base64-encoded certificate detection in code
- SHA-256/SHA-1 certificate hash extraction
- Domain-specific pinning configuration analysis
- Debug override detection
- Pin-set analysis with expiration dates

LIMITATIONS:
- Requires apktool for APK decompilation (external dependency)
- Cannot analyze encrypted/obfuscated APKs without decryption
- Limited effectiveness on apps with native code pinning
- No runtime pinning detection (static analysis only)
- Cannot detect dynamically generated pins
- May miss custom pinning implementations
- Requires valid APK file structure

USAGE EXAMPLES:
    # Basic APK analysis
    from intellicrack.core.certificate.apk_analyzer import APKAnalyzer

    analyzer = APKAnalyzer()
    network_config = analyzer.parse_network_security_config("app.apk")

    if network_config:
        for domain_config in network_config.domain_configs:
            print(f"Domain: {domain_config.domains}")
            for pin in domain_config.pins:
                print(f"  Pin: {pin.digest_algorithm} - {pin.hash_value}")

    # Detect OkHttp pinning
    pinning_info = analyzer.detect_okhttp_pinning("app.apk")
    for info in pinning_info:
        print(f"Domain: {info.domain}")
        print(f"Hashes: {info.certificate_hashes}")

    # Find hardcoded certificates
    certs = analyzer.find_hardcoded_certs("app.apk")
    for cert_path in certs:
        print(f"Found certificate: {cert_path}")

    # Extract APK and analyze
    extract_dir = analyzer.extract_apk("app.apk")
    # Analyze decompiled code...

RELATED MODULES:
- pinning_detector.py: Uses APK analyzer for Android pinning detection
- frida_scripts/android_pinning.js: Runtime bypass for detected pins
- multilayer_bypass.py: May use APK analysis for comprehensive bypass

NETWORK SECURITY CONFIG FORMAT:
    <?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <domain-config>
            <domain includeSubdomains="true">example.com</domain>
            <pin-set expiration="2026-01-01">
                <pin digest="SHA-256">base64+hash+here==</pin>
            </pin-set>
        </domain-config>
    </network-security-config>

OKHTTP PINNING PATTERNS:
    CertificatePinner.Builder()
        .add("example.com", "sha256/AAAA...")
        .add("*.example.com", "sha256/BBBB...")
        .build()

DETECTION STRATEGIES:
    1. Parse network_security_config.xml from res/xml/
    2. Decompile APK with apktool
    3. Search for CertificatePinner usage in smali code
    4. Extract certificate hashes from code
    5. Scan assets/ for .pem/.crt/.der files
    6. Search for Base64-encoded certificates
    7. Build PinningInfo for each detected pin
"""

import base64
import hashlib
import logging
import re
import shutil
import subprocess
import tempfile
import types
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from defusedxml import ElementTree as ET


logger = logging.getLogger(__name__)


@dataclass
class PinConfig:
    """Certificate pin configuration for a single pin.

    Represents a single certificate pin extracted from an Android
    application's pinning configuration, including the hash algorithm,
    the hash value, and the source where it was detected.

    Attributes:
        digest_algorithm: Hash algorithm used (e.g., "SHA-256", "SHA-1").
        hash_value: The hash value of the certificate's public key in
            Base64 format.
        source: Source where the pin was detected (e.g.,
            "network_security_config", "base_config", "okhttp").
    """

    digest_algorithm: str
    hash_value: str
    source: str

    def __hash__(self) -> int:
        """Generate hash value for set and dict storage.

        Returns:
            Numeric hash based on configuration attributes.
        """
        return hash((self.digest_algorithm, self.hash_value, self.source))


@dataclass
class DomainConfig:
    """Domain-specific pinning configuration for certificate validation.

    Represents the certificate pinning configuration that applies to
    specific domains or a wildcard ("*") for base configuration. Contains
    domain names, their associated pins, and expiration information.

    Attributes:
        domains: List of domain names (e.g., ["example.com"]) or ["*"]
            for base/wildcard configuration.
        pins: List of PinConfig objects representing certificate pins
            that are valid for these domains.
        include_subdomains: Whether subdomains should be included in
            the domain matching (default False).
        expiration: Optional expiration date for the pin configuration
            as an ISO date string (e.g., "2026-01-01"), or None if
            no expiration is set.
    """

    domains: list[str]
    pins: list[PinConfig]
    include_subdomains: bool = False
    expiration: str | None = None

    def __hash__(self) -> int:
        """Generate hash value for set and dict storage.

        Returns:
            Numeric hash based on domain configuration attributes.
        """
        return hash((tuple(self.domains), tuple(self.pins), self.include_subdomains))


@dataclass
class NetworkSecurityConfig:
    """Android Network Security Configuration representation.

    Represents the complete network security configuration parsed from
    an APK's network_security_config.xml file, including domain-specific
    settings, base configuration, and debug overrides.

    Attributes:
        domain_configs: List of DomainConfig objects for domain-specific
            pinning configurations.
        base_config: Base configuration that applies when no
            domain-specific configuration matches, or None if not defined.
        debug_overrides: Debug-specific configuration that may bypass
            pinning in debug builds, or None if not defined.
    """

    domain_configs: list[DomainConfig] = field(default_factory=list)
    base_config: DomainConfig | None = None
    debug_overrides: DomainConfig | None = None

    @property
    def has_pinning(self) -> bool:
        """Check if any pinning is configured.

        Returns:
            True if any pinning configuration exists, False otherwise.
        """
        if self.base_config and self.base_config.pins:
            return True
        return any(dc.pins for dc in self.domain_configs)


@dataclass
class PinningInfo:
    """General certificate pinning information detected in application.

    Represents a detected certificate pin or pinning configuration from
    various sources in the APK including network security config, OkHttp
    code, hardcoded certificates, or Base64-encoded certificates.

    Attributes:
        location: File path or location in code where pin was detected
            (relative to APK or decompiled directory).
        pin_type: Type of pinning detected ("okhttp", "hardcoded_cert",
            "base64_cert", "network_security_config", etc.).
        domains: List of domain names that this pin applies to.
        hashes: List of certificate hash values (typically SHA-256)
            as strings (e.g., "sha256/AAAA...").
        confidence: Confidence score (0.0 to 1.0) indicating how
            confident the detection is.
        additional_info: Dictionary of additional detection metadata
            (e.g., class name, detection method, file type, format).
    """

    location: str
    pin_type: str
    domains: list[str]
    hashes: list[str]
    confidence: float
    additional_info: dict[str, str] = field(default_factory=dict)

    def __hash__(self) -> int:
        """Generate hash value for set and dict storage.

        Returns:
            Numeric hash based on pinning information attributes.
        """
        return hash((self.location, self.pin_type, tuple(self.domains), tuple(self.hashes)))


class APKAnalyzer:
    """Analyzer for Android APK certificate pinning detection.

    Provides comprehensive static analysis of APK files to identify:
    - Network Security Config pinning
    - OkHttp certificate pinning
    - Hardcoded certificates
    - Custom pinning implementations
    """

    def __init__(self) -> None:
        """Initialize APK analyzer with empty state.

        Sets up instance variables for managing APK extraction and
        decompilation paths. All paths start as None and are populated
        as the analyzer processes the APK.
        """
        self.temp_dir: Path | None = None
        self.apk_path: Path | None = None
        self.extracted_path: Path | None = None
        self.decompiled_path: Path | None = None

    def extract_apk(self, apk_path: str) -> str:
        """Extract APK file to temporary directory.

        Extracts the APK (which is a ZIP archive) to a temporary
        directory and stores paths for later analysis. Validates that
        the file exists and is a valid ZIP archive before extraction.
        Creates temporary directories with intellicrack_apk_ prefix.

        Args:
            apk_path: Path to APK file to extract.

        Returns:
            Path to extracted directory containing APK contents as a
            string.

        Raises:
            FileNotFoundError: If APK file at apk_path doesn't exist.
            BadZipFile: If APK is not a valid ZIP file.
            RuntimeError: If extraction fails for any reason. Cleanup
                is automatically performed before raising exception.
        """
        self.apk_path = Path(apk_path)

        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK file not found: {apk_path}")

        if not zipfile.is_zipfile(self.apk_path):
            raise zipfile.BadZipFile(f"Not a valid APK/ZIP file: {apk_path}")

        self.temp_dir = Path(tempfile.mkdtemp(prefix="intellicrack_apk_"))
        self.extracted_path = self.temp_dir / "extracted"
        self.extracted_path.mkdir(exist_ok=True)

        logger.info("Extracting APK to %s", self.extracted_path)

        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                zf.extractall(self.extracted_path)
        except Exception as e:
            logger.exception("Failed to extract APK: %s", e)
            self.cleanup()
            raise RuntimeError(f"Failed to extract APK: {e}") from e

        return str(self.extracted_path)

    def parse_network_security_config(self, apk_path: str | None = None) -> NetworkSecurityConfig:
        """Parse Android Network Security Configuration from APK.

        Extracts and parses the network_security_config.xml file from
        an Android APK to identify certificate pinning configurations,
        domain-specific settings, base configurations, and debug
        overrides that define how the application validates server
        certificates.

        Args:
            apk_path: Path to APK file to analyze. If provided and APK
                is not already extracted, it will be extracted first.
                If None, uses previously extracted APK path.

        Returns:
            NetworkSecurityConfig object containing all parsed
            configurations including domain-specific pins, base config,
            and debug overrides. Returns empty NetworkSecurityConfig
            if network_security_config.xml is not found or cannot be
            parsed.

        Raises:
            RuntimeError: If APK has not been extracted and no apk_path
                is provided.

        Notes:
            Returns empty NetworkSecurityConfig rather than raising if
            XML file is missing or malformed, allowing analysis to
            continue with other detection methods.
        """
        if apk_path and not self.extracted_path:
            self.extract_apk(apk_path)

        if not self.extracted_path:
            raise RuntimeError("APK not extracted. Call extract_apk first.")

        nsc_path = self.extracted_path / "res" / "xml" / "network_security_config.xml"

        if not nsc_path.exists():
            logger.info("No network_security_config.xml found")
            return NetworkSecurityConfig()

        try:
            tree = ET.parse(nsc_path)
            root = tree.getroot()

            config = NetworkSecurityConfig()

            for domain_config_elem in root.findall(".//domain-config"):
                if domain_config := self._parse_domain_config(domain_config_elem):
                    config.domain_configs.append(domain_config)

            base_config_elem = root.find(".//base-config")
            if base_config_elem is not None:
                config.base_config = self._parse_base_config(base_config_elem)

            debug_overrides_elem = root.find(".//debug-overrides")
            if debug_overrides_elem is not None:
                config.debug_overrides = self._parse_base_config(debug_overrides_elem)

            logger.info("Parsed network security config: %s domain configs", len(config.domain_configs))
            return config

        except ET.ParseError as e:
            logger.exception("Failed to parse network_security_config.xml: %s", e)
            return NetworkSecurityConfig()

    def _parse_domain_config(self, elem: ET.Element) -> DomainConfig | None:
        """Parse domain-config XML element.

        Extracts domain names, pinning configuration, subdomain inclusion
        settings, and expiration dates from an Android network security
        configuration domain-config element.

        Args:
            elem: XML element containing domain configuration from
                network_security_config.xml.

        Returns:
            Parsed DomainConfig object containing domains, pins, and
            configuration settings, or None if no domains are found in
            the element.
        """
        domains = [domain_elem.text.strip() for domain_elem in elem.findall("domain") if domain_elem.text]
        if not domains:
            return None

        include_subdomains = elem.get("includeSubdomains", "false").lower() == "true"

        pins = []
        pin_set = elem.find("pin-set")
        if pin_set is not None:
            expiration = pin_set.get("expiration")
            for pin_elem in pin_set.findall("pin"):
                digest = pin_elem.get("digest", "SHA-256")
                if pin_elem.text:
                    pin_hash = pin_elem.text.strip()
                    pins.append(
                        PinConfig(
                            digest_algorithm=digest,
                            hash_value=pin_hash,
                            source="network_security_config",
                        )
                    )

            return DomainConfig(
                domains=domains,
                pins=pins,
                include_subdomains=include_subdomains,
                expiration=expiration,
            )
        return DomainConfig(domains=domains, pins=[], include_subdomains=include_subdomains)

    def _parse_base_config(self, elem: ET.Element) -> DomainConfig | None:
        """Parse base-config or debug-overrides element.

        Extracts pinning configuration from base-config or
        debug-overrides elements that apply globally to all domains
        when no domain-specific configuration matches.

        Args:
            elem: XML element containing base or debug override
                configuration from network_security_config.xml.

        Returns:
            Parsed DomainConfig object with domains set to ["*"] and
            include_subdomains=True if pins are found, or None if
            no pin-set element is present.
        """
        pins = []
        pin_set = elem.find("pin-set")
        if pin_set is not None:
            for pin_elem in pin_set.findall("pin"):
                digest = pin_elem.get("digest", "SHA-256")
                if pin_elem.text:
                    pin_hash = pin_elem.text.strip()
                    pins.append(PinConfig(digest_algorithm=digest, hash_value=pin_hash, source="base_config"))

        if pins:
            return DomainConfig(domains=["*"], pins=pins, include_subdomains=True)
        return None

    def detect_okhttp_pinning(self, apk_path: str | None = None) -> list[PinningInfo]:
        """Detect OkHttp CertificatePinner usage in decompiled APK code.

        Searches decompiled smali code for OkHttp CertificatePinner
        builder patterns and extracts domain-to-certificate-hash
        mappings. Uses regex patterns to identify both direct builder
        calls and const-string encoded pinning configurations.

        Args:
            apk_path: Path to APK file to analyze. If provided and APK
                is not already extracted, it will be extracted first.
                If None, uses previously extracted APK path.

        Returns:
            List of PinningInfo objects containing detected OkHttp
            pinning configurations with domain names, certificate hashes,
            location in code, and confidence scores.

        Raises:
            RuntimeError: If APK cannot be extracted and apk_path is None.
        """
        if apk_path and not self.extracted_path:
            self.extract_apk(apk_path)

        if not self.decompiled_path:
            self._decompile_apk()

        if not self.decompiled_path:
            logger.warning("APK decompilation failed, cannot detect OkHttp pinning")
            return []

        pinning_infos: list[PinningInfo] = []

        okhttp_pattern = re.compile(
            r'CertificatePinner\.Builder\(\).*?\.add\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']sha256/([^"\']+)["\']',
            re.DOTALL,
        )

        smali_files = list(self.decompiled_path.rglob("*.smali"))

        for smali_file in smali_files:
            try:
                content = smali_file.read_text(encoding="utf-8", errors="ignore")

                if "CertificatePinner" not in content:
                    continue

                matches = okhttp_pattern.findall(content)

                pinning_infos.extend(
                    PinningInfo(
                        location=str(smali_file.relative_to(self.decompiled_path)),
                        pin_type="okhttp",
                        domains=[domain],
                        hashes=[f"sha256/{pin_hash}"],
                        confidence=0.95,
                        additional_info={"class": smali_file.stem},
                    )
                    for domain, pin_hash in matches
                )
                const_string_pattern = re.compile(r'const-string\s+v\d+,\s+"sha256/([A-Za-z0-9+/=]+)"')
                pin_matches = const_string_pattern.findall(content)

                if pin_matches and "CertificatePinner" in content:
                    domain_pattern = re.compile(r'const-string\s+v\d+,\s+"([a-z0-9\-\.]+\.[a-z]{2,})"')
                    if domain_matches := domain_pattern.findall(content):
                        pinning_infos.extend(
                            PinningInfo(
                                location=str(smali_file.relative_to(self.decompiled_path)),
                                pin_type="okhttp",
                                domains=domain_matches[:5],
                                hashes=[f"sha256/{pin_hash}"],
                                confidence=0.80,
                                additional_info={"detection": "const-string-pattern"},
                            )
                            for pin_hash in pin_matches
                        )
            except Exception as e:
                logger.debug("Error processing %s: %s", smali_file, e)
                continue

        logger.info("Detected %s OkHttp pinning instances", len(pinning_infos))
        return pinning_infos

    def find_hardcoded_certs(self, apk_path: str | None = None) -> list[PinningInfo]:
        """Find hardcoded certificates in APK assets and resources.

        Searches for certificate files (.pem, .crt, .der, .cer, .p12, .pfx)
        in the assets/ and res/raw/ directories and extracts their public
        key SHA-256 hashes. Also searches decompiled code for Base64-encoded
        certificates.

        Args:
            apk_path: Path to APK file to analyze. If provided and APK
                is not already extracted, it will be extracted first.
                If None, uses previously extracted APK path.

        Returns:
            List of PinningInfo objects containing detected hardcoded
            certificates with their file locations, SHA-256 hashes,
            subject information, and certificate subjects.

        Raises:
            RuntimeError: If APK has not been extracted and no apk_path
                is provided.
        """
        if apk_path and not self.extracted_path:
            self.extract_apk(apk_path)

        if not self.extracted_path:
            raise RuntimeError("APK not extracted")

        pinning_infos = []

        cert_extensions = [".pem", ".crt", ".der", ".cer", ".p12", ".pfx"]

        assets_dir = self.extracted_path / "assets"
        res_raw_dir = self.extracted_path / "res" / "raw"

        for search_dir in [assets_dir, res_raw_dir]:
            if not search_dir.exists():
                continue

            for cert_file in search_dir.rglob("*"):
                if cert_file.is_file() and cert_file.suffix.lower() in cert_extensions:
                    if cert_info := self._extract_certificate_info(cert_file):
                        pinning_infos.append(cert_info)

        if self.decompiled_path:
            pinning_infos.extend(self._find_base64_certs())

        logger.info("Found %s hardcoded certificates", len(pinning_infos))
        return pinning_infos

    def _decompile_apk(self) -> bool:
        """Decompile APK using apktool to access source code.

        Uses the apktool command-line utility to decompile the extracted
        APK into smali (Dalvik assembly) code and resources. Requires
        apktool to be installed and available in PATH.

        Returns:
            True if decompilation succeeded and decompiled_path is set,
            False if apktool is not available or decompilation fails.

        Notes:
            Sets self.decompiled_path to the decompiled output directory
            on success. Has a 300-second timeout for decompilation.
        """
        if not self.temp_dir or not self.apk_path:
            return False

        self.decompiled_path = self.temp_dir / "decompiled"

        if not shutil.which("apktool"):
            logger.warning("apktool not found in PATH, skipping decompilation")
            return False

        try:
            cmd = ["apktool", "d", str(self.apk_path), "-o", str(self.decompiled_path), "-f"]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                logger.info("Successfully decompiled APK to %s", self.decompiled_path)
                return True
            logger.exception("apktool failed: %s", result.stderr)
            return False

        except subprocess.TimeoutExpired:
            logger.exception("apktool decompilation timeout (300s)")
            return False
        except Exception as e:
            logger.exception("Decompilation error: %s", e)
            return False

    def _extract_certificate_info(self, cert_file: Path) -> PinningInfo | None:
        """Extract pinning information from a certificate file.

        Attempts to load a certificate file in PEM or DER format,
        extracts the public key, computes its SHA-256 hash, and
        retrieves associated domain names from the certificate's
        Subject Alternative Name extension.

        Args:
            cert_file: Path to certificate file to analyze. Can be
                in PEM, DER, or other supported X.509 formats.

        Returns:
            PinningInfo object containing the certificate's SHA-256
            hash, location, associated domains, and subject information,
            or None if the file cannot be parsed as a valid X.509
            certificate.

        Notes:
            Tries PEM format first, then falls back to DER format.
            Extracts SubjectAlternativeName (SAN) extension for domains
            if available.
        """
        try:
            cert_data = cert_file.read_bytes()

            try:
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            except Exception:
                try:
                    cert = x509.load_der_x509_certificate(cert_data, default_backend())
                except Exception:
                    return None

            public_key_bytes = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            sha256_hash = hashlib.sha256(public_key_bytes).digest()
            sha256_base64 = base64.b64encode(sha256_hash).decode("ascii")

            subject = cert.subject.rfc4514_string()

            domains = []
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                domains = [name.value for name in san.value if isinstance(name, x509.DNSName)]
            except x509.ExtensionNotFound:
                pass

            if not self.extracted_path:
                return None

            return PinningInfo(
                location=str(cert_file.relative_to(self.extracted_path)),
                pin_type="hardcoded_cert",
                domains=domains,
                hashes=[f"sha256/{sha256_base64}"],
                confidence=1.0,
                additional_info={"subject": subject, "file_type": cert_file.suffix},
            )

        except Exception as e:
            logger.debug("Failed to parse certificate %s: %s", cert_file, e)
            return None

    def _find_base64_certs(self) -> list[PinningInfo]:
        """Find Base64-encoded certificates in decompiled smali code.

        Searches through decompiled smali code for two types of Base64
        certificate encoding patterns:
        1. PEM format certificates wrapped in BEGIN/END markers
        2. DER format certificates as const-string values

        Returns:
            List of PinningInfo objects containing detected Base64-encoded
            certificates with their SHA-256 hashes, source file locations,
            and confidence scores based on detection method.

        Notes:
            Returns empty list if APK has not been decompiled yet. Marks
            PEM-detected certificates with 0.90 confidence and DER-detected
            with 0.85 confidence.
        """
        if not self.decompiled_path:
            return []

        pinning_infos = []

        cert_begin_pattern = re.compile(
            r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----",
            re.MULTILINE,
        )

        base64_pattern = re.compile(r'const-string\s+v\d+,\s+"([A-Za-z0-9+/=]{500,})"', re.MULTILINE)

        smali_files = list(self.decompiled_path.rglob("*.smali"))

        for smali_file in smali_files:
            try:
                content = smali_file.read_text(encoding="utf-8", errors="ignore")

                cert_matches = cert_begin_pattern.findall(content)
                for cert_b64 in cert_matches:
                    cert_data = base64.b64decode(cert_b64.replace("\n", "").replace(" ", ""))

                    try:
                        cert = x509.load_der_x509_certificate(cert_data, default_backend())

                        from cryptography.hazmat.primitives import serialization

                        public_key_bytes = cert.public_key().public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )

                        sha256_hash = hashlib.sha256(public_key_bytes).digest()
                        sha256_base64 = base64.b64encode(sha256_hash).decode("ascii")

                        pinning_infos.append(
                            PinningInfo(
                                location=str(smali_file.relative_to(self.decompiled_path)),
                                pin_type="base64_cert",
                                domains=[],
                                hashes=[f"sha256/{sha256_base64}"],
                                confidence=0.90,
                                additional_info={"format": "pem"},
                            ),
                        )
                    except Exception as e:
                        logger.debug("Failed to parse PEM certificate: %s", e)
                        continue

                b64_matches = base64_pattern.findall(content)
                for b64_string in b64_matches:
                    try:
                        decoded = base64.b64decode(b64_string)

                        if decoded[:4] == b"\x30\x82":
                            cert = x509.load_der_x509_certificate(decoded, default_backend())

                            from cryptography.hazmat.primitives import serialization

                            public_key_bytes = cert.public_key().public_bytes(
                                encoding=serialization.Encoding.DER,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo,
                            )

                            sha256_hash = hashlib.sha256(public_key_bytes).digest()
                            sha256_base64 = base64.b64encode(sha256_hash).decode("ascii")

                            pinning_infos.append(
                                PinningInfo(
                                    location=str(smali_file.relative_to(self.decompiled_path)),
                                    pin_type="base64_cert",
                                    domains=[],
                                    hashes=[f"sha256/{sha256_base64}"],
                                    confidence=0.85,
                                    additional_info={"format": "der"},
                                ),
                            )
                    except Exception as e:
                        logger.debug("Failed to parse DER certificate: %s", e)
                        continue

            except Exception as e:
                logger.debug("Error processing %s: %s", smali_file, e)
                continue

        return pinning_infos

    def cleanup(self) -> None:
        """Clean up temporary files and directories created during analysis.

        Removes the entire temporary directory tree created for APK
        extraction and decompilation, including all extracted files,
        decompiled code, and intermediate artifacts.

        Notes:
            This method is safe to call multiple times. If cleanup
            fails, a warning is logged but no exception is raised.
        """
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
                logger.debug("Cleaned up temp directory: %s", self.temp_dir)
            except Exception as e:
                logger.warning("Failed to clean up temp directory: %s", e)

    def __enter__(self) -> "APKAnalyzer":
        """Enter context manager for APK analysis.

        Enables APKAnalyzer to be used with the 'with' statement for
        automatic resource cleanup via __exit__.

        Returns:
            The APKAnalyzer instance for use in the with block.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> Literal[False]:
        """Exit context manager and clean up resources.

        Automatically cleans up temporary files and directories created
        during APK analysis. This method is called when exiting a 'with'
        block, ensuring proper resource cleanup even if exceptions occur.

        Args:
            exc_type: Exception type if an exception occurred in the
                with block, or None if no exception occurred.
            exc_val: Exception value (instance) if an exception occurred,
                or None if no exception occurred.
            exc_tb: Traceback object if an exception occurred, or None
                if no exception occurred.

        Returns:
            False to propagate any exceptions that occurred in the
            with block (do not suppress exceptions).
        """
        self.cleanup()
        return False
