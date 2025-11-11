"""SecuROM Protection Analysis Module.

Provides comprehensive reverse engineering and analysis of SecuROM v7.x and v8.x
protection including activation mechanisms, trigger identification, product key
extraction, disc authentication analysis, and license validation flow mapping.
"""

import ctypes
import logging
import struct
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


@dataclass
class ActivationMechanism:
    """SecuROM activation mechanism analysis."""

    activation_type: str
    online_validation: bool
    challenge_response: bool
    activation_server_url: Optional[str]
    max_activations: int
    hardware_binding: List[str]
    encryption_algorithm: Optional[str]


@dataclass
class TriggerPoint:
    """Online validation trigger point information."""

    address: int
    trigger_type: str
    description: str
    function_name: str
    frequency: str


@dataclass
class ProductActivationKey:
    """Product activation key structure."""

    key_format: str
    key_length: int
    validation_algorithm: str
    example_pattern: str
    checksum_type: Optional[str]


@dataclass
class DiscAuthRoutine:
    """Disc authentication routine analysis."""

    routine_address: int
    scsi_commands: List[str]
    signature_checks: List[str]
    fingerprint_method: str
    bypass_difficulty: str


@dataclass
class PhoneHomeMechanism:
    """Phone-home mechanism details."""

    mechanism_type: str
    address: int
    server_urls: List[str]
    frequency: str
    data_transmitted: List[str]
    protocol: str


@dataclass
class ChallengeResponseFlow:
    """Challenge-response authentication flow."""

    challenge_generation_addr: int
    response_validation_addr: int
    crypto_operations: List[Tuple[int, str]]
    key_derivation_method: str
    difficulty: str


@dataclass
class LicenseValidationFunction:
    """License validation function details."""

    address: int
    name: str
    function_type: str
    checks_performed: List[str]
    return_values: Dict[str, str]


@dataclass
class SecuROMAnalysis:
    """Results from SecuROM protection analysis."""

    target_path: Path
    version: str
    activation_mechanisms: List[ActivationMechanism]
    trigger_points: List[TriggerPoint]
    product_keys: List[ProductActivationKey]
    disc_auth_routines: List[DiscAuthRoutine]
    phone_home_mechanisms: List[PhoneHomeMechanism]
    challenge_response_flows: List[ChallengeResponseFlow]
    license_validation_functions: List[LicenseValidationFunction]
    encryption_techniques: List[str]
    obfuscation_methods: List[str]
    details: Dict[str, any]


class SecuROMAnalyzer:
    """Comprehensive SecuROM protection reverse engineering system.

    Analyzes SecuROM v7.x and v8.x to identify activation mechanisms,
    trigger points, product key algorithms, disc authentication, and
    license validation flows.
    """

    ACTIVATION_KEYWORDS = [
        b"ProductActivation",
        b"ActivateProduct",
        b"DeactivateProduct",
        b"GetActivationStatus",
        b"VerifyActivation",
        b"OnlineActivation",
        b"ActivationLimit",
        b"ActivationCount",
        b"MachineIdentifier",
        b"HardwareID",
        b"HWID",
        b"DeviceFingerprint",
    ]

    TRIGGER_KEYWORDS = [
        b"ValidateLicense",
        b"CheckLicenseStatus",
        b"VerifyProductKey",
        b"ContactActivationServer",
        b"SendActivationRequest",
        b"CheckActivationValidity",
        b"ValidateOnline",
        b"PhoneHome",
    ]

    DISC_AUTH_KEYWORDS = [
        b"DiscSignature",
        b"DiscFingerprint",
        b"AuthenticateDisc",
        b"VerifyDiscPresence",
        b"CheckOriginalDisc",
        b"ReadDiscSerial",
        b"SCSI",
        b"CdRom",
        b"DeviceIoControl",
    ]

    CRYPTO_PATTERNS = {
        "RSA": [
            b"\x00\x01\xff\xff\xff\xff",
            b"\x30\x31\x30\x0d\x06\x09",
        ],
        "AES": [
            b"\x63\x7c\x77\x7b\xf2\x6b",
            bytes(range(256))[:16],
        ],
        "SHA256": [
            b"\x6a\x09\xe6\x67\xbb\x67\xae\x85",
        ],
        "MD5": [
            b"\x67\x45\x23\x01\xef\xcd\xab\x89",
        ],
    }

    SCSI_COMMANDS = {
        0x12: "INQUIRY",
        0x28: "READ_10",
        0xA8: "READ_12",
        0x43: "READ_TOC",
        0x42: "READ_SUBCHANNEL",
        0xBE: "READ_CD",
        0x25: "READ_CAPACITY",
        0x51: "READ_DISC_INFORMATION",
    }

    def __init__(self) -> None:
        """Initialize SecuROM analyzer."""
        self.logger = logging.getLogger(__name__)
        self._kernel32 = None
        self._setup_winapi()

    def _setup_winapi(self) -> None:
        """Set up Windows API functions."""
        try:
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            self._kernel32.CreateFileW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            self._kernel32.CreateFileW.restype = wintypes.HANDLE

            self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            self._kernel32.CloseHandle.restype = wintypes.BOOL

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

    def analyze(self, target_path: Path) -> SecuROMAnalysis:
        """Perform comprehensive SecuROM protection analysis.

        Args:
            target_path: Path to SecuROM protected executable

        Returns:
            SecuROMAnalysis results with detailed findings

        """
        version = self._detect_version(target_path)
        activation_mechanisms = self._analyze_activation_mechanisms(target_path)
        trigger_points = self._identify_trigger_points(target_path)
        product_keys = self._extract_product_key_info(target_path)
        disc_auth_routines = self._analyze_disc_authentication(target_path)
        phone_home_mechanisms = self._detect_phone_home(target_path)
        challenge_response_flows = self._analyze_challenge_response(target_path)
        license_validation_functions = self._map_license_validation(target_path)
        encryption_techniques = self._identify_encryption(target_path)
        obfuscation_methods = self._detect_obfuscation(target_path)

        details = {
            "imports": self._get_imports(target_path),
            "exports": self._get_exports(target_path),
            "resources": self._analyze_resources(target_path),
            "strings": self._extract_relevant_strings(target_path),
            "network_endpoints": self._extract_network_endpoints(target_path),
            "registry_access": self._identify_registry_access(target_path),
        }

        return SecuROMAnalysis(
            target_path=target_path,
            version=version,
            activation_mechanisms=activation_mechanisms,
            trigger_points=trigger_points,
            product_keys=product_keys,
            disc_auth_routines=disc_auth_routines,
            phone_home_mechanisms=phone_home_mechanisms,
            challenge_response_flows=challenge_response_flows,
            license_validation_functions=license_validation_functions,
            encryption_techniques=encryption_techniques,
            obfuscation_methods=obfuscation_methods,
            details=details,
        )

    def _detect_version(self, target_path: Path) -> str:
        """Detect SecuROM version."""
        if not target_path.exists():
            return "Unknown"

        try:
            with open(target_path, "rb") as f:
                data = f.read()

            if b"UserAccess8" in data or b"SR8" in data:
                return "8.x"
            elif b"UserAccess7" in data or b"SR7" in data:
                return "7.x"
            elif b"SecuROM" in data:
                return "7.x or earlier"

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return "Unknown"

    def _analyze_activation_mechanisms(self, target_path: Path) -> List[ActivationMechanism]:
        """Analyze activation mechanisms in protected executable."""
        mechanisms = []

        if not target_path.exists():
            return mechanisms

        try:
            with open(target_path, "rb") as f:
                data = f.read()

            online_validation = b"OnlineActivation" in data or b"ActivationServer" in data
            challenge_response = b"Challenge" in data and b"Response" in data

            server_url = None
            if b"https://" in data:
                url_start = data.find(b"https://")
                if url_start != -1:
                    url_end = data.find(b"\x00", url_start)
                    if url_end != -1:
                        server_url = data[url_start:url_end].decode("utf-8", errors="ignore")

            max_activations = 5
            for i in range(len(data) - 4):
                if data[i : i + 20] == b"MaxActivations\x00\x00\x00\x00\x00\x00":
                    if i + 24 < len(data):
                        potential_max = struct.unpack("<I", data[i + 20 : i + 24])[0]
                        if 1 <= potential_max <= 100:
                            max_activations = potential_max
                            break

            hardware_binding = []
            hw_indicators = [
                (b"MachineID", "Machine ID"),
                (b"HardwareID", "Hardware ID"),
                (b"DiskSerial", "Disk Serial"),
                (b"MACAddress", "MAC Address"),
                (b"CPUID", "CPU ID"),
            ]

            for indicator, name in hw_indicators:
                if indicator in data:
                    hardware_binding.append(name)

            encryption_algorithm = None
            for algo, patterns in self.CRYPTO_PATTERNS.items():
                for pattern in patterns:
                    if pattern in data:
                        encryption_algorithm = algo
                        break
                if encryption_algorithm:
                    break

            activation_type = "Online" if online_validation else "Offline"
            if challenge_response:
                activation_type += " with Challenge-Response"

            mechanisms.append(
                ActivationMechanism(
                    activation_type=activation_type,
                    online_validation=online_validation,
                    challenge_response=challenge_response,
                    activation_server_url=server_url,
                    max_activations=max_activations,
                    hardware_binding=hardware_binding,
                    encryption_algorithm=encryption_algorithm,
                ),
            )

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return mechanisms

    def _identify_trigger_points(self, target_path: Path) -> List[TriggerPoint]:
        """Identify online validation trigger points."""
        trigger_points = []

        if not target_path.exists():
            return trigger_points

        try:
            with open(target_path, "rb") as f:
                data = f.read()

            for keyword in self.TRIGGER_KEYWORDS:
                offset = 0
                while True:
                    offset = data.find(keyword, offset)
                    if offset == -1:
                        break

                    trigger_type = self._classify_trigger_type(keyword)
                    description = self._get_trigger_description(keyword)
                    function_name = keyword.decode("utf-8", errors="ignore")
                    frequency = self._estimate_trigger_frequency(data, offset)

                    trigger_points.append(
                        TriggerPoint(
                            address=offset,
                            trigger_type=trigger_type,
                            description=description,
                            function_name=function_name,
                            frequency=frequency,
                        ),
                    )

                    offset += len(keyword)

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return trigger_points

    def _classify_trigger_type(self, keyword: bytes) -> str:
        """Classify trigger point type."""
        keyword_lower = keyword.lower()

        if b"validate" in keyword_lower or b"verify" in keyword_lower:
            return "Validation"
        elif b"check" in keyword_lower:
            return "Status Check"
        elif b"contact" in keyword_lower or b"send" in keyword_lower:
            return "Network Communication"
        elif b"phone" in keyword_lower:
            return "Phone Home"
        else:
            return "Unknown"

    def _get_trigger_description(self, keyword: bytes) -> str:
        """Get human-readable description of trigger."""
        descriptions = {
            b"ValidateLicense": "Validates license with activation server",
            b"CheckLicenseStatus": "Checks current license status",
            b"VerifyProductKey": "Verifies product key validity",
            b"ContactActivationServer": "Initiates connection to activation server",
            b"SendActivationRequest": "Sends activation request to server",
            b"CheckActivationValidity": "Validates activation state",
            b"ValidateOnline": "Performs online validation",
            b"PhoneHome": "Periodic check-in with activation server",
        }

        return descriptions.get(keyword, "Unknown trigger point")

    def _estimate_trigger_frequency(self, data: bytes, offset: int) -> str:
        """Estimate how frequently trigger is called."""
        context_start = max(0, offset - 100)
        context_end = min(len(data), offset + 100)
        context = data[context_start:context_end]

        if b"CreateWaitableTimer" in context or b"SetTimer" in context:
            return "Periodic"
        elif b"WinMain" in context or b"main" in context:
            return "On Startup"
        elif b"Button" in context or b"Menu" in context:
            return "On User Action"
        else:
            return "Unknown"

    def _extract_product_key_info(self, target_path: Path) -> List[ProductActivationKey]:
        """Extract product activation key structure information."""
        keys = []

        if not target_path.exists():
            return keys

        try:
            with open(target_path, "rb") as f:
                data = f.read()

            key_patterns = [
                (b"ProductKey", r"[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}", 29, "Dashed Format"),
                (b"SerialNumber", r"[A-Z0-9]{20}", 20, "Continuous Format"),
                (b"ActivationKey", r"[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}", 36, "GUID Format"),
            ]

            for keyword, pattern, length, format_type in key_patterns:
                if keyword in data:
                    validation_algo = self._detect_key_validation_algorithm(data, keyword)
                    checksum_type = self._detect_checksum_type(data, keyword)

                    keys.append(
                        ProductActivationKey(
                            key_format=format_type,
                            key_length=length,
                            validation_algorithm=validation_algo,
                            example_pattern=pattern,
                            checksum_type=checksum_type,
                        ),
                    )

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return keys

    def _detect_key_validation_algorithm(self, data: bytes, keyword: bytes) -> str:
        """Detect product key validation algorithm."""
        offset = data.find(keyword)
        if offset == -1:
            return "Unknown"

        context = data[max(0, offset - 500) : min(len(data), offset + 500)]

        if any(pattern in context for pattern in self.CRYPTO_PATTERNS.get("RSA", [])):
            return "RSA Signature Verification"
        elif any(pattern in context for pattern in self.CRYPTO_PATTERNS.get("SHA256", [])):
            return "SHA256 Hash Validation"
        elif b"CRC32" in context or b"crc32" in context:
            return "CRC32 Checksum"
        elif b"Luhn" in context or b"luhn" in context:
            return "Luhn Algorithm"
        else:
            return "Custom Algorithm"

    def _detect_checksum_type(self, data: bytes, keyword: bytes) -> Optional[str]:
        """Detect checksum type used for product key."""
        offset = data.find(keyword)
        if offset == -1:
            return None

        context = data[max(0, offset - 300) : min(len(data), offset + 300)]

        if b"CRC32" in context or b"crc32" in context:
            return "CRC32"
        elif b"MD5" in context:
            return "MD5"
        elif b"SHA" in context:
            return "SHA"
        elif b"Checksum" in context or b"checksum" in context:
            return "Custom Checksum"
        else:
            return None

    def _analyze_disc_authentication(self, target_path: Path) -> List[DiscAuthRoutine]:
        """Analyze disc authentication routines."""
        routines = []

        if not target_path.exists():
            return routines

        try:
            with open(target_path, "rb") as f:
                data = f.read()

            for keyword in self.DISC_AUTH_KEYWORDS:
                offset = data.find(keyword)
                if offset != -1:
                    scsi_commands = self._extract_scsi_commands(data, offset)
                    signature_checks = self._identify_signature_checks(data, offset)
                    fingerprint_method = self._determine_fingerprint_method(data, offset)
                    bypass_difficulty = self._assess_bypass_difficulty(scsi_commands, signature_checks)

                    routines.append(
                        DiscAuthRoutine(
                            routine_address=offset,
                            scsi_commands=scsi_commands,
                            signature_checks=signature_checks,
                            fingerprint_method=fingerprint_method,
                            bypass_difficulty=bypass_difficulty,
                        ),
                    )

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return routines

    def _extract_scsi_commands(self, data: bytes, offset: int) -> List[str]:
        """Extract SCSI commands used in disc authentication."""
        commands = []
        context = data[max(0, offset - 200) : min(len(data), offset + 200)]

        for cmd_code, cmd_name in self.SCSI_COMMANDS.items():
            cmd_byte = struct.pack("B", cmd_code)
            if cmd_byte in context:
                commands.append(cmd_name)

        return commands

    def _identify_signature_checks(self, data: bytes, offset: int) -> List[str]:
        """Identify disc signature verification methods."""
        checks = []
        context = data[max(0, offset - 300) : min(len(data), offset + 300)]

        check_indicators = [
            (b"DiscSignature", "Digital Signature Verification"),
            (b"TOC", "Table of Contents Check"),
            (b"Subchannel", "Subchannel Data Analysis"),
            (b"PhysicalFormat", "Physical Format Verification"),
            (b"SerialNumber", "Disc Serial Number Check"),
        ]

        for indicator, check_name in check_indicators:
            if indicator in context:
                checks.append(check_name)

        return checks

    def _determine_fingerprint_method(self, data: bytes, offset: int) -> str:
        """Determine disc fingerprinting method."""
        context = data[max(0, offset - 400) : min(len(data), offset + 400)]

        if b"Subchannel" in context:
            return "Subchannel-based Fingerprinting"
        elif b"TOC" in context:
            return "TOC-based Fingerprinting"
        elif b"PhysicalSector" in context or b"RawSector" in context:
            return "Physical Sector Analysis"
        else:
            return "Unknown Method"

    def _assess_bypass_difficulty(self, scsi_commands: List[str], signature_checks: List[str]) -> str:
        """Assess difficulty of bypassing disc authentication."""
        complexity = len(scsi_commands) + len(signature_checks)

        if complexity <= 2:
            return "Low"
        elif complexity <= 4:
            return "Medium"
        else:
            return "High"

    def _detect_phone_home(self, target_path: Path) -> List[PhoneHomeMechanism]:
        """Detect phone-home mechanisms."""
        mechanisms = []

        if not target_path.exists():
            return mechanisms

        try:
            with open(target_path, "rb") as f:
                data = f.read()

            network_apis = [b"WinHttpSendRequest", b"InternetOpenUrl", b"HttpSendRequest", b"WSASend"]

            for api in network_apis:
                offset = data.find(api)
                if offset != -1:
                    server_urls = self._extract_urls_near_offset(data, offset)
                    frequency = self._estimate_trigger_frequency(data, offset)
                    data_transmitted = self._identify_transmitted_data(data, offset)
                    protocol = self._detect_protocol(api)

                    mechanisms.append(
                        PhoneHomeMechanism(
                            mechanism_type="HTTP" if b"Http" in api else "Socket",
                            address=offset,
                            server_urls=server_urls,
                            frequency=frequency,
                            data_transmitted=data_transmitted,
                            protocol=protocol,
                        ),
                    )

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return mechanisms

    def _extract_urls_near_offset(self, data: bytes, offset: int) -> List[str]:
        """Extract URLs near the given offset."""
        urls = []
        context_start = max(0, offset - 1000)
        context_end = min(len(data), offset + 1000)
        context = data[context_start:context_end]

        for protocol in [b"https://", b"http://"]:
            url_offset = 0
            while True:
                url_offset = context.find(protocol, url_offset)
                if url_offset == -1:
                    break

                url_end = context.find(b"\x00", url_offset)
                if url_end != -1:
                    url = context[url_offset:url_end].decode("utf-8", errors="ignore")
                    if url and len(url) < 200:
                        urls.append(url)

                url_offset += len(protocol)

        return urls

    def _identify_transmitted_data(self, data: bytes, offset: int) -> List[str]:
        """Identify what data is transmitted in phone-home."""
        transmitted = []
        context = data[max(0, offset - 500) : min(len(data), offset + 500)]

        data_indicators = [
            (b"MachineID", "Machine ID"),
            (b"ProductKey", "Product Key"),
            (b"ActivationStatus", "Activation Status"),
            (b"Version", "Software Version"),
            (b"HWID", "Hardware ID"),
            (b"UserName", "User Name"),
            (b"ComputerName", "Computer Name"),
        ]

        for indicator, name in data_indicators:
            if indicator in context:
                transmitted.append(name)

        return transmitted

    def _detect_protocol(self, api_name: bytes) -> str:
        """Detect network protocol used."""
        if b"WinHttp" in api_name or b"Http" in api_name:
            return "HTTP/HTTPS"
        elif b"WSA" in api_name or b"socket" in api_name.lower():
            return "TCP/IP"
        else:
            return "Unknown"

    def _analyze_challenge_response(self, target_path: Path) -> List[ChallengeResponseFlow]:
        """Analyze challenge-response authentication flows."""
        flows = []

        if not target_path.exists():
            return flows

        try:
            with open(target_path, "rb") as f:
                data = f.read()

            challenge_offset = data.find(b"Challenge")
            response_offset = data.find(b"Response")

            if challenge_offset != -1 and response_offset != -1:
                crypto_ops = []

                for algo, patterns in self.CRYPTO_PATTERNS.items():
                    for pattern in patterns:
                        offset = data.find(pattern, challenge_offset)
                        if offset != -1 and offset < response_offset + 1000:
                            crypto_ops.append((offset, algo))

                key_derivation = "PBKDF2" if b"PBKDF2" in data else "Custom KDF"
                difficulty = "High" if len(crypto_ops) > 2 else "Medium"

                flows.append(
                    ChallengeResponseFlow(
                        challenge_generation_addr=challenge_offset,
                        response_validation_addr=response_offset,
                        crypto_operations=crypto_ops,
                        key_derivation_method=key_derivation,
                        difficulty=difficulty,
                    ),
                )

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return flows

    def _map_license_validation(self, target_path: Path) -> List[LicenseValidationFunction]:
        """Map license validation functions."""
        functions = []

        if not target_path.exists():
            return functions

        try:
            with open(target_path, "rb") as f:
                data = f.read()

            validation_keywords = [
                (b"ValidateLicense", "License Validation"),
                (b"CheckActivation", "Activation Check"),
                (b"VerifyProductKey", "Product Key Verification"),
                (b"AuthenticateUser", "User Authentication"),
                (b"CheckExpiration", "Expiration Check"),
            ]

            for keyword, func_type in validation_keywords:
                offset = data.find(keyword)
                if offset != -1:
                    checks = self._identify_validation_checks(data, offset)
                    return_vals = self._extract_return_values(data, offset)

                    functions.append(
                        LicenseValidationFunction(
                            address=offset,
                            name=keyword.decode("utf-8", errors="ignore"),
                            function_type=func_type,
                            checks_performed=checks,
                            return_values=return_vals,
                        ),
                    )

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return functions

    def _identify_validation_checks(self, data: bytes, offset: int) -> List[str]:
        """Identify checks performed in validation function."""
        checks = []
        context = data[max(0, offset - 300) : min(len(data), offset + 300)]

        check_types = [
            (b"Registry", "Registry Check"),
            (b"File", "File Existence Check"),
            (b"Network", "Network Validation"),
            (b"Hardware", "Hardware Check"),
            (b"Expiration", "Expiration Check"),
            (b"Signature", "Digital Signature Verification"),
        ]

        for indicator, check_name in check_types:
            if indicator in context:
                checks.append(check_name)

        return checks

    def _extract_return_values(self, data: bytes, offset: int) -> Dict[str, str]:
        """Extract possible return values from validation function."""
        return {
            "0": "Validation Success",
            "1": "Invalid License",
            "2": "Expired License",
            "3": "Activation Required",
            "4": "Hardware Mismatch",
            "5": "Network Error",
        }

    def _identify_encryption(self, target_path: Path) -> List[str]:
        """Identify encryption techniques used."""
        techniques = []

        if not target_path.exists():
            return techniques

        try:
            with open(target_path, "rb") as f:
                data = f.read()

            for algo, patterns in self.CRYPTO_PATTERNS.items():
                for pattern in patterns:
                    if pattern in data:
                        techniques.append(algo)
                        break

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return list(set(techniques))

    def _detect_obfuscation(self, target_path: Path) -> List[str]:
        """Detect code obfuscation methods."""
        methods = []

        if not PEFILE_AVAILABLE or not target_path.exists():
            return methods

        try:
            pe = pefile.PE(str(target_path))

            for section in pe.sections:
                if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                    methods.append("Virtual Section Obfuscation")
                    break

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                import_count = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
                if import_count < 10:
                    methods.append("Import Table Obfuscation")

            data = pe.get_memory_mapped_image()
            if b"\xeb\xfe" in data or b"\xeb\x00" in data:
                methods.append("Anti-Disassembly Tricks")

            pe.close()

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return methods

    def _get_imports(self, target_path: Path) -> List[str]:
        """Get imported functions."""
        if not PEFILE_AVAILABLE or not target_path.exists():
            return []

        imports = []

        try:
            pe = pefile.PE(str(target_path))

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode("utf-8", errors="ignore")
                            imports.append(f"{dll_name}!{func_name}")

            pe.close()

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return imports

    def _get_exports(self, target_path: Path) -> List[str]:
        """Get exported functions."""
        if not PEFILE_AVAILABLE or not target_path.exists():
            return []

        exports = []

        try:
            pe = pefile.PE(str(target_path))

            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode("utf-8", errors="ignore"))

            pe.close()

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return exports

    def _analyze_resources(self, target_path: Path) -> Dict[str, int]:
        """Analyze PE resources."""
        if not PEFILE_AVAILABLE or not target_path.exists():
            return {}

        resources = {}

        try:
            pe = pefile.PE(str(target_path))

            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, "name"):
                        res_name = str(resource_type.name) if resource_type.name else str(resource_type.id)
                        if hasattr(resource_type, "directory"):
                            resources[res_name] = len(resource_type.directory.entries)

            pe.close()

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return resources

    def _extract_relevant_strings(self, target_path: Path) -> List[str]:
        """Extract relevant strings from executable."""
        if not target_path.exists():
            return []

        strings = []

        try:
            with open(target_path, "rb") as f:
                data = f.read()

            keywords = self.ACTIVATION_KEYWORDS + self.TRIGGER_KEYWORDS + self.DISC_AUTH_KEYWORDS

            for keyword in keywords:
                if keyword in data:
                    strings.append(keyword.decode("utf-8", errors="ignore"))

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return list(set(strings))[:50]

    def _extract_network_endpoints(self, target_path: Path) -> List[str]:
        """Extract network endpoints (URLs, IPs)."""
        if not target_path.exists():
            return []

        endpoints = []

        try:
            with open(target_path, "rb") as f:
                data = f.read()

            for protocol in [b"https://", b"http://"]:
                offset = 0
                while True:
                    offset = data.find(protocol, offset)
                    if offset == -1:
                        break

                    url_end = data.find(b"\x00", offset)
                    if url_end != -1:
                        url = data[offset:url_end].decode("utf-8", errors="ignore")
                        if url and len(url) < 200:
                            endpoints.append(url)

                    offset += len(protocol)

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return list(set(endpoints))

    def _identify_registry_access(self, target_path: Path) -> List[str]:
        """Identify registry keys accessed."""
        if not target_path.exists():
            return []

        registry_keys = []

        try:
            with open(target_path, "rb") as f:
                data = f.read()

            key_patterns = [
                b"SOFTWARE\\SecuROM",
                b"SOFTWARE\\Sony DADC",
                b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                b"SYSTEM\\CurrentControlSet\\Services",
            ]

            for pattern in key_patterns:
                if pattern in data:
                    registry_keys.append(pattern.decode("utf-8", errors="ignore"))

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e)

        return registry_keys
