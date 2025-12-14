"""Production-Grade Activation Pattern Analyzer for Software Licensing Detection.

Analyzes binaries to detect activation mechanisms, registration systems, trial
limitations, and hardware fingerprinting used by commercial software protections.

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

import re
import struct
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


class ActivationType(Enum):
    """Types of activation mechanisms detected in binaries."""

    ONLINE = "online"
    OFFLINE = "offline"
    CHALLENGE_RESPONSE = "challenge_response"
    HARDWARE_LOCKED = "hardware_locked"
    LICENSE_FILE = "license_file"
    REGISTRY_BASED = "registry_based"
    PHONE_ACTIVATION = "phone_activation"
    TRIAL_BASED = "trial_based"


class RegistrationType(Enum):
    """Types of registration systems detected."""

    SERIAL_NUMBER = "serial_number"
    PRODUCT_KEY = "product_key"
    ACTIVATION_CODE = "activation_code"
    LICENSE_KEY = "license_key"
    USER_REGISTRATION = "user_registration"


@dataclass
class ActivationPattern:
    """Detected activation pattern in binary."""

    pattern_type: ActivationType
    address: int
    confidence: float
    description: str
    related_strings: list[str]
    api_calls: list[str]


@dataclass
class RegistrationPattern:
    """Detected registration pattern in binary."""

    registration_type: RegistrationType
    address: int
    confidence: float
    validation_function: int | None
    algorithm_hints: list[str]


@dataclass
class TrialPattern:
    """Detected trial limitation pattern."""

    trial_type: str
    detection_address: int
    storage_location: str | None
    time_check_address: int | None
    expiration_check: int | None


@dataclass
class HardwareIDPattern:
    """Detected hardware fingerprinting pattern."""

    hwid_type: str
    generation_address: int
    components: list[str]
    api_calls: list[str]


@dataclass
class LicenseFilePattern:
    """Detected license file handling pattern."""

    file_path: str | None
    file_format: str | None
    validation_address: int | None
    encryption_used: bool


@dataclass
class ActivationAnalysisResult:
    """Complete activation analysis results."""

    activation_patterns: list[ActivationPattern]
    registration_patterns: list[RegistrationPattern]
    trial_patterns: list[TrialPattern]
    hardware_id_patterns: list[HardwareIDPattern]
    license_file_patterns: list[LicenseFilePattern]
    online_activation_urls: list[str]
    has_activation: bool
    has_trial: bool
    has_hwid_lock: bool
    protection_strength: float


class ActivationAnalyzer:
    """Production-grade analyzer for software activation and licensing patterns."""

    ACTIVATION_KEYWORDS = [
        b"activate",
        b"activation",
        b"activate now",
        b"enter activation code",
        b"product activation",
        b"activation required",
        b"trial expired",
        b"activate product",
        b"activation key",
        b"activation server",
    ]

    REGISTRATION_KEYWORDS = [
        b"register",
        b"registration",
        b"serial number",
        b"product key",
        b"license key",
        b"registration code",
        b"enter serial",
        b"unlock code",
        b"register now",
        b"registration required",
    ]

    TRIAL_KEYWORDS = [
        b"trial",
        b"trial period",
        b"trial expired",
        b"days remaining",
        b"trial version",
        b"evaluation",
        b"demo mode",
        b"time limited",
        b"trial limitation",
        b"buy now",
    ]

    HWID_KEYWORDS = [
        b"hardware id",
        b"machine id",
        b"computer id",
        b"hwid",
        b"fingerprint",
        b"machine fingerprint",
        b"hardware fingerprint",
        b"system id",
        b"installation id",
        b"device id",
    ]

    LICENSE_FILE_KEYWORDS = [
        b".lic",
        b".license",
        b"license.dat",
        b"license.xml",
        b"license.key",
        b".key",
        b"activation.dat",
        b"product.key",
    ]

    ACTIVATION_APIS = [
        b"GetVolumeInformationW",
        b"GetComputerNameW",
        b"GetUserNameW",
        b"GetSystemInfo",
        b"GetDiskFreeSpaceExW",
        b"RegCreateKeyExW",
        b"RegSetValueExW",
        b"RegQueryValueExW",
        b"CryptHashData",
        b"CryptCreateHash",
        b"InternetConnectW",
        b"HttpSendRequestW",
        b"WinHttpOpen",
        b"WinHttpConnect",
    ]

    URL_PATTERN = rb"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+"

    def __init__(self) -> None:
        """Initialize activation analyzer."""
        self.pe: pefile.PE | None = None
        self.binary_data: bytes = b""
        self.binary_path: Path | None = None

    def analyze(self, binary_path: str | Path) -> ActivationAnalysisResult:
        """Analyze binary for activation and licensing patterns.

        Args:
            binary_path: Path to binary file to analyze

        Returns:
            Complete activation analysis results

        """
        self.binary_path = Path(binary_path)

        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self.binary_data = self.binary_path.read_bytes()

        if PEFILE_AVAILABLE:
            try:
                self.pe = pefile.PE(str(binary_path))
            except Exception:
                self.pe = None

        activation_patterns = self._detect_activation_patterns()
        registration_patterns = self._detect_registration_patterns()
        trial_patterns = self._detect_trial_patterns()
        hardware_id_patterns = self._detect_hardware_id_patterns()
        license_file_patterns = self._detect_license_file_patterns()
        online_urls = self._extract_activation_urls()

        has_activation = len(activation_patterns) > 0
        has_trial = len(trial_patterns) > 0
        has_hwid = len(hardware_id_patterns) > 0

        strength = self._calculate_protection_strength(
            activation_patterns, registration_patterns, trial_patterns, hardware_id_patterns, license_file_patterns
        )

        return ActivationAnalysisResult(
            activation_patterns=activation_patterns,
            registration_patterns=registration_patterns,
            trial_patterns=trial_patterns,
            hardware_id_patterns=hardware_id_patterns,
            license_file_patterns=license_file_patterns,
            online_activation_urls=online_urls,
            has_activation=has_activation,
            has_trial=has_trial,
            has_hwid_lock=has_hwid,
            protection_strength=strength,
        )

    def _detect_activation_patterns(self) -> list[ActivationPattern]:
        """Detect activation-related patterns in binary."""
        patterns: list[ActivationPattern] = []

        for keyword in self.ACTIVATION_KEYWORDS:
            for match in re.finditer(re.escape(keyword), self.binary_data, re.IGNORECASE):
                offset = match.start()

                context_strings = self._extract_context_strings(offset, 512)
                api_calls = self._find_nearby_api_calls(offset)

                activation_type = self._determine_activation_type(context_strings, api_calls)
                confidence = self._calculate_confidence(context_strings, api_calls, keyword)

                pattern = ActivationPattern(
                    pattern_type=activation_type,
                    address=offset,
                    confidence=confidence,
                    description=f"Activation pattern found: {keyword.decode('utf-8', errors='ignore')}",
                    related_strings=context_strings,
                    api_calls=api_calls,
                )
                patterns.append(pattern)

        return self._deduplicate_patterns(patterns)

    def _detect_registration_patterns(self) -> list[RegistrationPattern]:
        """Detect registration code validation patterns."""
        patterns: list[RegistrationPattern] = []

        for keyword in self.REGISTRATION_KEYWORDS:
            for match in re.finditer(re.escape(keyword), self.binary_data, re.IGNORECASE):
                offset = match.start()

                validation_addr = self._find_validation_function(offset)
                algorithm_hints = self._detect_validation_algorithm(offset)
                reg_type = self._determine_registration_type(keyword, algorithm_hints)

                confidence = 0.7
                if validation_addr:
                    confidence += 0.2
                if algorithm_hints:
                    confidence += 0.1

                pattern = RegistrationPattern(
                    registration_type=reg_type,
                    address=offset,
                    confidence=min(confidence, 1.0),
                    validation_function=validation_addr,
                    algorithm_hints=algorithm_hints,
                )
                patterns.append(pattern)

        return self._deduplicate_registration_patterns(patterns)

    def _detect_trial_patterns(self) -> list[TrialPattern]:
        """Detect trial limitation and expiration patterns."""
        patterns: list[TrialPattern] = []

        for keyword in self.TRIAL_KEYWORDS:
            for match in re.finditer(re.escape(keyword), self.binary_data, re.IGNORECASE):
                offset = match.start()

                storage_location = self._find_trial_storage(offset)
                time_check = self._find_time_check_nearby(offset)
                expiration_check = self._find_expiration_check(offset)

                trial_type = self._determine_trial_type(keyword, storage_location)

                pattern = TrialPattern(
                    trial_type=trial_type,
                    detection_address=offset,
                    storage_location=storage_location,
                    time_check_address=time_check,
                    expiration_check=expiration_check,
                )
                patterns.append(pattern)

        return self._deduplicate_trial_patterns(patterns)

    def _detect_hardware_id_patterns(self) -> list[HardwareIDPattern]:
        """Detect hardware fingerprinting and HWID generation patterns."""
        patterns: list[HardwareIDPattern] = []

        for keyword in self.HWID_KEYWORDS:
            for match in re.finditer(re.escape(keyword), self.binary_data, re.IGNORECASE):
                offset = match.start()

                api_calls = self._find_nearby_api_calls(offset)
                components = self._detect_hwid_components(api_calls)
                hwid_type = self._determine_hwid_type(components)

                pattern = HardwareIDPattern(hwid_type=hwid_type, generation_address=offset, components=components, api_calls=api_calls)
                patterns.append(pattern)

        return self._deduplicate_hwid_patterns(patterns)

    def _detect_license_file_patterns(self) -> list[LicenseFilePattern]:
        """Detect license file handling patterns."""
        patterns: list[LicenseFilePattern] = []

        for keyword in self.LICENSE_FILE_KEYWORDS:
            for match in re.finditer(re.escape(keyword), self.binary_data, re.IGNORECASE):
                offset = match.start()

                file_path = self._extract_license_path(offset)
                file_format = self._detect_license_format(keyword, offset)
                validation_addr = self._find_license_validation(offset)
                encryption = self._detect_encryption_usage(offset)

                pattern = LicenseFilePattern(
                    file_path=file_path, file_format=file_format, validation_address=validation_addr, encryption_used=encryption
                )
                patterns.append(pattern)

        return self._deduplicate_license_patterns(patterns)

    def _extract_activation_urls(self) -> list[str]:
        """Extract activation server URLs from binary."""
        urls: list[str] = []

        for match in re.finditer(self.URL_PATTERN, self.binary_data):
            url = match.group(0).decode("utf-8", errors="ignore")

            if any(
                keyword in url.lower() for keyword in ["activate", "activation", "license", "registration", "auth", "validate", "verify"]
            ):
                urls.append(url)

        return list(set(urls))

    def _extract_context_strings(self, offset: int, window: int = 256) -> list[str]:
        """Extract readable strings near offset."""
        start = max(0, offset - window)
        end = min(len(self.binary_data), offset + window)
        context = self.binary_data[start:end]

        strings: list[str] = []
        for match in re.finditer(rb"[\x20-\x7e]{4,}", context):
            s = match.group(0).decode("utf-8", errors="ignore")
            strings.append(s)

        return strings[:10]

    def _find_nearby_api_calls(self, offset: int, window: int = 512) -> list[str]:
        """Find API calls near offset."""
        api_calls: list[str] = []

        start = max(0, offset - window)
        end = min(len(self.binary_data), offset + window)
        context = self.binary_data[start:end]

        for api in self.ACTIVATION_APIS:
            if api in context:
                api_calls.append(api.decode("utf-8", errors="ignore"))

        return list(set(api_calls))

    def _determine_activation_type(self, strings: list[str], api_calls: list[str]) -> ActivationType:
        """Determine type of activation mechanism."""
        all_text = " ".join(strings + api_calls).lower()

        if any(api in api_calls for api in ["InternetConnectW", "HttpSendRequestW", "WinHttpOpen"]):
            return ActivationType.ONLINE
        if "hardware" in all_text or "hwid" in all_text:
            return ActivationType.HARDWARE_LOCKED
        if "challenge" in all_text or "response" in all_text:
            return ActivationType.CHALLENGE_RESPONSE
        if ".lic" in all_text or "license.dat" in all_text:
            return ActivationType.LICENSE_FILE
        if "registry" in all_text or "RegCreateKeyExW" in " ".join(api_calls):
            return ActivationType.REGISTRY_BASED
        if "phone" in all_text:
            return ActivationType.PHONE_ACTIVATION
        if "trial" in all_text:
            return ActivationType.TRIAL_BASED

        return ActivationType.OFFLINE

    def _calculate_confidence(self, strings: list[str], api_calls: list[str], keyword: bytes) -> float:
        """Calculate confidence score for pattern detection."""
        confidence = 0.5

        if api_calls:
            confidence += 0.2
        if len(strings) >= 3:
            confidence += 0.1
        if len(keyword) > 10:
            confidence += 0.1
        if any("activate" in s.lower() for s in strings):
            confidence += 0.1

        return min(confidence, 1.0)

    def _find_validation_function(self, offset: int) -> int | None:
        """Find nearby function that validates registration codes."""
        if not self.pe:
            return None

        for section in self.pe.sections:
            if section.contains_offset(offset):
                section_data = section.get_data()

                call_pattern = rb"\xE8.{4}"
                for match in re.finditer(call_pattern, section_data):
                    call_offset = section.PointerToRawData + match.start()
                    if abs(call_offset - offset) < 1024:
                        return call_offset

        return None

    def _detect_validation_algorithm(self, offset: int) -> list[str]:
        """Detect hints about validation algorithm used."""
        hints: list[str] = []

        window = 1024
        start = max(0, offset - window)
        end = min(len(self.binary_data), offset + window)
        context = self.binary_data[start:end]

        if b"CryptHashData" in context or b"CryptCreateHash" in context:
            hints.append("cryptographic_hash")
        if b"md5" in context.lower() or b"MD5" in context:
            hints.append("md5")
        if b"sha" in context.lower() or b"SHA" in context:
            hints.append("sha")
        if b"rsa" in context.lower() or b"RSA" in context:
            hints.append("rsa")
        if b"aes" in context.lower() or b"AES" in context:
            hints.append("aes")
        if b"checksum" in context.lower():
            hints.append("checksum")

        return hints

    def _determine_registration_type(self, keyword: bytes, hints: list[str]) -> RegistrationType:
        """Determine type of registration system."""
        kw = keyword.decode("utf-8", errors="ignore").lower()

        if "serial" in kw:
            return RegistrationType.SERIAL_NUMBER
        if "product key" in kw:
            return RegistrationType.PRODUCT_KEY
        if "activation" in kw:
            return RegistrationType.ACTIVATION_CODE
        if "license" in kw:
            return RegistrationType.LICENSE_KEY

        return RegistrationType.USER_REGISTRATION

    def _find_trial_storage(self, offset: int) -> str | None:
        """Find where trial data is stored."""
        context_strings = self._extract_context_strings(offset, 512)
        api_calls = self._find_nearby_api_calls(offset)

        if any("Reg" in api for api in api_calls):
            for s in context_strings:
                if "software\\" in s.lower() or "hkey_" in s.lower():
                    return f"registry:{s}"

        for s in context_strings:
            if ".dat" in s or ".cfg" in s or ".ini" in s:
                return f"file:{s}"

        return None

    def _find_time_check_nearby(self, offset: int) -> int | None:
        """Find time comparison operations near offset."""
        if not self.pe:
            return None

        for section in self.pe.sections:
            if section.contains_offset(offset):
                section_data = section.get_data()

                cmp_pattern = rb"[\x3B\x39\x83]"
                for match in re.finditer(cmp_pattern, section_data):
                    cmp_offset = section.PointerToRawData + match.start()
                    if abs(cmp_offset - offset) < 256:
                        return cmp_offset

        return None

    def _find_expiration_check(self, offset: int) -> int | None:
        """Find expiration validation logic."""
        window = 512
        start = max(0, offset - window)
        end = min(len(self.binary_data), offset + window)
        context = self.binary_data[start:end]

        if b"expired" in context.lower() or b"expir" in context.lower():
            for match in re.finditer(rb"expir", context, re.IGNORECASE):
                return start + match.start()

        return None

    def _determine_trial_type(self, keyword: bytes, storage: str | None) -> str:
        """Determine type of trial mechanism."""
        kw = keyword.decode("utf-8", errors="ignore").lower()

        if "days" in kw:
            return "time_limited"
        if "evaluation" in kw:
            return "evaluation_version"
        if "demo" in kw:
            return "demo_mode"
        if storage and "registry" in storage:
            return "registry_trial"
        if storage and "file" in storage:
            return "file_trial"

        return "trial_limitation"

    def _detect_hwid_components(self, api_calls: list[str]) -> list[str]:
        """Detect which hardware components are fingerprinted."""
        components: list[str] = []

        if "GetVolumeInformationW" in api_calls:
            components.append("volume_serial")
        if "GetComputerNameW" in api_calls:
            components.append("computer_name")
        if "GetUserNameW" in api_calls:
            components.append("username")
        if "GetSystemInfo" in api_calls:
            components.append("system_info")

        return components

    def _determine_hwid_type(self, components: list[str]) -> str:
        """Determine type of hardware fingerprinting."""
        if len(components) >= 3:
            return "multi_component"
        if "volume_serial" in components:
            return "volume_based"
        if "system_info" in components:
            return "system_based"

        return "simple_hwid"

    def _extract_license_path(self, offset: int) -> str | None:
        """Extract license file path from binary."""
        strings = self._extract_context_strings(offset, 512)

        for s in strings:
            if any(ext in s.lower() for ext in [".lic", ".key", ".dat", "license"]):
                if "\\" in s or "/" in s or ":" in s:
                    return s

        return None

    def _detect_license_format(self, keyword: bytes, offset: int) -> str | None:
        """Detect license file format."""
        kw = keyword.decode("utf-8", errors="ignore").lower()

        if ".xml" in kw:
            return "xml"
        if ".json" in kw:
            return "json"
        if ".dat" in kw or ".key" in kw:
            return "binary"

        context_strings = self._extract_context_strings(offset, 256)
        for s in context_strings:
            if "xml" in s.lower():
                return "xml"
            if "json" in s.lower():
                return "json"

        return "unknown"

    def _find_license_validation(self, offset: int) -> int | None:
        """Find license file validation function."""
        api_calls = self._find_nearby_api_calls(offset, 1024)

        if any("Crypt" in api for api in api_calls):
            return offset

        return None

    def _detect_encryption_usage(self, offset: int) -> bool:
        """Detect if license data is encrypted."""
        api_calls = self._find_nearby_api_calls(offset, 512)

        crypto_apis = ["CryptHashData", "CryptCreateHash", "CryptEncrypt", "CryptDecrypt"]
        return any(api in api_calls for api in crypto_apis)

    def _calculate_protection_strength(
        self,
        activation: list[ActivationPattern],
        registration: list[RegistrationPattern],
        trial: list[TrialPattern],
        hwid: list[HardwareIDPattern],
        license_file: list[LicenseFilePattern],
    ) -> float:
        """Calculate overall protection strength score."""
        score = 0.0

        if activation:
            score += 0.3
        if registration:
            score += 0.2
        if trial:
            score += 0.1
        if hwid:
            score += 0.25
        if license_file:
            score += 0.15

        return min(score, 1.0)

    def _deduplicate_patterns(self, patterns: list[ActivationPattern]) -> list[ActivationPattern]:
        """Remove duplicate activation patterns."""
        seen: set[int] = set()
        unique: list[ActivationPattern] = []

        for pattern in patterns:
            addr_key = pattern.address // 64
            if addr_key not in seen:
                seen.add(addr_key)
                unique.append(pattern)

        return unique

    def _deduplicate_registration_patterns(self, patterns: list[RegistrationPattern]) -> list[RegistrationPattern]:
        """Remove duplicate registration patterns."""
        seen: set[int] = set()
        unique: list[RegistrationPattern] = []

        for pattern in patterns:
            addr_key = pattern.address // 64
            if addr_key not in seen:
                seen.add(addr_key)
                unique.append(pattern)

        return unique

    def _deduplicate_trial_patterns(self, patterns: list[TrialPattern]) -> list[TrialPattern]:
        """Remove duplicate trial patterns."""
        seen: set[int] = set()
        unique: list[TrialPattern] = []

        for pattern in patterns:
            addr_key = pattern.detection_address // 64
            if addr_key not in seen:
                seen.add(addr_key)
                unique.append(pattern)

        return unique

    def _deduplicate_hwid_patterns(self, patterns: list[HardwareIDPattern]) -> list[HardwareIDPattern]:
        """Remove duplicate HWID patterns."""
        seen: set[int] = set()
        unique: list[HardwareIDPattern] = []

        for pattern in patterns:
            addr_key = pattern.generation_address // 64
            if addr_key not in seen:
                seen.add(addr_key)
                unique.append(pattern)

        return unique

    def _deduplicate_license_patterns(self, patterns: list[LicenseFilePattern]) -> list[LicenseFilePattern]:
        """Remove duplicate license file patterns."""
        seen: set[str | None] = set()
        unique: list[LicenseFilePattern] = []

        for pattern in patterns:
            if pattern.file_path not in seen:
                seen.add(pattern.file_path)
                unique.append(pattern)

        return unique
