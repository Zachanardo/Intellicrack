"""SecuROM Protection Detection Module.

Provides comprehensive detection of SecuROM v7.x and v8.x copy protection including
kernel drivers, services, registry keys, activation state, and protected executable signatures.
"""

import ctypes
import winreg
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


@dataclass
class SecuROMVersion:
    """SecuROM version information."""

    major: int
    minor: int
    build: int
    variant: str

    def __str__(self) -> str:
        """Return string representation of SecuROM version."""
        return f"SecuROM {self.major}.{self.minor}.{self.build} {self.variant}"


@dataclass
class SecuROMActivation:
    """SecuROM activation state information."""

    is_activated: bool
    activation_date: str | None
    product_key: str | None
    machine_id: str | None
    activation_count: int
    remaining_activations: int


@dataclass
class SecuROMDetection:
    """Results from SecuROM detection analysis."""

    detected: bool
    version: SecuROMVersion | None
    drivers: list[str]
    services: list[str]
    registry_keys: list[str]
    protected_sections: list[str]
    activation_state: SecuROMActivation | None
    confidence: float
    details: dict[str, Any]


class SecuROMDetector:
    """Comprehensive SecuROM v7.x and v8.x copy protection detection system.

    Detects SecuROM through multiple indicators including kernel drivers,
    Windows services, registry artifacts, activation state, and executable signatures.
    """

    DRIVER_NAMES = [
        "secdrv.sys",
        "SecuROM.sys",
        "SR7.sys",
        "SR8.sys",
        "SecuROMv7.sys",
        "SecuROMv8.sys",
        "atapi.sys",
    ]

    SERVICE_NAMES = [
        "SecuROM",
        "SecuROM User Access Service",
        "SecuROM7",
        "SecuROM8",
        "UserAccess7",
        "UserAccess8",
        "SecDrv",
        "SRService",
    ]

    REGISTRY_KEYS = [
        r"SYSTEM\CurrentControlSet\Services\secdrv",
        r"SYSTEM\CurrentControlSet\Services\SecuROM",
        r"SYSTEM\CurrentControlSet\Services\UserAccess7",
        r"SYSTEM\CurrentControlSet\Services\UserAccess8",
        r"SOFTWARE\SecuROM",
        r"SOFTWARE\Wow6432Node\SecuROM",
        r"SOFTWARE\Sony DADC",
        r"SOFTWARE\Wow6432Node\Sony DADC",
    ]

    ACTIVATION_KEYS = [
        r"SOFTWARE\SecuROM\Activation",
        r"SOFTWARE\Wow6432Node\SecuROM\Activation",
        r"SOFTWARE\Sony DADC\SecuROM\Activation",
        r"SOFTWARE\Wow6432Node\Sony DADC\SecuROM\Activation",
    ]

    SECTION_NAMES = [
        ".securom",
        ".sdata",
        ".cms_t",
        ".cms_d",
        ".rdata2",
        ".protec",
        ".sr7",
        ".sr8",
    ]

    def __init__(self) -> None:
        """Initialize SecuROM detector."""
        self._advapi32: Any = None
        self._kernel32: Any = None
        self._setup_winapi()
        self._yara_rules: Any | None = self._compile_yara_rules() if YARA_AVAILABLE else None

    def _setup_winapi(self) -> None:
        """Set up Windows API functions with proper signatures.

        Initializes WinAPI function pointers for service control manager access.
        Safely handles failures if WinAPI initialization is not possible.

        Raises:
            None: Exceptions are caught and logged as debug messages.

        """
        try:
            self._advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            self._advapi32.OpenSCManagerW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.DWORD,
            ]
            self._advapi32.OpenSCManagerW.restype = wintypes.HANDLE

            self._advapi32.OpenServiceW.argtypes = [
                wintypes.HANDLE,
                wintypes.LPCWSTR,
                wintypes.DWORD,
            ]
            self._advapi32.OpenServiceW.restype = wintypes.HANDLE

            self._advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
            self._advapi32.CloseServiceHandle.restype = wintypes.BOOL

        except Exception as e:
            logger.debug("WinAPI setup failed: %s", e)

    def _compile_yara_rules(self) -> object | None:
        """Compile YARA rules for SecuROM signature detection.

        Compiles YARA rules for identifying SecuROM v7.x, v8.x signatures,
        loader patterns, disc authentication, and activation systems.

        Returns:
            Compiled YARA rules object or None if YARA is unavailable or compilation fails.

        Raises:
            None: Exceptions are caught and None is returned.

        """
        if not YARA_AVAILABLE:
            return None

        rules_source = """
        rule SecuROM_v7 {
            meta:
                description = "SecuROM v7.x protection"
                version = "7.x"
            strings:
                $prot1 = "Sony DADC" ascii
                $prot2 = "SecuROM" ascii
                $driver1 = "UserAccess7" ascii nocase
                $driver2 = "SR7" ascii nocase
                $sig1 = { 55 8B EC 83 EC ?? 53 56 57 8B 7D ?? 8B F1 85 FF }
                $sig2 = { E8 ?? ?? ?? ?? 8B F0 85 F6 74 ?? 8B CE E8 }
                $activation = "ProductActivation" ascii
            condition:
                (1 of ($prot*) or 1 of ($driver*)) and (1 of ($sig*) or $activation)
        }

        rule SecuROM_v8 {
            meta:
                description = "SecuROM v8.x protection with PA (Product Activation)"
                version = "8.x"
            strings:
                $prot = "Sony DADC" ascii
                $driver = "UserAccess8" ascii nocase
                $sr8 = "SR8" ascii nocase
                $sig1 = { 48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F9 }
                $sig2 = { 40 53 48 83 EC ?? 48 8B D9 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 84 C0 }
                $activation = "ActivationLimit" ascii
                $online = "OnlineActivation" ascii
                $challenge = "ChallengeResponse" ascii
            condition:
                $prot and ($driver or $sr8) and (1 of ($sig*) or 1 of ($activation, $online, $challenge))
        }

        rule SecuROM_Loader {
            meta:
                description = "SecuROM protection loader initialization"
            strings:
                $loader1 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 }
                $loader2 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 8D BD ?? ?? FF FF B9 }
                $check1 = "KERNEL32.dll" ascii nocase
                $check2 = "LoadLibraryA" ascii
                $check3 = "GetProcAddress" ascii
            condition:
                1 of ($loader*) and 2 of ($check*)
        }

        rule SecuROM_Disc_Auth {
            meta:
                description = "SecuROM disc authentication routines"
            strings:
                $api1 = "DeviceIoControl" ascii
                $api2 = "CreateFileA" ascii
                $scsi1 = "\\\\.\\Scsi" ascii
                $scsi2 = "\\\\.\\CdRom" ascii
                $ioctl = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 6A 03 6A 00 6A 00 }
                $signature = "DiscSignature" ascii
                $fingerprint = "DiscFingerprint" ascii
            condition:
                2 of ($api*) and 1 of ($scsi*) and ($ioctl or $signature or $fingerprint)
        }

        rule SecuROM_Activation_System {
            meta:
                description = "SecuROM v8+ product activation system"
            strings:
                $activate = "ProductActivation" ascii
                $deactivate = "DeactivateProduct" ascii
                $challenge = "GetActivationChallenge" ascii
                $response = "SubmitActivationResponse" ascii
                $hwid = "MachineIdentifier" ascii
                $limit = "ActivationLimit" ascii
                $count = "ActivationCount" ascii
                $online = "https://" ascii
                $registry = "SOFTWARE\\SecuROM\\Activation" ascii wide
            condition:
                3 of them
        }

        rule SecuROM_Trigger_Validation {
            meta:
                description = "SecuROM online validation trigger points"
            strings:
                $trigger1 = "ValidateLicense" ascii
                $trigger2 = "CheckActivationStatus" ascii
                $trigger3 = "VerifyProductKey" ascii
                $trigger4 = "ContactActivationServer" ascii
                $callback = "WinHttpSendRequest" ascii
                $callback2 = "InternetOpenUrl" ascii
                $timer = "CreateWaitableTimer" ascii
            condition:
                2 of ($trigger*) and 1 of ($callback*)
        }
        """

        try:
            return yara.compile(source=rules_source)
        except Exception:
            return None

    def detect(self, target_path: Path) -> SecuROMDetection:
        """Perform comprehensive SecuROM detection.

        Analyzes target executable for SecuROM copy protection by scanning
        kernel drivers, Windows services, registry keys, PE sections, and
        YARA signatures. Calculates composite confidence score combining all
        detection indicators.

        Args:
            target_path: Path to executable to analyze for SecuROM protection.

        Returns:
            SecuROMDetection: Detection results containing version info, detected
                drivers/services/registry keys, confidence score, and detailed
                analysis metadata.

        Raises:
            None: All exceptions are caught and handled gracefully.

        """
        drivers = self._detect_drivers()
        services = self._detect_services()
        registry_keys = self._detect_registry_keys()
        activation_state = self._detect_activation_state()

        sections = []
        version = None
        yara_matches = []

        if target_path.exists():
            sections = self._detect_protected_sections(target_path)
            version = self._detect_version(target_path)

            if self._yara_rules:
                yara_matches = self._yara_scan(target_path)

        confidence = self._calculate_confidence(
            drivers,
            services,
            registry_keys,
            sections,
            yara_matches,
            activation_state,
        )

        detected = confidence > 0.5

        details = {
            "yara_matches": yara_matches,
            "driver_paths": self._get_driver_paths(drivers),
            "service_status": self._get_service_status(services),
            "disc_auth_present": self._detect_disc_authentication(target_path)
            if target_path.exists()
            else False,
            "online_activation_present": self._detect_online_activation(target_path)
            if target_path.exists()
            else False,
            "encryption_detected": self._detect_encryption(target_path)
            if target_path.exists()
            else False,
        }

        return SecuROMDetection(
            detected=detected,
            version=version,
            drivers=drivers,
            services=services,
            registry_keys=registry_keys,
            protected_sections=sections,
            activation_state=activation_state,
            confidence=confidence,
            details=details,
        )

    def _detect_drivers(self) -> list[str]:
        """Detect SecuROM kernel drivers.

        Scans System32/drivers directory for known SecuROM driver files
        and verifies them by checking for SecuROM-specific indicators.

        Returns:
            List of detected SecuROM driver names present on the system.

        Raises:
            None: All exceptions are handled gracefully.

        """
        detected = []

        system_root = Path(r"C:\Windows\System32\drivers")
        if system_root.exists():
            for driver_name in self.DRIVER_NAMES:
                driver_path = system_root / driver_name
                if driver_path.exists() and self._is_securom_driver(driver_path):
                    detected.append(driver_name)

        return detected

    def _is_securom_driver(self, driver_path: Path) -> bool:
        """Verify if driver is actually a SecuROM driver.

        Checks driver file for SecuROM-specific string indicators like
        "Sony DADC", "SecuROM", "UserAccess", "SR7", "SR8".

        Args:
            driver_path: Path to driver file to verify.

        Returns:
            True if driver contains SecuROM indicators, False otherwise.

        Raises:
            None: All exceptions are caught and False is returned.

        """
        try:
            with open(driver_path, "rb") as f:
                data = f.read(8192)

            securom_indicators = [
                b"Sony DADC",
                b"SecuROM",
                b"UserAccess",
                b"SR7",
                b"SR8",
            ]

            return any(indicator in data for indicator in securom_indicators)

        except Exception:
            return False

    def _detect_services(self) -> list[str]:
        """Detect SecuROM Windows services.

        Uses Windows Service Control Manager API to enumerate installed
        services and identify SecuROM-related services.

        Returns:
            List of detected SecuROM service names installed on the system.

        Raises:
            None: All exceptions are caught and empty list is returned.

        """
        if not self._advapi32:
            return []

        detected = []
        SC_MANAGER_ALL_ACCESS = 0xF003F
        SERVICE_QUERY_CONFIG = 0x0001

        try:
            sc_manager = self._advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
            if not sc_manager:
                return []

            try:
                for service_name in self.SERVICE_NAMES:
                    if service_handle := self._advapi32.OpenServiceW(
                        sc_manager,
                        service_name,
                        SERVICE_QUERY_CONFIG,
                    ):
                        detected.append(service_name)
                        self._advapi32.CloseServiceHandle(service_handle)
            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            logger.debug("Service detection failed: %s", e)

        return detected

    def _detect_registry_keys(self) -> list[str]:
        """Detect SecuROM registry keys.

        Scans Windows registry for SecuROM configuration and activation keys
        in HKEY_LOCAL_MACHINE.

        Returns:
            List of detected SecuROM registry key paths present on the system.

        Raises:
            None: Registry errors are caught and processing continues.

        """
        detected = []

        for key_path in self.REGISTRY_KEYS:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                winreg.CloseKey(key)
                detected.append(key_path)
            except OSError:
                pass

        for key_path in self.ACTIVATION_KEYS:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                winreg.CloseKey(key)
                detected.append(key_path)
            except OSError:
                pass

        return detected

    def _detect_activation_state(self) -> SecuROMActivation | None:
        """Detect SecuROM activation state from registry.

        Queries Windows registry for SecuROM activation status, product key,
        machine identifier, and activation count information.

        Returns:
            SecuROMActivation object with activation details if registry key
            exists, None otherwise.

        Raises:
            None: Registry errors are caught and processing continues.

        """
        for key_path in self.ACTIVATION_KEYS:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)

                try:
                    is_activated_val, _ = winreg.QueryValueEx(key, "Activated")
                    is_activated = bool(is_activated_val)
                except OSError:
                    is_activated = False

                try:
                    activation_date, _ = winreg.QueryValueEx(key, "ActivationDate")
                except OSError:
                    activation_date = None

                try:
                    product_key, _ = winreg.QueryValueEx(key, "ProductKey")
                except OSError:
                    product_key = None

                try:
                    machine_id, _ = winreg.QueryValueEx(key, "MachineID")
                except OSError:
                    machine_id = None

                try:
                    activation_count, _ = winreg.QueryValueEx(key, "ActivationCount")
                except OSError:
                    activation_count = 0

                try:
                    max_activations, _ = winreg.QueryValueEx(key, "MaxActivations")
                    remaining = max_activations - activation_count
                except OSError:
                    remaining = -1

                winreg.CloseKey(key)

                return SecuROMActivation(
                    is_activated=is_activated,
                    activation_date=activation_date,
                    product_key=product_key,
                    machine_id=machine_id,
                    activation_count=activation_count,
                    remaining_activations=remaining,
                )

            except OSError:
                continue

        return None

    def _detect_protected_sections(self, target_path: Path) -> list[str]:
        """Detect SecuROM protected PE sections.

        Analyzes PE executable sections for SecuROM indicators: known section
        names, encrypted sections, and high entropy sections indicating encryption.

        Args:
            target_path: Path to PE executable to analyze.

        Returns:
            List of protected/encrypted section names found in the executable.

        Raises:
            None: All exceptions are caught and empty list is returned.

        """
        if not PEFILE_AVAILABLE:
            return []

        detected = []

        try:
            pe = pefile.PE(str(target_path))

            for section in pe.sections:
                section_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")

                if any(sr_name in section_name.lower() for sr_name in self.SECTION_NAMES):
                    detected.append(section_name)

                if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0 and section.Characteristics & 0x20000000:
                    detected.append(f"{section_name} (encrypted)")

                entropy = self._calculate_section_entropy(section.get_data())
                if entropy > 7.5 and ".text" not in section_name.lower():
                    detected.append(f"{section_name} (high entropy: {entropy:.2f})")

            pe.close()

        except Exception as e:
            logger.debug("Protected section detection failed: %s", e)

        return detected

    def _calculate_section_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of section data.

        Computes Shannon entropy value for binary data to detect encryption
        or obfuscation. Higher entropy (>7.5) typically indicates encryption.

        Args:
            data: Binary data bytes to analyze.

        Returns:
            Shannon entropy value as float between 0.0 and 8.0.

        Raises:
            None: All exceptions are handled gracefully.

        """
        if not data:
            return 0.0

        import math
        from collections import Counter

        counter = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _detect_version(self, target_path: Path) -> SecuROMVersion | None:
        """Detect SecuROM version from executable.

        Analyzes PE version info and embedded signatures to determine SecuROM
        version (7.x vs 8.x) and variant (standard vs PA with Product Activation).

        Args:
            target_path: Path to PE executable to analyze.

        Returns:
            SecuROMVersion with detected version and variant, or None if detection fails.

        Raises:
            None: All exceptions are caught and None is returned.

        """
        if not PEFILE_AVAILABLE:
            return None

        try:
            pe = pefile.PE(str(target_path))

            if hasattr(pe, "VS_VERSIONINFO"):
                for entry in pe.FileInfo:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            for _key, value in st.entries.items():
                                if b"SecuROM" in value or b"Sony DADC" in value:
                                    if version_result := self._parse_version_string(
                                        value.decode("utf-8", errors="ignore")
                                    ):
                                        pe.close()
                                        return version_result

            data = pe.get_memory_mapped_image()

            if b"UserAccess7" in data or b"SR7" in data:
                pe.close()
                return SecuROMVersion(7, 0, 0, "Standard")
            if b"UserAccess8" in data or b"SR8" in data:
                if b"ProductActivation" in data or b"OnlineActivation" in data:
                    pe.close()
                    return SecuROMVersion(8, 0, 0, "PA (Product Activation)")
                pe.close()
                return SecuROMVersion(8, 0, 0, "Standard")

            pe.close()

        except Exception as e:
            logger.debug("Version detection failed: %s", e)

        return None

    def _parse_version_string(self, version_str: str) -> SecuROMVersion | None:
        """Parse version string to extract SecuROM version.

        Extracts version numbers and variant information from SecuROM version
        strings using regular expression matching.

        Args:
            version_str: Version string to parse (e.g., "SecuROM 7.50.0").

        Returns:
            SecuROMVersion with parsed version info, or None if parsing fails.

        Raises:
            None: All exceptions are handled gracefully.

        """
        import re

        pattern = r"SecuROM[^\d]*(\d+)\.(\d+)\.?(\d*)"
        if match := re.search(pattern, version_str):
            major = int(match.group(1))
            minor = int(match.group(2))
            build = int(match.group(3)) if match.group(3) else 0

            variant = (
                "PA"
                if "activation" in version_str.lower() or "pa" in version_str.lower()
                else "Standard"
            )

            return SecuROMVersion(major, minor, build, variant)

        return None

    def _yara_scan(self, target_path: Path) -> list[dict[str, str]]:
        """Scan executable with YARA rules.

        Runs compiled YARA rules against target executable to detect SecuROM
        signatures, patterns, and behavioral indicators.

        Args:
            target_path: Path to executable file to scan.

        Returns:
            List of dictionaries containing matched YARA rules with metadata
            (rule name, version, description).

        Raises:
            None: All exceptions are caught and empty list is returned.

        """
        if not self._yara_rules:
            return []

        matches = []

        try:
            results = self._yara_rules.match(str(target_path))

            matches.extend(
                {
                    "rule": match.rule,
                    "version": match.meta.get("version", "unknown"),
                    "description": match.meta.get("description", ""),
                }
                for match in results
            )
        except Exception as e:
            logger.debug("YARA matching failed: %s", e)

        return matches

    def _calculate_confidence(
        self,
        drivers: list[str],
        services: list[str],
        registry_keys: list[str],
        sections: list[str],
        yara_matches: list[dict[str, str]],
        activation_state: SecuROMActivation | None,
    ) -> float:
        """Calculate detection confidence score.

        Combines detection indicators with weighted scoring: drivers (30%),
        services (25%), registry keys (20%), sections (15%), YARA matches (5%),
        and activation state (5%).

        Args:
            drivers: List of detected SecuROM driver names.
            services: List of detected SecuROM service names.
            registry_keys: List of detected SecuROM registry key paths.
            sections: List of detected protected PE sections.
            yara_matches: List of YARA rule matches found.
            activation_state: SecuROMActivation object or None.

        Returns:
            Confidence score as float between 0.0 and 1.0.

        Raises:
            None: All exceptions are handled gracefully.

        """
        score = 0.0

        if drivers:
            score += 0.30 * min(len(drivers) / 2, 1.0)

        if services:
            score += 0.25 * min(len(services) / 2, 1.0)

        if registry_keys:
            score += 0.20 * min(len(registry_keys) / 2, 1.0)

        if sections:
            score += 0.15 * min(len(sections) / 2, 1.0)

        if yara_matches:
            score += 0.05 * min(len(yara_matches) / 2, 1.0)

        if activation_state:
            score += 0.05

        return min(score, 1.0)

    def _get_driver_paths(self, drivers: list[str]) -> dict[str, str]:
        """Get full paths for detected drivers.

        Maps driver names to their full filesystem paths on the system.

        Args:
            drivers: List of detected driver names.

        Returns:
            Dictionary mapping driver names to full System32/drivers paths.

        Raises:
            None: All exceptions are handled gracefully.

        """
        paths = {}
        system_root = Path(r"C:\Windows\System32\drivers")

        for driver in drivers:
            driver_path = system_root / driver
            if driver_path.exists():
                paths[driver] = str(driver_path)

        return paths

    def _get_service_status(self, services: list[str]) -> dict[str, str]:
        """Get status information for detected services.

        Queries Windows Service Control Manager to retrieve current state
        (STOPPED, RUNNING, etc.) for each detected service.

        Args:
            services: List of service names to query.

        Returns:
            Dictionary mapping service names to their current status strings.

        Raises:
            None: All exceptions are caught and empty dict is returned.

        """
        if not self._advapi32:
            return {}

        status_info = {}
        SC_MANAGER_ALL_ACCESS = 0xF003F
        SERVICE_QUERY_STATUS = 0x0004

        class SERVICE_STATUS(ctypes.Structure):  # noqa: N801
            """Windows SERVICE_STATUS structure for service state information.

            Used by Windows Service Control Manager to report service state,
            controls accepted, exit codes, and checkpoint information.

            Attributes:
                dwServiceType: Type of service (SHARE_PROCESS, WIN32_OWN_PROCESS, etc).
                dwCurrentState: Current service state (STOPPED, RUNNING, etc).

                dwControlsAccepted: Control codes accepted by the service.
                dwWin32ExitCode: Win32 exit code from service.
                dwServiceSpecificExitCode: Service-specific exit code.
                dwCheckPoint: Checkpoint value for pending operations.
                dwWaitHint: Estimated wait time in milliseconds.

            """

            _fields_ = [
                ("dwServiceType", wintypes.DWORD),
                ("dwCurrentState", wintypes.DWORD),
                ("dwControlsAccepted", wintypes.DWORD),
                ("dwWin32ExitCode", wintypes.DWORD),
                ("dwServiceSpecificExitCode", wintypes.DWORD),
                ("dwCheckPoint", wintypes.DWORD),
                ("dwWaitHint", wintypes.DWORD),
            ]

        states = {
            1: "STOPPED",
            2: "START_PENDING",
            3: "STOP_PENDING",
            4: "RUNNING",
            5: "CONTINUE_PENDING",
            6: "PAUSE_PENDING",
            7: "PAUSED",
        }

        try:
            sc_manager = self._advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
            if not sc_manager:
                return {}

            try:
                for service_name in services:
                    if service_handle := self._advapi32.OpenServiceW(
                        sc_manager,
                        service_name,
                        SERVICE_QUERY_STATUS,
                    ):
                        status = SERVICE_STATUS()
                        if hasattr(self._advapi32, "QueryServiceStatus"):
                            self._advapi32.QueryServiceStatus.argtypes = [
                                wintypes.HANDLE,
                                ctypes.POINTER(SERVICE_STATUS),
                            ]
                            if self._advapi32.QueryServiceStatus(
                                service_handle, ctypes.byref(status)
                            ):
                                status_info[service_name] = states.get(
                                    status.dwCurrentState, "UNKNOWN"
                                )

                        self._advapi32.CloseServiceHandle(service_handle)
            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            logger.debug("Service status query failed: %s", e)

        return status_info

    def _detect_disc_authentication(self, target_path: Path) -> bool:
        """Detect presence of disc authentication mechanisms.

        Scans executable for disc authentication API calls and signature
        verification routines typical of SecuROM's anti-piracy scheme.

        Args:
            target_path: Path to executable to analyze.

        Returns:
            True if disc authentication indicators are found, False otherwise.

        Raises:
            None: All exceptions are caught and False is returned.

        """
        try:
            with open(target_path, "rb") as f:
                data = f.read()

            disc_indicators = [
                b"DiscSignature",
                b"DiscFingerprint",
                b"\\\\.\\Scsi",
                b"\\\\.\\CdRom",
                b"DeviceIoControl",
            ]

            return any(indicator in data for indicator in disc_indicators)

        except Exception:
            return False

    def _detect_online_activation(self, target_path: Path) -> bool:
        """Detect presence of online activation mechanisms.

        Scans executable for online activation endpoints, challenge-response
        protocols, and activation server communication routines.

        Args:
            target_path: Path to executable to analyze.

        Returns:
            True if 2 or more online activation indicators are found, False otherwise.

        Raises:
            None: All exceptions are caught and False is returned.

        """
        try:
            with open(target_path, "rb") as f:
                data = f.read()

            activation_indicators = [
                b"ProductActivation",
                b"OnlineActivation",
                b"ActivationServer",
                b"https://",
                b"WinHttpSendRequest",
                b"InternetOpenUrl",
            ]

            return sum(bool(indicator in data)
                   for indicator in activation_indicators) >= 2

        except Exception:
            return False

    def _detect_encryption(self, target_path: Path) -> bool:
        """Detect presence of SecuROM encryption.

        Analyzes PE sections for high entropy values (>7.8) indicating
        encrypted or obfuscated code typical of SecuROM protection.

        Args:
            target_path: Path to PE executable to analyze.

        Returns:
            True if high-entropy encrypted section is detected, False otherwise.

        Raises:
            None: All exceptions are caught and False is returned.

        """
        if not PEFILE_AVAILABLE:
            return False

        try:
            pe = pefile.PE(str(target_path))

            for section in pe.sections:
                entropy = self._calculate_section_entropy(section.get_data())
                if entropy > 7.8:
                    pe.close()
                    return True

            pe.close()

        except Exception as e:
            logger.debug("Disc authentication detection failed: %s", e)

        return False
