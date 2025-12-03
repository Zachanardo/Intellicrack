"""StarForce Protection Detection Module.

Provides comprehensive detection of StarForce copy protection system including
kernel drivers, services, registry keys, and protected executable signatures.
"""

import ctypes
import logging
import winreg
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path


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
class StarForceVersion:
    """StarForce version information."""

    major: int
    minor: int
    build: int
    variant: str

    def __str__(self) -> str:
        """Return string representation of StarForce version."""
        return f"StarForce {self.major}.{self.minor}.{self.build} {self.variant}"


@dataclass
class StarForceDetection:
    """Results from StarForce detection analysis."""

    detected: bool
    version: StarForceVersion | None
    drivers: list[str]
    services: list[str]
    registry_keys: list[str]
    protected_sections: list[str]
    confidence: float
    details: dict[str, any]


class StarForceDetector:
    """Comprehensive StarForce copy protection detection system.

    Detects StarForce through multiple indicators including kernel drivers,
    Windows services, registry artifacts, and executable signatures.
    """

    DRIVER_NAMES = [
        "sfdrv01.sys",
        "sfdrv01a.sys",
        "sfdrv01b.sys",
        "sfvfs02.sys",
        "sfvfs03.sys",
        "sfvfs04.sys",
        "sfsync02.sys",
        "sfsync03.sys",
        "sfsync04.sys",
        "sfhlp01.sys",
        "sfhlp02.sys",
        "StarForce.sys",
        "StarForce3.sys",
        "StarForce5.sys",
    ]

    SERVICE_NAMES = [
        "StarForce Protection",
        "StarForce",
        "StarForce1",
        "StarForce2",
        "StarForce3",
        "StarForce4",
        "StarForce5",
        "SFVFS",
        "SFDRV",
        "SFSYNC",
        "SFHLP",
    ]

    REGISTRY_KEYS = [
        r"SYSTEM\CurrentControlSet\Services\sfdrv01",
        r"SYSTEM\CurrentControlSet\Services\sfdrv01a",
        r"SYSTEM\CurrentControlSet\Services\sfdrv01b",
        r"SYSTEM\CurrentControlSet\Services\sfvfs02",
        r"SYSTEM\CurrentControlSet\Services\sfvfs03",
        r"SYSTEM\CurrentControlSet\Services\sfsync02",
        r"SYSTEM\CurrentControlSet\Services\StarForce",
        r"SOFTWARE\Protection Technology\StarForce",
        r"SOFTWARE\Wow6432Node\Protection Technology\StarForce",
    ]

    SECTION_NAMES = [".sforce", ".sf", ".protect", ".sfdata", ".sfcode", ".sfeng", ".sfrsc"]

    def __init__(self) -> None:
        """Initialize StarForce detector."""
        self.logger = logging.getLogger(__name__)
        self._advapi32 = None
        self._kernel32 = None
        self._setup_winapi()
        self._yara_rules = self._compile_yara_rules() if YARA_AVAILABLE else None

    def _setup_winapi(self) -> None:
        """Set up Windows API functions with proper signatures."""
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
            self.logger.debug(f"Failed to setup Windows API functions: {e}")

    def _compile_yara_rules(self) -> object | None:
        """Compile YARA rules for StarForce signature detection."""
        if not YARA_AVAILABLE:
            return None

        rules_source = """
        rule StarForce_v3 {
            meta:
                description = "StarForce v3.x protection"
                version = "3.x"
            strings:
                $prot1 = "Protection Technology" ascii
                $prot2 = "StarForce Technologies" ascii
                $driver1 = "sfdrv01" ascii nocase
                $driver2 = "sfvfs02" ascii nocase
                $sig1 = { 55 8B EC 83 EC ?? 53 56 57 8B 7D ?? 85 FF 74 ?? 8B 75 ?? 85 F6 }
                $sig2 = { E8 ?? ?? ?? ?? 8B F0 85 F6 74 ?? 68 ?? ?? ?? ?? 56 }
            condition:
                (2 of ($prot*) or 1 of ($driver*)) and 1 of ($sig*)
        }

        rule StarForce_v4 {
            meta:
                description = "StarForce v4.x protection"
                version = "4.x"
            strings:
                $prot = "Protection Technology" ascii
                $driver = "sfvfs03" ascii nocase
                $sig1 = { 8B FF 55 8B EC 83 EC ?? 53 8B 5D ?? 56 57 }
                $sig2 = { 64 A1 30 00 00 00 53 56 57 33 F6 8B 40 0C }
            condition:
                $prot and ($driver or (1 of ($sig*)))
        }

        rule StarForce_v5 {
            meta:
                description = "StarForce v5.x protection"
                version = "5.x"
            strings:
                $prot = "Protection Technology" ascii
                $driver = "sfvfs04" ascii nocase
                $sig1 = { 48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 }
                $sig2 = { 40 53 48 83 EC ?? 48 8B D9 48 8B 0D ?? ?? ?? ?? }
            condition:
                $prot and ($driver or (1 of ($sig*)))
        }

        rule StarForce_Loader {
            meta:
                description = "StarForce protection loader initialization code"
            strings:
                $loader1 = { 60 E8 00 00 00 00 5B 81 EB ?? ?? ?? ?? 8D 83 ?? ?? ?? ?? }
                $loader2 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 8D BD ?? ?? FF FF }
                $check1 = "KERNEL32.DLL" ascii nocase
                $check2 = "GetProcAddress" ascii
            condition:
                (1 of ($loader*)) and all of ($check*)
        }

        rule StarForce_Disc_Check {
            meta:
                description = "StarForce disc authentication code"
            strings:
                $api1 = "DeviceIoControl" ascii
                $api2 = "CreateFileA" ascii
                $scsi1 = "\\\\.\\Scsi" ascii
                $scsi2 = "\\\\.\\CdRom" ascii
                $sig = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 6A 03 6A 00 6A 00 }
            condition:
                2 of ($api*) and 1 of ($scsi*) and $sig
        }
        """

        try:
            return yara.compile(source=rules_source)
        except Exception:
            return None

    def detect(self, target_path: Path) -> StarForceDetection:
        """Perform comprehensive StarForce detection.

        Args:
            target_path: Path to executable to analyze

        Returns:
            StarForceDetection results with confidence score

        """
        drivers = self._detect_drivers()
        services = self._detect_services()
        registry_keys = self._detect_registry_keys()

        sections = []
        version = None
        yara_matches = []

        if target_path.exists():
            sections = self._detect_protected_sections(target_path)
            version = self._detect_version(target_path)

            if self._yara_rules:
                yara_matches = self._yara_scan(target_path)

        confidence = self._calculate_confidence(drivers, services, registry_keys, sections, yara_matches)

        detected = confidence > 0.6

        details = {
            "yara_matches": yara_matches,
            "driver_paths": self._get_driver_paths(drivers),
            "service_status": self._get_service_status(services),
            "scsi_miniport": self._detect_scsi_miniport(),
        }

        return StarForceDetection(
            detected=detected,
            version=version,
            drivers=drivers,
            services=services,
            registry_keys=registry_keys,
            protected_sections=sections,
            confidence=confidence,
            details=details,
        )

    def _detect_drivers(self) -> list[str]:
        """Detect StarForce kernel drivers."""
        detected = []

        system_root = Path(r"C:\Windows\System32\drivers")
        if system_root.exists():
            for driver_name in self.DRIVER_NAMES:
                driver_path = system_root / driver_name
                if driver_path.exists():
                    detected.append(driver_name)

        return detected

    def _detect_services(self) -> list[str]:
        """Detect StarForce Windows services."""
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
                    if service_handle := self._advapi32.OpenServiceW(sc_manager, service_name, SERVICE_QUERY_CONFIG):
                        detected.append(service_name)
                        self._advapi32.CloseServiceHandle(service_handle)
            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            self.logger.debug(f"Error detecting StarForce services: {e}")

        return detected

    def _detect_registry_keys(self) -> list[str]:
        """Detect StarForce registry keys."""
        detected = []

        for key_path in self.REGISTRY_KEYS:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                winreg.CloseKey(key)
                detected.append(key_path)
            except OSError:
                pass

        return detected

    def _detect_protected_sections(self, target_path: Path) -> list[str]:
        """Detect StarForce protected PE sections."""
        if not PEFILE_AVAILABLE:
            return []

        detected = []

        try:
            pe = pefile.PE(str(target_path))

            for section in pe.sections:
                section_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")

                if any(sf_name in section_name.lower() for sf_name in self.SECTION_NAMES):
                    detected.append(section_name)

                if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0 and section.Characteristics & 0x20000000:
                    detected.append(f"{section_name} (encrypted)")

            pe.close()

        except Exception as e:
            self.logger.debug(f"Error analyzing PE sections: {e}")

        return detected

    def _detect_version(self, target_path: Path) -> StarForceVersion | None:
        """Detect StarForce version from executable."""
        if not PEFILE_AVAILABLE:
            return None

        try:
            pe = pefile.PE(str(target_path))

            if hasattr(pe, "VS_VERSIONINFO"):
                for entry in pe.FileInfo:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            for value in st.entries.values():
                                if b"StarForce" in value or b"Protection Technology" in value:
                                    return self._parse_version_string(value.decode("utf-8", errors="ignore"))

            data = pe.get_memory_mapped_image()

            if b"sfdrv01" in data or b"sfvfs02" in data:
                return StarForceVersion(3, 0, 0, "Standard")
            if b"sfvfs03" in data:
                return StarForceVersion(4, 0, 0, "Standard")
            if b"sfvfs04" in data:
                return StarForceVersion(5, 0, 0, "Standard")

            pe.close()

        except Exception as e:
            self.logger.debug(f"Error detecting StarForce version: {e}")

        return None

    def _parse_version_string(self, version_str: str) -> StarForceVersion | None:
        """Parse version string to extract StarForce version."""
        import re

        pattern = r"StarForce[^\d]*(\d+)\.(\d+)\.?(\d*)"
        if match := re.search(pattern, version_str):
            major = int(match.group(1))
            minor = int(match.group(2))
            build = int(match.group(3)) if match.group(3) else 0

            variant = "Pro" if "pro" in version_str.lower() else "Standard"

            return StarForceVersion(major, minor, build, variant)

        return None

    def _yara_scan(self, target_path: Path) -> list[dict[str, str]]:
        """Scan executable with YARA rules."""
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
            self.logger.debug(f"Error in YARA signature detection: {e}")

        return matches

    def _calculate_confidence(
        self,
        drivers: list[str],
        services: list[str],
        registry_keys: list[str],
        sections: list[str],
        yara_matches: list[dict[str, str]],
    ) -> float:
        """Calculate detection confidence score."""
        score = 0.0

        if drivers:
            score += 0.3 * min(len(drivers) / 3, 1.0)

        if services:
            score += 0.2 * min(len(services) / 2, 1.0)

        if registry_keys:
            score += 0.15 * min(len(registry_keys) / 3, 1.0)

        if sections:
            score += 0.2 * min(len(sections) / 2, 1.0)

        if yara_matches:
            score += 0.15 * min(len(yara_matches) / 2, 1.0)

        return min(score, 1.0)

    def _get_driver_paths(self, drivers: list[str]) -> dict[str, str]:
        """Get full paths for detected drivers."""
        paths = {}
        system_root = Path(r"C:\Windows\System32\drivers")

        for driver in drivers:
            driver_path = system_root / driver
            if driver_path.exists():
                paths[driver] = str(driver_path)

        return paths

    def _get_service_status(self, services: list[str]) -> dict[str, str]:
        """Get status information for detected services."""
        if not self._advapi32:
            return {}

        status_info = {}
        SC_MANAGER_ALL_ACCESS = 0xF003F
        SERVICE_QUERY_STATUS = 0x0004

        class ServiceStatus(ctypes.Structure):
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
                    if service_handle := self._advapi32.OpenServiceW(sc_manager, service_name, SERVICE_QUERY_STATUS):
                        status = ServiceStatus()
                        if hasattr(self._advapi32, "QueryServiceStatus"):
                            self._advapi32.QueryServiceStatus.argtypes = [
                                wintypes.HANDLE,
                                ctypes.POINTER(ServiceStatus),
                            ]
                            if self._advapi32.QueryServiceStatus(service_handle, ctypes.byref(status)):
                                status_info[service_name] = states.get(status.dwCurrentState, "UNKNOWN")

                        self._advapi32.CloseServiceHandle(service_handle)
            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            self.logger.debug(f"Error querying service status: {e}")

        return status_info

    def _detect_scsi_miniport(self) -> bool:
        """Detect StarForce SCSI miniport driver."""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Scsi",
                0,
                winreg.KEY_READ,
            )

            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)

                    try:
                        value, _ = winreg.QueryValueEx(subkey, "Driver")
                        if "starforce" in value.lower() or "sfdrv" in value.lower():
                            winreg.CloseKey(subkey)
                            winreg.CloseKey(key)
                            return True
                    except OSError:
                        pass

                    winreg.CloseKey(subkey)
                    i += 1

                except OSError:
                    break

            winreg.CloseKey(key)

        except OSError:
            pass

        return False
