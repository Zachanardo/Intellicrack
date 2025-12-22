"""Trial reset engine for bypassing software trial period limitations."""

import ctypes
import datetime
import hashlib
import json
import os
import struct
import time
import winreg
from ctypes import wintypes
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable

import psutil

from intellicrack.utils.logger import log_all_methods, logger


class TrialType(Enum):
    """Enumeration of software trial limitation types."""

    TIME_BASED = "time_based"
    USAGE_BASED = "usage_based"
    FEATURE_LIMITED = "feature_limited"
    HYBRID = "hybrid"


@dataclass
class TrialInfo:
    """Trial information extracted from software installation."""

    product_name: str
    trial_type: TrialType
    trial_days: int
    usage_count: int
    install_date: datetime.datetime
    first_run_date: datetime.datetime
    last_run_date: datetime.datetime
    trial_expired: bool
    registry_keys: list[str]
    files: list[str]
    processes: list[str]


@log_all_methods
class TrialResetEngine:
    """Production-ready trial reset mechanism for defeating software trial limitations."""

    def __init__(self) -> None:
        """Initialize the TrialResetEngine with trial location data and reset strategies."""
        self.common_trial_locations = self._initialize_trial_locations()
        self.detection_patterns = self._initialize_detection_patterns()
        self.reset_strategies = self._initialize_reset_strategies()
        self.time_manipulation = TimeManipulator()

    def _initialize_trial_locations(self) -> dict[str, list[str]]:
        """Initialize common trial data storage locations."""
        username = os.environ.get("USERNAME", "User")

        locations = {
            "registry": [
                r"HKEY_CURRENT_USER\Software\{product}",
                r"HKEY_LOCAL_MACHINE\SOFTWARE\{product}",
                r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\{product}",
                r"HKEY_CURRENT_USER\Software\Classes\CLSID",
                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",  # pragma: allowlist secret
                r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",  # pragma: allowlist secret
            ],
            "files": [
                "C:\\ProgramData\\{product}",
                f"C:\\Users\\{username}\\AppData\\Local\\{{product}}",
                f"C:\\Users\\{username}\\AppData\\Roaming\\{{product}}",
                f"C:\\Users\\{username}\\AppData\\LocalLow\\{{product}}",
                "C:\\Windows\\System32\\config\\systemprofile\\AppData",
                "C:\\Windows\\Temp",
                f"C:\\Users\\{username}\\Documents\\{{product}}",
                "C:\\Program Files\\Common Files\\{product}",
                "C:\\Program Files (x86)\\Common Files\\{product}",
            ],
            "hidden": [
                f"C:\\Users\\{username}\\AppData\\Local\\Temp\\~{{product}}",
                "C:\\Windows\\System32\\drivers\\etc\\{product}.dat",
                f"C:\\Users\\{username}\\.{{product}}",
                "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\{product}\\.trial",
            ],
            "alternate_streams": [
                "C:\\Program Files\\{product}:Zone.Identifier",
                "C:\\Program Files\\{product}:trial",
                f"C:\\Users\\{username}\\Desktop\\{{product}}.lnk:trial",
            ],
        }
        logger.debug(
            "Initialized %s registry, %s file, %s hidden, and %s alternate stream trial locations.",
            len(locations["registry"]),
            len(locations["files"]),
            len(locations["hidden"]),
            len(locations["alternate_streams"]),
        )
        return locations

    def _initialize_detection_patterns(self) -> dict[str, list[str] | list[bytes]]:
        """Initialize patterns for detecting trial data."""
        registry_values: list[str] = [
            "TrialDays",
            "DaysLeft",
            "InstallDate",
            "FirstRun",
            "LastRun",
            "ExpireDate",
            "TrialPeriod",
            "Evaluation",
            "LicenseType",
            "ActivationDate",
            "TrialCounter",
            "UsageCount",
            "RunCount",
            "LaunchCount",
            "StartCount",
        ]
        file_patterns: list[str] = [
            "*.trial",
            "*.lic",
            "*.license",
            "*.dat",
            "*.db",
            "*.sqlite",
            "*.reg",
            "*.key",
            "*.activation",
            "*.lock",
            "trial.xml",
            "license.xml",
            "activation.xml",
            "config.ini",
        ]
        timestamp_files: list[str] = [
            "install.dat",
            "first_run.dat",
            "trial.dat",
            ".trial_info",
            "eval.bin",
            "timestamp.db",
        ]
        encrypted_markers: list[bytes] = [
            b"\x00TRIAL\x00",
            b"\xde\xad\xbe\xef",
            b"EVAL",
            b"DEMO",
            b"UNREGISTERED",
        ]
        patterns: dict[str, list[str] | list[bytes]] = {
            "registry_values": registry_values,
            "file_patterns": file_patterns,
            "timestamp_files": timestamp_files,
            "encrypted_markers": encrypted_markers,
        }
        logger.debug(
            "Initialized %s registry value, %s file, %s timestamp, and %s encrypted detection patterns.",
            len(registry_values),
            len(file_patterns),
            len(timestamp_files),
            len(encrypted_markers),
        )
        return patterns

    def _initialize_reset_strategies(self) -> dict[str, Callable[[TrialInfo], bool]]:
        """Initialize trial reset strategies."""
        strategies: dict[str, Callable[[TrialInfo], bool]] = {
            "clean_uninstall": self._clean_uninstall_reset,
            "time_manipulation": self._time_manipulation_reset,
            "registry_clean": self._registry_clean_reset,
            "file_wipe": self._file_wipe_reset,
            "guid_regeneration": self._guid_regeneration_reset,
            "sandbox_reset": self._sandbox_reset,
            "vm_reset": self._vm_reset,
            "system_restore": self._system_restore_reset,
        }
        logger.debug("Initialized %s trial reset strategies.", len(strategies))
        return strategies

    def scan_for_trial(self, product_name: str) -> TrialInfo:
        """Scan system for trial information."""
        logger.info("Starting comprehensive trial scan for product: %s", product_name)
        trial_info = TrialInfo(
            product_name=product_name,
            trial_type=TrialType.TIME_BASED,
            trial_days=0,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[],
            processes=[],
        )

        logger.info("Step 1: Scanning registry for trial data.")
        trial_info.registry_keys = self._scan_registry_for_trial(product_name)
        logger.info("Step 1: Found %s registry keys for %s.", len(trial_info.registry_keys), product_name)

        logger.info("Step 2: Scanning filesystem for trial data.")
        trial_info.files = self._scan_files_for_trial(product_name)
        logger.info("Step 2: Found %s files for %s.", len(trial_info.files), product_name)

        logger.info("Step 3: Detecting trial type.")
        trial_info.trial_type = self._detect_trial_type(trial_info)
        logger.info("Step 3: Detected trial type: %s", trial_info.trial_type.value)

        logger.info("Step 4: Extracting detailed trial information.")
        self._extract_trial_details(trial_info)
        logger.info(
            "Step 4: Extracted trial details: Install Date=%s, Trial Days=%s, Usage Count=%s",
            trial_info.install_date,
            trial_info.trial_days,
            trial_info.usage_count,
        )

        logger.info("Step 5: Checking if trial is expired.")
        trial_info.trial_expired = self._check_trial_expired(trial_info)
        logger.info("Step 5: Trial expired status: %s", trial_info.trial_expired)

        logger.info("Step 6: Finding related processes.")
        trial_info.processes = self._find_related_processes(product_name)
        logger.info("Step 6: Found %s related processes: %s", len(trial_info.processes), trial_info.processes)

        logger.info("Comprehensive trial scan completed for %s.", product_name)
        return trial_info

    def _scan_registry_for_trial(self, product_name: str) -> list[str]:
        """Scan registry for trial-related keys."""
        found_keys = []

        for template in self.common_trial_locations["registry"]:
            key_path = template.replace("{product}", product_name)
            logger.debug("Scanning registry key path: %s", key_path)

            # Parse registry hive and path
            parts = key_path.split("\\", 1)
            if len(parts) < 2:
                logger.debug("Skipping invalid registry key path: %s", key_path)
                continue

            hive_name = parts[0]
            subkey = parts[1]

            # Map hive name to handle
            hive_map = {
                "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
                "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
                "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
                "HKEY_USERS": winreg.HKEY_USERS,
                "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
            }

            if hive_name not in hive_map:
                logger.debug("Skipping unknown registry hive: %s", hive_name)
                continue

            try:
                # Try to open key
                with winreg.OpenKey(hive_map[hive_name], subkey) as key:
                    found_keys.append(key_path)
                    logger.debug("Found existing registry key: %s", key_path)

                    # Check for trial-related values
                    i = 0
                    while True:
                        try:
                            value_name, _value_data, _value_type = winreg.EnumValue(key, i)

                            # Check if value name indicates trial
                            registry_patterns = self.detection_patterns["registry_values"]
                            if isinstance(registry_patterns, list):
                                for pattern in registry_patterns:
                                    if isinstance(pattern, str) and pattern.lower() in value_name.lower():
                                        found_keys.append(f"{key_path}\\{value_name}")
                                        logger.debug("Found trial-related registry value: %s\\%s", key_path, value_name)
                                        break

                            i += 1
                        except OSError:
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.warning("Failed to access registry for process scanning: %s", e)
            except OSError as e:
                logger.warning("Failed to open registry key %s: %s", key_path, e)

        # Also scan for hidden/encoded keys
        hidden_found = self._scan_for_hidden_registry_keys(product_name)
        found_keys.extend(hidden_found)
        logger.debug("Finished scanning registry. Total found keys: %s", len(found_keys))
        return found_keys

    def _scan_for_hidden_registry_keys(self, product_name: str) -> list[str]:
        """Scan for hidden or encoded registry keys."""
        hidden_keys = []

        # Generate possible encoded key names
        encodings = [
            hashlib.sha256(product_name.encode()).hexdigest()[:32],  # Using more chars for SHA256
            hashlib.sha256(product_name.encode()).hexdigest()[:16],  # Another SHA256 variant
            hashlib.sha256(product_name.encode()).hexdigest()[:16],  # Original SHA256
            product_name[::-1],  # Reversed
            "".join([chr(ord(c) + 1) for c in product_name]),  # Caesar cipher
            product_name.encode().hex(),
        ]

        # Search CLSID registry for encoded entries
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\CLSID") as clsid_key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(clsid_key, i)

                        # Check if subkey matches any encoding
                        for encoded in encodings:
                            if encoded.lower() in subkey_name.lower():
                                hidden_keys.append(f"HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{subkey_name}")
                                logger.debug("Found hidden registry key: HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\%s", subkey_name)
                                break

                        i += 1
                    except OSError:
                        break
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as e:
            logger.warning("Failed to scan for hidden registry keys: %s", e)
        logger.debug("Finished scanning for hidden registry keys. Total found: %s", len(hidden_keys))
        return hidden_keys

    def _scan_files_for_trial(self, product_name: str) -> list[str]:
        """Scan filesystem for trial-related files."""
        found_files = []

        for template in self.common_trial_locations["files"]:
            path = template.replace("{product}", product_name)
            logger.debug("Scanning file path: %s", path)

            if os.path.exists(path):
                # Scan directory for trial files
                file_patterns = self.detection_patterns["file_patterns"]
                if isinstance(file_patterns, list):
                    for pattern in file_patterns:
                        if isinstance(pattern, str):
                            try:
                                for file_path in Path(path).rglob(pattern):
                                    found_files.append(str(file_path))
                                    logger.debug("Found trial-related file: %s", file_path)
                            except OSError as e:
                                logger.warning("Failed to scan path %s with pattern %s: %s", path, pattern, e)

        # Scan for hidden files
        for template in self.common_trial_locations["hidden"]:
            path = template.replace("{product}", product_name)
            if os.path.exists(path):
                found_files.append(path)
                logger.debug("Found hidden trial file: %s", path)

        # Scan for alternate data streams
        ads_found = self._scan_alternate_data_streams(product_name)
        found_files.extend(ads_found)
        logger.debug("Found %s alternate data streams.", len(ads_found))

        # Scan for encrypted/obfuscated files
        encrypted_found = self._scan_for_encrypted_trial_files(product_name)
        found_files.extend(encrypted_found)
        logger.debug("Found %s encrypted trial files.", len(encrypted_found))

        logger.debug("Finished scanning files. Total found files: %s", len(found_files))
        return found_files

    def _scan_alternate_data_streams(self, product_name: str) -> list[str]:
        """Scan for NTFS alternate data streams using Windows APIs."""
        ads_files = []
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class WIN32_STREAM_ID(ctypes.Structure):  # noqa: N801
            _fields_ = [
                ("dwStreamId", wintypes.DWORD),
                ("dwStreamAttributes", wintypes.DWORD),
                ("Size", wintypes.LARGE_INTEGER),
                ("dwStreamNameSize", wintypes.DWORD),
            ]

        class STREAM_INFO_LEVELS(ctypes.c_int):  # noqa: N801
            FindStreamInfoStandard = 0
            FindStreamInfoMaxInfoLevel = 1

        class WIN32_FIND_STREAM_DATA(ctypes.Structure):  # noqa: N801
            _fields_ = [
                ("StreamSize", wintypes.LARGE_INTEGER),
                ("cStreamName", wintypes.WCHAR * 296),
            ]

        # Setup FindFirstStreamW function
        kernel32.FindFirstStreamW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.c_int,
            ctypes.POINTER(WIN32_FIND_STREAM_DATA),
            wintypes.DWORD,
        ]
        kernel32.FindFirstStreamW.restype = wintypes.HANDLE

        kernel32.FindNextStreamW.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(WIN32_FIND_STREAM_DATA),
        ]
        kernel32.FindNextStreamW.restype = wintypes.BOOL

        kernel32.FindClose.argtypes = [wintypes.HANDLE]
        kernel32.FindClose.restype = wintypes.BOOL

        kernel32.BackupRead.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.BOOL,
            wintypes.BOOL,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        kernel32.BackupRead.restype = wintypes.BOOL

        for template in self.common_trial_locations["alternate_streams"]:
            path = template.replace("{product}", product_name)
            base_path = path.split(":")[0]

            if os.path.exists(base_path):
                try:
                    file_handle = kernel32.CreateFileW(
                        base_path,
                        0x80000000,
                        0x01 | 0x02,
                        None,
                        3,
                        0x02000000,
                        None,
                    )
                    if file_handle != -1:
                        try:
                            context = ctypes.c_void_p(0)
                            stream_id = WIN32_STREAM_ID()
                            bytes_read = wintypes.DWORD(0)

                            while (
                                kernel32.BackupRead(
                                    file_handle,
                                    ctypes.byref(stream_id),
                                    ctypes.sizeof(WIN32_STREAM_ID),
                                    ctypes.byref(bytes_read),
                                    False,
                                    False,
                                    ctypes.byref(context),
                                )
                                and bytes_read.value != 0
                            ):
                                if stream_id.dwStreamId == 4 and stream_id.dwStreamNameSize > 0:
                                    name_buffer = ctypes.create_unicode_buffer(stream_id.dwStreamNameSize // 2)
                                    kernel32.BackupRead(
                                        file_handle,
                                        name_buffer,
                                        stream_id.dwStreamNameSize,
                                        ctypes.byref(bytes_read),
                                        False,
                                        False,
                                        ctypes.byref(context),
                                    )
                                    if stream_name := name_buffer.value:
                                        ads_files.append(f"{base_path}{stream_name}")
                                        logger.debug("Found ADS via BackupRead: %s%s", base_path, stream_name)
                        finally:
                            kernel32.CloseHandle(file_handle)
                except OSError as backup_error:
                    logger.debug("BackupRead failed for %s: %s", base_path, backup_error)

                try:
                    stream_data = WIN32_FIND_STREAM_DATA()
                    handle = kernel32.FindFirstStreamW(
                        base_path,
                        STREAM_INFO_LEVELS.FindStreamInfoStandard,
                        ctypes.byref(stream_data),
                        0,
                    )

                    if handle != -1:  # INVALID_HANDLE_VALUE
                        try:
                            while True:
                                stream_name = stream_data.cStreamName
                                # Skip the main data stream
                                if stream_name and "::$DATA" not in stream_name:
                                    ads_files.append(f"{base_path}{stream_name}")
                                    logger.debug("Found ADS: %s%s", base_path, stream_name)

                                # Get next stream
                                if not kernel32.FindNextStreamW(handle, ctypes.byref(stream_data)):
                                    break
                        finally:
                            kernel32.FindClose(handle)

                    # Also check for common trial-related ADS names directly
                    common_ads_names = [
                        ":trial",
                        ":license",
                        ":activation",
                        ":expiry",
                        ":usage",
                        ":count",
                        ":timestamp",
                        ":evaluation",
                        ":demo",
                        ":registered",
                        ":serial",
                    ]

                    for ads_name in common_ads_names:
                        ads_path = f"{base_path}{ads_name}:$DATA"
                        # Try to open the stream to check if it exists
                        handle = kernel32.CreateFileW(
                            ads_path,
                            0x80000000,  # GENERIC_READ
                            0x01 | 0x02,  # FILE_SHARE_READ | FILE_SHARE_WRITE
                            None,
                            3,  # OPEN_EXISTING
                            0,
                            None,
                        )
                        if handle != -1:
                            kernel32.CloseHandle(handle)
                            ads_files.append(ads_path)
                            logger.debug("Found common ADS: %s", ads_path)

                except Exception as e:
                    logger.warning("ADS file identification failed for base path %s: %s", base_path, e)

        # Scan for ADS in subdirectories if specified
        for location in self.common_trial_locations.get("files", []):
            if "{product}" in location:
                dir_path = os.path.dirname(location.replace("{product}", product_name))
                if os.path.exists(dir_path):
                    ads_files.extend(self._scan_directory_for_ads(dir_path))
        logger.debug("Finished scanning for alternate data streams. Total found: %s", len(ads_files))
        return ads_files

    def _scan_directory_for_ads(self, directory: str) -> list[str]:
        """Recursively scan directory for files with alternate data streams."""
        ads_files = []
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class WIN32_FIND_STREAM_DATA(ctypes.Structure):  # noqa: N801
            _fields_ = [
                ("StreamSize", wintypes.LARGE_INTEGER),
                ("cStreamName", wintypes.WCHAR * 296),
            ]

        kernel32.FindFirstStreamW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.c_int,
            ctypes.POINTER(WIN32_FIND_STREAM_DATA),
            wintypes.DWORD,
        ]
        kernel32.FindFirstStreamW.restype = wintypes.HANDLE

        try:
            for root, dirs, files in os.walk(directory):
                for filename in files + dirs:
                    filepath = os.path.join(root, filename)
                    stream_data = WIN32_FIND_STREAM_DATA()

                    handle = kernel32.FindFirstStreamW(filepath, 0, ctypes.byref(stream_data), 0)

                    if handle != -1:
                        try:
                            while True:
                                stream_name = stream_data.cStreamName
                                if stream_name and "::$DATA" not in stream_name:
                                    ads_files.append(f"{filepath}{stream_name}")

                                if not kernel32.FindNextStreamW(handle, ctypes.byref(stream_data)):
                                    break
                        finally:
                            kernel32.FindClose(handle)
        except OSError as e:
            logger.warning("Failed to scan for alternate data streams in directory %s: %s", directory, e)

        return ads_files

    def _scan_for_encrypted_trial_files(self, product_name: str) -> list[str]:
        """Scan for encrypted trial data files."""
        encrypted_files = []

        search_paths = [
            os.environ.get("APPDATA"),
            os.environ.get("LOCALAPPDATA"),
            os.environ.get("PROGRAMDATA"),
            os.environ.get("TEMP"),
        ]

        for search_path in search_paths:
            if not search_path:
                continue

            try:
                for root, _dirs, files in os.walk(search_path):
                    for file in files:
                        file_path = os.path.join(root, file)

                        # Check file for encrypted markers
                        try:
                            with open(file_path, "rb") as f:
                                header = f.read(1024)

                                encrypted_markers = self.detection_patterns["encrypted_markers"]
                                if isinstance(encrypted_markers, list):
                                    for marker in encrypted_markers:
                                        if isinstance(marker, bytes) and marker in header:
                                            encrypted_files.append(file_path)
                                            logger.debug("Found encrypted trial file: %s", file_path)
                                            break
                        except OSError as e:
                            logger.warning("Failed to read file %s: %s", file_path, e)
            except (ValueError, TypeError) as e:
                logger.warning("Failed to process directory %s: %s", search_path, e)
        logger.debug("Finished scanning for encrypted trial files. Total found: %s", len(encrypted_files))
        return encrypted_files

    def _detect_trial_type(self, trial_info: TrialInfo) -> TrialType:
        """Detect the type of trial protection."""
        # Check for time-based markers
        time_markers = ["ExpireDate", "TrialDays", "DaysLeft", "InstallDate"]
        has_time = any(marker in str(trial_info.registry_keys) for marker in time_markers)

        # Check for usage-based markers
        usage_markers = ["UsageCount", "RunCount", "LaunchCount", "ExecutionCount"]
        has_usage = any(marker in str(trial_info.registry_keys) for marker in usage_markers)

        # Check for feature-limited markers
        feature_markers = ["Features", "Limitations", "Restricted", "Demo"]
        has_features = any(marker in str(trial_info.registry_keys) for marker in feature_markers)

        if has_time and has_usage:
            logger.debug("Detected Hybrid trial type.")
            return TrialType.HYBRID
        if has_usage:
            logger.debug("Detected Usage-Based trial type.")
            return TrialType.USAGE_BASED
        if has_features and not has_time:
            logger.debug("Detected Feature-Limited trial type.")
            return TrialType.FEATURE_LIMITED
        logger.debug("Detected Time-Based trial type.")
        return TrialType.TIME_BASED

    def _extract_trial_details(self, trial_info: TrialInfo) -> None:
        """Extract detailed trial information."""
        # Extract from registry
        for key_path in trial_info.registry_keys:
            if "\\" not in key_path:
                continue

            parts = key_path.split("\\")
            if len(parts) < 2:
                continue

            try:
                # Parse and open key
                hive_name = parts[0]
                subkey = "\\".join(parts[1:])

                hive_map = {
                    "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
                    "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
                }

                if hive_name in hive_map:
                    with winreg.OpenKey(hive_map[hive_name], subkey) as key:
                        # Try to read common trial values
                        try:
                            install_date = winreg.QueryValueEx(key, "InstallDate")[0]
                            trial_info.install_date = self._parse_date(install_date)
                            logger.debug("Extracted InstallDate: %s from %s", trial_info.install_date, key_path)
                        except (OSError, ValueError) as e:
                            logger.warning("Failed to read InstallDate from %s: %s", key_path, e)

                        try:
                            trial_days = winreg.QueryValueEx(key, "TrialDays")[0]
                            trial_info.trial_days = int(trial_days)
                            logger.debug("Extracted TrialDays: %s from %s", trial_info.trial_days, key_path)
                        except (OSError, ValueError) as e:
                            logger.warning("Failed to read TrialDays from %s: %s", key_path, e)

                        try:
                            usage_count = winreg.QueryValueEx(key, "UsageCount")[0]
                            trial_info.usage_count = int(usage_count)
                            logger.debug("Extracted UsageCount: %s from %s", trial_info.usage_count, key_path)
                        except (OSError, ValueError) as e:
                            logger.warning("Failed to read UsageCount from %s: %s", key_path, e)
            except OSError as e:
                logger.warning("Failed to access registry key %s: %s", key_path, e)

        # Extract from files
        for file_path in trial_info.files:
            if os.path.exists(file_path):
                # Get file timestamps
                stat = Path(file_path).stat()
                creation_time = datetime.datetime.fromtimestamp(stat.st_ctime)
                logger.debug("File %s creation time: %s", file_path, creation_time)

                trial_info.install_date = min(trial_info.install_date, creation_time)
        logger.debug(
            "Finished extracting trial details. Final Install Date: %s, Trial Days: %s, Usage Count: %s",
            trial_info.install_date,
            trial_info.trial_days,
            trial_info.usage_count,
        )

    def _parse_date(self, date_value: int | str) -> datetime.datetime:
        """Parse various date formats."""
        if isinstance(date_value, int):
            # Unix timestamp
            return datetime.datetime.fromtimestamp(date_value)
        if isinstance(date_value, str):
            # Try various formats
            formats = ["%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"]

            for fmt in formats:
                try:
                    return datetime.datetime.strptime(date_value, fmt).replace(tzinfo=datetime.UTC)
                except (ValueError, TypeError):
                    continue

        return datetime.datetime.now(datetime.UTC)

    def _check_trial_expired(self, trial_info: TrialInfo) -> bool:
        """Check if trial has expired."""
        if trial_info.trial_type == TrialType.TIME_BASED:
            if trial_info.trial_days > 0:
                expire_date = trial_info.install_date + datetime.timedelta(days=trial_info.trial_days)
                is_expired = datetime.datetime.now() > expire_date
                logger.debug(
                    "Time-based trial expiration check: Expire Date=%s, Current Date=%s, Expired=%s",
                    expire_date,
                    datetime.datetime.now(),
                    is_expired,
                )
                return is_expired

        elif trial_info.trial_type == TrialType.USAGE_BASED:
            # Check usage count limits
            if trial_info.usage_count > 30:  # Common trial limit
                logger.debug("Usage-based trial expiration check: Usage Count=%s, Limit=30, Expired=True", trial_info.usage_count)
                return True
        logger.debug("Trial not expired based on current checks.")
        return False

    def _find_related_processes(self, product_name: str) -> list[str]:
        """Find processes related to the product."""
        processes = []

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                if product_name.lower() in proc.info["name"].lower():
                    processes.append(proc.info["name"])
                    logger.debug("Found related process by name: %s (PID: %s)", proc.info["name"], proc.info["pid"])
                elif proc.info["exe"] and product_name.lower() in proc.info["exe"].lower():
                    processes.append(proc.info["name"])
                    logger.debug("Found related process by executable path: %s (PID: %s)", proc.info["exe"], proc.info["pid"])
            except (KeyError, TypeError, AttributeError) as e:
                logger.warning("Failed to process running process information: %s", e)
        unique_processes = list(set(processes))
        logger.debug("Finished finding related processes. Total unique processes found: %s", len(unique_processes))
        return unique_processes

    def reset_trial(self, trial_info: TrialInfo, strategy: str = "clean_uninstall") -> bool:
        """Reset trial using specified strategy."""
        logger.debug("Attempting to reset trial for product '%s' using strategy: '%s'", trial_info.product_name, strategy)
        if strategy not in self.reset_strategies:
            logger.warning("Unknown strategy '%s'. Falling back to 'clean_uninstall'.", strategy)
            strategy = "clean_uninstall"

        # Kill related processes first
        logger.debug("Killing %s related processes: %s", len(trial_info.processes), trial_info.processes)
        self._kill_processes(trial_info.processes)

        # Apply reset strategy
        logger.debug("Applying reset strategy: %s", strategy)
        reset_func: Callable[[TrialInfo], bool] = self.reset_strategies[strategy]
        success: bool = reset_func(trial_info)
        logger.debug("Trial reset for '%s' completed with strategy '%s'. Success: %s", trial_info.product_name, strategy, success)
        return success

    def _kill_processes(self, process_names: list[str]) -> None:
        """Kill specified processes."""
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["name"] in process_names:
                    logger.debug("Attempting to terminate process: %s (PID: %s)", proc.info["name"], proc.info["pid"])
                    proc.terminate()
                    proc.wait(timeout=3)
                    logger.debug("Successfully terminated process: %s (PID: %s)", proc.info["name"], proc.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                try:
                    logger.debug("Attempting to kill process: %s (PID: %s)", proc.info["name"], proc.info["pid"])
                    proc.kill()
                    logger.debug("Successfully killed process: %s (PID: %s)", proc.info["name"], proc.info["pid"])
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.debug("Failed to kill process %s: %s", proc.info["name"], e)

    def _clean_uninstall_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial by cleaning all traces."""
        success = True
        logger.debug("Starting clean uninstall reset strategy.")

        # Delete registry keys
        logger.debug("Deleting %s registry keys.", len(trial_info.registry_keys))
        for key_path in trial_info.registry_keys:
            if not self._delete_registry_key(key_path):
                success = False

        # Delete files
        logger.debug("Deleting %s files.", len(trial_info.files))
        for file_path in trial_info.files:
            if not self._delete_file_securely(file_path):
                success = False

        # Clear alternate data streams
        logger.debug("Clearing alternate data streams.")
        self._clear_alternate_data_streams(trial_info.product_name)

        # Clear prefetch
        logger.debug("Clearing prefetch data.")
        self._clear_prefetch_data(trial_info.product_name)

        # Clear event logs
        logger.debug("Clearing event logs.")
        self._clear_event_logs(trial_info.product_name)
        logger.debug("Clean uninstall reset strategy completed. Success: %s", success)
        return success

    def _delete_registry_key(self, key_path: str) -> bool:
        """Delete a registry key."""
        try:
            parts = key_path.split("\\")
            if len(parts) < 2:
                return False

            hive_name = parts[0]
            subkey = "\\".join(parts[1:])

            hive_map = {
                "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
                "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
                "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
                "HKEY_USERS": winreg.HKEY_USERS,
                "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
            }

            if hive_name in hive_map:
                winreg.DeleteKey(hive_map[hive_name], subkey)
                logger.debug("Successfully deleted registry key: %s", key_path)
                return True
        except OSError as e:
            logger.warning("Failed to delete registry key %s: %s", key_path, e)

        return False

    def _delete_file_securely(self, file_path: str) -> bool:
        """Securely delete a file."""
        try:
            if os.path.exists(file_path):
                logger.debug("Securely deleting file: %s", file_path)
                # Overwrite with random data
                file_size = os.path.getsize(file_path)
                with open(file_path, "wb") as f:
                    f.write(os.urandom(file_size))
                logger.debug("Overwritten %s bytes of %s with random data.", file_size, file_path)

                # Delete file
                os.remove(file_path)
                logger.debug("Successfully deleted file: %s", file_path)
                return True
        except OSError as e:
            logger.warning("Failed to securely delete file %s using standard methods: %s. Attempting alternate methods.", file_path, e)
            # Try alternate methods
            try:
                import win32file

                win32file.DeleteFile(file_path)
                logger.debug("Successfully deleted file %s via win32file.", file_path)
                return True
            except OSError as e:
                logger.warning("Failed to delete file via win32file %s: %s", file_path, e)

        return False

    def _clear_alternate_data_streams(self, product_name: str) -> None:
        """Clear NTFS alternate data streams using Windows APIs."""
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        # Define constants
        DELETE = 0x00010000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        FILE_SHARE_DELETE = 0x00000004
        OPEN_EXISTING = 3
        FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
        GENERIC_WRITE = 0x40000000

        def remove_ads_from_file(file_path: str) -> None:
            """Remove all alternate data streams from a file."""
            try:
                # First, enumerate all streams
                class Win32FindStreamData(ctypes.Structure):
                    _fields_ = [
                        ("StreamSize", wintypes.LARGE_INTEGER),
                        ("cStreamName", wintypes.WCHAR * 296),
                    ]

                kernel32.FindFirstStreamW.argtypes = [
                    wintypes.LPCWSTR,
                    ctypes.c_int,
                    ctypes.POINTER(Win32FindStreamData),
                    wintypes.DWORD,
                ]
                kernel32.FindFirstStreamW.restype = wintypes.HANDLE

                stream_data = Win32FindStreamData()
                handle = kernel32.FindFirstStreamW(file_path, 0, ctypes.byref(stream_data), 0)

                streams_to_delete = []
                if handle != -1:
                    try:
                        while True:
                            stream_name = stream_data.cStreamName
                            # Collect non-main streams
                            if stream_name and "::$DATA" not in stream_name:
                                streams_to_delete.append(stream_name)

                            if not kernel32.FindNextStreamW(handle, ctypes.byref(stream_data)):
                                break
                    finally:
                        kernel32.FindClose(handle)
                logger.debug("Found %s ADS to delete from %s.", len(streams_to_delete), file_path)
                # Delete each alternate stream
                for stream_name in streams_to_delete:
                    stream_path = f"{file_path}{stream_name}"
                    logger.debug("Attempting to delete ADS: %s", stream_path)
                    # Method 1: DeleteFileW
                    if not kernel32.DeleteFileW(stream_path):
                        # Method 2: CreateFileW with DELETE_ON_CLOSE flag
                        handle = kernel32.CreateFileW(
                            stream_path,
                            DELETE | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            None,
                            OPEN_EXISTING,
                            FILE_FLAG_DELETE_ON_CLOSE,
                            None,
                        )
                        if handle != -1:
                            kernel32.CloseHandle(handle)
                            logger.debug("Successfully deleted ADS %s using DELETE_ON_CLOSE.", stream_path)
                        else:
                            # Method 3: Zero out the stream
                            handle = kernel32.CreateFileW(
                                stream_path,
                                GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                None,
                                OPEN_EXISTING,
                                0,
                                None,
                            )
                            if handle != -1:
                                # Truncate stream to 0 bytes
                                kernel32.SetEndOfFile(handle)
                                kernel32.CloseHandle(handle)
                                logger.debug("Successfully zeroed out ADS %s.", stream_path)
                            else:
                                logger.debug("Failed to delete or zero out ADS %s.", stream_path)

            except Exception as e:
                logger.warning("ADS file handle operation failed for %s: %s", file_path, e)

        for template in self.common_trial_locations["alternate_streams"]:
            path = template.replace("{product}", product_name)
            base_path = path.split(":")[0]

            if os.path.exists(base_path):
                try:
                    # Remove ADS from the base file
                    logger.debug("Removing ADS from base file: %s", base_path)
                    remove_ads_from_file(base_path)

                    # Target common ADS names used for trial data
                    common_ads_names = [
                        ":Zone.Identifier",
                        ":trial",
                        ":license",
                        ":activation",
                        ":expiry",
                        ":usage",
                        ":count",
                        ":timestamp",
                        ":evaluation",
                        ":demo",
                        ":registered",
                        ":serial",
                        ":install",
                        ":firstrun",
                    ]

                    for ads_name in common_ads_names:
                        ads_path = f"{base_path}{ads_name}"
                        logger.debug("Attempting to delete common ADS: %s", ads_path)
                        # Try multiple deletion methods
                        if not kernel32.DeleteFileW(ads_path):
                            ads_data_path = f"{ads_path}:$DATA"
                            kernel32.DeleteFileW(ads_data_path)
                            logger.debug("Successfully deleted common ADS %s.", ads_path)

                    # Recursively check subdirectories for ADS
                    if Path(base_path).is_dir():
                        logger.debug("Recursively clearing ADS in directory: %s", base_path)
                        self._clear_directory_ads(base_path, remove_ads_from_file)

                except Exception as e:
                    logger.warning("Directory ADS clearing failed for %s: %s", base_path, e)

        # Also clear ADS from common file locations
        for location in self.common_trial_locations.get("files", []):
            if "{product}" in location:
                file_path = location.replace("{product}", product_name)
                if os.path.exists(file_path):
                    logger.debug("Removing ADS from common file location: %s", file_path)
                    remove_ads_from_file(file_path)

                # Check parent directory
                dir_path = os.path.dirname(file_path)
                if os.path.exists(dir_path):
                    logger.debug("Clearing ADS in parent directory: %s", dir_path)
                    self._clear_directory_ads(dir_path, remove_ads_from_file, max_depth=1)
        logger.debug("Finished clearing alternate data streams.")

    def _clear_directory_ads(self, directory: str, remove_func: Callable[[str], None], max_depth: int = 5) -> None:
        """Recursively clear alternate data streams from directory."""
        try:
            for root, dirs, files in os.walk(directory):
                # Limit recursion depth
                depth = root[len(directory) :].count(os.sep)
                if depth > max_depth:
                    continue

                # Process files
                for filename in files:
                    filepath = os.path.join(root, filename)
                    remove_func(filepath)

                # Process directories themselves (they can have ADS too)
                for dirname in dirs:
                    dirpath = os.path.join(root, dirname)
                    remove_func(dirpath)

        except Exception as e:
            logger.warning("Directory ADS recursive clearing failed for %s: %s", directory, e)

    def _clear_prefetch_data(self, product_name: str) -> None:
        """Clear Windows prefetch data."""
        prefetch_path = r"C:\Windows\Prefetch"
        logger.debug("Clearing prefetch data for product: %s from %s", product_name, prefetch_path)
        try:
            for file in os.listdir(prefetch_path):
                if product_name.upper() in file.upper():
                    file_path = os.path.join(prefetch_path, file)
                    self._delete_file_securely(file_path)
                    logger.debug("Deleted prefetch file: %s", file_path)
        except OSError as e:
            logger.warning("Failed to clear prefetch files from %s: %s", prefetch_path, e)
        logger.debug("Finished clearing prefetch data.")

    def _clear_event_logs(self, product_name: str) -> None:
        """Clear related event log entries."""
        try:
            import win32evtlog

            # Clear application event log entries
            logger.debug("Clearing application event logs for product: %s", product_name)
            handle = win32evtlog.OpenEventLog(None, "Application")
            win32evtlog.ClearEventLog(handle, None)
            win32evtlog.CloseEventLog(handle)
            logger.debug("Successfully cleared application event logs.")
        except OSError as e:
            logger.warning("Failed to clear event logs for product %s: %s", product_name, e)

    def _time_manipulation_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial by manipulating system time."""
        logger.debug("Attempting time manipulation reset for product: %s", trial_info.product_name)
        success = self.time_manipulation.reset_trial_time(trial_info)
        logger.debug("Time manipulation reset completed. Success: %s", success)
        return success

    def _registry_clean_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial by cleaning registry only."""
        success = True
        logger.debug("Starting registry clean reset strategy.")
        for key_path in trial_info.registry_keys:
            logger.debug("Attempting to delete registry key: %s", key_path)
            if not self._delete_registry_key(key_path):
                logger.debug("Failed to delete registry key %s. Attempting to reset values instead.", key_path)
                # Try to reset values instead
                if not self._reset_registry_values(key_path):
                    success = False
        logger.debug("Registry clean reset strategy completed. Success: %s", success)
        return success

    def _reset_registry_values(self, key_path: str) -> bool:
        """Reset registry values to default."""
        try:
            parts = key_path.split("\\")
            if len(parts) < 2:
                return False

            hive_name = parts[0]
            subkey = "\\".join(parts[1:])

            hive_map = {
                "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
                "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            }

            if hive_name in hive_map:
                with winreg.OpenKey(hive_map[hive_name], subkey, 0, winreg.KEY_ALL_ACCESS) as key:
                    # Reset trial values
                    winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 30)
                    winreg.SetValueEx(key, "UsageCount", 0, winreg.REG_DWORD, 0)
                    winreg.SetValueEx(key, "InstallDate", 0, winreg.REG_SZ, datetime.datetime.now().isoformat())
                    winreg.SetValueEx(key, "FirstRun", 0, winreg.REG_DWORD, 1)

                    return True
        except OSError as e:
            logger.warning("Failed to reset registry values for key %s: %s", key_path, e)

        return False

    def _file_wipe_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial by wiping files only."""
        success = True
        logger.debug("Starting file wipe reset strategy.")
        for file_path in trial_info.files:
            logger.debug("Attempting to wipe file: %s", file_path)
            if not self._delete_file_securely(file_path):
                logger.debug("Failed to securely delete file %s. Attempting to reset content instead.", file_path)
                # Try to reset file content
                if not self._reset_file_content(file_path):
                    success = False
        logger.debug("File wipe reset strategy completed. Success: %s", success)
        return success

    def _reset_file_content(self, file_path: str) -> bool:
        """Reset file content to appear new."""
        try:
            # Determine file type
            if file_path.endswith(".xml"):
                # Reset XML trial file
                content: str | bytes = '<?xml version="1.0"?>\n<trial><days>30</days><first_run>true</first_run></trial>'
            elif file_path.endswith(".json"):
                # Reset JSON trial file
                content = json.dumps({"trial_days": 30, "usage_count": 0, "first_run": True})
            elif file_path.endswith(".ini"):
                # Reset INI file
                content = "[Trial]\nDays=30\nUsageCount=0\nFirstRun=1"
            else:
                # Binary file - write zeros
                content = b"\x00" * 1024

            # Write reset content
            mode = "w" if isinstance(content, str) else "wb"
            with open(file_path, mode) as f:
                f.write(content)

            # Reset timestamps
            now = time.time()
            os.utime(file_path, (now, now))

            return True
        except OSError as e:
            logger.warning("Failed file wipe reset for %s: %s", file_path, e)

        return False

    def _guid_regeneration_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial by regenerating machine GUIDs."""
        import uuid

        try:
            logger.debug("Starting GUID regeneration reset strategy.")
            # Generate new machine GUID
            new_guid = str(uuid.uuid4()).upper()
            logger.debug("Generated new machine GUID: %s", new_guid)

            # Update machine GUID
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, new_guid)
            logger.debug("Updated MachineGuid in HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography.")

            # Update product-specific GUIDs
            for key_path in trial_info.registry_keys:
                self._update_guid_in_key(key_path)
            logger.debug("Updated product-specific GUIDs in registry keys.")
            logger.debug("GUID regeneration reset strategy completed. Success: True")
            return True
        except OSError as e:
            logger.warning("Failed GUID regeneration reset: %s", e)
            return False

    def _update_guid_in_key(self, key_path: str) -> None:
        """Update GUIDs in registry key."""
        import uuid

        try:
            parts = key_path.split("\\")
            if len(parts) < 2:
                return

            hive_name = parts[0]
            subkey = "\\".join(parts[1:])

            hive_map = {
                "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
                "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            }

            if hive_name in hive_map:
                with winreg.OpenKey(hive_map[hive_name], subkey, 0, winreg.KEY_ALL_ACCESS) as key:
                    # Find and update GUID values
                    i = 0
                    while True:
                        try:
                            value_name, _value_data, value_type = winreg.EnumValue(key, i)

                            if "guid" in value_name.lower() or "uuid" in value_name.lower():
                                new_guid = str(uuid.uuid4()).upper()
                                winreg.SetValueEx(key, value_name, 0, value_type, new_guid)
                                logger.debug("Updated GUID for value '%s' in '%s' to '%s'.", value_name, key_path, new_guid)

                            i += 1
                        except OSError:
                            break
        except OSError as e:
            logger.warning("Failed to update GUID in registry key %s: %s", key_path, e)

    def _sandbox_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial using sandbox isolation."""
        logger.debug("Attempting sandbox reset for product: %s", trial_info.product_name)
        # This would use sandbox technology to isolate trial
        # Simplified implementation
        success = self._clean_uninstall_reset(trial_info)
        logger.debug("Sandbox reset completed. Success: %s", success)
        return success

    def _vm_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial using VM snapshot."""
        logger.debug("Attempting VM reset for product: %s", trial_info.product_name)
        # This would revert VM to clean snapshot
        # Simplified implementation
        success = self._clean_uninstall_reset(trial_info)
        logger.debug("VM reset completed. Success: %s", success)
        return success

    def _system_restore_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial using system restore point."""
        try:
            logger.debug("Attempting system restore reset for product: %s", trial_info.product_name)
            # Create restore point
            import win32com.client

            wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\default")
            restore = wmi.Get("SystemRestore")

            # Create restore point
            result = restore.CreateRestorePoint("Before Trial Reset", 0, 100)
            logger.debug("System restore point creation result: %s", result[0])

            if result[0] == 0:
                # Clean trial data
                success = self._clean_uninstall_reset(trial_info)
                logger.debug("System restore reset completed. Success: %s", success)
                return success
        except OSError as e:
            logger.warning("Failed system restore reset: %s", e)

        return False


@log_all_methods
class TimeManipulator:
    """System time manipulation for trial reset."""

    def __init__(self) -> None:
        """Initialize the TimeManipulator with time tracking data structures."""
        self.original_time: datetime.datetime | None = None
        self.frozen_apps: dict[str, dict[str, datetime.datetime | list[int] | bool]] = {}

    def reset_trial_time(self, trial_info: TrialInfo) -> bool:
        """Reset trial by manipulating time."""
        try:
            logger.debug("Attempting to reset trial time for product: %s", trial_info.product_name)
            # Save current time
            current_time = datetime.datetime.now()
            self.original_time = current_time
            logger.debug("Original system time: %s", self.original_time)

            # Set time to before trial started
            target_time = trial_info.install_date - datetime.timedelta(days=1)
            logger.debug("Setting system time to target: %s", target_time)

            # Set system time
            if self._set_system_time(target_time):
                logger.debug("System time successfully set to target. Waiting for 2 seconds.")
                # Run application briefly
                time.sleep(2)

                # Restore time
                if self.original_time is not None:
                    self._set_system_time(self.original_time)
                    logger.debug("System time restored to original: %s", self.original_time)
                return True
        except OSError as e:
            logger.warning("Failed to reset trial time for product %s: %s", trial_info.product_name, e)

        return False

    def _set_system_time(self, new_time: datetime.datetime) -> bool:
        """Set Windows system time."""
        try:
            import win32api

            # Convert to Windows SYSTEMTIME
            win32api.SetSystemTime(
                new_time.year,
                new_time.month,
                new_time.weekday(),
                new_time.day,
                new_time.hour,
                new_time.minute,
                new_time.second,
                new_time.microsecond // 1000,
            )
            logger.debug("System time successfully set to: %s", new_time)
            return True
        except OSError as e:
            logger.warning("Failed to set system time to %s: %s", new_time, e)

        return False

    def freeze_time_for_app(self, process_name: str, frozen_time: datetime.datetime) -> bool:
        """Freeze time for specific application."""
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32

        # Process and thread access rights
        PROCESS_ALL_ACCESS = 0x1F0FFF

        # Memory protection constants
        PAGE_EXECUTE_READWRITE = 0x40

        # Find target process
        def find_process_by_name(name: str) -> list[int]:
            """Find process ID by name."""
            processes: list[int] = []
            logger.debug("Searching for process '%s' to freeze time.", name)
            # Create snapshot
            hSnapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
            if hSnapshot == -1:
                logger.warning("Failed to create process snapshot. Cannot find process by name.")
                return processes

            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_char * 260),
                ]

            pe32 = PROCESSENTRY32()
            pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

            if kernel32.Process32First(hSnapshot, ctypes.byref(pe32)):
                while True:
                    if name.lower() in pe32.szExeFile.decode("utf-8", errors="ignore").lower():
                        processes.append(pe32.th32ProcessID)
                        logger.debug("Found process '%s' with PID %s.", pe32.szExeFile.decode("utf-8", errors="ignore"), pe32.th32ProcessID)
                    if not kernel32.Process32Next(hSnapshot, ctypes.byref(pe32)):
                        break

            kernel32.CloseHandle(hSnapshot)
            return processes

        # Hook code to inject

        def inject_time_hooks(pid: int, frozen_time: datetime.datetime) -> bool:
            """Inject time hooks into target process."""
            logger.debug("Injecting time hooks into PID %s for frozen time: %s", pid, frozen_time)
            # Open process
            hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not hProcess:
                logger.warning("Failed to open process %s. Cannot inject time hooks.", pid)
                return False

            try:
                # Allocate memory for hook code and data
                code_size = 4096
                code_addr = kernel32.VirtualAllocEx(
                    hProcess,
                    None,
                    code_size,
                    0x3000,  # MEM_COMMIT | MEM_RESERVE
                    PAGE_EXECUTE_READWRITE,
                )

                if not code_addr:
                    logger.warning("Failed to allocate memory in process %s. Cannot inject time hooks.", pid)
                    return False

                # Convert datetime to SYSTEMTIME structure
                class SYSTEMTIME(ctypes.Structure):
                    _fields_ = [
                        ("wYear", wintypes.WORD),
                        ("wMonth", wintypes.WORD),
                        ("wDayOfWeek", wintypes.WORD),
                        ("wDay", wintypes.WORD),
                        ("wHour", wintypes.WORD),
                        ("wMinute", wintypes.WORD),
                        ("wSecond", wintypes.WORD),
                        ("wMilliseconds", wintypes.WORD),
                    ]

                sys_time = SYSTEMTIME()
                sys_time.wYear = frozen_time.year
                sys_time.wMonth = frozen_time.month
                sys_time.wDayOfWeek = frozen_time.weekday()
                sys_time.wDay = frozen_time.day
                sys_time.wHour = frozen_time.hour
                sys_time.wMinute = frozen_time.minute
                sys_time.wSecond = frozen_time.second
                sys_time.wMilliseconds = frozen_time.microsecond // 1000
                logger.debug(
                    "Frozen SYSTEMTIME structure created: %s-%s-%s %s:%s:%s",
                    sys_time.wYear,
                    sys_time.wMonth,
                    sys_time.wDay,
                    sys_time.wHour,
                    sys_time.wMinute,
                    sys_time.wSecond,
                )

                # Calculate frozen tick count (milliseconds since system start)
                from datetime import timezone

                tick_count = int((frozen_time - datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)).total_seconds() * 1000)
                logger.debug("Frozen tick count: %s", tick_count)

                # Calculate performance counter
                perf_counter = tick_count * 10000  # High resolution
                logger.debug("Frozen performance counter: %s", perf_counter)

                # Build hook code
                hook_bytes = bytearray()

                # GetSystemTime hook
                hook_bytes.extend(
                    [
                        0x48,
                        0x89,
                        0xC8,  # MOV RAX, RCX (parameter)
                        0x48,
                        0xB9,  # MOV RCX, immediate
                    ],
                )
                hook_bytes.extend(struct.pack("<Q", code_addr + 512))  # Address of frozen SYSTEMTIME
                hook_bytes.extend(
                    [
                        0x48,
                        0x89,
                        0xC7,  # MOV RDI, RAX
                        0x48,
                        0x89,
                        0xCE,  # MOV RSI, RCX
                        0xB9,
                        0x10,
                        0x00,
                        0x00,
                        0x00,  # MOV ECX, 16 (size)
                        0xF3,
                        0xA4,  # REP MOVSB
                        0xC3,  # RET
                    ],
                )

                # GetLocalTime hook (similar)
                get_local_time_hook = bytearray(hook_bytes)

                # GetTickCount hook
                get_tick_count_hook = bytearray(
                    [
                        0xB8,  # MOV EAX, immediate
                    ],
                )
                get_tick_count_hook.extend(struct.pack("<I", tick_count & 0xFFFFFFFF))
                get_tick_count_hook.extend([0xC3])  # RET

                # GetTickCount64 hook
                get_tick_count64_hook = bytearray(
                    [
                        0x48,
                        0xB8,  # MOV RAX, immediate
                    ],
                )
                get_tick_count64_hook.extend(struct.pack("<Q", tick_count))
                get_tick_count64_hook.extend([0xC3])  # RET

                # QueryPerformanceCounter hook
                qpc_hook = bytearray(
                    [
                        0x48,
                        0xB8,  # MOV RAX, immediate
                    ],
                )
                qpc_hook.extend(struct.pack("<Q", perf_counter))
                qpc_hook.extend(
                    [
                        0x48,
                        0x89,
                        0x01,  # MOV [RCX], RAX
                        0xB8,
                        0x01,
                        0x00,
                        0x00,
                        0x00,  # MOV EAX, 1
                        0xC3,  # RET
                    ],
                )

                # Write hooks to allocated memory
                offset = 0

                # Write GetSystemTime hook
                get_system_time_addr = code_addr + offset
                bytes_written = ctypes.c_size_t()
                kernel32.WriteProcessMemory(
                    hProcess,
                    get_system_time_addr,
                    bytes(hook_bytes),
                    len(hook_bytes),
                    ctypes.byref(bytes_written),
                )
                offset += len(hook_bytes) + 16
                logger.debug("GetSystemTime hook written to 0x%X", get_system_time_addr)

                # Write GetLocalTime hook
                get_local_time_addr = code_addr + offset
                kernel32.WriteProcessMemory(
                    hProcess,
                    get_local_time_addr,
                    bytes(get_local_time_hook),
                    len(get_local_time_hook),
                    ctypes.byref(bytes_written),
                )
                offset += len(get_local_time_hook) + 16
                logger.debug("GetLocalTime hook written to 0x%X", get_local_time_addr)

                # Write tick count hooks
                get_tick_count_addr = code_addr + offset
                kernel32.WriteProcessMemory(
                    hProcess,
                    get_tick_count_addr,
                    bytes(get_tick_count_hook),
                    len(get_tick_count_hook),
                    ctypes.byref(bytes_written),
                )
                offset += len(get_tick_count_hook) + 16
                logger.debug("GetTickCount hook written to 0x%X", get_tick_count_addr)

                get_tick_count64_addr = code_addr + offset
                kernel32.WriteProcessMemory(
                    hProcess,
                    get_tick_count64_addr,
                    bytes(get_tick_count64_hook),
                    len(get_tick_count64_hook),
                    ctypes.byref(bytes_written),
                )
                offset += len(get_tick_count64_hook) + 16
                logger.debug("GetTickCount64 hook written to 0x%X", get_tick_count64_addr)

                # Write QueryPerformanceCounter hook
                qpc_addr = code_addr + offset
                kernel32.WriteProcessMemory(hProcess, qpc_addr, bytes(qpc_hook), len(qpc_hook), ctypes.byref(bytes_written))
                offset += len(qpc_hook) + 16
                logger.debug("QueryPerformanceCounter hook written to 0x%X", qpc_addr)

                # Write frozen SYSTEMTIME structure
                kernel32.WriteProcessMemory(
                    hProcess,
                    code_addr + 512,
                    ctypes.byref(sys_time),
                    ctypes.sizeof(SYSTEMTIME),
                    ctypes.byref(bytes_written),
                )
                logger.debug("Frozen SYSTEMTIME structure written to 0x%X", code_addr + 512)

                # Now patch the IAT (Import Address Table)
                # Get kernel32.dll base address in target process
                kernel32_base = None

                # Enumerate modules
                hSnapshot = kernel32.CreateToolhelp32Snapshot(0x00000008, pid)  # TH32CS_SNAPMODULE
                if hSnapshot != -1:

                    class MODULEENTRY32(ctypes.Structure):
                        _fields_ = [
                            ("dwSize", wintypes.DWORD),
                            ("th32ModuleID", wintypes.DWORD),
                            ("th32ProcessID", wintypes.DWORD),
                            ("GlblcntUsage", wintypes.DWORD),
                            ("ProccntUsage", wintypes.DWORD),
                            ("modBaseAddr", ctypes.c_void_p),
                            ("modBaseSize", wintypes.DWORD),
                            ("hModule", wintypes.HMODULE),
                            ("szModule", ctypes.c_char * 256),
                            ("szExePath", ctypes.c_char * 260),
                        ]

                    me32 = MODULEENTRY32()
                    me32.dwSize = ctypes.sizeof(MODULEENTRY32)

                    if kernel32.Module32First(hSnapshot, ctypes.byref(me32)):
                        while True:
                            if b"kernel32.dll" in me32.szModule.lower():
                                kernel32_base = me32.modBaseAddr
                                logger.debug("Found kernel32.dll base address in target process: 0x%X", kernel32_base)
                                break
                            if not kernel32.Module32Next(hSnapshot, ctypes.byref(me32)):
                                break

                    kernel32.CloseHandle(hSnapshot)

                # Hook the functions in IAT
                if kernel32_base:
                    # Function names to hook
                    functions_to_hook = [
                        (b"GetSystemTime", get_system_time_addr),
                        (b"GetLocalTime", get_local_time_addr),
                        (b"GetTickCount", get_tick_count_addr),
                        (b"GetTickCount64", get_tick_count64_addr),
                        (b"QueryPerformanceCounter", qpc_addr),
                    ]

                    # This would require parsing PE structure to find IAT
                    # For now, use inline hooks instead

                    # Get function addresses in target process
                    for func_name, hook_addr in functions_to_hook:
                        # Get function address
                        func_addr = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), func_name.decode())

                        if func_addr:
                            logger.debug("Hooking function '%s' at 0x%X with hook at 0x%X", func_name.decode(), func_addr, hook_addr)
                            # Write JMP hook
                            jmp_code = bytearray(
                                [
                                    0xFF,
                                    0x25,
                                    0x00,
                                    0x00,
                                    0x00,
                                    0x00,  # JMP [RIP+0]
                                ],
                            )
                            jmp_code.extend(struct.pack("<Q", hook_addr))

                            # Change protection
                            old_protect = wintypes.DWORD()
                            kernel32.VirtualProtectEx(
                                hProcess,
                                func_addr,
                                len(jmp_code),
                                PAGE_EXECUTE_READWRITE,
                                ctypes.byref(old_protect),
                            )

                            # Write hook
                            kernel32.WriteProcessMemory(
                                hProcess,
                                func_addr,
                                bytes(jmp_code),
                                len(jmp_code),
                                ctypes.byref(bytes_written),
                            )

                            # Restore protection
                            kernel32.VirtualProtectEx(
                                hProcess,
                                func_addr,
                                len(jmp_code),
                                old_protect,
                                ctypes.byref(old_protect),
                            )
                            logger.debug("Successfully hooked '%s'.", func_name.decode())

                return True

            finally:
                kernel32.CloseHandle(hProcess)

        # Find and hook all matching processes
        processes = find_process_by_name(process_name)

        if not processes:
            logger.warning("Process '%s' not found", process_name)
            return False

        success_count = 0
        for pid in processes:
            if inject_time_hooks(pid, frozen_time):
                success_count += 1
                logger.info("Injected time freeze into PID %s", pid)

        if success_count > 0:
            logger.info("Time frozen to %s for %s process(es)", frozen_time, success_count)

            # Store frozen time info
            self.frozen_apps[process_name] = {
                "time": frozen_time,
                "pids": processes,
                "active": True,
            }

            return True
        logger.debug("Time freezing failed for process '%s'.", process_name)
        return False


def automated_trial_reset(product_name: str) -> bool:
    """Automated one-click trial reset."""
    engine = TrialResetEngine()

    logger.info("Scanning for %s trial data...", product_name)
    trial_info = engine.scan_for_trial(product_name)

    if not trial_info.registry_keys and not trial_info.files:
        logger.warning("No trial data found")
        return False

    logger.info("Found %s registry keys", len(trial_info.registry_keys))
    logger.info("Found %s files", len(trial_info.files))
    logger.info("Trial type: %s", trial_info.trial_type.value)

    # Select best strategy
    if trial_info.trial_type == TrialType.TIME_BASED:
        strategy = "time_manipulation"
    elif trial_info.trial_type == TrialType.USAGE_BASED:
        strategy = "registry_clean"
    else:
        strategy = "clean_uninstall"

    logger.info("Resetting trial using %s strategy...", strategy)
    success = engine.reset_trial(trial_info, strategy)

    if success:
        logger.info("Trial reset successful")
    else:
        logger.error("Trial reset failed")

    return success
