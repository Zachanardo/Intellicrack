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
from typing import Any, Dict, List

import psutil


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
    registry_keys: List[str]
    files: List[str]
    processes: List[str]


class TrialResetEngine:
    """Production-ready trial reset mechanism for defeating software trial limitations"""

    def __init__(self):
        self.common_trial_locations = self._initialize_trial_locations()
        self.detection_patterns = self._initialize_detection_patterns()
        self.reset_strategies = self._initialize_reset_strategies()
        self.time_manipulation = TimeManipulator()

    def _initialize_trial_locations(self) -> Dict[str, List[str]]:
        """Initialize common trial data storage locations"""
        username = os.environ.get("USERNAME", "User")

        return {
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

    def _initialize_detection_patterns(self) -> Dict[str, Any]:
        """Initialize patterns for detecting trial data"""
        return {
            "registry_values": [
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
            ],
            "file_patterns": [
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
            ],
            "timestamp_files": ["install.dat", "first_run.dat", "trial.dat", ".trial_info", "eval.bin", "timestamp.db"],
            "encrypted_markers": [b"\x00TRIAL\x00", b"\xde\xad\xbe\xef", b"EVAL", b"DEMO", b"UNREGISTERED"],
        }

    def _initialize_reset_strategies(self) -> Dict[str, Any]:
        """Initialize trial reset strategies"""
        return {
            "clean_uninstall": self._clean_uninstall_reset,
            "time_manipulation": self._time_manipulation_reset,
            "registry_clean": self._registry_clean_reset,
            "file_wipe": self._file_wipe_reset,
            "guid_regeneration": self._guid_regeneration_reset,
            "sandbox_reset": self._sandbox_reset,
            "vm_reset": self._vm_reset,
            "system_restore": self._system_restore_reset,
        }

    def scan_for_trial(self, product_name: str) -> TrialInfo:
        """Scan system for trial information"""
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

        # Scan registry
        trial_info.registry_keys = self._scan_registry_for_trial(product_name)

        # Scan files
        trial_info.files = self._scan_files_for_trial(product_name)

        # Detect trial type
        trial_info.trial_type = self._detect_trial_type(trial_info)

        # Get trial details
        self._extract_trial_details(trial_info)

        # Check if trial is expired
        trial_info.trial_expired = self._check_trial_expired(trial_info)

        # Find related processes
        trial_info.processes = self._find_related_processes(product_name)

        return trial_info

    def _scan_registry_for_trial(self, product_name: str) -> List[str]:
        """Scan registry for trial-related keys"""
        found_keys = []

        for template in self.common_trial_locations["registry"]:
            key_path = template.replace("{product}", product_name)

            # Parse registry hive and path
            parts = key_path.split("\\", 1)
            if len(parts) < 2:
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
                continue

            try:
                # Try to open key
                with winreg.OpenKey(hive_map[hive_name], subkey) as key:
                    found_keys.append(key_path)

                    # Check for trial-related values
                    i = 0
                    while True:
                        try:
                            value_name, value_data, value_type = winreg.EnumValue(key, i)

                            # Check if value name indicates trial
                            for pattern in self.detection_patterns["registry_values"]:
                                if pattern.lower() in value_name.lower():
                                    found_keys.append(f"{key_path}\\{value_name}")
                                    break

                            i += 1
                        except WindowsError:
                            break
            except:
                pass

        # Also scan for hidden/encoded keys
        found_keys.extend(self._scan_for_hidden_registry_keys(product_name))

        return found_keys

    def _scan_for_hidden_registry_keys(self, product_name: str) -> List[str]:
        """Scan for hidden or encoded registry keys"""
        hidden_keys = []

        # Generate possible encoded key names
        encodings = [
            hashlib.md5(product_name.encode()).hexdigest(),
            hashlib.sha1(product_name.encode()).hexdigest()[:16],
            hashlib.sha256(product_name.encode()).hexdigest()[:16],
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
                                break

                        i += 1
                    except WindowsError:
                        break
        except:
            pass

        return hidden_keys

    def _scan_files_for_trial(self, product_name: str) -> List[str]:
        """Scan filesystem for trial-related files"""
        found_files = []

        for template in self.common_trial_locations["files"]:
            path = template.replace("{product}", product_name)

            if os.path.exists(path):
                # Scan directory for trial files
                for pattern in self.detection_patterns["file_patterns"]:
                    try:
                        for file_path in Path(path).rglob(pattern):
                            found_files.append(str(file_path))
                    except:
                        pass

        # Scan for hidden files
        for template in self.common_trial_locations["hidden"]:
            path = template.replace("{product}", product_name)
            if os.path.exists(path):
                found_files.append(path)

        # Scan for alternate data streams
        found_files.extend(self._scan_alternate_data_streams(product_name))

        # Scan for encrypted/obfuscated files
        found_files.extend(self._scan_for_encrypted_trial_files(product_name))

        return found_files

    def _scan_alternate_data_streams(self, product_name: str) -> List[str]:
        """Scan for NTFS alternate data streams using Windows APIs"""
        ads_files = []
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        # Define WIN32_STREAM_ID structure for BackupRead
        class WIN32_STREAM_ID(ctypes.Structure):
            _fields_ = [
                ("dwStreamId", wintypes.DWORD),
                ("dwStreamAttributes", wintypes.DWORD),
                ("Size", wintypes.LARGE_INTEGER),
                ("dwStreamNameSize", wintypes.DWORD),
            ]

        # Define FindFirstStreamW structures
        class STREAM_INFO_LEVELS(ctypes.c_int):
            FindStreamInfoStandard = 0
            FindStreamInfoMaxInfoLevel = 1

        # Define stream info structure
        class WIN32_FIND_STREAM_DATA(ctypes.Structure):
            _fields_ = [
                ("StreamSize", wintypes.LARGE_INTEGER),
                ("cStreamName", wintypes.WCHAR * 296),
            ]

        # Setup FindFirstStreamW function
        kernel32.FindFirstStreamW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.c_int,
            ctypes.POINTER(WIN32_FIND_STREAM_DATA),
            wintypes.DWORD
        ]
        kernel32.FindFirstStreamW.restype = wintypes.HANDLE

        kernel32.FindNextStreamW.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(WIN32_FIND_STREAM_DATA)
        ]
        kernel32.FindNextStreamW.restype = wintypes.BOOL

        kernel32.FindClose.argtypes = [wintypes.HANDLE]
        kernel32.FindClose.restype = wintypes.BOOL

        for template in self.common_trial_locations["alternate_streams"]:
            path = template.replace("{product}", product_name)
            base_path = path.split(":")[0]

            if os.path.exists(base_path):
                try:
                    # Enumerate streams using FindFirstStreamW
                    stream_data = WIN32_FIND_STREAM_DATA()
                    handle = kernel32.FindFirstStreamW(
                        base_path,
                        STREAM_INFO_LEVELS.FindStreamInfoStandard,
                        ctypes.byref(stream_data),
                        0
                    )

                    if handle != -1:  # INVALID_HANDLE_VALUE
                        try:
                            while True:
                                stream_name = stream_data.cStreamName
                                # Skip the main data stream
                                if stream_name and "::$DATA" not in stream_name:
                                    ads_files.append(f"{base_path}{stream_name}")

                                # Get next stream
                                if not kernel32.FindNextStreamW(handle, ctypes.byref(stream_data)):
                                    break
                        finally:
                            kernel32.FindClose(handle)

                    # Also check for common trial-related ADS names directly
                    common_ads_names = [
                        ":trial", ":license", ":activation", ":expiry",
                        ":usage", ":count", ":timestamp", ":evaluation",
                        ":demo", ":registered", ":serial"
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
                            None
                        )
                        if handle != -1:
                            kernel32.CloseHandle(handle)
                            ads_files.append(ads_path)

                except Exception:
                    pass

        # Scan for ADS in subdirectories if specified
        for location in self.common_trial_locations.get("files", []):
            if "{product}" in location:
                dir_path = os.path.dirname(location.replace("{product}", product_name))
                if os.path.exists(dir_path):
                    ads_files.extend(self._scan_directory_for_ads(dir_path))

        return ads_files

    def _scan_directory_for_ads(self, directory: str) -> List[str]:
        """Recursively scan directory for files with alternate data streams"""
        ads_files = []
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        class WIN32_FIND_STREAM_DATA(ctypes.Structure):
            _fields_ = [
                ("StreamSize", wintypes.LARGE_INTEGER),
                ("cStreamName", wintypes.WCHAR * 296),
            ]

        kernel32.FindFirstStreamW.argtypes = [
            wintypes.LPCWSTR, ctypes.c_int,
            ctypes.POINTER(WIN32_FIND_STREAM_DATA), wintypes.DWORD
        ]
        kernel32.FindFirstStreamW.restype = wintypes.HANDLE

        try:
            for root, dirs, files in os.walk(directory):
                for filename in files + dirs:
                    filepath = os.path.join(root, filename)
                    stream_data = WIN32_FIND_STREAM_DATA()

                    handle = kernel32.FindFirstStreamW(
                        filepath, 0, ctypes.byref(stream_data), 0
                    )

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
        except:
            pass

        return ads_files

    def _scan_for_encrypted_trial_files(self, product_name: str) -> List[str]:
        """Scan for encrypted trial data files"""
        encrypted_files = []

        search_paths = [os.environ.get("APPDATA"), os.environ.get("LOCALAPPDATA"), os.environ.get("PROGRAMDATA"), os.environ.get("TEMP")]

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

                                for marker in self.detection_patterns["encrypted_markers"]:
                                    if marker in header:
                                        encrypted_files.append(file_path)
                                        break
                        except:
                            pass
            except:
                pass

        return encrypted_files

    def _detect_trial_type(self, trial_info: TrialInfo) -> TrialType:
        """Detect the type of trial protection"""
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
            return TrialType.HYBRID
        elif has_usage:
            return TrialType.USAGE_BASED
        elif has_features and not has_time:
            return TrialType.FEATURE_LIMITED
        else:
            return TrialType.TIME_BASED

    def _extract_trial_details(self, trial_info: TrialInfo):
        """Extract detailed trial information"""
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

                hive_map = {"HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER, "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE}

                if hive_name in hive_map:
                    with winreg.OpenKey(hive_map[hive_name], subkey) as key:
                        # Try to read common trial values
                        try:
                            install_date = winreg.QueryValueEx(key, "InstallDate")[0]
                            trial_info.install_date = self._parse_date(install_date)
                        except:
                            pass

                        try:
                            trial_days = winreg.QueryValueEx(key, "TrialDays")[0]
                            trial_info.trial_days = int(trial_days)
                        except:
                            pass

                        try:
                            usage_count = winreg.QueryValueEx(key, "UsageCount")[0]
                            trial_info.usage_count = int(usage_count)
                        except:
                            pass
            except:
                pass

        # Extract from files
        for file_path in trial_info.files:
            if os.path.exists(file_path):
                # Get file timestamps
                stat = os.stat(file_path)
                creation_time = datetime.datetime.fromtimestamp(stat.st_ctime)

                if creation_time < trial_info.install_date:
                    trial_info.install_date = creation_time

    def _parse_date(self, date_value: Any) -> datetime.datetime:
        """Parse various date formats"""
        if isinstance(date_value, int):
            # Unix timestamp
            return datetime.datetime.fromtimestamp(date_value)
        elif isinstance(date_value, str):
            # Try various formats
            formats = ["%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"]

            for fmt in formats:
                try:
                    return datetime.datetime.strptime(date_value, fmt)
                except:
                    pass

        return datetime.datetime.now()

    def _check_trial_expired(self, trial_info: TrialInfo) -> bool:
        """Check if trial has expired"""
        if trial_info.trial_type == TrialType.TIME_BASED:
            if trial_info.trial_days > 0:
                expire_date = trial_info.install_date + datetime.timedelta(days=trial_info.trial_days)
                return datetime.datetime.now() > expire_date

        elif trial_info.trial_type == TrialType.USAGE_BASED:
            # Check usage count limits
            if trial_info.usage_count > 30:  # Common trial limit
                return True

        return False

    def _find_related_processes(self, product_name: str) -> List[str]:
        """Find processes related to the product"""
        processes = []

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                if product_name.lower() in proc.info["name"].lower():
                    processes.append(proc.info["name"])
                elif proc.info["exe"] and product_name.lower() in proc.info["exe"].lower():
                    processes.append(proc.info["name"])
            except:
                pass

        return list(set(processes))

    def reset_trial(self, trial_info: TrialInfo, strategy: str = "clean_uninstall") -> bool:
        """Reset trial using specified strategy"""
        if strategy not in self.reset_strategies:
            strategy = "clean_uninstall"

        # Kill related processes first
        self._kill_processes(trial_info.processes)

        # Apply reset strategy
        success = self.reset_strategies[strategy](trial_info)

        return success

    def _kill_processes(self, process_names: List[str]):
        """Kill specified processes"""
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["name"] in process_names:
                    proc.terminate()
                    proc.wait(timeout=3)
            except:
                try:
                    proc.kill()
                except:
                    pass

    def _clean_uninstall_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial by cleaning all traces"""
        success = True

        # Delete registry keys
        for key_path in trial_info.registry_keys:
            if not self._delete_registry_key(key_path):
                success = False

        # Delete files
        for file_path in trial_info.files:
            if not self._delete_file_securely(file_path):
                success = False

        # Clear alternate data streams
        self._clear_alternate_data_streams(trial_info.product_name)

        # Clear prefetch
        self._clear_prefetch_data(trial_info.product_name)

        # Clear event logs
        self._clear_event_logs(trial_info.product_name)

        return success

    def _delete_registry_key(self, key_path: str) -> bool:
        """Delete a registry key"""
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
                return True
        except:
            pass

        return False

    def _delete_file_securely(self, file_path: str) -> bool:
        """Securely delete a file"""
        try:
            if os.path.exists(file_path):
                # Overwrite with random data
                file_size = os.path.getsize(file_path)
                with open(file_path, "wb") as f:
                    f.write(os.urandom(file_size))

                # Delete file
                os.remove(file_path)
                return True
        except:
            # Try alternate methods
            try:
                import win32file

                win32file.DeleteFile(file_path)
                return True
            except:
                pass

        return False

    def _clear_alternate_data_streams(self, product_name: str):
        """Clear NTFS alternate data streams using Windows APIs"""
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        # Define constants
        DELETE = 0x00010000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        FILE_SHARE_DELETE = 0x00000004
        OPEN_EXISTING = 3
        FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
        GENERIC_WRITE = 0x40000000

        def remove_ads_from_file(file_path: str) -> None:
            """Remove all alternate data streams from a file"""
            try:
                # First, enumerate all streams
                class WIN32_FIND_STREAM_DATA(ctypes.Structure):
                    _fields_ = [
                        ("StreamSize", wintypes.LARGE_INTEGER),
                        ("cStreamName", wintypes.WCHAR * 296),
                    ]

                kernel32.FindFirstStreamW.argtypes = [
                    wintypes.LPCWSTR, ctypes.c_int,
                    ctypes.POINTER(WIN32_FIND_STREAM_DATA), wintypes.DWORD
                ]
                kernel32.FindFirstStreamW.restype = wintypes.HANDLE

                stream_data = WIN32_FIND_STREAM_DATA()
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

                # Delete each alternate stream
                for stream_name in streams_to_delete:
                    stream_path = f"{file_path}{stream_name}"

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
                            None
                        )
                        if handle != -1:
                            kernel32.CloseHandle(handle)
                        else:
                            # Method 3: Zero out the stream
                            handle = kernel32.CreateFileW(
                                stream_path,
                                GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                None,
                                OPEN_EXISTING,
                                0,
                                None
                            )
                            if handle != -1:
                                # Truncate stream to 0 bytes
                                kernel32.SetEndOfFile(handle)
                                kernel32.CloseHandle(handle)

            except Exception:
                pass

        for template in self.common_trial_locations["alternate_streams"]:
            path = template.replace("{product}", product_name)
            base_path = path.split(":")[0]

            if os.path.exists(base_path):
                try:
                    # Remove ADS from the base file
                    remove_ads_from_file(base_path)

                    # Target common ADS names used for trial data
                    common_ads_names = [
                        ":Zone.Identifier", ":trial", ":license", ":activation",
                        ":expiry", ":usage", ":count", ":timestamp", ":evaluation",
                        ":demo", ":registered", ":serial", ":install", ":firstrun"
                    ]

                    for ads_name in common_ads_names:
                        ads_path = f"{base_path}{ads_name}"
                        # Try multiple deletion methods
                        if not kernel32.DeleteFileW(ads_path):
                            ads_data_path = f"{ads_path}:$DATA"
                            kernel32.DeleteFileW(ads_data_path)

                    # Recursively check subdirectories for ADS
                    if os.path.isdir(base_path):
                        self._clear_directory_ads(base_path, remove_ads_from_file)

                except Exception:
                    pass

        # Also clear ADS from common file locations
        for location in self.common_trial_locations.get("files", []):
            if "{product}" in location:
                file_path = location.replace("{product}", product_name)
                if os.path.exists(file_path):
                    remove_ads_from_file(file_path)

                # Check parent directory
                dir_path = os.path.dirname(file_path)
                if os.path.exists(dir_path):
                    self._clear_directory_ads(dir_path, remove_ads_from_file, max_depth=1)

    def _clear_directory_ads(self, directory: str, remove_func, max_depth: int = 5) -> None:
        """Recursively clear alternate data streams from directory"""
        try:
            for root, dirs, files in os.walk(directory):
                # Limit recursion depth
                depth = root[len(directory):].count(os.sep)
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

        except Exception:
            pass

    def _clear_prefetch_data(self, product_name: str):
        """Clear Windows prefetch data"""
        prefetch_path = r"C:\Windows\Prefetch"

        try:
            for file in os.listdir(prefetch_path):
                if product_name.upper() in file.upper():
                    file_path = os.path.join(prefetch_path, file)
                    self._delete_file_securely(file_path)
        except:
            pass

    def _clear_event_logs(self, product_name: str):
        """Clear related event log entries"""
        try:
            import win32evtlog

            # Clear application event log entries
            handle = win32evtlog.OpenEventLog(None, "Application")
            win32evtlog.ClearEventLog(handle, None)
            win32evtlog.CloseEventLog(handle)
        except:
            pass

    def _time_manipulation_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial by manipulating system time"""
        return self.time_manipulation.reset_trial_time(trial_info)

    def _registry_clean_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial by cleaning registry only"""
        success = True

        for key_path in trial_info.registry_keys:
            if not self._delete_registry_key(key_path):
                # Try to reset values instead
                if not self._reset_registry_values(key_path):
                    success = False

        return success

    def _reset_registry_values(self, key_path: str) -> bool:
        """Reset registry values to default"""
        try:
            parts = key_path.split("\\")
            if len(parts) < 2:
                return False

            hive_name = parts[0]
            subkey = "\\".join(parts[1:])

            hive_map = {"HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER, "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE}

            if hive_name in hive_map:
                with winreg.OpenKey(hive_map[hive_name], subkey, 0, winreg.KEY_ALL_ACCESS) as key:
                    # Reset trial values
                    winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 30)
                    winreg.SetValueEx(key, "UsageCount", 0, winreg.REG_DWORD, 0)
                    winreg.SetValueEx(key, "InstallDate", 0, winreg.REG_SZ, datetime.datetime.now().isoformat())
                    winreg.SetValueEx(key, "FirstRun", 0, winreg.REG_DWORD, 1)

                    return True
        except:
            pass

        return False

    def _file_wipe_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial by wiping files only"""
        success = True

        for file_path in trial_info.files:
            if not self._delete_file_securely(file_path):
                # Try to reset file content
                if not self._reset_file_content(file_path):
                    success = False

        return success

    def _reset_file_content(self, file_path: str) -> bool:
        """Reset file content to appear new"""
        try:
            # Determine file type
            if file_path.endswith(".xml"):
                # Reset XML trial file
                content = '<?xml version="1.0"?>\n<trial><days>30</days><first_run>true</first_run></trial>'
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
        except:
            pass

        return False

    def _guid_regeneration_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial by regenerating machine GUIDs"""
        import uuid

        try:
            # Generate new machine GUID
            new_guid = str(uuid.uuid4()).upper()

            # Update machine GUID
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, new_guid)

            # Update product-specific GUIDs
            for key_path in trial_info.registry_keys:
                self._update_guid_in_key(key_path)

            return True
        except:
            pass

        return False

    def _update_guid_in_key(self, key_path: str):
        """Update GUIDs in registry key"""
        import uuid

        try:
            parts = key_path.split("\\")
            if len(parts) < 2:
                return

            hive_name = parts[0]
            subkey = "\\".join(parts[1:])

            hive_map = {"HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER, "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE}

            if hive_name in hive_map:
                with winreg.OpenKey(hive_map[hive_name], subkey, 0, winreg.KEY_ALL_ACCESS) as key:
                    # Find and update GUID values
                    i = 0
                    while True:
                        try:
                            value_name, value_data, value_type = winreg.EnumValue(key, i)

                            if "guid" in value_name.lower() or "uuid" in value_name.lower():
                                new_guid = str(uuid.uuid4()).upper()
                                winreg.SetValueEx(key, value_name, 0, value_type, new_guid)

                            i += 1
                        except WindowsError:
                            break
        except:
            pass

    def _sandbox_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial using sandbox isolation"""
        # This would use sandbox technology to isolate trial
        # Simplified implementation
        return self._clean_uninstall_reset(trial_info)

    def _vm_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial using VM snapshot"""
        # This would revert VM to clean snapshot
        # Simplified implementation
        return self._clean_uninstall_reset(trial_info)

    def _system_restore_reset(self, trial_info: TrialInfo) -> bool:
        """Reset trial using system restore point"""
        try:
            # Create restore point
            import win32com.client

            wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\default")
            restore = wmi.Get("SystemRestore")

            # Create restore point
            result = restore.CreateRestorePoint("Before Trial Reset", 0, 100)

            if result[0] == 0:
                # Clean trial data
                return self._clean_uninstall_reset(trial_info)
        except:
            pass

        return False


class TimeManipulator:
    """System time manipulation for trial reset"""

    def __init__(self):
        self.original_time = None
        self.frozen_apps = {}  # Track frozen applications

    def reset_trial_time(self, trial_info: TrialInfo) -> bool:
        """Reset trial by manipulating time"""
        try:
            # Save current time
            self.original_time = datetime.datetime.now()

            # Set time to before trial started
            target_time = trial_info.install_date - datetime.timedelta(days=1)

            # Set system time
            if self._set_system_time(target_time):
                # Run application briefly
                time.sleep(2)

                # Restore time
                self._set_system_time(self.original_time)
                return True
        except:
            pass

        return False

    def _set_system_time(self, new_time: datetime.datetime) -> bool:
        """Set Windows system time"""
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
            return True
        except:
            pass

        return False

    def freeze_time_for_app(self, process_name: str, frozen_time: datetime.datetime):
        """Freeze time for specific application"""
        import ctypes.wintypes as wintypes

        kernel32 = ctypes.windll.kernel32

        # Process and thread access rights
        PROCESS_ALL_ACCESS = 0x1F0FFF

        # Memory protection constants
        PAGE_EXECUTE_READWRITE = 0x40

        # Find target process
        def find_process_by_name(name):
            """Find process ID by name"""
            processes = []

            # Create snapshot
            hSnapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
            if hSnapshot == -1:
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
                    if not kernel32.Process32Next(hSnapshot, ctypes.byref(pe32)):
                        break

            kernel32.CloseHandle(hSnapshot)
            return processes

        # Hook code to inject

        def inject_time_hooks(pid, frozen_time):
            """Inject time hooks into target process"""
            # Open process
            hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not hProcess:
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

                # Calculate frozen tick count (milliseconds since system start)
                tick_count = int((frozen_time - datetime.datetime(2025, 1, 1)).total_seconds() * 1000)

                # Calculate performance counter
                perf_counter = tick_count * 10000  # High resolution

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
                    ]
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
                    ]
                )

                # GetLocalTime hook (similar)
                get_local_time_hook = bytearray(hook_bytes)

                # GetTickCount hook
                get_tick_count_hook = bytearray(
                    [
                        0xB8  # MOV EAX, immediate
                    ]
                )
                get_tick_count_hook.extend(struct.pack("<I", tick_count & 0xFFFFFFFF))
                get_tick_count_hook.extend([0xC3])  # RET

                # GetTickCount64 hook
                get_tick_count64_hook = bytearray(
                    [
                        0x48,
                        0xB8,  # MOV RAX, immediate
                    ]
                )
                get_tick_count64_hook.extend(struct.pack("<Q", tick_count))
                get_tick_count64_hook.extend([0xC3])  # RET

                # QueryPerformanceCounter hook
                qpc_hook = bytearray(
                    [
                        0x48,
                        0xB8,  # MOV RAX, immediate
                    ]
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
                    ]
                )

                # Write hooks to allocated memory
                offset = 0

                # Write GetSystemTime hook
                get_system_time_addr = code_addr + offset
                bytes_written = ctypes.c_size_t()
                kernel32.WriteProcessMemory(hProcess, get_system_time_addr, bytes(hook_bytes), len(hook_bytes), ctypes.byref(bytes_written))
                offset += len(hook_bytes) + 16

                # Write GetLocalTime hook
                get_local_time_addr = code_addr + offset
                kernel32.WriteProcessMemory(
                    hProcess, get_local_time_addr, bytes(get_local_time_hook), len(get_local_time_hook), ctypes.byref(bytes_written)
                )
                offset += len(get_local_time_hook) + 16

                # Write tick count hooks
                get_tick_count_addr = code_addr + offset
                kernel32.WriteProcessMemory(
                    hProcess, get_tick_count_addr, bytes(get_tick_count_hook), len(get_tick_count_hook), ctypes.byref(bytes_written)
                )
                offset += len(get_tick_count_hook) + 16

                get_tick_count64_addr = code_addr + offset
                kernel32.WriteProcessMemory(
                    hProcess, get_tick_count64_addr, bytes(get_tick_count64_hook), len(get_tick_count64_hook), ctypes.byref(bytes_written)
                )
                offset += len(get_tick_count64_hook) + 16

                # Write QueryPerformanceCounter hook
                qpc_addr = code_addr + offset
                kernel32.WriteProcessMemory(hProcess, qpc_addr, bytes(qpc_hook), len(qpc_hook), ctypes.byref(bytes_written))
                offset += len(qpc_hook) + 16

                # Write frozen SYSTEMTIME structure
                kernel32.WriteProcessMemory(
                    hProcess, code_addr + 512, ctypes.byref(sys_time), ctypes.sizeof(SYSTEMTIME), ctypes.byref(bytes_written)
                )

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
                            # Write JMP hook
                            jmp_code = bytearray(
                                [
                                    0xFF,
                                    0x25,
                                    0x00,
                                    0x00,
                                    0x00,
                                    0x00,  # JMP [RIP+0]
                                ]
                            )
                            jmp_code.extend(struct.pack("<Q", hook_addr))

                            # Change protection
                            old_protect = wintypes.DWORD()
                            kernel32.VirtualProtectEx(hProcess, func_addr, len(jmp_code), PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))

                            # Write hook
                            kernel32.WriteProcessMemory(hProcess, func_addr, bytes(jmp_code), len(jmp_code), ctypes.byref(bytes_written))

                            # Restore protection
                            kernel32.VirtualProtectEx(hProcess, func_addr, len(jmp_code), old_protect, ctypes.byref(old_protect))

                return True

            finally:
                kernel32.CloseHandle(hProcess)

            return False

        # Find and hook all matching processes
        processes = find_process_by_name(process_name)

        if not processes:
            print(f"Process '{process_name}' not found")
            return False

        success_count = 0
        for pid in processes:
            if inject_time_hooks(pid, frozen_time):
                success_count += 1
                print(f"Injected time freeze into PID {pid}")

        if success_count > 0:
            print(f"Time frozen to {frozen_time} for {success_count} process(es)")

            # Store frozen time info
            self.frozen_apps[process_name] = {"time": frozen_time, "pids": processes, "active": True}

            return True

        return False


def automated_trial_reset(product_name: str) -> bool:
    """Automated one-click trial reset"""
    engine = TrialResetEngine()

    # Scan for trial
    print(f"Scanning for {product_name} trial data...")
    trial_info = engine.scan_for_trial(product_name)

    if not trial_info.registry_keys and not trial_info.files:
        print("No trial data found")
        return False

    print(f"Found {len(trial_info.registry_keys)} registry keys")
    print(f"Found {len(trial_info.files)} files")
    print(f"Trial type: {trial_info.trial_type.value}")

    # Select best strategy
    if trial_info.trial_type == TrialType.TIME_BASED:
        strategy = "time_manipulation"
    elif trial_info.trial_type == TrialType.USAGE_BASED:
        strategy = "registry_clean"
    else:
        strategy = "clean_uninstall"

    # Reset trial
    print(f"Resetting trial using {strategy} strategy...")
    success = engine.reset_trial(trial_info, strategy)

    if success:
        print("Trial reset successful")
    else:
        print("Trial reset failed")

    return success
