"""Program Discovery Engine for Intellicrack.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from ..core.path_discovery import PathDiscovery
from .file_resolution import file_resolver


logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform.startswith("darwin")

# Windows registry imports
if IS_WINDOWS:
    try:
        import winreg

        HAS_WINREG = True
    except ImportError as e:
        logger.exception("Import error in program_discovery: %s", e)
        HAS_WINREG = False
        winreg = None
else:
    HAS_WINREG = False
    winreg = None


@dataclass
class ProgramInfo:
    """Information about an installed program."""

    name: str
    display_name: str
    version: str
    publisher: str
    install_location: str
    executable_paths: list[str]
    icon_path: str | None
    uninstall_string: str | None
    install_date: str | None
    estimated_size: int | None
    architecture: str | None
    file_types: list[str]
    description: str | None
    registry_key: str | None
    discovery_method: str
    confidence_score: float
    analysis_priority: int


class ProgramDiscoveryEngine:
    """Engine for discovering installed programs and potential analysis targets."""

    # Common executable directories for different platforms
    COMMON_EXECUTABLE_DIRS = {
        "windows": [
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\ProgramData",
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
            r"C:\Users\{username}\AppData\Local",
            r"C:\Users\{username}\AppData\Roaming",
        ],
        "linux": [
            "/usr/bin",
            "/usr/local/bin",
            "/opt",
            "/snap",
            "/usr/share",
            "/home/{username}/.local/bin",
            "/home/{username}/bin",
        ],
        "macos": [
            "/Applications",
            "/System/Applications",
            "/usr/local/bin",
            "/opt",
            "/Users/{username}/Applications",
            "/Users/{username}/.local/bin",
        ],
    }

    # Registry paths for Windows program discovery
    WINDOWS_REGISTRY_PATHS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") if HAS_WINREG else (None, None),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        )
        if HAS_WINREG
        else (None, None),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") if HAS_WINREG else (None, None),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\Applications") if HAS_WINREG else (None, None),
    ]

    # Priority targets for analysis (higher score = higher priority)
    ANALYSIS_PRIORITIES = {
        # Security and protection software
        "antivirus": 10,
        "firewall": 10,
        "vpn": 10,
        "security": 10,
        # Development tools
        "debugger": 9,
        "disassembler": 9,
        "decompiler": 9,
        "hex editor": 9,
        "ghidra": 9,
        "radare2": 9,
        "x64dbg": 9,
        "ollydbg": 9,
        # Commercial software with licensing
        "adobe": 8,
        "autodesk": 8,
        "microsoft office": 8,
        "solidworks": 8,
        "matlab": 8,
        "vmware": 8,
        "virtualbox": 8,
        # Games and entertainment
        "steam": 7,
        "game": 7,
        "unity": 7,
        "unreal": 7,
        # Common applications
        "browser": 6,
        "chrome": 6,
        "firefox": 6,
        "edge": 6,
        # System utilities
        "system": 5,
        "utility": 5,
        "tool": 5,
        # Default priority
        "default": 3,
    }

    def __init__(self, cache_file: str | None = None) -> None:
        """Initialize the program discovery engine."""
        self.logger = logger
        self.path_discovery = PathDiscovery()
        self.cache_file = cache_file or self._get_default_cache_file()
        self.programs_cache: dict[str, ProgramInfo] = {}
        self.last_scan_time: float | None = None

        # Load cached data if available
        self._load_cache()

    def _get_default_cache_file(self) -> str:
        """Get default cache file path."""
        cache_dir = Path.home() / ".intellicrack"
        cache_dir.mkdir(exist_ok=True)
        return str(cache_dir / "program_discovery_cache.json")

    def analyze_program_from_path(self, program_path: str) -> ProgramInfo | None:
        """Analyze a program from its installation path.

        Args:
            program_path: Path to analyze (can be executable or installation folder)

        Returns:
            ProgramInfo object if analysis successful, None otherwise

        """
        try:
            program_path = Path(program_path)

            if not program_path.exists():
                return None

            # If it's a file, analyze the file and its parent directory
            if program_path.is_file():
                executable_path = program_path
                install_location = program_path.parent
            else:
                # It's a directory, find main executable
                install_location = program_path
                executable_path = self._find_main_executable(install_location)

            # Get basic file information
            display_name = executable_path.stem if executable_path else install_location.name

            # Try to get version info from executable
            version = "Unknown"
            publisher = "Unknown"

            if executable_path and executable_path.exists():
                if IS_WINDOWS:
                    version, publisher = self._get_windows_version_info(executable_path)
                else:
                    version, publisher = self._get_unix_version_info(executable_path)

            # Analyze installation folder for additional info
            folder_analysis = self._analyze_installation_folder(install_location)

            # Determine analysis priority
            priority = self._calculate_analysis_priority(display_name, str(install_location))

            program_info = ProgramInfo(
                name=display_name.lower(),
                display_name=display_name,
                version=version,
                publisher=publisher,
                install_location=str(install_location),
                executable_paths=[str(executable_path)] if executable_path else [],
                icon_path=folder_analysis.get("icon_path"),
                uninstall_string=None,
                install_date=None,
                estimated_size=folder_analysis.get("total_size", 0),
                architecture=folder_analysis.get("architecture", "Unknown"),
                file_types=folder_analysis.get("file_types", []),
                description=f"Program analyzed from path: {program_path}",
                registry_key=None,
                discovery_method="path_analysis",
                confidence_score=0.8,
                analysis_priority=priority,
            )

            return program_info

        except Exception as e:
            self.logger.exception("Error analyzing program from path %s: %s", program_path, e)
            return None

    def discover_programs_from_path(self, search_path: str) -> list[ProgramInfo]:
        """Discover programs from a specific path (like desktop folder).

        Args:
            search_path: Path to search for programs

        Returns:
            List of discovered programs

        """
        programs = []
        search_path = Path(search_path)

        if not search_path.exists():
            return programs

        try:
            # Look for shortcuts and executables
            for file_path in search_path.iterdir():
                if file_path.is_file() and file_path.suffix.lower() in [".lnk", ".url", ".exe", ".app"]:
                    resolved_path, metadata = file_resolver.resolve_file_path(file_path)

                    if "error" not in metadata:
                        if program_info := self.analyze_program_from_path(resolved_path):
                            programs.append(program_info)

        except Exception as e:
            self.logger.exception("Error discovering programs from path %s: %s", search_path, e)

        return programs

    def get_installed_programs(self) -> list[ProgramInfo]:
        """Get list of installed programs from system registry/package manager."""
        programs = []

        if IS_WINDOWS:
            programs.extend(self._get_windows_programs())
        elif IS_LINUX:
            programs.extend(self._get_linux_programs())
        elif IS_MACOS:
            programs.extend(self._get_macos_programs())

        return programs

    def scan_executable_directories(self) -> list[ProgramInfo]:
        """Scan common executable directories for programs."""
        programs = []

        # Get platform-specific directories
        if IS_WINDOWS:
            dirs = self.COMMON_EXECUTABLE_DIRS["windows"]
        elif IS_LINUX:
            dirs = self.COMMON_EXECUTABLE_DIRS["linux"]
        elif IS_MACOS:
            dirs = self.COMMON_EXECUTABLE_DIRS["macos"]
        else:
            return programs

        # Substitute {username} token with actual username in directory paths
        username = os.environ.get("USER", os.environ.get("USERNAME", "user"))
        dirs = [d.replace("{username}", username) for d in dirs]

        for dir_path in dirs:
            if os.path.exists(dir_path):
                try:
                    discovered_programs = self.discover_programs_from_path(dir_path)
                    programs.extend(discovered_programs)
                except Exception as e:
                    self.logger.debug("Error scanning directory %s: %s", dir_path, e)

        return programs

    def _find_main_executable(self, folder_path: Path) -> Path | None:
        """Find the main executable in a program folder."""
        if not folder_path.is_dir():
            return None

        # Common executable patterns
        exe_patterns = ["*.exe", "*.app", "*.bin"] if IS_WINDOWS else ["*"]

        # Look for executables in order of priority
        for pattern in exe_patterns:
            for exe_file in folder_path.glob(pattern):
                if exe_file.is_file() and exe_file.stem.lower() == folder_path.name.lower():
                    return exe_file

        # Fallback: return first executable found
        for pattern in exe_patterns:
            for exe_file in folder_path.glob(pattern):
                if exe_file.is_file():
                    return exe_file

        return None

    def _analyze_installation_folder(self, folder_path: Path) -> dict[str, any]:
        """Analyze program installation folder for metadata."""
        analysis = {
            "total_size": 0,
            "file_types": [],
            "architecture": "Unknown",
            "icon_path": None,
            "has_licensing": False,
            "licensing_files": [],
        }

        try:
            if not folder_path.is_dir():
                return analysis

            file_extensions = set()
            total_size = 0

            # Analyze files in folder
            for file_path in folder_path.rglob("*"):
                if file_path.is_file():
                    try:
                        file_size = file_path.stat().st_size
                        total_size += file_size

                        # Track file extensions
                        if file_path.suffix:
                            file_extensions.add(file_path.suffix.lower())

                        # Look for icon files
                        if file_path.suffix.lower() in [".ico", ".png", ".jpg", ".svg"] and not analysis["icon_path"]:
                            analysis["icon_path"] = str(file_path)

                        # Look for licensing files using comprehensive patterns
                        filename_lower = file_path.name.lower()
                        licensing_indicators = [
                            # Common licensing terms
                            "license",
                            "licence",
                            "eula",
                            "terms",
                            "agreement",
                            "copyright",
                            "legal",
                            "rights",
                            "disclaimer",
                            "activation",
                            "serial",
                            "key",
                            "keyfile",
                            "authenticate",
                            "register",
                            "unlock",
                            "crack",
                            "patch",
                            "keygen",
                            "dongle",
                            "hasp",
                            "sentinel",
                            "flexlm",
                            "safenet",
                            "token",
                            "permit",
                            "grant",
                            "cert",
                            "sig",
                            "fingerprint",
                            "expire",
                            "timeout",
                            "protected",
                            "secured",
                            "locked",
                        ]

                        if any(pattern in filename_lower for pattern in licensing_indicators) or file_path.suffix.lower() in [
                            ".lic",
                            ".license",
                            ".key",
                            ".dat",
                            ".bin",
                        ]:
                            analysis["has_licensing"] = True
                            analysis["licensing_files"].append(str(file_path))

                        # Determine architecture from executables
                        if file_path.suffix.lower() in [".exe", ".dll"]:
                            arch = self._get_pe_architecture(file_path)
                            if arch != "Unknown":
                                analysis["architecture"] = arch

                    except OSError as e:
                        logger.exception("Error in program_discovery: %s", e)
                        continue

            analysis["total_size"] = total_size
            analysis["file_types"] = list(file_extensions)

        except Exception as e:
            self.logger.debug("Error analyzing folder %s: %s", folder_path, e)

        return analysis

    def _get_pe_architecture(self, pe_path: Path) -> str:
        """Get architecture from PE file."""
        try:
            import struct

            with open(pe_path, "rb") as f:
                # Read DOS header
                dos_header = f.read(64)
                if len(dos_header) < 60:
                    return "Unknown"

                # Get PE header offset
                pe_offset = struct.unpack("<I", dos_header[60:64])[0]
                f.seek(pe_offset)

                # Read PE signature and file header
                pe_sig = f.read(4)
                if pe_sig != b"PE\x00\x00":
                    return "Unknown"

                file_header = f.read(20)
                if len(file_header) < 20:
                    return "Unknown"

                # Extract machine type
                machine_type = struct.unpack("<H", file_header[:2])[0]

                # Map machine type to architecture
                arch_map = {
                    0x014C: "x86",  # IMAGE_FILE_MACHINE_I386
                    0x8664: "x64",  # IMAGE_FILE_MACHINE_AMD64
                    0x01C0: "ARM",  # IMAGE_FILE_MACHINE_ARM
                    0xAA64: "ARM64",  # IMAGE_FILE_MACHINE_ARM64
                }

                return arch_map.get(machine_type, "Unknown")

        except Exception as e:
            logger.exception("Exception in program_discovery: %s", e)
            return "Unknown"

    def _get_windows_version_info(self, exe_path: Path) -> tuple[str, str]:
        """Get version and publisher info from Windows executable."""
        try:
            if HAS_WINREG:
                try:
                    import win32api

                    version_info = win32api.GetFileVersionInfo(str(exe_path), "\\")

                    version = f"{version_info['FileVersionMS'] >> 16}.{version_info['FileVersionMS'] & 0xFFFF}.{version_info['FileVersionLS'] >> 16}.{version_info['FileVersionLS'] & 0xFFFF}"
                except ImportError as e:
                    self.logger.exception("Import error in program_discovery: %s", e)
                    return "Unknown", "Unknown"

                if string_info := version_info.get("StringFileInfo", {}):
                    first_key = next(iter(string_info.keys()))
                    string_table = string_info[first_key]
                    publisher = string_table.get("CompanyName", "Unknown")
                else:
                    publisher = "Unknown"

                return version, publisher
        except Exception as e:
            self.logger.debug("Error getting Windows version info for %s: %s", exe_path, e)

        return "Unknown", "Unknown"

    def _get_unix_version_info(self, exe_path: Path) -> tuple[str, str]:
        """Get version and publisher info from Unix executable."""
        try:
            # Try to get version from --version flag
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                [str(exe_path), "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout:
                version_line = result.stdout.split("\n")[0]
                if version_match := re.search(r"(\d+\.\d+\.\d+)", version_line):
                    return version_match[1], "Unknown"
        except Exception as e:
            self.logger.debug("Error getting Unix version info for %s: %s", exe_path, e)

        return "Unknown", "Unknown"

    def _calculate_analysis_priority(self, program_name: str, install_path: str) -> int:
        """Calculate analysis priority for a program."""
        program_name_lower = program_name.lower()
        install_path_lower = install_path.lower()

        return next(
            (
                priority
                for keyword, priority in self.ANALYSIS_PRIORITIES.items()
                if keyword in program_name_lower or keyword in install_path_lower
            ),
            self.ANALYSIS_PRIORITIES["default"],
        )

    def _get_windows_programs(self) -> list[ProgramInfo]:
        """Get Windows programs from registry."""
        if not IS_WINDOWS or not HAS_WINREG:
            return []

        programs = []

        for hkey, path in self.WINDOWS_REGISTRY_PATHS:
            if hkey is None or path is None:
                continue

            programs.extend(self._scan_registry_path(hkey, path, False))

        return programs

    def _get_linux_programs(self) -> list[ProgramInfo]:
        """Get Linux programs from package managers."""
        programs = []

        # Try different package managers
        try:
            if dpkg_path := shutil.which("dpkg"):
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    [dpkg_path, "-l"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False,  # Explicitly secure - using list format prevents shell injection
                )
                if result.returncode == 0:
                    programs.extend(self._parse_dpkg_output(result.stdout))
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.exception("Error in program_discovery: %s", e)

        try:
            if rpm_path := shutil.which("rpm"):
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    [rpm_path, "-qa"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False,  # Explicitly secure - using list format prevents shell injection
                )
                if result.returncode == 0:
                    programs.extend(self._parse_rpm_output(result.stdout))
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.exception("Error in program_discovery: %s", e)

        return programs

    def _get_macos_programs(self) -> list[ProgramInfo]:
        """Get macOS programs from Applications folder."""
        programs = []

        app_dirs = ["/Applications", "/System/Applications"]
        if user_home := os.path.expanduser("~"):
            app_dirs.append(os.path.join(user_home, "Applications"))

        for app_dir in app_dirs:
            if os.path.exists(app_dir):
                try:
                    for item in os.listdir(app_dir):
                        if item.endswith(".app"):
                            app_path = os.path.join(app_dir, item)
                            if program := self.analyze_program_from_path(app_path):
                                programs.append(program)
                except PermissionError as e:
                    self.logger.exception("Permission error in program_discovery: %s", e)
                    continue

        return programs

    def _parse_dpkg_output(self, output: str) -> list[ProgramInfo]:
        """Parse dpkg output to extract program information."""
        programs = []

        for line in output.split("\n")[5:]:  # Skip header lines
            if line.startswith("ii"):  # Installed packages
                parts = line.split()
                if len(parts) >= 4:
                    name = parts[1]
                    version = parts[2]
                    description = " ".join(parts[3:])

                    programs.append(
                        ProgramInfo(
                            name=name,
                            display_name=name,
                            version=version,
                            publisher="Unknown",
                            install_location="/usr",
                            executable_paths=[],
                            icon_path=None,
                            uninstall_string=f"apt remove {name}",
                            install_date=None,
                            estimated_size=None,
                            architecture="Unknown",
                            file_types=[],
                            description=description,
                            registry_key=None,
                            discovery_method="dpkg",
                            confidence_score=0.9,
                            analysis_priority=self._calculate_analysis_priority(name, "/usr"),
                        ),
                    )

        return programs

    def _parse_rpm_output(self, output: str) -> list[ProgramInfo]:
        """Parse rpm output to extract program information."""
        programs = []

        for line in output.split("\n"):
            if line.strip():
                if match := re.match(r"^(.+?)-([^-]+)-([^-]+)\.(.+)$", line.strip()):
                    name = match[1]
                    version = match[2]
                    release = match[3]
                    arch = match[4]

                    programs.append(
                        ProgramInfo(
                            name=name,
                            display_name=name,
                            version=f"{version}-{release}",
                            publisher="Unknown",
                            install_location="/usr",
                            executable_paths=[],
                            icon_path=None,
                            uninstall_string=f"rpm -e {name}",
                            install_date=None,
                            estimated_size=None,
                            architecture=arch,
                            file_types=[],
                            description=f"RPM package {name}",
                            registry_key=None,
                            discovery_method="rpm",
                            confidence_score=0.9,
                            analysis_priority=self._calculate_analysis_priority(name, "/usr"),
                        ),
                    )

        return programs

    def _scan_registry_path(self, hkey: object, path: str, include_system: bool) -> list[ProgramInfo]:
        """Scan a specific registry path for installed programs."""
        programs = []
        self.logger.debug("Scanning registry path %s, include_system=%s", path, include_system)

        try:
            with winreg.OpenKey(hkey, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        if program := self._extract_program_from_registry(hkey, path, subkey_name, include_system):
                            programs.append(program)
                    except (OSError, ValueError) as e:
                        self.logger.debug("Error reading registry subkey %s: %s", subkey_name, e)
                        continue

        except (OSError, ValueError) as e:
            self.logger.debug("Error accessing registry path %s: %s", path, e)

        return programs

    def _extract_program_from_registry(self, hkey: object, path: str, subkey_name: str, include_system: bool) -> ProgramInfo | None:
        """Extract program information from a registry entry."""
        try:
            with winreg.OpenKey(hkey, f"{path}\\{subkey_name}") as subkey:
                # Get basic information
                display_name = self._get_registry_value(subkey, "DisplayName")
                if not display_name:
                    return None

                # Skip system components unless requested
                if not include_system and self._is_system_component(display_name, subkey_name):
                    self.logger.debug("Skipping system component: %s", display_name)
                    return None

                version = self._get_registry_value(subkey, "DisplayVersion") or "Unknown"
                publisher = self._get_registry_value(subkey, "Publisher") or "Unknown"
                install_location = self._get_registry_value(subkey, "InstallLocation")
                uninstall_string = self._get_registry_value(subkey, "UninstallString")
                install_date = self._get_registry_value(subkey, "InstallDate")
                estimated_size = self._get_registry_value(subkey, "EstimatedSize")

                # Try to get architecture
                architecture = "Unknown"
                if install_location and os.path.exists(install_location):
                    folder_analysis = self._analyze_installation_folder(Path(install_location))
                    architecture = folder_analysis.get("architecture", "Unknown")

                # Find executable paths
                executable_paths = []
                if install_location and os.path.exists(install_location):
                    if main_exe := self._find_main_executable(Path(install_location)):
                        executable_paths.append(str(main_exe))

                return ProgramInfo(
                    name=display_name.lower().replace(" ", "_"),
                    display_name=display_name,
                    version=version,
                    publisher=publisher,
                    install_location=install_location or "Unknown",
                    executable_paths=executable_paths,
                    icon_path=None,
                    uninstall_string=uninstall_string,
                    install_date=install_date,
                    estimated_size=estimated_size,
                    architecture=architecture,
                    file_types=[],
                    description=f"Installed program: {display_name}",
                    registry_key=f"{path}\\{subkey_name}",
                    discovery_method="windows_registry",
                    confidence_score=0.9,
                    analysis_priority=self._calculate_analysis_priority(display_name, install_location or ""),
                )
        except Exception as e:
            self.logger.debug("Error extracting program from registry %s: %s", subkey_name, e)
            return None

    def _get_registry_value(self, key: object, value_name: str) -> str | None:
        """Get a value from a registry key safely."""
        try:
            value, _ = winreg.QueryValueEx(key, value_name)
            return str(value) if value else None
        except (OSError, ValueError) as e:
            self.logger.exception("Error in program_discovery: %s", e)
            return None

    def _is_system_component(self, display_name: str, subkey_name: str) -> bool:
        """Check if a program is a system component."""
        system_indicators = [
            "microsoft visual c++",
            "microsoft .net",
            "windows",
            "update",
            "kb",
            "hotfix",
            "security update",
            "service pack",
            "redistributable",
            "runtime",
        ]

        name_lower = display_name.lower()
        key_lower = subkey_name.lower()

        return any(indicator in name_lower or indicator in key_lower for indicator in system_indicators)

    def _should_use_cache(self) -> bool:
        """Check if cached data should be used."""
        if not self.last_scan_time or not self.programs_cache:
            return False

        # Cache is valid for 1 hour
        cache_age = time.time() - self.last_scan_time
        return cache_age < 3600

    def _get_cached_programs(self) -> list[ProgramInfo]:
        """Get programs from cache."""
        program_list = list(self.programs_cache.values())
        program_list.sort(key=lambda p: (p.analysis_priority, p.confidence_score), reverse=True)
        return program_list

    def _load_cache(self) -> None:
        """Load cached program data."""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file) as f:
                    cache_data = json.load(f)

                self.last_scan_time = cache_data.get("last_scan_time")
                programs_data = cache_data.get("programs", {})

                # Convert dictionaries back to ProgramInfo objects
                for key, program_dict in programs_data.items():
                    self.programs_cache[key] = ProgramInfo(**program_dict)

        except Exception as e:
            self.logger.debug("Error loading cache: %s", e)
            self.programs_cache = {}
            self.last_scan_time = None

    def _save_cache(self) -> None:
        """Save program data to cache."""
        try:
            cache_data = {
                "last_scan_time": self.last_scan_time,
                "programs": {key: asdict(program) for key, program in self.programs_cache.items()},
            }

            with open(self.cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)

        except Exception as e:
            self.logger.debug("Error saving cache: %s", e)


# Create global instance for easy access
program_discovery_engine = ProgramDiscoveryEngine()
