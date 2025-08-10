"""Memory Forensics Engine

Advanced memory analysis using Volatility3 framework for runtime binary examination.
Provides comprehensive memory dump analysis, process inspection, and runtime forensics
capabilities for security research and incident response.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ...utils.logger import get_logger

logger = get_logger(__name__)

try:
    import volatility3
    import volatility3.framework
    import volatility3.framework.automagic
    import volatility3.framework.configuration
    import volatility3.framework.contexts
    import volatility3.framework.interfaces
    import volatility3.framework.plugins
    from volatility3.cli import text_renderer
    from volatility3.framework import automagic, configuration, constants, contexts, plugins
    from volatility3.framework.configuration import requirements

    VOLATILITY3_AVAILABLE = True
except ImportError:
    VOLATILITY3_AVAILABLE = False
    logger.warning("Volatility3 not available - memory forensics analysis disabled")


class MemoryArtifactType(Enum):
    """Types of memory artifacts"""

    PROCESS_LIST = "process_list"
    NETWORK_CONNECTIONS = "network_connections"
    FILE_HANDLES = "file_handles"
    REGISTRY_KEYS = "registry_keys"
    LOADED_MODULES = "loaded_modules"
    MEMORY_SECTIONS = "memory_sections"
    INJECTED_CODE = "injected_code"
    HIDDEN_PROCESSES = "hidden_processes"
    ROOTKIT_ARTIFACTS = "rootkit_artifacts"
    LICENSE_BYPASS_INDICATORS = "license_bypass_indicators"
    CREDENTIAL_MATERIAL = "credential_material"
    ENCRYPTED_REGIONS = "encrypted_regions"


class AnalysisProfile(Enum):
    """Memory analysis profiles"""

    WINDOWS_10 = "Win10x64_19041"
    WINDOWS_11 = "Win11x64_22000"
    WINDOWS_7 = "Win7SP1x64"
    WINDOWS_XP = "WinXPSP2x86"
    LINUX_GENERIC = "LinuxGeneric"
    MAC_OSX = "Mac"
    AUTO_DETECT = "auto"


@dataclass
class MemoryProcess:
    """Information about a process in memory"""

    pid: int
    ppid: int
    name: str
    command_line: str = ""
    create_time: str = ""
    exit_time: str = ""
    image_base: int = 0
    image_size: int = 0
    session_id: int = 0
    handle_count: int = 0
    thread_count: int = 0
    wow64: bool = False
    is_hidden: bool = False
    suspicious_indicators: list[str] = field(default_factory=list)


@dataclass
class MemoryModule:
    """Information about a loaded module"""

    base_address: int
    size: int
    name: str
    path: str
    version: str = ""
    company: str = ""
    description: str = ""
    is_signed: bool = False
    is_suspicious: bool = False
    hash_md5: str = ""
    hash_sha256: str = ""


@dataclass
class NetworkConnection:
    """Network connection information"""

    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    protocol: str
    state: str
    pid: int
    process_name: str = ""
    create_time: str = ""


@dataclass
class MemoryString:
    """String found in memory"""

    offset: int
    value: str
    encoding: str
    context: str = ""  # process/module context
    is_unicode: bool = False
    confidence: float = 1.0


@dataclass
class MemoryAnalysisResult:
    """Complete memory analysis results"""

    dump_path: str
    analysis_profile: str = ""
    processes: list[MemoryProcess] = field(default_factory=list)
    modules: list[MemoryModule] = field(default_factory=list)
    network_connections: list[NetworkConnection] = field(default_factory=list)
    memory_strings: list[MemoryString] = field(default_factory=list)
    registry_artifacts: list[dict[str, Any]] = field(default_factory=list)
    file_handles: list[dict[str, Any]] = field(default_factory=list)
    security_findings: list[dict[str, Any]] = field(default_factory=list)
    analysis_time: float = 0.0
    artifacts_found: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    @property
    def has_suspicious_activity(self) -> bool:
        """Check if any suspicious activity was detected"""
        return (
            any(p.is_hidden for p in self.processes)
            or any(p.suspicious_indicators for p in self.processes)
            or any(m.is_suspicious for m in self.modules)
            or len(self.security_findings) > 0
        )

    @property
    def hidden_process_count(self) -> int:
        """Get count of hidden processes"""
        return sum(1 for p in self.processes if p.is_hidden)


class MemoryForensicsEngine:
    """Advanced memory forensics analysis engine using Volatility3.

    Provides comprehensive memory dump analysis including:
    - Process and thread analysis
    - Network connection forensics
    - Module and DLL analysis
    - Registry artifact extraction
    - License bypass detection and analysis
    - Credential extraction
    - Rootkit detection
    """

    def __init__(self, cache_directory: str | None = None):
        """Initialize the memory forensics engine with cache configuration and plugin detection."""
        self.logger = logging.getLogger("IntellicrackLogger.MemoryForensics")

        # Set up cache directory
        if cache_directory:
            self.cache_directory = Path(cache_directory)
        else:
            self.cache_directory = Path("./cache/memory_forensics")

        self.cache_directory.mkdir(parents=True, exist_ok=True)

        # Initialize Volatility if available
        self.volatility_available = VOLATILITY3_AVAILABLE
        if not self.volatility_available:
            self.logger.warning("Volatility not available - memory analysis will be limited")

        # Results storage
        self.analysis_results = {}

    def _init_volatility(self):
        """Initialize Volatility3 framework"""
        try:
            # Initialize Volatility3 context
            self.vol_context = contexts.Context()

            # Set up configuration
            self.vol_config = configuration.HierarchicalDict()

            # Initialize automagic modules
            self.automagics = automagic.choose_automagic(
                automagic.available(self.vol_context),
                self.vol_context,
            )

            logger.info("Volatility3 framework initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize Volatility3: {e}")
            global VOLATILITY3_AVAILABLE
            VOLATILITY3_AVAILABLE = False

    def analyze_memory_dump(
        self,
        dump_path: str | Path,
        profile: AnalysisProfile = AnalysisProfile.AUTO_DETECT,
        deep_analysis: bool = True,
    ) -> MemoryAnalysisResult:
        """Analyze a memory dump file for forensic artifacts

        Args:
            dump_path: Path to the memory dump file
            profile: Memory analysis profile to use
            deep_analysis: Whether to perform deep analysis

        Returns:
            Complete memory forensics analysis results

        """
        start_time = time.time()
        dump_path = str(dump_path)

        if not os.path.exists(dump_path):
            return MemoryAnalysisResult(
                dump_path=dump_path,
                error=f"Memory dump not found: {dump_path}",
            )

        if not VOLATILITY3_AVAILABLE:
            return self._fallback_memory_analysis(dump_path)

        try:
            result = MemoryAnalysisResult(dump_path=dump_path)

            # Track analyzed dumps to prevent duplicate processing
            abs_path = os.path.abspath(dump_path)
            if abs_path in self.analyzed_dumps:
                logger.debug(f"Memory dump already analyzed: {abs_path}")
            self.analyzed_dumps.add(abs_path)

            # Detect profile if auto-detect
            if profile == AnalysisProfile.AUTO_DETECT:
                detected_profile = self._detect_profile(dump_path)
                result.analysis_profile = detected_profile
            else:
                result.analysis_profile = profile.value

            # Configure Volatility3 for this dump
            self._configure_volatility(dump_path, result.analysis_profile)

            # Run core analysis plugins
            logger.info("Running process analysis")
            result.processes = self._analyze_processes()

            logger.info("Running module analysis")
            result.modules = self._analyze_modules()

            logger.info("Running network analysis")
            result.network_connections = self._analyze_network_connections()

            if deep_analysis:
                logger.info("Running deep analysis")
                result.registry_artifacts = self._analyze_registry()
                result.file_handles = self._analyze_file_handles()
                result.memory_strings = self._extract_memory_strings()
                result.security_findings = self._detect_security_issues(result)

            # Generate artifact summary
            result.artifacts_found = {
                "processes": len(result.processes),
                "modules": len(result.modules),
                "network_connections": len(result.network_connections),
                "registry_keys": len(result.registry_artifacts),
                "file_handles": len(result.file_handles),
                "memory_strings": len(result.memory_strings),
                "security_findings": len(result.security_findings),
            }

            result.analysis_time = time.time() - start_time

            logger.info(f"Memory analysis complete: {result.artifacts_found}")
            return result

        except Exception as e:
            logger.error(f"Memory forensics analysis failed: {e}")
            return MemoryAnalysisResult(
                dump_path=dump_path,
                error=str(e),
                analysis_time=time.time() - start_time,
            )

    def _fallback_memory_analysis(self, dump_path: str) -> MemoryAnalysisResult:
        """Fallback analysis when Volatility3 is not available"""
        result = MemoryAnalysisResult(dump_path=dump_path)

        try:
            # Basic file information
            dump_size = os.path.getsize(dump_path)

            # Try using subprocess to gather system information about the dump
            try:
                file_result = subprocess.run(  # nosec S603 - Using file command for file type detection  # noqa: S603
                    ["file", dump_path],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,  # noqa: S607
                )
                if file_result.returncode == 0:
                    result.analysis_profile = file_result.stdout.strip()
                    logger.debug(f"File command output: {file_result.stdout}")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("File command not available or timed out")

            # Try to extract basic information using alternative methods
            strings = self._extract_strings_fallback(dump_path)

            result.memory_strings = [
                MemoryString(offset=i, value=s, encoding="ascii")
                for i, s in enumerate(strings[:1000])  # Limit to first 1000
            ]

            result.artifacts_found = {
                "dump_size": dump_size,
                "memory_strings": len(result.memory_strings),
                "fallback_analysis": True,
            }

            logger.info("Fallback memory analysis completed")

        except Exception as e:
            result.error = f"Fallback analysis failed: {e}"

        return result

    def _detect_profile(self, dump_path: str) -> str:
        """Detect appropriate Volatility3 profile for memory dump"""
        try:
            # First, try file-based heuristics using dump_path
            import os
            import struct

            # Analyze dump file header for OS signatures
            if os.path.exists(dump_path):
                with open(dump_path, "rb") as f:
                    # Read first 4KB for signatures
                    header_data = f.read(4096)

                    # Parse potential crash dump header using struct
                    if len(header_data) >= 32:
                        # Check for Windows crash dump signature (first 8 bytes)
                        signature = struct.unpack("<Q", header_data[:8])[0]
                        if signature == 0x45474150:  # 'PAGE' in little-endian
                            # Parse Windows dump header
                            dump_type = (
                                struct.unpack("<I", header_data[0xF88:0xF8C])[0]
                                if len(header_data) > 0xF8C
                                else 0
                            )
                            logger.info(f"Windows crash dump detected, type: {dump_type}")

                    # Look for common Windows signatures
                    if b"PAGEFILEDATA" in header_data or b"HIBERFIL" in header_data:
                        # Check for Windows version indicators
                        if b"Windows 11" in header_data or b"22H2" in header_data:
                            logger.info(f"Detected Windows 11 from dump file: {dump_path}")
                            return AnalysisProfile.WINDOWS_11.value
                        if (
                            b"Windows 10" in header_data
                            or b"2004" in header_data
                            or b"21H1" in header_data
                        ):
                            logger.info(f"Detected Windows 10 from dump file: {dump_path}")
                            return AnalysisProfile.WINDOWS_10.value
                        if b"Windows 7" in header_data:
                            logger.info(f"Detected Windows 7 from dump file: {dump_path}")
                            return AnalysisProfile.WINDOWS_7.value

                    # Look for Linux signatures
                    elif b"Linux" in header_data or b"vmlinux" in header_data:
                        # Check for ELF header using struct
                        if len(header_data) >= 16:
                            elf_magic = struct.unpack("4s", header_data[:4])[0]
                            if elf_magic == b"\x7fELF":
                                # Parse ELF header
                                e_machine = (
                                    struct.unpack("<H", header_data[18:20])[0]
                                    if len(header_data) > 20
                                    else 0
                                )
                                logger.info(
                                    f"ELF binary detected in dump, machine type: {e_machine}"
                                )
                        logger.info(f"Detected Linux from dump file: {dump_path}")
                        return AnalysisProfile.LINUX_GENERIC.value

                    # Look for macOS signatures
                    elif (
                        b"Darwin" in header_data
                        or b"MacOS" in header_data
                        or b"mach_kernel" in header_data
                    ):
                        # Check for Mach-O header using struct
                        if len(header_data) >= 8:
                            mach_magic = struct.unpack("<I", header_data[:4])[0]
                            if mach_magic in [
                                0xFEEDFACE,
                                0xFEEDFACF,
                                0xCEFAEDFE,
                                0xCFFAEDFE,
                            ]:  # Mach-O magic numbers
                                cpu_type = (
                                    struct.unpack("<I", header_data[4:8])[0]
                                    if len(header_data) >= 8
                                    else 0
                                )
                                logger.info(f"Mach-O binary detected in dump, CPU type: {cpu_type}")
                        logger.info(f"Detected macOS from dump file: {dump_path}")
                        return AnalysisProfile.MAC_OSX.value

            # Use Volatility3 banners plugin to detect profile
            plugin_list = self._run_volatility_plugin("banners.Banners", {})

            # Parse banner output to determine OS
            for banner in plugin_list:
                banner_text = str(banner).lower()
                if "windows 10" in banner_text:
                    return AnalysisProfile.WINDOWS_10.value
                if "windows 11" in banner_text:
                    return AnalysisProfile.WINDOWS_11.value
                if "windows 7" in banner_text:
                    return AnalysisProfile.WINDOWS_7.value
                if "linux" in banner_text:
                    return AnalysisProfile.LINUX_GENERIC.value
                if "darwin" in banner_text or "mac" in banner_text:
                    return AnalysisProfile.MAC_OSX.value

            # Default to Windows 10 if detection fails
            logger.debug(
                f"Profile detection inconclusive for {dump_path}, defaulting to Windows 10"
            )
            return AnalysisProfile.WINDOWS_10.value

        except Exception as e:
            logger.debug(f"Profile detection failed for {dump_path}: {e}")
            return AnalysisProfile.WINDOWS_10.value

    def _configure_volatility(self, dump_path: str, profile: str):
        """Configure Volatility3 for analysis"""
        try:
            # Clear existing configuration
            self.vol_config.clear()

            # Set memory dump file
            self.vol_config["automagic.LayerStacker.single_location"] = f"file://{dump_path}"

            # Set profile if specified
            if profile != "auto":
                self.vol_config["automagic.LayerStacker.stackers.intel.symbol_table_class"] = (
                    profile
                )

            # Apply automagic
            automagic.run(self.automagics, self.vol_context, self.vol_config, "plugins")

        except Exception as e:
            logger.error(f"Failed to configure Volatility3: {e}")
            raise

    def _run_volatility_plugin(self, plugin_name: str, plugin_config: dict[str, Any]) -> list[Any]:
        """Run a Volatility3 plugin and return results"""
        try:
            # Get plugin class using plugins framework
            available_plugins = plugins.list_plugins()
            if plugin_name not in [p.__name__ for p in available_plugins]:
                logger.warning(f"Plugin {plugin_name} not available")
                return []

            plugin_class = getattr(volatility3.framework.plugins, plugin_name.split(".")[0])
            plugin_class = getattr(plugin_class, plugin_name.split(".")[1])

            # Create plugin instance using requirements framework
            plugin_requirements = requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory dump translation layer",
            )

            # Validate plugin requirements before execution
            unsatisfied_requirements = []
            try:
                # Check if the specific plugin requirement is satisfied
                if plugin_requirements.name not in self.vol_context.layers:
                    unsatisfied_requirements.append(
                        f"Required layer '{plugin_requirements.name}' not available"
                    )

                # Check if the plugin's requirements can be satisfied
                automagics_list = [
                    automagic() for automagic in automagic.available(self.vol_context)
                ]
                for automagic_instance in automagics_list:
                    automagic_instance.run(self.vol_context, self.vol_config)

                # Verify translation layer requirement is satisfied again after automagics
                if not self.vol_context.layers.get(plugin_requirements.name):
                    unsatisfied_requirements.append(
                        f"Translation layer '{plugin_requirements.name}' still not available after automagics"
                    )

            except Exception as e:
                unsatisfied_requirements.append(f"Automagic failed: {e}")

            if unsatisfied_requirements:
                logger.warning(f"Plugin requirements not satisfied: {unsatisfied_requirements}")
                return []

            plugin_instance = plugin_class(
                context=self.vol_context,
                config_path="plugins." + plugin_name,
                progress_callback=None,
            )

            # Use constants framework for configuration validation
            config_constants = constants.BANG_TREE

            # Validate configuration using constants
            valid_config = {}
            for key, value in plugin_config.items():
                # Use constants to validate configuration values
                if hasattr(config_constants, key.upper()):
                    expected_type = getattr(config_constants, key.upper())
                    if isinstance(value, type(expected_type)):
                        valid_config[key] = value
                        config_key = f"plugins.{plugin_name}.{key}"
                        self.vol_config[config_key] = value
                    else:
                        logger.warning(
                            f"Invalid config type for {key}: expected {type(expected_type)}, got {type(value)}"
                        )
                else:
                    # Accept unknown configuration keys
                    valid_config[key] = value
                    config_key = f"plugins.{plugin_name}.{key}"
                    self.vol_config[config_key] = value

            # Use text_renderer for output formatting
            renderer = text_renderer.CLIRenderer()

            # Run plugin with formatted output
            try:
                results = list(plugin_instance.run())

                # Format results using renderer for logging
                formatted_output = []
                for result in results:
                    try:
                        formatted_result = renderer.render(result)
                        formatted_output.append(formatted_result)
                    except Exception as render_error:
                        logger.debug(f"Failed to render result: {render_error}")
                        formatted_output.append(str(result))

                logger.info(
                    f"Plugin {plugin_name} executed successfully with {len(results)} results"
                )
                if formatted_output:
                    logger.debug(f"Formatted output sample: {formatted_output[0][:200]}...")

                return results

            except Exception as run_error:
                logger.error(f"Plugin execution failed: {run_error}")
                return []

        except Exception as e:
            logger.error(f"Failed to run plugin {plugin_name}: {e}")
            return []

    def _analyze_processes(self) -> list[MemoryProcess]:
        """Analyze processes in memory dump"""
        processes = []

        try:
            # Run pslist plugin
            pslist_results = self._run_volatility_plugin("windows.pslist.PsList", {})

            for process_data in pslist_results:
                # Extract process information
                process = MemoryProcess(
                    pid=getattr(process_data, "PID", 0),
                    ppid=getattr(process_data, "PPID", 0),
                    name=getattr(process_data, "ImageFileName", "").strip(),
                    create_time=str(getattr(process_data, "CreateTime", "")),
                    exit_time=str(getattr(process_data, "ExitTime", "")),
                    image_base=getattr(process_data, "ImageBase", 0),
                    session_id=getattr(process_data, "SessionId", 0),
                    handle_count=getattr(process_data, "HandleCount", 0),
                    thread_count=getattr(process_data, "ThreadCount", 0),
                    wow64=getattr(process_data, "Wow64", False),
                )

                # Check for suspicious indicators
                process.suspicious_indicators = self._check_process_suspicious_indicators(process)

                processes.append(process)

            # Check for hidden processes
            self._detect_hidden_processes(processes)

        except Exception as e:
            logger.error(f"Process analysis failed: {e}")

        return processes

    def _analyze_modules(self) -> list[MemoryModule]:
        """Analyze loaded modules"""
        modules = []

        try:
            # Run ldrmodules plugin
            module_results = self._run_volatility_plugin("windows.ldrmodules.LdrModules", {})

            for module_data in module_results:
                module = MemoryModule(
                    base_address=getattr(module_data, "BaseAddress", 0),
                    size=getattr(module_data, "SizeOfImage", 0),
                    name=getattr(module_data, "BaseDllName", "").strip(),
                    path=getattr(module_data, "FullDllName", "").strip(),
                    is_suspicious=self._is_module_suspicious(module_data),
                )

                modules.append(module)

        except Exception as e:
            logger.error(f"Module analysis failed: {e}")

        return modules

    def _analyze_network_connections(self) -> list[NetworkConnection]:
        """Analyze network connections"""
        connections = []

        try:
            # Run netscan plugin
            netscan_results = self._run_volatility_plugin("windows.netscan.NetScan", {})

            for conn_data in netscan_results:
                connection = NetworkConnection(
                    local_addr=getattr(conn_data, "LocalAddr", ""),
                    local_port=getattr(conn_data, "LocalPort", 0),
                    remote_addr=getattr(conn_data, "ForeignAddr", ""),
                    remote_port=getattr(conn_data, "ForeignPort", 0),
                    protocol=getattr(conn_data, "Protocol", ""),
                    state=getattr(conn_data, "State", ""),
                    pid=getattr(conn_data, "PID", 0),
                    create_time=str(getattr(conn_data, "CreateTime", "")),
                )

                connections.append(connection)

        except Exception as e:
            logger.error(f"Network analysis failed: {e}")

        return connections

    def _analyze_registry(self) -> list[dict[str, Any]]:
        """Analyze registry artifacts"""
        registry_artifacts = []

        try:
            # Run registry plugins
            hivelist_results = self._run_volatility_plugin("windows.registry.hivelist.HiveList", {})

            for hive_data in hivelist_results:
                artifact = {
                    "hive_offset": getattr(hive_data, "Offset", 0),
                    "hive_name": getattr(hive_data, "HiveName", ""),
                    "file_full_path": getattr(hive_data, "FileFullPath", ""),
                    "file_user_name": getattr(hive_data, "FileUserName", ""),
                }
                registry_artifacts.append(artifact)

        except Exception as e:
            logger.error(f"Registry analysis failed: {e}")

        return registry_artifacts

    def _analyze_file_handles(self) -> list[dict[str, Any]]:
        """Analyze file handles"""
        file_handles = []

        try:
            # Run handles plugin
            handles_results = self._run_volatility_plugin("windows.handles.Handles", {})

            for handle_data in handles_results:
                if getattr(handle_data, "HandleType", "") == "File":
                    handle = {
                        "pid": getattr(handle_data, "PID", 0),
                        "handle_value": getattr(handle_data, "HandleValue", 0),
                        "access_mask": getattr(handle_data, "AccessMask", 0),
                        "object_name": getattr(handle_data, "ObjectName", ""),
                        "handle_type": getattr(handle_data, "HandleType", ""),
                    }
                    file_handles.append(handle)

        except Exception as e:
            logger.error(f"File handle analysis failed: {e}")

        return file_handles

    def _extract_memory_strings(self, min_length: int = 6) -> list[MemoryString]:
        """Extract strings from memory dump"""
        strings = []

        try:
            # Run strings plugin or manual extraction
            dump_path = self.vol_config.get("automagic.LayerStacker.single_location", "").replace(
                "file://", ""
            )

            if dump_path and os.path.exists(dump_path):
                extracted_strings = self._extract_strings_fallback(dump_path, min_length)

                for i, string_value in enumerate(extracted_strings[:5000]):  # Limit to 5000 strings
                    string_obj = MemoryString(
                        offset=i * 100,  # Approximate offset
                        value=string_value,
                        encoding="ascii",
                        confidence=0.8,
                    )
                    strings.append(string_obj)

        except Exception as e:
            logger.error(f"String extraction failed: {e}")

        return strings

    def _extract_strings_fallback(self, file_path: str, min_length: int = 4) -> list[str]:
        """Fallback string extraction using basic binary parsing"""
        strings = []

        try:
            with open(file_path, "rb") as f:
                # Read file in chunks to handle large dumps
                chunk_size = 1024 * 1024  # 1MB chunks
                current_string = ""

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    for byte in chunk:
                        if 32 <= byte <= 126:  # Printable ASCII
                            current_string += chr(byte)
                        else:
                            if len(current_string) >= min_length:
                                strings.append(current_string)
                            current_string = ""

                    # Limit to prevent memory issues
                    if len(strings) >= 10000:
                        break

                # Don't forget the last string
                if len(current_string) >= min_length:
                    strings.append(current_string)

        except Exception as e:
            logger.error(f"Fallback string extraction failed: {e}")

        return strings

    def _check_process_suspicious_indicators(self, process: MemoryProcess) -> list[str]:
        """Check for suspicious process indicators"""
        indicators = []

        # Check for common license bypass tool process names
        suspicious_names = [
            "svchost.exe",
            "explorer.exe",
            "winlogon.exe",
            "services.exe",
            "lsass.exe",
            "csrss.exe",
            "smss.exe",
            "wininit.exe",
        ]

        # Check if process name is suspicious (common system process names used by cracks)
        if process.name.lower() in [name.lower() for name in suspicious_names]:
            # Additional checks for legitimate vs suspicious instances
            # Check process path and signature to distinguish from legitimate system processes
            try:
                if hasattr(process, "image_file_name") and process.image_file_name:
                    image_path = str(process.image_file_name).lower()

                    # Legitimate system processes should be in system directories
                    legitimate_paths = [
                        "c:\\windows\\system32\\",
                        "c:\\windows\\syswow64\\",
                        "c:\\windows\\",
                        "/usr/bin/",
                        "/usr/sbin/",
                        "/bin/",
                        "/sbin/",
                    ]

                    is_in_system_dir = any(image_path.startswith(path) for path in legitimate_paths)

                    if not is_in_system_dir:
                        indicators.append(
                            f"System process name in non-system location: {image_path}"
                        )

                    # Check for suspicious file extensions
                    suspicious_extensions = [".tmp", ".dat", ".bin", ".exe~", ".scr"]
                    if any(image_path.endswith(ext) for ext in suspicious_extensions):
                        indicators.append(
                            f"Suspicious file extension for system process: {image_path}"
                        )

            except Exception:
                # Continue analysis if path checking fails
                pass
            if process.ppid == 0 and process.name.lower() != "system":
                indicators.append("Suspicious parent process ID")

        # Check for process hollowing indicators
        if process.image_base == 0:
            indicators.append("Zero image base - possible process hollowing")

        # Check for unusual session IDs
        if process.session_id > 10:
            indicators.append("Unusual session ID")

        return indicators

    def _detect_hidden_processes(self, processes: list[MemoryProcess]):
        """Detect hidden processes using psxview-like analysis"""
        try:
            # This would involve comparing multiple process listing methods
            # For now, mark processes with suspicious characteristics as potentially hidden
            for process in processes:
                if (
                    process.ppid == 0 and process.name.lower() != "system" and process.pid != 4
                ):  # System process usually has PID 4
                    process.is_hidden = True

        except Exception as e:
            logger.error(f"Hidden process detection failed: {e}")

    def _is_module_suspicious(self, module_data: Any) -> bool:
        """Check if a module appears suspicious"""
        try:
            module_name = getattr(module_data, "BaseDllName", "").lower()
            module_path = getattr(module_data, "FullDllName", "").lower()

            # Check for suspicious module names
            suspicious_module_names = [
                "keylogger",
                "rootkit",
                "backdoor",
                "keygen",
                "patch",
                "crack",
                "loader",
                "bypass",
                "activator",
                "license",
                "serial",
                "emulator",
                "unlocker",
                "miner",
                "dropper",
            ]

            # Check if module name contains suspicious keywords
            if any(sus_name in module_name for sus_name in suspicious_module_names):
                logger.warning(f"Suspicious module name detected: {module_name}")
                return True

            # Check for DLL masquerading (common system DLL names with slight variations)
            masquerading_patterns = {
                "kernel32.dll": ["kernal32.dll", "kernel33.dll", "kernell32.dll"],
                "ntdll.dll": ["ntdl.dll", "ntdlll.dll", "ntddll.dll"],
                "user32.dll": ["user33.dll", "users32.dll", "user322.dll"],
                "advapi32.dll": ["advapi33.dll", "advapii32.dll", "advapi322.dll"],
            }

            for legitimate_dll, variants in masquerading_patterns.items():
                if module_name in variants:
                    logger.warning(
                        f"Potential DLL masquerading detected: {module_name} (imitating {legitimate_dll})"
                    )
                    return True

            # Check for unsigned modules in system directories
            if any(sys_dir in module_path for sys_dir in ["system32", "syswow64"]):
                # In real implementation, check digital signature
                return False

            # Check for modules loaded from unusual locations
            suspicious_paths = ["temp", "appdata", "downloads", "desktop"]
            if any(path in module_path for path in suspicious_paths):
                return True

            # Check for modules with no name or path (could indicate injection)
            if not module_name and not module_path:
                logger.warning("Module with no name or path detected (possible code injection)")
                return True

            return False

        except Exception:
            return False

    def _detect_security_issues(
        self, analysis_result: MemoryAnalysisResult
    ) -> list[dict[str, Any]]:
        """Detect security issues based on analysis results"""
        findings = []

        try:
            # Check for hidden processes
            hidden_count = analysis_result.hidden_process_count
            if hidden_count > 0:
                findings.append(
                    {
                        "type": "hidden_processes",
                        "severity": "high",
                        "description": f"Found {hidden_count} potentially hidden processes",
                        "count": hidden_count,
                    }
                )

            # Check for suspicious modules
            suspicious_modules = [m for m in analysis_result.modules if m.is_suspicious]
            if suspicious_modules:
                findings.append(
                    {
                        "type": "suspicious_modules",
                        "severity": "medium",
                        "description": f"Found {len(suspicious_modules)} suspicious modules",
                        "modules": [m.name for m in suspicious_modules[:5]],
                    }
                )

            # Check for unusual network connections
            external_connections = [
                c
                for c in analysis_result.network_connections
                if not c.remote_addr.startswith(("127.", "192.168.", "10.", "172."))
            ]
            if len(external_connections) > 10:
                findings.append(
                    {
                        "type": "excessive_network_activity",
                        "severity": "medium",
                        "description": f"Found {len(external_connections)} external network connections",
                        "count": len(external_connections),
                    }
                )

            # Check for credential-related strings
            credential_strings = [
                s
                for s in analysis_result.memory_strings
                if any(
                    keyword in s.value.lower()
                    for keyword in ["password", "credential", "token", "key"]
                )
            ]
            if credential_strings:
                findings.append(
                    {
                        "type": "credential_material",
                        "severity": "high",
                        "description": f"Found {len(credential_strings)} potential credential strings",
                        "count": len(credential_strings),
                    }
                )

        except Exception as e:
            logger.error(f"Security issue detection failed: {e}")

        return findings

    def analyze_process_memory(
        self, process_id: int, dump_path: str | None = None
    ) -> dict[str, Any]:
        """Analyze live process memory or specific process from dump

        Args:
            process_id: Process ID to analyze
            dump_path: Optional memory dump path

        Returns:
            Process-specific memory analysis results

        """
        try:
            if dump_path:
                # Analyze specific process from memory dump
                full_analysis = self.analyze_memory_dump(dump_path, deep_analysis=False)

                # Filter results for specific process
                target_process = None
                for process in full_analysis.processes:
                    if process.pid == process_id:
                        target_process = process
                        break

                if not target_process:
                    return {"error": f"Process {process_id} not found in memory dump"}

                return {
                    "process_id": process_id,
                    "process_info": target_process,
                    "modules": [m for m in full_analysis.modules],  # All modules for context
                    "connections": [
                        c for c in full_analysis.network_connections if c.pid == process_id
                    ],
                    "analysis_status": "completed",
                }
            # Live process memory analysis implementation
            import platform

            if platform.system() == "Windows":
                return self._analyze_live_process_windows(process_id)
            if platform.system() == "Linux":
                return self._analyze_live_process_linux(process_id)
            return {
                "process_id": process_id,
                "error": f"Live process analysis not supported on {platform.system()}",
                "suggestion": "Use memory dump analysis instead",
            }

        except Exception as e:
            logger.error(f"Process memory analysis failed: {e}")
            return {"error": str(e)}

    def _analyze_live_process_windows(self, process_id: int) -> dict[str, Any]:
        """Analyze live process memory on Windows."""
        try:
            import ctypes
            from ctypes import wintypes

            import win32api
            import win32process
            import win32security

            # Enable debug privilege
            priv_flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            h_token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), priv_flags)
            privilege_id = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)
            win32security.AdjustTokenPrivileges(
                h_token, 0, [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)]
            )

            # Open target process
            PROCESS_ALL_ACCESS = 0x1F0FFF
            h_process = win32api.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)

            if not h_process:
                return {"error": f"Failed to open process {process_id}"}

            # Get process information
            modules = win32process.EnumProcessModules(h_process)
            module_info = []

            for module in modules:
                try:
                    module_name = win32process.GetModuleFileNameEx(h_process, module)
                    module_info.append(
                        {
                            "base": hex(module),
                            "name": module_name,
                            "path": module_name,
                        }
                    )
                except:
                    continue

            # Memory regions analysis
            memory_regions = []
            address = 0

            # Define MEMORY_BASIC_INFORMATION structure
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                ]

            mbi = MEMORY_BASIC_INFORMATION()
            kernel32 = ctypes.windll.kernel32

            while address < 0x7FFFFFFF0000:  # User space limit on x64
                result = kernel32.VirtualQueryEx(
                    h_process,
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi),
                )

                if result == 0:
                    break

                if mbi.State == 0x1000:  # MEM_COMMIT
                    # Read memory region
                    buffer = ctypes.create_string_buffer(mbi.RegionSize)
                    bytes_read = ctypes.c_size_t()

                    if kernel32.ReadProcessMemory(
                        h_process,
                        ctypes.c_void_p(address),
                        buffer,
                        mbi.RegionSize,
                        ctypes.byref(bytes_read),
                    ):
                        # Analyze memory content
                        memory_data = buffer.raw[: bytes_read.value]
                        strings = self.extract_strings(memory_data)

                        memory_regions.append(
                            {
                                "address": hex(address),
                                "size": mbi.RegionSize,
                                "protection": self._get_protection_string(mbi.Protect),
                                "type": self._get_memory_type(mbi.Type),
                                "strings_found": len(strings),
                                "interesting_strings": [
                                    s
                                    for s in strings
                                    if any(
                                        keyword in s.lower()
                                        for keyword in [
                                            "password",
                                            "token",
                                            "key",
                                            "secret",
                                            "api",
                                            "credential",
                                        ]
                                    )
                                ][:10],  # Limit to 10 interesting strings
                            }
                        )

                address += mbi.RegionSize

            # Get handles
            handles = []
            try:
                from intellicrack.handlers.psutil_handler import psutil

                proc = psutil.Process(process_id)

                # Get process handles information
                try:
                    open_files = proc.open_files()
                    for file_obj in open_files:
                        handles.append(
                            {
                                "type": "file",
                                "path": file_obj.path,
                                "fd": getattr(file_obj, "fd", "N/A"),
                            }
                        )
                except (psutil.AccessDenied, AttributeError):
                    pass

                # Get memory map handles
                try:
                    memory_maps = proc.memory_maps()
                    for mmap in memory_maps:
                        if hasattr(mmap, "path") and mmap.path:
                            handles.append(
                                {
                                    "type": "memory_map",
                                    "path": mmap.path,
                                    "size": getattr(mmap, "rss", 0),
                                }
                            )
                except (psutil.AccessDenied, AttributeError):
                    pass

            except Exception:
                # Fallback to empty handles list
                handles = []

            # Network connections
            connections = []
            try:
                from intellicrack.handlers.psutil_handler import psutil

                proc = psutil.Process(process_id)
                for conn in proc.connections():
                    connections.append(
                        {
                            "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                            "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                            "status": conn.status,
                        }
                    )
            except:
                pass

            # Close handle
            win32api.CloseHandle(h_process)

            return {
                "process_id": process_id,
                "status": "success",
                "analysis_type": "live",
                "modules": module_info,
                "memory_regions": memory_regions,
                "handles": handles,
                "connections": connections,
                "total_regions": len(memory_regions),
                "total_handles": len(handles),
                "suspicious_strings": sum(
                    len(r.get("interesting_strings", [])) for r in memory_regions
                ),
            }

        except Exception as e:
            return {
                "process_id": process_id,
                "error": f"Windows live analysis failed: {e!s}",
                "suggestion": "Ensure running with administrator privileges",
            }

    def _analyze_live_process_linux(self, process_id: int) -> dict[str, Any]:
        """Analyze live process memory on Linux."""
        try:
            import os
            import re

            # Check if we have permission
            if os.geteuid() != 0:
                return {
                    "process_id": process_id,
                    "error": "Root privileges required for live process analysis",
                    "suggestion": "Run with sudo or as root user",
                }

            # Read process maps
            maps_path = f"/proc/{process_id}/maps"
            mem_path = f"/proc/{process_id}/mem"

            if not os.path.exists(maps_path):
                return {"error": f"Process {process_id} not found"}

            memory_regions = []
            modules = []

            with open(maps_path) as f:
                for line in f:
                    # Parse memory mapping
                    match = re.match(
                        r"([0-9a-f]+)-([0-9a-f]+) ([-rwxp]{4}) ([0-9a-f]+) ([\d:]+) (\d+)\s*(.*)?",
                        line,
                    )
                    if match:
                        start = int(match.group(1), 16)
                        end = int(match.group(2), 16)
                        perms = match.group(3)
                        offset = match.group(4)
                        dev = match.group(5)
                        inode = match.group(6)
                        pathname = match.group(7) if match.group(7) else ""

                        # Skip non-readable regions
                        if "r" not in perms:
                            continue

                        region_info = {
                            "address": hex(start),
                            "end": hex(end),
                            "size": end - start,
                            "permissions": perms,
                            "offset": offset,
                            "device": dev,
                            "inode": inode,
                            "pathname": pathname,
                        }

                        # Read memory content
                        try:
                            with open(mem_path, "rb") as mem_file:
                                mem_file.seek(start)
                                memory_data = mem_file.read(
                                    min(end - start, 0x10000)
                                )  # Read up to 64KB

                                # Extract strings
                                strings = self.extract_strings(memory_data)
                                region_info["strings_found"] = len(strings)
                                region_info["interesting_strings"] = [
                                    s
                                    for s in strings
                                    if any(
                                        keyword in s.lower()
                                        for keyword in [
                                            "password",
                                            "token",
                                            "key",
                                            "secret",
                                            "api",
                                            "credential",
                                            "ssh",
                                            "private",
                                        ]
                                    )
                                ][:10]

                                # Look for specific patterns
                                if pathname and (".so" in pathname or "lib" in pathname):
                                    modules.append(
                                        {
                                            "base": hex(start),
                                            "name": os.path.basename(pathname),
                                            "path": pathname,
                                            "size": end - start,
                                        }
                                    )
                        except:
                            region_info["read_error"] = True

                        memory_regions.append(region_info)

            # Get process info
            status_info = {}
            try:
                with open(f"/proc/{process_id}/status") as f:
                    for line in f:
                        if ":" in line:
                            key, value = line.split(":", 1)
                            status_info[key.strip()] = value.strip()
            except:
                pass

            # Get network connections
            connections = []
            try:
                # Parse /proc/net/tcp and /proc/net/tcp6
                for proto, path in [("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6")]:
                    if os.path.exists(path):
                        with open(path) as f:
                            lines = f.readlines()[1:]  # Skip header
                            for line in lines:
                                fields = line.split()
                                if len(fields) >= 10:
                                    inode = fields[9]
                                    # Check if this inode belongs to our process
                                    fd_path = f"/proc/{process_id}/fd"
                                    if os.path.exists(fd_path):
                                        for fd in os.listdir(fd_path):
                                            try:
                                                link = os.readlink(f"{fd_path}/{fd}")
                                                if f"socket:[{inode}]" in link:
                                                    local_addr = self._parse_linux_addr(fields[1])
                                                    remote_addr = self._parse_linux_addr(fields[2])
                                                    connections.append(
                                                        {
                                                            "protocol": proto,
                                                            "local": local_addr,
                                                            "remote": remote_addr,
                                                            "state": fields[3],
                                                        }
                                                    )
                                            except:
                                                continue
            except:
                pass

            # Look for injected code
            injected_regions = []
            for region in memory_regions:
                if not region.get("pathname") and "x" in region.get("permissions", ""):
                    # Executable region without file backing - possibly injected
                    injected_regions.append(region["address"])

            return {
                "process_id": process_id,
                "status": "success",
                "analysis_type": "live",
                "process_name": status_info.get("Name", "unknown"),
                "state": status_info.get("State", "unknown"),
                "modules": modules,
                "memory_regions": memory_regions,
                "connections": connections,
                "total_regions": len(memory_regions),
                "suspicious_strings": sum(
                    len(r.get("interesting_strings", [])) for r in memory_regions
                ),
                "possible_injections": injected_regions,
            }

        except Exception as e:
            return {
                "process_id": process_id,
                "error": f"Linux live analysis failed: {e!s}",
                "suggestion": "Ensure running with root privileges",
            }

    def _get_protection_string(self, protect: int) -> str:
        """Convert Windows protection flags to string."""
        protections = {
            0x10: "PAGE_EXECUTE",
            0x20: "PAGE_EXECUTE_READ",
            0x40: "PAGE_EXECUTE_READWRITE",
            0x80: "PAGE_EXECUTE_WRITECOPY",
            0x01: "PAGE_NOACCESS",
            0x02: "PAGE_READONLY",
            0x04: "PAGE_READWRITE",
            0x08: "PAGE_WRITECOPY",
        }
        return protections.get(protect & 0xFF, f"0x{protect:X}")

    def _get_memory_type(self, mem_type: int) -> str:
        """Convert Windows memory type to string."""
        types = {
            0x1000000: "MEM_IMAGE",
            0x40000: "MEM_MAPPED",
            0x20000: "MEM_PRIVATE",
        }
        return types.get(mem_type, f"0x{mem_type:X}")

    def _parse_linux_addr(self, addr_str: str) -> str:
        """Parse Linux /proc/net address format."""
        try:
            host, port = addr_str.split(":")
            # Convert from hex and reverse byte order
            host_bytes = bytes.fromhex(host)
            if len(host_bytes) == 4:
                # IPv4
                host_ip = ".".join(str(b) for b in reversed(host_bytes))
            else:
                # IPv6
                host_ip = ":".join(host[i : i + 4] for i in range(0, len(host), 4))
            port_num = int(port, 16)
            return f"{host_ip}:{port_num}"
        except:
            return addr_str

    def extract_strings(self, memory_data: bytes, min_length: int = 4) -> list[str]:
        """Extract ASCII strings from memory data

        Args:
            memory_data: Binary memory data
            min_length: Minimum string length to extract

        Returns:
            List of extracted strings

        """
        try:
            strings = []
            current_string = ""

            for byte in memory_data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                    current_string = ""

            # Don't forget the last string
            if len(current_string) >= min_length:
                strings.append(current_string)

            return strings

        except Exception as e:
            logger.error(f"String extraction failed: {e}")
            return []

    def generate_icp_supplemental_data(
        self, analysis_result: MemoryAnalysisResult
    ) -> dict[str, Any]:
        """Generate supplemental data for ICP backend integration

        Args:
            analysis_result: Memory analysis results

        Returns:
            Dictionary with supplemental memory forensics data for ICP

        """
        if analysis_result.error:
            return {"error": analysis_result.error}

        supplemental_data = {
            "memory_forensics": {
                "analysis_profile": analysis_result.analysis_profile,
                "total_processes": len(analysis_result.processes),
                "total_modules": len(analysis_result.modules),
                "network_connections": len(analysis_result.network_connections),
                "security_findings": len(analysis_result.security_findings),
                "analysis_time": analysis_result.analysis_time,
                "has_suspicious_activity": analysis_result.has_suspicious_activity,
            },
            "process_indicators": [],
            "module_indicators": [],
            "network_indicators": [],
            "security_indicators": [],
        }

        # Process suspicious processes
        for process in analysis_result.processes:
            if process.suspicious_indicators or process.is_hidden:
                supplemental_data["process_indicators"].append(
                    {
                        "pid": process.pid,
                        "name": process.name,
                        "is_hidden": process.is_hidden,
                        "indicators": process.suspicious_indicators,
                        "parent_pid": process.ppid,
                    }
                )

        # Process suspicious modules
        for module in analysis_result.modules:
            if module.is_suspicious:
                supplemental_data["module_indicators"].append(
                    {
                        "name": module.name,
                        "path": module.path,
                        "base_address": hex(module.base_address),
                        "size": module.size,
                    }
                )

        # Process network connections
        for conn in analysis_result.network_connections:
            if not conn.remote_addr.startswith(("127.", "192.168.", "10.")):
                supplemental_data["network_indicators"].append(
                    {
                        "local_endpoint": f"{conn.local_addr}:{conn.local_port}",
                        "remote_endpoint": f"{conn.remote_addr}:{conn.remote_port}",
                        "protocol": conn.protocol,
                        "state": conn.state,
                        "pid": conn.pid,
                    }
                )

        # Process security findings
        for finding in analysis_result.security_findings:
            supplemental_data["security_indicators"].append(
                {
                    "type": finding.get("type", "unknown"),
                    "severity": finding.get("severity", "low"),
                    "description": finding.get("description", ""),
                    "evidence": finding,
                }
            )

        return supplemental_data

    def get_analysis_summary(self, analysis_result: MemoryAnalysisResult) -> dict[str, Any]:
        """Generate a summary of memory analysis results"""
        return {
            "dump_path": analysis_result.dump_path,
            "analysis_profile": analysis_result.analysis_profile,
            "total_artifacts": sum(analysis_result.artifacts_found.values()),
            "artifacts_breakdown": analysis_result.artifacts_found,
            "security_assessment": {
                "has_suspicious_activity": analysis_result.has_suspicious_activity,
                "hidden_processes": analysis_result.hidden_process_count,
                "total_findings": len(analysis_result.security_findings),
            },
            "performance": {
                "analysis_time": analysis_result.analysis_time,
                "volatility_available": VOLATILITY3_AVAILABLE,
            },
        }

    def export_analysis_report(
        self, analysis_result: MemoryAnalysisResult, output_path: str
    ) -> tuple[bool, str]:
        """Export memory analysis results to JSON report

        Args:
            analysis_result: Analysis results to export
            output_path: Path to save the JSON report

        Returns:
            Tuple of (success, message)

        """
        try:
            report_data = {
                "analysis_metadata": {
                    "dump_path": analysis_result.dump_path,
                    "analysis_profile": analysis_result.analysis_profile,
                    "analysis_time": analysis_result.analysis_time,
                    "timestamp": time.time(),
                    "volatility_available": VOLATILITY3_AVAILABLE,
                },
                "processes": [
                    {
                        "pid": proc.pid,
                        "ppid": proc.ppid,
                        "name": proc.name,
                        "command_line": proc.command_line,
                        "create_time": proc.create_time,
                        "is_hidden": proc.is_hidden,
                        "suspicious_indicators": proc.suspicious_indicators,
                    }
                    for proc in analysis_result.processes
                ],
                "modules": [
                    {
                        "base_address": hex(mod.base_address),
                        "size": mod.size,
                        "name": mod.name,
                        "path": mod.path,
                        "is_suspicious": mod.is_suspicious,
                    }
                    for mod in analysis_result.modules
                ],
                "network_connections": [
                    {
                        "local_addr": conn.local_addr,
                        "local_port": conn.local_port,
                        "remote_addr": conn.remote_addr,
                        "remote_port": conn.remote_port,
                        "protocol": conn.protocol,
                        "state": conn.state,
                        "pid": conn.pid,
                    }
                    for conn in analysis_result.network_connections
                ],
                "security_findings": analysis_result.security_findings,
                "artifacts_found": analysis_result.artifacts_found,
                "error": analysis_result.error,
            }

            with open(output_path, "w") as f:
                json.dump(report_data, f, indent=2, default=str)

            return True, f"Memory analysis report exported to {output_path}"

        except Exception as e:
            return False, f"Failed to export report: {e}"


# Singleton instance
_memory_forensics_engine: MemoryForensicsEngine | None = None


def get_memory_forensics_engine() -> MemoryForensicsEngine | None:
    """Get or create the memory forensics engine singleton"""
    global _memory_forensics_engine
    if _memory_forensics_engine is None:
        try:
            _memory_forensics_engine = MemoryForensicsEngine()
        except Exception as e:
            logger.error(f"Failed to initialize memory forensics engine: {e}")
            return None
    return _memory_forensics_engine


def is_volatility3_available() -> bool:
    """Check if Volatility3 functionality is available"""
    return VOLATILITY3_AVAILABLE


def analyze_memory_dump_file(dump_path: str) -> MemoryAnalysisResult | None:
    """Quick memory dump analysis function for integration"""
    engine = get_memory_forensics_engine()
    if engine:
        return engine.analyze_memory_dump(dump_path)
    return None
