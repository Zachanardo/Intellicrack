"""Intellicrack Protection Engine Backend Wrapper

Provides native ICP Engine integration for comprehensive protection analysis.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

# Import ICP Engine backend with DLL path fix for Windows
import asyncio
import os
import platform
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger

_ICP_BACKEND_AVAILABLE = False
_ICP_BACKEND_VERSION = None
_icp_backend_module = None

if platform.system() == "Windows":
    # Add potential DLL paths for ICP Engine on Windows
    dll_paths = [
        r"C:\Intellicrack\mamba_env\Lib\site-packages\die",
        r"C:\Intellicrack\mamba_env\DLLs",
        os.path.dirname(sys.executable),
    ]
    for path in dll_paths:
        if os.path.exists(path) and path not in os.environ.get("PATH", ""):
            os.environ["PATH"] = path + os.pathsep + os.environ.get("PATH", "")

try:
    # Skip die import during testing to avoid Windows fatal exceptions
    if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
        raise ImportError("Skipping die import during testing")

    import die as _die_module
    DIE_AVAILABLE = True
    DIE_VERSION = _die_module.__version__
except (ImportError, OSError):
    # ICP Engine has known issues with certain Windows configurations
    # This is not critical for most protection detection functionality
    DIE_AVAILABLE = False
    DIE_VERSION = None
    _die_module = None

logger = get_logger(__name__)

# Import analysis engines for supplemental data
try:
    from ..core.analysis.firmware_analyzer import get_firmware_analyzer, is_binwalk_available
    from ..core.analysis.memory_forensics_engine import (
        get_memory_forensics_engine,
        is_volatility3_available,
    )
    from ..core.analysis.yara_pattern_engine import get_yara_engine, is_yara_available

    SUPPLEMENTAL_ENGINES_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Some supplemental analysis engines not available: {e}")
    SUPPLEMENTAL_ENGINES_AVAILABLE = False


class ScanMode(Enum):
    """ICP Engine scan modes for comprehensive protection analysis"""

    NORMAL = "normal"
    DEEP = "deep"
    HEURISTIC = "heuristic"
    AGGRESSIVE = "aggressive"
    ALL = "all"


@dataclass
class ICPDetection:
    """Single detection from ICP engine"""

    name: str
    type: str
    version: str = ""
    info: str = ""
    string: str = ""
    confidence: float = 1.0  # Default to 100% if not provided

    @classmethod
    def from_icp_result(cls, result) -> "ICPDetection":
        """Create from ICP Engine scan result"""
        return cls(
            name=getattr(result, "name", "Unknown"),
            type=getattr(result, "type", "Unknown"),
            version=getattr(result, "version", ""),
            info=getattr(result, "info", ""),
            string=getattr(result, "string", ""),
            confidence=1.0,  # ICP Engine provides reliable detections with high confidence
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ICPDetection":
        """Create from ICP engine JSON output (legacy compatibility)"""
        return cls(
            name=data.get("name", "Unknown"),
            type=data.get("type", "Unknown"),
            version=data.get("version", ""),
            info=data.get("info", ""),
            string=data.get("string", ""),
        )


@dataclass
class ICPFileInfo:
    """File information from ICP engine"""

    filetype: str
    size: str
    offset: str = "0"
    parentfilepart: str = ""
    detections: list[ICPDetection] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ICPFileInfo":
        """Create from ICP engine JSON output (legacy compatibility)"""
        obj = cls(
            filetype=data.get("filetype", "Unknown"),
            size=data.get("size", "0"),
            offset=data.get("offset", "0"),
            parentfilepart=data.get("parentfilepart", ""),
        )

        # Parse detections
        for value in data.get("values", []):
            obj.detections.append(ICPDetection.from_dict(value))

        return obj


@dataclass
class ICPScanResult:
    """Complete scan result from ICP engine"""

    file_path: str
    file_infos: list[ICPFileInfo] = field(default_factory=list)
    error: str | None = None
    raw_json: dict[str, Any] | None = None
    supplemental_data: dict[str, Any] = field(default_factory=dict)

    @property
    def is_packed(self) -> bool:
        """Check if file is packed"""
        packer_types = ["Packer", "Protector", "Cryptor"]
        for info in self.file_infos:
            for detection in info.detections:
                if detection.type in packer_types:
                    return True
        return False

    @property
    def is_protected(self) -> bool:
        """Check if file has protections"""
        protection_types = ["Protector", "License", "DRM", "Dongle", "Anti-Debug"]
        for info in self.file_infos:
            for detection in info.detections:
                if detection.type in protection_types:
                    return True
        return False

    @property
    def all_detections(self) -> list[ICPDetection]:
        """Get all detections from all file infos"""
        detections = []
        for info in self.file_infos:
            detections.extend(info.detections)
        return detections

    @classmethod
    def from_json(cls, file_path: str, json_data: dict[str, Any]) -> "ICPScanResult":
        """Create from ICP engine JSON output (legacy compatibility)"""
        obj = cls(file_path=file_path, raw_json=json_data)

        # Parse detects array
        for detect in json_data.get("detects", []):
            obj.file_infos.append(ICPFileInfo.from_dict(detect))

        return obj

    @classmethod
    def from_icp_results(cls, file_path: str, icp_results: list) -> "ICPScanResult":
        """Create from ICP Engine scan results"""
        obj = cls(file_path=file_path)

        if not icp_results:
            # Create a basic file info with no detections
            file_info = ICPFileInfo(
                filetype="Binary",
                size=str(Path(file_path).stat().st_size if Path(file_path).exists() else 0),
            )
            obj.file_infos.append(file_info)
            return obj

        # Create file info with detections
        file_info = ICPFileInfo(
            filetype="Binary",  # ICP Engine doesn't provide file type info directly
            size=str(Path(file_path).stat().st_size if Path(file_path).exists() else 0),
        )

        # Convert ICP Engine results to our detection format
        for result in icp_results:
            detection = ICPDetection.from_icp_result(result)
            file_info.detections.append(detection)

        obj.file_infos.append(file_info)
        return obj

    @classmethod
    def from_icp_text(cls, file_path: str, icp_text: str) -> "ICPScanResult":
        """Create from ICP Engine text output.

        Args:
            file_path: Path to the analyzed file
            icp_text: Text output from ICP Engine scan.
                Example format: "PE64\\n    Unknown: Unknown\\n    Packer: UPX"

        Returns:
            ICPScanResult with parsed detections
        """
        obj = cls(file_path=file_path)

        if not icp_text or not icp_text.strip():
            # Create a basic file info with no detections
            file_info = ICPFileInfo(
                filetype="Binary",
                size=str(Path(file_path).stat().st_size if Path(file_path).exists() else 0),
            )
            obj.file_infos.append(file_info)
            return obj

        lines = icp_text.strip().split("\n")
        if not lines:
            return obj

        # First line is the file type (e.g., "PE64", "ELF64")
        filetype = lines[0].strip() if lines else "Binary"

        # Create file info
        file_info = ICPFileInfo(
            filetype=filetype,
            size=str(Path(file_path).stat().st_size if Path(file_path).exists() else 0),
        )

        # Parse detection lines (indented lines after the first)
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue

            # Parse "Type: Name" format
            if ":" in line:
                type_part, name_part = line.split(":", 1)
                detection_type = type_part.strip()
                detection_name = name_part.strip()

                # Create detection with parsed info
                detection = ICPDetection(
                    name=detection_name,
                    type=detection_type,
                    version="",  # ICP Engine text format doesn't include version
                    info="",  # ICP Engine text format doesn't include detailed info
                    string=line,  # Store original line
                    confidence=1.0,  # Default confidence
                )

                file_info.detections.append(detection)
            else:
                # Handle lines without colons (unusual case)
                detection = ICPDetection(
                    name=line,
                    type="Unknown",
                    version="",
                    info="",
                    string=line,
                    confidence=1.0,
                )
                file_info.detections.append(detection)

        obj.file_infos.append(file_info)
        return obj


class ICPEngineError(Exception):
    """ICP Engine specific errors"""


class ICPBackend:
    """Native ICP Engine wrapper providing comprehensive protection analysis functionality.

    This class serves as the core backend for Intellicrack's protection analysis,
    offering advanced native integration for comprehensive binary analysis.
    It provides all the functionality required for sophisticated protection detection
    with enhanced performance, reliability, and seamless integration.

    Core Capabilities:
    - File type detection and analysis
    - Packer and protector identification
    - Shannon entropy calculation and analysis
    - String extraction with offset mapping
    - PE section analysis with detailed metadata
    - Comprehensive binary analysis reports

    The backend supports multiple scan modes from quick analysis to deep
    investigation, and can process files asynchronously to maintain UI
    responsiveness in GUI applications.

    Example:
        .. code-block:: python

            backend = ICPBackend()
            result = await backend.analyze_file("target.exe", ScanMode.DEEP)
            if result.is_packed:
                print(f"File is packed with: {', '.join(result.all_detections)}")

            # Or use synchronous detailed analysis
            analysis = backend.get_detailed_analysis("target.exe")
            print(f"Entropy: {analysis['entropy']:.4f}")
            print(f"Strings found: {len(analysis['strings'])}")

    """

    def __init__(self, engine_path: str | None = None):
        """Initialize ICP backend

        Args:
            engine_path: Legacy parameter for compatibility, ignored in native ICP Engine implementation

        """
        self.engine_path = engine_path  # Keep for compatibility

        # Use pre-imported ICP Engine module to avoid DLL conflicts
        if not DIE_AVAILABLE:
            raise ICPEngineError("ICP Engine library not available - failed to import at module load time")

        self.icp_module = _die_module
        logger.info(f"ICP Backend initialized with ICP Engine v{DIE_VERSION}")
        try:
            logger.info(f"ICP Engine version: {self.icp_module.die_version}")
        except AttributeError:
            logger.debug("ICP Engine version info not available")

    def _get_icp_scan_flags(self, scan_mode: ScanMode) -> int:
        """Convert scan mode to ICP Engine scan flags"""
        flag_map = {
            ScanMode.NORMAL: 0,  # Default scanning
            ScanMode.DEEP: self.icp_module.ScanFlags.DEEP_SCAN,
            ScanMode.HEURISTIC: self.icp_module.ScanFlags.HEURISTIC_SCAN,
            ScanMode.AGGRESSIVE: self.icp_module.ScanFlags.DEEP_SCAN | self.icp_module.ScanFlags.HEURISTIC_SCAN,
            ScanMode.ALL: (
                self.icp_module.ScanFlags.DEEP_SCAN
                | self.icp_module.ScanFlags.HEURISTIC_SCAN
                | self.icp_module.ScanFlags.ALL_TYPES_SCAN
            ),
        }
        return flag_map.get(scan_mode, 0)

    async def analyze_file(
        self,
        file_path: str,
        scan_mode: ScanMode = ScanMode.DEEP,
        show_entropy: bool = True,
        show_info: bool = True,
        timeout: float = 30.0,
        include_supplemental: bool = True,
    ) -> ICPScanResult:
        """Analyze a file asynchronously using ICP Engine with optional supplemental analysis

        Args:
            file_path: Path to file to analyze
            scan_mode: Scan mode to use
            show_entropy: Include entropy analysis (ignored, kept for compatibility)
            show_info: Include file info (ignored, kept for compatibility)
            timeout: Maximum time to wait for analysis
            include_supplemental: Include supplemental analysis from YARA, Binwalk, and Volatility3

        Returns:
            ICPScanResult with analysis data and optional supplemental data

        """
        file_path = Path(file_path)
        if not file_path.exists():
            return ICPScanResult(
                file_path=str(file_path),
                error=f"File not found: {file_path}",
            )

        # Get scan flags
        scan_flags = self._get_icp_scan_flags(scan_mode)

        # Apply additional flags based on parameters
        if show_entropy:
            # Add entropy calculation flag if available
            scan_flags |= 0x0100  # ICP_SHOWERRORS flag can include entropy info

        if not show_info:
            # If info is not requested, use a faster scan mode
            scan_flags &= ~0x0002  # Remove ICP_SHOWVERSION flag

        try:
            # Run ICP Engine analysis in thread pool to avoid blocking
            def _scan_file():
                try:
                    # ICP Engine scan_file returns comprehensive text analysis
                    result_text = self.icp_module.scan_file(str(file_path), scan_flags)
                    return result_text
                except Exception as e:
                    logger.error(f"ICP Engine scan error: {e}")
                    raise

            # Run in executor with timeout
            loop = asyncio.get_event_loop()
            try:
                results = await asyncio.wait_for(
                    loop.run_in_executor(None, _scan_file),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.error(f"Analysis timed out after {timeout} seconds")
                return ICPScanResult(
                    file_path=str(file_path),
                    error=f"Analysis timed out after {timeout} seconds",
                )

            # Convert results to our format
            scan_result = ICPScanResult.from_icp_text(str(file_path), results)

            # Run supplemental analysis if requested
            if include_supplemental and SUPPLEMENTAL_ENGINES_AVAILABLE:
                try:
                    supplemental_data = await self._run_supplemental_analysis(str(file_path))
                    scan_result.supplemental_data = supplemental_data
                except Exception as e:
                    logger.warning(f"Supplemental analysis failed: {e}")

            # Add entropy information if requested
            if show_entropy and os.path.exists(file_path):
                try:
                    # Calculate file entropy
                    import math

                    with open(file_path, "rb") as f:
                        data = f.read(1024 * 1024)  # Read first MB for entropy
                        if data:
                            # Calculate entropy
                            byte_counts = [0] * 256
                            for byte in data:
                                byte_counts[byte] += 1

                            entropy = 0.0
                            data_len = len(data)
                            for count in byte_counts:
                                if count > 0:
                                    probability = count / data_len
                                    entropy -= probability * math.log2(probability)

                            # Add entropy to scan result
                            if not hasattr(scan_result, "metadata"):
                                scan_result.metadata = {}
                            scan_result.metadata["entropy"] = round(entropy, 4)
                            scan_result.metadata["entropy_high"] = (
                                entropy > 7.5
                            )  # High entropy indicates encryption/compression
                except Exception as e:
                    logger.debug(f"Could not calculate entropy: {e}")

            # Add file info if requested
            if show_info and os.path.exists(file_path):
                try:
                    stat_info = os.stat(file_path)
                    if not hasattr(scan_result, "file_info"):
                        scan_result.file_info = {}
                    scan_result.file_info.update(
                        {
                            "size": stat_info.st_size,
                            "modified": stat_info.st_mtime,
                            "created": getattr(stat_info, "st_birthtime", stat_info.st_ctime),
                            "permissions": oct(stat_info.st_mode),
                        }
                    )
                except Exception as e:
                    logger.debug(f"Could not get file info: {e}")

            logger.info(f"Analysis complete: {len(scan_result.all_detections)} detections found")
            return scan_result

        except Exception as e:
            logger.error(f"ICP analysis error: {e}")
            return ICPScanResult(
                file_path=str(file_path),
                error=str(e),
            )

    async def batch_analyze(
        self,
        file_paths: list[str],
        scan_mode: ScanMode = ScanMode.NORMAL,
        max_concurrent: int = 4,
    ) -> dict[str, ICPScanResult]:
        """Analyze multiple files concurrently

        Args:
            file_paths: List of file paths to analyze
            scan_mode: Scan mode to use for all files
            max_concurrent: Maximum concurrent analyses

        Returns:
            Dictionary mapping file paths to results

        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def analyze_with_limit(file_path: str) -> tuple[str, ICPScanResult]:
            async with semaphore:
                result = await self.analyze_file(file_path, scan_mode)
                return file_path, result

        # Run all analyses concurrently
        tasks = [analyze_with_limit(fp) for fp in file_paths]
        results = await asyncio.gather(*tasks)

        # Convert to dictionary
        return dict(results)

    def get_engine_version(self) -> str:
        """Get ICP engine version"""
        try:
            return f"ICP Engine {self.icp_module.__version__} (Core {self.icp_module.die_version})"
        except Exception as e:
            logger.error(f"Failed to get engine version: {e}")
            return "Unknown"

    def get_available_scan_modes(self) -> list[str]:
        """Get list of available scan modes"""
        return [mode.value for mode in ScanMode]

    def is_icp_available(self) -> bool:
        """Check if ICP Engine is available and working"""
        try:
            return hasattr(self, "icp_module") and self.icp_module is not None
        except Exception:
            return False

    def get_file_type(self, file_path: str) -> str:
        """Get file type using native ICP Engine analysis.

        Args:
            file_path: Path to the file to analyze

        Returns:
            str: File type (e.g., "PE64", "ELF64", "Unknown")

        """
        try:
            result = self.icp_module.scan_file(str(file_path), 0)
            lines = result.strip().split("\n")
            return lines[0] if lines else "Unknown"
        except Exception as e:
            logger.error(f"Error getting file type: {e}")
            return "Unknown"

    def get_file_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of file contents.

        Entropy is a measure of randomness/unpredictability in data.
        High entropy (>7.5) often indicates encryption or compression.
        Low entropy (<4.0) indicates normal code/text.

        Args:
            file_path: Path to the file to analyze

        Returns:
            float: Entropy value between 0.0 and 8.0

        """
        try:
            import math

            with open(file_path, "rb") as f:
                data = f.read()
                if not data:
                    return 0.0

                # Calculate entropy
                byte_counts = [0] * 256
                for byte in data:
                    byte_counts[byte] += 1

                entropy = 0.0
                data_len = len(data)
                for count in byte_counts:
                    if count > 0:
                        probability = count / data_len
                        entropy -= probability * math.log2(probability)

                return entropy
        except Exception as e:
            logger.error(f"Error calculating entropy: {e}")
            return 0.0

    def extract_strings(self, file_path: str, min_length: int = 4) -> list[dict[str, any]]:
        """Extract printable ASCII strings from binary file.

        Searches for sequences of printable ASCII characters that could
        indicate hardcoded strings, API names, error messages, etc.

        Args:
            file_path: Path to the file to analyze
            min_length: Minimum string length to extract (default: 4)

        Returns:
            List[Dict]: List of dictionaries containing:
                - offset: File offset where string was found
                - string: The extracted string
                - length: Length of the string
                - type: String type ("ASCII")

        """
        try:
            strings = []
            with open(file_path, "rb") as f:
                data = f.read()

            # Extract ASCII strings
            current_string = ""
            current_offset = 0

            for i, byte in enumerate(data):
                if 32 <= byte <= 126:  # Printable ASCII
                    if not current_string:
                        current_offset = i
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append(
                            {
                                "offset": current_offset,
                                "string": current_string,
                                "length": len(current_string),
                                "type": "ASCII",
                            }
                        )
                    current_string = ""

            # Don't forget the last string
            if len(current_string) >= min_length:
                strings.append(
                    {
                        "offset": current_offset,
                        "string": current_string,
                        "length": len(current_string),
                        "type": "ASCII",
                    }
                )

            return strings
        except Exception as e:
            logger.error(f"Error extracting strings: {e}")
            return []

    def get_file_sections(self, file_path: str) -> list[dict[str, any]]:
        """Extract file sections with detailed information.

        Attempts to parse PE file sections using pefile if available,
        otherwise provides basic file information as a single section.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List[Dict]: List of section dictionaries containing:
                - name: Section name
                - virtual_address: Virtual address in memory
                - virtual_size: Size in memory
                - raw_size: Size on disk
                - raw_offset: Offset in file
                - characteristics: Section characteristics flags
                - entropy: Section entropy (calculated if needed)

        """
        try:
            sections = []

            # Try to get sections from PE analysis
            from intellicrack.handlers.pefile_handler import pefile

            try:
                pe = pefile.PE(file_path)
                for section in pe.sections:
                    section_info = {
                        "name": section.Name.decode("utf-8").rstrip("\x00"),
                        "virtual_address": section.VirtualAddress,
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "raw_offset": section.PointerToRawData,
                        "characteristics": section.Characteristics,
                        "entropy": 0.0,  # Will calculate if needed
                    }
                    sections.append(section_info)
            except Exception as e:
                logger.debug("Error parsing PE sections: %s", e)

            # Fallback to basic file analysis
            if not sections:
                file_size = os.path.getsize(file_path)
                sections.append(
                    {
                        "name": ".data",
                        "virtual_address": 0,
                        "virtual_size": file_size,
                        "raw_size": file_size,
                        "raw_offset": 0,
                        "characteristics": 0,
                        "entropy": self.get_file_entropy(file_path),
                    }
                )

            return sections
        except Exception as e:
            logger.error(f"Error getting file sections: {e}")
            return []

    def detect_packers(self, file_path: str) -> list[str]:
        """Detect packers and protectors using native ICP Engine analysis.

        Scans the file and extracts any detections that are classified
        as packers or protectors based on the detection type.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List[str]: List of detected packer/protector names

        """
        try:
            result = self.icp_module.scan_file(str(file_path), 0)
            lines = result.strip().split("\n")

            packers = []
            for line in lines[1:]:  # Skip file type line
                line = line.strip()
                if ":" in line:
                    type_part, name_part = line.split(":", 1)
                    type_part = type_part.strip()
                    name_part = name_part.strip()

                    if "pack" in type_part.lower():
                        packers.append(name_part)

            return packers
        except Exception as e:
            logger.error(f"Error detecting packers: {e}")
            return []

    def add_supplemental_data(
        self, scan_result: ICPScanResult, supplemental_data: dict[str, Any]
    ) -> ICPScanResult:
        """Add supplemental analysis data to an ICP scan result

        Args:
            scan_result: Existing ICP scan result
            supplemental_data: Additional analysis data from external engines

        Returns:
            Updated ICPScanResult with merged supplemental data

        """
        if supplemental_data:
            scan_result.supplemental_data.update(supplemental_data)

            # Enhance detections with supplemental findings
            self._merge_supplemental_detections(scan_result, supplemental_data)

        return scan_result

    def _merge_supplemental_detections(
        self, scan_result: ICPScanResult, supplemental_data: dict[str, Any]
    ):
        """Merge supplemental analysis findings into ICP detections"""
        try:
            # Process YARA pattern findings
            if "yara_analysis" in supplemental_data:
                yara_data = supplemental_data["yara_analysis"]
                for pattern in yara_data.get("pattern_matches", []):
                    # Create detection for YARA match
                    detection = ICPDetection(
                        name=pattern.get("rule_name", "YARA Pattern"),
                        type="Pattern",
                        version="",
                        info=f"YARA: {pattern.get('category', 'Unknown')}",
                        string=pattern.get("description", ""),
                        confidence=pattern.get("confidence", 0.8),
                    )

                    # Add to first file info or create new one
                    if scan_result.file_infos:
                        scan_result.file_infos[0].detections.append(detection)
                    else:
                        file_info = ICPFileInfo(
                            filetype="Binary",
                            size=str(
                                Path(scan_result.file_path).stat().st_size
                                if Path(scan_result.file_path).exists()
                                else 0
                            ),
                        )
                        file_info.detections.append(detection)
                        scan_result.file_infos.append(file_info)

            # Process firmware analysis findings
            if "firmware_analysis" in supplemental_data:
                firmware_data = supplemental_data["firmware_analysis"]
                for component in firmware_data.get("embedded_components", []):
                    if component.get("is_executable") or component.get("is_filesystem"):
                        detection = ICPDetection(
                            name=component.get("name", "Embedded Component"),
                            type="Firmware",
                            version="",
                            info=f"Firmware: {component.get('type', 'Unknown')} at offset {component.get('offset', 0)}",
                            string=f"Size: {component.get('size', 0)} bytes",
                            confidence=component.get("confidence", 0.9),
                        )

                        if scan_result.file_infos:
                            scan_result.file_infos[0].detections.append(detection)
                        else:
                            file_info = ICPFileInfo(
                                filetype="Firmware",
                                size=str(
                                    Path(scan_result.file_path).stat().st_size
                                    if Path(scan_result.file_path).exists()
                                    else 0
                                ),
                            )
                            file_info.detections.append(detection)
                            scan_result.file_infos.append(file_info)

            # Process memory forensics findings
            if "memory_forensics" in supplemental_data:
                memory_data = supplemental_data["memory_forensics"]
                for indicator in memory_data.get("process_indicators", []):
                    if indicator.get("is_hidden") or indicator.get("indicators"):
                        detection = ICPDetection(
                            name=f"Process {indicator.get('name', 'Unknown')}",
                            type="Memory",
                            version="",
                            info=f"Memory: PID {indicator.get('pid', 0)} - {', '.join(indicator.get('indicators', []))}",
                            string=f"Hidden: {indicator.get('is_hidden', False)}",
                            confidence=0.7,
                        )

                        if scan_result.file_infos:
                            scan_result.file_infos[0].detections.append(detection)
                        else:
                            file_info = ICPFileInfo(
                                filetype="Memory Dump",
                                size=str(
                                    Path(scan_result.file_path).stat().st_size
                                    if Path(scan_result.file_path).exists()
                                    else 0
                                ),
                            )
                            file_info.detections.append(detection)
                            scan_result.file_infos.append(file_info)

        except Exception as e:
            logger.error(f"Error merging supplemental detections: {e}")

    def merge_analysis_engines_data(
        self,
        file_path: str,
        yara_data: dict[str, Any] | None = None,
        firmware_data: dict[str, Any] | None = None,
        memory_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Merge data from all analysis engines into a unified report

        Args:
            file_path: Path to the analyzed file
            yara_data: YARA pattern analysis results
            firmware_data: Binwalk firmware analysis results
            memory_data: Volatility3 memory forensics results

        Returns:
            Unified analysis report with all engine data

        """
        try:
            # Start with base ICP analysis
            base_analysis = self.get_detailed_analysis(file_path)

            # Create supplemental data structure
            supplemental_data = {}

            if yara_data:
                supplemental_data["yara_analysis"] = yara_data

            if firmware_data:
                supplemental_data["firmware_analysis"] = firmware_data

            if memory_data:
                supplemental_data["memory_forensics"] = memory_data

            # Merge supplemental data into base analysis
            if supplemental_data:
                base_analysis["supplemental_analysis"] = supplemental_data

                # Enhanced threat assessment with supplemental data
                base_analysis["threat_assessment"] = self._calculate_threat_score(
                    base_analysis, supplemental_data
                )

                # Combined security indicators
                base_analysis["security_indicators"] = self._extract_security_indicators(
                    supplemental_data
                )

                # Enhanced protection bypass recommendations
                base_analysis["bypass_recommendations"] = self._generate_bypass_recommendations(
                    base_analysis, supplemental_data
                )

            return base_analysis

        except Exception as e:
            logger.error(f"Error merging analysis engines data: {e}")
            return {
                "file_path": file_path,
                "error": str(e),
            }

    def _calculate_threat_score(
        self, base_analysis: dict[str, Any], supplemental_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Calculate comprehensive threat score based on all analysis data"""
        try:
            threat_score = 0.0
            threat_indicators = []

            # Base ICP analysis scoring
            if base_analysis.get("is_packed"):
                threat_score += 2.0
                threat_indicators.append("File is packed/protected")

            if base_analysis.get("is_encrypted") or base_analysis.get("entropy", 0) > 7.5:
                threat_score += 1.5
                threat_indicators.append("High entropy - possible encryption")

            # YARA analysis scoring
            yara_data = supplemental_data.get("yara_analysis", {})
            if yara_data.get("security_findings"):
                threat_score += len(yara_data["security_findings"]) * 0.5
                threat_indicators.append(
                    f"YARA: {len(yara_data['security_findings'])} security patterns found"
                )

            # Firmware analysis scoring
            firmware_data = supplemental_data.get("firmware_analysis", {})
            if firmware_data.get("security_findings"):
                threat_score += len(firmware_data["security_findings"]) * 0.3
                threat_indicators.append(
                    f"Firmware: {len(firmware_data['security_findings'])} security issues found"
                )

            # Memory forensics scoring
            memory_data = supplemental_data.get("memory_forensics", {})
            if memory_data.get("has_suspicious_activity"):
                threat_score += 2.0
                threat_indicators.append("Memory: Suspicious activity detected")

            # Normalize threat score (0-10 scale)
            threat_score = min(threat_score, 10.0)

            return {
                "score": round(threat_score, 2),
                "level": "critical"
                if threat_score >= 7.0
                else "high"
                if threat_score >= 5.0
                else "medium"
                if threat_score >= 3.0
                else "low",
                "indicators": threat_indicators,
                "assessment": f"Threat level: {threat_score:.1f}/10.0",
            }

        except Exception as e:
            logger.error(f"Error calculating threat score: {e}")
            return {
                "score": 0.0,
                "level": "unknown",
                "indicators": [],
                "assessment": "Assessment failed",
            }

    def _extract_security_indicators(
        self, supplemental_data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Extract unified security indicators from all analysis engines"""
        indicators = []

        try:
            # YARA security indicators
            yara_data = supplemental_data.get("yara_analysis", {})
            for indicator in yara_data.get("security_indicators", []):
                indicators.append(
                    {
                        "source": "YARA",
                        "type": indicator.get("type", "unknown"),
                        "severity": indicator.get("severity", "low"),
                        "description": indicator.get("description", ""),
                        "confidence": indicator.get("confidence", 0.5),
                    }
                )

            # Firmware security indicators
            firmware_data = supplemental_data.get("firmware_analysis", {})
            for indicator in firmware_data.get("security_indicators", []):
                indicators.append(
                    {
                        "source": "Firmware",
                        "type": indicator.get("type", "unknown"),
                        "severity": indicator.get("severity", "low"),
                        "description": indicator.get("description", ""),
                        "file": indicator.get("file", ""),
                        "remediation": indicator.get("remediation", ""),
                    }
                )

            # Memory forensics security indicators
            memory_data = supplemental_data.get("memory_forensics", {})
            for indicator in memory_data.get("security_indicators", []):
                indicators.append(
                    {
                        "source": "Memory",
                        "type": indicator.get("type", "unknown"),
                        "severity": indicator.get("severity", "low"),
                        "description": indicator.get("description", ""),
                        "evidence": indicator.get("evidence", {}),
                    }
                )

        except Exception as e:
            logger.error(f"Error extracting security indicators: {e}")

        return indicators

    def _generate_bypass_recommendations(
        self, base_analysis: dict[str, Any], supplemental_data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Generate protection bypass recommendations based on analysis data"""
        recommendations = []

        try:
            # Base ICP recommendations
            if base_analysis.get("is_packed"):
                packers = base_analysis.get("packers", [])
                for packer in packers:
                    recommendations.append(
                        {
                            "target": f"Packer: {packer}",
                            "method": "Unpacking",
                            "tools": ["UPX", "PEiD", "Universal Unpacker"],
                            "difficulty": "medium",
                            "description": f"Use specialized unpacker for {packer}",
                        }
                    )

            # YARA-based recommendations
            yara_data = supplemental_data.get("yara_analysis", {})
            for pattern in yara_data.get("pattern_matches", []):
                if pattern.get("category") in ["ANTI_DEBUG", "PROTECTION"]:
                    recommendations.append(
                        {
                            "target": f"Protection: {pattern.get('rule_name', 'Unknown')}",
                            "method": "Pattern Bypass",
                            "tools": ["Debugger", "Hex Editor", "Patch Tool"],
                            "difficulty": "high",
                            "description": f"Patch or bypass {pattern.get('description', 'protection mechanism')}",
                        }
                    )

            # Firmware-based recommendations
            firmware_data = supplemental_data.get("firmware_analysis", {})
            for component in firmware_data.get("embedded_components", []):
                if component.get("is_executable"):
                    recommendations.append(
                        {
                            "target": f"Embedded Executable: {component.get('name', 'Unknown')}",
                            "method": "Extraction & Analysis",
                            "tools": ["Binwalk", "Ghidra", "IDA Pro"],
                            "difficulty": "medium",
                            "description": f"Extract and analyze embedded component at offset {component.get('offset', 0)}",
                        }
                    )

            # Memory-based recommendations
            memory_data = supplemental_data.get("memory_forensics", {})
            if memory_data.get("has_suspicious_activity"):
                recommendations.append(
                    {
                        "target": "Runtime Protection",
                        "method": "Memory Analysis",
                        "tools": ["Volatility", "Process Hacker", "Debugging"],
                        "difficulty": "high",
                        "description": "Analyze runtime behavior and memory layout for bypass opportunities",
                    }
                )

        except Exception as e:
            logger.error(f"Error generating bypass recommendations: {e}")

        return recommendations

    def get_detailed_analysis(
        self,
        file_path: str,
        include_supplemental: bool = False,
        yara_data: dict[str, Any] | None = None,
        firmware_data: dict[str, Any] | None = None,
        memory_data: dict[str, Any] | None = None,
    ) -> dict[str, any]:
        """Perform comprehensive file analysis combining all ICP backend capabilities.

        This is the main analysis method that combines file type detection,
        entropy analysis, section parsing, string extraction, and packer
        detection into a single comprehensive report.

        Args:
            file_path: Path to the file to analyze
            include_supplemental: Whether to include supplemental analysis data
            yara_data: Optional YARA analysis results
            firmware_data: Optional firmware analysis results
            memory_data: Optional memory forensics results

        Returns:
            Dict[str, any]: Comprehensive analysis containing:
                - file_path: Original file path
                - file_type: Detected file type
                - file_size: Size in bytes
                - entropy: Overall file entropy
                - sections: List of file sections with details
                - strings: Extracted strings with offsets
                - packers: Detected packers/protectors
                - is_packed: Boolean indicating if file is packed
                - is_encrypted: Boolean indicating if file appears encrypted
                - supplemental_analysis: Additional analysis data (if requested)
                - threat_assessment: Unified threat scoring (if supplemental data provided)
                - security_indicators: Combined security findings (if supplemental data provided)
                - bypass_recommendations: Protection bypass suggestions (if supplemental data provided)
                - error: Error message if analysis failed

        """
        try:
            analysis = {
                "file_path": file_path,
                "file_type": self.get_file_type(file_path),
                "file_size": os.path.getsize(file_path),
                "entropy": self.get_file_entropy(file_path),
                "sections": self.get_file_sections(file_path),
                "strings": self.extract_strings(file_path),
                "packers": self.detect_packers(file_path),
                "is_packed": False,
                "is_encrypted": False,
            }

            # Determine if file is packed/encrypted
            analysis["is_packed"] = len(analysis["packers"]) > 0
            analysis["is_encrypted"] = analysis["entropy"] > 7.5

            # Include supplemental analysis if requested
            if include_supplemental and any([yara_data, firmware_data, memory_data]):
                return self.merge_analysis_engines_data(
                    file_path, yara_data, firmware_data, memory_data
                )

            return analysis
        except Exception as e:
            logger.error(f"Error in detailed analysis: {e}")
            return {
                "file_path": file_path,
                "error": str(e),
            }

    async def _run_supplemental_analysis(self, file_path: str) -> dict[str, Any]:
        """Run supplemental analysis using YARA, Binwalk, and Volatility3 engines

        Args:
            file_path: Path to file to analyze

        Returns:
            Merged supplemental data from all available engines

        """
        supplemental_data = {
            "engines_used": [],
            "analysis_summary": {
                "yara_available": False,
                "binwalk_available": False,
                "volatility_available": False,
            },
        }

        # Run YARA pattern analysis
        if is_yara_available():
            try:
                yara_engine = get_yara_engine()
                if yara_engine:
                    logger.debug("Running YARA pattern analysis")
                    yara_result = yara_engine.scan_file(file_path, timeout=30)
                    if not yara_result.error:
                        yara_supplemental = yara_engine.generate_icp_supplemental_data(yara_result)
                        if yara_supplemental:
                            supplemental_data.update(yara_supplemental)
                            supplemental_data["engines_used"].append("yara")
                            supplemental_data["analysis_summary"]["yara_available"] = True
            except Exception as e:
                logger.debug(f"YARA analysis failed: {e}")

        # Run Binwalk firmware analysis
        if is_binwalk_available():
            try:
                firmware_analyzer = get_firmware_analyzer()
                if firmware_analyzer:
                    logger.debug("Running Binwalk firmware analysis")
                    # Run firmware analysis asynchronously
                    loop = asyncio.get_event_loop()
                    firmware_result = await loop.run_in_executor(
                        None,
                        lambda: firmware_analyzer.analyze_firmware(
                            file_path,
                            extract_files=False,  # Skip extraction for performance
                            analyze_security=True,
                            extraction_depth=1,
                        ),
                    )
                    if not firmware_result.error:
                        firmware_supplemental = firmware_analyzer.generate_icp_supplemental_data(
                            firmware_result
                        )
                        if firmware_supplemental:
                            supplemental_data.update(firmware_supplemental)
                            supplemental_data["engines_used"].append("binwalk")
                            supplemental_data["analysis_summary"]["binwalk_available"] = True
            except Exception as e:
                logger.debug(f"Binwalk analysis failed: {e}")

        # Skip Volatility3 analysis for regular files (it's for memory dumps)
        if is_volatility3_available():
            try:
                # Only run Volatility3 if the file looks like a memory dump
                file_size = os.path.getsize(file_path)
                filename = os.path.basename(file_path).lower()

                # Heuristics for memory dump detection
                is_memory_dump = (
                    file_size > 100 * 1024 * 1024  # > 100MB
                    or any(keyword in filename for keyword in ["dump", "mem", "vmem", "raw", "dmp"])
                    or filename.endswith((".vmem", ".raw", ".dmp", ".mem"))
                )

                if is_memory_dump:
                    memory_engine = get_memory_forensics_engine()
                    if memory_engine:
                        logger.debug("Running Volatility3 memory analysis")
                        # Run memory analysis asynchronously
                        loop = asyncio.get_event_loop()
                        memory_result = await loop.run_in_executor(
                            None,
                            lambda: memory_engine.analyze_memory_dump(
                                file_path,
                                deep_analysis=False,  # Skip deep analysis for performance
                            ),
                        )
                        if not memory_result.error:
                            memory_supplemental = memory_engine.generate_icp_supplemental_data(
                                memory_result
                            )
                            if memory_supplemental:
                                supplemental_data.update(memory_supplemental)
                                supplemental_data["engines_used"].append("volatility3")
                                supplemental_data["analysis_summary"]["volatility_available"] = True
                else:
                    logger.debug(
                        "Skipping Volatility3 analysis - file doesn't appear to be a memory dump"
                    )
                    supplemental_data["analysis_summary"]["volatility_available"] = True
            except Exception as e:
                logger.debug(f"Volatility3 analysis failed: {e}")

        # Add summary information
        supplemental_data["analysis_summary"]["engines_run"] = len(
            supplemental_data["engines_used"]
        )
        supplemental_data["analysis_summary"]["total_engines_available"] = (
            int(is_yara_available()) + int(is_binwalk_available()) + int(is_volatility3_available())
        )

        logger.info(f"Supplemental analysis complete: {supplemental_data['engines_used']}")
        return supplemental_data

    def get_supplemental_engines_status(self) -> dict[str, Any]:
        """Get status of supplemental analysis engines

        Returns:
            Dictionary with engine availability and status

        """
        return {
            "supplemental_engines_available": SUPPLEMENTAL_ENGINES_AVAILABLE,
            "yara_available": is_yara_available() if SUPPLEMENTAL_ENGINES_AVAILABLE else False,
            "binwalk_available": is_binwalk_available()
            if SUPPLEMENTAL_ENGINES_AVAILABLE
            else False,
            "volatility3_available": is_volatility3_available()
            if SUPPLEMENTAL_ENGINES_AVAILABLE
            else False,
            "engines_summary": {
                "yara": "Pattern matching for protections, packers, and license systems",
                "binwalk": "Firmware analysis and embedded file extraction",
                "volatility3": "Memory forensics for runtime analysis",
            },
        }

    async def analyze_with_all_engines(
        self,
        file_path: str,
        scan_mode: ScanMode = ScanMode.DEEP,
    ) -> ICPScanResult:
        """Convenience method to analyze file with all available engines

        Args:
            file_path: Path to file to analyze
            scan_mode: ICP scan mode to use

        Returns:
            Complete analysis results with supplemental data

        """
        return await self.analyze_file(
            file_path=file_path,
            scan_mode=scan_mode,
            include_supplemental=True,
        )


# Singleton instance
_icp_backend: ICPBackend | None = None


def get_icp_backend() -> ICPBackend:
    """Get or create the ICP backend singleton"""
    global _icp_backend
    if _icp_backend is None:
        _icp_backend = ICPBackend()
    return _icp_backend


# Integration helper for existing protection detector
async def analyze_with_icp(file_path: str) -> ICPScanResult | None:
    """Helper function for easy integration"""
    backend = get_icp_backend()
    return await backend.analyze_file(file_path, ScanMode.DEEP)
