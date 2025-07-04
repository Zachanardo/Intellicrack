"""
Intellicrack Protection Engine Backend Wrapper

Provides native die-python integration for protection analysis.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ScanMode(Enum):
    """ICP Engine scan modes mapped to die-python flags"""
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
    def from_die_result(cls, result) -> 'ICPDetection':
        """Create from die-python scan result"""
        return cls(
            name=getattr(result, 'name', 'Unknown'),
            type=getattr(result, 'type', 'Unknown'),
            version=getattr(result, 'version', ''),
            info=getattr(result, 'info', ''),
            string=getattr(result, 'string', ''),
            confidence=1.0  # die-python doesn't provide confidence scores
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ICPDetection':
        """Create from ICP engine JSON output (legacy compatibility)"""
        return cls(
            name=data.get("name", "Unknown"),
            type=data.get("type", "Unknown"),
            version=data.get("version", ""),
            info=data.get("info", ""),
            string=data.get("string", "")
        )


@dataclass
class ICPFileInfo:
    """File information from ICP engine"""
    filetype: str
    size: str
    offset: str = "0"
    parentfilepart: str = ""
    detections: List[ICPDetection] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ICPFileInfo':
        """Create from ICP engine JSON output (legacy compatibility)"""
        obj = cls(
            filetype=data.get("filetype", "Unknown"),
            size=data.get("size", "0"),
            offset=data.get("offset", "0"),
            parentfilepart=data.get("parentfilepart", "")
        )

        # Parse detections
        for value in data.get("values", []):
            obj.detections.append(ICPDetection.from_dict(value))

        return obj


@dataclass
class ICPScanResult:
    """Complete scan result from ICP engine"""
    file_path: str
    file_infos: List[ICPFileInfo] = field(default_factory=list)
    error: Optional[str] = None
    raw_json: Optional[Dict[str, Any]] = None

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
    def all_detections(self) -> List[ICPDetection]:
        """Get all detections from all file infos"""
        detections = []
        for info in self.file_infos:
            detections.extend(info.detections)
        return detections

    @classmethod
    def from_json(cls, file_path: str, json_data: Dict[str, Any]) -> 'ICPScanResult':
        """Create from ICP engine JSON output (legacy compatibility)"""
        obj = cls(file_path=file_path, raw_json=json_data)

        # Parse detects array
        for detect in json_data.get("detects", []):
            obj.file_infos.append(ICPFileInfo.from_dict(detect))

        return obj

    @classmethod
    def from_die_results(cls, file_path: str, die_results: List) -> 'ICPScanResult':
        """Create from die-python scan results"""
        obj = cls(file_path=file_path)

        if not die_results:
            # Create a basic file info with no detections
            file_info = ICPFileInfo(
                filetype="Binary",
                size=str(Path(file_path).stat().st_size if Path(file_path).exists() else 0)
            )
            obj.file_infos.append(file_info)
            return obj

        # Create file info with detections
        file_info = ICPFileInfo(
            filetype="Binary",  # die-python doesn't provide file type info directly
            size=str(Path(file_path).stat().st_size if Path(file_path).exists() else 0)
        )

        # Convert die-python results to our detection format
        for result in die_results:
            detection = ICPDetection.from_die_result(result)
            file_info.detections.append(detection)

        obj.file_infos.append(file_info)
        return obj

    @classmethod
    def from_die_text(cls, file_path: str, die_text: str) -> 'ICPScanResult':
        """Create from die-python text output
        
        Args:
            file_path: Path to the analyzed file
            die_text: Text output from die.scan_file()
                     Format: "PE64\n    Unknown: Unknown\n    Packer: UPX"
        
        Returns:
            ICPScanResult with parsed detections
        """
        obj = cls(file_path=file_path)
        
        if not die_text or not die_text.strip():
            # Create a basic file info with no detections
            file_info = ICPFileInfo(
                filetype="Binary",
                size=str(Path(file_path).stat().st_size if Path(file_path).exists() else 0)
            )
            obj.file_infos.append(file_info)
            return obj

        lines = die_text.strip().split('\n')
        if not lines:
            return obj

        # First line is the file type (e.g., "PE64", "ELF64")
        filetype = lines[0].strip() if lines else "Binary"
        
        # Create file info
        file_info = ICPFileInfo(
            filetype=filetype,
            size=str(Path(file_path).stat().st_size if Path(file_path).exists() else 0)
        )

        # Parse detection lines (indented lines after the first)
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
                
            # Parse "Type: Name" format
            if ':' in line:
                type_part, name_part = line.split(':', 1)
                detection_type = type_part.strip()
                detection_name = name_part.strip()
                
                # Create detection with parsed info
                detection = ICPDetection(
                    name=detection_name,
                    type=detection_type,
                    version="",  # die-python text format doesn't include version
                    info="",     # die-python text format doesn't include detailed info
                    string=line, # Store original line
                    confidence=1.0  # Default confidence
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
                    confidence=1.0
                )
                file_info.detections.append(detection)

        obj.file_infos.append(file_info)
        return obj


class ICPEngineError(Exception):
    """ICP Engine specific errors"""
    pass


class ICPBackend:
    """Native die-python wrapper for ICP Engine functionality"""

    def __init__(self, engine_path: Optional[str] = None):
        """Initialize ICP backend

        Args:
            engine_path: Legacy parameter for compatibility, ignored in die-python implementation
        """
        self.engine_path = engine_path  # Keep for compatibility

        # Import die-python
        try:
            import die
            self.die = die
            logger.info(f"ICP Backend initialized with die-python v{die.__version__}")
            logger.info(f"DIE engine version: {die.die_version}")
        except ImportError as e:
            raise ICPEngineError(f"die-python library not available: {e}")

    def _get_die_scan_flags(self, scan_mode: ScanMode) -> int:
        """Convert scan mode to die-python scan flags"""
        flag_map = {
            ScanMode.NORMAL: 0,  # Default scanning
            ScanMode.DEEP: self.die.ScanFlags.DEEP_SCAN,
            ScanMode.HEURISTIC: self.die.ScanFlags.HEURISTIC_SCAN,
            ScanMode.AGGRESSIVE: self.die.ScanFlags.DEEP_SCAN | self.die.ScanFlags.HEURISTIC_SCAN,
            ScanMode.ALL: (self.die.ScanFlags.DEEP_SCAN |
                          self.die.ScanFlags.HEURISTIC_SCAN |
                          self.die.ScanFlags.ALL_TYPES_SCAN)
        }
        return flag_map.get(scan_mode, 0)

    async def analyze_file(
        self,
        file_path: str,
        scan_mode: ScanMode = ScanMode.DEEP,
        show_entropy: bool = True,
        show_info: bool = True,
        timeout: float = 30.0
    ) -> ICPScanResult:
        """Analyze a file asynchronously using die-python

        Args:
            file_path: Path to file to analyze
            scan_mode: Scan mode to use
            show_entropy: Include entropy analysis (ignored, kept for compatibility)
            show_info: Include file info (ignored, kept for compatibility)
            timeout: Maximum time to wait for analysis

        Returns:
            ICPScanResult with analysis data
        """
        file_path = Path(file_path)
        if not file_path.exists():
            return ICPScanResult(
                file_path=str(file_path),
                error=f"File not found: {file_path}"
            )

        # Get scan flags
        scan_flags = self._get_die_scan_flags(scan_mode)
        
        # Apply additional flags based on parameters
        if show_entropy:
            # Add entropy calculation flag if available
            scan_flags |= 0x0100  # DIE_SHOWERRORS flag can include entropy info
        
        if not show_info:
            # If info is not requested, use a faster scan mode
            scan_flags &= ~0x0002  # Remove DIE_SHOWVERSION flag

        try:
            # Run die-python analysis in thread pool to avoid blocking
            def _scan_file():
                try:
                    # die.scan_file returns a string, not a list
                    result_text = self.die.scan_file(str(file_path), scan_flags)
                    return result_text
                except Exception as e:
                    logger.error(f"die-python scan error: {e}")
                    raise

            # Run in executor with timeout
            loop = asyncio.get_event_loop()
            try:
                results = await asyncio.wait_for(
                    loop.run_in_executor(None, _scan_file),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.error(f"Analysis timed out after {timeout} seconds")
                return ICPScanResult(
                    file_path=str(file_path),
                    error=f"Analysis timed out after {timeout} seconds"
                )

            # Convert results to our format
            scan_result = ICPScanResult.from_die_text(str(file_path), results)
            
            # Add entropy information if requested
            if show_entropy and os.path.exists(file_path):
                try:
                    # Calculate file entropy
                    import math
                    with open(file_path, 'rb') as f:
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
                            if not hasattr(scan_result, 'metadata'):
                                scan_result.metadata = {}
                            scan_result.metadata['entropy'] = round(entropy, 4)
                            scan_result.metadata['entropy_high'] = entropy > 7.5  # High entropy indicates encryption/compression
                except Exception as e:
                    logger.debug(f"Could not calculate entropy: {e}")
            
            # Add file info if requested
            if show_info and os.path.exists(file_path):
                try:
                    stat_info = os.stat(file_path)
                    if not hasattr(scan_result, 'file_info'):
                        scan_result.file_info = {}
                    scan_result.file_info.update({
                        'size': stat_info.st_size,
                        'modified': stat_info.st_mtime,
                        'created': getattr(stat_info, 'st_birthtime', stat_info.st_ctime),
                        'permissions': oct(stat_info.st_mode),
                    })
                except Exception as e:
                    logger.debug(f"Could not get file info: {e}")

            logger.info(f"Analysis complete: {len(scan_result.all_detections)} detections found")
            return scan_result

        except Exception as e:
            logger.error(f"ICP analysis error: {e}")
            return ICPScanResult(
                file_path=str(file_path),
                error=str(e)
            )

    async def batch_analyze(
        self,
        file_paths: List[str],
        scan_mode: ScanMode = ScanMode.NORMAL,
        max_concurrent: int = 4
    ) -> Dict[str, ICPScanResult]:
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
            return f"die-python {self.die.__version__} (DIE {self.die.die_version})"
        except Exception as e:
            logger.error(f"Failed to get engine version: {e}")
            return "Unknown"

    def get_available_scan_modes(self) -> List[str]:
        """Get list of available scan modes"""
        return [mode.value for mode in ScanMode]

    def is_die_python_available(self) -> bool:
        """Check if die-python is available and working"""
        try:
            return hasattr(self, 'die') and self.die is not None
        except Exception:
            return False


# Singleton instance
_icp_backend: Optional[ICPBackend] = None


def get_icp_backend() -> ICPBackend:
    """Get or create the ICP backend singleton"""
    global _icp_backend
    if _icp_backend is None:
        _icp_backend = ICPBackend()
    return _icp_backend


# Integration helper for existing protection detector
async def analyze_with_icp(file_path: str) -> Optional[ICPScanResult]:
    """Helper function for easy integration"""
    backend = get_icp_backend()
    return await backend.analyze_file(file_path, ScanMode.DEEP)
