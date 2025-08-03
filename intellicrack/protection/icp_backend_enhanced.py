"""
Enhanced ICP Backend with JSON-based DIE Integration

Replaces fragile string parsing with robust JSON-based DIE analysis.
Maintains backward compatibility while providing improved reliability and structured output.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..core.analysis.die_json_wrapper import (
    DIEJSONWrapper,
    DIEAnalysisResult,
    DIEDetection,
    DIEScanMode,
    create_die_wrapper
)
from ..core.analysis.die_structured_logger import get_die_structured_logger, log_die_analysis_session
from ..utils.logger import get_logger

logger = get_logger(__name__)

# Import existing types for compatibility
try:
    from .icp_backend import ICPDetection, ICPFileInfo, ICPScanResult, ScanMode
    COMPATIBILITY_TYPES_AVAILABLE = True
except ImportError:
    logger.warning("Original ICP backend types not available, using local definitions")
    COMPATIBILITY_TYPES_AVAILABLE = False

    # Define compatibility types locally
    class ScanMode(Enum):
        NORMAL = "normal"
        DEEP = "deep"
        HEURISTIC = "heuristic"
        AGGRESSIVE = "aggressive"
        ALL = "all"

    @dataclass
    class ICPDetection:
        name: str
        type: str
        version: str = ""
        info: str = ""
        string: str = ""
        confidence: float = 1.0

    @dataclass
    class ICPFileInfo:
        filetype: str
        size: str
        detections: List[ICPDetection] = field(default_factory=list)

    @dataclass
    class ICPScanResult:
        file_path: str
        file_infos: List[ICPFileInfo] = field(default_factory=list)
        supplemental_data: Optional[Dict[str, Any]] = None
        analysis_time: float = 0.0
        error: Optional[str] = None


class EnhancedICPBackend:
    """
    Enhanced ICP Backend with JSON-based DIE integration
    
    Provides robust, structured analysis results while maintaining backward
    compatibility with existing ICP backend interface.
    """

    def __init__(self, die_executable_path: Optional[str] = None,
                 enable_supplemental_analysis: bool = True,
                 cache_results: bool = True):
        """
        Initialize enhanced ICP backend
        
        Args:
            die_executable_path: Path to DIE executable (optional)
            enable_supplemental_analysis: Enable additional analysis engines
            cache_results: Enable result caching
        """
        self.die_wrapper = DIEJSONWrapper(
            die_executable_path=die_executable_path,
            use_die_python=True
        )
        self.enable_supplemental_analysis = enable_supplemental_analysis
        self.cache_results = cache_results
        self._result_cache: Dict[str, ICPScanResult] = {}
        self.structured_logger = get_die_structured_logger()
        
        logger.info("Enhanced ICP Backend initialized with JSON-based DIE integration")
        
        # Log version information
        version_info = self.die_wrapper.get_version_info()
        for component, version in version_info.items():
            logger.info(f"{component}: {version}")

    def _convert_scan_mode(self, scan_mode: ScanMode) -> DIEScanMode:
        """Convert ICP scan mode to DIE JSON wrapper scan mode"""
        mode_map = {
            ScanMode.NORMAL: DIEScanMode.NORMAL,
            ScanMode.DEEP: DIEScanMode.DEEP,
            ScanMode.HEURISTIC: DIEScanMode.HEURISTIC,
            ScanMode.AGGRESSIVE: DIEScanMode.ALL,
            ScanMode.ALL: DIEScanMode.ALL
        }
        return mode_map.get(scan_mode, DIEScanMode.NORMAL)

    def _convert_die_to_icp_detection(self, die_detection: DIEDetection) -> ICPDetection:
        """Convert DIE detection to ICP detection format"""
        return ICPDetection(
            name=die_detection.name,
            type=die_detection.type,
            version=die_detection.version,
            info=die_detection.info,
            string=f"{die_detection.type}: {die_detection.name}",
            confidence=die_detection.confidence
        )

    def _convert_die_to_icp_result(self, die_result: DIEAnalysisResult) -> ICPScanResult:
        """Convert DIE analysis result to ICP scan result format"""
        # Create file info
        file_info = ICPFileInfo(
            filetype=die_result.file_type,
            size=str(die_result.file_size)
        )
        
        # Convert detections
        for die_detection in die_result.detections:
            icp_detection = self._convert_die_to_icp_detection(die_detection)
            file_info.detections.append(icp_detection)

        # Create scan result
        scan_result = ICPScanResult(
            file_path=die_result.file_path,
            file_infos=[file_info],
            analysis_time=die_result.analysis_time,
            error=die_result.error
        )

        # Add supplemental data
        supplemental_data = {
            'architecture': die_result.architecture,
            'entropy': die_result.entropy,
            'sections': die_result.sections,
            'imports': die_result.imports,
            'exports': die_result.exports,
            'strings': die_result.strings[:100],  # Limit strings for performance
            'overlay_detected': die_result.overlay_detected,
            'overlay_size': die_result.overlay_size,
            'entry_point': die_result.entry_point,
            'version_info': die_result.version_info,
            'warnings': die_result.warnings,
            'scan_mode': die_result.scan_mode
        }
        scan_result.supplemental_data = supplemental_data

        return scan_result

    async def analyze_file(self, file_path: Union[str, Path],
                          scan_mode: ScanMode = ScanMode.NORMAL,
                          timeout: int = 60,
                          include_supplemental: bool = True,
                          show_entropy: bool = True,
                          show_info: bool = True) -> ICPScanResult:
        """
        Analyze file with enhanced JSON-based DIE integration
        
        Args:
            file_path: Path to file to analyze
            scan_mode: Analysis mode
            timeout: Analysis timeout in seconds
            include_supplemental: Include supplemental analysis data
            show_entropy: Include entropy information
            show_info: Include detailed information
            
        Returns:
            ICP scan result with structured data
        """
        file_path = Path(file_path)
        cache_key = f"{file_path}:{scan_mode.value}:{timeout}"
        
        # Check cache
        if self.cache_results and cache_key in self._result_cache:
            logger.debug(f"Using cached result for {file_path}")
            self.structured_logger.log_cache_operation(
                "hit", str(file_path), cache_hit=True, cache_size=len(self._result_cache)
            )
            return self._result_cache[cache_key]

        start_time = time.time()
        
        try:
            # Convert scan mode
            die_scan_mode = self._convert_scan_mode(scan_mode)
            
            # Use structured logging session
            with log_die_analysis_session(str(file_path), scan_mode.value, timeout) as session_id:
                # Perform analysis with JSON wrapper
                logger.info(f"Starting enhanced DIE analysis: {file_path} (mode: {scan_mode.value})")
                
                # Run in executor to avoid blocking
                loop = asyncio.get_event_loop()
                die_result = await loop.run_in_executor(
                    None,
                    lambda: self.die_wrapper.analyze_file(file_path, die_scan_mode, timeout)
                )
                
                # Log analysis completion
                self.structured_logger.log_analysis_complete(session_id, die_result)
            
                # Validate result
                validation_errors = []
                is_valid = self.die_wrapper.validate_json_schema(die_result)
                if not is_valid:
                    logger.warning(f"DIE result failed schema validation for {file_path}")
                    die_result.warnings.append("Result failed schema validation")
                    validation_errors.append("Schema validation failed")
                
                # Log validation result
                self.structured_logger.log_validation_result(
                    session_id, str(file_path), is_valid, validation_errors
                )
                
                # Log detection details
                if die_result.detections:
                    self.structured_logger.log_detection_details(session_id, die_result.detections)

            # Convert to ICP format
            icp_result = self._convert_die_to_icp_result(die_result)
            
            # Add supplemental analysis if requested
            if include_supplemental and self.enable_supplemental_analysis:
                try:
                    supplemental_data = await self._run_supplemental_analysis(file_path)
                    if icp_result.supplemental_data:
                        icp_result.supplemental_data.update(supplemental_data)
                    else:
                        icp_result.supplemental_data = supplemental_data
                except Exception as e:
                    logger.warning(f"Supplemental analysis failed: {e}")
                    if icp_result.supplemental_data:
                        icp_result.supplemental_data['supplemental_error'] = str(e)

            # Update analysis time
            icp_result.analysis_time = time.time() - start_time
            
            # Cache result
            if self.cache_results:
                self._result_cache[cache_key] = icp_result
                self.structured_logger.log_cache_operation(
                    "store", str(file_path), cache_hit=False, cache_size=len(self._result_cache)
                )

            logger.info(f"Enhanced DIE analysis completed: {file_path} "
                       f"({len(die_result.detections)} detections, "
                       f"{icp_result.analysis_time:.2f}s)")

            return icp_result
            
        except Exception as e:
            logger.error(f"Enhanced ICP analysis failed for {file_path}: {e}")
            
            # Create error result
            error_result = ICPScanResult(
                file_path=str(file_path),
                file_infos=[ICPFileInfo(
                    filetype="Unknown",
                    size=str(file_path.stat().st_size if file_path.exists() else 0)
                )],
                analysis_time=time.time() - start_time,
                error=str(e)
            )
            
            return error_result

    async def _run_supplemental_analysis(self, file_path: Path) -> Dict[str, Any]:
        """Run supplemental analysis engines for additional data"""
        supplemental_data = {}
        
        try:
            # Import supplemental engines
            from ..core.analysis.firmware_analyzer import get_firmware_analyzer, is_binwalk_available
            from ..core.analysis.yara_pattern_engine import get_yara_engine, is_yara_available
            
            # Firmware analysis
            if is_binwalk_available():
                try:
                    firmware_analyzer = get_firmware_analyzer()
                    firmware_result = await firmware_analyzer.analyze_file(str(file_path))
                    supplemental_data['firmware_analysis'] = firmware_result
                except Exception as e:
                    logger.debug(f"Firmware analysis failed: {e}")

            # YARA pattern matching
            if is_yara_available():
                try:
                    yara_engine = get_yara_engine()
                    yara_result = await yara_engine.scan_file(str(file_path))
                    supplemental_data['yara_matches'] = yara_result
                except Exception as e:
                    logger.debug(f"YARA analysis failed: {e}")

            # Add basic file metadata
            try:
                stat = file_path.stat()
                supplemental_data['file_metadata'] = {
                    'size': stat.st_size,
                    'created': stat.st_ctime,
                    'modified': stat.st_mtime,
                    'accessed': stat.st_atime
                }
            except Exception as e:
                logger.debug(f"File metadata extraction failed: {e}")

        except ImportError:
            logger.debug("Supplemental analysis engines not available")

        return supplemental_data

    def analyze_file_sync(self, file_path: Union[str, Path],
                         scan_mode: ScanMode = ScanMode.NORMAL,
                         timeout: int = 60) -> ICPScanResult:
        """
        Synchronous wrapper for file analysis
        
        Args:
            file_path: Path to file to analyze
            scan_mode: Analysis mode
            timeout: Analysis timeout in seconds
            
        Returns:
            ICP scan result
        """
        try:
            # Get or create event loop
            loop = asyncio.get_event_loop()
        except RuntimeError:
            # Create new event loop if none exists
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        try:
            return loop.run_until_complete(
                self.analyze_file(file_path, scan_mode, timeout)
            )
        except Exception as e:
            logger.error(f"Synchronous analysis failed: {e}")
            return ICPScanResult(
                file_path=str(file_path),
                error=str(e)
            )

    def clear_cache(self):
        """Clear the result cache"""
        self._result_cache.clear()
        logger.info("Result cache cleared")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            'cached_results': len(self._result_cache),
            'cache_enabled': self.cache_results
        }

    def get_version_info(self) -> Dict[str, Any]:
        """Get version information for all components"""
        info = {
            'enhanced_icp_backend': '1.0.0',
            'json_based_parsing': True,
            'supplemental_analysis': self.enable_supplemental_analysis,
            'caching_enabled': self.cache_results
        }
        
        # Add DIE wrapper version info
        die_info = self.die_wrapper.get_version_info()
        info.update(die_info)
        
        return info

    def validate_installation(self) -> Dict[str, bool]:
        """Validate that all required components are available"""
        validation = {
            'die_python_available': self.die_wrapper.die_python is not None,
            'die_executable_available': self.die_wrapper.die_executable_path is not None,
            'can_analyze': False
        }
        
        # Check if we can analyze files
        validation['can_analyze'] = (
            validation['die_python_available'] or 
            validation['die_executable_available']
        )
        
        return validation


class BackwardCompatibilityWrapper:
    """
    Wrapper to maintain backward compatibility with existing ICP backend interface
    """

    def __init__(self, engine_path: Optional[str] = None):
        """Initialize with backward compatibility"""
        self.enhanced_backend = EnhancedICPBackend(
            die_executable_path=engine_path,
            enable_supplemental_analysis=True,
            cache_results=True
        )

    async def analyze_file(self, file_path: Union[str, Path],
                          scan_mode: ScanMode = ScanMode.NORMAL,
                          timeout: int = 60,
                          include_supplemental: bool = True,
                          show_entropy: bool = True,
                          show_info: bool = True) -> ICPScanResult:
        """Maintain original async interface"""
        return await self.enhanced_backend.analyze_file(
            file_path, scan_mode, timeout, include_supplemental, show_entropy, show_info
        )

    def get_detailed_analysis(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Get detailed analysis in original format"""
        result = self.enhanced_backend.analyze_file_sync(file_path, ScanMode.ALL)
        
        # Convert to detailed analysis format
        detailed = {
            'file_path': result.file_path,
            'analysis_time': result.analysis_time,
            'error': result.error,
            'detections': []
        }
        
        if result.file_infos:
            file_info = result.file_infos[0]
            detailed['file_type'] = file_info.filetype
            detailed['file_size'] = file_info.size
            
            for detection in file_info.detections:
                detailed['detections'].append({
                    'name': detection.name,
                    'type': detection.type,
                    'version': detection.version,
                    'confidence': detection.confidence
                })

        # Add supplemental data
        if result.supplemental_data:
            detailed.update(result.supplemental_data)

        return detailed


# Factory function for creating backend instances
def create_enhanced_icp_backend(die_executable_path: Optional[str] = None,
                               compatibility_mode: bool = False) -> Union[EnhancedICPBackend, BackwardCompatibilityWrapper]:
    """
    Create enhanced ICP backend instance
    
    Args:
        die_executable_path: Path to DIE executable (optional)
        compatibility_mode: Return backward compatibility wrapper
        
    Returns:
        Enhanced ICP backend or compatibility wrapper
    """
    if compatibility_mode:
        return BackwardCompatibilityWrapper(die_executable_path)
    else:
        return EnhancedICPBackend(die_executable_path)


# Global backend instance for singleton access
_global_backend: Optional[EnhancedICPBackend] = None

def get_icp_backend(die_executable_path: Optional[str] = None) -> EnhancedICPBackend:
    """Get or create global ICP backend instance"""
    global _global_backend
    
    if _global_backend is None:
        _global_backend = EnhancedICPBackend(die_executable_path)
        logger.info("Created global enhanced ICP backend instance")
    
    return _global_backend


# Example usage and testing
if __name__ == "__main__":
    import sys
    import asyncio
    
    async def test_analysis(file_path: str):
        """Test the enhanced backend"""
        backend = create_enhanced_icp_backend()
        
        print(f"=== Enhanced ICP Backend Test ===")
        print(f"Analyzing: {file_path}")
        
        # Validation check
        validation = backend.validate_installation()
        print(f"Validation: {validation}")
        
        if not validation['can_analyze']:
            print("Cannot analyze - DIE not available")
            return
        
        # Perform analysis
        result = await backend.analyze_file(file_path, ScanMode.DEEP)
        
        if result.error:
            print(f"Error: {result.error}")
        else:
            print(f"Analysis completed in {result.analysis_time:.2f}s")
            
            if result.file_infos:
                file_info = result.file_infos[0]
                print(f"File Type: {file_info.filetype}")
                print(f"File Size: {file_info.size}")
                print(f"Detections: {len(file_info.detections)}")
                
                for detection in file_info.detections:
                    print(f"  - {detection.type}: {detection.name}")
                    if detection.version:
                        print(f"    Version: {detection.version}")
                    print(f"    Confidence: {detection.confidence:.2f}")

            if result.supplemental_data:
                print(f"Supplemental data keys: {list(result.supplemental_data.keys())}")

    if len(sys.argv) > 1:
        asyncio.run(test_analysis(sys.argv[1]))
    else:
        print("Usage: python icp_backend_enhanced.py <binary_file>")