"""
DIE (Detect It Easy) JSON Wrapper

Provides robust JSON-based output from DIE analysis, replacing fragile string parsing
with structured data handling. Supports both die-python library and external DIE executable.

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
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class DIEScanMode(Enum):
    """DIE scan modes with JSON output support"""
    NORMAL = "normal"
    DEEP = "deep" 
    HEURISTIC = "heuristic"
    RECURSIVE = "recursive"
    ALL = "all"


@dataclass
class DIEDetection:
    """Structured DIE detection result"""
    name: str
    type: str
    version: str = ""
    info: str = ""
    confidence: float = 1.0
    offset: int = 0
    size: int = 0
    entropy: float = 0.0
    additional_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'name': self.name,
            'type': self.type,
            'version': self.version,
            'info': self.info,
            'confidence': self.confidence,
            'offset': self.offset,
            'size': self.size,
            'entropy': self.entropy,
            'additional_info': self.additional_info
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DIEDetection':
        """Create from dictionary"""
        return cls(
            name=data.get('name', ''),
            type=data.get('type', ''),
            version=data.get('version', ''),
            info=data.get('info', ''),
            confidence=data.get('confidence', 1.0),
            offset=data.get('offset', 0),
            size=data.get('size', 0),
            entropy=data.get('entropy', 0.0),
            additional_info=data.get('additional_info', {})
        )


@dataclass
class DIEAnalysisResult:
    """Complete DIE analysis result in JSON format"""
    file_path: str
    file_type: str
    architecture: str
    file_size: int
    detections: List[DIEDetection] = field(default_factory=list)
    entropy: float = 0.0
    sections: List[Dict[str, Any]] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    overlay_detected: bool = False
    overlay_size: int = 0
    entry_point: int = 0
    analysis_time: float = 0.0
    scan_mode: str = "normal"
    version_info: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    def to_json(self) -> str:
        """Convert to JSON string"""
        data = {
            'file_path': self.file_path,
            'file_type': self.file_type,
            'architecture': self.architecture,
            'file_size': self.file_size,
            'detections': [d.to_dict() for d in self.detections],
            'entropy': self.entropy,
            'sections': self.sections,
            'imports': self.imports,
            'exports': self.exports,
            'strings': self.strings,
            'overlay_detected': self.overlay_detected,
            'overlay_size': self.overlay_size,
            'entry_point': self.entry_point,
            'analysis_time': self.analysis_time,
            'scan_mode': self.scan_mode,
            'version_info': self.version_info,
            'error': self.error,
            'warnings': self.warnings
        }
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> 'DIEAnalysisResult':
        """Create from JSON string"""
        try:
            data = json.loads(json_str)
            
            # Parse detections
            detections = []
            for det_data in data.get('detections', []):
                detections.append(DIEDetection.from_dict(det_data))

            return cls(
                file_path=data.get('file_path', ''),
                file_type=data.get('file_type', ''),
                architecture=data.get('architecture', ''),
                file_size=data.get('file_size', 0),
                detections=detections,
                entropy=data.get('entropy', 0.0),
                sections=data.get('sections', []),
                imports=data.get('imports', []),
                exports=data.get('exports', []),
                strings=data.get('strings', []),
                overlay_detected=data.get('overlay_detected', False),
                overlay_size=data.get('overlay_size', 0),
                entry_point=data.get('entry_point', 0),
                analysis_time=data.get('analysis_time', 0.0),
                scan_mode=data.get('scan_mode', 'normal'),
                version_info=data.get('version_info', {}),
                error=data.get('error'),
                warnings=data.get('warnings', [])
            )
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse DIE JSON result: {e}")
            raise ValueError(f"Invalid DIE JSON format: {e}")


class DIEJSONWrapper:
    """
    Robust DIE wrapper with JSON output support
    
    Provides structured analysis results with proper error handling,
    validation, and fallback mechanisms.
    """

    def __init__(self, die_executable_path: Optional[str] = None, 
                 use_die_python: bool = True):
        """
        Initialize DIE JSON wrapper
        
        Args:
            die_executable_path: Path to DIE executable (optional)
            use_die_python: Whether to use die-python library if available
        """
        self.die_executable_path = die_executable_path
        self.use_die_python = use_die_python
        self.die_python = None
        
        # Try to import die-python if requested
        if use_die_python:
            try:
                import die
                self.die_python = die
                logger.info(f"DIE JSON Wrapper initialized with die-python v{die.__version__}")
            except ImportError:
                logger.warning("die-python not available, will use external executable if available")
        
        # Find DIE executable if not provided
        if not self.die_executable_path:
            self.die_executable_path = self._find_die_executable()

    def _find_die_executable(self) -> Optional[str]:
        """Find DIE executable in system PATH or common locations"""
        executables = ['diec', 'die', 'diec.exe', 'die.exe']
        
        # Check PATH first
        for exe in executables:
            try:
                result = subprocess.run(['where' if os.name == 'nt' else 'which', exe],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    path = result.stdout.strip().split('\n')[0]
                    if os.path.exists(path):
                        logger.info(f"Found DIE executable: {path}")
                        return path
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                continue
        
        # Check common installation paths
        common_paths = []
        if os.name == 'nt':
            common_paths = [
                r'C:\Program Files\DIE\diec.exe',
                r'C:\DIE\diec.exe',
                r'C:\Tools\DIE\diec.exe',
                os.path.expanduser(r'~\DIE\diec.exe')
            ]
        else:
            common_paths = [
                '/usr/bin/diec',
                '/usr/local/bin/diec',
                '/opt/die/diec',
                os.path.expanduser('~/die/diec')
            ]
        
        for path in common_paths:
            if os.path.exists(path):
                logger.info(f"Found DIE executable: {path}")
                return path
        
        logger.warning("DIE executable not found")
        return None

    def analyze_file(self, file_path: Union[str, Path], 
                    scan_mode: DIEScanMode = DIEScanMode.NORMAL,
                    timeout: int = 60) -> DIEAnalysisResult:
        """
        Analyze file with structured JSON output
        
        Args:
            file_path: Path to file to analyze
            scan_mode: Analysis mode
            timeout: Analysis timeout in seconds
            
        Returns:
            Structured DIE analysis result
        """
        start_time = time.time()
        file_path = Path(file_path)
        
        if not file_path.exists():
            return DIEAnalysisResult(
                file_path=str(file_path),
                file_type="Unknown",
                architecture="Unknown",
                file_size=0,
                error=f"File not found: {file_path}"
            )

        # Try die-python first if available
        if self.die_python:
            try:
                result = self._analyze_with_die_python(file_path, scan_mode, timeout)
                result.analysis_time = time.time() - start_time
                return result
            except Exception as e:
                logger.warning(f"die-python analysis failed: {e}, trying external executable")

        # Fallback to external executable
        if self.die_executable_path:
            try:
                result = self._analyze_with_executable(file_path, scan_mode, timeout)
                result.analysis_time = time.time() - start_time
                return result
            except Exception as e:
                logger.error(f"External DIE analysis failed: {e}")

        # Return error result
        return DIEAnalysisResult(
            file_path=str(file_path),
            file_type="Unknown", 
            architecture="Unknown",
            file_size=file_path.stat().st_size,
            error="No DIE analysis method available",
            analysis_time=time.time() - start_time
        )

    def _analyze_with_die_python(self, file_path: Path, scan_mode: DIEScanMode, 
                                timeout: int) -> DIEAnalysisResult:
        """Analyze using die-python library with structured output"""
        if not self.die_python:
            raise RuntimeError("die-python not available")

        # Map scan mode to flags
        scan_flags = self._get_die_python_flags(scan_mode)
        
        try:
            # Get basic file info
            file_size = file_path.stat().st_size
            
            # Perform scan
            scan_text = self.die_python.scan_file(str(file_path), scan_flags)
            
            # Convert text output to structured format
            result = self._parse_die_text_to_json(str(file_path), scan_text, file_size)
            result.scan_mode = scan_mode.value
            
            # Add additional analysis if available
            try:
                result = self._enhance_with_die_python_details(result, file_path)
            except Exception as e:
                result.warnings.append(f"Failed to get enhanced details: {e}")
            
            return result
            
        except Exception as e:
            logger.error(f"die-python scan failed: {e}")
            raise

    def _analyze_with_executable(self, file_path: Path, scan_mode: DIEScanMode,
                                timeout: int) -> DIEAnalysisResult:
        """Analyze using external DIE executable with JSON output"""
        if not self.die_executable_path:
            raise RuntimeError("DIE executable not available")

        # Build command with JSON output
        cmd = [
            self.die_executable_path,
            '--json',  # Request JSON output
            str(file_path)
        ]
        
        # Add scan mode flags
        if scan_mode == DIEScanMode.DEEP:
            cmd.append('--deep')
        elif scan_mode == DIEScanMode.HEURISTIC:
            cmd.append('--heuristic')
        elif scan_mode == DIEScanMode.RECURSIVE:
            cmd.append('--recursive')
        elif scan_mode == DIEScanMode.ALL:
            cmd.extend(['--deep', '--heuristic', '--recursive'])

        try:
            # Run DIE with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else "DIE analysis failed"
                logger.error(f"DIE executable failed: {error_msg}")
                raise RuntimeError(error_msg)

            # Parse JSON output
            if result.stdout.strip():
                try:
                    json_data = json.loads(result.stdout)
                    return self._parse_die_json_output(json_data, str(file_path))
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse DIE JSON output: {e}")
                    # Fallback to text parsing
                    return self._parse_die_text_to_json(str(file_path), result.stdout, 
                                                      file_path.stat().st_size)
            else:
                # No output, create basic result
                return DIEAnalysisResult(
                    file_path=str(file_path),
                    file_type="Binary",
                    architecture="Unknown",
                    file_size=file_path.stat().st_size,
                    scan_mode=scan_mode.value
                )
                
        except subprocess.TimeoutExpired:
            logger.error(f"DIE analysis timed out after {timeout} seconds")
            raise RuntimeError(f"Analysis timed out after {timeout} seconds")
        except Exception as e:
            logger.error(f"DIE executable error: {e}")
            raise

    def _get_die_python_flags(self, scan_mode: DIEScanMode) -> int:
        """Convert scan mode to die-python flags"""
        if not self.die_python:
            return 0
        
        flag_map = {
            DIEScanMode.NORMAL: 0,
            DIEScanMode.DEEP: getattr(self.die_python.ScanFlags, 'DEEP_SCAN', 0x0001),
            DIEScanMode.HEURISTIC: getattr(self.die_python.ScanFlags, 'HEURISTIC_SCAN', 0x0002),
            DIEScanMode.RECURSIVE: getattr(self.die_python.ScanFlags, 'RECURSIVE_SCAN', 0x0004),
            DIEScanMode.ALL: 0x0007  # All flags combined
        }
        
        return flag_map.get(scan_mode, 0)

    def _parse_die_text_to_json(self, file_path: str, die_text: str, 
                               file_size: int) -> DIEAnalysisResult:
        """Convert DIE text output to structured JSON format"""
        result = DIEAnalysisResult(
            file_path=file_path,
            file_type="Binary",
            architecture="Unknown", 
            file_size=file_size
        )

        if not die_text or not die_text.strip():
            return result

        lines = die_text.strip().split('\n')
        if not lines:
            return result

        # First line is typically the file type
        if lines:
            first_line = lines[0].strip()
            if first_line and not first_line.startswith(' '):
                result.file_type = first_line
                
                # Extract architecture from file type
                if 'PE32+' in first_line or 'PE64' in first_line:
                    result.architecture = "x64"
                elif 'PE32' in first_line:
                    result.architecture = "x86"
                elif 'ELF64' in first_line:
                    result.architecture = "x64"
                elif 'ELF32' in first_line:
                    result.architecture = "x86"

        # Parse detection lines (typically indented)
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue

            # Parse "Type: Name" format
            if ':' in line:
                try:
                    type_part, name_part = line.split(':', 1)
                    detection_type = type_part.strip()
                    detection_name = name_part.strip()

                    # Extract version if present
                    version = ""
                    if '(' in detection_name and ')' in detection_name:
                        # Try to extract version from parentheses
                        start = detection_name.find('(')
                        end = detection_name.find(')', start)
                        if start != -1 and end != -1:
                            version = detection_name[start+1:end]
                            detection_name = detection_name[:start].strip()

                    detection = DIEDetection(
                        name=detection_name,
                        type=detection_type,
                        version=version,
                        info=line,
                        confidence=1.0
                    )
                    result.detections.append(detection)
                    
                except ValueError:
                    # Fallback for lines that don't split properly
                    detection = DIEDetection(
                        name=line,
                        type="Unknown",
                        info=line,
                        confidence=0.8
                    )
                    result.detections.append(detection)

        return result

    def _parse_die_json_output(self, json_data: Dict[str, Any], 
                              file_path: str) -> DIEAnalysisResult:
        """Parse native DIE JSON output format"""
        result = DIEAnalysisResult(
            file_path=file_path,
            file_type=json_data.get('filetype', 'Binary'),
            architecture=json_data.get('arch', 'Unknown'),
            file_size=json_data.get('size', 0),
            entropy=json_data.get('entropy', 0.0),
            entry_point=json_data.get('entrypoint', 0),
            overlay_detected=json_data.get('overlay', {}).get('detected', False),
            overlay_size=json_data.get('overlay', {}).get('size', 0)
        )

        # Parse detections
        for detection_data in json_data.get('detections', []):
            detection = DIEDetection(
                name=detection_data.get('name', ''),
                type=detection_data.get('type', ''),
                version=detection_data.get('version', ''),
                info=detection_data.get('info', ''),
                confidence=detection_data.get('confidence', 1.0),
                offset=detection_data.get('offset', 0),
                size=detection_data.get('size', 0),
                entropy=detection_data.get('entropy', 0.0),
                additional_info=detection_data.get('additional', {})
            )
            result.detections.append(detection)

        # Add sections, imports, exports if present
        result.sections = json_data.get('sections', [])
        result.imports = json_data.get('imports', [])
        result.exports = json_data.get('exports', [])
        result.strings = json_data.get('strings', [])
        result.version_info = json_data.get('version_info', {})

        return result

    def _enhance_with_die_python_details(self, result: DIEAnalysisResult, 
                                       file_path: Path) -> DIEAnalysisResult:
        """Add additional details using die-python specific functions"""
        if not self.die_python:
            return result

        try:
            # Try to get additional file information
            file_str = str(file_path)
            
            # Get entropy if available
            if hasattr(self.die_python, 'get_entropy'):
                try:
                    result.entropy = self.die_python.get_entropy(file_str)
                except Exception as e:
                    result.warnings.append(f"Failed to get entropy: {e}")

            # Get overlay information
            if hasattr(self.die_python, 'get_overlay_info'):
                try:
                    overlay_info = self.die_python.get_overlay_info(file_str)
                    if overlay_info:
                        result.overlay_detected = True
                        result.overlay_size = overlay_info.get('size', 0)
                except Exception as e:
                    result.warnings.append(f"Failed to get overlay info: {e}")

        except Exception as e:
            result.warnings.append(f"Failed to enhance with die-python details: {e}")

        return result

    def validate_json_schema(self, result: DIEAnalysisResult) -> bool:
        """Validate DIE analysis result against expected schema"""
        try:
            # Basic validation
            if not result.file_path:
                return False
            if not result.file_type:
                return False
            if result.file_size < 0:
                return False
            
            # Validate detections
            for detection in result.detections:
                if not detection.name:
                    return False
                if detection.confidence < 0 or detection.confidence > 1:
                    return False

            return True
        except Exception as e:
            logger.error(f"JSON schema validation failed: {e}")
            return False

    def get_version_info(self) -> Dict[str, str]:
        """Get version information for DIE components"""
        info = {}
        
        if self.die_python:
            try:
                info['die_python'] = self.die_python.__version__
                info['die_engine'] = getattr(self.die_python, 'die_version', 'unknown')
            except Exception as e:
                info['die_python_error'] = str(e)

        if self.die_executable_path:
            try:
                result = subprocess.run(
                    [self.die_executable_path, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    info['die_executable'] = result.stdout.strip()
            except Exception as e:
                info['die_executable_error'] = str(e)

        return info


def create_die_wrapper() -> DIEJSONWrapper:
    """Create DIE JSON wrapper with best available configuration"""
    return DIEJSONWrapper(use_die_python=True)


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        wrapper = create_die_wrapper()
        result = wrapper.analyze_file(sys.argv[1])
        
        print("=== DIE JSON Analysis ===")
        print(result.to_json())
        
        if result.error:
            print(f"Error: {result.error}")
        else:
            print(f"File Type: {result.file_type}")
            print(f"Architecture: {result.architecture}")
            print(f"Detections: {len(result.detections)}")
            
            for detection in result.detections:
                print(f"  - {detection.type}: {detection.name}")
                if detection.version:
                    print(f"    Version: {detection.version}")
                print(f"    Confidence: {detection.confidence:.2f}")
    else:
        print("Usage: python die_json_wrapper.py <binary_file>")