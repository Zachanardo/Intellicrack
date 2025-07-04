"""
Intellicrack Protection Core Module

This module provides comprehensive protection detection capabilities for
detecting packers, protectors, compilers, and licensing schemes in binary files.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ProtectionType(Enum):
    """Types of protections that can be detected"""
    PACKER = "packer"
    PROTECTOR = "protector"
    COMPILER = "compiler"
    INSTALLER = "installer"
    LIBRARY = "library"
    OVERLAY = "overlay"
    CRYPTOR = "cryptor"
    DONGLE = "dongle"
    LICENSE = "license"
    DRM = "drm"
    UNKNOWN = "unknown"


@dataclass
class DetectionResult:
    """Result of a single detection"""
    name: str
    version: Optional[str] = None
    type: ProtectionType = ProtectionType.UNKNOWN
    confidence: float = 100.0
    details: Dict[str, any] = field(default_factory=dict)
    bypass_recommendations: List[str] = field(default_factory=list)


@dataclass
class ProtectionAnalysis:
    """Complete analysis results for a binary"""
    file_path: str
    file_type: str
    architecture: str
    detections: List[DetectionResult] = field(default_factory=list)
    compiler: Optional[str] = None
    linker: Optional[str] = None
    is_packed: bool = False
    is_protected: bool = False
    has_overlay: bool = False
    has_resources: bool = False
    entry_point: Optional[str] = None
    sections: List[Dict[str, any]] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    metadata: Dict[str, any] = field(default_factory=dict)


class IntellicrackProtectionCore:
    """
    Main class for detecting protections using Intellicrack's protection analysis engine
    """

    # Known protection schemes and their bypass recommendations
    PROTECTION_BYPASSES = {
        # Packers
        "UPX": [
            "Use 'upx -d' to unpack",
            "Manual unpacking: Find OEP, dump process, fix imports",
            "Use x64dbg with Scylla for import reconstruction"
        ],
        "ASPack": [
            "Use ASPack unpacker tools",
            "Set breakpoint on GetProcAddress",
            "Dump at OEP and fix imports"
        ],
        "PECompact": [
            "Use PECompact unpacker",
            "Breakpoint on VirtualProtect calls",
            "Dump when code is decompressed"
        ],

        # Protectors
        "Themida": [
            "Use Themida unpacker scripts",
            "Requires kernel driver bypass",
            "Consider VM-based analysis",
            "Look for Themida-specific API hooks"
        ],
        "VMProtect": [
            "Extremely difficult to unpack",
            "Use VMProtect devirtualizer tools",
            "Consider dynamic analysis instead",
            "Focus on API monitoring"
        ],
        "Enigma": [
            "Use Enigma Virtual Box unpacker",
            "Monitor file system virtualization",
            "Extract embedded files from process"
        ],
        "ASProtect": [
            "Use ASProtect unpacker",
            "Set hardware breakpoints",
            "Dump after decompression routine"
        ],

        # Licensing Systems
        "HASP": [
            "Monitor HASP API calls",
            "Use HASP emulator/logger",
            "Patch license check functions",
            "Analyze hasp_login parameters"
        ],
        "Sentinel": [
            "Use Sentinel emulator",
            "Monitor WinTrust API calls",
            "Patch SuperPro driver checks",
            "Analyze license file format"
        ],
        "CodeMeter": [
            "Monitor CodeMeter API",
            "Use WibuKey emulator",
            "Patch CmAccess calls",
            "Analyze license container"
        ],
        "FlexLM": [
            "Monitor lmgrd daemon",
            "Patch lc_checkout calls",
            "Analyze license.dat format",
            "Use FlexLM emulator"
        ],
        "CrypKey": [
            "Patch CrypKey API calls",
            "Monitor registry access",
            "Analyze license validation",
            "Use CrypKey tools"
        ],

        # DRM Systems
        "Denuvo": [
            "Extremely difficult protection",
            "Requires extensive RE skills",
            "Focus on trigger analysis",
            "Consider waiting for scene crack"
        ],
        "SecuROM": [
            "Use SecuROM removal tools",
            "Patch driver checks",
            "Monitor CD/DVD checks",
            "Analyze activation routines"
        ],
        "SafeDisc": [
            "Use SafeDisc unwrapper",
            "Patch ICD checks",
            "Fix import table",
            "Remove driver dependencies"
        ]
    }

    def __init__(self, engine_path: Optional[str] = None):
        """
        Initialize protection detector

        Args:
            engine_path: Path to protection engine executable. If None, will search common locations.
        """
        self.engine_path = self._find_engine_executable(engine_path)
        self._validate_engine_installation()

    def _find_engine_executable(self, custom_path: Optional[str] = None) -> str:
        """Find protection engine executable in various locations"""
        if custom_path and os.path.exists(custom_path):
            return custom_path

        # Search paths in order of preference
        search_paths = [
            # Actual location in project
            Path(__file__).parent.parent.parent / "tools" / "icp_engine" / "icp-engine.exe",

            # Relative to this module
            Path(__file__).parent.parent / "tools" / "icp_engine" / "icp-engine.exe",
            Path(__file__).parent.parent / "tools" / "icp_engine" / "console" / "icp-engine.exe",

            # In system PATH
            "icp-engine.exe",
            "icp-engine",

            # Common installation locations
            Path("C:/Program Files/Intellicrack/icp-engine.exe"),
            Path("C:/Program Files (x86)/Intellicrack/icp-engine.exe"),
            Path("C:/Tools/icp_engine/icp-engine.exe"),

            # Portable installations
            Path.home() / "Tools" / "icp_engine" / "icp-engine.exe",
            Path.home() / "Downloads" / "icp_engine" / "icp-engine.exe",
        ]

        for path in search_paths:
            path_str = str(path)
            if os.path.exists(path_str):
                logger.info(f"Found protection engine at: {path_str}")
                return path_str

            # Try with shutil.which for PATH entries
            import shutil
            which_result = shutil.which(path_str)
            if which_result:
                logger.info(f"Found protection engine in PATH: {which_result}")
                return which_result

        # If not found, return expected location for user to install
        expected_path = Path(__file__).parent.parent.parent / "tools" / "icp_engine" / "icp-engine.exe"
        logger.warning(f"Protection engine not found. Please install to: {expected_path}")
        return str(expected_path)

    def _validate_engine_installation(self):
        """Validate that protection engine is properly installed and working"""
        if not os.path.exists(self.engine_path):
            logger.error(f"Protection engine executable not found at: {self.engine_path}")
            logger.info("Please ensure Intellicrack protection engine is properly installed")
            logger.info(f"Expected location: {os.path.dirname(self.engine_path)}")
            return

        try:
            # Test DIE execution
            result = subprocess.run([self.engine_path, "--version"],
                                    capture_output=True,
                                    text=True,
                                    timeout=5)
            if result.returncode == 0:
                logger.info(f"DIE version: {result.stdout.strip()}")
            else:
                logger.warning("DIE executable found but may not be working properly")
        except Exception as e:
            logger.error(f"Error validating DIE: {e}")

    def detect_protections(self, file_path: str) -> ProtectionAnalysis:
        """
        Analyze a binary file for protections, packers, and licensing schemes

        Args:
            file_path: Path to the binary file to analyze

        Returns:
            ProtectionAnalysis object with all detection results
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if not os.path.exists(self.engine_path):
            logger.error("DIE not installed. Cannot perform analysis.")
            return ProtectionAnalysis(
                file_path=file_path,
                file_type="Unknown",
                architecture="Unknown"
            )

        try:
            # Convert WSL path to Windows path if needed
            if file_path.startswith('/mnt/'):
                # Convert /mnt/c/path to C:\path
                windows_path = file_path.replace('/mnt/', '')
                drive_letter = windows_path[0].upper()
                windows_path = drive_letter + ':' + windows_path[1:].replace('/', '\\')
                logger.debug(f"Converted WSL path {file_path} to Windows path {windows_path}")
                analysis_path = windows_path
            else:
                analysis_path = file_path

            # Run DIE with JSON output for easy parsing
            cmd = [self.engine_path, "-j", analysis_path]
            result = subprocess.run(cmd,
                                    capture_output=True,
                                    text=True,
                                    timeout=30)

            if result.returncode != 0:
                logger.error(f"DIE execution failed with code {result.returncode}")
                logger.error(f"STDERR: {result.stderr}")
                logger.error(f"STDOUT: {result.stdout}")
                return ProtectionAnalysis(
                    file_path=file_path,
                    file_type="Error",
                    architecture="Unknown"
                )

            # Parse JSON output
            try:
                # Skip any warning lines before JSON
                output = result.stdout
                json_start = output.find('{')
                if json_start > 0:
                    output = output[json_start:]
                    logger.debug(f"Skipped {json_start} chars before JSON")

                logger.debug(f"Protection engine output: {output[:500]}...")  # Log first 500 chars
                engine_data = json.loads(output)
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {e}")
                logger.error(f"Raw output: {result.stdout}")
                # Fallback to text parsing if JSON fails
                return self._parse_text_output(file_path, result.stdout)

            # Extract analysis results
            return self._parse_json_output(file_path, engine_data)

        except subprocess.TimeoutExpired:
            logger.error(f"DIE analysis timed out for: {file_path}")
            return ProtectionAnalysis(
                file_path=file_path,
                file_type="Timeout",
                architecture="Unknown"
            )
        except Exception as e:
            logger.error(f"Error analyzing file: {e}")
            return ProtectionAnalysis(
                file_path=file_path,
                file_type="Error",
                architecture="Unknown"
            )

    def _parse_json_output(self, file_path: str, engine_data: Dict) -> ProtectionAnalysis:
        """Parse DIE JSON output into structured results"""
        analysis = ProtectionAnalysis(file_path=file_path, file_type="Unknown", architecture="Unknown")

        # Extract detections from the new format
        detects = engine_data.get("detects", [])
        if detects:
            # Take the first detection (usually the main file)
            main_detect = detects[0]

            # Extract file type
            filetype = main_detect.get("filetype", "Unknown")
            analysis.file_type = filetype

            # Extract architecture from file type
            if "PE64" in filetype or "64" in filetype:
                analysis.architecture = "x64"
            elif "PE32" in filetype or "32" in filetype:
                analysis.architecture = "x86"
            elif "ELF64" in filetype:
                analysis.architecture = "x64"
            elif "ELF32" in filetype:
                analysis.architecture = "x86"

            # Process all values (detections)
            values = main_detect.get("values", [])
            for value in values:
                det_type = self._categorize_detection(value.get("type", ""))
                name = value.get("name", "Unknown")
                version = value.get("version", "")

                # Extract architecture from compiler info if available
                if det_type == ProtectionType.COMPILER and "info" in value:
                    info = value.get("info", "")
                    if "x64" in info or "64" in name:
                        analysis.architecture = "x64"
                    elif "x86" in info or "32" in name:
                        analysis.architecture = "x86"

                # Set compiler info
                if det_type == ProtectionType.COMPILER and not analysis.compiler:
                    analysis.compiler = f"{name} {version}" if version else name

                # Create detection result
                det_result = DetectionResult(
                    name=name,
                    version=version if version else None,
                    type=det_type,
                    confidence=100.0  # DIE detections are signature-based, so high confidence
                )

                # Add bypass recommendations
                det_result.bypass_recommendations = self._get_bypass_recommendations(name)

                # Add to appropriate flags
                if det_type == ProtectionType.PACKER:
                    analysis.is_packed = True
                elif det_type in [ProtectionType.PROTECTOR, ProtectionType.CRYPTOR]:
                    analysis.is_protected = True
                elif det_type in [ProtectionType.LICENSE, ProtectionType.DONGLE, ProtectionType.DRM]:
                    analysis.is_protected = True

                analysis.detections.append(det_result)

        # Extract compiler info
        if "compiler" in engine_data:
            analysis.compiler = engine_data["compiler"]

        # Extract additional info
        if "overlay" in engine_data:
            analysis.has_overlay = engine_data["overlay"].get("present", False)

        if "sections" in engine_data:
            analysis.sections = engine_data["sections"]

        if "imports" in engine_data:
            analysis.imports = [imp.get("name", "") for imp in engine_data["imports"]]

        # Add metadata
        analysis.metadata = {
            "engine_version": engine_data.get("version", "Unknown"),
            "scan_time": engine_data.get("scantime", "Unknown"),
            "file_size": engine_data.get("filesize", 0)
        }

        return analysis

    def _parse_text_output(self, file_path: str, output: str) -> ProtectionAnalysis:
        """Fallback parser for text output if JSON parsing fails"""
        analysis = ProtectionAnalysis(file_path=file_path, file_type="PE", architecture="Unknown")

        lines = output.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Parse detection lines (format: "Type: Name(Version)")
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    det_type = parts[0].strip()
                    det_info = parts[1].strip()

                    # Extract name and version
                    if '(' in det_info and ')' in det_info:
                        name = det_info[:det_info.index('(')].strip()
                        version = det_info[det_info.index('(')+1:det_info.index(')')].strip()
                    else:
                        name = det_info
                        version = None

                    # Create detection
                    detection = DetectionResult(
                        name=name,
                        version=version,
                        type=self._categorize_detection(det_type)
                    )
                    detection.bypass_recommendations = self._get_bypass_recommendations(name)

                    analysis.detections.append(detection)

                    # Set flags
                    if detection.type == ProtectionType.PACKER:
                        analysis.is_packed = True
                    elif detection.type in [ProtectionType.PROTECTOR, ProtectionType.CRYPTOR]:
                        analysis.is_protected = True

        return analysis

    def _categorize_detection(self, detection_type: str) -> ProtectionType:
        """Categorize detection type string into enum"""
        type_lower = detection_type.lower()

        if "pack" in type_lower:
            return ProtectionType.PACKER
        elif "protect" in type_lower:
            return ProtectionType.PROTECTOR
        elif "compil" in type_lower:
            return ProtectionType.COMPILER
        elif "install" in type_lower:
            return ProtectionType.INSTALLER
        elif "crypt" in type_lower:
            return ProtectionType.CRYPTOR
        elif "dongle" in type_lower or "hasp" in type_lower or "sentinel" in type_lower:
            return ProtectionType.DONGLE
        elif "licens" in type_lower or "flexlm" in type_lower:
            return ProtectionType.LICENSE
        elif "drm" in type_lower:
            return ProtectionType.DRM
        elif "library" in type_lower or "lib" in type_lower:
            return ProtectionType.LIBRARY
        elif "overlay" in type_lower:
            return ProtectionType.OVERLAY
        else:
            return ProtectionType.UNKNOWN

    def _get_bypass_recommendations(self, protection_name: str) -> List[str]:
        """Get bypass recommendations for a specific protection"""
        # Check exact match first
        if protection_name in self.PROTECTION_BYPASSES:
            return self.PROTECTION_BYPASSES[protection_name]

        # Check partial matches
        name_lower = protection_name.lower()
        for key, recommendations in self.PROTECTION_BYPASSES.items():
            if key.lower() in name_lower or name_lower in key.lower():
                return recommendations

        # Generic recommendations based on protection type
        if "pack" in name_lower:
            return [
                "Try generic unpacking tools",
                "Set breakpoint at OEP",
                "Dump process memory and reconstruct"
            ]
        elif "protect" in name_lower or "crypt" in name_lower:
            return [
                "Use debugger with anti-anti-debug plugins",
                "Monitor API calls for license checks",
                "Analyze protection-specific signatures"
            ]
        elif "licens" in name_lower or "dongle" in name_lower:
            return [
                "Monitor licensing API calls",
                "Use API hooks to bypass checks",
                "Analyze license validation logic"
            ]

        return ["Manual analysis required for this protection"]

    def analyze_directory(self, directory: str, recursive: bool = True) -> List[ProtectionAnalysis]:
        """
        Analyze all executable files in a directory

        Args:
            directory: Directory path to scan
            recursive: Whether to scan subdirectories

        Returns:
            List of ProtectionAnalysis results
        """
        results = []
        extensions = ['.exe', '.dll', '.sys', '.ocx', '.scr', '.com']

        if recursive:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in extensions):
                        file_path = os.path.join(root, file)
                        try:
                            analysis = self.detect_protections(file_path)
                            results.append(analysis)
                        except Exception as e:
                            logger.error(f"Error analyzing {file_path}: {e}")
        else:
            for file in os.listdir(directory):
                if any(file.lower().endswith(ext) for ext in extensions):
                    file_path = os.path.join(directory, file)
                    if os.path.isfile(file_path):
                        try:
                            analysis = self.detect_protections(file_path)
                            results.append(analysis)
                        except Exception as e:
                            logger.error(f"Error analyzing {file_path}: {e}")

        return results

    def get_summary(self, analysis: ProtectionAnalysis) -> str:
        """Get a human-readable summary of the analysis"""
        lines = []
        lines.append(f"File: {os.path.basename(analysis.file_path)}")
        lines.append(f"Type: {analysis.file_type} ({analysis.architecture})")

        if analysis.compiler:
            lines.append(f"Compiler: {analysis.compiler}")

        if analysis.is_packed:
            lines.append("Status: PACKED")
        if analysis.is_protected:
            lines.append("Status: PROTECTED")

        if analysis.detections:
            lines.append("\nDetections:")
            for det in analysis.detections:
                ver_str = f" v{det.version}" if det.version else ""
                lines.append(f"  - {det.name}{ver_str} ({det.type.value})")

        return "\n".join(lines)

    def export_results(self, analysis: ProtectionAnalysis, output_format: str = "json") -> str:
        """
        Export analysis results in various formats

        Args:
            analysis: ProtectionAnalysis to export
            output_format: Format to export ("json", "text", "csv")

        Returns:
            Formatted string of results
        """
        if output_format == "json":
            # Convert to dict for JSON serialization
            data = {
                "file_path": analysis.file_path,
                "file_type": analysis.file_type,
                "architecture": analysis.architecture,
                "is_packed": analysis.is_packed,
                "is_protected": analysis.is_protected,
                "compiler": analysis.compiler,
                "detections": [
                    {
                        "name": d.name,
                        "version": d.version,
                        "type": d.type.value,
                        "confidence": d.confidence,
                        "bypass_recommendations": d.bypass_recommendations
                    }
                    for d in analysis.detections
                ],
                "metadata": analysis.metadata
            }
            return json.dumps(data, indent=2)

        elif output_format == "text":
            return self.get_summary(analysis)

        elif output_format == "csv":
            lines = ["File,Type,Architecture,Protection,Version,Category"]
            for det in analysis.detections:
                lines.append(f"{analysis.file_path},{analysis.file_type},{analysis.architecture},{det.name},{det.version or 'N/A'},{det.type.value}")
            return "\n".join(lines)

        else:
            raise ValueError(f"Unknown output format: {output_format}")


# Convenience function for quick analysis
def quick_analyze(file_path: str) -> ProtectionAnalysis:
    """Quick analysis function for one-off use"""
    detector = IntellicrackProtectionCore()
    return detector.detect_protections(file_path)


# Backward compatibility alias
DIEProtectionDetector = IntellicrackProtectionCore


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        detector = IntellicrackProtectionCore()
        analysis = detector.detect_protections(target_file)
        print(detector.get_summary(analysis))

        if analysis.detections:
            print("\nBypass Recommendations:")
            for det in analysis.detections:
                if det.bypass_recommendations:
                    print(f"\n{det.name}:")
                    for rec in det.bypass_recommendations:
                        print(f"  - {rec}")
    else:
        print("Usage: python intellicrack_protection_core.py <binary_file>")
