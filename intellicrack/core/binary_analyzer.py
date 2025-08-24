"""Core binary analyzer for comprehensive executable analysis.

This module provides the main BinaryAnalyzer class that coordinates analysis
of various binary formats and integrates with other analysis components
within the Intellicrack security research framework.

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

import datetime
import hashlib
import logging
import mimetypes
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    from .analysis.multi_format_analyzer import BinaryInfo, MultiFormatBinaryAnalyzer
except ImportError:
    MultiFormatBinaryAnalyzer = None
    BinaryInfo = None

try:
    from ..utils.binary.pe_analysis_common import PEAnalyzer
except ImportError:
    PEAnalyzer = None

try:
    from ..utils.binary.elf_analyzer import ELFAnalyzer
except ImportError:
    ELFAnalyzer = None

try:
    from ..utils.system.os_detection import detect_file_type
except ImportError:
    def detect_file_type(file_path):
        """Fallback file type detection."""
        _, ext = os.path.splitext(file_path)
        return ext.lower() or "unknown"

try:
    from ..utils.protection.protection_utils import calculate_entropy
except ImportError:
    def calculate_entropy(data: bytes) -> float:
        """Calculate entropy of binary data."""
        if not data:
            return 0.0

        import math
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

logger = logging.getLogger(__name__)


class BinaryAnalyzer:
    """Main binary analyzer coordinating multiple analysis techniques."""

    def __init__(self):
        """Initialize the binary analyzer."""
        self.logger = logging.getLogger(__name__)

        # Initialize sub-analyzers
        self.multi_format_analyzer = MultiFormatBinaryAnalyzer() if MultiFormatBinaryAnalyzer else None
        self.pe_analyzer = PEAnalyzer() if PEAnalyzer else None
        self.elf_analyzer = ELFAnalyzer() if ELFAnalyzer else None

        # Analysis cache
        self.analysis_cache = {}

        # Supported file types
        self.supported_formats = [
            'exe', 'dll', 'sys', 'scr',  # PE formats
            'elf', 'so', 'a',            # ELF formats
            'dylib', 'bundle',           # Mach-O formats
            'apk', 'jar', 'dex',         # Android/Java formats
            'msi', 'com'                 # Other formats
        ]

    def analyze(self, file_path: Union[str, Path],
                analysis_options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze a binary file comprehensively.

        Args:
            file_path: Path to the binary file
            analysis_options: Optional analysis configuration

        Returns:
            Comprehensive analysis results

        """
        file_path = Path(file_path)

        if not file_path.exists():
            return {"error": f"File not found: {file_path}"}

        # Check cache
        file_key = self._get_file_cache_key(file_path)
        if file_key in self.analysis_cache:
            self.logger.info(f"Returning cached analysis for {file_path}")
            return self.analysis_cache[file_key]

        # Start timing
        start_time = time.time()

        # Initialize results
        results = {
            "file_path": str(file_path),
            "file_name": file_path.name,
            "file_size": file_path.stat().st_size,
            "timestamp": datetime.datetime.now().isoformat(),
            "analysis_duration": 0,
            "file_hashes": {},
            "file_type": {},
            "basic_info": {},
            "format_analysis": {},
            "strings": [],
            "entropy": {},
            "protection_info": {},
            "imports": {},
            "exports": {},
            "sections": [],
            "metadata": {},
            "recommendations": [],
            "warnings": [],
            "errors": []
        }

        try:
            # Basic file analysis
            self._analyze_basic_info(file_path, results, analysis_options)

            # File type detection
            self._detect_file_type(file_path, results)

            # Hash calculation
            self._calculate_hashes(file_path, results)

            # Format-specific analysis
            self._analyze_format_specific(file_path, results, analysis_options)

            # String extraction
            if analysis_options is None or analysis_options.get("extract_strings", True):
                self._extract_strings(file_path, results, analysis_options)

            # Entropy analysis
            if analysis_options is None or analysis_options.get("entropy_analysis", True):
                self._analyze_entropy(file_path, results)

            # Protection analysis
            if analysis_options is None or analysis_options.get("protection_analysis", True):
                self._analyze_protections(file_path, results)

            # Generate recommendations
            self._generate_recommendations(results)

        except Exception as e:
            self.logger.error(f"Analysis failed for {file_path}: {e}")
            results["errors"].append(f"Analysis failed: {str(e)}")

        # Record timing
        results["analysis_duration"] = time.time() - start_time

        # Cache results
        self.analysis_cache[file_key] = results

        return results

    def _get_file_cache_key(self, file_path: Path) -> str:
        """Generate cache key for file."""
        stat = file_path.stat()
        return f"{file_path}_{stat.st_size}_{stat.st_mtime}"

    def _analyze_basic_info(self, file_path: Path, results: Dict[str, Any],
                           options: Optional[Dict[str, Any]]):
        """Analyze basic file information."""
        try:
            stat_info = file_path.stat()

            results["basic_info"] = {
                "file_size": stat_info.st_size,
                "creation_time": datetime.datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                "modification_time": datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                "access_time": datetime.datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                "permissions": oct(stat_info.st_mode)[-3:],
                "is_executable": os.access(file_path, os.X_OK),
                "mime_type": mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
            }

        except Exception as e:
            self.logger.error(f"Basic info analysis failed: {e}")
            results["warnings"].append(f"Basic info analysis failed: {str(e)}")

    def _detect_file_type(self, file_path: Path, results: Dict[str, Any]):
        """Detect file type using multiple methods."""
        try:
            # Magic byte detection
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(16)

            file_type_info = {
                "magic_bytes": magic_bytes.hex(),
                "detected_type": detect_file_type(str(file_path)),
                "extension": file_path.suffix.lower(),
                "is_supported": file_path.suffix.lower().lstrip('.') in self.supported_formats
            }

            # Detailed magic byte analysis
            if magic_bytes.startswith(b'MZ'):
                file_type_info["format"] = "PE"
                file_type_info["description"] = "Windows Portable Executable"
            elif magic_bytes.startswith(b'\x7fELF'):
                file_type_info["format"] = "ELF"
                file_type_info["description"] = "Linux Executable and Linkable Format"
            elif magic_bytes[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                                   b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
                file_type_info["format"] = "Mach-O"
                file_type_info["description"] = "macOS Mach-O executable"
            elif magic_bytes.startswith(b'dex\n'):
                file_type_info["format"] = "DEX"
                file_type_info["description"] = "Android Dalvik Executable"
            elif magic_bytes.startswith(b'PK\x03\x04'):
                file_type_info["format"] = "ZIP"
                if file_path.suffix.lower() == '.apk':
                    file_type_info["format"] = "APK"
                    file_type_info["description"] = "Android Package"
                elif file_path.suffix.lower() == '.jar':
                    file_type_info["format"] = "JAR"
                    file_type_info["description"] = "Java Archive"
                else:
                    file_type_info["description"] = "ZIP Archive"
            elif magic_bytes.startswith(b'\xca\xfe\xba\xbe'):
                file_type_info["format"] = "CLASS"
                file_type_info["description"] = "Java Class File"
            else:
                file_type_info["format"] = "Unknown"
                file_type_info["description"] = "Unknown binary format"

            results["file_type"] = file_type_info

        except Exception as e:
            self.logger.error(f"File type detection failed: {e}")
            results["warnings"].append(f"File type detection failed: {str(e)}")

    def _calculate_hashes(self, file_path: Path, results: Dict[str, Any]):
        """Calculate various hash values for the file."""
        try:
            hash_algos = {
                'sha256': hashlib.sha256(),
                'sha512': hashlib.sha512(),
                'sha3_256': hashlib.sha3_256(),
                'blake2b': hashlib.blake2b()
            }

            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for hasher in hash_algos.values():
                        hasher.update(chunk)

            results["file_hashes"] = {
                name: hasher.hexdigest()
                for name, hasher in hash_algos.items()
            }

        except Exception as e:
            self.logger.error(f"Hash calculation failed: {e}")
            results["warnings"].append(f"Hash calculation failed: {str(e)}")

    def _analyze_format_specific(self, file_path: Path, results: Dict[str, Any],
                               options: Optional[Dict[str, Any]]):
        """Perform format-specific analysis."""
        try:
            if not self.multi_format_analyzer:
                results["warnings"].append("Multi-format analyzer not available")
                return

            # Use multi-format analyzer
            format_results = self.multi_format_analyzer.analyze(file_path)

            if "error" not in format_results:
                results["format_analysis"] = format_results

                # Extract specific information
                if "sections" in format_results:
                    results["sections"] = format_results["sections"]

                if "imports" in format_results:
                    results["imports"] = format_results["imports"]

                if "exports" in format_results:
                    results["exports"] = format_results["exports"]
            else:
                results["warnings"].append(f"Format analysis failed: {format_results['error']}")

        except Exception as e:
            self.logger.error(f"Format-specific analysis failed: {e}")
            results["warnings"].append(f"Format-specific analysis failed: {str(e)}")

    def _extract_strings(self, file_path: Path, results: Dict[str, Any],
                        options: Optional[Dict[str, Any]]):
        """Extract printable strings from the binary."""
        try:
            min_length = 4
            if options and "string_min_length" in options:
                min_length = options["string_min_length"]

            max_strings = 1000
            if options and "max_strings" in options:
                max_strings = options["max_strings"]

            strings = []

            with open(file_path, 'rb') as f:
                data = f.read()

            # Extract ASCII strings
            current = []
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        strings.append(''.join(current))
                        if len(strings) >= max_strings:
                            break
                    current = []

            if len(current) >= min_length and len(strings) < max_strings:
                strings.append(''.join(current))

            # Extract Unicode strings (simplified)
            if len(strings) < max_strings:
                current = []
                for i in range(0, len(data) - 1, 2):
                    if data[i+1] == 0 and 32 <= data[i] <= 126:
                        current.append(chr(data[i]))
                    else:
                        if len(current) >= min_length:
                            strings.append(''.join(current))
                            if len(strings) >= max_strings:
                                break
                        current = []

                if len(current) >= min_length and len(strings) < max_strings:
                    strings.append(''.join(current))

            # Analyze strings for interesting patterns
            interesting_strings = []
            suspicious_patterns = [
                "password", "passwd", "license", "serial", "crack",
                "patch", "keygen", "http://", "https://", "ftp://",
                "cmd.exe", "powershell", "bash", "sh", "/bin/",
                "admin", "administrator", "root", "sudo",
                "token", "api_key", "secret", "key",
                "SELECT", "INSERT", "UPDATE", "DELETE",
                "CreateFile", "WriteFile", "ReadFile",
                "VirtualAlloc", "VirtualProtect", "CreateProcess"
            ]

            for string in strings:
                string_lower = string.lower()
                for pattern in suspicious_patterns:
                    if pattern in string_lower:
                        interesting_strings.append({
                            "string": string,
                            "pattern": pattern,
                            "category": self._categorize_string_pattern(pattern)
                        })
                        break

            results["strings"] = {
                "total_count": len(strings),
                "sample": strings[:50],  # First 50 strings
                "interesting": interesting_strings,
                "analysis": {
                    "min_length": min_length,
                    "max_extracted": max_strings,
                    "truncated": len(strings) >= max_strings
                }
            }

        except Exception as e:
            self.logger.error(f"String extraction failed: {e}")
            results["warnings"].append(f"String extraction failed: {str(e)}")

    def _categorize_string_pattern(self, pattern: str) -> str:
        """Categorize string patterns."""
        categories = {
            "security": ["password", "passwd", "token", "api_key", "secret", "key", "admin", "administrator", "root", "sudo"],
            "licensing": ["license", "serial", "crack", "patch", "keygen"],
            "network": ["http://", "https://", "ftp://"],
            "system": ["cmd.exe", "powershell", "bash", "sh", "/bin/", "CreateFile", "WriteFile", "ReadFile"],
            "memory": ["VirtualAlloc", "VirtualProtect", "CreateProcess"],
            "database": ["SELECT", "INSERT", "UPDATE", "DELETE"]
        }

        for category, patterns in categories.items():
            if pattern in patterns:
                return category

        return "other"

    def _analyze_entropy(self, file_path: Path, results: Dict[str, Any]):
        """Analyze entropy of file sections."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # Overall file entropy
            overall_entropy = calculate_entropy(data)

            entropy_info = {
                "overall": overall_entropy,
                "sections": [],
                "analysis": {
                    "high_entropy_threshold": 7.0,
                    "is_high_entropy": overall_entropy > 7.0,
                    "interpretation": self._interpret_entropy(overall_entropy)
                }
            }

            # Section-wise entropy analysis
            if results.get("sections"):
                for section in results["sections"]:
                    # This is a simplified approach - in practice, you'd need
                    # to extract actual section data based on file format
                    section_entropy = {
                        "name": section.get("name", "unknown"),
                        "entropy": section.get("entropy", 0.0) if "entropy" in section else None
                    }
                    entropy_info["sections"].append(section_entropy)
            else:
                # Analyze file in chunks if no sections available
                chunk_size = 8192
                for i in range(0, min(len(data), 64*1024), chunk_size):  # First 64KB
                    chunk = data[i:i+chunk_size]
                    if len(chunk) > 0:
                        chunk_entropy = calculate_entropy(chunk)
                        entropy_info["sections"].append({
                            "name": f"chunk_{i//chunk_size}",
                            "offset": i,
                            "size": len(chunk),
                            "entropy": chunk_entropy
                        })

            results["entropy"] = entropy_info

        except Exception as e:
            self.logger.error(f"Entropy analysis failed: {e}")
            results["warnings"].append(f"Entropy analysis failed: {str(e)}")

    def _interpret_entropy(self, entropy: float) -> str:
        """Interpret entropy value."""
        if entropy < 1.0:
            return "Very low entropy - likely highly structured or repetitive data"
        elif entropy < 3.0:
            return "Low entropy - structured data with some variation"
        elif entropy < 5.0:
            return "Medium entropy - mixed content with moderate randomness"
        elif entropy < 7.0:
            return "High entropy - diverse content or light compression"
        elif entropy < 7.5:
            return "Very high entropy - possible compression or encryption"
        else:
            return "Extremely high entropy - likely encrypted or packed"

    def _analyze_protections(self, file_path: Path, results: Dict[str, Any]):
        """Analyze protection mechanisms."""
        try:
            protections = {
                "detected": [],
                "indicators": [],
                "analysis": {}
            }

            # Check for common protection indicators
            file_type = results.get("file_type", {}).get("format", "Unknown")

            if file_type == "PE":
                self._check_pe_protections(file_path, results, protections)
            elif file_type == "ELF":
                self._check_elf_protections(file_path, results, protections)

            # Generic protection checks
            self._check_generic_protections(file_path, results, protections)

            results["protection_info"] = protections

        except Exception as e:
            self.logger.error(f"Protection analysis failed: {e}")
            results["warnings"].append(f"Protection analysis failed: {str(e)}")

    def _check_pe_protections(self, file_path: Path, results: Dict[str, Any], protections: Dict[str, Any]):
        """Check PE-specific protections."""
        # Check for ASLR, DEP, etc.
        if "format_analysis" in results:
            format_data = results["format_analysis"]

            # Check characteristics
            characteristics = format_data.get("characteristics", [])
            if "Large address aware" in characteristics:
                protections["detected"].append("ASLR Support")

            # Check for high entropy sections (possible packing)
            sections = results.get("sections", [])
            for section in sections:
                if isinstance(section, dict) and "entropy" in section:
                    if section["entropy"] > 7.0:
                        protections["indicators"].append(f"High entropy section: {section.get('name', 'unknown')}")

            # Check imports for protection APIs
            imports = results.get("imports", [])
            protection_apis = [
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "VirtualProtect", "VirtualAlloc", "CreateRemoteThread"
            ]

            for imp_dll in imports:
                if isinstance(imp_dll, dict) and "functions" in imp_dll:
                    for func in imp_dll["functions"]:
                        if func in protection_apis:
                            protections["indicators"].append(f"Protection API: {func}")

    def _check_elf_protections(self, file_path: Path, results: Dict[str, Any], protections: Dict[str, Any]):
        """Check ELF-specific protections."""
        # Check for stack canaries, RELRO, etc.
        if "format_analysis" in results:
            # This would need more detailed ELF analysis
            protections["indicators"].append("ELF protection analysis requires deeper inspection")

    def _check_generic_protections(self, file_path: Path, results: Dict[str, Any], protections: Dict[str, Any]):
        """Check generic protection indicators."""
        # High entropy check
        entropy_info = results.get("entropy", {})
        if entropy_info.get("overall", 0) > 7.5:
            protections["indicators"].append("Very high entropy - possible packing/encryption")

        # Suspicious strings
        strings_info = results.get("strings", {})
        for interesting in strings_info.get("interesting", []):
            if interesting["category"] in ["security", "licensing"]:
                protections["indicators"].append(f"Suspicious string: {interesting['pattern']}")

    def _generate_recommendations(self, results: Dict[str, Any]):
        """Generate analysis recommendations."""
        recommendations = []

        file_type = results.get("file_type", {}).get("format", "Unknown")

        # Format-specific recommendations
        if file_type == "PE":
            recommendations.extend([
                "Use PE analysis tools like PEview, CFF Explorer, or ICP Analysis",
                "Check for digital signatures and certificate validity",
                "Analyze imports and exports for suspicious API usage"
            ])
        elif file_type == "ELF":
            recommendations.extend([
                "Use ELF analysis tools like readelf, objdump, or nm",
                "Check for stripped symbols and debug information",
                "Analyze dynamic dependencies and RPATH settings"
            ])
        elif file_type in ["APK", "DEX"]:
            recommendations.extend([
                "Use Android analysis tools like JADX, dex2jar, or APKTool",
                "Check AndroidManifest.xml for permissions and components",
                "Analyze native libraries for potential security issues"
            ])

        # Protection-based recommendations
        protection_info = results.get("protection_info", {})
        if protection_info.get("indicators"):
            recommendations.append("File shows signs of protection - consider using unpacking tools")

        # Entropy-based recommendations
        entropy = results.get("entropy", {}).get("overall", 0)
        if entropy > 7.5:
            recommendations.append("High entropy suggests compression/encryption - may need specialized tools")

        # String-based recommendations
        strings_info = results.get("strings", {})
        if strings_info.get("interesting"):
            recommendations.append("Interesting strings found - investigate for credentials or sensitive data")

        # Generic recommendations
        recommendations.extend([
            "Perform dynamic analysis in a controlled environment",
            "Check file against threat intelligence databases",
            "Consider behavioral analysis with sandbox tools"
        ])

        results["recommendations"] = recommendations

    def create_binary_info(self, file_path: Union[str, Path]) -> Optional['BinaryInfo']:
        """Create BinaryInfo object from file analysis."""
        if not BinaryInfo:
            return None

        try:
            analysis_results = self.analyze(file_path)

            if "error" in analysis_results:
                return None

            # Extract relevant information
            file_info = analysis_results.get("basic_info", {})
            file_type_info = analysis_results.get("file_type", {})
            format_analysis = analysis_results.get("format_analysis", {})
            hashes = analysis_results.get("file_hashes", {})

            return BinaryInfo(
                file_path=str(file_path),
                file_size=file_info.get("file_size", 0),
                file_type=file_type_info.get("description", "Unknown"),
                architecture=format_analysis.get("architecture", "Unknown"),
                endianness=format_analysis.get("endianness", "Unknown"),
                entry_point=format_analysis.get("entry_point", 0),
                sections=analysis_results.get("sections", []),
                imports=analysis_results.get("imports", {}),
                exports=analysis_results.get("exports", {}),
                strings=analysis_results.get("strings", {}).get("sample", []),
                md5=hashes.get("md5", ""),
                sha256=hashes.get("sha256", "")
            )

        except Exception as e:
            self.logger.error(f"Failed to create BinaryInfo: {e}")
            return None

    def get_supported_formats(self) -> List[str]:
        """Get list of supported file formats."""
        return self.supported_formats.copy()

    def is_supported_format(self, file_path: Union[str, Path]) -> bool:
        """Check if file format is supported."""
        file_path = Path(file_path)
        extension = file_path.suffix.lower().lstrip('.')
        return extension in self.supported_formats

    def clear_cache(self):
        """Clear analysis cache."""
        self.analysis_cache.clear()
        self.logger.info("Analysis cache cleared")

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            "cached_files": len(self.analysis_cache),
            "cache_memory_mb": sum(
                len(str(results)) for results in self.analysis_cache.values()
            ) // (1024 * 1024)
        }
