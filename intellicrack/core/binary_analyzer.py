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
from typing import Any

try:
    from .analysis.multi_format_analyzer import BinaryInfo, MultiFormatBinaryAnalyzer
except ImportError:
    logger.warning(
        "Failed to import BinaryInfo and MultiFormatBinaryAnalyzer from .analysis.multi_format_analyzer, "
        "multi-format analysis will be disabled.",
    )
    MultiFormatBinaryAnalyzer = None
    BinaryInfo = None

try:
    from ..utils.binary.pe_analysis_common import PEAnalyzer
except ImportError:
    logger.warning("Failed to import PEAnalyzer from ..utils.binary.pe_analysis_common, PE analysis will be disabled.")
    PEAnalyzer = None

try:
    from ..utils.binary.elf_analyzer import ELFAnalyzer
except ImportError:
    logger.warning("Failed to import ELFAnalyzer from ..utils.binary.elf_analyzer, ELF analysis will be disabled.")
    ELFAnalyzer = None

try:
    from ..utils.system.os_detection import detect_file_type
except ImportError:
    logger.warning("Failed to import detect_file_type from ..utils.system.os_detection, using fallback.")

    def detect_file_type(file_path: str | Path) -> str:
        """Fallback file type detection.

        Detects file type based on file extension when the primary detection
        function is unavailable.

        Args:
            file_path: Path to the file to analyze

        Returns:
            File extension lowercase or "unknown" if no extension found

        """
        _, ext = os.path.splitext(file_path)
        return ext.lower() or "unknown"


try:
    from ..utils.protection_utils import calculate_entropy
except ImportError:
    logger.warning("Failed to import calculate_entropy from ..utils.protection_utils, using fallback.")

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

from ..utils.logger import log_all_methods

logger = logging.getLogger(__name__)
logger.debug("Binary analyzer module loaded")


@log_all_methods
class BinaryAnalyzer:
    """Run binary analyzer coordinating multiple analysis techniques."""

    def __init__(self) -> None:
        """Initialize the binary analyzer."""
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initializing BinaryAnalyzer.")

        # Initialize sub-analyzers
        self.logger.debug("Initializing sub-analyzers.")
        self.multi_format_analyzer = MultiFormatBinaryAnalyzer() if MultiFormatBinaryAnalyzer else None
        self.pe_analyzer = PEAnalyzer() if PEAnalyzer else None
        self.elf_analyzer = ELFAnalyzer() if ELFAnalyzer else None
        if not self.multi_format_analyzer:
            self.logger.warning("MultiFormatBinaryAnalyzer not available. Analysis will be limited.")
        if not self.pe_analyzer:
            self.logger.warning("PEAnalyzer not available. PE file analysis will be limited.")
        if not self.elf_analyzer:
            self.logger.warning("ELFAnalyzer not available. ELF file analysis will be limited.")

        # Analysis cache
        self.analysis_cache = {}
        self.logger.debug("Analysis cache initialized.")

        # Supported file types
        self.supported_formats = [
            "exe",
            "dll",
            "sys",
            "scr",  # PE formats
            "elf",
            "so",
            "a",  # ELF formats
            "dylib",
            "bundle",  # Mach-O formats
            "apk",
            "jar",
            "dex",  # Android/Java formats
            "msi",
            "com",  # Other formats
        ]
        self.logger.info(f"BinaryAnalyzer initialized with {len(self.supported_formats)} supported formats.")

    def analyze(self, file_path: str | Path, analysis_options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Analyze a binary file comprehensively.

        Args:
            file_path: Path to the binary file
            analysis_options: Optional analysis configuration

        Returns:
            Comprehensive analysis results

        """
        self.logger.info(f"Starting comprehensive analysis for {file_path}")
        self.logger.debug(f"Analysis options: {analysis_options}")
        file_path = Path(file_path)

        if not file_path.exists():
            self.logger.error(f"File not found: {file_path}")
            return {"error": f"File not found: {file_path}"}

        # Check cache
        file_key = self._get_file_cache_key(file_path)
        if file_key in self.analysis_cache:
            self.logger.info(f"Returning cached analysis for {file_path}")
            return self.analysis_cache[file_key]

        # Start timing
        start_time = time.time()
        self.logger.debug("Analysis timer started.")

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
            "errors": [],
        }
        self.logger.debug("Results dictionary initialized.")

        try:
            self.logger.info("Step 1: Analyzing basic file information.")
            self._analyze_basic_info(file_path, results, analysis_options)
            self.logger.info("Step 1: Completed.")

            self.logger.info("Step 2: Detecting file type.")
            self._detect_file_type(file_path, results)
            self.logger.info(f"Detected file type: {results['file_type'].get('description', 'Unknown')}")
            self.logger.info("Step 2: Completed.")

            self.logger.info("Step 3: Calculating file hashes.")
            self._calculate_hashes(file_path, results)
            self.logger.info("Step 3: Completed.")

            self.logger.info("Step 4: Performing format-specific analysis.")
            self._analyze_format_specific(file_path, results, analysis_options)
            self.logger.info("Step 4: Completed.")

            # String extraction
            if analysis_options is None or analysis_options.get("extract_strings", True):
                self.logger.info("Step 5: Extracting strings.")
                self._extract_strings(file_path, results, analysis_options)
                self.logger.info(f"Found {results['strings'].get('total_count', 0)} strings, {len(results['strings'].get('interesting', []))} of which are interesting.")
                self.logger.info("Step 5: Completed.")

            # Entropy analysis
            if analysis_options is None or analysis_options.get("entropy_analysis", True):
                self.logger.info("Step 6: Analyzing entropy.")
                self._analyze_entropy(file_path, results)
                self.logger.info(f"Overall file entropy: {results['entropy'].get('overall', 0.0):.4f}")
                self.logger.info("Step 6: Completed.")

            # Protection analysis
            if analysis_options is None or analysis_options.get("protection_analysis", True):
                self.logger.info("Step 7: Analyzing for protections.")
                self._analyze_protections(file_path, results)
                self.logger.info(f"Found {len(results['protection_info'].get('detected', []))} protection(s).")
                self.logger.info("Step 7: Completed.")

            # Generate recommendations
            self.logger.info("Step 8: Generating recommendations.")
            self._generate_recommendations(results)
            self.logger.info(f"Generated {len(results['recommendations'])} recommendation(s).")
            self.logger.info("Step 8: Completed.")

            self.logger.info(f"Analysis for {file_path} completed successfully.")

        except Exception as e:
            self.logger.exception(f"A critical error occurred during analysis for {file_path}: {e}")
            results["errors"].append(f"Analysis failed: {e!s}")

        # Record timing
        duration = time.time() - start_time
        results["analysis_duration"] = duration
        self.logger.info(f"Total analysis duration: {duration:.2f} seconds.")

        # Cache results
        self.analysis_cache[file_key] = results
        self.logger.debug(f"Analysis results for {file_path} cached.")

        return results

    def _get_file_cache_key(self, file_path: Path) -> str:
        """Generate cache key for file."""
        stat = file_path.stat()
        return f"{file_path}_{stat.st_size}_{stat.st_mtime}"

    def _analyze_basic_info(self, file_path: Path, results: dict[str, Any], options: dict[str, Any] | None) -> None:
        """Analyze basic file information."""
        self.logger.debug(f"Extracting basic file metadata for {file_path}")
        try:
            stat_info = file_path.stat()
            self.logger.debug(f"File stat info: {stat_info}")

            results["basic_info"] = {
                "file_size": stat_info.st_size,
                "creation_time": datetime.datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                "modification_time": datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                "access_time": datetime.datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                "permissions": oct(stat_info.st_mode)[-3:],
                "is_executable": os.access(file_path, os.X_OK),
                "mime_type": mimetypes.guess_type(str(file_path))[0] or "application/octet-stream",
            }
            self.logger.debug(f"Extracted basic info: {results['basic_info']}")

        except Exception as e:
            self.logger.exception(f"Failed to extract basic file info for {file_path}: {e}")
            results["warnings"].append(f"Basic info analysis failed: {e!s}")

    def _detect_file_type(self, file_path: Path, results: dict[str, Any]) -> None:
        """Detect file type using multiple methods."""
        self.logger.debug(f"Detecting file type for {file_path} using magic bytes and extension.")
        try:
            # Magic byte detection
            with open(file_path, "rb") as f:
                magic_bytes = f.read(16)
            self.logger.debug(f"Magic bytes: {magic_bytes.hex()}")

            file_type_info = {
                "magic_bytes": magic_bytes.hex(),
                "detected_type": detect_file_type(str(file_path)),
                "extension": file_path.suffix.lower(),
                "is_supported": file_path.suffix.lower().lstrip(".") in self.supported_formats,
            }

            # Detailed magic byte analysis
            if magic_bytes.startswith(b"MZ"):
                file_type_info["format"] = "PE"
                file_type_info["description"] = "Windows Portable Executable"
            elif magic_bytes.startswith(b"\x7fELF"):
                file_type_info["format"] = "ELF"
                file_type_info["description"] = "Linux Executable and Linkable Format"
            elif magic_bytes[:4] in [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"]:
                file_type_info["format"] = "Mach-O"
                file_type_info["description"] = "macOS Mach-O executable"
            elif magic_bytes.startswith(b"dex\n"):
                file_type_info["format"] = "DEX"
                file_type_info["description"] = "Android Dalvik Executable"
            elif magic_bytes.startswith(b"PK\x03\x04"):
                file_type_info["format"] = "ZIP"
                if file_path.suffix.lower() == ".apk":
                    file_type_info["format"] = "APK"
                    file_type_info["description"] = "Android Package"
                elif file_path.suffix.lower() == ".jar":
                    file_type_info["format"] = "JAR"
                    file_type_info["description"] = "Java Archive"
                else:
                    file_type_info["description"] = "ZIP Archive"
            elif magic_bytes.startswith(b"\xca\xfe\xba\xbe"):
                file_type_info["format"] = "CLASS"
                file_type_info["description"] = "Java Class File"
            else:
                file_type_info["format"] = "Unknown"
                file_type_info["description"] = "Unknown binary format"

            self.logger.debug(f"Detected format: {file_type_info['format']} ({file_type_info['description']})")
            results["file_type"] = file_type_info

        except Exception as e:
            self.logger.exception(f"File type detection failed for {file_path}: {e}")
            results["warnings"].append(f"File type detection failed: {e!s}")

    def _calculate_hashes(self, file_path: Path, results: dict[str, Any]) -> None:
        """Calculate various hash values for the file."""
        self.logger.debug(f"Calculating hashes (sha256, sha512, sha3_256, blake2b) for {file_path}")
        try:
            hash_algos = {
                "sha256": hashlib.sha256(),
                "sha512": hashlib.sha512(),
                "sha3_256": hashlib.sha3_256(),
                "blake2b": hashlib.blake2b(),
            }
            self.logger.debug(f"Using hash algorithms: {list(hash_algos.keys())}")

            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    for hasher in hash_algos.values():
                        hasher.update(chunk)

            results["file_hashes"] = {name: hasher.hexdigest() for name, hasher in hash_algos.items()}
            self.logger.debug(f"Calculated hashes: {results['file_hashes']}")

        except Exception as e:
            self.logger.exception(f"Hash calculation failed for {file_path}: {e}")
            results["warnings"].append(f"Hash calculation failed: {e!s}")

    def _analyze_format_specific(self, file_path: Path, results: dict[str, Any], options: dict[str, Any] | None) -> None:
        """Perform format-specific analysis."""
        self.logger.debug(f"Performing format-specific analysis for {file_path}")
        try:
            if not self.multi_format_analyzer:
                self.logger.warning("Multi-format analyzer not available, skipping format-specific analysis.")
                results["warnings"].append("Multi-format analyzer not available")
                return

            # Use multi-format analyzer
            detected_format = results.get("file_type", {}).get("format", "Unknown")
            self.logger.debug(f"Calling multi-format analyzer for detected format: {detected_format}")
            format_results = self.multi_format_analyzer.analyze(file_path)

            if "error" not in format_results:
                results["format_analysis"] = format_results
                self.logger.debug(f"Format analysis results: {format_results}")

                # Extract specific information
                if "sections" in format_results:
                    results["sections"] = format_results["sections"]
                    self.logger.debug(f"Extracted {len(results['sections'])} sections.")

                if "imports" in format_results:
                    results["imports"] = format_results["imports"]
                    self.logger.debug(f"Extracted {len(results['imports'])} import entries.")

                if "exports" in format_results:
                    results["exports"] = format_results["exports"]
                    self.logger.debug(f"Extracted {len(results['exports'])} export entries.")
            else:
                self.logger.error(f"Format analysis failed: {format_results['error']}")
                results["warnings"].append(f"Format analysis failed: {format_results['error']}")

        except Exception as e:
            self.logger.exception(f"An unexpected error occurred during format-specific analysis for {file_path}: {e}")
            results["warnings"].append(f"Format-specific analysis failed: {e!s}")

    def _extract_strings(self, file_path: Path, results: dict[str, Any], options: dict[str, Any] | None) -> None:
        """Extract printable strings from the binary."""
        self.logger.debug(f"Extracting strings from {file_path}")
        try:
            min_length = 4
            if options and "string_min_length" in options:
                min_length = options["string_min_length"]
            self.logger.debug(f"Minimum string length: {min_length}")

            max_strings = 1000
            if options and "max_strings" in options:
                max_strings = options["max_strings"]
            self.logger.debug(f"Maximum number of strings to extract: {max_strings}")

            strings = []

            with open(file_path, "rb") as f:
                data = f.read()

            # Extract ASCII strings
            self.logger.debug("Extracting ASCII strings.")
            current = []
            ascii_strings_count = 0
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        strings.append("".join(current))
                        ascii_strings_count += 1
                        if len(strings) >= max_strings:
                            break
                    current = []

            if len(current) >= min_length and len(strings) < max_strings:
                strings.append("".join(current))
                ascii_strings_count += 1
            self.logger.debug(f"Extracted {ascii_strings_count} ASCII strings.")

            # Extract Unicode strings (simplified)
            if len(strings) < max_strings:
                self.logger.debug("Extracting Unicode strings.")
                current = []
                unicode_strings_count = 0
                for i in range(0, len(data) - 1, 2):
                    if data[i + 1] == 0 and 32 <= data[i] <= 126:
                        current.append(chr(data[i]))
                    else:
                        if len(current) >= min_length:
                            strings.append("".join(current))
                            unicode_strings_count += 1
                            if len(strings) >= max_strings:
                                break
                        current = []

                if len(current) >= min_length and len(strings) < max_strings:
                    strings.append("".join(current))
                    unicode_strings_count += 1
                self.logger.debug(f"Extracted {unicode_strings_count} Unicode strings.")

            self.logger.info(f"Extracted {len(strings)} strings.")

            # Analyze strings for interesting patterns
            self.logger.debug("Analyzing strings for interesting patterns.")
            interesting_strings = []
            suspicious_patterns = [
                "password",
                "passwd",
                "license",
                "serial",
                "crack",
                "patch",
                "keygen",
                "http://",
                "https://",
                "ftp://",
                "cmd.exe",
                "powershell",
                "bash",
                "sh",
                "/bin/",
                "admin",
                "administrator",
                "root",
                "sudo",
                "token",
                "api_key",
                "secret",
                "key",
                "SELECT",
                "INSERT",
                "UPDATE",
                "DELETE",
                "CreateFile",
                "WriteFile",
                "ReadFile",
                "VirtualAlloc",
                "VirtualProtect",
                "CreateProcess",
            ]

            for string in strings:
                string_lower = string.lower()
                for pattern in suspicious_patterns:
                    if pattern in string_lower:
                        interesting_strings.append(
                            {"string": string, "pattern": pattern, "category": self._categorize_string_pattern(pattern)},
                        )
                        break
            self.logger.info(f"Found {len(interesting_strings)} interesting strings.")

            results["strings"] = {
                "total_count": len(strings),
                "sample": strings[:50],  # First 50 strings
                "interesting": interesting_strings,
                "analysis": {"min_length": min_length, "max_extracted": max_strings, "truncated": len(strings) >= max_strings},
            }

        except Exception as e:
            self.logger.exception(f"String extraction failed for {file_path}: {e}")
            results["warnings"].append(f"String extraction failed: {e!s}")

    def _categorize_string_pattern(self, pattern: str) -> str:
        """Categorize string patterns."""
        categories = {
            "security": ["password", "passwd", "token", "api_key", "secret", "key", "admin", "administrator", "root", "sudo"],
            "licensing": ["license", "serial", "crack", "patch", "keygen"],
            "network": ["http://", "https://", "ftp://"],
            "system": ["cmd.exe", "powershell", "bash", "sh", "/bin/", "CreateFile", "WriteFile", "ReadFile"],
            "memory": ["VirtualAlloc", "VirtualProtect", "CreateProcess"],
            "database": ["SELECT", "INSERT", "UPDATE", "DELETE"],
        }

        for category, patterns in categories.items():
            if pattern in patterns:
                return category

        return "other"

    def _analyze_entropy(self, file_path: Path, results: dict[str, Any]) -> None:
        """Analyze entropy of file sections."""
        self.logger.debug(f"Analyzing entropy for {file_path}")
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Overall file entropy
            self.logger.debug("Calculating overall file entropy.")
            overall_entropy = calculate_entropy(data)
            self.logger.info(f"Overall file entropy: {overall_entropy:.4f}")

            entropy_info = {
                "overall": overall_entropy,
                "sections": [],
                "analysis": {
                    "high_entropy_threshold": 7.0,
                    "is_high_entropy": overall_entropy > 7.0,
                    "interpretation": self._interpret_entropy(overall_entropy),
                },
            }
            self.logger.debug(f"Entropy interpretation: {entropy_info['analysis']['interpretation']}")

            # Section-wise entropy analysis
            if results.get("sections"):
                self.logger.debug("Analyzing entropy of individual sections.")
                for section in results["sections"]:
                    # This is a simplified approach - in practice, you'd need
                    # to extract actual section data based on file format
                    section_entropy = {
                        "name": section.get("name", "unknown"),
                        "entropy": section.get("entropy", 0.0) if "entropy" in section else None,
                    }
                    entropy_info["sections"].append(section_entropy)
                self.logger.info(f"Analyzed entropy for {len(results['sections'])} sections.")
                self.logger.debug(f"Entropy analysis completed for {len(results['sections'])} sections.")
            else:
                # Analyze file in chunks if no sections available
                self.logger.debug("No sections found, analyzing entropy of file chunks.")
                chunk_size = 8192
                chunks_analyzed = 0
                for i in range(0, min(len(data), 64 * 1024), chunk_size):  # First 64KB
                    chunk = data[i : i + chunk_size]
                    if len(chunk) > 0:
                        chunk_entropy = calculate_entropy(chunk)
                        entropy_info["sections"].append(
                            {"name": f"chunk_{i // chunk_size}", "offset": i, "size": len(chunk), "entropy": chunk_entropy},
                        )
                        chunks_analyzed += 1
                self.logger.info(f"Analyzed entropy for {chunks_analyzed} chunks.")
                self.logger.debug(f"Entropy analysis completed for {chunks_analyzed} chunks.")

            results["entropy"] = entropy_info

        except Exception as e:
            self.logger.exception(f"Entropy analysis failed for {file_path}: {e}")
            results["warnings"].append(f"Entropy analysis failed: {e!s}")

    def _interpret_entropy(self, entropy: float) -> str:
        """Interpret entropy value."""
        if entropy < 1.0:
            return "Very low entropy - likely highly structured or repetitive data"
        if entropy < 3.0:
            return "Low entropy - structured data with some variation"
        if entropy < 5.0:
            return "Medium entropy - mixed content with moderate randomness"
        if entropy < 7.0:
            return "High entropy - diverse content or light compression"
        if entropy < 7.5:
            return "Very high entropy - possible compression or encryption"
        return "Extremely high entropy - likely encrypted or packed"

    def _analyze_protections(self, file_path: Path, results: dict[str, Any]) -> None:
        """Analyze protection mechanisms."""
        self.logger.debug(f"Analyzing protection mechanisms for {file_path}")
        try:
            protections = {"detected": [], "indicators": [], "analysis": {}}

            # Check for common protection indicators
            file_type = results.get("file_type", {}).get("format", "Unknown")
            self.logger.debug(f"Analyzing protections for file type: {file_type}")

            if file_type == "PE":
                self.logger.debug("Performing PE-specific protection checks.")
                self._check_pe_protections(file_path, results, protections)
            elif file_type == "ELF":
                self.logger.debug("Performing ELF-specific protection checks.")
                self._check_elf_protections(file_path, results, protections)

            # Generic protection checks
            self.logger.debug("Performing generic protection checks.")
            self._check_generic_protections(file_path, results, protections)

            results["protection_info"] = protections
            self.logger.info(f"Found {len(protections['detected'])} detected protections and {len(protections['indicators'])} indicators.")
            self.logger.debug(f"Protection analysis completed. Detected: {protections['detected']}, Indicators: {protections['indicators']}")

        except Exception as e:
            self.logger.exception(f"Protection analysis failed for {file_path}: {e}")
            results["warnings"].append(f"Protection analysis failed: {e!s}")

    def _check_pe_protections(self, file_path: Path, results: dict[str, Any], protections: dict[str, Any]) -> None:
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
            protection_apis = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "VirtualProtect", "VirtualAlloc", "CreateRemoteThread"]

            for imp_dll in imports:
                if isinstance(imp_dll, dict) and "functions" in imp_dll:
                    for func in imp_dll["functions"]:
                        if func in protection_apis:
                            protections["indicators"].append(f"Protection API: {func}")

    def _check_elf_protections(self, file_path: Path, results: dict[str, Any], protections: dict[str, Any]) -> None:
        """Check ELF-specific protections."""
        # Check for stack canaries, RELRO, etc.
        if "format_analysis" in results:
            # This would need more detailed ELF analysis
            protections["indicators"].append("ELF protection analysis requires deeper inspection")

    def _check_generic_protections(self, file_path: Path, results: dict[str, Any], protections: dict[str, Any]) -> None:
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

    def _generate_recommendations(self, results: dict[str, Any]) -> None:
        """Generate analysis recommendations."""
        recommendations = []

        file_type = results.get("file_type", {}).get("format", "Unknown")

        # Format-specific recommendations
        if file_type == "PE":
            recommendations.extend(
                [
                    "Use PE analysis tools like PEview, CFF Explorer, or ICP Analysis",
                    "Check for digital signatures and certificate validity",
                    "Analyze imports and exports for suspicious API usage",
                ],
            )
        elif file_type == "ELF":
            recommendations.extend(
                [
                    "Use ELF analysis tools like readelf, objdump, or nm",
                    "Check for stripped symbols and debug information",
                    "Analyze dynamic dependencies and RPATH settings",
                ],
            )
        elif file_type in ["APK", "DEX"]:
            recommendations.extend(
                [
                    "Use Android analysis tools like JADX, dex2jar, or APKTool",
                    "Check AndroidManifest.xml for permissions and components",
                    "Analyze native libraries for potential security issues",
                ],
            )

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
        recommendations.extend(
            [
                "Perform dynamic analysis in a controlled environment",
                "Check file against threat intelligence databases",
                "Consider behavioral analysis with sandbox tools",
            ],
        )

        results["recommendations"] = recommendations
        self.logger.debug(f"Generated {len(recommendations)} recommendations.")

    def create_binary_info(self, file_path: str | Path) -> object | None:
        """Create BinaryInfo object from file analysis.

        Generates a BinaryInfo object from comprehensive binary file analysis.
        Returns None if BinaryInfo class is not available or analysis fails.

        Args:
            file_path: Path to the binary file to analyze

        Returns:
            BinaryInfo object containing structured analysis data, or None if
            BinaryInfo is unavailable or analysis fails

        Raises:
            Exception: Logged internally if BinaryInfo creation fails

        """
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
                sha256=hashes.get("sha256", ""),
            )

        except Exception as e:
            self.logger.exception(f"Failed to create BinaryInfo: {e}")
            return None

    def get_supported_formats(self) -> list[str]:
        """Get list of supported file formats."""
        return self.supported_formats.copy()

    def is_supported_format(self, file_path: str | Path) -> bool:
        """Check if file format is supported."""
        file_path = Path(file_path)
        extension = file_path.suffix.lower().lstrip(".")
        return extension in self.supported_formats

    def clear_cache(self) -> None:
        """Clear analysis cache."""
        self.analysis_cache.clear()
        self.logger.info("Analysis cache cleared")

    def get_cache_stats(self) -> dict[str, int]:
        """Get cache statistics."""
        return {
            "cached_files": len(self.analysis_cache),
            "cache_memory_mb": sum(len(str(results)) for results in self.analysis_cache.values()) // (1024 * 1024),
        }
