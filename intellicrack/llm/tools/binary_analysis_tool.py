"""Binary Analysis Tool for LLM Integration

Provides AI models with binary analysis capabilities.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import math
import os
import re
import struct
from typing import Any

from ...utils.logger import get_logger

logger = get_logger(__name__)


class BinaryAnalysisTool:
    """LLM tool for binary analysis."""

    def __init__(self) -> None:
        """Initialize binary analysis tool.

        Initializes the binary analysis tool by loading PE and ELF analyzers
        for comprehensive binary format support. Gracefully handles missing
        analyzer dependencies.
        """
        self.pe_analyzer: Any | None = None
        self.elf_analyzer: Any | None = None
        self._init_analyzers()

    def _init_analyzers(self) -> None:
        """Initialize binary analyzers.

        Attempts to load PE and ELF analyzers for binary format support. If
        either analyzer fails to import, logs a warning and continues. This
        allows graceful degradation if dependencies are unavailable.
        """
        try:
            from ...binary_analysis.pe_analyzer import PEAnalyzer

            self.pe_analyzer = PEAnalyzer()
        except ImportError:
            logger.warning("PE analyzer not available")

        try:
            from ...binary_analysis.elf_analyzer import ELFAnalyzer

            self.elf_analyzer = ELFAnalyzer()
        except ImportError:
            logger.warning("ELF analyzer not available")

    def get_tool_definition(self) -> dict[str, Any]:
        """Get tool definition for LLM registration.

        Provides the tool definition required for LLM integration, including
        parameter schemas and descriptions for binary analysis operations.

        Returns:
            Tool definition dictionary with name, description, and JSON schema
                parameters for binary file analysis operations.
        """
        return {
            "name": "binary_analysis",
            "description": "Analyze binary files for structure, imports, exports, and other metadata",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the binary file to analyze",
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": ["basic", "imports", "exports", "sections", "strings", "full"],
                        "description": "Type of analysis to perform",
                        "default": "full",
                    },
                },
                "required": ["file_path"],
            },
        }

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        """Execute binary analysis.

        Performs comprehensive binary analysis on a target file by detecting
        its format (PE, ELF, or unknown) and applying appropriate analysis
        techniques. Supports multiple analysis types including basic metadata,
        imports, exports, sections, strings, and full analysis.

        Args:
            **kwargs: Keyword arguments containing file analysis parameters.
                file_path (str): Path to the binary file to analyze.
                analysis_type (str): Type of analysis to perform (basic,
                    imports, exports, sections, strings, or full). Defaults to
                    'full'.

        Returns:
            Dictionary containing analysis results with success status, file
                metadata, hashes, and format-specific analysis data based on
                the requested analysis type.

        Raises:
            No explicit exceptions raised; all errors are caught and returned
                in the result dictionary with success=False and error message.
        """
        file_path: Any = kwargs.get("file_path")
        analysis_type: Any = kwargs.get("analysis_type", "full")

        if not file_path or not os.path.exists(file_path):
            return {"success": False, "error": f"File not found: {file_path}"}

        try:
            # Detect file type
            file_type = self._detect_file_type(file_path)

            if file_type == "PE" and self.pe_analyzer:
                return self._analyze_pe(file_path, analysis_type)
            elif file_type == "ELF" and self.elf_analyzer:
                return self._analyze_elf(file_path, analysis_type)
            else:
                # Fallback to basic analysis
                return self._analyze_basic(file_path, analysis_type)

        except Exception as e:
            logger.error(f"Binary analysis error: {e}")
            return {"success": False, "error": str(e)}

    def _detect_file_type(self, file_path: str) -> str:
        """Detect binary file type.

        Examines the magic number (file header) to identify the binary format.
        Supports PE (Windows), ELF (Linux/Unix), and Mach-O (macOS) formats.

        Args:
            file_path: Path to the binary file to analyze.

        Returns:
            File type identifier string: "PE" for Windows executables, "ELF"
                for Linux/Unix binaries, "MACHO" for macOS binaries, or
                "UNKNOWN" for unrecognized formats.
        """
        with open(file_path, "rb") as f:
            magic = f.read(4)

        if magic[:2] == b"MZ":
            return "PE"
        elif magic == b"\x7fELF":
            return "ELF"
        elif magic[:4] in [b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"]:
            return "MACHO"
        else:
            return "UNKNOWN"

    def _analyze_pe(self, file_path: str, analysis_type: str) -> dict[str, Any]:
        """Analyze PE file.

        Performs detailed analysis of Windows PE (Portable Executable) files,
        extracting critical licensing-related information including imported
        libraries, exported functions, section metadata, and embedded strings
        that may contain protection or activation routines.

        Args:
            file_path: Path to the PE binary file to analyze.
            analysis_type: Type of analysis to perform. Valid options are
                'basic', 'imports', 'exports', 'sections', 'strings', or
                'full' for comprehensive analysis.

        Returns:
            Dictionary containing analysis results with success status, file
                metadata (path, size, MD5, SHA256), PE characteristics
                (machine type, subsystem, entry point), and requested analysis
                data (imports, exports, sections, strings).

        Raises:
            No explicit exceptions raised; returns error dictionary if PE
                analyzer is unavailable or analysis fails.
        """
        if self.pe_analyzer is None:
            return {"success": False, "error": "PE analyzer not available"}

        pe_info: Any = self.pe_analyzer.analyze(file_path)

        if not pe_info:
            return {"success": False, "error": "Failed to analyze PE file"}

        result = {
            "success": True,
            "file_path": file_path,
            "file_type": "PE",
            "file_size": os.path.getsize(file_path),
            "md5": self._calculate_hash(file_path, "md5"),
            "sha256": self._calculate_hash(file_path, "sha256"),
            "machine": pe_info.get("machine", "Unknown"),
            "subsystem": pe_info.get("subsystem", "Unknown"),
            "characteristics": pe_info.get("characteristics", []),
            "timestamp": pe_info.get("timestamp", 0),
            "entry_point": pe_info.get("entry_point", 0),
        }

        if analysis_type in ["imports", "full"]:
            result["imports"] = self._format_imports(pe_info.get("imports", {}))
            result["import_count"] = sum(len(funcs) for funcs in pe_info.get("imports", {}).values())

        if analysis_type in ["exports", "full"]:
            exports = pe_info.get("exports", [])
            result["exports"] = exports
            result["export_count"] = len(exports)

        if analysis_type in ["sections", "full"]:
            sections = pe_info.get("sections", [])
            result["sections"] = self._format_sections(sections)
            result["section_count"] = len(sections)

        if analysis_type in ["strings", "full"]:
            result["strings"] = self._extract_strings(file_path)

        return result

    def _analyze_elf(self, file_path: str, analysis_type: str) -> dict[str, Any]:
        """Analyze ELF file.

        Performs detailed analysis of ELF (Executable and Linkable Format)
        binaries used on Linux and Unix systems. Extracts header information
        including architecture, endianness, file type, and embedded strings
        for licensing protection analysis.

        Args:
            file_path: Path to the ELF binary file to analyze.
            analysis_type: Type of analysis to perform. Valid options are
                'basic', 'imports', 'exports', 'sections', 'strings', or
                'full' for comprehensive analysis.

        Returns:
            Dictionary containing analysis results with success status, file
                metadata (path, size, MD5, SHA256), ELF characteristics
                (architecture bits, endianness, file type, machine type), and
                strings if requested.

        Raises:
            No explicit exceptions raised; returns error dictionary if file
                cannot be read or parsed.
        """
        result = {
            "success": True,
            "file_path": file_path,
            "file_type": "ELF",
            "file_size": os.path.getsize(file_path),
            "md5": self._calculate_hash(file_path, "md5"),
            "sha256": self._calculate_hash(file_path, "sha256"),
        }

        # Read ELF header
        with open(file_path, "rb") as f:
            # Skip magic
            f.seek(4)

            # Read class (32/64 bit)
            ei_class = struct.unpack("B", f.read(1))[0]
            result["bits"] = 64 if ei_class == 2 else 32

            # Read data encoding (endianness)
            ei_data = struct.unpack("B", f.read(1))[0]
            result["endian"] = "little" if ei_data == 1 else "big"

            # Seek to e_type
            f.seek(16)
            e_type = struct.unpack("<H" if ei_data == 1 else ">H", f.read(2))[0]
            type_map = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
            result["elf_type"] = type_map.get(e_type, "UNKNOWN")

            # Read machine
            e_machine = struct.unpack("<H" if ei_data == 1 else ">H", f.read(2))[0]
            machine_map = {3: "x86", 62: "x86_64", 40: "ARM", 183: "ARM64"}
            result["machine"] = machine_map.get(e_machine, f"Unknown ({e_machine})")

        if analysis_type in {"strings", "full"}:
            result["strings"] = self._extract_strings(file_path)

        return result

    def _analyze_basic(self, file_path: str, analysis_type: str) -> dict[str, Any]:
        """Basic binary analysis for unknown file types.

        Performs fallback analysis for binaries that don't match recognized
        formats. Calculates entropy, extracts strings, and attempts to identify
        file type through content-based heuristics. Useful for analyzing
        packed, compressed, or obfuscated protection schemes.

        Args:
            file_path: Path to the binary file to analyze.
            analysis_type: Type of analysis to perform. Valid options are
                'basic', 'imports', 'exports', 'sections', 'strings', or
                'full' for comprehensive analysis.

        Returns:
            Dictionary containing analysis results with success status, file
                metadata (path, size, MD5, SHA256), entropy measurement, and
                strings if requested. Includes file_type_hint based on content
                heuristics.

        Raises:
            No explicit exceptions raised; returns error dictionary if file
                cannot be read.
        """
        result = {
            "success": True,
            "file_path": file_path,
            "file_type": "UNKNOWN",
            "file_size": os.path.getsize(file_path),
            "md5": self._calculate_hash(file_path, "md5"),
            "sha256": self._calculate_hash(file_path, "sha256"),
            "entropy": self._calculate_entropy(file_path),
        }

        if analysis_type in {"strings", "full"}:
            result["strings"] = self._extract_strings(file_path)

        # Detect potential file type by content
        with open(file_path, "rb") as f:
            header = f.read(512)

        if b"This program cannot be run in DOS mode" in header:
            result["file_type_hint"] = "Likely PE executable"
        elif b"#!/" in header[:2]:
            result["file_type_hint"] = "Script file"
        elif header.startswith(b"PK"):
            result["file_type_hint"] = "ZIP/JAR/APK archive"

        return result

    def _calculate_hash(self, file_path: str, hash_type: str) -> str:
        """Calculate file hash.

        Computes cryptographic hash digests of binary files for integrity
        verification and identification. Uses efficient chunked reading to
        handle large files without excessive memory consumption.

        Args:
            file_path: Path to the binary file to hash.
            hash_type: Hash algorithm to use as string (e.g., 'md5',
                'sha256', 'sha1'). Must be supported by hashlib.

        Returns:
            Hexadecimal string representation of the hash digest.

        Raises:
            ValueError: If hash_type is not supported by hashlib.
            FileNotFoundError: If file_path does not exist.
            IOError: If file cannot be read.
        """
        hash_obj = hashlib.new(hash_type)
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy.

        Computes Shannon entropy as a measure of data randomness and
        compression. High entropy indicates packed, encrypted, or compressed
        data common in protected binaries. Low entropy suggests plaintext or
        structured data.

        Args:
            file_path: Path to the binary file to analyze.

        Returns:
            Shannon entropy value (float between 0.0 and 8.0) rounded to 3
                decimal places. Returns 0.0 for empty files.

        Raises:
            FileNotFoundError: If file_path does not exist.
            IOError: If file cannot be read.
        """
        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            return 0.0

        freq: dict[int, int] = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        entropy = 0.0
        data_len = len(data)

        for count in freq.values():
            if count > 0:
                freq_ratio = count / data_len
                entropy -= freq_ratio * math.log2(freq_ratio)

        return round(entropy, 3)

    def _format_imports(self, imports: dict[str, list[Any]]) -> dict[str, Any]:
        """Format import information.

        Organizes imported functions by library with truncation for display.
        Critical for identifying licensing-related API calls (e.g., Windows
        licensing APIs, vendor-specific activation libraries).

        Args:
            imports: Dictionary mapping library/DLL names to lists of imported
                function names.

        Returns:
            Dictionary with formatted import data keyed by library name,
                containing function_count, functions list (max 20 items), and
                truncation metadata if original list exceeds 20 functions.

        Raises:
            No explicit exceptions raised; returns empty dictionary for
                invalid input.
        """
        formatted: dict[str, Any] = {}
        for dll, functions in imports.items():
            formatted[dll] = {
                "function_count": len(functions),
                "functions": functions[:20],
            }
            if len(functions) > 20:
                formatted[dll]["truncated"] = True
                formatted[dll]["total_functions"] = len(functions)
        return formatted

    def _format_sections(self, sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Format section information.

        Organizes binary section metadata for analysis display. Useful for
        identifying obfuscated code sections, packed data, or protection
        routines that indicate licensing controls.

        Args:
            sections: List of section information dictionaries from binary
                file, each containing section properties.

        Returns:
            List of formatted section dictionaries with standardized keys:
                name, virtual_address (hex format), virtual_size, raw_size,
                entropy, and characteristics flags.

        Raises:
            No explicit exceptions raised; returns formatted list for
                invalid sections.
        """
        return [
            {
                "name": section.get("name", ""),
                "virtual_address": hex(section.get("virtual_address", 0)),
                "virtual_size": section.get("virtual_size", 0),
                "raw_size": section.get("raw_size", 0),
                "entropy": round(section.get("entropy", 0), 3),
                "characteristics": section.get("characteristics", []),
            }
            for section in sections
        ]

    def _extract_strings(self, file_path: str, min_length: int = 4) -> list[str]:
        """Extract printable strings from binary.

        Identifies human-readable strings in binary data using ASCII and
        UTF-16 pattern matching. Essential for finding licensing libraries,
        error messages, configuration strings, and protection mechanism
        identifiers.

        Args:
            file_path: Path to the binary file to extract strings from.
            min_length: Minimum length (in characters) of strings to extract.
                Defaults to 4. Strings shorter than this are ignored.

        Returns:
            List of unique extracted strings limited to 100 entries, with
                each string having maximum length of 200 characters. Supports
                both ASCII and UTF-16LE encoded strings.

        Raises:
            FileNotFoundError: If file_path does not exist.
            IOError: If file cannot be read.
        """
        strings: list[str] = []
        with open(file_path, "rb") as f:
            data = f.read()

        ascii_pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
        for match in re.finditer(ascii_pattern, data):
            string = match.group().decode("ascii", errors="ignore")
            if string and len(string) <= 200:
                strings.append(string)

        utf16_pattern = rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}"
        for match in re.finditer(utf16_pattern, data):
            try:
                string = match.group().decode("utf-16le", errors="ignore").strip("\x00")
                if string and len(string) <= 200:
                    strings.append(string)
            except Exception as e:
                logger.debug(f"Failed to decode UTF-16 string: {e}")

        return list(set(strings))[:100]


def create_binary_tool() -> BinaryAnalysisTool:
    """Factory function to create binary analysis tool.

    Provides a convenient factory pattern for instantiating the binary
    analysis tool with all analyzers initialized.

    Returns:
        A new instance of BinaryAnalysisTool with PE and ELF analyzers
            initialized.

    Raises:
        No explicit exceptions raised; gracefully handles missing analyzer
            dependencies.
    """
    return BinaryAnalysisTool()
