"""Binary Analysis Tool for LLM Integration

Provides AI models with binary analysis capabilities.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import os
import struct
from typing import Any, Dict, List

from ...utils.logger import get_logger

logger = get_logger(__name__)


class BinaryAnalysisTool:
    """LLM tool for binary analysis"""

    def __init__(self):
        """Initialize binary analysis tool"""
        self.pe_analyzer = None
        self.elf_analyzer = None
        self._init_analyzers()

    def _init_analyzers(self):
        """Initialize binary analyzers"""
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

    def get_tool_definition(self) -> Dict[str, Any]:
        """Get tool definition for LLM registration"""
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

    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute binary analysis"""
        file_path = kwargs.get("file_path")
        analysis_type = kwargs.get("analysis_type", "full")

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
        """Detect binary file type"""
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

    def _analyze_pe(self, file_path: str, analysis_type: str) -> Dict[str, Any]:
        """Analyze PE file"""
        pe_info = self.pe_analyzer.analyze(file_path)

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

    def _analyze_elf(self, file_path: str, analysis_type: str) -> Dict[str, Any]:
        """Analyze ELF file"""
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

        if analysis_type in ["strings", "full"]:
            result["strings"] = self._extract_strings(file_path)

        return result

    def _analyze_basic(self, file_path: str, analysis_type: str) -> Dict[str, Any]:
        """Basic binary analysis for unknown file types"""
        result = {
            "success": True,
            "file_path": file_path,
            "file_type": "UNKNOWN",
            "file_size": os.path.getsize(file_path),
            "md5": self._calculate_hash(file_path, "md5"),
            "sha256": self._calculate_hash(file_path, "sha256"),
            "entropy": self._calculate_entropy(file_path),
        }

        if analysis_type in ["strings", "full"]:
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
        """Calculate file hash"""
        hash_obj = hashlib.new(hash_type)
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy"""
        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            return 0.0

        # Calculate byte frequency
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        # Calculate entropy
        import math

        entropy = 0.0
        data_len = len(data)

        for count in freq.values():
            if count > 0:
                freq_ratio = count / data_len
                entropy -= freq_ratio * math.log2(freq_ratio)

        return round(entropy, 3)

    def _format_imports(self, imports: Dict[str, List]) -> Dict[str, Any]:
        """Format import information"""
        formatted = {}
        for dll, functions in imports.items():
            formatted[dll] = {
                "function_count": len(functions),
                "functions": functions[:20],  # Limit to first 20
            }
            if len(functions) > 20:
                formatted[dll]["truncated"] = True
                formatted[dll]["total_functions"] = len(functions)
        return formatted

    def _format_sections(self, sections: List[Dict]) -> List[Dict]:
        """Format section information"""
        formatted = []
        for section in sections:
            formatted.append(
                {
                    "name": section.get("name", ""),
                    "virtual_address": hex(section.get("virtual_address", 0)),
                    "virtual_size": section.get("virtual_size", 0),
                    "raw_size": section.get("raw_size", 0),
                    "entropy": round(section.get("entropy", 0), 3),
                    "characteristics": section.get("characteristics", []),
                }
            )
        return formatted

    def _extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary"""
        strings = []
        with open(file_path, "rb") as f:
            data = f.read()

        # Extract ASCII strings
        import re

        ascii_pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
        for match in re.finditer(ascii_pattern, data):
            string = match.group().decode("ascii", errors="ignore")
            if string and len(string) <= 200:  # Limit string length
                strings.append(string)

        # Extract UTF-16 strings (common in Windows binaries)
        utf16_pattern = rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}"
        for match in re.finditer(utf16_pattern, data):
            try:
                string = match.group().decode("utf-16le", errors="ignore").strip("\x00")
                if string and len(string) <= 200:
                    strings.append(string)
            except Exception as e:
                logger.debug(f"Failed to decode UTF-16 string: {e}")

        # Return unique strings, limited to first 100
        return list(set(strings))[:100]


def create_binary_tool() -> BinaryAnalysisTool:
    """Factory function to create binary analysis tool"""
    return BinaryAnalysisTool()
