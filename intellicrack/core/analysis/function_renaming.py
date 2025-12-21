"""Function renaming engine for license-related function identification.

This module provides intelligent function identification and renaming
capabilities for Intellicrack's binary analysis, specifically focused on
identifying licensing, registration, activation, and protection functions
in Windows PE binaries.

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

import logging
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class FunctionType(Enum):
    """Categories of functions related to licensing."""

    LICENSE_VALIDATION = "license_validation"
    SERIAL_VALIDATION = "serial_validation"
    REGISTRATION = "registration"
    ACTIVATION = "activation"
    TRIAL_CHECK = "trial_check"
    EXPIRATION_CHECK = "expiration_check"
    HARDWARE_ID = "hardware_id"
    ONLINE_VALIDATION = "online_validation"
    CRYPTOGRAPHIC = "cryptographic"
    UNKNOWN = "unknown"


@dataclass
class FunctionSignature:
    """Represents a function signature in the binary."""

    address: int
    name: str
    size: int
    calls: list[int] = field(default_factory=list)
    called_by: list[int] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)


@dataclass
class FunctionRenameResult:
    """Result of function identification and renaming."""

    address: int
    original_name: str
    suggested_name: str
    function_type: FunctionType
    confidence: float
    evidence: list[str] = field(default_factory=list)


class FunctionRenamingEngine:
    """Engine for identifying and renaming license-related functions."""

    LICENSE_PATTERNS = {
        FunctionType.LICENSE_VALIDATION: [
            r"license",
            r"lic[_\s]?check",
            r"validate[_\s]?license",
            r"check[_\s]?license",
            r"verify[_\s]?license",
            r"is[_\s]?licensed",
            r"has[_\s]?license",
        ],
        FunctionType.SERIAL_VALIDATION: [
            r"serial",
            r"product[_\s]?key",
            r"cd[_\s]?key",
            r"validate[_\s]?serial",
            r"check[_\s]?serial",
            r"verify[_\s]?key",
            r"key[_\s]?check",
        ],
        FunctionType.REGISTRATION: [
            r"register",
            r"registration",
            r"reg[_\s]?check",
            r"is[_\s]?registered",
            r"check[_\s]?reg",
        ],
        FunctionType.ACTIVATION: [
            r"activate",
            r"activation",
            r"is[_\s]?activated",
            r"check[_\s]?activation",
            r"online[_\s]?activation",
        ],
        FunctionType.TRIAL_CHECK: [
            r"trial",
            r"demo",
            r"eval",
            r"is[_\s]?trial",
            r"check[_\s]?trial",
            r"trial[_\s]?expired",
        ],
        FunctionType.EXPIRATION_CHECK: [
            r"expir",
            r"expire[ds]?",
            r"check[_\s]?expir",
            r"is[_\s]?expired",
            r"get[_\s]?expir",
            r"valid[_\s]?until",
        ],
        FunctionType.HARDWARE_ID: [
            r"hwid",
            r"hardware[_\s]?id",
            r"machine[_\s]?id",
            r"computer[_\s]?id",
            r"get[_\s]?hwid",
            r"fingerprint",
        ],
        FunctionType.ONLINE_VALIDATION: [
            r"online[_\s]?check",
            r"server[_\s]?check",
            r"validate[_\s]?online",
            r"cloud[_\s]?check",
            r"remote[_\s]?valid",
        ],
        FunctionType.CRYPTOGRAPHIC: [
            r"decrypt",
            r"encrypt",
            r"hash",
            r"sha[12]",
            r"md5",
            r"rsa",
            r"aes",
            r"verify[_\s]?signature",
        ],
    }

    IMPORT_INDICATORS = {
        FunctionType.LICENSE_VALIDATION: [
            "RegOpenKeyEx",
            "RegQueryValueEx",
            "RegGetValue",
        ],
        FunctionType.SERIAL_VALIDATION: [
            "CryptStringToBinary",
            "CryptBinaryToString",
        ],
        FunctionType.HARDWARE_ID: [
            "GetVolumeInformation",
            "GetComputerName",
            "GetAdaptersInfo",
        ],
        FunctionType.ONLINE_VALIDATION: [
            "InternetOpen",
            "InternetConnect",
            "HttpSendRequest",
            "WinHttpOpen",
        ],
        FunctionType.CRYPTOGRAPHIC: [
            "CryptAcquireContext",
            "CryptCreateHash",
            "CryptHashData",
            "CryptVerifySignature",
        ],
    }

    def __init__(self, binary_path: str | Path) -> None:
        """Initialize the function renaming engine.

        Args:
            binary_path: Path to the binary to analyze
        """
        self.binary_path = Path(binary_path)
        self.logger = logging.getLogger(__name__)
        self.functions: dict[int, FunctionSignature] = {}
        self.pe_data: bytes = b""
        self.image_base: int = 0
        self.code_section_start: int = 0
        self.code_section_size: int = 0

        if self.binary_path.exists():
            self._load_binary()

    def _load_binary(self) -> None:
        """Load binary and extract basic PE information."""
        try:
            with open(self.binary_path, "rb") as f:
                self.pe_data = f.read()

            if len(self.pe_data) < 64 or self.pe_data[:2] != b"MZ":
                raise ValueError("Invalid PE file")

            pe_offset = struct.unpack("<I", self.pe_data[0x3C:0x40])[0]
            if pe_offset >= len(self.pe_data) or self.pe_data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
                raise ValueError("Invalid PE signature")

            optional_header_offset = pe_offset + 24
            magic = struct.unpack("<H", self.pe_data[optional_header_offset : optional_header_offset + 2])[0]

            if magic == 0x10B:
                self.image_base = struct.unpack("<I", self.pe_data[optional_header_offset + 28 : optional_header_offset + 32])[0]
            elif magic == 0x20B:
                self.image_base = struct.unpack("<Q", self.pe_data[optional_header_offset + 24 : optional_header_offset + 32])[0]
            else:
                self.image_base = 0x400000

            num_sections = struct.unpack("<H", self.pe_data[pe_offset + 6 : pe_offset + 8])[0]
            optional_header_size = struct.unpack("<H", self.pe_data[pe_offset + 20 : pe_offset + 22])[0]

            section_table_offset = pe_offset + 24 + optional_header_size
            for i in range(num_sections):
                section_offset = section_table_offset + (i * 40)
                if section_offset + 40 > len(self.pe_data):
                    break

                name = self.pe_data[section_offset : section_offset + 8].rstrip(b"\x00")
                virtual_size = struct.unpack("<I", self.pe_data[section_offset + 8 : section_offset + 12])[0]
                struct.unpack("<I", self.pe_data[section_offset + 12 : section_offset + 16])[0]
                raw_size = struct.unpack("<I", self.pe_data[section_offset + 16 : section_offset + 20])[0]
                raw_address = struct.unpack("<I", self.pe_data[section_offset + 20 : section_offset + 24])[0]

                if name in (b".text", b"CODE", b".code"):
                    self.code_section_start = raw_address
                    self.code_section_size = min(virtual_size, raw_size)
                    break

        except Exception:
            self.logger.exception("Failed to load binary")
            raise

    def scan_for_functions(self) -> dict[int, FunctionSignature]:
        """Scan binary for function prologs and build function signatures.

        Returns:
            Dictionary mapping function addresses to signatures
        """
        if not self.pe_data or self.code_section_size == 0:
            return {}

        code_start = self.code_section_start
        code_end = code_start + self.code_section_size

        code_end = min(code_end, len(self.pe_data))

        code_data = self.pe_data[code_start:code_end]
        functions: dict[int, FunctionSignature] = {}

        prolog_patterns = [
            b"\x55\x8b\xec",
            b"\x55\x89\xe5",
            b"\x40\x55",
            b"\x48\x89\x5c\x24",
            b"\x48\x89\x4c\x24",
            b"\x48\x83\xec",
            b"\x40\x53",
            b"\x40\x57",
        ]

        for pattern in prolog_patterns:
            offset = 0
            while offset < len(code_data) - len(pattern):
                idx = code_data.find(pattern, offset)
                if idx == -1:
                    break

                func_addr = self.image_base + self.code_section_start + idx
                if func_addr not in functions:
                    functions[func_addr] = FunctionSignature(
                        address=func_addr,
                        name=f"sub_{func_addr:X}",
                        size=0,
                    )

                offset = idx + 1

        sorted_addrs = sorted(functions.keys())
        for i, addr in enumerate(sorted_addrs):
            if i < len(sorted_addrs) - 1:
                functions[addr].size = sorted_addrs[i + 1] - addr
            else:
                functions[addr].size = (self.image_base + code_end) - addr

        self.functions = functions
        return functions

    def extract_function_strings(self, func_addr: int, max_distance: int = 1024) -> list[str]:
        """Extract strings referenced near a function.

        Args:
            func_addr: Function address
            max_distance: Maximum distance to search for strings

        Returns:
            List of strings found near the function
        """
        if func_addr not in self.functions:
            return []

        func = self.functions[func_addr]
        file_offset = func_addr - self.image_base

        if file_offset < 0 or file_offset >= len(self.pe_data):
            return []

        search_start = max(0, file_offset - max_distance)
        search_end = min(len(self.pe_data), file_offset + func.size + max_distance)

        search_data = self.pe_data[search_start:search_end]
        strings = []
        min_length = 4
        current_string = bytearray()

        for byte in search_data:
            if 32 <= byte <= 126:
                current_string.append(byte)
            else:
                if len(current_string) >= min_length:
                    try:
                        s = current_string.decode("ascii", errors="ignore")
                        if any(c.isalpha() for c in s):
                            strings.append(s)
                    except UnicodeDecodeError:
                        pass
                current_string = bytearray()

        if len(current_string) >= min_length:
            try:
                s = current_string.decode("ascii", errors="ignore")
                if any(c.isalpha() for c in s):
                    strings.append(s)
            except UnicodeDecodeError:
                pass

        func.strings = strings[:50]
        return strings[:50]

    def identify_function_type(
        self,
        func_addr: int,
        custom_patterns: dict[FunctionType, list[str]] | None = None,
    ) -> FunctionRenameResult:
        """Identify function type based on strings and patterns.

        Args:
            func_addr: Function address
            custom_patterns: Optional custom pattern dictionary

        Returns:
            Function rename result with suggested name and type
        """
        if func_addr not in self.functions:
            return FunctionRenameResult(
                address=func_addr,
                original_name=f"sub_{func_addr:X}",
                suggested_name=f"sub_{func_addr:X}",
                function_type=FunctionType.UNKNOWN,
                confidence=0.0,
            )

        func = self.functions[func_addr]
        patterns = custom_patterns or self.LICENSE_PATTERNS

        if not func.strings:
            self.extract_function_strings(func_addr)

        all_text = " ".join(func.strings).lower()
        scores: dict[FunctionType, float] = dict.fromkeys(FunctionType, 0.0)
        evidence: dict[FunctionType, list[str]] = {ft: [] for ft in FunctionType}

        for func_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                try:
                    if matches := re.findall(pattern, all_text, re.IGNORECASE):
                        scores[func_type] += len(matches) * 10.0
                        evidence[func_type].append(f"Pattern '{pattern}' matched {len(matches)} times")
                except re.error:
                    continue

        for func_type, imports in self.IMPORT_INDICATORS.items():
            for import_name in imports:
                if import_name.lower() in all_text:
                    scores[func_type] += 15.0
                    evidence[func_type].append(f"Import '{import_name}' detected")

        best_type = max(scores, key=scores.get)
        confidence = min(scores[best_type] / 100.0, 1.0)

        if confidence < 0.2:
            best_type = FunctionType.UNKNOWN

        suggested_name = self._generate_function_name(best_type, func_addr)

        return FunctionRenameResult(
            address=func_addr,
            original_name=func.name,
            suggested_name=suggested_name,
            function_type=best_type,
            confidence=confidence,
            evidence=evidence[best_type],
        )

    def _generate_function_name(self, func_type: FunctionType, func_addr: int) -> str:
        """Generate suggested function name based on type.

        Args:
            func_type: Identified function type
            func_addr: Function address

        Returns:
            Suggested function name
        """
        type_prefixes = {
            FunctionType.LICENSE_VALIDATION: "check_license",
            FunctionType.SERIAL_VALIDATION: "validate_serial",
            FunctionType.REGISTRATION: "check_registration",
            FunctionType.ACTIVATION: "check_activation",
            FunctionType.TRIAL_CHECK: "check_trial",
            FunctionType.EXPIRATION_CHECK: "check_expiration",
            FunctionType.HARDWARE_ID: "get_hwid",
            FunctionType.ONLINE_VALIDATION: "validate_online",
            FunctionType.CRYPTOGRAPHIC: "crypto_function",
            FunctionType.UNKNOWN: "sub",
        }

        prefix = type_prefixes.get(func_type, "sub")
        return f"{prefix}_{func_addr:X}"

    def batch_identify_functions(
        self,
        filter_func: Callable[[FunctionSignature], bool] | None = None,
        min_confidence: float = 0.2,
    ) -> list[FunctionRenameResult]:
        """Identify all functions in batch.

        Args:
            filter_func: Optional filter to select specific functions
            min_confidence: Minimum confidence threshold

        Returns:
            List of rename results for all identified functions
        """
        if not self.functions:
            self.scan_for_functions()

        results = []
        for func_addr, func_sig in self.functions.items():
            if filter_func and not filter_func(func_sig):
                continue

            result = self.identify_function_type(func_addr)
            if result.confidence >= min_confidence:
                results.append(result)

        return sorted(results, key=lambda r: r.confidence, reverse=True)

    def find_license_functions(
        self,
        function_types: list[FunctionType] | None = None,
        min_confidence: float = 0.3,
    ) -> list[FunctionRenameResult]:
        """Find functions matching specific license-related types.

        Args:
            function_types: List of function types to search for
            min_confidence: Minimum confidence threshold

        Returns:
            List of matching function rename results
        """
        if function_types is None:
            function_types = [
                FunctionType.LICENSE_VALIDATION,
                FunctionType.SERIAL_VALIDATION,
                FunctionType.REGISTRATION,
                FunctionType.ACTIVATION,
            ]

        all_results = self.batch_identify_functions(min_confidence=min_confidence)
        return [r for r in all_results if r.function_type in function_types]

    def export_rename_script(
        self,
        results: list[FunctionRenameResult],
        output_path: str | Path,
        format: str = "ida",
    ) -> bool:
        """Export rename results as a script for reverse engineering tools.

        Args:
            results: List of rename results
            output_path: Path to output script
            format: Script format ('ida', 'ghidra', 'radare2')

        Returns:
            True if successful
        """
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            if format == "ida":
                script = self._generate_ida_script(results)
            elif format == "ghidra":
                script = self._generate_ghidra_script(results)
            elif format == "radare2":
                script = self._generate_radare2_script(results)
            else:
                raise ValueError(f"Unknown format: {format}")

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(script)

            return True

        except Exception:
            self.logger.exception("Failed to export rename script")
            return False

    def _generate_ida_script(self, results: list[FunctionRenameResult]) -> str:
        """Generate IDA Pro Python script for renaming."""
        lines = [
            "import idc",
            "import idaapi",
            "",
            "def rename_functions():",
        ]

        for result in results:
            lines.extend((
                f'    idc.set_name(0x{result.address:X}, "{result.suggested_name}", idc.SN_NOWARN)',
                f'    idc.set_func_cmt(0x{result.address:X}, "Type: {result.function_type.value}, Confidence: {result.confidence:.2f}", 1)',
            ))
        lines.extend((
            "",
            "if __name__ == '__main__':",
            "    rename_functions()",
            f'    print("Renamed {len(results)} functions")',
        ))
        return "\n".join(lines)

    def _generate_ghidra_script(self, results: list[FunctionRenameResult]) -> str:
        """Generate Ghidra Python script for renaming."""
        lines = [
            "from ghidra.program.model.symbol import SourceType",
            "",
            "def rename_functions():",
            "    fm = currentProgram.getFunctionManager()",
            "    listing = currentProgram.getListing()",
            "",
        ]

        for result in results:
            lines.extend((
                f"    addr = toAddr(0x{result.address:X})",
                "    func = fm.getFunctionAt(addr)",
                "    if func:",
                f'        func.setName("{result.suggested_name}", SourceType.USER_DEFINED)',
                f'        func.setComment("Type: {result.function_type.value}, Confidence: {result.confidence:.2f}")',
                "",
            ))
        lines.extend((
            "if __name__ == '__main__':",
            "    rename_functions()",
            f'    println("Renamed {len(results)} functions")',
        ))
        return "\n".join(lines)

    def _generate_radare2_script(self, results: list[FunctionRenameResult]) -> str:
        """Generate radare2 script for renaming."""
        lines = []

        for result in results:
            lines.extend((
                f"afn {result.suggested_name} 0x{result.address:X}",
                f"CC Type: {result.function_type.value}, Confidence: {result.confidence:.2f} @ 0x{result.address:X}",
            ))
        return "\n".join(lines)

    def get_statistics(self) -> dict[str, Any]:
        """Get statistics about identified functions.

        Returns:
            Dictionary containing statistics
        """
        if not self.functions:
            return {}

        results = self.batch_identify_functions(min_confidence=0.0)

        type_counts: dict[str, int] = {}
        for result in results:
            type_name = result.function_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        high_confidence = sum(r.confidence >= 0.7 for r in results)
        medium_confidence = sum(0.4 <= r.confidence < 0.7 for r in results)
        low_confidence = sum(r.confidence < 0.4 for r in results)

        return {
            "total_functions": len(self.functions),
            "identified_functions": len(results),
            "function_types": type_counts,
            "confidence_distribution": {
                "high (>= 0.7)": high_confidence,
                "medium (0.4-0.7)": medium_confidence,
                "low (< 0.4)": low_confidence,
            },
        }
