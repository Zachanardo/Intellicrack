"""Production-grade PE Export Table Analyzer for license cracking.

Analyzes exported functions from PE DLLs to identify license validation,
activation, and registration functions that are potential bypass targets.

Provides comprehensive export table parsing including:
- Export directory structure parsing
- Function name and ordinal resolution
- Forwarded export detection and parsing
- License-related export identification
- C++ name demangling
- Export address calculation
- API pattern analysis

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import logging
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class ExportEntry:
    """Represents a single exported function from a PE binary."""

    name: str
    ordinal: int
    rva: int
    address: int
    is_forwarded: bool = False
    forward_name: str | None = None
    forward_dll: str | None = None
    forward_function: str | None = None


@dataclass
class ForwardedExport:
    """Represents a forwarded export (redirects to another DLL)."""

    original_name: str
    target_dll: str
    target_function: str
    original_ordinal: int


class ExportAnalyzer:
    """Analyzes PE export tables to identify license validation functions.

    This analyzer extracts and categorizes exported functions from PE DLLs,
    with special focus on identifying license validation, activation, and
    registration functions that are primary targets for bypass operations.
    """

    LICENSE_KEYWORDS: list[str] = [
        "license",
        "licence",
        "activation",
        "activate",
        "register",
        "registration",
        "serial",
        "key",
        "validation",
        "validate",
        "verify",
        "check",
        "auth",
        "trial",
        "demo",
        "expire",
        "deactivate",
        "unlock",
        "product",
        "subscription",
    ]

    CRYPTO_KEYWORDS: list[str] = ["crypt", "encrypt", "decrypt", "hash", "sign", "verify", "aes", "rsa", "sha", "md5", "hmac", "pbkdf"]

    REGISTRY_KEYWORDS: list[str] = ["reg", "registry", "hkey", "hklm", "hkcu"]

    NETWORK_KEYWORDS: list[str] = ["socket", "connect", "send", "recv", "http", "https", "internet", "url", "download", "upload", "wsa"]

    def __init__(self, binary_path: str) -> None:
        """Initialize export analyzer.

        Args:
            binary_path: Path to PE binary to analyze

        Raises:
            FileNotFoundError: If binary file doesn't exist
        """
        self.binary_path: str = binary_path

        if not Path(binary_path).exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self.exports: list[ExportEntry] = []
        self.export_directory: dict[str, Any] | None = None
        self.base_address: int = 0
        self.image_size: int = 0
        self.pe_data: bytes = b""

        self.logger = logging.getLogger(__name__)

    def analyze(self) -> None:
        """Parse PE binary and extract all export information."""
        try:
            with open(self.binary_path, "rb") as f:
                self.pe_data = f.read()

            if not self._validate_pe_format():
                raise ValueError("Invalid PE format")

            self._parse_pe_headers()
            self._parse_export_directory()
            self._parse_export_functions()

        except Exception as e:
            self.logger.exception("Export analysis failed: %s", e)
            raise

    def _validate_pe_format(self) -> bool:
        """Validate that binary is a valid PE file."""
        if len(self.pe_data) < 64:
            return False

        if self.pe_data[:2] != b"MZ":
            return False

        pe_offset: int = struct.unpack("<I", self.pe_data[0x3C:0x40])[0]

        if pe_offset + 4 > len(self.pe_data):
            return False

        return self.pe_data[pe_offset : pe_offset + 4] == b"PE\x00\x00"

    def _parse_pe_headers(self) -> None:
        """Parse PE headers to extract base address and image size."""
        pe_offset: int = struct.unpack("<I", self.pe_data[0x3C:0x40])[0]

        coff_offset: int = pe_offset + 4
        struct.unpack("<H", self.pe_data[coff_offset : coff_offset + 2])[0]
        struct.unpack("<H", self.pe_data[coff_offset + 16 : coff_offset + 18])[0]

        optional_header_offset: int = coff_offset + 20
        magic: int = struct.unpack("<H", self.pe_data[optional_header_offset : optional_header_offset + 2])[0]

        if magic == 0x010B:
            self.base_address = struct.unpack("<I", self.pe_data[optional_header_offset + 28 : optional_header_offset + 32])[0]
            self.image_size = struct.unpack("<I", self.pe_data[optional_header_offset + 56 : optional_header_offset + 60])[0]
        elif magic == 0x020B:
            self.base_address = struct.unpack("<Q", self.pe_data[optional_header_offset + 24 : optional_header_offset + 32])[0]
            self.image_size = struct.unpack("<I", self.pe_data[optional_header_offset + 56 : optional_header_offset + 60])[0]
        else:
            raise ValueError(f"Unknown PE magic: {hex(magic)}")

    def _parse_export_directory(self) -> None:
        """Parse export directory from PE optional header."""
        pe_offset: int = struct.unpack("<I", self.pe_data[0x3C:0x40])[0]
        coff_offset: int = pe_offset + 4
        optional_header_offset: int = coff_offset + 20
        magic: int = struct.unpack("<H", self.pe_data[optional_header_offset : optional_header_offset + 2])[0]

        if magic == 0x010B:
            data_directory_offset: int = optional_header_offset + 96
        elif magic == 0x020B:
            data_directory_offset: int = optional_header_offset + 112
        else:
            return

        export_dir_rva: int = struct.unpack("<I", self.pe_data[data_directory_offset : data_directory_offset + 4])[0]
        export_dir_size: int = struct.unpack("<I", self.pe_data[data_directory_offset + 4 : data_directory_offset + 8])[0]

        if export_dir_rva == 0 or export_dir_size == 0:
            self.export_directory = None
            return

        export_dir_offset: int = self._rva_to_offset(export_dir_rva)

        if export_dir_offset == 0:
            return

        try:
            export_data: bytes = self.pe_data[export_dir_offset : export_dir_offset + 40]

            if len(export_data) < 40:
                return

            self.export_directory = {
                "characteristics": struct.unpack("<I", export_data[:4])[0],
                "timestamp": struct.unpack("<I", export_data[4:8])[0],
                "major_version": struct.unpack("<H", export_data[8:10])[0],
                "minor_version": struct.unpack("<H", export_data[10:12])[0],
                "name_rva": struct.unpack("<I", export_data[12:16])[0],
                "ordinal_base": struct.unpack("<I", export_data[16:20])[0],
                "num_functions": struct.unpack("<I", export_data[20:24])[0],
                "num_names": struct.unpack("<I", export_data[24:28])[0],
                "functions_rva": struct.unpack("<I", export_data[28:32])[0],
                "names_rva": struct.unpack("<I", export_data[32:36])[0],
                "ordinals_rva": struct.unpack("<I", export_data[36:40])[0],
                "rva": export_dir_rva,
                "size": export_dir_size,
            }

        except Exception as e:
            self.logger.exception("Failed to parse export directory: %s", e)
            self.export_directory = None

    def _parse_export_functions(self) -> None:
        """Parse all exported functions from export directory."""
        if not self.export_directory:
            return

        try:
            num_functions: int = self.export_directory["num_functions"]
            num_names: int = self.export_directory["num_names"]
            functions_rva: int = self.export_directory["functions_rva"]
            names_rva: int = self.export_directory["names_rva"]
            ordinals_rva: int = self.export_directory["ordinals_rva"]
            ordinal_base: int = self.export_directory["ordinal_base"]

            functions_offset: int = self._rva_to_offset(functions_rva)
            names_offset: int = self._rva_to_offset(names_rva)
            ordinals_offset: int = self._rva_to_offset(ordinals_rva)

            if functions_offset == 0:
                return

            function_rvas: list[int] = []
            for i in range(num_functions):
                rva_data: bytes = self.pe_data[functions_offset + (i * 4) : functions_offset + (i * 4) + 4]
                if len(rva_data) == 4:
                    function_rvas.append(struct.unpack("<I", rva_data)[0])

            name_ptrs: list[int] = []
            if names_offset != 0:
                for i in range(num_names):
                    ptr_data: bytes = self.pe_data[names_offset + (i * 4) : names_offset + (i * 4) + 4]
                    if len(ptr_data) == 4:
                        name_ptrs.append(struct.unpack("<I", ptr_data)[0])

            ordinal_values: list[int] = []
            if ordinals_offset != 0:
                for i in range(num_names):
                    ord_data: bytes = self.pe_data[ordinals_offset + (i * 2) : ordinals_offset + (i * 2) + 2]
                    if len(ord_data) == 2:
                        ordinal_values.append(struct.unpack("<H", ord_data)[0])

            name_to_ordinal: dict[int, str] = {}
            for i in range(num_names):
                if i < len(name_ptrs) and i < len(ordinal_values):
                    name_offset: int = self._rva_to_offset(name_ptrs[i])
                    if name_offset != 0:
                        name: str = self._read_string(name_offset)
                        name_to_ordinal[ordinal_values[i]] = name

            for func_idx in range(num_functions):
                if func_idx >= len(function_rvas):
                    continue

                func_rva: int = function_rvas[func_idx]

                if func_rva == 0:
                    continue

                ordinal: int = ordinal_base + func_idx
                name: str = name_to_ordinal.get(func_idx, "")

                is_forwarded: bool = False
                forward_name: str | None = None
                forward_dll: str | None = None
                forward_function: str | None = None

                if self.export_directory and self._is_forwarded_export(func_rva):
                    is_forwarded = True
                    forward_offset: int = self._rva_to_offset(func_rva)
                    if forward_offset != 0:
                        forward_name = self._read_string(forward_offset)
                        if "." in forward_name:
                            parts: list[str] = forward_name.split(".", 1)
                            forward_dll = parts[0]
                            forward_function = parts[1]

                export_entry = ExportEntry(
                    name=name,
                    ordinal=ordinal,
                    rva=func_rva,
                    address=0 if is_forwarded else self.base_address + func_rva,
                    is_forwarded=is_forwarded,
                    forward_name=forward_name,
                    forward_dll=forward_dll,
                    forward_function=forward_function,
                )

                self.exports.append(export_entry)

        except Exception as e:
            self.logger.exception("Failed to parse export functions: %s", e)

    def _is_forwarded_export(self, rva: int) -> bool:
        """Check if export RVA points to forwarded export string."""
        if not self.export_directory:
            return False

        export_dir_rva: int = self.export_directory["rva"]
        export_dir_size: int = self.export_directory["size"]

        return export_dir_rva <= rva < (export_dir_rva + export_dir_size)

    def _rva_to_offset(self, rva: int) -> int:
        """Convert RVA to file offset using section table."""
        if rva in {0, 4294967295}:
            return 0

        pe_offset: int = struct.unpack("<I", self.pe_data[0x3C:0x40])[0]
        coff_offset: int = pe_offset + 4
        num_sections: int = struct.unpack("<H", self.pe_data[coff_offset + 2 : coff_offset + 4])[0]
        optional_header_size: int = struct.unpack("<H", self.pe_data[coff_offset + 16 : coff_offset + 18])[0]

        section_table_offset: int = coff_offset + 20 + optional_header_size

        for i in range(num_sections):
            section_offset: int = section_table_offset + (i * 40)

            if section_offset + 40 > len(self.pe_data):
                continue

            virtual_address: int = struct.unpack("<I", self.pe_data[section_offset + 12 : section_offset + 16])[0]
            virtual_size: int = struct.unpack("<I", self.pe_data[section_offset + 8 : section_offset + 12])[0]
            if virtual_address <= rva < (virtual_address + virtual_size):
                raw_data_ptr: int = struct.unpack("<I", self.pe_data[section_offset + 20 : section_offset + 24])[0]

                offset: int = raw_data_ptr + (rva - virtual_address)
                return offset if offset < len(self.pe_data) else 0
        return 0

    def _read_string(self, offset: int) -> str:
        """Read null-terminated ASCII string from offset."""
        if offset >= len(self.pe_data):
            return ""

        end: int = self.pe_data.find(b"\x00", offset)
        if end == -1:
            return ""

        try:
            return self.pe_data[offset:end].decode("ascii", errors="ignore")
        except Exception:
            return ""

    def get_export_by_name(self, name: str) -> ExportEntry | None:
        """Get export entry by function name."""
        return next((export for export in self.exports if export.name == name), None)

    def get_export_by_ordinal(self, ordinal: int) -> ExportEntry | None:
        """Get export entry by ordinal."""
        return next((export for export in self.exports if export.ordinal == ordinal), None)

    def get_license_related_exports(self) -> list[ExportEntry]:
        """Identify exports related to license validation and activation."""
        license_exports: list[ExportEntry] = []

        for export in self.exports:
            if not export.name:
                continue

            name_lower: str = export.name.lower()

            if any(keyword in name_lower for keyword in self.LICENSE_KEYWORDS):
                license_exports.append(export)

        return license_exports

    def categorize_license_exports(self) -> dict[str, list[ExportEntry]]:
        """Categorize license-related exports by function type."""
        categories: dict[str, list[ExportEntry]] = {
            "validation": [],
            "activation": [],
            "registration": [],
            "serial": [],
            "trial": [],
            "deactivation": [],
        }

        license_exports: list[ExportEntry] = self.get_license_related_exports()

        for export in license_exports:
            name_lower: str = export.name.lower()

            if any(kw in name_lower for kw in ["validate", "verify", "check"]):
                categories["validation"].append(export)

            if any(kw in name_lower for kw in ["activate", "activation"]):
                categories["activation"].append(export)

            if any(kw in name_lower for kw in ["register", "registration"]):
                categories["registration"].append(export)

            if any(kw in name_lower for kw in ["serial", "key"]):
                categories["serial"].append(export)

            if any(kw in name_lower for kw in ["trial", "demo", "expire"]):
                categories["trial"].append(export)

            if any(kw in name_lower for kw in ["deactivate", "unregister"]):
                categories["deactivation"].append(export)

        return categories

    def get_crypto_related_exports(self) -> list[ExportEntry]:
        """Identify exports related to cryptographic operations."""
        crypto_exports: list[ExportEntry] = []

        for export in self.exports:
            if not export.name:
                continue

            name_lower: str = export.name.lower()

            if any(keyword in name_lower for keyword in self.CRYPTO_KEYWORDS):
                crypto_exports.append(export)

        return crypto_exports

    def get_registry_related_exports(self) -> list[ExportEntry]:
        """Identify exports related to registry operations."""
        registry_exports: list[ExportEntry] = []

        for export in self.exports:
            if not export.name:
                continue

            name_lower: str = export.name.lower()

            if any(keyword in name_lower for keyword in self.REGISTRY_KEYWORDS):
                registry_exports.append(export)

        return registry_exports

    def get_network_related_exports(self) -> list[ExportEntry]:
        """Identify exports related to network operations."""
        network_exports: list[ExportEntry] = []

        for export in self.exports:
            if not export.name:
                continue

            name_lower: str = export.name.lower()

            if any(keyword in name_lower for keyword in self.NETWORK_KEYWORDS):
                network_exports.append(export)

        return network_exports

    def is_mangled_name(self, name: str) -> bool:
        """Check if export name is C++ mangled."""
        if not name:
            return False

        if name.startswith("?") and "@@" in name:
            return True

        return bool(name.startswith("_Z"))

    def demangle_name(self, name: str) -> str:
        """Attempt to demangle C++ export name.

        This is a simplified demangler for MSVC name mangling.
        For production use, integrate with undname or similar tools.
        """
        if not self.is_mangled_name(name):
            return name

        if name.startswith("?"):
            if parts := name.split("@@"):
                base_name: str = parts[0][1:]

                return base_name

        return name

    def search_exports(self, search_term: str) -> list[ExportEntry]:
        """Search exports by name substring."""
        search_lower: str = search_term.lower()

        results: list[ExportEntry] = [export for export in self.exports if export.name and search_lower in export.name.lower()]
        return results

    def filter_exports_by_pattern(self, pattern: str) -> list[ExportEntry]:
        """Filter exports matching regex pattern."""
        results: list[ExportEntry] = []

        try:
            regex = re.compile(pattern)

            results.extend(export for export in self.exports if export.name and regex.search(export.name))
        except re.error as e:
            self.logger.exception("Invalid regex pattern: %s", e)

        return results

    def get_export_statistics(self) -> dict[str, Any]:
        """Generate comprehensive export statistics."""
        stats: dict[str, Any] = {
            "total_exports": len(self.exports),
            "named_exports": len([e for e in self.exports if e.name]),
            "ordinal_only_exports": len([e for e in self.exports if not e.name]),
            "forwarded_exports": len([e for e in self.exports if e.is_forwarded]),
            "ordinal_range": {
                "min": min((e.ordinal for e in self.exports), default=0),
                "max": max((e.ordinal for e in self.exports), default=0),
            },
            "license_related": len(self.get_license_related_exports()),
            "crypto_related": len(self.get_crypto_related_exports()),
            "registry_related": len(self.get_registry_related_exports()),
            "network_related": len(self.get_network_related_exports()),
            "mangled_names": len([e for e in self.exports if e.name and self.is_mangled_name(e.name)]),
        }

        return stats

    def get_export_summary(self) -> dict[str, Any]:
        """Generate export summary with API categorization."""
        summary: dict[str, Any] = {
            "total_exports": len(self.exports),
            "dll_name": Path(self.binary_path).name,
            "base_address": hex(self.base_address),
            "api_categories": {
                "file_operations": 0,
                "memory_operations": 0,
                "process_operations": 0,
                "registry_operations": 0,
                "network_operations": 0,
                "cryptographic_operations": 0,
                "license_operations": 0,
            },
        }

        for export in self.exports:
            if not export.name:
                continue

            name_lower: str = export.name.lower()

            if any(kw in name_lower for kw in ["file", "read", "write", "create", "open", "close"]):
                summary["api_categories"]["file_operations"] += 1

            if any(kw in name_lower for kw in ["alloc", "free", "heap", "virtual", "memory"]):
                summary["api_categories"]["memory_operations"] += 1

            if any(kw in name_lower for kw in ["process", "thread", "module", "dll"]):
                summary["api_categories"]["process_operations"] += 1

            if any(kw in name_lower for kw in ["reg", "registry", "key"]):
                summary["api_categories"]["registry_operations"] += 1

            if any(kw in name_lower for kw in ["socket", "send", "recv", "connect", "internet"]):
                summary["api_categories"]["network_operations"] += 1

            if any(kw in name_lower for kw in ["crypt", "hash", "encrypt", "decrypt"]):
                summary["api_categories"]["cryptographic_operations"] += 1

            if any(kw in name_lower for kw in self.LICENSE_KEYWORDS):
                summary["api_categories"]["license_operations"] += 1

        return summary

    def analyze_export_usage(self, exports: list[ExportEntry]) -> dict[str, Any]:
        """Analyze usage patterns of specific exports."""
        analysis: dict[str, Any] = {
            "validation_functions": [],
            "activation_functions": [],
            "serial_functions": [],
            "trial_functions": [],
        }

        for export in exports:
            if not export.name:
                continue

            name_lower: str = export.name.lower()

            if any(kw in name_lower for kw in ["validate", "verify", "check"]):
                analysis["validation_functions"].append({
                    "name": export.name,
                    "address": hex(export.address),
                    "ordinal": export.ordinal,
                })

            if any(kw in name_lower for kw in ["activate", "activation"]):
                analysis["activation_functions"].append({
                    "name": export.name,
                    "address": hex(export.address),
                    "ordinal": export.ordinal,
                })

            if any(kw in name_lower for kw in ["serial", "key"]):
                analysis["serial_functions"].append({
                    "name": export.name,
                    "address": hex(export.address),
                    "ordinal": export.ordinal,
                })

            if any(kw in name_lower for kw in ["trial", "demo", "expire"]):
                analysis["trial_functions"].append({
                    "name": export.name,
                    "address": hex(export.address),
                    "ordinal": export.ordinal,
                })

        return analysis

    def identify_bypass_targets(self) -> list[ExportEntry]:
        """Identify exports that are high-priority bypass targets."""
        targets: list[ExportEntry] = []

        high_priority_keywords: list[str] = [
            "validate",
            "verify",
            "check",
            "authenticate",
            "activate",
            "register",
            "trial",
            "expire",
        ]

        for export in self.exports:
            if not export.name:
                continue

            name_lower: str = export.name.lower()

            for keyword in high_priority_keywords:
                if keyword in name_lower:
                    targets.append(export)
                    break

        return targets

    @staticmethod
    def compare_exports(analyzer1: "ExportAnalyzer", analyzer2: "ExportAnalyzer") -> dict[str, Any]:
        """Compare exports between two versions of same DLL."""
        exports1_names: set[str] = {e.name for e in analyzer1.exports if e.name}
        exports2_names: set[str] = {e.name for e in analyzer2.exports if e.name}

        added: set[str] = exports2_names - exports1_names
        removed: set[str] = exports1_names - exports2_names
        common: set[str] = exports1_names & exports2_names

        comparison: dict[str, Any] = {
            "added_exports": [analyzer2.get_export_by_name(name) for name in added],
            "removed_exports": [analyzer1.get_export_by_name(name) for name in removed],
            "common_exports": [analyzer1.get_export_by_name(name) for name in common],
        }

        return comparison


def analyze_exports(binary_path: str) -> dict[str, Any]:
    """Convenience function to analyze exports from a PE binary.

    Args:
        binary_path: Path to PE binary

    Returns:
        Dictionary containing exports, statistics, and summary
    """
    analyzer = ExportAnalyzer(binary_path)
    analyzer.analyze()

    return {
        "exports": [
            {
                "name": exp.name,
                "ordinal": exp.ordinal,
                "address": hex(exp.address),
                "rva": hex(exp.rva),
                "is_forwarded": exp.is_forwarded,
                "forward_name": exp.forward_name,
            }
            for exp in analyzer.exports
        ],
        "statistics": analyzer.get_export_statistics(),
        "summary": analyzer.get_export_summary(),
        "license_exports": [
            {
                "name": exp.name,
                "address": hex(exp.address),
                "ordinal": exp.ordinal,
            }
            for exp in analyzer.get_license_related_exports()
        ],
    }


__all__ = [
    "ExportAnalyzer",
    "ExportEntry",
    "ForwardedExport",
    "analyze_exports",
]
