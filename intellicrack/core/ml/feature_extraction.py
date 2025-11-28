"""Binary feature extraction for ML-based protection classification.

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
import math
import re
import struct
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np


class BinaryFeatureExtractor:
    """Extract features from PE binaries for machine learning classification."""

    PROTECTOR_PATTERNS = {
        "vmprotect": {
            "section_names": [b".vmp0", b".vmp1", b".vmp2"],
            "byte_patterns": [b"VMProtect", b"PolyEnE", b"\x9c\x8d\x64"],
            "section_flags": {"zero_size": True},
        },
        "themida": {
            "section_names": [b"Themida", b".Themida"],
            "byte_patterns": [b"Themida", b"WinLicense", b"Oreans"],
            "entry_point_sig": b"\xb8\x00\x00\x00\x60",
            "min_entropy": 7.5,
        },
        "enigma": {
            "byte_patterns": [b"ENIGMA", b"Enigma Protector"],
            "timestamp": 0x2A425E19,
            "last_section_sig": True,
        },
        "obsidium": {
            "byte_patterns": [b"Obsidium", b".obsid"],
            "section_names": [b".obsid"],
        },
        "asprotect": {
            "byte_patterns": [b"ASProtect", b"Seppyev", b".aspack", b".adata"],
            "section_names": [b".aspack", b".adata"],
        },
        "armadillo": {
            "byte_patterns": [b"Armadillo", b"SoftwarePassport", b".spp"],
            "section_names": [b".spp"],
        },
        "upx": {
            "section_names": [b"UPX0", b"UPX1", b"UPX2", b"UPX!"],
            "byte_patterns": [b"UPX!"],
        },
    }

    SUSPICIOUS_IMPORTS = {
        "VirtualProtect",
        "VirtualAlloc",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "LoadLibraryA",
        "GetProcAddress",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "ZwQueryInformationProcess",
    }

    def __init__(self) -> None:
        """Initialize the feature extractor."""
        self.logger = logging.getLogger(__name__)
        self.feature_names = self._get_feature_names()

    def _get_feature_names(self) -> list[str]:
        """Get ordered list of all feature names."""
        opcode_names = [f"opcode_freq_{i:02x}" for i in range(16)]
        return [
            "overall_entropy",
            "text_entropy",
            "data_entropy",
            "rdata_entropy",
            "max_section_entropy",
            "min_section_entropy",
            "avg_section_entropy",
            "section_count",
            "executable_section_count",
            "high_entropy_section_count",
            "import_count",
            "unique_dll_count",
            "suspicious_import_count",
            "text_to_raw_ratio",
            "entry_point_section_idx",
            "overlay_size",
            "resource_size",
            "has_tls_callbacks",
            "signature_vmprotect",
            "signature_themida",
            "signature_enigma",
            "signature_obsidium",
            "signature_asprotect",
            "signature_armadillo",
            "signature_upx",
            "unusual_section_names",
            "packed_import_table",
            "high_cyclomatic_complexity",
            *opcode_names,
        ]

    def extract_features(self, binary_path: str | Path) -> np.ndarray:
        """Extract feature vector from binary file.

        Args:
            binary_path: Path to the binary file

        Returns:
            Feature vector as numpy array

        Raises:
            ValueError: If feature extraction fails

        """
        binary_path = Path(binary_path)
        if not binary_path.exists():
            raise ValueError(f"Binary file not found: {binary_path}")

        try:
            with open(binary_path, "rb") as f:
                data = f.read()

            features = {}

            features |= self._extract_entropy_features(data)
            features.update(self._extract_pe_features(data))
            features.update(self._extract_section_features(data))
            features.update(self._extract_import_features(data))
            features.update(self._extract_signature_features(data))
            features.update(self._extract_opcode_features(data))

            return np.array(
                [features.get(name, 0.0) for name in self.feature_names],
                dtype=np.float32,
            )
        except Exception as e:
            raise ValueError(f"Feature extraction failed: {e}") from e

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        byte_counts = Counter(data)
        data_len = len(data)
        entropy = 0.0

        for count in byte_counts.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def _extract_entropy_features(self, data: bytes) -> dict[str, float]:
        """Extract entropy-based features."""
        features = {"overall_entropy": self._calculate_entropy(data)}

        try:
            pe_data = self._parse_pe_basic(data)
            sections = pe_data.get("sections", [])

            section_entropies = []
            text_entropy = 0.0
            data_entropy = 0.0
            rdata_entropy = 0.0

            for section in sections:
                if section_data := section.get("data", b""):
                    entropy = self._calculate_entropy(section_data)
                    section_entropies.append(entropy)

                    section_name = section.get("name", "").lower()
                    if ".text" in section_name or "code" in section_name:
                        text_entropy = entropy
                    elif ".data" in section_name:
                        data_entropy = entropy
                    elif ".rdata" in section_name or "rdata" in section_name:
                        rdata_entropy = entropy

            features["text_entropy"] = text_entropy
            features["data_entropy"] = data_entropy
            features["rdata_entropy"] = rdata_entropy

            if section_entropies:
                features["max_section_entropy"] = max(section_entropies)
                features["min_section_entropy"] = min(section_entropies)
                features["avg_section_entropy"] = sum(section_entropies) / len(section_entropies)
                features["high_entropy_section_count"] = sum(bool(e > 7.0) for e in section_entropies)
            else:
                features["max_section_entropy"] = 0.0
                features["min_section_entropy"] = 0.0
                features["avg_section_entropy"] = 0.0
                features["high_entropy_section_count"] = 0.0

        except Exception:
            features |= {
                "text_entropy": 0.0,
                "data_entropy": 0.0,
                "rdata_entropy": 0.0,
                "max_section_entropy": 0.0,
                "min_section_entropy": 0.0,
                "avg_section_entropy": 0.0,
                "high_entropy_section_count": 0.0,
            }

        return features

    def _extract_pe_features(self, data: bytes) -> dict[str, float]:
        """Extract PE structure features."""
        features = {}

        try:
            pe_data = self._parse_pe_basic(data)

            features["has_tls_callbacks"] = 1.0 if pe_data.get("has_tls", False) else 0.0

            overlay_size = pe_data.get("overlay_size", 0)
            features["overlay_size"] = min(overlay_size / 1024.0, 1000.0)

            resource_size = pe_data.get("resource_size", 0)
            features["resource_size"] = min(resource_size / 1024.0, 1000.0)

            features["entry_point_section_idx"] = float(pe_data.get("entry_point_section", 0))

        except Exception:
            features |= {
                "has_tls_callbacks": 0.0,
                "overlay_size": 0.0,
                "resource_size": 0.0,
                "entry_point_section_idx": 0.0,
            }

        return features

    def _extract_section_features(self, data: bytes) -> dict[str, float]:
        """Extract section-related features."""
        features = {}

        try:
            pe_data = self._parse_pe_basic(data)
            sections = pe_data.get("sections", [])

            features["section_count"] = float(len(sections))

            executable_count = 0
            unusual_names = 0
            text_to_raw_ratios = []

            for section in sections:
                if section.get("executable", False):
                    executable_count += 1

                section_name = section.get("name", "").lower().strip("\x00")
                if section_name and all(
                    common not in section_name
                    for common in [
                        ".text",
                        ".data",
                        ".rdata",
                        ".bss",
                        ".idata",
                        ".edata",
                        ".rsrc",
                    ]
                ):
                    unusual_names += 1

                virtual_size = section.get("virtual_size", 0)
                raw_size = section.get("raw_size", 1)
                if raw_size > 0:
                    ratio = virtual_size / raw_size
                    text_to_raw_ratios.append(ratio)

            features["executable_section_count"] = float(executable_count)
            features["unusual_section_names"] = float(unusual_names)

            if text_to_raw_ratios:
                avg_ratio = sum(text_to_raw_ratios) / len(text_to_raw_ratios)
                features["text_to_raw_ratio"] = min(avg_ratio, 10.0)
            else:
                features["text_to_raw_ratio"] = 1.0

        except Exception:
            features |= {
                "section_count": 0.0,
                "executable_section_count": 0.0,
                "unusual_section_names": 0.0,
                "text_to_raw_ratio": 1.0,
            }

        return features

    def _extract_import_features(self, data: bytes) -> dict[str, float]:
        """Extract import table features."""
        features = {}

        try:
            pe_data = self._parse_pe_basic(data)
            imports = pe_data.get("imports", [])

            features["import_count"] = float(len(imports))

            unique_dlls = set()
            suspicious_count = 0

            for imp in imports:
                if dll_name := imp.get("dll", "").lower():
                    unique_dlls.add(dll_name)

                func_name = imp.get("function", "")
                if func_name in self.SUSPICIOUS_IMPORTS:
                    suspicious_count += 1

            features["unique_dll_count"] = float(len(unique_dlls))
            features["suspicious_import_count"] = float(suspicious_count)

            if len(imports) > 0 and unique_dlls:
                avg_imports_per_dll = len(imports) / len(unique_dlls)
                features["packed_import_table"] = 1.0 if avg_imports_per_dll < 2.0 else 0.0
            else:
                features["packed_import_table"] = 1.0 if len(imports) < 10 else 0.0

        except Exception:
            features |= {
                "import_count": 0.0,
                "unique_dll_count": 0.0,
                "suspicious_import_count": 0.0,
                "packed_import_table": 0.0,
            }

        return features

    def _extract_signature_features(self, data: bytes) -> dict[str, float]:
        """Extract protector signature features using sophisticated multi-factor detection."""
        features = {}

        try:
            pe_data = self._parse_pe_basic(data)
            sections = pe_data.get("sections", [])
            timestamp = pe_data.get("timestamp", 0)
            entry_point = pe_data.get("entry_point_data", b"")

            for protector, patterns in self.PROTECTOR_PATTERNS.items():
                feature_name = f"signature_{protector}"
                score = 0.0
                matches = []

                if "byte_patterns" in patterns:
                    for pattern in patterns["byte_patterns"]:
                        if pattern in data:
                            score += 0.3
                            matches.append(f"byte:{pattern[:20]}")
                            break

                if "section_names" in patterns:
                    section_match_found = False
                    for section in sections:
                        if section_match_found:
                            break
                        section_name = section.get("name", "").encode("utf-8", errors="ignore")
                        for pattern in patterns["section_names"]:
                            if pattern in section_name or section_name in pattern:
                                score += 0.4
                                matches.append(f"section:{section_name[:20]}")
                                section_match_found = True
                                break

                if "section_flags" in patterns:
                    flags = patterns["section_flags"]
                    if flags.get("zero_size"):
                        for section in sections:
                            if section.get("raw_size", 1) == 0 and section.get("virtual_size", 0) > 0:
                                score += 0.2
                                matches.append("zero_size_section")
                                break

                if "entry_point_sig" in patterns and entry_point.startswith(patterns["entry_point_sig"]):
                    score += 0.5
                    matches.append("entry_point_match")

                if "timestamp" in patterns and timestamp == patterns["timestamp"]:
                    score += 0.6
                    matches.append(f"timestamp:{hex(timestamp)}")

                if "min_entropy" in patterns:
                    overall_entropy = self._calculate_entropy(data)
                    if overall_entropy >= patterns["min_entropy"]:
                        score += 0.2
                        matches.append(f"high_entropy:{overall_entropy:.2f}")

                if patterns.get("last_section_sig") and sections:
                    last_section_data = sections[-1].get("data", b"")
                    for pattern in patterns.get("byte_patterns", []):
                        if pattern in last_section_data:
                            score += 0.4
                            matches.append("last_section_match")
                            break

                features[feature_name] = min(score, 1.0)

                if matches and score > 0.5:
                    self.logger.debug(
                        "Strong %s detection (score: %.2f): %s",
                        protector,
                        score,
                        ", ".join(matches),
                    )

        except Exception as e:
            self.logger.warning("Failed to extract signature features: %s", e)
            for protector in self.PROTECTOR_PATTERNS:
                features[f"signature_{protector}"] = 0.0

        return features

    def _extract_opcode_features(self, data: bytes) -> dict[str, float]:
        """Extract opcode frequency features from executable sections."""
        features = {f"opcode_freq_{i:02x}": 0.0 for i in range(16)}

        try:
            pe_data = self._parse_pe_basic(data)
            sections = pe_data.get("sections", [])

            code_bytes = b""
            for section in sections:
                if section.get("executable", False):
                    section_data = section.get("data", b"")
                    code_bytes += section_data

            if code_bytes:
                opcode_counts = Counter(b & 0xF0 for b in code_bytes[: min(len(code_bytes), 10000)])
                total_opcodes = sum(opcode_counts.values())

                if total_opcodes > 0:
                    for opcode, count in opcode_counts.items():
                        key = f"opcode_freq_{(opcode >> 4):02x}"
                        features[key] = count / total_opcodes

            complexity_score = self._estimate_cyclomatic_complexity(code_bytes[: min(len(code_bytes), 10000)])
            features["high_cyclomatic_complexity"] = 1.0 if complexity_score > 50 else 0.0

        except Exception as e:
            self.logger.warning("Failed to extract advanced code features: %s", e)

        return features

    def _estimate_cyclomatic_complexity(self, code: bytes) -> float:
        """Estimate cyclomatic complexity from bytecode patterns."""
        if not code:
            return 0.0

        branch_opcodes = {
            0x70,
            0x71,
            0x72,
            0x73,
            0x74,
            0x75,
            0x76,
            0x77,
            0x78,
            0x79,
            0x7A,
            0x7B,
            0x7C,
            0x7D,
            0x7E,
            0x7F,
            0xE8,
            0xE9,
            0xEB,
            0x0F,
        }

        branch_count = sum(bool(b in branch_opcodes) for b in code)
        return float(branch_count)

    def _parse_pe_basic(self, data: bytes) -> dict[str, Any]:
        """Parse PE file without external dependencies.

        Args:
            data: Raw binary data

        Returns:
            Dictionary containing PE information

        """
        if len(data) < 64:
            raise ValueError("Data too small to be PE file")

        if data[:2] != b"MZ":
            raise ValueError("Invalid PE signature")

        pe_offset = struct.unpack("<I", data[60:64])[0]
        if pe_offset >= len(data) - 4:
            raise ValueError("Invalid PE offset")

        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            raise ValueError("Invalid PE signature")

        result = {
            "sections": [],
            "imports": [],
            "has_tls": False,
            "overlay_size": 0,
            "resource_size": 0,
            "entry_point_section": 0,
            "timestamp": 0,
            "entry_point_data": b"",
        }

        coff_header_offset = pe_offset + 4
        number_of_sections = struct.unpack("<H", data[coff_header_offset + 2 : coff_header_offset + 4])[0]
        timestamp = struct.unpack("<I", data[coff_header_offset + 4 : coff_header_offset + 8])[0]
        size_of_optional_header = struct.unpack("<H", data[coff_header_offset + 16 : coff_header_offset + 18])[0]

        result["timestamp"] = timestamp

        optional_header_offset = coff_header_offset + 20

        entry_point_rva = 0
        if optional_header_offset + 20 <= len(data):
            entry_point_rva = struct.unpack("<I", data[optional_header_offset + 16 : optional_header_offset + 20])[0]

        section_table_offset = optional_header_offset + size_of_optional_header

        for i in range(number_of_sections):
            section_offset = section_table_offset + (i * 40)
            if section_offset + 40 > len(data):
                break

            section_name_bytes = data[section_offset : section_offset + 8]
            section_name = section_name_bytes.decode("utf-8", errors="ignore").strip("\x00")

            virtual_size = struct.unpack("<I", data[section_offset + 8 : section_offset + 12])[0]
            virtual_address = struct.unpack("<I", data[section_offset + 12 : section_offset + 16])[0]
            raw_size = struct.unpack("<I", data[section_offset + 16 : section_offset + 20])[0]
            raw_offset = struct.unpack("<I", data[section_offset + 20 : section_offset + 24])[0]
            characteristics = struct.unpack("<I", data[section_offset + 36 : section_offset + 40])[0]

            executable = bool(characteristics & 0x20000000)

            section_data = b""
            if raw_offset < len(data) and raw_size > 0:
                end = min(raw_offset + raw_size, len(data))
                section_data = data[raw_offset:end]

            result["sections"].append(
                {
                    "name": section_name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_offset": raw_offset,
                    "characteristics": characteristics,
                    "executable": executable,
                    "data": section_data,
                }
            )

        if number_of_sections > 0:
            last_section = result["sections"][-1]
            last_section_end = last_section["raw_offset"] + last_section["raw_size"]
            if last_section_end < len(data):
                result["overlay_size"] = len(data) - last_section_end

        if entry_point_rva > 0:
            for section in result["sections"]:
                va = section.get("virtual_address", 0)
                vsize = section.get("virtual_size", 0)
                if va <= entry_point_rva < va + vsize:
                    section_data = section.get("data", b"")
                    offset_in_section = entry_point_rva - va
                    if offset_in_section < len(section_data):
                        result["entry_point_data"] = section_data[offset_in_section : min(offset_in_section + 32, len(section_data))]
                    break

        try:
            import_pattern = re.compile(rb"(?:[\x20-\x7E]{3,})\x00")
            import_matches = import_pattern.findall(data[: min(len(data), 100000)])

            for match in import_matches[:500]:
                import_str = match.decode("ascii", errors="ignore").strip("\x00")
                if "." in import_str and import_str.lower().endswith(".dll"):
                    result["imports"].append({"dll": import_str, "function": ""})
                elif import_str and "." not in import_str and len(import_str) > 2:
                    result["imports"].append({"dll": "", "function": import_str})

        except Exception as e:
            self.logger.warning("Failed to parse PE imports: %s", e)

        return result
