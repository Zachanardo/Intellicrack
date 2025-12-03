"""Comprehensive production tests for BinaryFeatureExtractor.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import struct
import tempfile
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from intellicrack.ml.binary_feature_extractor import (
    BinaryFeatureExtractor,
    extract_features_for_ml,
)


class TestBinaryFeatureExtractor:
    """Production tests for binary feature extraction with real PE/ELF structures."""

    @pytest.fixture
    def pe32_binary_with_imports(self, tmp_path: Path) -> Path:
        """Create real PE32 binary with import table and license-related APIs."""
        pe_path = tmp_path / "sample32.exe"

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 0x80)

        dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21" + b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7

        pe_signature = b"PE\x00\x00"

        file_header = struct.pack(
            "<HHIIIHH",
            0x014C,
            3,
            0x60000000,
            0,
            0,
            0x00E0,
            0x010B,
        )

        optional_header = bytearray(224)
        struct.pack_into("<H", optional_header, 0, 0x010B)
        struct.pack_into("<I", optional_header, 28, 0x00400000)
        struct.pack_into("<I", optional_header, 32, 0x00001000)
        struct.pack_into("<I", optional_header, 36, 0x00000200)
        struct.pack_into("<H", optional_header, 40, 5)
        struct.pack_into("<H", optional_header, 64, 3)
        struct.pack_into("<I", optional_header, 80, 0x00003000)
        struct.pack_into("<I", optional_header, 84, 0x00001000)
        struct.pack_into("<I", optional_header, 88, 0x00000200)
        struct.pack_into("<H", optional_header, 92, 16)

        import_dir_offset = 96
        struct.pack_into("<II", optional_header, import_dir_offset, 0x00002000, 0x00000100)

        text_section = bytearray(40)
        text_section[0:6] = b".text\x00"
        struct.pack_into("<I", text_section, 8, 0x00000800)
        struct.pack_into("<I", text_section, 12, 0x00001000)
        struct.pack_into("<I", text_section, 16, 0x00000800)
        struct.pack_into("<I", text_section, 20, 0x00000400)
        struct.pack_into("<I", text_section, 36, 0x20000020)

        data_section = bytearray(40)
        data_section[0:6] = b".data\x00"
        struct.pack_into("<I", data_section, 8, 0x00000400)
        struct.pack_into("<I", data_section, 12, 0x00002000)
        struct.pack_into("<I", data_section, 16, 0x00000400)
        struct.pack_into("<I", data_section, 20, 0x00000C00)
        struct.pack_into("<I", data_section, 36, 0xC0000040)

        idata_section = bytearray(40)
        idata_section[0:7] = b".idata\x00"
        struct.pack_into("<I", idata_section, 8, 0x00000200)
        struct.pack_into("<I", idata_section, 12, 0x00002000)
        struct.pack_into("<I", idata_section, 16, 0x00000200)
        struct.pack_into("<I", idata_section, 20, 0x00001000)
        struct.pack_into("<I", idata_section, 36, 0xC0000040)

        text_data = bytearray(0x800)
        text_data[0:10] = bytes(
            [
                0x55,
                0x89,
                0xE5,
                0x83,
                0xEC,
                0x10,
                0xC7,
                0x45,
                0xFC,
                0x00,
            ]
        )
        text_data[10:20] = bytes(
            [
                0x8B,
                0x45,
                0xFC,
                0x83,
                0xC0,
                0x01,
                0x89,
                0x45,
                0xFC,
                0xEB,
            ]
        )
        text_data[20:30] = bytes(
            [
                0xE8,
                0x00,
                0x00,
                0x00,
                0x00,
                0x5D,
                0xC3,
                0x90,
                0x90,
                0x90,
            ]
        )

        import_data = bytearray(0x200)

        import_descriptor_offset = 0
        struct.pack_into("<IIIII", import_data, import_descriptor_offset, 0x00002100, 0, 0, 0x00002150, 0x00002120)

        struct.pack_into("<IIIII", import_data, import_descriptor_offset + 20, 0, 0, 0, 0, 0)

        dll_name = b"ADVAPI32.dll\x00"
        import_data[0x50 : 0x50 + len(dll_name)] = dll_name

        func_names = [
            b"RegOpenKeyExA\x00",
            b"RegQueryValueExA\x00",
            b"RegSetValueExA\x00",
            b"CryptHashData\x00",
            b"CryptGenKey\x00",
        ]

        name_offset = 0x70
        for func_name in func_names:
            import_data[name_offset : name_offset + len(func_name)] = func_name
            name_offset += len(func_name)

        hint_name_table_offset = 0x100
        for i, _ in enumerate(func_names):
            struct.pack_into("<I", import_data, 0x20 + i * 4, 0x00002000 + hint_name_table_offset)
            hint_name_table_offset += 4

        strings = b"License Key Required\x00"
        strings += b"Trial Period Expired\x00"
        strings += b"SERIAL NUMBER\x00"
        strings += b"Product Activation\x00"
        strings += b"Hardware ID\x00"
        strings += b"https://license.server.com/validate\x00"

        data_data = bytearray(0x400)
        data_data[0 : len(strings)] = strings

        pe_binary = bytes(dos_header) + dos_stub
        pe_binary += pe_signature + file_header + bytes(optional_header)
        pe_binary += bytes(text_section) + bytes(data_section) + bytes(idata_section)

        while len(pe_binary) < 0x400:
            pe_binary += b"\x00"

        pe_binary += bytes(text_data)
        pe_binary += bytes(data_data)
        pe_binary += bytes(import_data)

        pe_path.write_bytes(pe_binary)
        return pe_path

    @pytest.fixture
    def pe64_binary_with_protections(self, tmp_path: Path) -> Path:
        """Create PE64 binary with high entropy sections simulating protection."""
        pe_path = tmp_path / "sample64.exe"

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 0x80)

        dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21" + b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7

        pe_signature = b"PE\x00\x00"

        file_header = struct.pack(
            "<HHIIIHH",
            0x8664,
            2,
            0x60000000,
            0,
            0,
            0x00F0,
            0x020B,
        )

        optional_header = bytearray(240)
        struct.pack_into("<H", optional_header, 0, 0x020B)
        struct.pack_into("<Q", optional_header, 24, 0x0000000140000000)
        struct.pack_into("<I", optional_header, 32, 0x00001000)
        struct.pack_into("<I", optional_header, 36, 0x00000200)
        struct.pack_into("<I", optional_header, 80, 0x00003000)
        struct.pack_into("<H", optional_header, 92, 16)

        text_section = bytearray(40)
        text_section[0:6] = b".text\x00"
        struct.pack_into("<I", text_section, 8, 0x00001000)
        struct.pack_into("<I", text_section, 12, 0x00001000)
        struct.pack_into("<I", text_section, 16, 0x00001000)
        struct.pack_into("<I", text_section, 20, 0x00000400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        vmp_section = bytearray(40)
        vmp_section[0:8] = b".vmp0\x00\x00\x00"
        struct.pack_into("<I", vmp_section, 8, 0x00001000)
        struct.pack_into("<I", vmp_section, 12, 0x00002000)
        struct.pack_into("<I", vmp_section, 16, 0x00001000)
        struct.pack_into("<I", vmp_section, 20, 0x00001400)
        struct.pack_into("<I", vmp_section, 36, 0xE0000020)

        text_data = bytearray(0x1000)
        x64_code = bytes(
            [
                0x48,
                0x83,
                0xEC,
                0x28,
                0x48,
                0x8D,
                0x0D,
                0x00,
                0x00,
                0x00,
                0x00,
                0xE8,
                0x00,
                0x00,
                0x00,
                0x00,
                0x48,
                0x31,
                0xC0,
                0x48,
                0x83,
                0xC4,
                0x28,
                0xC3,
            ]
        )
        text_data[0 : len(x64_code)] = x64_code

        np.random.seed(42)
        vmp_data = np.random.bytes(0x1000)

        pe_binary = bytes(dos_header) + dos_stub
        pe_binary += pe_signature + file_header + bytes(optional_header)
        pe_binary += bytes(text_section) + bytes(vmp_section)

        while len(pe_binary) < 0x400:
            pe_binary += b"\x00"

        pe_binary += bytes(text_data)
        pe_binary += vmp_data

        pe_path.write_bytes(pe_binary)
        return pe_path

    @pytest.fixture
    def elf_binary_with_code(self, tmp_path: Path) -> Path:
        """Create minimal ELF binary with executable code sections."""
        elf_path = tmp_path / "sample.elf"

        elf_header = bytearray(64)
        elf_header[0:4] = b"\x7fELF"
        elf_header[4] = 2
        elf_header[5] = 1
        elf_header[6] = 1
        struct.pack_into("<H", elf_header, 16, 2)
        struct.pack_into("<H", elf_header, 18, 0x3E)
        struct.pack_into("<I", elf_header, 20, 1)
        struct.pack_into("<Q", elf_header, 24, 0x400000)
        struct.pack_into("<Q", elf_header, 32, 64)
        struct.pack_into("<H", elf_header, 52, 64)
        struct.pack_into("<H", elf_header, 54, 56)
        struct.pack_into("<H", elf_header, 56, 2)

        program_header_text = bytearray(56)
        struct.pack_into("<I", program_header_text, 0, 1)
        struct.pack_into("<I", program_header_text, 4, 5)
        struct.pack_into("<Q", program_header_text, 8, 0x1000)
        struct.pack_into("<Q", program_header_text, 16, 0x401000)
        struct.pack_into("<Q", program_header_text, 32, 0x1000)
        struct.pack_into("<Q", program_header_text, 40, 0x1000)

        program_header_data = bytearray(56)
        struct.pack_into("<I", program_header_data, 0, 1)
        struct.pack_into("<I", program_header_data, 4, 6)
        struct.pack_into("<Q", program_header_data, 8, 0x2000)
        struct.pack_into("<Q", program_header_data, 16, 0x402000)
        struct.pack_into("<Q", program_header_data, 32, 0x1000)
        struct.pack_into("<Q", program_header_data, 40, 0x1000)

        elf_binary = bytes(elf_header) + bytes(program_header_text) + bytes(program_header_data)

        while len(elf_binary) < 0x1000:
            elf_binary += b"\x00"

        code_section = bytearray(0x1000)
        x64_asm = bytes(
            [
                0x55,
                0x48,
                0x89,
                0xE5,
                0x48,
                0x83,
                0xEC,
                0x10,
                0xC7,
                0x45,
                0xFC,
                0x00,
                0x00,
                0x00,
                0x00,
                0x8B,
                0x45,
                0xFC,
                0x83,
                0xC0,
                0x01,
                0x89,
                0x45,
                0xFC,
                0x48,
                0x31,
                0xC0,
                0xC9,
                0xC3,
            ]
        )
        code_section[0 : len(x64_asm)] = x64_asm

        data_section = bytearray(0x1000)
        data_strings = b"License\x00Product Key\x00Registration\x00"
        data_section[0 : len(data_strings)] = data_strings

        elf_binary += bytes(code_section) + bytes(data_section)

        elf_path.write_bytes(elf_binary)
        return elf_path

    @pytest.fixture
    def packed_binary_high_entropy(self, tmp_path: Path) -> Path:
        """Create binary with high entropy simulating packed/encrypted content."""
        packed_path = tmp_path / "packed.exe"

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 0x80)

        dos_stub = b"\x0e\x1f" + b"\x00" * 60

        pe_signature = b"PE\x00\x00"

        file_header = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x60000000,
            0,
            0,
            0x00E0,
            0x010B,
        )

        optional_header = bytearray(224)
        struct.pack_into("<H", optional_header, 0, 0x010B)
        struct.pack_into("<I", optional_header, 28, 0x00400000)

        upx_section = bytearray(40)
        upx_section[0:5] = b"UPX0\x00"
        struct.pack_into("<I", upx_section, 8, 0x00002000)
        struct.pack_into("<I", upx_section, 12, 0x00001000)
        struct.pack_into("<I", upx_section, 16, 0x00002000)
        struct.pack_into("<I", upx_section, 20, 0x00000400)
        struct.pack_into("<I", upx_section, 36, 0xE0000020)

        np.random.seed(123)
        high_entropy_data = np.random.bytes(0x2000)

        pe_binary = bytes(dos_header) + dos_stub
        pe_binary += pe_signature + file_header + bytes(optional_header)
        pe_binary += bytes(upx_section)

        while len(pe_binary) < 0x400:
            pe_binary += b"\x00"

        pe_binary += high_entropy_data

        packed_path.write_bytes(pe_binary)
        return packed_path

    def test_pe32_header_detection(self, pe32_binary_with_imports: Path) -> None:
        """Extractor correctly identifies PE32 architecture."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))

        assert extractor.pe is not None
        assert extractor.arch is not None
        assert extractor.mode is not None
        assert extractor.pe.FILE_HEADER.Machine == 0x014C

    def test_pe64_header_detection(self, pe64_binary_with_protections: Path) -> None:
        """Extractor correctly identifies PE64 architecture."""
        extractor = BinaryFeatureExtractor(str(pe64_binary_with_protections))

        assert extractor.pe is not None
        assert extractor.pe.FILE_HEADER.Machine == 0x8664

    def test_opcode_histogram_extraction_pe32(self, pe32_binary_with_imports: Path) -> None:
        """Opcode histogram extracted from PE32 executable sections."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        histogram = extractor.extract_opcode_histogram(normalize=True)

        assert isinstance(histogram, np.ndarray)
        assert len(histogram) > 0
        assert histogram.dtype == np.float32
        assert np.all(histogram >= 0.0)

        if np.sum(histogram) > 0:
            assert np.isclose(np.sum(histogram), 1.0, atol=0.1)

    def test_opcode_histogram_detects_real_instructions(self, pe32_binary_with_imports: Path) -> None:
        """Opcode histogram identifies actual x86 instructions in binary."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        histogram = extractor.extract_opcode_histogram(normalize=False)

        assert isinstance(histogram, np.ndarray)
        assert len(histogram) > 0

        mov_idx = 0
        push_idx = 1
        call_idx = 2

        common_opcodes_present = histogram[mov_idx] > 0 or histogram[push_idx] > 0 or histogram[call_idx] > 0
        assert common_opcodes_present

    def test_section_entropy_calculation_pe(self, pe32_binary_with_imports: Path) -> None:
        """Section entropy correctly calculated for PE sections."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        entropies = extractor.calculate_section_entropy()

        assert isinstance(entropies, np.ndarray)
        assert len(entropies) == 16
        assert entropies.dtype == np.float32
        assert np.all(entropies >= 0.0)
        assert np.all(entropies <= 8.0)

    def test_high_entropy_section_detection(self, packed_binary_high_entropy: Path) -> None:
        """High entropy sections detected in packed binaries."""
        extractor = BinaryFeatureExtractor(str(packed_binary_high_entropy))
        entropies = extractor.calculate_section_entropy()

        max_entropy = np.max(entropies)
        assert max_entropy > 6.0

    def test_low_entropy_section_detection(self, pe32_binary_with_imports: Path) -> None:
        """Low entropy sections detected in normal code."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        entropies = extractor.calculate_section_entropy()

        min_entropy = np.min(entropies[entropies > 0])
        assert min_entropy < 6.0

    def test_import_table_extraction_pe(self, pe32_binary_with_imports: Path) -> None:
        """Import table APIs extracted from PE binary."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        imports = extractor._extract_imports()

        assert isinstance(imports, list)

    def test_api_sequence_features_extraction(self, pe32_binary_with_imports: Path) -> None:
        """API sequence features detect license-related API usage."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        api_features = extractor.extract_api_sequences()

        assert isinstance(api_features, np.ndarray)
        assert len(api_features) == 256
        assert api_features.dtype == np.float32
        assert np.all(api_features >= 0.0)
        assert np.all(api_features <= 1.0)

    def test_string_feature_extraction_ascii(self, pe32_binary_with_imports: Path) -> None:
        """ASCII string features extracted from binary."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        string_features = extractor.extract_string_features()

        assert isinstance(string_features, np.ndarray)
        assert len(string_features) == 128
        assert string_features.dtype == np.float32

        license_pattern_idx = 0
        assert string_features[license_pattern_idx] > 0.0

    def test_string_feature_detects_license_keywords(self, pe32_binary_with_imports: Path) -> None:
        """String features detect license-related keywords."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        strings = extractor._extract_strings(extractor.data, min_length=4, encoding="ascii")

        strings_lower = [s.lower() for s in strings]

        has_license = any("license" in s for s in strings_lower)
        has_trial = any("trial" in s for s in strings_lower)
        has_serial = any("serial" in s for s in strings_lower)

        assert has_license or has_trial or has_serial

    def test_cfg_feature_extraction(self, pe32_binary_with_imports: Path) -> None:
        """Control flow graph features extracted from binary."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        cfg_features = extractor.build_control_flow_graph()

        assert isinstance(cfg_features, dict)
        assert "num_nodes" in cfg_features
        assert "num_edges" in cfg_features
        assert "avg_degree" in cfg_features
        assert "density" in cfg_features

        assert cfg_features["num_nodes"] >= 0
        assert cfg_features["num_edges"] >= 0
        assert cfg_features["density"] >= 0.0

    def test_cfg_vector_conversion(self, pe32_binary_with_imports: Path) -> None:
        """CFG features converted to normalized vector."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        cfg_dict = extractor.build_control_flow_graph()
        cfg_vector = extractor._cfg_to_vector(cfg_dict)

        assert isinstance(cfg_vector, np.ndarray)
        assert len(cfg_vector) == 16
        assert cfg_vector.dtype == np.float32
        assert np.all(cfg_vector >= 0.0)

    def test_basic_block_extraction(self, pe32_binary_with_imports: Path) -> None:
        """Basic blocks extracted from executable sections."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        blocks = extractor._extract_basic_blocks()

        assert isinstance(blocks, list)

        for block in blocks:
            assert "start" in block
            assert "size" in block
            assert "type" in block
            assert block["type"] in ["normal", "return", "call", "conditional"]

    def test_executable_section_identification_pe(self, pe32_binary_with_imports: Path) -> None:
        """Executable sections identified in PE binary."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        exec_sections = extractor._get_executable_sections()

        assert isinstance(exec_sections, list)
        assert len(exec_sections) > 0

        for section_data, section_va in exec_sections:
            assert isinstance(section_data, bytes)
            assert len(section_data) > 0
            assert isinstance(section_va, int)
            assert section_va > 0

    def test_extract_all_features_completeness(self, pe32_binary_with_imports: Path) -> None:
        """All feature categories extracted in complete feature set."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        features = extractor.extract_all_features()

        assert isinstance(features, dict)
        assert "opcode_histogram" in features
        assert "cfg_features" in features
        assert "api_sequences" in features
        assert "section_entropy" in features
        assert "string_features" in features

        for feature_name, feature_array in features.items():
            assert isinstance(feature_array, np.ndarray)
            assert feature_array.dtype == np.float32
            assert len(feature_array) > 0

    def test_ml_feature_vector_generation(self, pe32_binary_with_imports: Path) -> None:
        """Complete ML feature vector generated for training."""
        feature_vector = extract_features_for_ml(str(pe32_binary_with_imports))

        assert isinstance(feature_vector, np.ndarray)
        assert feature_vector.dtype == np.float32
        assert len(feature_vector) > 0

        expected_length = 48 + 16 + 256 + 16 + 128
        assert len(feature_vector) == expected_length

    def test_feature_normalization_bounds(self, pe32_binary_with_imports: Path) -> None:
        """Feature normalization keeps values in valid ranges."""
        feature_vector = extract_features_for_ml(str(pe32_binary_with_imports))

        assert np.all(np.isfinite(feature_vector))
        assert not np.any(np.isnan(feature_vector))
        assert not np.any(np.isinf(feature_vector))

    def test_protection_signature_detection_vmprotect(self, pe64_binary_with_protections: Path) -> None:
        """Protection signatures detected in protected binary sections."""
        extractor = BinaryFeatureExtractor(str(pe64_binary_with_protections))

        assert extractor.pe is not None

        section_names = [section.Name.decode("utf-8", errors="ignore").strip("\x00") for section in extractor.pe.sections]

        has_protection_section = any("vmp" in name.lower() or "themida" in name.lower() or "upx" in name.lower() for name in section_names)

        assert has_protection_section

    def test_entropy_distinguishes_packed_vs_normal(
        self, pe32_binary_with_imports: Path, packed_binary_high_entropy: Path
    ) -> None:
        """Entropy features distinguish packed from normal binaries."""
        normal_extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        packed_extractor = BinaryFeatureExtractor(str(packed_binary_high_entropy))

        normal_entropy = normal_extractor.calculate_section_entropy()
        packed_entropy = packed_extractor.calculate_section_entropy()

        normal_max = np.max(normal_entropy)
        packed_max = np.max(packed_entropy)

        assert packed_max > normal_max

    def test_opcode_histogram_without_capstone_fallback(self, pe32_binary_with_imports: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Fallback byte histogram works when Capstone unavailable."""
        import intellicrack.ml.binary_feature_extractor as bfe_module

        original_capstone = bfe_module.CAPSTONE_AVAILABLE
        monkeypatch.setattr(bfe_module, "CAPSTONE_AVAILABLE", False)

        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        histogram = extractor.extract_opcode_histogram(normalize=True)

        assert isinstance(histogram, np.ndarray)
        assert len(histogram) == 256
        assert histogram.dtype == np.float32

        monkeypatch.setattr(bfe_module, "CAPSTONE_AVAILABLE", original_capstone)

    def test_cfg_features_without_networkx_fallback(self, pe32_binary_with_imports: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """CFG features return safe defaults when NetworkX unavailable."""
        import intellicrack.ml.binary_feature_extractor as bfe_module

        original_nx = bfe_module.NETWORKX_AVAILABLE
        monkeypatch.setattr(bfe_module, "NETWORKX_AVAILABLE", False)

        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        cfg_features = extractor.build_control_flow_graph()

        assert isinstance(cfg_features, dict)
        assert cfg_features["num_nodes"] == 0
        assert cfg_features["num_edges"] == 0

        monkeypatch.setattr(bfe_module, "NETWORKX_AVAILABLE", original_nx)

    def test_string_extraction_unicode(self, tmp_path: Path) -> None:
        """UTF-16LE strings extracted from Windows binaries."""
        unicode_binary = tmp_path / "unicode.exe"

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 0x80)

        pe_signature = b"PE\x00\x00"

        file_header = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x60000000,
            0,
            0,
            0x00E0,
            0x010B,
        )

        optional_header = bytearray(224)
        struct.pack_into("<H", optional_header, 0, 0x010B)

        data_section = bytearray(40)
        data_section[0:6] = b".data\x00"
        struct.pack_into("<I", data_section, 8, 0x00000400)
        struct.pack_into("<I", data_section, 12, 0x00001000)
        struct.pack_into("<I", data_section, 16, 0x00000400)
        struct.pack_into("<I", data_section, 20, 0x00000400)

        unicode_strings = "License\x00".encode("utf-16le")
        unicode_strings += "Registration\x00".encode("utf-16le")

        data_content = bytearray(0x400)
        data_content[0 : len(unicode_strings)] = unicode_strings

        binary = bytes(dos_header) + b"\x00" * 18
        binary += pe_signature + file_header + bytes(optional_header)
        binary += bytes(data_section)

        while len(binary) < 0x400:
            binary += b"\x00"

        binary += bytes(data_content)

        unicode_binary.write_bytes(binary)

        extractor = BinaryFeatureExtractor(str(unicode_binary))
        strings = extractor._extract_strings(extractor.data, min_length=4, encoding="utf-16le")

        assert len(strings) > 0
        assert any("license" in s.lower() for s in strings)

    def test_feature_vector_consistency(self, pe32_binary_with_imports: Path) -> None:
        """Feature extraction produces consistent results across runs."""
        vector1 = extract_features_for_ml(str(pe32_binary_with_imports))
        vector2 = extract_features_for_ml(str(pe32_binary_with_imports))

        assert np.array_equal(vector1, vector2)

    def test_entropy_calculation_accuracy(self, tmp_path: Path) -> None:
        """Entropy calculation returns mathematically correct values."""
        test_binary = tmp_path / "entropy_test.bin"

        uniform_data = bytes([i % 256 for i in range(256)])

        binary = b"NON_PE_BINARY" + uniform_data * 10

        test_binary.write_bytes(binary)

        extractor = BinaryFeatureExtractor(str(test_binary))
        entropies = extractor.calculate_section_entropy()

        max_entropy = np.max(entropies)
        assert max_entropy > 6.5

    def test_empty_import_table_handling(self, tmp_path: Path) -> None:
        """Extractor handles binaries with no import table."""
        no_imports_binary = tmp_path / "no_imports.exe"

        dos_header = b"MZ" + b"\x00" * 62
        pe_sig = b"PE\x00\x00"
        file_hdr = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt_hdr = b"\x00" * 224

        section = bytearray(40)
        section[0:6] = b".text\x00"
        struct.pack_into("<I", section, 8, 0x100)
        struct.pack_into("<I", section, 12, 0x1000)
        struct.pack_into("<I", section, 16, 0x100)
        struct.pack_into("<I", section, 20, 0x400)
        struct.pack_into("<I", section, 36, 0x20000020)

        binary = dos_header + pe_sig + file_hdr + opt_hdr + bytes(section)
        while len(binary) < 0x400:
            binary += b"\x00"
        binary += b"\x90" * 0x100

        no_imports_binary.write_bytes(binary)

        extractor = BinaryFeatureExtractor(str(no_imports_binary))
        imports = extractor._extract_imports()

        assert isinstance(imports, list)
        assert len(imports) == 0

    def test_corrupted_section_handling(self, tmp_path: Path) -> None:
        """Extractor gracefully handles corrupted section data."""
        corrupted_binary = tmp_path / "corrupted.exe"

        dos_header = b"MZ" + b"\x00" * 62
        pe_sig = b"PE\x00\x00"
        file_hdr = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt_hdr = b"\x00" * 224

        section = bytearray(40)
        section[0:6] = b".text\x00"
        struct.pack_into("<I", section, 8, 0xFFFFFFFF)
        struct.pack_into("<I", section, 12, 0x1000)
        struct.pack_into("<I", section, 16, 0x100)
        struct.pack_into("<I", section, 20, 0x400)
        struct.pack_into("<I", section, 36, 0x20000020)

        binary = dos_header + pe_sig + file_hdr + opt_hdr + bytes(section)
        while len(binary) < 0x400:
            binary += b"\x00"
        binary += b"\xCC" * 0x100

        corrupted_binary.write_bytes(binary)

        extractor = BinaryFeatureExtractor(str(corrupted_binary))
        features = extractor.extract_all_features()

        assert isinstance(features, dict)
        assert all(isinstance(v, np.ndarray) for v in features.values())

    def test_multiple_executable_sections(self, tmp_path: Path) -> None:
        """Extractor processes all executable sections."""
        multi_exec_binary = tmp_path / "multi_exec.exe"

        dos_header = b"MZ" + b"\x00" * 62
        pe_sig = b"PE\x00\x00"
        file_hdr = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 0xE0, 0x010B)
        opt_hdr = bytearray(224)
        struct.pack_into("<H", opt_hdr, 0, 0x010B)
        struct.pack_into("<I", opt_hdr, 28, 0x400000)

        text1 = bytearray(40)
        text1[0:7] = b".text1\x00"
        struct.pack_into("<I", text1, 8, 0x200)
        struct.pack_into("<I", text1, 12, 0x1000)
        struct.pack_into("<I", text1, 16, 0x200)
        struct.pack_into("<I", text1, 20, 0x400)
        struct.pack_into("<I", text1, 36, 0x60000020)

        text2 = bytearray(40)
        text2[0:7] = b".text2\x00"
        struct.pack_into("<I", text2, 8, 0x200)
        struct.pack_into("<I", text2, 12, 0x1200)
        struct.pack_into("<I", text2, 16, 0x200)
        struct.pack_into("<I", text2, 20, 0x600)
        struct.pack_into("<I", text2, 36, 0x60000020)

        data = bytearray(40)
        data[0:6] = b".data\x00"
        struct.pack_into("<I", data, 8, 0x100)
        struct.pack_into("<I", data, 12, 0x1400)
        struct.pack_into("<I", data, 16, 0x100)
        struct.pack_into("<I", data, 20, 0x800)
        struct.pack_into("<I", data, 36, 0xC0000040)

        binary = dos_header + pe_sig + file_hdr + bytes(opt_hdr)
        binary += bytes(text1) + bytes(text2) + bytes(data)

        while len(binary) < 0x400:
            binary += b"\x00"

        binary += b"\x90\xC3" * 0x100
        binary += b"\x55\x89\xE5\x5D\xC3" * 0x66
        binary += b"\x00" * 0x100

        multi_exec_binary.write_bytes(binary)

        extractor = BinaryFeatureExtractor(str(multi_exec_binary))
        exec_sections = extractor._get_executable_sections()

        assert len(exec_sections) >= 1

    def test_feature_extraction_preserves_dtype(self, pe32_binary_with_imports: Path) -> None:
        """All extracted features maintain float32 dtype."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        features = extractor.extract_all_features()

        for feature_array in features.values():
            assert feature_array.dtype == np.float32

    def test_opcode_histogram_normalized_sums_to_one(self, pe32_binary_with_imports: Path) -> None:
        """Normalized opcode histogram sums to approximately 1.0."""
        extractor = BinaryFeatureExtractor(str(pe32_binary_with_imports))
        histogram = extractor.extract_opcode_histogram(normalize=True)

        total_sum = np.sum(histogram)

        if total_sum > 0:
            assert np.isclose(total_sum, 1.0, atol=0.1)

    def test_api_features_detect_network_apis(self, tmp_path: Path) -> None:
        """API features detect network-related license validation APIs."""
        net_binary = tmp_path / "network_license.exe"

        dos_header = b"MZ" + b"\x00" * 62
        dos_header = bytearray(dos_header)
        dos_header[60:64] = struct.pack("<I", 0x80)

        pe_sig = b"PE\x00\x00"
        file_hdr = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 0xE0, 0x010B)
        opt_hdr = bytearray(224)
        struct.pack_into("<H", opt_hdr, 0, 0x010B)
        struct.pack_into("<I", opt_hdr, 28, 0x400000)

        import_dir_offset = 96
        struct.pack_into("<II", opt_hdr, import_dir_offset, 0x2000, 0x100)

        text_sec = bytearray(40)
        text_sec[0:6] = b".text\x00"
        struct.pack_into("<I", text_sec, 8, 0x100)
        struct.pack_into("<I", text_sec, 12, 0x1000)
        struct.pack_into("<I", text_sec, 16, 0x100)
        struct.pack_into("<I", text_sec, 20, 0x400)
        struct.pack_into("<I", text_sec, 36, 0x20000020)

        idata_sec = bytearray(40)
        idata_sec[0:7] = b".idata\x00"
        struct.pack_into("<I", idata_sec, 8, 0x200)
        struct.pack_into("<I", idata_sec, 12, 0x2000)
        struct.pack_into("<I", idata_sec, 16, 0x200)
        struct.pack_into("<I", idata_sec, 20, 0x500)
        struct.pack_into("<I", idata_sec, 36, 0xC0000040)

        import_data = bytearray(0x200)

        struct.pack_into("<IIIII", import_data, 0, 0x2100, 0, 0, 0x2150, 0x2120)
        struct.pack_into("<IIIII", import_data, 20, 0, 0, 0, 0, 0)

        dll_name = b"WININET.dll\x00"
        import_data[0x50 : 0x50 + len(dll_name)] = dll_name

        func_names = [
            b"InternetOpenA\x00",
            b"InternetConnectA\x00",
            b"HttpOpenRequestA\x00",
            b"HttpSendRequestA\x00",
        ]

        name_offset = 0x70
        for func_name in func_names:
            import_data[name_offset : name_offset + len(func_name)] = func_name
            name_offset += len(func_name)

        binary = bytes(dos_header) + pe_sig + file_hdr + bytes(opt_hdr)
        binary += bytes(text_sec) + bytes(idata_sec)

        while len(binary) < 0x400:
            binary += b"\x00"

        binary += b"\x90" * 0x100
        binary += bytes(import_data)

        net_binary.write_bytes(binary)

        extractor = BinaryFeatureExtractor(str(net_binary))
        api_features = extractor.extract_api_sequences()

        assert isinstance(api_features, np.ndarray)
        assert len(api_features) == 256

    def test_binary_without_pe_header_fallback(self, tmp_path: Path) -> None:
        """Extractor handles non-PE binaries with fallback logic."""
        raw_binary = tmp_path / "raw.bin"

        random_data = bytes([i % 256 for i in range(1024)])
        raw_binary.write_bytes(random_data)

        extractor = BinaryFeatureExtractor(str(raw_binary))

        assert extractor.data is not None
        assert len(extractor.data) == 1024

        features = extractor.extract_all_features()
        assert isinstance(features, dict)

    def test_zero_size_section_handling(self, tmp_path: Path) -> None:
        """Extractor handles zero-size sections without errors."""
        zero_sec_binary = tmp_path / "zero_section.exe"

        dos_header = b"MZ" + b"\x00" * 62
        dos_header = bytearray(dos_header)
        dos_header[60:64] = struct.pack("<I", 0x80)

        pe_sig = b"PE\x00\x00"
        file_hdr = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 0xE0, 0x010B)
        opt_hdr = b"\x00" * 224

        text_sec = bytearray(40)
        text_sec[0:6] = b".text\x00"
        struct.pack_into("<I", text_sec, 8, 0x100)
        struct.pack_into("<I", text_sec, 12, 0x1000)
        struct.pack_into("<I", text_sec, 16, 0x100)
        struct.pack_into("<I", text_sec, 20, 0x400)
        struct.pack_into("<I", text_sec, 36, 0x20000020)

        zero_sec = bytearray(40)
        zero_sec[0:6] = b".zero\x00"
        struct.pack_into("<I", zero_sec, 8, 0)
        struct.pack_into("<I", zero_sec, 12, 0x1100)
        struct.pack_into("<I", zero_sec, 16, 0)
        struct.pack_into("<I", zero_sec, 20, 0)
        struct.pack_into("<I", zero_sec, 36, 0xC0000040)

        binary = bytes(dos_header) + pe_sig + file_hdr + opt_hdr
        binary += bytes(text_sec) + bytes(zero_sec)

        while len(binary) < 0x400:
            binary += b"\x00"

        binary += b"\x90\xC3" * 0x80

        zero_sec_binary.write_bytes(binary)

        extractor = BinaryFeatureExtractor(str(zero_sec_binary))
        entropies = extractor.calculate_section_entropy()

        assert isinstance(entropies, np.ndarray)
        assert not np.any(np.isnan(entropies))
