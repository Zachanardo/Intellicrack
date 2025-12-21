#!/usr/bin/env python3
from __future__ import annotations

import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.protection.themida_analyzer import (
    DevirtualizedCode,
    ThemidaAnalyzer,
    ThemidaAnalysisResult,
    ThemidaVersion,
    VMArchitecture,
    VMContext,
    VMHandler,
)


def create_pe_header() -> bytes:
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 0x80)

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,
        3,
        0,
        0,
        0,
        0xE0,
        0x010B,
    )

    optional_header = bytearray(224)
    optional_header[:2] = struct.pack("<H", 0x010B)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[20:24] = struct.pack("<I", 0x1000)
    optional_header[24:28] = struct.pack("<I", 0x400000)
    optional_header[28:32] = struct.pack("<I", 0x1000)
    optional_header[32:36] = struct.pack("<I", 0x200)

    return bytes(dos_header) + pe_signature + coff_header + bytes(optional_header)


def create_pe_section(
    name: bytes,
    virtual_address: int,
    virtual_size: int,
    raw_size: int,
    raw_offset: int,
    characteristics: int,
) -> bytes:
    section = bytearray(40)
    section[:8] = name[:8].ljust(8, b"\x00")
    section[8:12] = struct.pack("<I", virtual_size)
    section[12:16] = struct.pack("<I", virtual_address)
    section[16:20] = struct.pack("<I", raw_size)
    section[20:24] = struct.pack("<I", raw_offset)
    section[36:40] = struct.pack("<I", characteristics)
    return bytes(section)


def create_themida_protected_binary_v1() -> bytes:
    pe_header = create_pe_header()

    text_section = create_pe_section(
        b".text",
        0x1000,
        0x1000,
        0x1000,
        0x400,
        0x60000020,
    )

    themida_section = create_pe_section(
        b".themida",
        0x2000,
        0x2000,
        0x2000,
        0x1400,
        0xE0000020,
    )

    data_section = create_pe_section(
        b".data",
        0x4000,
        0x1000,
        0x1000,
        0x3400,
        0xC0000040,
    )

    sections = text_section + themida_section + data_section

    pe = pe_header + sections

    padding = b"\x00" * (0x400 - len(pe))

    text_code = bytearray(0x1000)
    text_code[:10] = b"\x8b\xc5\x8b\xd4\x60\xe8\x00\x00\x00\x00"
    text_code[100:106] = b"\x8b\x45\x00\x89\x45\x04"
    text_code[200:206] = b"\x8b\x45\x00\x03\x45\x04"
    text_code[300:304] = b"\xf7\x45\x00"
    text_code[400:403] = b"\xff\x24\x85"
    text_code[403:407] = struct.pack("<I", 0x402000)
    text_code[500:510] = b"\x9c\x60\xe8\x00\x00\x00\x00\x5d\x81\xed"
    text_code[600:606] = b"\x64\xa1\x30\x00\x00\x00"
    text_code[700:716] = b"IsDebuggerPresent\x00"
    text_code[800:815] = b"VirtualProtect\x00"

    themida_code = bytearray(0x2000)
    themida_code[:10] = b"\x8b\xc5\x8b\xd4\x60\xe8\x00\x00\x00\x00"
    themida_code[100:112] = b"\xeb\x10\x66\x62\x3a\x43\x2b\x2b\x48\x4f\x4f\x4b"

    for i in range(10):
        themida_code[1000 + i * 4 : 1000 + i * 4 + 4] = struct.pack("<I", 0x402000 + i * 16)

    themida_code[1500:1506] = b"\x8b\x45\x00\x89\x45\x04"
    themida_code[1510:1516] = b"\x8b\x45\x00\x03\x45\x04"
    themida_code[1520:1526] = b"\x8b\x45\x00\x2b\x45\x04"
    themida_code[1530:1536] = b"\x8b\x45\x00\x0f\xaf\x45\x04"
    themida_code[1540:1546] = b"\x8b\x45\x00\x33\x45\x04"

    high_entropy_key = bytes(i ^ 0xA5 for i in range(32))
    themida_code[2000:2032] = high_entropy_key

    themida_code[3000:3002] = b"\x61\xc3"

    data_section_content = bytearray(0x1000)
    data_section_content[:32] = bytes(i ^ 0x5A for i in range(32))

    return pe + padding + bytes(text_code) + bytes(themida_code) + bytes(data_section_content)


def create_themida_protected_binary_v2() -> bytes:
    pe_header = create_pe_header()

    text_section = create_pe_section(
        b".text",
        0x1000,
        0x1000,
        0x1000,
        0x400,
        0x60000020,
    )

    themida_section = create_pe_section(
        b".winlice",
        0x2000,
        0x2000,
        0x2000,
        0x1400,
        0xE0000020,
    )

    data_section = create_pe_section(
        b".data",
        0x4000,
        0x1000,
        0x1000,
        0x3400,
        0xC0000040,
    )

    sections = text_section + themida_section + data_section
    pe = pe_header + sections
    padding = b"\x00" * (0x400 - len(pe))

    text_code = bytearray(0x1000)
    text_code[:9] = b"\xb8\x00\x00\x00\x00\x60\x0b\xc0\x74"
    text_code[100:106] = b"\x8b\x45\x00\x89\x45\x04"
    text_code[200:203] = b"\xff\x24\x85"
    text_code[203:207] = struct.pack("<I", 0x402000)
    text_code[300:310] = b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed"
    text_code[400:407] = b"\x64\x8b\x15\x30\x00\x00\x00"
    text_code[500:502] = b"\x0f\x31"
    text_code[600:622] = b"CheckRemoteDebuggerPresent\x00"
    text_code[700:713] = b"VirtualAlloc\x00"

    themida_code = bytearray(0x2000)
    themida_code[:9] = b"\xb8\x00\x00\x00\x00\x60\x0b\xc0\x74"

    for i in range(12):
        themida_code[1000 + i * 4 : 1000 + i * 4 + 4] = struct.pack("<I", 0x402000 + i * 16)

    themida_code[1500:1506] = b"\x8b\x45\x00\x89\x45\x04"
    themida_code[1510:1516] = b"\x8b\x45\x00\x03\x45\x04"
    themida_code[1520:1526] = b"\x8b\x45\x00\x2b\x45\x04"
    themida_code[1530:1536] = b"\x8b\x45\x00\x0f\xaf\x45\x04"
    themida_code[1540:1546] = b"\x8b\x45\x00\x33\x45\x04"
    themida_code[1550:1556] = b"\x8b\x45\x00\x0b\x45\x04"
    themida_code[1560:1566] = b"\x8b\x45\x00\x23\x45\x04"

    high_entropy_key1 = bytes((i * 7 + 13) % 256 for i in range(16))
    high_entropy_key2 = bytes((i * 11 + 23) % 256 for i in range(32))
    themida_code[2000:2016] = high_entropy_key1
    themida_code[2100:2132] = high_entropy_key2

    themida_code[3000:3003] = b"\x61\x9d\xc3"

    data_section_content = b"\x00" * 0x1000

    return pe + padding + bytes(text_code) + bytes(themida_code) + data_section_content


def create_themida_protected_binary_v3() -> bytes:
    pe_header = create_pe_header()

    text_section = create_pe_section(
        b".text",
        0x1000,
        0x1000,
        0x1000,
        0x400,
        0x60000020,
    )

    themida_section = create_pe_section(
        b".oreans",
        0x2000,
        0x2000,
        0x2000,
        0x1400,
        0xE0000020,
    )

    data_section = create_pe_section(
        b".data",
        0x4000,
        0x1000,
        0x1000,
        0x3400,
        0xC0000040,
    )

    sections = text_section + themida_section + data_section
    pe = pe_header + sections
    padding = b"\x00" * (0x400 - len(pe))

    text_code = bytearray(0x1000)
    text_code[:9] = b"\x55\x8b\xec\x83\xc4\xf0\x53\x56\x57"
    text_code[100:106] = b"\x8b\x45\x00\x89\x45\x04"
    text_code[200:209] = b"\x89\x45\x00\x8b\x45\x04\x89\x45\x08"
    text_code[300:310] = b"Themida\x00\x00\x00"

    themida_code = bytearray(0x2000)
    themida_code[:9] = b"\x55\x8b\xec\x83\xc4\xf0\x53\x56\x57"

    data_section_content = b"\x00" * 0x1000

    return pe + padding + bytes(text_code) + bytes(themida_code) + data_section_content


def create_winlicense_protected_binary_v1() -> bytes:
    pe_header = create_pe_header()

    text_section = create_pe_section(
        b".text",
        0x1000,
        0x1000,
        0x1000,
        0x400,
        0x60000020,
    )

    winlicense_section = create_pe_section(
        b"WinLice",
        0x2000,
        0x2000,
        0x2000,
        0x1400,
        0xE0000020,
    )

    data_section = create_pe_section(
        b".data",
        0x4000,
        0x1000,
        0x1000,
        0x3400,
        0xC0000040,
    )

    sections = text_section + winlicense_section + data_section
    pe = pe_header + sections
    padding = b"\x00" * (0x400 - len(pe))

    text_code = bytearray(0x1000)
    text_code[:8] = b"\x68\x00\x00\x00\x00\x9c\x60\xe8"
    text_code[100:112] = b"\xeb\x10\x66\x62\x3a\x43\x2b\x2b\x48\x4f\x4f\x4b"
    text_code[200:206] = b"\x8b\x45\x00\x89\x45\x04"

    winlicense_code = bytearray(0x2000)
    winlicense_code[:8] = b"\x68\x00\x00\x00\x00\x9c\x60\xe8"
    winlicense_code[100:112] = b"\xeb\x10\x66\x62\x3a\x43\x2b\x2b\x48\x4f\x4f\x4b"

    data_section_content = b"\x00" * 0x1000

    return pe + padding + bytes(text_code) + bytes(winlicense_code) + data_section_content


def create_risc_vm_binary() -> bytes:
    pe_header = create_pe_header()

    text_section = create_pe_section(
        b".text",
        0x1000,
        0x1000,
        0x1000,
        0x400,
        0x60000020,
    )

    themida_section = create_pe_section(
        b".themida",
        0x2000,
        0x2000,
        0x2000,
        0x1400,
        0xE0000020,
    )

    data_section = create_pe_section(
        b".data",
        0x4000,
        0x1000,
        0x1000,
        0x3400,
        0xC0000040,
    )

    sections = text_section + themida_section + data_section
    pe = pe_header + sections
    padding = b"\x00" * (0x400 - len(pe))

    text_code = bytearray(0x1000)
    text_code[:10] = b"\x8b\xc5\x8b\xd4\x60\xe8\x00\x00\x00\x00"

    themida_code = bytearray(0x2000)
    themida_code[:4] = b"\xe2\x8f\x00\x00"
    themida_code[10:14] = b"\xe0\x80\x00\x00"
    themida_code[20:24] = b"\xe0\x40\x00\x00"
    themida_code[30:34] = b"\xe0\x00\x00\x00"
    themida_code[40:44] = b"\xe2\x00\x00\x00"
    themida_code[50:54] = b"\xe1\x80\x00\x00"
    themida_code[60:64] = b"\xe0\x00\x00\x01"
    themida_code[70:74] = b"\xe2\x61\x00\x00"
    themida_code[100:105] = b"RISC\x00"

    data_section_content = b"\x00" * 0x1000

    return pe + padding + bytes(text_code) + bytes(themida_code) + data_section_content


def create_fish_vm_binary() -> bytes:
    pe_header = create_pe_header()

    text_section = create_pe_section(
        b".text",
        0x1000,
        0x1000,
        0x1000,
        0x400,
        0x60000020,
    )

    themida_section = create_pe_section(
        b".themida",
        0x2000,
        0x2000,
        0x2000,
        0x1400,
        0xE0000020,
    )

    data_section = create_pe_section(
        b".data",
        0x4000,
        0x1000,
        0x1000,
        0x3400,
        0xC0000040,
    )

    sections = text_section + themida_section + data_section
    pe = pe_header + sections
    padding = b"\x00" * (0x400 - len(pe))

    text_code = bytearray(0x1000)
    text_code[:10] = b"\x8b\xc5\x8b\xd4\x60\xe8\x00\x00\x00\x00"

    themida_code = bytearray(0x2000)
    themida_code[:3] = b"\x48\x8b\x00"
    themida_code[10:13] = b"\x48\x01\x00"
    themida_code[20:23] = b"\x48\x29\x00"
    themida_code[30:34] = b"\x48\x0f\xaf\x00"
    themida_code[40:43] = b"\x48\x31\x00"
    themida_code[50:53] = b"\x48\x09\x00"
    themida_code[60:63] = b"\x48\x21\x00"
    themida_code[70:73] = b"\x48\xf7\x18"
    themida_code[100:105] = b"FISH\x00"

    data_section_content = b"\x00" * 0x1000

    return pe + padding + bytes(text_code) + bytes(themida_code) + data_section_content


def create_clean_binary() -> bytes:
    pe_header = create_pe_header()

    text_section = create_pe_section(
        b".text",
        0x1000,
        0x1000,
        0x1000,
        0x400,
        0x60000020,
    )

    data_section = create_pe_section(
        b".data",
        0x2000,
        0x1000,
        0x1000,
        0x1400,
        0xC0000040,
    )

    sections = text_section + data_section
    pe = pe_header + sections
    padding = b"\x00" * (0x400 - len(pe))

    text_code = b"\x00" * 0x1000
    data_section_content = b"\x00" * 0x1000

    return pe + padding + text_code + data_section_content


class TestThemidaAnalyzerInitialization:
    def test_analyzer_creation(self) -> None:
        analyzer = ThemidaAnalyzer()

        assert analyzer is not None
        assert hasattr(analyzer, "analyze")
        assert hasattr(analyzer, "binary_data")
        assert analyzer.binary_data is None
        assert analyzer.is_64bit is False

    def test_analyzer_has_signature_databases(self) -> None:
        assert hasattr(ThemidaAnalyzer, "THEMIDA_SIGNATURES")
        assert hasattr(ThemidaAnalyzer, "VM_SECTION_NAMES")
        assert hasattr(ThemidaAnalyzer, "CISC_HANDLER_PATTERNS")
        assert hasattr(ThemidaAnalyzer, "RISC_HANDLER_PATTERNS")
        assert hasattr(ThemidaAnalyzer, "FISH_HANDLER_PATTERNS")

        assert len(ThemidaAnalyzer.THEMIDA_SIGNATURES) > 0
        assert len(ThemidaAnalyzer.VM_SECTION_NAMES) > 0
        assert len(ThemidaAnalyzer.CISC_HANDLER_PATTERNS) > 0

    def test_signature_databases_have_correct_structure(self) -> None:
        for signature in ThemidaAnalyzer.THEMIDA_SIGNATURES:
            assert isinstance(signature, bytes)
            assert len(signature) > 0

        for section_name in ThemidaAnalyzer.VM_SECTION_NAMES:
            assert isinstance(section_name, bytes)

        for opcode, pattern in ThemidaAnalyzer.CISC_HANDLER_PATTERNS.items():
            assert isinstance(opcode, int)
            assert isinstance(pattern, bytes)
            assert len(pattern) > 0


class TestThemidaVersionDetection:
    def test_version_enum_exists(self) -> None:
        assert ThemidaVersion.THEMIDA_1X
        assert ThemidaVersion.THEMIDA_2X
        assert ThemidaVersion.THEMIDA_3X
        assert ThemidaVersion.WINLICENSE_1X
        assert ThemidaVersion.WINLICENSE_2X
        assert ThemidaVersion.WINLICENSE_3X
        assert ThemidaVersion.UNKNOWN

    def test_detect_themida_1x_version(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.is_protected is True
            assert result.version == ThemidaVersion.THEMIDA_1X
            assert result.confidence > 0.0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_detect_themida_2x_version(self) -> None:
        binary = create_themida_protected_binary_v2()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.is_protected is True
            assert result.version == ThemidaVersion.THEMIDA_2X
            assert result.confidence > 0.0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_detect_themida_3x_version(self) -> None:
        binary = create_themida_protected_binary_v3()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.is_protected is True
            assert result.version == ThemidaVersion.THEMIDA_3X
            assert result.confidence > 0.0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_detect_winlicense_version(self) -> None:
        binary = create_winlicense_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.is_protected is True
            assert result.version in [ThemidaVersion.WINLICENSE_1X, ThemidaVersion.WINLICENSE_2X]
            assert result.confidence > 0.0
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestThemidaPresenceDetection:
    def test_detect_protection_by_signature(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.is_protected is True
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_detect_protection_by_section_name(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.is_protected is True
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_no_detection_on_clean_binary(self) -> None:
        binary = create_clean_binary()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.is_protected is False
            assert result.version == ThemidaVersion.UNKNOWN
            assert result.vm_architecture == VMArchitecture.UNKNOWN
            assert len(result.vm_sections) == 0
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestVMArchitectureDetection:
    def test_detect_cisc_architecture(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.vm_architecture == VMArchitecture.CISC
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_detect_risc_architecture(self) -> None:
        binary = create_risc_vm_binary()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.vm_architecture == VMArchitecture.RISC
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_detect_fish_architecture(self) -> None:
        binary = create_fish_vm_binary()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.vm_architecture == VMArchitecture.FISH
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestVMSectionDetection:
    def test_find_themida_section(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.is_protected is True
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_find_winlicense_section(self) -> None:
        binary = create_themida_protected_binary_v2()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.is_protected is True
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_find_oreans_section(self) -> None:
        binary = create_themida_protected_binary_v3()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.is_protected is True
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestVMEntryPointDetection:
    def test_find_entry_points(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert len(result.vm_entry_points) > 0
            assert all(isinstance(ep, int) for ep in result.vm_entry_points)
            assert all(ep >= 0 for ep in result.vm_entry_points)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_entry_points_are_sorted(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            if len(result.vm_entry_points) > 1:
                assert result.vm_entry_points == sorted(result.vm_entry_points)
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestHandlerTableDetection:
    def test_find_handler_table(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.handler_table_address >= 0
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestHandlerExtraction:
    def test_extract_cisc_handlers(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert len(result.handlers) > 0

            for opcode, handler in result.handlers.items():
                assert isinstance(handler, VMHandler)
                assert handler.opcode == opcode
                assert handler.address >= 0
                assert handler.size > 0
                assert isinstance(handler.category, str)
                assert 1 <= handler.complexity <= 10
                assert isinstance(handler.references, list)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_handler_categories_are_valid(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            valid_categories = [
                "arithmetic",
                "logical",
                "data_transfer",
                "comparison",
                "control_flow",
                "stack_operation",
                "complex",
                "unknown",
            ]

            for handler in result.handlers.values():
                assert handler.category in valid_categories
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestVMContextExtraction:
    def test_extract_vm_contexts(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert len(result.vm_contexts) > 0

            for context in result.vm_contexts:
                assert isinstance(context, VMContext)
                assert context.vm_entry >= 0
                assert context.vm_exit >= 0
                assert context.context_size > 0
                assert isinstance(context.register_mapping, dict)
                assert context.stack_offset >= 0
                assert context.flags_offset >= 0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_context_register_mapping(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            if result.vm_contexts:
                context = result.vm_contexts[0]
                assert len(context.register_mapping) > 0
                assert all(isinstance(k, str) for k in context.register_mapping.keys())
                assert all(isinstance(v, int) for v in context.register_mapping.values())
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestEncryptionKeyExtraction:
    def test_extract_encryption_keys(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert isinstance(result.encryption_keys, list)

            for key in result.encryption_keys:
                assert isinstance(key, bytes)
                assert len(key) in {16, 32}
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_extracted_keys_have_high_entropy(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            for key in result.encryption_keys:
                entropy = analyzer._calculate_entropy_bytes(key)
                assert entropy > 6.0
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestAntiDebugDetection:
    def test_find_anti_debug_checks(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert isinstance(result.anti_debug_locations, list)
            assert len(result.anti_debug_locations) > 0

            for location in result.anti_debug_locations:
                assert isinstance(location, int)
                assert location >= 0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_detect_peb_check(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            peb_check_offset = binary.find(b"\x64\xa1\x30\x00\x00\x00")

            assert peb_check_offset in result.anti_debug_locations
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_detect_api_checks(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            isdebuggerpresent_offset = binary.find(b"IsDebuggerPresent")

            assert isdebuggerpresent_offset in result.anti_debug_locations
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestAntiDumpDetection:
    def test_find_anti_dump_checks(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert isinstance(result.anti_dump_locations, list)
            assert len(result.anti_dump_locations) > 0

            for location in result.anti_dump_locations:
                assert isinstance(location, int)
                assert location >= 0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_detect_virtualprotect_calls(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            virtualprotect_offset = binary.find(b"VirtualProtect")

            assert virtualprotect_offset in result.anti_dump_locations
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestDevirtualization:
    def test_devirtualize_code_sections(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert isinstance(result.devirtualized_sections, list)

            for section in result.devirtualized_sections:
                assert isinstance(section, DevirtualizedCode)
                assert section.original_rva >= 0
                assert section.original_size > 0
                assert isinstance(section.vm_handlers_used, list)
                assert isinstance(section.native_code, bytes)
                assert isinstance(section.assembly, list)
                assert 0.0 <= section.confidence <= 100.0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_devirtualized_code_has_native_instructions(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            if result.devirtualized_sections:
                for section in result.devirtualized_sections:
                    assert len(section.native_code) > 0
                    assert len(section.assembly) > 0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_devirtualization_confidence_score(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            for section in result.devirtualized_sections:
                assert section.confidence >= 0.0
                assert section.confidence <= 100.0
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestConfidenceCalculation:
    def test_confidence_on_protected_binary(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.confidence > 0.0
            assert result.confidence <= 100.0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_confidence_on_clean_binary(self) -> None:
        binary = create_clean_binary()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.confidence == 0.0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_higher_confidence_with_more_features(self) -> None:
        binary_v1 = create_themida_protected_binary_v1()
        binary_v2 = create_themida_protected_binary_v2()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f1:
            f1.write(binary_v1)
            temp_path1 = f1.name

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f2:
            f2.write(binary_v2)
            temp_path2 = f2.name

        try:
            analyzer = ThemidaAnalyzer()
            result1 = analyzer.analyze(temp_path1)

            analyzer2 = ThemidaAnalyzer()
            result2 = analyzer2.analyze(temp_path2)

            assert result1.confidence > 0.0
            assert result2.confidence > 0.0
        finally:
            Path(temp_path1).unlink(missing_ok=True)
            Path(temp_path2).unlink(missing_ok=True)


class TestAnalysisReport:
    def test_generate_analysis_report(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)
            report = analyzer.get_analysis_report(result)

            assert isinstance(report, dict)

            required_keys = [
                "protection_detected",
                "version",
                "vm_architecture",
                "confidence",
                "vm_sections",
                "vm_entry_points",
                "handler_table",
                "handlers_extracted",
                "vm_contexts",
                "devirtualized_sections",
                "anti_debug_checks",
                "anti_dump_checks",
                "integrity_checks",
            ]

            for key in required_keys:
                assert key in report
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_report_contains_handler_categories(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)
            report = analyzer.get_analysis_report(result)

            if result.handlers:
                assert "handler_categories" in report
                assert isinstance(report["handler_categories"], dict)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_report_contains_devirtualization_quality(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)
            report = analyzer.get_analysis_report(result)

            if result.devirtualized_sections:
                assert "devirtualization_quality" in report
                assert "average_confidence" in report["devirtualization_quality"]
                assert "total_instructions" in report["devirtualization_quality"]
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestEdgeCases:
    def test_handle_corrupted_binary(self) -> None:
        corrupted_binary = b"MZ" + b"\xFF" * 1000

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(corrupted_binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert isinstance(result, ThemidaAnalysisResult)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_handle_empty_binary(self) -> None:
        empty_binary = b""

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(empty_binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.is_protected is False
            assert result.confidence == 0.0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_handle_tiny_binary(self) -> None:
        tiny_binary = b"MZ\x00\x00"

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(tiny_binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert isinstance(result, ThemidaAnalysisResult)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_handle_large_binary_gracefully(self) -> None:
        large_binary = create_themida_protected_binary_v1() + b"\x00" * 10_000_000

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(large_binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert isinstance(result, ThemidaAnalysisResult)
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestIntegrationScenarios:
    def test_full_analysis_workflow_themida_1x(self) -> None:
        binary = create_themida_protected_binary_v1()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.is_protected is True
            assert result.version == ThemidaVersion.THEMIDA_1X
            assert result.vm_architecture == VMArchitecture.CISC
            assert len(result.vm_entry_points) > 0
            assert len(result.handlers) > 0
            assert len(result.anti_debug_locations) > 0
            assert len(result.anti_dump_locations) > 0
            assert result.confidence > 40.0

            report = analyzer.get_analysis_report(result)
            assert report["protection_detected"] is True
            assert "CISC" in report["vm_architecture"]
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_full_analysis_workflow_themida_2x(self) -> None:
        binary = create_themida_protected_binary_v2()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(temp_path)

            assert result.is_protected is True
            assert result.version == ThemidaVersion.THEMIDA_2X
            assert result.vm_architecture == VMArchitecture.CISC
            assert len(result.handlers) > 0
            assert result.confidence > 40.0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_comparison_themida_versions(self) -> None:
        binary_v1 = create_themida_protected_binary_v1()
        binary_v2 = create_themida_protected_binary_v2()
        binary_v3 = create_themida_protected_binary_v3()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f1:
            f1.write(binary_v1)
            temp_path1 = f1.name

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f2:
            f2.write(binary_v2)
            temp_path2 = f2.name

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f3:
            f3.write(binary_v3)
            temp_path3 = f3.name

        try:
            analyzer1 = ThemidaAnalyzer()
            result1 = analyzer1.analyze(temp_path1)

            analyzer2 = ThemidaAnalyzer()
            result2 = analyzer2.analyze(temp_path2)

            analyzer3 = ThemidaAnalyzer()
            result3 = analyzer3.analyze(temp_path3)

            assert result1.version == ThemidaVersion.THEMIDA_1X
            assert result2.version == ThemidaVersion.THEMIDA_2X
            assert result3.version == ThemidaVersion.THEMIDA_3X

            assert all(r.is_protected for r in [result1, result2, result3])
        finally:
            Path(temp_path1).unlink(missing_ok=True)
            Path(temp_path2).unlink(missing_ok=True)
            Path(temp_path3).unlink(missing_ok=True)
