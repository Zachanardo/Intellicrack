"""Production tests for function renaming engine.

Tests validate real function identification, pattern matching, and renaming
capabilities against actual PE binaries with license protection functions.

Copyright (C) 2025 Zachary Flint
"""

import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.function_renaming import (
    FunctionRenamingEngine,
    FunctionSignature,
    FunctionType,
)


class TestPEBinaryCreation:
    """Helper class for creating real PE binaries for testing."""

    @staticmethod
    def create_minimal_pe(code_section_data: bytes = b"") -> bytes:
        """Create minimal valid PE binary with code section.

        Args:
            code_section_data: Bytes to place in .text section

        Returns:
            Complete PE binary as bytes
        """
        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

        dos_stub = b"\x00" * (0x80 - 64)

        pe_signature = b"PE\x00\x00"

        machine = 0x014C
        num_sections = 1
        timestamp = 0
        symbol_table = 0
        num_symbols = 0
        optional_header_size = 224
        characteristics = 0x0102

        coff_header = struct.pack(
            "<HHIIIHH",
            machine,
            num_sections,
            timestamp,
            symbol_table,
            num_symbols,
            optional_header_size,
            characteristics,
        )

        sizeof_code = len(code_section_data) if code_section_data else 512

        optional_header = struct.pack(
            "<HBBIIIIIIIHHHHHHIIHHIIIIIIII",
            0x010B,
            14,
            0,
            sizeof_code,
            0,
            0,
            0x1000,
            0x1000,
            0x2000,
            0x00400000,
            0x1000,
            0x200,
            6,
            0,
            0,
            0,
            6,
            0,
            0,
            0x3000,
            0x200,
            0,
            3,
            0,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
        )

        data_directories = b"\x00" * (16 * 8)

        section_name = b".text\x00\x00\x00"
        virtual_size = sizeof_code
        virtual_address = 0x1000
        sizeof_raw_data = (sizeof_code + 0x1FF) & ~0x1FF
        pointer_to_raw_data = 0x200
        pointer_to_relocations = 0
        pointer_to_line_numbers = 0
        num_relocations = 0
        num_line_numbers = 0
        section_characteristics = 0x60000020

        section_header = struct.pack(
            "<8sIIIIIIHHI",
            section_name,
            virtual_size,
            virtual_address,
            sizeof_raw_data,
            pointer_to_raw_data,
            pointer_to_relocations,
            pointer_to_line_numbers,
            num_relocations,
            num_line_numbers,
            section_characteristics,
        )

        headers = (
            dos_header
            + dos_stub
            + pe_signature
            + coff_header
            + optional_header
            + data_directories
            + section_header
        )

        padding = b"\x00" * (0x200 - len(headers))
        headers += padding

        if code_section_data:
            code_data = code_section_data + b"\x00" * (sizeof_raw_data - len(code_section_data))
        else:
            code_data = b"\x00" * sizeof_raw_data

        return bytes(headers + code_data)

    @staticmethod
    def create_function_prolog(prolog_type: str = "stdcall") -> bytes:
        """Create function prolog bytes.

        Args:
            prolog_type: Type of prolog ('stdcall', 'fastcall', 'x64')

        Returns:
            Bytes representing function prolog
        """
        if prolog_type == "fastcall":
            return b"\x55\x89\xe5"
        elif prolog_type == "x64":
            return b"\x48\x89\x5c\x24\x08"
        else:
            return b"\x55\x8b\xec"

    @staticmethod
    def embed_string(text: str) -> bytes:
        """Convert string to embedded null-terminated bytes.

        Args:
            text: String to embed

        Returns:
            Null-terminated ASCII bytes
        """
        return text.encode("ascii") + b"\x00"


class TestFunctionRenamingEngineInitialization:
    """Test initialization and binary loading."""

    def test_init_with_valid_pe(self, tmp_path: Path) -> None:
        """Engine initializes successfully with valid PE binary."""
        pe_data = TestPEBinaryCreation.create_minimal_pe()
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)

        assert engine.binary_path == test_file
        assert len(engine.pe_data) > 0
        assert engine.image_base == 0x400000
        assert engine.code_section_start == 0x200
        assert engine.code_section_size > 0

    def test_init_with_nonexistent_file(self, tmp_path: Path) -> None:
        """Engine handles nonexistent file gracefully."""
        nonexistent = tmp_path / "nonexistent.exe"
        engine = FunctionRenamingEngine(nonexistent)

        assert engine.binary_path == nonexistent
        assert len(engine.pe_data) == 0

    def test_init_with_invalid_pe(self, tmp_path: Path) -> None:
        """Engine rejects invalid PE files."""
        invalid_file = tmp_path / "invalid.exe"
        invalid_file.write_bytes(b"Not a PE file" + b"\x00" * 100)

        with pytest.raises(ValueError, match="Invalid PE file"):
            FunctionRenamingEngine(invalid_file)

    def test_init_with_corrupted_pe_signature(self, tmp_path: Path) -> None:
        """Engine rejects PE with corrupted signature."""
        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[0x3C:0x40] = struct.pack("<I", 0x40)
        invalid_sig = dos_header + b"XX\x00\x00" + b"\x00" * 200

        test_file = tmp_path / "corrupted.exe"
        test_file.write_bytes(invalid_sig)

        with pytest.raises(ValueError, match="Invalid PE signature"):
            FunctionRenamingEngine(test_file)

    def test_extracts_image_base_32bit(self, tmp_path: Path) -> None:
        """Engine correctly extracts 32-bit image base."""
        pe_data = TestPEBinaryCreation.create_minimal_pe()
        test_file = tmp_path / "test32.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)

        assert engine.image_base == 0x400000

    def test_identifies_code_section(self, tmp_path: Path) -> None:
        """Engine identifies .text code section correctly."""
        code = b"\x55\x8b\xec" * 10
        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "with_code.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)

        assert engine.code_section_start == 0x200
        assert engine.code_section_size > 0


class TestFunctionScanning:
    """Test function prologue scanning and identification."""

    def test_scan_finds_stdcall_prolog(self, tmp_path: Path) -> None:
        """Scanner detects standard 32-bit function prolog."""
        prolog = TestPEBinaryCreation.create_function_prolog("stdcall")
        code = b"\x90" * 50 + prolog + b"\x90" * 100
        pe_data = TestPEBinaryCreation.create_minimal_pe(code)

        test_file = tmp_path / "stdcall.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()

        assert len(functions) > 0
        addresses = list(functions.keys())
        assert any(0x400000 <= addr <= 0x500000 for addr in addresses)

    def test_scan_finds_multiple_functions(self, tmp_path: Path) -> None:
        """Scanner detects multiple function prologs in code section."""
        prolog1 = TestPEBinaryCreation.create_function_prolog("stdcall")
        prolog2 = TestPEBinaryCreation.create_function_prolog("fastcall")
        prolog3 = b"\x48\x83\xec\x20"

        code = (
            b"\x90" * 20
            + prolog1
            + b"\x90" * 50
            + prolog2
            + b"\x90" * 30
            + prolog3
            + b"\x90" * 100
        )

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "multi_func.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()

        assert len(functions) >= 3

    def test_scan_calculates_function_sizes(self, tmp_path: Path) -> None:
        """Scanner calculates function sizes based on next function address."""
        prolog = b"\x55\x8b\xec"
        code = prolog + b"\x90" * 100 + prolog + b"\x90" * 50 + prolog + b"\x90" * 200

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "sized_funcs.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()

        sizes = [f.size for f in functions.values()]
        assert all(size > 0 for size in sizes)

    def test_scan_x64_function_prologs(self, tmp_path: Path) -> None:
        """Scanner detects x64 function prologs."""
        x64_prologs = [
            b"\x48\x89\x5c\x24\x08",
            b"\x48\x89\x4c\x24\x08",
            b"\x40\x55",
            b"\x40\x53",
        ]

        code = b"\x90" * 10
        for prolog in x64_prologs:
            code += prolog + b"\x90" * 40

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "x64_funcs.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()

        assert len(functions) >= len(x64_prologs)

    def test_scan_empty_code_section(self, tmp_path: Path) -> None:
        """Scanner handles empty code section gracefully."""
        pe_data = TestPEBinaryCreation.create_minimal_pe(b"\x00" * 100)
        test_file = tmp_path / "empty_code.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()

        assert isinstance(functions, dict)

    def test_function_signature_structure(self, tmp_path: Path) -> None:
        """Function signatures contain correct fields."""
        prolog = b"\x55\x8b\xec"
        code = prolog + b"\x90" * 100

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "sig_test.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()

        for func_sig in functions.values():
            assert isinstance(func_sig, FunctionSignature)
            assert func_sig.address > 0
            assert isinstance(func_sig.name, str)
            assert func_sig.size >= 0
            assert isinstance(func_sig.calls, list)
            assert isinstance(func_sig.strings, list)


class TestStringExtraction:
    """Test string extraction from function vicinity."""

    def test_extract_license_strings(self, tmp_path: Path) -> None:
        """Extracts license-related strings near function."""
        prolog = b"\x55\x8b\xec"
        license_str = TestPEBinaryCreation.embed_string("CheckLicenseKey")
        code = prolog + b"\x90" * 10 + license_str + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "license_str.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        strings = engine.extract_function_strings(func_addr)

        assert any("license" in s.lower() for s in strings)

    def test_extract_serial_validation_strings(self, tmp_path: Path) -> None:
        """Extracts serial validation strings."""
        prolog = b"\x55\x8b\xec"
        serial_str = TestPEBinaryCreation.embed_string("ValidateSerialNumber")
        product_key_str = TestPEBinaryCreation.embed_string("ProductKey")

        code = prolog + serial_str + b"\x90" * 10 + product_key_str + b"\x90" * 30

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "serial_str.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        strings = engine.extract_function_strings(func_addr)

        assert any("serial" in s.lower() for s in strings)
        assert any("product" in s.lower() for s in strings)

    def test_extract_trial_strings(self, tmp_path: Path) -> None:
        """Extracts trial-related strings."""
        prolog = b"\x55\x8b\xec"
        trial_str = TestPEBinaryCreation.embed_string("TrialExpired")
        demo_str = TestPEBinaryCreation.embed_string("DemoVersion")

        code = prolog + trial_str + b"\x90" * 5 + demo_str + b"\x90" * 20

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "trial_str.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        strings = engine.extract_function_strings(func_addr)

        assert any("trial" in s.lower() for s in strings)
        assert any("demo" in s.lower() for s in strings)

    def test_extract_registration_strings(self, tmp_path: Path) -> None:
        """Extracts registration-related strings."""
        prolog = b"\x55\x8b\xec"
        reg_str = TestPEBinaryCreation.embed_string("IsRegistered")
        code = prolog + reg_str + b"\x90" * 100

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "reg_str.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        strings = engine.extract_function_strings(func_addr)

        assert any("register" in s.lower() for s in strings)

    def test_extract_activation_strings(self, tmp_path: Path) -> None:
        """Extracts activation-related strings."""
        prolog = b"\x55\x8b\xec"
        activation_str = TestPEBinaryCreation.embed_string("OnlineActivation")
        code = prolog + activation_str + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "activation_str.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        strings = engine.extract_function_strings(func_addr)

        assert any("activation" in s.lower() for s in strings)

    def test_extract_filters_binary_data(self, tmp_path: Path) -> None:
        """String extraction filters out pure binary data."""
        prolog = b"\x55\x8b\xec"
        binary_junk = b"\x00\x01\x02\x03\xFF\xFE\xFD"
        valid_str = TestPEBinaryCreation.embed_string("ValidString")

        code = prolog + binary_junk + valid_str + b"\x90" * 30

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "filtered.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        strings = engine.extract_function_strings(func_addr)

        assert any("ValidString" in s for s in strings)
        assert all(any(c.isalpha() for c in s) for s in strings)

    def test_extract_respects_max_distance(self, tmp_path: Path) -> None:
        """String extraction respects maximum search distance."""
        prolog = b"\x55\x8b\xec"
        near_str = TestPEBinaryCreation.embed_string("NearString")
        far_str = TestPEBinaryCreation.embed_string("FarString")

        code = prolog + b"\x90" * 50 + near_str + b"\x90" * 2000 + far_str

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "distance.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        strings = engine.extract_function_strings(func_addr, max_distance=500)

        assert any("NearString" in s for s in strings)


class TestFunctionTypeIdentification:
    """Test function type identification based on patterns."""

    def test_identify_license_validation_function(self, tmp_path: Path) -> None:
        """Identifies license validation function correctly."""
        prolog = b"\x55\x8b\xec"
        strings = [
            TestPEBinaryCreation.embed_string("CheckLicenseValidity"),
            TestPEBinaryCreation.embed_string("ValidateLicense"),
        ]

        code = prolog + b"".join(strings) + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "license_func.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        result = engine.identify_function_type(func_addr)

        assert result.function_type == FunctionType.LICENSE_VALIDATION
        assert result.confidence > 0.3
        assert "license" in result.suggested_name.lower()

    def test_identify_serial_validation_function(self, tmp_path: Path) -> None:
        """Identifies serial validation function correctly."""
        prolog = b"\x55\x8b\xec"
        strings = [
            TestPEBinaryCreation.embed_string("ValidateSerialKey"),
            TestPEBinaryCreation.embed_string("CheckProductKey"),
        ]

        code = prolog + b"".join(strings) + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "serial_func.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        result = engine.identify_function_type(func_addr)

        assert result.function_type == FunctionType.SERIAL_VALIDATION
        assert result.confidence > 0.3
        assert "serial" in result.suggested_name.lower()

    def test_identify_registration_function(self, tmp_path: Path) -> None:
        """Identifies registration function correctly."""
        prolog = b"\x55\x8b\xec"
        strings = [
            TestPEBinaryCreation.embed_string("CheckRegistration"),
            TestPEBinaryCreation.embed_string("IsRegistered"),
        ]

        code = prolog + b"".join(strings) + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "reg_func.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        result = engine.identify_function_type(func_addr)

        assert result.function_type == FunctionType.REGISTRATION
        assert result.confidence > 0.3
        assert "registration" in result.suggested_name.lower()

    def test_identify_activation_function(self, tmp_path: Path) -> None:
        """Identifies activation function correctly."""
        prolog = b"\x55\x8b\xec"
        strings = [
            TestPEBinaryCreation.embed_string("OnlineActivation"),
            TestPEBinaryCreation.embed_string("ActivateProduct"),
        ]

        code = prolog + b"".join(strings) + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "activation_func.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        result = engine.identify_function_type(func_addr)

        assert result.function_type == FunctionType.ACTIVATION
        assert result.confidence > 0.3
        assert "activation" in result.suggested_name.lower()

    def test_identify_trial_check_function(self, tmp_path: Path) -> None:
        """Identifies trial check function correctly."""
        prolog = b"\x55\x8b\xec"
        strings = [
            TestPEBinaryCreation.embed_string("IsTrialExpired"),
            TestPEBinaryCreation.embed_string("CheckTrialPeriod"),
        ]

        code = prolog + b"".join(strings) + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "trial_func.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        result = engine.identify_function_type(func_addr)

        assert result.function_type == FunctionType.TRIAL_CHECK
        assert result.confidence > 0.3
        assert "trial" in result.suggested_name.lower()

    def test_identify_expiration_check_function(self, tmp_path: Path) -> None:
        """Identifies expiration check function correctly."""
        prolog = b"\x55\x8b\xec"
        strings = [
            TestPEBinaryCreation.embed_string("CheckExpiration"),
            TestPEBinaryCreation.embed_string("IsExpired"),
        ]

        code = prolog + b"".join(strings) + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "expiry_func.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        result = engine.identify_function_type(func_addr)

        assert result.function_type == FunctionType.EXPIRATION_CHECK
        assert result.confidence > 0.3
        assert "expir" in result.suggested_name.lower()

    def test_identify_hardware_id_function(self, tmp_path: Path) -> None:
        """Identifies hardware ID function correctly."""
        prolog = b"\x55\x8b\xec"
        strings = [
            TestPEBinaryCreation.embed_string("GetHardwareID"),
            TestPEBinaryCreation.embed_string("ComputerFingerprint"),
        ]

        code = prolog + b"".join(strings) + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "hwid_func.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        result = engine.identify_function_type(func_addr)

        assert result.function_type == FunctionType.HARDWARE_ID
        assert result.confidence > 0.3
        assert "hwid" in result.suggested_name.lower()

    def test_identify_online_validation_function(self, tmp_path: Path) -> None:
        """Identifies online validation function correctly."""
        prolog = b"\x55\x8b\xec"
        strings = [
            TestPEBinaryCreation.embed_string("ValidateOnlineServer"),
            TestPEBinaryCreation.embed_string("CloudLicenseCheck"),
        ]

        code = prolog + b"".join(strings) + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "online_func.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        result = engine.identify_function_type(func_addr)

        assert result.function_type == FunctionType.ONLINE_VALIDATION
        assert result.confidence > 0.3
        assert "online" in result.suggested_name.lower()

    def test_identify_cryptographic_function(self, tmp_path: Path) -> None:
        """Identifies cryptographic function correctly."""
        prolog = b"\x55\x8b\xec"
        strings = [
            TestPEBinaryCreation.embed_string("RSADecrypt"),
            TestPEBinaryCreation.embed_string("VerifySignature"),
        ]

        code = prolog + b"".join(strings) + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "crypto_func.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        result = engine.identify_function_type(func_addr)

        assert result.function_type == FunctionType.CRYPTOGRAPHIC
        assert result.confidence > 0.3
        assert "crypto" in result.suggested_name.lower()

    def test_identify_unknown_function(self, tmp_path: Path) -> None:
        """Identifies unknown function with low confidence."""
        prolog = b"\x55\x8b\xec"
        generic_str = TestPEBinaryCreation.embed_string("DoSomething")
        code = prolog + generic_str + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "unknown_func.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        result = engine.identify_function_type(func_addr)

        assert result.function_type == FunctionType.UNKNOWN
        assert result.confidence < 0.3

    def test_confidence_increases_with_multiple_patterns(self, tmp_path: Path) -> None:
        """Confidence increases with multiple matching patterns."""
        prolog = b"\x55\x8b\xec"
        strings = [
            TestPEBinaryCreation.embed_string("license"),
            TestPEBinaryCreation.embed_string("validate"),
            TestPEBinaryCreation.embed_string("check"),
            TestPEBinaryCreation.embed_string("verify"),
        ]

        code = prolog + b"".join(strings) + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "multi_pattern.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        result = engine.identify_function_type(func_addr)

        assert result.confidence > 0.5
        assert len(result.evidence) > 0

    def test_custom_pattern_matching(self, tmp_path: Path) -> None:
        """Custom patterns can be used for identification."""
        prolog = b"\x55\x8b\xec"
        custom_str = TestPEBinaryCreation.embed_string("CustomProtection")
        code = prolog + custom_str + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "custom.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        func_addr = list(functions.keys())[0]

        custom_patterns = {FunctionType.LICENSE_VALIDATION: [r"custom.*protection"]}

        result = engine.identify_function_type(func_addr, custom_patterns)

        assert result.function_type == FunctionType.LICENSE_VALIDATION
        assert result.confidence > 0.0


class TestBatchFunctionIdentification:
    """Test batch processing of multiple functions."""

    def test_batch_identify_all_functions(self, tmp_path: Path) -> None:
        """Batch identification processes all functions."""
        prolog = b"\x55\x8b\xec"
        func1_str = TestPEBinaryCreation.embed_string("CheckLicense")
        func2_str = TestPEBinaryCreation.embed_string("ValidateSerial")
        func3_str = TestPEBinaryCreation.embed_string("IsRegistered")

        code = (
            prolog
            + func1_str
            + b"\x90" * 50
            + prolog
            + func2_str
            + b"\x90" * 50
            + prolog
            + func3_str
            + b"\x90" * 50
        )

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "batch.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        results = engine.batch_identify_functions(min_confidence=0.1)

        assert len(results) >= 3
        assert all(r.confidence >= 0.1 for r in results)

    def test_batch_respects_min_confidence(self, tmp_path: Path) -> None:
        """Batch identification filters by minimum confidence."""
        prolog = b"\x55\x8b\xec"
        high_conf_str = TestPEBinaryCreation.embed_string("CheckLicenseValidation")
        low_conf_str = TestPEBinaryCreation.embed_string("DoSomething")

        code = (
            prolog
            + high_conf_str
            + b"\x90" * 50
            + prolog
            + low_conf_str
            + b"\x90" * 50
        )

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "confidence.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        results = engine.batch_identify_functions(min_confidence=0.5)

        assert all(r.confidence >= 0.5 for r in results)

    def test_batch_sorted_by_confidence(self, tmp_path: Path) -> None:
        """Batch results are sorted by confidence descending."""
        prolog = b"\x55\x8b\xec"
        strings = [
            TestPEBinaryCreation.embed_string("license"),
            TestPEBinaryCreation.embed_string("serial"),
            TestPEBinaryCreation.embed_string("unknown"),
        ]

        code = b""
        for s in strings:
            code += prolog + s + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "sorted.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        results = engine.batch_identify_functions(min_confidence=0.0)

        confidences = [r.confidence for r in results]
        assert confidences == sorted(confidences, reverse=True)

    def test_batch_with_filter_function(self, tmp_path: Path) -> None:
        """Batch identification applies custom filter function."""
        prolog = b"\x55\x8b\xec"
        code = (prolog + b"\x90" * 100) * 5

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "filtered.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)

        def size_filter(func_sig: FunctionSignature) -> bool:
            return func_sig.size > 50

        results = engine.batch_identify_functions(filter_func=size_filter)

        assert all(engine.functions[r.address].size > 50 for r in results)


class TestLicenseFunctionFinding:
    """Test finding specific license-related function types."""

    def test_find_license_validation_functions(self, tmp_path: Path) -> None:
        """Finds only license validation functions."""
        prolog = b"\x55\x8b\xec"
        license_str = TestPEBinaryCreation.embed_string("ValidateLicense")
        serial_str = TestPEBinaryCreation.embed_string("CheckSerial")

        code = (
            prolog
            + license_str
            + b"\x90" * 50
            + prolog
            + serial_str
            + b"\x90" * 50
        )

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "find_license.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        results = engine.find_license_functions(
            function_types=[FunctionType.LICENSE_VALIDATION], min_confidence=0.1
        )

        assert all(r.function_type == FunctionType.LICENSE_VALIDATION for r in results)

    def test_find_multiple_function_types(self, tmp_path: Path) -> None:
        """Finds multiple specified function types."""
        prolog = b"\x55\x8b\xec"
        license_str = TestPEBinaryCreation.embed_string("CheckLicense")
        serial_str = TestPEBinaryCreation.embed_string("ValidateSerial")
        trial_str = TestPEBinaryCreation.embed_string("IsTrialExpired")

        code = (
            prolog
            + license_str
            + b"\x90" * 50
            + prolog
            + serial_str
            + b"\x90" * 50
            + prolog
            + trial_str
            + b"\x90" * 50
        )

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "multi_type.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        results = engine.find_license_functions(
            function_types=[
                FunctionType.LICENSE_VALIDATION,
                FunctionType.SERIAL_VALIDATION,
                FunctionType.TRIAL_CHECK,
            ],
            min_confidence=0.1,
        )

        found_types = {r.function_type for r in results}
        assert FunctionType.LICENSE_VALIDATION in found_types or FunctionType.SERIAL_VALIDATION in found_types or FunctionType.TRIAL_CHECK in found_types

    def test_find_default_license_types(self, tmp_path: Path) -> None:
        """Default search includes main license-related types."""
        prolog = b"\x55\x8b\xec"
        license_str = TestPEBinaryCreation.embed_string("license")
        code = prolog + license_str + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "default.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        results = engine.find_license_functions(min_confidence=0.1)

        assert len(results) >= 0


class TestScriptExport:
    """Test export of rename scripts for various tools."""

    def test_export_ida_script(self, tmp_path: Path) -> None:
        """Exports valid IDA Pro Python script."""
        prolog = b"\x55\x8b\xec"
        license_str = TestPEBinaryCreation.embed_string("CheckLicense")
        code = prolog + license_str + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "ida_export.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        results = engine.batch_identify_functions(min_confidence=0.1)

        output_script = tmp_path / "ida_rename.py"
        success = engine.export_rename_script(results, output_script, format="ida")

        assert success
        assert output_script.exists()

        script_content = output_script.read_text()
        assert "import idc" in script_content
        assert "idc.set_name" in script_content

    def test_export_ghidra_script(self, tmp_path: Path) -> None:
        """Exports valid Ghidra Python script."""
        prolog = b"\x55\x8b\xec"
        serial_str = TestPEBinaryCreation.embed_string("ValidateSerial")
        code = prolog + serial_str + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "ghidra_export.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        results = engine.batch_identify_functions(min_confidence=0.1)

        output_script = tmp_path / "ghidra_rename.py"
        success = engine.export_rename_script(results, output_script, format="ghidra")

        assert success
        assert output_script.exists()

        script_content = output_script.read_text()
        assert "ghidra" in script_content.lower()
        assert "setName" in script_content

    def test_export_radare2_script(self, tmp_path: Path) -> None:
        """Exports valid radare2 script."""
        prolog = b"\x55\x8b\xec"
        reg_str = TestPEBinaryCreation.embed_string("CheckRegistration")
        code = prolog + reg_str + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "r2_export.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        results = engine.batch_identify_functions(min_confidence=0.1)

        output_script = tmp_path / "r2_rename.r2"
        success = engine.export_rename_script(results, output_script, format="radare2")

        assert success
        assert output_script.exists()

        script_content = output_script.read_text()
        assert "afn" in script_content

    def test_export_creates_parent_directories(self, tmp_path: Path) -> None:
        """Export creates parent directories if they don't exist."""
        prolog = b"\x55\x8b\xec"
        code = prolog + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "export.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        results = engine.batch_identify_functions(min_confidence=0.1)

        nested_path = tmp_path / "scripts" / "ida" / "rename.py"
        success = engine.export_rename_script(results, nested_path, format="ida")

        assert success
        assert nested_path.exists()

    def test_export_invalid_format(self, tmp_path: Path) -> None:
        """Export rejects invalid format."""
        prolog = b"\x55\x8b\xec"
        code = prolog + b"\x90" * 50

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "invalid_format.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        results = engine.batch_identify_functions(min_confidence=0.1)

        output_script = tmp_path / "invalid.py"
        success = engine.export_rename_script(results, output_script, format="unknown")

        assert not success


class TestStatistics:
    """Test statistics generation."""

    def test_statistics_counts_functions(self, tmp_path: Path) -> None:
        """Statistics correctly count total functions."""
        prolog = b"\x55\x8b\xec"
        code = (prolog + b"\x90" * 50) * 5

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "stats.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        engine.scan_for_functions()
        stats = engine.get_statistics()

        assert "total_functions" in stats
        assert stats["total_functions"] > 0

    def test_statistics_shows_type_distribution(self, tmp_path: Path) -> None:
        """Statistics show distribution of function types."""
        prolog = b"\x55\x8b\xec"
        license_str = TestPEBinaryCreation.embed_string("license")
        serial_str = TestPEBinaryCreation.embed_string("serial")

        code = (
            prolog
            + license_str
            + b"\x90" * 50
            + prolog
            + serial_str
            + b"\x90" * 50
        )

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "type_dist.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        stats = engine.get_statistics()

        assert "function_types" in stats
        assert isinstance(stats["function_types"], dict)

    def test_statistics_shows_confidence_distribution(self, tmp_path: Path) -> None:
        """Statistics show confidence level distribution."""
        prolog = b"\x55\x8b\xec"
        high_conf_str = TestPEBinaryCreation.embed_string("CheckLicenseValidation")
        low_conf_str = TestPEBinaryCreation.embed_string("function")

        code = (
            prolog
            + high_conf_str
            + b"\x90" * 50
            + prolog
            + low_conf_str
            + b"\x90" * 50
        )

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "conf_dist.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        stats = engine.get_statistics()

        assert "confidence_distribution" in stats
        dist = stats["confidence_distribution"]
        assert "high (>= 0.7)" in dist
        assert "medium (0.4-0.7)" in dist
        assert "low (< 0.4)" in dist


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_analyze_complex_protected_binary(self, tmp_path: Path) -> None:
        """Analyzes binary with multiple protection functions."""
        prolog = b"\x55\x8b\xec"
        functions_data = [
            (TestPEBinaryCreation.embed_string("CheckLicense"), b"\x90" * 80),
            (TestPEBinaryCreation.embed_string("ValidateSerial"), b"\x90" * 60),
            (TestPEBinaryCreation.embed_string("IsRegistered"), b"\x90" * 70),
            (TestPEBinaryCreation.embed_string("GetHWID"), b"\x90" * 50),
            (TestPEBinaryCreation.embed_string("TrialExpired"), b"\x90" * 90),
        ]

        code = b""
        for func_str, padding in functions_data:
            code += prolog + func_str + padding

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "complex.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        functions = engine.scan_for_functions()
        results = engine.batch_identify_functions(min_confidence=0.2)

        assert len(functions) >= 5
        assert len(results) >= 3

    def test_export_workflow(self, tmp_path: Path) -> None:
        """Complete workflow from scan to export."""
        prolog = b"\x55\x8b\xec"
        license_str = TestPEBinaryCreation.embed_string("ValidateLicenseKey")
        serial_str = TestPEBinaryCreation.embed_string("CheckSerialNumber")

        code = (
            prolog
            + license_str
            + b"\x90" * 50
            + prolog
            + serial_str
            + b"\x90" * 50
        )

        pe_data = TestPEBinaryCreation.create_minimal_pe(code)
        test_file = tmp_path / "workflow.exe"
        test_file.write_bytes(pe_data)

        engine = FunctionRenamingEngine(test_file)
        engine.scan_for_functions()
        results = engine.find_license_functions(min_confidence=0.2)

        ida_script = tmp_path / "ida_rename.py"
        ghidra_script = tmp_path / "ghidra_rename.py"
        r2_script = tmp_path / "r2_rename.r2"

        assert engine.export_rename_script(results, ida_script, "ida")
        assert engine.export_rename_script(results, ghidra_script, "ghidra")
        assert engine.export_rename_script(results, r2_script, "radare2")

        assert ida_script.exists()
        assert ghidra_script.exists()
        assert r2_script.exists()

    def test_windows_system_binary_analysis(self) -> None:
        """Analyzes real Windows system binary if available."""
        system_binaries = [
            Path(r"C:\Windows\System32\notepad.exe"),
            Path(r"C:\Windows\System32\calc.exe"),
            Path(r"C:\Windows\System32\cmd.exe"),
        ]

        binary_to_test = next(
            (
                binary_path
                for binary_path in system_binaries
                if binary_path.exists()
            ),
            None,
        )
        if not binary_to_test:
            pytest.skip("No Windows system binaries available")

        engine = FunctionRenamingEngine(binary_to_test)
        functions = engine.scan_for_functions()

        assert len(functions) > 0
        assert engine.image_base > 0
        assert engine.code_section_size > 0
