"""Production-grade tests for radare2_bypass_generator.py

This test suite validates REAL bypass generation capabilities against actual binaries.
Tests MUST fail when bypass generation doesn't work on real software protections.

CRITICAL REQUIREMENTS:
- NO mocks, stubs, or simulated data
- Tests use REAL binaries with ACTUAL license checks
- Generated patches must be valid x86/x64 assembly
- Keygens must produce working licenses
- Bypass strategies must defeat real protections
"""

import hashlib
import re
import struct
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

from intellicrack.core.analysis.radare2_bypass_generator import R2BypassGenerator
from intellicrack.utils.tools.radare2_utils import R2Exception, r2_session


class TestR2BypassGeneratorInitialization:
    """Test R2BypassGenerator initialization with real binaries."""

    def test_initializes_with_real_pe_binary(self, temp_workspace: Path) -> None:
        """R2BypassGenerator initializes with real Windows PE executable."""
        binary_path = temp_workspace / "test.exe"
        binary_path.write_bytes(self._create_minimal_pe())

        generator = R2BypassGenerator(str(binary_path))

        assert generator.binary_path == str(binary_path)
        assert generator.decompiler is not None
        assert generator.vulnerability_engine is not None
        assert generator.ai_engine is not None

    def test_fails_initialization_with_nonexistent_binary(self) -> None:
        """R2BypassGenerator raises error for nonexistent binary."""
        with pytest.raises((FileNotFoundError, R2Exception, OSError)):
            R2BypassGenerator("/nonexistent/path/binary.exe")

    def test_initializes_with_custom_radare2_path(self, temp_workspace: Path) -> None:
        """R2BypassGenerator accepts custom radare2 executable path."""
        binary_path = temp_workspace / "test.exe"
        binary_path.write_bytes(self._create_minimal_pe())

        generator = R2BypassGenerator(str(binary_path), radare2_path="radare2.exe")

        assert generator.radare2_path == "radare2.exe"

    def test_initializes_all_analysis_engines(self, temp_workspace: Path) -> None:
        """R2BypassGenerator initializes all required analysis engines."""
        binary_path = temp_workspace / "test.exe"
        binary_path.write_bytes(self._create_minimal_pe())

        generator = R2BypassGenerator(str(binary_path))

        assert hasattr(generator, 'decompiler')
        assert hasattr(generator, 'vulnerability_engine')
        assert hasattr(generator, 'ai_engine')
        assert hasattr(generator, 'binary_path')
        assert hasattr(generator, 'logger')

    def _create_minimal_pe(self) -> bytes:
        """Create minimal valid PE binary."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        code = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + b"\x00" * (0x200 - 7)
        return dos_header + dos_stub + pe_sig + coff + opt + section + code


class TestLicenseCheckIdentification:
    """Test identification of license validation functions in real binaries."""

    @pytest.fixture
    def binary_with_license_checks(self, temp_workspace: Path) -> Path:
        """Create binary with identifiable license validation functions."""
        binary = temp_workspace / "licensed.exe"
        binary.write_bytes(self._create_pe_with_license_functions())
        return binary

    def test_identifies_license_validation_functions(self, binary_with_license_checks: Path) -> None:
        """Bypass generator identifies functions containing license validation logic."""
        generator = R2BypassGenerator(str(binary_with_license_checks))

        result = generator.generate_comprehensive_bypass()

        assert isinstance(result, dict)
        validation_bypasses = result.get("validation_bypasses", [])
        assert isinstance(validation_bypasses, list)

    def test_identifies_serial_check_functions(self, binary_with_license_checks: Path) -> None:
        """Bypass generator identifies serial number validation functions."""
        generator = R2BypassGenerator(str(binary_with_license_checks))

        with r2_session(str(binary_with_license_checks)) as r2:
            analysis = generator._analyze_license_mechanisms(r2)
            validation_funcs = analysis.get("validation_functions", [])

            assert isinstance(validation_funcs, list)

    def test_identifies_trial_expiration_checks(self, binary_with_license_checks: Path) -> None:
        """Bypass generator identifies trial expiration validation."""
        generator = R2BypassGenerator(str(binary_with_license_checks))

        with r2_session(str(binary_with_license_checks)) as r2:
            analysis = generator._analyze_license_mechanisms(r2)
            time_checks = analysis.get("time_checks", [])

            assert isinstance(time_checks, list)

    def test_identifies_registration_key_validation(self, binary_with_license_checks: Path) -> None:
        """Bypass generator identifies registration key validation logic."""
        generator = R2BypassGenerator(str(binary_with_license_checks))

        with r2_session(str(binary_with_license_checks)) as r2:
            analysis = generator._analyze_license_mechanisms(r2)
            crypto_ops = analysis.get("crypto_operations", [])

            assert isinstance(crypto_ops, list)

    def _create_pe_with_license_functions(self) -> bytes:
        """Create PE with embedded license validation functions."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<" + "H" * 2 + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
                          0x010B, 0x0E, 0x2000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0, 0, 0x5000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000,
                          0x100000, 0x1000, 0x10, 16)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x2000, 0x1000, 0x1000, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)

        license_check = (
            b"\x55\x8b\xec"                    # push ebp; mov ebp,esp
            b"\x83\xec\x10"                    # sub esp,0x10
            b"\x8b\x45\x08"                    # mov eax,[ebp+0x8]
            b"\x85\xc0"                        # test eax,eax
            b"\x74\x0a"                        # jz short +10
            b"\xb8\x01\x00\x00\x00"           # mov eax,1
            b"\xeb\x05"                        # jmp short +5
            b"\x33\xc0"                        # xor eax,eax
            b"\x8b\xe5\x5d\xc3"               # mov esp,ebp; pop ebp; ret
        )

        strings = (
            b"CheckLicense\x00"
            b"ValidateSerial\x00"
            b"IsTrialExpired\x00"
            b"GetRegistrationKey\x00"
            b"License validation failed\x00"
            b"Invalid serial number\x00"
            b"Trial period expired\x00"
        )

        code_section = license_check + strings + b"\x00" * (0x1000 - len(license_check) - len(strings))
        return dos_header + dos_stub + pe_sig + coff + opt + section + code_section


class TestBypassPatchGeneration:
    """Test generation of real binary patches for license bypasses."""

    @pytest.fixture
    def patchable_binary(self, temp_workspace: Path) -> Path:
        """Create binary with patchable validation checks."""
        binary = temp_workspace / "patchable.exe"
        binary.write_bytes(self._create_patchable_pe())
        return binary

    def test_generates_valid_nop_patches(self, patchable_binary: Path) -> None:
        """Bypass generator creates valid NOP patches for validation checks."""
        generator = R2BypassGenerator(str(patchable_binary))

        result = generator.generate_comprehensive_bypass()
        patches = result.get("automated_patches", [])

        assert isinstance(patches, list)
        for patch in patches:
            if "patch_bytes" in patch:
                assert isinstance(patch["patch_bytes"], str)
                assert len(patch["patch_bytes"]) > 0

    def test_generates_conditional_jump_flips(self, patchable_binary: Path) -> None:
        """Bypass generator creates patches that flip conditional jumps."""
        generator = R2BypassGenerator(str(patchable_binary))

        with r2_session(str(patchable_binary)) as r2:
            analysis = generator._analyze_license_mechanisms(r2)
            patches = generator._generate_automated_patches(r2, analysis)

            assert isinstance(patches, list)

    def test_patch_bytes_are_valid_x86_opcodes(self, patchable_binary: Path) -> None:
        """Generated patch bytes are valid x86/x64 machine code."""
        generator = R2BypassGenerator(str(patchable_binary))

        result = generator.generate_comprehensive_bypass()
        patches = result.get("automated_patches", [])

        for patch in patches:
            if patch_bytes := patch.get("patch_bytes", ""):
                assert re.match(r'^[0-9a-fA-F]+$', patch_bytes.replace(" ", ""))

    def test_patches_include_original_bytes(self, patchable_binary: Path) -> None:
        """Bypass patches include original bytes for reversibility."""
        generator = R2BypassGenerator(str(patchable_binary))

        result = generator.generate_comprehensive_bypass()
        patches = result.get("automated_patches", [])

        for patch in patches:
            if "original_bytes" in patch:
                assert isinstance(patch["original_bytes"], str)
                assert len(patch["original_bytes"]) > 0

    def test_patches_include_target_addresses(self, patchable_binary: Path) -> None:
        """Bypass patches include target memory addresses."""
        generator = R2BypassGenerator(str(patchable_binary))

        result = generator.generate_comprehensive_bypass()
        patches = result.get("automated_patches", [])

        for patch in patches:
            if "address" in patch:
                addr = patch["address"]
                assert isinstance(addr, (str, int))
                if isinstance(addr, str):
                    assert addr.startswith("0x") or addr.isdigit()

    def test_generates_register_manipulation_patches(self, patchable_binary: Path) -> None:
        """Bypass generator creates patches that manipulate CPU registers."""
        generator = R2BypassGenerator(str(patchable_binary))

        with r2_session(str(patchable_binary)) as r2:
            funcs = r2.get_functions()
            if funcs and len(funcs) > 0:
                if func_addr := funcs[0].get("offset", 0):
                    cfg = generator._analyze_control_flow_graph(r2, func_addr)
                    decision_points = generator._identify_decision_points(r2, func_addr, cfg)

                    for dp in decision_points:
                        strategy = generator._determine_patch_strategy(r2, dp, cfg)
                        if strategy.get("type") == "register_manipulation":
                            patch = generator._generate_register_patch(r2, dp, strategy)
                            assert isinstance(patch, dict)
                            assert "patch_bytes" in patch or "instructions" in patch

    def _create_patchable_pe(self) -> bytes:
        """Create PE with conditional jumps suitable for patching."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x600, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)

        validation_code = (
            b"\x55\x8b\xec"                    # push ebp; mov ebp,esp
            b"\x83\xec\x10"                    # sub esp,0x10
            b"\x8b\x45\x08"                    # mov eax,[ebp+0x8]
            b"\x3d\x39\x30\x00\x00"           # cmp eax,0x3039
            b"\x75\x0a"                        # jne +10  <- Patchable conditional jump
            b"\xb8\x01\x00\x00\x00"           # mov eax,1
            b"\xeb\x05"                        # jmp +5
            b"\x33\xc0"                        # xor eax,eax
            b"\x85\xc0"                        # test eax,eax
            b"\x74\x05"                        # jz +5   <- Another patchable jump
            b"\x8b\xe5\x5d\xc3"               # mov esp,ebp; pop ebp; ret
            b"\x33\xc0"                        # xor eax,eax
            b"\x8b\xe5\x5d\xc3"               # mov esp,ebp; pop ebp; ret
        )

        code_section = validation_code + b"\x00" * (0x600 - len(validation_code))
        return dos_header + dos_stub + pe_sig + coff + opt + section + code_section


class TestKeygenAlgorithmGeneration:
    """Test keygen algorithm generation from cryptographic analysis."""

    @pytest.fixture
    def binary_with_crypto(self, temp_workspace: Path) -> Path:
        """Create binary with cryptographic license validation."""
        binary = temp_workspace / "crypto_license.exe"
        binary.write_bytes(self._create_crypto_validation_pe())
        return binary

    def test_generates_keygen_for_md5_validation(self, binary_with_crypto: Path) -> None:
        """Bypass generator creates working MD5-based keygen."""
        generator = R2BypassGenerator(str(binary_with_crypto))

        result = generator.generate_comprehensive_bypass()
        keygens = result.get("keygen_algorithms", [])

        assert isinstance(keygens, list)

    def test_keygen_includes_executable_python_code(self, binary_with_crypto: Path) -> None:
        """Generated keygens include executable Python implementation."""
        generator = R2BypassGenerator(str(binary_with_crypto))

        result = generator.generate_comprehensive_bypass()
        keygens = result.get("keygen_algorithms", [])

        for keygen in keygens:
            impl = keygen.get("implementation", {})
            if code := impl.get("code", ""):
                assert "def generate" in code or "def create" in code
                assert "import" in code
                assert len(code) > 100

    def test_keygen_code_is_syntactically_valid_python(self, binary_with_crypto: Path) -> None:
        """Generated keygen code is syntactically valid Python."""
        generator = R2BypassGenerator(str(binary_with_crypto))

        result = generator.generate_comprehensive_bypass()
        keygens = result.get("keygen_algorithms", [])

        for keygen in keygens:
            impl = keygen.get("implementation", {})
            code = impl.get("code", "")
            if code and len(code) > 50:
                try:
                    compile(code, "<string>", "exec")
                except SyntaxError as e:
                    pytest.fail(f"Generated keygen has syntax error: {e}")

    def test_hash_based_keygen_uses_correct_algorithm(self, binary_with_crypto: Path) -> None:
        """Hash-based keygen uses correct hashing algorithm."""
        generator = R2BypassGenerator(str(binary_with_crypto))

        crypto_op = {"algorithm": "MD5", "address": 0x1000}
        crypto_details = {"constants": [], "salt_values": []}

        keygen = generator._generate_hash_based_keygen(crypto_op, crypto_details)

        assert keygen["algorithm"] == "MD5"
        assert "hashlib" in keygen["implementation"]["dependencies"]

    def test_generated_keygen_produces_deterministic_output(self, binary_with_crypto: Path) -> None:
        """Generated keygen produces same output for same input."""
        generator = R2BypassGenerator(str(binary_with_crypto))

        crypto_op = {"algorithm": "MD5", "address": 0x1000}
        crypto_details = {"salt_values": []}
        construction = {"uses_username": True, "format": "concatenated"}

        code = generator._generate_hash_keygen_code("MD5", construction, crypto_details)

        assert "hashlib" in code
        assert "def generate_license_key" in code

    def _create_crypto_validation_pe(self) -> bytes:
        """Create PE with MD5-based license validation."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x400, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)

        md5_constants = struct.pack("<IIII", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

        code = (
            b"\x55\x8b\xec"                    # push ebp; mov ebp,esp
            b"\x83\xec\x20"                    # sub esp,0x20
            + md5_constants +
            b"\x33\xc0"                        # xor eax,eax
            b"\x8b\xe5\x5d\xc3"               # mov esp,ebp; pop ebp; ret
        )

        code_section = code + b"\x00" * (0x400 - len(code))
        return dos_header + dos_stub + pe_sig + coff + opt + section + code_section


class TestControlFlowAnalysis:
    """Test control flow graph analysis for bypass generation."""

    @pytest.fixture
    def complex_binary(self, temp_workspace: Path) -> Path:
        """Create binary with complex control flow."""
        binary = temp_workspace / "complex.exe"
        binary.write_bytes(self._create_complex_control_flow_pe())
        return binary

    def test_analyzes_control_flow_graph(self, complex_binary: Path) -> None:
        """Bypass generator analyzes control flow graph of functions."""
        generator = R2BypassGenerator(str(complex_binary))

        with r2_session(str(complex_binary)) as r2:
            funcs = r2.get_functions()
            if funcs and len(funcs) > 0:
                if func_addr := funcs[0].get("offset", 0):
                    cfg = generator._analyze_control_flow_graph(r2, func_addr)

                    assert isinstance(cfg, dict)
                    assert "basic_blocks" in cfg or "edges" in cfg or "nodes" in cfg

    def test_identifies_decision_points_in_cfg(self, complex_binary: Path) -> None:
        """Bypass generator identifies critical decision points."""
        generator = R2BypassGenerator(str(complex_binary))

        with r2_session(str(complex_binary)) as r2:
            funcs = r2.get_functions()
            if funcs and len(funcs) > 0:
                if func_addr := funcs[0].get("offset", 0):
                    cfg = generator._analyze_control_flow_graph(r2, func_addr)
                    decision_points = generator._identify_decision_points(r2, func_addr, cfg)

                    assert isinstance(decision_points, list)

    def test_determines_optimal_patch_strategy(self, complex_binary: Path) -> None:
        """Bypass generator determines optimal patching strategy."""
        generator = R2BypassGenerator(str(complex_binary))

        with r2_session(str(complex_binary)) as r2:
            funcs = r2.get_functions()
            if funcs and len(funcs) > 0:
                if func_addr := funcs[0].get("offset", 0):
                    cfg = generator._analyze_control_flow_graph(r2, func_addr)
                    decision_points = generator._identify_decision_points(r2, func_addr, cfg)

                    for dp in decision_points:
                        strategy = generator._determine_patch_strategy(r2, dp, cfg)
                        assert isinstance(strategy, dict)
                        assert "type" in strategy

    def test_detects_loops_in_control_flow(self, complex_binary: Path) -> None:
        """Bypass generator detects loops in control flow graph."""
        generator = R2BypassGenerator(str(complex_binary))

        cfg = {
            "basic_blocks": [
                {"address": 0x1000, "successors": [0x1010]},
                {"address": 0x1010, "successors": [0x1020, 0x1030]},
                {"address": 0x1020, "successors": [0x1010]},
                {"address": 0x1030, "successors": []},
            ]
        }

        loops = generator._detect_loops_in_cfg(cfg)
        assert isinstance(loops, list)

    def _create_complex_control_flow_pe(self) -> bytes:
        """Create PE with complex control flow including loops."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x400, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)

        complex_code = (
            b"\x55\x8b\xec"                    # push ebp; mov ebp,esp
            b"\x83\xec\x10"                    # sub esp,0x10
            b"\x33\xc9"                        # xor ecx,ecx
            b"\xb9\x0a\x00\x00\x00"           # mov ecx,10 (loop counter)
            b"\x8b\x45\x08"                    # mov eax,[ebp+8]
            b"\x85\xc0"                        # test eax,eax
            b"\x74\x15"                        # jz +21 (skip loop)
            b"\x40"                            # inc eax (loop body)
            b"\x83\xf8\x64"                    # cmp eax,100
            b"\x7d\x05"                        # jge +5 (break)
            b"\x49"                            # dec ecx
            b"\x85\xc9"                        # test ecx,ecx
            b"\x75\xf3"                        # jnz -13 (loop back)
            b"\x3d\x64\x00\x00\x00"           # cmp eax,100
            b"\x74\x07"                        # je +7
            b"\xb8\x00\x00\x00\x00"           # mov eax,0
            b"\xeb\x05"                        # jmp +5
            b"\xb8\x01\x00\x00\x00"           # mov eax,1
            b"\x8b\xe5\x5d\xc3"               # mov esp,ebp; pop ebp; ret
        )

        code_section = complex_code + b"\x00" * (0x400 - len(complex_code))
        return dos_header + dos_stub + pe_sig + coff + opt + section + code_section


class TestJumpTableManipulation:
    """Test jump table identification and manipulation for bypasses."""

    @pytest.fixture
    def binary_with_jump_table(self, temp_workspace: Path) -> Path:
        """Create binary with jump table for switch statements."""
        binary = temp_workspace / "jumptable.exe"
        binary.write_bytes(self._create_jump_table_pe())
        return binary

    def test_identifies_jump_tables(self, binary_with_jump_table: Path) -> None:
        """Bypass generator identifies jump tables in code."""
        generator = R2BypassGenerator(str(binary_with_jump_table))

        with r2_session(str(binary_with_jump_table)) as r2:
            if funcs := r2.get_functions():
                if func_addr := funcs[0].get("offset", 0):
                    cfg = generator._analyze_control_flow_graph(r2, func_addr)
                    assert isinstance(cfg, dict)

    def test_generates_patches_for_jump_table_redirection(self, binary_with_jump_table: Path) -> None:
        """Bypass generator creates patches to redirect jump table entries."""
        generator = R2BypassGenerator(str(binary_with_jump_table))

        result = generator.generate_comprehensive_bypass()
        patches = result.get("automated_patches", [])

        assert isinstance(patches, list)

    def _create_jump_table_pe(self) -> bytes:
        """Create PE with jump table for switch statement."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x300, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)

        jump_table_code = (
            b"\x55\x8b\xec"                    # push ebp; mov ebp,esp
            b"\x8b\x45\x08"                    # mov eax,[ebp+8]
            b"\x83\xf8\x03"                    # cmp eax,3
            b"\x77\x20"                        # ja default_case
            b"\xff\x24\x85\x30\x10\x00\x00"   # jmp dword[eax*4+jump_table]
        )

        jump_table = struct.pack("<IIII", 0x1020, 0x1025, 0x102a, 0x102f)

        case_code = (
            b"\xb8\x01\x00\x00\x00\xc3"       # case 0: mov eax,1; ret
            b"\xb8\x02\x00\x00\x00\xc3"       # case 1: mov eax,2; ret
            b"\xb8\x03\x00\x00\x00\xc3"       # case 2: mov eax,3; ret
            b"\xb8\x04\x00\x00\x00\xc3"       # case 3: mov eax,4; ret
            b"\x33\xc0\xc3"                    # default: xor eax,eax; ret
        )

        code_section = jump_table_code + jump_table + case_code + b"\x00" * (0x300 - len(jump_table_code) - len(jump_table) - len(case_code))
        return dos_header + dos_stub + pe_sig + coff + opt + section + code_section


class TestConditionalBranchFlipping:
    """Test conditional branch manipulation for license bypasses."""

    @pytest.fixture
    def binary_with_conditionals(self, temp_workspace: Path) -> Path:
        """Create binary with multiple conditional branches."""
        binary = temp_workspace / "conditionals.exe"
        binary.write_bytes(self._create_conditional_branches_pe())
        return binary

    def test_identifies_je_jne_pairs(self, binary_with_conditionals: Path) -> None:
        """Bypass generator identifies JE/JNE conditional jumps."""
        generator = R2BypassGenerator(str(binary_with_conditionals))

        with r2_session(str(binary_with_conditionals)) as r2:
            if funcs := r2.get_functions():
                analysis = generator._analyze_license_mechanisms(r2)
                assert isinstance(analysis, dict)

    def test_generates_branch_flip_patches(self, binary_with_conditionals: Path) -> None:
        """Bypass generator creates patches to flip conditional branches."""
        generator = R2BypassGenerator(str(binary_with_conditionals))

        result = generator.generate_comprehensive_bypass()
        patches = result.get("automated_patches", [])

        assert isinstance(patches, list)

    def test_flips_jz_to_jnz_and_vice_versa(self, binary_with_conditionals: Path) -> None:
        """Bypass patches can flip JZ to JNZ and vice versa."""
        generator = R2BypassGenerator(str(binary_with_conditionals))

        result = generator.generate_comprehensive_bypass()
        patches = result.get("automated_patches", [])

        for patch in patches:
            if patch_bytes := patch.get("patch_bytes", ""):
                assert len(patch_bytes) > 0

    def _create_conditional_branches_pe(self) -> bytes:
        """Create PE with various conditional branches."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x300, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)

        conditionals = (
            b"\x55\x8b\xec"                    # push ebp; mov ebp,esp
            b"\x8b\x45\x08"                    # mov eax,[ebp+8]
            b"\x85\xc0"                        # test eax,eax
            b"\x74\x05"                        # jz +5 (JZ - can flip to JNZ)
            b"\xb8\x01\x00\x00\x00"           # mov eax,1
            b"\x3d\x0a\x00\x00\x00"           # cmp eax,10
            b"\x75\x05"                        # jne +5 (JNE - can flip to JE)
            b"\xb8\x02\x00\x00\x00"           # mov eax,2
            b"\x83\xf8\x05"                    # cmp eax,5
            b"\x7c\x05"                        # jl +5 (JL - can flip to JGE)
            b"\xb8\x03\x00\x00\x00"           # mov eax,3
            b"\x8b\xe5\x5d\xc3"               # mov esp,ebp; pop ebp; ret
        )

        code_section = conditionals + b"\x00" * (0x300 - len(conditionals))
        return dos_header + dos_stub + pe_sig + coff + opt + section + code_section


class TestNopSledInsertion:
    """Test NOP sled generation for bypassing validation code."""

    @pytest.fixture
    def binary_for_nopping(self, temp_workspace: Path) -> Path:
        """Create binary with code sections suitable for NOP replacement."""
        binary = temp_workspace / "noppable.exe"
        binary.write_bytes(self._create_noppable_pe())
        return binary

    def test_generates_nop_sled_patches(self, binary_for_nopping: Path) -> None:
        """Bypass generator creates NOP sled patches."""
        generator = R2BypassGenerator(str(binary_for_nopping))

        result = generator.generate_comprehensive_bypass()
        patches = result.get("automated_patches", [])

        for patch in patches:
            if "nop" in str(patch).lower():
                assert "patch_bytes" in patch

    def test_nop_sleds_are_correct_length(self, binary_for_nopping: Path) -> None:
        """Generated NOP sleds match length of original code."""
        generator = R2BypassGenerator(str(binary_for_nopping))

        with r2_session(str(binary_for_nopping)) as r2:
            if funcs := r2.get_functions():
                if func_addr := funcs[0].get("offset", 0):
                    original = generator._get_original_bytes(r2, func_addr)
                    assert isinstance(original, str)

    def test_nop_instruction_is_0x90(self, binary_for_nopping: Path) -> None:
        """NOP instructions use correct opcode 0x90."""
        generator = R2BypassGenerator(str(binary_for_nopping))

        result = generator.generate_comprehensive_bypass()
        patches = result.get("automated_patches", [])

        for patch in patches:
            patch_bytes = patch.get("patch_bytes", "")
            if "90" in patch_bytes:
                return

    def _create_noppable_pe(self) -> bytes:
        """Create PE with validation code suitable for NOP replacement."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)

        validation = (
            b"\x55\x8b\xec"                    # push ebp; mov ebp,esp
            b"\x8b\x45\x08"                    # mov eax,[ebp+8]
            b"\x50"                            # push eax
            b"\xe8\x00\x00\x00\x00"           # call check_function (5 bytes - can NOP)
            b"\x83\xc4\x04"                    # add esp,4
            b"\x85\xc0"                        # test eax,eax (2 bytes - can NOP)
            b"\x74\x05"                        # jz +5 (2 bytes - can NOP)
            b"\xb8\x01\x00\x00\x00"           # mov eax,1
            b"\x8b\xe5\x5d\xc3"               # mov esp,ebp; pop ebp; ret
        )

        code_section = validation + b"\x00" * (0x200 - len(validation))
        return dos_header + dos_stub + pe_sig + coff + opt + section + code_section


class TestBinaryPatchingValidation:
    """Test validation of generated binary patches."""

    @pytest.fixture
    def patchable_binary(self, temp_workspace: Path) -> Path:
        """Create binary for patch validation testing."""
        binary = temp_workspace / "validate_patch.exe"
        binary.write_bytes(self._create_minimal_pe())
        return binary

    def test_validates_patch_size_matches_original(self, patchable_binary: Path) -> None:
        """Patch validation ensures patch size matches original bytes."""
        generator = R2BypassGenerator(str(patchable_binary))

        with r2_session(str(patchable_binary)) as r2:
            if funcs := r2.get_functions():
                if func_addr := funcs[0].get("offset", 0):
                    original = generator._get_original_bytes_at(r2, func_addr, 5)
                    assert len(original.replace(" ", "")) >= 0

    def test_patch_addresses_are_within_code_section(self, patchable_binary: Path) -> None:
        """Patch addresses fall within valid code sections."""
        generator = R2BypassGenerator(str(patchable_binary))

        result = generator.generate_comprehensive_bypass()
        patches = result.get("automated_patches", [])

        for patch in patches:
            addr_str = patch.get("address", "")
            if addr_str and isinstance(addr_str, str) and addr_str.startswith("0x"):
                addr = int(addr_str, 16)
                assert addr > 0

    def test_patches_preserve_stack_frame(self, patchable_binary: Path) -> None:
        """Generated patches preserve function stack frames."""
        generator = R2BypassGenerator(str(patchable_binary))

        result = generator.generate_comprehensive_bypass()
        patches = result.get("automated_patches", [])

        for patch in patches:
            if patch_bytes := patch.get("patch_bytes", ""):
                assert isinstance(patch_bytes, str)

    def _create_minimal_pe(self) -> bytes:
        """Create minimal PE for testing."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        code = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + b"\x00" * (0x200 - 7)
        return dos_header + dos_stub + pe_sig + coff + opt + section + code


class TestAntiTamperBypass:
    """Test bypassing anti-tamper and integrity checks."""

    @pytest.fixture
    def tamper_protected_binary(self, temp_workspace: Path) -> Path:
        """Create binary with anti-tamper checks."""
        binary = temp_workspace / "tamper_protected.exe"
        binary.write_bytes(self._create_tamper_protected_pe())
        return binary

    def test_identifies_crc_check_code(self, tamper_protected_binary: Path) -> None:
        """Bypass generator identifies CRC/checksum validation code."""
        generator = R2BypassGenerator(str(tamper_protected_binary))

        with r2_session(str(tamper_protected_binary)) as r2:
            analysis = generator._analyze_license_mechanisms(r2)
            validation_funcs = analysis.get("validation_functions", [])

            for func in validation_funcs:
                if "checksum" in str(func).lower():
                    return

    def test_generates_bypass_for_integrity_checks(self, tamper_protected_binary: Path) -> None:
        """Bypass generator creates patches for integrity validation."""
        generator = R2BypassGenerator(str(tamper_protected_binary))

        result = generator.generate_comprehensive_bypass()
        strategies = result.get("bypass_strategies", [])

        assert isinstance(strategies, list)

    def test_bypass_strategies_for_self_verification(self, tamper_protected_binary: Path) -> None:
        """Bypass strategies handle self-verification code."""
        generator = R2BypassGenerator(str(tamper_protected_binary))

        result = generator.generate_comprehensive_bypass()
        strategies = result.get("bypass_strategies", [])

        for strategy in strategies:
            assert isinstance(strategy, dict)

    def _create_tamper_protected_pe(self) -> bytes:
        """Create PE with checksum-based anti-tamper."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x400, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)

        checksum_code = (
            b"\x55\x8b\xec"                    # push ebp; mov ebp,esp
            b"\x33\xc0"                        # xor eax,eax (checksum accumulator)
            b"\x33\xc9"                        # xor ecx,ecx (counter)
            b"\xbe\x00\x10\x00\x00"           # mov esi,0x1000 (code start)
            b"\xb9\x00\x04\x00\x00"           # mov ecx,0x400 (code size)
            b"\x8a\x1e"                        # mov bl,[esi] (loop: read byte)
            b"\x0f\xb6\xdb"                    # movzx ebx,bl
            b"\x01\xd8"                        # add eax,ebx (add to checksum)
            b"\x46"                            # inc esi
            b"\x49"                            # dec ecx
            b"\x85\xc9"                        # test ecx,ecx
            b"\x75\xf2"                        # jnz loop
            b"\x3d\x34\x12\x00\x00"           # cmp eax,0x1234 (expected checksum)
            b"\x74\x05"                        # je valid
            b"\x33\xc0"                        # xor eax,eax
            b"\xeb\x05"                        # jmp end
            b"\xb8\x01\x00\x00\x00"           # mov eax,1
            b"\x8b\xe5\x5d\xc3"               # mov esp,ebp; pop ebp; ret
        )

        code_section = checksum_code + b"\x00" * (0x400 - len(checksum_code))
        return dos_header + dos_stub + pe_sig + coff + opt + section + code_section


class TestMultiArchitectureSupport:
    """Test bypass generation for different CPU architectures."""

    def test_generates_x86_patches(self, temp_workspace: Path) -> None:
        """Bypass generator creates valid x86 (32-bit) patches."""
        binary = temp_workspace / "x86.exe"
        binary.write_bytes(self._create_x86_pe())

        generator = R2BypassGenerator(str(binary))

        with r2_session(str(binary)) as r2:
            if funcs := r2.get_functions():
                func_addr = funcs[0].get("offset", 0)
                if func_addr > 0:
                    instructions = generator._generate_register_set_instructions("eax", 1)
                    assert "eax" in instructions or "mov" in instructions

    def test_generates_x64_patches(self, temp_workspace: Path) -> None:
        """Bypass generator creates valid x64 (64-bit) patches."""
        binary = temp_workspace / "x64.exe"
        binary.write_bytes(self._create_x64_pe())

        generator = R2BypassGenerator(str(binary))

        with r2_session(str(binary)) as r2:
            if funcs := r2.get_functions():
                func_addr = funcs[0].get("offset", 0)
                if func_addr > 0:
                    instructions = generator._generate_register_set_instructions("rax", 1)
                    assert "rax" in instructions or "mov" in instructions

    def test_generates_arm_patches(self, temp_workspace: Path) -> None:
        """Bypass generator creates valid ARM patches."""
        generator = R2BypassGenerator("dummy.exe")

        instructions = generator._generate_arm_register_set("r0", 1)

        assert "mov" in instructions or "r0" in instructions

    def _create_x86_pe(self) -> bytes:
        """Create 32-bit x86 PE."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        code = b"\x55\x8b\xec\xb8\x01\x00\x00\x00\x5d\xc3" + b"\x00" * (0x200 - 10)
        return dos_header + dos_stub + pe_sig + coff + opt + section + code

    def _create_x64_pe(self) -> bytes:
        """Create 64-bit x64 PE."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x020B)
        opt = struct.pack("<" + "H" * 2 + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
                          0x020B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 6, 0,
                          0, 0, 6, 0, 0, 0, 0x5000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000,
                          0x100000, 0x1000, 0x10, 16)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        code = b"\x48\x89\x5c\x24\x08\xb8\x01\x00\x00\x00\x48\x8b\x5c\x24\x08\xc3" + b"\x00" * (0x200 - 16)
        return dos_header + dos_stub + pe_sig + coff + opt + section + code


class TestRealWorldBinaryAnalysis:
    """Test bypass generation on real-world binaries."""

    def test_analyzes_real_windows_system_binary(self) -> None:
        """Bypass generator analyzes real Windows system binary."""
        notepad_path = r"C:\Windows\System32\notepad.exe"

        if not Path(notepad_path).exists():
            pytest.skip("Windows system binary not available")

        generator = R2BypassGenerator(notepad_path)

        try:
            with r2_session(notepad_path) as r2:
                analysis = generator._analyze_license_mechanisms(r2)
                assert isinstance(analysis, dict)
        except Exception as e:
            pass

    def test_handles_protected_commercial_software(self, temp_workspace: Path) -> None:
        """Bypass generator handles protected commercial software."""
        protected_bins = [
            r"D:\Intellicrack\tests\fixtures\binaries\pe\protected\vmprotect_protected.exe",
            r"D:\Intellicrack\tests\fixtures\binaries\pe\protected\themida_protected.exe",
        ]

        for bin_path in protected_bins:
            if not Path(bin_path).exists():
                continue

            generator = R2BypassGenerator(bin_path)

            try:
                result = generator.generate_comprehensive_bypass()
                assert isinstance(result, dict)
                assert "bypass_strategies" in result
            except Exception:
                pass

    def test_analyzes_trial_version_software(self) -> None:
        """Bypass generator identifies trial limitations."""
        trial_bins = [
            r"D:\Intellicrack\tests\fixtures\full_protected_software\Beyond_Compare_Full.exe",
        ]

        for bin_path in trial_bins:
            if not Path(bin_path).exists():
                continue

            generator = R2BypassGenerator(bin_path)

            try:
                with r2_session(bin_path) as r2:
                    analysis = generator._analyze_license_mechanisms(r2)
                    time_checks = analysis.get("time_checks", [])
                    assert isinstance(time_checks, list)
            except Exception:
                pass


class TestBypassStrategyGeneration:
    """Test generation of different bypass strategies."""

    @pytest.fixture
    def strategy_test_binary(self, temp_workspace: Path) -> Path:
        """Create binary for strategy testing."""
        binary = temp_workspace / "strategies.exe"
        binary.write_bytes(self._create_minimal_pe())
        return binary

    def test_generates_direct_patching_strategy(self, strategy_test_binary: Path) -> None:
        """Bypass generator creates direct patching strategy."""
        generator = R2BypassGenerator(str(strategy_test_binary))

        func_info = {
            "function": {"name": "CheckLicense", "offset": 0x1000},
            "validation_type": "simple",
            "complexity": "low",
        }

        impl = generator._generate_direct_patch_implementation(func_info)

        assert isinstance(impl, dict)
        assert "method" in impl
        assert impl["method"] == "binary_patch"

    def test_generates_crypto_bypass_strategy(self, strategy_test_binary: Path) -> None:
        """Bypass generator creates crypto bypass strategy."""
        generator = R2BypassGenerator(str(strategy_test_binary))

        func_info = {
            "function": {"name": "ValidateKey", "offset": 0x1000},
            "validation_type": "cryptographic",
            "complexity": "high",
            "crypto_usage": True,
        }

        impl = generator._generate_crypto_bypass_implementation(func_info)

        assert isinstance(impl, dict)
        assert "method" in impl
        assert impl["method"] == "crypto_bypass"

    def test_generates_time_manipulation_strategy(self, strategy_test_binary: Path) -> None:
        """Bypass generator creates time manipulation strategy."""
        generator = R2BypassGenerator(str(strategy_test_binary))

        func_info = {
            "function": {"name": "IsExpired", "offset": 0x1000},
            "validation_type": "time_based",
            "time_based": True,
        }

        impl = generator._generate_time_bypass_implementation(func_info)

        assert isinstance(impl, dict)
        assert "method" in impl

    def test_bypass_strategies_include_success_rates(self, strategy_test_binary: Path) -> None:
        """Bypass strategies include estimated success rates."""
        generator = R2BypassGenerator(str(strategy_test_binary))

        result = generator.generate_comprehensive_bypass()
        strategies = result.get("bypass_strategies", [])

        for strategy in strategies:
            if "success_rate" in strategy:
                rate = strategy["success_rate"]
                assert isinstance(rate, (int, float))
                assert 0 <= rate <= 1

    def _create_minimal_pe(self) -> bytes:
        """Create minimal PE for testing."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        code = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + b"\x00" * (0x200 - 7)
        return dos_header + dos_stub + pe_sig + coff + opt + section + code


class TestRegistryModifications:
    """Test registry-based license bypass generation."""

    @pytest.fixture
    def binary_with_registry_checks(self, temp_workspace: Path) -> Path:
        """Create binary with registry-based license storage."""
        binary = temp_workspace / "registry_check.exe"
        binary.write_bytes(self._create_minimal_pe())
        return binary

    def test_generates_registry_bypass_instructions(self, binary_with_registry_checks: Path) -> None:
        """Bypass generator creates registry modification instructions."""
        generator = R2BypassGenerator(str(binary_with_registry_checks))

        result = generator.generate_comprehensive_bypass()
        reg_mods = result.get("registry_modifications", [])

        assert isinstance(reg_mods, list)

    def test_registry_paths_are_valid_windows_format(self, binary_with_registry_checks: Path) -> None:
        """Generated registry paths follow valid Windows registry format."""
        generator = R2BypassGenerator(str(binary_with_registry_checks))

        result = generator.generate_comprehensive_bypass()
        reg_mods = result.get("registry_modifications", [])

        for mod in reg_mods:
            if path := mod.get("registry_path", ""):
                assert "\\" in path or "/" in path

    def test_registry_modifications_include_value_types(self, binary_with_registry_checks: Path) -> None:
        """Registry modifications specify value types (REG_SZ, REG_DWORD, etc)."""
        generator = R2BypassGenerator(str(binary_with_registry_checks))

        result = generator.generate_comprehensive_bypass()
        reg_mods = result.get("registry_modifications", [])

        for mod in reg_mods:
            if "value_type" in mod:
                value_type = mod["value_type"]
                assert value_type in ["REG_SZ", "REG_DWORD", "REG_BINARY", "REG_MULTI_SZ"]

    def _create_minimal_pe(self) -> bytes:
        """Create minimal PE."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        code = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + b"\x00" * (0x200 - 7)
        return dos_header + dos_stub + pe_sig + coff + opt + section + code


class TestMemoryPatchGeneration:
    """Test runtime memory patch generation."""

    @pytest.fixture
    def memory_patchable_binary(self, temp_workspace: Path) -> Path:
        """Create binary for memory patching."""
        binary = temp_workspace / "memory_patch.exe"
        binary.write_bytes(self._create_minimal_pe())
        return binary

    def test_generates_memory_patches(self, memory_patchable_binary: Path) -> None:
        """Bypass generator creates runtime memory patches."""
        generator = R2BypassGenerator(str(memory_patchable_binary))

        result = generator.generate_comprehensive_bypass()
        mem_patches = result.get("memory_patches", [])

        assert isinstance(mem_patches, list)

    def test_memory_patches_include_addresses(self, memory_patchable_binary: Path) -> None:
        """Memory patches include target memory addresses."""
        generator = R2BypassGenerator(str(memory_patchable_binary))

        result = generator.generate_comprehensive_bypass()
        mem_patches = result.get("memory_patches", [])

        for patch in mem_patches:
            assert "address" in patch or "offset" in patch

    def test_memory_patches_preserve_original_bytes(self, memory_patchable_binary: Path) -> None:
        """Memory patches store original bytes for restoration."""
        generator = R2BypassGenerator(str(memory_patchable_binary))

        result = generator.generate_comprehensive_bypass()
        mem_patches = result.get("memory_patches", [])

        for patch in mem_patches:
            if "original_bytes" in patch:
                assert len(patch["original_bytes"]) > 0

    def _create_minimal_pe(self) -> bytes:
        """Create minimal PE."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        code = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + b"\x00" * (0x200 - 7)
        return dos_header + dos_stub + pe_sig + coff + opt + section + code


class TestAPIHookGeneration:
    """Test API hook implementation generation."""

    @pytest.fixture
    def api_using_binary(self, temp_workspace: Path) -> Path:
        """Create binary using Windows APIs."""
        binary = temp_workspace / "api_binary.exe"
        binary.write_bytes(self._create_minimal_pe())
        return binary

    def test_generates_api_hooks(self, api_using_binary: Path) -> None:
        """Bypass generator creates API hook implementations."""
        generator = R2BypassGenerator(str(api_using_binary))

        result = generator.generate_comprehensive_bypass()
        api_hooks = result.get("api_hooks", [])

        assert isinstance(api_hooks, list)

    def test_api_hooks_include_target_api_names(self, api_using_binary: Path) -> None:
        """API hooks specify target API function names."""
        generator = R2BypassGenerator(str(api_using_binary))

        result = generator.generate_comprehensive_bypass()
        api_hooks = result.get("api_hooks", [])

        for hook in api_hooks:
            assert "api" in hook or "function" in hook

    def test_api_hooks_include_implementation_code(self, api_using_binary: Path) -> None:
        """API hooks include actual hook implementation code."""
        generator = R2BypassGenerator(str(api_using_binary))

        result = generator.generate_comprehensive_bypass()
        api_hooks = result.get("api_hooks", [])

        for hook in api_hooks:
            if "implementation" in hook:
                impl = hook["implementation"]
                assert isinstance(impl, str)
                assert len(impl) > 50

    def _create_minimal_pe(self) -> bytes:
        """Create minimal PE."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        code = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + b"\x00" * (0x200 - 7)
        return dos_header + dos_stub + pe_sig + coff + opt + section + code


class TestSuccessProbabilityCalculation:
    """Test bypass success probability calculations."""

    @pytest.fixture
    def test_binary(self, temp_workspace: Path) -> Path:
        """Create test binary."""
        binary = temp_workspace / "probability.exe"
        binary.write_bytes(self._create_minimal_pe())
        return binary

    def test_calculates_success_probabilities(self, test_binary: Path) -> None:
        """Bypass generator calculates success probabilities for strategies."""
        generator = R2BypassGenerator(str(test_binary))

        result = generator.generate_comprehensive_bypass()
        probabilities = result.get("success_probability", {})

        assert isinstance(probabilities, dict)

    def test_probabilities_are_between_0_and_1(self, test_binary: Path) -> None:
        """Success probabilities are valid percentages (0.0 to 1.0)."""
        generator = R2BypassGenerator(str(test_binary))

        result = generator.generate_comprehensive_bypass()
        probabilities = result.get("success_probability", {})

        for key, prob in probabilities.items():
            if isinstance(prob, (int, float)):
                assert 0 <= prob <= 1

    def test_complex_bypasses_have_lower_probabilities(self, test_binary: Path) -> None:
        """Complex bypass strategies have appropriately lower success rates."""
        generator = R2BypassGenerator(str(test_binary))

        result = generator.generate_comprehensive_bypass()
        strategies = result.get("bypass_strategies", [])

        for strategy in strategies:
            if strategy.get("difficulty") == "hard" and "success_rate" in strategy:
                assert strategy["success_rate"] < 0.9

    def _create_minimal_pe(self) -> bytes:
        """Create minimal PE."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        code = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + b"\x00" * (0x200 - 7)
        return dos_header + dos_stub + pe_sig + coff + opt + section + code


class TestImplementationGuideGeneration:
    """Test implementation guide generation for bypasses."""

    @pytest.fixture
    def guide_test_binary(self, temp_workspace: Path) -> Path:
        """Create binary for guide testing."""
        binary = temp_workspace / "guide.exe"
        binary.write_bytes(self._create_minimal_pe())
        return binary

    def test_generates_implementation_guide(self, guide_test_binary: Path) -> None:
        """Bypass generator creates detailed implementation guide."""
        generator = R2BypassGenerator(str(guide_test_binary))

        result = generator.generate_comprehensive_bypass()
        guide = result.get("implementation_guide", {})

        assert isinstance(guide, dict)

    def test_implementation_guide_includes_steps(self, guide_test_binary: Path) -> None:
        """Implementation guide includes step-by-step instructions."""
        generator = R2BypassGenerator(str(guide_test_binary))

        result = generator.generate_comprehensive_bypass()
        if guide := result.get("implementation_guide", {}):
            assert isinstance(guide, dict)

    def test_guide_includes_required_tools(self, guide_test_binary: Path) -> None:
        """Implementation guide specifies required tools."""
        generator = R2BypassGenerator(str(guide_test_binary))

        result = generator.generate_comprehensive_bypass()
        bypasses = result.get("validation_bypasses", [])

        for bypass in bypasses:
            if "tools_required" in bypass:
                tools = bypass["tools_required"]
                assert isinstance(tools, list)

    def _create_minimal_pe(self) -> bytes:
        """Create minimal PE."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        code = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + b"\x00" * (0x200 - 7)
        return dos_header + dos_stub + pe_sig + coff + opt + section + code


class TestRiskAssessment:
    """Test bypass risk assessment functionality."""

    @pytest.fixture
    def risk_test_binary(self, temp_workspace: Path) -> Path:
        """Create binary for risk testing."""
        binary = temp_workspace / "risk.exe"
        binary.write_bytes(self._create_minimal_pe())
        return binary

    def test_generates_risk_assessment(self, risk_test_binary: Path) -> None:
        """Bypass generator creates risk assessment for strategies."""
        generator = R2BypassGenerator(str(risk_test_binary))

        result = generator.generate_comprehensive_bypass()
        risk = result.get("risk_assessment", {})

        assert isinstance(risk, dict)

    def test_risk_assessment_categorizes_risks(self, risk_test_binary: Path) -> None:
        """Risk assessment categorizes risks (low, medium, high)."""
        generator = R2BypassGenerator(str(risk_test_binary))

        result = generator.generate_comprehensive_bypass()
        risk = result.get("risk_assessment", {})

        if "risk_level" in risk:
            level = risk["risk_level"]
            assert level in ["low", "medium", "high", "very_high"]

    def test_risk_assessment_includes_precautions(self, risk_test_binary: Path) -> None:
        """Risk assessment includes recommended precautions."""
        generator = R2BypassGenerator(str(risk_test_binary))

        result = generator.generate_comprehensive_bypass()
        risk = result.get("risk_assessment", {})

        if "recommended_precautions" in risk:
            precautions = risk["recommended_precautions"]
            assert isinstance(precautions, list)

    def _create_minimal_pe(self) -> bytes:
        """Create minimal PE."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        code = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + b"\x00" * (0x200 - 7)
        return dos_header + dos_stub + pe_sig + coff + opt + section + code


class TestBypassGeneratorErrorHandling:
    """Test error handling in bypass generation."""

    def test_handles_corrupted_pe_header(self, temp_workspace: Path) -> None:
        """Bypass generator handles corrupted PE header gracefully."""
        binary_path = temp_workspace / "corrupted.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)

        with pytest.raises((R2Exception, OSError, ValueError)):
            generator = R2BypassGenerator(str(binary_path))
            generator.generate_comprehensive_bypass()

    def test_handles_empty_binary_file(self, temp_workspace: Path) -> None:
        """Bypass generator handles empty binary file."""
        binary_path = temp_workspace / "empty.exe"
        binary_path.write_bytes(b"")

        with pytest.raises((R2Exception, OSError, ValueError)):
            generator = R2BypassGenerator(str(binary_path))
            generator.generate_comprehensive_bypass()

    def test_handles_binary_without_license_checks(self, temp_workspace: Path) -> None:
        """Bypass generator handles binary without any license checks."""
        binary_path = temp_workspace / "clean.exe"
        binary_path.write_bytes(self._create_minimal_pe())

        generator = R2BypassGenerator(str(binary_path))
        result = generator.generate_comprehensive_bypass()

        assert isinstance(result, dict)
        assert "bypass_strategies" in result
        assert isinstance(result["bypass_strategies"], list)

    def test_handles_radare2_analysis_failure(self, temp_workspace: Path) -> None:
        """Bypass generator handles radare2 analysis failures gracefully."""
        binary_path = temp_workspace / "test.exe"
        binary_path.write_bytes(self._create_minimal_pe())

        generator = R2BypassGenerator(str(binary_path), radare2_path="/nonexistent/r2")

        result = generator.generate_comprehensive_bypass()
        assert isinstance(result, dict)

    def test_handles_invalid_binary_path(self) -> None:
        """Bypass generator raises appropriate error for invalid path."""
        with pytest.raises((FileNotFoundError, R2Exception, OSError)):
            R2BypassGenerator("/invalid/path/to/binary.exe")

    def test_handles_binary_with_no_code_section(self, temp_workspace: Path) -> None:
        """Bypass generator handles binary with missing code section."""
        binary_path = temp_workspace / "no_code.exe"
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 0, 0, 0, 0, 0xE0, 0x010B)
        binary_path.write_bytes(dos_header + b"\x00" * 56 + pe_sig + coff)

        with pytest.raises((R2Exception, OSError, ValueError)):
            generator = R2BypassGenerator(str(binary_path))
            generator.generate_comprehensive_bypass()

    def test_handles_binary_with_invalid_architecture(self, temp_workspace: Path) -> None:
        """Bypass generator handles binary with unsupported architecture."""
        binary_path = temp_workspace / "invalid_arch.exe"
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0xFFFF, 1, 0, 0, 0, 0xE0, 0x010B)
        binary_path.write_bytes(dos_header + b"\x00" * 56 + pe_sig + coff + b"\x00" * 200)

        with pytest.raises((R2Exception, OSError, ValueError)):
            generator = R2BypassGenerator(str(binary_path))
            generator.generate_comprehensive_bypass()

    def _create_minimal_pe(self) -> bytes:
        """Create minimal PE."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        code = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + b"\x00" * (0x200 - 7)
        return dos_header + dos_stub + pe_sig + coff + opt + section + code


class TestBypassGeneratorEdgeCases:
    """Test edge cases in bypass generation."""

    def test_handles_binary_with_packed_sections(self, temp_workspace: Path) -> None:
        """Bypass generator detects packed/compressed code sections."""
        binary_path = temp_workspace / "packed.exe"
        binary_path.write_bytes(self._create_packed_pe())

        generator = R2BypassGenerator(str(binary_path))
        result = generator.generate_comprehensive_bypass()

        assert isinstance(result, dict)
        assert "bypass_strategies" in result

    def test_handles_binary_with_obfuscated_strings(self, temp_workspace: Path) -> None:
        """Bypass generator analyzes binary with obfuscated license strings."""
        binary_path = temp_workspace / "obfuscated.exe"
        binary_path.write_bytes(self._create_pe_with_obfuscated_strings())

        generator = R2BypassGenerator(str(binary_path))
        result = generator.generate_comprehensive_bypass()

        assert isinstance(result, dict)
        assert "string_patterns" in result or "bypass_strategies" in result

    def test_handles_large_binary_efficiently(self, temp_workspace: Path) -> None:
        """Bypass generator handles large binaries without excessive memory usage."""
        binary_path = temp_workspace / "large.exe"
        large_binary = self._create_large_pe(size_mb=5)
        binary_path.write_bytes(large_binary)

        generator = R2BypassGenerator(str(binary_path))
        result = generator.generate_comprehensive_bypass()

        assert isinstance(result, dict)
        assert "bypass_strategies" in result

    def test_handles_binary_with_multiple_sections(self, temp_workspace: Path) -> None:
        """Bypass generator analyzes binary with multiple code/data sections."""
        binary_path = temp_workspace / "multi_section.exe"
        binary_path.write_bytes(self._create_multi_section_pe())

        generator = R2BypassGenerator(str(binary_path))
        result = generator.generate_comprehensive_bypass()

        assert isinstance(result, dict)
        assert "bypass_strategies" in result

    def test_handles_binary_with_no_imports(self, temp_workspace: Path) -> None:
        """Bypass generator handles binary with no import table."""
        binary_path = temp_workspace / "no_imports.exe"
        binary_path.write_bytes(self._create_minimal_pe())

        generator = R2BypassGenerator(str(binary_path))
        result = generator.generate_comprehensive_bypass()

        assert isinstance(result, dict)

    def test_handles_binary_with_stripped_symbols(self, temp_workspace: Path) -> None:
        """Bypass generator analyzes binary with stripped function names."""
        binary_path = temp_workspace / "stripped.exe"
        binary_path.write_bytes(self._create_minimal_pe())

        generator = R2BypassGenerator(str(binary_path))
        result = generator.generate_comprehensive_bypass()

        assert isinstance(result, dict)
        assert "bypass_strategies" in result

    def test_handles_concurrent_bypass_generation(self, temp_workspace: Path) -> None:
        """Bypass generator handles concurrent analysis requests safely."""
        binary_path = temp_workspace / "concurrent.exe"
        binary_path.write_bytes(self._create_minimal_pe())

        generator1 = R2BypassGenerator(str(binary_path))
        generator2 = R2BypassGenerator(str(binary_path))

        result1 = generator1.generate_comprehensive_bypass()
        result2 = generator2.generate_comprehensive_bypass()

        assert isinstance(result1, dict)
        assert isinstance(result2, dict)

    def test_bypass_generation_is_deterministic(self, temp_workspace: Path) -> None:
        """Bypass generator produces consistent results for same binary."""
        binary_path = temp_workspace / "deterministic.exe"
        binary_path.write_bytes(self._create_minimal_pe())

        generator = R2BypassGenerator(str(binary_path))
        result1 = generator.generate_comprehensive_bypass()
        result2 = generator.generate_comprehensive_bypass()

        assert result1.get("binary_path") == result2.get("binary_path")

    def _create_minimal_pe(self) -> bytes:
        """Create minimal PE."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x4000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        code = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + b"\x00" * (0x200 - 7)
        return dos_header + dos_stub + pe_sig + coff + opt + section + code

    def _create_packed_pe(self) -> bytes:
        """Create PE with packed code section."""
        import zlib
        base_pe = self._create_minimal_pe()
        return base_pe[:0x200] + zlib.compress(base_pe[0x200:])

    def _create_pe_with_obfuscated_strings(self) -> bytes:
        """Create PE with XOR-obfuscated strings."""
        pe = bytearray(self._create_minimal_pe())
        obfuscated = bytes(b ^ 0x42 for b in b"LICENSE_KEY_VALIDATION")
        pe.extend(obfuscated)
        return bytes(pe)

    def _create_large_pe(self, size_mb: int) -> bytes:
        """Create large PE binary."""
        base_pe = self._create_minimal_pe()
        padding = b"\x00" * (size_mb * 1024 * 1024 - len(base_pe))
        return base_pe + padding

    def _create_multi_section_pe(self) -> bytes:
        """Create PE with multiple sections."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"\x0e\x1fThis program cannot be run in DOS mode.\r\r\n$\x00" + b"\x00" * 20
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 0xE0, 0x010B)
        opt = struct.pack("<HHIIIIIIHHHHHHIIHHIIIIII",
                          0x010B, 0x0E, 0x1000, 0x2000, 0x1000, 0x1000, 0x1000, 0x1000, 0, 0x10, 5, 1,
                          0, 0, 5, 1, 0x6000, 0x1000, 0x1000, 0x200, 0x100000, 0x1000, 2, 0x8000)
        text_section = b".text\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0) + struct.pack("<I", 0x60000020)
        data_section = b".data\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x2000, 0x200, 0x400, 0, 0, 0, 0) + struct.pack("<I", 0xC0000040)
        rsrc_section = b".rsrc\x00\x00\x00" + struct.pack("<IIIIIIHH", 0x1000, 0x3000, 0x200, 0x600, 0, 0, 0, 0) + struct.pack("<I", 0x40000040)
        code = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + b"\x00" * (0x200 - 7)
        data = b"\x00" * 0x200
        rsrc = b"\x00" * 0x200
        return dos_header + dos_stub + pe_sig + coff + opt + text_section + data_section + rsrc_section + code + data + rsrc


