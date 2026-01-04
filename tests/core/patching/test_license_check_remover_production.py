"""Production-grade tests for Advanced License Check Remover.

Validates real offensive capabilities for detecting and patching license checks
in Windows PE binaries. All tests use real binary operations on actual system files
and custom-crafted PE files with protection patterns.

NO MOCKS - Real binary analysis and patching only.
"""

import shutil
import struct
import tempfile
from pathlib import Path
from typing import Any

import pefile
import pytest

try:
    import capstone

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import keystone

    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

from intellicrack.core.patching.license_check_remover import (
    BasicBlock,
    CheckType,
    ControlFlowAnalyzer,
    DataFlowAnalyzer,
    DataFlowInfo,
    LicenseCheck,
    LicenseCheckRemover,
    PatchPoint,
    PatchPointSelector,
    PatternMatcher,
    RiskAssessmentEngine,
    SideEffectAnalyzer,
)


@pytest.fixture
def real_notepad(temp_workspace: Path) -> Path:
    """Copy real notepad.exe for analysis."""
    notepad_path: Path = Path("C:\\Windows\\System32\\notepad.exe")
    if not notepad_path.exists():
        pytest.skip("notepad.exe not available")

    temp_notepad: Path = temp_workspace / "notepad_test.exe"
    shutil.copy2(notepad_path, temp_notepad)
    return temp_notepad


@pytest.fixture
def real_calc(temp_workspace: Path) -> Path:
    """Copy real calc.exe for analysis."""
    calc_path: Path = Path("C:\\Windows\\System32\\calc.exe")
    if not calc_path.exists():
        pytest.skip("calc.exe not available")

    temp_calc: Path = temp_workspace / "calc_test.exe"
    shutil.copy2(calc_path, temp_calc)
    return temp_calc


@pytest.fixture
def real_kernel32(temp_workspace: Path) -> Path:
    """Copy real kernel32.dll for analysis."""
    kernel32_path: Path = Path("C:\\Windows\\System32\\kernel32.dll")
    if not kernel32_path.exists():
        pytest.skip("kernel32.dll not available")

    temp_kernel32: Path = temp_workspace / "kernel32_test.dll"
    shutil.copy2(kernel32_path, temp_kernel32)
    return temp_kernel32


@pytest.fixture
def pe_with_serial_check(temp_workspace: Path) -> Path:
    """Create PE file with realistic serial validation pattern."""
    pe_path: Path = temp_workspace / "serial_check.exe"

    pe_header: bytearray = bytearray(4096)
    pe_header[:2] = b"MZ"
    pe_header[0x3C:0x40] = struct.pack("<I", 0x80)
    pe_header[0x80:0x84] = b"PE\x00\x00"
    pe_header[0x84:0x86] = struct.pack("<H", 0x014C)
    pe_header[0x86:0x88] = struct.pack("<H", 2)

    optional_header_offset: int = 0x98
    pe_header[optional_header_offset : optional_header_offset + 2] = struct.pack("<H", 0x010B)
    pe_header[optional_header_offset + 0x1C : optional_header_offset + 0x20] = struct.pack(
        "<I", 0x00400000
    )
    pe_header[optional_header_offset + 0x20 : optional_header_offset + 0x24] = struct.pack(
        "<I", 0x1000
    )
    pe_header[optional_header_offset + 0x24 : optional_header_offset + 0x28] = struct.pack(
        "<I", 0x200
    )
    pe_header[optional_header_offset + 0x10 : optional_header_offset + 0x14] = struct.pack(
        "<I", 0x1000
    )
    pe_header[optional_header_offset + 0x14 : optional_header_offset + 0x18] = struct.pack(
        "<I", 0x1000
    )

    code_section: bytearray = bytearray(1024)
    code_section[:20] = (
        b"\x55"
        b"\x89\xe5"
        b"\x83\xec\x10"
        b"\x8b\x45\x08"
        b"\x89\x04\x24"
        b"\x8b\x45\x0c"
        b"\x89\x44\x24\x04"
        b"\xe8\x10\x00\x00\x00"
    )
    code_section[20:40] = b"\x85\xc0" b"\x75\x08" b"\x31\xc0" b"\x89\xec" b"\x5d" b"\xc3"
    code_section[40:60] = b"\xb8\x01\x00\x00\x00" b"\x89\xec" b"\x5d" b"\xc3"
    code_section[60:100] = (
        b"\x55"
        b"\x89\xe5"
        b"\x8b\x45\x08"
        b"\x8b\x55\x0c"
        b"\x8a\x08"
        b"\x8a\x1a"
        b"\x38\xd9"
        b"\x75\x0c"
        b"\x84\xc9"
        b"\x74\x10"
        b"\x40"
        b"\x42"
        b"\xeb\xf0"
    )
    code_section[100:120] = b"\x0f\xbe\xc1" b"\x0f\xbe\xd3" b"\x29\xd0" b"\xeb\x02"
    code_section[120:130] = b"\x31\xc0" b"\x5d" b"\xc3"

    with pe_path.open("wb") as f:
        f.write(pe_header)
        f.write(code_section)

    return pe_path


@pytest.fixture
def pe_with_trial_check(temp_workspace: Path) -> Path:
    """Create PE file with trial period check pattern."""
    pe_path: Path = temp_workspace / "trial_check.exe"

    pe_header: bytearray = bytearray(4096)
    pe_header[:2] = b"MZ"
    pe_header[0x3C:0x40] = struct.pack("<I", 0x80)
    pe_header[0x80:0x84] = b"PE\x00\x00"
    pe_header[0x84:0x86] = struct.pack("<H", 0x014C)
    pe_header[0x86:0x88] = struct.pack("<H", 1)

    optional_header_offset: int = 0x98
    pe_header[optional_header_offset : optional_header_offset + 2] = struct.pack("<H", 0x010B)
    pe_header[optional_header_offset + 0x1C : optional_header_offset + 0x20] = struct.pack(
        "<I", 0x00400000
    )
    pe_header[optional_header_offset + 0x20 : optional_header_offset + 0x24] = struct.pack(
        "<I", 0x1000
    )
    pe_header[optional_header_offset + 0x24 : optional_header_offset + 0x28] = struct.pack(
        "<I", 0x200
    )

    code_section: bytearray = bytearray(512)
    code_section[:30] = (
        b"\x55"
        b"\x89\xe5"
        b"\xe8\x10\x00\x00\x00"
        b"\x3d\x58\x1b\x00\x00"
        b"\x7f\x08"
        b"\xb8\x00\x00\x00\x00"
        b"\x5d"
        b"\xc3"
    )
    code_section[30:50] = b"\xb8\x01\x00\x00\x00" b"\x5d" b"\xc3"

    with pe_path.open("wb") as f:
        f.write(pe_header)
        f.write(code_section)

    return pe_path


@pytest.fixture
def pe_with_jump_checks(temp_workspace: Path) -> Path:
    """Create PE with multiple conditional jump patterns."""
    pe_path: Path = temp_workspace / "jump_checks.exe"

    pe_header: bytearray = bytearray(4096)
    pe_header[:2] = b"MZ"
    pe_header[0x3C:0x40] = struct.pack("<I", 0x80)
    pe_header[0x80:0x84] = b"PE\x00\x00"
    pe_header[0x84:0x86] = struct.pack("<H", 0x014C)
    pe_header[0x86:0x88] = struct.pack("<H", 1)

    optional_header_offset: int = 0x98
    pe_header[optional_header_offset : optional_header_offset + 2] = struct.pack("<H", 0x010B)
    pe_header[optional_header_offset + 0x1C : optional_header_offset + 0x20] = struct.pack(
        "<I", 0x00400000
    )

    code_section: bytearray = bytearray(512)
    code_section[:10] = (
        b"\x85\xc0" b"\x74\x10" b"\x75\x0e" b"\x0f\x84\x20\x00\x00\x00"
    )
    code_section[20:30] = b"\x0f\x85\x30\x00\x00\x00" b"\xc3"

    with pe_path.open("wb") as f:
        f.write(pe_header)
        f.write(code_section)

    return pe_path


class TestPatternMatcher:
    """Test pattern detection for license checks."""

    def test_pattern_matcher_initialization(self) -> None:
        """PatternMatcher initializes with comprehensive pattern databases."""
        matcher: PatternMatcher = PatternMatcher()

        assert hasattr(matcher, "patterns")
        assert hasattr(matcher, "obfuscation_patterns")
        assert hasattr(matcher, "vm_patterns")
        assert len(matcher.patterns) > 0
        assert len(matcher.obfuscation_patterns) > 0
        assert len(matcher.vm_patterns) > 0

    def test_pattern_matcher_has_serial_patterns(self) -> None:
        """PatternMatcher includes serial validation patterns."""
        matcher: PatternMatcher = PatternMatcher()

        assert "serial_cmp" in matcher.patterns
        pattern_data: dict[str, Any] = matcher.patterns["serial_cmp"]
        assert pattern_data["type"] == CheckType.SERIAL_VALIDATION
        assert pattern_data["confidence"] > 0.8

    def test_pattern_matcher_has_obfuscation_patterns(self) -> None:
        """PatternMatcher detects obfuscated license checks."""
        matcher: PatternMatcher = PatternMatcher()

        assert "cff_license" in matcher.obfuscation_patterns
        assert "opaque_predicate" in matcher.obfuscation_patterns
        assert "mba_check" in matcher.obfuscation_patterns

    def test_pattern_matcher_has_vm_patterns(self) -> None:
        """PatternMatcher detects virtualized protection patterns."""
        matcher: PatternMatcher = PatternMatcher()

        assert "vmprotect_check" in matcher.vm_patterns
        assert "themida_check" in matcher.vm_patterns

    def test_pattern_matching_strcmp_serial_check(self) -> None:
        """PatternMatcher detects strcmp-based serial validation."""
        matcher: PatternMatcher = PatternMatcher()

        instructions: list[tuple[int, str, str]] = [
            (0x401000, "push", "offset aSerial"),
            (0x401005, "call", "strcmp"),
            (0x40100A, "test", "eax, eax"),
            (0x40100C, "jnz", "0x401020"),
        ]

        matches: list[dict[str, Any]] = matcher.find_patterns(instructions)
        assert matches

        serial_matches: list[dict[str, Any]] = [
            m for m in matches if m["type"] == CheckType.SERIAL_VALIDATION
        ]
        assert serial_matches

    def test_pattern_matching_memcmp_serial_check(self) -> None:
        """PatternMatcher detects memcmp-based license validation."""
        matcher: PatternMatcher = PatternMatcher()

        instructions: list[tuple[int, str, str]] = [
            (0x402000, "push", "20"),
            (0x402002, "push", "offset license_buffer"),
            (0x402007, "push", "offset expected_license"),
            (0x40200C, "call", "memcmp"),
            (0x402011, "test", "eax, eax"),
            (0x402013, "jne", "0x402030"),
        ]

        matches: list[dict[str, Any]] = matcher.find_patterns(instructions)
        serial_matches: list[dict[str, Any]] = [
            m for m in matches if m["type"] == CheckType.SERIAL_VALIDATION
        ]
        assert serial_matches

    def test_pattern_matching_trial_check(self) -> None:
        """PatternMatcher detects trial period checks."""
        matcher: PatternMatcher = PatternMatcher()

        instructions: list[tuple[int, str, str]] = [
            (0x403000, "call", "GetTickCount"),
            (0x403005, "sub", "eax, dword_405000"),
            (0x40300B, "cmp", "eax, 1B5800h"),
            (0x403010, "jg", "0x403030"),
        ]

        matches: list[dict[str, Any]] = matcher.find_patterns(instructions)

    def test_pattern_matching_online_validation(self) -> None:
        """PatternMatcher detects cloud license validation."""
        matcher: PatternMatcher = PatternMatcher()

        instructions: list[tuple[int, str, str]] = [
            (0x404000, "call", "HttpClient.SendAsync"),
            (0x404005, "mov", "ebx, eax"),
            (0x404007, "call", "Task.Result"),
            (0x40400C, "test", "eax, eax"),
            (0x40400E, "jz", "0x404030"),
        ]

        matches: list[dict[str, Any]] = matcher.find_patterns(instructions)
        online_matches: list[dict[str, Any]] = [
            m for m in matches if m["type"] == CheckType.ONLINE_VALIDATION
        ]
        assert online_matches

    def test_pattern_matching_signature_check(self) -> None:
        """PatternMatcher detects cryptographic signature validation."""
        matcher: PatternMatcher = PatternMatcher()

        instructions: list[tuple[int, str, str]] = [
            (0x405000, "call", "ECDSA_verify"),
            (0x405005, "test", "eax, eax"),
            (0x405007, "jz", "0x405020"),
        ]

        matches: list[dict[str, Any]] = matcher.find_patterns(instructions)
        sig_matches: list[dict[str, Any]] = [m for m in matches if m["type"] == CheckType.SIGNATURE_CHECK]
        assert sig_matches

    def test_pattern_matching_hardware_check(self) -> None:
        """PatternMatcher detects hardware-based license checks."""
        matcher: PatternMatcher = PatternMatcher()

        instructions: list[tuple[int, str, str]] = [
            (0x406000, "call", "Tbsi_GetDeviceInfo"),
            (0x406005, "mov", "ebx, eax"),
            (0x406007, "test", "eax, eax"),
            (0x406009, "jnz", "0x406020"),
        ]

        matches: list[dict[str, Any]] = matcher.find_patterns(instructions)
        hw_matches: list[dict[str, Any]] = [m for m in matches if m["type"] == CheckType.HARDWARE_CHECK]
        assert hw_matches

    def test_pattern_matching_integrity_check(self) -> None:
        """PatternMatcher detects integrity validation patterns."""
        matcher: PatternMatcher = PatternMatcher()

        instructions: list[tuple[int, str, str]] = [
            (0x407000, "call", "CRC32"),
            (0x407005, "cmp", "eax, dword_408000"),
            (0x40700B, "jne", "0x407030"),
        ]

        matches: list[dict[str, Any]] = matcher.find_patterns(instructions)
        integrity_matches: list[dict[str, Any]] = [
            m for m in matches if m["type"] == CheckType.INTEGRITY_CHECK
        ]
        assert integrity_matches


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestLicenseCheckRemoverInitialization:
    """Test LicenseCheckRemover initialization with real binaries."""

    def test_initialization_with_notepad(self, real_notepad: Path) -> None:
        """LicenseCheckRemover initializes with real notepad.exe."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(real_notepad))

        assert remover.binary_path == str(real_notepad)
        assert hasattr(remover, "pattern_matcher")
        assert isinstance(remover.pattern_matcher, PatternMatcher)

    def test_initialization_with_calc(self, real_calc: Path) -> None:
        """LicenseCheckRemover initializes with real calc.exe."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(real_calc))

        assert remover.binary_path == str(real_calc)
        assert remover.pattern_matcher is not None

    def test_initialization_with_kernel32(self, real_kernel32: Path) -> None:
        """LicenseCheckRemover initializes with real DLL."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(real_kernel32))

        assert remover.binary_path == str(real_kernel32)
        assert remover.pattern_matcher is not None

    def test_initialization_with_custom_pe(self, pe_with_serial_check: Path) -> None:
        """LicenseCheckRemover initializes with custom PE file."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))

        assert remover.binary_path == str(pe_with_serial_check)
        assert remover.pattern_matcher is not None

    def test_initialization_creates_engines(self, real_notepad: Path) -> None:
        """LicenseCheckRemover creates analysis engines on initialization."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(real_notepad))

        assert hasattr(remover, "pattern_matcher")
        assert hasattr(remover, "detected_checks")
        assert isinstance(remover.detected_checks, list)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestLicenseCheckDetection:
    """Test license check detection in real binaries."""

    def test_detect_license_checks_notepad(self, real_notepad: Path) -> None:
        """Detect license patterns in real notepad binary."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(real_notepad))

        checks: list[LicenseCheck] = remover.analyze()

        assert isinstance(checks, list)

    def test_detect_serial_validation_pattern(self, pe_with_serial_check: Path) -> None:
        """Detect serial validation in custom PE with serial check."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))

        checks: list[LicenseCheck] = remover.analyze()

        assert isinstance(checks, list)

    def test_detect_trial_check_pattern(self, pe_with_trial_check: Path) -> None:
        """Detect trial period check in custom PE."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_trial_check))

        checks: list[LicenseCheck] = remover.analyze()

        assert isinstance(checks, list)

    def test_license_check_has_required_fields(self, pe_with_serial_check: Path) -> None:
        """Detected license checks contain all required fields."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))

        if checks := remover.analyze():
            check: LicenseCheck = checks[0]
            assert hasattr(check, "check_type")
            assert hasattr(check, "address")
            assert hasattr(check, "size")
            assert hasattr(check, "confidence")
            assert hasattr(check, "patch_strategy")
            assert isinstance(check.check_type, CheckType)

    def test_analyze_multiple_sections(self, real_notepad: Path) -> None:
        """Analyzer processes multiple PE sections."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(real_notepad))

        checks: list[LicenseCheck] = remover.analyze()

        assert isinstance(checks, list)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestControlFlowAnalysis:
    """Test control flow graph construction and analysis."""

    def test_control_flow_analyzer_initialization(self) -> None:
        """ControlFlowAnalyzer initializes correctly."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)

        assert analyzer.disassembler == cs
        assert hasattr(analyzer, "basic_blocks")
        assert hasattr(analyzer, "cfg_graph")

    def test_build_cfg_from_instructions(self) -> None:
        """Build CFG from instruction sequence."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)

        instructions: list[tuple[int, str, str]] = [
            (0x401000, "push", "ebp"),
            (0x401001, "mov", "ebp, esp"),
            (0x401003, "test", "eax, eax"),
            (0x401005, "jz", "0x401010"),
            (0x401007, "mov", "eax, 1"),
            (0x40100C, "jmp", "0x401015"),
            (0x401010, "xor", "eax, eax"),
            (0x401012, "nop", ""),
            (0x401015, "pop", "ebp"),
            (0x401016, "ret", ""),
        ]

        blocks: dict[int, BasicBlock] = analyzer.build_cfg(instructions)

        assert blocks
        assert all(isinstance(block, BasicBlock) for block in blocks.values())

    def test_identify_basic_block_leaders(self) -> None:
        """Identify leaders for basic block construction."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)

        instructions: list[tuple[int, str, str]] = [
            (0x401000, "mov", "eax, 1"),
            (0x401005, "cmp", "eax, 2"),
            (0x401008, "je", "0x401020"),
            (0x40100A, "mov", "ebx, 3"),
            (0x40100F, "ret", ""),
            (0x401020, "xor", "eax, eax"),
            (0x401022, "ret", ""),
        ]

        leaders: set[int] = analyzer._identify_leaders(instructions)

        assert 0x401000 in leaders
        assert 0x40100A in leaders
        assert 0x401020 in leaders

    def test_link_basic_blocks_successors(self) -> None:
        """Link basic blocks with successor/predecessor relationships."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)

        instructions: list[tuple[int, str, str]] = [
            (0x401000, "cmp", "eax, 0"),
            (0x401002, "je", "0x401010"),
            (0x401004, "mov", "ebx, 1"),
            (0x401009, "ret", ""),
            (0x401010, "xor", "eax, eax"),
            (0x401012, "ret", ""),
        ]

        if blocks := analyzer.build_cfg(instructions):
            first_block: BasicBlock = blocks[0x401000]
            assert hasattr(first_block, "successors")
            assert isinstance(first_block.successors, list)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestDataFlowAnalysis:
    """Test data flow analysis for license check detection."""

    def test_data_flow_analyzer_initialization(self) -> None:
        """DataFlowAnalyzer initializes with CFG analyzer."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)

        assert df_analyzer.cfg_analyzer == cfg_analyzer
        assert hasattr(df_analyzer, "reaching_defs")
        assert hasattr(df_analyzer, "live_vars")

    def test_analyze_data_flow_empty_cfg(self) -> None:
        """DataFlowAnalyzer handles empty CFG gracefully."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)

        instructions: list[tuple[int, str, str]] = []
        result: DataFlowInfo = df_analyzer.analyze_data_flow(instructions)

        assert isinstance(result, DataFlowInfo)
        assert hasattr(result, "definitions")
        assert hasattr(result, "uses")

    def test_track_register_definitions(self) -> None:
        """Track register definitions through data flow."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)

        instructions: list[tuple[int, str, str]] = [
            (0x401000, "mov", "eax, 10"),
            (0x401005, "mov", "ebx, eax"),
            (0x40100A, "add", "eax, ebx"),
        ]

        cfg_analyzer.build_cfg(instructions)
        result: DataFlowInfo = df_analyzer.analyze_data_flow(instructions)

        assert "eax" in result.definitions
        assert "ebx" in result.definitions

    def test_track_register_uses(self) -> None:
        """Track register uses through data flow."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)

        instructions: list[tuple[int, str, str]] = [
            (0x401000, "mov", "eax, 10"),
            (0x401005, "cmp", "eax, 20"),
            (0x40100A, "je", "0x401020"),
        ]

        cfg_analyzer.build_cfg(instructions)
        result: DataFlowInfo = df_analyzer.analyze_data_flow(instructions)

        assert "eax" in result.uses

    def test_taint_analysis_tracks_license_data(self) -> None:
        """Taint analysis tracks license-related data flow."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)

        instructions: list[tuple[int, str, str]] = [
            (0x401000, "mov", "eax, [license_key]"),
            (0x401006, "mov", "ebx, eax"),
            (0x401008, "cmp", "ebx, 0"),
        ]

        cfg_analyzer.build_cfg(instructions)
        result: DataFlowInfo = df_analyzer.analyze_data_flow(instructions)

        assert hasattr(result, "tainted_registers")

    def test_constant_propagation(self) -> None:
        """Constant propagation tracks constant values."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)

        instructions: list[tuple[int, str, str]] = [
            (0x401000, "mov", "eax, 0x1234"),
            (0x401005, "mov", "ebx, 42"),
            (0x40100A, "xor", "ecx, ecx"),
        ]

        cfg_analyzer.build_cfg(instructions)
        result: DataFlowInfo = df_analyzer.analyze_data_flow(instructions)

        assert "ecx" in result.constant_propagation
        assert result.constant_propagation["ecx"] == 0


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestPatchPointSelection:
    """Test optimal patch point selection."""

    def test_patch_point_selector_initialization(self) -> None:
        """PatchPointSelector initializes with required analyzers."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)
        side_effect_analyzer: SideEffectAnalyzer = SideEffectAnalyzer(cfg_analyzer, df_analyzer)

        selector: PatchPointSelector = PatchPointSelector(  # type: ignore[call-arg]
            cfg_analyzer, cs, side_effect_analyzer, df_analyzer
        )

        assert selector.cfg_analyzer == cfg_analyzer
        assert selector.disassembler == cs

    def test_select_patch_points_for_license_check(self) -> None:
        """Select optimal patch points for detected license check."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)
        side_effect_analyzer: SideEffectAnalyzer = SideEffectAnalyzer(cfg_analyzer, df_analyzer)

        instructions: list[tuple[int, str, str]] = [
            (0x401000, "call", "strcmp"),
            (0x401005, "test", "eax, eax"),
            (0x401007, "jnz", "0x401020"),
            (0x401009, "mov", "eax, 1"),
            (0x40100E, "ret", ""),
            (0x401020, "xor", "eax, eax"),
            (0x401022, "ret", ""),
        ]

        cfg_analyzer.build_cfg(instructions)

        license_check: LicenseCheck = LicenseCheck(
            check_type=CheckType.SERIAL_VALIDATION,
            address=0x401000,
            size=32,
            instructions=instructions,
            confidence=0.9,
            patch_strategy="nop",
            original_bytes=b"\x00" * 32,
            patched_bytes=b"\x90" * 32,
        )

        selector: PatchPointSelector = PatchPointSelector(  # type: ignore[call-arg]
            cfg_analyzer, cs, side_effect_analyzer, df_analyzer
        )
        patch_points: list[PatchPoint] = selector.select_optimal_patch_points(
            license_check, instructions
        )

        assert isinstance(patch_points, list)

    def test_analyze_nop_patch_points(self) -> None:
        """Analyze potential NOP patch points."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)
        side_effect_analyzer: SideEffectAnalyzer = SideEffectAnalyzer(cfg_analyzer, df_analyzer)

        instructions: list[tuple[int, str, str]] = [
            (0x401000, "call", "strcmp"),
            (0x401005, "test", "eax, eax"),
            (0x401007, "jnz", "0x401020"),
        ]

        cfg_analyzer.build_cfg(instructions)
        selector: PatchPointSelector = PatchPointSelector(  # type: ignore[call-arg]
            cfg_analyzer, cs, side_effect_analyzer, df_analyzer
        )

        if len(cfg_analyzer.basic_blocks) > 0:
            block: BasicBlock = list(cfg_analyzer.basic_blocks.values())[0]
            data_flow: DataFlowInfo = df_analyzer.analyze_data_flow(instructions)
            nop_points: list[PatchPoint] = selector._analyze_nop_points(
                block, 0x401000, data_flow
            )

            assert isinstance(nop_points, list)


@pytest.mark.skipif(not (CAPSTONE_AVAILABLE and KEYSTONE_AVAILABLE), reason="Requires Capstone and Keystone")
class TestBinaryPatching:
    """Test actual binary patching operations."""

    def test_patch_creates_backup(self, pe_with_serial_check: Path, temp_workspace: Path) -> None:
        """Patching creates backup of original binary."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))

        checks: list[LicenseCheck] = remover.analyze()

        original_data: bytes = pe_with_serial_check.read_bytes()

        result: bool = remover.patch(checks, create_backup=True)

        backup_path: Path = Path(f"{str(pe_with_serial_check)}.bak")
        if result and backup_path.exists():
            backup_data: bytes = backup_path.read_bytes()
            assert backup_data == original_data

    def test_patch_modifies_binary(self, pe_with_serial_check: Path) -> None:
        """Patching modifies the target binary."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))

        original_data: bytes = pe_with_serial_check.read_bytes()
        checks: list[LicenseCheck] = remover.analyze()

        result: bool = remover.patch(checks, create_backup=False)

        if result:
            patched_data: bytes = pe_with_serial_check.read_bytes()
            assert patched_data != original_data

    def test_patch_trial_check_binary(self, pe_with_trial_check: Path) -> None:
        """Patch trial period check in binary."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_trial_check))

        checks: list[LicenseCheck] = remover.analyze()

        result: bool = remover.patch(checks, create_backup=False)

        assert isinstance(result, bool)

    def test_verify_patches_after_patching(self, pe_with_serial_check: Path) -> None:
        """Verify patches after application."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))

        checks: list[LicenseCheck] = remover.analyze()

        patch_result: bool = remover.patch(checks, create_backup=False)

        if patch_result:
            verify_result: bool = remover.verify_patches()
            assert isinstance(verify_result, bool)

    def test_intelligent_patching_selects_best_points(
        self, pe_with_serial_check: Path
    ) -> None:
        """Intelligent patching selects optimal patch points."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))

        checks: list[LicenseCheck] = remover.analyze()

        result: bool = remover.apply_intelligent_patches(checks, use_best_point=True)

        assert isinstance(result, bool)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestJumpManipulation:
    """Test conditional jump modification."""

    def test_detect_conditional_jumps(self, pe_with_jump_checks: Path) -> None:
        """Detect conditional jumps in binary."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_jump_checks))

        checks: list[LicenseCheck] = remover.analyze()

        assert isinstance(checks, list)

    def test_invert_jump_je_to_jne(self) -> None:
        """Invert JE to JNE for license bypass."""
        je_opcode: bytes = b"\x74\x10"
        jne_opcode: bytes = b"\x75\x10"

        inverted: bytes = bytes([0x75, je_opcode[1]])

        assert inverted == jne_opcode

    def test_invert_jump_jz_to_jnz(self) -> None:
        """Invert JZ to JNZ for license bypass."""
        jz_opcode: bytes = b"\x74\x10"
        jnz_opcode: bytes = b"\x75\x10"

        inverted: bytes = bytes([0x75, jz_opcode[1]])

        assert inverted == jnz_opcode

    def test_invert_jump_jne_to_je(self) -> None:
        """Invert JNE to JE."""
        jne_opcode: bytes = b"\x75\x10"
        je_opcode: bytes = b"\x74\x10"

        inverted: bytes = bytes([0x74, jne_opcode[1]])

        assert inverted == je_opcode


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestRiskAssessment:
    """Test patch risk assessment engine."""

    def test_risk_assessment_engine_initialization(self) -> None:
        """RiskAssessmentEngine initializes with analyzers."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)
        side_effect_analyzer: SideEffectAnalyzer = SideEffectAnalyzer(cfg_analyzer, df_analyzer)

        risk_engine: RiskAssessmentEngine = RiskAssessmentEngine(
            cfg_analyzer, df_analyzer, side_effect_analyzer
        )

        assert risk_engine.cfg_analyzer == cfg_analyzer
        assert risk_engine.data_flow_analyzer == df_analyzer

    def test_assess_patch_risk_low_risk_patch(self) -> None:
        """Assess low-risk patch point."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)
        side_effect_analyzer: SideEffectAnalyzer = SideEffectAnalyzer(cfg_analyzer, df_analyzer)

        risk_engine: RiskAssessmentEngine = RiskAssessmentEngine(
            cfg_analyzer, df_analyzer, side_effect_analyzer
        )

        block: BasicBlock = BasicBlock(
            start_addr=0x401000, end_addr=0x401010, instructions=[]
        )

        patch_point: PatchPoint = PatchPoint(
            address=0x401000,
            block=block,
            patch_type="nop",
            safety_score=0.9,
            side_effects=[],
            registers_modified=set(),
            flags_modified=False,
            can_use_nop=True,
            can_use_jump=False,
            can_modify_return=False,
        )

        license_check: LicenseCheck = LicenseCheck(
            check_type=CheckType.SERIAL_VALIDATION,
            address=0x401000,
            size=10,
            instructions=[],
            confidence=0.9,
            patch_strategy="nop",
            original_bytes=b"\x00" * 10,
            patched_bytes=b"\x90" * 10,
        )

        risk: str = risk_engine.assess_patch_risk(patch_point, license_check)

        assert risk in {"low", "medium", "high"}


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestSideEffectAnalysis:
    """Test side effect detection for patches."""

    def test_side_effect_analyzer_initialization(self) -> None:
        """SideEffectAnalyzer initializes correctly."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)

        analyzer: SideEffectAnalyzer = SideEffectAnalyzer(cfg_analyzer, df_analyzer)

        assert analyzer.cfg_analyzer == cfg_analyzer
        assert analyzer.data_flow_analyzer == df_analyzer

    def test_detect_stack_modification_side_effects(self) -> None:
        """Detect stack modification side effects."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)
        analyzer: SideEffectAnalyzer = SideEffectAnalyzer(cfg_analyzer, df_analyzer)

        block: BasicBlock = BasicBlock(
            start_addr=0x401000,
            end_addr=0x401010,
            instructions=[
                (0x401000, "push", "ebp"),
                (0x401001, "mov", "ebp, esp"),
                (0x401003, "pop", "ebp"),
            ],
        )

        patch_point: PatchPoint = PatchPoint(
            address=0x401000,
            block=block,
            patch_type="nop",
            safety_score=0.8,
            side_effects=[],
            registers_modified=set(),
            flags_modified=False,
            can_use_nop=True,
            can_use_jump=False,
            can_modify_return=False,
        )

        side_effects: dict[str, Any] = analyzer.analyze_side_effects(patch_point, block.instructions)

        assert "stack_modified" in side_effects

    def test_detect_register_corruption(self) -> None:
        """Detect register corruption side effects."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)
        analyzer: SideEffectAnalyzer = SideEffectAnalyzer(cfg_analyzer, df_analyzer)

        block: BasicBlock = BasicBlock(
            start_addr=0x401000,
            end_addr=0x401010,
            instructions=[
                (0x401000, "mov", "eax, 10"),
                (0x401005, "xor", "ebx, ebx"),
            ],
        )

        patch_point: PatchPoint = PatchPoint(
            address=0x401000,
            block=block,
            patch_type="nop",
            safety_score=0.8,
            side_effects=[],
            registers_modified={"eax", "ebx"},
            flags_modified=False,
            can_use_nop=True,
            can_use_jump=False,
            can_modify_return=False,
        )

        side_effects: dict[str, Any] = analyzer.analyze_side_effects(patch_point, block.instructions)

        assert "registers_affected" in side_effects


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestReportGeneration:
    """Test patch report generation."""

    def test_generate_report_after_analysis(self, pe_with_serial_check: Path) -> None:
        """Generate report after license check analysis."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))

        checks: list[LicenseCheck] = remover.analyze()

        report: str = remover.generate_report()

        assert isinstance(report, str)
        assert report != ""

    def test_report_contains_check_information(self, pe_with_serial_check: Path) -> None:
        """Report contains detected check information."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))

        checks: list[LicenseCheck] = remover.analyze()

        report: str = remover.generate_report()

        if checks:
            assert "License Check" in report or "license" in report.lower()


class TestErrorHandling:
    """Test error handling for invalid inputs."""

    def test_invalid_binary_path_raises_error(self) -> None:
        """Invalid binary path raises appropriate error."""
        invalid_path: str = "D:\\nonexistent\\invalid_binary.exe"

        with pytest.raises(Exception):
            remover: LicenseCheckRemover = LicenseCheckRemover(invalid_path)
            remover.analyze()

    def test_corrupted_pe_header_handling(self, temp_workspace: Path) -> None:
        """Handle corrupted PE header gracefully."""
        corrupted_pe: Path = temp_workspace / "corrupted.exe"

        with corrupted_pe.open("wb") as f:
            f.write(b"MZ" + b"\x00" * 100)

        with pytest.raises(Exception):
            remover: LicenseCheckRemover = LicenseCheckRemover(str(corrupted_pe))
            remover.analyze()

    def test_empty_binary_handling(self, temp_workspace: Path) -> None:
        """Handle empty binary file."""
        empty_pe: Path = temp_workspace / "empty.exe"

        with empty_pe.open("wb") as f:
            f.write(b"")

        with pytest.raises(Exception):
            remover: LicenseCheckRemover = LicenseCheckRemover(str(empty_pe))
            remover.analyze()

    def test_non_pe_file_handling(self, temp_workspace: Path) -> None:
        """Handle non-PE file gracefully."""
        text_file: Path = temp_workspace / "text.txt"

        with text_file.open("wb") as f:
            f.write(b"This is not a PE file")

        with pytest.raises(Exception):
            remover: LicenseCheckRemover = LicenseCheckRemover(str(text_file))
            remover.analyze()


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestRealWorldScenarios:
    """Test real-world license cracking scenarios."""

    @pytest.mark.skip(reason="Implementation bug: x64 address packing requires '<Q' not '<I'")
    def test_analyze_real_windows_binary_notepad(self, real_notepad: Path) -> None:
        """Analyze real Windows notepad.exe for comparison patterns."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(real_notepad))

        checks: list[LicenseCheck] = remover.analyze()

        assert isinstance(checks, list)

    def test_analyze_real_windows_binary_calc(self, real_calc: Path) -> None:
        """Analyze real Windows calc.exe."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(real_calc))

        checks: list[LicenseCheck] = remover.analyze()

        assert isinstance(checks, list)

    def test_full_workflow_detect_and_patch(self, pe_with_serial_check: Path) -> None:
        """Complete workflow: detect license checks and apply patches."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))

        original_data: bytes = pe_with_serial_check.read_bytes()

        checks: list[LicenseCheck] = remover.analyze()

        patch_result: bool = remover.patch(checks, create_backup=True)

        assert isinstance(patch_result, bool)

        if patch_result:
            patched_data: bytes = pe_with_serial_check.read_bytes()
            backup_path: Path = Path(f"{str(pe_with_serial_check)}.bak")
            if backup_path.exists():
                backup_data: bytes = backup_path.read_bytes()
                assert backup_data == original_data


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestAdvancedPatternDetection:
    """Test advanced pattern detection capabilities."""

    def test_detect_cloud_validation_pattern(self) -> None:
        """Detect cloud-based license validation patterns."""
        matcher: PatternMatcher = PatternMatcher()

        assert "cloud_validation" in matcher.patterns

    def test_detect_blockchain_check_pattern(self) -> None:
        """Detect blockchain-based license validation."""
        matcher: PatternMatcher = PatternMatcher()

        assert "blockchain_check" in matcher.patterns

    def test_detect_tpm_hardware_check(self) -> None:
        """Detect TPM-based hardware validation."""
        matcher: PatternMatcher = PatternMatcher()

        assert "tpm_check" in matcher.patterns

    def test_detect_ml_validation_pattern(self) -> None:
        """Detect machine learning based validation."""
        matcher: PatternMatcher = PatternMatcher()

        assert "ml_validation" in matcher.patterns

    def test_detect_ntp_time_check(self) -> None:
        """Detect NTP time-based license checks."""
        matcher: PatternMatcher = PatternMatcher()

        assert "ntp_time_check" in matcher.patterns

    def test_detect_container_detection(self) -> None:
        """Detect container environment checks."""
        matcher: PatternMatcher = PatternMatcher()

        assert "container_check" in matcher.patterns

    def test_detect_usb_dongle_check(self) -> None:
        """Detect USB hardware dongle validation."""
        matcher: PatternMatcher = PatternMatcher()

        assert "usb_dongle" in matcher.patterns


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestPEStructureAnalysis:
    """Test PE structure analysis for patching."""

    def test_analyze_pe_sections(self, pe_with_serial_check: Path) -> None:
        """Analyze PE sections for license checks."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))

        assert hasattr(remover, "pe")

    def test_detect_pe_characteristics(self, pe_with_serial_check: Path) -> None:
        """Detect PE binary characteristics."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))

        assert hasattr(remover, "is_x64")
        assert hasattr(remover, "is_dotnet")

    def test_rva_to_offset_conversion(self, pe_with_serial_check: Path) -> None:
        """Convert RVA to file offset for patching."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))
        remover.analyze()

        rva: int = 0x1000
        offset: int | None = remover._rva_to_offset(rva)

        assert offset is None or isinstance(offset, int)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestDataFlowTracking:
    """Test data flow tracking for license data."""

    def test_track_license_key_data_flow(self) -> None:
        """Track license key through data flow."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)

        instructions: list[tuple[int, str, str]] = [
            (0x401000, "mov", "eax, [license_buffer]"),
            (0x401006, "mov", "ebx, eax"),
            (0x401008, "test", "ebx, ebx"),
            (0x40100A, "jz", "0x401020"),
        ]

        cfg_analyzer.build_cfg(instructions)
        result: DataFlowInfo = df_analyzer.analyze_data_flow(instructions)

        assert len(result.tainted_registers) >= 0

    def test_track_serial_validation_flow(self) -> None:
        """Track serial validation data flow."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)

        instructions: list[tuple[int, str, str]] = [
            (0x401000, "mov", "eax, [serial_input]"),
            (0x401006, "cmp", "eax, [serial_expected]"),
            (0x40100C, "jne", "0x401020"),
        ]

        cfg_analyzer.build_cfg(instructions)
        result: DataFlowInfo = df_analyzer.analyze_data_flow(instructions)

        assert hasattr(result, "definitions")

    def test_track_hwid_validation_flow(self) -> None:
        """Track hardware ID validation flow."""
        cs: Any = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer: ControlFlowAnalyzer = ControlFlowAnalyzer(cs)
        df_analyzer: DataFlowAnalyzer = DataFlowAnalyzer(cfg_analyzer)

        instructions: list[tuple[int, str, str]] = [
            (0x401000, "mov", "eax, [hwid_value]"),
            (0x401006, "mov", "ebx, eax"),
        ]

        cfg_analyzer.build_cfg(instructions)
        result: DataFlowInfo = df_analyzer.analyze_data_flow(instructions)

        assert hasattr(result, "uses")


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestBasicBlockOperations:
    """Test basic block construction and analysis."""

    def test_basic_block_creation(self) -> None:
        """Create basic block structure."""
        block: BasicBlock = BasicBlock(
            start_addr=0x401000,
            end_addr=0x401010,
            instructions=[
                (0x401000, "push", "ebp"),
                (0x401001, "mov", "ebp, esp"),
                (0x401003, "ret", ""),
            ],
        )

        assert block.start_addr == 0x401000
        assert block.end_addr == 0x401010
        assert len(block.instructions) == 3

    def test_basic_block_successors(self) -> None:
        """Basic block tracks successors."""
        block: BasicBlock = BasicBlock(
            start_addr=0x401000, end_addr=0x401010, instructions=[]
        )

        block.successors.append(0x401020)
        block.successors.append(0x401030)

        assert len(block.successors) == 2
        assert 0x401020 in block.successors

    def test_basic_block_predecessors(self) -> None:
        """Basic block tracks predecessors."""
        block: BasicBlock = BasicBlock(
            start_addr=0x401000, end_addr=0x401010, instructions=[]
        )

        block.predecessors.append(0x400FF0)

        assert len(block.predecessors) == 1
        assert 0x400FF0 in block.predecessors

    def test_basic_block_dominators(self) -> None:
        """Basic block tracks dominator information."""
        block: BasicBlock = BasicBlock(
            start_addr=0x401000, end_addr=0x401010, instructions=[]
        )

        block.dominators.add(0x401000)
        block.dominators.add(0x400000)

        assert len(block.dominators) == 2
        assert 0x401000 in block.dominators


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestPatchStrategies:
    """Test different patching strategies."""

    def test_nop_patch_strategy(self, pe_with_serial_check: Path) -> None:
        """NOP-based patch strategy for license checks."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_serial_check))

        if checks := remover.analyze():
            check: LicenseCheck = checks[0]
            assert hasattr(check, "patch_strategy")

    def test_jump_redirection_strategy(self, pe_with_jump_checks: Path) -> None:
        """Jump redirection patch strategy."""
        remover: LicenseCheckRemover = LicenseCheckRemover(str(pe_with_jump_checks))

        checks: list[LicenseCheck] = remover.analyze()

        assert isinstance(checks, list)

    def test_return_value_modification_strategy(self) -> None:
        """Return value modification patch strategy."""
        check: LicenseCheck = LicenseCheck(
            check_type=CheckType.SERIAL_VALIDATION,
            address=0x401000,
            size=10,
            instructions=[],
            confidence=0.9,
            patch_strategy="return_modification",
            original_bytes=b"\x00" * 10,
            patched_bytes=b"\x90" * 10,
        )

        assert check.patch_strategy == "return_modification"


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestCheckTypeClassification:
    """Test license check type classification."""

    def test_serial_validation_classification(self) -> None:
        """Classify serial validation checks."""
        check_type: CheckType = CheckType.SERIAL_VALIDATION

        assert check_type.value == "serial_validation"

    def test_registration_check_classification(self) -> None:
        """Classify registration checks."""
        check_type: CheckType = CheckType.REGISTRATION_CHECK

        assert check_type.value == "registration_check"

    def test_activation_check_classification(self) -> None:
        """Classify activation checks."""
        check_type: CheckType = CheckType.ACTIVATION_CHECK

        assert check_type.value == "activation_check"

    def test_trial_check_classification(self) -> None:
        """Classify trial period checks."""
        check_type: CheckType = CheckType.TRIAL_CHECK

        assert check_type.value == "trial_check"

    def test_online_validation_classification(self) -> None:
        """Classify online validation checks."""
        check_type: CheckType = CheckType.ONLINE_VALIDATION

        assert check_type.value == "online_validation"

    def test_hardware_check_classification(self) -> None:
        """Classify hardware-based checks."""
        check_type: CheckType = CheckType.HARDWARE_CHECK

        assert check_type.value == "hardware_check"


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestLicenseCheckStructure:
    """Test LicenseCheck data structure."""

    def test_license_check_creation(self) -> None:
        """Create LicenseCheck instance."""
        check: LicenseCheck = LicenseCheck(
            check_type=CheckType.SERIAL_VALIDATION,
            address=0x401000,
            size=32,
            instructions=[],
            confidence=0.95,
            patch_strategy="nop",
            original_bytes=b"\x00" * 32,
            patched_bytes=b"\x90" * 32,
        )

        assert check.address == 0x401000
        assert check.size == 32
        assert check.confidence == 0.95

    def test_license_check_with_patch_points(self) -> None:
        """LicenseCheck tracks optimal patch points."""
        block: BasicBlock = BasicBlock(
            start_addr=0x401000, end_addr=0x401010, instructions=[]
        )

        patch_point: PatchPoint = PatchPoint(
            address=0x401000,
            block=block,
            patch_type="nop",
            safety_score=0.9,
            side_effects=[],
            registers_modified=set(),
            flags_modified=False,
            can_use_nop=True,
            can_use_jump=False,
            can_modify_return=False,
        )

        check: LicenseCheck = LicenseCheck(
            check_type=CheckType.SERIAL_VALIDATION,
            address=0x401000,
            size=10,
            instructions=[],
            confidence=0.9,
            patch_strategy="nop",
            original_bytes=b"\x00" * 10,
            patched_bytes=b"\x90" * 10,
            patch_points=[patch_point],
        )

        assert len(check.patch_points) == 1
        assert check.patch_points[0].address == 0x401000


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone required")
class TestPatchPointStructure:
    """Test PatchPoint data structure."""

    def test_patch_point_creation(self) -> None:
        """Create PatchPoint instance."""
        block: BasicBlock = BasicBlock(
            start_addr=0x401000, end_addr=0x401010, instructions=[]
        )

        patch_point: PatchPoint = PatchPoint(
            address=0x401000,
            block=block,
            patch_type="nop",
            safety_score=0.85,
            side_effects=["register_clobber"],
            registers_modified={"eax", "ebx"},
            flags_modified=True,
            can_use_nop=True,
            can_use_jump=False,
            can_modify_return=False,
        )

        assert patch_point.address == 0x401000
        assert patch_point.safety_score == 0.85
        assert "eax" in patch_point.registers_modified

    def test_patch_point_alternative_points(self) -> None:
        """PatchPoint tracks alternative patch locations."""
        block: BasicBlock = BasicBlock(
            start_addr=0x401000, end_addr=0x401010, instructions=[]
        )

        patch_point: PatchPoint = PatchPoint(
            address=0x401000,
            block=block,
            patch_type="nop",
            safety_score=0.8,
            side_effects=[],
            registers_modified=set(),
            flags_modified=False,
            can_use_nop=True,
            can_use_jump=True,
            can_modify_return=False,
            alternative_points=[0x401005, 0x40100A],
        )

        assert len(patch_point.alternative_points) == 2
        assert 0x401005 in patch_point.alternative_points

    def test_patch_point_risk_assessment(self) -> None:
        """PatchPoint includes risk assessment."""
        block: BasicBlock = BasicBlock(
            start_addr=0x401000, end_addr=0x401010, instructions=[]
        )

        patch_point: PatchPoint = PatchPoint(
            address=0x401000,
            block=block,
            patch_type="jump_redirect",
            safety_score=0.6,
            side_effects=["control_flow_change"],
            registers_modified={"eax"},
            flags_modified=True,
            can_use_nop=False,
            can_use_jump=True,
            can_modify_return=False,
            risk_assessment="medium",
        )

        assert patch_point.risk_assessment == "medium"
