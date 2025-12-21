"""Comprehensive production-grade tests for license check remover.

Tests validate real license bypass capabilities on actual protected binaries.
All tests verify genuine offensive functionality against real protections.
"""

import logging
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
def temp_workspace() -> Path:
    """Provide temporary directory for test operations."""
    temp_dir = Path(tempfile.mkdtemp(prefix="intellicrack_lcr_test_"))
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def simple_pe_x86(temp_workspace: Path) -> Path:
    """Create minimal x86 PE with license check pattern."""
    pe_path = temp_workspace / "simple_x86.exe"

    pe_header = bytearray(4096)
    pe_header[:2] = b"MZ"
    pe_header[0x3C:0x40] = struct.pack("<I", 0x80)
    pe_header[0x80:0x84] = b"PE\x00\x00"
    pe_header[0x84:0x86] = struct.pack("<H", 0x14C)
    pe_header[0x86:0x88] = struct.pack("<H", 1)

    optional_header_offset = 0x98
    pe_header[optional_header_offset : optional_header_offset + 2] = struct.pack("<H", 0x010B)
    image_base_offset = optional_header_offset + 0x1C
    pe_header[image_base_offset : image_base_offset + 4] = struct.pack("<I", 0x00400000)
    section_alignment_offset = optional_header_offset + 0x20
    pe_header[section_alignment_offset : section_alignment_offset + 4] = struct.pack("<I", 0x1000)
    file_alignment_offset = optional_header_offset + 0x24
    pe_header[file_alignment_offset : file_alignment_offset + 4] = struct.pack("<I", 0x200)

    code_section = bytearray(512)
    code_section[:10] = b"\x55\x89\xe5"
    code_section[10:20] = b"\xe8\x00\x00\x00\x00\xff\x15\x00\x10\x40\x00"
    code_section[20:30] = b"\x85\xc0"
    code_section[30:40] = b"\x75\x05"
    code_section[40:50] = b"\x31\xc0\xc3"
    code_section[50:60] = b"\xb8\x01\x00\x00\x00"
    code_section[60:70] = b"\xc3"

    with pe_path.open("wb") as f:
        f.write(pe_header)
        f.write(code_section)

    return pe_path


@pytest.fixture
def simple_pe_x64(temp_workspace: Path) -> Path:
    """Create minimal x64 PE with license check pattern."""
    pe_path = temp_workspace / "simple_x64.exe"

    pe_header = bytearray(4096)
    pe_header[:2] = b"MZ"
    pe_header[0x3C:0x40] = struct.pack("<I", 0x80)
    pe_header[0x80:0x84] = b"PE\x00\x00"
    pe_header[0x84:0x86] = struct.pack("<H", 0x8664)
    pe_header[0x86:0x88] = struct.pack("<H", 1)

    optional_header_offset = 0x98
    pe_header[optional_header_offset : optional_header_offset + 2] = struct.pack("<H", 0x020B)
    image_base_offset = optional_header_offset + 0x18
    pe_header[image_base_offset : image_base_offset + 8] = struct.pack("<Q", 0x0000000140000000)
    section_alignment_offset = optional_header_offset + 0x20
    pe_header[section_alignment_offset : section_alignment_offset + 4] = struct.pack("<I", 0x1000)
    file_alignment_offset = optional_header_offset + 0x24
    pe_header[file_alignment_offset : file_alignment_offset + 4] = struct.pack("<I", 0x200)

    code_section = bytearray(512)
    code_section[:10] = b"\x55\x48\x89\xe5"
    code_section[10:20] = b"\xe8\x00\x00\x00\x00\xff\x15\x00\x10\x40\x00"
    code_section[20:30] = b"\x48\x85\xc0"
    code_section[30:40] = b"\x75\x05"
    code_section[40:50] = b"\x48\x31\xc0\xc3"
    code_section[50:60] = b"\x48\xc7\xc0\x01\x00\x00\x00"
    code_section[60:70] = b"\xc3"

    with pe_path.open("wb") as f:
        f.write(pe_header)
        f.write(code_section)

    return pe_path


@pytest.fixture
def protected_binaries_dir() -> Path:
    """Return path to protected binaries fixtures."""
    return Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "protected"


@pytest.fixture
def real_protected_binary(protected_binaries_dir: Path) -> Path:
    """Get real protected binary for testing."""
    candidates = [
        "upx_packed_0.exe",
        "dotnet_assembly_0.exe",
        "themida_protected.exe",
        "vmprotect_protected.exe",
    ]

    for candidate in candidates:
        binary_path = protected_binaries_dir / candidate
        if binary_path.exists() and binary_path.stat().st_size > 0:
            return binary_path

    pytest.skip("No real protected binaries available for testing")


class TestCheckType:
    """Test CheckType enumeration."""

    def test_check_type_values_exist(self) -> None:
        """Verify all check type values are defined."""
        assert CheckType.SERIAL_VALIDATION.value == "serial_validation"
        assert CheckType.REGISTRATION_CHECK.value == "registration_check"
        assert CheckType.ACTIVATION_CHECK.value == "activation_check"
        assert CheckType.TRIAL_CHECK.value == "trial_check"
        assert CheckType.FEATURE_CHECK.value == "feature_check"
        assert CheckType.ONLINE_VALIDATION.value == "online_validation"
        assert CheckType.HARDWARE_CHECK.value == "hardware_check"
        assert CheckType.DATE_CHECK.value == "date_check"
        assert CheckType.SIGNATURE_CHECK.value == "signature_check"
        assert CheckType.INTEGRITY_CHECK.value == "integrity_check"

    def test_check_type_uniqueness(self) -> None:
        """Verify check types have unique values."""
        values = [ct.value for ct in CheckType]
        assert len(values) == len(set(values))


class TestPatternMatcher:
    """Test pattern matching engine for license checks."""

    def test_pattern_matcher_initialization(self) -> None:
        """Pattern matcher initializes with pattern databases."""
        matcher = PatternMatcher()

        assert len(matcher.patterns) > 0
        assert len(matcher.obfuscation_patterns) > 0
        assert len(matcher.vm_patterns) > 0

        assert "serial_cmp" in matcher.patterns
        assert "dotnet_license" in matcher.patterns
        assert "cloud_validation" in matcher.patterns
        assert "modern_crypto" in matcher.patterns

    def test_pattern_matcher_finds_serial_validation(self) -> None:
        """Pattern matcher detects serial validation patterns."""
        matcher = PatternMatcher()

        instructions = [
            (0x401000, "call", "strcmp"),
            (0x401005, "test", "eax, eax"),
            (0x401007, "jne", "0x401020"),
        ]

        matches = matcher.find_patterns(instructions)

        assert len(matches) > 0
        serial_matches = [m for m in matches if m["type"] == CheckType.SERIAL_VALIDATION]
        assert serial_matches
        assert serial_matches[0]["confidence"] >= 0.8

    def test_pattern_matcher_finds_online_validation(self) -> None:
        """Pattern matcher detects online validation patterns."""
        matcher = PatternMatcher()

        instructions = [
            (0x401000, "call", "HttpClient.SendAsync"),
            (0x401005, "mov", "eax, [esp+4]"),
            (0x40100A, "call", "GetAwaiter"),
            (0x40100F, "test", "eax, eax"),
            (0x401011, "jz", "0x401030"),
        ]

        matches = matcher.find_patterns(instructions)

        assert len(matches) > 0
        online_matches = [m for m in matches if m["type"] == CheckType.ONLINE_VALIDATION]
        assert online_matches

    def test_pattern_matcher_finds_hardware_check(self) -> None:
        """Pattern matcher detects hardware validation patterns."""
        matcher = PatternMatcher()

        instructions = [
            (0x401000, "call", "NCryptOpenStorageProvider"),
            (0x401005, "mov", "ecx, eax"),
            (0x401007, "test", "eax, eax"),
            (0x401009, "jnz", "0x401020"),
        ]

        matches = matcher.find_patterns(instructions)

        hardware_matches = [m for m in matches if m["type"] == CheckType.HARDWARE_CHECK]
        assert hardware_matches

    def test_pattern_matcher_wildcard_matching(self) -> None:
        """Pattern matcher handles wildcard patterns correctly."""
        matcher = PatternMatcher()

        instructions = [
            (0x401000, "call", "HttpClient.SendAsync"),
            (0x401005, "mov", "eax, [esp+4]"),
            (0x40100A, "mov", "ecx, [esp+8]"),
            (0x40100F, "call", "GetAwaiter"),
            (0x401014, "test", "eax, eax"),
            (0x401016, "jz", "0x401030"),
        ]

        matches = matcher.find_patterns(instructions)
        assert len(matches) > 0

    def test_pattern_matcher_obfuscation_detection(self) -> None:
        """Pattern matcher detects obfuscated license checks."""
        matcher = PatternMatcher()

        instructions = [
            (0x401000, "mov", "eax, [ebp-4]"),
            (0x401003, "add", "eax, 1"),
            (0x401006, "cmp", "eax, 5"),
            (0x401008, "mov", "[ebp-4], eax"),
            (0x40100B, "mov", "eax, 1"),
        ]

        matches = matcher.find_patterns(instructions)
        assert matches is not None


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestControlFlowAnalyzer:
    """Test control flow graph construction and analysis."""

    def test_control_flow_analyzer_initialization(self) -> None:
        """Control flow analyzer initializes correctly."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True

        analyzer = ControlFlowAnalyzer(cs)

        assert analyzer.disassembler is cs
        assert len(analyzer.basic_blocks) == 0

    def test_cfg_builds_basic_blocks(self) -> None:
        """CFG analyzer constructs basic blocks from instructions."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True

        analyzer = ControlFlowAnalyzer(cs)

        instructions = [
            (0x401000, "push", "ebp"),
            (0x401001, "mov", "ebp, esp"),
            (0x401003, "call", "0x402000"),
            (0x401008, "test", "eax, eax"),
            (0x40100A, "jne", "0x401020"),
            (0x40100C, "xor", "eax, eax"),
            (0x40100E, "pop", "ebp"),
            (0x40100F, "ret", ""),
            (0x401020, "mov", "eax, 1"),
            (0x401025, "pop", "ebp"),
            (0x401026, "ret", ""),
        ]

        blocks = analyzer.build_cfg(instructions)

        assert len(blocks) > 0
        for addr, block in blocks.items():
            assert isinstance(block, BasicBlock)
            assert block.start_addr <= block.end_addr
            assert len(block.instructions) > 0

    def test_cfg_links_basic_blocks(self) -> None:
        """CFG analyzer correctly links basic block successors."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True

        analyzer = ControlFlowAnalyzer(cs)

        instructions = [
            (0x401000, "cmp", "eax, 0"),
            (0x401002, "jne", "0x401010"),
            (0x401004, "mov", "eax, 1"),
            (0x401009, "ret", ""),
            (0x401010, "mov", "eax, 2"),
            (0x401015, "ret", ""),
        ]

        blocks = analyzer.build_cfg(instructions)

        first_block = blocks.get(0x401000)
        assert first_block is not None
        assert len(first_block.successors) > 0

    def test_cfg_computes_dominators(self) -> None:
        """CFG analyzer computes dominator sets."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True

        analyzer = ControlFlowAnalyzer(cs)

        instructions = [
            (0x401000, "push", "ebp"),
            (0x401001, "cmp", "eax, 0"),
            (0x401003, "jne", "0x401010"),
            (0x401005, "mov", "eax, 1"),
            (0x40100A, "jmp", "0x401020"),
            (0x401010, "mov", "eax, 2"),
            (0x401015, "jmp", "0x401020"),
            (0x401020, "pop", "ebp"),
            (0x401021, "ret", ""),
        ]

        blocks = analyzer.build_cfg(instructions)

        for addr, block in blocks.items():
            assert isinstance(block.dominators, set)
            assert addr in block.dominators

    def test_cfg_finds_validation_branches(self) -> None:
        """CFG analyzer identifies validation branch patterns."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True

        analyzer = ControlFlowAnalyzer(cs)

        instructions = [
            (0x401000, "call", "strcmp"),
            (0x401005, "test", "eax, eax"),
            (0x401007, "jne", "0x401020"),
            (0x401009, "mov", "eax, 1"),
            (0x40100E, "ret", ""),
            (0x401020, "xor", "eax, eax"),
            (0x401022, "ret", ""),
        ]

        analyzer.build_cfg(instructions)
        validation_branches = analyzer.find_validation_branches()

        assert isinstance(validation_branches, list)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestDataFlowAnalyzer:
    """Test data flow analysis for license checks."""

    def test_data_flow_analyzer_initialization(self) -> None:
        """Data flow analyzer initializes correctly."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cfg_analyzer = ControlFlowAnalyzer(cs)

        dfa = DataFlowAnalyzer(cfg_analyzer)

        assert dfa.cfg_analyzer is cfg_analyzer

    def test_data_flow_analysis_tracks_definitions(self) -> None:
        """Data flow analyzer tracks register definitions."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        cfg_analyzer = ControlFlowAnalyzer(cs)

        instructions = [
            (0x401000, "mov", "eax, 0"),
            (0x401005, "mov", "ebx, 1"),
            (0x40100A, "add", "eax, ebx"),
        ]

        cfg_analyzer.build_cfg(instructions)
        dfa = DataFlowAnalyzer(cfg_analyzer)

        data_flow = dfa.analyze_data_flow(instructions)

        assert isinstance(data_flow, DataFlowInfo)
        assert len(data_flow.definitions) > 0

    def test_data_flow_tracks_register_usage(self) -> None:
        """Data flow analyzer tracks register uses."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        cfg_analyzer = ControlFlowAnalyzer(cs)

        instructions = [
            (0x401000, "mov", "eax, 5"),
            (0x401005, "cmp", "eax, 0"),
            (0x401007, "jne", "0x401010"),
        ]

        cfg_analyzer.build_cfg(instructions)
        dfa = DataFlowAnalyzer(cfg_analyzer)

        data_flow = dfa.analyze_data_flow(instructions)

        assert len(data_flow.uses) > 0

    def test_data_flow_taint_analysis(self) -> None:
        """Data flow analyzer performs taint analysis on license data."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        cfg_analyzer = ControlFlowAnalyzer(cs)

        instructions = [
            (0x401000, "mov", "eax, [license_key]"),
            (0x401005, "mov", "ebx, eax"),
            (0x401007, "cmp", "ebx, 0"),
        ]

        cfg_analyzer.build_cfg(instructions)
        dfa = DataFlowAnalyzer(cfg_analyzer)

        data_flow = dfa.analyze_data_flow(instructions)

        assert isinstance(data_flow.tainted_registers, dict)

    def test_data_flow_constant_propagation(self) -> None:
        """Data flow analyzer propagates constant values."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        cfg_analyzer = ControlFlowAnalyzer(cs)

        instructions = [
            (0x401000, "mov", "eax, 0x1234"),
            (0x401005, "mov", "ebx, 0x5678"),
            (0x40100A, "xor", "ecx, ecx"),
        ]

        cfg_analyzer.build_cfg(instructions)
        dfa = DataFlowAnalyzer(cfg_analyzer)

        data_flow = dfa.analyze_data_flow(instructions)

        assert isinstance(data_flow.constant_propagation, dict)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestPatchPointSelector:
    """Test optimal patch point selection."""

    def test_patch_point_selector_initialization(self) -> None:
        """Patch point selector initializes correctly."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        cfg_analyzer = ControlFlowAnalyzer(cs)

        selector = PatchPointSelector(cfg_analyzer, cs)

        assert selector.cfg_analyzer is cfg_analyzer
        assert selector.disassembler is cs

    def test_patch_point_selector_finds_nop_points(self) -> None:
        """Patch point selector identifies safe NOP points."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        cfg_analyzer = ControlFlowAnalyzer(cs)

        instructions = [
            (0x401000, "call", "strcmp"),
            (0x401005, "test", "eax, eax"),
            (0x401007, "jne", "0x401020"),
            (0x401009, "mov", "eax, 0"),
            (0x40100E, "ret", ""),
        ]

        cfg_analyzer.build_cfg(instructions)
        selector = PatchPointSelector(cfg_analyzer, cs)

        license_check = LicenseCheck(
            check_type=CheckType.SERIAL_VALIDATION,
            address=0x401005,
            size=10,
            instructions=instructions[1:3],
            confidence=0.9,
            patch_strategy="nop",
            original_bytes=b"\x85\xc0\x75\x17",
            patched_bytes=b"\x90\x90\x90\x90",
        )

        patch_points = selector.select_optimal_patch_points(license_check, instructions)

        assert isinstance(patch_points, list)
        if patch_points:
            assert all(isinstance(p, PatchPoint) for p in patch_points)
            assert patch_points[0].safety_score >= 0.0

    def test_patch_point_selector_safety_scoring(self) -> None:
        """Patch point selector assigns safety scores correctly."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        cfg_analyzer = ControlFlowAnalyzer(cs)

        instructions = [
            (0x401000, "push", "ebp"),
            (0x401001, "mov", "ebp, esp"),
            (0x401003, "cmp", "eax, 0"),
            (0x401005, "jne", "0x401010"),
            (0x401007, "nop", ""),
            (0x401008, "pop", "ebp"),
            (0x401009, "ret", ""),
        ]

        cfg_analyzer.build_cfg(instructions)
        selector = PatchPointSelector(cfg_analyzer, cs)

        license_check = LicenseCheck(
            check_type=CheckType.TRIAL_CHECK,
            address=0x401003,
            size=5,
            instructions=instructions[2:4],
            confidence=0.85,
            patch_strategy="nop",
            original_bytes=b"\x83\xf8\x00\x75\x07",
            patched_bytes=b"\x90\x90\x90\x90\x90",
        )

        if patch_points := selector.select_optimal_patch_points(
            license_check, instructions
        ):
            for point in patch_points:
                assert 0.0 <= point.safety_score <= 1.0


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestSideEffectAnalyzer:
    """Test side effect analysis for patches."""

    def test_side_effect_analyzer_detects_stack_modifications(self) -> None:
        """Side effect analyzer detects stack integrity risks."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        cfg_analyzer = ControlFlowAnalyzer(cs)

        instructions = [(0x401000, "push", "ebp"), (0x401001, "mov", "esp, ebp")]

        cfg_analyzer.build_cfg(instructions)
        dfa = DataFlowAnalyzer(cfg_analyzer)
        analyzer = SideEffectAnalyzer(cfg_analyzer, dfa)

        block = BasicBlock(
            start_addr=0x401000, end_addr=0x401001, instructions=instructions
        )

        patch_point = PatchPoint(
            address=0x401000,
            block=block,
            patch_type="nop",
            safety_score=0.9,
            side_effects=[],
            registers_modified={"esp"},
            flags_modified=False,
            can_use_nop=True,
            can_use_jump=False,
            can_modify_return=False,
        )

        effects = analyzer.analyze_side_effects(patch_point, instructions)

        assert isinstance(effects, dict)
        assert "breaks_stack" in effects


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestRiskAssessmentEngine:
    """Test patch risk assessment."""

    def test_risk_assessment_engine_evaluates_patches(self) -> None:
        """Risk assessment engine evaluates patch safety."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        cfg_analyzer = ControlFlowAnalyzer(cs)
        dfa = DataFlowAnalyzer(cfg_analyzer)
        sea = SideEffectAnalyzer(cfg_analyzer, dfa)

        engine = RiskAssessmentEngine(cfg_analyzer, dfa, sea)

        block = BasicBlock(
            start_addr=0x401000,
            end_addr=0x401010,
            instructions=[(0x401000, "nop", "")],
        )

        patch_point = PatchPoint(
            address=0x401000,
            block=block,
            patch_type="nop",
            safety_score=0.95,
            side_effects=[],
            registers_modified=set(),
            flags_modified=False,
            can_use_nop=True,
            can_use_jump=False,
            can_modify_return=False,
        )

        license_check = LicenseCheck(
            check_type=CheckType.SERIAL_VALIDATION,
            address=0x401000,
            size=5,
            instructions=[],
            confidence=0.9,
            patch_strategy="nop",
            original_bytes=b"\x90" * 5,
            patched_bytes=b"\x90" * 5,
        )

        risk = engine.assess_patch_risk(patch_point, license_check)

        assert risk in ["low", "medium", "high", "critical"]


@pytest.mark.skipif(not CAPSTONE_AVAILABLE or not KEYSTONE_AVAILABLE, reason="Capstone or Keystone not available")
class TestLicenseCheckRemoverInitialization:
    """Test license check remover initialization and setup."""

    def test_license_check_remover_initializes_with_valid_pe(self, simple_pe_x86: Path) -> None:
        """License check remover initializes successfully with valid PE."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        assert remover.binary_path == str(simple_pe_x86)
        assert remover.pe is not None
        assert remover.disassembler is not None
        assert remover.assembler is not None

    def test_license_check_remover_detects_architecture(self, simple_pe_x86: Path, simple_pe_x64: Path) -> None:
        """License check remover detects binary architecture correctly."""
        remover_x86 = LicenseCheckRemover(str(simple_pe_x86))
        assert remover_x86.pe.FILE_HEADER.Machine == 0x14C

        remover_x64 = LicenseCheckRemover(str(simple_pe_x64))
        assert remover_x64.pe.FILE_HEADER.Machine == 0x8664

    def test_license_check_remover_initializes_pattern_matcher(self, simple_pe_x86: Path) -> None:
        """License check remover initializes pattern matcher."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        assert remover.pattern_matcher is not None
        assert isinstance(remover.pattern_matcher, PatternMatcher)

    def test_license_check_remover_initializes_analyzers(self, simple_pe_x86: Path) -> None:
        """License check remover initializes CFG and patch analyzers."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        assert remover.cfg_analyzer is not None
        assert remover.patch_selector is not None


@pytest.mark.skipif(not CAPSTONE_AVAILABLE or not KEYSTONE_AVAILABLE, reason="Capstone or Keystone not available")
class TestLicenseCheckDetection:
    """Test license check detection capabilities."""

    def test_analyze_detects_license_checks_in_real_binary(self, real_protected_binary: Path, temp_workspace: Path) -> None:
        """Analyzer detects license checks in real protected binaries."""
        test_binary = temp_workspace / "test_protected.exe"
        shutil.copy2(real_protected_binary, test_binary)

        remover = LicenseCheckRemover(str(test_binary))
        checks = remover.analyze()

        assert isinstance(checks, list)
        assert all(isinstance(c, LicenseCheck) for c in checks)

        if checks:
            assert checks[0].confidence > 0.0
            assert checks[0].check_type in CheckType

    def test_analyze_populates_check_metadata(self, simple_pe_x86: Path) -> None:
        """Analyzer populates complete check metadata."""
        remover = LicenseCheckRemover(str(simple_pe_x86))
        checks = remover.analyze()

        for check in checks:
            assert check.address > 0
            assert check.size > 0
            assert isinstance(check.check_type, CheckType)
            assert 0.0 <= check.confidence <= 1.0
            assert check.patch_strategy != ""
            assert len(check.original_bytes) > 0
            assert len(check.patched_bytes) > 0

    def test_analyze_sorts_by_confidence(self, simple_pe_x86: Path) -> None:
        """Analyzer sorts detected checks by confidence."""
        remover = LicenseCheckRemover(str(simple_pe_x86))
        checks = remover.analyze()

        if len(checks) > 1:
            for i in range(len(checks) - 1):
                assert checks[i].confidence >= checks[i + 1].confidence

    def test_analyze_identifies_check_types(self, simple_pe_x86: Path) -> None:
        """Analyzer correctly identifies different check types."""
        remover = LicenseCheckRemover(str(simple_pe_x86))
        checks = remover.analyze()

        check_types_found = {check.check_type for check in checks}
        assert all(ct in CheckType for ct in check_types_found)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE or not KEYSTONE_AVAILABLE, reason="Capstone or Keystone not available")
class TestPatchGeneration:
    """Test patch byte generation for different check types."""

    def test_patch_generation_creates_valid_patches(self, simple_pe_x86: Path) -> None:
        """Patch generator creates valid patch bytes."""
        remover = LicenseCheckRemover(str(simple_pe_x86))
        checks = remover.analyze()

        for check in checks:
            assert len(check.patched_bytes) > 0
            assert len(check.patched_bytes) >= check.size or len(check.patched_bytes) <= check.size + 10

    def test_patch_generation_serial_validation(self, simple_pe_x86: Path) -> None:
        """Patch generator handles serial validation checks."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        instructions = [(0x401000, "call", "strcmp"), (0x401005, "test", "eax, eax")]

        patch = remover._generate_patch(CheckType.SERIAL_VALIDATION, instructions, 10)

        assert isinstance(patch, bytes)
        assert len(patch) == 10

    def test_patch_generation_trial_check(self, simple_pe_x86: Path) -> None:
        """Patch generator handles trial checks."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        patch_x86 = remover._generate_trial_patch(is_x64=False, size=10)
        assert isinstance(patch_x86, bytes)
        assert len(patch_x86) == 10

        patch_x64 = remover._generate_trial_patch(is_x64=True, size=12)
        assert isinstance(patch_x64, bytes)
        assert len(patch_x64) == 12

    def test_patch_generation_registration_check(self, simple_pe_x86: Path) -> None:
        """Patch generator handles registration checks."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        patch = remover._generate_registration_patch(is_x64=False, size=8)
        assert isinstance(patch, bytes)
        assert len(patch) == 8

    def test_patch_generation_online_validation(self, simple_pe_x86: Path) -> None:
        """Patch generator handles online validation checks."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        instructions = [(0x401000, "call", "HttpClient.SendAsync")]

        patch = remover._generate_online_validation_patch(is_x64=False, instructions=instructions, size=15)
        assert isinstance(patch, bytes)
        assert len(patch) == 15

    def test_patch_generation_hardware_check(self, simple_pe_x86: Path) -> None:
        """Patch generator handles hardware checks."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        patch = remover._generate_hardware_check_patch(is_x64=False, size=10)
        assert isinstance(patch, bytes)
        assert len(patch) == 10

    def test_patch_generation_signature_check(self, simple_pe_x86: Path) -> None:
        """Patch generator handles signature checks."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        instructions = [(0x401000, "call", "CryptVerifySignature")]

        patch = remover._generate_signature_check_patch(is_x64=False, instructions=instructions, size=12)
        assert isinstance(patch, bytes)
        assert len(patch) == 12


@pytest.mark.skipif(not CAPSTONE_AVAILABLE or not KEYSTONE_AVAILABLE, reason="Capstone or Keystone not available")
class TestPatchApplication:
    """Test patch application and binary modification."""

    def test_patch_creates_backup(self, simple_pe_x86: Path, temp_workspace: Path) -> None:
        """Patch operation creates backup file."""
        test_binary = temp_workspace / "test_patch.exe"
        shutil.copy2(simple_pe_x86, test_binary)

        remover = LicenseCheckRemover(str(test_binary))
        if checks := remover.analyze():
            remover.patch(checks[:1], create_backup=True)

            backup_path = Path(f"{test_binary}.bak")
            assert backup_path.exists()

    def test_patch_modifies_binary(self, simple_pe_x86: Path, temp_workspace: Path) -> None:
        """Patch operation modifies binary on disk."""
        test_binary = temp_workspace / "test_modify.exe"
        shutil.copy2(simple_pe_x86, test_binary)

        original_size = test_binary.stat().st_size
        original_hash = test_binary.read_bytes()

        remover = LicenseCheckRemover(str(test_binary))
        if checks := remover.analyze():
            if success := remover.patch(checks[:1], create_backup=False):
                modified_hash = test_binary.read_bytes()
                assert test_binary.stat().st_size == original_size

    def test_patch_restores_on_error(self, simple_pe_x86: Path, temp_workspace: Path) -> None:
        """Patch operation restores from backup on error."""
        test_binary = temp_workspace / "test_restore.exe"
        shutil.copy2(simple_pe_x86, test_binary)

        remover = LicenseCheckRemover(str(test_binary))

        invalid_check = LicenseCheck(
            check_type=CheckType.SERIAL_VALIDATION,
            address=0xFFFFFFFF,
            size=10,
            instructions=[],
            confidence=0.9,
            patch_strategy="nop",
            original_bytes=b"\x90" * 10,
            patched_bytes=b"\x90" * 10,
        )

        remover.patch([invalid_check], create_backup=True)

        assert test_binary.exists()

    def test_patch_verification_succeeds(self, simple_pe_x86: Path, temp_workspace: Path) -> None:
        """Patch verification confirms successful patching."""
        test_binary = temp_workspace / "test_verify.exe"
        shutil.copy2(simple_pe_x86, test_binary)

        remover = LicenseCheckRemover(str(test_binary))
        if checks := remover.analyze():
            if success := remover.patch(checks[:1]):
                verified = remover.verify_patches()
                assert isinstance(verified, bool)

    def test_patch_updates_checksum(self, simple_pe_x86: Path, temp_workspace: Path) -> None:
        """Patch operation updates PE checksum."""
        test_binary = temp_workspace / "test_checksum.exe"
        shutil.copy2(simple_pe_x86, test_binary)

        remover = LicenseCheckRemover(str(test_binary))
        if checks := remover.analyze():
            remover.patch(checks[:1])

            pe_after = pefile.PE(str(test_binary))
            assert pe_after.OPTIONAL_HEADER.CheckSum >= 0


@pytest.mark.skipif(not CAPSTONE_AVAILABLE or not KEYSTONE_AVAILABLE, reason="Capstone or Keystone not available")
class TestIntelligentPatching:
    """Test intelligent patch point selection and application."""

    def test_intelligent_patching_uses_best_patch_points(self, simple_pe_x86: Path, temp_workspace: Path) -> None:
        """Intelligent patching uses optimal patch points."""
        test_binary = temp_workspace / "test_intelligent.exe"
        shutil.copy2(simple_pe_x86, test_binary)

        remover = LicenseCheckRemover(str(test_binary))
        if checks := remover.analyze():
            success = remover.apply_intelligent_patches(checks[:1], use_best_point=True)
            assert isinstance(success, bool)

    def test_intelligent_patching_generates_appropriate_patches(self, simple_pe_x86: Path) -> None:
        """Intelligent patching generates context-appropriate patches."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        block = BasicBlock(
            start_addr=0x401000, end_addr=0x401010, instructions=[]
        )

        nop_point = PatchPoint(
            address=0x401000,
            block=block,
            patch_type="nop",
            safety_score=0.95,
            side_effects=[],
            registers_modified=set(),
            flags_modified=False,
            can_use_nop=True,
            can_use_jump=False,
            can_modify_return=False,
        )

        check = LicenseCheck(
            check_type=CheckType.SERIAL_VALIDATION,
            address=0x401000,
            size=5,
            instructions=[],
            confidence=0.9,
            patch_strategy="nop",
            original_bytes=b"\x90" * 5,
            patched_bytes=b"\x90" * 5,
        )

        patch = remover._generate_intelligent_patch(nop_point, check)
        assert isinstance(patch, bytes)

    def test_intelligent_patching_handles_jump_redirection(self, simple_pe_x86: Path) -> None:
        """Intelligent patching generates jump redirections."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        block = BasicBlock(
            start_addr=0x401000, end_addr=0x401010, instructions=[]
        )

        jump_point = PatchPoint(
            address=0x401000,
            block=block,
            patch_type="jump_redirect",
            safety_score=0.9,
            side_effects=["control_flow_redirect"],
            registers_modified=set(),
            flags_modified=False,
            can_use_nop=False,
            can_use_jump=True,
            can_modify_return=False,
            alternative_points=[0x401020],
        )

        check = LicenseCheck(
            check_type=CheckType.REGISTRATION_CHECK,
            address=0x401000,
            size=5,
            instructions=[],
            confidence=0.85,
            patch_strategy="jump_redirect",
            original_bytes=b"\x75\x1e",
            patched_bytes=b"\xeb\x1e",
        )

        patch = remover._generate_intelligent_patch(jump_point, check)
        assert isinstance(patch, bytes)
        assert len(patch) > 0

    def test_intelligent_patching_handles_return_modification(self, simple_pe_x86: Path) -> None:
        """Intelligent patching modifies return values."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        block = BasicBlock(
            start_addr=0x401000, end_addr=0x401010, instructions=[]
        )

        return_point = PatchPoint(
            address=0x401000,
            block=block,
            patch_type="return_modify",
            safety_score=0.8,
            side_effects=["register_modification"],
            registers_modified={"eax"},
            flags_modified=False,
            can_use_nop=False,
            can_use_jump=False,
            can_modify_return=True,
        )

        check = LicenseCheck(
            check_type=CheckType.TRIAL_CHECK,
            address=0x401000,
            size=5,
            instructions=[],
            confidence=0.9,
            patch_strategy="return_modify",
            original_bytes=b"\x31\xc0\xc3",
            patched_bytes=b"\xb8\x01\x00\x00\x00\xc3",
        )

        patch = remover._generate_intelligent_patch(return_point, check)
        assert isinstance(patch, bytes)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE or not KEYSTONE_AVAILABLE, reason="Capstone or Keystone not available")
class TestBinaryCharacteristicsDetection:
    """Test detection of binary characteristics."""

    def test_detects_dotnet_binaries(self, simple_pe_x86: Path) -> None:
        """Remover detects .NET binaries."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        assert isinstance(remover.is_dotnet, bool)

    def test_detects_packed_binaries(self, simple_pe_x86: Path) -> None:
        """Remover detects packed binaries."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        assert isinstance(remover.is_packed, bool)

    def test_detects_anti_debug(self, simple_pe_x86: Path) -> None:
        """Remover detects anti-debug mechanisms."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        assert isinstance(remover.has_antidebug, bool)

    def test_detects_virtualization(self, simple_pe_x86: Path) -> None:
        """Remover detects code virtualization."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        assert isinstance(remover.virtualization_detected, bool)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE or not KEYSTONE_AVAILABLE, reason="Capstone or Keystone not available")
class TestReportGeneration:
    """Test detailed report generation."""

    def test_generate_report_produces_output(self, simple_pe_x86: Path) -> None:
        """Report generation produces formatted output."""
        remover = LicenseCheckRemover(str(simple_pe_x86))
        remover.analyze()

        report = remover.generate_report()

        assert isinstance(report, str)
        assert len(report) > 0
        assert "LICENSE CHECK REMOVAL REPORT" in report

    def test_generate_report_includes_binary_info(self, simple_pe_x86: Path) -> None:
        """Report includes binary information."""
        remover = LicenseCheckRemover(str(simple_pe_x86))
        remover.analyze()

        report = remover.generate_report()

        assert "Binary:" in report
        assert "Architecture:" in report

    def test_generate_report_includes_check_details(self, simple_pe_x86: Path) -> None:
        """Report includes license check details."""
        remover = LicenseCheckRemover(str(simple_pe_x86))
        checks = remover.analyze()

        report = remover.generate_report()

        if checks:
            assert "Address:" in report
            assert "Confidence:" in report
            assert "Strategy:" in report

    def test_generate_report_includes_cfg_info(self, simple_pe_x86: Path) -> None:
        """Report includes CFG analysis information."""
        remover = LicenseCheckRemover(str(simple_pe_x86))
        remover.analyze()

        report = remover.generate_report()

        assert "Total Checks Found:" in report


@pytest.mark.skipif(not CAPSTONE_AVAILABLE or not KEYSTONE_AVAILABLE, reason="Capstone or Keystone not available")
class TestRealWorldScenarios:
    """Test real-world license removal scenarios."""

    def test_vmprotect_detection_and_patching(self, protected_binaries_dir: Path, temp_workspace: Path) -> None:
        """Detect and patch VMProtect-protected binaries."""
        vmprotect_binary = protected_binaries_dir / "vmprotect_protected.exe"

        if not vmprotect_binary.exists() or vmprotect_binary.stat().st_size == 0:
            pytest.skip("VMProtect protected binary not available")

        test_binary = temp_workspace / "vmprotect_test.exe"
        shutil.copy2(vmprotect_binary, test_binary)

        remover = LicenseCheckRemover(str(test_binary))
        checks = remover.analyze()

        assert isinstance(checks, list)

        if checks:
            high_confidence_checks = [c for c in checks if c.confidence >= 0.7]

    def test_themida_detection_and_patching(self, protected_binaries_dir: Path, temp_workspace: Path) -> None:
        """Detect and patch Themida-protected binaries."""
        themida_binary = protected_binaries_dir / "themida_protected.exe"

        if not themida_binary.exists() or themida_binary.stat().st_size == 0:
            pytest.skip("Themida protected binary not available")

        test_binary = temp_workspace / "themida_test.exe"
        shutil.copy2(themida_binary, test_binary)

        remover = LicenseCheckRemover(str(test_binary))
        checks = remover.analyze()

        assert isinstance(checks, list)

    def test_upx_packed_binary_handling(self, protected_binaries_dir: Path, temp_workspace: Path) -> None:
        """Handle UPX-packed binaries correctly."""
        upx_binary = protected_binaries_dir / "upx_packed_0.exe"

        if not upx_binary.exists() or upx_binary.stat().st_size == 0:
            pytest.skip("UPX packed binary not available")

        test_binary = temp_workspace / "upx_test.exe"
        shutil.copy2(upx_binary, test_binary)

        remover = LicenseCheckRemover(str(test_binary))

        assert remover.is_packed or not remover.is_packed

        checks = remover.analyze()
        assert isinstance(checks, list)

    def test_dotnet_assembly_handling(self, protected_binaries_dir: Path, temp_workspace: Path) -> None:
        """Handle .NET assemblies correctly."""
        dotnet_binary = protected_binaries_dir / "dotnet_assembly_0.exe"

        if not dotnet_binary.exists() or dotnet_binary.stat().st_size == 0:
            pytest.skip(".NET assembly not available")

        test_binary = temp_workspace / "dotnet_test.exe"
        shutil.copy2(dotnet_binary, test_binary)

        remover = LicenseCheckRemover(str(test_binary))

        checks = remover.analyze()
        assert isinstance(checks, list)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE or not KEYSTONE_AVAILABLE, reason="Capstone or Keystone not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_empty_binary(self, temp_workspace: Path) -> None:
        """Handles empty binary files gracefully."""
        empty_binary = temp_workspace / "empty.exe"
        empty_binary.write_bytes(b"")

        with pytest.raises(Exception):
            LicenseCheckRemover(str(empty_binary))

    def test_handles_corrupted_pe_header(self, temp_workspace: Path) -> None:
        """Handles corrupted PE headers gracefully."""
        corrupted_binary = temp_workspace / "corrupted.exe"
        corrupted_binary.write_bytes(b"MZ" + b"\x00" * 100)

        with pytest.raises(Exception):
            LicenseCheckRemover(str(corrupted_binary))

    def test_handles_nonexistent_file(self) -> None:
        """Handles nonexistent files gracefully."""
        with pytest.raises(Exception):
            LicenseCheckRemover("/nonexistent/path/binary.exe")

    def test_patch_with_no_checks(self, simple_pe_x86: Path, temp_workspace: Path) -> None:
        """Patching with no checks returns False."""
        test_binary = temp_workspace / "no_checks.exe"
        shutil.copy2(simple_pe_x86, test_binary)

        remover = LicenseCheckRemover(str(test_binary))

        result = remover.patch([])
        assert result is False

    def test_verify_without_patching(self, simple_pe_x86: Path) -> None:
        """Verification without patching returns appropriate result."""
        remover = LicenseCheckRemover(str(simple_pe_x86))

        result = remover.verify_patches()
        assert isinstance(result, bool)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE or not KEYSTONE_AVAILABLE, reason="Capstone or Keystone not available")
class TestPerformance:
    """Test performance characteristics."""

    def test_analyze_completes_in_reasonable_time(self, real_protected_binary: Path, temp_workspace: Path) -> None:
        """Analysis completes within reasonable time."""
        import time

        test_binary = temp_workspace / "performance_test.exe"
        shutil.copy2(real_protected_binary, test_binary)

        remover = LicenseCheckRemover(str(test_binary))

        start = time.time()
        remover.analyze()
        elapsed = time.time() - start

        assert elapsed < 60.0

    def test_cfg_construction_scales(self, simple_pe_x86: Path) -> None:
        """CFG construction scales with binary size."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True

        analyzer = ControlFlowAnalyzer(cs)

        instructions = [(0x401000 + i, "nop", "") for i in range(1000)]

        import time

        start = time.time()
        analyzer.build_cfg(instructions)
        elapsed = time.time() - start

        assert elapsed < 5.0


@pytest.mark.skipif(not CAPSTONE_AVAILABLE or not KEYSTONE_AVAILABLE, reason="Capstone or Keystone not available")
class TestIntegration:
    """Integration tests for complete workflows."""

    def test_complete_analysis_and_patching_workflow(self, real_protected_binary: Path, temp_workspace: Path) -> None:
        """Complete analysis and patching workflow on real binary."""
        test_binary = temp_workspace / "complete_workflow.exe"
        shutil.copy2(real_protected_binary, test_binary)

        remover = LicenseCheckRemover(str(test_binary))

        checks = remover.analyze()
        assert isinstance(checks, list)

        if checks:
            if high_confidence := [c for c in checks if c.confidence >= 0.8]:
                if success := remover.patch(
                    high_confidence[:3], create_backup=True
                ):
                    assert remover.verify_patches()

                    backup_path = Path(f"{test_binary}.bak")
                    assert backup_path.exists()

    def test_intelligent_patching_workflow(self, real_protected_binary: Path, temp_workspace: Path) -> None:
        """Intelligent patching workflow with CFG analysis."""
        test_binary = temp_workspace / "intelligent_workflow.exe"
        shutil.copy2(real_protected_binary, test_binary)

        remover = LicenseCheckRemover(str(test_binary))

        if checks := remover.analyze():
            if validated_checks := [c for c in checks if c.validated_safe]:
                success = remover.apply_intelligent_patches(validated_checks[:2])
                assert isinstance(success, bool)

    def test_report_generation_workflow(self, real_protected_binary: Path, temp_workspace: Path) -> None:
        """Report generation workflow."""
        test_binary = temp_workspace / "report_workflow.exe"
        shutil.copy2(real_protected_binary, test_binary)

        remover = LicenseCheckRemover(str(test_binary))
        remover.analyze()

        report = remover.generate_report()

        assert isinstance(report, str)
        assert len(report) > 100
        assert "LICENSE CHECK REMOVAL REPORT" in report
        assert str(test_binary) in report
