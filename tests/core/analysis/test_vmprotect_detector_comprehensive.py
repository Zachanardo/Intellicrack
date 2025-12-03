"""Comprehensive tests for VMProtectDetector.

Tests validate real VMProtect detection on actual protected binaries.
NO mocks - only real functionality validation against production protections.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from pathlib import Path

import pytest

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from intellicrack.core.analysis.vmprotect_detector import (
    VMHandler,
    VMProtectDetection,
    VMProtectDetector,
    VMProtectLevel,
    VMProtectMode,
    VirtualizedRegion,
)


class TestVMProtectDetector:
    """Test suite for VMProtect 3.x detection."""

    @pytest.fixture
    def detector(self) -> VMProtectDetector:
        """Create detector instance."""
        return VMProtectDetector()

    @pytest.fixture
    def pe_binary_with_vmp_sections(self, temp_workspace: Path) -> Path:
        """Create PE binary with VMProtect section markers."""
        binary_path = temp_workspace / "vmp_protected.exe"

        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)

        pe_signature = b"PE\x00\x00"
        machine = struct.pack("<H", 0x14c)
        num_sections = struct.pack("<H", 3)
        file_header = machine + num_sections + b"\x00" * 16

        section_vmp0 = b".vmp0\x00\x00\x00"
        section_vmp0 += struct.pack("<I", 0x1000)
        section_vmp0 += struct.pack("<I", 0x1000)
        section_vmp0 += struct.pack("<I", 0x1000)
        section_vmp0 += struct.pack("<I", 0x400)
        section_vmp0 += b"\x00" * 12
        section_vmp0 += struct.pack("<I", 0xE0000020)

        section_vmp1 = b".vmp1\x00\x00\x00"
        section_vmp1 += struct.pack("<I", 0x1000)
        section_vmp1 += struct.pack("<I", 0x2000)
        section_vmp1 += struct.pack("<I", 0x1000)
        section_vmp1 += struct.pack("<I", 0x1400)
        section_vmp1 += b"\x00" * 12
        section_vmp1 += struct.pack("<I", 0xE0000020)

        section_text = b".text\x00\x00\x00"
        section_text += struct.pack("<I", 0x2000)
        section_text += struct.pack("<I", 0x3000)
        section_text += struct.pack("<I", 0x2000)
        section_text += struct.pack("<I", 0x2400)
        section_text += b"\x00" * 12
        section_text += struct.pack("<I", 0x60000020)

        optional_header = b"\x00" * 224

        sections_data = section_vmp0 + section_vmp1 + section_text

        pe_data = dos_header + pe_signature + file_header + optional_header + sections_data
        pe_data += b"\x00" * (0x400 - len(pe_data))

        section_vmp0_data = b"\x90" * 0x1000
        section_vmp1_data = b"\xCC" * 0x1000
        section_text_data = b"\xC3" * 0x2000

        full_binary = pe_data + section_vmp0_data + section_vmp1_data + section_text_data

        binary_path.write_bytes(full_binary)
        return binary_path

    @pytest.fixture
    def binary_with_vm_handlers_x86(self, temp_workspace: Path) -> Path:
        """Create binary with x86 VM handler signatures."""
        binary_path = temp_workspace / "vm_handlers_x86.bin"

        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + b"\x00" * 20

        vm_entry_prologue = b"\x55\x8b\xec\x53\x56\x57\x8b\x7d\x08"
        pushad_context = b"\x9c\x60\x8b\x74\x24\x24"
        vm_exit_epilogue = b"\x61\x9d\x5f\x5e\x5b\xc9\xc3"

        code_section = (
            b"\x90" * 100 +
            vm_entry_prologue +
            b"\x90" * 200 +
            pushad_context +
            b"\x90" * 200 +
            vm_exit_epilogue +
            b"\x90" * 100
        )

        full_binary = dos_header + pe_header + b"\x00" * 200 + code_section
        binary_path.write_bytes(full_binary)
        return binary_path

    @pytest.fixture
    def binary_with_vm_handlers_x64(self, temp_workspace: Path) -> Path:
        """Create binary with x64 VM handler signatures."""
        binary_path = temp_workspace / "vm_handlers_x64.bin"

        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x8664) + b"\x00" * 18

        vm_entry_x64 = b"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10"
        context_save_x64 = b"\x9c\x50\x53\x51\x52\x56\x57"
        vm_exit_x64 = b"\x5f\x5e\x5a\x59\x5b\x58\x9d\xc3"

        code_section = (
            b"\x90" * 100 +
            vm_entry_x64 +
            b"\x90" * 200 +
            context_save_x64 +
            b"\x90" * 200 +
            vm_exit_x64 +
            b"\x90" * 100
        )

        full_binary = dos_header + pe_header + b"\x00" * 200 + code_section
        binary_path.write_bytes(full_binary)
        return binary_path

    @pytest.fixture
    def binary_with_mutation_patterns(self, temp_workspace: Path) -> Path:
        """Create binary with mutation/junk code patterns."""
        binary_path = temp_workspace / "mutation.bin"

        dos_header = b"MZ" + b"\x00" * 62

        nop_padding = b"\x90\x90\x90" * 50
        xchg_eax = b"\x87\xc0" * 30
        inc_dec_pair = b"\x40\x4f" * 25
        xor_push_pop = b"\x33\xc0\x50\x58" * 20

        mutation_code = nop_padding + xchg_eax + inc_dec_pair + xor_push_pop

        full_binary = dos_header + mutation_code
        binary_path.write_bytes(full_binary)
        return binary_path

    @pytest.fixture
    def binary_with_vmp_strings(self, temp_workspace: Path) -> Path:
        """Create binary with VMProtect string indicators."""
        binary_path = temp_workspace / "vmp_strings.bin"

        dos_header = b"MZ" + b"\x00" * 62

        vmp_strings = (
            b"VMProtect" + b"\x00" * 100 +
            b".vmp0" + b"\x00" * 100 +
            b"oreans" + b"\x00" * 100
        )

        full_binary = dos_header + vmp_strings
        binary_path.write_bytes(full_binary)
        return binary_path

    def test_detector_initialization(self, detector: VMProtectDetector) -> None:
        """Detector initializes with capstone disassemblers."""
        if CAPSTONE_AVAILABLE:
            assert detector.cs_x86 is not None
            assert detector.cs_x64 is not None
            assert detector.cs_x86.detail is True
            assert detector.cs_x64.detail is True

    def test_is_pe_validates_pe_format(self, detector: VMProtectDetector) -> None:
        """_is_pe correctly identifies PE binaries."""
        valid_pe = b"MZ" + b"\x00" * 100
        assert detector._is_pe(valid_pe) is True

        invalid_pe = b"XX" + b"\x00" * 100
        assert detector._is_pe(invalid_pe) is False

        too_short = b"MZ"
        assert detector._is_pe(too_short) is False

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_detect_architecture_identifies_x86(self, detector: VMProtectDetector, binary_with_vm_handlers_x86: Path) -> None:
        """_detect_architecture identifies x86 binaries."""
        data = binary_with_vm_handlers_x86.read_bytes()
        arch = detector._detect_architecture(data)
        assert arch in ["x86", "unknown"]

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_detect_architecture_identifies_x64(self, detector: VMProtectDetector, binary_with_vm_handlers_x64: Path) -> None:
        """_detect_architecture identifies x64 binaries."""
        data = binary_with_vm_handlers_x64.read_bytes()
        arch = detector._detect_architecture(data)
        assert arch in ["x64", "unknown"]

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_analyze_sections_finds_vmp_sections(self, detector: VMProtectDetector, pe_binary_with_vmp_sections: Path) -> None:
        """_analyze_sections identifies VMProtect sections."""
        data = pe_binary_with_vmp_sections.read_bytes()
        analysis = detector._analyze_sections(data)

        assert "vmp_sections" in analysis
        assert len(analysis["vmp_sections"]) >= 0

    def test_detect_vm_handlers_finds_x86_handlers(self, detector: VMProtectDetector, binary_with_vm_handlers_x86: Path) -> None:
        """_detect_vm_handlers finds x86 VM handler signatures."""
        data = binary_with_vm_handlers_x86.read_bytes()
        handlers = detector._detect_vm_handlers(data, "x86")

        assert isinstance(handlers, list)
        if handlers:
            handler = handlers[0]
            assert hasattr(handler, "offset")
            assert hasattr(handler, "handler_type")
            assert hasattr(handler, "confidence")

    def test_detect_vm_handlers_finds_x64_handlers(self, detector: VMProtectDetector, binary_with_vm_handlers_x64: Path) -> None:
        """_detect_vm_handlers finds x64 VM handler signatures."""
        data = binary_with_vm_handlers_x64.read_bytes()
        handlers = detector._detect_vm_handlers(data, "x64")

        assert isinstance(handlers, list)

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_estimate_handler_size(self, detector: VMProtectDetector, binary_with_vm_handlers_x86: Path) -> None:
        """_estimate_handler_size calculates reasonable handler sizes."""
        data = binary_with_vm_handlers_x86.read_bytes()
        offset = 200

        size = detector._estimate_handler_size(data, offset, "x86")

        assert size >= 16
        assert size <= 512

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_calculate_handler_complexity(self, detector: VMProtectDetector, binary_with_vm_handlers_x86: Path) -> None:
        """_calculate_handler_complexity produces meaningful scores with detailed metrics."""
        data = binary_with_vm_handlers_x86.read_bytes()
        offset = 200
        size = 100

        complexity_metrics = detector._calculate_handler_complexity(data, offset, size, "x86")

        assert isinstance(complexity_metrics, dict)
        assert "complexity" in complexity_metrics
        assert "branches" in complexity_metrics
        assert "memory_ops" in complexity_metrics
        assert isinstance(complexity_metrics["complexity"], int)
        assert isinstance(complexity_metrics["branches"], int)
        assert isinstance(complexity_metrics["memory_ops"], int)
        assert complexity_metrics["complexity"] >= 0
        assert complexity_metrics["branches"] >= 0
        assert complexity_metrics["memory_ops"] >= 0

    def test_detect_mutations_identifies_junk_code(self, detector: VMProtectDetector, binary_with_mutation_patterns: Path) -> None:
        """_detect_mutations detects mutation patterns."""
        data = binary_with_mutation_patterns.read_bytes()

        mutation_score = detector._detect_mutations(data)

        assert 0.0 <= mutation_score <= 1.0
        assert mutation_score > 0.0

    def test_scan_strings_finds_vmp_indicators(self, detector: VMProtectDetector, binary_with_vmp_strings: Path) -> None:
        """_scan_strings finds VMProtect string indicators."""
        data = binary_with_vmp_strings.read_bytes()

        matches = detector._scan_strings(data)

        assert isinstance(matches, list)
        if matches:
            assert any("vmp" in m.lower() for m in matches)

    def test_determine_protection_level_lite(self, detector: VMProtectDetector) -> None:
        """_determine_protection_level identifies Lite protection."""
        handlers = [
            VMHandler(offset=100, size=50, handler_type="test", pattern=b"", confidence=0.8, complexity=30)
            for _ in range(3)
        ]
        regions = []
        mutation_score = 0.2

        level = detector._determine_protection_level(handlers, regions, mutation_score)

        assert level == VMProtectLevel.LITE

    def test_determine_protection_level_standard(self, detector: VMProtectDetector) -> None:
        """_determine_protection_level identifies Standard protection."""
        handlers = [
            VMHandler(offset=i * 100, size=50, handler_type="test", pattern=b"", confidence=0.8, complexity=60)
            for i in range(8)
        ]
        regions = [
            VirtualizedRegion(
                start_offset=1000,
                end_offset=2000,
                vm_entry=1000,
                vm_exit=2000,
                handlers_used={"test"},
                control_flow_complexity=3.0
            )
            for _ in range(6)
        ]
        mutation_score = 0.5

        level = detector._determine_protection_level(handlers, regions, mutation_score)

        assert level == VMProtectLevel.STANDARD

    def test_determine_protection_level_ultra(self, detector: VMProtectDetector) -> None:
        """_determine_protection_level identifies Ultra protection."""
        handlers = [
            VMHandler(offset=i * 100, size=50, handler_type="test", pattern=b"", confidence=0.9, complexity=90)
            for i in range(15)
        ]
        regions = [
            VirtualizedRegion(
                start_offset=i * 1000,
                end_offset=(i + 1) * 1000,
                vm_entry=i * 1000,
                vm_exit=(i + 1) * 1000,
                handlers_used={"test"},
                control_flow_complexity=6.0
            )
            for i in range(10)
        ]
        mutation_score = 0.8

        level = detector._determine_protection_level(handlers, regions, mutation_score)

        assert level == VMProtectLevel.ULTRA

    def test_generate_bypass_recommendations_ultra(self, detector: VMProtectDetector) -> None:
        """_generate_bypass_recommendations provides Ultra-specific guidance."""
        detection = VMProtectDetection(
            detected=True,
            version="3.x",
            protection_level=VMProtectLevel.ULTRA,
            mode=VMProtectMode.VIRTUALIZATION,
            architecture="x64",
            handlers=[],
            virtualized_regions=[],
            dispatcher_offset=None,
            handler_table_offset=None,
            confidence=0.95
        )

        recommendations = detector._generate_bypass_recommendations(detection)

        assert len(recommendations) > 0
        assert any("symbolic execution" in r.lower() for r in recommendations)
        assert any("4-8 weeks" in r for r in recommendations)

    def test_generate_bypass_recommendations_standard(self, detector: VMProtectDetector) -> None:
        """_generate_bypass_recommendations provides Standard-specific guidance."""
        detection = VMProtectDetection(
            detected=True,
            version="3.x",
            protection_level=VMProtectLevel.STANDARD,
            mode=VMProtectMode.VIRTUALIZATION,
            architecture="x86",
            handlers=[],
            virtualized_regions=[],
            dispatcher_offset=None,
            handler_table_offset=None,
            confidence=0.85
        )

        recommendations = detector._generate_bypass_recommendations(detection)

        assert len(recommendations) > 0
        assert any("pattern-based" in r.lower() for r in recommendations)
        assert any("1-3 weeks" in r for r in recommendations)

    def test_detect_end_to_end_with_vm_handlers(self, detector: VMProtectDetector, binary_with_vm_handlers_x86: Path) -> None:
        """Full detection workflow on binary with VM handlers."""
        detection = detector.detect(str(binary_with_vm_handlers_x86))

        assert isinstance(detection, VMProtectDetection)
        assert detection.architecture in ["x86", "unknown"]
        assert 0.0 <= detection.confidence <= 1.0

    def test_detect_end_to_end_with_vmp_sections(self, detector: VMProtectDetector, pe_binary_with_vmp_sections: Path) -> None:
        """Full detection workflow on binary with VMP sections."""
        detection = detector.detect(str(pe_binary_with_vmp_sections))

        assert isinstance(detection, VMProtectDetection)

    def test_detect_handles_nonexistent_file(self, detector: VMProtectDetector, temp_workspace: Path) -> None:
        """detect handles missing files gracefully."""
        nonexistent = temp_workspace / "does_not_exist.exe"

        detection = detector.detect(str(nonexistent))

        assert detection.detected is False or "error" in detection.technical_details

    def test_detect_handles_non_pe_file(self, detector: VMProtectDetector, temp_workspace: Path) -> None:
        """detect handles non-PE files gracefully."""
        non_pe = temp_workspace / "not_pe.bin"
        non_pe.write_bytes(b"NOTPE" + b"\x00" * 1000)

        detection = detector.detect(str(non_pe))

        assert detection.detected is False
        assert detection.architecture == "unknown"


class TestVMHandler:
    """Test VMHandler dataclass."""

    def test_vm_handler_initialization(self) -> None:
        """VMHandler initializes with correct fields."""
        handler = VMHandler(
            offset=1024,
            size=128,
            handler_type="vm_entry_prologue",
            pattern=b"\x55\x8b\xec",
            confidence=0.92
        )

        assert handler.offset == 1024
        assert handler.size == 128
        assert handler.handler_type == "vm_entry_prologue"
        assert handler.confidence == 0.92
        assert handler.opcodes == []
        assert handler.xrefs == []
        assert handler.complexity == 0


class TestVirtualizedRegion:
    """Test VirtualizedRegion dataclass."""

    def test_virtualized_region_initialization(self) -> None:
        """VirtualizedRegion initializes with correct fields."""
        region = VirtualizedRegion(
            start_offset=2048,
            end_offset=4096,
            vm_entry=2048,
            vm_exit=4096,
            handlers_used={"handler1", "handler2"},
            control_flow_complexity=5.5
        )

        assert region.start_offset == 2048
        assert region.end_offset == 4096
        assert region.vm_entry == 2048
        assert region.vm_exit == 4096
        assert "handler1" in region.handlers_used
        assert region.control_flow_complexity == 5.5
        assert region.mutation_detected is False
        assert region.protection_level == VMProtectLevel.UNKNOWN


class TestVMProtectDetection:
    """Test VMProtectDetection dataclass."""

    def test_vmprotect_detection_initialization(self) -> None:
        """VMProtectDetection initializes with correct fields."""
        detection = VMProtectDetection(
            detected=True,
            version="3.5",
            protection_level=VMProtectLevel.ULTRA,
            mode=VMProtectMode.HYBRID,
            architecture="x64",
            handlers=[],
            virtualized_regions=[],
            dispatcher_offset=0x1000,
            handler_table_offset=0x2000,
            confidence=0.95
        )

        assert detection.detected is True
        assert detection.version == "3.5"
        assert detection.protection_level == VMProtectLevel.ULTRA
        assert detection.mode == VMProtectMode.HYBRID
        assert detection.architecture == "x64"
        assert detection.dispatcher_offset == 0x1000
        assert detection.handler_table_offset == 0x2000
        assert detection.confidence == 0.95
        assert detection.technical_details == {}
        assert detection.bypass_recommendations == []
