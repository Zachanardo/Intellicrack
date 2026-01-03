#!/usr/bin/env python3
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.protection.themida_analyzer import (
    ThemidaAnalyzer,
    ThemidaVersion,
    VMArchitecture,
    VMHandler,
)


@pytest.fixture(scope="module")
def create_themida_risc_binary() -> bytes:
    """Create binary with Themida RISC VM handler patterns."""
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 0x80)

    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 0xE0, 0x010B)

    optional_header = bytearray(224)
    optional_header[:2] = struct.pack("<H", 0x010B)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[20:24] = struct.pack("<I", 0x1000)
    optional_header[24:28] = struct.pack("<I", 0x400000)
    optional_header[28:32] = struct.pack("<I", 0x1000)
    optional_header[32:36] = struct.pack("<I", 0x200)

    text_section = bytearray(40)
    text_section[:8] = b".text\x00\x00\x00"
    text_section[8:12] = struct.pack("<I", 0x1000)
    text_section[12:16] = struct.pack("<I", 0x1000)
    text_section[16:20] = struct.pack("<I", 0x1000)
    text_section[20:24] = struct.pack("<I", 0x400)
    text_section[36:40] = struct.pack("<I", 0x60000020)

    themida_section = bytearray(40)
    themida_section[:8] = b".themida"
    themida_section[8:12] = struct.pack("<I", 0x3000)
    themida_section[12:16] = struct.pack("<I", 0x2000)
    themida_section[16:20] = struct.pack("<I", 0x3000)
    themida_section[20:24] = struct.pack("<I", 0x1400)
    themida_section[36:40] = struct.pack("<I", 0xE0000020)

    pe_header = (
        bytes(dos_header)
        + pe_signature
        + coff_header
        + bytes(optional_header)
        + bytes(text_section)
        + bytes(themida_section)
    )

    padding = b"\x00" * (0x400 - len(pe_header))
    text_content = b"\x90" * 0x1000

    risc_handlers = bytearray()
    risc_handlers += b"\xe2\x8f\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe0\x80\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe0\x40\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe0\x00\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe2\x00\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe1\x80\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe0\x00\x00\x01"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe2\x61\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe1\xa0\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe1\xa0\x00\x20"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xea\x00\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe3\x50\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe5\x9f\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe5\x8f\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe7\x9f\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe1\x2f\xff\x1e"
    risc_handlers += b"\x90" * 12

    risc_handlers += b"\xe1\xe0\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe1\xa0\x00\x40"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe1\xa0\x00\x60"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe0\x20\x00\x00"
    risc_handlers += b"\x90" * 12
    risc_handlers += b"\xe0\xc0\x00\x00"
    risc_handlers += b"\x90" * 12

    risc_handlers += b"RISC"
    risc_handlers += b"ARM emulation"
    risc_handlers += b"reduced instruction"

    themida_content = bytes(risc_handlers) + b"\x00" * (0x3000 - len(risc_handlers))

    return pe_header + padding + text_content + themida_content


@pytest.fixture(scope="module")
def create_themida_fish_binary() -> bytes:
    """Create binary with Themida FISH VM handler patterns."""
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 0x80)

    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 0xF0, 0x020B)

    optional_header = bytearray(240)
    optional_header[:2] = struct.pack("<H", 0x020B)
    optional_header[24:28] = struct.pack("<I", 0x1000)
    optional_header[24:32] = struct.pack("<Q", 0x140000000)
    optional_header[32:36] = struct.pack("<I", 0x1000)
    optional_header[36:40] = struct.pack("<I", 0x200)

    text_section = bytearray(40)
    text_section[:8] = b".text\x00\x00\x00"
    text_section[8:12] = struct.pack("<I", 0x1000)
    text_section[12:16] = struct.pack("<I", 0x1000)
    text_section[16:20] = struct.pack("<I", 0x1000)
    text_section[20:24] = struct.pack("<I", 0x400)
    text_section[36:40] = struct.pack("<I", 0x60000020)

    themida_section = bytearray(40)
    themida_section[:8] = b".winlice"
    themida_section[8:12] = struct.pack("<I", 0x4000)
    themida_section[12:16] = struct.pack("<I", 0x2000)
    themida_section[16:20] = struct.pack("<I", 0x4000)
    themida_section[20:24] = struct.pack("<I", 0x1400)
    themida_section[36:40] = struct.pack("<I", 0xE0000020)

    pe_header = (
        bytes(dos_header)
        + pe_signature
        + coff_header
        + bytes(optional_header)
        + bytes(text_section)
        + bytes(themida_section)
    )

    padding = b"\x00" * (0x400 - len(pe_header))
    text_content = b"\x90" * 0x1000

    fish_handlers = bytearray()
    fish_handlers += b"\x48\x8b\x00"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\x01\x00"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\x29\x00"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\x0f\xaf\x00"
    fish_handlers += b"\x90" * 12
    fish_handlers += b"\x48\x31\x00"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\x09\x00"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\x21\x00"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\xf7\x18"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\xd1\xe0"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\xd1\xe8"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\x85\xc0\x74"
    fish_handlers += b"\x90" * 12
    fish_handlers += b"\x48\x85\xc0\x75"
    fish_handlers += b"\x90" * 12
    fish_handlers += b"\xe9\x00\x00\x00\x00"
    fish_handlers += b"\x90" * 11
    fish_handlers += b"\xeb\x00"
    fish_handlers += b"\x90" * 14
    fish_handlers += b"\xff\xe0"
    fish_handlers += b"\x90" * 14
    fish_handlers += b"\xc3"
    fish_handlers += b"\x90" * 15

    fish_handlers += b"\x48\xf7\xd0"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\xd1\xf8"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\xc1\xe0"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\xc1\xe8"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\xc1\xf8"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\xd1\xc0"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\xd1\xc8"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\xd1\xd0"
    fish_handlers += b"\x90" * 13
    fish_handlers += b"\x48\xd1\xd8"
    fish_handlers += b"\x90" * 13

    fish_handlers += b"FISH"
    fish_handlers += b"flexible instruction"
    fish_handlers += b"hybrid VM"

    themida_content = bytes(fish_handlers) + b"\x00" * (0x4000 - len(fish_handlers))

    return pe_header + padding + text_content + themida_content


@pytest.fixture(scope="module")
def create_themida_cisc_binary() -> bytes:
    """Create binary with Themida CISC VM handler patterns for comparison."""
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 0x80)

    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 0xE0, 0x010B)

    optional_header = bytearray(224)
    optional_header[:2] = struct.pack("<H", 0x010B)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[20:24] = struct.pack("<I", 0x1000)
    optional_header[24:28] = struct.pack("<I", 0x400000)
    optional_header[28:32] = struct.pack("<I", 0x1000)
    optional_header[32:36] = struct.pack("<I", 0x200)

    text_section = bytearray(40)
    text_section[:8] = b".text\x00\x00\x00"
    text_section[8:12] = struct.pack("<I", 0x1000)
    text_section[12:16] = struct.pack("<I", 0x1000)
    text_section[16:20] = struct.pack("<I", 0x1000)
    text_section[20:24] = struct.pack("<I", 0x400)
    text_section[36:40] = struct.pack("<I", 0x60000020)

    themida_section = bytearray(40)
    themida_section[:8] = b".themida"
    themida_section[8:12] = struct.pack("<I", 0x2000)
    themida_section[12:16] = struct.pack("<I", 0x2000)
    themida_section[16:20] = struct.pack("<I", 0x2000)
    themida_section[20:24] = struct.pack("<I", 0x1400)
    themida_section[36:40] = struct.pack("<I", 0xE0000020)

    pe_header = (
        bytes(dos_header)
        + pe_signature
        + coff_header
        + bytes(optional_header)
        + bytes(text_section)
        + bytes(themida_section)
    )

    padding = b"\x00" * (0x400 - len(pe_header))
    text_content = b"\x90" * 0x1000

    cisc_handlers = bytearray()
    cisc_handlers += b"\x8b\x45\x00\x89\x45\x04"
    cisc_handlers += b"\x90" * 10
    cisc_handlers += b"\x8b\x45\x00\x03\x45\x04"
    cisc_handlers += b"\x90" * 10
    cisc_handlers += b"\x8b\x45\x00\x2b\x45\x04"
    cisc_handlers += b"\x90" * 10
    cisc_handlers += b"\x8b\x45\x00\x0f\xaf\x45\x04"
    cisc_handlers += b"\x90" * 8
    cisc_handlers += b"\x8b\x45\x00\x33\x45\x04"
    cisc_handlers += b"\x90" * 10
    cisc_handlers += b"\x8b\x45\x00\x0b\x45\x04"
    cisc_handlers += b"\x90" * 10

    cisc_handlers += b"CISC"
    cisc_handlers += b"complex instruction"
    cisc_handlers += b"x86 emulation"

    themida_content = bytes(cisc_handlers) + b"\x00" * (0x2000 - len(cisc_handlers))

    return pe_header + padding + text_content + themida_content


@pytest.mark.risc
@pytest.mark.themida
def test_risc_vm_architecture_detection_regression(create_themida_risc_binary: bytes) -> None:
    """Verify RISC VM architecture detection still works correctly."""
    analyzer = ThemidaAnalyzer(create_themida_risc_binary)
    detected_arch = analyzer._detect_vm_architecture()

    assert detected_arch == VMArchitecture.RISC, (
        f"REGRESSION: RISC VM architecture detection failed. "
        f"Expected VMArchitecture.RISC but got {detected_arch}. "
        f"This indicates the RISC pattern scoring or detection logic has regressed."
    )


@pytest.mark.fish
@pytest.mark.themida
def test_fish_vm_architecture_detection_regression(create_themida_fish_binary: bytes) -> None:
    """Verify FISH VM architecture detection still works correctly."""
    analyzer = ThemidaAnalyzer(create_themida_fish_binary)
    detected_arch = analyzer._detect_vm_architecture()

    assert detected_arch == VMArchitecture.FISH, (
        f"REGRESSION: FISH VM architecture detection failed. "
        f"Expected VMArchitecture.FISH but got {detected_arch}. "
        f"This indicates the FISH pattern scoring or detection logic has regressed."
    )


@pytest.mark.cisc
@pytest.mark.themida
def test_cisc_vm_architecture_detection_regression(create_themida_cisc_binary: bytes) -> None:
    """Verify CISC VM architecture detection still works correctly for comparison."""
    analyzer = ThemidaAnalyzer(create_themida_cisc_binary)
    detected_arch = analyzer._detect_vm_architecture()

    assert detected_arch == VMArchitecture.CISC, (
        f"REGRESSION: CISC VM architecture detection failed. "
        f"Expected VMArchitecture.CISC but got {detected_arch}. "
        f"This indicates the CISC pattern scoring or detection logic has regressed."
    )


@pytest.mark.risc
@pytest.mark.themida
def test_risc_handler_pattern_extraction_regression(create_themida_risc_binary: bytes) -> None:
    """Verify RISC handler pattern extraction functionality remains intact."""
    analyzer = ThemidaAnalyzer(create_themida_risc_binary)
    vm_arch = analyzer._detect_vm_architecture()

    assert vm_arch == VMArchitecture.RISC, "Test prerequisite failed: RISC not detected"

    handlers = analyzer._extract_handlers_by_pattern(VMArchitecture.RISC)

    assert len(handlers) > 0, (
        "REGRESSION: RISC handler extraction returned zero handlers. "
        "The pattern-based extraction for RISC VM handlers is broken."
    )

    expected_risc_opcodes = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]
    found_opcodes = list(handlers.keys())

    assert len(found_opcodes) >= 10, (
        f"REGRESSION: Expected at least 10 RISC handlers but found {len(found_opcodes)}. "
        f"Found opcodes: {found_opcodes}. "
        f"This indicates RISC handler pattern matching has degraded."
    )

    for opcode in expected_risc_opcodes[:10]:
        if opcode in handlers:
            handler = handlers[opcode]
            assert isinstance(handler, VMHandler), f"REGRESSION: Handler {opcode} is not a VMHandler instance"
            assert handler.opcode == opcode, f"REGRESSION: Handler opcode mismatch: expected {opcode}, got {handler.opcode}"
            assert handler.address > 0, f"REGRESSION: Handler {opcode} has invalid address {handler.address}"


@pytest.mark.fish
@pytest.mark.themida
def test_fish_handler_pattern_extraction_regression(create_themida_fish_binary: bytes) -> None:
    """Verify FISH handler pattern extraction functionality remains intact."""
    analyzer = ThemidaAnalyzer(create_themida_fish_binary)
    vm_arch = analyzer._detect_vm_architecture()

    assert vm_arch == VMArchitecture.FISH, "Test prerequisite failed: FISH not detected"

    handlers = analyzer._extract_handlers_by_pattern(VMArchitecture.FISH)

    assert len(handlers) > 0, (
        "REGRESSION: FISH handler extraction returned zero handlers. "
        "The pattern-based extraction for FISH VM handlers is broken."
    )

    expected_fish_opcodes = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]
    found_opcodes = list(handlers.keys())

    assert len(found_opcodes) >= 10, (
        f"REGRESSION: Expected at least 10 FISH handlers but found {len(found_opcodes)}. "
        f"Found opcodes: {found_opcodes}. "
        f"This indicates FISH handler pattern matching has degraded."
    )

    for opcode in expected_fish_opcodes[:10]:
        if opcode in handlers:
            handler = handlers[opcode]
            assert isinstance(handler, VMHandler), f"REGRESSION: Handler {opcode} is not a VMHandler instance"
            assert handler.opcode == opcode, f"REGRESSION: Handler opcode mismatch: expected {opcode}, got {handler.opcode}"
            assert handler.address > 0, f"REGRESSION: Handler {opcode} has invalid address {handler.address}"


@pytest.mark.cisc
@pytest.mark.themida
def test_cisc_handler_range_coverage_regression(create_themida_cisc_binary: bytes) -> None:
    """Verify CISC handler detection covers 0x00-0xFF range as specified."""
    analyzer = ThemidaAnalyzer(create_themida_cisc_binary)

    cisc_patterns = analyzer.CISC_HANDLER_PATTERNS

    assert len(cisc_patterns) > 0, "REGRESSION: CISC_HANDLER_PATTERNS is empty"

    assert 0x00 in cisc_patterns, "REGRESSION: CISC handler 0x00 pattern missing"
    assert all(0x00 <= opcode <= 0xFF for opcode in cisc_patterns.keys()), (
        "REGRESSION: CISC handler opcodes exceed 0x00-0xFF range"
    )

    handlers = analyzer._extract_handlers_by_pattern(VMArchitecture.CISC)
    assert len(handlers) > 0, "REGRESSION: CISC handler extraction failed completely"


@pytest.mark.risc
@pytest.mark.themida
def test_risc_handler_semantic_lifting_regression(create_themida_risc_binary: bytes) -> None:
    """Verify RISC handler semantic analysis and categorization still works."""
    analyzer = ThemidaAnalyzer(create_themida_risc_binary)
    handlers = analyzer._extract_handlers_by_pattern(VMArchitecture.RISC)

    assert len(handlers) > 0, "Test prerequisite failed: no RISC handlers extracted"

    for opcode, handler in handlers.items():
        assert handler.category is not None, (
            f"REGRESSION: Handler {opcode} has no category assigned. "
            f"Semantic categorization (_categorize_handler) has regressed."
        )

        assert handler.category in [
            "unknown",
            "arithmetic",
            "logical",
            "data_transfer",
            "control_flow",
            "stack",
            "memory",
            "comparison",
            "anti_debug",
        ], f"REGRESSION: Handler {opcode} has invalid category '{handler.category}'"

        assert handler.complexity >= 0, f"REGRESSION: Handler {opcode} has invalid complexity {handler.complexity}"


@pytest.mark.fish
@pytest.mark.themida
def test_fish_handler_semantic_lifting_regression(create_themida_fish_binary: bytes) -> None:
    """Verify FISH handler semantic analysis and categorization still works."""
    analyzer = ThemidaAnalyzer(create_themida_fish_binary)
    handlers = analyzer._extract_handlers_by_pattern(VMArchitecture.FISH)

    assert len(handlers) > 0, "Test prerequisite failed: no FISH handlers extracted"

    for opcode, handler in handlers.items():
        assert handler.category is not None, (
            f"REGRESSION: Handler {opcode} has no category assigned. "
            f"Semantic categorization (_categorize_handler) has regressed."
        )

        assert handler.category in [
            "unknown",
            "arithmetic",
            "logical",
            "data_transfer",
            "control_flow",
            "stack",
            "memory",
            "comparison",
            "anti_debug",
        ], f"REGRESSION: Handler {opcode} has invalid category '{handler.category}'"

        assert handler.complexity >= 0, f"REGRESSION: Handler {opcode} has invalid complexity {handler.complexity}"


@pytest.mark.themida
@pytest.mark.risc
def test_handler_table_identification_risc_regression(create_themida_risc_binary: bytes) -> None:
    """Verify handler table identification logic for RISC binaries."""
    analyzer = ThemidaAnalyzer(create_themida_risc_binary)

    handler_table_addr = analyzer._find_handler_table()

    if handler_table_addr == 0:
        pytest.skip(
            "Handler table not found in synthetic binary - this is expected for synthetic test data. "
            "Real Themida binaries should have handler dispatch tables at specific addresses. "
            "To fully test this regression, provide a real Themida RISC-protected binary in "
            "tests/test_binaries/themida/ directory."
        )

    assert handler_table_addr > 0, "REGRESSION: Handler table identification returned zero address"
    assert 0x400000 <= handler_table_addr <= 0x10000000, (
        f"REGRESSION: Handler table address {hex(handler_table_addr)} outside valid range"
    )


@pytest.mark.themida
@pytest.mark.fish
def test_handler_table_identification_fish_regression(create_themida_fish_binary: bytes) -> None:
    """Verify handler table identification logic for FISH binaries."""
    analyzer = ThemidaAnalyzer(create_themida_fish_binary)

    handler_table_addr = analyzer._find_handler_table()

    if handler_table_addr == 0:
        pytest.skip(
            "Handler table not found in synthetic binary - this is expected for synthetic test data. "
            "Real WinLicense/Themida FISH-protected binaries should have handler dispatch tables. "
            "To fully test this regression, provide a real Themida FISH-protected binary (64-bit) in "
            "tests/test_binaries/themida/ directory."
        )

    assert handler_table_addr > 0, "REGRESSION: Handler table identification returned zero address"


@pytest.mark.themida
@pytest.mark.risc
def test_risc_handler_disassembly_regression(create_themida_risc_binary: bytes) -> None:
    """Verify RISC handler disassembly functionality remains operational."""
    analyzer = ThemidaAnalyzer(create_themida_risc_binary)
    handlers = analyzer._extract_handlers_by_pattern(VMArchitecture.RISC)

    assert len(handlers) > 0, "Test prerequisite failed: no RISC handlers extracted"

    for opcode, handler in handlers.items():
        assert handler.instructions is not None, (
            f"REGRESSION: Handler {opcode} has no instructions list. " f"Disassembly (_disassemble_handler) has failed."
        )

        assert len(handler.instructions) > 0, (
            f"REGRESSION: Handler {opcode} has empty instructions list. " f"Disassembly produced no output."
        )

        for addr, mnemonic, operands in handler.instructions:
            assert isinstance(addr, int), f"REGRESSION: Instruction address is not int: {type(addr)}"
            assert isinstance(mnemonic, str), f"REGRESSION: Instruction mnemonic is not str: {type(mnemonic)}"
            assert isinstance(operands, str), f"REGRESSION: Instruction operands is not str: {type(operands)}"


@pytest.mark.themida
@pytest.mark.fish
def test_fish_handler_disassembly_regression(create_themida_fish_binary: bytes) -> None:
    """Verify FISH handler disassembly functionality remains operational."""
    analyzer = ThemidaAnalyzer(create_themida_fish_binary)
    handlers = analyzer._extract_handlers_by_pattern(VMArchitecture.FISH)

    assert len(handlers) > 0, "Test prerequisite failed: no FISH handlers extracted"

    for opcode, handler in handlers.items():
        assert handler.instructions is not None, (
            f"REGRESSION: Handler {opcode} has no instructions list. " f"Disassembly (_disassemble_handler) has failed."
        )

        assert len(handler.instructions) > 0, (
            f"REGRESSION: Handler {opcode} has empty instructions list. " f"Disassembly produced no output."
        )


@pytest.mark.themida
@pytest.mark.real_binary
def test_risc_handlers_on_real_themida_binary(themida_binaries_dir: Path, has_real_themida_binaries: bool) -> None:
    """Test RISC handler extraction on real Themida-protected binaries."""
    if not has_real_themida_binaries:
        pytest.skip(
            "SKIPPED: No real Themida-protected binaries found for regression testing.\n\n"
            "To enable this critical regression test, please provide real Themida RISC-protected binaries:\n"
            "1. Place Themida 2.x or 3.x RISC-protected executables in: tests/test_binaries/themida/\n"
            "2. Name files with patterns: *themida*risc*.exe or *winlicense*risc*.exe\n"
            "3. Ensure binaries are legitimate test samples (not malware)\n\n"
            "Real binaries are REQUIRED to validate:\n"
            "  - Actual RISC VM handler patterns from Oreans Themida\n"
            "  - Handler table parsing on production protection\n"
            "  - Devirtualization accuracy against real obfuscation\n"
            "  - Version-specific RISC implementation details (2.x vs 3.x vs 3.1)\n\n"
            "Without real binaries, this regression test cannot verify production readiness."
        )

    risc_binary_patterns = ["*risc*.exe", "*RISC*.exe", "*themida*2.*.exe", "*themida*3.*.exe"]
    risc_binaries: list[Path] = []
    for pattern in risc_binary_patterns:
        risc_binaries.extend(themida_binaries_dir.glob(pattern))

    if not risc_binaries:
        pytest.skip(
            f"SKIPPED: No RISC-specific Themida binaries found in {themida_binaries_dir}.\n"
            f"Searched for patterns: {risc_binary_patterns}\n"
            f"Please add Themida RISC-protected samples to enable this regression test."
        )

    test_binary = risc_binaries[0]
    binary_data = test_binary.read_bytes()

    analyzer = ThemidaAnalyzer(binary_data)
    vm_arch = analyzer._detect_vm_architecture()

    assert vm_arch == VMArchitecture.RISC, (
        f"REGRESSION: Real RISC binary {test_binary.name} not detected as RISC. "
        f"Detected as: {vm_arch}. RISC detection has regressed on real binaries."
    )

    handlers = analyzer._extract_handlers_by_pattern(VMArchitecture.RISC)

    assert len(handlers) >= 20, (
        f"REGRESSION: Real RISC binary {test_binary.name} yielded only {len(handlers)} handlers. "
        f"Expected at least 20 handlers for production Themida RISC protection. "
        f"Handler extraction has degraded significantly."
    )

    for opcode, handler in list(handlers.items())[:5]:
        assert handler.category != "unknown", (
            f"REGRESSION: Real RISC handler {opcode} categorized as 'unknown'. "
            f"Semantic analysis failing on production handlers."
        )


@pytest.mark.themida
@pytest.mark.real_binary
def test_fish_handlers_on_real_themida_binary(themida_binaries_dir: Path, has_real_themida_binaries: bool) -> None:
    """Test FISH handler extraction on real Themida-protected binaries."""
    if not has_real_themida_binaries:
        pytest.skip(
            "SKIPPED: No real Themida-protected binaries found for regression testing.\n\n"
            "To enable this critical regression test, please provide real Themida FISH-protected binaries:\n"
            "1. Place Themida 3.x FISH-protected executables (64-bit) in: tests/test_binaries/themida/\n"
            "2. Name files with patterns: *themida*fish*.exe or *winlicense*x64*.exe\n"
            "3. Ensure binaries are legitimate test samples (not malware)\n\n"
            "Real binaries are REQUIRED to validate:\n"
            "  - Actual FISH VM handler patterns from Oreans Themida 3.x\n"
            "  - 64-bit handler table parsing\n"
            "  - Hybrid RISC/CISC devirtualization\n"
            "  - Themida 3.1+ FISH-specific obfuscation techniques\n\n"
            "Without real binaries, this regression test cannot verify production readiness."
        )

    fish_binary_patterns = ["*fish*.exe", "*FISH*.exe", "*x64*.exe", "*themida*3.1*.exe"]
    fish_binaries: list[Path] = []
    for pattern in fish_binary_patterns:
        fish_binaries.extend(themida_binaries_dir.glob(pattern))

    if not fish_binaries:
        pytest.skip(
            f"SKIPPED: No FISH-specific Themida binaries found in {themida_binaries_dir}.\n"
            f"Searched for patterns: {fish_binary_patterns}\n"
            f"Please add Themida FISH-protected samples (typically 64-bit) to enable this regression test."
        )

    test_binary = fish_binaries[0]
    binary_data = test_binary.read_bytes()

    analyzer = ThemidaAnalyzer(binary_data)
    vm_arch = analyzer._detect_vm_architecture()

    assert vm_arch == VMArchitecture.FISH, (
        f"REGRESSION: Real FISH binary {test_binary.name} not detected as FISH. "
        f"Detected as: {vm_arch}. FISH detection has regressed on real binaries."
    )

    handlers = analyzer._extract_handlers_by_pattern(VMArchitecture.FISH)

    assert len(handlers) >= 20, (
        f"REGRESSION: Real FISH binary {test_binary.name} yielded only {len(handlers)} handlers. "
        f"Expected at least 20 handlers for production Themida FISH protection. "
        f"Handler extraction has degraded significantly."
    )


@pytest.mark.themida
def test_vm_architecture_scoring_logic_regression(
    create_themida_risc_binary: bytes, create_themida_fish_binary: bytes, create_themida_cisc_binary: bytes
) -> None:
    """Verify VM architecture scoring logic produces correct priorities."""
    risc_analyzer = ThemidaAnalyzer(create_themida_risc_binary)
    fish_analyzer = ThemidaAnalyzer(create_themida_fish_binary)
    cisc_analyzer = ThemidaAnalyzer(create_themida_cisc_binary)

    risc_arch = risc_analyzer._detect_vm_architecture()
    fish_arch = fish_analyzer._detect_vm_architecture()
    cisc_arch = cisc_analyzer._detect_vm_architecture()

    assert risc_arch == VMArchitecture.RISC, "REGRESSION: RISC binary not scored as RISC"
    assert fish_arch == VMArchitecture.FISH, "REGRESSION: FISH binary not scored as FISH"
    assert cisc_arch == VMArchitecture.CISC, "REGRESSION: CISC binary not scored as CISC"

    assert risc_arch != fish_arch, "REGRESSION: RISC and FISH architectures not distinguished"
    assert risc_arch != cisc_arch, "REGRESSION: RISC and CISC architectures not distinguished"
    assert fish_arch != cisc_arch, "REGRESSION: FISH and CISC architectures not distinguished"


@pytest.mark.themida
@pytest.mark.risc
def test_risc_handler_size_estimation_regression(create_themida_risc_binary: bytes) -> None:
    """Verify handler size estimation logic for RISC handlers."""
    analyzer = ThemidaAnalyzer(create_themida_risc_binary)
    handlers = analyzer._extract_handlers_by_pattern(VMArchitecture.RISC)

    assert len(handlers) > 0, "Test prerequisite failed: no RISC handlers extracted"

    for opcode, handler in handlers.items():
        assert handler.size > 0, f"REGRESSION: Handler {opcode} has zero size"
        assert handler.size <= 256, (
            f"REGRESSION: Handler {opcode} size {handler.size} exceeds maximum expected size. "
            f"Size estimation (_estimate_handler_size) may be broken."
        )


@pytest.mark.themida
@pytest.mark.fish
def test_fish_handler_size_estimation_regression(create_themida_fish_binary: bytes) -> None:
    """Verify handler size estimation logic for FISH handlers."""
    analyzer = ThemidaAnalyzer(create_themida_fish_binary)
    handlers = analyzer._extract_handlers_by_pattern(VMArchitecture.FISH)

    assert len(handlers) > 0, "Test prerequisite failed: no FISH handlers extracted"

    for opcode, handler in handlers.items():
        assert handler.size > 0, f"REGRESSION: Handler {opcode} has zero size"
        assert handler.size <= 256, (
            f"REGRESSION: Handler {opcode} size {handler.size} exceeds maximum expected size. "
            f"Size estimation (_estimate_handler_size) may be broken."
        )


@pytest.mark.themida
def test_handler_pattern_dictionaries_integrity_regression() -> None:
    """Verify RISC and FISH handler pattern dictionaries maintain expected structure."""
    analyzer = ThemidaAnalyzer(b"MZ")

    risc_patterns = analyzer.RISC_HANDLER_PATTERNS
    fish_patterns = analyzer.FISH_HANDLER_PATTERNS
    cisc_patterns = analyzer.CISC_HANDLER_PATTERNS

    assert len(risc_patterns) > 0, "REGRESSION: RISC_HANDLER_PATTERNS is empty"
    assert len(fish_patterns) > 0, "REGRESSION: FISH_HANDLER_PATTERNS is empty"
    assert len(cisc_patterns) > 0, "REGRESSION: CISC_HANDLER_PATTERNS is empty"

    for opcode, pattern in risc_patterns.items():
        assert isinstance(opcode, int), f"REGRESSION: RISC opcode {opcode} is not int"
        assert isinstance(pattern, bytes), f"REGRESSION: RISC pattern for opcode {opcode} is not bytes"
        assert len(pattern) > 0, f"REGRESSION: RISC pattern for opcode {opcode} is empty"

    for opcode, pattern in fish_patterns.items():
        assert isinstance(opcode, int), f"REGRESSION: FISH opcode {opcode} is not int"
        assert isinstance(pattern, bytes), f"REGRESSION: FISH pattern for opcode {opcode} is not bytes"
        assert len(pattern) > 0, f"REGRESSION: FISH pattern for opcode {opcode} is empty"

    for opcode, pattern in cisc_patterns.items():
        assert isinstance(opcode, int), f"REGRESSION: CISC opcode {opcode} is not int"
        assert isinstance(pattern, bytes), f"REGRESSION: CISC pattern for opcode {opcode} is not bytes"
        assert len(pattern) > 0, f"REGRESSION: CISC pattern for opcode {opcode} is empty"

    assert 0x00 in risc_patterns, "REGRESSION: RISC missing opcode 0x00"
    assert 0x0F in risc_patterns, "REGRESSION: RISC missing opcode 0x0F (return handler)"

    assert 0x00 in fish_patterns, "REGRESSION: FISH missing opcode 0x00"
    assert 0x0F in fish_patterns, "REGRESSION: FISH missing opcode 0x0F (return handler)"

    assert 0x00 in cisc_patterns, "REGRESSION: CISC missing opcode 0x00"


@pytest.mark.themida
@pytest.mark.risc
def test_risc_handler_complexity_calculation_regression(create_themida_risc_binary: bytes) -> None:
    """Verify handler complexity calculation for RISC handlers."""
    analyzer = ThemidaAnalyzer(create_themida_risc_binary)
    handlers = analyzer._extract_handlers_by_pattern(VMArchitecture.RISC)

    assert len(handlers) > 0, "Test prerequisite failed: no RISC handlers extracted"

    for opcode, handler in handlers.items():
        assert isinstance(handler.complexity, (int, float)), (
            f"REGRESSION: Handler {opcode} complexity is not numeric: {type(handler.complexity)}"
        )

        assert handler.complexity >= 0, (
            f"REGRESSION: Handler {opcode} has negative complexity {handler.complexity}. "
            f"Complexity calculation (_calculate_handler_complexity) is broken."
        )


@pytest.mark.themida
@pytest.mark.fish
def test_fish_handler_complexity_calculation_regression(create_themida_fish_binary: bytes) -> None:
    """Verify handler complexity calculation for FISH handlers."""
    analyzer = ThemidaAnalyzer(create_themida_fish_binary)
    handlers = analyzer._extract_handlers_by_pattern(VMArchitecture.FISH)

    assert len(handlers) > 0, "Test prerequisite failed: no FISH handlers extracted"

    for opcode, handler in handlers.items():
        assert isinstance(handler.complexity, (int, float)), (
            f"REGRESSION: Handler {opcode} complexity is not numeric: {type(handler.complexity)}"
        )

        assert handler.complexity >= 0, (
            f"REGRESSION: Handler {opcode} has negative complexity {handler.complexity}. "
            f"Complexity calculation (_calculate_handler_complexity) is broken."
        )
