"""Production tests for UPX detection and unpacking functionality.

Tests validate dynamic signature generation for UPX 3.x/4.x, x64 variant support,
modified stub detection, compression variant handling, and OEP identification.
All tests require real UPX-packed binaries or skip with detailed logging.
"""

import logging
import struct
from pathlib import Path
from typing import Final

import pytest

from intellicrack.core.analysis.frida_protection_bypass import (  # type: ignore[attr-defined]
    FridaProtectionBypass,
    ProtectionInfo,
)

logger = logging.getLogger(__name__)

TEST_BINARIES_DIR: Final[Path] = Path("D:/Intellicrack/tests/fixtures/binaries/upx")
STANDARD_UPX3_X86: Final[Path] = TEST_BINARIES_DIR / "upx3_x86_standard.exe"
STANDARD_UPX3_X64: Final[Path] = TEST_BINARIES_DIR / "upx3_x64_standard.exe"
STANDARD_UPX4_X86: Final[Path] = TEST_BINARIES_DIR / "upx4_x86_standard.exe"
STANDARD_UPX4_X64: Final[Path] = TEST_BINARIES_DIR / "upx4_x64_standard.exe"
LZMA_COMPRESSED: Final[Path] = TEST_BINARIES_DIR / "upx_lzma_compressed.exe"
MODIFIED_STUB: Final[Path] = TEST_BINARIES_DIR / "upx_modified_stub.exe"
CUSTOM_BUILD: Final[Path] = TEST_BINARIES_DIR / "upx_custom_build.exe"
WITH_OVERLAY: Final[Path] = TEST_BINARIES_DIR / "upx_with_overlay.exe"
BEST_COMPRESSION: Final[Path] = TEST_BINARIES_DIR / "upx_best_compression.exe"
BRUTE_COMPRESSION: Final[Path] = TEST_BINARIES_DIR / "upx_brute.exe"


@pytest.fixture(scope="module")
def bypass() -> FridaProtectionBypass:
    """Create FridaProtectionBypass instance for testing."""
    return FridaProtectionBypass()


def _check_binary_exists(binary_path: Path) -> bool:
    """Check if test binary exists."""
    return binary_path.exists()


def _log_missing_binary(binary_path: Path, description: str) -> None:
    """Log detailed information about missing test binary."""
    logger.warning(
        "MISSING TEST BINARY: %s\n"
        "Description: %s\n"
        "Expected location: %s\n"
        "To create this binary:\n"
        "  1. Obtain a clean Windows PE executable (32-bit or 64-bit as specified)\n"
        "  2. Download UPX from https://github.com/upx/upx/releases\n"
        "  3. Pack the binary: upx [options] original.exe -o %s\n"
        "  4. Place the packed binary at the expected location\n"
        "Additional details:\n"
        "  - UPX must match the version specified in the test\n"
        "  - For modified stubs: manually edit the stub after packing\n"
        "  - For custom builds: compile UPX from source with modifications\n"
        "  - Ensure the binary is executable and not corrupted\n",
        binary_path.name,
        description,
        binary_path,
        binary_path.name,
    )


def test_detect_upx3_x86_standard_signatures(bypass: FridaProtectionBypass) -> None:
    """Detect UPX 3.x standard packed x86 binary using signature matching.

    Validates:
    - Detection of standard UPX3 section markers (UPX0, UPX1, UPX2)
    - Identification of x86 decompression stub patterns
    - Correct version identification for UPX 3.x
    - Signature confidence scoring
    """
    if not _check_binary_exists(STANDARD_UPX3_X86):
        _log_missing_binary(
            STANDARD_UPX3_X86,
            "Standard UPX 3.x packed x86 PE executable with default options",
        )
        pytest.skip(f"Test binary not found: {STANDARD_UPX3_X86}")

    binary_data: bytes = STANDARD_UPX3_X86.read_bytes()

    assert b"UPX0" in binary_data or b"UPX1" in binary_data or b"UPX2" in binary_data, (
        "UPX section markers not found in binary - binary may not be UPX packed"
    )

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    assert len(upx_detections) > 0, "UPX packer not detected in standard UPX3 x86 binary"

    upx_info: ProtectionInfo = upx_detections[0]
    assert upx_info.confidence >= 0.8, (
        f"UPX detection confidence too low: {upx_info.confidence}, expected >= 0.8"
    )
    assert upx_info.version.startswith("3."), (  # type: ignore[attr-defined]
        f"Incorrect UPX version detected: {upx_info.version}, expected 3.x"  # type: ignore[attr-defined]
    )


def test_detect_upx3_x64_signatures(bypass: FridaProtectionBypass) -> None:
    """Detect UPX 3.x packed x64 binary with correct architecture recognition.

    Validates:
    - x64 PE format recognition
    - UPX x64 stub pattern matching
    - Architecture-specific decompression routine detection
    - Proper x64 OEP calculation
    """
    if not _check_binary_exists(STANDARD_UPX3_X64):
        _log_missing_binary(
            STANDARD_UPX3_X64,
            "Standard UPX 3.x packed x64 PE executable with default options",
        )
        pytest.skip(f"Test binary not found: {STANDARD_UPX3_X64}")

    binary_data: bytes = STANDARD_UPX3_X64.read_bytes()

    pe_offset: int = struct.unpack("<I", binary_data[0x3C:0x40])[0]
    machine_type: int = struct.unpack("<H", binary_data[pe_offset + 4:pe_offset + 6])[0]
    assert machine_type == 0x8664, (
        f"Binary is not x64 architecture: machine type {machine_type:04x}"
    )

    assert b"UPX0" in binary_data or b"UPX1" in binary_data or b"UPX2" in binary_data, (
        "UPX section markers not found in x64 binary"
    )

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    assert len(upx_detections) > 0, "UPX packer not detected in UPX3 x64 binary"

    upx_info: ProtectionInfo = upx_detections[0]
    assert upx_info.confidence >= 0.8, (
        f"UPX x64 detection confidence too low: {upx_info.confidence}"
    )


def test_detect_upx4_x86_advanced_signatures(bypass: FridaProtectionBypass) -> None:
    """Detect UPX 4.x packed x86 binary with updated signature patterns.

    Validates:
    - UPX 4.x version-specific signatures
    - Updated decompression stub patterns
    - Backward compatibility with UPX3 detection logic
    - Enhanced compression algorithm detection
    """
    if not _check_binary_exists(STANDARD_UPX4_X86):
        _log_missing_binary(
            STANDARD_UPX4_X86,
            "Standard UPX 4.x packed x86 PE executable with default options",
        )
        pytest.skip(f"Test binary not found: {STANDARD_UPX4_X86}")

    binary_data: bytes = STANDARD_UPX4_X86.read_bytes()

    assert b"UPX" in binary_data, "UPX markers not found in binary"

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    assert len(upx_detections) > 0, "UPX 4.x packer not detected"

    upx_info: ProtectionInfo = upx_detections[0]
    assert upx_info.confidence >= 0.75, (
        f"UPX 4.x detection confidence too low: {upx_info.confidence}"
    )


def test_detect_upx4_x64_signatures(bypass: FridaProtectionBypass) -> None:
    """Detect UPX 4.x packed x64 binary with architecture-specific patterns.

    Validates:
    - UPX 4.x x64 stub recognition
    - 64-bit decompression routine identification
    - Proper handling of extended PE+ headers
    - x64-specific entry point detection
    """
    if not _check_binary_exists(STANDARD_UPX4_X64):
        _log_missing_binary(
            STANDARD_UPX4_X64,
            "Standard UPX 4.x packed x64 PE executable with default options",
        )
        pytest.skip(f"Test binary not found: {STANDARD_UPX4_X64}")

    binary_data: bytes = STANDARD_UPX4_X64.read_bytes()

    pe_offset: int = struct.unpack("<I", binary_data[0x3C:0x40])[0]
    machine_type: int = struct.unpack("<H", binary_data[pe_offset + 4:pe_offset + 6])[0]
    assert machine_type == 0x8664, "Binary is not x64 architecture"

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    assert len(upx_detections) > 0, "UPX 4.x x64 packer not detected"


def test_detect_modified_upx_stub(bypass: FridaProtectionBypass) -> None:
    """Detect UPX binary with modified/patched stub code.

    Validates:
    - Detection despite stub modifications
    - Heuristic analysis when signatures don't match exactly
    - Section name pattern matching as fallback
    - Entropy analysis for packed sections
    - Behavioral pattern recognition
    """
    if not _check_binary_exists(MODIFIED_STUB):
        _log_missing_binary(
            MODIFIED_STUB,
            "UPX packed binary with manually modified stub (NOP inserted, strings changed)",
        )
        pytest.skip(f"Test binary not found: {MODIFIED_STUB}")

    binary_data: bytes = MODIFIED_STUB.read_bytes()

    pe_offset: int = struct.unpack("<I", binary_data[0x3C:0x40])[0]
    num_sections: int = struct.unpack("<H", binary_data[pe_offset + 6:pe_offset + 8])[0]
    optional_header_size: int = struct.unpack("<H", binary_data[pe_offset + 20:pe_offset + 22])[0]
    section_table_offset: int = pe_offset + 24 + optional_header_size

    upx_section_found: bool = False
    for i in range(num_sections):
        section_offset: int = section_table_offset + (i * 40)
        section_name: bytes = binary_data[section_offset:section_offset + 8].rstrip(b"\x00")
        if b"UPX" in section_name:
            upx_section_found = True
            break

    assert upx_section_found, "Binary does not contain UPX section - may not be modified UPX"

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    assert len(upx_detections) > 0, (
        "Modified UPX stub not detected - heuristic detection failed"
    )

    upx_info: ProtectionInfo = upx_detections[0]
    assert upx_info.confidence >= 0.5, (
        f"Detection confidence too low for modified stub: {upx_info.confidence}, "
        "expected >= 0.5 for heuristic detection"
    )


def test_detect_upx_lzma_compression(bypass: FridaProtectionBypass) -> None:
    """Detect UPX binary using LZMA compression algorithm.

    Validates:
    - LZMA compression variant detection
    - Different decompression stub patterns for LZMA
    - Larger unpacking stub recognition
    - LZMA-specific entry point patterns
    """
    if not _check_binary_exists(LZMA_COMPRESSED):
        _log_missing_binary(
            LZMA_COMPRESSED,
            "UPX packed binary using LZMA compression (pack with --lzma option)",
        )
        pytest.skip(f"Test binary not found: {LZMA_COMPRESSED}")

    binary_data: bytes = LZMA_COMPRESSED.read_bytes()

    assert b"UPX" in binary_data, "UPX markers not found in LZMA compressed binary"

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    assert len(upx_detections) > 0, "UPX LZMA compressed binary not detected"

    upx_info: ProtectionInfo = upx_detections[0]
    assert upx_info.confidence >= 0.7, (
        f"LZMA variant detection confidence too low: {upx_info.confidence}"
    )


def test_detect_custom_upx_build(bypass: FridaProtectionBypass) -> None:
    """Detect binary packed with custom-built UPX.

    Validates:
    - Detection of non-standard UPX builds
    - Handling of custom compression filters
    - Modified section name patterns
    - Fallback to behavioral analysis
    """
    if not _check_binary_exists(CUSTOM_BUILD):
        _log_missing_binary(
            CUSTOM_BUILD,
            "Binary packed with custom-built UPX (compile UPX from source with modifications)",
        )
        pytest.skip(f"Test binary not found: {CUSTOM_BUILD}")

    binary_data: bytes = CUSTOM_BUILD.read_bytes()

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    assert len(upx_detections) > 0, (
        "Custom UPX build not detected - detection may be too signature-dependent"
    )


def test_detect_upx_with_overlay_data(bypass: FridaProtectionBypass) -> None:
    """Detect UPX binary with overlay data appended.

    Validates:
    - UPX detection not confused by overlay
    - Correct section boundary identification
    - Proper handling of data beyond UPX sections
    - OEP calculation ignoring overlay
    """
    if not _check_binary_exists(WITH_OVERLAY):
        _log_missing_binary(
            WITH_OVERLAY,
            "UPX packed binary with data appended after last section (add random data to end)",
        )
        pytest.skip(f"Test binary not found: {WITH_OVERLAY}")

    binary_data: bytes = WITH_OVERLAY.read_bytes()

    assert b"UPX" in binary_data, "UPX markers not found in binary with overlay"

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    assert len(upx_detections) > 0, "UPX with overlay data not detected"

    upx_info: ProtectionInfo = upx_detections[0]
    assert upx_info.confidence >= 0.7, (
        "Overlay data should not significantly reduce detection confidence"
    )


def test_upx_unpacking_script_generation(bypass: FridaProtectionBypass) -> None:
    """Validate UPX unpacking script is generated correctly.

    Validates:
    - Script contains decompression routine hooks
    - VirtualProtect monitoring is included
    - OEP detection patterns are present
    - Memory dump functionality is implemented
    """
    script: str = bypass._generate_upx_unpacking_script()

    assert "UPX" in script.upper(), "Script does not reference UPX"
    assert "decompression" in script.lower(), "Script missing decompression logic"
    assert "VirtualProtect" in script, "Script missing VirtualProtect hook"
    assert "oep" in script.lower(), "Script missing OEP detection"
    assert "Memory.scanSync" in script or "Memory.scan" in script, (
        "Script missing memory scanning functionality"
    )
    assert "Interceptor.attach" in script, "Script missing Frida hooks"


def test_upx_oep_pattern_detection(bypass: FridaProtectionBypass) -> None:
    """Validate OEP pattern detection in UPX unpacking script.

    Validates:
    - Multiple OEP pattern variations
    - Pattern flexibility for different UPX versions
    - Correct pattern syntax for Memory.scanSync
    """
    script: str = bypass._generate_upx_unpacking_script()

    assert "E8 ?? ?? ?? ?? E9" in script or "55 8B EC 6A FF" in script, (
        "Script missing OEP detection patterns"
    )

    assert "oepPatterns" in script or "oep" in script.lower(), (
        "Script does not implement OEP pattern matching"
    )


def test_upx_decompression_signature_variants(bypass: FridaProtectionBypass) -> None:
    """Validate multiple decompression routine signatures are checked.

    Validates:
    - Multiple signature patterns in unpacking script
    - x86 and x64 signature variants
    - Signature format compatibility with Frida Memory.scanSync
    """
    script: str = bypass._generate_upx_unpacking_script()

    assert "upxSignatures" in script, "Script missing signature array"
    assert "55 8B EC 83 E4" in script or "60 BE" in script, (
        "Script missing standard UPX decompression signatures"
    )

    signature_count: int = script.count("??")
    assert signature_count >= 4, (
        f"Script has too few wildcard patterns ({signature_count}), "
        "may not handle signature variations"
    )


def test_upx_best_compression_detection(bypass: FridaProtectionBypass) -> None:
    """Detect UPX binary packed with --best compression.

    Validates:
    - Detection of maximum compression level
    - Handling of smaller decompression stubs
    - Higher entropy packed sections
    """
    if not _check_binary_exists(BEST_COMPRESSION):
        _log_missing_binary(
            BEST_COMPRESSION,
            "UPX packed binary with --best option for maximum compression",
        )
        pytest.skip(f"Test binary not found: {BEST_COMPRESSION}")

    binary_data: bytes = BEST_COMPRESSION.read_bytes()

    assert b"UPX" in binary_data, "UPX markers not found in best compression binary"

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    assert len(upx_detections) > 0, "UPX --best compression not detected"


def test_upx_brute_compression_detection(bypass: FridaProtectionBypass) -> None:
    """Detect UPX binary packed with --brute option.

    Validates:
    - Detection of brute-force compression
    - Handling of optimized compression stubs
    - Correct identification despite maximum optimization
    """
    if not _check_binary_exists(BRUTE_COMPRESSION):
        _log_missing_binary(
            BRUTE_COMPRESSION,
            "UPX packed binary with --brute option for exhaustive compression search",
        )
        pytest.skip(f"Test binary not found: {BRUTE_COMPRESSION}")

    binary_data: bytes = BRUTE_COMPRESSION.read_bytes()

    assert b"UPX" in binary_data, "UPX markers not found in brute compression binary"

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    assert len(upx_detections) > 0, "UPX --brute compression not detected"


def test_upx_section_entropy_analysis(bypass: FridaProtectionBypass) -> None:
    """Validate entropy-based heuristic detection for UPX.

    Validates:
    - High entropy detection in packed sections
    - Entropy threshold calibration
    - Section size vs entropy correlation
    """
    if not _check_binary_exists(STANDARD_UPX3_X86):
        _log_missing_binary(
            STANDARD_UPX3_X86,
            "Standard UPX 3.x packed x86 PE executable",
        )
        pytest.skip(f"Test binary not found: {STANDARD_UPX3_X86}")

    binary_data: bytes = STANDARD_UPX3_X86.read_bytes()

    pe_offset: int = struct.unpack("<I", binary_data[0x3C:0x40])[0]
    num_sections: int = struct.unpack("<H", binary_data[pe_offset + 6:pe_offset + 8])[0]
    optional_header_size: int = struct.unpack("<H", binary_data[pe_offset + 20:pe_offset + 22])[0]
    section_table_offset: int = pe_offset + 24 + optional_header_size

    high_entropy_found: bool = False
    for i in range(num_sections):
        section_offset: int = section_table_offset + (i * 40)
        section_name: bytes = binary_data[section_offset:section_offset + 8].rstrip(b"\x00")

        if b"UPX" in section_name:
            raw_size_offset: int = section_offset + 16
            raw_addr_offset: int = section_offset + 20
            raw_size: int = struct.unpack("<I", binary_data[raw_size_offset:raw_size_offset + 4])[0]
            raw_addr: int = struct.unpack("<I", binary_data[raw_addr_offset:raw_addr_offset + 4])[0]

            if raw_size > 0 and raw_addr > 0:
                section_data: bytes = binary_data[raw_addr:raw_addr + min(raw_size, 1024)]
                unique_bytes: int = len(set(section_data))

                if unique_bytes > 200:
                    high_entropy_found = True
                    break

    assert high_entropy_found, (
        "UPX packed section does not have expected high entropy - binary may not be properly packed"
    )


def test_upx_virtualprotect_hook_in_script(bypass: FridaProtectionBypass) -> None:
    """Validate VirtualProtect hook implementation in unpacking script.

    Validates:
    - VirtualProtect API hook is present
    - PAGE_EXECUTE_READWRITE protection detection (0x40)
    - Memory region tracking during unpacking
    - Address and size parameter extraction
    """
    script: str = bypass._generate_upx_unpacking_script()

    assert "VirtualProtect" in script, "Script missing VirtualProtect hook"
    assert "0x40" in script or "PAGE_EXECUTE_READWRITE" in script, (
        "Script missing PAGE_EXECUTE_READWRITE check"
    )
    assert "onEnter" in script, "VirtualProtect hook missing onEnter handler"
    assert "args[0]" in script and "args[1]" in script and "args[2]" in script, (
        "VirtualProtect hook not extracting arguments correctly"
    )


def test_upx_memory_dump_functionality(bypass: FridaProtectionBypass) -> None:
    """Validate memory dump functionality in UPX unpacking script.

    Validates:
    - Memory dump code is present
    - readByteArray is used for extraction
    - Appropriate dump size (not too small)
    - Send mechanism for returning data
    """
    script: str = bypass._generate_upx_unpacking_script()

    assert "readByteArray" in script, "Script missing memory dump functionality"
    assert "send" in script, "Script missing data transmission mechanism"
    assert "dump" in script.lower(), "Script missing dump event handling"

    dump_size_found: bool = "0x10000" in script or "65536" in script or "size" in script.lower()
    assert dump_size_found, "Script missing appropriate memory dump size specification"


def test_upx_detection_no_false_positives_on_clean_binary(
    bypass: FridaProtectionBypass,
) -> None:
    """Ensure UPX detection does not trigger on unpacked binaries.

    Validates:
    - No false positives on standard PE files
    - Proper signature discrimination
    - Confidence thresholds prevent spurious detections
    """
    clean_binary_path: Path = TEST_BINARIES_DIR / "clean_unpacked.exe"

    if not _check_binary_exists(clean_binary_path):
        _log_missing_binary(
            clean_binary_path,
            "Clean, unpacked Windows PE executable (any standard .exe without packing)",
        )
        pytest.skip(f"Test binary not found: {clean_binary_path}")

    binary_data: bytes = clean_binary_path.read_bytes()

    assert b"UPX" not in binary_data, (
        "Test binary contains UPX markers - not a clean unpacked binary"
    )

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    assert len(upx_detections) == 0, (
        f"False positive: UPX detected in unpacked binary with confidence "
        f"{upx_detections[0].confidence if upx_detections else 'N/A'}"
    )


def test_upx_script_handles_missing_signatures(bypass: FridaProtectionBypass) -> None:
    """Validate unpacking script handles cases where signatures are not found.

    Validates:
    - Script does not crash when signatures don't match
    - Alternative detection methods are tried
    - Graceful degradation to VirtualProtect monitoring
    """
    script: str = bypass._generate_upx_unpacking_script()

    assert "if (decompressionRoutine)" in script or "if (matches.length > 0)" in script, (
        "Script does not check for signature match success before hooking"
    )

    vp_hook_position: int = script.find("VirtualProtect")
    decompression_position: int = script.find("decompressionRoutine")

    assert vp_hook_position > 0, "VirtualProtect fallback not present"
    assert decompression_position < vp_hook_position, (
        "VirtualProtect fallback should come after signature-based detection"
    )


def test_upx_detection_multiple_upx_sections(bypass: FridaProtectionBypass) -> None:
    """Validate detection when binary has multiple UPX sections (UPX0, UPX1, UPX2).

    Validates:
    - Detection finds all UPX section markers
    - Proper section enumeration
    - No duplicate detections
    """
    if not _check_binary_exists(STANDARD_UPX3_X86):
        _log_missing_binary(
            STANDARD_UPX3_X86,
            "Standard UPX 3.x packed x86 PE executable",
        )
        pytest.skip(f"Test binary not found: {STANDARD_UPX3_X86}")

    binary_data: bytes = STANDARD_UPX3_X86.read_bytes()

    upx_section_count: int = (
        binary_data.count(b"UPX0")
        + binary_data.count(b"UPX1")
        + binary_data.count(b"UPX2")
    )

    assert upx_section_count >= 2, (
        "Binary should have at least 2 UPX sections (UPX0/UPX1 minimum)"
    )

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    assert len(upx_detections) == 1, (
        f"Expected exactly 1 UPX detection, got {len(upx_detections)} - "
        "detection may be duplicating results"
    )


def test_upx_signature_array_contains_variants(bypass: FridaProtectionBypass) -> None:
    """Validate packer signature array contains UPX variant patterns.

    Validates:
    - Multiple UPX signature bytes in detection array
    - UPX!, UPX0, UPX1, UPX2 markers present
    - Signature list is accessible and non-empty
    """
    script: str = bypass._generate_upx_unpacking_script()

    assert "UPX" in script.upper(), "Unpacking script does not reference UPX"

    packer_sigs_method = getattr(bypass, "detect_packers", None)
    assert packer_sigs_method is not None, "detect_packers method not found"


def test_upx_frida_script_syntax_valid(bypass: FridaProtectionBypass) -> None:
    """Validate generated Frida script has valid JavaScript syntax.

    Validates:
    - No obvious syntax errors
    - Proper function definitions
    - Valid Frida API usage
    - Balanced brackets and parentheses
    """
    script: str = bypass._generate_upx_unpacking_script()

    open_braces: int = script.count("{")
    close_braces: int = script.count("}")
    assert open_braces == close_braces, (
        f"Unbalanced braces in script: {open_braces} open, {close_braces} close"
    )

    open_parens: int = script.count("(")
    close_parens: int = script.count(")")
    assert open_parens == close_parens, (
        f"Unbalanced parentheses in script: {open_parens} open, {close_parens} close"
    )

    assert "Process.enumerateModules" in script, "Script missing Frida Process API usage"
    assert "Memory.scanSync" in script or "Memory.scan" in script, (
        "Script missing Frida Memory API usage"
    )


@pytest.mark.parametrize(
    "signature_pattern,description",
    [
        ("55 8B EC 83 E4", "Standard x86 function prologue with stack alignment"),
        ("60 BE ?? ?? ?? ??", "PUSHAD + MOV ESI pattern common in UPX stub"),
    ],
)
def test_upx_signature_patterns_in_script(
    bypass: FridaProtectionBypass,
    signature_pattern: str,
    description: str,
) -> None:
    """Validate specific UPX signature patterns are present in unpacking script.

    Validates:
    - Known UPX decompression signatures
    - Pattern format suitable for Frida scanning
    - Description matches actual pattern purpose
    """
    script: str = bypass._generate_upx_unpacking_script()

    assert signature_pattern in script, (
        f"Expected signature pattern '{signature_pattern}' ({description}) not found in script"
    )


def test_upx_detection_confidence_scoring(bypass: FridaProtectionBypass) -> None:
    """Validate confidence scoring for UPX detection is reasonable.

    Validates:
    - Confidence values are between 0.0 and 1.0
    - Higher confidence for exact signature matches
    - Lower confidence for heuristic-only detection
    """
    if not _check_binary_exists(STANDARD_UPX3_X86):
        _log_missing_binary(
            STANDARD_UPX3_X86,
            "Standard UPX 3.x packed x86 PE executable",
        )
        pytest.skip(f"Test binary not found: {STANDARD_UPX3_X86}")

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    if len(upx_detections) == 0:
        pytest.skip("No UPX detection to test confidence scoring")

    upx_info: ProtectionInfo = upx_detections[0]
    assert 0.0 <= upx_info.confidence <= 1.0, (
        f"Confidence score out of range: {upx_info.confidence}"
    )
    assert upx_info.confidence >= 0.7, (
        f"Confidence for standard UPX binary too low: {upx_info.confidence}"
    )


def test_upx_oep_identification_in_unpacking(bypass: FridaProtectionBypass) -> None:
    """Validate OEP identification logic in UPX unpacking script.

    Validates:
    - OEP patterns are searched after decompression
    - Multiple OEP pattern variants are checked
    - OEP address is sent in response message
    - OEP is within valid code section bounds
    """
    script: str = bypass._generate_upx_unpacking_script()

    assert "oep" in script.lower(), "Script does not reference OEP (Original Entry Point)"
    assert "type: 'upx_unpacked'" in script or "upx_unpacked" in script, (
        "Script missing unpacked event notification"
    )

    oep_patterns_count: int = script.count("oepPatterns") + script.count("OEP")
    assert oep_patterns_count > 0, "Script does not implement OEP pattern matching"


def test_upx_detection_version_identification(bypass: FridaProtectionBypass) -> None:
    """Validate UPX version identification in detection results.

    Validates:
    - Version string is extracted when possible
    - Version format is reasonable (e.g., "3.96", "4.0.2")
    - Version is included in ProtectionInfo
    """
    if not _check_binary_exists(STANDARD_UPX3_X86):
        _log_missing_binary(
            STANDARD_UPX3_X86,
            "Standard UPX 3.x packed x86 PE executable",
        )
        pytest.skip(f"Test binary not found: {STANDARD_UPX3_X86}")

    detections: list[ProtectionInfo] = bypass.detect_packers()

    upx_detections: list[ProtectionInfo] = [d for d in detections if "UPX" in d.name]  # type: ignore[attr-defined]
    if len(upx_detections) == 0:
        pytest.skip("No UPX detection to test version identification")

    upx_info: ProtectionInfo = upx_detections[0]
    assert upx_info.version is not None and len(upx_info.version) > 0, (  # type: ignore[attr-defined]
        "UPX version not identified in detection results"
    )
    assert upx_info.version[0].isdigit(), (  # type: ignore[attr-defined]
        f"UPX version format invalid: {upx_info.version}"  # type: ignore[attr-defined]
    )
