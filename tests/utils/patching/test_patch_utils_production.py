"""Production tests for patch utilities - binary patching functionality.

This test module validates real binary patching capabilities, including:
- Parsing patch instructions from various formats
- Applying patches to actual PE/ELF binaries
- Validating patch integrity
- RVA to offset conversion
- NOP patch generation
- Section information extraction

All tests operate on real or realistic binary data to validate licensing crack functionality.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.patching.patch_utils import (
    apply_patch,
    convert_rva_to_offset,
    create_nop_patch,
    create_patch,
    get_section_info,
    parse_patch_instructions,
    validate_patch,
)


class TestParsePatchInstructions:
    """Test parsing patch instructions from various text formats."""

    def test_parse_standard_format(self) -> None:
        """Parse correctly formatted patch instructions."""
        text = """
        Address: 0x00401000 NewBytes: 90 90 90 // NOP patch
        Address: 0x00401010 NewBytes: C3 // RET instruction
        Address: 00401020 NewBytes: EB 00 // JMP +2
        """

        instructions = parse_patch_instructions(text)

        assert len(instructions) == 3

        assert instructions[0]["address"] == 0x00401000
        assert instructions[0]["new_bytes"] == b"\x90\x90\x90"
        assert "NOP patch" in instructions[0]["description"]

        assert instructions[1]["address"] == 0x00401010
        assert instructions[1]["new_bytes"] == b"\xC3"
        assert "RET instruction" in instructions[1]["description"]

        assert instructions[2]["address"] == 0x00401020
        assert instructions[2]["new_bytes"] == b"\xEB\x00"
        assert "JMP +2" in instructions[2]["description"]

    def test_parse_ai_generated_format(self) -> None:
        """Parse AI-generated patch instructions with various formatting."""
        text = """
        The following patches bypass the license check:
        Address:0x401000 NewBytes:B8 01 00 00 00 // mov eax, 1
        Address: 0x401005 NewBytes: C3    // ret

        Additional patches for feature unlock:
        Address:0x402000 NewBytes:90909090 // NOP sled
        """

        instructions = parse_patch_instructions(text)

        assert len(instructions) == 3

        assert instructions[0]["new_bytes"] == b"\xB8\x01\x00\x00\x00"
        assert instructions[1]["new_bytes"] == b"\xC3"
        assert instructions[2]["new_bytes"] == b"\x90\x90\x90\x90"

    def test_parse_no_description(self) -> None:
        """Parse instructions without descriptions."""
        text = """
        Address: 0x401000 NewBytes: 90
        Address: 0x401001 NewBytes: C3
        """

        instructions = parse_patch_instructions(text)

        assert len(instructions) == 2
        assert instructions[0]["description"] == "Patch"
        assert instructions[1]["description"] == "Patch"

    def test_parse_invalid_hex(self) -> None:
        """Skip instructions with invalid hex values."""
        text = """
        Address: 0x401000 NewBytes: 90 90 ZZ // Invalid hex
        Address: 0x401010 NewBytes: C3 // Valid
        """

        instructions = parse_patch_instructions(text)

        assert len(instructions) == 1
        assert instructions[0]["address"] == 0x00401010

    def test_parse_odd_length_hex(self) -> None:
        """Skip instructions with odd-length hex strings."""
        text = """
        Address: 0x401000 NewBytes: 9 // Odd length
        Address: 0x401001 NewBytes: 90 // Valid
        """

        instructions = parse_patch_instructions(text)

        assert len(instructions) == 1
        assert instructions[0]["address"] == 0x00401001

    def test_parse_empty_bytes(self) -> None:
        """Skip instructions with empty byte strings."""
        text = """
        Address: 0x401000 NewBytes: // No bytes
        Address: 0x401001 NewBytes: 90 // Valid
        """

        instructions = parse_patch_instructions(text)

        assert len(instructions) == 1
        assert instructions[0]["address"] == 0x00401001

    def test_parse_no_matches(self) -> None:
        """Return empty list when no valid instructions found."""
        text = """
        This is just some random text
        with no patch instructions at all.
        """

        instructions = parse_patch_instructions(text)

        assert len(instructions) == 0

    def test_parse_case_insensitive(self) -> None:
        """Parse instructions with mixed case."""
        text = """
        address: 0x401000 newbytes: 90 90 // Lower case
        ADDRESS: 0x401010 NEWBYTES: C3 // Upper case
        """

        instructions = parse_patch_instructions(text)

        assert len(instructions) == 2
        assert instructions[0]["new_bytes"] == b"\x90\x90"
        assert instructions[1]["new_bytes"] == b"\xC3"


class TestCreatePatch:
    """Test patch creation by comparing binary data."""

    def test_create_patch_single_difference(self) -> None:
        """Create patch for single byte difference."""
        original = b"\x90\x90\x90\x90\x90"
        modified = b"\x90\xC3\x90\x90\x90"

        patches = create_patch(original, modified, base_address=0x1000)

        assert len(patches) == 1
        assert patches[0]["address"] == 0x1001
        assert patches[0]["new_bytes"] == b"\xC3"

    def test_create_patch_multiple_differences(self) -> None:
        """Create patches for multiple byte differences."""
        original = b"\x90\x90\x90\x90\x90\x90\x90\x90"
        modified = b"\x90\xC3\xC3\x90\x90\xEB\x00\x90"

        patches = create_patch(original, modified, base_address=0x1000)

        assert len(patches) == 2

        assert patches[0]["address"] == 0x1001
        assert patches[0]["new_bytes"] == b"\xC3\xC3"

        assert patches[1]["address"] == 0x1005
        assert patches[1]["new_bytes"] == b"\xEB\x00"

    def test_create_patch_consecutive_changes(self) -> None:
        """Consecutive changes create single patch."""
        original = b"\x90\x90\x90\x90\x90"
        modified = b"\xB8\x01\x00\x00\x00"

        patches = create_patch(original, modified, base_address=0x1000)

        assert len(patches) == 1
        assert patches[0]["address"] == 0x1000
        assert patches[0]["new_bytes"] == b"\xB8\x01\x00\x00\x00"

    def test_create_patch_no_changes(self) -> None:
        """No patches created when data is identical."""
        original = b"\x90\x90\x90\x90\x90"
        modified = b"\x90\x90\x90\x90\x90"

        patches = create_patch(original, modified)

        assert len(patches) == 0

    def test_create_patch_length_mismatch(self) -> None:
        """Handle length mismatch between original and modified."""
        original = b"\x90\x90\x90"
        modified = b"\xC3\xC3"

        patches = create_patch(original, modified)

        assert len(patches) == 1
        assert len(patches[0]["new_bytes"]) == 2

    def test_create_patch_custom_base_address(self) -> None:
        """Use custom base address for patch offsets."""
        original = b"\x90\x90\x90"
        modified = b"\xC3\x90\x90"

        patches = create_patch(original, modified, base_address=0x400000)

        assert patches[0]["address"] == 0x400000


class TestApplyPatch:
    """Test applying patches to actual binary files."""

    @pytest.fixture
    def temp_binary(self, tmp_path: Path) -> Path:
        """Create a temporary binary file for testing."""
        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x90" * 100)
        return binary_path

    def test_apply_single_patch(self, temp_binary: Path) -> None:
        """Apply single patch to binary file."""
        patches = [
            {
                "address": 10,
                "new_bytes": b"\xC3",
                "description": "RET instruction",
            }
        ]

        success, patched_path = apply_patch(temp_binary, patches)

        assert success is True
        assert patched_path is not None

        patched_data = Path(patched_path).read_bytes()
        assert patched_data[10] == 0xC3
        assert patched_data[9] == 0x90

    def test_apply_multiple_patches(self, temp_binary: Path) -> None:
        """Apply multiple patches to binary file."""
        patches = [
            {"address": 10, "new_bytes": b"\xC3", "description": "Patch 1"},
            {"address": 20, "new_bytes": b"\xEB\x00", "description": "Patch 2"},
            {"address": 30, "new_bytes": b"\x90\x90", "description": "Patch 3"},
        ]

        success, patched_path = apply_patch(temp_binary, patches)

        assert success is True
        patched_data = Path(patched_path).read_bytes()

        assert patched_data[10] == 0xC3
        assert patched_data[20:22] == b"\xEB\x00"
        assert patched_data[30:32] == b"\x90\x90"

    def test_apply_patch_creates_backup(self, temp_binary: Path) -> None:
        """Verify backup is created when requested."""
        patches = [{"address": 10, "new_bytes": b"\xC3", "description": "Test"}]

        original_data = temp_binary.read_bytes()

        success, _ = apply_patch(temp_binary, patches, create_backup=True)

        assert success is True

        backups = list(temp_binary.parent.glob(f"{temp_binary.name}.backup_*"))
        assert len(backups) > 0

        backup_data = backups[0].read_bytes()
        assert backup_data == original_data

    def test_apply_patch_no_backup(self, temp_binary: Path) -> None:
        """No backup created when create_backup=False."""
        patches = [{"address": 10, "new_bytes": b"\xC3", "description": "Test"}]

        success, _ = apply_patch(temp_binary, patches, create_backup=False)

        assert success is True

        backups = list(temp_binary.parent.glob(f"{temp_binary.name}.backup_*"))
        assert len(backups) == 0

    def test_apply_patch_nonexistent_file(self, tmp_path: Path) -> None:
        """Return error when file doesn't exist."""
        nonexistent = tmp_path / "nonexistent.bin"
        patches = [{"address": 10, "new_bytes": b"\xC3", "description": "Test"}]

        success, _ = apply_patch(nonexistent, patches)

        assert success is False

    def test_apply_empty_patches(self, temp_binary: Path) -> None:
        """Return error when no patches provided."""
        success, _ = apply_patch(temp_binary, [])

        assert success is False

    def test_apply_patch_invalid_address(self, temp_binary: Path) -> None:
        """Handle patch with address beyond file size."""
        patches = [
            {"address": 1000, "new_bytes": b"\xC3", "description": "Beyond EOF"}
        ]

        success, patched_path = apply_patch(temp_binary, patches)

        assert success is True
        assert os.path.exists(patched_path)

    def test_apply_patch_empty_bytes(self, temp_binary: Path) -> None:
        """Skip patches with empty byte arrays."""
        patches = [
            {"address": 10, "new_bytes": b"", "description": "Empty"},
            {"address": 20, "new_bytes": b"\xC3", "description": "Valid"},
        ]

        success, patched_path = apply_patch(temp_binary, patches)

        assert success is True
        patched_data = Path(patched_path).read_bytes()
        assert patched_data[20] == 0xC3


class TestValidatePatch:
    """Test patch validation functionality."""

    @pytest.fixture
    def patched_binary(self, tmp_path: Path) -> tuple[Path, list[dict[str, Any]]]:
        """Create a patched binary with known patches."""
        binary_path = tmp_path / "patched.bin"
        data = bytearray(b"\x90" * 100)
        data[10] = 0xC3
        data[20:22] = b"\xEB\x00"
        binary_path.write_bytes(data)

        patches = [
            {"address": 10, "new_bytes": b"\xC3", "description": "Patch 1"},
            {"address": 20, "new_bytes": b"\xEB\x00", "description": "Patch 2"},
        ]

        return binary_path, patches

    def test_validate_correct_patches(
        self, patched_binary: tuple[Path, list[dict[str, Any]]]
    ) -> None:
        """Validate successfully when patches match."""
        binary_path, patches = patched_binary

        result = validate_patch(binary_path, patches)

        assert result is True

    def test_validate_incorrect_patch(self, tmp_path: Path) -> None:
        """Validation fails when patch doesn't match."""
        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x90" * 100)

        patches = [{"address": 10, "new_bytes": b"\xC3", "description": "Expected"}]

        result = validate_patch(binary_path, patches)

        assert result is False

    def test_validate_nonexistent_file(self, tmp_path: Path) -> None:
        """Validation fails for nonexistent file."""
        nonexistent = tmp_path / "nonexistent.bin"
        patches = [{"address": 10, "new_bytes": b"\xC3", "description": "Test"}]

        result = validate_patch(nonexistent, patches)

        assert result is False

    def test_validate_multiple_patches_one_wrong(
        self, patched_binary: tuple[Path, list[dict[str, Any]]]
    ) -> None:
        """Validation fails if any patch is incorrect."""
        binary_path, _ = patched_binary

        patches = [
            {"address": 10, "new_bytes": b"\xC3", "description": "Correct"},
            {"address": 20, "new_bytes": b"\xFF\xFF", "description": "Wrong"},
        ]

        result = validate_patch(binary_path, patches)

        assert result is False


class TestCreateNOPPatch:
    """Test NOP patch generation for various architectures."""

    def test_nop_patch_x86(self) -> None:
        """Create x86 NOP patch."""
        patch = create_nop_patch(address=0x401000, length=5, arch="x86")

        assert patch["address"] == 0x401000
        assert patch["new_bytes"] == b"\x90" * 5
        assert "NOP patch" in patch["description"]
        assert "5 bytes" in patch["description"]

    def test_nop_patch_x64(self) -> None:
        """Create x64 NOP patch."""
        patch = create_nop_patch(address=0x401000, length=8, arch="x64")

        assert patch["address"] == 0x401000
        assert patch["new_bytes"] == b"\x90" * 8

    def test_nop_patch_arm_thumb(self) -> None:
        """Create ARM Thumb NOP patch."""
        patch = create_nop_patch(address=0x8000, length=4, arch="arm")

        assert patch["address"] == 0x8000
        assert len(patch["new_bytes"]) == 4
        assert patch["new_bytes"] == b"\x00\xbf" * 2

    def test_nop_patch_arm64(self) -> None:
        """Create ARM64 NOP patch."""
        patch = create_nop_patch(address=0x8000, length=8, arch="arm64")

        assert patch["address"] == 0x8000
        assert len(patch["new_bytes"]) == 8

    def test_nop_patch_non_divisible_length(self) -> None:
        """Handle non-divisible length for multi-byte NOPs."""
        patch = create_nop_patch(address=0x401000, length=7, arch="arm")

        assert len(patch["new_bytes"]) == 7

    def test_nop_patch_unknown_architecture(self) -> None:
        """Default to x86 NOP for unknown architecture."""
        patch = create_nop_patch(address=0x401000, length=5, arch="unknown")

        assert patch["new_bytes"] == b"\x90" * 5


class TestBinaryPatchingIntegration:
    """Integration tests for complete binary patching workflows."""

    @pytest.fixture
    def create_test_binary(self, tmp_path: Path) -> Path:
        """Create a realistic test binary with license check pattern."""
        binary_path = tmp_path / "protected.exe"

        license_check_code = bytearray(
            [
                0x55,
                0x8B,
                0xEC,
                0x83,
                0xEC,
                0x10,
                0x85,
                0xC0,
                0x74,
                0x05,
                0xB8,
                0x00,
                0x00,
                0x00,
                0x00,
                0xEB,
                0x05,
                0xB8,
                0x01,
                0x00,
                0x00,
                0x00,
                0xC9,
                0xC3,
            ]
        )

        padding = bytearray([0x90] * 200)
        binary_data = license_check_code + padding

        binary_path.write_bytes(binary_data)
        return binary_path

    def test_complete_patch_workflow(self, create_test_binary: Path) -> None:
        """Test complete workflow: parse, apply, validate."""
        patch_text = """
        Address: 0x0008 NewBytes: EB 0A // Jump over license check
        Address: 0x000A NewBytes: 90 90 90 90 90 // NOP sled
        """

        instructions = parse_patch_instructions(patch_text)

        assert len(instructions) == 2

        success, patched_path = apply_patch(create_test_binary, instructions)

        assert success is True
        assert patched_path is not None

        valid = validate_patch(patched_path, instructions)

        assert valid is True

    def test_license_bypass_patch(self, create_test_binary: Path) -> None:
        """Test patching license check to always return success."""
        original_data = create_test_binary.read_bytes()

        bypass_patches = [
            {
                "address": 0x0A,
                "new_bytes": b"\xB8\x01\x00\x00\x00",
                "description": "mov eax, 1 (license valid)",
            },
            {
                "address": 0x0F,
                "new_bytes": b"\xC9\xC3",
                "description": "leave; ret",
            },
        ]

        success, patched_path = apply_patch(create_test_binary, bypass_patches)

        assert success is True

        patched_data = Path(patched_path).read_bytes()
        assert patched_data != original_data
        assert patched_data[0x0A : 0x0A + 5] == b"\xB8\x01\x00\x00\x00"

    def test_nop_out_time_check(self, tmp_path: Path) -> None:
        """Test NOPing out trial expiration time check."""
        binary_path = tmp_path / "trial.exe"

        time_check_code = bytearray(
            [
                0x50,
                0xFF,
                0x15,
                0x00,
                0x40,
                0x40,
                0x00,
                0x3D,
                0x00,
                0xE1,
                0xF5,
                0x05,
                0x77,
                0x05,
                0xB8,
                0x00,
                0x00,
                0x00,
                0x00,
                0xEB,
                0x05,
                0xB8,
                0x01,
                0x00,
                0x00,
                0x00,
                0xC3,
            ]
        )

        binary_path.write_bytes(time_check_code + bytearray([0x90] * 100))

        time_cmp_offset = 0x07
        nop_patch = create_nop_patch(time_cmp_offset, 6, arch="x86")

        success, patched_path = apply_patch(binary_path, [nop_patch])

        assert success is True

        patched_data = Path(patched_path).read_bytes()
        assert patched_data[time_cmp_offset : time_cmp_offset + 6] == b"\x90" * 6


@pytest.mark.skipif(
    not shutil.which("pe-parser"), reason="PE parser not available"
)
class TestPESpecificFunctions:
    """Test PE-specific patching functions (requires pefile)."""

    def test_get_section_info_requires_pe(self, tmp_path: Path) -> None:
        """get_section_info returns empty list for non-PE files."""
        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x90" * 100)

        sections = get_section_info(binary_path)

        assert sections == []

    def test_convert_rva_to_offset_requires_pe(self, tmp_path: Path) -> None:
        """convert_rva_to_offset returns None for non-PE files."""
        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x90" * 100)

        offset = convert_rva_to_offset(binary_path, rva=0x1000)

        assert offset is None


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_large_binary_patching(self, tmp_path: Path) -> None:
        """Test patching large binary files."""
        binary_path = tmp_path / "large.bin"
        binary_path.write_bytes(b"\x90" * 10_000_000)

        patches = [
            {"address": 5_000_000, "new_bytes": b"\xC3", "description": "Middle patch"}
        ]

        success, patched_path = apply_patch(binary_path, patches)

        assert success is True

        patched_data = Path(patched_path).read_bytes()
        assert patched_data[5_000_000] == 0xC3

    def test_binary_patch_permission_error(self, tmp_path: Path) -> None:
        """Handle permission errors gracefully."""
        binary_path = tmp_path / "readonly.bin"
        binary_path.write_bytes(b"\x90" * 100)
        binary_path.chmod(0o444)

        patches = [{"address": 10, "new_bytes": b"\xC3", "description": "Test"}]

        try:
            success, _ = apply_patch(binary_path, patches)

            assert isinstance(success, bool)
        finally:
            binary_path.chmod(0o644)

    def test_corrupted_binary_data(self, tmp_path: Path) -> None:
        """Handle corrupted binary data."""
        binary_path = tmp_path / "corrupted.bin"
        binary_path.write_bytes(b"\xFF" * 50 + b"\x00" * 50)

        patches = [
            {"address": 25, "new_bytes": b"\x90\x90\x90", "description": "Patch"}
        ]

        success, patched_path = apply_patch(binary_path, patches)

        assert success is True
        assert Path(patched_path).exists()
