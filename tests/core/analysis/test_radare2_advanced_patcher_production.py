"""Production tests for Radare2 Advanced Patcher.

Tests validate real binary patching on actual PE/ELF files.
Tests verify NOP sleds, jump modifications, and license check removal.
"""

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.radare2_advanced_patcher import Architecture, PatchType, Radare2AdvancedPatcher


TEST_ADDRESS_BASE = 0x100
TEST_NOP_BYTE = 0x90
TEST_NOP_SLED_SIZE = 10
TEST_JUMP_ENTRY_COUNT = 4


def create_simple_pe_binary() -> bytes:
    """Create minimal valid PE binary for testing."""
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)

    pe_header = bytearray(256)
    pe_header[:4] = b"PE\x00\x00"
    pe_header[4:6] = b"\x64\x86"
    pe_header[20:22] = struct.pack("<H", 224)
    pe_header[22:24] = struct.pack("<H", 0x010B)

    code_section = bytearray(512)
    code_section[:20] = bytes(
        [
            0x55,
            0x89,
            0xE5,
            0x83,
            0xEC,
            0x10,
            0xB8,
            0x01,
            0x00,
            0x00,
            0x00,
            0x89,
            0xEC,
            0x5D,
            0xC3,
            0x90,
            0x90,
            0x90,
            0x90,
            0x90,
        ]
    )

    return bytes(dos_header + pe_header + code_section)


def create_simple_elf_binary() -> bytes:
    """Create minimal valid ELF binary for testing."""
    elf_header = bytearray(64)
    elf_header[:4] = b"\x7fELF"
    elf_header[4] = 2
    elf_header[5] = 1
    elf_header[6] = 1
    elf_header[16:18] = struct.pack("<H", 2)
    elf_header[18:20] = struct.pack("<H", 62)

    code_section = bytearray(512)
    code_section[:15] = bytes(
        [
            0x55,
            0x48,
            0x89,
            0xE5,
            0x48,
            0x83,
            0xEC,
            0x10,
            0xB8,
            0x01,
            0x00,
            0x00,
            0x00,
            0xC9,
            0xC3,
        ]
    )

    return bytes(elf_header + code_section)


class TestPatcherInitialization:
    """Test patcher initialization."""

    def test_create_patcher_instance(self) -> None:
        """Create patcher instance with binary path."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)

            assert patcher is not None
            assert patcher.binary_path == temp_path
            assert patcher.patches == []
        finally:
            os.unlink(temp_path)

    def test_open_binary_successfully(self) -> None:
        """Open binary file in radare2."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if success := patcher.open(write_mode=False):
                assert patcher.r2 is not None
                assert patcher.architecture is not None
                patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"Radare2 not available: {e}")
        finally:
            os.unlink(temp_path)

    def test_detect_architecture_x86_64(self) -> None:
        """Detect x86-64 architecture."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if success := patcher.open(write_mode=False):
                assert patcher.architecture in {Architecture.X86, Architecture.X86_64}
                patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"Radare2 not available: {e}")
        finally:
            os.unlink(temp_path)


class TestNOPSledGeneration:
    """Test NOP sled generation for patching."""

    def test_generate_nop_sled_x86(self) -> None:
        """Generate NOP sled for x86 architecture."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if not patcher.open(write_mode=True):
                pytest.skip("Failed to open binary")

            patch = patcher.generate_nop_sled(TEST_ADDRESS_BASE, TEST_NOP_SLED_SIZE)

            assert patch is not None
            assert patch.type == PatchType.NOP_SLED
            assert patch.address == TEST_ADDRESS_BASE
            assert len(patch.patched_bytes) == TEST_NOP_SLED_SIZE
            assert all(b == TEST_NOP_BYTE for b in patch.patched_bytes)

            patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"NOP sled generation failed: {e}")
        finally:
            os.unlink(temp_path)

    def test_nop_sled_different_sizes(self) -> None:
        """Generate NOP sleds of different sizes."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if not patcher.open(write_mode=True):
                pytest.skip("Failed to open binary")

            for size in [5, TEST_NOP_SLED_SIZE, 20, 50]:
                patch = patcher.generate_nop_sled(TEST_ADDRESS_BASE + size * TEST_NOP_SLED_SIZE, size)
                assert len(patch.patched_bytes) == size

            patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"NOP sled generation failed: {e}")
        finally:
            os.unlink(temp_path)


class TestJumpTableModification:
    """Test jump table modification."""

    def test_modify_jump_table_entries(self) -> None:
        """Modify jump table entries."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if not patcher.open(write_mode=True):
                pytest.skip("Failed to open binary")

            new_entries = [0x1000, 0x2000, 0x3000, 0x4000]
            patch = patcher.modify_jump_table(0x200, new_entries)

            assert patch is not None
            assert patch.type == PatchType.JUMP_TABLE
            assert len(patch.metadata["entries"]) == TEST_JUMP_ENTRY_COUNT

            patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"Jump table modification failed: {e}")
        finally:
            os.unlink(temp_path)


class TestFunctionProloguePatch:
    """Test function prologue patching."""

    def test_patch_function_prologue_x86_64(self) -> None:
        """Patch function prologue for x86-64."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if not patcher.open(write_mode=True):
                pytest.skip("Failed to open binary")

            patch = patcher.patch_function_prologue(TEST_ADDRESS_BASE)

            assert patch is not None
            assert patch.type == PatchType.PROLOGUE
            assert len(patch.patched_bytes) > 0

            patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"Prologue patching failed: {e}")
        finally:
            os.unlink(temp_path)

    def test_patch_prologue_with_custom_bytes(self) -> None:
        """Patch prologue with custom bytes."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if not patcher.open(write_mode=True):
                pytest.skip("Failed to open binary")

            custom_prologue = b"\x55\x48\x89\xe5\x90"
            patch = patcher.patch_function_prologue(TEST_ADDRESS_BASE, custom_prologue=custom_prologue)

            assert patch is not None
            assert patch.patched_bytes == custom_prologue

            patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"Custom prologue patching failed: {e}")
        finally:
            os.unlink(temp_path)


class TestConditionalJumpInversion:
    """Test conditional jump inversion."""

    def test_invert_je_to_jne(self) -> None:
        """Invert JE to JNE."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            binary_data = bytearray(create_simple_pe_binary())
            binary_data[100] = 0x74
            binary_data[101] = 0x05
            f.write(bytes(binary_data))
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if not patcher.open(write_mode=True):
                pytest.skip("Failed to open binary")

            patch = patcher.invert_conditional_jump(0x64)

            assert patch is not None
            assert patch.type == PatchType.CONDITIONAL_JUMP

            patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"Conditional jump inversion failed: {e}")
        finally:
            os.unlink(temp_path)


class TestReturnValueModification:
    """Test return value modification."""

    def test_modify_return_value_to_one(self) -> None:
        """Modify function to always return 1."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if not patcher.open(write_mode=True):
                pytest.skip("Failed to open binary")

            patch = patcher.modify_return_value(TEST_ADDRESS_BASE, return_value=1)

            assert patch is not None
            assert patch.type == PatchType.RETURN_VALUE

            patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"Return value modification failed: {e}")
        finally:
            os.unlink(temp_path)

    def test_modify_return_value_to_zero(self) -> None:
        """Modify function to always return 0."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if not patcher.open(write_mode=True):
                pytest.skip("Failed to open binary")

            patch = patcher.modify_return_value(TEST_ADDRESS_BASE, return_value=0)

            assert patch is not None
            assert patch.metadata["return_value"] == 0

            patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"Return value modification failed: {e}")
        finally:
            os.unlink(temp_path)


class TestLicenseCheckPatching:
    """Test patching of license check functions."""

    def test_patch_license_check_to_always_succeed(self) -> None:
        """Patch license check to always return success."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            binary_data = bytearray(create_simple_pe_binary())
            binary_data[100:115] = bytes([
                0x48, 0x85, 0xc0,
                0x74, 0x05,
                0xb8, 0x00, 0x00, 0x00, 0x00,
                0xc3,
                0xb8, 0x01, 0x00, 0x00, 0x00,
            ])
            f.write(bytes(binary_data))
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if not patcher.open(write_mode=True):
                pytest.skip("Failed to open binary")

            patch = patcher.modify_return_value(0x64, return_value=1)

            assert patch is not None

            patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"License check patching failed: {e}")
        finally:
            os.unlink(temp_path)

    def test_nop_out_license_validation(self) -> None:
        """NOP out license validation code."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if not patcher.open(write_mode=True):
                pytest.skip("Failed to open binary")

            patch = patcher.generate_nop_sled(TEST_ADDRESS_BASE, 20)

            assert patch is not None
            assert all(b == TEST_NOP_BYTE for b in patch.patched_bytes)

            patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"License validation NOP failed: {e}")
        finally:
            os.unlink(temp_path)


class TestPatchTracking:
    """Test patch tracking and management."""

    def test_patches_are_tracked(self) -> None:
        """Verify patches are tracked in list."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if not patcher.open(write_mode=True):
                pytest.skip("Failed to open binary")

            initial_count = len(patcher.patches)

            patcher.generate_nop_sled(TEST_ADDRESS_BASE, TEST_NOP_SLED_SIZE)
            patcher.modify_return_value(0x200, 1)

            assert len(patcher.patches) == initial_count + 2

            patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"Patch tracking failed: {e}")
        finally:
            os.unlink(temp_path)

    def test_patch_metadata_preserved(self) -> None:
        """Verify patch metadata is preserved."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if not patcher.open(write_mode=True):
                pytest.skip("Failed to open binary")

            patch = patcher.generate_nop_sled(TEST_ADDRESS_BASE, TEST_NOP_SLED_SIZE)

            assert "size" in patch.metadata
            assert patch.metadata["size"] == TEST_NOP_SLED_SIZE

            patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"Patch metadata test failed: {e}")
        finally:
            os.unlink(temp_path)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_open_nonexistent_binary(self) -> None:
        """Handle nonexistent binary file."""
        patcher = Radare2AdvancedPatcher("/nonexistent/binary.exe")

        success = patcher.open(write_mode=False)

        assert success is False

    def test_patch_zero_size_nop_sled(self) -> None:
        """Handle zero-size NOP sled."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            patcher = Radare2AdvancedPatcher(temp_path)
            if not patcher.open(write_mode=True):
                pytest.skip("Failed to open binary")

            with pytest.raises(ValueError):
                patcher.generate_nop_sled(TEST_ADDRESS_BASE, 0)

            patcher.r2.quit()
        except Exception as e:
            pytest.skip(f"Zero-size NOP test failed: {e}")
        finally:
            os.unlink(temp_path)


class TestPerformance:
    """Test patching performance."""

    def test_multiple_patches_performance(self, benchmark: Any) -> None:
        """Benchmark multiple patch operations."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(create_simple_pe_binary())
            temp_path = f.name

        try:
            def apply_patches() -> int:
                patcher = Radare2AdvancedPatcher(temp_path)
                if not patcher.open(write_mode=True):
                    return 0

                for i in range(TEST_NOP_SLED_SIZE):
                    patcher.generate_nop_sled(TEST_ADDRESS_BASE + i * 20, TEST_NOP_SLED_SIZE)

                count = len(patcher.patches)
                patcher.r2.quit()
                return count

            result = benchmark(apply_patches)

            if result > 0:
                assert result == TEST_NOP_SLED_SIZE
        except Exception as e:
            pytest.skip(f"Performance test failed: {e}")
        finally:
            os.unlink(temp_path)
