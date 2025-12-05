"""Production-ready tests for LicenseBypassCodeGenerator.

This module validates real assembly code generation for bypassing software licensing
protections across multiple architectures (x86, x64, ARM, ARM64) with proper calling
conventions, stack management, and position-independent code.

Tests verify actual binary code generation and validate instruction correctness.
"""

import struct
from typing import Any

import pytest

from intellicrack.core.exploitation.license_bypass_code_generator import (
    LicenseBypassCodeGenerator,
)


class TestLicenseBypassCodeGeneratorInitialization:
    """Test LicenseBypassCodeGenerator initialization and configuration."""

    def test_init_x86_64_windows(self) -> None:
        """x86_64 Windows generator initializes with correct calling convention."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")

        assert gen.architecture == "x86_64"
        assert gen.platform == "windows"
        assert len(gen.generated_patches) == 0
        assert "x86_64" in gen.calling_conventions
        assert "windows" in gen.calling_conventions["x86_64"]

        cc_info = gen.get_calling_convention_info()
        assert cc_info["int_params"] == ["rcx", "rdx", "r8", "r9"]
        assert cc_info["shadow_space"] == 32
        assert cc_info["stack_align"] == 16

    def test_init_x86_64_linux(self) -> None:
        """x86_64 Linux generator initializes with correct calling convention."""
        gen = LicenseBypassCodeGenerator("x86_64", "linux")

        assert gen.architecture == "x86_64"
        assert gen.platform == "linux"

        cc_info = gen.get_calling_convention_info()
        assert cc_info["int_params"] == ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        assert cc_info["shadow_space"] == 0
        assert cc_info["stack_align"] == 16

    def test_init_x86_windows(self) -> None:
        """x86 Windows generator initializes with cdecl convention."""
        gen = LicenseBypassCodeGenerator("x86", "windows")

        assert gen.architecture == "x86"
        assert gen.platform == "windows"

        cc_info = gen.get_calling_convention_info()
        assert cc_info["calling"] == "cdecl"
        assert cc_info["stack_align"] == 4
        assert cc_info["cleanup"] == "caller"

    def test_init_arm64(self) -> None:
        """ARM64 generator initializes with correct register convention."""
        gen = LicenseBypassCodeGenerator("arm64", "linux")

        assert gen.architecture == "arm64"

        cc_info = gen.get_calling_convention_info()
        assert cc_info["int_params"] == ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
        assert cc_info["stack_align"] == 16

    def test_init_arm(self) -> None:
        """ARM generator initializes with correct register convention."""
        gen = LicenseBypassCodeGenerator("arm", "linux")

        assert gen.architecture == "arm"

        cc_info = gen.get_calling_convention_info()
        assert cc_info["int_params"] == ["r0", "r1", "r2", "r3"]
        assert cc_info["stack_align"] == 8


class TestLicenseCheckBypass:
    """Test license check bypass code generation."""

    def test_x86_64_windows_with_stack_preservation(self) -> None:
        """x86_64 Windows bypass generates valid code with stack frame."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_license_check_bypass(0x401000, preserve_stack=True)

        assert len(code) > 0
        assert code[:4] == b"\x48\x83\xec\x28"
        assert code[-1:] == b"\xc3"
        assert b"\x48\x31\xc0" in code
        assert b"\x48\xff\xc0" in code
        assert b"\x48\x83\xc4\x28" in code

        patches = gen.get_generated_patches()
        assert len(patches) == 1
        assert patches[0]["type"] == "license_check_bypass"
        assert patches[0]["address"] == 0x401000
        assert patches[0]["preserve_stack"] is True

    def test_x86_64_linux_with_stack_preservation(self) -> None:
        """x86_64 Linux bypass generates valid code with stack frame."""
        gen = LicenseBypassCodeGenerator("x86_64", "linux")
        code = gen.generate_license_check_bypass(0x401000, preserve_stack=True)

        assert len(code) > 0
        assert code[:1] == b"\x55"
        assert code[1:4] == b"\x48\x89\xe5"
        assert b"\x48\x31\xc0" in code
        assert b"\x48\xff\xc0" in code
        assert b"\x5d" in code
        assert code[-1:] == b"\xc3"

    def test_x86_64_without_stack_preservation(self) -> None:
        """x86_64 bypass without stack frame generates minimal code."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_license_check_bypass(0x401000, preserve_stack=False)

        assert len(code) == 7
        assert code[:3] == b"\x48\x31\xc0"
        assert code[3:6] == b"\x48\xff\xc0"
        assert code[6:] == b"\xc3"

    def test_x86_with_stack_preservation(self) -> None:
        """x86 bypass generates valid 32-bit code with stack frame."""
        gen = LicenseBypassCodeGenerator("x86", "windows")
        code = gen.generate_license_check_bypass(0x401000, preserve_stack=True)

        assert len(code) > 0
        assert code[:1] == b"\x55"
        assert code[1:3] == b"\x89\xe5"
        assert code[3:5] == b"\x31\xc0"
        assert code[5:6] == b"\x40"
        assert code[6:7] == b"\x5d"
        assert code[7:] == b"\xc3"

    def test_x86_without_stack_preservation(self) -> None:
        """x86 bypass without stack frame generates minimal code."""
        gen = LicenseBypassCodeGenerator("x86", "windows")
        code = gen.generate_license_check_bypass(0x401000, preserve_stack=False)

        assert len(code) == 4
        assert code[:2] == b"\x31\xc0"
        assert code[2:3] == b"\x40"
        assert code[3:] == b"\xc3"

    def test_arm64_bypass(self) -> None:
        """ARM64 bypass generates valid AArch64 instructions."""
        gen = LicenseBypassCodeGenerator("arm64", "linux")
        code = gen.generate_license_check_bypass(0x401000, preserve_stack=True)

        assert len(code) == 8
        assert code[:4] == b"\x20\x00\x80\xd2"
        assert code[4:] == b"\xc0\x03\x5f\xd6"

    def test_arm_bypass(self) -> None:
        """ARM bypass generates valid ARM32 instructions."""
        gen = LicenseBypassCodeGenerator("arm", "linux")
        code = gen.generate_license_check_bypass(0x401000, preserve_stack=True)

        assert len(code) == 8
        assert code[:4] == b"\x01\x00\xa0\xe3"
        assert code[4:] == b"\x1e\xff\x2f\xe1"

    def test_multiple_bypasses_tracked(self) -> None:
        """Multiple bypass patches are tracked correctly."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")

        code1 = gen.generate_license_check_bypass(0x401000)
        code2 = gen.generate_license_check_bypass(0x402000)
        code3 = gen.generate_license_check_bypass(0x403000)

        patches = gen.get_generated_patches()
        assert len(patches) == 3
        assert patches[0]["address"] == 0x401000
        assert patches[1]["address"] == 0x402000
        assert patches[2]["address"] == 0x403000


class TestTrialExtensionPatch:
    """Test trial period extension patch generation."""

    def test_x86_64_windows_trial_extension(self) -> None:
        """x86_64 Windows trial extension includes NOPs and returns zero."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_trial_extension_patch(0x402000, preserve_stack=True)

        assert len(code) > 0
        assert code[:4] == b"\x48\x83\xec\x28"
        assert b"\x48\x31\xc0" in code
        assert code.count(b"\x90") == 5
        assert b"\x48\x83\xc4\x28" in code
        assert code[-1:] == b"\xc3"

    def test_x86_64_linux_trial_extension(self) -> None:
        """x86_64 Linux trial extension includes stack frame."""
        gen = LicenseBypassCodeGenerator("x86_64", "linux")
        code = gen.generate_trial_extension_patch(0x402000, preserve_stack=True)

        assert code[:1] == b"\x55"
        assert code[1:4] == b"\x48\x89\xe5"
        assert b"\x48\x31\xc0" in code
        assert code.count(b"\x90") == 5
        assert b"\x5d" in code
        assert code[-1:] == b"\xc3"

    def test_x86_trial_extension(self) -> None:
        """x86 trial extension generates valid 32-bit code."""
        gen = LicenseBypassCodeGenerator("x86", "windows")
        code = gen.generate_trial_extension_patch(0x402000, preserve_stack=True)

        assert code[:1] == b"\x55"
        assert code[1:3] == b"\x89\xe5"
        assert code[3:5] == b"\x31\xc0"
        assert code.count(b"\x90") == 5

    def test_arm64_trial_extension(self) -> None:
        """ARM64 trial extension generates valid code with NOPs."""
        gen = LicenseBypassCodeGenerator("arm64", "linux")
        code = gen.generate_trial_extension_patch(0x402000)

        assert len(code) > 0
        assert code[:4] == b"\x00\x00\x80\xd2"
        assert code.count(b"\x1f\x20\x03\xd5") == 3
        assert code[-4:] == b"\xc0\x03\x5f\xd6"


class TestActivationBypass:
    """Test product activation bypass code generation."""

    def test_x86_64_windows_activation_bypass(self) -> None:
        """x86_64 Windows activation bypass returns 1."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_activation_bypass(0x403000, preserve_stack=True)

        assert len(code) > 0
        assert code[:4] == b"\x48\x83\xec\x28"
        assert b"\x48\xc7\xc0\x01\x00\x00\x00" in code
        assert b"\x48\x83\xc4\x28" in code
        assert code[-1:] == b"\xc3"

    def test_x86_64_linux_activation_bypass(self) -> None:
        """x86_64 Linux activation bypass returns 1."""
        gen = LicenseBypassCodeGenerator("x86_64", "linux")
        code = gen.generate_activation_bypass(0x403000, preserve_stack=True)

        assert code[:1] == b"\x55"
        assert b"\x48\xc7\xc0\x01\x00\x00\x00" in code
        assert b"\x5d" in code
        assert code[-1:] == b"\xc3"

    def test_x86_activation_bypass(self) -> None:
        """x86 activation bypass returns 1."""
        gen = LicenseBypassCodeGenerator("x86", "windows")
        code = gen.generate_activation_bypass(0x403000, preserve_stack=True)

        assert code[:1] == b"\x55"
        assert b"\xb8\x01\x00\x00\x00" in code
        assert b"\x5d" in code
        assert code[-1:] == b"\xc3"

    def test_activation_bypass_without_stack(self) -> None:
        """Activation bypass without stack preservation is minimal."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_activation_bypass(0x403000, preserve_stack=False)

        assert len(code) == 8
        assert code[:7] == b"\x48\xc7\xc0\x01\x00\x00\x00"
        assert code[7:] == b"\xc3"


class TestSerialValidationBypass:
    """Test serial number validation bypass code generation."""

    def test_x86_64_windows_serial_bypass(self) -> None:
        """x86_64 Windows serial bypass returns success."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_serial_validation_bypass(0x404000, preserve_stack=True)

        assert len(code) > 0
        assert code[:4] == b"\x48\x83\xec\x28"
        assert b"\x48\x31\xc0" in code
        assert b"\x48\xff\xc0" in code
        assert b"\x48\x83\xc4\x28" in code
        assert code[-1:] == b"\xc3"

    def test_x86_serial_bypass(self) -> None:
        """x86 serial bypass returns success."""
        gen = LicenseBypassCodeGenerator("x86", "windows")
        code = gen.generate_serial_validation_bypass(0x404000, preserve_stack=True)

        assert code[:1] == b"\x55"
        assert code[3:5] == b"\x31\xc0"
        assert code[5:6] == b"\x40"
        assert code[-1:] == b"\xc3"

    def test_serial_bypass_tracking(self) -> None:
        """Serial bypass patch is tracked correctly."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        gen.generate_serial_validation_bypass(0x404000)

        patches = gen.get_generated_patches()
        assert len(patches) == 1
        assert patches[0]["type"] == "serial_validation_bypass"
        assert patches[0]["address"] == 0x404000


class TestHardwareIdSpoof:
    """Test hardware ID spoofing code generation."""

    def test_x86_64_windows_hwid_spoof(self) -> None:
        """x86_64 Windows HWID spoof loads spoofed value into RAX."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        spoofed = b"TESTID12"
        code = gen.generate_hardware_id_spoof(0x405000, spoofed, preserve_stack=True)

        assert len(code) > 0
        assert code[:4] == b"\x48\x83\xec\x28"
        assert code[4:6] == b"\x48\xb8"
        assert code[6:14] == spoofed
        assert b"\x48\x83\xc4\x28" in code
        assert code[-1:] == b"\xc3"

    def test_x86_64_linux_hwid_spoof(self) -> None:
        """x86_64 Linux HWID spoof loads spoofed value."""
        gen = LicenseBypassCodeGenerator("x86_64", "linux")
        spoofed = b"HWID9876"
        code = gen.generate_hardware_id_spoof(0x405000, spoofed, preserve_stack=True)

        assert code[:1] == b"\x55"
        assert code[4:6] == b"\x48\xb8"
        assert code[6:14] == spoofed
        assert b"\x5d" in code

    def test_x86_hwid_spoof(self) -> None:
        """x86 HWID spoof loads 4 bytes into EAX."""
        gen = LicenseBypassCodeGenerator("x86", "windows")
        spoofed = b"TEST"
        code = gen.generate_hardware_id_spoof(0x405000, spoofed, preserve_stack=True)

        assert code[:1] == b"\x55"
        assert code[3:4] == b"\xb8"
        assert code[4:8] == spoofed

    def test_hwid_spoof_short_value_padded(self) -> None:
        """HWID spoof pads short values correctly."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        spoofed = b"AB"
        code = gen.generate_hardware_id_spoof(0x405000, spoofed, preserve_stack=False)

        assert code[2:4] == b"AB"
        assert code[4:10] == b"\x00" * 6

    def test_hwid_spoof_long_value_truncated(self) -> None:
        """HWID spoof truncates long values correctly."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        spoofed = b"VERYLONGHWIDVALUE"
        code = gen.generate_hardware_id_spoof(0x405000, spoofed, preserve_stack=False)

        assert code[2:10] == b"VERYLONG"

    def test_arm64_hwid_spoof(self) -> None:
        """ARM64 HWID spoof generates valid instruction."""
        gen = LicenseBypassCodeGenerator("arm64", "linux")
        spoofed = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"
        code = gen.generate_hardware_id_spoof(0x405000, spoofed)

        assert len(code) == 8
        assert code[4:] == b"\xc0\x03\x5f\xd6"


class TestNopPatch:
    """Test NOP sled generation for neutralizing protection code."""

    def test_x86_64_nop_generation(self) -> None:
        """x86_64 NOP patch generates correct NOP instructions."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_nop_patch(0x406000, 16)

        assert len(code) == 16
        assert code == b"\x90" * 16

    def test_x86_nop_generation(self) -> None:
        """x86 NOP patch generates correct NOP instructions."""
        gen = LicenseBypassCodeGenerator("x86", "linux")
        code = gen.generate_nop_patch(0x406000, 32)

        assert len(code) == 32
        assert code == b"\x90" * 32

    def test_arm64_nop_generation(self) -> None:
        """ARM64 NOP patch generates valid NOP instructions."""
        gen = LicenseBypassCodeGenerator("arm64", "linux")
        code = gen.generate_nop_patch(0x406000, 16)

        assert len(code) == 16
        nop_instr = b"\x1f\x20\x03\xd5"
        assert code == nop_instr * 4

    def test_arm_nop_generation(self) -> None:
        """ARM NOP patch generates valid NOP instructions."""
        gen = LicenseBypassCodeGenerator("arm", "linux")
        code = gen.generate_nop_patch(0x406000, 12)

        assert len(code) == 12
        nop_instr = b"\x00\xf0\x20\xe3"
        assert code == nop_instr * 3

    def test_nop_patch_tracking(self) -> None:
        """NOP patches are tracked correctly."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        gen.generate_nop_patch(0x406000, 16)

        patches = gen.get_generated_patches()
        assert len(patches) == 1
        assert patches[0]["type"] == "nop_patch"
        assert patches[0]["size"] == 16


class TestConditionalJumpPatch:
    """Test conditional jump modification for license checks."""

    def test_x86_64_always_jump(self) -> None:
        """x86_64 jump patch forces unconditional jump."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_conditional_jump_patch(0x407000, always_jump=True)

        assert len(code) == 1
        assert code == b"\xeb"

    def test_x86_64_never_jump(self) -> None:
        """x86_64 jump patch NOPs out jump."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_conditional_jump_patch(0x407000, always_jump=False)

        assert len(code) == 2
        assert code == b"\x90\x90"

    def test_arm64_always_jump(self) -> None:
        """ARM64 jump patch forces unconditional branch."""
        gen = LicenseBypassCodeGenerator("arm64", "linux")
        code = gen.generate_conditional_jump_patch(0x407000, always_jump=True)

        assert len(code) == 4
        assert code == b"\x00\x00\x00\x14"

    def test_arm64_never_jump(self) -> None:
        """ARM64 jump patch NOPs out branch."""
        gen = LicenseBypassCodeGenerator("arm64", "linux")
        code = gen.generate_conditional_jump_patch(0x407000, always_jump=False)

        assert len(code) == 4
        assert code == b"\x1f\x20\x03\xd5"

    def test_jump_patch_tracking(self) -> None:
        """Jump patches are tracked with correct metadata."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        gen.generate_conditional_jump_patch(0x407000, always_jump=True)

        patches = gen.get_generated_patches()
        assert len(patches) == 1
        assert patches[0]["type"] == "jump_patch"
        assert patches[0]["address"] == 0x407000


class TestReturnValuePatch:
    """Test forced return value patch generation."""

    def test_x86_64_windows_return_value(self) -> None:
        """x86_64 Windows return value patch sets RAX correctly."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_return_value_patch(0x408000, 42, preserve_stack=True)

        assert len(code) > 0
        assert code[:4] == b"\x48\x83\xec\x28"
        assert b"\x48\xc7\xc0" in code
        value_bytes = struct.pack("<I", 42)
        assert value_bytes in code
        assert b"\x48\x83\xc4\x28" in code
        assert code[-1:] == b"\xc3"

    def test_x86_64_linux_return_value(self) -> None:
        """x86_64 Linux return value patch sets RAX correctly."""
        gen = LicenseBypassCodeGenerator("x86_64", "linux")
        code = gen.generate_return_value_patch(0x408000, 255, preserve_stack=True)

        assert code[:1] == b"\x55"
        assert b"\x48\xc7\xc0" in code
        value_bytes = struct.pack("<I", 255)
        assert value_bytes in code

    def test_x86_return_value(self) -> None:
        """x86 return value patch sets EAX correctly."""
        gen = LicenseBypassCodeGenerator("x86", "windows")
        code = gen.generate_return_value_patch(0x408000, 100, preserve_stack=True)

        assert code[:1] == b"\x55"
        assert code[3:4] == b"\xb8"
        value_bytes = struct.pack("<I", 100)
        assert value_bytes in code

    def test_return_value_zero(self) -> None:
        """Return value patch handles zero correctly."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_return_value_patch(0x408000, 0, preserve_stack=False)

        assert b"\x48\xc7\xc0" in code
        assert b"\x00\x00\x00\x00" in code

    def test_return_value_large(self) -> None:
        """Return value patch handles large values correctly."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        large_val = 0xDEADBEEF
        code = gen.generate_return_value_patch(0x408000, large_val, preserve_stack=False)

        value_bytes = struct.pack("<I", large_val)
        assert value_bytes in code

    def test_arm64_return_value(self) -> None:
        """ARM64 return value patch generates valid instruction."""
        gen = LicenseBypassCodeGenerator("arm64", "linux")
        code = gen.generate_return_value_patch(0x408000, 10)

        assert len(code) == 8
        assert code[4:] == b"\xc0\x03\x5f\xd6"


class TestPatchManagement:
    """Test patch tracking, clearing, and export functionality."""

    def test_get_generated_patches_returns_copy(self) -> None:
        """get_generated_patches returns a copy, not reference."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        gen.generate_license_check_bypass(0x401000)

        patches1 = gen.get_generated_patches()
        patches2 = gen.get_generated_patches()

        assert patches1 is not patches2
        assert patches1 == patches2

    def test_clear_patches(self) -> None:
        """clear_patches removes all generated patches."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        gen.generate_license_check_bypass(0x401000)
        gen.generate_trial_extension_patch(0x402000)
        gen.generate_activation_bypass(0x403000)

        assert len(gen.get_generated_patches()) == 3

        gen.clear_patches()

        assert len(gen.get_generated_patches()) == 0

    def test_patch_metadata_complete(self) -> None:
        """Patches contain all required metadata fields."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        gen.generate_license_check_bypass(0x401000, preserve_stack=True)

        patches = gen.get_generated_patches()
        patch = patches[0]

        assert "type" in patch
        assert "address" in patch
        assert "code" in patch
        assert "size" in patch
        assert "description" in patch
        assert "preserve_stack" in patch

        assert patch["type"] == "license_check_bypass"
        assert patch["address"] == 0x401000
        assert isinstance(patch["code"], bytes)
        assert patch["size"] == len(patch["code"])
        assert isinstance(patch["description"], str)


class TestPatchExport:
    """Test patch export functionality in different formats."""

    def test_export_binary_format(self) -> None:
        """Export patches in binary format preserves raw bytes."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        gen.generate_license_check_bypass(0x401000)
        gen.generate_nop_patch(0x402000, 16)

        export = gen.export_patches("binary")

        assert export["architecture"] == "x86_64"
        assert export["platform"] == "windows"
        assert export["format"] == "binary"
        assert len(export["patches"]) == 2
        assert isinstance(export["patches"][0]["code"], bytes)

    def test_export_hex_format(self) -> None:
        """Export patches in hex format converts to hex strings."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_license_check_bypass(0x401000)

        export = gen.export_patches("hex")

        assert export["format"] == "hex"
        assert isinstance(export["patches"][0]["code"], str)
        assert export["patches"][0]["code"] == code.hex()

    def test_export_asm_format(self) -> None:
        """Export patches in ASM format provides disassembly."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        gen.generate_license_check_bypass(0x401000)

        export = gen.export_patches("asm")

        assert export["format"] == "asm"
        assert isinstance(export["patches"][0]["code"], str)

    def test_export_preserves_metadata(self) -> None:
        """Export preserves all patch metadata."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        gen.generate_activation_bypass(0x403000, preserve_stack=True)

        export = gen.export_patches("hex")
        patch = export["patches"][0]

        assert patch["type"] == "activation_bypass"
        assert patch["address"] == 0x403000
        assert patch["size"] > 0
        assert patch["description"]
        assert patch["preserve_stack"] is True


class TestArchitectureSupport:
    """Test support for all declared architectures."""

    @pytest.mark.parametrize(
        "arch,platform",
        [
            ("x86_64", "windows"),
            ("x86_64", "linux"),
            ("x86", "windows"),
            ("x86", "linux"),
            ("arm64", "linux"),
            ("arm", "linux"),
        ],
    )
    def test_all_architectures_generate_code(self, arch: str, platform: str) -> None:
        """All supported architectures generate valid bypass code."""
        gen = LicenseBypassCodeGenerator(arch, platform)

        code = gen.generate_license_check_bypass(0x401000)
        assert len(code) > 0
        assert isinstance(code, bytes)

        code = gen.generate_activation_bypass(0x402000)
        assert len(code) > 0

        code = gen.generate_nop_patch(0x403000, 16)
        assert len(code) >= 4

    def test_unsupported_architecture_raises_error(self) -> None:
        """Unsupported architectures raise ValueError."""
        gen = LicenseBypassCodeGenerator("mips", "linux")

        with pytest.raises(ValueError, match="Unsupported architecture"):
            gen.generate_license_check_bypass(0x401000)


class TestCallingConventions:
    """Test calling convention handling across platforms."""

    def test_windows_x64_shadow_space(self) -> None:
        """Windows x64 calling convention includes shadow space."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        cc_info = gen.get_calling_convention_info()

        assert cc_info["shadow_space"] == 32
        assert cc_info["int_params"][0] == "rcx"

        code = gen.generate_license_check_bypass(0x401000, preserve_stack=True)
        assert b"\x48\x83\xec\x28" in code

    def test_linux_x64_no_shadow_space(self) -> None:
        """Linux x64 calling convention has no shadow space."""
        gen = LicenseBypassCodeGenerator("x86_64", "linux")
        cc_info = gen.get_calling_convention_info()

        assert cc_info["shadow_space"] == 0
        assert cc_info["int_params"][0] == "rdi"

        code = gen.generate_license_check_bypass(0x401000, preserve_stack=True)
        assert b"\x48\x83\xec\x28" not in code

    def test_calling_convention_volatile_registers(self) -> None:
        """Calling conventions define volatile registers correctly."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        cc_info = gen.get_calling_convention_info()

        assert "rax" in cc_info["volatile_regs"]
        assert "rcx" in cc_info["volatile_regs"]
        assert "rbx" in cc_info["nonvolatile_regs"]

    def test_calling_convention_stack_alignment(self) -> None:
        """Calling conventions define stack alignment correctly."""
        gen_win = LicenseBypassCodeGenerator("x86_64", "windows")
        assert gen_win.get_calling_convention_info()["stack_align"] == 16

        gen_x86 = LicenseBypassCodeGenerator("x86", "windows")
        assert gen_x86.get_calling_convention_info()["stack_align"] == 4


class TestRealWorldScenarios:
    """Test real-world licensing bypass scenarios."""

    def test_complete_license_bypass_workflow(self) -> None:
        """Complete workflow: detect, patch, bypass license checks."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")

        license_check_addr = 0x401000
        trial_check_addr = 0x402000
        activation_addr = 0x403000
        serial_addr = 0x404000

        gen.generate_license_check_bypass(license_check_addr)
        gen.generate_trial_extension_patch(trial_check_addr)
        gen.generate_activation_bypass(activation_addr)
        gen.generate_serial_validation_bypass(serial_addr)

        patches = gen.get_generated_patches()
        assert len(patches) == 4

        export = gen.export_patches("hex")
        assert len(export["patches"]) == 4

    def test_protection_removal_with_nops(self) -> None:
        """Protection removal workflow using NOP sleds."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")

        gen.generate_nop_patch(0x401000, 32)
        gen.generate_nop_patch(0x402000, 16)
        gen.generate_nop_patch(0x403000, 64)

        patches = gen.get_generated_patches()
        assert len(patches) == 3
        assert sum(p["size"] for p in patches) == 112

    def test_conditional_logic_manipulation(self) -> None:
        """Manipulate conditional jumps to bypass checks."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")

        gen.generate_conditional_jump_patch(0x401000, always_jump=True)
        gen.generate_conditional_jump_patch(0x402000, always_jump=False)

        patches = gen.get_generated_patches()
        assert len(patches) == 2
        assert "always" in patches[0]["description"]
        assert "never" in patches[1]["description"]

    def test_hardware_locked_license_bypass(self) -> None:
        """Bypass hardware-locked licensing with ID spoofing."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")

        spoofed_hwid = b"VALID-HW"
        code = gen.generate_hardware_id_spoof(0x405000, spoofed_hwid)

        assert len(code) > 0
        assert spoofed_hwid in code

        patches = gen.get_generated_patches()
        assert "hardware_id_spoof" in patches[0]["type"]

    def test_multi_architecture_deployment(self) -> None:
        """Generate bypasses for multiple architectures."""
        gen_x64 = LicenseBypassCodeGenerator("x86_64", "windows")
        gen_x86 = LicenseBypassCodeGenerator("x86", "windows")
        gen_arm = LicenseBypassCodeGenerator("arm64", "linux")

        code_x64 = gen_x64.generate_license_check_bypass(0x401000)
        code_x86 = gen_x86.generate_license_check_bypass(0x401000)
        code_arm = gen_arm.generate_license_check_bypass(0x401000)

        assert len(code_x64) != len(code_x86)
        assert code_x64 != code_arm
        assert all(len(c) > 0 for c in [code_x64, code_x86, code_arm])


class TestCodeCorrectness:
    """Test correctness of generated assembly instructions."""

    def test_x86_64_ret_instruction(self) -> None:
        """All x86_64 functions end with RET."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")

        code1 = gen.generate_license_check_bypass(0x401000)
        code2 = gen.generate_activation_bypass(0x402000)
        code3 = gen.generate_trial_extension_patch(0x403000)

        assert code1[-1:] == b"\xc3"
        assert code2[-1:] == b"\xc3"
        assert code3[-1:] == b"\xc3"

    def test_x86_64_stack_alignment(self) -> None:
        """x86_64 stack operations maintain alignment."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_license_check_bypass(0x401000, preserve_stack=True)

        assert code[:4] == b"\x48\x83\xec\x28"
        assert b"\x48\x83\xc4\x28" in code

    def test_arm64_ret_instruction(self) -> None:
        """All ARM64 functions end with RET."""
        gen = LicenseBypassCodeGenerator("arm64", "linux")

        code1 = gen.generate_license_check_bypass(0x401000)
        code2 = gen.generate_activation_bypass(0x402000)

        assert code1[-4:] == b"\xc0\x03\x5f\xd6"
        assert code2[-4:] == b"\xc0\x03\x5f\xd6"

    def test_nop_instruction_validity(self) -> None:
        """NOP instructions are valid for each architecture."""
        x86_gen = LicenseBypassCodeGenerator("x86", "windows")
        x86_nop = x86_gen.generate_nop_patch(0x401000, 4)
        assert x86_nop == b"\x90\x90\x90\x90"

        arm64_gen = LicenseBypassCodeGenerator("arm64", "linux")
        arm64_nop = arm64_gen.generate_nop_patch(0x401000, 8)
        assert arm64_nop == b"\x1f\x20\x03\xd5" * 2

    def test_register_usage_correctness(self) -> None:
        """Generated code uses correct return register."""
        gen_x64 = LicenseBypassCodeGenerator("x86_64", "windows")
        code_x64 = gen_x64.generate_license_check_bypass(0x401000)
        assert b"\x48\x31\xc0" in code_x64

        gen_x86 = LicenseBypassCodeGenerator("x86", "windows")
        code_x86 = gen_x86.generate_license_check_bypass(0x401000)
        assert b"\x31\xc0" in code_x86


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_zero_size_nop_patch(self) -> None:
        """Zero-size NOP patch generates empty code."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_nop_patch(0x401000, 0)

        assert len(code) == 0

    def test_empty_hwid_spoof(self) -> None:
        """Empty HWID is padded correctly."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        code = gen.generate_hardware_id_spoof(0x405000, b"", preserve_stack=False)

        assert len(code) > 0
        assert b"\x00" * 8 in code

    def test_multiple_clear_patches(self) -> None:
        """Multiple clear_patches calls work correctly."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        gen.generate_license_check_bypass(0x401000)

        gen.clear_patches()
        gen.clear_patches()
        gen.clear_patches()

        assert len(gen.get_generated_patches()) == 0

    def test_patch_generation_after_clear(self) -> None:
        """Patch generation works correctly after clearing."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")

        gen.generate_license_check_bypass(0x401000)
        gen.clear_patches()
        gen.generate_activation_bypass(0x402000)

        patches = gen.get_generated_patches()
        assert len(patches) == 1
        assert patches[0]["type"] == "activation_bypass"

    def test_large_return_value(self) -> None:
        """Large return values are handled correctly."""
        gen = LicenseBypassCodeGenerator("x86_64", "windows")
        max_32bit = 0xFFFFFFFF

        code = gen.generate_return_value_patch(0x408000, max_32bit, preserve_stack=False)

        assert len(code) > 0
        value_bytes = struct.pack("<I", max_32bit)
        assert value_bytes in code
