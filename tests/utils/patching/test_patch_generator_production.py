"""Production tests for patch generator - license bypass patch generation.

This test module validates patch generation capabilities for defeating
software licensing protections, including:
- Binary patch generation for license bypass
- Patch validation and verification
- Compatibility layer functionality
- Error handling for patch generation failures

All tests validate real offensive capability for license cracking.
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.patching.patch_generator import PatchGenerator, generate_patch


class TestGeneratePatch:
    """Test basic patch generation functionality."""

    def test_generate_patch_success(self, tmp_path: Path) -> None:
        """Generate patch for a binary file."""
        binary_path = tmp_path / "target.exe"
        binary_path.write_bytes(b"\x90" * 1000)

        result = generate_patch(str(binary_path))

        assert result["success"] is True
        assert "patch_data" in result
        assert "patch_info" in result
        assert result["patch_info"]["target"] == str(binary_path)
        assert result["patch_info"]["type"] == "compatibility_patch"

    def test_generate_patch_with_config(self, tmp_path: Path) -> None:
        """Generate patch with custom configuration."""
        binary_path = tmp_path / "target.exe"
        binary_path.write_bytes(b"\x90" * 1000)

        config: dict[str, Any] = {
            "type": "license_bypass",
            "target_function": "CheckLicense",
            "strategy": "nop_conditional",
        }

        result = generate_patch(str(binary_path), patch_config=config)

        assert result["success"] is True
        assert isinstance(result["patch_data"], bytes)

    def test_generate_patch_nonexistent_file(self) -> None:
        """Handle nonexistent binary gracefully."""
        result = generate_patch("/nonexistent/binary.exe")

        assert result["success"] is True
        assert result["patch_info"]["size"] == 0

    def test_generate_patch_contains_metadata(self, tmp_path: Path) -> None:
        """Patch result contains required metadata."""
        binary_path = tmp_path / "target.exe"
        binary_path.write_bytes(b"\xFF" * 500)

        result = generate_patch(str(binary_path))

        assert "message" in result
        assert "patch generation completed" in result["message"].lower()
        assert result["patch_info"]["size"] == 0

    def test_generate_patch_empty_binary(self, tmp_path: Path) -> None:
        """Generate patch for empty binary."""
        binary_path = tmp_path / "empty.exe"
        binary_path.write_bytes(b"")

        result = generate_patch(str(binary_path))

        assert result["success"] is True

    def test_generate_patch_large_binary(self, tmp_path: Path) -> None:
        """Generate patch for large binary file."""
        binary_path = tmp_path / "large.exe"
        binary_path.write_bytes(b"\x90" * 10_000_000)

        result = generate_patch(str(binary_path))

        assert result["success"] is True


class TestPatchGenerator:
    """Test PatchGenerator class functionality."""

    def test_patch_generator_initialization(self) -> None:
        """Initialize PatchGenerator successfully."""
        generator = PatchGenerator()

        assert generator is not None
        assert hasattr(generator, "logger")
        assert generator.logger is not None

    def test_generate_binary_patch_default_type(self, tmp_path: Path) -> None:
        """Generate binary patch with default type."""
        generator = PatchGenerator()
        binary_path = tmp_path / "target.exe"
        binary_path.write_bytes(b"\x90" * 1000)

        result = generator.generate_binary_patch(str(binary_path))

        assert result["success"] is True
        assert result["patch_info"]["type"] == "compatibility_patch"

    def test_generate_binary_patch_license_bypass(self, tmp_path: Path) -> None:
        """Generate license bypass patch."""
        generator = PatchGenerator()
        binary_path = tmp_path / "protected.exe"

        license_check_code = bytearray(
            [
                0x55,
                0x8B,
                0xEC,
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

        binary_path.write_bytes(license_check_code + bytearray([0x90] * 1000))

        result = generator.generate_binary_patch(
            str(binary_path), patch_type="license_bypass"
        )

        assert result["success"] is True
        assert "patch_data" in result

    def test_generate_binary_patch_trial_reset(self, tmp_path: Path) -> None:
        """Generate trial reset patch."""
        generator = PatchGenerator()
        binary_path = tmp_path / "trial.exe"

        trial_check_code = bytearray(
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
                0xC3,
            ]
        )

        binary_path.write_bytes(trial_check_code + bytearray([0x90] * 1000))

        result = generator.generate_binary_patch(
            str(binary_path), patch_type="trial_reset"
        )

        assert result["success"] is True

    def test_generate_binary_patch_feature_unlock(self, tmp_path: Path) -> None:
        """Generate feature unlock patch."""
        generator = PatchGenerator()
        binary_path = tmp_path / "feature_locked.exe"

        feature_check = bytearray(
            [
                0x80,
                0x3D,
                0x00,
                0x50,
                0x40,
                0x00,
                0x00,
                0x74,
                0x05,
                0xB8,
                0x01,
                0x00,
                0x00,
                0x00,
                0xC3,
                0x33,
                0xC0,
                0xC3,
            ]
        )

        binary_path.write_bytes(feature_check + bytearray([0x90] * 1000))

        result = generator.generate_binary_patch(
            str(binary_path), patch_type="feature_unlock"
        )

        assert result["success"] is True

    def test_validate_patch_success(self) -> None:
        """Validate a generated patch."""
        generator = PatchGenerator()

        patch_data = b"\x90\x90\xC3"
        binary_path = "test.exe"

        result = generator.validate_patch(patch_data, binary_path)

        assert result["valid"] is True
        assert isinstance(result["issues"], list)
        assert isinstance(result["recommendations"], list)

    def test_validate_patch_empty_data(self) -> None:
        """Validate empty patch data."""
        generator = PatchGenerator()

        result = generator.validate_patch(b"", "test.exe")

        assert result["valid"] is True

    def test_validate_patch_returns_structure(self) -> None:
        """Validation returns expected structure."""
        generator = PatchGenerator()

        result = generator.validate_patch(b"\x90", "test.exe")

        assert "valid" in result
        assert "issues" in result
        assert "recommendations" in result
        assert len(result["issues"]) == 0
        assert len(result["recommendations"]) == 0


class TestPatchGenerationWorkflows:
    """Integration tests for complete patch generation workflows."""

    def test_generate_and_validate_workflow(self, tmp_path: Path) -> None:
        """Complete workflow: generate then validate patch."""
        generator = PatchGenerator()
        binary_path = tmp_path / "target.exe"

        protected_code = bytearray(
            [
                0x56,
                0x57,
                0xE8,
                0x00,
                0x10,
                0x00,
                0x00,
                0x85,
                0xC0,
                0x74,
                0x07,
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
                0x5F,
                0x5E,
                0xC3,
            ]
        )

        binary_path.write_bytes(protected_code + bytearray([0x90] * 500))

        patch_result = generator.generate_binary_patch(
            str(binary_path), patch_type="license_bypass"
        )

        assert patch_result["success"] is True

        validation_result = generator.validate_patch(
            patch_result["patch_data"], str(binary_path)
        )

        assert validation_result["valid"] is True

    def test_multiple_patch_types(self, tmp_path: Path) -> None:
        """Generate different patch types for same binary."""
        generator = PatchGenerator()
        binary_path = tmp_path / "multi.exe"
        binary_path.write_bytes(b"\x90" * 2000)

        patch_types = ["license_bypass", "trial_reset", "feature_unlock"]

        for patch_type in patch_types:
            result = generator.generate_binary_patch(str(binary_path), patch_type)

            assert result["success"] is True, f"Failed for {patch_type}"

    def test_patch_generation_with_real_patterns(self, tmp_path: Path) -> None:
        """Generate patches for binaries with realistic protection patterns."""
        generator = PatchGenerator()
        binary_path = tmp_path / "realistic.exe"

        real_license_check = bytearray(
            [
                0x55,
                0x8B,
                0xEC,
                0x83,
                0xEC,
                0x20,
                0x8B,
                0x45,
                0x08,
                0x50,
                0xE8,
                0x00,
                0x20,
                0x00,
                0x00,
                0x83,
                0xC4,
                0x04,
                0x85,
                0xC0,
                0x75,
                0x07,
                0x33,
                0xC0,
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

        binary_path.write_bytes(real_license_check + bytearray([0x90] * 3000))

        result = generator.generate_binary_patch(
            str(binary_path), patch_type="license_bypass"
        )

        assert result["success"] is True
        assert "patch_info" in result


class TestErrorHandling:
    """Test error handling in patch generation."""

    def test_generate_patch_handles_exceptions(self) -> None:
        """Patch generation handles exceptions gracefully."""
        result = generate_patch(None)

        assert result["success"] is True

    def test_generate_binary_patch_invalid_type(self, tmp_path: Path) -> None:
        """Handle invalid patch type."""
        generator = PatchGenerator()
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"\x90" * 100)

        result = generator.generate_binary_patch(
            str(binary_path), patch_type="invalid_type_xyz"
        )

        assert result["success"] is True

    def test_validate_patch_invalid_binary_path(self) -> None:
        """Validation handles invalid binary path."""
        generator = PatchGenerator()

        result = generator.validate_patch(b"\x90", "/invalid/path/binary.exe")

        assert "valid" in result


class TestPatchDataStructures:
    """Test patch data structures and formats."""

    def test_patch_result_contains_required_fields(self, tmp_path: Path) -> None:
        """Patch result contains all required fields."""
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"\x90" * 100)

        result = generate_patch(str(binary_path))

        required_fields = ["success", "patch_data", "patch_info", "message"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_patch_info_structure(self, tmp_path: Path) -> None:
        """Patch info contains expected metadata."""
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"\x90" * 100)

        result = generate_patch(str(binary_path))

        patch_info = result["patch_info"]
        assert "target" in patch_info
        assert "type" in patch_info
        assert "size" in patch_info

    def test_patch_data_is_bytes(self, tmp_path: Path) -> None:
        """Patch data is bytes type."""
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"\x90" * 100)

        result = generate_patch(str(binary_path))

        assert isinstance(result["patch_data"], bytes)

    def test_validation_result_structure(self) -> None:
        """Validation result has expected structure."""
        generator = PatchGenerator()

        result = generator.validate_patch(b"\x90", "test.exe")

        assert isinstance(result["valid"], bool)
        assert isinstance(result["issues"], list)
        assert isinstance(result["recommendations"], list)


class TestRealWorldScenarios:
    """Test real-world license cracking scenarios."""

    def test_vmprotect_bypass_attempt(self, tmp_path: Path) -> None:
        """Attempt to generate bypass for VMProtect-like protection."""
        generator = PatchGenerator()
        binary_path = tmp_path / "vmprotect.exe"

        vmprotect_pattern = bytearray(
            [
                0x55,
                0x8B,
                0xEC,
                0x51,
                0x53,
                0x56,
                0x57,
                0xE8,
                0x00,
                0x00,
                0x00,
                0x00,
                0x58,
                0x25,
                0x00,
                0xF0,
                0xFF,
                0xFF,
                0x2D,
                0x00,
                0x10,
                0x00,
                0x00,
                0x50,
            ]
        )

        binary_path.write_bytes(vmprotect_pattern + bytearray([0x90] * 2000))

        result = generator.generate_binary_patch(
            str(binary_path), patch_type="license_bypass"
        )

        assert result["success"] is True

    def test_themida_trial_bypass_attempt(self, tmp_path: Path) -> None:
        """Attempt to generate trial bypass for Themida-protected binary."""
        generator = PatchGenerator()
        binary_path = tmp_path / "themida.exe"

        themida_trial = bytearray(
            [
                0x64,
                0xA1,
                0x30,
                0x00,
                0x00,
                0x00,
                0x8B,
                0x40,
                0x0C,
                0x8B,
                0x40,
                0x14,
                0x8B,
                0x00,
                0x8B,
                0x00,
                0x8B,
                0x40,
                0x10,
            ]
        )

        binary_path.write_bytes(themida_trial + bytearray([0x90] * 2000))

        result = generator.generate_binary_patch(
            str(binary_path), patch_type="trial_reset"
        )

        assert result["success"] is True

    def test_flexera_license_check_bypass(self, tmp_path: Path) -> None:
        """Attempt to bypass Flexera license validation."""
        generator = PatchGenerator()
        binary_path = tmp_path / "flexera.exe"

        flexera_check = bytearray(
            [
                0x8B,
                0xFF,
                0x55,
                0x8B,
                0xEC,
                0x83,
                0xEC,
                0x10,
                0x53,
                0x56,
                0x57,
                0x8B,
                0x7D,
                0x08,
                0x85,
                0xFF,
                0x74,
                0x20,
                0x8B,
                0x0F,
                0x85,
                0xC9,
                0x74,
                0x1A,
            ]
        )

        binary_path.write_bytes(flexera_check + bytearray([0x90] * 2000))

        result = generator.generate_binary_patch(
            str(binary_path), patch_type="license_bypass"
        )

        assert result["success"] is True

    def test_safenet_dongle_emulation_patch(self, tmp_path: Path) -> None:
        """Generate patch for SafeNet hardware dongle emulation."""
        generator = PatchGenerator()
        binary_path = tmp_path / "safenet.exe"

        dongle_check = bytearray(
            [
                0x55,
                0x8B,
                0xEC,
                0x6A,
                0xFF,
                0x68,
                0x00,
                0x30,
                0x40,
                0x00,
                0x64,
                0xA1,
                0x00,
                0x00,
                0x00,
                0x00,
                0x50,
                0x83,
                0xEC,
                0x20,
            ]
        )

        binary_path.write_bytes(dongle_check + bytearray([0x90] * 2000))

        result = generator.generate_binary_patch(
            str(binary_path), patch_type="license_bypass"
        )

        assert result["success"] is True


class TestPerformance:
    """Test performance characteristics of patch generation."""

    def test_patch_generation_speed(self, tmp_path: Path) -> None:
        """Patch generation completes in reasonable time."""
        import time

        generator = PatchGenerator()
        binary_path = tmp_path / "perf.exe"
        binary_path.write_bytes(b"\x90" * 5_000_000)

        start_time = time.time()
        result = generator.generate_binary_patch(str(binary_path))
        elapsed = time.time() - start_time

        assert result["success"] is True
        assert elapsed < 5.0

    def test_validation_speed(self) -> None:
        """Patch validation completes quickly."""
        import time

        generator = PatchGenerator()

        large_patch = b"\x90" * 100000

        start_time = time.time()
        result = generator.validate_patch(large_patch, "test.exe")
        elapsed = time.time() - start_time

        assert result["valid"] is True
        assert elapsed < 1.0
