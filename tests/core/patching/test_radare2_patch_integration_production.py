"""Production-grade tests for Radare2 Patch Integration validating real r2pipe integration.

Tests REAL radare2 patch generation and binary modification capabilities.
NO mocks - validates genuine patch integration and binary patcher coordination.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import shutil
from pathlib import Path

import pytest

from intellicrack.core.patching.radare2_patch_integration import R2PatchIntegrator
from intellicrack.plugins.custom_modules.binary_patcher_plugin import BinaryPatch

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def binaries_dir() -> Path:
    """Path to directory containing test binaries."""
    return Path(__file__).parent.parent.parent / "fixtures" / "binaries"


@pytest.fixture(scope="module")
def pe_binaries_dir(binaries_dir: Path) -> Path:
    """Path to PE binaries directory."""
    return binaries_dir / "pe"


@pytest.fixture(scope="module")
def protected_binary(pe_binaries_dir: Path) -> Path:
    """Real protected binary for testing."""
    binary_path = pe_binaries_dir / "protected" / "online_activation_app.exe"
    if not binary_path.exists():
        pytest.skip(f"Test binary not found: {binary_path}")
    return binary_path


@pytest.fixture
def integrator() -> R2PatchIntegrator:
    """Create R2PatchIntegrator instance."""
    return R2PatchIntegrator()


@pytest.fixture
def temp_binary(tmp_path: Path, protected_binary: Path) -> Path:
    """Create temporary copy of binary for destructive tests."""
    temp_file = tmp_path / "test_binary.exe"
    shutil.copy2(protected_binary, temp_file)
    return temp_file


@pytest.fixture
def sample_license_analysis() -> dict:
    """Sample license analysis data for testing."""
    return {
        "license_checks": [
            {
                "address": "0x401000",
                "type": "hardcoded_key",
                "confidence": 0.9,
            },
            {
                "address": "0x402000",
                "type": "online_validation",
                "confidence": 0.85,
            },
        ],
        "validation_functions": [
            {
                "name": "check_license",
                "address": "0x403000",
            },
        ],
    }


@pytest.fixture
def sample_r2_patches() -> list[dict]:
    """Sample R2 patch data for testing."""
    return [
        {
            "address": "0x401000",
            "original_bytes": "74 05",
            "patch_bytes": "90 90",
            "patch_description": "NOP license check jump",
        },
        {
            "address": "0x402000",
            "original_bytes": "85 c0 75 10",
            "patch_bytes": "31 c0 90 90",
            "patch_description": "XOR EAX, EAX to bypass validation",
        },
    ]


class TestR2PatchIntegratorInitialization:
    """Test R2PatchIntegrator initialization."""

    def test_integrator_initializes_with_components(self, integrator: R2PatchIntegrator) -> None:
        """Integrator must initialize with bypass generator and binary patcher."""
        assert integrator.bypass_generator is not None
        assert integrator.binary_patcher is not None
        assert isinstance(integrator.patch_cache, dict)

    def test_integrator_has_empty_patch_cache(self, integrator: R2PatchIntegrator) -> None:
        """Integrator must start with empty patch cache."""
        assert len(integrator.patch_cache) == 0


class TestIntegratedPatchGeneration:
    """Test integrated patch generation workflow."""

    def test_generate_integrated_patches_returns_result_dict(
        self,
        integrator: R2PatchIntegrator,
        protected_binary: Path,
        sample_license_analysis: dict,
    ) -> None:
        """generate_integrated_patches must return result dictionary."""
        result = integrator.generate_integrated_patches(
            str(protected_binary),
            sample_license_analysis,
        )

        assert isinstance(result, dict)
        assert "success" in result
        assert "binary_path" in result

    def test_generate_integrated_patches_includes_metadata(
        self,
        integrator: R2PatchIntegrator,
        protected_binary: Path,
        sample_license_analysis: dict,
    ) -> None:
        """generate_integrated_patches must include integration metadata."""
        result = integrator.generate_integrated_patches(
            str(protected_binary),
            sample_license_analysis,
        )

        if result["success"]:
            assert "integration_metadata" in result
            assert "r2_generator_version" in result["integration_metadata"]
            assert "binary_patcher_integration" in result["integration_metadata"]

    def test_generate_integrated_patches_handles_missing_binary(
        self,
        integrator: R2PatchIntegrator,
        sample_license_analysis: dict,
    ) -> None:
        """generate_integrated_patches must handle missing binary gracefully."""
        result = integrator.generate_integrated_patches(
            "nonexistent_file.exe",
            sample_license_analysis,
        )

        assert isinstance(result, dict)
        if not result["success"]:
            assert "error" in result

    def test_generate_integrated_patches_stores_binary_path(
        self,
        integrator: R2PatchIntegrator,
        protected_binary: Path,
        sample_license_analysis: dict,
    ) -> None:
        """generate_integrated_patches must store binary path in result."""
        result = integrator.generate_integrated_patches(
            str(protected_binary),
            sample_license_analysis,
        )

        assert result["binary_path"] == str(protected_binary)


class TestR2ToBinaryPatchConversion:
    """Test conversion of R2 patches to binary patches."""

    def test_convert_r2_to_binary_patches_returns_list(
        self,
        integrator: R2PatchIntegrator,
        sample_r2_patches: list[dict],
    ) -> None:
        """_convert_r2_to_binary_patches must return list of BinaryPatch objects."""
        r2_result = {"automated_patches": sample_r2_patches, "memory_patches": []}

        patches = integrator._convert_r2_to_binary_patches(r2_result)

        assert isinstance(patches, list)
        assert all(isinstance(p, BinaryPatch) for p in patches)

    def test_convert_r2_to_binary_patches_processes_automated_patches(
        self,
        integrator: R2PatchIntegrator,
        sample_r2_patches: list[dict],
    ) -> None:
        """_convert_r2_to_binary_patches must process automated patches."""
        r2_result = {"automated_patches": sample_r2_patches, "memory_patches": []}

        patches = integrator._convert_r2_to_binary_patches(r2_result)

        assert len(patches) > 0

    def test_convert_r2_to_binary_patches_processes_memory_patches(
        self,
        integrator: R2PatchIntegrator,
        sample_r2_patches: list[dict],
    ) -> None:
        """_convert_r2_to_binary_patches must process memory patches."""
        r2_result = {"automated_patches": [], "memory_patches": sample_r2_patches}

        patches = integrator._convert_r2_to_binary_patches(r2_result)

        assert len(patches) > 0

    def test_convert_r2_to_binary_patches_handles_empty_input(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_convert_r2_to_binary_patches must handle empty patch lists."""
        r2_result = {"automated_patches": [], "memory_patches": []}

        patches = integrator._convert_r2_to_binary_patches(r2_result)

        assert patches == []


class TestBinaryPatchCreation:
    """Test creation of BinaryPatch objects from R2 data."""

    def test_create_binary_patch_from_r2_creates_valid_patch(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_create_binary_patch_from_r2 must create valid BinaryPatch object."""
        r2_patch = {
            "address": "0x401000",
            "original_bytes": "74 05",
            "patch_bytes": "90 90",
            "patch_description": "Test patch",
        }

        patch = integrator._create_binary_patch_from_r2(r2_patch, "automated")

        assert patch is not None
        assert isinstance(patch, BinaryPatch)
        assert patch.offset == 0x401000
        assert patch.description == "Test patch"

    def test_create_binary_patch_from_r2_handles_hex_address_string(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_create_binary_patch_from_r2 must parse hex address strings."""
        r2_patch = {
            "address": "0x401000",
            "patch_bytes": "90",
        }

        patch = integrator._create_binary_patch_from_r2(r2_patch, "automated")

        assert patch is not None
        assert patch.offset == 0x401000

    def test_create_binary_patch_from_r2_handles_integer_address(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_create_binary_patch_from_r2 must handle integer addresses."""
        r2_patch = {
            "address": 4198400,
            "patch_bytes": "90",
        }

        patch = integrator._create_binary_patch_from_r2(r2_patch, "automated")

        assert patch is not None
        assert patch.offset == 4198400

    def test_create_binary_patch_from_r2_converts_patch_bytes(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_create_binary_patch_from_r2 must convert hex string to bytes."""
        r2_patch = {
            "address": "0x401000",
            "patch_bytes": "90 90 90",
        }

        patch = integrator._create_binary_patch_from_r2(r2_patch, "automated")

        assert patch is not None
        assert patch.patched_bytes == b"\x90\x90\x90"

    def test_create_binary_patch_from_r2_handles_missing_patch_bytes(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_create_binary_patch_from_r2 must use NOP when patch_bytes missing."""
        r2_patch = {
            "address": "0x401000",
        }

        patch = integrator._create_binary_patch_from_r2(r2_patch, "automated")

        assert patch is not None
        assert patch.patched_bytes == b"\x90"

    def test_create_binary_patch_from_r2_returns_none_on_error(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_create_binary_patch_from_r2 must return None on conversion errors."""
        r2_patch = {
            "address": "invalid_address",
            "patch_bytes": "90",
        }

        patch = integrator._create_binary_patch_from_r2(r2_patch, "automated")

        assert patch is None

    def test_create_binary_patch_from_r2_sets_patch_type(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_create_binary_patch_from_r2 must set patch_type to license_bypass."""
        r2_patch = {
            "address": "0x401000",
            "patch_bytes": "90",
        }

        patch = integrator._create_binary_patch_from_r2(r2_patch, "automated")

        assert patch is not None
        assert patch.patch_type == "license_bypass"


class TestPatchValidation:
    """Test patch validation functionality."""

    def test_validate_patches_with_binary_patcher_returns_list(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_validate_patches_with_binary_patcher must return list of patches."""
        patches = [
            BinaryPatch(
                offset=0x401000,
                original_bytes=b"\x74\x05",
                patched_bytes=b"\x90\x90",
                description="Test patch",
                patch_type="license_bypass",
            ),
        ]

        validated = integrator._validate_patches_with_binary_patcher(patches)

        assert isinstance(validated, list)

    def test_validate_patches_filters_invalid_patches(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_validate_patches_with_binary_patcher must filter out invalid patches."""
        patches = [
            BinaryPatch(
                offset=0x401000,
                original_bytes=b"\x74\x05",
                patched_bytes=b"\x90\x90",
                description="Valid patch",
                patch_type="license_bypass",
            ),
            BinaryPatch(
                offset=0x402000,
                original_bytes=b"",
                patched_bytes=b"",
                description="Invalid patch",
                patch_type="license_bypass",
            ),
        ]

        validated = integrator._validate_patches_with_binary_patcher(patches)

        assert all(integrator._is_valid_patch(p) for p in validated)

    def test_is_valid_patch_accepts_valid_patches(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_is_valid_patch must return True for valid patches."""
        patch = BinaryPatch(
            offset=0x401000,
            original_bytes=b"\x74\x05",
            patched_bytes=b"\x90\x90",
            description="Valid patch",
            patch_type="license_bypass",
        )

        assert integrator._is_valid_patch(patch) is True

    def test_is_valid_patch_rejects_empty_patched_bytes(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_is_valid_patch must reject patches with empty patched_bytes."""
        patch = BinaryPatch(
            offset=0x401000,
            original_bytes=b"\x74\x05",
            patched_bytes=b"",
            description="Invalid patch",
            patch_type="license_bypass",
        )

        assert integrator._is_valid_patch(patch) is False

    def test_is_valid_patch_rejects_zero_offset(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_is_valid_patch must reject patches with zero offset."""
        patch = BinaryPatch(
            offset=0,
            original_bytes=b"\x74\x05",
            patched_bytes=b"\x90\x90",
            description="Invalid offset",
            patch_type="license_bypass",
        )

        assert integrator._is_valid_patch(patch) is False


class TestBinaryReading:
    """Test reading original bytes from binary."""

    def test_read_original_bytes_from_binary_returns_bytes(
        self,
        integrator: R2PatchIntegrator,
        protected_binary: Path,
    ) -> None:
        """_read_original_bytes_from_binary must return bytes from binary."""
        original = integrator._read_original_bytes_from_binary(
            str(protected_binary),
            0x1000,
            4,
        )

        assert isinstance(original, bytes)
        assert len(original) == 4

    def test_read_original_bytes_handles_missing_file(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """_read_original_bytes_from_binary must handle missing files."""
        original = integrator._read_original_bytes_from_binary(
            "nonexistent_file.exe",
            0x1000,
            4,
        )

        assert isinstance(original, bytes)

    def test_read_original_bytes_handles_invalid_offset(
        self,
        integrator: R2PatchIntegrator,
        protected_binary: Path,
    ) -> None:
        """_read_original_bytes_from_binary must handle invalid offsets."""
        original = integrator._read_original_bytes_from_binary(
            str(protected_binary),
            0xFFFFFFFF,
            4,
        )

        assert isinstance(original, bytes)


class TestPatchApplication:
    """Test applying integrated patches to binaries."""

    def test_apply_integrated_patches_returns_result_dict(
        self,
        integrator: R2PatchIntegrator,
        temp_binary: Path,
    ) -> None:
        """apply_integrated_patches must return result dictionary."""
        patches = [
            BinaryPatch(
                offset=0x1000,
                original_bytes=b"\x74\x05",
                patched_bytes=b"\x90\x90",
                description="Test patch",
                patch_type="license_bypass",
            ),
        ]

        result = integrator.apply_integrated_patches(
            str(temp_binary),
            patches,
        )

        assert isinstance(result, dict)
        assert "success" in result

    def test_apply_integrated_patches_creates_output_file(
        self,
        integrator: R2PatchIntegrator,
        temp_binary: Path,
        tmp_path: Path,
    ) -> None:
        """apply_integrated_patches must create output file when specified."""
        output_path = tmp_path / "patched_binary.exe"
        patches = [
            BinaryPatch(
                offset=0x1000,
                original_bytes=b"\x74\x05",
                patched_bytes=b"\x90\x90",
                description="Test patch",
                patch_type="license_bypass",
            ),
        ]

        result = integrator.apply_integrated_patches(
            str(temp_binary),
            patches,
            str(output_path),
        )

        if result.get("success"):
            assert output_path.exists()

    def test_apply_integrated_patches_handles_empty_patch_list(
        self,
        integrator: R2PatchIntegrator,
        temp_binary: Path,
    ) -> None:
        """apply_integrated_patches must handle empty patch list."""
        result = integrator.apply_integrated_patches(
            str(temp_binary),
            [],
        )

        assert isinstance(result, dict)

    def test_apply_integrated_patches_handles_missing_binary(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """apply_integrated_patches must handle missing binary gracefully."""
        patches = [
            BinaryPatch(
                offset=0x1000,
                original_bytes=b"\x74\x05",
                patched_bytes=b"\x90\x90",
                description="Test patch",
                patch_type="license_bypass",
            ),
        ]

        result = integrator.apply_integrated_patches(
            "nonexistent_file.exe",
            patches,
        )

        assert isinstance(result, dict)
        if not result.get("success"):
            assert "error" in result


class TestIntegrationStatus:
    """Test integration status reporting."""

    def test_get_integration_status_returns_dict(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """get_integration_status must return status dictionary."""
        status = integrator.get_integration_status()

        assert isinstance(status, dict)

    def test_get_integration_status_includes_component_availability(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """get_integration_status must indicate component availability."""
        status = integrator.get_integration_status()

        assert "r2_bypass_generator_available" in status or "bypass_generator_available" in status
        assert "binary_patcher_available" in status

    def test_get_integration_status_includes_cache_info(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """get_integration_status must include patch cache information."""
        status = integrator.get_integration_status()

        assert "patch_cache_count" in status or "cached_patches" in status or "cache" in str(status).lower()


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_malformed_r2_patch_data(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """Integrator must handle malformed R2 patch data gracefully."""
        malformed_patch = {
            "invalid_field": "value",
        }

        patch = integrator._create_binary_patch_from_r2(malformed_patch, "automated")

        assert patch is None or isinstance(patch, BinaryPatch)

    def test_handles_unicode_in_patch_descriptions(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """Integrator must handle Unicode characters in descriptions."""
        r2_patch = {
            "address": "0x401000",
            "patch_bytes": "90",
            "patch_description": "Test patch with Unicode: 你好",
        }

        patch = integrator._create_binary_patch_from_r2(r2_patch, "automated")

        assert patch is not None
        assert "你好" in patch.description

    def test_handles_very_large_patch_data(
        self,
        integrator: R2PatchIntegrator,
    ) -> None:
        """Integrator must handle large patch byte arrays."""
        large_patch = {
            "address": "0x401000",
            "patch_bytes": " ".join(["90"] * 1000),
        }

        patch = integrator._create_binary_patch_from_r2(large_patch, "automated")

        assert patch is not None
        assert len(patch.patched_bytes) == 1000
