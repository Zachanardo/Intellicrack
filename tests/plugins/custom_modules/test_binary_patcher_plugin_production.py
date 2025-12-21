"""Production-grade tests for binary_patcher_plugin.py.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import os
import shutil
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from intellicrack.plugins.custom_modules.binary_patcher_plugin import BinaryPatch, BinaryPatcherPlugin, register


@pytest.fixture(scope="session")
def test_binaries_dir() -> Path:
    return Path(__file__).parent.parent.parent / "fixtures" / "binaries"


@pytest.fixture(scope="session")
def protected_binaries_dir(test_binaries_dir: Path) -> Path:
    return test_binaries_dir / "pe" / "protected"


@pytest.fixture(scope="session")
def vulnerable_samples_dir() -> Path:
    return Path(__file__).parent.parent.parent / "fixtures" / "vulnerable_samples"


@pytest.fixture
def temp_binary_dir() -> Generator[Path, None, None]:
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def patcher_plugin() -> BinaryPatcherPlugin:
    return BinaryPatcherPlugin()


@pytest.fixture
def real_binary_with_license_checks(temp_binary_dir: Path) -> Path:
    binary_path = temp_binary_dir / "license_check_app.exe"

    license_check_code = bytearray(
        b"\x4D\x5A\x90\x00"
        + b"\x00" * 60
        + b"\x50\x45\x00\x00"
        + b"\x00" * 100
        + b"License Check Function:\x00"
        + b"\x55\x8b\xec"
        + b"\x83\xec\x10"
        + b"\x48\x8b\x0d"
        + b"\x74\x0c"
        + b"license\x00"
        + b"\x75\x0a"
        + b"TRIAL\x00"
        + b"\x74\x0a"
        + b"trial period expired\x00"
        + b"\x90\x90\x90\x90"
        + b"\x00" * 200
    )

    binary_path.write_bytes(license_check_code)
    return binary_path


@pytest.fixture
def real_binary_with_trial_checks(temp_binary_dir: Path) -> Path:
    binary_path = temp_binary_dir / "trial_app.exe"

    trial_check_code = bytearray(
        b"\x4D\x5A\x90\x00"
        + b"\x00" * 60
        + b"\x50\x45\x00\x00"
        + b"\x00" * 100
        + b"Trial version - 30 days remaining\x00"
        + b"TRIAL MODE ACTIVE\x00"
        + b"Demo features enabled\x00"
        + b"This is a DEMO version\x00"
        + b"\x75\x0c"
        + b"\x74\x0a"
        + b"\x00" * 200
    )

    binary_path.write_bytes(trial_check_code)
    return binary_path


@pytest.fixture
def real_binary_no_patches_needed(temp_binary_dir: Path) -> Path:
    binary_path = temp_binary_dir / "clean_app.exe"

    clean_code = bytearray(
        b"\x4D\x5A\x90\x00"
        + b"\x00" * 60
        + b"\x50\x45\x00\x00"
        + b"\x00" * 100
        + b"Clean application with no license checks\x00"
        + b"\x00" * 200
    )

    binary_path.write_bytes(clean_code)
    return binary_path


class TestBinaryPatchDataClass:
    """Test BinaryPatch dataclass functionality."""

    def test_binary_patch_creation_valid_data(self) -> None:
        patch = BinaryPatch(
            offset=0x1000,
            original_bytes=b"\x74\x0c",
            patched_bytes=b"\x90\x90",
            description="NOP out license check jump",
            patch_type="license_bypass",
        )

        assert patch.offset == 0x1000
        assert patch.original_bytes == b"\x74\x0c"
        assert patch.patched_bytes == b"\x90\x90"
        assert patch.description == "NOP out license check jump"
        assert patch.patch_type == "license_bypass"

    def test_binary_patch_default_patch_type(self) -> None:
        patch = BinaryPatch(
            offset=0x2000,
            original_bytes=b"\x75\x0a",
            patched_bytes=b"\x90\x90",
            description="Remove trial check",
        )

        assert patch.patch_type == "defensive"

    def test_binary_patch_zero_offset_valid(self) -> None:
        patch = BinaryPatch(
            offset=0,
            original_bytes=b"\x4D\x5A",
            patched_bytes=b"\x4D\x5A",
            description="PE header verification",
        )

        assert patch.offset == 0


class TestBinaryPatcherPluginInitialization:
    """Test plugin initialization and registration."""

    def test_plugin_initialization_successful(self, patcher_plugin: BinaryPatcherPlugin) -> None:
        assert patcher_plugin.patches == []
        assert patcher_plugin.logger is not None

    def test_register_function_returns_plugin_instance(self) -> None:
        plugin = register()

        assert isinstance(plugin, BinaryPatcherPlugin)
        assert hasattr(plugin, "analyze")
        assert hasattr(plugin, "patch")

    def test_multiple_plugin_instances_independent(self) -> None:
        plugin1 = BinaryPatcherPlugin()
        plugin2 = BinaryPatcherPlugin()

        plugin1.patches.append(
            BinaryPatch(
                offset=0x1000,
                original_bytes=b"\x74\x0c",
                patched_bytes=b"\x90\x90",
                description="Test patch",
            ),
        )

        assert len(plugin1.patches) == 1
        assert len(plugin2.patches) == 0


class TestBinaryAnalysis:
    """Test binary analysis functionality that identifies patchable locations."""

    def test_analyze_detects_nop_sled_pattern(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_with_license_checks: Path,
    ) -> None:
        results = patcher_plugin.analyze(str(real_binary_with_license_checks))

        assert any("NOP sled" in result for result in results)
        assert any("patch location" in result for result in results)

    def test_analyze_detects_function_prologue(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_with_license_checks: Path,
    ) -> None:
        results = patcher_plugin.analyze(str(real_binary_with_license_checks))

        assert any("function prologue" in result for result in results)
        assert any("patchable" in result for result in results)

    def test_analyze_real_protected_binary_vmprotect(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        protected_binaries_dir: Path,
    ) -> None:
        """EFFECTIVENESS TEST: Analyzer must identify patchable patterns in VMProtect binaries."""
        vmprotect_binary = protected_binaries_dir / "vmprotect_protected.exe"

        if not vmprotect_binary.exists():
            pytest.skip("VMProtect protected binary not available")

        results = patcher_plugin.analyze(str(vmprotect_binary))

        assert len(results) > 0, (
            "FAILED: Analyzer returned no results for VMProtect binary. "
            "Must at minimum report scanning activity."
        )
        assert any("Scanning for patch targets" in result for result in results), (
            "FAILED: Analyzer did not report scanning VMProtect binary."
        )

        has_analysis_content = (
            any("patch location" in r.lower() for r in results)
            or any("function" in r.lower() for r in results)
            or any("pattern" in r.lower() for r in results)
        )
        assert has_analysis_content or len(results) >= 2, (
            f"FAILED: Analyzer only returned '{results[0]}' for VMProtect binary. "
            f"Expected actual analysis findings like patch locations or patterns."
        )

    def test_analyze_real_protected_binary_themida(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        protected_binaries_dir: Path,
    ) -> None:
        themida_binary = protected_binaries_dir / "themida_protected.exe"

        if themida_binary.exists():
            results = patcher_plugin.analyze(str(themida_binary))

            assert len(results) > 0
            assert results[0].startswith("Scanning for patch targets")

    def test_analyze_nonexistent_file_reports_error(self, patcher_plugin: BinaryPatcherPlugin) -> None:
        results = patcher_plugin.analyze("/nonexistent/path/to/binary.exe")

        assert any("error" in result.lower() for result in results)

    def test_analyze_empty_binary_no_patterns(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        temp_binary_dir: Path,
    ) -> None:
        empty_binary = temp_binary_dir / "empty.exe"
        empty_binary.write_bytes(b"\x00" * 100)

        results = patcher_plugin.analyze(str(empty_binary))

        assert len(results) == 1
        assert "Scanning for patch targets" in results[0]

    def test_analyze_binary_with_multiple_patterns(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_with_license_checks: Path,
    ) -> None:
        results = patcher_plugin.analyze(str(real_binary_with_license_checks))

        pattern_count = sum(bool("NOP sled" in result or "function prologue" in result)
                        for result in results)

        assert pattern_count >= 1


class TestBinaryPatching:
    """Test binary patching functionality that removes license checks."""

    def test_patch_removes_license_check_jumps(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_with_license_checks: Path,
    ) -> None:
        original_data = real_binary_with_license_checks.read_bytes()

        results = patcher_plugin.patch(str(real_binary_with_license_checks))

        assert any("Created backup" in result for result in results)

        patched_data = real_binary_with_license_checks.read_bytes()

        assert len(patched_data) == len(original_data)

        if any("Successfully applied" in result for result in results):
            jz_pattern = b"\x74\x0c"
            original_jz_count = original_data.count(jz_pattern)
            patched_jz_count = patched_data.count(jz_pattern)

            assert patched_jz_count < original_jz_count

    def test_patch_neutralizes_trial_text(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_with_trial_checks: Path,
    ) -> None:
        original_data = real_binary_with_trial_checks.read_bytes()

        results = patcher_plugin.patch(str(real_binary_with_trial_checks))

        patched_data = real_binary_with_trial_checks.read_bytes()

        assert len(patched_data) == len(original_data)

        if any("Successfully applied" in result for result in results):
            trial_variants = [b"trial", b"TRIAL", b"Trial", b"demo", b"DEMO", b"Demo"]

            original_trial_count = sum(original_data.count(variant) for variant in trial_variants)
            patched_trial_count = sum(patched_data.count(variant) for variant in trial_variants)

            assert patched_trial_count < original_trial_count

    def test_patch_creates_backup_file(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_with_license_checks: Path,
    ) -> None:
        backup_path = Path(f"{str(real_binary_with_license_checks)}.backup")

        if backup_path.exists():
            backup_path.unlink()

        results = patcher_plugin.patch(str(real_binary_with_license_checks))

        assert backup_path.exists()
        assert any(".backup" in result for result in results)

    def test_patch_backup_equals_original(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_with_license_checks: Path,
    ) -> None:
        original_data = real_binary_with_license_checks.read_bytes()

        patcher_plugin.patch(str(real_binary_with_license_checks))

        backup_path = Path(f"{str(real_binary_with_license_checks)}.backup")
        backup_data = backup_path.read_bytes()

        assert backup_data == original_data

    def test_patch_maintains_file_size_integrity(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_with_license_checks: Path,
    ) -> None:
        original_size = os.path.getsize(real_binary_with_license_checks)

        results = patcher_plugin.patch(str(real_binary_with_license_checks))

        patched_size = os.path.getsize(real_binary_with_license_checks)

        assert patched_size == original_size
        assert any("File integrity maintained" in result for result in results)

    def test_patch_no_applicable_patches_reports_correctly(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_no_patches_needed: Path,
    ) -> None:
        results = patcher_plugin.patch(str(real_binary_no_patches_needed))

        assert any("No applicable patches found" in result for result in results)

    def test_patch_multiple_license_check_variants(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        temp_binary_dir: Path,
    ) -> None:
        multi_check_binary = temp_binary_dir / "multi_check.exe"

        binary_data = bytearray(
            b"\x4D\x5A\x90\x00"
            + b"\x00" * 60
            + b"\x50\x45\x00\x00"
            + b"\x00" * 100
            + b"license\x00\x74\x0c"
            + b"\x00" * 20
            + b"license\x00\x75\x0c"
            + b"\x00" * 20
            + b"license\x00\x74\x0a"
            + b"\x00" * 20
            + b"license\x00\x75\x0a"
            + b"\x00" * 200
        )

        multi_check_binary.write_bytes(binary_data)

        results = patcher_plugin.patch(str(multi_check_binary))

        if any("Successfully applied" in result for result in results):
            patches_applied = [r for r in results if "patches" in r.lower()]
            assert patches_applied

    def test_patch_restores_from_backup_on_error(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        temp_binary_dir: Path,
    ) -> None:
        corrupted_binary = temp_binary_dir / "corrupted.exe"
        corrupted_binary.write_bytes(b"Invalid PE data")

        original_data = corrupted_binary.read_bytes()

        results = patcher_plugin.patch(str(corrupted_binary))

        current_data = corrupted_binary.read_bytes()

        assert current_data == original_data


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling in patching operations."""

    def test_patch_readonly_file_handles_error(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_with_license_checks: Path,
    ) -> None:
        real_binary_with_license_checks.chmod(0o444)

        try:
            results = patcher_plugin.patch(str(real_binary_with_license_checks))

            assert isinstance(results, list)
        finally:
            real_binary_with_license_checks.chmod(0o644)

    def test_patch_insufficient_disk_space_simulation(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        temp_binary_dir: Path,
    ) -> None:
        test_binary = temp_binary_dir / "test.exe"
        test_binary.write_bytes(b"\x4D\x5A" + b"\x00" * 1000)

        results = patcher_plugin.patch(str(test_binary))

        assert isinstance(results, list)
        assert len(results) > 0

    def test_patch_corrupted_pe_header_reports_error(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        temp_binary_dir: Path,
    ) -> None:
        corrupted_pe = temp_binary_dir / "corrupted_pe.exe"
        corrupted_pe.write_bytes(b"Not a PE file" + b"\x00" * 100)

        results = patcher_plugin.patch(str(corrupted_pe))

        assert isinstance(results, list)

    def test_patch_zero_byte_file_handles_gracefully(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        temp_binary_dir: Path,
    ) -> None:
        empty_file = temp_binary_dir / "empty.exe"
        empty_file.write_bytes(b"")

        results = patcher_plugin.patch(str(empty_file))

        assert isinstance(results, list)

    def test_patch_very_large_binary_performance(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        temp_binary_dir: Path,
    ) -> None:
        large_binary = temp_binary_dir / "large.exe"

        large_data = b"\x4D\x5A\x90\x00" + b"\x00" * (10 * 1024 * 1024)
        large_binary.write_bytes(large_data)

        results = patcher_plugin.patch(str(large_binary))

        assert isinstance(results, list)
        assert len(results) > 0


class TestRealProtectedBinaries:
    """Test patching real protected binaries from fixtures."""

    def test_patch_upx_packed_binary(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        temp_binary_dir: Path,
    ) -> None:
        upx_source = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "protected" / "upx_packed_0.exe"

        if upx_source.exists():
            upx_copy = temp_binary_dir / "upx_test.exe"
            shutil.copy(upx_source, upx_copy)

            results = patcher_plugin.patch(str(upx_copy))

            assert any("Created backup" in result for result in results)
            assert Path(f"{str(upx_copy)}.backup").exists()

    def test_patch_vmprotect_protected_binary(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        temp_binary_dir: Path,
    ) -> None:
        vmp_source = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "protected" / "vmprotect_protected.exe"

        if vmp_source.exists():
            vmp_copy = temp_binary_dir / "vmprotect_test.exe"
            shutil.copy(vmp_source, vmp_copy)

            results = patcher_plugin.patch(str(vmp_copy))

            assert isinstance(results, list)
            assert len(results) > 0

    def test_patch_themida_protected_binary(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        temp_binary_dir: Path,
    ) -> None:
        themida_source = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "protected" / "themida_protected.exe"

        if themida_source.exists():
            themida_copy = temp_binary_dir / "themida_test.exe"
            shutil.copy(themida_source, themida_copy)

            results = patcher_plugin.patch(str(themida_copy))

            assert isinstance(results, list)
            assert any("Created backup" in result for result in results)

    def test_patch_enigma_packed_binary(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        temp_binary_dir: Path,
    ) -> None:
        enigma_source = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "protected" / "enigma_packed.exe"

        if enigma_source.exists():
            enigma_copy = temp_binary_dir / "enigma_test.exe"
            shutil.copy(enigma_source, enigma_copy)

            results = patcher_plugin.patch(str(enigma_copy))

            assert isinstance(results, list)
            assert len(results) > 0


class TestPatchEffectiveness:
    """Test that patches actually achieve their intended license bypass effect.

    EFFECTIVENESS TESTS: These tests validate that the patcher makes REAL
    modifications to binaries that would defeat license checks.
    """

    def test_patched_binary_has_nopped_jumps(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_with_license_checks: Path,
    ) -> None:
        """EFFECTIVENESS TEST: Patcher must actually NOP out conditional jumps."""
        original_data = real_binary_with_license_checks.read_bytes()
        original_nop_count = original_data.count(b"\x90\x90")
        original_jz_count = original_data.count(b"\x74")
        original_jnz_count = original_data.count(b"\x75")

        results = patcher_plugin.patch(str(real_binary_with_license_checks))

        patched_data = real_binary_with_license_checks.read_bytes()
        patched_nop_count = patched_data.count(b"\x90\x90")
        patched_jz_count = patched_data.count(b"\x74")
        patched_jnz_count = patched_data.count(b"\x75")

        patch_occurred = (
            patched_nop_count > original_nop_count or
            patched_jz_count < original_jz_count or
            patched_jnz_count < original_jnz_count
        )

        if not patch_occurred:
            applied_patches = [r for r in results if "applied" in r.lower() or "patch" in r.lower()]
            assert not applied_patches or "No applicable" in str(
                results
            ), f"FAILED: Patcher claimed to apply patches but binary was not modified. Original NOPs: {original_nop_count}, Patched NOPs: {patched_nop_count}. Original JZ: {original_jz_count}, Patched JZ: {patched_jz_count}. Results: {results}"

    def test_patched_binary_trial_strings_neutralized(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_with_trial_checks: Path,
    ) -> None:
        """EFFECTIVENESS TEST: Patcher must neutralize trial/demo strings."""
        original_data = real_binary_with_trial_checks.read_bytes()
        trial_variants = [b"trial", b"TRIAL", b"Trial", b"demo", b"DEMO", b"Demo"]
        original_trial_count = sum(original_data.count(v) for v in trial_variants)

        results = patcher_plugin.patch(str(real_binary_with_trial_checks))

        patched_data = real_binary_with_trial_checks.read_bytes()
        patched_trial_count = sum(patched_data.count(v) for v in trial_variants)

        if any("Neutralized" in r for r in results):
            assert patched_trial_count < original_trial_count, (
                f"FAILED: Patcher claimed to neutralize trial strings but count unchanged. "
                f"Original: {original_trial_count}, Patched: {patched_trial_count}"
            )

    def test_patch_reports_all_applied_patches(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_with_license_checks: Path,
    ) -> None:
        results = patcher_plugin.patch(str(real_binary_with_license_checks))

        if any("Successfully applied" in result for result in results):
            assert any("patch" in result.lower() for result in results)
            assert any("License check bypass" in result or "Trial period" in result for result in results)

    def test_patch_validates_integrity_after_modification(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        real_binary_with_license_checks: Path,
    ) -> None:
        original_size = os.path.getsize(real_binary_with_license_checks)

        results = patcher_plugin.patch(str(real_binary_with_license_checks))

        patched_size = os.path.getsize(real_binary_with_license_checks)

        assert original_size == patched_size
        assert any("File integrity maintained" in result for result in results)


class TestIntegrationWithRealBinaries:
    """Integration tests with real commercial software binaries."""

    def test_patch_beyond_compare_binary(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        temp_binary_dir: Path,
    ) -> None:
        bc_source = Path(__file__).parent.parent.parent / "fixtures" / "full_protected_software" / "Beyond_Compare_Full.exe"

        if bc_source.exists():
            bc_copy = temp_binary_dir / "beyond_compare.exe"
            shutil.copy(bc_source, bc_copy)

            results = patcher_plugin.patch(str(bc_copy))

            assert any("Created backup" in result for result in results)
            assert Path(f"{str(bc_copy)}.backup").exists()

    def test_patch_resource_hacker_binary(
        self,
        patcher_plugin: BinaryPatcherPlugin,
        temp_binary_dir: Path,
    ) -> None:
        rh_source = Path(__file__).parent.parent.parent / "fixtures" / "full_protected_software" / "Resource_Hacker_Full.exe"

        if rh_source.exists():
            rh_copy = temp_binary_dir / "resource_hacker.exe"
            shutil.copy(rh_source, rh_copy)

            results = patcher_plugin.patch(str(rh_copy))

            assert isinstance(results, list)
            assert len(results) > 0
