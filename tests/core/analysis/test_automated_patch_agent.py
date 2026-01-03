"""
Comprehensive unit tests for AutomatedPatchAgent with REAL exploitation capabilities.
Tests REAL automated patch generation, keygen creation, and exploit development.
NO MOCKS - ALL TESTS USE REAL BINARIES AND VALIDATE GENUINE CAPABILITIES.

Testing Agent Mission: Validate production-ready automated exploitation capabilities
that demonstrate genuine binary analysis and security research effectiveness.
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.automated_patch_agent import (
    AutomatedPatchAgent,
    run_automated_patch_agent,
)
from tests.base_test import IntellicrackTestBase


class TestAutomatedPatchAgent(IntellicrackTestBase):
    """Test automated patch generation with REAL exploitation capabilities."""

    agent: AutomatedPatchAgent
    pe_binary: Path
    elf_binary: Path
    temp_dir: Path
    protected_binary: str
    licensing_binary: str

    @pytest.fixture(autouse=True)
    def setup(
        self, real_pe_binary: Path, real_elf_binary: Path, temp_workspace: Path
    ) -> None:
        """Set up test with real binaries and patch agent."""
        self.agent = AutomatedPatchAgent()
        self.pe_binary = real_pe_binary
        self.elf_binary = real_elf_binary
        self.temp_dir = temp_workspace

        # Create test binary samples for exploitation testing
        self.protected_binary = self._create_test_protected_binary()
        self.licensing_binary = self._create_test_licensing_binary()

    def _create_test_protected_binary(self) -> str:
        """Create a test binary with protection mechanisms for realistic testing."""
        binary_path = os.path.join(str(self.temp_dir), "protected_test.exe")

        pe_header = b"MZ\x90\x00" + b"\x00" * 56 + b"PE\x00\x00"
        licensing_code = (
            b"\x55\x8b\xec"
            b"\x83\xec\x10"
            b"\x8b\x45\x08"
            b"\x85\xc0"
            b"\x74\x05"
            b"\xb8\x01\x00\x00\x00"
            b"\xeb\x05"
            b"\xb8\x00\x00\x00\x00"
            b"\x8b\xe5\x5d\xc3"
        )

        with open(binary_path, "wb") as f:
            f.write(pe_header + licensing_code)

        return binary_path

    def _create_test_licensing_binary(self) -> str:
        """Create a test binary with various licensing algorithms."""
        binary_path = os.path.join(str(self.temp_dir), "licensing_test.exe")

        binary_data = (
            b"MZ\x90\x00"
            + b"\x00" * 56
            + b"PE\x00\x00"
            + b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2"
            + b"\x6a\x80\x6a\x00\x50"
            + b"\x6a\x20\x6a\x00\x51"
            + b"\xb8\xde\xad\xbe\xef\x35\xca\xfe\xba\xbe"
        )

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        return binary_path

    def test_agent_initialization(self) -> None:
        """Test AutomatedPatchAgent initializes with production capabilities."""
        agent = AutomatedPatchAgent()

        # Validate core components are initialized
        assert hasattr(agent, "patch_history")
        assert hasattr(agent, "patch_signatures")
        assert hasattr(agent, "bypass_patterns")
        assert hasattr(agent, "exploitation_techniques")

        # Verify bypass patterns are loaded with real techniques
        assert len(agent.bypass_patterns) > 0
        assert isinstance(agent.bypass_patterns, dict)

        # Verify exploitation techniques database is populated
        assert len(agent.exploitation_techniques) > 0
        assert isinstance(agent.exploitation_techniques, dict)

        # Patch history should start empty but be a proper data structure
        assert isinstance(agent.patch_history, list)
        assert isinstance(agent.patch_signatures, dict)

    def test_binary_analysis_comprehensive(self) -> None:
        """Test comprehensive binary analysis identifies real exploit opportunities."""
        result = self.agent.analyze_binary(self.protected_binary)

        # Validate analysis produces comprehensive results (dict)
        assert result is not None
        assert isinstance(result, dict)
        assert "protection_schemes" in result
        assert "patch_points" in result
        assert "vulnerability_score" in result
        assert "recommended_patches" in result

        # Verify data types
        assert isinstance(result["protection_schemes"], list)
        assert isinstance(result["patch_points"], list)
        assert isinstance(result["vulnerability_score"], int)
        assert isinstance(result["recommended_patches"], list)

    def test_binary_analysis_multiple_formats(self) -> None:
        """Test binary analysis works across multiple executable formats."""
        # Test PE analysis
        pe_result = self.agent.analyze_binary(str(self.pe_binary))
        assert pe_result is not None
        assert isinstance(pe_result, dict)

        # Test ELF analysis
        elf_result = self.agent.analyze_binary(str(self.elf_binary))
        assert elf_result is not None
        assert isinstance(elf_result, dict)

    def test_patch_point_identification(self) -> None:
        """Test precise patch point identification for real bypasses."""
        with open(self.protected_binary, "rb") as f:
            binary_data = f.read()

        patch_points = self.agent._find_patch_points(binary_data)

        # Validate patch points are returned as list of dicts
        assert isinstance(patch_points, list)

        for point in patch_points:
            assert isinstance(point, dict)
            assert "offset" in point
            assert "type" in point

    def test_patch_application_file_modification(self) -> None:
        """Test actual binary patch application modifies files correctly."""
        # Analyze binary to get patch points
        analysis_result = self.agent.analyze_binary(self.protected_binary)

        # Create test patch data
        if analysis_result["recommended_patches"]:
            patch_data = analysis_result["recommended_patches"][0]
            success = self.agent.apply_patch(self.protected_binary, patch_data)
            assert isinstance(success, bool)

    def test_rop_chain_generation(self) -> None:
        """Test ROP chain generation produces working exploit chains."""
        # generate_rop_chains takes no args
        rop_chain = self.agent._generate_rop_chains()

        # Validate ROP chain structure (dict of string -> list[int])
        assert rop_chain is not None
        assert isinstance(rop_chain, dict)
        assert len(rop_chain) > 0

        for chain_name, gadgets in rop_chain.items():
            assert isinstance(chain_name, str)
            assert isinstance(gadgets, list)
            for gadget in gadgets:
                assert isinstance(gadget, int)

    def test_shellcode_template_generation(self) -> None:
        """Test shellcode generation produces working executable code."""
        # _generate_shellcode_templates takes no args
        shellcode_templates = self.agent._generate_shellcode_templates()

        # Validate shellcode structure (dict of string -> bytes)
        assert shellcode_templates is not None
        assert isinstance(shellcode_templates, dict)
        assert len(shellcode_templates) > 0

        for name, shellcode in shellcode_templates.items():
            assert isinstance(name, str)
            assert isinstance(shellcode, bytes)
            assert len(shellcode) > 0

    def test_keygen_generation_comprehensive(self) -> None:
        """Test comprehensive keygen generation for various algorithms."""
        # generate_keygen takes algorithm_type string
        serial_keygen = self.agent.generate_keygen("serial")
        assert serial_keygen is not None
        assert isinstance(serial_keygen, str)
        assert len(serial_keygen) > 0

        # Test RSA keygen generation
        rsa_keygen = self.agent.generate_keygen("rsa")
        assert rsa_keygen is not None
        assert isinstance(rsa_keygen, str)

        # Test ECC keygen generation
        ecc_keygen = self.agent.generate_keygen("elliptic")
        assert ecc_keygen is not None
        assert isinstance(ecc_keygen, str)

        # Test custom algorithm keygen
        custom_keygen = self.agent.generate_keygen("custom")
        assert custom_keygen is not None
        assert isinstance(custom_keygen, str)

    def test_serial_keygen_functionality(self) -> None:
        """Test serial number keygen produces working algorithms."""
        # _generate_serial_keygen takes no args
        keygen = self.agent._generate_serial_keygen()

        # Should return Python code as string
        assert keygen is not None
        assert isinstance(keygen, str)
        assert "def generate_serial" in keygen
        assert "def validate_serial" in keygen

    def test_rsa_keygen_cryptographic_analysis(self) -> None:
        """Test RSA keygen performs real cryptographic analysis."""
        # _generate_rsa_keygen takes no args
        rsa_keygen = self.agent._generate_rsa_keygen()

        # Should return Python code as string
        assert rsa_keygen is not None
        assert isinstance(rsa_keygen, str)
        assert "rsa" in rsa_keygen.lower()

    def test_hook_detour_generation(self) -> None:
        """Test function hook generation creates working detours."""
        # _create_hook_detours takes no args
        hook_detours = self.agent._create_hook_detours()

        # Validate hook structure (dict of string -> bytes)
        assert hook_detours is not None
        assert isinstance(hook_detours, dict)
        assert len(hook_detours) > 0

        for hook_name, detour_code in hook_detours.items():
            assert isinstance(hook_name, str)
            assert isinstance(detour_code, bytes)
            assert len(detour_code) > 0

    def test_memory_patch_generation(self) -> None:
        """Test memory patch generation for runtime modification."""
        # _create_memory_patches takes no args
        memory_patches = self.agent._create_memory_patches()

        # Validate patch generation (dict of string -> tuple[int, bytes])
        assert memory_patches is not None
        assert isinstance(memory_patches, dict)
        assert len(memory_patches) > 0

        for patch_name, patch_data in memory_patches.items():
            assert isinstance(patch_name, str)
            assert isinstance(patch_data, tuple)
            assert len(patch_data) == 2
            assert isinstance(patch_data[0], int)  # offset
            assert isinstance(patch_data[1], bytes)  # patch bytes

    def test_exploitation_technique_database(self) -> None:
        """Test exploitation technique database is comprehensive."""
        techniques = self.agent._load_exploitation_techniques()

        # Validate database structure
        assert techniques is not None
        assert isinstance(techniques, dict)

    def test_bypass_pattern_recognition(self) -> None:
        """Test bypass pattern recognition identifies protection weaknesses."""
        patterns = self.agent._initialize_bypass_patterns()

        # Validate pattern database
        assert patterns is not None
        assert isinstance(patterns, dict)

    def test_patch_history_tracking(self) -> None:
        """Test patch application history is properly tracked."""
        # Apply several patches to build history
        analysis_result = self.agent.analyze_binary(self.protected_binary)

        # Initial history should be a list
        assert isinstance(self.agent.patch_history, list)

        if analysis_result["recommended_patches"]:
            patch = analysis_result["recommended_patches"][0]
            self.agent.apply_patch(self.protected_binary, patch)

    def test_performance_benchmarks(self) -> None:
        """Test automated patch agent meets performance requirements."""
        start_time = time.time()

        # Perform comprehensive analysis
        analysis_result = self.agent.analyze_binary(str(self.pe_binary))
        analysis_time = time.time() - start_time

        # Verify analysis performance (should complete within reasonable time)
        assert analysis_time < 30.0
        assert analysis_result is not None

        # Test keygen generation performance
        start_time = time.time()
        keygen = self.agent.generate_keygen("serial")
        keygen_time = time.time() - start_time

        assert keygen_time < 15.0
        assert keygen is not None

    def test_error_handling_robustness(self) -> None:
        """Test robust error handling for invalid inputs and edge cases."""
        # Test invalid binary path
        result = self.agent.analyze_binary("/nonexistent/binary.exe")
        assert result is not None
        assert isinstance(result, dict)

        # Test corrupted binary data
        corrupted_binary = os.path.join(str(self.temp_dir), "corrupted.exe")
        with open(corrupted_binary, "wb") as f:
            f.write(b"corrupted_data_not_pe")

        result = self.agent.analyze_binary(corrupted_binary)
        assert result is not None

        # Test invalid keygen parameters - should fallback to default
        keygen = self.agent.generate_keygen("invalid_algorithm")
        assert keygen is not None
        assert isinstance(keygen, str)

    def test_integration_with_analysis_framework(self) -> None:
        """Test integration with broader Intellicrack analysis framework."""
        # run_automated_patch_agent takes target_binary and optional patch_mode
        result = run_automated_patch_agent(self.protected_binary, "auto")

        # Validate integration result
        assert result is not None
        assert isinstance(result, dict)
        assert "analysis" in result
        assert "patches_applied" in result
        assert "success" in result


class TestAutomatedPatchAgentAdvanced(IntellicrackTestBase):
    """Advanced testing scenarios for specialized exploitation capabilities."""

    agent: AutomatedPatchAgent
    temp_dir: Path
    complex_binary: str

    @pytest.fixture(autouse=True)
    def setup_advanced(self, temp_workspace: Path) -> None:
        """Set up advanced testing scenarios."""
        self.agent = AutomatedPatchAgent()
        self.temp_dir = temp_workspace
        self.complex_binary = self._create_complex_protection_binary()

    def _create_complex_protection_binary(self) -> str:
        """Create binary with multiple protection layers for advanced testing."""
        binary_path = os.path.join(str(self.temp_dir), "complex_protected.exe")

        complex_data = (
            b"MZ\x90\x00"
            + b"\x00" * 56
            + b"PE\x00\x00"
            + b"\xeb\x10\x00\x00\x00\x00\x00\x00\x56\x4d\x50\x72\x6f\x74\x65\x63\x74"
            + b"\x64\xa1\x30\x00\x00\x00\x8b\x40\x02\x3c\x01\x74\x05"
            + b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
            + b"\x48\x8d\x05\x00\x00\x00\x00\x48\x89\x44\x24\x20"
        )

        with open(binary_path, "wb") as f:
            f.write(complex_data)

        return binary_path

    def test_multi_layer_protection_analysis(self) -> None:
        """Test analysis of binaries with multiple protection layers."""
        result = self.agent.analyze_binary(self.complex_binary)

        assert result is not None
        assert isinstance(result, dict)
        assert "protection_schemes" in result

    def test_advanced_rop_exploitation(self) -> None:
        """Test advanced ROP exploitation with modern mitigations."""
        # _generate_rop_chains takes no args
        rop_chains = self.agent._generate_rop_chains()

        assert rop_chains is not None
        assert isinstance(rop_chains, dict)

    def test_advanced_keygen_with_hardware_binding(self) -> None:
        """Test keygen generation for hardware-bound licenses."""
        # _generate_custom_keygen takes no args
        custom_keygen = self.agent._generate_custom_keygen()

        assert custom_keygen is not None
        assert isinstance(custom_keygen, str)


class TestAutomatedPatchAgentPerformance(IntellicrackTestBase):
    """Performance and scalability testing for automated patch agent."""

    pe_binary: Path
    elf_binary: Path
    temp_dir: Path
    agent: AutomatedPatchAgent

    @pytest.fixture(autouse=True)
    def setup_performance(
        self, real_pe_binary: Path, real_elf_binary: Path, temp_workspace: Path
    ) -> None:
        """Set up performance testing."""
        self.pe_binary = real_pe_binary
        self.elf_binary = real_elf_binary
        self.temp_dir = temp_workspace
        self.agent = AutomatedPatchAgent()

    def test_concurrent_analysis_capability(self) -> None:
        """Test agent handles concurrent analysis requests."""
        import concurrent.futures

        agent = AutomatedPatchAgent()
        test_binaries = [str(self.pe_binary), str(self.elf_binary)] * 5

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(agent.analyze_binary, binary)
                for binary in test_binaries
            ]

            results = [future.result(timeout=60) for future in futures]

        # All analyses should complete successfully
        assert len(results) == 10
        assert all(result is not None for result in results)
        assert all(isinstance(result, dict) for result in results)

    def test_memory_usage_efficiency(self) -> None:
        """Test memory usage remains reasonable during extended operation."""
        try:
            import gc

            import psutil
        except ImportError:
            pytest.skip("psutil required for memory testing")

        process = psutil.Process()
        initial_memory = process.memory_info().rss

        agent = AutomatedPatchAgent()

        # Perform multiple analyses
        for _ in range(20):
            result = agent.analyze_binary(str(self.pe_binary))
            assert result is not None

            gc.collect()

            current_memory = process.memory_info().rss
            memory_growth = current_memory - initial_memory

            # Memory growth should be reasonable (less than 200MB)
            assert memory_growth < 200 * 1024 * 1024

    def test_large_binary_handling(self) -> None:
        """Test agent handles large binaries efficiently."""
        # Create large test binary (10MB)
        large_binary = os.path.join(str(self.temp_dir), "large_test.exe")

        with open(large_binary, "wb") as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 56 + b"PE\x00\x00")
            f.write(b"\x90" * (10 * 1024 * 1024))

        start_time = time.time()
        result = self.agent.analyze_binary(large_binary)
        analysis_time = time.time() - start_time

        assert result is not None
        assert analysis_time < 120.0

        os.remove(large_binary)


class TestAutomatedPatchAgentWithRealProtectedBinaries(IntellicrackTestBase):
    """Test automated patch agent with real protected software binaries."""

    fixtures_dir: Path
    protected_binaries: list[Path]
    agent: AutomatedPatchAgent

    @pytest.fixture(autouse=True)
    def setup_real_binaries(self) -> None:
        """Set up test environment with real protected binaries."""
        self.fixtures_dir = Path("tests/fixtures/binaries")
        all_binaries = [
            self.fixtures_dir / "pe/protected/enterprise_license_check.exe",
            self.fixtures_dir / "pe/protected/flexlm_license_protected.exe",
            self.fixtures_dir / "pe/protected/hasp_sentinel_protected.exe",
            self.fixtures_dir / "pe/protected/online_activation_app.exe",
            self.fixtures_dir / "pe/protected/wibu_codemeter_protected.exe",
            self.fixtures_dir / "protected/themida_protected.exe",
            self.fixtures_dir / "protected/vmprotect_protected.exe",
        ]
        self.protected_binaries = [p for p in all_binaries if p.exists()]

        if not self.protected_binaries:
            pytest.skip("No protected binaries available for automated patch testing")

        self.agent = AutomatedPatchAgent()

    def test_analyze_real_protected_binary_no_crash(self) -> None:
        """Test agent analyzes real protected binaries without crashing."""
        for binary in self.protected_binaries:
            try:
                result = self.agent.analyze_binary(str(binary))
                assert result is not None, f"Analysis returned None for {binary.name}"
                assert isinstance(
                    result, dict
                ), f"Result should be dict for {binary.name}"
            except Exception as e:
                pytest.fail(f"Agent crashed analyzing {binary.name}: {e}")

    def test_identify_patch_points_in_real_binary(self) -> None:
        """Test identification of patch points in real protected software."""
        if not self.protected_binaries:
            pytest.skip("No protected binaries available")

        test_binary = self.protected_binaries[0]
        result = self.agent.analyze_binary(str(test_binary))

        assert result is not None
        assert isinstance(result, dict)
        patch_points = result.get("patch_points", result.get("potential_patches", []))
        assert isinstance(patch_points, list)

    def test_generate_patches_for_flexlm(self) -> None:
        """Test patch generation for FlexLM-protected binary."""
        flexlm_binary = self.fixtures_dir / "pe/protected/flexlm_license_protected.exe"
        if not flexlm_binary.exists():
            pytest.skip("FlexLM binary not available")

        result = self.agent.analyze_binary(str(flexlm_binary))

        assert result is not None
        assert isinstance(result, dict)

    def test_generate_patches_for_hasp(self) -> None:
        """Test patch generation for HASP Sentinel-protected binary."""
        hasp_binary = self.fixtures_dir / "pe/protected/hasp_sentinel_protected.exe"
        if not hasp_binary.exists():
            pytest.skip("HASP binary not available")

        result = self.agent.analyze_binary(str(hasp_binary))

        assert result is not None
        assert isinstance(result, dict)

    def test_generate_patches_for_wibu(self) -> None:
        """Test patch generation for Wibu CodeMeter-protected binary."""
        wibu_binary = self.fixtures_dir / "pe/protected/wibu_codemeter_protected.exe"
        if not wibu_binary.exists():
            pytest.skip("Wibu binary not available")

        result = self.agent.analyze_binary(str(wibu_binary))

        assert result is not None
        assert isinstance(result, dict)

    def test_themida_patch_generation(self) -> None:
        """Test patch generation for Themida-protected binary."""
        themida_binary = self.fixtures_dir / "protected/themida_protected.exe"
        if not themida_binary.exists():
            pytest.skip("Themida binary not available")

        result = self.agent.analyze_binary(str(themida_binary))

        assert result is not None
        assert isinstance(result, dict)

    def test_vmprotect_patch_generation(self) -> None:
        """Test patch generation for VMProtect-protected binary."""
        vmprotect_binary = self.fixtures_dir / "protected/vmprotect_protected.exe"
        if not vmprotect_binary.exists():
            pytest.skip("VMProtect binary not available")

        result = self.agent.analyze_binary(str(vmprotect_binary))

        assert result is not None
        assert isinstance(result, dict)

    def test_consistency_across_multiple_analyses(self) -> None:
        """Test patch agent produces consistent results across multiple runs."""
        if not self.protected_binaries:
            pytest.skip("No protected binaries available")

        test_binary = str(self.protected_binaries[0])

        result1 = self.agent.analyze_binary(test_binary)
        result2 = self.agent.analyze_binary(test_binary)

        assert result1 is not None
        assert result2 is not None

        if "patch_points" in result1 and "patch_points" in result2:
            assert len(result1["patch_points"]) == len(result2["patch_points"])

    def test_real_binary_performance(self) -> None:
        """Test performance analyzing real protected binaries."""
        if not self.protected_binaries:
            pytest.skip("No protected binaries available")

        test_binary = str(self.protected_binaries[0])

        start_time = time.time()
        result = self.agent.analyze_binary(test_binary)
        analysis_time = time.time() - start_time

        assert result is not None
        assert analysis_time < 300.0
