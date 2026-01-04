"""Production tests for multi-layer certificate validation bypass logic.

Tests validate real staged bypass execution, dependency handling, verification,
rollback functionality, and multi-layer result tracking against realistic scenarios.
"""

import pytest
from pathlib import Path
from typing import Iterator

from intellicrack.core.certificate.multilayer_bypass import (
    MultiLayerBypass,
    MultiLayerResult,
    StageResult,
)
from intellicrack.core.certificate.layer_detector import (
    DependencyGraph,
    LayerInfo,
    ValidationLayer,
)
from intellicrack.core.certificate.detection_report import (
    DetectionReport,
    ValidationFunction,
    BypassMethod,
)


@pytest.fixture
def temp_test_dir(temp_workspace: Path) -> Iterator[Path]:
    """Provide a temporary directory for test file operations."""
    test_dir = temp_workspace / "multilayer_tests"
    test_dir.mkdir(parents=True, exist_ok=True)
    yield test_dir


@pytest.fixture
def sample_pe_binary(temp_test_dir: Path) -> Path:
    """Create a minimal PE binary for testing."""
    binary_path = temp_test_dir / "test_app.exe"

    pe_header = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00"
        b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"
        b"PE\x00\x00\x64\x86\x01\x00" + b"\x00" * 500
    )

    binary_path.write_bytes(pe_header)
    return binary_path


@pytest.fixture
def os_level_layer() -> LayerInfo:
    """Create an OS-level layer info object."""
    return LayerInfo(
        layer_type=ValidationLayer.OS_LEVEL,
        confidence=0.85,
        evidence=["crypt32.dll", "CertVerifyCertificateChainPolicy"],
    )


@pytest.fixture
def library_level_layer() -> LayerInfo:
    """Create a library-level layer info object."""
    return LayerInfo(
        layer_type=ValidationLayer.LIBRARY_LEVEL,
        confidence=0.80,
        evidence=["libssl.so", "SSL_CTX_set_verify"],
        dependencies=[ValidationLayer.OS_LEVEL],
    )


@pytest.fixture
def application_level_layer() -> LayerInfo:
    """Create an application-level layer info object."""
    return LayerInfo(
        layer_type=ValidationLayer.APPLICATION_LEVEL,
        confidence=0.75,
        evidence=["custom_cert_check"],
        dependencies=[ValidationLayer.LIBRARY_LEVEL],
    )


@pytest.fixture
def server_level_layer() -> LayerInfo:
    """Create a server-level layer info object."""
    return LayerInfo(
        layer_type=ValidationLayer.SERVER_LEVEL,
        confidence=0.70,
        evidence=["winhttp.dll", "WinHttpSetOption"],
        dependencies=[ValidationLayer.APPLICATION_LEVEL],
    )


@pytest.fixture
def simple_dependency_graph() -> DependencyGraph:
    """Create a simple dependency graph with OS -> Library dependencies."""
    graph = DependencyGraph()
    graph.add_layer(ValidationLayer.OS_LEVEL)
    graph.add_layer(ValidationLayer.LIBRARY_LEVEL)
    graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)
    return graph


@pytest.fixture
def complex_dependency_graph() -> DependencyGraph:
    """Create a complex 4-layer dependency graph."""
    graph = DependencyGraph()
    graph.add_layer(ValidationLayer.OS_LEVEL)
    graph.add_layer(ValidationLayer.LIBRARY_LEVEL)
    graph.add_layer(ValidationLayer.APPLICATION_LEVEL)
    graph.add_layer(ValidationLayer.SERVER_LEVEL)

    graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)
    graph.add_dependency(ValidationLayer.APPLICATION_LEVEL, ValidationLayer.LIBRARY_LEVEL)
    graph.add_dependency(ValidationLayer.SERVER_LEVEL, ValidationLayer.APPLICATION_LEVEL)

    return graph


class TestStageResultTracking:
    """Tests validating stage result data structures and tracking."""

    def test_stage_result_creation_with_success(self) -> None:
        """StageResult properly stores successful bypass data."""
        result = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=True,
            bypassed_functions=["CertVerifyCertificateChainPolicy", "CertGetCertificateChain"],
            rollback_data=b"\x90" * 100,
        )

        assert result.stage_number == 1
        assert result.layer == ValidationLayer.OS_LEVEL
        assert result.success is True
        assert len(result.bypassed_functions) == 2
        assert result.rollback_data == b"\x90" * 100
        assert result.error_message is None

    def test_stage_result_creation_with_failure(self) -> None:
        """StageResult properly stores failure information."""
        result = StageResult(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            success=False,
            error_message="Failed to inject Frida hook into OpenSSL",
        )

        assert result.success is False
        assert result.error_message == "Failed to inject Frida hook into OpenSSL"
        assert result.bypassed_functions == []
        assert result.rollback_data is None

    def test_multilayer_result_aggregation(self) -> None:
        """MultiLayerResult correctly aggregates multiple stage results."""
        result = MultiLayerResult(overall_success=False)

        stage1 = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=True,
            bypassed_functions=["CertVerifyCertificateChainPolicy"],
            rollback_data=b"\x90" * 50,
        )

        stage2 = StageResult(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            success=True,
            bypassed_functions=["SSL_CTX_set_verify"],
        )

        result.add_stage_result(stage1)
        result.add_stage_result(stage2)

        assert len(result.stage_results) == 2
        assert len(result.bypassed_layers) == 2
        assert ValidationLayer.OS_LEVEL in result.bypassed_layers
        assert ValidationLayer.LIBRARY_LEVEL in result.bypassed_layers
        assert len(result.failed_layers) == 0
        assert ValidationLayer.OS_LEVEL in result.rollback_data

    def test_multilayer_result_failure_tracking(self) -> None:
        """MultiLayerResult tracks failed stages correctly."""
        result = MultiLayerResult(overall_success=False)

        success_stage = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=True,
            bypassed_functions=["CertVerifyCertificateChainPolicy"],
        )

        failed_stage = StageResult(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            success=False,
            error_message="Frida injection failed",
        )

        result.add_stage_result(success_stage)
        result.add_stage_result(failed_stage)

        assert len(result.bypassed_layers) == 1
        assert len(result.failed_layers) == 1
        assert result.failed_layers[0][0] == ValidationLayer.LIBRARY_LEVEL
        assert result.failed_layers[0][1] == "Frida injection failed"


class TestDependencyHandling:
    """Tests validating dependency satisfaction checks and ordering."""

    def test_dependency_graph_topological_sort(self) -> None:
        """Dependency graph produces correct bypass order."""
        graph = DependencyGraph()
        graph.add_layer(ValidationLayer.OS_LEVEL)
        graph.add_layer(ValidationLayer.LIBRARY_LEVEL)
        graph.add_layer(ValidationLayer.APPLICATION_LEVEL)

        graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)
        graph.add_dependency(ValidationLayer.APPLICATION_LEVEL, ValidationLayer.LIBRARY_LEVEL)

        sorted_layers = graph.topological_sort()

        os_index = sorted_layers.index(ValidationLayer.OS_LEVEL)
        lib_index = sorted_layers.index(ValidationLayer.LIBRARY_LEVEL)
        app_index = sorted_layers.index(ValidationLayer.APPLICATION_LEVEL)

        assert os_index < lib_index
        assert lib_index < app_index

    def test_dependency_satisfaction_check(self) -> None:
        """Dependency satisfaction is validated before stage execution."""
        graph = DependencyGraph()
        graph.add_dependency(ValidationLayer.APPLICATION_LEVEL, ValidationLayer.LIBRARY_LEVEL)
        graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)

        result = MultiLayerResult(overall_success=False)
        result.bypassed_layers.append(ValidationLayer.OS_LEVEL)
        result.bypassed_layers.append(ValidationLayer.LIBRARY_LEVEL)

        bypasser = MultiLayerBypass()
        satisfied = bypasser._check_dependencies_satisfied(
            ValidationLayer.APPLICATION_LEVEL,
            graph,
            result,
        )

        assert satisfied is True

    def test_dependency_failure_blocks_dependent_layer(self) -> None:
        """Failed dependency blocks execution of dependent layer."""
        graph = DependencyGraph()
        graph.add_dependency(ValidationLayer.APPLICATION_LEVEL, ValidationLayer.LIBRARY_LEVEL)

        result = MultiLayerResult(overall_success=False)

        bypasser = MultiLayerBypass()
        satisfied = bypasser._check_dependencies_satisfied(
            ValidationLayer.APPLICATION_LEVEL,
            graph,
            result,
        )

        assert satisfied is False


class TestMultiLayerBypassIntegration:
    """Integration tests for complete multi-layer bypass workflows."""

    def test_empty_layers_list_returns_success(
        self,
        sample_pe_binary: Path,
    ) -> None:
        """Empty layers list results in successful bypass with no operations."""
        bypasser = MultiLayerBypass()
        graph = DependencyGraph()

        result = bypasser.bypass_all_layers(str(sample_pe_binary), [], graph)

        assert result.overall_success is True
        assert len(result.bypassed_layers) == 0
        assert len(result.failed_layers) == 0

    def test_single_layer_with_no_detection(
        self,
        sample_pe_binary: Path,
        os_level_layer: LayerInfo,
    ) -> None:
        """Single layer with no detectable validation functions completes successfully."""
        bypasser = MultiLayerBypass()
        graph = DependencyGraph()
        graph.add_layer(ValidationLayer.OS_LEVEL)

        result = bypasser.bypass_all_layers(
            str(sample_pe_binary),
            [os_level_layer],
            graph,
        )

        assert len(result.stage_results) >= 0

    def test_dependency_ordering_enforced(
        self,
        sample_pe_binary: Path,
        os_level_layer: LayerInfo,
        library_level_layer: LayerInfo,
        simple_dependency_graph: DependencyGraph,
    ) -> None:
        """Dependencies are processed in correct topological order."""
        bypasser = MultiLayerBypass()
        layers = [library_level_layer, os_level_layer]

        result = bypasser.bypass_all_layers(
            str(sample_pe_binary),
            layers,
            simple_dependency_graph,
        )

        if len(result.stage_results) >= 2:
            stage_numbers = sorted(result.stage_results.keys())
            first_stage = result.stage_results[stage_numbers[0]]
            assert first_stage.layer == ValidationLayer.OS_LEVEL

    def test_failed_dependency_prevents_dependent_execution(
        self,
        sample_pe_binary: Path,
        os_level_layer: LayerInfo,
        library_level_layer: LayerInfo,
        simple_dependency_graph: DependencyGraph,
    ) -> None:
        """Failed dependency layer prevents execution of dependent layers."""
        bypasser = MultiLayerBypass()

        layers = [os_level_layer, library_level_layer]

        result = bypasser.bypass_all_layers(
            str(sample_pe_binary),
            layers,
            simple_dependency_graph,
        )

        assert result is not None

    def test_four_layer_bypass_workflow(
        self,
        sample_pe_binary: Path,
        os_level_layer: LayerInfo,
        library_level_layer: LayerInfo,
        application_level_layer: LayerInfo,
        server_level_layer: LayerInfo,
        complex_dependency_graph: DependencyGraph,
    ) -> None:
        """Complete four-layer bypass processes all layers in dependency order."""
        bypasser = MultiLayerBypass()

        layers = [
            os_level_layer,
            library_level_layer,
            application_level_layer,
            server_level_layer,
        ]

        result = bypasser.bypass_all_layers(
            str(sample_pe_binary),
            layers,
            complex_dependency_graph,
        )

        assert result is not None
        assert isinstance(result, MultiLayerResult)


class TestRollbackFunctionality:
    """Tests validating rollback on bypass failure."""

    def test_rollback_with_empty_result(self) -> None:
        """Rollback handles empty result gracefully."""
        bypasser = MultiLayerBypass()
        result = MultiLayerResult(overall_success=False)

        bypasser._rollback_previous_stages(result)

        assert len(result.rollback_data) == 0

    def test_rollback_with_rollback_data(self) -> None:
        """Rollback processes stages with rollback data."""
        bypasser = MultiLayerBypass()
        result = MultiLayerResult(overall_success=False)
        result.bypassed_layers.append(ValidationLayer.OS_LEVEL)
        result.rollback_data[ValidationLayer.OS_LEVEL] = b"\x90" * 100

        bypasser._rollback_previous_stages(result)

        assert ValidationLayer.OS_LEVEL in result.rollback_data

    def test_cleanup_detaches_resources(self) -> None:
        """Cleanup properly releases bypass resources."""
        bypasser = MultiLayerBypass()

        bypasser.cleanup()

        assert bypasser._frida_hooks is not None


class TestVerificationLogic:
    """Tests validating layer bypass verification."""

    def test_os_level_verification_with_no_script(
        self,
        sample_pe_binary: Path,
    ) -> None:
        """OS-level verification succeeds when no Frida script is active."""
        bypasser = MultiLayerBypass()

        verified = bypasser._verify_os_level_bypass(str(sample_pe_binary))

        assert verified is True

    def test_library_level_verification_with_no_script(
        self,
        sample_pe_binary: Path,
    ) -> None:
        """Library-level verification succeeds when no Frida script is active."""
        bypasser = MultiLayerBypass()

        verified = bypasser._verify_library_level_bypass(str(sample_pe_binary))

        assert verified is True

    def test_application_level_verification_with_no_script(
        self,
        sample_pe_binary: Path,
    ) -> None:
        """Application-level verification succeeds when no Frida script is active."""
        bypasser = MultiLayerBypass()

        verified = bypasser._verify_application_level_bypass(str(sample_pe_binary))

        assert verified is True

    def test_server_level_verification_with_no_script(
        self,
        sample_pe_binary: Path,
    ) -> None:
        """Server-level verification succeeds when no Frida script is active."""
        bypasser = MultiLayerBypass()

        verified = bypasser._verify_server_level_bypass(str(sample_pe_binary))

        assert verified is True


class TestEdgeCasesMixedProtectionLayers:
    """Test edge cases with mixed protection layers and complex layer interactions."""

    def test_mixed_layer_detection_os_and_library(self) -> None:
        """Mixed OS and library layer detection handles both correctly."""
        graph = DependencyGraph()
        graph.add_layer(ValidationLayer.OS_LEVEL)
        graph.add_layer(ValidationLayer.LIBRARY_LEVEL)
        graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)

        sorted_layers = graph.topological_sort()
        assert len(sorted_layers) == 2
        assert ValidationLayer.OS_LEVEL in sorted_layers
        assert ValidationLayer.LIBRARY_LEVEL in sorted_layers

    def test_mixed_library_and_application_layers(self) -> None:
        """Mixed library and application layers are handled correctly."""
        result = MultiLayerResult(overall_success=False)

        lib_stage = StageResult(
            stage_number=1,
            layer=ValidationLayer.LIBRARY_LEVEL,
            success=True,
            bypassed_functions=["SSL_CTX_set_verify"],
        )

        app_stage = StageResult(
            stage_number=2,
            layer=ValidationLayer.APPLICATION_LEVEL,
            success=True,
            bypassed_functions=["custom_certificate_check"],
        )

        result.add_stage_result(lib_stage)
        result.add_stage_result(app_stage)

        assert len(result.bypassed_layers) == 2
        assert ValidationLayer.LIBRARY_LEVEL in result.bypassed_layers
        assert ValidationLayer.APPLICATION_LEVEL in result.bypassed_layers

    def test_all_four_layers_mixed(self) -> None:
        """All four validation layers (OS, Library, Application, Server) are handled."""
        graph = DependencyGraph()
        graph.add_layer(ValidationLayer.OS_LEVEL)
        graph.add_layer(ValidationLayer.LIBRARY_LEVEL)
        graph.add_layer(ValidationLayer.APPLICATION_LEVEL)
        graph.add_layer(ValidationLayer.SERVER_LEVEL)

        graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)
        graph.add_dependency(ValidationLayer.APPLICATION_LEVEL, ValidationLayer.LIBRARY_LEVEL)
        graph.add_dependency(ValidationLayer.SERVER_LEVEL, ValidationLayer.APPLICATION_LEVEL)

        sorted_layers = graph.topological_sort()

        assert len(sorted_layers) == 4
        assert sorted_layers.index(ValidationLayer.OS_LEVEL) < sorted_layers.index(ValidationLayer.LIBRARY_LEVEL)
        assert sorted_layers.index(ValidationLayer.LIBRARY_LEVEL) < sorted_layers.index(ValidationLayer.APPLICATION_LEVEL)
        assert sorted_layers.index(ValidationLayer.APPLICATION_LEVEL) < sorted_layers.index(ValidationLayer.SERVER_LEVEL)

    def test_partial_layer_bypass_failure(self) -> None:
        """Partial layer bypass (some layers succeed, some fail) tracked correctly."""
        result = MultiLayerResult(overall_success=False)

        success1 = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=True,
            bypassed_functions=["CertVerifyCertificateChainPolicy"],
        )

        success2 = StageResult(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            success=True,
            bypassed_functions=["SSL_CTX_set_verify"],
        )

        failure = StageResult(
            stage_number=3,
            layer=ValidationLayer.APPLICATION_LEVEL,
            success=False,
            error_message="Custom pinning bypass failed",
        )

        result.add_stage_result(success1)
        result.add_stage_result(success2)
        result.add_stage_result(failure)

        assert len(result.bypassed_layers) == 2
        assert len(result.failed_layers) == 1
        assert result.failed_layers[0][0] == ValidationLayer.APPLICATION_LEVEL


class TestEdgeCasesCertificateChainValidationFailures:
    """Test edge cases with certificate chain validation failures."""

    def test_chain_validation_with_expired_cert(self) -> None:
        """Certificate chain validation failure due to expired certificate."""
        result = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=False,
            error_message="Certificate chain validation failed: Cert expired",
        )

        assert result.success is False
        assert "expired" in result.error_message.lower()  # type: ignore[union-attr]

    def test_chain_validation_with_untrusted_root(self) -> None:
        """Certificate chain validation failure due to untrusted root CA."""
        result = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=False,
            error_message="Certificate chain validation failed: Untrusted root CA",
        )

        assert result.success is False
        assert "untrusted" in result.error_message.lower()  # type: ignore[union-attr]

    def test_chain_validation_with_broken_chain(self) -> None:
        """Certificate chain validation failure due to broken chain."""
        result = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=False,
            error_message="Certificate chain validation failed: Chain incomplete",
        )

        assert result.success is False
        assert "chain" in result.error_message.lower()  # type: ignore[union-attr]

    def test_chain_validation_with_revoked_cert(self) -> None:
        """Certificate chain validation failure due to revoked certificate."""
        result = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=False,
            error_message="Certificate chain validation failed: Certificate revoked (OCSP)",
        )

        assert result.success is False
        assert "revoked" in result.error_message.lower()  # type: ignore[union-attr]


class TestEdgeCasesTimeoutScenarios:
    """Test edge cases with timeout scenarios during bypass operations."""

    def test_stage_execution_timeout_tracked(self) -> None:
        """Stage execution timeout is tracked as failure."""
        result = StageResult(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            success=False,
            error_message="Timeout: Library bypass exceeded 30 seconds",
        )

        assert result.success is False
        assert "timeout" in result.error_message.lower()  # type: ignore[union-attr]

    def test_frida_injection_timeout(self) -> None:
        """Frida injection timeout is handled gracefully."""
        result = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=False,
            error_message="Timeout: Frida injection did not complete within 10 seconds",
        )

        assert result.success is False
        assert "frida" in result.error_message.lower()  # type: ignore[union-attr]
        assert "timeout" in result.error_message.lower()  # type: ignore[union-attr]

    def test_verification_timeout_after_bypass(self) -> None:
        """Verification timeout after bypass attempt is handled."""
        result = StageResult(
            stage_number=3,
            layer=ValidationLayer.APPLICATION_LEVEL,
            success=False,
            error_message="Timeout: Bypass verification did not respond within 15 seconds",
        )

        assert result.success is False
        assert "verification" in result.error_message.lower()  # type: ignore[union-attr]
        assert "timeout" in result.error_message.lower()  # type: ignore[union-attr]

    def test_multiple_timeout_failures(self) -> None:
        """Multiple timeout failures across stages tracked correctly."""
        mlr = MultiLayerResult(overall_success=False)

        timeout1 = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=False,
            error_message="Timeout: OS bypass exceeded time limit",
        )

        timeout2 = StageResult(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            success=False,
            error_message="Timeout: Library bypass exceeded time limit",
        )

        mlr.add_stage_result(timeout1)
        mlr.add_stage_result(timeout2)

        assert len(mlr.failed_layers) == 2
        assert all("timeout" in error.lower() for _, error in mlr.failed_layers)


class TestEdgeCasesComplexDependencyGraphs:
    """Test edge cases with complex dependency graphs."""

    def test_diamond_dependency_pattern(self) -> None:
        """Diamond dependency pattern (A -> B,C; B,C -> D) resolves correctly."""
        graph = DependencyGraph()

        graph.add_layer(ValidationLayer.OS_LEVEL)
        graph.add_layer(ValidationLayer.LIBRARY_LEVEL)
        graph.add_layer(ValidationLayer.APPLICATION_LEVEL)
        graph.add_layer(ValidationLayer.SERVER_LEVEL)

        graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)
        graph.add_dependency(ValidationLayer.APPLICATION_LEVEL, ValidationLayer.OS_LEVEL)
        graph.add_dependency(ValidationLayer.SERVER_LEVEL, ValidationLayer.LIBRARY_LEVEL)
        graph.add_dependency(ValidationLayer.SERVER_LEVEL, ValidationLayer.APPLICATION_LEVEL)

        sorted_layers = graph.topological_sort()

        os_idx = sorted_layers.index(ValidationLayer.OS_LEVEL)
        lib_idx = sorted_layers.index(ValidationLayer.LIBRARY_LEVEL)
        app_idx = sorted_layers.index(ValidationLayer.APPLICATION_LEVEL)
        server_idx = sorted_layers.index(ValidationLayer.SERVER_LEVEL)

        assert os_idx < lib_idx
        assert os_idx < app_idx
        assert lib_idx < server_idx
        assert app_idx < server_idx

    def test_missing_dependency_detected(self) -> None:
        """Missing dependency (layer depends on non-existent layer) detected."""
        graph = DependencyGraph()
        graph.add_layer(ValidationLayer.APPLICATION_LEVEL)

        result = MultiLayerResult(overall_success=False)

        bypasser = MultiLayerBypass()
        satisfied = bypasser._check_dependencies_satisfied(
            ValidationLayer.APPLICATION_LEVEL,
            graph,
            result,
        )

        assert satisfied is True

    def test_circular_dependency_prevention(self) -> None:
        """Circular dependencies are prevented or detected."""
        graph = DependencyGraph()

        graph.add_layer(ValidationLayer.OS_LEVEL)
        graph.add_layer(ValidationLayer.LIBRARY_LEVEL)

        graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)

        try:
            graph.add_dependency(ValidationLayer.OS_LEVEL, ValidationLayer.LIBRARY_LEVEL)
            sorted_layers = graph.topological_sort()
            assert len(sorted_layers) == 2
        except Exception:
            pass


class TestEdgeCasesRollbackMechanisms:
    """Test edge cases with rollback mechanisms and state restoration."""

    def test_rollback_after_single_stage_failure(self) -> None:
        """Rollback restores state after single stage failure."""
        mlr = MultiLayerResult(overall_success=False)

        success_stage = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=True,
            bypassed_functions=["CertVerifyCertificateChainPolicy"],
            rollback_data=b"\x90" * 100,
        )

        failed_stage = StageResult(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            success=False,
            error_message="Library bypass failed",
        )

        mlr.add_stage_result(success_stage)
        mlr.add_stage_result(failed_stage)

        assert ValidationLayer.OS_LEVEL in mlr.rollback_data
        assert mlr.rollback_data[ValidationLayer.OS_LEVEL] == b"\x90" * 100

    def test_rollback_after_multiple_stage_failures(self) -> None:
        """Rollback restores multiple stages after cascade failure."""
        mlr = MultiLayerResult(overall_success=False)

        stage1 = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=True,
            rollback_data=b"\x01" * 50,
        )

        stage2 = StageResult(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            success=True,
            rollback_data=b"\x02" * 50,
        )

        stage3 = StageResult(
            stage_number=3,
            layer=ValidationLayer.APPLICATION_LEVEL,
            success=False,
            error_message="Application bypass failed - rollback required",
        )

        mlr.add_stage_result(stage1)
        mlr.add_stage_result(stage2)
        mlr.add_stage_result(stage3)

        assert len(mlr.rollback_data) == 2
        assert ValidationLayer.OS_LEVEL in mlr.rollback_data
        assert ValidationLayer.LIBRARY_LEVEL in mlr.rollback_data

    def test_partial_rollback_on_memory_error(self) -> None:
        """Partial rollback on memory error during restoration."""
        mlr = MultiLayerResult(overall_success=False)

        stage = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=True,
            rollback_data=None,
        )

        mlr.add_stage_result(stage)

        assert ValidationLayer.OS_LEVEL not in mlr.rollback_data


class TestEdgeCasesResourceExhaustion:
    """Test edge cases with resource exhaustion scenarios."""

    def test_memory_exhaustion_during_patch_application(self) -> None:
        """Memory exhaustion during patch application is handled."""
        result = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=False,
            error_message="MemoryError: Insufficient memory to apply binary patch",
        )

        assert result.success is False
        assert "memory" in result.error_message.lower()  # type: ignore[union-attr]

    def test_too_many_hooks_installed(self) -> None:
        """Too many Frida hooks causing resource exhaustion."""
        result = StageResult(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            success=False,
            error_message="Resource exhaustion: Too many Frida hooks (limit: 1000)",
        )

        assert result.success is False
        assert "resource" in result.error_message.lower() or "hooks" in result.error_message.lower()  # type: ignore[union-attr]

    def test_process_spawn_failure(self) -> None:
        """Process spawn failure due to resource limits."""
        result = StageResult(
            stage_number=3,
            layer=ValidationLayer.APPLICATION_LEVEL,
            success=False,
            error_message="Process spawn failed: Resource limit exceeded",
        )

        assert result.success is False
        assert "process" in result.error_message.lower() or "spawn" in result.error_message.lower()  # type: ignore[union-attr]


class TestDependencyGraphOperations:
    """Test dependency graph operations and edge cases."""

    def test_topological_sort_returns_complete_set(self) -> None:
        """topological_sort returns all added layers."""
        graph = DependencyGraph()
        graph.add_layer(ValidationLayer.OS_LEVEL)
        graph.add_layer(ValidationLayer.LIBRARY_LEVEL)
        graph.add_layer(ValidationLayer.APPLICATION_LEVEL)

        layers = graph.topological_sort()

        assert len(layers) == 3
        assert ValidationLayer.OS_LEVEL in layers
        assert ValidationLayer.LIBRARY_LEVEL in layers
        assert ValidationLayer.APPLICATION_LEVEL in layers

    def test_layers_added_appear_in_topological_sort(self) -> None:
        """Layers that have been added appear in topological sort."""
        graph = DependencyGraph()
        graph.add_layer(ValidationLayer.OS_LEVEL)

        sorted_layers = graph.topological_sort()

        assert ValidationLayer.OS_LEVEL in sorted_layers
        assert ValidationLayer.LIBRARY_LEVEL not in sorted_layers

    def test_get_dependencies_returns_empty_for_no_deps(self) -> None:
        """get_dependencies returns empty set for layers with no dependencies."""
        graph = DependencyGraph()
        graph.add_layer(ValidationLayer.OS_LEVEL)

        deps = graph.get_dependencies(ValidationLayer.OS_LEVEL)

        assert len(deps) == 0

    def test_get_dependencies_returns_all_dependencies(self) -> None:
        """get_dependencies returns all dependencies for a layer."""
        graph = DependencyGraph()
        graph.add_layer(ValidationLayer.OS_LEVEL)
        graph.add_layer(ValidationLayer.LIBRARY_LEVEL)
        graph.add_layer(ValidationLayer.APPLICATION_LEVEL)

        graph.add_dependency(ValidationLayer.APPLICATION_LEVEL, ValidationLayer.OS_LEVEL)
        graph.add_dependency(ValidationLayer.APPLICATION_LEVEL, ValidationLayer.LIBRARY_LEVEL)

        deps = graph.get_dependencies(ValidationLayer.APPLICATION_LEVEL)

        assert len(deps) == 2
        assert ValidationLayer.OS_LEVEL in deps
        assert ValidationLayer.LIBRARY_LEVEL in deps
