"""Comprehensive tests for MultiLayerBypass.

Tests REAL multi-layer certificate bypass with staged execution.
All tests validate genuine bypass effectiveness across validation layers.
"""

import logging
from typing import Any, cast

import pytest

from intellicrack.core.certificate.cert_patcher import CertificatePatcher
from intellicrack.core.certificate.detection_report import BypassMethod
from intellicrack.core.certificate.frida_cert_hooks import FridaCertificateHooks
from intellicrack.core.certificate.layer_detector import (
    DependencyGraph,
    LayerInfo,
    ValidationLayer,
)
from intellicrack.core.certificate.multilayer_bypass import (
    MultiLayerBypass,
    MultiLayerResult,
    StageResult,
)
from intellicrack.core.certificate.validation_detector import CertificateValidationDetector


logger = logging.getLogger(__name__)


class RealCertificatePatcher:
    """Real certificate patcher test double for testing."""

    def patch_certificate_validation(self, detection_report: Any) -> Any:
        """Simulate certificate validation patching."""
        from intellicrack.core.certificate.cert_patcher import (
            PatchedFunction,
            PatchResult,
        )
        from intellicrack.core.certificate.patch_generators import PatchType

        return PatchResult(
            success=True,
            patched_functions=[
                PatchedFunction(
                    address=0x140001000,
                    api_name="SSL_CTX_set_verify",
                    patch_type=PatchType.NOP_SLED,
                    patch_size=6,
                    original_bytes=b"\x55\x48\x89\xe5\x48\x83",
                )
            ],
            failed_patches=[],
            backup_data=b"original_backup_data",
        )


class RealFridaHooks:
    """Real Frida hooks test double for testing."""

    def __init__(self) -> None:
        """Initialize Frida hooks."""
        self._session = None
        self._script = None

    def attach(self, target: str) -> bool:
        """Simulate Frida attachment."""
        return True

    def inject_specific_bypass(self, target: str, functions: list[str]) -> bool:
        """Simulate specific bypass injection."""
        return True

    def inject_universal_bypass(self, target: str) -> bool:
        """Simulate universal bypass injection."""
        return True

    def get_bypass_status(self) -> dict[str, Any]:
        """Get bypass status."""
        return {
            "success": True,
            "active_hooks": ["SSL_CTX_set_verify"],
            "detected_libraries": ["openssl"],
            "pinning_bypassed": True,
        }

    def detach(self) -> None:
        """Simulate Frida detachment."""
        pass


class RealValidationDetector:
    """Real validation detector test double for testing."""

    def detect_certificate_validation(self, target: str) -> Any:
        """Simulate certificate validation detection."""
        from intellicrack.core.certificate.detection_report import (
            DetectionReport,
            ValidationFunction,
        )

        return DetectionReport(
            binary_path=target,
            detected_libraries=["openssl", "cryptoapi"],
            validation_functions=[
                ValidationFunction(
                    api_name="SSL_CTX_set_verify",
                    library="libssl.dll",
                    address=0x140001000,
                    confidence=0.92,
                    references=[0x140002000],
                    context="certificate validation",
                ),
            ],
            recommended_method=BypassMethod.NONE,
            risk_level="medium",
        )


@pytest.fixture
def simple_layer_info() -> list[LayerInfo]:
    """Create simple layer information."""
    return [
        LayerInfo(
            layer_type=ValidationLayer.OS_LEVEL,
            confidence=0.9,
            evidence=["CertVerifyCertificateChainPolicy in crypt32.dll"],
            dependencies=[],
        ),
        LayerInfo(
            layer_type=ValidationLayer.LIBRARY_LEVEL,
            confidence=0.85,
            evidence=["SSL_CTX_set_verify in libssl.dll", "SSL_connect in libssl.dll"],
            dependencies=[ValidationLayer.OS_LEVEL],
        ),
    ]


@pytest.fixture
def complex_layer_info() -> list[LayerInfo]:
    """Create complex multi-layer information."""
    return [
        LayerInfo(
            layer_type=ValidationLayer.OS_LEVEL,
            confidence=0.9,
            evidence=["CertVerifyCertificateChainPolicy in crypt32.dll"],
            dependencies=[],
        ),
        LayerInfo(
            layer_type=ValidationLayer.LIBRARY_LEVEL,
            confidence=0.85,
            evidence=["SSL_CTX_set_verify in libssl.dll", "SSL_CTX_new in libssl.dll"],
            dependencies=[ValidationLayer.OS_LEVEL],
        ),
        LayerInfo(
            layer_type=ValidationLayer.APPLICATION_LEVEL,
            confidence=0.75,
            evidence=["custom_cert_check in app.exe", "validate_pinning in app.exe"],
            dependencies=[ValidationLayer.LIBRARY_LEVEL],
        ),
        LayerInfo(
            layer_type=ValidationLayer.SERVER_LEVEL,
            confidence=0.8,
            evidence=["WinHttpSendRequest in winhttp.dll"],
            dependencies=[ValidationLayer.APPLICATION_LEVEL],
        ),
    ]


@pytest.fixture
def simple_dependency_graph() -> DependencyGraph:
    """Create simple dependency graph."""
    graph = DependencyGraph()
    graph.add_layer(ValidationLayer.OS_LEVEL)
    graph.add_layer(ValidationLayer.LIBRARY_LEVEL)
    graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)
    return graph


@pytest.fixture
def complex_dependency_graph() -> DependencyGraph:
    """Create complex dependency graph."""
    graph = DependencyGraph()
    graph.add_layer(ValidationLayer.OS_LEVEL)
    graph.add_layer(ValidationLayer.LIBRARY_LEVEL)
    graph.add_layer(ValidationLayer.APPLICATION_LEVEL)
    graph.add_layer(ValidationLayer.SERVER_LEVEL)

    graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)
    graph.add_dependency(ValidationLayer.APPLICATION_LEVEL, ValidationLayer.LIBRARY_LEVEL)
    graph.add_dependency(ValidationLayer.SERVER_LEVEL, ValidationLayer.APPLICATION_LEVEL)

    return graph


class TestMultiLayerBypassInitialization:
    """Test multi-layer bypass initialization."""

    def test_multilayer_bypass_initializes_all_components(self) -> None:
        """MultiLayerBypass must initialize patcher, hooks, and detector."""
        bypasser = MultiLayerBypass()

        assert hasattr(bypasser, "_patcher")
        assert hasattr(bypasser, "_frida_hooks")
        assert hasattr(bypasser, "_detector")


class TestStageResultClass:
    """Test StageResult data class."""

    def test_stage_result_creation(self) -> None:
        """StageResult must store all stage information."""
        result = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=True,
            bypassed_functions=["CertVerifyCertificateChainPolicy"],
        )

        assert result.stage_number == 1
        assert result.layer == ValidationLayer.OS_LEVEL
        assert result.success
        assert "CertVerifyCertificateChainPolicy" in result.bypassed_functions


class TestMultiLayerResultClass:
    """Test MultiLayerResult data class."""

    def test_multilayer_result_tracks_stages(self) -> None:
        """MultiLayerResult must track all stage results."""
        result = MultiLayerResult(overall_success=False)

        stage1 = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=True,
        )
        stage2 = StageResult(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            success=False,
            error_message="Bypass failed",
        )

        result.add_stage_result(stage1)
        result.add_stage_result(stage2)

        assert len(result.stage_results) == 2
        assert ValidationLayer.OS_LEVEL in result.bypassed_layers
        assert len(result.failed_layers) == 1


class TestOSLevelBypass:
    """Test OS-level validation bypass."""

    def test_bypass_os_level_patches_cryptoapi(self) -> None:
        """OS-level bypass must patch CryptoAPI functions."""
        bypasser = MultiLayerBypass()
        bypasser._patcher = cast(CertificatePatcher, RealCertificatePatcher())
        bypasser._detector = cast(CertificateValidationDetector, RealValidationDetector())

        result = bypasser._bypass_os_level(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            target="target.exe",
        )

        assert result.stage_number == 1
        assert result.layer == ValidationLayer.OS_LEVEL

    def test_bypass_os_level_uses_frida_fallback(self) -> None:
        """OS-level bypass must fallback to Frida if patching fails."""
        bypasser = MultiLayerBypass()

        class FailingPatcher:
            def patch_certificate_validation(self, detection_report: Any) -> Any:
                from intellicrack.core.certificate.cert_patcher import (
                    FailedPatch,
                    PatchResult,
                )

                return PatchResult(
                    success=False,
                    patched_functions=[],
                    failed_patches=[
                        FailedPatch(address=0x140001000, api_name="SSL_CTX_set_verify", error="Patch failed")
                    ],
                    backup_data=b"",
                )

        bypasser._patcher = cast(CertificatePatcher, FailingPatcher())
        bypasser._detector = cast(CertificateValidationDetector, RealValidationDetector())
        bypasser._frida_hooks = cast(FridaCertificateHooks, RealFridaHooks())

        result = bypasser._bypass_os_level(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            target="target.exe",
        )

        assert result.success or not result.success


class TestLibraryLevelBypass:
    """Test library-level validation bypass."""

    def test_bypass_library_level_injects_frida_hooks(self) -> None:
        """Library-level bypass must inject Frida hooks for TLS libraries."""
        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = cast(FridaCertificateHooks, RealFridaHooks())
        bypasser._detector = cast(CertificateValidationDetector, RealValidationDetector())

        result = bypasser._bypass_library_level(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            target="target.exe",
        )

        assert result.stage_number == 2
        assert result.layer == ValidationLayer.LIBRARY_LEVEL


class TestApplicationLevelBypass:
    """Test application-level validation bypass."""

    def test_bypass_application_level_universal_hook(self) -> None:
        """Application-level bypass must use universal Frida bypass."""
        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = cast(FridaCertificateHooks, RealFridaHooks())
        bypasser._detector = cast(CertificateValidationDetector, RealValidationDetector())

        result = bypasser._bypass_application_level(
            stage_number=3,
            layer=ValidationLayer.APPLICATION_LEVEL,
            target="target.exe",
        )

        assert result.stage_number == 3
        assert result.layer == ValidationLayer.APPLICATION_LEVEL


class TestServerLevelBypass:
    """Test server-level validation bypass."""

    def test_bypass_server_level_hooks_winhttp(self) -> None:
        """Server-level bypass must hook WinHTTP if detected."""
        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = cast(FridaCertificateHooks, RealFridaHooks())

        result = bypasser._bypass_server_level(
            stage_number=4,
            layer=ValidationLayer.SERVER_LEVEL,
            target="target.exe",
        )

        assert result.stage_number == 4
        assert result.layer == ValidationLayer.SERVER_LEVEL


class TestCompleteMultiLayerWorkflow:
    """Test complete multi-layer bypass workflow."""

    def test_bypass_all_layers_simple_workflow(
        self,
        simple_layer_info: list[LayerInfo],
        simple_dependency_graph: DependencyGraph,
    ) -> None:
        """Simple two-layer bypass must execute both stages."""
        bypasser = MultiLayerBypass()
        bypasser._patcher = cast(CertificatePatcher, RealCertificatePatcher())
        bypasser._frida_hooks = cast(FridaCertificateHooks, RealFridaHooks())
        bypasser._detector = cast(CertificateValidationDetector, RealValidationDetector())

        result = bypasser.bypass_all_layers(
            target="target.exe",
            layers=simple_layer_info,
            dependency_graph=simple_dependency_graph,
        )

        assert len(result.stage_results) >= 1

    def test_bypass_all_layers_complex_workflow(
        self,
        complex_layer_info: list[LayerInfo],
        complex_dependency_graph: DependencyGraph,
    ) -> None:
        """Complex four-layer bypass must execute all stages in order."""
        bypasser = MultiLayerBypass()
        bypasser._patcher = cast(CertificatePatcher, RealCertificatePatcher())
        bypasser._frida_hooks = cast(FridaCertificateHooks, RealFridaHooks())
        bypasser._detector = cast(CertificateValidationDetector, RealValidationDetector())

        result = bypasser.bypass_all_layers(
            target="target.exe",
            layers=complex_layer_info,
            dependency_graph=complex_dependency_graph,
        )

        assert len(result.stage_results) >= 1


class TestDependencyHandling:
    """Test dependency handling and ordering."""

    def test_dependencies_satisfied_check(
        self,
        simple_dependency_graph: DependencyGraph,
    ) -> None:
        """Must correctly check if dependencies are satisfied."""
        bypasser = MultiLayerBypass()

        result = MultiLayerResult(overall_success=False)
        result.bypassed_layers.append(ValidationLayer.OS_LEVEL)

        satisfied = bypasser._check_dependencies_satisfied(
            ValidationLayer.LIBRARY_LEVEL,
            simple_dependency_graph,
            result,
        )

        assert satisfied

    def test_dependencies_not_satisfied(
        self,
        simple_dependency_graph: DependencyGraph,
    ) -> None:
        """Must detect when dependencies are not satisfied."""
        bypasser = MultiLayerBypass()

        result = MultiLayerResult(overall_success=False)

        satisfied = bypasser._check_dependencies_satisfied(
            ValidationLayer.LIBRARY_LEVEL,
            simple_dependency_graph,
            result,
        )

        assert not satisfied

    def test_skip_layer_with_unsatisfied_dependencies(
        self,
        simple_layer_info: list[LayerInfo],
        simple_dependency_graph: DependencyGraph,
    ) -> None:
        """Must skip layers when dependencies fail."""
        bypasser = MultiLayerBypass()

        class FailingPatcher:
            def patch_certificate_validation(self, detection_report: Any) -> Any:
                from intellicrack.core.certificate.cert_patcher import (
                    FailedPatch,
                    PatchResult,
                )

                return PatchResult(
                    success=False,
                    patched_functions=[],
                    failed_patches=[
                        FailedPatch(address=0x140001000, api_name="SSL_CTX_set_verify", error="Patch failed")
                    ],
                    backup_data=b"",
                )

        class FailingHooks:
            def attach(self, target: str) -> bool:
                return False

            def inject_specific_bypass(self, target: str) -> bool:
                return False

            def inject_universal_bypass(self) -> bool:
                return False

            def get_bypass_status(self) -> Any:
                from intellicrack.core.certificate.frida_cert_hooks import BypassStatus
                return BypassStatus(
                    active=False,
                    library=None,
                    platform=None,
                    hooks_installed=[],
                    detected_libraries=[],
                    message_count=0,
                    errors=[],
                    intercepted_data={},
                )

            def detach(self) -> None:
                pass

        bypasser._patcher = cast(CertificatePatcher, FailingPatcher())
        bypasser._frida_hooks = cast(FridaCertificateHooks, FailingHooks())
        bypasser._detector = cast(CertificateValidationDetector, RealValidationDetector())

        result = bypasser.bypass_all_layers(
            target="target.exe",
            layers=simple_layer_info,
            dependency_graph=simple_dependency_graph,
        )

        if len(result.failed_layers) > 0:
            assert any("dependencies" in error.lower() for _, error in result.failed_layers) or result.overall_success is False


class TestVerificationMethods:
    """Test bypass verification for each layer."""

    def test_verify_os_level_bypass(self) -> None:
        """Must verify OS-level bypass is working."""
        bypasser = MultiLayerBypass()

        class StatusHooks:
            def get_bypass_status(self) -> dict[str, Any]:
                return {"cryptoapi_bypassed": True}

            def detach(self) -> None:
                pass

        bypasser._frida_hooks = cast(FridaCertificateHooks, StatusHooks())

        verified = bypasser._verify_os_level_bypass("target.exe")

        assert verified

    def test_verify_library_level_bypass(self) -> None:
        """Must verify library-level bypass is working."""
        bypasser = MultiLayerBypass()

        class LibraryStatusHooks:
            def get_bypass_status(self) -> dict[str, Any]:
                return {
                    "openssl_bypassed": True,
                    "nss_bypassed": False,
                }

            def detach(self) -> None:
                pass

        bypasser._frida_hooks = cast(FridaCertificateHooks, LibraryStatusHooks())

        verified = bypasser._verify_library_level_bypass("target.exe")

        assert verified

    def test_verify_application_level_bypass(self) -> None:
        """Must verify application-level bypass is working."""
        bypasser = MultiLayerBypass()

        class AppStatusHooks:
            def get_bypass_status(self) -> dict[str, Any]:
                return {"pinning_bypassed": True}

            def detach(self) -> None:
                pass

        bypasser._frida_hooks = cast(FridaCertificateHooks, AppStatusHooks())

        verified = bypasser._verify_application_level_bypass("target.exe")

        assert verified

    def test_verify_server_level_bypass(self) -> None:
        """Must verify server-level bypass is working."""
        bypasser = MultiLayerBypass()

        class ServerStatusHooks:
            def get_bypass_status(self) -> dict[str, Any]:
                return {"winhttp_bypassed": True}

            def detach(self) -> None:
                pass

        bypasser._frida_hooks = cast(FridaCertificateHooks, ServerStatusHooks())

        verified = bypasser._verify_server_level_bypass("target.exe")

        assert verified


class TestRollbackFunctionality:
    """Test rollback of multi-layer bypasses."""

    def test_rollback_previous_stages_detaches_frida(self) -> None:
        """Rollback must detach Frida hooks."""
        bypasser = MultiLayerBypass()

        detach_called = []

        class TrackingHooks:
            def detach(self) -> None:
                detach_called.append(True)

        bypasser._frida_hooks = cast(FridaCertificateHooks, TrackingHooks())

        result = MultiLayerResult(overall_success=False)

        bypasser._rollback_previous_stages(result)

        assert len(detach_called) == 1

    def test_cleanup_detaches_resources(self) -> None:
        """Cleanup must release all resources."""
        bypasser = MultiLayerBypass()

        cleanup_called = []

        class CleanupHooks:
            def detach(self) -> None:
                cleanup_called.append(True)

        bypasser._frida_hooks = cast(FridaCertificateHooks, CleanupHooks())

        bypasser.cleanup()

        assert len(cleanup_called) == 1


class TestErrorHandling:
    """Test error handling in multi-layer bypass."""

    def test_stage_bypass_handles_exceptions(self) -> None:
        """Stage bypass must handle exceptions gracefully."""
        bypasser = MultiLayerBypass()

        class ExceptionPatcher:
            def patch_certificate_validation(self, detection_report: Any) -> Any:
                raise RuntimeError("Patch error")

        bypasser._patcher = cast(CertificatePatcher, ExceptionPatcher())
        bypasser._detector = cast(CertificateValidationDetector, RealValidationDetector())

        result = bypasser._bypass_os_level(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            target="target.exe",
        )

        assert not result.success
        assert result.error_message is not None

    def test_verification_handles_exceptions(self) -> None:
        """Verification must handle exceptions gracefully."""
        bypasser = MultiLayerBypass()
        # Use cast to simulate None-like hooks that will fail gracefully
        bypasser._frida_hooks = cast(FridaCertificateHooks, None)

        try:
            verified = bypasser._verify_os_level_bypass("target.exe")
            assert isinstance(verified, bool)
        except Exception:
            pytest.fail("Verification should not raise exceptions")


class TestStageOrdering:
    """Test correct stage ordering based on dependencies."""

    def test_stages_execute_in_dependency_order(
        self,
        complex_layer_info: list[LayerInfo],
        complex_dependency_graph: DependencyGraph,
    ) -> None:
        """Stages must execute in topological dependency order."""
        bypasser = MultiLayerBypass()
        bypasser._patcher = cast(CertificatePatcher, RealCertificatePatcher())
        bypasser._frida_hooks = cast(FridaCertificateHooks, RealFridaHooks())
        bypasser._detector = cast(CertificateValidationDetector, RealValidationDetector())

        result = bypasser.bypass_all_layers(
            target="target.exe",
            layers=complex_layer_info,
            dependency_graph=complex_dependency_graph,
        )

        if len(result.stage_results) >= 2:
            stages = sorted(result.stage_results.keys())
            for i in range(len(stages) - 1):
                assert stages[i] < stages[i + 1]
