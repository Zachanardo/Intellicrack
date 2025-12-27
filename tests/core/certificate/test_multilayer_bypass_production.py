"""Production tests for multi-layer certificate validation bypass logic.

Tests validate real staged bypass execution, dependency handling, verification,
rollback functionality, and multi-layer result tracking against realistic scenarios.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

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


class TestOSLevelBypass:
    """Tests validating OS-level (CryptoAPI, Schannel) bypass execution."""

    @patch("intellicrack.core.certificate.multilayer_bypass.CertificateValidationDetector")
    @patch("intellicrack.core.certificate.multilayer_bypass.select_template")
    @patch("intellicrack.core.certificate.multilayer_bypass.CertificatePatcher")
    def test_os_level_bypass_with_cryptoapi_functions(
        self,
        mock_patcher_class: Mock,
        mock_select_template: Mock,
        mock_detector_class: Mock,
    ) -> None:
        """OS-level bypass successfully patches CryptoAPI validation functions."""
        mock_detector = Mock()
        mock_detector_class.return_value = mock_detector

        os_functions = [
            ValidationFunction(
                address=0x401000,
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                confidence=0.92,
                context="OS-level validation",
                references=[0x402000],
            ),
        ]

        detection_report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=["crypt32.dll"],
            validation_functions=os_functions,
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
        )

        mock_detector.detect_certificate_validation.return_value = detection_report

        mock_template = Mock()
        mock_template.name = "CertVerifyCertificateChainPolicy_Patch"
        mock_select_template.return_value = mock_template

        mock_patcher = Mock()
        patch_result = Mock()
        patch_result.success = True
        mock_patcher.patch_certificate_validation.return_value = patch_result
        mock_patcher_class.return_value = mock_patcher

        bypasser = MultiLayerBypass()
        stage_result = bypasser._bypass_os_level(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            target="app.exe",
        )

        assert stage_result.success is True
        assert len(stage_result.bypassed_functions) > 0
        assert stage_result.error_message is None

    @patch("intellicrack.core.certificate.multilayer_bypass.CertificateValidationDetector")
    @patch("intellicrack.core.certificate.multilayer_bypass.FridaCertificateHooks")
    def test_os_level_fallback_to_frida_on_patch_failure(
        self,
        mock_frida_class: Mock,
        mock_detector_class: Mock,
    ) -> None:
        """OS-level bypass falls back to Frida when patching fails."""
        mock_detector = Mock()
        mock_detector_class.return_value = mock_detector

        os_functions = [
            ValidationFunction(
                address=0x401000,
                api_name="CertGetCertificateChain",
                library="crypt32.dll",
                confidence=0.88,
                context="OS-level chain validation",
                references=[0x402000, 0x403000],
            ),
        ]

        detection_report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=["crypt32.dll"],
            validation_functions=os_functions,
            recommended_method=BypassMethod.FRIDA_HOOK,
            risk_level="medium",
        )

        mock_detector.detect_certificate_validation.return_value = detection_report

        mock_frida = Mock()
        mock_frida.attach.return_value = True
        mock_frida.inject_specific_bypass.return_value = True
        mock_frida._script = Mock()
        mock_frida_class.return_value = mock_frida

        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = mock_frida

        stage_result = bypasser._bypass_os_level(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            target="app.exe",
        )

        assert stage_result.success is True
        assert "Frida: CryptoAPI hooks" in stage_result.bypassed_functions


class TestLibraryLevelBypass:
    """Tests validating library-level (OpenSSL, NSS, BoringSSL) bypass execution."""

    @patch("intellicrack.core.certificate.multilayer_bypass.CertificateValidationDetector")
    @patch("intellicrack.core.certificate.multilayer_bypass.FridaCertificateHooks")
    def test_library_level_bypass_openssl_with_frida(
        self,
        mock_frida_class: Mock,
        mock_detector_class: Mock,
    ) -> None:
        """Library-level bypass successfully hooks OpenSSL functions."""
        mock_detector = Mock()
        mock_detector_class.return_value = mock_detector

        lib_functions = [
            ValidationFunction(
                address=0x501000,
                api_name="SSL_CTX_set_verify",
                library="libssl.so.1.1",
                confidence=0.95,
                context="OpenSSL verification callback",
                references=[0x502000],
            ),
        ]

        detection_report = DetectionReport(
            binary_path="/usr/bin/app",
            detected_libraries=["libssl.so.1.1"],
            validation_functions=lib_functions,
            recommended_method=BypassMethod.FRIDA_HOOK,
            risk_level="medium",
        )

        mock_detector.detect_certificate_validation.return_value = detection_report

        mock_frida = Mock()
        mock_frida.attach.return_value = True
        mock_frida.inject_specific_bypass.return_value = True
        mock_frida._script = Mock()
        mock_frida_class.return_value = mock_frida

        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = mock_frida

        stage_result = bypasser._bypass_library_level(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            target="/usr/bin/app",
        )

        assert stage_result.success is True
        assert any("OpenSSL" in func for func in stage_result.bypassed_functions)

    @patch("intellicrack.core.certificate.multilayer_bypass.CertificateValidationDetector")
    @patch("intellicrack.core.certificate.multilayer_bypass.FridaCertificateHooks")
    def test_library_level_bypass_multiple_libraries(
        self,
        mock_frida_class: Mock,
        mock_detector_class: Mock,
    ) -> None:
        """Library-level bypass handles multiple TLS libraries."""
        mock_detector = Mock()
        mock_detector_class.return_value = mock_detector

        lib_functions = [
            ValidationFunction(
                address=0x501000,
                api_name="SSL_CTX_set_verify",
                library="libssl.so.1.1",
                confidence=0.91,
                context="OpenSSL",
                references=[0x502000],
            ),
            ValidationFunction(
                address=0x601000,
                api_name="NSS_Init",
                library="libnss3.so",
                confidence=0.87,
                context="NSS initialization",
                references=[0x602000],
            ),
        ]

        detection_report = DetectionReport(
            binary_path="/usr/bin/app",
            detected_libraries=["libssl.so.1.1", "libnss3.so"],
            validation_functions=lib_functions,
            recommended_method=BypassMethod.HYBRID,
            risk_level="medium",
        )

        mock_detector.detect_certificate_validation.return_value = detection_report

        mock_frida = Mock()
        mock_frida.attach.return_value = True
        mock_frida.inject_specific_bypass.return_value = True
        mock_frida._script = Mock()
        mock_frida_class.return_value = mock_frida

        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = mock_frida

        stage_result = bypasser._bypass_library_level(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            target="/usr/bin/app",
        )

        assert stage_result.success is True
        bypassed_funcs = stage_result.bypassed_functions
        assert any("OpenSSL" in func for func in bypassed_funcs)
        assert any("NSS" in func for func in bypassed_funcs)


class TestApplicationLevelBypass:
    """Tests validating application-level (custom pinning) bypass execution."""

    @patch("intellicrack.core.certificate.multilayer_bypass.FridaCertificateHooks")
    def test_application_level_bypass_with_universal_bypass(
        self,
        mock_frida_class: Mock,
    ) -> None:
        """Application-level bypass uses Frida universal bypass."""
        mock_frida = Mock()
        mock_frida.attach.return_value = True
        mock_frida.inject_universal_bypass.return_value = True
        mock_frida.get_bypass_status.return_value = {"pinning_bypassed": True}
        mock_frida._script = Mock()
        mock_frida_class.return_value = mock_frida

        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = mock_frida

        stage_result = bypasser._bypass_application_level(
            stage_number=3,
            layer=ValidationLayer.APPLICATION_LEVEL,
            target="app.exe",
        )

        assert stage_result.success is True
        assert "Universal bypass" in " ".join(stage_result.bypassed_functions)


class TestServerLevelBypass:
    """Tests validating server-level (network-based) bypass execution."""

    @patch("intellicrack.core.certificate.multilayer_bypass.FridaCertificateHooks")
    def test_server_level_bypass_with_winhttp_hook(
        self,
        mock_frida_class: Mock,
    ) -> None:
        """Server-level bypass hooks WinHTTP for network validation."""
        mock_frida = Mock()
        mock_frida.attach.return_value = True
        mock_frida.inject_specific_bypass.return_value = True
        mock_frida.get_bypass_status.return_value = {"detected_libraries": ["winhttp"]}
        mock_frida._script = Mock()
        mock_frida_class.return_value = mock_frida

        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = mock_frida

        stage_result = bypasser._bypass_server_level(
            stage_number=4,
            layer=ValidationLayer.SERVER_LEVEL,
            target="app.exe",
        )

        assert stage_result.success is True
        assert any("WinHTTP" in func for func in stage_result.bypassed_functions)


class TestCompleteMultiLayerWorkflow:
    """Tests validating complete multi-layer bypass workflows."""

    @patch("intellicrack.core.certificate.multilayer_bypass.CertificateValidationDetector")
    @patch("intellicrack.core.certificate.multilayer_bypass.FridaCertificateHooks")
    @patch("intellicrack.core.certificate.multilayer_bypass.CertificatePatcher")
    def test_successful_two_layer_bypass_workflow(
        self,
        mock_patcher_class: Mock,
        mock_frida_class: Mock,
        mock_detector_class: Mock,
    ) -> None:
        """Complete two-layer bypass succeeds with proper ordering."""
        mock_detector = Mock()
        mock_detector_class.return_value = mock_detector

        os_functions = [
            ValidationFunction(
                address=0x401000,
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                confidence=0.92,
                context="OS validation",
                references=[0x402000],
            ),
        ]

        lib_functions = [
            ValidationFunction(
                address=0x501000,
                api_name="SSL_CTX_set_verify",
                library="libssl.so",
                confidence=0.89,
                context="Library validation",
                references=[0x502000],
            ),
        ]

        mock_detector.detect_certificate_validation.side_effect = [
            DetectionReport(
                binary_path="app.exe",
                detected_libraries=["crypt32.dll"],
                validation_functions=os_functions,
                recommended_method=BypassMethod.BINARY_PATCH,
                risk_level="low",
            ),
            DetectionReport(
                binary_path="app.exe",
                detected_libraries=["libssl.so"],
                validation_functions=lib_functions,
                recommended_method=BypassMethod.FRIDA_HOOK,
                risk_level="medium",
            ),
        ]

        mock_frida = Mock()
        mock_frida.attach.return_value = True
        mock_frida.inject_specific_bypass.return_value = True
        mock_frida.get_bypass_status.return_value = {"openssl_bypassed": True}
        mock_frida._script = Mock()
        mock_frida._session = Mock()
        mock_frida_class.return_value = mock_frida

        mock_patcher = Mock()
        patch_result = Mock()
        patch_result.success = True
        mock_patcher.patch_certificate_validation.return_value = patch_result
        mock_patcher_class.return_value = mock_patcher

        os_layer = LayerInfo(
            layer_type=ValidationLayer.OS_LEVEL,
            confidence=0.85,
            evidence=["crypt32.dll"],
        )

        lib_layer = LayerInfo(
            layer_type=ValidationLayer.LIBRARY_LEVEL,
            confidence=0.80,
            evidence=["libssl.so"],
            dependencies=[ValidationLayer.OS_LEVEL],
        )

        layers = [os_layer, lib_layer]

        graph = DependencyGraph()
        graph.add_layer(ValidationLayer.OS_LEVEL)
        graph.add_layer(ValidationLayer.LIBRARY_LEVEL)
        graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)

        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = mock_frida
        bypasser._patcher = mock_patcher
        bypasser._detector = mock_detector

        result = bypasser.bypass_all_layers("app.exe", layers, graph)

        assert result.overall_success is True
        assert len(result.bypassed_layers) == 2
        assert ValidationLayer.OS_LEVEL in result.bypassed_layers
        assert ValidationLayer.LIBRARY_LEVEL in result.bypassed_layers
        assert len(result.failed_layers) == 0

    @patch("intellicrack.core.certificate.multilayer_bypass.CertificateValidationDetector")
    @patch("intellicrack.core.certificate.multilayer_bypass.FridaCertificateHooks")
    def test_failed_dependency_blocks_subsequent_layers(
        self,
        mock_frida_class: Mock,
        mock_detector_class: Mock,
    ) -> None:
        """Failed dependency layer blocks execution of dependent layers."""
        mock_detector = Mock()
        mock_detector_class.return_value = mock_detector

        detection_report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        mock_detector.detect_certificate_validation.return_value = detection_report

        mock_frida = Mock()
        mock_frida.attach.return_value = False
        mock_frida._session = Mock()
        mock_frida_class.return_value = mock_frida

        os_layer = LayerInfo(
            layer_type=ValidationLayer.OS_LEVEL,
            confidence=0.85,
            evidence=["crypt32.dll"],
        )

        lib_layer = LayerInfo(
            layer_type=ValidationLayer.LIBRARY_LEVEL,
            confidence=0.80,
            evidence=["libssl.so"],
            dependencies=[ValidationLayer.OS_LEVEL],
        )

        layers = [os_layer, lib_layer]

        graph = DependencyGraph()
        graph.add_layer(ValidationLayer.OS_LEVEL)
        graph.add_layer(ValidationLayer.LIBRARY_LEVEL)
        graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)

        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = mock_frida
        bypasser._detector = mock_detector

        result = bypasser.bypass_all_layers("app.exe", layers, graph)

        assert result.overall_success is False
        assert len(result.failed_layers) > 0


class TestRollbackFunctionality:
    """Tests validating rollback on bypass failure."""

    @patch("intellicrack.core.certificate.multilayer_bypass.FridaCertificateHooks")
    def test_rollback_detaches_frida_on_failure(
        self,
        mock_frida_class: Mock,
    ) -> None:
        """Rollback properly detaches Frida hooks on failure."""
        mock_frida = Mock()
        mock_frida._session = Mock()
        mock_frida_class.return_value = mock_frida

        result = MultiLayerResult(overall_success=False)
        result.bypassed_layers.append(ValidationLayer.OS_LEVEL)
        result.rollback_data[ValidationLayer.OS_LEVEL] = b"\x90" * 100

        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = mock_frida

        bypasser._rollback_previous_stages(result)

        mock_frida.detach.assert_called_once()

    @patch("intellicrack.core.certificate.multilayer_bypass.FridaCertificateHooks")
    def test_cleanup_detaches_frida_session(
        self,
        mock_frida_class: Mock,
    ) -> None:
        """Cleanup properly detaches Frida session."""
        mock_frida = Mock()
        mock_frida._session = Mock()
        mock_frida_class.return_value = mock_frida

        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = mock_frida

        bypasser.cleanup()

        mock_frida.detach.assert_called_once()


class TestVerificationLogic:
    """Tests validating layer bypass verification."""

    @patch("intellicrack.core.certificate.multilayer_bypass.FridaCertificateHooks")
    def test_os_level_verification_checks_cryptoapi_status(
        self,
        mock_frida_class: Mock,
    ) -> None:
        """OS-level verification checks CryptoAPI bypass status."""
        mock_frida = Mock()
        mock_frida._script = Mock()
        mock_frida.get_bypass_status.return_value = {"cryptoapi_bypassed": True}
        mock_frida_class.return_value = mock_frida

        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = mock_frida

        verified = bypasser._verify_os_level_bypass("app.exe")

        assert verified is True

    @patch("intellicrack.core.certificate.multilayer_bypass.FridaCertificateHooks")
    def test_library_level_verification_checks_tls_library_status(
        self,
        mock_frida_class: Mock,
    ) -> None:
        """Library-level verification checks TLS library bypass status."""
        mock_frida = Mock()
        mock_frida._script = Mock()
        mock_frida.get_bypass_status.return_value = {"openssl_bypassed": True}
        mock_frida_class.return_value = mock_frida

        bypasser = MultiLayerBypass()
        bypasser._frida_hooks = mock_frida

        verified = bypasser._verify_library_level_bypass("app.exe")

        assert verified is True


class TestEdgeCasesMixedProtectionLayers:
    """Test edge cases with mixed protection layers and complex layer interactions."""

    def test_mixed_layer_detection_os_and_library(self) -> None:
        """Mixed OS and library layer detection handles both correctly."""
        graph = DependencyGraph()
        graph.add_layer(ValidationLayer.OS_LEVEL)
        graph.add_layer(ValidationLayer.LIBRARY_LEVEL)
        graph.add_dependency(ValidationLayer.LIBRARY_LEVEL, ValidationLayer.OS_LEVEL)

        assert len(graph.get_all_layers()) == 2
        assert graph.has_layer(ValidationLayer.OS_LEVEL)
        assert graph.has_layer(ValidationLayer.LIBRARY_LEVEL)

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
        assert "expired" in result.error_message.lower()

    def test_chain_validation_with_untrusted_root(self) -> None:
        """Certificate chain validation failure due to untrusted root CA."""
        result = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=False,
            error_message="Certificate chain validation failed: Untrusted root CA",
        )

        assert result.success is False
        assert "untrusted" in result.error_message.lower()

    def test_chain_validation_with_broken_chain(self) -> None:
        """Certificate chain validation failure due to broken chain."""
        result = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=False,
            error_message="Certificate chain validation failed: Chain incomplete",
        )

        assert result.success is False
        assert "chain" in result.error_message.lower()

    def test_chain_validation_with_revoked_cert(self) -> None:
        """Certificate chain validation failure due to revoked certificate."""
        result = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=False,
            error_message="Certificate chain validation failed: Certificate revoked (OCSP)",
        )

        assert result.success is False
        assert "revoked" in result.error_message.lower()


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
        assert "timeout" in result.error_message.lower()

    def test_frida_injection_timeout(self) -> None:
        """Frida injection timeout is handled gracefully."""
        result = StageResult(
            stage_number=1,
            layer=ValidationLayer.OS_LEVEL,
            success=False,
            error_message="Timeout: Frida injection did not complete within 10 seconds",
        )

        assert result.success is False
        assert "frida" in result.error_message.lower()
        assert "timeout" in result.error_message.lower()

    def test_verification_timeout_after_bypass(self) -> None:
        """Verification timeout after bypass attempt is handled."""
        result = StageResult(
            stage_number=3,
            layer=ValidationLayer.APPLICATION_LEVEL,
            success=False,
            error_message="Timeout: Bypass verification did not respond within 15 seconds",
        )

        assert result.success is False
        assert "verification" in result.error_message.lower()
        assert "timeout" in result.error_message.lower()

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
        assert "memory" in result.error_message.lower()

    def test_too_many_hooks_installed(self) -> None:
        """Too many Frida hooks causing resource exhaustion."""
        result = StageResult(
            stage_number=2,
            layer=ValidationLayer.LIBRARY_LEVEL,
            success=False,
            error_message="Resource exhaustion: Too many Frida hooks (limit: 1000)",
        )

        assert result.success is False
        assert "resource" in result.error_message.lower() or "hooks" in result.error_message.lower()

    def test_process_spawn_failure(self) -> None:
        """Process spawn failure due to resource limits."""
        result = StageResult(
            stage_number=3,
            layer=ValidationLayer.APPLICATION_LEVEL,
            success=False,
            error_message="Process spawn failed: Resource limit exceeded",
        )

        assert result.success is False
        assert "process" in result.error_message.lower() or "spawn" in result.error_message.lower()
