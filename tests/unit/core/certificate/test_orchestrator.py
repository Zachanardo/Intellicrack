"""Unit tests for bypass orchestrator module.

This test suite validates the CertificateBypassOrchestrator functionality with
comprehensive coverage of workflow orchestration, method execution, and verification.
Tests use mocking to avoid dependencies on real binaries and external tools.
"""

import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, PropertyMock
from typing import Dict, List

from intellicrack.core.certificate.bypass_orchestrator import (
    CertificateBypassOrchestrator,
    BypassResult,
)
from intellicrack.core.certificate.detection_report import (
    DetectionReport,
    ValidationFunction,
    BypassMethod,
)
from intellicrack.core.certificate.cert_patcher import PatchResult, PatchedFunction
from intellicrack.core.certificate.patch_generators import PatchType


@pytest.fixture
def orchestrator():
    """Create orchestrator instance for testing."""
    return CertificateBypassOrchestrator()


@pytest.fixture
def sample_detection_report():
    """Create sample detection report."""
    return DetectionReport(
        binary_path="test.exe",
        detected_libraries=["winhttp.dll"],
        validation_functions=[
            ValidationFunction(
                address=0x140001234,
                api_name="WinHttpSetOption",
                library="winhttp.dll",
                confidence=0.9,
                context="license validation",
                references=[],
            )
        ],
        recommended_method=BypassMethod.BINARY_PATCH,
        risk_level="low",
        timestamp=datetime.now(),
    )


@pytest.fixture
def sample_patch_result():
    """Create sample patch result."""
    return PatchResult(
        success=True,
        patched_functions=[
            PatchedFunction(
                address=0x140001234,
                api_name="WinHttpSetOption",
                patch_type=PatchType.ALWAYS_SUCCEED,
                patch_size=8,
                original_bytes=b"\x48\x8b\xec\x48\x83\xec\x20\xc3",
            )
        ],
        failed_patches=[],
        backup_data=b"\x48\x8b\xec\x48\x83\xec\x20\xc3",
    )


class TestOrchestratorInitialization:
    """Tests for orchestrator initialization."""

    def test_orchestrator_initializes_with_components(self, orchestrator):
        """Test orchestrator initializes with all required components."""
        assert orchestrator.detector is not None
        assert orchestrator.strategy_selector is not None
        assert orchestrator.frida_hooks is None


class TestTargetAnalysis:
    """Tests for target analysis."""

    @patch("intellicrack.core.certificate.bypass_orchestrator.Path")
    def test_analyze_existing_file_target(self, mock_path, orchestrator):
        """Test analyzing existing file target."""
        mock_path_instance = Mock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.is_file.return_value = True
        mock_path_instance.name = "test.exe"
        mock_path.return_value = mock_path_instance

        with patch.object(orchestrator, "_is_process_running", return_value=False):
            target_path, is_running = orchestrator._analyze_target("C:/test.exe")

        assert target_path == mock_path_instance
        assert is_running is False

    @patch("intellicrack.core.certificate.bypass_orchestrator.psutil")
    @patch("intellicrack.core.certificate.bypass_orchestrator.Path")
    def test_analyze_pid_target(self, mock_path, mock_psutil, orchestrator):
        """Test analyzing target by PID."""
        mock_path_instance = Mock()
        mock_path_instance.exists.return_value = False
        mock_path.return_value = mock_path_instance

        mock_process = Mock()
        mock_process.exe.return_value = "C:/test.exe"
        mock_psutil.Process.return_value = mock_process

        mock_result_path = Mock()
        mock_path.side_effect = [mock_path_instance, mock_result_path]

        target_path, is_running = orchestrator._analyze_target("1234")

        assert is_running is True
        mock_psutil.Process.assert_called_once_with(1234)

    @patch("intellicrack.core.certificate.bypass_orchestrator.Path")
    def test_analyze_process_name_target(self, mock_path, orchestrator):
        """Test analyzing target by process name."""
        import sys
        mock_psutil = sys.modules["psutil"]

        mock_path_instance = Mock()
        mock_path_instance.exists.return_value = False
        mock_path.return_value = mock_path_instance

        mock_proc = Mock()
        mock_proc.info = {"name": "target.exe", "exe": "C:/target.exe"}
        mock_psutil.process_iter.return_value = [mock_proc]

        mock_result_path = Mock()
        mock_path.side_effect = [mock_path_instance, mock_result_path]

        target_path, is_running = orchestrator._analyze_target("target.exe")

        assert is_running is True

        mock_psutil.process_iter.return_value = []

    @patch("intellicrack.core.certificate.bypass_orchestrator.psutil")
    def test_is_process_running_when_running(self, mock_psutil, orchestrator):
        """Test checking if process is running when it is."""
        mock_proc = Mock()
        mock_proc.info = {"name": "test.exe"}
        mock_psutil.process_iter.return_value = [mock_proc]

        result = orchestrator._is_process_running("test.exe")

        assert result is True

    @patch("intellicrack.core.certificate.bypass_orchestrator.psutil")
    def test_is_process_running_when_not_running(self, mock_psutil, orchestrator):
        """Test checking if process is running when it's not."""
        mock_psutil.process_iter.return_value = []

        result = orchestrator._is_process_running("test.exe")

        assert result is False


class TestBypassWorkflow:
    """Tests for complete bypass workflow."""

    @patch.object(CertificateBypassOrchestrator, "_verify_bypass")
    @patch.object(CertificateBypassOrchestrator, "_execute_binary_patch")
    @patch.object(CertificateBypassOrchestrator, "_analyze_target")
    @patch("intellicrack.core.certificate.bypass_orchestrator.CertificateValidationDetector")
    def test_bypass_with_no_validation_detected(
        self, mock_detector_cls, mock_analyze, mock_exec_patch, mock_verify, orchestrator
    ):
        """Test bypass when no validation is detected."""
        mock_path = Mock()
        mock_path.exists.return_value = True
        mock_analyze.return_value = (mock_path, False)

        mock_detector = Mock()
        empty_report = DetectionReport(
            binary_path="test.exe",
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
            timestamp=datetime.now(),
        )
        mock_detector.detect_certificate_validation.return_value = empty_report
        orchestrator.detector = mock_detector

        result = orchestrator.bypass("test.exe")

        assert result.success is True
        assert result.method_used == BypassMethod.NONE
        assert result.verification_passed is True
        mock_exec_patch.assert_not_called()

    @patch.object(CertificateBypassOrchestrator, "_verify_bypass")
    @patch.object(CertificateBypassOrchestrator, "_execute_binary_patch")
    @patch.object(CertificateBypassOrchestrator, "_analyze_target")
    def test_bypass_with_binary_patch_method(
        self, mock_analyze, mock_exec_patch, mock_verify,
        orchestrator, sample_detection_report, sample_patch_result
    ):
        """Test bypass using binary patch method."""
        mock_path = Mock()
        mock_path.exists.return_value = True
        mock_analyze.return_value = (mock_path, False)

        orchestrator.detector.detect_certificate_validation = Mock(
            return_value=sample_detection_report
        )
        mock_exec_patch.return_value = sample_patch_result
        mock_verify.return_value = True

        result = orchestrator.bypass("test.exe", method=BypassMethod.BINARY_PATCH)

        assert result.success is True
        assert result.method_used == BypassMethod.BINARY_PATCH
        assert result.patch_result is not None
        assert result.verification_passed is True
        mock_exec_patch.assert_called_once()

    @patch.object(CertificateBypassOrchestrator, "_verify_bypass")
    @patch.object(CertificateBypassOrchestrator, "_execute_frida_hook")
    @patch.object(CertificateBypassOrchestrator, "_analyze_target")
    def test_bypass_with_frida_hook_method(
        self, mock_analyze, mock_exec_frida, mock_verify,
        orchestrator, sample_detection_report
    ):
        """Test bypass using Frida hook method."""
        mock_path = Mock()
        mock_path.exists.return_value = True
        mock_analyze.return_value = (mock_path, True)

        orchestrator.detector.detect_certificate_validation = Mock(
            return_value=sample_detection_report
        )
        mock_exec_frida.return_value = {"success": True, "active_hooks": ["SSL_verify"]}
        mock_verify.return_value = True

        result = orchestrator.bypass("test.exe", method=BypassMethod.FRIDA_HOOK)

        assert result.success is True
        assert result.method_used == BypassMethod.FRIDA_HOOK
        assert result.frida_status is not None
        mock_exec_frida.assert_called_once()

    @patch.object(CertificateBypassOrchestrator, "_verify_bypass")
    @patch.object(CertificateBypassOrchestrator, "_execute_frida_hook")
    @patch.object(CertificateBypassOrchestrator, "_execute_binary_patch")
    @patch.object(CertificateBypassOrchestrator, "_analyze_target")
    def test_bypass_with_hybrid_method(
        self, mock_analyze, mock_exec_patch, mock_exec_frida, mock_verify,
        orchestrator, sample_detection_report, sample_patch_result
    ):
        """Test bypass using hybrid method."""
        mock_path = Mock()
        mock_path.exists.return_value = True
        mock_analyze.return_value = (mock_path, True)

        orchestrator.detector.detect_certificate_validation = Mock(
            return_value=sample_detection_report
        )
        mock_exec_patch.return_value = sample_patch_result
        mock_exec_frida.return_value = {"success": True}
        mock_verify.return_value = True

        result = orchestrator.bypass("test.exe", method=BypassMethod.HYBRID)

        assert result.success is True
        assert result.method_used == BypassMethod.HYBRID
        assert result.patch_result is not None
        assert result.frida_status is not None
        mock_exec_patch.assert_called_once()
        mock_exec_frida.assert_called_once()

    @patch.object(CertificateBypassOrchestrator, "_analyze_target")
    def test_bypass_fails_when_target_not_found(self, mock_analyze, orchestrator):
        """Test bypass fails when target doesn't exist."""
        mock_path = Mock()
        mock_path.exists.return_value = False
        mock_analyze.return_value = (mock_path, False)

        result = orchestrator.bypass("nonexistent.exe")

        assert result.success is False
        assert len(result.errors) > 0

    @patch.object(CertificateBypassOrchestrator, "_verify_bypass")
    @patch.object(CertificateBypassOrchestrator, "_execute_binary_patch")
    @patch.object(CertificateBypassOrchestrator, "_analyze_target")
    def test_bypass_with_automatic_strategy_selection(
        self, mock_analyze, mock_exec_patch, mock_verify,
        orchestrator, sample_detection_report, sample_patch_result
    ):
        """Test bypass with automatic strategy selection."""
        mock_path = Mock()
        mock_path.exists.return_value = True
        mock_analyze.return_value = (mock_path, False)

        orchestrator.detector.detect_certificate_validation = Mock(
            return_value=sample_detection_report
        )
        orchestrator.strategy_selector.select_optimal_strategy = Mock(
            return_value=BypassMethod.BINARY_PATCH
        )
        mock_exec_patch.return_value = sample_patch_result
        mock_verify.return_value = True

        result = orchestrator.bypass("test.exe")

        assert result.method_used == BypassMethod.BINARY_PATCH
        orchestrator.strategy_selector.select_optimal_strategy.assert_called_once()


class TestBypassExecution:
    """Tests for individual bypass method execution."""

    def test_execute_binary_patch_successfully(
        self, orchestrator, sample_detection_report, sample_patch_result
    ):
        """Test successful binary patch execution."""
        with patch("intellicrack.core.certificate.bypass_orchestrator.CertificatePatcher") as mock_patcher_cls:
            mock_patcher = Mock()
            mock_patcher.patch_certificate_validation.return_value = sample_patch_result
            mock_patcher_cls.return_value = mock_patcher

            result = orchestrator._execute_binary_patch(sample_detection_report)

            assert result.success is True
            assert len(result.patched_functions) > 0

    def test_execute_binary_patch_handles_errors(
        self, orchestrator, sample_detection_report
    ):
        """Test binary patch execution handles errors."""
        with patch("intellicrack.core.certificate.bypass_orchestrator.CertificatePatcher") as mock_patcher_cls:
            mock_patcher_cls.side_effect = Exception("Patcher failed")

            with pytest.raises(Exception):
                orchestrator._execute_binary_patch(sample_detection_report)

    def test_execute_frida_hook_successfully(self, orchestrator):
        """Test successful Frida hook execution."""
        with patch("intellicrack.core.certificate.bypass_orchestrator.FridaCertificateHooks") as mock_hooks_cls:
            mock_hooks = Mock()
            mock_hooks.attach.return_value = True
            mock_hooks.inject_universal_bypass.return_value = True
            mock_hooks.get_bypass_status.return_value = {
                "active": True,
                "active_hooks": ["SSL_verify"],
            }
            mock_hooks_cls.return_value = mock_hooks

            orchestrator.frida_hooks = None
            result = orchestrator._execute_frida_hook("test.exe")

            assert result["success"] is True
            mock_hooks.attach.assert_called_once()

    def test_execute_frida_hook_fails_on_attach_error(self, orchestrator):
        """Test Frida hook execution fails when attach fails."""
        with patch("intellicrack.core.certificate.bypass_orchestrator.FridaCertificateHooks") as mock_hooks_cls:
            mock_hooks = Mock()
            mock_hooks.attach.return_value = False
            mock_hooks_cls.return_value = mock_hooks

            orchestrator.frida_hooks = None
            result = orchestrator._execute_frida_hook("test.exe")

            assert result["success"] is False
            assert "error" in result

    @patch("intellicrack.core.certificate.bypass_orchestrator.Path")
    @patch.object(CertificateBypassOrchestrator, "_extract_licensing_domains")
    def test_execute_mitm_proxy_successfully(
        self, mock_extract, mock_path_cls, orchestrator
    ):
        """Test successful MITM proxy execution."""
        mock_extract.return_value = ["license.example.com"]

        with patch("intellicrack.core.certificate.cert_cache.CertificateCache") as mock_cache_cls:
            with patch("intellicrack.core.certificate.cert_chain_generator.CertificateChainGenerator") as mock_gen_cls:
                mock_cache = Mock()
                mock_cache.get_cached_cert.return_value = None

                mock_gen = Mock()
                mock_chain = Mock()
                mock_chain.leaf_cert = Mock()
                mock_chain.leaf_cert.public_bytes.return_value = b"cert"
                mock_chain.leaf_key = Mock()
                mock_chain.leaf_key.private_bytes.return_value = b"key"
                mock_gen.generate_full_chain.return_value = mock_chain

                mock_cache_cls.return_value = mock_cache
                mock_gen_cls.return_value = mock_gen

                mock_path = Mock()
                mock_path.mkdir = Mock()
                mock_path.__truediv__ = Mock(return_value=mock_path)
                mock_path_cls.home.return_value = mock_path

                with patch("builtins.open", create=True) as mock_open:
                    result = orchestrator._execute_mitm_proxy("test.exe")

                assert result is True


class TestDomainExtraction:
    """Tests for licensing domain extraction."""

    @patch("intellicrack.core.certificate.binary_scanner.BinaryScanner")
    @patch("intellicrack.core.certificate.bypass_orchestrator.Path")
    def test_extract_licensing_domains_from_binary(
        self, mock_path_cls, mock_scanner_cls, orchestrator
    ):
        """Test extracting licensing domains from binary strings."""
        mock_path = Mock()
        mock_path.exists.return_value = True
        mock_path_cls.return_value = mock_path

        mock_scanner = Mock()
        mock_scanner.__enter__ = Mock(return_value=mock_scanner)
        mock_scanner.__exit__ = Mock(return_value=False)
        mock_scanner.scan_strings.return_value = [
            "https://license.example.com/activate",
            "https://api.example.com/verify",
            "https://unrelated.com/data",
        ]
        mock_scanner_cls.return_value = mock_scanner

        domains = orchestrator._extract_licensing_domains("test.exe")

        assert any(d == "license.example.com" or d.endswith(".license.example.com") for d in domains)
        assert any(d == "api.example.com" or d.endswith(".api.example.com") for d in domains)

    @patch("intellicrack.core.certificate.bypass_orchestrator.Path")
    def test_extract_licensing_domains_handles_nonexistent_file(
        self, mock_path_cls, orchestrator
    ):
        """Test domain extraction returns empty when file doesn't exist."""
        mock_path = Mock()
        mock_path.exists.return_value = False
        mock_path_cls.return_value = mock_path

        domains = orchestrator._extract_licensing_domains("nonexistent.exe")

        assert domains == []


class TestBypassVerification:
    """Tests for bypass verification."""

    @patch.object(CertificateBypassOrchestrator, "_verify_validation_bypassed")
    @patch.object(CertificateBypassOrchestrator, "_verify_frida_hooks")
    @patch.object(CertificateBypassOrchestrator, "_verify_binary_patches")
    def test_verify_bypass_all_methods_pass(
        self, mock_verify_patches, mock_verify_frida, mock_verify_validation, orchestrator
    ):
        """Test verification when all methods pass."""
        mock_verify_patches.return_value = True
        mock_verify_frida.return_value = True
        mock_verify_validation.return_value = True

        result = orchestrator._verify_bypass(Path("test.exe"))

        assert result is True

    @patch.object(CertificateBypassOrchestrator, "_verify_validation_bypassed")
    @patch.object(CertificateBypassOrchestrator, "_verify_frida_hooks")
    @patch.object(CertificateBypassOrchestrator, "_verify_binary_patches")
    def test_verify_bypass_passes_with_partial_success(
        self, mock_verify_patches, mock_verify_frida, mock_verify_validation, orchestrator
    ):
        """Test verification passes with at least 33% confidence."""
        mock_verify_patches.return_value = True
        mock_verify_frida.return_value = False
        mock_verify_validation.return_value = False

        result = orchestrator._verify_bypass(Path("test.exe"))

        assert result is True

    @patch.object(CertificateBypassOrchestrator, "_verify_validation_bypassed")
    @patch.object(CertificateBypassOrchestrator, "_verify_frida_hooks")
    @patch.object(CertificateBypassOrchestrator, "_verify_binary_patches")
    def test_verify_bypass_fails_with_all_methods_failing(
        self, mock_verify_patches, mock_verify_frida, mock_verify_validation, orchestrator
    ):
        """Test verification fails when all methods fail."""
        mock_verify_patches.return_value = False
        mock_verify_frida.return_value = False
        mock_verify_validation.return_value = False

        result = orchestrator._verify_bypass(Path("test.exe"))

        assert result is False

    @patch("builtins.open", create=True)
    @patch("intellicrack.core.certificate.bypass_orchestrator.Path")
    def test_verify_binary_patches_detects_patch_signatures(
        self, mock_path_cls, mock_open, orchestrator
    ):
        """Test patch verification detects known signatures."""
        mock_path = Mock()
        mock_path.exists.return_value = True
        mock_path_cls.return_value = mock_path

        patch_signature = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])
        binary_data = b"\x00" * 100 + patch_signature + b"\x00" * 100

        mock_file = Mock()
        mock_file.read.return_value = binary_data
        mock_file.__enter__ = Mock(return_value=mock_file)
        mock_file.__exit__ = Mock(return_value=False)
        mock_open.return_value = mock_file

        result = orchestrator._verify_binary_patches(mock_path)

        assert result is True

    def test_verify_frida_hooks_when_hooks_active(self, orchestrator):
        """Test Frida verification when hooks are active."""
        mock_hooks = Mock()
        mock_hooks.is_attached.return_value = True

        mock_status = Mock()
        mock_status.active = True
        mock_status.active_hooks = ["SSL_verify", "SSL_set_verify"]
        mock_hooks.get_bypass_status.return_value = mock_status

        orchestrator.frida_hooks = mock_hooks

        result = orchestrator._verify_frida_hooks()

        assert result is True

    def test_verify_frida_hooks_when_no_hooks(self, orchestrator):
        """Test Frida verification when no hooks present."""
        orchestrator.frida_hooks = None

        result = orchestrator._verify_frida_hooks()

        assert result is False


class TestRollback:
    """Tests for rollback functionality."""

    def test_rollback_binary_patches(self, orchestrator, sample_patch_result):
        """Test rollback of binary patches."""
        bypass_result = BypassResult(
            success=True,
            method_used=BypassMethod.BINARY_PATCH,
            detection_report=Mock(binary_path="test.exe"),
            patch_result=sample_patch_result,
        )

        with patch("intellicrack.core.certificate.bypass_orchestrator.CertificatePatcher") as mock_patcher_cls:
            mock_patcher = Mock()
            mock_patcher.rollback_patches.return_value = True
            mock_patcher_cls.return_value = mock_patcher

            result = orchestrator.rollback(bypass_result)

            assert result is True
            mock_patcher.rollback_patches.assert_called_once()

    def test_rollback_frida_hooks(self, orchestrator):
        """Test rollback of Frida hooks."""
        bypass_result = BypassResult(
            success=True,
            method_used=BypassMethod.FRIDA_HOOK,
            detection_report=Mock(binary_path="test.exe"),
            frida_status={"active": True},
        )

        mock_hooks = Mock()
        mock_hooks.detach.return_value = True
        orchestrator.frida_hooks = mock_hooks

        result = orchestrator.rollback(bypass_result)

        assert result is True
        mock_hooks.detach.assert_called_once()

    def test_rollback_handles_errors_gracefully(self, orchestrator, sample_patch_result):
        """Test rollback handles errors without crashing."""
        bypass_result = BypassResult(
            success=True,
            method_used=BypassMethod.BINARY_PATCH,
            detection_report=Mock(binary_path="test.exe"),
            patch_result=sample_patch_result,
        )

        with patch("intellicrack.core.certificate.bypass_orchestrator.CertificatePatcher") as mock_patcher_cls:
            mock_patcher = Mock()
            mock_patcher.rollback_patches.side_effect = Exception("Rollback failed")
            mock_patcher_cls.return_value = mock_patcher

            result = orchestrator.rollback(bypass_result)

            assert result is False


class TestBypassResult:
    """Tests for BypassResult dataclass."""

    def test_bypass_result_to_dict(self, sample_detection_report):
        """Test BypassResult conversion to dictionary."""
        result = BypassResult(
            success=True,
            method_used=BypassMethod.BINARY_PATCH,
            detection_report=sample_detection_report,
            verification_passed=True,
            errors=[],
        )

        result_dict = result.to_dict()

        assert result_dict["success"] is True
        assert result_dict["method_used"] == "binary_patch"
        assert result_dict["verification_passed"] is True
        assert "detection_summary" in result_dict


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
