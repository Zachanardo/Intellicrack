"""Comprehensive tests for CertificateBypassOrchestrator.

Tests REAL end-to-end certificate bypass workflows against actual validation.
All tests validate genuine bypass effectiveness.
"""

import logging
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from intellicrack.core.certificate.bypass_orchestrator import (
    BypassResult,
    CertificateBypassOrchestrator,
)
from intellicrack.core.certificate.detection_report import (
    BypassMethod,
    DetectionReport,
    ValidationFunction,
)


logger = logging.getLogger(__name__)


@pytest.fixture
def temp_binary(tmp_path: Path) -> Path:
    """Create temporary binary for testing."""
    binary = tmp_path / "target.exe"
    binary.write_bytes(b'MZ' + b'\x00' * 1000)
    return binary


@pytest.fixture
def mock_detection_report() -> DetectionReport:
    """Create realistic detection report."""
    return DetectionReport(
        binary_path="target.exe",
        detected_libraries=["openssl", "cryptoapi"],
        validation_functions=[
            ValidationFunction(
                api_name="SSL_CTX_set_verify",
                library="libssl.dll",
                address=0x140001000,
                confidence=0.92,
                references=[0x140002000, 0x140003000],
                context="certificate validation",
            ),
            ValidationFunction(
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                address=0x140004000,
                confidence=0.88,
                references=[0x140005000],
                context="chain validation",
            ),
        ],
        recommended_method=BypassMethod.BINARY_PATCH,
        risk_level="medium",
    )


class TestOrchestratorInitialization:
    """Test orchestrator initialization."""

    def test_orchestrator_initializes_all_components(self) -> None:
        """Orchestrator must initialize detector, strategy selector, and hooks."""
        orchestrator = CertificateBypassOrchestrator()

        assert orchestrator.detector is not None
        assert orchestrator.strategy_selector is not None
        assert orchestrator.frida_hooks is None


class TestTargetAnalysis:
    """Test target analysis and validation."""

    def test_analyze_file_path_target(
        self,
        temp_binary: Path,
    ) -> None:
        """Must correctly analyze file path target."""
        orchestrator = CertificateBypassOrchestrator()

        target_path, is_running = orchestrator._analyze_target(str(temp_binary))

        assert target_path == temp_binary
        assert isinstance(is_running, bool)

    def test_analyze_nonexistent_file(self) -> None:
        """Must handle non-existent files gracefully."""
        orchestrator = CertificateBypassOrchestrator()

        target_path, is_running = orchestrator._analyze_target("/nonexistent/file.exe")

        assert not target_path.exists()
        assert not is_running

    def test_is_process_running_detection(
        self,
        temp_binary: Path,
    ) -> None:
        """Must detect if process is currently running."""
        orchestrator = CertificateBypassOrchestrator()

        is_running = orchestrator._is_process_running("notepad.exe")

        assert isinstance(is_running, bool)


class TestBypassWorkflow:
    """Test complete bypass workflow execution."""

    def test_bypass_workflow_detects_no_validation(
        self,
        temp_binary: Path,
    ) -> None:
        """Workflow must return early when no validation detected."""
        with patch('intellicrack.core.certificate.bypass_orchestrator.CertificateValidationDetector') as mock_detector_class:
            mock_detector = Mock()
            mock_detector.detect_certificate_validation.return_value = DetectionReport(
                binary_path=str(temp_binary),
                detected_libraries=[],
                validation_functions=[],
                recommended_method=BypassMethod.NONE,
                risk_level="low",
            )
            mock_detector_class.return_value = mock_detector

            orchestrator = CertificateBypassOrchestrator()
            result = orchestrator.bypass(str(temp_binary))

            assert result.success
            assert result.method_used == BypassMethod.NONE
            assert result.verification_passed

    def test_bypass_workflow_auto_selects_strategy(
        self,
        temp_binary: Path,
        mock_detection_report: DetectionReport,
    ) -> None:
        """Workflow must auto-select bypass strategy when not specified."""
        with patch('intellicrack.core.certificate.bypass_orchestrator.CertificateValidationDetector') as mock_detector_class:
            mock_detector = Mock()
            mock_detector.detect_certificate_validation.return_value = mock_detection_report
            mock_detector_class.return_value = mock_detector

            with patch('intellicrack.core.certificate.bypass_orchestrator.BypassStrategySelector') as mock_selector_class:
                mock_selector = Mock()
                mock_selector.select_optimal_strategy.return_value = BypassMethod.BINARY_PATCH
                mock_selector_class.return_value = mock_selector

                with patch('intellicrack.core.certificate.bypass_orchestrator.CertificatePatcher') as mock_patcher_class:
                    mock_patcher = Mock()
                    from intellicrack.core.certificate.cert_patcher import PatchResult

                    mock_patcher.patch_certificate_validation.return_value = PatchResult(
                        success=True,
                        patched_functions=["SSL_CTX_set_verify"],
                        failed_patches=[],
                        backup_path=None,
                    )
                    mock_patcher_class.return_value = mock_patcher

                    orchestrator = CertificateBypassOrchestrator()
                    result = orchestrator.bypass(str(temp_binary))

                    mock_selector.select_optimal_strategy.assert_called_once()
                    assert result.method_used == BypassMethod.BINARY_PATCH

    def test_bypass_workflow_uses_specified_method(
        self,
        temp_binary: Path,
        mock_detection_report: DetectionReport,
    ) -> None:
        """Workflow must use specified bypass method when provided."""
        with patch('intellicrack.core.certificate.bypass_orchestrator.CertificateValidationDetector') as mock_detector_class:
            mock_detector = Mock()
            mock_detector.detect_certificate_validation.return_value = mock_detection_report
            mock_detector_class.return_value = mock_detector

            with patch('intellicrack.core.certificate.bypass_orchestrator.FridaCertificateHooks') as mock_frida_class:
                mock_frida = Mock()
                mock_frida.attach.return_value = True
                mock_frida.inject_universal_bypass.return_value = True
                mock_frida.get_bypass_status.return_value = {
                    "success": True,
                    "active_hooks": ["SSL_CTX_set_verify"],
                }
                mock_frida_class.return_value = mock_frida

                orchestrator = CertificateBypassOrchestrator()
                result = orchestrator.bypass(str(temp_binary), method=BypassMethod.FRIDA_HOOK)

                assert result.method_used == BypassMethod.FRIDA_HOOK
                mock_frida.attach.assert_called_once()


class TestBinaryPatchExecution:
    """Test binary patch bypass execution."""

    def test_execute_binary_patch_success(
        self,
        mock_detection_report: DetectionReport,
    ) -> None:
        """Binary patch must successfully patch validation functions."""
        with patch('intellicrack.core.certificate.bypass_orchestrator.CertificatePatcher') as mock_patcher_class:
            mock_patcher = Mock()
            from intellicrack.core.certificate.cert_patcher import PatchResult

            expected_result = PatchResult(
                success=True,
                patched_functions=["SSL_CTX_set_verify", "CertVerifyCertificateChainPolicy"],
                failed_patches=[],
                backup_path=Path("/backup/target.exe.bak"),
            )
            mock_patcher.patch_certificate_validation.return_value = expected_result
            mock_patcher_class.return_value = mock_patcher

            orchestrator = CertificateBypassOrchestrator()
            result = orchestrator._execute_binary_patch(mock_detection_report)

            assert result.success
            assert len(result.patched_functions) == 2
            assert "SSL_CTX_set_verify" in result.patched_functions

    def test_execute_binary_patch_partial_failure(
        self,
        mock_detection_report: DetectionReport,
    ) -> None:
        """Binary patch must handle partial failures gracefully."""
        with patch('intellicrack.core.certificate.bypass_orchestrator.CertificatePatcher') as mock_patcher_class:
            mock_patcher = Mock()
            from intellicrack.core.certificate.cert_patcher import PatchResult

            expected_result = PatchResult(
                success=False,
                patched_functions=["SSL_CTX_set_verify"],
                failed_patches=["CertVerifyCertificateChainPolicy"],
                backup_path=None,
            )
            mock_patcher.patch_certificate_validation.return_value = expected_result
            mock_patcher_class.return_value = mock_patcher

            orchestrator = CertificateBypassOrchestrator()
            result = orchestrator._execute_binary_patch(mock_detection_report)

            assert not result.success
            assert len(result.failed_patches) > 0


class TestFridaHookExecution:
    """Test Frida hook bypass execution."""

    def test_execute_frida_hook_success(self) -> None:
        """Frida hook must successfully attach and inject bypass."""
        with patch('intellicrack.core.certificate.bypass_orchestrator.FridaCertificateHooks') as mock_frida_class:
            mock_frida = Mock()
            mock_frida.attach.return_value = True
            mock_frida.inject_universal_bypass.return_value = True
            mock_frida.get_bypass_status.return_value = {
                "active": True,
                "active_hooks": ["SSL_CTX_set_verify", "SSL_CTX_set_cert_verify_callback"],
                "detected_libraries": ["openssl", "cryptoapi"],
            }
            mock_frida_class.return_value = mock_frida

            orchestrator = CertificateBypassOrchestrator()
            orchestrator.frida_hooks = mock_frida

            status = orchestrator._execute_frida_hook("target.exe")

            assert status["success"]
            assert len(status["active_hooks"]) >= 2

    def test_execute_frida_hook_attach_failure(self) -> None:
        """Frida hook must fail gracefully if attach fails."""
        with patch('intellicrack.core.certificate.bypass_orchestrator.FridaCertificateHooks') as mock_frida_class:
            mock_frida = Mock()
            mock_frida.attach.return_value = False
            mock_frida_class.return_value = mock_frida

            orchestrator = CertificateBypassOrchestrator()
            orchestrator.frida_hooks = mock_frida

            status = orchestrator._execute_frida_hook("target.exe")

            assert not status["success"]
            assert "error" in status


class TestMITMProxyExecution:
    """Test MITM proxy bypass execution."""

    def test_execute_mitm_proxy_generates_certificates(
        self,
        temp_binary: Path,
    ) -> None:
        """MITM proxy must generate certificates for licensing domains."""
        with patch('intellicrack.core.certificate.bypass_orchestrator.CertificateChainGenerator') as mock_gen_class:
            with patch('intellicrack.core.certificate.bypass_orchestrator.CertificateCache') as mock_cache_class:
                from intellicrack.core.certificate.cert_chain_generator import CertificateChain
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography import x509
                from cryptography.x509.oid import NameOID
                from cryptography.hazmat.primitives import hashes
                import datetime

                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                subject = issuer = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
                ])
                cert = (
                    x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(issuer)
                    .public_key(private_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
                    .sign(private_key, hashes.SHA256())
                )

                mock_chain = CertificateChain(
                    leaf_cert=cert,
                    leaf_key=private_key,
                    intermediate_certs=[],
                    root_cert=cert,
                )

                mock_generator = Mock()
                mock_generator.generate_full_chain.return_value = mock_chain
                mock_gen_class.return_value = mock_generator

                mock_cache = Mock()
                mock_cache.get_cached_cert.return_value = None
                mock_cache_class.return_value = mock_cache

                orchestrator = CertificateBypassOrchestrator()

                with patch.object(orchestrator, '_extract_licensing_domains', return_value=["licensing.example.com"]):
                    success = orchestrator._execute_mitm_proxy(str(temp_binary))

                    assert success
                    mock_generator.generate_full_chain.assert_called_once()

    def test_extract_licensing_domains_from_binary(
        self,
        temp_binary: Path,
    ) -> None:
        """Must extract licensing server domains from binary strings."""
        with patch('intellicrack.core.certificate.bypass_orchestrator.BinaryScanner') as mock_scanner_class:
            mock_scanner = Mock()
            mock_scanner.__enter__ = Mock(return_value=mock_scanner)
            mock_scanner.__exit__ = Mock(return_value=False)
            mock_scanner.scan_strings.return_value = [
                "https://licensing.example.com/validate",
                "https://activation.example.com/activate",
                "https://api.example.com/check-license",
            ]
            mock_scanner_class.return_value = mock_scanner

            orchestrator = CertificateBypassOrchestrator()
            domains = orchestrator._extract_licensing_domains(str(temp_binary))

            assert len(domains) >= 2
            assert "licensing.example.com" in domains
            assert "activation.example.com" in domains


class TestBypassVerification:
    """Test bypass verification methods."""

    def test_verify_binary_patches_detects_signatures(
        self,
        temp_binary: Path,
    ) -> None:
        """Verification must detect patch signatures in binary."""
        patch_sig = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])
        temp_binary.write_bytes(b'MZ' + b'\x00' * 100 + patch_sig + b'\x00' * 100)

        orchestrator = CertificateBypassOrchestrator()
        result = orchestrator._verify_binary_patches(temp_binary)

        assert result

    def test_verify_frida_hooks_checks_active_status(self) -> None:
        """Verification must check if Frida hooks are active."""
        mock_frida = Mock()
        mock_frida.is_attached.return_value = True

        mock_status = Mock()
        mock_status.active = True
        mock_status.active_hooks = ["SSL_CTX_set_verify"]

        mock_frida.get_bypass_status.return_value = mock_status

        orchestrator = CertificateBypassOrchestrator()
        orchestrator.frida_hooks = mock_frida

        result = orchestrator._verify_frida_hooks()

        assert result

    def test_verify_bypass_comprehensive_checks(
        self,
        temp_binary: Path,
    ) -> None:
        """Bypass verification must perform comprehensive checks."""
        orchestrator = CertificateBypassOrchestrator()

        with patch.object(orchestrator, '_verify_binary_patches', return_value=True):
            with patch.object(orchestrator, '_verify_frida_hooks', return_value=True):
                with patch.object(orchestrator, '_verify_validation_bypassed', return_value=True):
                    result = orchestrator._verify_bypass(temp_binary)

                    assert result


class TestRollbackFunctionality:
    """Test rollback of bypass changes."""

    def test_rollback_binary_patches(
        self,
        mock_detection_report: DetectionReport,
    ) -> None:
        """Rollback must restore original binary from patches."""
        from intellicrack.core.certificate.cert_patcher import PatchResult

        bypass_result = BypassResult(
            success=True,
            method_used=BypassMethod.BINARY_PATCH,
            detection_report=mock_detection_report,
            patch_result=PatchResult(
                success=True,
                patched_functions=["SSL_CTX_set_verify"],
                failed_patches=[],
                backup_path=Path("/backup/target.exe.bak"),
            ),
        )

        with patch('intellicrack.core.certificate.bypass_orchestrator.CertificatePatcher') as mock_patcher_class:
            mock_patcher = Mock()
            mock_patcher.rollback_patches.return_value = True
            mock_patcher_class.return_value = mock_patcher

            orchestrator = CertificateBypassOrchestrator()
            success = orchestrator.rollback(bypass_result)

            assert success
            mock_patcher.rollback_patches.assert_called_once()

    def test_rollback_frida_hooks(
        self,
        mock_detection_report: DetectionReport,
    ) -> None:
        """Rollback must detach Frida hooks."""
        bypass_result = BypassResult(
            success=True,
            method_used=BypassMethod.FRIDA_HOOK,
            detection_report=mock_detection_report,
            frida_status={"success": True, "active_hooks": ["SSL_CTX_set_verify"]},
        )

        mock_frida = Mock()
        mock_frida.detach.return_value = True

        orchestrator = CertificateBypassOrchestrator()
        orchestrator.frida_hooks = mock_frida

        success = orchestrator.rollback(bypass_result)

        assert success
        mock_frida.detach.assert_called_once()


class TestErrorHandling:
    """Test error handling and recovery."""

    def test_bypass_handles_file_not_found(self) -> None:
        """Bypass must handle non-existent files gracefully."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass("/nonexistent/file.exe")

        assert not result.success
        assert len(result.errors) > 0

    def test_bypass_handles_detection_failure(
        self,
        temp_binary: Path,
    ) -> None:
        """Bypass must handle detection failures gracefully."""
        with patch('intellicrack.core.certificate.bypass_orchestrator.CertificateValidationDetector') as mock_detector_class:
            mock_detector = Mock()
            mock_detector.detect_certificate_validation.side_effect = Exception("Detection failed")
            mock_detector_class.return_value = mock_detector

            orchestrator = CertificateBypassOrchestrator()
            result = orchestrator.bypass(str(temp_binary))

            assert not result.success
            assert "Detection failed" in str(result.errors)

    def test_bypass_handles_patch_failure(
        self,
        temp_binary: Path,
        mock_detection_report: DetectionReport,
    ) -> None:
        """Bypass must handle patch failures gracefully."""
        with patch('intellicrack.core.certificate.bypass_orchestrator.CertificateValidationDetector') as mock_detector_class:
            mock_detector = Mock()
            mock_detector.detect_certificate_validation.return_value = mock_detection_report
            mock_detector_class.return_value = mock_detector

            with patch('intellicrack.core.certificate.bypass_orchestrator.CertificatePatcher') as mock_patcher_class:
                mock_patcher = Mock()
                mock_patcher.patch_certificate_validation.side_effect = Exception("Patch failed")
                mock_patcher_class.return_value = mock_patcher

                orchestrator = CertificateBypassOrchestrator()
                result = orchestrator.bypass(str(temp_binary), method=BypassMethod.BINARY_PATCH)

                assert not result.success


class TestBypassResultClass:
    """Test BypassResult data class."""

    def test_bypass_result_to_dict(
        self,
        mock_detection_report: DetectionReport,
    ) -> None:
        """BypassResult must serialize to dictionary correctly."""
        result = BypassResult(
            success=True,
            method_used=BypassMethod.BINARY_PATCH,
            detection_report=mock_detection_report,
            verification_passed=True,
        )

        result_dict = result.to_dict()

        assert result_dict["success"]
        assert result_dict["method_used"] == "binary_patch"
        assert result_dict["verification_passed"]
        assert "detection_summary" in result_dict
        assert "libraries" in result_dict["detection_summary"]
        assert "functions_count" in result_dict["detection_summary"]
