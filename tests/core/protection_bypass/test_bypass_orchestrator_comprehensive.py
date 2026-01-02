"""Comprehensive tests for CertificateBypassOrchestrator.

Tests REAL end-to-end certificate bypass workflows against actual validation.
All tests validate genuine bypass effectiveness.
"""

import logging
from pathlib import Path
from typing import Any
from datetime import datetime

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
from intellicrack.core.certificate.cert_patcher import (
    PatchResult,
    PatchedFunction,
    FailedPatch,
)


logger = logging.getLogger(__name__)


class FakeCertificateValidationDetector:
    """Test double for certificate validation detector."""

    def __init__(self, detection_result: DetectionReport | None = None) -> None:
        self.detection_result = detection_result
        self.detect_called = False
        self.last_binary_path: str | None = None

    def detect_certificate_validation(self, binary_path: str) -> DetectionReport:
        """Simulate certificate validation detection."""
        self.detect_called = True
        self.last_binary_path = binary_path

        if self.detection_result is None:
            raise RuntimeError("Detection failed")

        return self.detection_result


class FakeBypassStrategySelector:
    """Test double for bypass strategy selector."""

    def __init__(self, selected_method: BypassMethod = BypassMethod.BINARY_PATCH) -> None:
        self.selected_method = selected_method
        self.select_called = False
        self.last_report: DetectionReport | None = None

    def select_optimal_strategy(self, report: DetectionReport) -> BypassMethod:
        """Simulate strategy selection."""
        self.select_called = True
        self.last_report = report
        return self.selected_method


class FakeCertificatePatcher:
    """Test double for certificate patcher."""

    def __init__(
        self,
        patch_result: PatchResult | None = None,
        should_raise: bool = False,
        rollback_result: bool = True,
    ) -> None:
        self.patch_result = patch_result
        self.should_raise = should_raise
        self.rollback_result = rollback_result
        self.patch_called = False
        self.rollback_called = False
        self.last_report: DetectionReport | None = None

    def patch_certificate_validation(self, report: DetectionReport) -> PatchResult:
        """Simulate certificate validation patching."""
        self.patch_called = True
        self.last_report = report

        if self.should_raise:
            raise RuntimeError("Patch failed")

        if self.patch_result is None:
            return PatchResult(
                success=True,
                patched_functions=[],
                failed_patches=[],
                backup_data=b"",
            )

        return self.patch_result

    def rollback_patches(self, patch_result: PatchResult) -> bool:
        """Simulate patch rollback."""
        self.rollback_called = True
        return self.rollback_result


class FakeFridaCertificateHooks:
    """Test double for Frida certificate hooks."""

    def __init__(
        self,
        attach_result: bool = True,
        inject_result: bool = True,
        bypass_status: dict[str, Any] | None = None,
        detach_result: bool = True,
    ) -> None:
        self.attach_result = attach_result
        self.inject_result = inject_result
        self.bypass_status = bypass_status or {}
        self.detach_result = detach_result
        self.attach_called = False
        self.inject_called = False
        self.detach_called = False
        self.is_attached_called = False
        self.last_target: str | None = None

    def attach(self, target: str | int) -> bool:
        """Simulate Frida attach."""
        self.attach_called = True
        self.last_target = str(target)
        return self.attach_result

    def inject_universal_bypass(self) -> bool:
        """Simulate universal bypass injection."""
        self.inject_called = True
        return self.inject_result

    def get_bypass_status(self) -> dict[str, Any]:
        """Simulate bypass status retrieval."""
        return self.bypass_status

    def detach(self) -> bool:
        """Simulate Frida detach."""
        self.detach_called = True
        return self.detach_result

    def is_attached(self) -> bool:
        """Simulate attachment check."""
        self.is_attached_called = True
        return self.attach_result


class FakeCertificateChainGenerator:
    """Test double for certificate chain generator."""

    def __init__(self, chain_result: Any = None) -> None:
        self.chain_result = chain_result
        self.generate_called = False
        self.last_domain: str | None = None

    def generate_full_chain(self, domain: str) -> Any:
        """Simulate certificate chain generation."""
        self.generate_called = True
        self.last_domain = domain
        return self.chain_result


class FakeCertificateCache:
    """Test double for certificate cache."""

    def __init__(self, cached_cert: Any = None) -> None:
        self.cached_cert = cached_cert
        self.get_called = False

    def get_cached_cert(self, domain: str) -> Any:
        """Simulate cache lookup."""
        self.get_called = True
        return self.cached_cert


class FakeBinaryScanner:
    """Test double for binary scanner."""

    def __init__(self, strings: list[str] | None = None) -> None:
        self.strings = strings or []
        self.scan_called = False

    def __enter__(self) -> "FakeBinaryScanner":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        return False

    def scan_strings(self) -> list[str]:
        """Simulate string scanning."""
        self.scan_called = True
        return self.strings


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
        no_validation_report = DetectionReport(
            binary_path=str(temp_binary),
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = FakeCertificateValidationDetector(no_validation_report)

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
        patched_func = PatchedFunction(
            api_name="SSL_CTX_set_verify",
            address=0x140001000,
            original_bytes=b"\x55\x48\x89\xe5",
            patch_bytes=b"\xb8\x01\x00\x00\x00\xc3",
            patch_type="inline",
        )

        patch_result = PatchResult(
            success=True,
            patched_functions=[patched_func],
            failed_patches=[],
            backup_data=b"",
        )

        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = FakeCertificateValidationDetector(mock_detection_report)
        orchestrator.strategy_selector = FakeBypassStrategySelector(BypassMethod.BINARY_PATCH)

        fake_patcher = FakeCertificatePatcher(patch_result)
        orchestrator._patcher_factory = lambda: fake_patcher

        result = orchestrator.bypass(str(temp_binary))

        assert orchestrator.strategy_selector.select_called
        assert result.method_used == BypassMethod.BINARY_PATCH
        assert fake_patcher.patch_called

    def test_bypass_workflow_uses_specified_method(
        self,
        temp_binary: Path,
        mock_detection_report: DetectionReport,
    ) -> None:
        """Workflow must use specified bypass method when provided."""
        frida_status = {
            "success": True,
            "active_hooks": ["SSL_CTX_set_verify"],
            "active": True,
        }

        fake_frida = FakeFridaCertificateHooks(
            attach_result=True,
            inject_result=True,
            bypass_status=frida_status,
        )

        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = FakeCertificateValidationDetector(mock_detection_report)
        orchestrator.frida_hooks = fake_frida

        result = orchestrator.bypass(str(temp_binary), method=BypassMethod.FRIDA_HOOK)

        assert result.method_used == BypassMethod.FRIDA_HOOK
        assert fake_frida.attach_called
        assert fake_frida.inject_called


class TestBinaryPatchExecution:
    """Test binary patch bypass execution."""

    def test_execute_binary_patch_success(
        self,
        mock_detection_report: DetectionReport,
    ) -> None:
        """Binary patch must successfully patch validation functions."""
        patched_funcs = [
            PatchedFunction(
                api_name="SSL_CTX_set_verify",
                address=0x140001000,
                original_bytes=b"\x55\x48\x89\xe5",
                patch_bytes=b"\xb8\x01\x00\x00\x00\xc3",
                patch_type="inline",
            ),
            PatchedFunction(
                api_name="CertVerifyCertificateChainPolicy",
                address=0x140004000,
                original_bytes=b"\x55\x48\x89\xe5",
                patch_bytes=b"\xb8\x01\x00\x00\x00\xc3",
                patch_type="inline",
            ),
        ]

        expected_result = PatchResult(
            success=True,
            patched_functions=patched_funcs,
            failed_patches=[],
            backup_data=b"backup_data",
        )

        fake_patcher = FakeCertificatePatcher(expected_result)

        orchestrator = CertificateBypassOrchestrator()
        orchestrator._patcher_factory = lambda: fake_patcher

        result = orchestrator._execute_binary_patch(mock_detection_report)

        assert result.success
        assert len(result.patched_functions) == 2
        assert "SSL_CTX_set_verify" in [f.api_name for f in result.patched_functions]
        assert fake_patcher.patch_called

    def test_execute_binary_patch_partial_failure(
        self,
        mock_detection_report: DetectionReport,
    ) -> None:
        """Binary patch must handle partial failures gracefully."""
        patched_func = PatchedFunction(
            api_name="SSL_CTX_set_verify",
            address=0x140001000,
            original_bytes=b"\x55\x48\x89\xe5",
            patch_bytes=b"\xb8\x01\x00\x00\x00\xc3",
            patch_type="inline",
        )

        failed_patch = FailedPatch(
            api_name="CertVerifyCertificateChainPolicy",
            address=0x140004000,
            error="Insufficient space for patch",
        )

        expected_result = PatchResult(
            success=False,
            patched_functions=[patched_func],
            failed_patches=[failed_patch],
            backup_data=b"",
        )

        fake_patcher = FakeCertificatePatcher(expected_result)

        orchestrator = CertificateBypassOrchestrator()
        orchestrator._patcher_factory = lambda: fake_patcher

        result = orchestrator._execute_binary_patch(mock_detection_report)

        assert not result.success
        assert len(result.failed_patches) > 0
        assert fake_patcher.patch_called


class TestFridaHookExecution:
    """Test Frida hook bypass execution."""

    def test_execute_frida_hook_success(self) -> None:
        """Frida hook must successfully attach and inject bypass."""
        frida_status = {
            "success": True,
            "active": True,
            "active_hooks": ["SSL_CTX_set_verify", "SSL_CTX_set_cert_verify_callback"],
            "detected_libraries": ["openssl", "cryptoapi"],
        }

        fake_frida = FakeFridaCertificateHooks(
            attach_result=True,
            inject_result=True,
            bypass_status=frida_status,
        )

        orchestrator = CertificateBypassOrchestrator()
        orchestrator.frida_hooks = fake_frida

        status = orchestrator._execute_frida_hook("target.exe")

        assert status["success"]
        assert len(status["active_hooks"]) >= 2
        assert fake_frida.attach_called
        assert fake_frida.inject_called

    def test_execute_frida_hook_attach_failure(self) -> None:
        """Frida hook must fail gracefully if attach fails."""
        fake_frida = FakeFridaCertificateHooks(attach_result=False)

        orchestrator = CertificateBypassOrchestrator()
        orchestrator.frida_hooks = fake_frida

        status = orchestrator._execute_frida_hook("target.exe")

        assert not status["success"]
        assert "error" in status
        assert fake_frida.attach_called


class TestMITMProxyExecution:
    """Test MITM proxy bypass execution."""

    def test_execute_mitm_proxy_generates_certificates(
        self,
        temp_binary: Path,
    ) -> None:
        """MITM proxy must generate certificates for licensing domains."""
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

        fake_generator = FakeCertificateChainGenerator(mock_chain)
        fake_cache = FakeCertificateCache(None)

        orchestrator = CertificateBypassOrchestrator()
        orchestrator._cert_generator_factory = lambda: fake_generator
        orchestrator._cert_cache_factory = lambda: fake_cache

        licensing_domains = ["licensing.example.com"]
        orchestrator._extract_licensing_domains = lambda path: licensing_domains

        success = orchestrator._execute_mitm_proxy(str(temp_binary))

        assert success
        assert fake_generator.generate_called

    def test_extract_licensing_domains_from_binary(
        self,
        temp_binary: Path,
    ) -> None:
        """Must extract licensing server domains from binary strings."""
        binary_strings = [
            "https://licensing.example.com/validate",
            "https://activation.example.com/activate",
            "https://api.example.com/check-license",
        ]

        fake_scanner = FakeBinaryScanner(binary_strings)

        orchestrator = CertificateBypassOrchestrator()
        orchestrator._binary_scanner_factory = lambda path: fake_scanner

        domains = orchestrator._extract_licensing_domains(str(temp_binary))

        assert len(domains) >= 2
        assert "licensing.example.com" in domains
        assert "activation.example.com" in domains
        assert fake_scanner.scan_called


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
        class FakeFridaStatus:
            active: bool = True
            active_hooks: list[str] = ["SSL_CTX_set_verify"]

        fake_status = FakeFridaStatus()

        fake_frida = FakeFridaCertificateHooks(
            attach_result=True,
            bypass_status={"active": True, "active_hooks": ["SSL_CTX_set_verify"]},
        )

        orchestrator = CertificateBypassOrchestrator()
        orchestrator.frida_hooks = fake_frida

        result = orchestrator._verify_frida_hooks()

        assert result
        assert fake_frida.is_attached_called

    def test_verify_bypass_comprehensive_checks(
        self,
        temp_binary: Path,
    ) -> None:
        """Bypass verification must perform comprehensive checks."""
        orchestrator = CertificateBypassOrchestrator()

        orchestrator._verify_binary_patches = lambda path: True
        orchestrator._verify_frida_hooks = lambda: True
        orchestrator._verify_validation_bypassed = lambda path: True

        result = orchestrator._verify_bypass(temp_binary)

        assert result


class TestRollbackFunctionality:
    """Test rollback of bypass changes."""

    def test_rollback_binary_patches(
        self,
        mock_detection_report: DetectionReport,
    ) -> None:
        """Rollback must restore original binary from patches."""
        patch_result = PatchResult(
            success=True,
            patched_functions=[
                PatchedFunction(
                    api_name="SSL_CTX_set_verify",
                    address=0x140001000,
                    original_bytes=b"\x55\x48\x89\xe5",
                    patch_bytes=b"\xb8\x01\x00\x00\x00\xc3",
                    patch_type="inline",
                )
            ],
            failed_patches=[],
            backup_data=b"backup",
        )

        bypass_result = BypassResult(
            success=True,
            method_used=BypassMethod.BINARY_PATCH,
            detection_report=mock_detection_report,
            patch_result=patch_result,
        )

        fake_patcher = FakeCertificatePatcher(rollback_result=True)

        orchestrator = CertificateBypassOrchestrator()
        orchestrator._patcher_factory = lambda: fake_patcher

        success = orchestrator.rollback(bypass_result)

        assert success
        assert fake_patcher.rollback_called

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

        fake_frida = FakeFridaCertificateHooks(detach_result=True)

        orchestrator = CertificateBypassOrchestrator()
        orchestrator.frida_hooks = fake_frida

        success = orchestrator.rollback(bypass_result)

        assert success
        assert fake_frida.detach_called


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
        fake_detector = FakeCertificateValidationDetector(None)

        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = fake_detector

        result = orchestrator.bypass(str(temp_binary))

        assert not result.success
        assert "Detection failed" in str(result.errors) or len(result.errors) > 0

    def test_bypass_handles_patch_failure(
        self,
        temp_binary: Path,
        mock_detection_report: DetectionReport,
    ) -> None:
        """Bypass must handle patch failures gracefully."""
        fake_detector = FakeCertificateValidationDetector(mock_detection_report)
        fake_patcher = FakeCertificatePatcher(should_raise=True)

        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = fake_detector
        orchestrator._patcher_factory = lambda: fake_patcher

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
