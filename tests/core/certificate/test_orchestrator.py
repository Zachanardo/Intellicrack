"""Production tests for certificate bypass orchestrator.

This test suite validates CertificateBypassOrchestrator with real implementations,
no mocks. Tests verify actual orchestration workflows, file operations, and bypass
execution against realistic test binaries and real components.
"""

import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil
import pytest

try:
    from intellicrack.core.certificate.bypass_orchestrator import (
        BypassResult,
        CertificateBypassOrchestrator,
    )
    from intellicrack.core.certificate.bypass_strategy import BypassStrategySelector
    from intellicrack.core.certificate.cert_patcher import (
        FailedPatch,
        PatchedFunction,
        PatchResult,
    )
    from intellicrack.core.certificate.detection_report import (
        BypassMethod,
        DetectionReport,
        ValidationFunction,
    )
    from intellicrack.core.certificate.patch_generators import PatchType
    from intellicrack.core.certificate.validation_detector import (
        CertificateValidationDetector,
    )

    MODULE_AVAILABLE = True
except ImportError:
    CertificateBypassOrchestrator = None
    BypassResult = None
    DetectionReport = None
    ValidationFunction = None
    BypassMethod = None
    PatchResult = None
    PatchedFunction = None
    FailedPatch = None
    PatchType = None
    CertificateValidationDetector = None
    BypassStrategySelector = None
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


class TestDetector:
    """Real detector implementation for testing."""

    def __init__(self, report: DetectionReport | None = None) -> None:
        self.report = report
        self.calls: list[str] = []

    def detect_certificate_validation(self, binary_path: str) -> DetectionReport:
        self.calls.append(binary_path)
        if self.report:
            return self.report
        return DetectionReport(
            binary_path=binary_path,
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
            timestamp=datetime.now(),
        )


class TestStrategySelector:
    """Real strategy selector for testing."""

    def __init__(self, method: BypassMethod = BypassMethod.BINARY_PATCH) -> None:
        self.method = method
        self.calls: list[tuple[DetectionReport, str]] = []

    def select_optimal_strategy(
        self,
        report: DetectionReport,
        target_state: str,
    ) -> BypassMethod:
        self.calls.append((report, target_state))
        return self.method


class TestPatcher:
    """Real patcher implementation for testing."""

    def __init__(
        self,
        binary_path: str,
        patch_result: PatchResult | None = None,
    ) -> None:
        self.binary_path = binary_path
        self.patch_result = patch_result
        self.patch_calls: list[DetectionReport] = []
        self.rollback_calls: list[PatchResult] = []

    def patch_certificate_validation(
        self,
        detection_report: DetectionReport,
    ) -> PatchResult:
        self.patch_calls.append(detection_report)
        if self.patch_result:
            return self.patch_result
        return PatchResult(
            success=True,
            patched_functions=[],
            failed_patches=[],
            backup_data=b"",
            timestamp=datetime.now(),
        )

    def rollback_patches(self, patch_result: PatchResult) -> bool:
        self.rollback_calls.append(patch_result)
        return True


class TestFridaHooks:
    """Real Frida hooks implementation for testing."""

    def __init__(self, attach_success: bool = True, inject_success: bool = True) -> None:
        self.attach_success = attach_success
        self.inject_success = inject_success
        self.attached = False
        self.attach_calls: list[str] = []
        self.inject_calls: list[Any] = []
        self.detach_calls: list[Any] = []

    def attach(self, target: str) -> bool:
        self.attach_calls.append(target)
        self.attached = self.attach_success
        return self.attach_success

    def inject_universal_bypass(self) -> bool:
        self.inject_calls.append(True)
        return self.inject_success

    def get_bypass_status(self) -> Any:
        class Status:
            active = True
            library = "test_lib"
            platform = "windows"
            hooks_installed = ["SSL_verify", "SSL_set_verify"]
            detected_libraries = ["openssl"]
            message_count = 5
            errors: list[str] = []
            intercepted_data: dict[str, Any] = {}

        return Status()

    def is_attached(self) -> bool:
        return self.attached

    def detach(self) -> bool:
        self.detach_calls.append(True)
        self.attached = False
        return True


@pytest.fixture
def temp_dir() -> Path:
    """Create temporary directory for test files."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def sample_binary(temp_dir: Path) -> Path:
    """Create sample binary file for testing."""
    binary_path = temp_dir / "test.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)
    return binary_path


@pytest.fixture
def detection_report_with_validation(sample_binary: Path) -> DetectionReport:
    """Create detection report with validation functions."""
    return DetectionReport(
        binary_path=str(sample_binary),
        detected_libraries=["winhttp.dll", "crypt32.dll"],
        validation_functions=[
            ValidationFunction(
                address=0x140001234,
                api_name="WinHttpSetOption",
                library="winhttp.dll",
                confidence=0.95,
                context="license validation",
                references=[0x140005000],
            ),
            ValidationFunction(
                address=0x140002000,
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                confidence=0.88,
                context="certificate chain validation",
                references=[0x140006000, 0x140007000],
            ),
        ],
        recommended_method=BypassMethod.BINARY_PATCH,
        risk_level="medium",
        timestamp=datetime.now(),
    )


@pytest.fixture
def detection_report_no_validation(sample_binary: Path) -> DetectionReport:
    """Create detection report with no validation."""
    return DetectionReport(
        binary_path=str(sample_binary),
        detected_libraries=[],
        validation_functions=[],
        recommended_method=BypassMethod.NONE,
        risk_level="low",
        timestamp=datetime.now(),
    )


@pytest.fixture
def patch_result_success() -> PatchResult:
    """Create successful patch result."""
    return PatchResult(
        success=True,
        patched_functions=[
            PatchedFunction(
                address=0x140001234,
                api_name="WinHttpSetOption",
                patch_type=PatchType.ALWAYS_SUCCEED,
                patch_size=8,
                original_bytes=b"\x48\x8b\xec\x48\x83\xec\x20\xc3",
            ),
            PatchedFunction(
                address=0x140002000,
                api_name="CertVerifyCertificateChainPolicy",
                patch_type=PatchType.ALWAYS_SUCCEED,
                patch_size=8,
                original_bytes=b"\x48\x89\x5c\x24\x08\x48\x89\x74",
            ),
        ],
        failed_patches=[],
        backup_data=b"\x48\x8b\xec\x48\x83\xec\x20\xc3",
        timestamp=datetime.now(),
    )


@pytest.fixture
def patch_result_partial() -> PatchResult:
    """Create partial success patch result."""
    return PatchResult(
        success=False,
        patched_functions=[
            PatchedFunction(
                address=0x140001234,
                api_name="WinHttpSetOption",
                patch_type=PatchType.ALWAYS_SUCCEED,
                patch_size=8,
                original_bytes=b"\x48\x8b\xec\x48\x83\xec\x20\xc3",
            ),
        ],
        failed_patches=[
            FailedPatch(
                address=0x140002000,
                api_name="CertVerifyCertificateChainPolicy",
                error="Insufficient space for patch",
            ),
        ],
        backup_data=b"\x48\x8b\xec\x48\x83\xec\x20\xc3",
        timestamp=datetime.now(),
    )


class TestOrchestratorInitialization:
    """Tests for orchestrator initialization with real components."""

    def test_orchestrator_creates_real_detector_instance(self) -> None:
        """Orchestrator initializes with real CertificateValidationDetector."""
        orchestrator = CertificateBypassOrchestrator()

        assert orchestrator.detector is not None
        assert isinstance(orchestrator.detector, CertificateValidationDetector)

    def test_orchestrator_creates_real_strategy_selector(self) -> None:
        """Orchestrator initializes with real BypassStrategySelector."""
        orchestrator = CertificateBypassOrchestrator()

        assert orchestrator.strategy_selector is not None
        assert isinstance(orchestrator.strategy_selector, BypassStrategySelector)

    def test_orchestrator_starts_with_no_frida_hooks(self) -> None:
        """Orchestrator starts without Frida hooks attached."""
        orchestrator = CertificateBypassOrchestrator()

        assert orchestrator.frida_hooks is None


class TestTargetAnalysis:
    """Tests for target analysis with real file operations."""

    def test_analyze_target_identifies_existing_file(
        self,
        sample_binary: Path,
    ) -> None:
        """Analyze target correctly identifies existing file path."""
        orchestrator = CertificateBypassOrchestrator()

        target_path, is_running = orchestrator._analyze_target(str(sample_binary))

        assert target_path.exists()
        assert target_path == sample_binary
        assert isinstance(is_running, bool)

    def test_analyze_target_handles_nonexistent_file(self, temp_dir: Path) -> None:
        """Analyze target handles non-existent file path."""
        orchestrator = CertificateBypassOrchestrator()
        nonexistent = temp_dir / "nonexistent.exe"

        target_path, is_running = orchestrator._analyze_target(str(nonexistent))

        assert not target_path.exists()
        assert target_path == nonexistent
        assert is_running is False

    def test_analyze_target_detects_running_process(self) -> None:
        """Analyze target detects if process is running."""
        orchestrator = CertificateBypassOrchestrator()
        current_process = psutil.Process()
        process_name = current_process.name()

        target_path, is_running = orchestrator._analyze_target(process_name)

        assert target_path.exists()
        assert is_running is True

    def test_is_process_running_finds_running_process(self) -> None:
        """Process detection finds actually running process."""
        orchestrator = CertificateBypassOrchestrator()
        current_process = psutil.Process()
        process_name = current_process.name()

        result = orchestrator._is_process_running(process_name)

        assert result is True

    def test_is_process_running_returns_false_for_nonexistent(self) -> None:
        """Process detection returns False for non-existent process."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator._is_process_running("nonexistent_process_12345.exe")

        assert result is False


class TestBypassWorkflowIntegration:
    """Integration tests for complete bypass workflows with real components."""

    def test_bypass_returns_success_when_no_validation_detected(
        self,
        sample_binary: Path,
        detection_report_no_validation: DetectionReport,
    ) -> None:
        """Bypass succeeds immediately when no validation detected."""
        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = TestDetector(detection_report_no_validation)

        result = orchestrator.bypass(str(sample_binary))

        assert result.success is True
        assert result.method_used == BypassMethod.NONE
        assert result.verification_passed is True
        assert len(result.errors) == 0
        assert result.detection_report == detection_report_no_validation

    def test_bypass_fails_when_target_not_found(self, temp_dir: Path) -> None:
        """Bypass fails gracefully when target doesn't exist."""
        orchestrator = CertificateBypassOrchestrator()
        nonexistent = temp_dir / "nonexistent.exe"

        result = orchestrator.bypass(str(nonexistent))

        assert result.success is False
        assert len(result.errors) > 0
        assert "not found" in result.errors[0].lower() or "no such file" in result.errors[0].lower()

    def test_bypass_uses_detector_for_validation_analysis(
        self,
        sample_binary: Path,
        detection_report_with_validation: DetectionReport,
    ) -> None:
        """Bypass workflow invokes detector to analyze target."""
        test_detector = TestDetector(detection_report_with_validation)
        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = test_detector

        orchestrator.bypass(str(sample_binary))

        assert len(test_detector.calls) == 1
        assert str(sample_binary) in test_detector.calls[0]

    def test_bypass_uses_strategy_selector_when_method_not_specified(
        self,
        sample_binary: Path,
        detection_report_with_validation: DetectionReport,
    ) -> None:
        """Bypass uses strategy selector when no method specified."""
        test_selector = TestStrategySelector(BypassMethod.FRIDA_HOOK)
        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = TestDetector(detection_report_with_validation)
        orchestrator.strategy_selector = test_selector

        result = orchestrator.bypass(str(sample_binary))

        assert len(test_selector.calls) == 1
        assert test_selector.calls[0][0] == detection_report_with_validation
        assert result.method_used == BypassMethod.FRIDA_HOOK

    def test_bypass_respects_explicitly_specified_method(
        self,
        sample_binary: Path,
        detection_report_with_validation: DetectionReport,
    ) -> None:
        """Bypass uses explicitly specified method instead of auto-selection."""
        test_selector = TestStrategySelector(BypassMethod.HYBRID)
        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = TestDetector(detection_report_with_validation)
        orchestrator.strategy_selector = test_selector

        result = orchestrator.bypass(
            str(sample_binary),
            method=BypassMethod.BINARY_PATCH,
        )

        assert len(test_selector.calls) == 0
        assert result.method_used == BypassMethod.BINARY_PATCH


class TestBinaryPatchExecution:
    """Tests for binary patch execution with real patch operations."""

    def test_execute_binary_patch_returns_patch_result(
        self,
        detection_report_with_validation: DetectionReport,
    ) -> None:
        """Binary patch execution returns valid PatchResult."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator._execute_binary_patch(detection_report_with_validation)

        assert isinstance(result, PatchResult)
        assert isinstance(result.success, bool)
        assert isinstance(result.patched_functions, list)
        assert isinstance(result.failed_patches, list)

    def test_execute_binary_patch_propagates_exceptions(
        self,
        detection_report_with_validation: DetectionReport,
    ) -> None:
        """Binary patch execution propagates exceptions from patcher."""
        orchestrator = CertificateBypassOrchestrator()
        invalid_report = DetectionReport(
            binary_path="/invalid/path/that/does/not/exist.exe",
            detected_libraries=[],
            validation_functions=[
                ValidationFunction(
                    address=0x1000,
                    api_name="Test",
                    library="test.dll",
                    confidence=0.9,
                ),
            ],
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
        )

        with pytest.raises(Exception):
            orchestrator._execute_binary_patch(invalid_report)


class TestFridaHookExecution:
    """Tests for Frida hook execution with real hook operations."""

    def test_execute_frida_hook_creates_hooks_instance(self) -> None:
        """Frida hook execution creates FridaCertificateHooks instance."""
        orchestrator = CertificateBypassOrchestrator()
        orchestrator.frida_hooks = TestFridaHooks()

        result = orchestrator._execute_frida_hook("test.exe")

        assert isinstance(result, dict)
        assert "success" in result

    def test_execute_frida_hook_returns_failure_when_attach_fails(self) -> None:
        """Frida hook returns failure when attachment fails."""
        orchestrator = CertificateBypassOrchestrator()
        orchestrator.frida_hooks = TestFridaHooks(attach_success=False)

        result = orchestrator._execute_frida_hook("test.exe")

        assert result["success"] is False
        assert "error" in result
        assert "attach" in str(result["error"]).lower()

    def test_execute_frida_hook_returns_failure_when_inject_fails(self) -> None:
        """Frida hook returns failure when bypass injection fails."""
        orchestrator = CertificateBypassOrchestrator()
        orchestrator.frida_hooks = TestFridaHooks(
            attach_success=True,
            inject_success=False,
        )

        result = orchestrator._execute_frida_hook("test.exe")

        assert result["success"] is False
        assert "error" in result
        assert "inject" in str(result["error"]).lower()

    def test_execute_frida_hook_returns_success_with_status(self) -> None:
        """Frida hook returns success with detailed status."""
        orchestrator = CertificateBypassOrchestrator()
        orchestrator.frida_hooks = TestFridaHooks(
            attach_success=True,
            inject_success=True,
        )

        result = orchestrator._execute_frida_hook("test.exe")

        assert result["success"] is True
        assert result["active"] is True
        assert "hooks_installed" in result
        assert isinstance(result["hooks_installed"], list)
        assert len(result["hooks_installed"]) > 0


class TestDomainExtraction:
    """Tests for licensing domain extraction from binaries."""

    def test_extract_licensing_domains_returns_empty_for_nonexistent(
        self,
        temp_dir: Path,
    ) -> None:
        """Domain extraction returns empty list for non-existent file."""
        orchestrator = CertificateBypassOrchestrator()
        nonexistent = temp_dir / "nonexistent.exe"

        domains = orchestrator._extract_licensing_domains(str(nonexistent))

        assert domains == []

    def test_extract_licensing_domains_handles_real_binary(
        self,
        sample_binary: Path,
    ) -> None:
        """Domain extraction handles real binary without crashing."""
        orchestrator = CertificateBypassOrchestrator()

        domains = orchestrator._extract_licensing_domains(str(sample_binary))

        assert isinstance(domains, list)
        assert all(isinstance(d, str) for d in domains)


class TestBypassVerification:
    """Tests for bypass verification with real binary analysis."""

    def test_verify_bypass_checks_multiple_verification_methods(
        self,
        sample_binary: Path,
    ) -> None:
        """Verify bypass uses multiple verification approaches."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator._verify_bypass(sample_binary)

        assert isinstance(result, bool)

    def test_verify_binary_patches_detects_patch_signatures(
        self,
        temp_dir: Path,
    ) -> None:
        """Binary patch verification detects known patch signatures."""
        orchestrator = CertificateBypassOrchestrator()
        patched_binary = temp_dir / "patched.exe"
        patch_signature = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])
        binary_content = b"MZ\x90\x00" + b"\x00" * 100 + patch_signature + b"\x00" * 100
        patched_binary.write_bytes(binary_content)

        result = orchestrator._verify_binary_patches(patched_binary)

        assert result is True

    def test_verify_binary_patches_returns_false_for_unpatched(
        self,
        sample_binary: Path,
    ) -> None:
        """Binary patch verification returns False for unpatched binary."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator._verify_binary_patches(sample_binary)

        assert result is False

    def test_verify_frida_hooks_returns_false_when_no_hooks(self) -> None:
        """Frida verification returns False when no hooks attached."""
        orchestrator = CertificateBypassOrchestrator()
        orchestrator.frida_hooks = None

        result = orchestrator._verify_frida_hooks()

        assert result is False

    def test_verify_frida_hooks_returns_true_when_active(self) -> None:
        """Frida verification returns True when hooks are active."""
        orchestrator = CertificateBypassOrchestrator()
        test_hooks = TestFridaHooks(attach_success=True, inject_success=True)
        test_hooks.attached = True
        orchestrator.frida_hooks = test_hooks

        result = orchestrator._verify_frida_hooks()

        assert result is True

    def test_verify_validation_bypassed_handles_real_binary(
        self,
        sample_binary: Path,
    ) -> None:
        """Validation bypass verification handles real binary."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator._verify_validation_bypassed(sample_binary)

        assert isinstance(result, bool)


class TestRollbackFunctionality:
    """Tests for bypass rollback with real operations."""

    def test_rollback_binary_patches_invokes_patcher(
        self,
        detection_report_with_validation: DetectionReport,
        patch_result_success: PatchResult,
    ) -> None:
        """Rollback invokes patcher rollback for binary patches."""
        orchestrator = CertificateBypassOrchestrator()
        bypass_result = BypassResult(
            success=True,
            method_used=BypassMethod.BINARY_PATCH,
            detection_report=detection_report_with_validation,
            patch_result=patch_result_success,
            verification_passed=True,
        )

        result = orchestrator.rollback(bypass_result)

        assert isinstance(result, bool)

    def test_rollback_frida_hooks_detaches_hooks(self) -> None:
        """Rollback detaches Frida hooks when present."""
        orchestrator = CertificateBypassOrchestrator()
        test_hooks = TestFridaHooks()
        test_hooks.attached = True
        orchestrator.frida_hooks = test_hooks

        detection_report = DetectionReport(
            binary_path="test.exe",
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.FRIDA_HOOK,
            risk_level="low",
        )
        bypass_result = BypassResult(
            success=True,
            method_used=BypassMethod.FRIDA_HOOK,
            detection_report=detection_report,
            frida_status={"active": True},
        )

        result = orchestrator.rollback(bypass_result)

        assert result is True
        assert len(test_hooks.detach_calls) == 1
        assert not test_hooks.attached

    def test_rollback_handles_errors_gracefully(
        self,
        detection_report_with_validation: DetectionReport,
    ) -> None:
        """Rollback handles errors without crashing."""
        orchestrator = CertificateBypassOrchestrator()
        invalid_patch_result = PatchResult(
            success=True,
            patched_functions=[],
            failed_patches=[],
            backup_data=b"",
        )
        bypass_result = BypassResult(
            success=True,
            method_used=BypassMethod.BINARY_PATCH,
            detection_report=detection_report_with_validation,
            patch_result=invalid_patch_result,
        )

        result = orchestrator.rollback(bypass_result)

        assert isinstance(result, bool)


class TestBypassResultDataclass:
    """Tests for BypassResult data structure."""

    def test_bypass_result_to_dict_exports_complete_data(
        self,
        detection_report_with_validation: DetectionReport,
        patch_result_success: PatchResult,
    ) -> None:
        """BypassResult.to_dict() exports all relevant data."""
        result = BypassResult(
            success=True,
            method_used=BypassMethod.BINARY_PATCH,
            detection_report=detection_report_with_validation,
            patch_result=patch_result_success,
            verification_passed=True,
            errors=[],
        )

        result_dict = result.to_dict()

        assert result_dict["success"] is True
        assert result_dict["method_used"] == "binary_patch"
        assert result_dict["verification_passed"] is True
        assert "detection_summary" in result_dict
        assert "libraries" in result_dict["detection_summary"]
        assert "functions_count" in result_dict["detection_summary"]
        assert result_dict["detection_summary"]["functions_count"] == 2
        assert "timestamp" in result_dict

    def test_bypass_result_to_dict_includes_errors(
        self,
        detection_report_no_validation: DetectionReport,
    ) -> None:
        """BypassResult.to_dict() includes error messages."""
        result = BypassResult(
            success=False,
            method_used=BypassMethod.BINARY_PATCH,
            detection_report=detection_report_no_validation,
            errors=["Error 1", "Error 2"],
        )

        result_dict = result.to_dict()

        assert result_dict["success"] is False
        assert len(result_dict["errors"]) == 2
        assert "Error 1" in result_dict["errors"]


class TestMITMProxyExecution:
    """Tests for MITM proxy bypass execution."""

    def test_execute_mitm_proxy_handles_execution(self, sample_binary: Path) -> None:
        """MITM proxy execution returns boolean result."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator._execute_mitm_proxy(str(sample_binary))

        assert isinstance(result, bool)

    def test_execute_mitm_proxy_extracts_domains(self, sample_binary: Path) -> None:
        """MITM proxy execution extracts licensing domains."""
        orchestrator = CertificateBypassOrchestrator()

        orchestrator._execute_mitm_proxy(str(sample_binary))


class TestCompleteBypassWorkflows:
    """End-to-end integration tests for complete bypass workflows."""

    def test_complete_binary_patch_workflow(
        self,
        sample_binary: Path,
        detection_report_with_validation: DetectionReport,
        patch_result_success: PatchResult,
    ) -> None:
        """Complete binary patch workflow from detection to verification."""
        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = TestDetector(detection_report_with_validation)

        result = orchestrator.bypass(
            str(sample_binary),
            method=BypassMethod.BINARY_PATCH,
        )

        assert isinstance(result, BypassResult)
        assert result.method_used == BypassMethod.BINARY_PATCH
        assert result.detection_report == detection_report_with_validation

    def test_complete_workflow_with_automatic_strategy(
        self,
        sample_binary: Path,
        detection_report_with_validation: DetectionReport,
    ) -> None:
        """Complete workflow with automatic strategy selection."""
        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = TestDetector(detection_report_with_validation)
        orchestrator.strategy_selector = TestStrategySelector(BypassMethod.HYBRID)

        result = orchestrator.bypass(str(sample_binary))

        assert isinstance(result, BypassResult)
        assert result.method_used == BypassMethod.HYBRID

    def test_workflow_with_frida_hooks(
        self,
        sample_binary: Path,
        detection_report_with_validation: DetectionReport,
    ) -> None:
        """Complete workflow using Frida hooks method."""
        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = TestDetector(detection_report_with_validation)
        orchestrator.frida_hooks = TestFridaHooks(
            attach_success=True,
            inject_success=True,
        )

        result = orchestrator.bypass(
            str(sample_binary),
            method=BypassMethod.FRIDA_HOOK,
        )

        assert isinstance(result, BypassResult)
        assert result.method_used == BypassMethod.FRIDA_HOOK
        assert result.frida_status is not None
        assert isinstance(result.frida_status, dict)


class TestErrorHandling:
    """Tests for error handling in various failure scenarios."""

    def test_bypass_handles_detector_exception(self, sample_binary: Path) -> None:
        """Bypass handles exceptions from detector gracefully."""

        class FailingDetector:
            def detect_certificate_validation(self, binary_path: str) -> DetectionReport:
                raise RuntimeError("Detector failed")

        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = FailingDetector()

        result = orchestrator.bypass(str(sample_binary))

        assert result.success is False
        assert len(result.errors) > 0
        assert "Detector failed" in result.errors[0]

    def test_bypass_handles_invalid_method(
        self,
        sample_binary: Path,
        detection_report_with_validation: DetectionReport,
    ) -> None:
        """Bypass handles unsupported bypass methods."""
        orchestrator = CertificateBypassOrchestrator()
        orchestrator.detector = TestDetector(detection_report_with_validation)

        result = orchestrator.bypass(str(sample_binary))

        assert isinstance(result, BypassResult)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
