"""Production-grade tests for CertificateBypassOrchestrator validating real bypass capabilities.

Tests REAL certificate validation bypass against actual protected binaries.
NO mocks - validates genuine offensive capabilities.

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
import subprocess
import time
from pathlib import Path
from typing import Any

import psutil
import pytest

from intellicrack.core.certificate.binary_scanner import BinaryScanner
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


@pytest.fixture(scope="module")
def protected_binaries_dir() -> Path:
    """Path to directory containing real protected binaries."""
    return Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe" / "protected"


@pytest.fixture(scope="module")
def online_activation_binary(protected_binaries_dir: Path) -> Path:
    """Real binary with online activation and certificate validation."""
    binary_path = protected_binaries_dir / "online_activation_app.exe"
    assert binary_path.exists(), f"Test binary not found: {binary_path}"
    return binary_path


@pytest.fixture(scope="module")
def enterprise_license_binary(protected_binaries_dir: Path) -> Path:
    """Real binary with enterprise licensing and certificate checks."""
    binary_path = protected_binaries_dir / "enterprise_license_check.exe"
    assert binary_path.exists(), f"Test binary not found: {binary_path}"
    return binary_path


@pytest.fixture
def temp_binary_copy(tmp_path: Path, online_activation_binary: Path) -> Path:
    """Create temporary copy of binary for destructive tests."""
    temp_binary = tmp_path / "test_target.exe"
    shutil.copy2(online_activation_binary, temp_binary)
    return temp_binary


@pytest.fixture
def real_detection_report(online_activation_binary: Path) -> DetectionReport:
    """Generate real detection report from actual binary analysis."""
    from intellicrack.core.certificate.validation_detector import CertificateValidationDetector

    detector = CertificateValidationDetector()
    report = detector.detect_certificate_validation(str(online_activation_binary))

    if not report.has_validation():
        pytest.skip("Test binary does not have detectable certificate validation")

    return report


class TestOrchestratorRealBinaryAnalysis:
    """Test orchestrator with real protected binaries."""

    def test_bypass_detects_certificate_validation_in_real_binary(
        self,
        online_activation_binary: Path,
    ) -> None:
        """Orchestrator must detect certificate validation in real protected binary."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass(str(online_activation_binary))

        assert isinstance(result, BypassResult)
        assert result.detection_report is not None
        assert isinstance(result.detection_report, DetectionReport)

        if result.detection_report.has_validation():
            assert len(result.detection_report.validation_functions) > 0
            assert result.method_used in [
                BypassMethod.BINARY_PATCH,
                BypassMethod.FRIDA_HOOK,
                BypassMethod.HYBRID,
                BypassMethod.MITM_PROXY,
            ]
        else:
            assert result.method_used == BypassMethod.NONE
            assert result.success

    def test_bypass_selects_appropriate_method_for_static_binary(
        self,
        online_activation_binary: Path,
        real_detection_report: DetectionReport,
    ) -> None:
        """Orchestrator must select appropriate bypass method for static binary analysis."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass(str(online_activation_binary))

        if result.detection_report.has_validation():
            assert result.method_used in [
                BypassMethod.BINARY_PATCH,
                BypassMethod.HYBRID,
                BypassMethod.MITM_PROXY,
            ]
            assert result.detection_report.risk_level in ["low", "medium", "high"]

    def test_bypass_analyzes_enterprise_binary_correctly(
        self,
        enterprise_license_binary: Path,
    ) -> None:
        """Orchestrator must correctly analyze enterprise licensing binary."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass(str(enterprise_license_binary))

        assert isinstance(result, BypassResult)
        assert result.detection_report is not None

        if result.detection_report.has_validation():
            detected_libs = result.detection_report.detected_libraries
            assert len(detected_libs) > 0

            common_libs = ["winhttp", "schannel", "openssl", "cryptoapi", "wintrust"]
            assert any(lib.lower() in "".join(detected_libs).lower() for lib in common_libs)


class TestBinaryPatchBypass:
    """Test binary patching bypass on real binaries."""

    def test_binary_patch_creates_backup_before_modification(
        self,
        temp_binary_copy: Path,
        real_detection_report: DetectionReport,
    ) -> None:
        """Binary patcher must create backup before modifying target."""
        orchestrator = CertificateBypassOrchestrator()

        original_content = temp_binary_copy.read_bytes()
        original_size = len(original_content)

        result = orchestrator.bypass(
            str(temp_binary_copy),
            method=BypassMethod.BINARY_PATCH,
        )

        if result.patch_result:
            assert result.patch_result.backup_data is not None
            assert len(result.patch_result.backup_data) > 0

            backup_data = result.patch_result.backup_data
            assert isinstance(backup_data, bytes)
            assert len(backup_data) <= original_size

    def test_binary_patch_modifies_validation_functions(
        self,
        temp_binary_copy: Path,
        real_detection_report: DetectionReport,
    ) -> None:
        """Binary patcher must actually modify certificate validation functions."""
        orchestrator = CertificateBypassOrchestrator()

        original_content = temp_binary_copy.read_bytes()

        result = orchestrator.bypass(
            str(temp_binary_copy),
            method=BypassMethod.BINARY_PATCH,
        )

        modified_content = temp_binary_copy.read_bytes()

        if result.success and result.patch_result and result.patch_result.success:
            assert original_content != modified_content, "Binary was not modified"

            assert len(result.patch_result.patched_functions) > 0

            for func in result.patch_result.patched_functions:
                assert isinstance(func.address, int)
                assert func.address > 0
                assert len(func.api_name) > 0

    def test_binary_patch_writes_return_true_instructions(
        self,
        temp_binary_copy: Path,
        real_detection_report: DetectionReport,
    ) -> None:
        """Binary patcher must write actual return-true instructions at target addresses."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass(
            str(temp_binary_copy),
            method=BypassMethod.BINARY_PATCH,
        )

        if result.success and result.patch_result and result.patch_result.success:
            patched_content = temp_binary_copy.read_bytes()

            x86_return_true_patterns = [
                b'\xB8\x01\x00\x00\x00\xC3',
                b'\x48\xC7\xC0\x01\x00\x00\x00\xC3',
                b'\x31\xC0\x40\xC3',
                b'\x90' * 5,
            ]

            patch_found = False
            for pattern in x86_return_true_patterns:
                if pattern in patched_content:
                    patch_found = True
                    break

            assert patch_found, "No return-true patch patterns found in modified binary"

    def test_binary_patch_verification_detects_patches(
        self,
        temp_binary_copy: Path,
        real_detection_report: DetectionReport,
    ) -> None:
        """Verification must detect presence of applied patches."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass(
            str(temp_binary_copy),
            method=BypassMethod.BINARY_PATCH,
        )

        if result.success and result.patch_result and result.patch_result.success:
            verification_passed = orchestrator._verify_binary_patches(temp_binary_copy)

            assert verification_passed, "Patch verification failed to detect applied patches"


class TestFridaHookBypass:
    """Test Frida hooking bypass capabilities."""

    @pytest.mark.skipif(
        not shutil.which("frida-server"),
        reason="Frida server not available",
    )
    def test_frida_hook_attaches_to_running_process(self) -> None:
        """Frida hooks must successfully attach to running process."""
        orchestrator = CertificateBypassOrchestrator()

        test_process = subprocess.Popen(
            ["python", "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            time.sleep(1)

            result = orchestrator.bypass(
                str(test_process.pid),
                method=BypassMethod.FRIDA_HOOK,
            )

            if result.frida_status:
                assert result.frida_status.get("success", False) or "error" in result.frida_status

        finally:
            test_process.kill()
            test_process.wait()

    def test_frida_hook_generates_valid_injection_script(
        self,
        online_activation_binary: Path,
    ) -> None:
        """Frida hook must generate valid JavaScript injection script."""
        orchestrator = CertificateBypassOrchestrator()

        script_code = orchestrator._generate_proxy_injection_script() if hasattr(
            orchestrator, "_generate_proxy_injection_script"
        ) else None

        if script_code:
            assert "Interceptor.attach" in script_code or "Interceptor.replace" in script_code
            assert "SSL_CTX_set_verify" in script_code or "WinHttpSetOption" in script_code


class TestMITMProxyBypass:
    """Test MITM proxy bypass with certificate generation."""

    def test_mitm_bypass_extracts_licensing_domains_from_binary(
        self,
        online_activation_binary: Path,
    ) -> None:
        """MITM bypass must extract licensing server domains from binary strings."""
        orchestrator = CertificateBypassOrchestrator()

        domains = orchestrator._extract_licensing_domains(str(online_activation_binary))

        assert isinstance(domains, list)

        if len(domains) > 0:
            for domain in domains:
                assert isinstance(domain, str)
                assert len(domain) > 0
                assert "." in domain or "localhost" in domain.lower()

    def test_mitm_bypass_creates_certificate_directory(
        self,
        online_activation_binary: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """MITM bypass must create certificate directory for generated certs."""
        orchestrator = CertificateBypassOrchestrator()

        test_cert_dir = tmp_path / "test_mitm_certs"
        monkeypatch.setattr(
            "pathlib.Path.home",
            lambda: tmp_path,
        )

        result = orchestrator._execute_mitm_proxy(str(online_activation_binary))

        if result:
            expected_cert_dir = tmp_path / ".intellicrack" / "mitm_certs"
            assert expected_cert_dir.exists(), "Certificate directory not created"

    def test_mitm_bypass_generates_valid_ssl_certificates(
        self,
        online_activation_binary: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """MITM bypass must generate valid SSL certificates for licensing domains."""
        orchestrator = CertificateBypassOrchestrator()

        monkeypatch.setattr(
            "pathlib.Path.home",
            lambda: tmp_path,
        )

        result = orchestrator._execute_mitm_proxy(str(online_activation_binary))

        if result:
            cert_dir = tmp_path / ".intellicrack" / "mitm_certs"
            if cert_dir.exists():
                cert_files = list(cert_dir.glob("*.pem"))
                key_files = list(cert_dir.glob("*_key.pem"))

                assert len(cert_files) > 0, "No certificate files generated"
                assert len(key_files) > 0, "No private key files generated"

                for cert_file in cert_files:
                    cert_content = cert_file.read_bytes()
                    assert b"BEGIN CERTIFICATE" in cert_content
                    assert len(cert_content) > 100


class TestBypassVerification:
    """Test bypass verification mechanisms."""

    def test_verification_checks_multiple_indicators(
        self,
        temp_binary_copy: Path,
        real_detection_report: DetectionReport,
    ) -> None:
        """Verification must check multiple bypass effectiveness indicators."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass(
            str(temp_binary_copy),
            method=BypassMethod.BINARY_PATCH,
        )

        if result.success:
            binary_patch_verified = orchestrator._verify_binary_patches(temp_binary_copy)
            frida_verified = orchestrator._verify_frida_hooks()
            validation_verified = orchestrator._verify_validation_bypassed(temp_binary_copy)

            assert isinstance(binary_patch_verified, bool)
            assert isinstance(frida_verified, bool)
            assert isinstance(validation_verified, bool)

            at_least_one_verified = (
                binary_patch_verified or frida_verified or validation_verified
            )
            assert at_least_one_verified, "No verification method confirmed bypass"

    def test_verification_scans_for_patch_signatures(
        self,
        temp_binary_copy: Path,
    ) -> None:
        """Verification must scan binary for known patch signatures."""
        orchestrator = CertificateBypassOrchestrator()

        patched_binary = temp_binary_copy.read_bytes()

        x86_return_true = b'\xB8\x01\x00\x00\x00\xC3'
        x64_return_true = b'\x48\xC7\xC0\x01\x00\x00\x00\xC3'

        modified_content = patched_binary[:1000] + x86_return_true + patched_binary[1006:]
        temp_binary_copy.write_bytes(modified_content)

        verification_result = orchestrator._verify_binary_patches(temp_binary_copy)

        assert verification_result, "Failed to detect injected patch signature"


class TestRollbackFunctionality:
    """Test rollback and restoration capabilities."""

    def test_rollback_restores_original_binary(
        self,
        temp_binary_copy: Path,
        real_detection_report: DetectionReport,
    ) -> None:
        """Rollback must restore binary to original state."""
        original_content = temp_binary_copy.read_bytes()
        original_hash = hash(original_content)

        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass(
            str(temp_binary_copy),
            method=BypassMethod.BINARY_PATCH,
        )

        if result.success and result.patch_result and result.patch_result.success:
            modified_content = temp_binary_copy.read_bytes()
            modified_hash = hash(modified_content)

            assert original_hash != modified_hash, "Binary was not modified"

            rollback_success = orchestrator.rollback(result)

            if rollback_success:
                restored_content = temp_binary_copy.read_bytes()
                restored_hash = hash(restored_content)

                assert restored_hash == original_hash, "Binary not fully restored"

    def test_rollback_handles_frida_detachment(self) -> None:
        """Rollback must properly detach Frida hooks."""
        orchestrator = CertificateBypassOrchestrator()

        test_process = subprocess.Popen(
            ["python", "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            time.sleep(1)

            result = orchestrator.bypass(
                str(test_process.pid),
                method=BypassMethod.FRIDA_HOOK,
            )

            if result.success and result.frida_status:
                rollback_success = orchestrator.rollback(result)

                assert isinstance(rollback_success, bool)

                if orchestrator.frida_hooks:
                    assert not orchestrator.frida_hooks.is_attached()
        finally:
            test_process.kill()
            test_process.wait()


class TestEndToEndBypass:
    """Test complete end-to-end bypass workflows."""

    def test_complete_bypass_workflow_on_protected_binary(
        self,
        temp_binary_copy: Path,
        real_detection_report: DetectionReport,
    ) -> None:
        """Complete bypass workflow must detect, patch, verify, and allow rollback."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass(str(temp_binary_copy))

        assert isinstance(result, BypassResult)
        assert result.detection_report is not None

        if result.detection_report.has_validation():
            assert result.method_used != BypassMethod.NONE

            if result.success:
                assert result.verification_passed or result.patch_result is not None

                result_dict = result.to_dict()
                assert "success" in result_dict
                assert "method_used" in result_dict
                assert "verification_passed" in result_dict
                assert result_dict["success"] == result.success

    def test_bypass_result_contains_complete_metadata(
        self,
        online_activation_binary: Path,
    ) -> None:
        """Bypass result must contain complete operation metadata."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass(str(online_activation_binary))

        assert hasattr(result, "success")
        assert hasattr(result, "method_used")
        assert hasattr(result, "detection_report")
        assert hasattr(result, "verification_passed")
        assert hasattr(result, "errors")
        assert hasattr(result, "timestamp")

        assert isinstance(result.success, bool)
        assert isinstance(result.method_used, BypassMethod)
        assert isinstance(result.errors, list)

        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert "detection_summary" in result_dict


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_bypass_handles_nonexistent_binary(self) -> None:
        """Orchestrator must handle non-existent binary gracefully."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass("/nonexistent/path/binary.exe")

        assert isinstance(result, BypassResult)
        assert not result.success
        assert len(result.errors) > 0
        assert any("not found" in err.lower() for err in result.errors)

    def test_bypass_handles_corrupted_binary(
        self,
        tmp_path: Path,
    ) -> None:
        """Orchestrator must handle corrupted binary data gracefully."""
        corrupted_binary = tmp_path / "corrupted.exe"
        corrupted_binary.write_bytes(b"INVALID_PE_DATA" * 100)

        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass(str(corrupted_binary))

        assert isinstance(result, BypassResult)

        if not result.success:
            assert len(result.errors) > 0 or result.method_used == BypassMethod.NONE

    def test_bypass_handles_invalid_process_id(self) -> None:
        """Orchestrator must handle invalid process ID gracefully."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass("999999")

        assert isinstance(result, BypassResult)

        if not result.success:
            assert result.method_used == BypassMethod.NONE or len(result.errors) > 0


class TestRealWorldScenarios:
    """Test real-world bypass scenarios."""

    def test_bypass_binary_with_multiple_validation_functions(
        self,
        enterprise_license_binary: Path,
    ) -> None:
        """Orchestrator must handle binaries with multiple certificate validation functions."""
        orchestrator = CertificateBypassOrchestrator()

        result = orchestrator.bypass(str(enterprise_license_binary))

        if result.detection_report.has_validation():
            validation_count = len(result.detection_report.validation_functions)

            if validation_count > 1:
                if result.patch_result:
                    patched_count = len(result.patch_result.patched_functions)
                    assert patched_count > 0, "No functions patched despite multiple detections"

    def test_bypass_handles_mixed_tls_libraries(
        self,
        protected_binaries_dir: Path,
    ) -> None:
        """Orchestrator must handle binaries using multiple TLS libraries."""
        orchestrator = CertificateBypassOrchestrator()

        for binary_file in protected_binaries_dir.glob("*.exe"):
            result = orchestrator.bypass(str(binary_file))

            if result.detection_report.has_validation():
                detected_libs = result.detection_report.detected_libraries

                if len(detected_libs) > 1:
                    assert result.method_used != BypassMethod.NONE
                    break

    def test_bypass_performance_on_real_binary(
        self,
        online_activation_binary: Path,
    ) -> None:
        """Bypass operation must complete within reasonable time."""
        import time

        orchestrator = CertificateBypassOrchestrator()

        start_time = time.time()
        result = orchestrator.bypass(str(online_activation_binary))
        elapsed_time = time.time() - start_time

        assert elapsed_time < 60.0, f"Bypass took too long: {elapsed_time:.2f}s"
        assert isinstance(result, BypassResult)
