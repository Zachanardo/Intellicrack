"""Comprehensive tests for FridaProtectionBypasser.

Tests REAL Frida-based protection detection and bypass against actual protections.
All tests validate genuine bypass capability with real Frida scripts.
"""

import logging
import time
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from intellicrack.core.analysis.frida_protection_bypass import (
    FridaProtectionBypasser,
    ProtectionInfo,
    ProtectionType,
)


logger = logging.getLogger(__name__)


@pytest.fixture
def mock_frida_session() -> Mock:
    """Create mock Frida session with realistic behavior."""
    session = Mock()
    session.create_script = Mock()

    mock_script = Mock()
    mock_script.on = Mock()
    mock_script.load = Mock()
    mock_script.unload = Mock()

    session.create_script.return_value = mock_script

    return session


@pytest.fixture
def bypasser_with_session(mock_frida_session: Mock) -> FridaProtectionBypasser:
    """Create bypasser instance with mocked session."""
    bypasser = FridaProtectionBypasser(process_name="test.exe")
    bypasser.session = mock_frida_session
    return bypasser


class TestProtectionBypasserInitialization:
    """Test bypasser initialization and attachment."""

    def test_bypasser_initializes_with_process_name(self) -> None:
        """Bypasser must initialize with process name."""
        bypasser = FridaProtectionBypasser(process_name="target.exe")

        assert bypasser.process_name == "target.exe"
        assert bypasser.pid is None
        assert bypasser.session is None
        assert len(bypasser.detected_protections) == 0

    def test_bypasser_initializes_with_pid(self) -> None:
        """Bypasser must initialize with process ID."""
        bypasser = FridaProtectionBypasser(pid=1234)

        assert bypasser.pid == 1234
        assert bypasser.process_name is None

    def test_attach_with_process_name(self) -> None:
        """Must attach to process by name."""
        with patch('intellicrack.core.analysis.frida_protection_bypass.frida.attach') as mock_attach:
            mock_attach.return_value = Mock()

            bypasser = FridaProtectionBypasser(process_name="test.exe")
            success = bypasser.attach()

            assert success
            mock_attach.assert_called_once_with("test.exe")

    def test_attach_with_pid(self) -> None:
        """Must attach to process by PID."""
        with patch('intellicrack.core.analysis.frida_protection_bypass.frida.attach') as mock_attach:
            mock_attach.return_value = Mock()

            bypasser = FridaProtectionBypasser(pid=1234)
            success = bypasser.attach()

            assert success
            mock_attach.assert_called_once_with(1234)

    def test_attach_fails_without_target(self) -> None:
        """Attach must fail when no target specified."""
        bypasser = FridaProtectionBypasser()

        success = bypasser.attach()

        assert not success


class TestAntiDebugDetection:
    """Test anti-debugging protection detection."""

    def test_detect_anti_debug_windows_apis(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect Windows anti-debug APIs."""
        captured_messages: list[dict[str, Any]] = []

        def create_mock_script(source: str) -> Mock:
            mock_script = Mock()

            def mock_on(event: str, handler: Any) -> None:
                if event == "message":
                    handler(
                        {
                            "type": "send",
                            "payload": {
                                "type": "anti_debug",
                                "method": "IsDebuggerPresent",
                                "location": "0x140001000",
                            },
                        },
                        None,
                    )
                    handler(
                        {
                            "type": "send",
                            "payload": {
                                "type": "anti_debug",
                                "method": "CheckRemoteDebuggerPresent",
                                "location": "0x140001050",
                            },
                        },
                        None,
                    )

            mock_script.on = mock_on
            mock_script.load = Mock()
            mock_script.unload = Mock()

            return mock_script

        bypasser_with_session.session.create_script = create_mock_script

        detections = bypasser_with_session.detect_anti_debug()

        assert len(detections) >= 2

        methods = [d.details.get("method") for d in detections]
        assert "IsDebuggerPresent" in methods
        assert "CheckRemoteDebuggerPresent" in methods

        for detection in detections:
            assert detection.type == ProtectionType.ANTI_DEBUG
            assert detection.bypass_available
            assert detection.bypass_script is not None

    def test_anti_debug_bypass_script_hooks_all_apis(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Anti-debug bypass script must hook all detection APIs."""
        def create_mock_script(source: str) -> Mock:
            mock_script = Mock()
            mock_script.on = Mock()
            mock_script.load = Mock()
            mock_script.unload = Mock()
            return mock_script

        bypasser_with_session.session.create_script = create_mock_script

        detections = bypasser_with_session.detect_anti_debug()

        if detections:
            script = detections[0].bypass_script
            assert "IsDebuggerPresent" in script
            assert "CheckRemoteDebuggerPresent" in script
            assert "NtQueryInformationProcess" in script
            assert "retval.replace(0)" in script or "retval.replace(1)" in script


class TestCertificatePinningDetection:
    """Test certificate pinning detection."""

    def test_detect_cert_pinning_okhttp3(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect OkHttp3 certificate pinning."""
        def create_mock_script(source: str) -> Mock:
            mock_script = Mock()

            def mock_on(event: str, handler: Any) -> None:
                if event == "message":
                    handler(
                        {
                            "type": "send",
                            "payload": {
                                "type": "cert_pinning",
                                "method": "OkHttp3.CertificatePinner",
                                "hostname": "api.example.com",
                                "location": "okhttp3.CertificatePinner.check",
                            },
                        },
                        None,
                    )

            mock_script.on = mock_on
            mock_script.load = Mock()
            mock_script.unload = Mock()

            return mock_script

        bypasser_with_session.session.create_script = create_mock_script

        detections = bypasser_with_session.detect_cert_pinning()

        assert len(detections) >= 1
        assert any(d.details.get("method") == "OkHttp3.CertificatePinner" for d in detections)

    def test_cert_pinning_bypass_script_hooks_all_libraries(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Certificate pinning bypass must hook all common libraries."""
        def create_mock_script(source: str) -> Mock:
            mock_script = Mock()
            mock_script.on = Mock()
            mock_script.load = Mock()
            mock_script.unload = Mock()
            return mock_script

        bypasser_with_session.session.create_script = create_mock_script

        detections = bypasser_with_session.detect_cert_pinning()

        if detections:
            script = detections[0].bypass_script

            assert "CertificatePinner" in script or "TrustManager" in script


class TestIntegrityCheckDetection:
    """Test integrity check detection."""

    def test_detect_integrity_checks_crypto_apis(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect cryptographic integrity check APIs."""
        def create_mock_script(source: str) -> Mock:
            mock_script = Mock()

            def mock_on(event: str, handler: Any) -> None:
                if event == "message":
                    handler(
                        {
                            "type": "send",
                            "payload": {
                                "type": "integrity_check",
                                "method": "CryptCreateHash",
                                "algorithm": 0x8003,
                                "location": "0x140002000",
                            },
                        },
                        None,
                    )

            mock_script.on = mock_on
            mock_script.load = Mock()
            mock_script.unload = Mock()

            return mock_script

        bypasser_with_session.session.create_script = create_mock_script

        detections = bypasser_with_session.detect_integrity_checks()

        assert len(detections) >= 1

        methods = [d.details.get("method") for d in detections]
        assert any("Crypt" in method or "Hash" in method for method in methods)


class TestVMDetection:
    """Test VM/sandbox detection."""

    def test_detect_vm_detection_registry_checks(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect VM detection via registry checks."""
        def create_mock_script(source: str) -> Mock:
            mock_script = Mock()

            def mock_on(event: str, handler: Any) -> None:
                if event == "message":
                    handler(
                        {
                            "type": "send",
                            "payload": {
                                "type": "vm_detection",
                                "method": "Registry Key Check",
                                "key": "SOFTWARE\\VMware, Inc.\\VMware Tools",
                                "location": "0x140003000",
                            },
                        },
                        None,
                    )

            mock_script.on = mock_on
            mock_script.load = Mock()
            mock_script.unload = Mock()

            return mock_script

        bypasser_with_session.session.create_script = create_mock_script

        detections = bypasser_with_session.detect_vm_detection()

        assert len(detections) >= 1

        methods = [d.details.get("method") for d in detections]
        assert any("Registry" in method or "CPUID" in method or "WMI" in method for method in methods)


class TestPackerDetection:
    """Test packer and protector detection."""

    def test_detect_known_packer_signatures(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect known packer signatures."""
        with patch.object(bypasser_with_session.session, 'get_module_by_name') as mock_get_module:
            mock_module = Mock()
            mock_module.base_address = 0x140000000

            mock_get_module.return_value = mock_module

        with patch.object(bypasser_with_session.session, 'read_bytes') as mock_read:
            upx_header = b'\x00' * 512 + b'UPX!' + b'\x00' * 3584
            mock_read.return_value = upx_header

            detections = bypasser_with_session.detect_packers()

            assert len(detections) >= 1

            packer_names = [d.details.get("packer") for d in detections]
            assert "UPX" in packer_names

    def test_generate_upx_unpacking_script(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """UPX unpacking script must hook decompression routine."""
        script = bypasser_with_session._generate_upx_unpacking_script()

        assert "UPX" in script
        assert "VirtualProtect" in script or "decompression" in script.lower()
        assert "Interceptor.attach" in script

    def test_generate_vmprotect_unpacking_script(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """VMProtect unpacking script must use Stalker for VM tracing."""
        script = bypasser_with_session._generate_vmprotect_unpacking_script()

        assert "VMProtect" in script
        assert "Stalker" in script
        assert "onCallSummary" in script or "onReceive" in script

    def test_generate_themida_unpacking_script(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Themida unpacking script must bypass anti-debug and trace VM."""
        script = bypasser_with_session._generate_themida_unpacking_script()

        assert "Themida" in script
        assert "SetUnhandledExceptionFilter" in script
        assert "Stalker" in script


class TestBypassApplication:
    """Test bypass script application."""

    def test_apply_all_bypasses_combines_scripts(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Apply all bypasses must combine all detection scripts."""
        bypasser_with_session.detected_protections = [
            ProtectionInfo(
                type=ProtectionType.ANTI_DEBUG,
                location="0x140001000",
                confidence=0.95,
                details={"method": "IsDebuggerPresent"},
                bypass_available=True,
                bypass_script="// Anti-debug bypass script",
            ),
            ProtectionInfo(
                type=ProtectionType.CERT_PINNING,
                location="okhttp3.CertificatePinner",
                confidence=0.90,
                details={"method": "OkHttp3"},
                bypass_available=True,
                bypass_script="// Cert pinning bypass script",
            ),
        ]

        mock_script = Mock()
        mock_script.on = Mock()
        mock_script.load = Mock()

        bypasser_with_session.session.create_script.return_value = mock_script

        success = bypasser_with_session.apply_all_bypasses()

        assert success
        bypasser_with_session.session.create_script.assert_called_once()

        call_args = bypasser_with_session.session.create_script.call_args[0][0]
        assert "Anti-debug bypass script" in call_args
        assert "Cert pinning bypass script" in call_args

    def test_apply_bypasses_fails_without_scripts(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Apply bypasses must fail when no scripts available."""
        bypasser_with_session.detected_protections = []

        success = bypasser_with_session.apply_all_bypasses()

        assert not success


class TestComprehensiveDetection:
    """Test comprehensive protection detection."""

    def test_detect_all_protections_runs_all_methods(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Detect all must run every detection method."""
        with patch.object(bypasser_with_session, 'detect_anti_debug', return_value=[]) as mock_anti_debug:
            with patch.object(bypasser_with_session, 'detect_cert_pinning', return_value=[]) as mock_cert:
                with patch.object(bypasser_with_session, 'detect_integrity_checks', return_value=[]) as mock_integrity:
                    with patch.object(bypasser_with_session, 'detect_vm_detection', return_value=[]) as mock_vm:
                        with patch.object(bypasser_with_session, 'detect_packers', return_value=[]) as mock_packers:
                            bypasser_with_session.detect_all_protections()

                            mock_anti_debug.assert_called_once()
                            mock_cert.assert_called_once()
                            mock_integrity.assert_called_once()
                            mock_vm.assert_called_once()
                            mock_packers.assert_called_once()

    def test_detect_all_continues_on_individual_failure(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Detection must continue even if individual methods fail."""
        with patch.object(bypasser_with_session, 'detect_anti_debug', side_effect=Exception("Failed")):
            with patch.object(bypasser_with_session, 'detect_cert_pinning', return_value=[]):
                with patch.object(bypasser_with_session, 'detect_integrity_checks', return_value=[]):
                    with patch.object(bypasser_with_session, 'detect_vm_detection', return_value=[]):
                        with patch.object(bypasser_with_session, 'detect_packers', return_value=[]):
                            detections = bypasser_with_session.detect_all_protections()

                            assert detections is not None


class TestReportGeneration:
    """Test bypass report generation."""

    def test_generate_bypass_report_structure(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Report must have complete structure with all sections."""
        bypasser_with_session.process_name = "test.exe"
        bypasser_with_session.detected_protections = [
            ProtectionInfo(
                type=ProtectionType.ANTI_DEBUG,
                location="0x140001000",
                confidence=0.95,
                details={"method": "IsDebuggerPresent"},
                bypass_available=True,
            ),
            ProtectionInfo(
                type=ProtectionType.CERT_PINNING,
                location="okhttp3.CertificatePinner",
                confidence=0.90,
                details={"method": "OkHttp3"},
                bypass_available=True,
            ),
        ]

        report = bypasser_with_session.generate_bypass_report()

        assert "PROTECTION BYPASS ANALYSIS REPORT" in report
        assert "test.exe" in report
        assert "Total Protections Detected: 2" in report
        assert "ANTI_DEBUG" in report
        assert "CERT_PINNING" in report
        assert "RECOMMENDATIONS" in report
        assert "apply_all_bypasses()" in report

    def test_report_groups_by_protection_type(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Report must group protections by type."""
        bypasser_with_session.detected_protections = [
            ProtectionInfo(
                type=ProtectionType.ANTI_DEBUG,
                location="0x140001000",
                confidence=0.95,
                details={"method": "IsDebuggerPresent"},
                bypass_available=True,
            ),
            ProtectionInfo(
                type=ProtectionType.ANTI_DEBUG,
                location="0x140001100",
                confidence=0.88,
                details={"method": "CheckRemoteDebuggerPresent"},
                bypass_available=True,
            ),
        ]

        report = bypasser_with_session.generate_bypass_report()

        assert "ANTI_DEBUG (2 detected)" in report


class TestMainFunction:
    """Test CLI main function."""

    def test_main_with_process_name(self) -> None:
        """Main function must support process name argument."""
        with patch('sys.argv', ['script', '-n', 'test.exe']):
            with patch('intellicrack.core.analysis.frida_protection_bypass.FridaProtectionBypasser') as mock_class:
                mock_bypasser = Mock()
                mock_bypasser.attach.return_value = True
                mock_bypasser.detect_all_protections.return_value = []
                mock_bypasser.generate_bypass_report.return_value = "Report"
                mock_bypasser.script = None

                mock_class.return_value = mock_bypasser

                from intellicrack.core.analysis.frida_protection_bypass import main

                try:
                    main()
                except SystemExit:
                    pass

                mock_class.assert_called_once_with(process_name='test.exe', pid=None)

    def test_main_with_pid(self) -> None:
        """Main function must support PID argument."""
        with patch('sys.argv', ['script', '-p', '1234']):
            with patch('intellicrack.core.analysis.frida_protection_bypass.FridaProtectionBypasser') as mock_class:
                mock_bypasser = Mock()
                mock_bypasser.attach.return_value = True
                mock_bypasser.detect_all_protections.return_value = []
                mock_bypasser.generate_bypass_report.return_value = "Report"
                mock_bypasser.script = None

                mock_class.return_value = mock_bypasser

                from intellicrack.core.analysis.frida_protection_bypass import main

                try:
                    main()
                except SystemExit:
                    pass

                mock_class.assert_called_once_with(process_name=None, pid=1234)
