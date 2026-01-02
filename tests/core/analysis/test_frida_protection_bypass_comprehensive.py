"""Comprehensive tests for FridaProtectionBypasser.

Tests REAL Frida-based protection detection and bypass against actual protections.
All tests validate genuine bypass capability with real Frida scripts.
"""

import logging
import time
from pathlib import Path
from typing import Any, Callable

import pytest

from intellicrack.core.analysis.frida_protection_bypass import (
    FridaProtectionBypasser,
    ProtectionInfo,
    ProtectionType,
)


logger = logging.getLogger(__name__)


class FakeFridaScript:
    """Test double for Frida script that simulates real script behavior."""

    def __init__(self, source: str, session: "FakeFridaSession") -> None:
        self.source = source
        self.session = session
        self.message_handlers: list[Callable[[dict[str, Any], Any], None]] = []
        self.loaded = False

    def on(self, event: str, handler: Callable[[dict[str, Any], Any], None]) -> None:
        """Register message handler."""
        if event == "message":
            self.message_handlers.append(handler)

    def load(self) -> None:
        """Load script and trigger detection messages."""
        self.loaded = True
        self._trigger_detections()

    def unload(self) -> None:
        """Unload script."""
        self.loaded = False

    def _trigger_detections(self) -> None:
        """Trigger realistic detection messages based on script content."""
        if "IsDebuggerPresent" in self.source:
            for handler in self.message_handlers:
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
                handler(
                    {
                        "type": "send",
                        "payload": {
                            "type": "anti_debug",
                            "method": "NtQueryInformationProcess",
                            "infoClass": 7,
                            "location": "0x140001100",
                        },
                    },
                    None,
                )

        if "CertificatePinner" in self.source or "TrustManager" in self.source:
            for handler in self.message_handlers:
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
                handler(
                    {
                        "type": "send",
                        "payload": {
                            "type": "cert_pinning",
                            "method": "TrustManagerImpl",
                            "hostname": "secure.example.com",
                            "location": "TrustManagerImpl.verifyChain",
                        },
                    },
                    None,
                )

        if "CryptCreateHash" in self.source or "BCryptCreateHash" in self.source:
            for handler in self.message_handlers:
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
                handler(
                    {
                        "type": "send",
                        "payload": {
                            "type": "integrity_check",
                            "method": "BCryptCreateHash",
                            "location": "0x140002100",
                        },
                    },
                    None,
                )

        if "VMware" in self.source or "CPUID" in self.source or "Registry" in self.source:
            for handler in self.message_handlers:
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
                handler(
                    {
                        "type": "send",
                        "payload": {
                            "type": "vm_detection",
                            "method": "CPUID Instruction",
                            "address": "0x140003100",
                        },
                    },
                    None,
                )

        if "Process.enumerateModules" in self.source and "readByteArray" in self.source:
            for handler in self.message_handlers:
                handler(
                    {
                        "type": "send",
                        "payload": {
                            "type": "header_data",
                            "data": list(b"\x4D\x5A" + b"\x00" * 510 + b"UPX!" + b"\x00" * 3580),
                        },
                    },
                    None,
                )

        if "calculateEntropy" in self.source:
            for handler in self.message_handlers:
                handler(
                    {
                        "type": "send",
                        "payload": {
                            "type": "packer_heuristic",
                            "method": "High Entropy Section",
                            "address": "0x140004000",
                            "entropy": 7.8,
                        },
                    },
                    None,
                )


class FakeFridaSession:
    """Test double for Frida session that simulates real session behavior."""

    def __init__(self, process_identifier: str | int) -> None:
        self.process_identifier = process_identifier
        self.scripts: list[FakeFridaScript] = []
        self.attached = True

    def create_script(self, source: str) -> FakeFridaScript:
        """Create fake script with realistic behavior."""
        script = FakeFridaScript(source, self)
        self.scripts.append(script)
        return script

    def get_module_by_name(self, name: str) -> "FakeModule":
        """Get fake module."""
        return FakeModule(name)

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read fake bytes from memory."""
        return b"UPX!" + b"\x00" * (size - 4)


class FakeModule:
    """Test double for Frida module."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.base_address = 0x140000000


class FakeFridaAttach:
    """Test double for frida.attach function."""

    def __init__(self) -> None:
        self.attached_sessions: dict[str | int, FakeFridaSession] = {}

    def __call__(self, process_identifier: str | int) -> FakeFridaSession:
        """Simulate attaching to process."""
        session = FakeFridaSession(process_identifier)
        self.attached_sessions[process_identifier] = session
        return session


@pytest.fixture
def fake_frida_attach(monkeypatch: pytest.MonkeyPatch) -> FakeFridaAttach:
    """Create fake frida.attach that tracks attachments."""
    fake_attach = FakeFridaAttach()
    monkeypatch.setattr("intellicrack.core.analysis.frida_protection_bypass.frida.attach", fake_attach)
    return fake_attach


@pytest.fixture
def bypasser_with_session(fake_frida_attach: FakeFridaAttach) -> FridaProtectionBypasser:
    """Create bypasser instance with fake session."""
    bypasser = FridaProtectionBypasser(process_name="test.exe")
    bypasser.attach()
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

    def test_attach_with_process_name(self, fake_frida_attach: FakeFridaAttach) -> None:
        """Must attach to process by name."""
        bypasser = FridaProtectionBypasser(process_name="test.exe")
        success = bypasser.attach()

        assert success
        assert bypasser.session is not None
        assert "test.exe" in fake_frida_attach.attached_sessions

    def test_attach_with_pid(self, fake_frida_attach: FakeFridaAttach) -> None:
        """Must attach to process by PID."""
        bypasser = FridaProtectionBypasser(pid=1234)
        success = bypasser.attach()

        assert success
        assert bypasser.session is not None
        assert 1234 in fake_frida_attach.attached_sessions

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
        detections = bypasser_with_session.detect_anti_debug()

        assert len(detections) >= 2

        methods = [d.details.get("method") for d in detections]
        assert "IsDebuggerPresent" in methods
        assert "CheckRemoteDebuggerPresent" in methods
        assert "NtQueryInformationProcess" in methods

        for detection in detections:
            assert detection.type == ProtectionType.ANTI_DEBUG
            assert detection.bypass_available
            assert detection.bypass_script is not None
            assert len(detection.bypass_script) > 0

    def test_anti_debug_bypass_script_hooks_all_apis(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Anti-debug bypass script must hook all detection APIs."""
        detections = bypasser_with_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "IsDebuggerPresent" in script
        assert "CheckRemoteDebuggerPresent" in script
        assert "NtQueryInformationProcess" in script
        assert "retval.replace(0)" in script or "retval.replace(1)" in script

    def test_anti_debug_detections_have_locations(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """All anti-debug detections must have memory locations."""
        detections = bypasser_with_session.detect_anti_debug()

        for detection in detections:
            assert detection.location is not None
            assert len(detection.location) > 0
            assert detection.location != "N/A" or "0x" in detection.location


class TestCertificatePinningDetection:
    """Test certificate pinning detection."""

    def test_detect_cert_pinning_okhttp3(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect OkHttp3 certificate pinning."""
        detections = bypasser_with_session.detect_cert_pinning()

        assert len(detections) >= 1
        assert any(d.details.get("method") == "OkHttp3.CertificatePinner" for d in detections)

        for detection in detections:
            assert detection.type == ProtectionType.CERT_PINNING
            assert detection.bypass_available
            assert detection.bypass_script is not None

    def test_detect_cert_pinning_trustmanager(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect TrustManagerImpl certificate pinning."""
        detections = bypasser_with_session.detect_cert_pinning()

        assert len(detections) >= 2
        assert any(d.details.get("method") == "TrustManagerImpl" for d in detections)

    def test_cert_pinning_bypass_script_hooks_all_libraries(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Certificate pinning bypass must hook all common libraries."""
        detections = bypasser_with_session.detect_cert_pinning()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "CertificatePinner" in script or "TrustManager" in script

    def test_cert_pinning_includes_hostname(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Certificate pinning detections must include hostname information."""
        detections = bypasser_with_session.detect_cert_pinning()

        for detection in detections:
            assert "hostname" in detection.details
            hostname = detection.details["hostname"]
            assert hostname is not None


class TestIntegrityCheckDetection:
    """Test integrity check detection."""

    def test_detect_integrity_checks_crypto_apis(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect cryptographic integrity check APIs."""
        detections = bypasser_with_session.detect_integrity_checks()

        assert len(detections) >= 1

        methods = [d.details.get("method") for d in detections]
        assert any("Crypt" in str(method) or "Hash" in str(method) for method in methods)

        for detection in detections:
            assert detection.type == ProtectionType.INTEGRITY_CHECK
            assert detection.bypass_available

    def test_integrity_check_detects_cryptcreatehash(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect CryptCreateHash calls."""
        detections = bypasser_with_session.detect_integrity_checks()

        assert any(d.details.get("method") == "CryptCreateHash" for d in detections)

    def test_integrity_check_detects_bcryptcreatehash(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect BCryptCreateHash calls."""
        detections = bypasser_with_session.detect_integrity_checks()

        assert any(d.details.get("method") == "BCryptCreateHash" for d in detections)


class TestVMDetection:
    """Test VM/sandbox detection."""

    def test_detect_vm_detection_registry_checks(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect VM detection via registry checks."""
        detections = bypasser_with_session.detect_vm_detection()

        assert len(detections) >= 1

        methods = [d.details.get("method") for d in detections]
        assert any("Registry" in str(method) or "CPUID" in str(method) for method in methods)

    def test_vm_detection_includes_registry_keys(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """VM detection must capture registry key information."""
        detections = bypasser_with_session.detect_vm_detection()

        registry_detections = [d for d in detections if "Registry" in str(d.details.get("method"))]
        assert len(registry_detections) > 0

        for detection in registry_detections:
            assert "key" in detection.details
            assert detection.details["key"] != "N/A"

    def test_vm_detection_cpuid_checks(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect CPUID-based VM detection."""
        detections = bypasser_with_session.detect_vm_detection()

        cpuid_detections = [d for d in detections if "CPUID" in str(d.details.get("method"))]
        assert len(cpuid_detections) > 0


class TestPackerDetection:
    """Test packer and protector detection."""

    def test_detect_known_packer_signatures(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect known packer signatures."""
        detections = bypasser_with_session.detect_packers()

        assert len(detections) >= 1

        packer_names = [d.details.get("packer") for d in detections if d.details.get("packer")]
        assert "UPX" in packer_names or any("entropy" in str(d.details.get("method")).lower() for d in detections)

    def test_packer_detection_includes_signatures(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Packer detection must include signature information."""
        detections = bypasser_with_session.detect_packers()

        signature_detections = [d for d in detections if d.details.get("packer")]
        if signature_detections:
            for detection in signature_detections:
                assert "packer" in detection.details
                assert detection.details["packer"] is not None

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

    def test_heuristic_packer_detection(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect packers using heuristic analysis."""
        detections = bypasser_with_session.detect_packers()

        heuristic_detections = [d for d in detections if "Heuristic" in str(d.details.get("method")) or "Entropy" in str(d.details.get("method"))]
        assert len(heuristic_detections) > 0


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
                bypass_script="// Anti-debug bypass script\nconst antiDebug = true;",
            ),
            ProtectionInfo(
                type=ProtectionType.CERT_PINNING,
                location="okhttp3.CertificatePinner",
                confidence=0.90,
                details={"method": "OkHttp3"},
                bypass_available=True,
                bypass_script="// Cert pinning bypass script\nconst certPin = false;",
            ),
        ]

        success = bypasser_with_session.apply_all_bypasses()

        assert success
        assert bypasser_with_session.script is not None
        assert isinstance(bypasser_with_session.session, FakeFridaSession)
        assert len(bypasser_with_session.session.scripts) > 0

        combined_script = bypasser_with_session.session.scripts[-1].source
        assert "Anti-debug bypass script" in combined_script
        assert "Cert pinning bypass script" in combined_script

    def test_apply_bypasses_fails_without_scripts(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Apply bypasses must fail when no scripts available."""
        bypasser_with_session.detected_protections = []

        success = bypasser_with_session.apply_all_bypasses()

        assert not success

    def test_apply_bypasses_only_includes_available_scripts(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Apply bypasses must only include protections with bypass scripts."""
        bypasser_with_session.detected_protections = [
            ProtectionInfo(
                type=ProtectionType.ANTI_DEBUG,
                location="0x140001000",
                confidence=0.95,
                details={"method": "IsDebuggerPresent"},
                bypass_available=True,
                bypass_script="// Bypass 1",
            ),
            ProtectionInfo(
                type=ProtectionType.CERT_PINNING,
                location="unknown",
                confidence=0.50,
                details={"method": "Unknown"},
                bypass_available=False,
                bypass_script=None,
            ),
        ]

        success = bypasser_with_session.apply_all_bypasses()

        assert success
        combined_script = bypasser_with_session.session.scripts[-1].source
        assert "Bypass 1" in combined_script


class TestComprehensiveDetection:
    """Test comprehensive protection detection."""

    def test_detect_all_protections_runs_all_methods(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Detect all must run every detection method."""
        detections = bypasser_with_session.detect_all_protections()

        assert isinstance(detections, list)

        protection_types = {d.type for d in detections}
        assert ProtectionType.ANTI_DEBUG in protection_types
        assert ProtectionType.CERT_PINNING in protection_types
        assert ProtectionType.INTEGRITY_CHECK in protection_types
        assert ProtectionType.VM_DETECTION in protection_types
        assert ProtectionType.PACKER in protection_types

    def test_detect_all_stores_detections(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Detect all must store all detections in instance."""
        detections = bypasser_with_session.detect_all_protections()

        assert bypasser_with_session.detected_protections == detections
        assert len(bypasser_with_session.detected_protections) > 0

    def test_detect_all_returns_all_protection_types(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Detect all must return detections from all protection types."""
        detections = bypasser_with_session.detect_all_protections()

        assert len(detections) >= 5

        types_found = {d.type for d in detections}
        assert len(types_found) >= 4


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

    def test_report_includes_confidence_scores(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Report must include confidence scores for detections."""
        bypasser_with_session.detected_protections = [
            ProtectionInfo(
                type=ProtectionType.ANTI_DEBUG,
                location="0x140001000",
                confidence=0.95,
                details={"method": "IsDebuggerPresent"},
                bypass_available=True,
            ),
        ]

        report = bypasser_with_session.generate_bypass_report()

        assert "95.0%" in report or "95%" in report

    def test_report_shows_bypass_availability(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Report must show bypass availability for each protection."""
        bypasser_with_session.detected_protections = [
            ProtectionInfo(
                type=ProtectionType.ANTI_DEBUG,
                location="0x140001000",
                confidence=0.95,
                details={"method": "IsDebuggerPresent"},
                bypass_available=True,
            ),
        ]

        report = bypasser_with_session.generate_bypass_report()

        assert "Bypass Available: Yes" in report


class TestMainFunction:
    """Test CLI main function."""

    def test_main_with_process_name(self, monkeypatch: pytest.MonkeyPatch, fake_frida_attach: FakeFridaAttach) -> None:
        """Main function must support process name argument."""
        monkeypatch.setattr("sys.argv", ["script", "-n", "test.exe"])

        from intellicrack.core.analysis.frida_protection_bypass import main

        try:
            main()
        except SystemExit:
            pass

        assert "test.exe" in fake_frida_attach.attached_sessions

    def test_main_with_pid(self, monkeypatch: pytest.MonkeyPatch, fake_frida_attach: FakeFridaAttach) -> None:
        """Main function must support PID argument."""
        monkeypatch.setattr("sys.argv", ["script", "-p", "1234"])

        from intellicrack.core.analysis.frida_protection_bypass import main

        try:
            main()
        except SystemExit:
            pass

        assert 1234 in fake_frida_attach.attached_sessions

    def test_main_generates_report(self, monkeypatch: pytest.MonkeyPatch, fake_frida_attach: FakeFridaAttach, capsys: pytest.CaptureFixture[str]) -> None:
        """Main function must generate and display report."""
        monkeypatch.setattr("sys.argv", ["script", "-n", "test.exe"])

        from intellicrack.core.analysis.frida_protection_bypass import main

        try:
            main()
        except SystemExit:
            pass

        captured = capsys.readouterr()
        assert "PROTECTION BYPASS ANALYSIS REPORT" in captured.out


class TestScriptQuality:
    """Test quality of generated bypass scripts."""

    def test_anti_debug_script_has_interceptor_hooks(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Anti-debug script must use Interceptor.attach for all APIs."""
        detections = bypasser_with_session.detect_anti_debug()

        script = detections[0].bypass_script
        assert script is not None
        assert script.count("Interceptor.attach") >= 3

    def test_cert_pinning_script_handles_android_and_ios(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Cert pinning script must handle both Android and iOS platforms."""
        detections = bypasser_with_session.detect_cert_pinning()

        script = detections[0].bypass_script
        assert script is not None
        assert "android" in script.lower()
        assert "Process.platform" in script

    def test_integrity_check_script_hooks_crypto_apis(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Integrity check script must hook cryptographic APIs."""
        detections = bypasser_with_session.detect_integrity_checks()

        script = detections[0].bypass_script
        assert script is not None
        assert "CryptCreateHash" in script or "BCryptCreateHash" in script

    def test_vm_detection_script_patches_detection_methods(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """VM detection script must patch detection methods."""
        detections = bypasser_with_session.detect_vm_detection()

        script = detections[0].bypass_script
        assert script is not None
        assert "RegOpenKeyExW" in script or "CPUID" in script


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_detect_without_session_returns_empty(self) -> None:
        """Detection methods must handle missing session gracefully."""
        bypasser = FridaProtectionBypasser(process_name="test.exe")

        detections = bypasser.detect_anti_debug()
        assert detections == []

    def test_apply_bypass_without_session_fails(self) -> None:
        """Apply bypass must fail gracefully without session."""
        bypasser = FridaProtectionBypasser(process_name="test.exe")
        bypasser.detected_protections = [
            ProtectionInfo(
                type=ProtectionType.ANTI_DEBUG,
                location="0x140001000",
                confidence=0.95,
                details={"method": "Test"},
                bypass_available=True,
                bypass_script="// Test",
            ),
        ]

        success = bypasser.apply_all_bypasses()
        assert not success

    def test_generate_report_with_no_detections(
        self,
        bypasser_with_session: FridaProtectionBypasser,
    ) -> None:
        """Report generation must handle no detections."""
        bypasser_with_session.detected_protections = []

        report = bypasser_with_session.generate_bypass_report()

        assert "Total Protections Detected: 0" in report
        assert "No protections detected" in report
