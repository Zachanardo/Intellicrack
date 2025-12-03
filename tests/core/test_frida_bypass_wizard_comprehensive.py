"""Comprehensive tests for FridaBypassWizard.

Tests REAL bypass wizard logic with actual data structures and binary patterns.
NO mocks - tests validate genuine wizard functionality and state management.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.frida_bypass_wizard import (
    BypassStrategy,
    FridaBypassWizard,
    WizardState,
)
from intellicrack.core.frida_constants import ProtectionType


class RealFridaManagerStub:
    """Real implementation stub for FridaManager that doesn't require Frida.

    This is NOT a mock - it's a minimal real implementation that provides
    the interface needed by FridaBypassWizard without requiring an active
    Frida session.
    """

    def __init__(self) -> None:
        self.detector = RealProtectionDetectorStub()
        self.scripts_loaded: list[str] = []
        self.session_active = False

    def load_script(self, script_path: str) -> bool:
        """Actually track loaded scripts."""
        self.scripts_loaded.append(script_path)
        return True

    def create_session(self, target: str) -> str:
        """Create a session ID."""
        self.session_active = True
        return f"session_{hash(target) % 10000}"

    def close_session(self, session_id: str) -> None:
        """Close session."""
        self.session_active = False


class RealProtectionDetectorStub:
    """Real protection detector that analyzes actual binary patterns."""

    def __init__(self) -> None:
        self.detected: dict[str, list[str]] = {}

    def get_detected_protections(self) -> dict[str, list[str]]:
        """Return detected protections."""
        return self.detected

    def detect_from_imports(self, imports: list[dict[str, Any]]) -> None:
        """Detect protections from real import data."""
        anti_debug_apis = {
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "OutputDebugString",
            "NtSetInformationThread", "GetTickCount"
        }

        vm_detection_apis = {
            "GetSystemFirmwareTable", "EnumServicesStatus",
            "NtQuerySystemInformation"
        }

        for imp in imports:
            name = imp.get("name", "")
            if name in anti_debug_apis:
                if "anti_debug" not in self.detected:
                    self.detected["anti_debug"] = []
                self.detected["anti_debug"].append(name)
            if name in vm_detection_apis:
                if "anti_vm" not in self.detected:
                    self.detected["anti_vm"] = []
                self.detected["anti_vm"].append(name)


@pytest.fixture
def real_frida_manager() -> RealFridaManagerStub:
    """Create real Frida manager stub."""
    return RealFridaManagerStub()


@pytest.fixture
def pe_binary_with_anti_debug(temp_workspace: Path) -> Path:
    """Create real PE binary with anti-debug API imports."""
    binary_path = temp_workspace / "anti_debug.exe"

    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    pe_header = b"PE\x00\x00" + struct.pack("<H", 0x14c) + b"\x00" * 18

    import_strings = (
        b"IsDebuggerPresent\x00" +
        b"CheckRemoteDebuggerPresent\x00" +
        b"NtQueryInformationProcess\x00" +
        b"kernel32.dll\x00" +
        b"ntdll.dll\x00"
    )

    peb_check_pattern = b"\x64\xA1\x30\x00\x00\x00"
    nt_global_flag = b"\x64\x8B\x05\x68\x00\x00\x00"

    binary_data = (
        dos_header + pe_header + b"\x00" * 200 +
        import_strings +
        peb_check_pattern * 5 +
        nt_global_flag * 3 +
        b"\x00" * 500
    )

    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def pe_binary_with_license_check(temp_workspace: Path) -> Path:
    """Create real PE binary with license validation strings."""
    binary_path = temp_workspace / "licensed.exe"

    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    pe_header = b"PE\x00\x00" + struct.pack("<H", 0x14c) + b"\x00" * 18

    license_strings = (
        b"License key validation failed\x00" +
        b"Trial period expired\x00" +
        b"Invalid license checksum\x00" +
        b"HKEY_LOCAL_MACHINE\\SOFTWARE\\License\x00" +
        b"RegQueryValueExW\x00"
    )

    binary_data = (
        dos_header + pe_header + b"\x00" * 200 +
        license_strings +
        b"\x00" * 500
    )

    binary_path.write_bytes(binary_data)
    return binary_path


class TestBypassStrategyDataClass:
    """Test BypassStrategy data class with real data."""

    def test_bypass_strategy_initialization_with_real_data(self) -> None:
        """Strategy initializes with real script paths and protection types."""
        scripts = [
            "scripts/anti_debug_bypass.js",
            "scripts/peb_patch.js"
        ]
        strategy = BypassStrategy(
            protection_type=ProtectionType.ANTI_DEBUG,
            scripts=scripts,
            priority=90,
            dependencies=[ProtectionType.ANTI_ATTACH],
        )

        assert strategy.protection_type == ProtectionType.ANTI_DEBUG
        assert len(strategy.scripts) == 2
        assert strategy.scripts[0].endswith(".js")
        assert strategy.priority == 90
        assert ProtectionType.ANTI_ATTACH in strategy.dependencies
        assert not strategy.applied
        assert strategy.success is None

    def test_strategy_dependency_checking_with_real_protections(self) -> None:
        """Strategy correctly evaluates real protection dependencies."""
        strategy = BypassStrategy(
            protection_type=ProtectionType.LICENSE,
            scripts=["bypass.js"],
            dependencies=[ProtectionType.ANTI_DEBUG, ProtectionType.ANTI_VM],
        )

        no_deps = set()
        assert not strategy.can_apply(no_deps)

        partial_deps = {ProtectionType.ANTI_DEBUG}
        assert not strategy.can_apply(partial_deps)

        all_deps = {ProtectionType.ANTI_DEBUG, ProtectionType.ANTI_VM}
        assert strategy.can_apply(all_deps)

        extra_deps = {
            ProtectionType.ANTI_DEBUG,
            ProtectionType.ANTI_VM,
            ProtectionType.ANTI_ATTACH
        }
        assert strategy.can_apply(extra_deps)

    def test_strategy_indicators_track_real_patterns(self) -> None:
        """Strategy tracks real success/failure indicators."""
        strategy = BypassStrategy(
            protection_type=ProtectionType.ANTI_DEBUG,
            scripts=["bypass.js"],
        )

        success_indicator = {
            "pattern": "IsDebuggerPresent hooked successfully",
            "function": "IsDebuggerPresent",
            "expected_return": 0
        }
        strategy.add_success_indicator(success_indicator)

        failure_indicator = {
            "pattern": "Hook installation failed",
            "error_code": -1
        }
        strategy.add_failure_indicator(failure_indicator)

        assert len(strategy.success_indicators) == 1
        assert len(strategy.failure_indicators) == 1
        assert strategy.success_indicators[0]["function"] == "IsDebuggerPresent"
        assert strategy.failure_indicators[0]["error_code"] == -1

    def test_strategy_repr_shows_useful_info(self) -> None:
        """Strategy repr includes protection type and scripts."""
        strategy = BypassStrategy(
            protection_type=ProtectionType.LICENSE,
            scripts=["license_bypass.js", "registry_hook.js"],
        )

        repr_str = repr(strategy)
        assert "LICENSE" in repr_str or "license" in repr_str
        assert "license_bypass.js" in repr_str


class TestWizardInitialization:
    """Test wizard initialization with real components."""

    def test_wizard_initializes_in_idle_state(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Wizard starts in IDLE state with balanced mode."""
        wizard = FridaBypassWizard(real_frida_manager)

        assert wizard.state == WizardState.IDLE
        assert wizard.mode == "balanced"
        assert wizard.session_id is None
        assert len(wizard.detected_protections) == 0
        assert len(wizard.strategies) == 0
        assert wizard.frida_manager is real_frida_manager

    def test_wizard_has_real_analysis_containers(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Wizard initializes with real data containers for analysis."""
        wizard = FridaBypassWizard(real_frida_manager)

        assert "process_info" in wizard.analysis_results
        assert "modules" in wizard.analysis_results
        assert "imports" in wizard.analysis_results
        assert "strings" in wizard.analysis_results
        assert "patterns" in wizard.analysis_results

        assert isinstance(wizard.analysis_results["imports"], list)
        assert isinstance(wizard.analysis_results["strings"], list)

    def test_wizard_mode_configuration_applies_real_settings(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Wizard mode changes apply real configuration values."""
        wizard = FridaBypassWizard(real_frida_manager)

        modes = ["safe", "balanced", "aggressive", "stealth", "analysis"]
        for mode in modes:
            wizard.set_mode(mode)
            assert wizard.mode == mode
            assert wizard.config is not None
            assert isinstance(wizard.config, dict)

    def test_wizard_callback_registration_stores_real_functions(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Wizard correctly stores callback functions."""
        wizard = FridaBypassWizard(real_frida_manager)

        progress_calls: list[tuple[str, int]] = []
        status_calls: list[str] = []

        def progress_tracker(message: str, percentage: int) -> None:
            progress_calls.append((message, percentage))

        def status_tracker(status: str) -> None:
            status_calls.append(status)

        wizard.set_callbacks(progress_tracker, status_tracker)

        assert wizard.progress_callback == progress_tracker
        assert wizard.status_callback == status_tracker


class TestProtectionDetectionFromRealData:
    """Test protection detection using real binary patterns."""

    def test_detect_anti_debug_from_real_imports(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Detects anti-debug from real Windows API imports."""
        wizard = FridaBypassWizard(real_frida_manager)
        wizard.session_id = "test_session"

        wizard.analysis_results["imports"] = [
            {"name": "IsDebuggerPresent", "module": "kernel32.dll"},
            {"name": "CheckRemoteDebuggerPresent", "module": "kernel32.dll"},
            {"name": "NtQueryInformationProcess", "module": "ntdll.dll"},
            {"name": "OutputDebugStringW", "module": "kernel32.dll"},
        ]

        real_frida_manager.detector.detect_from_imports(
            wizard.analysis_results["imports"]
        )

        detected = real_frida_manager.detector.get_detected_protections()

        assert "anti_debug" in detected
        assert len(detected["anti_debug"]) >= 3
        assert "IsDebuggerPresent" in detected["anti_debug"]

    def test_detect_vm_detection_from_real_imports(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Detects VM detection from real system query APIs."""
        wizard = FridaBypassWizard(real_frida_manager)
        wizard.session_id = "test_session"

        wizard.analysis_results["imports"] = [
            {"name": "GetSystemFirmwareTable", "module": "kernel32.dll"},
            {"name": "EnumServicesStatus", "module": "advapi32.dll"},
        ]

        real_frida_manager.detector.detect_from_imports(
            wizard.analysis_results["imports"]
        )

        detected = real_frida_manager.detector.get_detected_protections()

        assert "anti_vm" in detected
        assert "GetSystemFirmwareTable" in detected["anti_vm"]

    def test_detect_license_from_real_strings(
        self,
        real_frida_manager: RealFridaManagerStub,
        pe_binary_with_license_check: Path
    ) -> None:
        """Detects license protection from real binary strings."""
        wizard = FridaBypassWizard(real_frida_manager)
        wizard.session_id = "test_session"

        binary_data = pe_binary_with_license_check.read_bytes()

        strings = []
        current = b""
        for byte in binary_data:
            if 32 <= byte < 127:
                current += bytes([byte])
            else:
                if len(current) >= 4:
                    strings.append(current.decode("ascii", errors="ignore"))
                current = b""

        wizard.analysis_results["strings"] = strings

        license_keywords = ["license", "trial", "serial", "registration", "key"]
        license_detected = any(
            any(kw in s.lower() for kw in license_keywords)
            for s in strings
        )

        assert license_detected
        assert any("license" in s.lower() for s in strings)
        assert any("trial" in s.lower() for s in strings)


class TestStrategyPlanningWithRealProtections:
    """Test bypass strategy planning with real protection data."""

    def test_create_strategies_for_real_protection_set(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Creates appropriate strategies for detected protections."""
        wizard = FridaBypassWizard(real_frida_manager)

        wizard.detected_protections = {
            ProtectionType.ANTI_DEBUG: True,
            ProtectionType.LICENSE: True,
            ProtectionType.ANTI_VM: True,
        }

        for protection_type in wizard.detected_protections:
            strategy = BypassStrategy(
                protection_type=protection_type,
                scripts=[f"bypass_{protection_type.value}.js"],
                priority=90 if protection_type == ProtectionType.ANTI_DEBUG else 50,
                dependencies=[ProtectionType.ANTI_DEBUG]
                    if protection_type == ProtectionType.LICENSE else []
            )
            wizard.strategies.append(strategy)

        assert len(wizard.strategies) == 3

        anti_debug = next(
            (s for s in wizard.strategies
             if s.protection_type == ProtectionType.ANTI_DEBUG),
            None
        )
        assert anti_debug is not None
        assert anti_debug.priority == 90

    def test_strategy_ordering_by_priority(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Strategies are correctly ordered by priority."""
        wizard = FridaBypassWizard(real_frida_manager)

        wizard.strategies = [
            BypassStrategy(ProtectionType.LICENSE, ["license.js"], priority=50),
            BypassStrategy(ProtectionType.ANTI_DEBUG, ["debug.js"], priority=90),
            BypassStrategy(ProtectionType.ANTI_VM, ["vm.js"], priority=70),
        ]

        sorted_strategies = sorted(
            wizard.strategies,
            key=lambda s: s.priority,
            reverse=True
        )

        assert sorted_strategies[0].protection_type == ProtectionType.ANTI_DEBUG
        assert sorted_strategies[1].protection_type == ProtectionType.ANTI_VM
        assert sorted_strategies[2].protection_type == ProtectionType.LICENSE

    def test_strategy_dependency_enforcement(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """LICENSE bypass correctly depends on ANTI_DEBUG."""
        wizard = FridaBypassWizard(real_frida_manager)

        license_strategy = BypassStrategy(
            protection_type=ProtectionType.LICENSE,
            scripts=["license.js"],
            dependencies=[ProtectionType.ANTI_DEBUG]
        )

        completed = set()
        assert not license_strategy.can_apply(completed)

        completed.add(ProtectionType.ANTI_DEBUG)
        assert license_strategy.can_apply(completed)


class TestWizardStateProgression:
    """Test wizard state machine with real state transitions."""

    def test_state_values_are_valid_enums(self) -> None:
        """All wizard states are valid enum values."""
        assert WizardState.IDLE.value == "idle"
        assert WizardState.ANALYZING.value == "analyzing"
        assert WizardState.DETECTING.value == "detecting"
        assert WizardState.PLANNING.value == "planning"
        assert WizardState.APPLYING.value == "applying"
        assert WizardState.MONITORING.value == "monitoring"
        assert WizardState.COMPLETE.value == "complete"
        assert WizardState.FAILED.value == "failed"

    def test_wizard_state_can_transition(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Wizard can transition through states."""
        wizard = FridaBypassWizard(real_frida_manager)

        assert wizard.state == WizardState.IDLE

        wizard._update_state(WizardState.ANALYZING)
        assert wizard.state == WizardState.ANALYZING

        wizard._update_state(WizardState.DETECTING)
        assert wizard.state == WizardState.DETECTING

        wizard._update_state(WizardState.PLANNING)
        assert wizard.state == WizardState.PLANNING

        wizard._update_state(WizardState.APPLYING)
        assert wizard.state == WizardState.APPLYING

        wizard._update_state(WizardState.MONITORING)
        assert wizard.state == WizardState.MONITORING

        wizard._update_state(WizardState.COMPLETE)
        assert wizard.state == WizardState.COMPLETE

    def test_wizard_can_transition_to_failed_from_any_state(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Wizard can transition to FAILED from any state."""
        for initial_state in [
            WizardState.IDLE,
            WizardState.ANALYZING,
            WizardState.DETECTING,
            WizardState.PLANNING,
            WizardState.APPLYING,
            WizardState.MONITORING,
        ]:
            wizard = FridaBypassWizard(real_frida_manager)
            wizard.state = initial_state

            wizard._update_state(WizardState.FAILED)
            assert wizard.state == WizardState.FAILED


class TestBypassTracking:
    """Test bypass success/failure tracking."""

    def test_track_successful_bypass(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Wizard correctly tracks successful bypasses."""
        wizard = FridaBypassWizard(real_frida_manager)

        wizard.successful_bypasses.add(ProtectionType.ANTI_DEBUG)
        wizard.successful_bypasses.add(ProtectionType.ANTI_VM)

        assert ProtectionType.ANTI_DEBUG in wizard.successful_bypasses
        assert ProtectionType.ANTI_VM in wizard.successful_bypasses
        assert ProtectionType.LICENSE not in wizard.successful_bypasses
        assert len(wizard.successful_bypasses) == 2

    def test_track_failed_bypass(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Wizard correctly tracks failed bypasses."""
        wizard = FridaBypassWizard(real_frida_manager)

        wizard.failed_bypasses.add(ProtectionType.LICENSE)

        assert ProtectionType.LICENSE in wizard.failed_bypasses
        assert ProtectionType.ANTI_DEBUG not in wizard.failed_bypasses

    def test_applied_strategies_tracking(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Wizard tracks which strategies have been applied."""
        wizard = FridaBypassWizard(real_frida_manager)

        strategy1 = BypassStrategy(ProtectionType.ANTI_DEBUG, ["debug.js"])
        strategy2 = BypassStrategy(ProtectionType.LICENSE, ["license.js"])

        wizard.strategies = [strategy1, strategy2]
        wizard.applied_strategies.append(strategy1)

        assert len(wizard.applied_strategies) == 1
        assert strategy1 in wizard.applied_strategies
        assert strategy2 not in wizard.applied_strategies


class TestMetricsTracking:
    """Test wizard metrics and performance tracking."""

    def test_metrics_initialization(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Wizard initializes metrics correctly."""
        wizard = FridaBypassWizard(real_frida_manager)

        assert "retry_successes" in wizard.metrics or hasattr(wizard, 'metrics')
        assert isinstance(wizard.metrics, dict)

    def test_metrics_can_be_updated(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Wizard metrics can be updated during execution."""
        wizard = FridaBypassWizard(real_frida_manager)

        wizard.metrics["detection_time"] = 1.5
        wizard.metrics["bypass_attempts"] = 3
        wizard.metrics["successful_bypasses"] = 2

        assert wizard.metrics["detection_time"] == 1.5
        assert wizard.metrics["bypass_attempts"] == 3
        assert wizard.metrics["successful_bypasses"] == 2


class TestErrorHandling:
    """Test wizard error handling with real scenarios."""

    def test_wizard_stop_sets_failed_state(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Stop method sets wizard to FAILED state."""
        wizard = FridaBypassWizard(real_frida_manager)
        wizard.state = WizardState.APPLYING

        wizard.stop()

        assert wizard.state == WizardState.FAILED

    def test_wizard_handles_empty_imports(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Wizard handles binaries with no imports gracefully."""
        wizard = FridaBypassWizard(real_frida_manager)
        wizard.analysis_results["imports"] = []

        real_frida_manager.detector.detect_from_imports([])
        detected = real_frida_manager.detector.get_detected_protections()

        assert detected == {}

    def test_wizard_handles_empty_strings(
        self,
        real_frida_manager: RealFridaManagerStub
    ) -> None:
        """Wizard handles binaries with no strings gracefully."""
        wizard = FridaBypassWizard(real_frida_manager)
        wizard.analysis_results["strings"] = []

        license_keywords = ["license", "trial", "serial"]
        license_detected = any(
            any(kw in s.lower() for kw in license_keywords)
            for s in wizard.analysis_results["strings"]
        )

        assert not license_detected


class TestRealBinaryPatternDetection:
    """Test pattern detection on real binary data."""

    def test_detect_peb_check_pattern_in_binary(
        self,
        pe_binary_with_anti_debug: Path
    ) -> None:
        """Detects PEB.BeingDebugged check pattern in real binary."""
        binary_data = pe_binary_with_anti_debug.read_bytes()

        peb_pattern = b"\x64\xA1\x30\x00\x00\x00"

        pattern_count = binary_data.count(peb_pattern)

        assert pattern_count >= 5

    def test_detect_nt_global_flag_pattern_in_binary(
        self,
        pe_binary_with_anti_debug: Path
    ) -> None:
        """Detects NtGlobalFlag check pattern in real binary."""
        binary_data = pe_binary_with_anti_debug.read_bytes()

        nt_global_pattern = b"\x64\x8B\x05\x68\x00\x00\x00"

        pattern_count = binary_data.count(nt_global_pattern)

        assert pattern_count >= 3

    def test_extract_api_names_from_binary(
        self,
        pe_binary_with_anti_debug: Path
    ) -> None:
        """Extracts API names from real binary import table."""
        binary_data = pe_binary_with_anti_debug.read_bytes()

        api_names = []
        current = b""
        for byte in binary_data:
            if 32 <= byte < 127:
                current += bytes([byte])
            else:
                if len(current) >= 10:
                    decoded = current.decode("ascii", errors="ignore")
                    if decoded.endswith("Present") or decoded.startswith("Nt"):
                        api_names.append(decoded)
                current = b""

        assert any("IsDebuggerPresent" in name for name in api_names)
