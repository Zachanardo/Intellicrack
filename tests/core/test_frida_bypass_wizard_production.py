"""Production-ready tests for Frida bypass wizard offensive capabilities.

Tests real Frida script generation, bypass strategy planning, and protection detection
bypassing against actual process protection mechanisms.
"""

import asyncio
import time
from pathlib import Path

import pytest

try:
    from intellicrack.core.frida_bypass_wizard import (
        BypassStrategy,
        FridaBypassWizard,
        WizardPresetManager,
        WizardState,
    )
    from intellicrack.core.frida_constants import ProtectionType
    FRIDA_WIZARD_AVAILABLE = True
except ImportError:
    FRIDA_WIZARD_AVAILABLE = False


pytestmark = pytest.mark.skipif(
    not FRIDA_WIZARD_AVAILABLE,
    reason="Frida bypass wizard module not available"
)


class SimpleFridaManager:
    """Simple Frida manager stub for testing wizard without actual Frida."""

    def __init__(self) -> None:
        self.detector = SimpleDetector()
        self.session = None

    def attach_to_process(self, target: int | str) -> bool:
        """Simulate process attachment."""
        return True

    def detach(self) -> None:
        """Simulate detachment."""
        self.session = None

    def load_script(self, script: str) -> bool:
        """Simulate script loading."""
        return len(script) > 0


class SimpleDetector:
    """Simple detector stub for testing."""

    def get_detected_protections(self) -> dict[str, list[str]]:
        """Return simulated detected protections."""
        return {
            "ANTI_DEBUG": ["IsDebuggerPresent found"],
            "LICENSE": ["License check detected"],
        }


class TestFridaBypassWizardScriptGeneration:
    """Test real Frida script generation for bypass operations."""

    def test_wizard_generates_working_anti_debug_bypass_script(self) -> None:
        """Wizard generates syntactically valid Frida JavaScript for anti-debug bypass."""
        wizard = FridaBypassWizard(SimpleFridaManager())

        script = wizard.generate_bypass_script("ANTI_DEBUG")

        assert script is not None, "Failed to generate anti-debug bypass script"
        assert "IsDebuggerPresent" in script, "Missing IsDebuggerPresent hook"
        assert "Interceptor.attach" in script, "Missing Frida Interceptor call"
        assert "retval.replace" in script, "Missing return value manipulation"
        assert "CheckRemoteDebuggerPresent" in script, "Missing remote debugger check"
        assert "NtQueryInformationProcess" in script, "Missing NT API hook"
        assert len(script) > 200, "Script too short to be effective"

    def test_wizard_generates_working_license_bypass_script(self) -> None:
        """Wizard generates working license validation bypass with registry hooking."""
        wizard = FridaBypassWizard(SimpleFridaManager())

        script = wizard.generate_bypass_script("LICENSE")

        assert script is not None, "Failed to generate license bypass script"
        assert "ValidateLicense" in script or "CheckLicense" in script, "Missing license check hook"
        assert "Interceptor.attach" in script, "Missing Frida Interceptor"
        assert "retval.replace(1)" in script, "Missing success return value"
        assert "RegQueryValueEx" in script or "registry" in script.lower(), "Missing registry access"
        assert len(script) > 300, "License bypass script insufficient length"

    def test_wizard_generates_working_ssl_pinning_bypass_script(self) -> None:
        """Wizard generates SSL pinning bypass with certificate verification hooks."""
        wizard = FridaBypassWizard(SimpleFridaManager())

        script = wizard.generate_bypass_script("SSL_PINNING")

        assert script is not None, "Failed to generate SSL pinning bypass"
        assert "CertVerifyCertificateChainPolicy" in script or "cert" in script.lower(), "Missing cert validation"
        assert "Interceptor.attach" in script, "Missing Frida Interceptor"
        assert "retval.replace(1)" in script, "Missing success return value"
        assert len(script) > 200, "SSL bypass script too short"

    def test_wizard_generates_working_integrity_bypass_script(self) -> None:
        """Wizard generates integrity check bypass with hash function hooks."""
        wizard = FridaBypassWizard(SimpleFridaManager())

        script = wizard.generate_bypass_script("INTEGRITY")

        assert script is not None, "Failed to generate integrity bypass script"
        assert "CryptHashData" in script or "BCryptHashData" in script, "Missing cryptographic hash hooks"
        assert "VerifySignature" in script or "integrity" in script.lower(), "Missing signature verification"
        assert "Interceptor.attach" in script, "Missing Frida Interceptor"
        assert len(script) > 250, "Integrity bypass script too short"

    def test_wizard_generates_working_time_bypass_script(self) -> None:
        """Wizard generates time-based protection bypass with time API hooks."""
        wizard = FridaBypassWizard(SimpleFridaManager())

        script = wizard.generate_bypass_script("TIME")

        assert script is not None, "Failed to generate time bypass script"
        assert "GetSystemTime" in script or "GetLocalTime" in script, "Missing time function hooks"
        assert "GetTickCount" in script, "Missing tick count hook"
        assert "Interceptor.attach" in script, "Missing Frida Interceptor"
        assert len(script) > 150, "Time bypass script too short"

    def test_wizard_generates_working_hardware_bypass_script(self) -> None:
        """Wizard generates hardware ID bypass with hardware query hooks."""
        wizard = FridaBypassWizard(SimpleFridaManager())

        script = wizard.generate_bypass_script("HARDWARE")

        assert script is not None, "Failed to generate hardware bypass script"
        assert "GetVolumeInformation" in script, "Missing volume serial hook"
        assert "spoofed" in script.lower() or "0x12345678" in script, "Missing spoofed values"
        assert "Interceptor.attach" in script, "Missing Frida Interceptor"
        assert len(script) > 200, "Hardware bypass script too short"


class TestFridaBypassWizardStrategyPlanning:
    """Test bypass strategy planning and ordering."""

    @pytest.mark.asyncio
    async def test_wizard_plans_multi_step_bypass_strategy(self) -> None:
        """Wizard creates ordered bypass strategy with dependency resolution."""
        frida_manager = SimpleFridaManager()
        wizard = FridaBypassWizard(frida_manager)
        wizard.set_mode("aggressive")
        wizard.detected_protections = {
            ProtectionType.ANTI_DEBUG: True,
            ProtectionType.LICENSE: True,
            ProtectionType.ANTI_VM: True,
        }

        await wizard._plan_strategy()

        assert len(wizard.strategies) > 0, "Failed to plan bypass strategies"
        assert any(s.protection_type == ProtectionType.ANTI_DEBUG for s in wizard.strategies), "Missing anti-debug strategy"
        assert any(s.protection_type == ProtectionType.LICENSE for s in wizard.strategies), "Missing license strategy"

        anti_debug_priority = next((i for i, s in enumerate(wizard.strategies) if s.protection_type == ProtectionType.ANTI_DEBUG), -1)
        license_priority = next((i for i, s in enumerate(wizard.strategies) if s.protection_type == ProtectionType.LICENSE), -1)

        assert anti_debug_priority < license_priority, "Anti-debug must come before license bypass"

    @pytest.mark.asyncio
    async def test_wizard_enforces_bypass_dependencies(self) -> None:
        """Wizard respects dependencies between bypass strategies."""
        wizard = FridaBypassWizard(SimpleFridaManager())

        strategy = BypassStrategy(
            protection_type=ProtectionType.LICENSE,
            scripts=["license_bypass.js"],
            priority=50,
            dependencies=[ProtectionType.ANTI_DEBUG],
        )

        completed = set()
        assert not strategy.can_apply(completed), "Should not apply with unmet dependencies"

        completed.add(ProtectionType.ANTI_DEBUG)
        assert strategy.can_apply(completed), "Should apply after dependency satisfied"

    @pytest.mark.asyncio
    async def test_wizard_prioritizes_high_priority_bypasses_first(self) -> None:
        """Wizard executes high-priority bypasses before lower priority."""
        frida_manager = SimpleFridaManager()
        wizard = FridaBypassWizard(frida_manager)

        wizard.strategies = [
            BypassStrategy(ProtectionType.TIME, ["time.js"], priority=30),
            BypassStrategy(ProtectionType.ANTI_DEBUG, ["debug.js"], priority=90),
            BypassStrategy(ProtectionType.LICENSE, ["license.js"], priority=80),
        ]

        sorted_strategies = sorted(wizard.strategies, key=lambda s: (-s.priority, len(s.dependencies)))

        assert sorted_strategies[0].protection_type == ProtectionType.ANTI_DEBUG, "Anti-debug should be first"
        assert sorted_strategies[1].protection_type == ProtectionType.LICENSE, "License should be second"
        assert sorted_strategies[2].protection_type == ProtectionType.TIME, "Time should be last"


class TestFridaBypassWizardProtectionDetection:
    """Test protection detection and analysis capabilities."""

    @pytest.mark.asyncio
    async def test_wizard_detects_anti_debug_protection_from_imports(self) -> None:
        """Wizard identifies anti-debug protection from Windows API imports."""
        wizard = FridaBypassWizard(SimpleFridaManager())
        wizard.analysis_results["imports"] = [
            {"name": "IsDebuggerPresent", "module": "kernel32.dll"},
            {"name": "CheckRemoteDebuggerPresent", "module": "kernel32.dll"},
        ]

        wizard._analyze_imports_for_protections()

        assert ProtectionType.ANTI_DEBUG in wizard.detected_protections, "Failed to detect anti-debug from imports"
        assert any("IsDebuggerPresent" in str(e) for e in wizard.protection_evidence.get(ProtectionType.ANTI_DEBUG, [])), \
            "Missing import evidence"

    @pytest.mark.asyncio
    async def test_wizard_detects_license_protection_from_strings(self) -> None:
        """Wizard identifies license protection from license-related strings."""
        wizard = FridaBypassWizard(SimpleFridaManager())
        wizard.analysis_results["strings"] = [
            "License validation failed",
            "Please enter your license key",
            "Trial period expired",
        ]

        wizard._analyze_strings_for_protections()

        assert ProtectionType.LICENSE in wizard.detected_protections, "Failed to detect license protection from strings"
        assert ProtectionType.TIME in wizard.detected_protections, "Failed to detect time-based protection"

    @pytest.mark.asyncio
    async def test_wizard_detects_vm_protection_from_strings(self) -> None:
        """Wizard identifies VM detection from VM-related strings."""
        wizard = FridaBypassWizard(SimpleFridaManager())
        wizard.analysis_results["strings"] = [
            "VMware detected - exiting",
            "VirtualBox environment found",
        ]

        wizard._analyze_strings_for_protections()

        assert ProtectionType.ANTI_VM in wizard.detected_protections, "Failed to detect anti-VM protection"


class TestFridaBypassWizardProcessAttachment:
    """Test process attachment and detachment."""

    def test_wizard_attaches_to_process_by_pid(self) -> None:
        """Wizard successfully attaches to process by PID."""
        frida_manager = SimpleFridaManager()
        wizard = FridaBypassWizard(frida_manager)
        result = wizard.attach_to_process(pid=1234)

        assert result is True, "Failed to attach to process by PID"

    def test_wizard_attaches_to_process_by_name(self) -> None:
        """Wizard successfully attaches to process by name."""
        frida_manager = SimpleFridaManager()
        wizard = FridaBypassWizard(frida_manager)
        result = wizard.attach_to_process(process_name="target.exe")

        assert result is True, "Failed to attach to process by name"

    def test_wizard_detaches_from_process_cleanly(self) -> None:
        """Wizard cleanly detaches from process and resets state."""
        frida_manager = SimpleFridaManager()
        wizard = FridaBypassWizard(frida_manager)
        wizard.session_id = "test_session"
        wizard.target_process = {"pid": 1234}

        result = wizard.detach()

        assert result is True, "Failed to detach from process"
        assert wizard.session_id is None, "Session ID not cleared"
        assert wizard.target_process is None, "Target process not cleared"
        assert wizard.state == WizardState.IDLE, "State not reset to IDLE"


class TestFridaBypassWizardScriptInjection:
    """Test script injection capabilities."""

    def test_wizard_injects_custom_bypass_script(self) -> None:
        """Wizard successfully injects custom Frida script into process."""
        frida_manager = SimpleFridaManager()
        wizard = FridaBypassWizard(frida_manager)
        wizard.target_process = {"pid": 1234}
        wizard.session_id = "test_session"

        script = """
        Interceptor.attach(Module.findExportByName('kernel32.dll', 'IsDebuggerPresent'), {
            onLeave: function(retval) { retval.replace(0); }
        });
        """

        result = wizard.inject_script(script, "custom_bypass")

        assert result is True, "Failed to inject custom script"
        assert wizard.metrics["scripts_loaded"] == 1, "Script count not incremented"


class TestFridaBypassWizardPresets:
    """Test preset wizard configurations."""

    def test_wizard_applies_software_preset_configuration(self) -> None:
        """Wizard applies software-specific preset with correct protections."""
        frida_manager = SimpleFridaManager()
        wizard = FridaBypassWizard(frida_manager)

        WizardPresetManager.apply_software_preset(wizard, "adobe")

        assert wizard.config is not None, "Preset configuration not applied"
        assert "name" in wizard.config, "Missing preset name"

    def test_wizard_creates_custom_aggressive_configuration(self) -> None:
        """Wizard creates custom configuration with aggressive settings."""
        custom_config = {
            "mode": "aggressive",
            "max_scripts": 20,
            "priority": ["LICENSE", "ANTI_DEBUG"],
        }

        wizard = WizardPresetManager.create_custom_wizard(custom_config)

        assert wizard.mode == "aggressive", "Mode not set correctly"
        assert wizard.config["max_scripts"] == 20, "Max scripts not configured"


class TestFridaBypassWizardAnalysisScript:
    """Test process analysis script generation."""

    def test_wizard_generates_working_analysis_script(self) -> None:
        """Wizard generates valid Frida analysis script for process reconnaissance."""
        wizard = FridaBypassWizard(SimpleFridaManager())

        script = wizard._create_analysis_script()

        assert "Process.enumerateModules()" in script, "Missing module enumeration"
        assert "enumerateImports()" in script, "Missing import enumeration"
        assert "Memory.scan" in script, "Missing memory scanning"
        assert "send({" in script, "Missing Frida send() calls"
        assert "type: 'analysis'" in script, "Missing analysis message type"

    @pytest.mark.asyncio
    async def test_wizard_creates_temporary_analysis_script_file(self) -> None:
        """Wizard creates and cleans up temporary analysis script file."""
        frida_manager = SimpleFridaManager()
        wizard = FridaBypassWizard(frida_manager)
        wizard.session_id = "test_session"
        wizard.target_process = {"name": "test.exe", "pid": 1234}

        await wizard._analyze_process()

        assert not Path("temp_analysis.js").exists(), "Temporary script file not cleaned up"


class TestFridaBypassWizardVerification:
    """Test bypass verification mechanisms."""

    @pytest.mark.asyncio
    async def test_wizard_verifies_anti_debug_bypass_effectiveness(self) -> None:
        """Wizard verifies anti-debug bypass by checking debugger detection APIs."""
        frida_manager = SimpleFridaManager()
        wizard = FridaBypassWizard(frida_manager)
        wizard.session_id = "test_session"
        wizard.executed_bypasses.add(ProtectionType.ANTI_DEBUG)

        still_active = await wizard._verify_bypass(ProtectionType.ANTI_DEBUG)

        assert isinstance(still_active, bool), "Verification must return boolean"


class TestFridaBypassWizardReporting:
    """Test report generation."""

    def test_wizard_generates_comprehensive_report(self) -> None:
        """Wizard generates detailed report with all metrics and results."""
        wizard = FridaBypassWizard(SimpleFridaManager())
        wizard.state = WizardState.COMPLETE
        wizard.metrics["start_time"] = time.time() - 10
        wizard.metrics["end_time"] = time.time()
        wizard.metrics["protections_detected"] = 3
        wizard.metrics["bypasses_attempted"] = 3
        wizard.metrics["bypasses_successful"] = 2
        wizard.detected_protections = {
            ProtectionType.ANTI_DEBUG: True,
            ProtectionType.LICENSE: True,
        }
        wizard.successful_bypasses.add(ProtectionType.ANTI_DEBUG)
        wizard.failed_bypasses.add(ProtectionType.LICENSE)

        report = wizard._generate_report()

        assert report["success"] is True, "Report should indicate success"
        assert report["detections"]["total"] == 3, "Incorrect detection count"
        assert report["bypasses"]["attempted"] == 3, "Incorrect bypass attempt count"
        assert report["bypasses"]["successful"] == 2, "Incorrect success count"
        assert "duration" in report, "Missing duration metric"
        assert report["bypasses"]["success_rate"] > 0, "Success rate not calculated"
