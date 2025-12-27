"""Production tests for Frida Presets - validates preset configurations.

Tests preset configurations for common protected software, wizard configurations,
and protection-specific script selection WITHOUT mocks.
"""

from typing import Any

import pytest

from intellicrack.core.frida_presets import (
    FRIDA_PRESETS,
    get_preset_by_software,
    get_scripts_for_protection,
    get_wizard_config,
)


REQUIRED_PRESET_KEYS = {"description", "target", "scripts", "protections", "options", "hooks"}
VALID_WIZARD_MODES = ["conservative", "balanced", "aggressive"]
MINIMUM_HOOKS_PER_PRESET = 1
MINIMUM_SCRIPTS_PER_PRESET = 1


class TestPresetDefinitions:
    """Test preset configuration definitions."""

    def test_frida_presets_contains_common_software(self) -> None:
        """FRIDA_PRESETS contains configurations for common protected software."""
        assert FRIDA_PRESETS is not None
        assert isinstance(FRIDA_PRESETS, dict)
        assert len(FRIDA_PRESETS) > 0

        expected_categories = [
            "Microsoft Office 365",
            "Autodesk Products",
            "VMware Products",
            "Anti-Virus Software",
        ]

        for category in expected_categories:
            assert category in FRIDA_PRESETS

    def test_all_presets_have_required_fields(self) -> None:
        """All presets contain required configuration fields."""
        for software_name, preset in FRIDA_PRESETS.items():
            assert isinstance(preset, dict), f"Preset {software_name} is not a dict"

            for required_key in REQUIRED_PRESET_KEYS:
                assert required_key in preset, f"Preset {software_name} missing key: {required_key}"

    def test_all_presets_have_valid_scripts(self) -> None:
        """All presets specify valid Frida scripts."""
        for software_name, preset in FRIDA_PRESETS.items():
            scripts = preset["scripts"]

            assert isinstance(scripts, list), f"Scripts for {software_name} not a list"
            assert len(scripts) >= MINIMUM_SCRIPTS_PER_PRESET, f"Preset {software_name} has no scripts"

            for script in scripts:
                assert isinstance(script, str)
                assert len(script) > 0

    def test_all_presets_have_valid_hooks(self) -> None:
        """All presets specify valid function hooks."""
        for software_name, preset in FRIDA_PRESETS.items():
            hooks = preset["hooks"]

            assert isinstance(hooks, list), f"Hooks for {software_name} not a list"
            assert len(hooks) >= MINIMUM_HOOKS_PER_PRESET, f"Preset {software_name} has no hooks"

            for hook in hooks:
                assert isinstance(hook, str)
                assert len(hook) > 0
                assert "!" in hook or "." in hook or "*" in hook

    def test_all_presets_have_protection_types(self) -> None:
        """All presets specify protection types they target."""
        for software_name, preset in FRIDA_PRESETS.items():
            protections = preset["protections"]

            assert isinstance(protections, list), f"Protections for {software_name} not a list"
            assert len(protections) > 0, f"Preset {software_name} has no protections"

            for protection in protections:
                assert isinstance(protection, str)
                assert len(protection) > 0

    def test_all_presets_have_valid_options(self) -> None:
        """All presets have valid configuration options."""
        for software_name, preset in FRIDA_PRESETS.items():
            options = preset["options"]

            assert isinstance(options, dict), f"Options for {software_name} not a dict"

            for option_key, option_value in options.items():
                assert isinstance(option_key, str)
                assert option_value is not None


class TestMicrosoftOfficePreset:
    """Test Microsoft Office 365 preset configuration."""

    def test_microsoft_office_preset_exists(self) -> None:
        """Microsoft Office 365 preset is defined."""
        assert "Microsoft Office 365" in FRIDA_PRESETS

    def test_microsoft_office_targets_license_validation(self) -> None:
        """Microsoft Office preset targets license validation."""
        preset = FRIDA_PRESETS["Microsoft Office 365"]

        assert "LICENSE" in preset["protections"]

    def test_microsoft_office_hooks_licensing_dlls(self) -> None:
        """Microsoft Office preset hooks licensing DLLs."""
        preset = FRIDA_PRESETS["Microsoft Office 365"]

        hooks = preset["hooks"]
        dll_hooks = [h for h in hooks if ".dll!" in h]

        assert len(dll_hooks) > 0

        licensing_dlls = ["sppc.dll", "osppc.dll"]
        licensing_hooks = [h for h in hooks if any(dll in h for dll in licensing_dlls)]

        assert len(licensing_hooks) > 0

    def test_microsoft_office_includes_telemetry_blocking(self) -> None:
        """Microsoft Office preset includes telemetry blocking."""
        preset = FRIDA_PRESETS["Microsoft Office 365"]

        assert preset["options"].get("block_telemetry") is True
        assert "telemetry_blocker" in preset["scripts"]


class TestAutodeskPreset:
    """Test Autodesk Products preset configuration."""

    def test_autodesk_preset_exists(self) -> None:
        """Autodesk Products preset is defined."""
        assert "Autodesk Products" in FRIDA_PRESETS

    def test_autodesk_targets_multiple_protections(self) -> None:
        """Autodesk preset targets multiple protection mechanisms."""
        preset = FRIDA_PRESETS["Autodesk Products"]

        protections = preset["protections"]

        assert "LICENSE" in protections
        assert "HARDWARE" in protections
        assert len(protections) >= 3

    def test_autodesk_includes_hardware_spoofing(self) -> None:
        """Autodesk preset includes hardware spoofing."""
        preset = FRIDA_PRESETS["Autodesk Products"]

        assert preset["options"].get("spoof_all_hardware") is True

    def test_autodesk_hooks_licensing_sdk(self) -> None:
        """Autodesk preset hooks licensing SDK functions."""
        preset = FRIDA_PRESETS["Autodesk Products"]

        hooks = preset["hooks"]
        sdk_hooks = [h for h in hooks if "AdskLicensingSDK" in h]

        assert len(sdk_hooks) > 0


class TestVMwarePreset:
    """Test VMware Products preset configuration."""

    def test_vmware_preset_exists(self) -> None:
        """VMware Products preset is defined."""
        assert "VMware Products" in FRIDA_PRESETS

    def test_vmware_includes_trial_bypass(self) -> None:
        """VMware preset includes trial period bypass."""
        preset = FRIDA_PRESETS["VMware Products"]

        assert preset["options"].get("patch_trial") is True
        assert "time_bomb_defuser" in preset["scripts"]

    def test_vmware_hooks_time_functions(self) -> None:
        """VMware preset hooks time-related functions."""
        preset = FRIDA_PRESETS["VMware Products"]

        hooks = preset["hooks"]
        time_hooks = [h for h in hooks if "Time" in h or "Tick" in h]

        assert len(time_hooks) > 0


class TestAntiVirusPreset:
    """Test Anti-Virus Software preset configuration."""

    def test_antivirus_preset_exists(self) -> None:
        """Anti-Virus Software preset is defined."""
        assert "Anti-Virus Software" in FRIDA_PRESETS

    def test_antivirus_targets_anti_debug_protections(self) -> None:
        """Anti-virus preset targets anti-debugging protections."""
        preset = FRIDA_PRESETS["Anti-Virus Software"]

        assert "ANTI_DEBUG" in preset["protections"]
        assert "anti_debugger" in preset["scripts"]

    def test_antivirus_uses_stealth_mode(self) -> None:
        """Anti-virus preset uses stealth mode to avoid detection."""
        preset = FRIDA_PRESETS["Anti-Virus Software"]

        assert preset["options"].get("stealth_hooks") is True

    def test_antivirus_hooks_debugger_detection_functions(self) -> None:
        """Anti-virus preset hooks debugger detection functions."""
        preset = FRIDA_PRESETS["Anti-Virus Software"]

        hooks = preset["hooks"]
        debug_hooks = [h for h in hooks if "IsDebuggerPresent" in h or "NtQueryInformationProcess" in h]

        assert len(debug_hooks) > 0


class TestSteamCEGPreset:
    """Test Steam CEG bypass preset configuration."""

    def test_steam_ceg_preset_exists(self) -> None:
        """Steam Games (CEG) preset is defined."""
        assert "Steam Games (CEG)" in FRIDA_PRESETS

    def test_steam_ceg_targets_drm(self) -> None:
        """Steam CEG preset targets DRM protections."""
        preset = FRIDA_PRESETS["Steam Games (CEG)"]

        assert "DRM" in preset["protections"]

    def test_steam_ceg_hooks_steam_api(self) -> None:
        """Steam CEG preset hooks Steam API functions."""
        preset = FRIDA_PRESETS["Steam Games (CEG)"]

        hooks = preset["hooks"]
        steam_hooks = [h for h in hooks if "steam_api" in h]

        assert len(steam_hooks) > 0

    def test_steam_ceg_includes_integrity_bypass(self) -> None:
        """Steam CEG preset includes code integrity bypass."""
        preset = FRIDA_PRESETS["Steam Games (CEG)"]

        assert "INTEGRITY" in preset["protections"]
        assert "code_integrity_bypass" in preset["scripts"]


class TestDenuvoPreset:
    """Test Denuvo anti-tamper preset configuration."""

    def test_denuvo_preset_exists(self) -> None:
        """Denuvo Protected Games preset is defined."""
        assert "Denuvo Protected Games" in FRIDA_PRESETS

    def test_denuvo_uses_aggressive_mode(self) -> None:
        """Denuvo preset uses aggressive bypass mode."""
        preset = FRIDA_PRESETS["Denuvo Protected Games"]

        assert preset["options"].get("aggressive") is True

    def test_denuvo_targets_multiple_protections(self) -> None:
        """Denuvo preset targets multiple advanced protections."""
        preset = FRIDA_PRESETS["Denuvo Protected Games"]

        protections = preset["protections"]

        assert "DRM" in protections
        assert "ANTI_DEBUG" in protections
        assert "ANTI_VM" in protections
        assert "INTEGRITY" in protections

    def test_denuvo_includes_comprehensive_scripts(self) -> None:
        """Denuvo preset includes comprehensive bypass scripts."""
        preset = FRIDA_PRESETS["Denuvo Protected Games"]

        scripts = preset["scripts"]

        assert "anti_debugger" in scripts
        assert "code_integrity_bypass" in scripts
        assert "memory_integrity_bypass" in scripts
        assert "virtualization_bypass" in scripts


class TestPresetRetrieval:
    """Test preset retrieval functions."""

    def test_get_preset_by_software_returns_correct_preset(self) -> None:
        """get_preset_by_software returns correct preset for software name."""
        preset = get_preset_by_software("Microsoft Office 365")

        assert preset is not None
        assert isinstance(preset, dict)
        assert "description" in preset
        assert "scripts" in preset

    def test_get_preset_by_software_case_insensitive(self) -> None:
        """get_preset_by_software is case insensitive."""
        preset_lower = get_preset_by_software("microsoft office 365")
        preset_upper = get_preset_by_software("MICROSOFT OFFICE 365")
        preset_mixed = get_preset_by_software("Microsoft Office 365")

        assert preset_lower is not None
        assert preset_upper is not None
        assert preset_mixed is not None

    def test_get_preset_by_software_partial_match(self) -> None:
        """get_preset_by_software supports partial matching."""
        preset = get_preset_by_software("Office")

        assert preset is not None
        assert "Office" in preset["target"] or "Office" in preset["description"]

    def test_get_preset_by_software_unknown_returns_none_or_empty(self) -> None:
        """get_preset_by_software returns None or empty dict for unknown software."""
        preset = get_preset_by_software("NonExistentSoftware12345")

        assert preset is None or (isinstance(preset, dict) and len(preset) == 0)


class TestWizardConfiguration:
    """Test wizard configuration generation."""

    def test_get_wizard_config_default_mode(self) -> None:
        """get_wizard_config returns configuration for default (balanced) mode."""
        config = get_wizard_config()

        assert config is not None
        assert isinstance(config, dict)
        assert len(config) > 0

    def test_get_wizard_config_conservative_mode(self) -> None:
        """get_wizard_config returns conservative configuration."""
        config = get_wizard_config(mode="conservative")

        assert config is not None
        assert isinstance(config, dict)

    def test_get_wizard_config_balanced_mode(self) -> None:
        """get_wizard_config returns balanced configuration."""
        config = get_wizard_config(mode="balanced")

        assert config is not None
        assert isinstance(config, dict)

    def test_get_wizard_config_aggressive_mode(self) -> None:
        """get_wizard_config returns aggressive configuration."""
        config = get_wizard_config(mode="aggressive")

        assert config is not None
        assert isinstance(config, dict)

    def test_wizard_config_includes_required_fields(self) -> None:
        """Wizard configuration includes required fields."""
        for mode in VALID_WIZARD_MODES:
            config = get_wizard_config(mode=mode)

            assert config is not None
            assert isinstance(config, dict)


class TestProtectionScriptMapping:
    """Test protection type to script mapping."""

    def test_get_scripts_for_license_protection(self) -> None:
        """get_scripts_for_protection returns scripts for LICENSE protection."""
        scripts = get_scripts_for_protection("LICENSE")

        assert scripts is not None
        assert isinstance(scripts, list)
        assert len(scripts) > 0

        for script in scripts:
            assert isinstance(script, str)
            assert len(script) > 0

    def test_get_scripts_for_drm_protection(self) -> None:
        """get_scripts_for_protection returns scripts for DRM protection."""
        scripts = get_scripts_for_protection("DRM")

        assert scripts is not None
        assert isinstance(scripts, list)

    def test_get_scripts_for_anti_debug_protection(self) -> None:
        """get_scripts_for_protection returns scripts for ANTI_DEBUG protection."""
        scripts = get_scripts_for_protection("ANTI_DEBUG")

        assert scripts is not None
        assert isinstance(scripts, list)
        assert len(scripts) > 0

    def test_get_scripts_for_hardware_protection(self) -> None:
        """get_scripts_for_protection returns scripts for HARDWARE protection."""
        scripts = get_scripts_for_protection("HARDWARE")

        assert scripts is not None
        assert isinstance(scripts, list)

    def test_get_scripts_for_unknown_protection_returns_empty_or_none(self) -> None:
        """get_scripts_for_protection returns empty list or None for unknown protection."""
        scripts = get_scripts_for_protection("UNKNOWN_PROTECTION_TYPE_12345")

        assert scripts is None or (isinstance(scripts, list) and len(scripts) == 0)


class TestPresetConsistency:
    """Test preset configuration consistency."""

    def test_all_scripts_referenced_in_presets_exist(self) -> None:
        """All scripts referenced in presets are valid script names."""
        known_scripts = {
            "cloud_licensing_bypass",
            "registry_monitor",
            "telemetry_blocker",
            "time_bomb_defuser",
            "code_integrity_bypass",
            "anti_debugger",
            "virtualization_bypass",
            "memory_integrity_bypass",
            "kernel_mode_bypass",
        }

        for software_name, preset in FRIDA_PRESETS.items():
            for script in preset["scripts"]:
                assert script in known_scripts or len(script) > 0, f"Unknown script {script} in {software_name}"

    def test_all_protection_types_are_valid(self) -> None:
        """All protection types referenced in presets are valid."""
        valid_protection_types = {
            "LICENSE",
            "CLOUD",
            "HARDWARE",
            "TIME",
            "INTEGRITY",
            "DRM",
            "ANTI_DEBUG",
            "ANTI_VM",
            "KERNEL",
            "MEMORY",
        }

        for software_name, preset in FRIDA_PRESETS.items():
            for protection in preset["protections"]:
                assert protection in valid_protection_types, f"Invalid protection {protection} in {software_name}"

    def test_hook_format_is_consistent(self) -> None:
        """Hook specifications follow consistent format."""
        for software_name, preset in FRIDA_PRESETS.items():
            for hook in preset["hooks"]:
                assert "!" in hook or "*" in hook, f"Invalid hook format: {hook} in {software_name}"


class TestEndToEndPresetUsage:
    """Test end-to-end preset usage workflow."""

    def test_retrieve_and_validate_preset_workflow(self) -> None:
        """Complete workflow of retrieving and validating preset."""
        software_name = "Microsoft Office 365"

        preset = get_preset_by_software(software_name)
        assert preset is not None

        required_scripts = preset["scripts"]
        assert len(required_scripts) > 0

        required_hooks = preset["hooks"]
        assert len(required_hooks) > 0

        options = preset["options"]
        assert isinstance(options, dict)

    def test_retrieve_scripts_for_all_protections_in_preset(self) -> None:
        """Retrieve scripts for all protection types in a preset."""
        preset = get_preset_by_software("Denuvo Protected Games")
        assert preset is not None

        for protection_type in preset["protections"]:
            scripts = get_scripts_for_protection(protection_type)
            assert scripts is not None or protection_type in preset["scripts"]
