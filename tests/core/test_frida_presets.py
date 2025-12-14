"""Production tests for Frida Presets module.

Tests preset configurations, script recommendations, and wizard modes.
Validates that presets contain real bypass configurations for software licensing protections.
"""

import pytest

from intellicrack.core.frida_presets import (
    FRIDA_PRESETS,
    QUICK_TEMPLATES,
    WIZARD_CONFIGS,
    FridaPresets,
    get_preset_by_software,
    get_scripts_for_protection,
    get_wizard_config,
)


class TestFridaPresetsConstants:
    """Test FRIDA_PRESETS constant structure and content."""

    def test_frida_presets_contains_microsoft_office(self) -> None:
        """FRIDA_PRESETS includes Microsoft Office 365 preset."""
        assert "Microsoft Office 365" in FRIDA_PRESETS

    def test_frida_presets_contains_autodesk(self) -> None:
        """FRIDA_PRESETS includes Autodesk Products preset."""
        assert "Autodesk Products" in FRIDA_PRESETS

    def test_frida_presets_contains_vmware(self) -> None:
        """FRIDA_PRESETS includes VMware Products preset."""
        assert "VMware Products" in FRIDA_PRESETS

    def test_frida_presets_contains_denuvo(self) -> None:
        """FRIDA_PRESETS includes Denuvo Protected Games preset."""
        assert "Denuvo Protected Games" in FRIDA_PRESETS

    def test_frida_presets_contains_trial_software(self) -> None:
        """FRIDA_PRESETS includes Trial Software (Generic) preset."""
        assert "Trial Software (Generic)" in FRIDA_PRESETS

    def test_all_presets_have_required_keys(self) -> None:
        """All presets contain required configuration keys."""
        required_keys = {"description", "target", "scripts", "protections", "options", "hooks"}

        for preset_name, preset_config in FRIDA_PRESETS.items():
            assert all(
                key in preset_config for key in required_keys
            ), f"Preset '{preset_name}' missing required keys"

    def test_all_presets_have_non_empty_scripts(self) -> None:
        """All presets define at least one script except minimal bypass."""
        for preset_name, preset_config in FRIDA_PRESETS.items():
            scripts = preset_config["scripts"]
            assert isinstance(scripts, list), f"Preset '{preset_name}' scripts not a list"
            if preset_name not in ["Minimal Bypass"]:
                assert len(scripts) > 0, f"Preset '{preset_name}' has no scripts"

    def test_all_presets_have_non_empty_hooks(self) -> None:
        """All presets define at least one hook."""
        for preset_name, preset_config in FRIDA_PRESETS.items():
            hooks = preset_config["hooks"]
            assert isinstance(hooks, list), f"Preset '{preset_name}' hooks not a list"
            assert len(hooks) > 0, f"Preset '{preset_name}' has no hooks"

    def test_microsoft_office_preset_structure(self) -> None:
        """Microsoft Office 365 preset has correct licensing bypass structure."""
        preset = FRIDA_PRESETS["Microsoft Office 365"]

        assert preset["description"] == "Bypass for Microsoft Office licensing and activation"
        assert "cloud_licensing_bypass" in preset["scripts"]
        assert "LICENSE" in preset["protections"]
        assert "CLOUD" in preset["protections"]
        assert preset["options"]["stealth_mode"] is True
        assert any("SLGetLicensingStatusInformation" in hook for hook in preset["hooks"])

    def test_autodesk_preset_includes_hardware_spoofing(self) -> None:
        """Autodesk preset includes hardware spoofing options."""
        preset = FRIDA_PRESETS["Autodesk Products"]

        assert preset["options"]["spoof_all_hardware"] is True
        assert "HARDWARE" in preset["protections"]

    def test_denuvo_preset_has_aggressive_options(self) -> None:
        """Denuvo preset has aggressive anti-tamper bypass options."""
        preset = FRIDA_PRESETS["Denuvo Protected Games"]

        assert preset["options"]["aggressive"] is True
        assert preset["options"]["deep_hooks"] is True
        assert "ANTI_DEBUG" in preset["protections"]
        assert "ANTI_VM" in preset["protections"]

    def test_trial_software_preset_includes_time_bypass(self) -> None:
        """Trial Software preset includes time-based protection bypass."""
        preset = FRIDA_PRESETS["Trial Software (Generic)"]

        assert "time_bomb_defuser" in preset["scripts"]
        assert "TIME" in preset["protections"]
        assert preset["options"]["freeze_time"] is True

    def test_maximum_protection_bypass_includes_all_scripts(self) -> None:
        """Maximum Protection Bypass preset loads all available bypasses."""
        preset = FRIDA_PRESETS["Maximum Protection Bypass"]

        assert len(preset["scripts"]) >= 9
        assert preset["protections"] == ["ALL"]
        assert preset["options"]["all_bypasses"] is True


class TestWizardConfigs:
    """Test WIZARD_CONFIGS constant structure."""

    def test_wizard_configs_has_all_modes(self) -> None:
        """WIZARD_CONFIGS defines all standard modes."""
        expected_modes = ["safe", "balanced", "aggressive", "stealth", "analysis"]

        for mode in expected_modes:
            assert mode in WIZARD_CONFIGS, f"Mode '{mode}' missing from WIZARD_CONFIGS"

    def test_all_wizard_configs_have_required_keys(self) -> None:
        """All wizard configs contain required configuration keys."""
        required_keys = {"name", "description", "detection_first", "max_scripts", "priority", "exclude", "options"}

        for mode_name, config in WIZARD_CONFIGS.items():
            assert all(key in config for key in required_keys), f"Wizard '{mode_name}' missing required keys"

    def test_safe_mode_limits_scripts(self) -> None:
        """Safe mode limits number of scripts for safety."""
        safe_config = WIZARD_CONFIGS["safe"]

        assert safe_config["max_scripts"] <= 3
        assert safe_config["options"]["safe_mode"] is True
        assert "KERNEL" in safe_config["exclude"]

    def test_aggressive_mode_has_no_exclusions(self) -> None:
        """Aggressive mode has no protection exclusions."""
        aggressive_config = WIZARD_CONFIGS["aggressive"]

        assert aggressive_config["exclude"] == []
        assert aggressive_config["priority"] == ["ALL"]
        assert aggressive_config["options"]["aggressive"] is True

    def test_stealth_mode_avoids_detection(self) -> None:
        """Stealth mode excludes anti-debug to avoid detection."""
        stealth_config = WIZARD_CONFIGS["stealth"]

        assert "ANTI_DEBUG" in stealth_config["exclude"]
        assert stealth_config["options"]["stealth_mode"] is True

    def test_analysis_mode_is_read_only(self) -> None:
        """Analysis mode doesn't apply bypasses, only detects."""
        analysis_config = WIZARD_CONFIGS["analysis"]

        assert analysis_config["options"]["log_only"] is True
        assert analysis_config["options"]["no_patches"] is True
        assert analysis_config["options"]["monitor_mode"] is True


class TestQuickTemplates:
    """Test QUICK_TEMPLATES constant structure."""

    def test_quick_templates_has_expected_scenarios(self) -> None:
        """QUICK_TEMPLATES defines common quick-use scenarios."""
        expected_templates = ["trial_reset", "hardware_spoof", "cloud_bypass", "anti_debug_bypass", "drm_bypass"]

        for template in expected_templates:
            assert template in QUICK_TEMPLATES, f"Template '{template}' missing"

    def test_trial_reset_template_structure(self) -> None:
        """trial_reset template has correct time manipulation configuration."""
        template = QUICK_TEMPLATES["trial_reset"]

        assert "time_bomb_defuser" in template["scripts"]
        assert "registry_monitor" in template["scripts"]
        assert template["options"]["reset_trial"] is True
        assert template["options"]["freeze_time"] is True

    def test_hardware_spoof_template_enables_spoofing(self) -> None:
        """hardware_spoof template enables all hardware spoofing."""
        template = QUICK_TEMPLATES["hardware_spoof"]

        assert template["options"]["spoof_all"] is True
        assert template["options"]["persistent"] is True

    def test_cloud_bypass_template_blocks_telemetry(self) -> None:
        """cloud_bypass template blocks cloud licensing and telemetry."""
        template = QUICK_TEMPLATES["cloud_bypass"]

        assert "cloud_licensing_bypass" in template["scripts"]
        assert "telemetry_blocker" in template["scripts"]
        assert template["options"]["block_telemetry"] is True


class TestGetPresetBySoftware:
    """Test get_preset_by_software function with fuzzy matching."""

    def test_finds_office_by_office_keyword(self) -> None:
        """Finds Microsoft Office preset with 'office' keyword."""
        preset = get_preset_by_software("office")

        assert preset["target"] == "Word, Excel, PowerPoint, Outlook"
        assert "cloud_licensing_bypass" in preset["scripts"]

    def test_finds_autodesk_by_autocad_keyword(self) -> None:
        """Finds Autodesk preset with 'AutoCAD' keyword."""
        preset = get_preset_by_software("AutoCAD")

        assert "AutoCAD" in preset["target"]

    def test_finds_vmware_by_vmware_keyword(self) -> None:
        """Finds VMware preset with 'vmware' keyword."""
        preset = get_preset_by_software("vmware")

        assert preset["description"] == "Bypass for VMware Workstation and vSphere"

    def test_finds_denuvo_by_denuvo_keyword(self) -> None:
        """Finds Denuvo preset with 'denuvo' keyword."""
        preset = get_preset_by_software("denuvo")

        assert "Denuvo" in preset["description"]

    def test_case_insensitive_matching(self) -> None:
        """Fuzzy matching is case-insensitive."""
        preset_lower = get_preset_by_software("microsoft")
        preset_upper = get_preset_by_software("MICROSOFT")
        preset_mixed = get_preset_by_software("MiCrOsOfT")

        assert preset_lower == preset_upper == preset_mixed

    def test_returns_minimal_bypass_for_unknown_software(self) -> None:
        """Returns Minimal Bypass preset for unknown software."""
        preset = get_preset_by_software("UnknownSoftware12345XYZ")

        assert preset == FRIDA_PRESETS["Minimal Bypass"]

    def test_matches_target_field(self) -> None:
        """Matches against target field when preset name doesn't match."""
        preset = get_preset_by_software("Excel")

        assert "Excel" in preset["target"]


class TestGetScriptsForProtection:
    """Test get_scripts_for_protection function."""

    def test_license_protection_returns_correct_scripts(self) -> None:
        """LICENSE protection returns cloud bypass and registry monitor."""
        scripts = get_scripts_for_protection("LICENSE")

        assert "cloud_licensing_bypass" in scripts
        assert "registry_monitor" in scripts

    def test_cloud_protection_returns_correct_scripts(self) -> None:
        """CLOUD protection returns cloud bypass and telemetry blocker."""
        scripts = get_scripts_for_protection("CLOUD")

        assert "cloud_licensing_bypass" in scripts
        assert "telemetry_blocker" in scripts

    def test_time_protection_returns_time_defuser(self) -> None:
        """TIME protection returns time bomb defuser."""
        scripts = get_scripts_for_protection("TIME")

        assert "time_bomb_defuser" in scripts

    def test_anti_debug_returns_anti_debugger(self) -> None:
        """ANTI_DEBUG protection returns anti_debugger script."""
        scripts = get_scripts_for_protection("ANTI_DEBUG")

        assert "anti_debugger" in scripts

    def test_integrity_returns_bypass_scripts(self) -> None:
        """INTEGRITY protection returns code and memory integrity bypasses."""
        scripts = get_scripts_for_protection("INTEGRITY")

        assert "code_integrity_bypass" in scripts
        assert "memory_integrity_bypass" in scripts

    def test_unknown_protection_returns_empty_list(self) -> None:
        """Unknown protection type returns empty list."""
        scripts = get_scripts_for_protection("UNKNOWN_PROTECTION_TYPE")

        assert scripts == []


class TestGetWizardConfig:
    """Test get_wizard_config function."""

    def test_returns_safe_config(self) -> None:
        """Returns safe wizard configuration."""
        config = get_wizard_config("safe")

        assert config["name"] == "Safe Mode"
        assert config["max_scripts"] == 3

    def test_returns_balanced_config(self) -> None:
        """Returns balanced wizard configuration."""
        config = get_wizard_config("balanced")

        assert config["name"] == "Balanced Mode"
        assert config["max_scripts"] == 5

    def test_returns_aggressive_config(self) -> None:
        """Returns aggressive wizard configuration."""
        config = get_wizard_config("aggressive")

        assert config["name"] == "Aggressive Mode"
        assert config["max_scripts"] == 10

    def test_defaults_to_balanced_for_unknown_mode(self) -> None:
        """Defaults to balanced mode for unknown mode names."""
        config = get_wizard_config("unknown_mode_xyz")

        assert config["name"] == "Balanced Mode"

    def test_default_mode_is_balanced(self) -> None:
        """Default mode (no parameter) returns balanced."""
        config = get_wizard_config()

        assert config["name"] == "Balanced Mode"


class TestFridaPresetsClass:
    """Test FridaPresets class static methods."""

    def test_get_all_presets_returns_dict(self) -> None:
        """get_all_presets returns dictionary of all presets."""
        presets = FridaPresets.get_all_presets()

        assert isinstance(presets, dict)
        assert "Microsoft Office 365" in presets
        assert "Autodesk Products" in presets
        assert len(presets) >= 10

    def test_get_all_presets_returns_copy(self) -> None:
        """get_all_presets returns copy, not reference to original."""
        presets1 = FridaPresets.get_all_presets()
        presets2 = FridaPresets.get_all_presets()

        assert presets1 is not presets2
        assert presets1 == presets2

    def test_get_preset_by_exact_name(self) -> None:
        """get_preset returns preset by exact name."""
        preset = FridaPresets.get_preset("VMware Products")

        assert preset is not None
        assert preset["description"] == "Bypass for VMware Workstation and vSphere"

    def test_get_preset_returns_none_for_unknown(self) -> None:
        """get_preset returns None for unknown preset name."""
        preset = FridaPresets.get_preset("NonExistentPreset12345")

        assert preset is None

    def test_get_preset_by_software_fuzzy_match(self) -> None:
        """get_preset_by_software uses fuzzy matching."""
        preset = FridaPresets.get_preset_by_software("photoshop")

        assert preset is not None

    def test_get_wizard_configs_returns_all_modes(self) -> None:
        """get_wizard_configs returns all wizard configurations."""
        configs = FridaPresets.get_wizard_configs()

        assert isinstance(configs, dict)
        assert "safe" in configs
        assert "balanced" in configs
        assert "aggressive" in configs
        assert "stealth" in configs
        assert "analysis" in configs

    def test_get_wizard_config_by_mode(self) -> None:
        """get_wizard_config returns specific wizard configuration."""
        config = FridaPresets.get_wizard_config("stealth")

        assert config["name"] == "Stealth Mode"

    def test_get_quick_templates_returns_all_templates(self) -> None:
        """get_quick_templates returns all quick templates."""
        templates = FridaPresets.get_quick_templates()

        assert isinstance(templates, dict)
        assert "trial_reset" in templates
        assert "hardware_spoof" in templates
        assert "cloud_bypass" in templates

    def test_get_quick_template_by_name(self) -> None:
        """get_quick_template returns specific template."""
        template = FridaPresets.get_quick_template("trial_reset")

        assert template is not None
        assert template["options"]["reset_trial"] is True

    def test_get_quick_template_returns_none_for_unknown(self) -> None:
        """get_quick_template returns None for unknown template."""
        template = FridaPresets.get_quick_template("unknown_template_xyz")

        assert template is None

    def test_get_scripts_for_protection_via_class(self) -> None:
        """get_scripts_for_protection works through class method."""
        scripts = FridaPresets.get_scripts_for_protection("DRM")

        assert "drm_bypass" in scripts or "code_integrity_bypass" in scripts

    def test_list_preset_names_returns_all_names(self) -> None:
        """list_preset_names returns list of all preset names."""
        names = FridaPresets.list_preset_names()

        assert isinstance(names, list)
        assert "Microsoft Office 365" in names
        assert "Autodesk Products" in names
        assert len(names) >= 10

    def test_list_protection_types_returns_all_types(self) -> None:
        """list_protection_types returns all supported protection types."""
        types = FridaPresets.list_protection_types()

        assert isinstance(types, list)
        assert "LICENSE" in types
        assert "CLOUD" in types
        assert "TIME" in types
        assert "ANTI_DEBUG" in types
        assert "DRM" in types


class TestPresetIntegrity:
    """Test preset data integrity and consistency."""

    def test_no_duplicate_preset_names(self) -> None:
        """No duplicate preset names exist."""
        preset_names = list(FRIDA_PRESETS.keys())
        assert len(preset_names) == len(set(preset_names))

    def test_all_scripts_are_strings(self) -> None:
        """All script names in presets are strings."""
        for preset_name, preset_config in FRIDA_PRESETS.items():
            for script in preset_config["scripts"]:
                assert isinstance(script, str), f"Non-string script in {preset_name}: {script}"

    def test_all_hooks_are_strings(self) -> None:
        """All hook specifications in presets are strings."""
        for preset_name, preset_config in FRIDA_PRESETS.items():
            for hook in preset_config["hooks"]:
                assert isinstance(hook, str), f"Non-string hook in {preset_name}: {hook}"

    def test_all_protections_are_strings(self) -> None:
        """All protection types in presets are strings."""
        for preset_name, preset_config in FRIDA_PRESETS.items():
            for protection in preset_config["protections"]:
                assert isinstance(protection, str), f"Non-string protection in {preset_name}: {protection}"

    def test_all_options_are_dicts(self) -> None:
        """All preset options are dictionaries."""
        for preset_name, preset_config in FRIDA_PRESETS.items():
            assert isinstance(
                preset_config["options"], dict
            ), f"Options not dict in {preset_name}"

    def test_description_and_target_are_strings(self) -> None:
        """Description and target fields are always strings."""
        for preset_name, preset_config in FRIDA_PRESETS.items():
            assert isinstance(
                preset_config["description"], str
            ), f"Description not string in {preset_name}"
            assert isinstance(
                preset_config["target"], str
            ), f"Target not string in {preset_name}"


class TestRealWorldUseCases:
    """Test real-world usage scenarios."""

    def test_enterprise_software_licensing_bypass(self) -> None:
        """Enterprise Software preset targets SAP/Oracle/IBM licensing."""
        preset = FRIDA_PRESETS["Enterprise Software"]

        assert "enterprise_mode" in preset["options"]
        assert preset["options"]["enterprise_mode"] is True
        assert any("winhttp.dll" in hook for hook in preset["hooks"])

    def test_flexlm_licensed_software_bypass(self) -> None:
        """FlexLM preset emulates license server."""
        preset = FRIDA_PRESETS["FlexLM/FlexNet Licensed"]

        assert preset["options"]["emulate_license_server"] is True
        assert any("lmgr" in hook or "flexnet" in hook for hook in preset["hooks"])

    def test_hasp_dongle_emulation(self) -> None:
        """HASP/Sentinel preset emulates hardware dongle."""
        preset = FRIDA_PRESETS["HASP/Sentinel Protected"]

        assert preset["options"]["dongle_emulation"] is True
        assert "HARDWARE" in preset["protections"]

    def test_development_tools_licensing(self) -> None:
        """Development Tools preset targets JetBrains and Visual Studio."""
        preset = FRIDA_PRESETS["Development Tools"]

        assert "JetBrains" in preset["target"]
        assert preset["options"]["unlock_features"] is True

    def test_media_production_software_bypass(self) -> None:
        """Media Production preset handles DAW/NLE licensing."""
        preset = FRIDA_PRESETS["Media Production Software"]

        assert preset["options"]["auth_bypass"] is True
        assert "plugin_mode" in preset["options"]
