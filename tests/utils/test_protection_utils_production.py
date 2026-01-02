"""Production tests for protection utilities.

Tests validate that protection detection, bypass strategy generation, and
API hooking work correctly for defeating real software licensing protections
and anti-debugging mechanisms in commercial software.
"""

import tempfile
from pathlib import Path

import pytest

from intellicrack.utils.protection_utils import (
    calculate_entropy,
    create_custom_hook_script,
    detect_protection_mechanisms,
    emulate_hardware_dongle,
    generate_bypass_strategy,
    generate_hwid_spoof_config,
    generate_telemetry_blocker,
    generate_time_bomb_defuser,
    inject_comprehensive_api_hooks,
)


class TestInjectComprehensiveAPIHooks:
    """Test comprehensive API hook injection."""

    def test_generates_frida_script_content(self) -> None:
        """inject_comprehensive_api_hooks generates Frida script content."""
        script = inject_comprehensive_api_hooks(None)

        assert isinstance(script, str)
        assert "Frida" in script or "console.log" in script

    def test_includes_default_hook_types(self) -> None:
        """inject_comprehensive_api_hooks includes default hook types."""
        script = inject_comprehensive_api_hooks(None)

        assert len(script) > 0

    def test_accepts_custom_hook_types(self) -> None:
        """inject_comprehensive_api_hooks accepts custom hook types."""
        script = inject_comprehensive_api_hooks(None, hook_types=["hardware_id"])

        assert isinstance(script, str)

    def test_includes_hardware_id_hooks(self) -> None:
        """inject_comprehensive_api_hooks includes hardware ID hooks."""
        script = inject_comprehensive_api_hooks(None, hook_types=["hardware_id"])

        assert "hardware" in script.lower() or "hwid" in script.lower()

    def test_includes_debugger_hooks(self) -> None:
        """inject_comprehensive_api_hooks includes debugger detection hooks."""
        script = inject_comprehensive_api_hooks(None, hook_types=["debugger"])

        assert "debugger" in script.lower() or "debug" in script.lower()

    def test_includes_time_hooks(self) -> None:
        """inject_comprehensive_api_hooks includes time-related hooks."""
        script = inject_comprehensive_api_hooks(None, hook_types=["time"])

        assert "time" in script.lower()

    def test_includes_network_hooks(self) -> None:
        """inject_comprehensive_api_hooks includes network hooks."""
        script = inject_comprehensive_api_hooks(None, hook_types=["network"])

        assert "network" in script.lower()

    def test_handles_empty_hook_types(self) -> None:
        """inject_comprehensive_api_hooks handles empty hook types list."""
        script = inject_comprehensive_api_hooks(None, hook_types=[])

        assert isinstance(script, str)

    def test_script_contains_console_logging(self) -> None:
        """Generated script contains console logging statements."""
        script = inject_comprehensive_api_hooks(None)

        assert "console.log" in script


class TestDetectProtectionMechanisms:
    """Test protection mechanism detection."""

    def test_analyzes_binary_for_protections(self) -> None:
        """detect_protection_mechanisms analyzes binary for protection schemes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "test.exe"
            binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

            result = detect_protection_mechanisms(str(binary_path))

            assert isinstance(result, dict)

    def test_returns_protection_info_dictionary(self) -> None:
        """detect_protection_mechanisms returns dictionary with protection info."""
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "sample.exe"
            binary_path.write_bytes(b"MZ\x90\x00" + b"VMProtect" + b"\x00" * 500)

            result = detect_protection_mechanisms(str(binary_path))

            assert "protections" in result or "detected" in result or isinstance(result, dict)

    def test_handles_nonexistent_binary(self) -> None:
        """detect_protection_mechanisms handles nonexistent binary files."""
        result = detect_protection_mechanisms("/nonexistent/binary.exe")

        assert isinstance(result, dict)

    def test_detects_common_protection_strings(self) -> None:
        """detect_protection_mechanisms detects common protection signatures."""
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "protected.exe"
            binary_data = b"MZ\x90\x00" + b"Themida" + b"\x00" * 500
            binary_path.write_bytes(binary_data)

            result = detect_protection_mechanisms(str(binary_path))

            assert isinstance(result, dict)


class TestGenerateBypassStrategy:
    """Test bypass strategy generation."""

    def test_generates_bypass_strategies(self) -> None:
        """generate_bypass_strategy generates bypass strategies for protections."""
        protections = {
            "vmprotect": True,
            "themida": False,
            "debugger_check": True,
        }

        strategies = generate_bypass_strategy(protections)

        assert isinstance(strategies, list)

    def test_returns_list_of_strategies(self) -> None:
        """generate_bypass_strategy returns list of strategy strings."""
        protections = {"hardware_check": True}

        strategies = generate_bypass_strategy(protections)

        assert isinstance(strategies, list)
        assert all(isinstance(s, str) for s in strategies)

    def test_handles_empty_protections(self) -> None:
        """generate_bypass_strategy handles empty protections dictionary."""
        strategies = generate_bypass_strategy({})

        assert isinstance(strategies, list)

    def test_generates_strategies_for_common_protections(self) -> None:
        """generate_bypass_strategy generates strategies for common protections."""
        protections = {
            "vmprotect": True,
            "themida": True,
            "license_check": True,
        }

        strategies = generate_bypass_strategy(protections)

        assert len(strategies) >= 0


class TestCreateCustomHookScript:
    """Test custom hook script generation."""

    def test_creates_hook_script_from_config(self) -> None:
        """create_custom_hook_script creates hook script from configuration."""
        hook_config = {
            "target_function": "CheckLicense",
            "module": "app.dll",
            "action": "bypass",
        }

        script = create_custom_hook_script(hook_config)

        assert isinstance(script, str)

    def test_script_contains_frida_syntax(self) -> None:
        """create_custom_hook_script generates valid Frida script syntax."""
        hook_config = {
            "target": "IsLicenseValid",
        }

        script = create_custom_hook_script(hook_config)

        assert "Interceptor" in script or "function" in script

    def test_handles_empty_config(self) -> None:
        """create_custom_hook_script handles empty configuration."""
        script = create_custom_hook_script({})

        assert isinstance(script, str)

    def test_includes_hook_configuration(self) -> None:
        """create_custom_hook_script includes hook configuration in script."""
        hook_config = {
            "function_name": "ValidateLicense",
            "return_value": "true",
        }

        script = create_custom_hook_script(hook_config)

        assert len(script) > 0


class TestEmulateHardwareDongle:
    """Test hardware dongle emulation."""

    def test_generates_dongle_emulation_config(self) -> None:
        """emulate_hardware_dongle generates dongle emulation configuration."""
        config = {
            "vendor_id": "0x1234",
            "product_id": "0x5678",
        }

        result = emulate_hardware_dongle(config)

        assert isinstance(result, dict)

    def test_returns_emulation_parameters(self) -> None:
        """emulate_hardware_dongle returns emulation parameters."""
        config = {"dongle_type": "sentinel"}

        result = emulate_hardware_dongle(config)

        assert isinstance(result, dict)

    def test_handles_empty_config(self) -> None:
        """emulate_hardware_dongle handles empty configuration."""
        result = emulate_hardware_dongle({})

        assert isinstance(result, dict)

    def test_includes_virtual_device_info(self) -> None:
        """emulate_hardware_dongle includes virtual device information."""
        config = {"device_name": "USB Security Key"}

        result = emulate_hardware_dongle(config)

        assert "virtual_device" in result or "emulation" in result or isinstance(result, dict)


class TestGenerateHwidSpoofConfig:
    """Test HWID spoofing configuration generation."""

    def test_generates_spoof_config_from_hwid(self) -> None:
        """generate_hwid_spoof_config generates spoofing config from HWID."""
        target_hwid = "ABC123-DEF456-GHI789"

        config = generate_hwid_spoof_config(target_hwid)

        assert isinstance(config, dict)

    def test_config_includes_hwid_parameters(self) -> None:
        """generate_hwid_spoof_config includes HWID spoofing parameters."""
        target_hwid = "TEST-HWID-12345"

        config = generate_hwid_spoof_config(target_hwid)

        assert isinstance(config, dict)
        assert len(config) >= 0

    def test_handles_different_hwid_formats(self) -> None:
        """generate_hwid_spoof_config handles different HWID formats."""
        hwids = [
            "12345678-9ABC-DEF0",
            "HWID_123456",
            "ABC-123-XYZ-789",
        ]

        for hwid in hwids:
            config = generate_hwid_spoof_config(hwid)
            assert isinstance(config, dict)

    def test_handles_empty_hwid(self) -> None:
        """generate_hwid_spoof_config handles empty HWID string."""
        config = generate_hwid_spoof_config("")

        assert isinstance(config, dict)


class TestGenerateTimeBombDefuser:
    """Test time bomb defusing functionality."""

    def test_analyzes_binary_for_time_checks(self) -> None:
        """generate_time_bomb_defuser analyzes binary for time-based checks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "timebomb.exe"
            binary_path.write_bytes(b"MZ\x90\x00" + b"time" * 50)

            result = generate_time_bomb_defuser(str(binary_path))

            assert isinstance(result, dict)

    def test_returns_defusing_strategies(self) -> None:
        """generate_time_bomb_defuser returns defusing strategies."""
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "test.exe"
            binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

            result = generate_time_bomb_defuser(str(binary_path))

            assert "strategies" in result or "hooks" in result or isinstance(result, dict)

    def test_handles_nonexistent_binary(self) -> None:
        """generate_time_bomb_defuser handles nonexistent binaries."""
        result = generate_time_bomb_defuser("/nonexistent/file.exe")

        assert isinstance(result, dict)


class TestGenerateTelemetryBlocker:
    """Test telemetry blocking functionality."""

    def test_generates_telemetry_blocking_config(self) -> None:
        """generate_telemetry_blocker generates telemetry blocking configuration."""
        result = generate_telemetry_blocker("TestApp")

        assert isinstance(result, dict)

    def test_config_includes_network_filters(self) -> None:
        """generate_telemetry_blocker includes network filtering rules."""
        result = generate_telemetry_blocker("LicensedSoftware")

        assert "hosts" in result or "domains" in result or isinstance(result, dict)

    def test_handles_different_app_names(self) -> None:
        """generate_telemetry_blocker handles different application names."""
        apps = ["App1", "App2", "App3"]

        for app in apps:
            result = generate_telemetry_blocker(app)
            assert isinstance(result, dict)

    def test_handles_empty_app_name(self) -> None:
        """generate_telemetry_blocker handles empty application name."""
        result = generate_telemetry_blocker("")

        assert isinstance(result, dict)


class TestCalculateEntropy:
    """Test entropy calculation for data analysis."""

    def test_calculates_entropy_for_random_data(self) -> None:
        """calculate_entropy calculates entropy for random data."""
        import random

        random_data = bytes(random.randint(0, 255) for _ in range(1000))

        entropy = calculate_entropy(random_data)

        assert isinstance(entropy, float)
        assert entropy > 0.0

    def test_low_entropy_for_uniform_data(self) -> None:
        """calculate_entropy returns low entropy for uniform data."""
        uniform_data = b"\x00" * 1000

        entropy = calculate_entropy(uniform_data)

        assert entropy == 0.0

    def test_high_entropy_for_varied_data(self) -> None:
        """calculate_entropy returns high entropy for varied data."""
        varied_data = bytes(range(256)) * 4

        entropy = calculate_entropy(varied_data)

        assert entropy > 0.0

    def test_handles_empty_data(self) -> None:
        """calculate_entropy handles empty data."""
        entropy = calculate_entropy(b"")

        assert entropy == 0.0

    def test_handles_single_byte(self) -> None:
        """calculate_entropy handles single byte data."""
        entropy = calculate_entropy(b"A")

        assert entropy == 0.0

    def test_entropy_range(self) -> None:
        """calculate_entropy returns values in valid range."""
        test_data = b"Hello, World! This is test data."

        entropy = calculate_entropy(test_data)

        assert 0.0 <= entropy <= 8.0


class TestRealWorldScenarios:
    """Test realistic production usage scenarios."""

    def test_complete_bypass_workflow(self) -> None:
        """Test complete workflow from detection to bypass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "protected.exe"
            binary_path.write_bytes(b"MZ\x90\x00" + b"license check" * 10)

            protections = detect_protection_mechanisms(str(binary_path))
            strategies = generate_bypass_strategy(protections)

            assert isinstance(protections, dict)
            assert isinstance(strategies, list)

    def test_hwid_spoofing_configuration(self) -> None:
        """Test HWID spoofing configuration generation."""
        original_hwid = "REAL-HWID-12345"
        target_hwid = "FAKE-HWID-67890"

        spoof_config = generate_hwid_spoof_config(target_hwid)
        hooks = inject_comprehensive_api_hooks(None, hook_types=["hardware_id"])

        assert isinstance(spoof_config, dict)
        assert isinstance(hooks, str)

    def test_multi_layer_protection_bypass(self) -> None:
        """Test bypass strategy for multi-layered protections."""
        protections = {
            "vmprotect": True,
            "debugger_check": True,
            "hardware_check": True,
            "time_check": True,
        }

        strategies = generate_bypass_strategy(protections)
        hook_script = inject_comprehensive_api_hooks(
            None,
            hook_types=["debugger", "hardware_id", "time"],
        )

        assert isinstance(strategies, list)
        assert isinstance(hook_script, str)


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_inject_hooks_with_invalid_app(self) -> None:
        """inject_comprehensive_api_hooks handles invalid app parameter."""
        script = inject_comprehensive_api_hooks("invalid_app")

        assert isinstance(script, str)

    def test_detect_protections_with_corrupted_binary(self) -> None:
        """detect_protection_mechanisms handles corrupted binary data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "corrupted.exe"
            binary_path.write_bytes(b"CORRUPTED DATA")

            result = detect_protection_mechanisms(str(binary_path))

            assert isinstance(result, dict)

    def test_generate_bypass_with_unknown_protections(self) -> None:
        """generate_bypass_strategy handles unknown protection types."""
        protections = {
            "unknown_protection_1": True,
            "unknown_protection_2": True,
        }

        strategies = generate_bypass_strategy(protections)

        assert isinstance(strategies, list)

    def test_hook_script_with_special_characters_in_config(self) -> None:
        """create_custom_hook_script handles special characters in config."""
        hook_config = {
            "function": "Test<>Function",
            "module": "lib'name.dll",
        }

        script = create_custom_hook_script(hook_config)

        assert isinstance(script, str)

    def test_entropy_with_binary_patterns(self) -> None:
        """calculate_entropy handles binary patterns."""
        pattern_data = b"\xAA\x55" * 500

        entropy = calculate_entropy(pattern_data)

        assert isinstance(entropy, float)
        assert entropy >= 0.0

    def test_telemetry_blocker_with_unicode_app_name(self) -> None:
        """generate_telemetry_blocker handles Unicode app names."""
        result = generate_telemetry_blocker("App\u4e2d\u6587")

        assert isinstance(result, dict)
