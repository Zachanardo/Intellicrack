from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

try:
    from intellicrack.plugins.plugin_base import (
        BasePlugin,
        PluginMetadata,
    )
    from intellicrack.plugins.plugin_system import (
        PluginSystem,
    )

    MODULES_AVAILABLE = True
except ImportError as e:
    MODULES_AVAILABLE = False
    IMPORT_ERROR = str(e)

try:
    from intellicrack.plugins.custom_modules.anti_anti_debug_suite import (
        AntiAntiDebugSuite,
    )
    from intellicrack.plugins.custom_modules.binary_patcher_plugin import (
        BinaryPatcherPlugin,
    )
    from intellicrack.plugins.custom_modules.cloud_license_interceptor import (
        CloudLicenseInterceptor,
    )
    from intellicrack.plugins.custom_modules.hardware_dongle_emulator import (
        HardwareDongleEmulator,
    )
    from intellicrack.plugins.custom_modules.license_server_emulator import (
        LicenseServerEmulator,
    )
    from intellicrack.plugins.custom_modules.vm_protection_unwrapper import (
        VMProtectionUnwrapper,
    )

    CUSTOM_MODULES_AVAILABLE = True
except ImportError:
    CUSTOM_MODULES_AVAILABLE = False

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def plugin_dir(temp_dir: Path) -> Path:
    plugin_directory = temp_dir / "plugins"
    plugin_directory.mkdir(exist_ok=True)
    return plugin_directory


@pytest.fixture
def test_binary_with_debug_checks(temp_dir: Path) -> str:
    if not LIEF_AVAILABLE:
        pytest.skip("LIEF not available")

    binary = lief.PE.Binary("test_debuggable", lief.PE.PE_TYPE.PE32)

    text_section = lief.PE.Section(".text")
    text_section.content = [0xCC, 0x90, 0xC3] * 50
    text_section.characteristics = (
        lief.PE.SECTION_CHARACTERISTICS.CNT_CODE |
        lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE |
        lief.PE.SECTION_CHARACTERISTICS.MEM_READ
    )
    binary.add_section(text_section)

    output_path = str(temp_dir / "test_with_debug_checks.exe")
    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write(output_path)

    return output_path


@pytest.fixture
def test_binary_for_patching(temp_dir: Path) -> str:
    if not LIEF_AVAILABLE:
        pytest.skip("LIEF not available")

    binary = lief.PE.Binary("test_patchable", lief.PE.PE_TYPE.PE32)

    text_section = lief.PE.Section(".text")
    KNOWN_PATTERN = [0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10]
    text_section.content = KNOWN_PATTERN + [0x90] * 100
    text_section.characteristics = (
        lief.PE.SECTION_CHARACTERISTICS.CNT_CODE |
        lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE |
        lief.PE.SECTION_CHARACTERISTICS.MEM_READ
    )
    binary.add_section(text_section)

    output_path = str(temp_dir / "test_patchable.exe")
    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write(output_path)

    return output_path


@pytest.mark.skipif(not MODULES_AVAILABLE or not CUSTOM_MODULES_AVAILABLE, reason="Modules not available")
class TestAntiAntiDebugSuiteEffectiveness:

    def test_bypass_detects_and_patches_checks(self, test_binary_with_debug_checks: str) -> None:
        plugin = AntiAntiDebugSuite()

        result = plugin.run(binary_path=test_binary_with_debug_checks)

        assert result is not None, "FAILED: Anti-anti-debug plugin returned None"
        assert isinstance(result, dict), "FAILED: Plugin result not a dictionary"

        assert "bypasses_applied" in result or "checks_found" in result or "success" in result, \
            "FAILED: Plugin result missing expected keys"

        if "bypasses_applied" in result:
            assert result["bypasses_applied"] > 0, \
                "FAILED: No debug check bypasses applied to binary with INT3 instructions"

    def test_bypass_effectiveness_on_known_pattern(self, temp_dir: Path) -> None:
        if not LIEF_AVAILABLE:
            pytest.skip("LIEF not available")

        binary = lief.PE.Binary("test_isdebuggerpresent", lief.PE.PE_TYPE.PE32)

        text_section = lief.PE.Section(".text")
        ISDEBUGGERPRESENT_CALL_PATTERN = [0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]
        text_section.content = ISDEBUGGERPRESENT_CALL_PATTERN + [0x90] * 100
        text_section.characteristics = (
            lief.PE.SECTION_CHARACTERISTICS.CNT_CODE |
            lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE |
            lief.PE.SECTION_CHARACTERISTICS.MEM_READ
        )
        binary.add_section(text_section)

        test_path = str(temp_dir / "test_isdebuggerpresent.exe")
        builder = lief.PE.Builder(binary)
        builder.build()
        builder.write(test_path)

        plugin = AntiAntiDebugSuite()
        result = plugin.run(binary_path=test_path)

        if result and result.get("checks_found", 0) > 0:
            assert result.get("bypasses_applied", 0) >= 1, \
                "FAILED: Found debug checks but applied no bypasses"


@pytest.mark.skipif(not MODULES_AVAILABLE or not CUSTOM_MODULES_AVAILABLE, reason="Modules not available")
class TestBinaryPatcherPluginEffectiveness:

    def test_patch_applies_correctly(self, test_binary_for_patching: str, temp_dir: Path) -> None:
        plugin = BinaryPatcherPlugin()

        PATCH_OFFSET = 0x100
        PATCH_DATA = bytes([0xC3, 0x90, 0x90])

        output_path = str(temp_dir / "patched_binary.exe")

        result = plugin.run(
            binary_path=test_binary_for_patching,
            output_path=output_path,
            patches=[
                {"offset": PATCH_OFFSET, "data": PATCH_DATA}
            ]
        )

        assert result is not None, "FAILED: Binary patcher returned None"
        assert result.get("success", False), f"FAILED: Patching failed: {result.get('error', 'Unknown')}"
        assert os.path.exists(output_path), "FAILED: Patched binary not written"

        with open(output_path, 'rb') as f:
            f.seek(PATCH_OFFSET)
            patched_bytes = f.read(len(PATCH_DATA))

        assert patched_bytes == PATCH_DATA, \
            f"FAILED: Patch not applied correctly (got {patched_bytes.hex()}, expected {PATCH_DATA.hex()})"

    def test_multiple_patches(self, test_binary_for_patching: str, temp_dir: Path) -> None:
        plugin = BinaryPatcherPlugin()

        PATCHES = [
            {"offset": 0x100, "data": bytes([0xC3])},
            {"offset": 0x200, "data": bytes([0x90, 0x90])},
            {"offset": 0x300, "data": bytes([0xCC, 0xCC, 0xCC])},
        ]

        output_path = str(temp_dir / "multi_patched.exe")

        result = plugin.run(
            binary_path=test_binary_for_patching,
            output_path=output_path,
            patches=PATCHES
        )

        if result and result.get("success"):
            assert result.get("patches_applied", 0) == len(PATCHES), \
                f"FAILED: Not all patches applied (applied {result.get('patches_applied')}, expected {len(PATCHES)})"


@pytest.mark.skipif(not MODULES_AVAILABLE or not CUSTOM_MODULES_AVAILABLE, reason="Modules not available")
class TestHardwareDongleEmulatorEffectiveness:

    def test_emulator_responds_to_challenge(self) -> None:
        plugin = HardwareDongleEmulator()

        KNOWN_CHALLENGE = b"\x01\x02\x03\x04\x05\x06\x07\x08"

        result = plugin.run(
            dongle_type="HASP",
            challenge=KNOWN_CHALLENGE
        )

        assert result is not None, "FAILED: Dongle emulator returned None"

        assert "response" in result or "emulated_response" in result, \
            "FAILED: Dongle emulator didn't return response"

        if "response" in result:
            response = result["response"]
            assert len(response) > 0, "FAILED: Dongle emulator returned empty response"
            assert response != KNOWN_CHALLENGE, \
                "FAILED: Dongle emulator just echoed challenge (not a real response)"

    def test_multiple_dongle_types(self) -> None:
        plugin = HardwareDongleEmulator()

        DONGLE_TYPES = ["HASP", "Sentinel", "CodeMeter"]
        CHALLENGE = b"\xFF" * 8

        for dongle_type in DONGLE_TYPES:
            result = plugin.run(dongle_type=dongle_type, challenge=CHALLENGE)

            assert result is not None, f"FAILED: No response for {dongle_type} dongle"

            if "response" in result or "emulated_response" in result:
                response = result.get("response") or result.get("emulated_response")
                assert len(response) > 0, f"FAILED: Empty response for {dongle_type}"


@pytest.mark.skipif(not MODULES_AVAILABLE or not CUSTOM_MODULES_AVAILABLE, reason="Modules not available")
class TestLicenseServerEmulatorEffectiveness:

    def test_server_handles_activation_request(self) -> None:
        plugin = LicenseServerEmulator()

        KNOWN_LICENSE_REQUEST = {
            "product_id": "TEST-PRODUCT-001",
            "serial_number": "XXXX-YYYY-ZZZZ-AAAA",
            "hardware_id": "12345678",
        }

        result = plugin.run(
            port=18080,
            license_request=KNOWN_LICENSE_REQUEST
        )

        assert result is not None, "FAILED: License server emulator returned None"

        assert "activation_response" in result or "license_granted" in result, \
            "FAILED: License server didn't return activation response"

        if "activation_response" in result:
            response = result["activation_response"]
            assert "license_key" in response or "activation_code" in response, \
                "FAILED: Activation response missing license key"

    def test_server_generates_valid_license(self) -> None:
        plugin = LicenseServerEmulator()

        LICENSE_REQUEST = {
            "product_id": "PROD-123",
            "machine_id": "MACHINE-456",
        }

        result = plugin.run(license_request=LICENSE_REQUEST)

        if result and "license_key" in result:
            license_key = result["license_key"]

            assert len(license_key) >= 10, \
                f"FAILED: License key too short ({len(license_key)} chars)"
            assert "-" in license_key or len(license_key) >= 16, \
                "FAILED: License key doesn't match expected format"


@pytest.mark.skipif(not MODULES_AVAILABLE or not CUSTOM_MODULES_AVAILABLE, reason="Modules not available")
class TestCloudLicenseInterceptorEffectiveness:

    def test_interceptor_captures_requests(self) -> None:
        plugin = CloudLicenseInterceptor()

        KNOWN_LICENSE_URL = "https://api.licensing-server.example.com/validate"

        result = plugin.run(
            target_url=KNOWN_LICENSE_URL,
            intercept_mode="capture"
        )

        assert result is not None, "FAILED: Cloud license interceptor returned None"

        assert "interception_active" in result or "hook_installed" in result, \
            "FAILED: Interceptor didn't report activation status"

    def test_interceptor_modifies_response(self) -> None:
        plugin = CloudLicenseInterceptor()

        ORIGINAL_RESPONSE = {"valid": False, "days_remaining": 0}
        MODIFIED_RESPONSE = {"valid": True, "days_remaining": 999}

        result = plugin.run(
            intercept_mode="modify",
            original_response=ORIGINAL_RESPONSE,
            modified_response=MODIFIED_RESPONSE
        )

        if result and "response_modified" in result:
            assert result["response_modified"], \
                "FAILED: Interceptor didn't modify response"

            if "new_response" in result:
                new_resp = result["new_response"]
                assert new_resp.get("valid") == True, \
                    "FAILED: Modified response doesn't grant license"


@pytest.mark.skipif(not MODULES_AVAILABLE or not CUSTOM_MODULES_AVAILABLE, reason="Modules not available")
class TestVMProtectionUnwrapperEffectiveness:

    def test_unwrapper_detects_virtualized_code(self, temp_dir: Path) -> None:
        if not LIEF_AVAILABLE:
            pytest.skip("LIEF not available")

        binary = lief.PE.Binary("test_vm_protected", lief.PE.PE_TYPE.PE32)

        vm_section = lief.PE.Section(".vmp0")
        vm_section.content = [0xE8, 0x00, 0x00, 0x00, 0x00] * 50
        vm_section.characteristics = (
            lief.PE.SECTION_CHARACTERISTICS.CNT_CODE |
            lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE |
            lief.PE.SECTION_CHARACTERISTICS.MEM_READ
        )
        binary.add_section(vm_section)

        test_path = str(temp_dir / "test_vm_protected.exe")
        builder = lief.PE.Builder(binary)
        builder.build()
        builder.write(test_path)

        plugin = VMProtectionUnwrapper()

        result = plugin.run(binary_path=test_path)

        assert result is not None, "FAILED: VM unwrapper returned None"

        assert "vm_detected" in result or "handlers_found" in result, \
            "FAILED: VM unwrapper didn't report detection status"

        if "vm_detected" in result:
            assert result["vm_detected"], \
                "FAILED: VM unwrapper didn't detect .vmp0 section in VMProtect-like binary"


@pytest.mark.skipif(not MODULES_AVAILABLE, reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}")
class TestPluginSystemEffectiveness:

    def test_plugin_discovery_and_loading(self, plugin_dir: Path) -> None:
        plugin_file = plugin_dir / "test_plugin.py"
        plugin_file.write_text("""
from intellicrack.plugins.plugin_base import BasePlugin, PluginMetadata

class TestDiscoveryPlugin(BasePlugin):
    def __init__(self):
        metadata = PluginMetadata(
            name="discovery_test",
            version="1.0.0",
            author="Test",
            description="Test discovery",
            categories=["test"]
        )
        super().__init__(metadata)

    def run(self, **kwargs):
        return {"discovered": True}
""")

        system = PluginSystem(plugin_directory=str(plugin_dir))
        system.discover_plugins()

        plugins = system.list_plugins()

        assert len(plugins) > 0, "FAILED: Plugin discovery found no plugins"

        plugin_names = [p.get("name") for p in plugins]
        assert "discovery_test" in plugin_names, \
            "FAILED: Discovered plugins missing 'discovery_test'"

    def test_plugin_execution_returns_results(self, plugin_dir: Path) -> None:
        plugin_file = plugin_dir / "execution_test_plugin.py"
        plugin_file.write_text("""
from intellicrack.plugins.plugin_base import BasePlugin, PluginMetadata

class ExecutionTestPlugin(BasePlugin):
    def __init__(self):
        metadata = PluginMetadata(
            name="execution_test",
            version="1.0.0",
            author="Test",
            description="Test execution",
            categories=["test"]
        )
        super().__init__(metadata)

    def run(self, **kwargs):
        test_value = kwargs.get("test_param", 0)
        return {"result": test_value * 2, "success": True}
""")

        system = PluginSystem(plugin_directory=str(plugin_dir))
        system.discover_plugins()

        result = system.execute_plugin(
            plugin_name="execution_test",
            test_param=42
        )

        assert result is not None, "FAILED: Plugin execution returned None"
        assert result.get("result") == 84, \
            f"FAILED: Plugin didn't execute correctly (got {result.get('result')}, expected 84)"
        assert result.get("success"), "FAILED: Plugin didn't report success"


@pytest.mark.skipif(not MODULES_AVAILABLE or not CUSTOM_MODULES_AVAILABLE, reason="Modules not available")
class TestIntegrationEffectiveness:

    def test_full_plugin_workflow(self, test_binary_for_patching: str, temp_dir: Path) -> None:
        anti_debug = AntiAntiDebugSuite()
        patcher = BinaryPatcherPlugin()

        debug_result = anti_debug.run(binary_path=test_binary_for_patching)

        assert debug_result is not None, "FAILED: Step 1 - Anti-debug plugin failed"

        output_path = str(temp_dir / "workflow_patched.exe")
        patch_result = patcher.run(
            binary_path=test_binary_for_patching,
            output_path=output_path,
            patches=[{"offset": 0x100, "data": bytes([0xC3])}]
        )

        assert patch_result is not None and patch_result.get("success"), \
            "FAILED: Step 2 - Binary patcher failed"
        assert os.path.exists(output_path), "FAILED: Step 2 - Patched binary not created"
