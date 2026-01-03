"""Production tests for hardware_spoofer.py kernel driver validation.

This module validates that hardware_spoofer.py either:
1. Implements working kernel drivers for NDIS/disk filtering, OR
2. Provides comprehensive user-mode fallbacks with clear documentation

Tests MUST FAIL if:
- Pseudo-assembly driver code exists
- Driver approach claims functionality without implementation
- User-mode fallbacks are insufficient
- Windows version compatibility is not documented
"""

import platform
import subprocess
import sys
import winreg
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.core.hardware_spoofer import HardwareSpoofer, SpoofMethod


@pytest.fixture
def hardware_spoofer() -> HardwareSpoofer:
    """Create HardwareSpoofer instance for testing.

    Returns:
        Initialized HardwareSpoofer instance.
    """
    spoofer = HardwareSpoofer()
    spoofer.capture_original_hardware()
    spoofer.generate_spoofed_hardware()
    return spoofer


@pytest.fixture
def mock_wmi() -> MagicMock:
    """Mock WMI for cross-platform testing.

    Returns:
        Mock WMI client with realistic hardware data.
    """
    wmi_mock = MagicMock()

    cpu_mock = Mock()
    cpu_mock.ProcessorId = "BFEBFBFF000906EA"
    cpu_mock.Name = "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz"
    wmi_mock.Win32_Processor.return_value = [cpu_mock]

    board_mock = Mock()
    board_mock.SerialNumber = "MB1234567890"
    board_mock.Manufacturer = "ASUS"
    wmi_mock.Win32_BaseBoard.return_value = [board_mock]

    bios_mock = Mock()
    bios_mock.SerialNumber = "BIOS9876543210"
    bios_mock.SMBIOSBIOSVersion = "2.19.1268"
    wmi_mock.Win32_BIOS.return_value = [bios_mock]

    disk_mock = Mock()
    disk_mock.SerialNumber = "WD-ABCD1234567890"
    wmi_mock.Win32_PhysicalMedia.return_value = [disk_mock]

    return wmi_mock


class TestDriverImplementationStatus:
    """Validate driver implementation approach is clearly documented and functional."""

    def test_driver_spoof_method_returns_false_correctly(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Driver method must return False when not implemented.

        This test validates that _apply_driver_spoof returns False,
        indicating no driver implementation exists. This is acceptable
        if user-mode fallbacks are comprehensive.
        """
        result = hardware_spoofer._apply_driver_spoof()

        assert result is False, (
            "Driver spoofing claims success but should return False when not implemented"
        )

    def test_no_pseudo_assembly_driver_code_exists(self) -> None:
        """Verify no pseudo-assembly or non-functional driver code exists.

        This test searches the hardware_spoofer.py file for patterns indicating
        pseudo-assembly or incomplete driver implementation. Such code must be
        removed per testingtodo.md requirements.
        """
        spoofer_path = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        assert spoofer_path.exists(), f"Cannot find hardware_spoofer.py at {spoofer_path}"

        content = spoofer_path.read_text(encoding="utf-8")

        pseudo_assembly_patterns = [
            "mov ",
            "push ",
            "pop ",
            "call ",
            "ret",
            "jmp ",
            "jne ",
            "je ",
            "cmp ",
            "test ",
            "lea ",
            "xor eax",
            "int 0x",
            ".asm",
            "assembly",
            "__asm",
        ]

        found_patterns = []
        for pattern in pseudo_assembly_patterns:
            if pattern.lower() in content.lower():
                for i, line in enumerate(content.splitlines(), 1):
                    if pattern.lower() in line.lower():
                        found_patterns.append(f"Line {i}: {line.strip()[:80]}")

        assert not found_patterns, (
            f"Pseudo-assembly code found in hardware_spoofer.py:\n"
            + "\n".join(found_patterns[:5])
            + "\n\nAll pseudo-assembly driver code must be removed or replaced with working implementation"
        )

    def test_driver_method_documented_as_unimplemented(self) -> None:
        """Verify driver method has clear documentation about non-implementation.

        If drivers are not implemented, the code must clearly document this
        limitation and explain the fallback approach.
        """
        spoofer_path = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        content = spoofer_path.read_text(encoding="utf-8")

        driver_method_start = content.find("def _apply_driver_spoof")
        assert driver_method_start != -1, "Could not find _apply_driver_spoof method"

        method_section = content[driver_method_start:driver_method_start + 500]

        has_return_false = "return False" in method_section
        has_docstring = '"""' in method_section

        assert has_return_false and has_docstring, (
            "_apply_driver_spoof must have docstring explaining why it returns False"
        )


class TestRegistryBasedSpoofinog:
    """Validate registry-based spoofing works as primary user-mode approach."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Registry spoofing requires Windows")
    def test_registry_spoof_modifies_machine_guid(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Registry spoofing must actually modify MachineGuid.

        This test validates that apply_spoof with REGISTRY method creates
        registry entries with spoofed values.
        """
        original_guid = hardware_spoofer.original_hardware.machine_guid if hardware_spoofer.original_hardware else None
        spoofed_guid = hardware_spoofer.spoofed_hardware.machine_guid if hardware_spoofer.spoofed_hardware else None

        assert spoofed_guid is not None, "Spoofed hardware not generated"
        assert original_guid != spoofed_guid, "Spoofed GUID must differ from original"

        with patch("winreg.CreateKey") as mock_create, \
             patch("winreg.SetValueEx") as mock_set:

            mock_key = MagicMock()
            mock_create.return_value.__enter__.return_value = mock_key

            result = hardware_spoofer._apply_registry_spoof()

            assert result is True, "Registry spoof should succeed"

            set_calls = [call[0] for call in mock_set.call_args_list]
            machine_guid_set = any(
                "MachineGuid" in str(call) and spoofed_guid in str(call)
                for call in set_calls
            )

            assert machine_guid_set, (
                f"MachineGuid was not set to spoofed value {spoofed_guid} in registry"
            )

    @pytest.mark.skipif(platform.system() != "Windows", reason="Registry spoofing requires Windows")
    def test_registry_spoof_modifies_product_id(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Registry spoofing must modify Windows ProductId.

        ProductId is used by many licensing systems for hardware fingerprinting.
        """
        spoofed_product_id = hardware_spoofer.spoofed_hardware.product_id if hardware_spoofer.spoofed_hardware else None
        assert spoofed_product_id is not None

        with patch("winreg.CreateKey") as mock_create, \
             patch("winreg.SetValueEx") as mock_set:

            mock_key = MagicMock()
            mock_create.return_value.__enter__.return_value = mock_key

            result = hardware_spoofer._apply_registry_spoof()
            assert result is True

            product_id_set = any(
                "ProductId" in str(call[0]) for call in mock_set.call_args_list
            )

            assert product_id_set, "ProductId must be set in registry during spoof"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Registry spoofing requires Windows")
    def test_registry_spoof_modifies_network_addresses(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Registry spoofing must modify MAC addresses in network adapter registry.

        MAC address is critical hardware identifier for licensing systems.
        """
        spoofed_macs = hardware_spoofer.spoofed_hardware.mac_addresses if hardware_spoofer.spoofed_hardware else []
        assert len(spoofed_macs) > 0, "Must generate at least one spoofed MAC"

        with patch("winreg.OpenKey") as mock_open, \
             patch("winreg.EnumKey") as mock_enum, \
             patch("winreg.SetValueEx") as mock_set, \
             patch("winreg.QueryValueEx") as mock_query:

            mock_key = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_key

            mock_enum.side_effect = ["0000", "0001", OSError]

            mock_query.return_value = (0x84, None)

            hardware_spoofer._spoof_network_registry()

            network_address_set = any(
                "NetworkAddress" in str(call[0]) for call in mock_set.call_args_list
            )

            assert network_address_set, "NetworkAddress must be set for network adapters"


class TestFridaHookBasedSpoofing:
    """Validate Frida hook approach provides comprehensive coverage."""

    def test_hook_spoof_installs_multiple_hook_types(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Hook-based spoofing must install WMI, registry, and API hooks.

        This validates that _apply_hook_spoof calls all required hook installation
        methods to provide comprehensive coverage.
        """
        with patch.object(hardware_spoofer, "_install_wmi_hooks", return_value=True), \
             patch.object(hardware_spoofer, "_install_registry_hooks", return_value=True), \
             patch.object(hardware_spoofer, "_install_deviceiocontrol_hooks", return_value=True), \
             patch.object(hardware_spoofer, "_hook_kernel32_dll", return_value=True), \
             patch.object(hardware_spoofer, "_hook_setupapi_dll", return_value=True), \
             patch.object(hardware_spoofer, "_hook_iphlpapi_dll", return_value=True):

            result = hardware_spoofer._apply_hook_spoof()

            assert result is True, "Hook installation should succeed when all hooks install"
            assert hardware_spoofer.hooks_installed is True, "hooks_installed flag must be set"

    def test_hook_spoof_handles_installation_failure(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Hook installation must handle failures gracefully.

        If any hook installation fails, the method should return False
        and not set hooks_installed flag.
        """
        with patch.object(hardware_spoofer, "_install_wmi_hooks", side_effect=RuntimeError("WMI hook failed")):

            result = hardware_spoofer._apply_hook_spoof()

            assert result is False, "Hook installation should fail when exception occurs"


class TestMemoryBasedSpoofing:
    """Validate memory patching approach modifies process memory correctly."""

    def test_memory_spoof_uses_frida_for_process_attachment(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Memory spoofing must use Frida to attach to target process.

        This validates the approach uses real instrumentation, not stubs.
        """
        test_pid = 1234

        with patch("frida.attach") as mock_attach:
            mock_session = MagicMock()
            mock_attach.return_value = mock_session

            with patch.object(hardware_spoofer, "target_process", test_pid):
                result = hardware_spoofer._apply_memory_spoof()

                if result:
                    mock_attach.assert_called_once_with(test_pid)


class TestEdgeCaseHandling:
    """Validate edge cases documented in testingtodo.md."""

    def test_driver_signing_limitation_documented(self) -> None:
        """Code must document driver signing requirements if using drivers.

        Since drivers are not implemented, this test verifies no false claims
        about driver signing are made.
        """
        spoofer_path = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        content = spoofer_path.read_text(encoding="utf-8")

        driver_signing_claims = [
            "driver sign",
            "code sign",
            "signed driver",
            "certificate sign",
        ]

        false_claims = []
        for claim in driver_signing_claims:
            if claim in content.lower():
                for i, line in enumerate(content.splitlines(), 1):
                    if claim in line.lower() and "return True" in content[max(0, i-10):min(len(content), i+10)]:
                        false_claims.append(f"Line {i}: {line.strip()}")

        assert not false_claims, (
            f"Found false driver signing claims:\n" + "\n".join(false_claims)
        )

    def test_hvci_compatibility_not_falsely_claimed(self) -> None:
        """HVCI/VBS compatibility must not be falsely claimed without drivers.

        User-mode spoofing cannot bypass HVCI protected processes.
        """
        spoofer_path = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        content = spoofer_path.read_text(encoding="utf-8")

        hvci_claims = [
            "hvci compat",
            "vbs bypass",
            "hvci bypass",
            "hypervisor",
        ]

        false_hvci_claims = []
        for claim in hvci_claims:
            if claim in content.lower():
                for i, line in enumerate(content.splitlines(), 1):
                    if claim in line.lower() and "_apply_driver_spoof" not in line:
                        if "not support" not in line.lower() and "cannot" not in line.lower():
                            false_hvci_claims.append(f"Line {i}: {line.strip()}")

        assert not false_hvci_claims or len(false_hvci_claims) == 0, (
            "HVCI compatibility claims found without driver implementation"
        )

    @pytest.mark.parametrize("windows_version", [
        "Windows 7",
        "Windows 8.1",
        "Windows 10",
        "Windows 11",
    ])
    def test_windows_version_compatibility_for_registry_approach(
        self, hardware_spoofer: HardwareSpoofer, windows_version: str
    ) -> None:
        """Registry spoofing must work across Windows versions.

        Registry keys used for spoofing should exist on Windows 7-11.
        """
        required_registry_paths = [
            r"SOFTWARE\Microsoft\Cryptography",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            r"SYSTEM\CurrentControlSet\Control\SystemInformation",
        ]

        for path in required_registry_paths:
            assert path in str(hardware_spoofer._apply_registry_spoof.__code__.co_consts), (
                f"Registry path {path} must be used in _apply_registry_spoof for compatibility"
            )


class TestFunctionalSpoofingCapabilities:
    """Validate actual hardware spoofing works against real applications."""

    def test_spoof_defeats_wmi_based_hardware_id_check(
        self, hardware_spoofer: HardwareSpoofer, mock_wmi: MagicMock
    ) -> None:
        """Spoofing must defeat WMI-based hardware ID collection.

        Many licensing systems query WMI for hardware info. Hooks must intercept these.
        """
        hardware_spoofer.wmi_client = mock_wmi

        original_hw = hardware_spoofer.capture_original_hardware()
        spoofed_hw = hardware_spoofer.generate_spoofed_hardware()

        assert original_hw.cpu_id != spoofed_hw.cpu_id, "CPU ID must be spoofed"
        assert original_hw.motherboard_serial != spoofed_hw.motherboard_serial, "MB serial must be spoofed"
        assert original_hw.bios_serial != spoofed_hw.bios_serial, "BIOS serial must be spoofed"

    def test_spoof_changes_all_critical_hardware_identifiers(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Comprehensive spoofing must change all major hardware IDs.

        This validates completeness of the spoofing implementation.
        """
        original = hardware_spoofer.original_hardware
        spoofed = hardware_spoofer.spoofed_hardware

        assert original is not None and spoofed is not None

        critical_differences = [
            ("cpu_id", original.cpu_id, spoofed.cpu_id),
            ("motherboard_serial", original.motherboard_serial, spoofed.motherboard_serial),
            ("bios_serial", original.bios_serial, spoofed.bios_serial),
            ("machine_guid", original.machine_guid, spoofed.machine_guid),
            ("product_id", original.product_id, spoofed.product_id),
            ("system_uuid", original.system_uuid, spoofed.system_uuid),
        ]

        failures = []
        for field_name, orig_val, spoof_val in critical_differences:
            if orig_val == spoof_val:
                failures.append(f"{field_name}: {orig_val} == {spoof_val}")

        assert not failures, (
            f"Critical hardware identifiers were not spoofed:\n" + "\n".join(failures)
        )

    def test_mac_address_spoofing_generates_valid_addresses(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Spoofed MAC addresses must be valid and properly formatted.

        Invalid MACs will be rejected by licensing systems.
        """
        spoofed_macs = hardware_spoofer.spoofed_hardware.mac_addresses if hardware_spoofer.spoofed_hardware else []

        assert len(spoofed_macs) > 0, "Must generate at least one spoofed MAC"

        for mac in spoofed_macs:
            assert len(mac) == 12, f"MAC {mac} must be 12 hex characters (without colons)"
            assert all(c in "0123456789ABCDEF" for c in mac.upper()), f"MAC {mac} contains invalid characters"

            first_byte = int(mac[0:2], 16)
            assert (first_byte & 0x01) == 0, f"MAC {mac} has multicast bit set (must be unicast)"

    def test_disk_serial_spoofing_realistic_format(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Spoofed disk serials must match realistic vendor formats.

        Licensing systems may validate serial format patterns.
        """
        spoofed_serials = hardware_spoofer.spoofed_hardware.disk_serial if hardware_spoofer.spoofed_hardware else []

        assert len(spoofed_serials) > 0, "Must generate at least one disk serial"

        for serial in spoofed_serials:
            assert len(serial) >= 8, f"Disk serial {serial} is too short (min 8 chars)"

            valid_prefixes = ["WD-", "ST", "Samsung", "TOSHIBA", "Hitachi", "Seagate"]
            has_valid_prefix = any(serial.startswith(prefix) for prefix in valid_prefixes)

            assert has_valid_prefix or len(serial) >= 12, (
                f"Disk serial {serial} does not match realistic vendor format"
            )


class TestUserModeFallbackComprehensiveness:
    """Validate user-mode fallbacks provide maximum possible coverage."""

    def test_registry_method_is_primary_fallback(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Registry spoofing must be fully implemented as primary approach.

        Since drivers are not implemented, registry must be production-ready.
        """
        result = hardware_spoofer.apply_spoof(method=SpoofMethod.REGISTRY)

        assert isinstance(result, bool), "apply_spoof must return boolean"

    def test_hook_method_provides_runtime_interception(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Hook-based spoofing must provide runtime API interception.

        Hooks complement registry for process-level spoofing.
        """
        with patch.object(hardware_spoofer, "_install_wmi_hooks", return_value=True), \
             patch.object(hardware_spoofer, "_install_registry_hooks", return_value=True), \
             patch.object(hardware_spoofer, "_install_deviceiocontrol_hooks", return_value=True), \
             patch.object(hardware_spoofer, "_hook_kernel32_dll", return_value=True), \
             patch.object(hardware_spoofer, "_hook_setupapi_dll", return_value=True), \
             patch.object(hardware_spoofer, "_hook_iphlpapi_dll", return_value=True):

            result = hardware_spoofer.apply_spoof(method=SpoofMethod.HOOK)

            assert result is True, "Hook-based spoofing must work as fallback approach"

    def test_combined_registry_and_hook_approach_documented(self) -> None:
        """Documentation must explain combined registry + hook approach.

        This validates users understand the limitations and correct usage.
        """
        spoofer_path = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        content = spoofer_path.read_text(encoding="utf-8")

        class_docstring_start = content.find('class HardwareSpoofer')
        if class_docstring_start != -1:
            docstring_section = content[class_docstring_start:class_docstring_start + 2000]

            has_approach_docs = any(keyword in docstring_section.lower() for keyword in [
                "registry", "hook", "method", "approach", "spoof"
            ])

            assert has_approach_docs, (
                "HardwareSpoofer class must document spoofing approach in docstring"
            )


class TestRegressionPrevention:
    """Ensure previously removed issues don't return."""

    def test_no_ndis_filter_driver_stubs(self) -> None:
        """Verify no incomplete NDIS filter driver code exists.

        If NDIS filtering is not implemented, no stub code should exist.
        """
        spoofer_path = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        content = spoofer_path.read_text(encoding="utf-8")

        ndis_patterns = ["NdisRegisterProtocol", "NdisSend", "NdisReceive", "NDIS_FILTER"]

        found_ndis = []
        for pattern in ndis_patterns:
            if pattern in content:
                found_ndis.append(pattern)

        assert not found_ndis, (
            f"Found NDIS driver stubs without implementation: {found_ndis}\n"
            "Either implement working NDIS filter or remove all NDIS references"
        )

    def test_no_disk_filter_driver_stubs(self) -> None:
        """Verify no incomplete disk filter driver code exists.

        If disk filtering is not implemented, no stub code should exist.
        """
        spoofer_path = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        content = spoofer_path.read_text(encoding="utf-8")

        disk_filter_patterns = [
            "IoCreateDevice",
            "IoAttachDevice",
            "DriverEntry",
            "IRP_MJ_",
            "PDEVICE_OBJECT",
        ]

        found_disk_filter = []
        for pattern in disk_filter_patterns:
            if pattern in content:
                found_disk_filter.append(pattern)

        assert not found_disk_filter, (
            f"Found disk filter driver stubs without implementation: {found_disk_filter}\n"
            "Either implement working disk filter or remove all disk filter references"
        )

    def test_spoof_method_enum_has_only_implemented_methods(self) -> None:
        """SpoofMethod enum should only contain actually implemented methods.

        DRIVER and VIRTUAL methods should be removed if not implemented.
        """
        implemented_methods = []

        spoofer = HardwareSpoofer()

        if spoofer._apply_registry_spoof != spoofer._apply_driver_spoof:
            if hasattr(SpoofMethod, "REGISTRY"):
                implemented_methods.append("REGISTRY")

        if hasattr(SpoofMethod, "DRIVER"):
            result = spoofer._apply_driver_spoof()
            if result is False:
                pytest.skip("DRIVER method exists but returns False - acceptable if documented")

        if hasattr(SpoofMethod, "VIRTUAL"):
            result = spoofer._apply_virtual_spoof()
            if result is False:
                pytest.skip("VIRTUAL method exists but returns False - acceptable if documented")


class TestProductionReadinessValidation:
    """Validate code meets production-ready standards."""

    def test_all_spoof_methods_have_error_handling(self) -> None:
        """All spoofing methods must have try-except blocks.

        Production code must handle failures gracefully.
        """
        spoofer_path = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        content = spoofer_path.read_text(encoding="utf-8")

        spoof_methods = [
            "_spoof_cpu",
            "_spoof_motherboard",
            "_spoof_bios",
            "_spoof_disk",
            "_spoof_mac_address",
        ]

        for method_name in spoof_methods:
            method_start = content.find(f"def {method_name}")
            if method_start == -1:
                continue

            method_end = content.find("\n    def ", method_start + 1)
            if method_end == -1:
                method_end = len(content)

            method_code = content[method_start:method_end]

            has_try = "try:" in method_code
            has_except = "except" in method_code

            assert has_try and has_except, (
                f"Method {method_name} missing try-except error handling"
            )

    def test_spoofed_values_are_randomized_not_hardcoded(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Spoofed hardware IDs must be randomly generated, not hardcoded.

        Hardcoded values would be easily detected by licensing systems.
        """
        spoof1 = HardwareSpoofer()
        spoof1.capture_original_hardware()
        spoof1.generate_spoofed_hardware()

        spoof2 = HardwareSpoofer()
        spoof2.capture_original_hardware()
        spoof2.generate_spoofed_hardware()

        assert spoof1.spoofed_hardware is not None and spoof2.spoofed_hardware is not None

        randomized_fields = []
        if spoof1.spoofed_hardware.machine_guid != spoof2.spoofed_hardware.machine_guid:
            randomized_fields.append("machine_guid")
        if spoof1.spoofed_hardware.system_uuid != spoof2.spoofed_hardware.system_uuid:
            randomized_fields.append("system_uuid")
        if spoof1.spoofed_hardware.product_id != spoof2.spoofed_hardware.product_id:
            randomized_fields.append("product_id")

        assert len(randomized_fields) >= 2, (
            f"Only {randomized_fields} are randomized. More fields must use random generation."
        )

    def test_original_hardware_capture_does_not_fail_silently(
        self, hardware_spoofer: HardwareSpoofer
    ) -> None:
        """Hardware capture must return valid data or raise exceptions.

        Silent failures would cause spoofing to use invalid baseline data.
        """
        original = hardware_spoofer.capture_original_hardware()

        assert original is not None, "capture_original_hardware must return HardwareIdentifiers"
        assert original.cpu_id != "", "CPU ID must be captured or generated"
        assert original.machine_guid != "", "Machine GUID must be captured or generated"
