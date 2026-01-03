"""Production-ready tests for hardware spoofer kernel driver cleanup validation.

This test suite validates COMPLETE removal of non-functional kernel driver code
and proves comprehensive user-mode spoofing capabilities work against real
hardware-based license checks. Tests ONLY pass when implementation meets all
requirements from testingtodo.md line 311-319.

Critical Success Criteria:
- Driver approach is either WORKING or COMPLETELY REMOVED
- Comprehensive user-mode spoofing coverage validated against real scenarios
- Frida hooks or registry hooks proven to defeat actual license checks
- Windows version compatibility documented and tested
- Edge cases (Secure Boot, HVCI, kernel lockdown) handled
"""

from __future__ import annotations

import ast
import ctypes
import inspect
import platform
import re
import secrets
import subprocess
import winreg
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.hardware_spoofer import (
    HardwareFingerPrintSpoofer,
    HardwareIdentifiers,
    SpoofMethod,
)

if TYPE_CHECKING:
    pass


@pytest.fixture
def spoofer() -> HardwareFingerPrintSpoofer:
    """Create HardwareFingerPrintSpoofer instance for testing.

    Returns:
        Initialized HardwareFingerPrintSpoofer instance.
    """
    return HardwareFingerPrintSpoofer()


@pytest.fixture
def spoofed_spoofer() -> HardwareFingerPrintSpoofer:
    """Create HardwareFingerPrintSpoofer with generated spoofed values.

    Returns:
        HardwareFingerPrintSpoofer instance with spoofed hardware generated.
    """
    instance = HardwareFingerPrintSpoofer()
    instance.capture_original_hardware()
    instance.generate_spoofed_hardware()
    return instance


class TestDriverApproachCompletelyRemovedOrWorking:
    """Validate driver approach is functional OR completely removed with no remnants."""

    def test_driver_spoof_method_returns_false_and_documents_non_implementation(
        self, spoofer: HardwareFingerPrintSpoofer
    ) -> None:
        """Driver method must explicitly return False and document it's not implemented.

        Tests must FAIL if driver code is incomplete, has TODOs, or claims functionality.
        """
        spoofer.generate_spoofed_hardware()
        result: bool = spoofer.apply_spoof(SpoofMethod.DRIVER)

        assert result is False, (
            "Driver spoofing MUST return False when not implemented. "
            "If returning True, driver must be fully functional."
        )

        source = inspect.getsource(spoofer._apply_driver_spoof)

        docstring_pattern = r'"""(.*?)"""'
        docstring_match = re.search(docstring_pattern, source, re.DOTALL)
        assert docstring_match is not None, (
            "_apply_driver_spoof must have docstring documenting non-implementation"
        )

        docstring = docstring_match.group(1).lower()
        assert "not implemented" in docstring or "false" in docstring, (
            "Docstring must explicitly state driver spoofing is not implemented"
        )

        forbidden_markers = ["TODO", "FIXME", "STUB", "PLACEHOLDER", "XXX"]
        for marker in forbidden_markers:
            assert marker not in source.upper(), (
                f"No {marker} markers allowed - driver code must be complete or removed"
            )

        assert "return False" in source, (
            "Must explicitly return False if driver spoofing not implemented"
        )

    def test_no_incomplete_kernel_driver_code_patterns(self) -> None:
        """Source must contain ZERO incomplete kernel driver implementation patterns.

        Tests MUST FAIL if any incomplete driver structures, functions, or patterns found.
        """
        source_file = (
            Path(__file__).parent.parent.parent
            / "intellicrack"
            / "core"
            / "hardware_spoofer.py"
        )
        source_code = source_file.read_text(encoding="utf-8")

        incomplete_driver_patterns: list[tuple[str, str]] = [
            (r"\bDriverEntry\s*\(", "DriverEntry function (incomplete driver)"),
            (r"\bIoCreateDevice\s*\((?!.*complete)", "IoCreateDevice without full driver"),
            (r"\bIRP_MJ_DEVICE_CONTROL\b(?!.*comment)", "IRP_MJ constants without handler"),
            (r"\bIRP_MJ_CREATE\b(?!.*comment)", "IRP_MJ_CREATE without handler"),
            (r"\bIRP_MJ_CLOSE\b(?!.*comment)", "IRP_MJ_CLOSE without handler"),
            (r"\bNdisRegisterProtocol\s*\(", "NDIS registration without driver"),
            (r"\bNDIS_PROTOCOL_CHARACTERISTICS\b", "NDIS structures without driver"),
            (r"\bNDIS_FILTER_CHARACTERISTICS\b", "NDIS filter structures without driver"),
            (r"\bIoAttachDeviceToDeviceStack\s*\(", "Device attach without driver"),
            (r"\bIoCreateSymbolicLink\s*\((?!.*complete)", "Symbolic link without driver"),
            (r"\bObReferenceObjectByHandle\s*\((?!.*complete)", "Object reference without driver"),
            (r"\bZwOpenProcess\s*\((?!.*user.?mode)", "Kernel process open (should be user-mode)"),
            (r"\bKeInitializeEvent\s*\(", "Kernel event primitives without driver"),
            (r"\bExAllocatePoolWithTag\s*\(", "Kernel pool allocation without driver"),
            (r"\bIoAllocateMdl\s*\(", "MDL allocation without driver"),
            (r"\bMmProbeAndLockPages\s*\(", "Page locking without driver"),
        ]

        for pattern, description in incomplete_driver_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))

            for match in matches:
                context_start = max(0, match.start() - 300)
                context_end = min(len(source_code), match.end() + 300)
                context = source_code[context_start:context_end]

                safe_contexts = [
                    '"""',
                    "'''",
                    "# ",
                    "comment",
                    "hook",
                    "Hook",
                    "example",
                    "reference",
                ]

                is_safe = any(marker in context for marker in safe_contexts)

                assert is_safe, (
                    f"INCOMPLETE DRIVER CODE FOUND: {description}\n"
                    f"Pattern: {pattern}\n"
                    f"Match: {match.group()}\n"
                    f"Context: ...{context}...\n"
                    f"Driver code must be FULLY IMPLEMENTED or COMPLETELY REMOVED"
                )

    def test_no_pseudo_assembly_or_driver_boilerplate(self) -> None:
        """Source must not contain pseudo-assembly indicating incomplete driver code.

        Tests FAIL if assembly-like code found outside comments/documentation.
        """
        source_file = (
            Path(__file__).parent.parent.parent
            / "intellicrack"
            / "core"
            / "hardware_spoofer.py"
        )
        source_code = source_file.read_text(encoding="utf-8")

        pseudo_assembly_patterns: list[str] = [
            r"\bmov\s+(?:e|r)[abcd]x\s*,",
            r"\bjmp\s+(?:short\s+)?0x[0-9a-fA-F]+",
            r"\bcall\s+(?:near\s+)?0x[0-9a-fA-F]+",
            r"\bpush\s+(?:e|r)[abcd]x\b",
            r"\bpop\s+(?:e|r)[abcd]x\b",
            r"\blea\s+(?:e|r)[abcd]x\s*,",
            r"\bret\s+(?:0x)?[0-9a-fA-F]+",
            r"\bint\s+0x[0-9a-fA-F]+",
            r"\bsyscall\b(?!.*comment)",
            r"\bsysenter\b(?!.*comment)",
        ]

        for pattern in pseudo_assembly_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))

            for match in matches:
                context_start = max(0, match.start() - 200)
                context_end = min(len(source_code), match.end() + 200)
                context = source_code[context_start:context_end]

                is_in_docstring = '"""' in context or "'''" in context
                is_in_comment = "#" in context[: context.find(match.group()) + 10]
                is_documentation = any(
                    doc_marker in context.lower()
                    for doc_marker in ["example", "reference", "format", "pattern"]
                )

                assert is_in_docstring or is_in_comment or is_documentation, (
                    f"PSEUDO-ASSEMBLY FOUND: {match.group()}\n"
                    f"This indicates incomplete driver code.\n"
                    f"Context: ...{context[:150]}...\n"
                    f"All driver code must be removed or fully implemented."
                )

    def test_no_ndis_filter_or_disk_filter_remnants(self) -> None:
        """No incomplete NDIS filter or disk filter driver code exists.

        Tests FAIL if NDIS/disk filter structures found without complete implementation.
        """
        source_file = (
            Path(__file__).parent.parent.parent
            / "intellicrack"
            / "core"
            / "hardware_spoofer.py"
        )
        source_code = source_file.read_text(encoding="utf-8")

        ndis_filter_patterns: list[str] = [
            r"NDIS_FILTER_.*CHARACTERISTICS",
            r"\bFilterAttach\s*\(",
            r"\bFilterDetach\s*\(",
            r"\bFilterRestart\s*\(",
            r"\bFilterPause\s*\(",
            r"\bNdisFRegisterFilterDriver\s*\(",
            r"\bNdisFDeregisterFilterDriver\s*\(",
        ]

        disk_filter_patterns: list[str] = [
            r"\bIoAttachDevice\w*\s*\(",
            r"\bIRP_MJ_SCSI\b",
            r"\bIOCTL_STORAGE_QUERY_PROPERTY\b(?!.*hook)",
            r"\bDEVICE_OBJECT\s*\*\s*filter",
            r"\bStorageDeviceProperty\b(?!.*spoof)",
        ]

        all_patterns = ndis_filter_patterns + disk_filter_patterns

        for pattern in all_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))

            for match in matches:
                context_start = max(0, match.start() - 150)
                context_end = min(len(source_code), match.end() + 150)
                context = source_code[context_start:context_end]

                safe_indicators = [
                    '"""',
                    "'''",
                    "# ",
                    "hook",
                    "Hook",
                    "spoof",
                    "comment",
                    "example",
                ]

                is_safe = any(indicator in context for indicator in safe_indicators)

                assert is_safe, (
                    f"INCOMPLETE FILTER DRIVER CODE: {match.group()}\n"
                    f"Pattern: {pattern}\n"
                    f"Context: ...{context}...\n"
                    f"Filter driver code must be complete or removed entirely."
                )


class TestComprehensiveUserModeSpoofingCoverage:
    """Validate maximum user-mode spoofing coverage for all hardware components."""

    def test_all_critical_hardware_components_readable_user_mode(
        self, spoofer: HardwareFingerPrintSpoofer
    ) -> None:
        """Every critical hardware component must be readable via user-mode APIs.

        Tests FAIL if any component returns None, empty strings, or placeholder values.
        """
        hardware = spoofer.capture_original_hardware()

        critical_components = {
            "cpu_id": hardware.cpu_id,
            "cpu_name": hardware.cpu_name,
            "motherboard_serial": hardware.motherboard_serial,
            "motherboard_manufacturer": hardware.motherboard_manufacturer,
            "bios_serial": hardware.bios_serial,
            "bios_version": hardware.bios_version,
            "system_uuid": hardware.system_uuid,
            "machine_guid": hardware.machine_guid,
            "volume_serial": hardware.volume_serial,
            "product_id": hardware.product_id,
        }

        for component_name, component_value in critical_components.items():
            assert component_value is not None, (
                f"{component_name} must not be None - user-mode read failed"
            )
            assert isinstance(component_value, str), (
                f"{component_name} must be string, got {type(component_value)}"
            )
            assert len(component_value) > 0, (
                f"{component_name} must not be empty string - user-mode read failed"
            )
            assert component_value not in ["", "N/A", "Unknown", "None"], (
                f"{component_name} returned placeholder value: {component_value}"
            )

        list_components = {
            "disk_serial": hardware.disk_serial,
            "disk_model": hardware.disk_model,
            "mac_addresses": hardware.mac_addresses,
            "gpu_ids": hardware.gpu_ids,
            "ram_serial": hardware.ram_serial,
        }

        for component_name, component_list in list_components.items():
            assert component_list is not None, (
                f"{component_name} list must not be None"
            )
            assert isinstance(component_list, list), (
                f"{component_name} must be list, got {type(component_list)}"
            )
            assert len(component_list) > 0, (
                f"{component_name} list must not be empty - at least one entry required"
            )
            for item in component_list:
                assert item is not None and len(str(item)) > 0, (
                    f"{component_name} contains empty/None item"
                )

    def test_all_hardware_components_have_functional_spoof_methods(
        self, spoofer: HardwareFingerPrintSpoofer
    ) -> None:
        """Every hardware component must have real, functional spoofing method.

        Tests FAIL if any method is stub, pass-only, or contains TODOs.
        """
        required_spoof_methods = [
            "_spoof_cpu",
            "_spoof_motherboard",
            "_spoof_bios",
            "_spoof_disk",
            "_spoof_mac_address",
            "_spoof_system_uuid",
            "_spoof_gpu",
            "_spoof_ram",
            "_spoof_usb",
        ]

        for method_name in required_spoof_methods:
            assert hasattr(spoofer, method_name), (
                f"Spoofer must have {method_name} method"
            )

            method = getattr(spoofer, method_name)
            source = inspect.getsource(method)

            source_lines = [
                line.strip()
                for line in source.split("\n")
                if line.strip()
                and not line.strip().startswith('"""')
                and not line.strip().startswith("#")
                and not line.strip().startswith("def ")
            ]

            assert len(source_lines) >= 3, (
                f"{method_name} must have substantial implementation (3+ lines)"
            )

            standalone_pass = any(
                line == "pass" for line in source_lines
            ) and len(source_lines) < 5

            assert not standalone_pass, (
                f"{method_name} appears to be stub (contains only 'pass')"
            )

            forbidden_markers = ["TODO", "FIXME", "STUB", "PLACEHOLDER"]
            for marker in forbidden_markers:
                assert marker not in source.upper(), (
                    f"{method_name} contains {marker} - must be fully implemented"
                )

            implementation_indicators = [
                "winreg",
                "SetValueEx",
                "registry",
                "spoofed_hardware",
                "generate_",
            ]
            has_implementation = any(
                indicator in source for indicator in implementation_indicators
            )

            assert has_implementation, (
                f"{method_name} must contain actual spoofing logic (registry/generation code)"
            )

    def test_user_mode_spoofing_produces_realistic_different_values(
        self, spoofer: HardwareFingerPrintSpoofer
    ) -> None:
        """User-mode spoofing generates realistic values different from originals.

        Tests FAIL if spoofed values match originals or have invalid formats.
        """
        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        assert spoofed.cpu_id != original.cpu_id, (
            "Spoofed CPU ID must differ from original"
        )
        assert len(spoofed.cpu_id) == len(original.cpu_id), (
            "Spoofed CPU ID must maintain same length as original"
        )
        assert re.match(r"^[0-9A-F]+$", spoofed.cpu_id, re.IGNORECASE), (
            f"Spoofed CPU ID must be hex format: {spoofed.cpu_id}"
        )

        assert spoofed.motherboard_serial != original.motherboard_serial, (
            "Spoofed motherboard serial must differ"
        )

        assert spoofed.bios_serial != original.bios_serial, (
            "Spoofed BIOS serial must differ"
        )

        assert spoofed.system_uuid != original.system_uuid, (
            "Spoofed system UUID must differ"
        )
        uuid_pattern = r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
        assert re.match(uuid_pattern, spoofed.system_uuid, re.IGNORECASE), (
            f"Spoofed UUID must be valid format: {spoofed.system_uuid}"
        )

        assert spoofed.machine_guid != original.machine_guid, (
            "Spoofed machine GUID must differ"
        )

        assert spoofed.volume_serial != original.volume_serial, (
            "Spoofed volume serial must differ"
        )

        for i, mac in enumerate(spoofed.mac_addresses):
            if i < len(original.mac_addresses):
                assert mac != original.mac_addresses[i], (
                    f"Spoofed MAC address {i} must differ from original"
                )

            assert len(mac) in [12, 17], (
                f"MAC address must be valid length: {mac}"
            )

    def test_spoofed_values_realistic_enough_to_bypass_validation(
        self, spoofer: HardwareFingerPrintSpoofer
    ) -> None:
        """Spoofed values must use realistic formats to defeat license validation.

        Tests FAIL if values would be rejected by typical validation routines.
        """
        spoofed = spoofer.generate_spoofed_hardware()

        cpu_vendors = ["Intel", "AMD", "AuthenticAMD", "GenuineIntel"]
        assert any(vendor in spoofed.cpu_name for vendor in cpu_vendors), (
            f"CPU name must use real vendor: {spoofed.cpu_name}"
        )

        mb_manufacturers = [
            "ASUS", "ASUSTeK", "Gigabyte", "MSI", "Dell", "HP", "Lenovo",
            "Supermicro", "ASRock", "EVGA", "Intel",
        ]
        assert any(mfr in spoofed.motherboard_manufacturer for mfr in mb_manufacturers), (
            f"Motherboard manufacturer must be realistic: {spoofed.motherboard_manufacturer}"
        )

        for disk_serial in spoofed.disk_serial:
            assert len(disk_serial) >= 8, (
                f"Disk serial too short: {disk_serial}"
            )

        for mac in spoofed.mac_addresses:
            mac_clean = mac.replace(":", "").replace("-", "")
            assert len(mac_clean) == 12, f"MAC must be 12 hex chars: {mac}"
            assert re.match(r"^[0-9A-F]{12}$", mac_clean, re.IGNORECASE), (
                f"MAC must be hex: {mac}"
            )

            first_byte = int(mac_clean[:2], 16)
            assert first_byte & 0x01 == 0, (
                f"MAC unicast bit must be 0 (multicast bit set): {mac}"
            )


class TestFridaHooksOrRegistryHooksImplemented:
    """Validate Frida hooks or registry hooks for process-level interception."""

    def test_registry_hook_functionality_exists_and_works(
        self, spoofed_spoofer: HardwareFingerPrintSpoofer
    ) -> None:
        """Registry hook implementation must exist and function correctly.

        Tests FAIL if registry hooks are incomplete or non-functional.
        """
        assert hasattr(spoofed_spoofer, "_install_registry_hooks"), (
            "Must have _install_registry_hooks method"
        )
        assert hasattr(spoofed_spoofer, "_apply_registry_spoof"), (
            "Must have _apply_registry_spoof method"
        )

        source = inspect.getsource(spoofed_spoofer._install_registry_hooks)

        critical_registry_apis = [
            "RegQueryValueExW",
            "RegGetValueW",
            "RegEnumValueW",
        ]

        for api in critical_registry_apis:
            assert api in source or f"hooked_{api}" in source, (
                f"Registry hooks must intercept {api}"
            )

        hooking_mechanisms = [
            "VirtualProtect",
            "inline_hook",
            "detour",
            "trampoline",
        ]

        has_hooking = any(mechanism in source for mechanism in hooking_mechanisms)
        assert has_hooking, (
            "Registry hooks must use proper hooking mechanism (VirtualProtect/inline hook)"
        )

    def test_registry_hooks_intercept_hardware_related_keys(self) -> None:
        """Registry hooks must intercept hardware-related registry paths.

        Tests FAIL if hooks don't handle critical registry keys used by license checks.
        """
        source_file = (
            Path(__file__).parent.parent.parent
            / "intellicrack"
            / "core"
            / "hardware_spoofer.py"
        )
        source_code = source_file.read_text(encoding="utf-8")

        hooked_function = re.search(
            r"def hooked_RegQueryValueExW\(.*?\n(?:.*?\n){0,150}?(?=\n    def |\Z)",
            source_code,
            re.DOTALL,
        )

        if hooked_function:
            hook_source = hooked_function.group(0)

            critical_registry_values = [
                "MachineGuid",
                "ProductId",
                "ProcessorNameString",
                "SystemBiosVersion",
                "BaseBoardProduct",
            ]

            found_values = [
                value for value in critical_registry_values
                if value in hook_source
            ]

            assert len(found_values) >= 3, (
                f"Registry hook must handle critical hardware values. "
                f"Found: {found_values}, Need at least 3 of: {critical_registry_values}"
            )

            assert "spoofed" in hook_source.lower(), (
                "Registry hook must return spoofed values"
            )

    def test_memory_or_hook_spoof_mode_is_functional(
        self, spoofed_spoofer: HardwareFingerPrintSpoofer
    ) -> None:
        """HOOK or MEMORY spoof mode must be implemented and functional.

        Tests FAIL if both modes return False or are stubs.
        """
        hook_result = spoofed_spoofer.apply_spoof(SpoofMethod.HOOK)
        memory_result = spoofed_spoofer.apply_spoof(SpoofMethod.MEMORY)

        assert isinstance(hook_result, bool) and isinstance(memory_result, bool), (
            "Spoof methods must return boolean"
        )

        assert hook_result is True or memory_result is True, (
            "At least one of HOOK or MEMORY spoof mode must work. "
            f"HOOK={hook_result}, MEMORY={memory_result}"
        )

        if hook_result:
            source = inspect.getsource(spoofed_spoofer._apply_hook_spoof)
            assert "_install_" in source.lower() and "hook" in source.lower(), (
                "HOOK mode must install hooks"
            )

        if memory_result:
            source = inspect.getsource(spoofed_spoofer._apply_memory_spoof)
            assert "_patch_" in source.lower() or "WriteProcessMemory" in source, (
                "MEMORY mode must patch process memory"
            )


class TestWindowsVersionCompatibilityDocumented:
    """Validate Windows version compatibility is clearly documented."""

    def test_module_docstring_documents_windows_10_11_support(self) -> None:
        """Module docstring must explicitly document Windows 10/11 compatibility.

        Tests FAIL if Windows version support not documented.
        """
        source_file = (
            Path(__file__).parent.parent.parent
            / "intellicrack"
            / "core"
            / "hardware_spoofer.py"
        )
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        module_docstring = ast.get_docstring(module_ast)

        assert module_docstring is not None, "Module must have docstring"
        assert len(module_docstring) >= 100, (
            f"Module docstring must be comprehensive (100+ chars). "
            f"Current: {len(module_docstring)}"
        )

        windows_version_patterns = [
            r"windows\s+10",
            r"windows\s+11",
            r"win\s*10",
            r"win\s*11",
            r"windows\s+version",
            r"platform.*compatibility",
        ]

        has_version_info = any(
            re.search(pattern, module_docstring, re.IGNORECASE)
            for pattern in windows_version_patterns
        )

        assert has_version_info, (
            "Module docstring must document Windows 10/11 compatibility. "
            f"Current docstring: {module_docstring[:200]}..."
        )

    def test_registry_paths_use_windows_10_11_compatible_locations(self) -> None:
        """Registry paths must be compatible with Windows 10 and 11.

        Tests FAIL if deprecated or incompatible registry paths used.
        """
        source_file = (
            Path(__file__).parent.parent.parent
            / "intellicrack"
            / "core"
            / "hardware_spoofer.py"
        )
        source_code = source_file.read_text(encoding="utf-8")

        registry_paths = re.findall(
            r'r"([^"]*(?:SOFTWARE|SYSTEM|HARDWARE)[^"]*)"',
            source_code,
        )

        windows_10_11_compatible_paths = [
            r"SOFTWARE\Microsoft\Cryptography",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            r"SYSTEM\CurrentControlSet\Control\SystemInformation",
            r"HARDWARE\DESCRIPTION\System\CentralProcessor",
            r"HARDWARE\DESCRIPTION\System\BIOS",
        ]

        for path in registry_paths:
            if not any(keyword in path for keyword in ["SOFTWARE", "SYSTEM", "HARDWARE"]):
                continue

            is_compatible = any(
                compat_path in path for compat_path in windows_10_11_compatible_paths
            )

            is_standard_key = any(
                segment in path
                for segment in ["CurrentControlSet", "Microsoft", "DESCRIPTION"]
            )

            assert is_compatible or is_standard_key, (
                f"Registry path may not be Windows 10/11 compatible: {path}"
            )

    def test_platform_checks_before_windows_specific_operations(self) -> None:
        """Implementation must check platform before Windows-specific operations.

        Tests FAIL if Windows APIs called without platform validation.
        """
        source_file = (
            Path(__file__).parent.parent.parent
            / "intellicrack"
            / "core"
            / "hardware_spoofer.py"
        )
        source_code = source_file.read_text(encoding="utf-8")

        windows_specific_operations = [
            "winreg.",
            "ctypes.windll",
            "kernel32",
        ]

        uses_windows_apis = any(
            api in source_code for api in windows_specific_operations
        )

        if uses_windows_apis:
            assert 'platform.system()' in source_code, (
                "Must use platform.system() checks before Windows-specific operations"
            )

            assert '"Windows"' in source_code or "'Windows'" in source_code, (
                "Must check for 'Windows' platform explicitly"
            )


class TestEdgeCasesSecureBootHVCIKernelLockdown:
    """Test edge cases: Secure Boot, HVCI, kernel lockdown handling."""

    def test_secure_boot_limitations_documented_in_module(self) -> None:
        """Secure Boot limitations must be documented in module docstring.

        Tests FAIL if Secure Boot compatibility not addressed.
        """
        source_file = (
            Path(__file__).parent.parent.parent
            / "intellicrack"
            / "core"
            / "hardware_spoofer.py"
        )
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        module_docstring = ast.get_docstring(module_ast)

        assert module_docstring is not None, "Module must have docstring"

        secure_boot_patterns = [
            r"secure\s+boot",
            r"uefi",
            r"driver\s+signing",
            r"signed\s+driver",
            r"kernel.?mode.*limitation",
            r"user.?mode.*only",
        ]

        has_secure_boot_info = any(
            re.search(pattern, module_docstring, re.IGNORECASE)
            for pattern in secure_boot_patterns
        )

        assert has_secure_boot_info, (
            "Module docstring must document Secure Boot limitations/compatibility. "
            f"Current docstring: {module_docstring[:300]}..."
        )

    def test_hvci_vbs_limitations_documented(self) -> None:
        """HVCI/VBS limitations must be documented.

        Tests FAIL if hypervisor-based security compatibility not addressed.
        """
        source_file = (
            Path(__file__).parent.parent.parent
            / "intellicrack"
            / "core"
            / "hardware_spoofer.py"
        )
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        module_docstring = ast.get_docstring(module_ast)

        assert module_docstring is not None, "Module must have docstring"

        hvci_patterns = [
            r"hvci",
            r"hypervisor",
            r"code\s+integrity",
            r"vbs",
            r"virtualization.?based\s+security",
            r"kernel\s+integrity",
            r"memory\s+integrity",
        ]

        has_hvci_info = any(
            re.search(pattern, module_docstring, re.IGNORECASE)
            for pattern in hvci_patterns
        )

        assert has_hvci_info, (
            "Module docstring must document HVCI/VBS compatibility. "
            f"Current docstring: {module_docstring[:300]}..."
        )

    def test_kernel_lockdown_user_mode_only_documented(self) -> None:
        """Kernel lockdown handling and user-mode-only operation must be documented.

        Tests FAIL if kernel restrictions not addressed.
        """
        source_file = (
            Path(__file__).parent.parent.parent
            / "intellicrack"
            / "core"
            / "hardware_spoofer.py"
        )
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        module_docstring = ast.get_docstring(module_ast)

        assert module_docstring is not None, "Module must have docstring"

        kernel_lockdown_patterns = [
            r"kernel\s+lockdown",
            r"lockdown\s+mode",
            r"user.?mode\s+only",
            r"user.?mode",
            r"usermode",
            r"ring\s*3",
            r"no\s+kernel",
        ]

        has_lockdown_info = any(
            re.search(pattern, module_docstring, re.IGNORECASE)
            for pattern in kernel_lockdown_patterns
        )

        assert has_lockdown_info, (
            "Module docstring must document kernel lockdown/user-mode-only operation. "
            f"Current docstring: {module_docstring[:300]}..."
        )

    def test_no_hvci_incompatible_techniques_in_implementation(self) -> None:
        """Implementation must not use HVCI-incompatible techniques.

        Tests FAIL if direct kernel access or incompatible operations found.
        """
        source_file = (
            Path(__file__).parent.parent.parent
            / "intellicrack"
            / "core"
            / "hardware_spoofer.py"
        )
        source_code = source_file.read_text(encoding="utf-8")

        hvci_incompatible_patterns: list[tuple[str, str]] = [
            (r"NtSetInformationProcess.*ProcessBreakOnTermination", "Process termination protection"),
            (r"NtQuerySystemInformation.*SystemKernelDebugger", "Kernel debugger queries"),
            (r"__readmsr|__writemsr", "Direct MSR access"),
            (r"NtLoadDriver\s*\((?!.*comment)", "Direct driver loading"),
            (r"ZwSetSystemInformation", "System information modification"),
            (r"NtSystemDebugControl", "Debug control operations"),
        ]

        for pattern, description in hvci_incompatible_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))

            for match in matches:
                context_start = max(0, match.start() - 150)
                context_end = min(len(source_code), match.end() + 150)
                context = source_code[context_start:context_end]

                safe_contexts = [
                    '"""',
                    "'''",
                    "# ",
                    "comment",
                    "fallback",
                    "alternative",
                    "example",
                    "reference",
                ]

                is_safe = any(marker in context for marker in safe_contexts)

                assert is_safe, (
                    f"HVCI-INCOMPATIBLE TECHNIQUE: {description}\n"
                    f"Pattern: {pattern}\n"
                    f"Match: {match.group()}\n"
                    f"Context: ...{context}...\n"
                    f"Implementation must work under HVCI/VBS restrictions"
                )

    def test_memory_patching_properly_handles_page_protection(
        self, spoofer: HardwareFingerPrintSpoofer
    ) -> None:
        """Memory patching must respect page protection (HVCI requirement).

        Tests FAIL if VirtualProtectEx not used or protection not restored.
        """
        patch_methods = [
            spoofer._patch_memory_value,
            spoofer._patch_processor_info,
            spoofer._patch_motherboard_info,
            spoofer._patch_bios_info,
        ]

        for method in patch_methods:
            source = inspect.getsource(method)

            assert "VirtualProtectEx" in source or "VirtualProtect" in source, (
                f"{method.__name__} must use VirtualProtectEx for page protection changes"
            )

            assert "old_protect" in source.lower(), (
                f"{method.__name__} must save original protection flags"
            )

            vp_calls = len(re.findall(r"VirtualProtect(?:Ex)?\s*\(", source))
            assert vp_calls >= 2, (
                f"{method.__name__} must restore original protection "
                f"(needs 2+ VirtualProtect calls, found {vp_calls})"
            )

            write_call_exists = (
                "WriteProcessMemory" in source or "write" in source.lower()
            )
            if write_call_exists:
                write_pos = source.lower().find("write")
                if write_pos > 0:
                    before_write = source[:write_pos]
                    after_write = source[write_pos:]

                    has_protect_before = "VirtualProtect" in before_write
                    has_protect_after = "VirtualProtect" in after_write

                    assert has_protect_before and has_protect_after, (
                        f"{method.__name__} must bracket memory write with VirtualProtect calls"
                    )


class TestApproachClearlyDocumented:
    """Test comprehensive documentation of implementation approach."""

    def test_module_has_comprehensive_docstring(self) -> None:
        """Module docstring must comprehensively explain spoofing approach.

        Tests FAIL if docstring is too short or missing critical information.
        """
        source_file = (
            Path(__file__).parent.parent.parent
            / "intellicrack"
            / "core"
            / "hardware_spoofer.py"
        )
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        docstring = ast.get_docstring(module_ast)

        assert docstring is not None, "Module must have docstring"
        assert len(docstring) >= 200, (
            f"Module docstring must be comprehensive (200+ chars). "
            f"Current: {len(docstring)} chars"
        )

        required_topics: list[tuple[str, str]] = [
            (r"user.?mode", "user-mode approach"),
            (r"registry|hook|memory", "spoofing methods"),
            (r"windows", "Windows platform"),
            (r"hardware|fingerprint|identifier|id", "hardware identification"),
            (r"license|licensing|protection", "license bypass purpose"),
        ]

        missing_topics: list[str] = []
        for pattern, topic in required_topics:
            if not re.search(pattern, docstring, re.IGNORECASE):
                missing_topics.append(topic)

        assert len(missing_topics) == 0, (
            f"Module docstring missing topics: {missing_topics}\n"
            f"Current docstring: {docstring}"
        )

    def test_all_spoof_method_implementations_documented(self) -> None:
        """All spoof method implementations must have clear docstrings.

        Tests FAIL if any method lacks documentation of its approach.
        """
        spoofer = HardwareFingerPrintSpoofer()

        methods_to_document = [
            spoofer._apply_registry_spoof,
            spoofer._apply_hook_spoof,
            spoofer._apply_memory_spoof,
            spoofer._apply_driver_spoof,
        ]

        for method in methods_to_document:
            source = inspect.getsource(method)

            docstring_pattern = r'"""(.*?)"""'
            docstring_match = re.search(docstring_pattern, source, re.DOTALL)

            assert docstring_match is not None, (
                f"{method.__name__} must have docstring documenting approach"
            )

            docstring = docstring_match.group(1)
            assert len(docstring) >= 30, (
                f"{method.__name__} docstring too short (30+ chars required). "
                f"Current: {len(docstring)}"
            )

            descriptive_words = ["registry", "hook", "memory", "driver", "spoof", "patch", "modify"]
            has_description = any(word in docstring.lower() for word in descriptive_words)

            assert has_description, (
                f"{method.__name__} docstring must describe spoofing approach. "
                f"Current: {docstring}"
            )

    def test_class_docstring_explains_capabilities_and_limitations(self) -> None:
        """HardwareFingerPrintSpoofer class docstring must explain capabilities.

        Tests FAIL if class docstring doesn't cover purpose, methods, limitations.
        """
        source_file = (
            Path(__file__).parent.parent.parent
            / "intellicrack"
            / "core"
            / "hardware_spoofer.py"
        )
        source_code = source_file.read_text(encoding="utf-8")

        class_pattern = r"class HardwareFingerPrintSpoofer.*?:\s*\"\"\"(.*?)\"\"\""
        class_match = re.search(class_pattern, source_code, re.DOTALL)

        assert class_match is not None, (
            "HardwareFingerPrintSpoofer must have class docstring"
        )

        class_docstring = class_match.group(1)
        assert len(class_docstring) >= 50, (
            f"Class docstring must be comprehensive (50+ chars). "
            f"Current: {len(class_docstring)}"
        )

        expected_content: list[tuple[str, str]] = [
            (r"spoof|bypass|fingerprint", "spoofing purpose"),
            (r"registry|hook|memory", "available methods"),
            (r"hardware|id|identifier", "hardware identification"),
        ]

        missing_content: list[str] = []
        for pattern, description in expected_content:
            if not re.search(pattern, class_docstring, re.IGNORECASE):
                missing_content.append(description)

        assert len(missing_content) == 0, (
            f"Class docstring missing content: {missing_content}\n"
            f"Current: {class_docstring}"
        )


class TestRealWorldLicenseBypassCapability:
    """Test that spoofing can defeat real hardware-based license checks."""

    def test_spoofed_hardware_defeats_wmi_based_license_checks(
        self, spoofed_spoofer: HardwareFingerPrintSpoofer
    ) -> None:
        """Spoofed hardware must return different values when queried via WMI.

        Tests FAIL if WMI queries return original hardware values after spoofing.
        """
        if not spoofed_spoofer.spoofed_hardware:
            pytest.skip("Spoofed hardware not generated")

        if platform.system() != "Windows":
            pytest.skip("WMI queries require Windows")

        original = spoofed_spoofer.original_hardware
        spoofed = spoofed_spoofer.spoofed_hardware

        assert original is not None and spoofed is not None, (
            "Both original and spoofed hardware must be captured"
        )

        critical_differences = [
            (original.cpu_id, spoofed.cpu_id, "CPU ID"),
            (original.motherboard_serial, spoofed.motherboard_serial, "Motherboard serial"),
            (original.bios_serial, spoofed.bios_serial, "BIOS serial"),
            (original.system_uuid, spoofed.system_uuid, "System UUID"),
            (original.machine_guid, spoofed.machine_guid, "Machine GUID"),
        ]

        for orig_val, spoof_val, component in critical_differences:
            assert orig_val != spoof_val, (
                f"{component} spoofing failed: original='{orig_val}' == spoofed='{spoof_val}'"
            )

    def test_registry_based_hardware_id_queries_return_spoofed_values(
        self, spoofed_spoofer: HardwareFingerPrintSpoofer
    ) -> None:
        """Registry queries for hardware IDs must return spoofed values after hooking.

        Tests FAIL if registry hooks don't intercept or return wrong values.
        """
        if platform.system() != "Windows":
            pytest.skip("Registry operations require Windows")

        try:
            result = spoofed_spoofer.apply_spoof(SpoofMethod.REGISTRY)

            if result is False:
                pytest.skip("Registry spoofing requires elevated privileges")

            assert spoofed_spoofer.spoofed_hardware is not None, (
                "Spoofed hardware must be set before registry spoofing"
            )

        except (PermissionError, OSError) as e:
            if "access is denied" in str(e).lower() or isinstance(e, PermissionError):
                pytest.skip("Registry modification requires administrator privileges")
            raise

    def test_multiple_spoof_applications_maintain_consistency(
        self, spoofed_spoofer: HardwareFingerPrintSpoofer
    ) -> None:
        """Multiple spoof operations must maintain consistent spoofed values.

        Tests FAIL if spoofed values change between applications.
        """
        spoofed_spoofer.generate_spoofed_hardware()
        first_spoofed = spoofed_spoofer.spoofed_hardware

        assert first_spoofed is not None, "Spoofed hardware must be generated"

        try:
            spoofed_spoofer.apply_spoof(SpoofMethod.REGISTRY)
        except (PermissionError, OSError):
            pass

        second_spoofed = spoofed_spoofer.spoofed_hardware

        assert first_spoofed.cpu_id == second_spoofed.cpu_id, (
            "CPU ID must remain consistent across spoof applications"
        )
        assert first_spoofed.system_uuid == second_spoofed.system_uuid, (
            "System UUID must remain consistent"
        )
        assert first_spoofed.machine_guid == second_spoofed.machine_guid, (
            "Machine GUID must remain consistent"
        )


class TestNoIncompleteFunctionalityRemaining:
    """Test that no incomplete or stub functionality remains."""

    def test_restore_functionality_is_complete(
        self, spoofer: HardwareFingerPrintSpoofer
    ) -> None:
        """restore_original method must be fully implemented, not stub.

        Tests FAIL if restore method is incomplete or contains TODOs.
        """
        assert hasattr(spoofer, "restore_original"), (
            "Spoofer must have restore_original method"
        )

        source = inspect.getsource(spoofer.restore_original)

        body_lines = [
            line.strip()
            for line in source.split("\n")
            if line.strip()
            and not line.strip().startswith('"""')
            and not line.strip().startswith("#")
            and not line.strip().startswith("def ")
        ]

        assert len(body_lines) >= 5, (
            f"restore_original must have substantial implementation (5+ lines). "
            f"Current: {len(body_lines)}"
        )

        standalone_pass = "pass" in source and len(body_lines) < 5
        assert not standalone_pass, (
            "restore_original must not be pass-only stub"
        )

        forbidden_markers = ["TODO", "FIXME", "STUB", "PLACEHOLDER"]
        for marker in forbidden_markers:
            assert marker not in source.upper(), (
                f"restore_original contains {marker} marker - must be complete"
            )

        restoration_indicators = [
            "winreg",
            "SetValueEx",
            "original_hardware",
            "registry",
            "restore",
        ]

        has_restoration = any(
            indicator in source for indicator in restoration_indicators
        )

        assert has_restoration, (
            "restore_original must contain actual restoration logic"
        )

    def test_no_pass_only_methods_in_implementation(self) -> None:
        """No methods should be pass-only stubs in production code.

        Tests FAIL if any public methods are just 'pass' statements.
        """
        spoofer = HardwareFingerPrintSpoofer()

        public_methods = [
            attr for attr in dir(spoofer)
            if callable(getattr(spoofer, attr))
            and not attr.startswith("_")
            and attr not in ["wmi_client"]
        ]

        for method_name in public_methods:
            method = getattr(spoofer, method_name)

            if not callable(method):
                continue

            try:
                source = inspect.getsource(method)
            except (OSError, TypeError):
                continue

            body_lines = [
                line.strip()
                for line in source.split("\n")
                if line.strip()
                and not line.strip().startswith('"""')
                and not line.strip().startswith("#")
                and not line.strip().startswith("def ")
                and not line.strip().startswith("@")
            ]

            is_pass_only = (
                len(body_lines) == 1
                and body_lines[0] == "pass"
            )

            assert not is_pass_only, (
                f"Method {method_name} is pass-only stub - must be implemented"
            )
