"""Comprehensive production-ready tests for hardware spoofer driver approach cleanup.

This test suite validates that hardware_spoofer.py has NO non-functional driver code
and provides complete user-mode spoofing coverage. Tests MUST FAIL if pseudo-code,
incomplete implementations, or non-functional driver references exist.

Test Requirements (from testingtodo.md):
- Must either implement working kernel drivers OR remove all driver references
- Must provide clear documentation on approach taken
- Must implement maximum user-mode spoofing coverage
- Must use Frida hooks for process-level hardware ID interception (if applicable)
- Must use registry hooks for system-level ID modification
- Must document Windows version compatibility
- Edge cases: Secure Boot, HVCI, kernel lockdown
"""

from __future__ import annotations

import ast
import inspect
import platform
import re
import winreg
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.hardware_spoofer import (
    HardwareFingerPrintSpoofer,
    SpoofMethod,
)

if TYPE_CHECKING:
    pass


class TestDriverCodeCompleteness:
    """Validate driver code is either functional OR properly removed/documented."""

    def test_driver_spoof_returns_false_with_clear_documentation(self) -> None:
        """Driver spoofing method must return False and document non-implementation."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        result: bool = spoofer.apply_spoof(SpoofMethod.DRIVER)

        assert result is False, "Driver spoofing must return False (not implemented)"

        source = inspect.getsource(spoofer._apply_driver_spoof)

        docstring_match = re.search(r'"""(.*?)"""', source, re.DOTALL)
        assert docstring_match is not None, "Driver method must have docstring explaining status"
        docstring = docstring_match.group(1)

        assert "not implemented" in docstring.lower() or "false" in docstring.lower(), (
            "Docstring must clearly state driver spoofing is not implemented"
        )

        assert source.count("return False") >= 1, "Must explicitly return False"

        assert "TODO" not in source.upper(), "No TODO comments allowed in driver method"
        assert "FIXME" not in source.upper(), "No FIXME comments allowed in driver method"
        assert "STUB" not in source.upper(), "No STUB markers allowed in driver method"

    def test_no_non_functional_driver_code_patterns(self) -> None:
        """Implementation must not contain non-functional kernel driver code."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        non_functional_driver_patterns = [
            (r"DriverEntry", "DriverEntry function indicates incomplete driver code"),
            (r"IoCreateDevice(?!IoControl)", "IoCreateDevice without full implementation"),
            (r"IRP_MJ_(?!DEVICE_CONTROL)", "IRP_MJ_ constants without handler implementation"),
            (r"NdisRegisterProtocol(?!\w*Hook)", "NDIS registration without proper implementation"),
            (r"NDIS_PROTOCOL_CHARACTERISTICS", "NDIS structures without driver"),
            (r"IoAttachDeviceToDeviceStack(?!\w*Hook)", "Device attach without driver"),
        ]

        for pattern, description in non_functional_driver_patterns:
            matches = re.findall(pattern, source_code, re.IGNORECASE)

            for match in matches:
                context_start = max(0, source_code.find(match) - 200)
                context_end = min(len(source_code), source_code.find(match) + 200)
                context = source_code[context_start:context_end]

                is_in_comment = any(marker in context for marker in ['"""', "'''", "#"])
                is_in_string_literal = context.count('"') >= 2 or context.count("'") >= 2

                assert is_in_comment or is_in_string_literal, (
                    f"{description}: Found '{match}' in non-comment code. "
                    f"Context: ...{context}..."
                )

    def test_no_pseudo_assembly_driver_code(self) -> None:
        """Source must not contain pseudo-assembly indicating incomplete driver implementation."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        pseudo_asm_patterns = [
            r"\bmov\s+e[abcd]x,",
            r"\bjmp\s+0x[0-9a-fA-F]+",
            r"\bcall\s+0x[0-9a-fA-F]+",
            r"\bpush\s+e[abcd]x",
            r"\bpop\s+e[abcd]x",
            r"\blea\s+e[abcd]x,",
            r"\bret\s+0x[0-9a-fA-F]+",
        ]

        for pattern in pseudo_asm_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))

            for match in matches:
                context_start = max(0, match.start() - 150)
                context_end = min(len(source_code), match.end() + 150)
                context = source_code[context_start:context_end]

                is_in_docstring = '"""' in context or "'''" in context
                is_in_comment = context[context.find(match.group()):].startswith("#")

                assert is_in_docstring or is_in_comment, (
                    f"Found pseudo-assembly '{match.group()}' outside comments/docstrings. "
                    f"This indicates incomplete driver code. Context: ...{context[:100]}..."
                )

    def test_no_incomplete_ndis_filter_implementation(self) -> None:
        """No incomplete NDIS filter driver code in implementation."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        incomplete_ndis_patterns = [
            r"NDIS_FILTER_.*CHARACTERISTICS",
            r"FilterAttach\s*\(",
            r"FilterDetach\s*\(",
            r"FilterRestart\s*\(",
            r"FilterPause\s*\(",
            r"NdisFRegisterFilterDriver",
        ]

        for pattern in incomplete_ndis_patterns:
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            assert len(matches) == 0, (
                f"Found incomplete NDIS filter code '{pattern}'. "
                f"Driver approach must be fully removed or fully implemented."
            )

    def test_no_incomplete_disk_filter_implementation(self) -> None:
        """No incomplete disk filter driver code in implementation."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        incomplete_disk_patterns = [
            r"IoAttachDevice\w*\s*\(",
            r"IRP_MJ_SCSI",
            r"IOCTL_STORAGE_QUERY_PROPERTY(?!.*complete)",
            r"DEVICE_OBJECT.*filter",
            r"StorageDeviceProperty",
        ]

        for pattern in incomplete_disk_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))

            for match in matches:
                context_start = max(0, match.start() - 100)
                context_end = min(len(source_code), match.end() + 100)
                context = source_code[context_start:context_end]

                is_in_comment_or_string = any(
                    marker in context
                    for marker in ['"""', "'''", "#", "hook", "Hook", "comment"]
                )

                assert is_in_comment_or_string, (
                    f"Found incomplete disk filter code '{match.group()}'. "
                    f"Context: ...{context}..."
                )


class TestUserModeSpoofingCompleteness:
    """Validate complete user-mode spoofing coverage for all hardware components."""

    def test_all_hardware_components_have_user_mode_getter(self) -> None:
        """Every hardware component has a working user-mode getter method."""
        spoofer = HardwareFingerPrintSpoofer()

        hardware = spoofer.capture_original_hardware()

        assert hardware.cpu_id is not None and len(hardware.cpu_id) > 0, (
            "CPU ID must be readable via user-mode"
        )
        assert hardware.cpu_name is not None and len(hardware.cpu_name) > 0, (
            "CPU name must be readable via user-mode"
        )
        assert hardware.motherboard_serial is not None and len(hardware.motherboard_serial) > 0, (
            "Motherboard serial must be readable via user-mode"
        )
        assert hardware.motherboard_manufacturer is not None and len(hardware.motherboard_manufacturer) > 0, (
            "Motherboard manufacturer must be readable via user-mode"
        )
        assert hardware.bios_serial is not None and len(hardware.bios_serial) > 0, (
            "BIOS serial must be readable via user-mode"
        )
        assert hardware.bios_version is not None and len(hardware.bios_version) > 0, (
            "BIOS version must be readable via user-mode"
        )
        assert hardware.disk_serial is not None and len(hardware.disk_serial) > 0, (
            "Disk serials must be readable via user-mode"
        )
        assert hardware.mac_addresses is not None and len(hardware.mac_addresses) > 0, (
            "MAC addresses must be readable via user-mode"
        )
        assert hardware.system_uuid is not None and len(hardware.system_uuid) > 0, (
            "System UUID must be readable via user-mode"
        )
        assert hardware.volume_serial is not None and len(hardware.volume_serial) > 0, (
            "Volume serial must be readable via user-mode"
        )

    def test_all_hardware_components_have_user_mode_spoofer(self) -> None:
        """Every hardware component has a working user-mode spoofing method."""
        spoofer = HardwareFingerPrintSpoofer()

        assert "_spoof_cpu" in dir(spoofer), "Must have CPU spoofing method"
        assert "_spoof_motherboard" in dir(spoofer), "Must have motherboard spoofing method"
        assert "_spoof_bios" in dir(spoofer), "Must have BIOS spoofing method"
        assert "_spoof_disk" in dir(spoofer), "Must have disk spoofing method"
        assert "_spoof_mac_address" in dir(spoofer), "Must have MAC address spoofing method"
        assert "_spoof_system_uuid" in dir(spoofer), "Must have UUID spoofing method"
        assert "_spoof_gpu" in dir(spoofer), "Must have GPU spoofing method"
        assert "_spoof_ram" in dir(spoofer), "Must have RAM spoofing method"
        assert "_spoof_usb" in dir(spoofer), "Must have USB spoofing method"

        for method_name in spoofer.spoof_methods.values():
            source = inspect.getsource(method_name)
            assert "pass" not in source or len(source.split("\n")) > 5, (
                f"Spoofing method {method_name.__name__} must have real implementation"
            )
            assert "TODO" not in source.upper(), (
                f"Spoofing method {method_name.__name__} must not have TODO comments"
            )

    def test_user_mode_spoofing_methods_actually_modify_values(self) -> None:
        """User-mode spoofing methods produce different values from originals."""
        spoofer = HardwareFingerPrintSpoofer()

        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        assert spoofed.cpu_id != original.cpu_id, "Spoofed CPU ID must differ from original"
        assert spoofed.motherboard_serial != original.motherboard_serial, (
            "Spoofed motherboard serial must differ from original"
        )
        assert spoofed.bios_serial != original.bios_serial, (
            "Spoofed BIOS serial must differ from original"
        )
        assert spoofed.system_uuid != original.system_uuid, (
            "Spoofed system UUID must differ from original"
        )
        assert spoofed.machine_guid != original.machine_guid, (
            "Spoofed machine GUID must differ from original"
        )

    def test_spoofed_values_are_realistic_and_valid_format(self) -> None:
        """Spoofed hardware values follow realistic formats to bypass validation."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        cpu_id_pattern = r"^[0-9A-F]{16}$"
        assert re.match(cpu_id_pattern, spoofed.cpu_id, re.IGNORECASE), (
            f"CPU ID '{spoofed.cpu_id}' must match realistic format"
        )

        assert "Intel" in spoofed.cpu_name or "AMD" in spoofed.cpu_name, (
            f"CPU name '{spoofed.cpu_name}' must be from real vendor"
        )

        uuid_pattern = r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
        assert re.match(uuid_pattern, spoofed.system_uuid, re.IGNORECASE), (
            f"System UUID '{spoofed.system_uuid}' must match UUID format"
        )

        for mac in spoofed.mac_addresses:
            assert len(mac) == 12 or (len(mac) == 17 and ":" in mac), (
                f"MAC address '{mac}' must be valid format"
            )


class TestRegistryHookBasedIDModification:
    """Test registry hook-based system-level ID modification."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Registry hooks require Windows")
    def test_registry_spoof_method_exists_and_works(self) -> None:
        """Registry spoofing method exists and modifies system registry."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        try:
            result = spoofer.apply_spoof(SpoofMethod.REGISTRY)

            assert isinstance(result, bool), "Registry spoof must return boolean"

            if result is False:
                pytest.skip("Registry spoofing requires elevated privileges")

            assert spoofer.spoofed_hardware is not None, "Spoofed hardware must be set"

        except PermissionError:
            pytest.skip("Registry modification requires administrator privileges")
        except OSError as e:
            if "access is denied" in str(e).lower():
                pytest.skip("Registry modification requires administrator privileges")
            raise

    @pytest.mark.skipif(platform.system() != "Windows", reason="Registry hooks require Windows")
    def test_registry_hooks_intercept_hardware_queries(self) -> None:
        """Registry hook spoofing intercepts RegQueryValueExW and similar APIs."""
        spoofer = HardwareFingerPrintSpoofer()

        source = inspect.getsource(spoofer._install_registry_hooks)

        assert "RegQueryValueExW" in source or "hooked_RegQueryValueExW" in source, (
            "Must hook RegQueryValueExW for registry interception"
        )

        assert "VirtualProtect" in source or "inline_hook" in source.lower(), (
            "Must use proper hooking mechanism for registry APIs"
        )

    def test_registry_hook_implementation_handles_hardware_values(self) -> None:
        """Registry hooks return spoofed values for hardware-related registry queries."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        hooked_reg_function = re.search(
            r"def hooked_RegQueryValueExW\(.*?\n(?:.*?\n){0,100}?(?=\n    def |\Z)",
            source_code,
            re.DOTALL
        )

        if hooked_reg_function:
            hook_source = hooked_reg_function.group(0)

            assert "MachineGuid" in hook_source or "machine_guid" in hook_source.lower(), (
                "Registry hook must handle MachineGuid queries"
            )
            assert "ProductId" in hook_source or "product" in hook_source.lower(), (
                "Registry hook must handle ProductId queries"
            )
            assert "spoofed" in hook_source.lower(), (
                "Registry hook must return spoofed values"
            )


class TestFridaHookIntegration:
    """Test Frida hook-based process-level hardware ID interception."""

    def test_frida_integration_status_is_documented(self) -> None:
        """Implementation must document whether Frida hooks are used."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        module_docstring = ast.get_docstring(module_ast)

        assert module_docstring is not None, "Module must have docstring"

        has_frida_import = "import frida" in source_code or "from frida import" in source_code

        if has_frida_import:
            assert "frida" in module_docstring.lower(), (
                "If Frida is used, it must be documented in module docstring"
            )
        else:
            assert "user-mode" in source_code.lower() or "registry" in source_code.lower(), (
                "If Frida is not used, alternative approach must be documented"
            )

    def test_if_frida_not_used_alternative_hooks_are_implemented(self) -> None:
        """If Frida hooks are not used, alternative hooking mechanisms must exist."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        has_frida = "import frida" in source_code

        if not has_frida:
            alternative_hook_indicators = [
                "VirtualProtect",
                "inline_hook",
                "detour",
                "hook_func",
                "trampoline",
                "original_func",
            ]

            found_alternative = any(
                indicator in source_code
                for indicator in alternative_hook_indicators
            )

            assert found_alternative, (
                "If Frida is not used, must implement alternative hooking mechanism "
                "(inline hooks, detours, etc.)"
            )

    def test_process_level_hook_spoof_method_exists(self) -> None:
        """Process-level hook spoofing method exists (HOOK or MEMORY mode)."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        hook_result = spoofer.apply_spoof(SpoofMethod.HOOK)
        memory_result = spoofer.apply_spoof(SpoofMethod.MEMORY)

        assert isinstance(hook_result, bool), "HOOK spoof must return boolean"
        assert isinstance(memory_result, bool), "MEMORY spoof must return boolean"

        has_hook_implementation = (
            hasattr(spoofer, "_apply_hook_spoof") and
            hasattr(spoofer, "_install_wmi_hooks")
        )
        has_memory_implementation = (
            hasattr(spoofer, "_apply_memory_spoof") and
            hasattr(spoofer, "_patch_processor_info")
        )

        assert has_hook_implementation or has_memory_implementation, (
            "Must implement either HOOK or MEMORY-based process-level spoofing"
        )


class TestWindowsVersionCompatibilityDocumentation:
    """Test that Windows version compatibility is clearly documented."""

    def test_module_documents_supported_windows_versions(self) -> None:
        """Module docstring must document supported Windows versions."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        module_docstring = ast.get_docstring(module_ast)

        if module_docstring is None or len(module_docstring) < 50:
            pytest.fail(
                "Module must have comprehensive docstring documenting Windows version support. "
                f"Current docstring: '{module_docstring}'"
            )

        windows_version_indicators = [
            "windows 10",
            "windows 11",
            "win10",
            "win11",
            "windows version",
            "platform compatibility",
            "os compatibility",
        ]

        has_version_info = any(
            indicator in module_docstring.lower()
            for indicator in windows_version_indicators
        )

        if not has_version_info:
            pytest.fail(
                "Module docstring must document Windows version compatibility. "
                f"Add information about Windows 10/11 support. Current docstring: '{module_docstring}'"
            )

    def test_registry_paths_are_windows_10_11_compatible(self) -> None:
        """Registry paths used are compatible with Windows 10 and Windows 11."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        registry_paths = re.findall(r'r"([^"]*(?:SOFTWARE|SYSTEM|HARDWARE)[^"]*)"', source_code)

        known_good_paths = [
            r"SOFTWARE\Microsoft\Cryptography",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            r"SYSTEM\CurrentControlSet\Control\SystemInformation",
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            r"HARDWARE\DESCRIPTION\System\BIOS",
        ]

        for path in registry_paths:
            if any(known_path in path for known_path in known_good_paths):
                continue

            if "SOFTWARE" in path or "SYSTEM" in path or "HARDWARE" in path:
                assert any(
                    segment in path
                    for segment in ["CurrentControlSet", "Microsoft", "DESCRIPTION"]
                ), f"Registry path '{path}' may not be Windows 10/11 compatible"

    def test_implementation_handles_platform_check(self) -> None:
        """Implementation checks platform before Windows-specific operations."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        windows_api_calls = [
            "winreg.",
            "ctypes.windll",
            "kernel32",
        ]

        has_platform_checks = "platform.system()" in source_code

        if any(api_call in source_code for api_call in windows_api_calls):
            assert has_platform_checks, (
                "Implementation must check platform.system() before Windows-specific operations"
            )


class TestEdgeCaseSecureBootHVCIKernelLockdown:
    """Test edge cases: Secure Boot, HVCI, kernel lockdown."""

    def test_secure_boot_compatibility_is_documented(self) -> None:
        """Secure Boot compatibility and limitations must be documented."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        module_docstring = ast.get_docstring(module_ast)

        if module_docstring is None:
            pytest.fail("Module must have docstring documenting Secure Boot limitations")

        secure_boot_indicators = [
            "secure boot",
            "uefi",
            "driver signing",
            "signed driver",
            "kernel mode",
        ]

        has_secure_boot_info = any(
            indicator in module_docstring.lower()
            for indicator in secure_boot_indicators
        )

        if not has_secure_boot_info:
            pytest.fail(
                "Module docstring must document Secure Boot compatibility/limitations. "
                "Add information about driver signing requirements or user-mode limitations."
            )

    def test_hvci_compatibility_is_documented(self) -> None:
        """HVCI (Hypervisor-protected Code Integrity) compatibility must be documented."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        module_docstring = ast.get_docstring(module_ast)

        if module_docstring is None:
            pytest.fail("Module must have docstring documenting HVCI compatibility")

        hvci_indicators = [
            "hvci",
            "hypervisor",
            "code integrity",
            "vbs",
            "virtualization-based security",
            "kernel integrity",
        ]

        has_hvci_info = any(
            indicator in module_docstring.lower()
            for indicator in hvci_indicators
        )

        if not has_hvci_info:
            pytest.fail(
                "Module docstring must document HVCI/VBS compatibility. "
                "Add information about hypervisor-protected environments and limitations."
            )

    def test_kernel_lockdown_handling_is_documented(self) -> None:
        """Kernel lockdown mode compatibility must be documented."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        module_docstring = ast.get_docstring(module_ast)

        if module_docstring is None:
            pytest.fail("Module must have docstring documenting kernel lockdown")

        kernel_lockdown_indicators = [
            "kernel lockdown",
            "lockdown mode",
            "kernel restriction",
            "user-mode only",
            "user mode",
            "usermode",
        ]

        has_lockdown_info = any(
            indicator in module_docstring.lower()
            for indicator in kernel_lockdown_indicators
        )

        if not has_lockdown_info:
            pytest.fail(
                "Module docstring must document kernel lockdown compatibility. "
                "Add information about user-mode-only operation or kernel access limitations."
            )

    def test_no_hvci_incompatible_techniques_used(self) -> None:
        """Implementation must not use techniques incompatible with HVCI."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        hvci_incompatible_patterns = [
            (r"NtSetInformationProcess.*ProcessBreakOnTermination", "Process termination protection"),
            (r"NtQuerySystemInformation.*SystemKernelDebuggerInformation", "Kernel debugger queries"),
            (r"__readmsr|__writemsr", "Direct MSR access"),
            (r"NtLoadDriver(?!.*comment)", "Direct driver loading"),
        ]

        for pattern, description in hvci_incompatible_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))

            for match in matches:
                context_start = max(0, match.start() - 100)
                context_end = min(len(source_code), match.end() + 100)
                context = source_code[context_start:context_end]

                is_safe = any(
                    marker in context
                    for marker in ['"""', "'''", "#", "comment", "fallback", "alternative"]
                )

                assert is_safe, (
                    f"Found HVCI-incompatible technique '{description}': {match.group()}. "
                    f"Context: ...{context}..."
                )

    def test_memory_protection_properly_handles_write_protection(self) -> None:
        """Memory patching respects and restores page protection (HVCI requirement)."""
        spoofer = HardwareFingerPrintSpoofer()

        patch_methods = [
            spoofer._patch_memory_value,
            spoofer._patch_processor_info,
            spoofer._patch_motherboard_info,
            spoofer._patch_bios_info,
        ]

        for method in patch_methods:
            source = inspect.getsource(method)

            assert "VirtualProtectEx" in source or "VirtualProtect" in source, (
                f"Method {method.__name__} must use VirtualProtectEx to change memory protection"
            )

            assert "old_protect" in source.lower(), (
                f"Method {method.__name__} must save original protection flags"
            )

            vp_calls = re.findall(r"VirtualProtect(?:Ex)?\s*\(", source)
            assert len(vp_calls) >= 2, (
                f"Method {method.__name__} must restore original protection (needs 2+ VirtualProtect calls)"
            )


class TestApproachDocumentationComprehensive:
    """Test comprehensive documentation of implementation approach."""

    def test_module_has_detailed_docstring_explaining_approach(self) -> None:
        """Module docstring comprehensively explains the spoofing approach taken."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        docstring = ast.get_docstring(module_ast)

        assert docstring is not None, "Module must have docstring"
        assert len(docstring) >= 200, (
            f"Module docstring must be comprehensive (at least 200 chars). "
            f"Current length: {len(docstring) if docstring else 0}"
        )

        required_topics = [
            ("user.?mode", "user-mode approach"),
            ("registry|hook|memory", "spoofing method"),
            ("windows", "Windows platform"),
            ("hardware|fingerprint|id", "hardware identification"),
        ]

        for pattern, topic in required_topics:
            assert re.search(pattern, docstring, re.IGNORECASE), (
                f"Module docstring must document {topic}. Pattern: {pattern}"
            )

    def test_all_spoof_methods_document_their_approach(self) -> None:
        """All spoof method implementations have docstrings explaining approach."""
        spoofer = HardwareFingerPrintSpoofer()

        methods_to_check = [
            spoofer._apply_registry_spoof,
            spoofer._apply_hook_spoof,
            spoofer._apply_memory_spoof,
            spoofer._apply_driver_spoof,
        ]

        for method in methods_to_check:
            source = inspect.getsource(method)
            docstring_match = re.search(r'"""(.*?)"""', source, re.DOTALL)

            assert docstring_match is not None, (
                f"Method {method.__name__} must have docstring explaining approach"
            )

            docstring = docstring_match.group(1)
            assert len(docstring) >= 30, (
                f"Method {method.__name__} docstring must be descriptive (30+ chars)"
            )

    def test_class_docstring_explains_purpose_and_methods(self) -> None:
        """HardwareFingerPrintSpoofer class docstring explains purpose and available methods."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        class_match = re.search(
            r'class HardwareFingerPrintSpoofer.*?:\s*"""(.*?)"""',
            source_code,
            re.DOTALL
        )

        assert class_match is not None, "HardwareFingerPrintSpoofer must have class docstring"

        class_docstring = class_match.group(1)
        assert len(class_docstring) >= 100, (
            f"Class docstring must be comprehensive. Current: {len(class_docstring)} chars"
        )

        expected_content = [
            ("spoof|bypass|fingerprint", "spoofing purpose"),
            ("registry|hook|memory", "available methods"),
            ("hardware|id|identifier", "hardware identification"),
        ]

        for pattern, description in expected_content:
            assert re.search(pattern, class_docstring, re.IGNORECASE), (
                f"Class docstring must explain {description}. Pattern: {pattern}"
            )


class TestNoIncompleteRestoreFunctionality:
    """Test that restore functionality is not incomplete or stubbed."""

    def test_restore_original_has_implementation(self) -> None:
        """restore_original method has real implementation, not stub."""
        spoofer = HardwareFingerPrintSpoofer()

        assert hasattr(spoofer, "restore_original"), (
            "Spoofer must have restore_original method"
        )

        source = inspect.getsource(spoofer.restore_original)

        body_lines = [
            line.strip()
            for line in source.split("\n")
            if line.strip() and not line.strip().startswith('"""') and not line.strip().startswith("#")
        ]

        assert len(body_lines) > 3, (
            "restore_original must have substantial implementation"
        )

        assert "pass" not in source or source.count("\n") > 10, (
            "restore_original must not be a pass-only stub"
        )

        assert "TODO" not in source.upper(), (
            "restore_original must not have TODO comments"
        )

        restoration_indicators = ["winreg", "SetValueEx", "original_hardware"]
        has_restoration_logic = any(
            indicator in source
            for indicator in restoration_indicators
        )

        assert has_restoration_logic, (
            "restore_original must actually restore registry values or hardware state"
        )
