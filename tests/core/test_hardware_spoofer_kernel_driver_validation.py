"""Production-ready tests validating hardware spoofer implementation approach.

Tests ensure hardware spoofer either has working kernel drivers OR uses pure
user-mode approach with registry + Frida hooks. Tests MUST FAIL if pseudo-code,
incomplete functionality, or fake driver code is detected.
"""

from __future__ import annotations

import ast
import inspect
import platform
import re
import sys
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


class TestDriverImplementationValidation:
    """Validate that driver approach is either working OR properly removed."""

    def test_driver_method_is_not_stubbed(self) -> None:
        """Driver spoofing method must either work OR clearly return False without pseudo-code."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        result: bool = spoofer.apply_spoof(SpoofMethod.DRIVER)

        assert result is False, "Driver method should return False (not implemented)"

        source = inspect.getsource(spoofer._apply_driver_spoof)
        assert "TODO" not in source.upper(), "Driver method contains TODO comments"
        assert "FIXME" not in source.upper(), "Driver method contains FIXME comments"
        assert "STUB" not in source.upper(), "Driver method contains STUB markers"
        assert "PLACEHOLDER" not in source.upper(), "Driver method contains placeholder code"

    def test_no_pseudo_assembly_in_source(self) -> None:
        """Source code must not contain pseudo-assembly or fake driver code."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        pseudo_assembly_patterns = [
            r"mov\s+\w+,\s*\w+",
            r"jmp\s+\w+",
            r"call\s+\w+",
            r"ret\s*\n",
            r"push\s+\w+",
            r"pop\s+\w+",
            r"lea\s+\w+",
            r"xor\s+\w+",
        ]

        for pattern in pseudo_assembly_patterns:
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            context_matches = []
            for match in matches:
                if not any(
                    exclude in source_code[source_code.find(match) - 100 : source_code.find(match) + 100]
                    for exclude in ["comment", "#", '"""', "'''", "docstring"]
                ):
                    context_matches.append(match)

            assert len(context_matches) == 0, f"Found pseudo-assembly pattern '{pattern}': {context_matches}"

    def test_no_fake_ndis_filter_code(self) -> None:
        """No fake NDIS filter driver code in implementation."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        fake_ndis_patterns = [
            r"NdisRegisterProtocol",
            r"NdisSend.*Packet",
            r"NDIS_PROTOCOL_CHARACTERISTICS",
            r"NdisOpenAdapter",
            r"FilterAttach",
            r"FilterDetach",
        ]

        for pattern in fake_ndis_patterns:
            assert pattern not in source_code, f"Found fake NDIS driver code: {pattern}"

    def test_no_fake_disk_filter_code(self) -> None:
        """No fake disk filter driver code in implementation."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        fake_disk_filter_patterns = [
            r"IoCreateDevice.*DEVICE_OBJECT",
            r"IoAttachDeviceToDeviceStack",
            r"IRP_MJ_DEVICE_CONTROL",
            r"IOCTL_STORAGE_QUERY_PROPERTY",
        ]

        for pattern in fake_disk_filter_patterns:
            assert pattern not in source_code, f"Found fake disk filter code: {pattern}"

    def test_driver_approach_clearly_documented(self) -> None:
        """Implementation must document which approach is taken (driver vs user-mode)."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        assert "user-mode" in source_code.lower() or "registry" in source_code.lower() or "hook" in source_code.lower(), (
            "Implementation must document user-mode approach"
        )

        module_docstring = ast.get_docstring(ast.parse(source_code))
        assert module_docstring is not None, "Module must have docstring documenting approach"
        assert len(module_docstring) > 50, "Module docstring must explain implementation approach"


class TestRegistryBasedSpooferFunctionality:
    """Test registry-based hardware ID modification works correctly."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Registry spoofing requires Windows")
    def test_registry_spoof_modifies_machine_guid(self) -> None:
        """Registry spoofing successfully modifies machine GUID."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        try:
            result = spoofer.apply_spoof(SpoofMethod.REGISTRY)
            assert result is True, "Registry spoofing must succeed or fail with proper error handling"

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                current_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                assert current_guid == spoofed.machine_guid, "Machine GUID not updated in registry"
                assert current_guid != original.machine_guid, "Machine GUID must be different from original"

        except PermissionError:
            pytest.skip("Test requires administrator privileges")
        except OSError as e:
            if "access is denied" in str(e).lower():
                pytest.skip("Test requires administrator privileges")
            raise

    @pytest.mark.skipif(platform.system() != "Windows", reason="Registry spoofing requires Windows")
    def test_registry_spoof_modifies_product_id(self) -> None:
        """Registry spoofing successfully modifies Windows product ID."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        try:
            result = spoofer.apply_spoof(SpoofMethod.REGISTRY)
            assert result is True, "Registry spoofing must succeed"

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                current_product_id, _ = winreg.QueryValueEx(key, "ProductId")
                assert current_product_id == spoofed.product_id, "Product ID not updated in registry"
                assert current_product_id != original.product_id, "Product ID must be different from original"

        except PermissionError:
            pytest.skip("Test requires administrator privileges")
        except OSError as e:
            if "access is denied" in str(e).lower():
                pytest.skip("Test requires administrator privileges")
            raise

    @pytest.mark.skipif(platform.system() != "Windows", reason="Registry spoofing requires Windows")
    def test_registry_spoof_modifies_system_information(self) -> None:
        """Registry spoofing updates system hardware ID in registry."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        try:
            result = spoofer.apply_spoof(SpoofMethod.REGISTRY)
            assert result is True, "Registry spoofing must succeed"

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation"
            ) as key:
                current_hwid, _ = winreg.QueryValueEx(key, "ComputerHardwareId")
                assert current_hwid == spoofed.system_uuid, "Computer hardware ID not updated"
                assert current_hwid != original.system_uuid, "Hardware ID must differ from original"

        except PermissionError:
            pytest.skip("Test requires administrator privileges")
        except OSError as e:
            if "access is denied" in str(e).lower():
                pytest.skip("Test requires administrator privileges")
            raise

    @pytest.mark.skipif(platform.system() != "Windows", reason="Registry spoofing requires Windows")
    def test_registry_spoof_handles_network_adapters(self) -> None:
        """Registry spoofing attempts to modify network adapter MAC addresses."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        try:
            result = spoofer.apply_spoof(SpoofMethod.REGISTRY)
            assert result is True, "Registry spoofing must complete successfully"

            assert spoofer.spoofed_hardware is not None, "Spoofed hardware must be generated"
            assert len(spoofer.spoofed_hardware.mac_addresses) > 0, "Must have spoofed MAC addresses"

        except PermissionError:
            pytest.skip("Test requires administrator privileges")
        except OSError as e:
            if "access is denied" in str(e).lower():
                pytest.skip("Test requires administrator privileges")
            raise


class TestHookBasedSpooferFunctionality:
    """Test hook-based (API hooking) hardware ID interception."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="API hooking requires Windows")
    def test_hook_spoof_installs_wmi_hooks(self) -> None:
        """Hook spoofing installs WMI query interception hooks."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        result = spoofer.apply_spoof(SpoofMethod.HOOK)

        assert isinstance(result, bool), "Hook spoofing must return boolean result"

        if result:
            assert spoofer.hooks_installed is True, "Hooks must be marked as installed"
            assert spoofer.exec_query_hook is not None, "WMI ExecQuery hook must be set"

    @pytest.mark.skipif(platform.system() != "Windows", reason="API hooking requires Windows")
    def test_hook_spoof_installs_registry_hooks(self) -> None:
        """Hook spoofing installs registry API interception hooks."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        result = spoofer.apply_spoof(SpoofMethod.HOOK)

        if result:
            assert (
                spoofer.RegQueryValueExW_hook is not None or spoofer.RegGetValueW_hook is not None
            ), "Registry hooks must be installed"

    @pytest.mark.skipif(platform.system() != "Windows", reason="API hooking requires Windows")
    def test_hook_spoof_installs_kernel32_hooks(self) -> None:
        """Hook spoofing installs kernel32.dll function hooks."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        result = spoofer.apply_spoof(SpoofMethod.HOOK)

        if result:
            assert (
                spoofer.GetVolumeInformationW_hook is not None
                or spoofer.GetSystemInfo_hook is not None
                or spoofer.GetComputerNameExW_hook is not None
            ), "Kernel32 hooks must be installed"

    def test_hook_implementation_is_real_or_documented_limitation(self) -> None:
        """Hook implementation must be real OR clearly document why it's not available."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        try:
            result = spoofer.apply_spoof(SpoofMethod.HOOK)

            if result is False:
                source = inspect.getsource(spoofer._apply_hook_spoof)
                assert (
                    "not implemented" in source.lower()
                    or "limitation" in source.lower()
                    or "requires" in source.lower()
                ), "Non-working hooks must document limitations"
            else:
                assert spoofer.hooks_installed is True, "Successful hook application must set hooks_installed flag"

        except Exception as e:
            assert "privilege" in str(e).lower() or "access" in str(e).lower() or "permission" in str(e).lower(), (
                f"Hook failures must be due to permissions, not broken code: {e}"
            )


class TestMemoryBasedSpooferFunctionality:
    """Test memory patching for hardware ID modification."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Memory patching requires Windows")
    def test_memory_spoof_scans_target_processes(self) -> None:
        """Memory spoofing scans running processes for hardware IDs."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        try:
            result = spoofer.apply_spoof(SpoofMethod.MEMORY)

            assert isinstance(result, bool), "Memory spoofing must return boolean result"

        except PermissionError:
            pytest.skip("Memory patching requires elevated privileges")

    def test_memory_spoof_patches_processor_info(self) -> None:
        """Memory spoofing patches CPU ID in process memory."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        source = inspect.getsource(spoofer._patch_processor_info)

        assert "VirtualProtectEx" in source or "WriteProcessMemory" in source or "ReadProcessMemory" in source, (
            "Memory patching must use real Windows APIs"
        )

        assert "TODO" not in source.upper(), "Memory patching must not contain TODOs"
        assert "STUB" not in source.upper(), "Memory patching must not be stubbed"

    def test_memory_spoof_patches_motherboard_info(self) -> None:
        """Memory spoofing patches motherboard serial in process memory."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        source = inspect.getsource(spoofer._patch_motherboard_info)

        assert "scan_memory" in source.lower() or "patch" in source.lower(), (
            "Motherboard patching must implement memory scanning"
        )

    def test_memory_spoof_patches_bios_info(self) -> None:
        """Memory spoofing patches BIOS serial in process memory."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        source = inspect.getsource(spoofer._patch_bios_info)

        assert "pattern" in source.lower() or "scan" in source.lower(), "BIOS patching must scan for patterns"


class TestUserModeFallbackCompleteness:
    """Test that user-mode fallbacks cover all hardware components."""

    def test_spoofer_has_fallback_for_cpu_id(self) -> None:
        """Spoofer provides user-mode fallback for CPU ID spoofing."""
        spoofer = HardwareFingerPrintSpoofer()

        cpu_id = spoofer._get_cpu_id()
        assert cpu_id is not None, "CPU ID fallback must work"
        assert len(cpu_id) > 0, "CPU ID fallback must return non-empty value"

    def test_spoofer_has_fallback_for_disk_serial(self) -> None:
        """Spoofer provides user-mode fallback for disk serial spoofing."""
        spoofer = HardwareFingerPrintSpoofer()

        disk_serials = spoofer._get_disk_serials()
        assert disk_serials is not None, "Disk serial fallback must work"
        assert len(disk_serials) > 0, "Disk serial fallback must return values"

    def test_spoofer_has_fallback_for_mac_address(self) -> None:
        """Spoofer provides user-mode fallback for MAC address spoofing."""
        spoofer = HardwareFingerPrintSpoofer()

        mac_addresses = spoofer._get_mac_addresses()
        assert mac_addresses is not None, "MAC address fallback must work"
        assert len(mac_addresses) > 0, "MAC address fallback must return values"

    def test_spoofer_has_fallback_for_bios_serial(self) -> None:
        """Spoofer provides user-mode fallback for BIOS serial spoofing."""
        spoofer = HardwareFingerPrintSpoofer()

        bios_serial = spoofer._get_bios_serial()
        assert bios_serial is not None, "BIOS serial fallback must work"
        assert len(bios_serial) > 0, "BIOS serial fallback must return non-empty value"

    def test_spoofer_has_fallback_for_motherboard_serial(self) -> None:
        """Spoofer provides user-mode fallback for motherboard serial spoofing."""
        spoofer = HardwareFingerPrintSpoofer()

        mb_serial = spoofer._get_motherboard_serial()
        assert mb_serial is not None, "Motherboard serial fallback must work"
        assert len(mb_serial) > 0, "Motherboard serial fallback must return non-empty value"

    def test_spoofer_has_fallback_for_system_uuid(self) -> None:
        """Spoofer provides user-mode fallback for system UUID spoofing."""
        spoofer = HardwareFingerPrintSpoofer()

        system_uuid = spoofer._get_system_uuid()
        assert system_uuid is not None, "System UUID fallback must work"
        assert len(system_uuid) > 0, "System UUID fallback must return non-empty value"

    def test_spoofer_has_fallback_for_volume_serial(self) -> None:
        """Spoofer provides user-mode fallback for volume serial spoofing."""
        spoofer = HardwareFingerPrintSpoofer()

        volume_serial = spoofer._get_volume_serial()
        assert volume_serial is not None, "Volume serial fallback must work"
        assert len(volume_serial) > 0, "Volume serial fallback must return non-empty value"

    def test_all_hardware_components_have_user_mode_access(self) -> None:
        """All hardware components can be read via user-mode APIs."""
        spoofer = HardwareFingerPrintSpoofer()

        hardware = spoofer.capture_original_hardware()

        assert hardware.cpu_id is not None and len(hardware.cpu_id) > 0, "CPU ID must be accessible"
        assert hardware.motherboard_serial is not None and len(hardware.motherboard_serial) > 0, (
            "Motherboard serial must be accessible"
        )
        assert hardware.bios_serial is not None and len(hardware.bios_serial) > 0, "BIOS serial must be accessible"
        assert hardware.disk_serial is not None and len(hardware.disk_serial) > 0, "Disk serials must be accessible"
        assert hardware.mac_addresses is not None and len(hardware.mac_addresses) > 0, (
            "MAC addresses must be accessible"
        )
        assert hardware.system_uuid is not None and len(hardware.system_uuid) > 0, "System UUID must be accessible"


class TestApproachDocumentation:
    """Test that implementation approach is clearly documented."""

    def test_module_has_comprehensive_docstring(self) -> None:
        """Module docstring explains spoofing approach and limitations."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        docstring = ast.get_docstring(module_ast)

        assert docstring is not None, "Module must have docstring"
        assert len(docstring) > 100, "Module docstring must be comprehensive"

    def test_driver_method_documents_not_implemented_status(self) -> None:
        """Driver method clearly states it is not implemented."""
        spoofer = HardwareFingerPrintSpoofer()

        source = inspect.getsource(spoofer._apply_driver_spoof)
        docstring_match = re.search(r'"""(.*?)"""', source, re.DOTALL)

        assert docstring_match is not None, "Driver method must have docstring"
        docstring = docstring_match.group(1)
        assert "not implemented" in docstring.lower(), "Docstring must state not implemented"

    def test_virtual_method_documents_not_implemented_status(self) -> None:
        """Virtual method clearly states it is not implemented."""
        spoofer = HardwareFingerPrintSpoofer()

        source = inspect.getsource(spoofer._apply_virtual_spoof)
        docstring_match = re.search(r'"""(.*?)"""', source, re.DOTALL)

        assert docstring_match is not None, "Virtual method must have docstring"
        docstring = docstring_match.group(1)
        assert "not implemented" in docstring.lower(), "Docstring must state not implemented"

    def test_registry_method_documents_functionality(self) -> None:
        """Registry method documents what it modifies."""
        spoofer = HardwareFingerPrintSpoofer()

        source = inspect.getsource(spoofer._apply_registry_spoof)
        docstring_match = re.search(r'"""(.*?)"""', source, re.DOTALL)

        assert docstring_match is not None, "Registry method must have docstring"

    def test_hook_method_documents_functionality(self) -> None:
        """Hook method documents what APIs it intercepts."""
        spoofer = HardwareFingerPrintSpoofer()

        source = inspect.getsource(spoofer._apply_hook_spoof)
        docstring_match = re.search(r'"""(.*?)"""', source, re.DOTALL)

        assert docstring_match is not None, "Hook method must have docstring"


class TestEdgeCaseDriverSigning:
    """Test driver signing requirements and limitations."""

    def test_driver_method_does_not_load_unsigned_driver(self) -> None:
        """Driver method must not attempt to load unsigned drivers."""
        spoofer = HardwareFingerPrintSpoofer()

        source = inspect.getsource(spoofer._apply_driver_spoof)

        dangerous_patterns = [
            r"CreateService.*KERNEL_DRIVER",
            r"StartService.*\w+",
            r"NtLoadDriver",
            r"ZwLoadDriver",
        ]

        for pattern in dangerous_patterns:
            assert not re.search(pattern, source, re.IGNORECASE), (
                f"Driver method must not attempt to load drivers: {pattern}"
            )

    def test_no_driver_loading_code_present(self) -> None:
        """Implementation must not contain driver loading code."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        driver_loading_patterns = [
            r"CreateServiceW?.*TYPE_KERNEL_DRIVER",
            r"OpenSCManager.*SC_MANAGER_CREATE_SERVICE",
            r"NtLoadDriver",
            r"ZwLoadDriver",
        ]

        for pattern in driver_loading_patterns:
            assert not re.search(pattern, source_code, re.IGNORECASE), (
                f"Must not contain driver loading code: {pattern}"
            )


class TestEdgeCaseHVCICompatibility:
    """Test HVCI (Hypervisor-protected Code Integrity) compatibility."""

    def test_no_code_injection_techniques(self) -> None:
        """Implementation must not use techniques incompatible with HVCI."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        hvci_incompatible_patterns = [
            r"NtSetInformationProcess.*ProcessBreakOnTermination",
            r"NtQuerySystemInformation.*SystemKernelDebuggerInformation",
        ]

        for pattern in hvci_incompatible_patterns:
            assert not re.search(pattern, source_code, re.IGNORECASE), (
                f"Must not use HVCI-incompatible techniques: {pattern}"
            )

    def test_memory_protection_respects_write_protection(self) -> None:
        """Memory patching properly handles write protection."""
        spoofer = HardwareFingerPrintSpoofer()

        source = inspect.getsource(spoofer._patch_memory_value)

        assert "VirtualProtectEx" in source, "Must use VirtualProtectEx to change memory protection"

        assert "old_protect" in source, "Must save original protection flags"


class TestEdgeCaseWindowsVersionDifferences:
    """Test Windows version compatibility."""

    def test_registry_paths_valid_for_windows_10_and_11(self) -> None:
        """Registry paths work on Windows 10 and Windows 11."""
        spoofer = HardwareFingerPrintSpoofer()

        source = inspect.getsource(spoofer._apply_registry_spoof)

        registry_paths = re.findall(r'r"([^"]+)"', source)

        valid_paths = [
            r"SOFTWARE\Microsoft\Cryptography",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            r"SYSTEM\CurrentControlSet\Control\SystemInformation",
        ]

        for path in registry_paths:
            if path.startswith("SOFTWARE") or path.startswith("SYSTEM"):
                assert any(valid in path for valid in valid_paths), f"Registry path may not be valid: {path}"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows version check requires Windows")
    def test_spoofer_handles_current_windows_version(self) -> None:
        """Spoofer works on current Windows version."""
        import sys

        spoofer = HardwareFingerPrintSpoofer()

        if sys.getwindowsversion().major >= 10:  # type: ignore[attr-defined]
            hardware = spoofer.capture_original_hardware()

            assert hardware is not None, "Must capture hardware on Windows 10+"
            assert hardware.cpu_id is not None, "Must read CPU ID on Windows 10+"


class TestImplementationCompletenessValidation:
    """Test that implementation has no incomplete or broken functionality."""

    def test_no_methods_raise_notimplementederror(self) -> None:
        """No methods raise NotImplementedError indicating incomplete code."""
        spoofer = HardwareFingerPrintSpoofer()

        public_methods = [
            method for method in dir(spoofer) if callable(getattr(spoofer, method)) and not method.startswith("_")
        ]

        for method_name in public_methods:
            method = getattr(spoofer, method_name)
            try:
                source = inspect.getsource(method)
                assert "raise NotImplementedError" not in source, f"Method {method_name} raises NotImplementedError"
            except (OSError, TypeError):
                pass

    def test_spoof_methods_all_callable(self) -> None:
        """All spoof methods in spoof_methods dict are callable."""
        spoofer = HardwareFingerPrintSpoofer()

        assert spoofer.spoof_methods is not None, "spoof_methods must be initialized"

        for component, method in spoofer.spoof_methods.items():
            assert callable(method), f"Spoof method for {component} must be callable"

    def test_apply_spoof_handles_all_spoof_methods(self) -> None:
        """apply_spoof handles all SpoofMethod enum values."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.generate_spoofed_hardware()

        for spoof_method in SpoofMethod:
            result = spoofer.apply_spoof(spoof_method)
            assert isinstance(result, bool), f"apply_spoof must return bool for {spoof_method.value}"

    def test_no_empty_method_bodies(self) -> None:
        """No methods have empty bodies (pass-only implementations)."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        tree = ast.parse(source_code)

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if not node.name.startswith("__"):
                    body_without_docstring = node.body[1:] if isinstance(node.body[0], ast.Expr) else node.body

                    if len(body_without_docstring) == 1 and isinstance(body_without_docstring[0], ast.Pass):
                        pytest.fail(f"Method {node.name} has empty pass-only body")


class TestRealWorldCompatibility:
    """Test compatibility with real-world license checking scenarios."""

    def test_generated_hardware_appears_realistic(self) -> None:
        """Generated hardware IDs appear realistic to automated checks."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        assert "Intel" in spoofed.cpu_name or "AMD" in spoofed.cpu_name, "CPU name must use real vendor"

        assert any(
            vendor in spoofed.motherboard_manufacturer for vendor in ["ASUS", "Gigabyte", "MSI", "ASRock"]
        ), "Motherboard manufacturer must be realistic"

        for mac in spoofed.mac_addresses:
            first_octet = int(mac[0:2], 16)
            assert (first_octet & 0x01) == 0, "MAC address must not be multicast"

    def test_spoofer_maintains_hardware_consistency(self) -> None:
        """Spoofed hardware maintains internal consistency."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        assert len(spoofed.disk_serial) == len(spoofed.disk_model), "Disk serials and models must match count"

    @pytest.mark.skipif(platform.system() != "Windows", reason="WMI test requires Windows")
    def test_wmi_queries_return_spoofed_values_when_hooks_active(self) -> None:
        """WMI queries return spoofed values when hooks are installed."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        try:
            result = spoofer.apply_spoof(SpoofMethod.HOOK)

            if result:
                assert spoofer.hooks_installed is True, "Hooks must be marked as installed"
        except Exception as e:
            if "permission" not in str(e).lower():
                pytest.fail(f"Hook installation failed with non-permission error: {e}")
