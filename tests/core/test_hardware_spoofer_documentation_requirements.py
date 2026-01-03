"""Production tests validating hardware spoofer documentation requirements.

These tests ensure the hardware_spoofer.py module has comprehensive documentation
explaining the approach, limitations, and compatibility. Tests provide actionable
error messages showing exactly what documentation is missing.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


class TestModuleDocstringComprehensiveness:
    """Test that module docstring meets all documentation requirements."""

    def test_module_has_docstring(self) -> None:
        """Module must have a docstring."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        docstring = ast.get_docstring(module_ast)

        assert docstring is not None, (
            "Module hardware_spoofer.py MUST have a module-level docstring. "
            "Add a comprehensive docstring at the top of the file explaining the approach."
        )

    def test_module_docstring_is_comprehensive(self) -> None:
        """Module docstring must be at least 200 characters explaining approach."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        docstring = ast.get_docstring(module_ast)

        if docstring is None:
            pytest.fail("Module must have docstring")

        actual_length = len(docstring)

        assert actual_length >= 200, (
            f"Module docstring must be comprehensive (minimum 200 characters). "
            f"Current length: {actual_length} chars. "
            f"Current docstring: '{docstring}'\n\n"
            f"Add documentation explaining:\n"
            f"- What spoofing approach is used (user-mode, no drivers)\n"
            f"- What methods are available (REGISTRY, HOOK, MEMORY)\n"
            f"- Windows version compatibility (Windows 10/11)\n"
            f"- Secure Boot/HVCI/kernel lockdown limitations\n"
            f"- Why Frida is or isn't used (alternative approach)"
        )

    def test_module_docstring_documents_windows_compatibility(self) -> None:
        """Module docstring must explicitly mention Windows version compatibility."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        docstring = ast.get_docstring(module_ast)

        if docstring is None:
            pytest.fail("Module must have docstring")

        windows_version_keywords = [
            "windows 10",
            "windows 11",
            "win10",
            "win11",
        ]

        has_version_info = any(
            keyword in docstring.lower()
            for keyword in windows_version_keywords
        )

        assert has_version_info, (
            f"Module docstring MUST document Windows version compatibility. "
            f"Current docstring: '{docstring}'\n\n"
            f"Add a 'Platform Compatibility:' section mentioning:\n"
            f"- Windows 10 (all versions)\n"
            f"- Windows 11 (all versions)"
        )

    def test_module_docstring_documents_secure_boot(self) -> None:
        """Module docstring must document Secure Boot compatibility/limitations."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        docstring = ast.get_docstring(module_ast)

        if docstring is None:
            pytest.fail("Module must have docstring")

        secure_boot_keywords = [
            "secure boot",
            "uefi",
            "driver signing",
            "signed driver",
        ]

        has_secure_boot_info = any(
            keyword in docstring.lower()
            for keyword in secure_boot_keywords
        )

        assert has_secure_boot_info, (
            f"Module docstring MUST document Secure Boot compatibility. "
            f"Current docstring: '{docstring}'\n\n"
            f"Add a 'Limitations:' section mentioning:\n"
            f"- Compatible with Secure Boot enabled systems (user-mode only)\n"
            f"- Driver-based spoofing not implemented due to Secure Boot signing requirements\n"
            f"OR explain how signed drivers are used if drivers are implemented"
        )

    def test_module_docstring_documents_hvci_vbs(self) -> None:
        """Module docstring must document HVCI/VBS compatibility/limitations."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        docstring = ast.get_docstring(module_ast)

        if docstring is None:
            pytest.fail("Module must have docstring")

        hvci_keywords = [
            "hvci",
            "hypervisor",
            "virtualization-based security",
            "vbs",
            "code integrity",
        ]

        has_hvci_info = any(
            keyword in docstring.lower()
            for keyword in hvci_keywords
        )

        assert has_hvci_info, (
            f"Module docstring MUST document HVCI/VBS compatibility. "
            f"Current docstring: '{docstring}'\n\n"
            f"Add a 'Limitations:' section mentioning:\n"
            f"- Compatible with HVCI/VBS enabled systems (no kernel-mode operations)\n"
            f"- HVCI systems may prevent inline hook installation (graceful fallback)\n"
            f"OR explain how HVCI is handled if kernel-mode operations are used"
        )

    def test_module_docstring_documents_kernel_lockdown(self) -> None:
        """Module docstring must document kernel lockdown mode compatibility."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        docstring = ast.get_docstring(module_ast)

        if docstring is None:
            pytest.fail("Module must have docstring")

        kernel_lockdown_keywords = [
            "kernel lockdown",
            "lockdown mode",
            "user-mode only",
            "user mode",
            "usermode",
        ]

        has_lockdown_info = any(
            keyword in docstring.lower()
            for keyword in kernel_lockdown_keywords
        )

        assert has_lockdown_info, (
            f"Module docstring MUST document kernel lockdown compatibility. "
            f"Current docstring: '{docstring}'\n\n"
            f"Add a 'Limitations:' section mentioning:\n"
            f"- Compatible with kernel lockdown mode (user-mode only)\n"
            f"- Kernel lockdown prevents kernel-mode driver loading (user-mode fallback available)\n"
            f"OR explain approach to kernel lockdown if applicable"
        )

    def test_module_docstring_documents_driver_approach(self) -> None:
        """Module docstring must document whether drivers are used and why."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        docstring = ast.get_docstring(module_ast)

        if docstring is None:
            pytest.fail("Module must have docstring")

        driver_keywords = [
            "driver",
            "kernel-mode",
            "kernel mode",
            "user-mode",
            "user mode",
        ]

        has_driver_info = any(
            keyword in docstring.lower()
            for keyword in driver_keywords
        )

        assert has_driver_info, (
            f"Module docstring MUST document driver approach. "
            f"Current docstring: '{docstring}'\n\n"
            f"Add documentation explaining:\n"
            f"- Whether kernel drivers are used (YES or NO)\n"
            f"- If NO: Explain user-mode-only approach\n"
            f"- If YES: Explain driver signing and compatibility"
        )

    def test_module_docstring_documents_frida_usage(self) -> None:
        """Module docstring must document Frida usage or alternative approach."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        docstring = ast.get_docstring(module_ast)

        if docstring is None:
            pytest.fail("Module must have docstring")

        has_frida = "import frida" in source_code or "from frida import" in source_code

        if has_frida:
            assert "frida" in docstring.lower(), (
                f"Module uses Frida but doesn't document it. "
                f"Add 'Alternative to Frida:' section or similar to docstring."
            )
        else:
            hook_keywords = [
                "hook",
                "inline",
                "detour",
                "virtualprotect",
                "api hooking",
            ]

            has_alternative_info = any(
                keyword in docstring.lower()
                for keyword in hook_keywords
            )

            assert has_alternative_info, (
                f"Module doesn't use Frida and doesn't document alternative approach. "
                f"Current docstring: '{docstring}'\n\n"
                f"Add an 'Alternative to Frida:' section explaining:\n"
                f"- This implementation uses custom inline hooking via VirtualProtect\n"
                f"- Hooks intercept WMI queries, registry queries, and kernel32 functions\n"
                f"- Minimal dependencies and maximum compatibility"
            )

    def test_module_docstring_documents_spoofing_methods(self) -> None:
        """Module docstring must list available spoofing methods."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        docstring = ast.get_docstring(module_ast)

        if docstring is None:
            pytest.fail("Module must have docstring")

        method_keywords = [
            "registry",
            "hook",
            "memory",
        ]

        methods_documented = sum(
            1 for keyword in method_keywords
            if keyword in docstring.lower()
        )

        assert methods_documented >= 2, (
            f"Module docstring MUST document spoofing methods (REGISTRY, HOOK, MEMORY). "
            f"Current docstring: '{docstring}'\n\n"
            f"Add a 'Spoofing Methods:' section listing:\n"
            f"- REGISTRY: Direct registry modification of hardware IDs\n"
            f"- HOOK: Inline API hooking of WMI, registry, and kernel32 functions\n"
            f"- MEMORY: Direct memory patching of hardware IDs in running processes\n"
            f"- DRIVER: Not implemented (returns False)\n"
            f"- VIRTUAL: Not implemented (returns False)"
        )


class TestClassDocstringComprehensiveness:
    """Test that HardwareFingerPrintSpoofer class has comprehensive docstring."""

    def test_class_has_docstring(self) -> None:
        """HardwareFingerPrintSpoofer class must have docstring."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        import re
        class_match = re.search(
            r'class HardwareFingerPrintSpoofer.*?:\s*"""(.*?)"""',
            source_code,
            re.DOTALL
        )

        assert class_match is not None, (
            "HardwareFingerPrintSpoofer class MUST have a docstring. "
            "Add a docstring explaining the class purpose, methods, and usage."
        )

    def test_class_docstring_is_comprehensive(self) -> None:
        """Class docstring must be at least 100 characters."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        import re
        class_match = re.search(
            r'class HardwareFingerPrintSpoofer.*?:\s*"""(.*?)"""',
            source_code,
            re.DOTALL
        )

        if class_match is None:
            pytest.fail("Class must have docstring")

        class_docstring = class_match.group(1)
        actual_length = len(class_docstring)

        assert actual_length >= 100, (
            f"Class docstring must be comprehensive (minimum 100 characters). "
            f"Current length: {actual_length} chars. "
            f"Current docstring: '{class_docstring}'\n\n"
            f"Add documentation explaining:\n"
            f"- Purpose: Production-ready hardware fingerprint spoofing system\n"
            f"- Methods: Multiple spoofing methods (registry, hook, memory)\n"
            f"- Hardware: CPU ID, motherboard, BIOS, disk, MAC, UUID, etc.\n"
            f"- Compatibility: Windows 10/11 with user-mode operations"
        )

    def test_class_docstring_mentions_hardware_components(self) -> None:
        """Class docstring must mention hardware components being spoofed."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        import re
        class_match = re.search(
            r'class HardwareFingerPrintSpoofer.*?:\s*"""(.*?)"""',
            source_code,
            re.DOTALL
        )

        if class_match is None:
            pytest.fail("Class must have docstring")

        class_docstring = class_match.group(1)

        hardware_keywords = [
            "cpu",
            "motherboard",
            "bios",
            "disk",
            "mac",
            "uuid",
            "hardware",
        ]

        hardware_mentioned = sum(
            1 for keyword in hardware_keywords
            if keyword in class_docstring.lower()
        )

        assert hardware_mentioned >= 2, (
            f"Class docstring must mention hardware components. "
            f"Current docstring: '{class_docstring}'\n\n"
            f"Add mention of spoofed components: CPU ID, motherboard serial, BIOS serial, "
            f"disk serials, MAC addresses, system UUID, etc."
        )


class TestMethodDocstringComprehensiveness:
    """Test that critical methods have comprehensive docstrings."""

    def test_apply_spoof_has_docstring(self) -> None:
        """apply_spoof method must have comprehensive docstring."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        import re
        method_match = re.search(
            r'def apply_spoof\(.*?\).*?:\s*"""(.*?)"""',
            source_code,
            re.DOTALL
        )

        assert method_match is not None, (
            "apply_spoof method MUST have a docstring explaining parameters and return values."
        )

        docstring = method_match.group(1)
        assert len(docstring) >= 50, (
            f"apply_spoof docstring must explain method parameter and return value. "
            f"Current: '{docstring}'"
        )

    def test_driver_method_documents_not_implemented(self) -> None:
        """_apply_driver_spoof must clearly state it's not implemented."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        import re
        method_match = re.search(
            r'def _apply_driver_spoof\(.*?\).*?:\s*"""(.*?)"""',
            source_code,
            re.DOTALL
        )

        assert method_match is not None, (
            "_apply_driver_spoof MUST have docstring stating driver approach is not implemented."
        )

        docstring = method_match.group(1)
        assert "not implemented" in docstring.lower() or "false" in docstring.lower(), (
            f"_apply_driver_spoof docstring must clearly state driver approach is not implemented. "
            f"Current: '{docstring}'"
        )

    def test_virtual_method_documents_not_implemented(self) -> None:
        """_apply_virtual_spoof must clearly state it's not implemented."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        import re
        method_match = re.search(
            r'def _apply_virtual_spoof\(.*?\).*?:\s*"""(.*?)"""',
            source_code,
            re.DOTALL
        )

        assert method_match is not None, (
            "_apply_virtual_spoof MUST have docstring stating virtual approach is not implemented."
        )

        docstring = method_match.group(1)
        assert "not implemented" in docstring.lower() or "false" in docstring.lower(), (
            f"_apply_virtual_spoof docstring must clearly state virtual approach is not implemented. "
            f"Current: '{docstring}'"
        )


class TestDocumentationProvidesSolution:
    """Test that documentation provides clear path for users."""

    def test_documentation_explains_which_methods_work(self) -> None:
        """Documentation must clearly state which methods work and which don't."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        docstring = ast.get_docstring(module_ast)

        if docstring is None:
            pytest.fail("Module must have docstring")

        working_indicators = ["registry", "hook", "memory"]
        not_working_indicators = ["driver", "not implemented", "false", "virtual"]

        has_working_info = any(
            indicator in docstring.lower()
            for indicator in working_indicators
        )

        has_limitation_info = any(
            indicator in docstring.lower()
            for indicator in not_working_indicators
        )

        assert has_working_info and has_limitation_info, (
            f"Documentation must clearly state which methods work and which don't. "
            f"Current docstring: '{docstring}'\n\n"
            f"Add clear statements like:\n"
            f"- REGISTRY: Works (requires admin privileges)\n"
            f"- HOOK: Works (inline API hooking)\n"
            f"- MEMORY: Works (process memory patching)\n"
            f"- DRIVER: Not implemented (returns False)\n"
            f"- VIRTUAL: Not implemented (returns False)"
        )

    def test_documentation_provides_usage_example_or_guidance(self) -> None:
        """Documentation should provide usage guidance or reference to examples."""
        source_file = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "hardware_spoofer.py"
        source_code = source_file.read_text(encoding="utf-8")

        module_ast = ast.parse(source_code)
        module_docstring = ast.get_docstring(module_ast)

        import re
        class_match = re.search(
            r'class HardwareFingerPrintSpoofer.*?:\s*"""(.*?)"""',
            source_code,
            re.DOTALL
        )

        class_docstring = class_match.group(1) if class_match else ""

        combined_docs = (module_docstring or "") + " " + class_docstring

        usage_indicators = [
            "example",
            "usage",
            "use",
            "apply",
            "spoof",
            "generate",
        ]

        has_usage_info = any(
            indicator in combined_docs.lower()
            for indicator in usage_indicators
        )

        if not has_usage_info:
            pytest.skip(
                "Optional: Consider adding usage example to module or class docstring. "
                "Example: 'spoofer = HardwareFingerPrintSpoofer(); "
                "spoofer.generate_spoofed_hardware(); spoofer.apply_spoof(SpoofMethod.REGISTRY)'"
            )
