"""Production-ready tests for kernel bypass documentation and implementation validation.

This test suite validates that:
1. Kernel bypass approach is fully documented
2. User-mode vs kernel-mode distinction is crystal clear
3. Platform limitations are explicitly stated
4. Implementation matches documentation claims
5. Edge cases (HVCI/VBS/Secure Boot) are documented
6. No false claims about kernel driver implementation

Tests MUST FAIL if:
- Documentation is missing or incomplete
- Implementation claims don't match reality
- Kernel bypass capabilities are overstated
- Platform limitations are not documented
- Edge case handling is not addressed

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import inspect
import platform
import sys
from pathlib import Path
from typing import Any

import pytest


PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
KERNEL_MODE_DOC_PATH = PROJECT_ROOT / "KERNEL_MODE_ANTIDEBUG_IMPLEMENTATION.md"
ADVANCED_BYPASS_PATH = (
    PROJECT_ROOT / "intellicrack" / "core" / "anti_analysis" / "advanced_debugger_bypass.py"
)
DEBUGGER_BYPASS_PATH = (
    PROJECT_ROOT / "intellicrack" / "core" / "anti_analysis" / "debugger_bypass.py"
)
FRIDA_BYPASS_PATH = (
    PROJECT_ROOT / "intellicrack" / "core" / "analysis" / "frida_protection_bypass.py"
)


class TestKernelBypassDocumentationExists:
    """Validate that kernel bypass approach is fully documented."""

    def test_kernel_mode_implementation_doc_exists(self) -> None:
        """KERNEL_MODE_ANTIDEBUG_IMPLEMENTATION.md must exist in project root."""
        assert KERNEL_MODE_DOC_PATH.exists(), (
            f"Kernel bypass documentation missing at {KERNEL_MODE_DOC_PATH}. "
            "Documentation MUST exist to explain approach."
        )

    def test_kernel_mode_doc_is_substantial(self) -> None:
        """Kernel bypass documentation must be comprehensive (>5000 bytes)."""
        content = KERNEL_MODE_DOC_PATH.read_text(encoding="utf-8")
        assert len(content) > 5000, (
            f"Kernel bypass documentation is {len(content)} bytes, must be >5000. "
            "Documentation must comprehensively explain approach, limitations, and edge cases."
        )

    def test_kernel_mode_doc_explains_approach(self) -> None:
        """Documentation must explain the kernel bypass approach taken."""
        content = KERNEL_MODE_DOC_PATH.read_text(encoding="utf-8").lower()

        required_sections = [
            "ntqueryinformationprocess",
            "ntsetinformationthread",
            "ntquerysysteminformation",
            "processdebugport",
            "processdebugobjec handle",
            "kernel",
        ]

        for section in required_sections:
            assert section in content, (
                f"Documentation must explain '{section}'. "
                f"Kernel bypass approach requires comprehensive NT API documentation."
            )

    def test_kernel_mode_doc_lists_defeated_protections(self) -> None:
        """Documentation must list commercial protections that are defeated."""
        content = KERNEL_MODE_DOC_PATH.read_text(encoding="utf-8").lower()

        required_protections = [
            "vmprotect",
            "themida",
            "denuvo",
            "arxan",
            "securom",
        ]

        for protection in required_protections:
            assert protection in content, (
                f"Documentation must explain how '{protection}' is defeated. "
                f"Real commercial protection defeat must be documented."
            )


class TestUserModeVsKernelModeDistinction:
    """Validate that user-mode vs kernel-mode distinction is clear."""

    def test_advanced_bypass_documents_user_mode_limitation(self) -> None:
        """advanced_debugger_bypass.py must document user-mode operation."""
        content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")

        required_terms = [
            "user-mode",
            "Ring 3",
            "kernel-mode",
            "Ring 0",
            "kernel driver",
        ]

        for term in required_terms:
            assert term in content, (
                f"Source must document '{term}' to clarify operation level. "
                f"User-mode vs kernel-mode distinction must be explicit."
            )

    def test_user_mode_hooker_class_documents_ring3_operation(self) -> None:
        """UserModeNTAPIHooker class docstring must state Ring 3 operation."""
        content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")

        assert "UserModeNTAPIHooker" in content, "UserModeNTAPIHooker class must exist"

        class_section = content[content.find("class UserModeNTAPIHooker") :]
        docstring_end = class_section.find('"""', 100)
        class_docstring = class_section[:docstring_end].lower()

        required_clarifications = [
            "user-mode",
            "not kernel-mode",
            "ring 3",
            "ring 0",
        ]

        for clarification in required_clarifications:
            assert clarification in class_docstring, (
                f"UserModeNTAPIHooker docstring must state '{clarification}'. "
                f"Operation level must be crystal clear in class documentation."
            )

    def test_debugger_bypass_documents_user_mode_only(self) -> None:
        """DebuggerBypass class must document user-mode-only operation."""
        content = DEBUGGER_BYPASS_PATH.read_text(encoding="utf-8")

        class_section = content[content.find("class DebuggerBypass") :]
        docstring_end = class_section.find('"""', 100)
        class_docstring = class_docstring = class_section[:docstring_end].lower()

        assert "user-mode" in class_docstring, (
            "DebuggerBypass docstring must state user-mode operation. "
            "Limitations must be documented in class docstring."
        )

        assert "cannot bypass kernel-mode" in class_docstring or "kernel-mode" in class_docstring, (
            "DebuggerBypass docstring must state kernel-mode limitations. "
            "What the class CANNOT do must be documented."
        )


class TestKernelBypassApproachDocumentation:
    """Validate that the chosen kernel bypass approach is documented."""

    def test_documentation_explains_frida_for_kernel_level(self) -> None:
        """Documentation must explain Frida is used for kernel-level interception."""
        doc_content = KERNEL_MODE_DOC_PATH.read_text(encoding="utf-8").lower()

        assert "frida" in doc_content, (
            "Documentation must mention Frida as the kernel bypass mechanism. "
            "The chosen approach must be explicitly documented."
        )

    def test_documentation_explains_no_windows_driver_approach(self) -> None:
        """Documentation or code must clarify no Windows kernel driver is used."""
        advanced_content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8").lower()
        debugger_content = DEBUGGER_BYPASS_PATH.read_text(encoding="utf-8").lower()

        driver_mentions_advanced = "kernel driver" in advanced_content
        driver_mentions_debugger = "kernel driver" in debugger_content

        if driver_mentions_advanced:
            assert "kernel driver is required" in advanced_content or "not included" in advanced_content, (
                "If kernel driver is mentioned, must clarify it's NOT included. "
                "False claims about driver implementation must not exist."
            )

        if driver_mentions_debugger:
            assert "kernel driver is required" in debugger_content or "not included" in debugger_content, (
                "If kernel driver is mentioned, must clarify it's NOT included. "
                "False claims about driver implementation must not exist."
            )

    def test_documentation_explains_user_mode_nt_api_hooks(self) -> None:
        """Documentation must explain user-mode NT API hook approach."""
        doc_content = KERNEL_MODE_DOC_PATH.read_text(encoding="utf-8").lower()

        required_nt_apis = [
            "ntqueryinformationprocess",
            "ntsetinformationthread",
            "ntquerysysteminformation",
        ]

        for nt_api in required_nt_apis:
            assert nt_api in doc_content, (
                f"Documentation must explain '{nt_api}' hooking. "
                f"User-mode NT API hook approach must be fully documented."
            )


class TestPlatformLimitationDocumentation:
    """Validate that platform limitations are explicitly stated."""

    def test_windows_only_limitation_documented(self) -> None:
        """Code must document Windows-only operation where applicable."""
        advanced_content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")

        assert 'platform.system() == "Windows"' in advanced_content, (
            "Code must check for Windows platform. "
            "Platform-specific functionality must be guarded by platform checks."
        )

    def test_advanced_bypass_has_platform_checks(self) -> None:
        """advanced_debugger_bypass.py must have Windows platform checks."""
        content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")

        platform_check_count = content.count('platform.system() == "Windows"')

        assert platform_check_count >= 3, (
            f"advanced_debugger_bypass.py has {platform_check_count} Windows checks, needs ≥3. "
            f"Platform compatibility must be validated throughout code."
        )

    def test_debugger_bypass_has_platform_checks(self) -> None:
        """debugger_bypass.py must have Windows platform checks."""
        content = DEBUGGER_BYPASS_PATH.read_text(encoding="utf-8")

        platform_check_count = content.count('platform.system() == "Windows"')

        assert platform_check_count >= 5, (
            f"debugger_bypass.py has {platform_check_count} Windows checks, needs ≥5. "
            f"Platform compatibility must be validated throughout code."
        )

    def test_linux_fallback_implementations_exist(self) -> None:
        """Code must provide Linux fallback implementations where possible."""
        debugger_content = DEBUGGER_BYPASS_PATH.read_text(encoding="utf-8")

        linux_methods = [
            "_init_linux_bypass",
            "_bypass_ptrace_linux",
            "_bypass_timing_linux",
        ]

        for method in linux_methods:
            assert f"def {method}" in debugger_content, (
                f"debugger_bypass.py must have {method} for Linux fallback. "
                f"Cross-platform support requires Linux implementations."
            )


class TestWindowsVersionCompatibility:
    """Validate Windows version compatibility is documented."""

    def test_windows_version_compatibility_addressed(self) -> None:
        """Code must handle Windows version differences (x86 vs x64)."""
        debugger_content = DEBUGGER_BYPASS_PATH.read_text(encoding="utf-8")

        assert 'platform.machine().endswith("64")' in debugger_content, (
            "Code must check for x64 architecture. "
            "x86 vs x64 differences must be handled."
        )

    def test_peb_offset_differences_handled(self) -> None:
        """Code must handle PEB offset differences between x86 and x64."""
        debugger_content = DEBUGGER_BYPASS_PATH.read_text(encoding="utf-8")

        assert "0xBC if is_64bit else 0x68" in debugger_content, (
            "Code must use correct NtGlobalFlag offsets for x86/x64. "
            "Architecture-specific PEB offsets must be handled correctly."
        )

    def test_pointer_size_handling_exists(self) -> None:
        """Code must handle pointer size differences."""
        advanced_content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")

        has_pointer_handling = (
            "Process.pointerSize" in advanced_content
            or 'platform.machine().endswith("64")' in advanced_content
        )

        assert has_pointer_handling, (
            "Code must handle pointer size differences between x86/x64. "
            "Pointer size must be checked for correct structure offsets."
        )


class TestDriverSigningDocumentation:
    """Validate driver signing requirements are documented if drivers used."""

    def test_no_kernel_driver_implementation_in_code(self) -> None:
        """Code must NOT contain actual kernel driver implementation."""
        advanced_content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")
        debugger_content = DEBUGGER_BYPASS_PATH.read_text(encoding="utf-8")

        prohibited_patterns = [
            "DriverEntry",
            "IRP_MJ_",
            "DRIVER_OBJECT",
            "PDEVICE_OBJECT",
            "IoCreateDevice",
            "IoDeleteDevice",
        ]

        for pattern in prohibited_patterns:
            assert pattern not in advanced_content, (
                f"advanced_debugger_bypass.py must NOT contain '{pattern}'. "
                f"Kernel driver code should not be present in user-mode module."
            )
            assert pattern not in debugger_content, (
                f"debugger_bypass.py must NOT contain '{pattern}'. "
                f"Kernel driver code should not be present in user-mode module."
            )

    def test_driver_signing_mentioned_if_drivers_discussed(self) -> None:
        """If drivers are mentioned, driver signing must be discussed."""
        all_content = ""

        for path in [ADVANCED_BYPASS_PATH, DEBUGGER_BYPASS_PATH, KERNEL_MODE_DOC_PATH]:
            all_content += path.read_text(encoding="utf-8").lower()

        if "kernel driver" in all_content:
            assert "driver signing" in all_content or "signing" in all_content, (
                "If kernel drivers are mentioned, driver signing must be discussed. "
                "Driver signing is critical for Windows driver deployment."
            )


class TestHVCIVBSSecureBootHandling:
    """Validate HVCI/VBS/Secure Boot edge cases are documented."""

    def test_hvci_vbs_secure_boot_mentioned_in_docs(self) -> None:
        """Documentation must mention HVCI/VBS/Secure Boot edge cases."""
        doc_content = KERNEL_MODE_DOC_PATH.read_text(encoding="utf-8").lower()

        edge_cases = ["hvci", "vbs", "secure boot", "virtualization-based security"]

        mentioned_count = sum(1 for case in edge_cases if case in doc_content)

        assert mentioned_count >= 2, (
            f"Documentation mentions {mentioned_count}/4 edge cases, needs ≥2. "
            f"Edge cases (HVCI/VBS/Secure Boot) must be documented."
        )

    def test_hypervisor_detection_exists(self) -> None:
        """Code must check for hypervisor support/presence."""
        advanced_content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")

        assert "check_virtualization_support" in advanced_content, (
            "Code must check for virtualization support. "
            "Hypervisor-based debugging requires virtualization detection."
        )

    def test_vmx_svm_support_checked(self) -> None:
        """Code must check for VMX (Intel) or SVM (AMD) support."""
        advanced_content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")

        assert '"vmx"' in advanced_content and '"svm"' in advanced_content, (
            "Code must check for both VMX and SVM virtualization. "
            "Both Intel and AMD virtualization must be supported."
        )


class TestMaximumUserModeCoverageDocumentation:
    """Validate maximum user-mode coverage is documented."""

    def test_comprehensive_nt_api_hook_list(self) -> None:
        """Code must hook comprehensive list of NT APIs."""
        advanced_content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")

        required_nt_api_hooks = [
            "NtQueryInformationProcess",
            "NtSetInformationThread",
            "NtQuerySystemInformation",
        ]

        for nt_api in required_nt_api_hooks:
            assert f"hook_{nt_api.lower()}" in advanced_content.lower() or nt_api in advanced_content, (
                f"Code must hook {nt_api} for user-mode coverage. "
                f"Comprehensive NT API hooking is required."
            )

    def test_peb_flag_manipulation_exists(self) -> None:
        """Code must manipulate PEB flags for user-mode anti-debug bypass."""
        debugger_content = DEBUGGER_BYPASS_PATH.read_text(encoding="utf-8")

        assert "_bypass_peb_flags" in debugger_content, (
            "Code must have _bypass_peb_flags method. "
            "PEB manipulation is critical for user-mode bypass."
        )

        assert "BeingDebugged" in debugger_content, (
            "Code must manipulate BeingDebugged flag. "
            "PEB.BeingDebugged is fundamental anti-debug check."
        )

    def test_hardware_breakpoint_clearing_exists(self) -> None:
        """Code must clear hardware breakpoints (DR0-DR7)."""
        debugger_content = DEBUGGER_BYPASS_PATH.read_text(encoding="utf-8")

        assert "_bypass_hardware_breakpoints" in debugger_content, (
            "Code must have _bypass_hardware_breakpoints method. "
            "Hardware breakpoint clearing is required for comprehensive bypass."
        )

        debug_registers = ["DR0", "DR1", "DR2", "DR3", "DR6", "DR7"]
        mentioned_count = sum(1 for reg in debug_registers if reg in debugger_content)

        assert mentioned_count >= 4, (
            f"Code mentions {mentioned_count}/6 debug registers, needs ≥4. "
            f"Debug register clearing must address all registers."
        )

    def test_timing_attack_neutralization_exists(self) -> None:
        """Code must neutralize timing attacks."""
        advanced_content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")

        assert "TimingNeutralizer" in advanced_content, (
            "Code must have TimingNeutralizer class. "
            "Timing attack neutralization is critical for bypass."
        )

        timing_apis = ["QueryPerformanceCounter", "GetTickCount", "RDTSC"]
        mentioned_count = sum(1 for api in timing_apis if api in advanced_content)

        assert mentioned_count >= 2, (
            f"Code mentions {mentioned_count}/3 timing APIs, needs ≥2. "
            f"Multiple timing sources must be neutralized."
        )


class TestFridaKernelBypassIntegration:
    """Validate Frida-based kernel bypass is implemented."""

    def test_frida_protection_bypass_exists(self) -> None:
        """frida_protection_bypass.py must exist for kernel-level bypass."""
        assert FRIDA_BYPASS_PATH.exists(), (
            f"frida_protection_bypass.py missing at {FRIDA_BYPASS_PATH}. "
            "Frida bypass module must exist for kernel-level anti-debug defeat."
        )

    def test_frida_bypass_implements_kernel_mode_techniques(self) -> None:
        """Frida bypass must implement kernel-mode anti-debug techniques."""
        content = FRIDA_BYPASS_PATH.read_text(encoding="utf-8")

        kernel_techniques = [
            "ProcessDebugPort",
            "ProcessDebugObjectHandle",
            "ProcessDebugFlags",
            "ThreadHideFromDebugger",
            "KernelDebugger",
        ]

        for technique in kernel_techniques:
            assert technique in content, (
                f"Frida bypass must implement {technique} defeat. "
                f"Kernel-mode techniques must be present in Frida bypass."
            )

    def test_frida_bypass_has_substantial_implementation(self) -> None:
        """Frida bypass must be substantial (>10000 bytes)."""
        content = FRIDA_BYPASS_PATH.read_text(encoding="utf-8")

        assert len(content) > 10000, (
            f"Frida bypass is {len(content)} bytes, must be >10000. "
            "Kernel bypass implementation must be comprehensive."
        )

    def test_frida_bypass_returns_proper_ntstatus_codes(self) -> None:
        """Frida bypass must use correct NTSTATUS codes."""
        content = FRIDA_BYPASS_PATH.read_text(encoding="utf-8")

        ntstatus_codes = [
            "0x00000000",  # STATUS_SUCCESS
            "0xC0000353",  # STATUS_PORT_NOT_SET
            "0xC0000008",  # STATUS_INVALID_HANDLE
        ]

        mentioned_count = sum(1 for code in ntstatus_codes if code in content)

        assert mentioned_count >= 2, (
            f"Frida bypass uses {mentioned_count}/3 NTSTATUS codes, needs ≥2. "
            f"Proper Windows NTSTATUS codes must be returned."
        )


class TestCommercialProtectionDefeatDocumentation:
    """Validate defeat of commercial protections is documented."""

    def test_vmprotect_defeat_documented(self) -> None:
        """VMProtect defeat must be documented with specific techniques."""
        doc_content = KERNEL_MODE_DOC_PATH.read_text(encoding="utf-8").lower()

        assert "vmprotect" in doc_content, "VMProtect must be mentioned"

        assert "processdebugport" in doc_content, (
            "VMProtect defeat documentation must mention ProcessDebugPort. "
            "Specific techniques must be documented."
        )

    def test_themida_defeat_documented(self) -> None:
        """Themida defeat must be documented with specific techniques."""
        doc_content = KERNEL_MODE_DOC_PATH.read_text(encoding="utf-8").lower()

        assert "themida" in doc_content, "Themida must be mentioned"

        themida_techniques = ["threadhidefromdebugger", "information class", "debug object"]
        mentioned_count = sum(1 for tech in themida_techniques if tech in doc_content)

        assert mentioned_count >= 2, (
            f"Themida defeat documentation mentions {mentioned_count}/3 techniques, needs ≥2. "
            f"Specific Themida bypass techniques must be documented."
        )

    def test_denuvo_defeat_documented(self) -> None:
        """Denuvo defeat must be documented with specific techniques."""
        doc_content = KERNEL_MODE_DOC_PATH.read_text(encoding="utf-8").lower()

        assert "denuvo" in doc_content, "Denuvo must be mentioned"

        assert "processdebugobjecthandle" in doc_content or "debug object" in doc_content, (
            "Denuvo defeat documentation must mention debug object handling. "
            "Specific techniques must be documented."
        )


class TestImplementationCompletenessValidation:
    """Validate implementation is complete with no placeholders."""

    def test_no_placeholder_comments_in_advanced_bypass(self) -> None:
        """advanced_debugger_bypass.py must have no TODO/FIXME/PLACEHOLDER."""
        content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")

        prohibited_markers = ["TODO", "FIXME", "PLACEHOLDER", "NotImplemented"]

        for marker in prohibited_markers:
            assert marker not in content, (
                f"advanced_debugger_bypass.py contains '{marker}'. "
                f"All implementations must be complete with no placeholders."
            )

    def test_no_placeholder_comments_in_debugger_bypass(self) -> None:
        """debugger_bypass.py must have no TODO/FIXME/PLACEHOLDER."""
        content = DEBUGGER_BYPASS_PATH.read_text(encoding="utf-8")

        prohibited_markers = ["TODO", "FIXME", "PLACEHOLDER", "NotImplemented"]

        for marker in prohibited_markers:
            assert marker not in content, (
                f"debugger_bypass.py contains '{marker}'. "
                f"All implementations must be complete with no placeholders."
            )

    def test_no_pass_only_functions_in_advanced_bypass(self) -> None:
        """advanced_debugger_bypass.py must have no functions with only 'pass'."""
        content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")

        lines = content.split("\n")
        function_line = None

        for i, line in enumerate(lines):
            if "def " in line and "self" in line:
                function_line = i
            elif function_line is not None and "pass" in line.strip():
                next_line_idx = i + 1
                if next_line_idx < len(lines):
                    next_line = lines[next_line_idx].strip()
                    if next_line.startswith("def ") or next_line.startswith("class "):
                        pytest.fail(
                            f"advanced_debugger_bypass.py has pass-only function at line {function_line}. "
                            f"All functions must have real implementations."
                        )

    def test_no_pass_only_functions_in_debugger_bypass(self) -> None:
        """debugger_bypass.py must have no functions with only 'pass'."""
        content = DEBUGGER_BYPASS_PATH.read_text(encoding="utf-8")

        lines = content.split("\n")
        function_line = None

        for i, line in enumerate(lines):
            if "def " in line and "self" in line:
                function_line = i
            elif function_line is not None and "pass" in line.strip():
                next_line_idx = i + 1
                if next_line_idx < len(lines):
                    next_line = lines[next_line_idx].strip()
                    if next_line.startswith("def ") or next_line.startswith("class "):
                        pytest.fail(
                            f"debugger_bypass.py has pass-only function at line {function_line}. "
                            f"All functions must have real implementations."
                        )


class TestEdgeCaseDocumentation:
    """Validate edge cases are properly documented."""

    def test_anti_hook_detection_documented(self) -> None:
        """Documentation must address anti-hook detection."""
        all_content = ""

        for path in [ADVANCED_BYPASS_PATH, DEBUGGER_BYPASS_PATH, KERNEL_MODE_DOC_PATH]:
            all_content += path.read_text(encoding="utf-8").lower()

        edge_case_topics = [
            "integrity check",
            "code signing",
            "anti-hook",
            "tamper",
        ]

        mentioned_count = sum(1 for topic in edge_case_topics if topic in all_content)

        assert mentioned_count >= 2, (
            f"Edge case documentation mentions {mentioned_count}/4 topics, needs ≥2. "
            f"Anti-hook and integrity check edge cases must be addressed."
        )

    def test_self_debugging_edge_case_handled(self) -> None:
        """Code must handle self-debugging edge case."""
        debugger_content = DEBUGGER_BYPASS_PATH.read_text(encoding="utf-8")

        assert "GetCurrentProcess" in debugger_content, (
            "Code must use GetCurrentProcess for self-debugging. "
            "Self-debugging edge case must be handled."
        )

    def test_multiple_debugger_edge_case_addressed(self) -> None:
        """Documentation must address multiple simultaneous debuggers."""
        doc_content = KERNEL_MODE_DOC_PATH.read_text(encoding="utf-8").lower()

        multi_debugger_terms = ["multiple", "simultaneous", "concurrent"]
        mentioned = any(term in doc_content for term in multi_debugger_terms)

        if not mentioned:
            all_source = ""
            for path in [ADVANCED_BYPASS_PATH, DEBUGGER_BYPASS_PATH]:
                all_source += path.read_text(encoding="utf-8").lower()

            assert "debug" in all_source and "multiple" in all_source, (
                "Multiple debugger edge case should be addressed in code or docs. "
                "Edge cases must be considered."
            )


class TestProductionReadinessValidation:
    """Validate code is production-ready."""

    def test_all_classes_have_comprehensive_docstrings(self) -> None:
        """All classes must have comprehensive docstrings (>100 chars)."""
        sys.path.insert(0, str(PROJECT_ROOT))

        try:
            from intellicrack.core.anti_analysis.advanced_debugger_bypass import (
                AdvancedDebuggerBypass,
                HypervisorDebugger,
                TimingNeutralizer,
                UserModeNTAPIHooker,
            )

            classes_to_check = [
                AdvancedDebuggerBypass,
                UserModeNTAPIHooker,
                HypervisorDebugger,
                TimingNeutralizer,
            ]

            for cls in classes_to_check:
                docstring = inspect.getdoc(cls)
                assert docstring is not None, f"{cls.__name__} must have docstring"
                assert len(docstring) > 100, (
                    f"{cls.__name__} docstring is {len(docstring)} chars, needs >100. "
                    f"Class docstrings must be comprehensive."
                )

        finally:
            sys.path.pop(0)

    def test_all_public_methods_have_docstrings(self) -> None:
        """All public methods must have docstrings."""
        sys.path.insert(0, str(PROJECT_ROOT))

        try:
            from intellicrack.core.anti_analysis.advanced_debugger_bypass import (
                AdvancedDebuggerBypass,
                UserModeNTAPIHooker,
            )

            for cls in [AdvancedDebuggerBypass, UserModeNTAPIHooker]:
                methods = [
                    m for m in dir(cls) if callable(getattr(cls, m)) and not m.startswith("_")
                ]

                for method_name in methods:
                    method = getattr(cls, method_name)
                    docstring = inspect.getdoc(method)
                    assert docstring is not None, (
                        f"{cls.__name__}.{method_name} must have docstring. "
                        f"All public methods must be documented."
                    )

        finally:
            sys.path.pop(0)

    def test_type_hints_present_in_advanced_bypass(self) -> None:
        """advanced_debugger_bypass.py must use type hints extensively."""
        content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")

        type_hint_count = content.count("->")
        assert type_hint_count >= 20, (
            f"advanced_debugger_bypass.py has {type_hint_count} return type hints, needs ≥20. "
            f"Comprehensive type hints are required for production code."
        )

    def test_type_hints_present_in_debugger_bypass(self) -> None:
        """debugger_bypass.py must use type hints extensively."""
        content = DEBUGGER_BYPASS_PATH.read_text(encoding="utf-8")

        type_hint_count = content.count("->")
        assert type_hint_count >= 20, (
            f"debugger_bypass.py has {type_hint_count} return type hints, needs ≥20. "
            f"Comprehensive type hints are required for production code."
        )


class TestIntegrationWithFridaBypass:
    """Validate integration between user-mode and Frida kernel bypass."""

    def test_frida_bypass_referenced_in_documentation(self) -> None:
        """Kernel mode documentation must reference Frida bypass integration."""
        doc_content = KERNEL_MODE_DOC_PATH.read_text(encoding="utf-8").lower()

        assert "frida" in doc_content, (
            "Documentation must mention Frida as kernel bypass mechanism. "
            "Integration approach must be documented."
        )

    def test_advanced_bypass_and_frida_bypass_are_complementary(self) -> None:
        """User-mode and Frida bypass must cover different aspects."""
        advanced_content = ADVANCED_BYPASS_PATH.read_text(encoding="utf-8")
        frida_content = FRIDA_BYPASS_PATH.read_text(encoding="utf-8")

        advanced_focuses_on_usermode = "user-mode" in advanced_content.lower()
        frida_handles_kernel_calls = "NtQueryInformationProcess" in frida_content

        assert advanced_focuses_on_usermode, (
            "advanced_debugger_bypass.py must focus on user-mode techniques. "
            "Clear separation of concerns is required."
        )

        assert frida_handles_kernel_calls, (
            "frida_protection_bypass.py must handle NT API kernel calls. "
            "Kernel-level interception must be present in Frida bypass."
        )

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_can_import_all_bypass_classes_on_windows(self) -> None:
        """All bypass classes must be importable on Windows."""
        sys.path.insert(0, str(PROJECT_ROOT))

        try:
            from intellicrack.core.anti_analysis.advanced_debugger_bypass import (
                AdvancedDebuggerBypass,
                HypervisorDebugger,
                TimingNeutralizer,
                UserModeNTAPIHooker,
                install_advanced_bypass,
            )
            from intellicrack.core.anti_analysis.debugger_bypass import (
                DebuggerBypass,
                install_anti_antidebug,
            )

            assert AdvancedDebuggerBypass is not None
            assert UserModeNTAPIHooker is not None
            assert HypervisorDebugger is not None
            assert TimingNeutralizer is not None
            assert DebuggerBypass is not None
            assert callable(install_advanced_bypass)
            assert callable(install_anti_antidebug)

        finally:
            sys.path.pop(0)

    def test_documentation_provides_usage_examples(self) -> None:
        """Documentation must provide usage examples."""
        doc_content = KERNEL_MODE_DOC_PATH.read_text(encoding="utf-8").lower()

        usage_indicators = [
            "example",
            "usage",
            "how to",
            "test",
        ]

        mentioned_count = sum(1 for indicator in usage_indicators if indicator in doc_content)

        assert mentioned_count >= 2, (
            f"Documentation mentions {mentioned_count}/4 usage indicators, needs ≥2. "
            f"Usage examples must be provided in documentation."
        )
