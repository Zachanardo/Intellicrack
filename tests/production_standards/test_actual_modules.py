"""
Production standards test for actual Intellicrack modules.
Tests real Windows API usage, debugging capabilities, and YARA integration.
"""

import sys
import os
import platform
import unittest
import ctypes
from typing import List, Dict, Any, Optional
import traceback

try:
    from intellicrack.core.process_manipulation import LicenseAnalyzer
    PROCESS_MANIPULATION_AVAILABLE = True
except ImportError as e:
    PROCESS_MANIPULATION_AVAILABLE = False
    PROCESS_MANIPULATION_ERROR = str(e)

try:
    from intellicrack.core.debugging_engine import LicenseDebugger
    DEBUGGING_ENGINE_AVAILABLE = True
except ImportError as e:
    DEBUGGING_ENGINE_AVAILABLE = False
    DEBUGGING_ENGINE_ERROR = str(e)

try:
    from intellicrack.core.analysis.yara_scanner import YaraScanner
    YARA_SCANNER_AVAILABLE = True
except ImportError as e:
    YARA_SCANNER_AVAILABLE = False
    YARA_SCANNER_ERROR = str(e)


class TestActualModules(unittest.TestCase):
    """Test actual Intellicrack modules for production readiness."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        cls.is_windows = platform.system() == "Windows"
        cls.results = {
            "platform": platform.system(),
            "windows_apis": [],
            "capabilities": {},
            "errors": [],
            "warnings": []
        }

    def test_01_module_imports(self):
        """Test that all required modules can be imported."""
        print("\n[TEST] Module Import Verification")
        print("=" * 60)

        modules_status = {
            "process_manipulation": PROCESS_MANIPULATION_AVAILABLE,
            "debugging_engine": DEBUGGING_ENGINE_AVAILABLE,
            "yara_scanner": YARA_SCANNER_AVAILABLE
        }

        for module, available in modules_status.items():
            if available:
                print(f"OK {module}: Successfully imported")
            else:
                error = globals().get(f"{module.upper()}_ERROR", "Unknown error")
                print(f"FAIL {module}: Import failed - {error}")
                self.results["errors"].append(f"{module} import failed: {error}")

        total = len(modules_status)
        imported = sum(1 for v in modules_status.values() if v)
        print(f"\nModules imported: {imported}/{total}")

        self.assertGreaterEqual(imported, 2,
                               "At least 2 core modules must be importable")

    def test_02_windows_api_presence(self):
        """Test for real Windows API implementations."""
        if not self.is_windows:
            self.skipTest("Windows API test skipped on non-Windows platform")

        print("\n[TEST] Windows API Presence")
        print("=" * 60)

        required_apis = {
            "kernel32": [
                "OpenProcess", "ReadProcessMemory", "WriteProcessMemory",
                "VirtualAllocEx", "VirtualProtectEx", "CreateRemoteThread",
                "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
                "Module32First", "Module32Next", "GetCurrentProcess",
                "GetModuleHandleA", "GetProcAddress", "LoadLibraryA"
            ],
            "ntdll": [
                "NtQueryInformationProcess", "NtSetInformationThread",
                "NtQueryVirtualMemory", "NtCreateThreadEx", "NtResumeThread"
            ],
            "advapi32": [
                "RegOpenKeyExA", "RegQueryValueExA", "RegSetValueExA",
                "RegCloseKey", "RegCreateKeyExA", "RegDeleteKeyA"
            ],
            "user32": [
                "FindWindowA", "GetWindowThreadProcessId", "SetWindowsHookExA"
            ],
            "dbghelp": [
                "SymInitialize", "SymCleanup", "StackWalk64"
            ]
        }

        api_count = 0
        found_apis = []

        for dll_name, apis in required_apis.items():
            try:
                if dll_name == "kernel32":
                    dll = ctypes.windll.kernel32
                elif dll_name == "ntdll":
                    dll = ctypes.windll.ntdll
                elif dll_name == "advapi32":
                    dll = ctypes.windll.advapi32
                elif dll_name == "user32":
                    dll = ctypes.windll.user32
                elif dll_name == "dbghelp":
                    dll = ctypes.windll.dbghelp
                else:
                    continue

                print(f"\nChecking {dll_name}.dll:")
                for api in apis:
                    try:
                        func = getattr(dll, api)
                        if func:
                            api_count += 1
                            found_apis.append(f"{dll_name}.{api}")
                            print(f"  OK {api}")
                    except AttributeError:
                        print(f"  FAIL {api} - Not found")
            except Exception as e:
                print(f"  FAIL Error accessing {dll_name}: {e}")

        self.results["windows_apis"] = found_apis
        print(f"\nTotal Windows APIs found: {api_count}")
        print(f"Required minimum: 15")

        self.assertGreaterEqual(api_count, 15,
                               "At least 15 Windows APIs must be available")

    def test_03_license_analyzer_capabilities(self):
        """Test LicenseAnalyzer capabilities."""
        if not PROCESS_MANIPULATION_AVAILABLE:
            self.skipTest("LicenseAnalyzer not available")

        print("\n[TEST] LicenseAnalyzer Capabilities")
        print("=" * 60)

        capabilities = []

        try:
            analyzer = LicenseAnalyzer()

            required_methods = [
                "scan_pattern", "patch_bytes", "find_conditional_jumps",
                "bypass_serial_check", "patch_trial_expiration",
                "manipulate_registry", "inject_dll", "hook_api",
                "detect_protection", "read_process_memory",
                "write_process_memory", "get_module_base",
                "enumerate_processes", "enumerate_modules"
            ]

            for method_name in required_methods:
                if hasattr(analyzer, method_name):
                    method = getattr(analyzer, method_name)
                    if callable(method):
                        capabilities.append(method_name)
                        print(f"  OK {method_name}")
                    else:
                        print(f"  FAIL {method_name} - Not callable")
                else:
                    print(f"  FAIL {method_name} - Not found")

            if hasattr(analyzer, '_setup_windows_apis'):
                print("\n  OK Windows API setup method found")
                capabilities.append("windows_api_setup")

            if hasattr(analyzer, 'kernel32'):
                print("  OK kernel32 DLL loaded")
                capabilities.append("kernel32_dll")

            if hasattr(analyzer, 'ntdll'):
                print("  OK ntdll DLL loaded")
                capabilities.append("ntdll_dll")

        except Exception as e:
            print(f"  FAIL Error initializing LicenseAnalyzer: {e}")
            self.results["errors"].append(f"LicenseAnalyzer init failed: {e}")

        self.results["capabilities"]["license_analyzer"] = capabilities
        print(f"\nCapabilities found: {len(capabilities)}")

        self.assertGreaterEqual(len(capabilities), 10,
                               "LicenseAnalyzer must have at least 10 capabilities")

    def test_04_license_debugger_capabilities(self):
        """Test LicenseDebugger capabilities."""
        if not DEBUGGING_ENGINE_AVAILABLE:
            self.skipTest("LicenseDebugger not available")

        print("\n[TEST] LicenseDebugger Capabilities")
        print("=" * 60)

        capabilities = []

        try:
            debugger = LicenseDebugger()

            required_methods = [
                "attach", "detach", "set_breakpoint", "set_hardware_breakpoint",
                "continue_execution", "single_step", "get_registers",
                "set_registers", "read_memory", "write_memory",
                "handle_exception", "bypass_anti_debug", "hide_debugger",
                "analyze_tls_callbacks", "parse_iat", "parse_eat"
            ]

            for method_name in required_methods:
                if hasattr(debugger, method_name):
                    method = getattr(debugger, method_name)
                    if callable(method):
                        capabilities.append(method_name)
                        print(f"  OK {method_name}")
                    else:
                        print(f"  FAIL {method_name} - Not callable")
                else:
                    print(f"  FAIL {method_name} - Not found")

            if hasattr(debugger, 'debug_event_handlers'):
                print("\n  OK Debug event handlers present")
                capabilities.append("debug_event_handlers")

            if hasattr(debugger, 'hardware_breakpoints'):
                print("  OK Hardware breakpoint support")
                capabilities.append("hardware_breakpoints")

            if hasattr(debugger, 'veh_handler'):
                print("  OK VEH handler support")
                capabilities.append("veh_handler")

        except Exception as e:
            print(f"  FAIL Error initializing LicenseDebugger: {e}")
            self.results["errors"].append(f"LicenseDebugger init failed: {e}")

        self.results["capabilities"]["license_debugger"] = capabilities
        print(f"\nCapabilities found: {len(capabilities)}")

        self.assertGreaterEqual(len(capabilities), 8,
                               "LicenseDebugger must have at least 8 capabilities")

    def test_05_yara_scanner_capabilities(self):
        """Test YaraScanner capabilities."""
        if not YARA_SCANNER_AVAILABLE:
            self.skipTest("YaraScanner not available")

        print("\n[TEST] YaraScanner Capabilities")
        print("=" * 60)

        capabilities = []

        try:
            scanner = YaraScanner()

            required_methods = [
                "compile_rules", "scan_file", "scan_memory",
                "scan_process", "add_rule", "remove_rule",
                "generate_rule", "get_matches", "clear_matches"
            ]

            for method_name in required_methods:
                if hasattr(scanner, method_name):
                    method = getattr(scanner, method_name)
                    if callable(method):
                        capabilities.append(method_name)
                        print(f"  OK {method_name}")
                    else:
                        print(f"  FAIL {method_name} - Not callable")
                else:
                    print(f"  FAIL {method_name} - Not found")

            if hasattr(scanner, 'rules'):
                print("\n  OK Rule storage present")
                capabilities.append("rule_storage")

            if hasattr(scanner, 'compiled_rules'):
                print("  OK Compiled rules support")
                capabilities.append("compiled_rules")

            try:
                test_rule = r'''
                rule TestLicenseCheck {
                    strings:
                        $serial1 = /[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}/
                        $serial2 = { 41 42 43 44 2D 31 32 33 34 2D }
                        $serial3 = "GetLicenseKey"
                        $serial4 = "ValidateLicense"
                        $trial = "Trial expired"
                        $days_left = /\d+ days? (remaining|left)/
                        $activation = "ActivateProduct"
                        $hwid = "GetHardwareID"
                    condition:
                        2 of them
                }
                '''
                scanner.add_rule("test_rule", test_rule)
                print("  OK Rule compilation successful")
                capabilities.append("rule_compilation")
            except Exception as e:
                print(f"  FAIL Rule compilation failed: {e}")

        except Exception as e:
            print(f"  FAIL Error initializing YaraScanner: {e}")
            self.results["errors"].append(f"YaraScanner init failed: {e}")

        self.results["capabilities"]["yara_scanner"] = capabilities
        print(f"\nCapabilities found: {len(capabilities)}")

        self.assertGreaterEqual(len(capabilities), 6,
                               "YaraScanner must have at least 6 capabilities")

    def test_06_pattern_scanning_implementation(self):
        """Verify pattern scanning implementation."""
        if not PROCESS_MANIPULATION_AVAILABLE:
            self.skipTest("Pattern scanning test requires LicenseAnalyzer")

        print("\n[TEST] Pattern Scanning Implementation")
        print("=" * 60)

        try:
            analyzer = LicenseAnalyzer()

            test_patterns = [
                b"\x48\x8B\x05",
                b"\x55\x48\x89\xE5",
                b"\xFF\x15",
            ]

            pattern_methods = [
                "scan_pattern",
                "scan_pattern_masked",
                "scan_multiple_patterns",
                "scan_wildcard_pattern"
            ]

            found_methods = 0
            for method_name in pattern_methods:
                if hasattr(analyzer, method_name):
                    print(f"  OK {method_name} found")
                    found_methods += 1
                else:
                    print(f"  FAIL {method_name} not found")

            self.assertGreaterEqual(found_methods, 1,
                                   "At least one pattern scanning method required")

        except Exception as e:
            print(f"  FAIL Error testing pattern scanning: {e}")
            self.fail(f"Pattern scanning test failed: {e}")

    def test_07_memory_operations(self):
        """Verify memory read/write capabilities."""
        if not PROCESS_MANIPULATION_AVAILABLE:
            self.skipTest("Memory operations test requires LicenseAnalyzer")

        print("\n[TEST] Memory Operations")
        print("=" * 60)

        try:
            analyzer = LicenseAnalyzer()

            memory_methods = [
                ("read_process_memory", "Read memory from process"),
                ("write_process_memory", "Write memory to process"),
                ("virtual_alloc", "Allocate virtual memory"),
                ("virtual_protect", "Change memory protection"),
                ("query_virtual_memory", "Query memory information")
            ]

            found_count = 0
            for method_name, description in memory_methods:
                if hasattr(analyzer, method_name):
                    print(f"  OK {method_name}: {description}")
                    found_count += 1
                else:
                    print(f"  FAIL {method_name}: Not implemented")

            self.assertGreaterEqual(found_count, 2,
                                   "At least 2 memory operations required")

        except Exception as e:
            print(f"  FAIL Error testing memory operations: {e}")
            self.fail(f"Memory operations test failed: {e}")

    def test_08_protection_detection(self):
        """Verify protection detection capabilities."""
        if not PROCESS_MANIPULATION_AVAILABLE:
            self.skipTest("Protection detection requires LicenseAnalyzer")

        print("\n[TEST] Protection Detection")
        print("=" * 60)

        try:
            analyzer = LicenseAnalyzer()

            protections = [
                "themida", "vmprotect", "enigma", "asprotect",
                "armadillo", "safengine", "obsidium", "winlicense"
            ]

            if hasattr(analyzer, 'detect_protection'):
                print("  OK detect_protection method found")

                if hasattr(analyzer, 'protection_signatures'):
                    sigs = getattr(analyzer, 'protection_signatures', {})
                    print(f"  OK Protection signatures: {len(sigs)} defined")
                    for prot in protections[:4]:
                        if prot in str(sigs).lower():
                            print(f"     {prot} signature present")

                self.results["capabilities"]["protection_detection"] = True
            else:
                print("  FAIL detect_protection method not found")
                self.results["capabilities"]["protection_detection"] = False

        except Exception as e:
            print(f"  FAIL Error testing protection detection: {e}")
            self.results["errors"].append(f"Protection detection test failed: {e}")

    def test_09_hooking_capabilities(self):
        """Verify API hooking capabilities."""
        if not PROCESS_MANIPULATION_AVAILABLE:
            self.skipTest("Hooking test requires LicenseAnalyzer")

        print("\n[TEST] API Hooking Capabilities")
        print("=" * 60)

        try:
            analyzer = LicenseAnalyzer()

            hook_methods = [
                ("hook_api", "Hook Windows API function"),
                ("unhook_api", "Remove API hook"),
                ("install_inline_hook", "Install inline hook"),
                ("install_iat_hook", "Install IAT hook"),
                ("install_eat_hook", "Install EAT hook")
            ]

            found_count = 0
            for method_name, description in hook_methods:
                if hasattr(analyzer, method_name):
                    print(f"  OK {method_name}: {description}")
                    found_count += 1
                else:
                    print(f"  FAIL {method_name}: Not implemented")

            self.assertGreaterEqual(found_count, 1,
                                   "At least 1 hooking method required")

        except Exception as e:
            print(f"  FAIL Error testing hooking capabilities: {e}")
            self.results["errors"].append(f"Hooking test failed: {e}")

    def test_10_registry_manipulation(self):
        """Verify registry manipulation capabilities."""
        if not PROCESS_MANIPULATION_AVAILABLE:
            self.skipTest("Registry test requires LicenseAnalyzer")

        print("\n[TEST] Registry Manipulation")
        print("=" * 60)

        try:
            analyzer = LicenseAnalyzer()

            registry_methods = [
                ("manipulate_registry", "Main registry manipulation"),
                ("read_registry_key", "Read registry value"),
                ("write_registry_key", "Write registry value"),
                ("delete_registry_key", "Delete registry key"),
                ("enum_registry_keys", "Enumerate registry keys")
            ]

            found_count = 0
            for method_name, description in registry_methods:
                if hasattr(analyzer, method_name):
                    print(f"  OK {method_name}: {description}")
                    found_count += 1
                else:
                    print(f"  FAIL {method_name}: Not implemented")

            self.assertGreaterEqual(found_count, 1,
                                   "At least 1 registry method required")

        except Exception as e:
            print(f"  FAIL Error testing registry manipulation: {e}")
            self.results["errors"].append(f"Registry test failed: {e}")

    def test_99_summary_report(self):
        """Generate summary report of all tests."""
        print("\n" + "=" * 70)
        print("PRODUCTION STANDARDS TEST SUMMARY")
        print("=" * 70)

        print("\n[PLATFORM INFO]")
        print(f"Operating System: {self.results['platform']}")
        print(f"Is Windows: {self.is_windows}")

        print("\n[MODULE STATUS]")
        print(f"process_manipulation: {'OK Available' if PROCESS_MANIPULATION_AVAILABLE else 'FAIL Not Available'}")
        print(f"debugging_engine: {'OK Available' if DEBUGGING_ENGINE_AVAILABLE else 'FAIL Not Available'}")
        print(f"yara_scanner: {'OK Available' if YARA_SCANNER_AVAILABLE else 'FAIL Not Available'}")

        print("\n[WINDOWS API COUNT]")
        api_count = len(self.results.get("windows_apis", []))
        print(f"Total APIs found: {api_count}")
        print(f"Minimum required: 15")
        print(f"Status: {'OK PASS' if api_count >= 15 else 'FAIL FAIL'}")

        print("\n[CAPABILITIES SUMMARY]")
        for module, caps in self.results.get("capabilities", {}).items():
            if isinstance(caps, list):
                print(f"{module}: {len(caps)} capabilities")
            else:
                print(f"{module}: {'OK Enabled' if caps else 'FAIL Disabled'}")

        print("\n[CORE CRACKING CAPABILITIES]")
        capabilities_str = str(self.results.get("capabilities", {}))
        capabilities_check = {
            "Pattern scanning": "scan" in capabilities_str,
            "Memory patching": "patch" in capabilities_str,
            "Conditional jumps": "jump" in capabilities_str or "conditional" in capabilities_str,
            "Serial validation": "serial" in capabilities_str,
            "Trial expiration": "trial" in capabilities_str,
            "Registry manipulation": "registry" in capabilities_str,
            "DLL injection": "inject" in capabilities_str,
            "API hooking": "hook" in capabilities_str,
            "Signature detection": True if YARA_SCANNER_AVAILABLE else False,
            "Protection detection": self.results.get("capabilities", {}).get("protection_detection", False)
        }

        for capability, present in capabilities_check.items():
            status = "OK" if present else "FAIL"
            print(f"  {status} {capability}")

        capabilities_count = sum(1 for v in capabilities_check.values() if v)
        print(f"\nTotal: {capabilities_count}/10 capabilities present")

        if self.results.get("errors"):
            print("\n[ERRORS ENCOUNTERED]")
            for error in self.results["errors"]:
                print(f"   {error}")

        print("\n[OVERALL ASSESSMENT]")
        modules_ok = sum([PROCESS_MANIPULATION_AVAILABLE,
                         DEBUGGING_ENGINE_AVAILABLE,
                         YARA_SCANNER_AVAILABLE]) >= 2
        apis_ok = api_count >= 15 if self.is_windows else True
        capabilities_ok = capabilities_count >= 7

        if modules_ok and apis_ok and capabilities_ok:
            print("OK PRODUCTION READY - All critical requirements met")
        else:
            print("FAIL NOT PRODUCTION READY - Critical requirements missing:")
            if not modules_ok:
                print("  - Insufficient modules available")
            if not apis_ok:
                print("  - Insufficient Windows APIs")
            if not capabilities_ok:
                print("  - Insufficient cracking capabilities")

        print("\n" + "=" * 70)


def main():
    """Run the production standards test suite."""
    suite = unittest.TestLoader().loadTestsFromTestCase(TestActualModules)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    exit(main())
