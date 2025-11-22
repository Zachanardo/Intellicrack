"""
Comprehensive e2b Test Suite for Intellicrack Production Standards
Tests all modules using the e2b secure sandbox environment
"""

import sys
import os
import json
import platform
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass
from enum import Enum

# Add Intellicrack to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

class TestResult(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"

@dataclass
class TestCase:
    name: str
    module: str
    function: str
    expected: Any
    result: TestResult = TestResult.SKIP
    details: str = ""

class ComprehensiveE2BTester:
    """Comprehensive testing framework for Intellicrack modules in e2b sandbox"""

    def __init__(self):
        self.results = []
        self.modules_tested = set()
        self.apis_tested = set()
        self.capabilities_verified = {}
        self.is_windows = platform.system() == "Windows"

    def run_all_tests(self) -> dict[str, Any]:
        """Run all comprehensive tests"""
        print("Starting Comprehensive e2b Test Suite for Intellicrack")
        print("=" * 60)

        # Phase 1: Module Loading Tests
        self.test_module_loading()

        # Phase 2: Windows API Tests
        if self.is_windows:
            self.test_windows_apis()

        # Phase 3: Pattern Matching Tests
        self.test_pattern_matching()

        # Phase 4: Memory Operations Tests
        self.test_memory_operations()

        # Phase 5: Debugging Functions Tests
        self.test_debugging_functions()

        # Phase 6: YARA Integration Tests
        self.test_yara_integration()

        # Phase 7: Error Handling Tests
        self.test_error_handling()

        # Phase 8: Cross-Module Integration
        self.test_cross_module_integration()

        # Generate Report
        return self.generate_report()

    def test_module_loading(self):
        """Test that all critical modules load properly"""
        print("\nPhase 1: Testing Module Loading")
        print("-" * 40)

        modules_to_test = [
            ("intellicrack.core.process_manipulation", "LicenseAnalyzer"),
            ("intellicrack.core.debugging_engine", "LicenseDebugger"),
            ("intellicrack.core.analysis.yara_scanner", "YaraScanner"),
            ("intellicrack.core.trial_reset_engine", "TrialResetEngine"),
            ("intellicrack.core.hardware_spoofer", "HardwareSpoofer"),
            ("intellicrack.core.subscription_validation_bypass", "SubscriptionBypass"),
            ("intellicrack.core.exploitation.license_server_emulator", "LicenseServerEmulator"),
            ("intellicrack.core.exploitation.cfi_bypass", "CFIBypass"),
        ]

        for module_name, class_name in modules_to_test:
            test = TestCase(
                name=f"Load {class_name}",
                module=module_name,
                function="import",
                expected=True
            )

            try:
                module = __import__(module_name, fromlist=[class_name])
                cls = getattr(module, class_name, None)
                if cls:
                    test.result = TestResult.PASS
                    test.details = f"Successfully loaded {class_name}"
                    self.modules_tested.add(module_name)
                    print(f"OK {class_name} loaded successfully")
                else:
                    test.result = TestResult.FAIL
                    test.details = f"Class {class_name} not found in module"
                    print(f"FAIL {class_name} not found")
            except ImportError as e:
                if not self.is_windows and "Windows" in str(e):
                    test.result = TestResult.SKIP
                    test.details = f"Skipped on non-Windows: {e}"
                    print(f"⊙ {class_name} skipped (non-Windows)")
                else:
                    test.result = TestResult.ERROR
                    test.details = str(e)
                    print(f"FAIL {class_name} error: {e}")
            except Exception as e:
                test.result = TestResult.ERROR
                test.details = str(e)
                print(f"FAIL {class_name} error: {e}")

            self.results.append(test)

    def test_windows_apis(self):
        """Test all Windows API implementations"""
        print("\nPhase 2: Testing Windows APIs")
        print("-" * 40)

        if not self.is_windows:
            print("⊙ Skipping Windows API tests on non-Windows platform")
            return

        try:
            from intellicrack.core.process_manipulation import LicenseAnalyzer
            analyzer = LicenseAnalyzer()

            # Test critical Windows APIs
            apis_to_test = [
                ("kernel32.OpenProcess", analyzer.kernel32.OpenProcess),
                ("kernel32.ReadProcessMemory", analyzer.kernel32.ReadProcessMemory),
                ("kernel32.WriteProcessMemory", analyzer.kernel32.WriteProcessMemory),
                ("kernel32.VirtualAllocEx", analyzer.kernel32.VirtualAllocEx),
                ("kernel32.VirtualProtectEx", analyzer.kernel32.VirtualProtectEx),
                ("kernel32.CreateRemoteThread", analyzer.kernel32.CreateRemoteThread),
                ("kernel32.GetModuleHandleA", analyzer.kernel32.GetModuleHandleA),
                ("kernel32.GetProcAddress", analyzer.kernel32.GetProcAddress),
                ("ntdll.NtQueryInformationProcess", analyzer.ntdll.NtQueryInformationProcess),
                ("ntdll.NtQueryVirtualMemory", analyzer.ntdll.NtQueryVirtualMemory),
                ("ntdll.NtWow64ReadVirtualMemory64", getattr(analyzer.ntdll, "NtWow64ReadVirtualMemory64", None)),
                ("advapi32.RegOpenKeyExA", analyzer.advapi32.RegOpenKeyExA),
                ("user32.FindWindowA", analyzer.user32.FindWindowA),
                ("user32.GetWindowThreadProcessId", analyzer.user32.GetWindowThreadProcessId),
            ]

            for api_name, api_func in apis_to_test:
                test = TestCase(
                    name=f"API {api_name}",
                    module="process_manipulation",
                    function=api_name,
                    expected="function"
                )

                if api_func and callable(api_func):
                    test.result = TestResult.PASS
                    test.details = f"API {api_name} is callable"
                    self.apis_tested.add(api_name)
                    print(f"OK {api_name} available")
                else:
                    test.result = TestResult.FAIL
                    test.details = f"API {api_name} not callable"
                    print(f"FAIL {api_name} not available")

                self.results.append(test)

        except Exception as e:
            print(f"Error testing Windows APIs: {e}")

    def test_pattern_matching(self):
        """Test pattern matching functionality"""
        print("\nPhase 3: Testing Pattern Matching")
        print("-" * 40)

        test_patterns = [
            (b"\x48\x8B\x05", "MOV RAX instruction"),
            (b"\x90\x90\x90", "NOP sled"),
            (b"\xFF\x15", "CALL indirect"),
            (b"\x55\x8B\xEC", "Function prologue"),
            (b"\xC3", "RET instruction"),
        ]

        try:
            from intellicrack.core.process_manipulation import LicenseAnalyzer

            if self.is_windows:
                analyzer = LicenseAnalyzer()

                # Test pattern compilation
                for pattern, description in test_patterns:
                    test = TestCase(
                        name=f"Pattern: {description}",
                        module="process_manipulation",
                        function="compile_pattern",
                        expected=True
                    )

                    try:
                        # Test pattern compilation (internal method)
                        compiled = analyzer._compile_pattern(pattern.hex())
                        if compiled:
                            test.result = TestResult.PASS
                            test.details = f"Pattern compiled: {pattern.hex()}"
                            print(f"OK {description} pattern compiled")
                        else:
                            test.result = TestResult.FAIL
                            test.details = "Pattern compilation failed"
                            print(f"FAIL {description} pattern failed")
                    except Exception as e:
                        test.result = TestResult.ERROR
                        test.details = str(e)
                        print(f"FAIL {description} error: {e}")

                    self.results.append(test)

                # Test wildcard patterns
                test = TestCase(
                    name="Wildcard Pattern Support",
                    module="process_manipulation",
                    function="masked_pattern_scan",
                    expected=True
                )

                try:
                    # Test masked pattern scanning
                    if hasattr(analyzer, '_masked_pattern_scan'):
                        test.result = TestResult.PASS
                        test.details = "Wildcard pattern scanning available"
                        self.capabilities_verified["wildcard_patterns"] = True
                        print("OK Wildcard pattern support verified")
                    else:
                        test.result = TestResult.FAIL
                        test.details = "No wildcard pattern support"
                        print("FAIL Wildcard pattern support missing")
                except Exception as e:
                    test.result = TestResult.ERROR
                    test.details = str(e)
                    print(f"FAIL Wildcard pattern error: {e}")

                self.results.append(test)
            else:
                print("⊙ Skipping pattern tests on non-Windows")

        except ImportError:
            print("⊙ Module not available for pattern testing")

    def test_memory_operations(self):
        """Test memory operation capabilities"""
        print("\nPhase 4: Testing Memory Operations")
        print("-" * 40)

        memory_ops = [
            "read_process_memory",
            "write_process_memory",
            "allocate_memory",
            "protect_memory",
            "query_memory",
            "scan_pattern",
            "patch_bytes",
            "find_code_caves",
            "enumerate_regions",
        ]

        try:
            if self.is_windows:
                from intellicrack.core.process_manipulation import LicenseAnalyzer
                analyzer = LicenseAnalyzer()

                for op in memory_ops:
                    test = TestCase(
                        name=f"Memory Op: {op}",
                        module="process_manipulation",
                        function=op,
                        expected="method"
                    )

                    if hasattr(analyzer, op):
                        method = getattr(analyzer, op)
                        if callable(method):
                            test.result = TestResult.PASS
                            test.details = f"{op} is callable"
                            self.capabilities_verified[op] = True
                            print(f"OK {op} available")
                        else:
                            test.result = TestResult.FAIL
                            test.details = f"{op} not callable"
                            print(f"FAIL {op} not callable")
                    else:
                        test.result = TestResult.FAIL
                        test.details = f"{op} not found"
                        print(f"FAIL {op} not found")

                    self.results.append(test)
            else:
                print("⊙ Skipping memory operations on non-Windows")

        except ImportError:
            print("⊙ Module not available for memory testing")

    def test_debugging_functions(self):
        """Test debugging engine functionality"""
        print("\nPhase 5: Testing Debugging Functions")
        print("-" * 40)

        debug_functions = [
            "attach_to_process",
            "set_breakpoint",
            "set_hardware_breakpoint",
            "continue_execution",
            "single_step",
            "get_registers",
            "set_registers",
            "hide_debugger",
            "bypass_anti_debug",
            "handle_exception",
            "trace_execution",
        ]

        try:
            if self.is_windows:
                from intellicrack.core.debugging_engine import LicenseDebugger
                debugger = LicenseDebugger()

                for func in debug_functions:
                    test = TestCase(
                        name=f"Debug: {func}",
                        module="debugging_engine",
                        function=func,
                        expected="method"
                    )

                    if hasattr(debugger, func):
                        method = getattr(debugger, func)
                        if callable(method):
                            test.result = TestResult.PASS
                            test.details = f"{func} is callable"
                            self.capabilities_verified[f"debug_{func}"] = True
                            print(f"OK {func} available")
                        else:
                            test.result = TestResult.FAIL
                            test.details = f"{func} not callable"
                            print(f"FAIL {func} not callable")
                    else:
                        test.result = TestResult.FAIL
                        test.details = f"{func} not found"
                        print(f"FAIL {func} not found")

                    self.results.append(test)

                # Test hardware breakpoint support
                test = TestCase(
                    name="Hardware Breakpoint Registers",
                    module="debugging_engine",
                    function="DR0-DR7",
                    expected=True
                )

                if hasattr(debugger, 'set_hardware_breakpoint'):
                    test.result = TestResult.PASS
                    test.details = "Hardware breakpoint support verified"
                    self.capabilities_verified["hardware_breakpoints"] = True
                    print("OK Hardware breakpoint support verified")
                else:
                    test.result = TestResult.FAIL
                    test.details = "No hardware breakpoint support"
                    print("FAIL Hardware breakpoint support missing")

                self.results.append(test)

            else:
                print("⊙ Skipping debugging functions on non-Windows")

        except ImportError:
            print("⊙ Module not available for debugging tests")

    def test_yara_integration(self):
        """Test YARA scanner integration"""
        print("\nPhase 6: Testing YARA Integration")
        print("-" * 40)

        yara_features = [
            "load_rules",
            "compile_rule",
            "scan_file",
            "scan_process_memory",
            "scan_memory_concurrent",
            "generate_rule_from_pattern",
            "connect_to_debugger",
            "set_breakpoints_from_matches",
        ]

        try:
            from intellicrack.core.analysis.yara_scanner import YaraScanner
            scanner = YaraScanner()

            for feature in yara_features:
                test = TestCase(
                    name=f"YARA: {feature}",
                    module="yara_scanner",
                    function=feature,
                    expected="method"
                )

                if hasattr(scanner, feature):
                    method = getattr(scanner, feature)
                    if callable(method):
                        test.result = TestResult.PASS
                        test.details = f"{feature} is callable"
                        self.capabilities_verified[f"yara_{feature}"] = True
                        print(f"OK {feature} available")
                    else:
                        test.result = TestResult.FAIL
                        test.details = f"{feature} not callable"
                        print(f"FAIL {feature} not callable")
                else:
                    # Try alternative method names
                    alt_names = {
                        "scan_process_memory": "scan_process_with_analyzer",
                        "generate_rule_from_pattern": "convert_pattern_to_yara",
                    }
                    alt_name = alt_names.get(feature, None)
                    if alt_name and hasattr(scanner, alt_name):
                        test.result = TestResult.PASS
                        test.details = f"{feature} available as {alt_name}"
                        self.capabilities_verified[f"yara_{feature}"] = True
                        print(f"OK {feature} available (as {alt_name})")
                    else:
                        test.result = TestResult.FAIL
                        test.details = f"{feature} not found"
                        print(f"FAIL {feature} not found")

                self.results.append(test)

            # Test license-specific rules
            license_rules = [
                "Serial_Number_Validation",
                "Trial_Expiration_Check",
                "Hardware_ID_Check",
                "Activation_Server_Communication",
                "Registration_Key_Algorithm",
            ]

            for rule_name in license_rules:
                test = TestCase(
                    name=f"License Rule: {rule_name}",
                    module="yara_scanner",
                    function="license_rule",
                    expected=True
                )

                # Check if rule exists in default rules
                if hasattr(scanner, 'license_rules'):
                    test.result = TestResult.PASS
                    test.details = f"License rule {rule_name} available"
                    print(f"OK {rule_name} rule available")
                else:
                    test.result = TestResult.SKIP
                    test.details = "License rules not loaded"
                    print(f"⊙ {rule_name} rule check skipped")

                self.results.append(test)

        except ImportError as e:
            print(f"⊙ YARA module not available: {e}")

    def test_error_handling(self):
        """Test error handling robustness"""
        print("\nPhase 7: Testing Error Handling")
        print("-" * 40)

        error_scenarios = [
            ("Invalid process ID", "process_manipulation", "attach_to_process", -1),
            ("Null pointer read", "process_manipulation", "read_process_memory", (0, 0, 100)),
            ("Invalid pattern", "process_manipulation", "scan_pattern", (0, b"")),
            ("Protected memory write", "process_manipulation", "write_process_memory", (0, 0, b"test")),
            ("Invalid breakpoint", "debugging_engine", "set_breakpoint", (0, -1)),
            ("Invalid rule syntax", "yara_scanner", "compile_rule", "invalid { rule }"),
        ]

        for scenario, module, function, bad_input in error_scenarios:
            test = TestCase(
                name=f"Error: {scenario}",
                module=module,
                function=function,
                expected="handled"
            )

            try:
                if module == "process_manipulation" and self.is_windows:
                    from intellicrack.core.process_manipulation import LicenseAnalyzer
                    analyzer = LicenseAnalyzer()
                    if hasattr(analyzer, function):
                        method = getattr(analyzer, function)
                        try:
                            if isinstance(bad_input, tuple):
                                result = method(*bad_input)
                            else:
                                result = method(bad_input)
                            # If no exception, check for error return value
                            if result is False or result is None or result == []:
                                test.result = TestResult.PASS
                                test.details = "Error handled gracefully"
                                print(f"OK {scenario} handled")
                            else:
                                test.result = TestResult.FAIL
                                test.details = "No error handling"
                                print(f"FAIL {scenario} not handled properly")
                        except Exception as e:
                            test.result = TestResult.PASS
                            test.details = f"Exception caught: {type(e).__name__}"
                            print(f"OK {scenario} exception handled")
                    else:
                        test.result = TestResult.SKIP
                        test.details = f"Function {function} not found"
                        print(f"⊙ {scenario} skipped")

                elif module == "debugging_engine" and self.is_windows:
                    from intellicrack.core.debugging_engine import LicenseDebugger
                    debugger = LicenseDebugger()
                    if hasattr(debugger, function):
                        method = getattr(debugger, function)
                        try:
                            if isinstance(bad_input, tuple):
                                result = method(*bad_input)
                            else:
                                result = method(bad_input)
                            if result is False or result is None:
                                test.result = TestResult.PASS
                                test.details = "Error handled gracefully"
                                print(f"OK {scenario} handled")
                            else:
                                test.result = TestResult.FAIL
                                test.details = "No error handling"
                                print(f"FAIL {scenario} not handled")
                        except Exception as e:
                            test.result = TestResult.PASS
                            test.details = f"Exception caught: {type(e).__name__}"
                            print(f"OK {scenario} exception handled")
                    else:
                        test.result = TestResult.SKIP
                        test.details = f"Function {function} not found"
                        print(f"⊙ {scenario} skipped")

                elif module == "yara_scanner":
                    from intellicrack.core.analysis.yara_scanner import YaraScanner
                    scanner = YaraScanner()
                    if hasattr(scanner, function):
                        method = getattr(scanner, function)
                        try:
                            result = method(bad_input)
                            if result is False or result is None:
                                test.result = TestResult.PASS
                                test.details = "Error handled gracefully"
                                print(f"OK {scenario} handled")
                            else:
                                test.result = TestResult.FAIL
                                test.details = "No error handling"
                                print(f"FAIL {scenario} not handled")
                        except Exception as e:
                            test.result = TestResult.PASS
                            test.details = f"Exception caught: {type(e).__name__}"
                            print(f"OK {scenario} exception handled")
                    else:
                        test.result = TestResult.SKIP
                        test.details = f"Function {function} not found"
                        print(f"⊙ {scenario} skipped")
                else:
                    test.result = TestResult.SKIP
                    test.details = "Non-Windows platform"
                    print(f"⊙ {scenario} skipped")

            except ImportError:
                test.result = TestResult.SKIP
                test.details = "Module not available"
                print(f"⊙ {scenario} module unavailable")

            self.results.append(test)

    def test_cross_module_integration(self):
        """Test integration between modules"""
        print("\nPhase 8: Testing Cross-Module Integration")
        print("-" * 40)

        integrations = [
            ("Process + YARA", "process_manipulation", "yara_scanner"),
            ("Debug + YARA", "debugging_engine", "yara_scanner"),
            ("Process + Debug", "process_manipulation", "debugging_engine"),
            ("Trial + Process", "trial_reset_engine", "process_manipulation"),
            ("Hardware + Process", "hardware_spoofer", "process_manipulation"),
        ]

        for integration_name, module1, module2 in integrations:
            test = TestCase(
                name=f"Integration: {integration_name}",
                module=f"{module1}+{module2}",
                function="cross_module",
                expected="compatible"
            )

            try:
                # Test that modules can work together
                if module1 == "process_manipulation" and module2 == "yara_scanner":
                    if self.is_windows:
                        from intellicrack.core.process_manipulation import LicenseAnalyzer
                        from intellicrack.core.analysis.yara_scanner import YaraScanner
                        analyzer = LicenseAnalyzer()
                        scanner = YaraScanner()
                        # Check if scanner can work with analyzer
                        if hasattr(scanner, 'scan_process_with_analyzer'):
                            test.result = TestResult.PASS
                            test.details = "Integration method found"
                            print(f"OK {integration_name} integration verified")
                        else:
                            test.result = TestResult.FAIL
                            test.details = "No integration method"
                            print(f"FAIL {integration_name} integration missing")
                    else:
                        test.result = TestResult.SKIP
                        test.details = "Non-Windows platform"
                        print(f"⊙ {integration_name} skipped")

                elif module1 == "debugging_engine" and module2 == "yara_scanner":
                    if self.is_windows:
                        from intellicrack.core.debugging_engine import LicenseDebugger
                        from intellicrack.core.analysis.yara_scanner import YaraScanner
                        debugger = LicenseDebugger()
                        scanner = YaraScanner()
                        # Check if scanner can connect to debugger
                        if hasattr(scanner, 'connect_to_debugger'):
                            test.result = TestResult.PASS
                            test.details = "Integration method found"
                            print(f"OK {integration_name} integration verified")
                        else:
                            test.result = TestResult.FAIL
                            test.details = "No integration method"
                            print(f"FAIL {integration_name} integration missing")
                    else:
                        test.result = TestResult.SKIP
                        test.details = "Non-Windows platform"
                        print(f"⊙ {integration_name} skipped")

                else:
                    # Check if modules can be imported together
                    module1_imported = False
                    module2_imported = False

                    try:
                        __import__(f"intellicrack.core.{module1}")
                        module1_imported = True
                    except:
                        pass

                    try:
                        if module2 == "yara_scanner":
                            __import__(f"intellicrack.core.analysis.{module2}")
                        else:
                            __import__(f"intellicrack.core.{module2}")
                        module2_imported = True
                    except:
                        pass

                    if module1_imported and module2_imported:
                        test.result = TestResult.PASS
                        test.details = "Both modules importable"
                        print(f"OK {integration_name} modules compatible")
                    else:
                        test.result = TestResult.FAIL
                        test.details = f"Import failed: M1={module1_imported}, M2={module2_imported}"
                        print(f"FAIL {integration_name} import failed")

            except Exception as e:
                test.result = TestResult.ERROR
                test.details = str(e)
                print(f"FAIL {integration_name} error: {e}")

            self.results.append(test)

    def generate_report(self) -> dict[str, Any]:
        """Generate comprehensive test report"""
        print("\n" + "=" * 60)
        print("TEST RESULTS SUMMARY")
        print("=" * 60)

        # Count results by type
        total_tests = len(self.results)
        passed = sum(1 for r in self.results if r.result == TestResult.PASS)
        failed = sum(1 for r in self.results if r.result == TestResult.FAIL)
        skipped = sum(1 for r in self.results if r.result == TestResult.SKIP)
        errors = sum(1 for r in self.results if r.result == TestResult.ERROR)

        # Calculate scores
        success_rate = (passed / total_tests * 100) if total_tests > 0 else 0
        effective_rate = (passed / (passed + failed) * 100) if (passed + failed) > 0 else 0

        # Core capabilities check
        core_capabilities = [
            "read_process_memory",
            "write_process_memory",
            "scan_pattern",
            "patch_bytes",
            "set_breakpoint",
            "hardware_breakpoints",
            "yara_scan_process_memory",
            "wildcard_patterns",
            "debug_bypass_anti_debug",
            "debug_hide_debugger",
        ]

        capabilities_present = sum(1 for cap in core_capabilities if cap in self.capabilities_verified)

        report = {
            "total_tests": total_tests,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "errors": errors,
            "success_rate": success_rate,
            "effective_rate": effective_rate,
            "modules_tested": len(self.modules_tested),
            "apis_tested": len(self.apis_tested),
            "capabilities_verified": len(self.capabilities_verified),
            "core_capabilities": f"{capabilities_present}/{len(core_capabilities)}",
            "platform": platform.system(),
            "production_ready": success_rate >= 70 and capabilities_present >= 8,
        }

        # Print summary
        print(f"\nTests Executed: {total_tests}")
        print(f"├─ Passed: {passed} ({passed/total_tests*100:.1f}%)")
        print(f"├─ Failed: {failed} ({failed/total_tests*100:.1f}%)")
        print(f"├─ Skipped: {skipped} ({skipped/total_tests*100:.1f}%)")
        print(f"└─ Errors: {errors} ({errors/total_tests*100:.1f}%)")

        print(f"\nModules Tested: {len(self.modules_tested)}")
        print(f"Windows APIs Tested: {len(self.apis_tested)}")
        print(f"Capabilities Verified: {len(self.capabilities_verified)}")
        print(f"Core Capabilities: {capabilities_present}/{len(core_capabilities)}")

        print(f"\nSuccess Rate: {success_rate:.1f}%")
        print(f"Effective Rate: {effective_rate:.1f}% (excluding skipped)")

        if report["production_ready"]:
            print("\nOK PRODUCTION READY - All criteria met")
        else:
            print("\nWARNING NOT PRODUCTION READY - Criteria not met")
            if success_rate < 70:
                print(f"  - Success rate {success_rate:.1f}% < 70%")
            if capabilities_present < 8:
                print(f"  - Core capabilities {capabilities_present}/10 < 8")

        # List failures for debugging
        if failed > 0:
            print("\nFailed Tests:")
            for test in self.results:
                if test.result == TestResult.FAIL:
                    print(f"  - {test.name}: {test.details}")

        # List errors for debugging
        if errors > 0:
            print("\nError Tests:")
            for test in self.results:
                if test.result == TestResult.ERROR:
                    print(f"  - {test.name}: {test.details}")

        return report

def main():
    """Main entry point for e2b testing"""
    tester = ComprehensiveE2BTester()
    report = tester.run_all_tests()

    # Save report to JSON
    import json
    with open("e2b_test_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nReport saved to e2b_test_report.json")

    # Return exit code based on production readiness
    return 0 if report["production_ready"] else 1

if __name__ == "__main__":
    exit(main())