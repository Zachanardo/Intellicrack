"""
Regression Testing Suite for Frida Scripts

Ensures all Frida scripts continue to work correctly after updates.
Tests script syntax, functionality, and compatibility.
"""

import hashlib
import json
import re
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


class FridaScriptValidator:
    """Validates Frida script syntax and structure"""

    # Common Frida API patterns
    FRIDA_API_PATTERNS = {
        'interceptor': re.compile(r'Interceptor\.(attach|detach|replace)\s*\('),
        'module': re.compile(r'Module\.(findExportByName|findBaseAddress|enumerateExports|enumerateImports)\s*\('),
        'memory': re.compile(r'Memory\.(alloc|protect|scan|read\w+|write\w+)\s*\('),
        'process': re.compile(r'Process\.(enumerateModules|enumerateThreads|getCurrentThreadId|platform|arch)'),
        'send': re.compile(r'send\s*\('),
        'recv': re.compile(r'recv\s*\('),
        'console': re.compile(r'console\.(log|warn|error)\s*\('),
    }

    # Required patterns for specific script types
    SCRIPT_REQUIREMENTS = {
        'anti_debugger': ['Interceptor.attach', 'IsDebuggerPresent'],
        'cloud_licensing_bypass': ['Interceptor.attach', 'send'],
        'registry_monitor': ['Interceptor.attach', 'RegQueryValue'],
        'time_bomb_defuser': ['Interceptor.attach', 'GetSystemTime'],
        'hardware_spoofer': ['Interceptor.replace', 'GetVolumeInformation'],
        'memory_integrity_bypass': ['Memory.protect', 'VirtualProtect'],
    }

    @staticmethod
    def validate_syntax(script_content: str) -> Tuple[bool, Optional[str]]:
        """Validate JavaScript syntax (basic check)"""
        try:
            # Check for basic syntax errors
            # Look for common JS syntax issues
            bracket_count = script_content.count('{') - script_content.count('}')
            paren_count = script_content.count('(') - script_content.count(')')

            if bracket_count != 0:
                return False, f"Mismatched brackets: {bracket_count} extra '{' or '}'"

            if paren_count != 0:
                return False, f"Mismatched parentheses: {paren_count} extra '(' or ')'"

            # Check for unterminated strings
            in_string = False
            quote_char = None
            escaped = False

            for char in script_content:
                if escaped:
                    escaped = False
                    continue

                if char == '\\':
                    escaped = True
                    continue

                if char in ['"', "'", '`'] and not in_string:
                    in_string = True
                    quote_char = char
                elif char == quote_char and in_string:
                    in_string = False
                    quote_char = None

            if in_string:
                return False, f"Unterminated string starting with {quote_char}"

            return True, None

        except Exception as e:
            return False, str(e)

    @staticmethod
    def validate_api_usage(script_content: str, script_name: str) -> List[str]:
        """Validate Frida API usage"""
        warnings = []

        # Check for deprecated API usage
        deprecated_apis = {
            'Interceptor.detachAll': 'Use specific detach calls instead',
            'Memory.readUtf8String': 'Consider using Memory.readCString',
            'ptr()': 'Use ptr() with explicit base',
        }

        for api, suggestion in deprecated_apis.items():
            if api in script_content:
                warnings.append(f"Deprecated API '{api}': {suggestion}")

        # Check for required patterns
        if script_name in FridaScriptValidator.SCRIPT_REQUIREMENTS:
            required = FridaScriptValidator.SCRIPT_REQUIREMENTS[script_name]
            for pattern in required:
                if pattern not in script_content:
                    warnings.append(f"Missing required pattern: {pattern}")

        # Check for unsafe patterns
        unsafe_patterns = [
            (r'eval\s*\(', 'Avoid using eval()'),
            (r'Function\s*\(.*\)', 'Avoid dynamic function creation'),
            (r'setTimeout.*0\)', 'Use setImmediate() instead of setTimeout(0)'),
        ]

        for pattern, warning in unsafe_patterns:
            if re.search(pattern, script_content):
                warnings.append(warning)

        return warnings

    @staticmethod
    def extract_hooked_apis(script_content: str) -> Set[str]:
        """Extract APIs being hooked in the script"""
        hooked_apis = set()

        # Pattern to match Interceptor.attach calls
        attach_pattern = re.compile(
            r'Interceptor\.attach\s*\(\s*Module\.findExportByName\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']\s*\)'
        )

        for match in attach_pattern.finditer(script_content):
            module = match.group(1)
            function = match.group(2)
            hooked_apis.add(f"{module}!{function}")

        # Also check for getNativeFunction patterns
        native_pattern = re.compile(
            r'getNativeFunction\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']\s*\)'
        )

        for match in native_pattern.finditer(script_content):
            module = match.group(1)
            function = match.group(2)
            hooked_apis.add(f"{module}!{function}")

        return hooked_apis


class ScriptRegressionTest:
    """Individual regression test for a Frida script"""

    def __init__(self, script_path: Path, expected_behavior: Dict = None):
        self.script_path = script_path
        self.script_name = script_path.stem
        self.expected_behavior = expected_behavior or {}
        self.last_hash = None
        self.last_test_time = None
        self.test_results = []

    def calculate_hash(self) -> str:
        """Calculate hash of script content"""
        content = self.script_path.read_bytes()
        return hashlib.sha256(content).hexdigest()

    def has_changed(self) -> bool:
        """Check if script has changed since last test"""
        current_hash = self.calculate_hash()
        changed = current_hash != self.last_hash
        self.last_hash = current_hash
        return changed

    def run_test(self) -> Dict[str, any]:
        """Run regression test on the script"""
        result = {
            'script': self.script_name,
            'timestamp': datetime.now().isoformat(),
            'hash': self.calculate_hash(),
            'syntax_valid': False,
            'warnings': [],
            'hooked_apis': [],
            'test_passed': False,
            'error': None
        }

        try:
            # Read script content
            content = self.script_path.read_text(encoding='utf-8')

            # Validate syntax
            syntax_valid, syntax_error = FridaScriptValidator.validate_syntax(content)
            result['syntax_valid'] = syntax_valid

            if not syntax_valid:
                result['error'] = syntax_error
                return result

            # Validate API usage
            warnings = FridaScriptValidator.validate_api_usage(content, self.script_name)
            result['warnings'] = warnings

            # Extract hooked APIs
            hooked_apis = FridaScriptValidator.extract_hooked_apis(content)
            result['hooked_apis'] = list(hooked_apis)

            # Check expected behavior
            if self.expected_behavior:
                result['test_passed'] = self._check_expected_behavior(content)
            else:
                result['test_passed'] = syntax_valid and len(warnings) == 0

        except Exception as e:
            result['error'] = str(e)

        self.test_results.append(result)
        self.last_test_time = datetime.now()

        return result

    def _check_expected_behavior(self, content: str) -> bool:
        """Check if script matches expected behavior"""
        # Check for expected APIs
        if 'expected_apis' in self.expected_behavior:
            for api in self.expected_behavior['expected_apis']:
                if api not in content:
                    return False

        # Check for expected patterns
        if 'expected_patterns' in self.expected_behavior:
            for pattern in self.expected_behavior['expected_patterns']:
                if not re.search(pattern, content):
                    return False

        # Check for forbidden patterns
        if 'forbidden_patterns' in self.expected_behavior:
            for pattern in self.expected_behavior['forbidden_patterns']:
                if re.search(pattern, content):
                    return False

        return True


class FridaScriptRegressionSuite:
    """Complete regression test suite for all Frida scripts"""

    def __init__(self, scripts_dir: Path = None):
        if scripts_dir:
            self.scripts_dir = scripts_dir
        else:
            # Use relative path from test location
            test_dir = Path(__file__).parent
            project_root = test_dir.parent
            self.scripts_dir = project_root / "scripts" / "frida"
        self.tests = {}
        self.results_file = Path("frida_regression_results.json")
        self.baseline_file = Path("frida_regression_baseline.json")
        self._load_baseline()
        self._initialize_tests()

    def _load_baseline(self):
        """Load baseline test results"""
        self.baseline = {}
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file) as f:
                    self.baseline = json.load(f)
            except Exception as e:
                print(f"Failed to load baseline: {e}")

    def _save_baseline(self):
        """Save current results as baseline"""
        baseline_data = {}

        for script_name, test in self.tests.items():
            if test.test_results:
                latest_result = test.test_results[-1]
                baseline_data[script_name] = {
                    'hash': latest_result['hash'],
                    'hooked_apis': latest_result['hooked_apis'],
                    'timestamp': latest_result['timestamp']
                }

        with open(self.baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)

    def _initialize_tests(self):
        """Initialize regression tests for all scripts"""
        # Expected behaviors for known scripts
        expected_behaviors = {
            'anti_debugger': {
                'expected_apis': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent'],
                'expected_patterns': [r'Interceptor\.attach', r'retval\.replace\(0\)']
            },
            'cloud_licensing_bypass': {
                'expected_apis': ['InternetOpenUrl', 'HttpSendRequest'],
                'expected_patterns': [r'send\({[\s\S]*type.*:.*license']
            },
            'registry_monitor': {
                'expected_apis': ['RegQueryValueEx', 'RegSetValueEx'],
                'expected_patterns': [r'args\[1\]\.readUtf16String']
            },
            'time_bomb_defuser': {
                'expected_apis': ['GetSystemTime', 'GetLocalTime'],
                'expected_patterns': [r'SYSTEMTIME', r'writeU16']
            },
            'enhanced_hardware_spoofer': {
                'expected_apis': ['GetVolumeInformation', 'GetAdaptersInfo'],
                'expected_patterns': [r'Interceptor\.replace']
            },
            'memory_integrity_bypass': {
                'expected_apis': ['VirtualProtect', 'NtProtectVirtualMemory'],
                'expected_patterns': [r'Memory\.protect', r'PAGE_EXECUTE_READWRITE']
            }
        }

        # Create tests for all scripts
        if self.scripts_dir.exists():
            for script_path in self.scripts_dir.glob("*.js"):
                script_name = script_path.stem
                expected = expected_behaviors.get(script_name, {})
                self.tests[script_name] = ScriptRegressionTest(script_path, expected)

    def run_all_tests(self) -> Dict[str, any]:
        """Run all regression tests"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_scripts': len(self.tests),
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'changes_detected': 0,
            'script_results': {}
        }

        for script_name, test in self.tests.items():
            # Check if script changed
            if test.has_changed():
                results['changes_detected'] += 1

            # Run test
            test_result = test.run_test()
            results['script_results'][script_name] = test_result

            # Update counters
            if test_result['test_passed']:
                results['passed'] += 1
            else:
                results['failed'] += 1

            if test_result['warnings']:
                results['warnings'] += len(test_result['warnings'])

        # Save results
        self._save_results(results)

        return results

    def _save_results(self, results: Dict):
        """Save test results"""
        with open(self.results_file, 'w') as f:
            json.dump(results, f, indent=2)

    def compare_with_baseline(self) -> Dict[str, any]:
        """Compare current results with baseline"""
        comparison = {
            'new_scripts': [],
            'removed_scripts': [],
            'modified_scripts': [],
            'api_changes': {},
            'regression_detected': False
        }

        current_scripts = set(self.tests.keys())
        baseline_scripts = set(self.baseline.keys())

        # Find new scripts
        comparison['new_scripts'] = list(current_scripts - baseline_scripts)

        # Find removed scripts
        comparison['removed_scripts'] = list(baseline_scripts - current_scripts)

        # Check for modifications
        for script_name in current_scripts & baseline_scripts:
            test = self.tests[script_name]
            baseline_data = self.baseline[script_name]

            # Check hash
            if test.last_hash != baseline_data.get('hash'):
                comparison['modified_scripts'].append(script_name)

            # Check API changes
            if test.test_results:
                current_apis = set(test.test_results[-1]['hooked_apis'])
                baseline_apis = set(baseline_data.get('hooked_apis', []))

                added_apis = current_apis - baseline_apis
                removed_apis = baseline_apis - current_apis

                if added_apis or removed_apis:
                    comparison['api_changes'][script_name] = {
                        'added': list(added_apis),
                        'removed': list(removed_apis)
                    }
                    comparison['regression_detected'] = True

        return comparison

    def generate_report(self) -> str:
        """Generate regression test report"""
        report_lines = []
        report_lines.append("=" * 60)
        report_lines.append("Frida Script Regression Test Report")
        report_lines.append("=" * 60)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")

        # Run tests
        results = self.run_all_tests()

        # Summary
        report_lines.append("Summary:")
        report_lines.append(f"  Total Scripts: {results['total_scripts']}")
        report_lines.append(f"  Passed: {results['passed']}")
        report_lines.append(f"  Failed: {results['failed']}")
        report_lines.append(f"  Warnings: {results['warnings']}")
        report_lines.append(f"  Changes Detected: {results['changes_detected']}")
        report_lines.append("")

        # Detailed results
        report_lines.append("Detailed Results:")
        report_lines.append("-" * 40)

        for script_name, result in results['script_results'].items():
            status = "PASS" if result['test_passed'] else "FAIL"
            report_lines.append(f"\n{script_name}: {status}")

            if not result['syntax_valid']:
                report_lines.append(f"  Syntax Error: {result['error']}")

            if result['warnings']:
                report_lines.append("  Warnings:")
                for warning in result['warnings']:
                    report_lines.append(f"    - {warning}")

            if result['hooked_apis']:
                report_lines.append("  Hooked APIs:")
                for api in result['hooked_apis'][:5]:  # Show first 5
                    report_lines.append(f"    - {api}")
                if len(result['hooked_apis']) > 5:
                    report_lines.append(f"    ... and {len(result['hooked_apis']) - 5} more")

        # Baseline comparison
        report_lines.append("\n" + "=" * 40)
        report_lines.append("Baseline Comparison:")
        report_lines.append("-" * 40)

        comparison = self.compare_with_baseline()

        if comparison['new_scripts']:
            report_lines.append("New Scripts:")
            for script in comparison['new_scripts']:
                report_lines.append(f"  + {script}")

        if comparison['removed_scripts']:
            report_lines.append("Removed Scripts:")
            for script in comparison['removed_scripts']:
                report_lines.append(f"  - {script}")

        if comparison['modified_scripts']:
            report_lines.append("Modified Scripts:")
            for script in comparison['modified_scripts']:
                report_lines.append(f"  * {script}")

        if comparison['api_changes']:
            report_lines.append("API Changes:")
            for script, changes in comparison['api_changes'].items():
                report_lines.append(f"  {script}:")
                if changes['added']:
                    report_lines.append("    Added:")
                    for api in changes['added']:
                        report_lines.append(f"      + {api}")
                if changes['removed']:
                    report_lines.append("    Removed:")
                    for api in changes['removed']:
                        report_lines.append(f"      - {api}")

        if comparison['regression_detected']:
            report_lines.append("\n⚠️  REGRESSION DETECTED - Review changes carefully!")
        else:
            report_lines.append("\n✅ No regressions detected")

        return "\n".join(report_lines)


class TestFridaScriptRegression(unittest.TestCase):
    """Unit tests for regression testing system"""

    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.scripts_dir = Path(self.temp_dir) / "scripts"
        self.scripts_dir.mkdir()

        # Create test scripts
        self._create_test_scripts()

    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_test_scripts(self):
        """Create test Frida scripts"""
        # Valid script
        valid_script = """
        Interceptor.attach(Module.findExportByName('kernel32.dll', 'CreateFileW'), {
            onEnter: function(args) {
                send({
                    type: 'api_call',
                    api: 'CreateFileW',
                    filename: args[0].readUtf16String()
                });
            },
            onLeave: function(retval) {
                console.log('CreateFileW returned:', retval);
            }
        });
        """
        (self.scripts_dir / "valid_script.js").write_text(valid_script)

        # Script with syntax error
        invalid_script = """
        Interceptor.attach(Module.findExportByName('kernel32.dll', 'ReadFile'), {
            onEnter: function(args) {
                // Missing closing brace
                send({type: 'test'});
        });
        """
        (self.scripts_dir / "invalid_script.js").write_text(invalid_script)

        # Script with deprecated API
        deprecated_script = """
        Interceptor.detachAll();
        var data = Memory.readUtf8String(ptr('0x12345'));
        """
        (self.scripts_dir / "deprecated_script.js").write_text(deprecated_script)

    def test_syntax_validation(self):
        """Test script syntax validation"""
        # Valid syntax
        valid_content = "Interceptor.attach(ptr('0x12345'), {});"
        valid, error = FridaScriptValidator.validate_syntax(valid_content)
        self.assertTrue(valid)
        self.assertIsNone(error)

        # Invalid syntax - mismatched brackets
        invalid_content = "Interceptor.attach(ptr('0x12345'), {);"
        valid, error = FridaScriptValidator.validate_syntax(invalid_content)
        self.assertFalse(valid)
        self.assertIn("bracket", error.lower())

    def test_api_extraction(self):
        """Test API extraction from scripts"""
        script_content = """
        Interceptor.attach(Module.findExportByName('kernel32.dll', 'CreateFileW'), {});
        Interceptor.attach(Module.findExportByName('ntdll.dll', 'NtCreateFile'), {});
        """

        apis = FridaScriptValidator.extract_hooked_apis(script_content)
        self.assertEqual(len(apis), 2)
        self.assertIn('kernel32.dll!CreateFileW', apis)
        self.assertIn('ntdll.dll!NtCreateFile', apis)

    def test_regression_suite(self):
        """Test regression suite functionality"""
        suite = FridaScriptRegressionSuite(self.scripts_dir)

        # Run tests
        results = suite.run_all_tests()

        self.assertEqual(results['total_scripts'], 3)
        self.assertGreater(results['passed'], 0)
        self.assertGreater(results['failed'], 0)  # Due to invalid_script
        self.assertGreater(results['warnings'], 0)  # Due to deprecated_script

    def test_change_detection(self):
        """Test script change detection"""
        script_path = self.scripts_dir / "changing_script.js"
        script_path.write_text("// Version 1")

        test = ScriptRegressionTest(script_path)

        # First run
        self.assertFalse(test.has_changed())  # No previous hash

        # No change
        self.assertFalse(test.has_changed())

        # Modify script
        script_path.write_text("// Version 2")
        self.assertTrue(test.has_changed())

    def test_report_generation(self):
        """Test report generation"""
        suite = FridaScriptRegressionSuite(self.scripts_dir)
        report = suite.generate_report()

        self.assertIn("Regression Test Report", report)
        self.assertIn("Total Scripts:", report)
        self.assertIn("Passed:", report)
        self.assertIn("Failed:", report)


def run_regression_tests(scripts_dir: Path = None):
    """Run regression tests on Frida scripts"""
    if not FRIDA_AVAILABLE:
        print("Frida not available - skipping regression tests")
        return False

    print("Running Frida script regression tests...")

    # Create regression suite
    suite = FridaScriptRegressionSuite(scripts_dir)

    # Generate and print report
    report = suite.generate_report()
    print(report)

    # Save report
    report_file = Path("frida_regression_report.txt")
    report_file.write_text(report)
    print(f"\nReport saved to: {report_file}")

    # Update baseline if requested
    import sys
    if "--update-baseline" in sys.argv:
        suite._save_baseline()
        print("Baseline updated")

    # Return success if no regressions detected
    comparison = suite.compare_with_baseline()
    return not comparison['regression_detected']


if __name__ == '__main__':
    # Run unit tests
    unittest.main(argv=[''], exit=False, verbosity=2)

    # Run regression tests on actual scripts
    print("\n" + "="*60)
    # Use relative path from test location
    test_dir = Path(__file__).parent
    project_root = test_dir.parent
    scripts_dir = project_root / "scripts" / "frida"
    if scripts_dir.exists():
        success = run_regression_tests(scripts_dir)
        sys.exit(0 if success else 1)
    else:
        print(f"Scripts directory not found: {scripts_dir}")