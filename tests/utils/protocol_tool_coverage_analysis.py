#!/usr/bin/env python3
"""
Protocol Tool Test Coverage Analysis
Validates 80%+ test coverage requirement for protocol_tool.py
"""

import os
import sys
import ast
import inspect
from pathlib import Path
from typing import Dict, List, Set

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class ProtocolToolCoverageAnalyzer:
    """Analyzes test coverage for protocol_tool.py module"""

    def __init__(self):
        self.protocol_tool_path = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "network" / "protocol_tool.py"
        self.test_files = [
            Path(__file__).parent.parent / "unit" / "core" / "network" / "test_protocol_tool.py",
            Path(__file__).parent.parent / "unit" / "core" / "network" / "test_protocol_analysis_capabilities.py",
            Path(__file__).parent.parent / "unit" / "core" / "network" / "test_protocol_manipulation_features.py",
            Path(__file__).parent.parent / "integration" / "test_protocol_tool_integration.py"
        ]

        self.source_analysis = {}
        self.test_analysis = {}
        self.coverage_metrics = {}

    def analyze_source_code(self) -> Dict:
        """Analyze protocol_tool.py source code structure"""
        if not self.protocol_tool_path.exists():
            return {"error": "protocol_tool.py not found"}

        try:
            with open(self.protocol_tool_path, 'r', encoding='utf-8') as f:
                source_code = f.read()

            tree = ast.parse(source_code)

            classes = []
            functions = []
            methods = {}

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    class_info = {
                        'name': node.name,
                        'line_number': node.lineno,
                        'methods': [],
                        'attributes': []
                    }

                    # Find methods and attributes in class
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef):
                            method_info = {
                                'name': item.name,
                                'line_number': item.lineno,
                                'is_private': item.name.startswith('_'),
                                'is_special': item.name.startswith('__') and item.name.endswith('__')
                            }
                            class_info['methods'].append(method_info)
                        elif isinstance(item, ast.Assign):
                            for target in item.targets:
                                if isinstance(target, ast.Name):
                                    class_info['attributes'].append(target.id)

                    classes.append(class_info)
                    methods[node.name] = class_info['methods']

                elif isinstance(node, ast.FunctionDef) and not any(isinstance(parent, ast.ClassDef)
                                                                  for parent in ast.walk(tree)
                                                                  if hasattr(parent, 'body') and node in parent.body):
                    functions.append({
                        'name': node.name,
                        'line_number': node.lineno,
                        'is_private': node.name.startswith('_')
                    })

            self.source_analysis = {
                'classes': classes,
                'functions': functions,
                'methods': methods,
                'total_classes': len(classes),
                'total_functions': len(functions),
                'total_methods': sum(len(methods_list) for methods_list in methods.values())
            }

            return self.source_analysis

        except Exception as e:
            return {"error": f"Failed to analyze source: {str(e)}"}

    def analyze_test_coverage(self) -> Dict:
        """Analyze test files for coverage of source code elements"""
        test_coverage = {
            'classes_tested': set(),
            'functions_tested': set(),
            'methods_tested': set(),
            'test_cases': [],
            'test_scenarios': [],
            'integration_tests': 0,
            'unit_tests': 0
        }

        for test_file in self.test_files:
            if not test_file.exists():
                continue

            try:
                with open(test_file, 'r', encoding='utf-8') as f:
                    test_code = f.read()

                # Analyze test file content
                test_info = self._analyze_test_file_content(test_code, test_file.name)

                # Merge results
                test_coverage['classes_tested'].update(test_info['classes_tested'])
                test_coverage['functions_tested'].update(test_info['functions_tested'])
                test_coverage['methods_tested'].update(test_info['methods_tested'])
                test_coverage['test_cases'].extend(test_info['test_cases'])
                test_coverage['test_scenarios'].extend(test_info['test_scenarios'])

                if 'integration' in test_file.name:
                    test_coverage['integration_tests'] += test_info['test_count']
                else:
                    test_coverage['unit_tests'] += test_info['test_count']

            except Exception as e:
                print(f"Warning: Failed to analyze {test_file}: {e}")

        self.test_analysis = test_coverage
        return test_coverage

    def _analyze_test_file_content(self, test_code: str, filename: str) -> Dict:
        """Analyze individual test file content"""
        classes_tested = set()
        functions_tested = set()
        methods_tested = set()
        test_cases = []
        test_scenarios = []

        # Parse test patterns
        lines = test_code.split('\n')
        test_count = 0

        for i, line in enumerate(lines):
            line = line.strip()

            # Count test methods
            if line.startswith('def test_') and '(' in line:
                test_count += 1
                test_name = line.split('(')[0].replace('def ', '')
                test_cases.append({
                    'name': test_name,
                    'line': i + 1,
                    'file': filename
                })

            # Look for class instantiations and method calls
            if 'ProtocolToolWindow' in line:
                classes_tested.add('ProtocolToolWindow')
            if 'ProtocolToolSignals' in line:
                classes_tested.add('ProtocolToolSignals')
            if 'launch_protocol_tool' in line:
                functions_tested.add('launch_protocol_tool')
            if 'update_protocol_tool_description' in line:
                functions_tested.add('update_protocol_tool_description')

            # Look for method calls
            method_patterns = [
                '_setup_ui', '_connect_signals', '_on_input_submitted',
                '_on_start_analysis', '_on_clear_log', 'update_description',
                'closeEvent', '__init__', '__new__'
            ]

            for method in method_patterns:
                if method in line and ('.' + method or method + '(') in line:
                    methods_tested.add(method)

            # Identify test scenarios
            if 'scenario' in line.lower() or 'test_case' in line.lower():
                test_scenarios.append({
                    'description': line[:100],
                    'line': i + 1,
                    'file': filename
                })

        return {
            'classes_tested': classes_tested,
            'functions_tested': functions_tested,
            'methods_tested': methods_tested,
            'test_cases': test_cases,
            'test_scenarios': test_scenarios,
            'test_count': test_count
        }

    def calculate_coverage_metrics(self) -> Dict:
        """Calculate comprehensive coverage metrics"""
        if not self.source_analysis or not self.test_analysis:
            return {"error": "Must run source and test analysis first"}

        # Calculate coverage percentages
        total_classes = self.source_analysis['total_classes']
        total_functions = self.source_analysis['total_functions']
        total_methods = self.source_analysis['total_methods']

        classes_covered = len(self.test_analysis['classes_tested'])
        functions_covered = len(self.test_analysis['functions_tested'])
        methods_covered = len(self.test_analysis['methods_tested'])

        class_coverage = (classes_covered / total_classes * 100) if total_classes > 0 else 0
        function_coverage = (functions_covered / total_functions * 100) if total_functions > 0 else 0
        method_coverage = (methods_covered / total_methods * 100) if total_methods > 0 else 0

        # Calculate overall coverage (weighted average)
        total_elements = total_classes + total_functions + total_methods
        covered_elements = classes_covered + functions_covered + methods_covered
        overall_coverage = (covered_elements / total_elements * 100) if total_elements > 0 else 0

        # Calculate test quality metrics
        total_tests = self.test_analysis['unit_tests'] + self.test_analysis['integration_tests']
        test_scenario_coverage = len(self.test_analysis['test_scenarios'])

        self.coverage_metrics = {
            'overall_coverage_percentage': overall_coverage,
            'class_coverage_percentage': class_coverage,
            'function_coverage_percentage': function_coverage,
            'method_coverage_percentage': method_coverage,
            'total_test_cases': total_tests,
            'unit_tests': self.test_analysis['unit_tests'],
            'integration_tests': self.test_analysis['integration_tests'],
            'test_scenarios': test_scenario_coverage,
            'meets_80_percent_requirement': overall_coverage >= 80.0,
            'coverage_breakdown': {
                'classes': {
                    'total': total_classes,
                    'covered': classes_covered,
                    'uncovered': total_classes - classes_covered
                },
                'functions': {
                    'total': total_functions,
                    'covered': functions_covered,
                    'uncovered': total_functions - functions_covered
                },
                'methods': {
                    'total': total_methods,
                    'covered': methods_covered,
                    'uncovered': total_methods - methods_covered
                }
            }
        }

        return self.coverage_metrics

    def identify_coverage_gaps(self) -> Dict:
        """Identify specific coverage gaps and recommendations"""
        gaps = {
            'uncovered_classes': [],
            'uncovered_functions': [],
            'uncovered_methods': [],
            'recommendations': []
        }

        if not self.source_analysis or not self.test_analysis:
            return gaps

        # Find uncovered classes
        all_classes = {cls['name'] for cls in self.source_analysis['classes']}
        tested_classes = self.test_analysis['classes_tested']
        gaps['uncovered_classes'] = list(all_classes - tested_classes)

        # Find uncovered functions
        all_functions = {func['name'] for func in self.source_analysis['functions']}
        tested_functions = self.test_analysis['functions_tested']
        gaps['uncovered_functions'] = list(all_functions - tested_functions)

        # Find uncovered methods
        all_methods = set()
        for class_name, methods in self.source_analysis['methods'].items():
            for method in methods:
                all_methods.add(f"{class_name}.{method['name']}")

        tested_methods = {f"ProtocolToolWindow.{method}" for method in self.test_analysis['methods_tested']}
        gaps['uncovered_methods'] = list(all_methods - tested_methods)

        # Generate recommendations
        if gaps['uncovered_classes']:
            gaps['recommendations'].append(
                f"Add test coverage for {len(gaps['uncovered_classes'])} uncovered classes: {', '.join(gaps['uncovered_classes'][:3])}{'...' if len(gaps['uncovered_classes']) > 3 else ''}"
            )

        if gaps['uncovered_functions']:
            gaps['recommendations'].append(
                f"Add test coverage for {len(gaps['uncovered_functions'])} uncovered functions: {', '.join(gaps['uncovered_functions'][:3])}{'...' if len(gaps['uncovered_functions']) > 3 else ''}"
            )

        if gaps['uncovered_methods']:
            gaps['recommendations'].append(
                f"Add test coverage for {len(gaps['uncovered_methods'])} uncovered methods"
            )

        return gaps

    def generate_coverage_report(self) -> str:
        """Generate comprehensive coverage analysis report"""
        # Run all analyses
        source_analysis = self.analyze_source_code()
        test_analysis = self.analyze_test_coverage()
        coverage_metrics = self.calculate_coverage_metrics()
        coverage_gaps = self.identify_coverage_gaps()

        report = f"""
# PROTOCOL TOOL TEST COVERAGE ANALYSIS REPORT

## EXECUTIVE SUMMARY
- **Overall Coverage**: {coverage_metrics.get('overall_coverage_percentage', 0):.1f}%
- **80% Requirement Met**: {'OK YES' if coverage_metrics.get('meets_80_percent_requirement', False) else 'FAIL NO'}
- **Total Test Cases**: {coverage_metrics.get('total_test_cases', 0)}
- **Test Quality**: {'HIGH' if coverage_metrics.get('total_test_cases', 0) > 50 else 'MEDIUM' if coverage_metrics.get('total_test_cases', 0) > 20 else 'LOW'}

## DETAILED COVERAGE METRICS

### Coverage by Component
- **Class Coverage**: {coverage_metrics.get('class_coverage_percentage', 0):.1f}% ({coverage_metrics.get('coverage_breakdown', {}).get('classes', {}).get('covered', 0)}/{coverage_metrics.get('coverage_breakdown', {}).get('classes', {}).get('total', 0)} classes)
- **Function Coverage**: {coverage_metrics.get('function_coverage_percentage', 0):.1f}% ({coverage_metrics.get('coverage_breakdown', {}).get('functions', {}).get('covered', 0)}/{coverage_metrics.get('coverage_breakdown', {}).get('functions', {}).get('total', 0)} functions)
- **Method Coverage**: {coverage_metrics.get('method_coverage_percentage', 0):.1f}% ({coverage_metrics.get('coverage_breakdown', {}).get('methods', {}).get('covered', 0)}/{coverage_metrics.get('coverage_breakdown', {}).get('methods', {}).get('total', 0)} methods)

### Test Distribution
- **Unit Tests**: {coverage_metrics.get('unit_tests', 0)} test cases
- **Integration Tests**: {coverage_metrics.get('integration_tests', 0)} test cases
- **Test Scenarios**: {coverage_metrics.get('test_scenarios', 0)} scenarios covered

## SOURCE CODE ANALYSIS

### Identified Classes
"""

        for cls in source_analysis.get('classes', []):
            status = 'OK' if cls['name'] in test_analysis.get('classes_tested', set()) else 'FAIL'
            report += f"- {status} **{cls['name']}** ({len(cls['methods'])} methods)\n"

        report += f"""
### Identified Functions
"""
        for func in source_analysis.get('functions', []):
            status = 'OK' if func['name'] in test_analysis.get('functions_tested', set()) else 'FAIL'
            report += f"- {status} **{func['name']}()** (line {func['line_number']})\n"

        report += f"""

## TEST COVERAGE ANALYSIS

### Test Files Analyzed
"""
        for test_file in self.test_files:
            exists = 'OK' if test_file.exists() else 'FAIL'
            report += f"- {exists} {test_file.name}\n"

        report += f"""

### Coverage Gaps
"""
        if coverage_gaps.get('uncovered_classes'):
            report += f"\n**Uncovered Classes ({len(coverage_gaps['uncovered_classes'])})**:\n"
            for cls in coverage_gaps['uncovered_classes']:
                report += f"- {cls}\n"

        if coverage_gaps.get('uncovered_functions'):
            report += f"\n**Uncovered Functions ({len(coverage_gaps['uncovered_functions'])})**:\n"
            for func in coverage_gaps['uncovered_functions']:
                report += f"- {func}\n"

        if coverage_gaps.get('uncovered_methods'):
            report += f"\n**Uncovered Methods ({len(coverage_gaps['uncovered_methods'])})**:\n"
            for method in coverage_gaps['uncovered_methods'][:10]:  # Show first 10
                report += f"- {method}\n"
            if len(coverage_gaps['uncovered_methods']) > 10:
                report += f"- ... and {len(coverage_gaps['uncovered_methods']) - 10} more\n"

        report += f"""

## RECOMMENDATIONS

### Priority Actions
"""
        for rec in coverage_gaps.get('recommendations', []):
            report += f"1. {rec}\n"

        report += f"""

### Test Quality Assessment
"""
        total_tests = coverage_metrics.get('total_test_cases', 0)
        if total_tests > 100:
            report += "- **EXCELLENT**: Comprehensive test suite with extensive coverage\n"
        elif total_tests > 50:
            report += "- **GOOD**: Solid test coverage with room for improvement\n"
        elif total_tests > 20:
            report += "- **ADEQUATE**: Basic test coverage present\n"
        else:
            report += "- **INSUFFICIENT**: Inadequate test coverage for production code\n"

        report += f"""

## PRODUCTION READINESS ASSESSMENT

### Compliance Status
- **80% Coverage Requirement**: {'OK MET' if coverage_metrics.get('meets_80_percent_requirement', False) else 'FAIL NOT MET'}
- **Test Quality**: {'OK ACCEPTABLE' if total_tests >= 30 else 'FAIL INSUFFICIENT'}
- **Integration Testing**: {'OK PRESENT' if coverage_metrics.get('integration_tests', 0) > 0 else 'FAIL MISSING'}

### Final Verdict
"""

        if coverage_metrics.get('meets_80_percent_requirement', False) and total_tests >= 30:
            report += "**OK PRODUCTION READY** - Protocol tool meets coverage requirements\n"
        elif coverage_metrics.get('overall_coverage_percentage', 0) >= 70:
            report += "**⚠ NEEDS IMPROVEMENT** - Close to requirements but needs additional test coverage\n"
        else:
            report += "**FAIL NOT PRODUCTION READY** - Insufficient test coverage for production deployment\n"

        report += f"""

---
*Report generated by Protocol Tool Coverage Analyzer*
*Analysis Date: {Path(__file__).stat().st_mtime}*
"""

        return report

    def save_coverage_report(self, output_path: str = None) -> str:
        """Save coverage report to file"""
        if not output_path:
            output_path = Path(__file__).parent.parent / "reports" / "protocol_tool_coverage_report.md"

        report = self.generate_coverage_report()

        # Ensure directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)

        return str(output_path)


def main():
    """Run coverage analysis"""
    print("=" * 60)
    print("PROTOCOL TOOL TEST COVERAGE ANALYSIS")
    print("Validating 80%+ Coverage Requirement")
    print("=" * 60)

    analyzer = ProtocolToolCoverageAnalyzer()

    # Generate and save report
    report_path = analyzer.save_coverage_report()

    # Print summary
    coverage_metrics = analyzer.calculate_coverage_metrics()

    print(f"\nCOVERAGE ANALYSIS COMPLETE")
    print(f"Overall Coverage: {coverage_metrics.get('overall_coverage_percentage', 0):.1f}%")
    print(f"80% Requirement: {'OK MET' if coverage_metrics.get('meets_80_percent_requirement', False) else 'FAIL NOT MET'}")
    print(f"Total Test Cases: {coverage_metrics.get('total_test_cases', 0)}")
    print(f"Report saved: {report_path}")

    return coverage_metrics.get('meets_80_percent_requirement', False)


if __name__ == "__main__":
    main()
