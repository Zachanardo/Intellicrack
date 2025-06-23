#!/usr/bin/env python3
"""
Comprehensive Placeholder Code Detection Script
Finds ALL placeholder, stub, or simulated code in the Intellicrack project.
"""

import os
import re
import ast
from typing import List, Dict

class PlaceholderDetector:
    def __init__(self):
        self.patterns = {
            'empty_return': [
                r'return\s*$',
                r'return\s+None\s*$',
                r'return\s+\[\]\s*$',
                r'return\s+\{\}\s*$',
                r'return\s+""?\s*$',
                r'return\s+0\s*$',
                r'return\s+False\s*$',
                r'return\s+True\s*$'
            ],
            'placeholder_strings': [
                r'["\']placeholder["\']',
                r'["\']stub["\']',
                r'["\']mock["\']',
                r'["\']fake["\']',
                r'["\']dummy["\']',
                r'["\']test["\']',
                r'["\']TODO["\']',
                r'["\']FIXME["\']',
                r'["\']Not implemented["\']',
                r'["\']Not yet implemented["\']'
            ],
            'todo_comments': [
                r'#\s*TODO',
                r'#\s*FIXME',
                r'#\s*XXX',
                r'#\s*HACK',
                r'#\s*BUG',
                r'#\s*NOTE.*implement',
                r'#\s*Placeholder',
                r'#\s*Stub',
                r'#.*not.*implement',
                r'#.*need.*implement'
            ],
            'not_implemented': [
                r'NotImplementedError',
                r'raise\s+NotImplementedError',
                r'raise\s+Exception.*not.*implement',
                r'raise\s+RuntimeError.*not.*implement'
            ],
            'pass_statements': [
                r'^\s*pass\s*$',
                r'^\s*pass\s*#.*$'
            ],
            'hardcoded_returns': [
                r'return\s+\[.*sample.*\]',
                r'return\s+\{.*example.*\}',
                r'return\s+["\'].*example.*["\']',
                r'return\s+["\'].*demo.*["\']',
                r'return\s+["\'].*sample.*["\']'
            ],
            'simulation_patterns': [
                r'simulate',
                r'mock_',
                r'fake_',
                r'dummy_',
                r'test_data',
                r'sample_data',
                r'example_data',
                r'hardcoded',
                r'for\s+demonstration',
                r'random\.',
                r'np\.random\.',
                r'fake\..*\('
            ]
        }

        self.found_issues = []
        self.stats = {
            'files_scanned': 0,
            'total_issues': 0,
            'empty_functions': 0,
            'placeholder_strings': 0,
            'todo_comments': 0,
            'not_implemented': 0,
            'hardcoded_returns': 0,
            'simulated_code': 0
        }

    def scan_file(self, filepath: str) -> List[Dict]:
        """Scan a single file for placeholder patterns."""
        issues = []

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            self.stats['files_scanned'] += 1

            # Check each line for patterns
            for line_num, line in enumerate(lines, 1):
                # Skip import lines and comments that are just descriptions
                if line.strip().startswith('import ') or line.strip().startswith('from '):
                    continue

                # Check for each pattern category
                for category, patterns in self.patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            # Additional context checking for false positives
                            if self._is_valid_issue(line, category, filepath, line_num, lines):
                                issues.append({
                                    'file': filepath,
                                    'line': line_num,
                                    'content': line.strip(),
                                    'category': category,
                                    'pattern': pattern
                                })
                                self.stats[category] = self.stats.get(category, 0) + 1
                                self.stats['total_issues'] += 1

            # Additional AST-based analysis for function bodies
            try:
                tree = ast.parse(content)
                issues.extend(self._analyze_ast(tree, filepath, lines))
            except SyntaxError:
                # Skip files with syntax errors
                pass

        except Exception as e:
            print(f"Error scanning {filepath}: {e}")

        return issues

    def _is_valid_issue(self, line: str, category: str, filepath: str, line_num: int, lines: List[str]) -> bool:
        """Check if detected pattern is actually an issue or false positive."""
        line = line.strip().lower()

        # Skip certain files that are known to be test/example files
        if any(x in filepath.lower() for x in ['test', 'example', 'demo', 'sample']):
            return False

        # Skip lines that are just logging
        if 'logging' in line or 'logger' in line or 'print(' in line:
            return False

        # Skip docstrings and comments that are just documentation
        if line.startswith('"""') or line.startswith("'''") or line.startswith('#'):
            # Only flag TODO/FIXME comments, not descriptive ones
            if category == 'todo_comments':
                return True
            return False

        # For empty returns, check if it's in a meaningful function
        if category == 'empty_return':
            # Look for function definition above
            for i in range(max(0, line_num - 10), line_num):
                if 'def ' in lines[i]:
                    # Skip property getters/setters and simple accessors
                    if any(x in lines[i].lower() for x in ['@property', 'get_', 'set_', '__str__', '__repr__']):
                        return False
                    return True

        return True

    def _analyze_ast(self, tree: ast.AST, filepath: str, lines: List[str]) -> List[Dict]:
        """Analyze AST for empty functions and other patterns."""
        issues = []

        class FunctionVisitor(ast.NodeVisitor):
            def visit_FunctionDef(self, node):
                # Check if function body is empty or just pass
                if len(node.body) == 1:
                    if isinstance(node.body[0], ast.Pass):
                        issues.append({
                            'file': filepath,
                            'line': node.lineno,
                            'content': f"def {node.name}(...): pass",
                            'category': 'empty_functions',
                            'pattern': 'function_with_only_pass'
                        })
                        self.stats['empty_functions'] += 1
                        self.stats['total_issues'] += 1

                    elif isinstance(node.body[0], ast.Return):
                        ret_node = node.body[0]
                        if ret_node.value is None or (
                            isinstance(ret_node.value, ast.Constant) and 
                            ret_node.value.value in [None, [], {}, "", 0, False, True]
                        ):
                            issues.append({
                                'file': filepath,
                                'line': node.lineno,
                                'content': f"def {node.name}(...): return simple_value",
                                'category': 'empty_functions',
                                'pattern': 'function_with_simple_return'
                            })
                            self.stats['empty_functions'] += 1
                            self.stats['total_issues'] += 1

                self.generic_visit(node)

        visitor = FunctionVisitor()
        visitor.visit(tree)
        return issues

    def scan_directory(self, directory: str, extensions: List[str] = ['.py']) -> List[Dict]:
        """Scan all files in directory tree."""
        all_issues = []

        for root, dirs, files in os.walk(directory):
            # Skip certain directories
            skip_dirs = {'venv', '__pycache__', '.git', 'tools', 'examples', 'tests'}
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    filepath = os.path.join(root, file)
                    issues = self.scan_file(filepath)
                    all_issues.extend(issues)

        return all_issues

    def generate_report(self, issues: List[Dict]) -> str:
        """Generate comprehensive report of all found issues."""
        report = []
        report.append("=" * 80)
        report.append("COMPREHENSIVE PLACEHOLDER CODE DETECTION REPORT")
        report.append("=" * 80)
        report.append(f"Files scanned: {self.stats['files_scanned']}")
        report.append(f"Total issues found: {self.stats['total_issues']}")
        report.append("")

        # Statistics by category
        report.append("ISSUES BY CATEGORY:")
        report.append("-" * 40)
        for category, count in self.stats.items():
            if category not in ['files_scanned', 'total_issues'] and count > 0:
                report.append(f"{category.replace('_', ' ').title()}: {count}")
        report.append("")

        # Group issues by file
        issues_by_file = {}
        for issue in issues:
            file_path = issue['file']
            if file_path not in issues_by_file:
                issues_by_file[file_path] = []
            issues_by_file[file_path].append(issue)

        # Sort files by number of issues (most problematic first)
        sorted_files = sorted(issues_by_file.items(), key=lambda x: len(x[1]), reverse=True)

        report.append("DETAILED FINDINGS:")
        report.append("=" * 60)

        for file_path, file_issues in sorted_files:
            relative_path = file_path.replace('/mnt/c/Intellicrack/', '')
            report.append(f"\n📁 {relative_path} ({len(file_issues)} issues)")
            report.append("-" * (len(relative_path) + 20))

            # Group by category within file
            issues_by_category = {}
            for issue in file_issues:
                cat = issue['category']
                if cat not in issues_by_category:
                    issues_by_category[cat] = []
                issues_by_category[cat].append(issue)

            for category, cat_issues in sorted(issues_by_category.items()):
                report.append(f"\n  🔸 {category.replace('_', ' ').title()} ({len(cat_issues)} instances):")
                for issue in cat_issues[:10]:  # Show first 10 per category
                    report.append(f"    Line {issue['line']:4d}: {issue['content'][:80]}")
                if len(cat_issues) > 10:
                    report.append(f"    ... and {len(cat_issues) - 10} more instances")

        # Summary of most problematic files
        report.append("\n" + "=" * 60)
        report.append("TOP 20 MOST PROBLEMATIC FILES:")
        report.append("=" * 60)

        for i, (file_path, file_issues) in enumerate(sorted_files[:20], 1):
            relative_path = file_path.replace('/mnt/c/Intellicrack/', '')
            categories = set(issue['category'] for issue in file_issues)
            report.append(f"{i:2d}. {relative_path} ({len(file_issues)} issues)")
            report.append(f"    Categories: {', '.join(sorted(categories))}")

        return "\n".join(report)

def main():
    """Main function to run comprehensive placeholder detection."""
    detector = PlaceholderDetector()

    print("🔍 Starting comprehensive placeholder code detection...")
    print("This will scan ALL Python files in the Intellicrack project.")
    print("Looking for:")
    print("  - Empty function bodies")
    print("  - TODO/FIXME comments") 
    print("  - NotImplementedError raises")
    print("  - Hardcoded/mock return values")
    print("  - Placeholder strings")
    print("  - Simulated/fake implementations")
    print("")

    # Scan the entire intellicrack directory
    intellicrack_dir = "/mnt/c/Intellicrack/intellicrack"
    issues = detector.scan_directory(intellicrack_dir)

    # Also scan models, plugins, scripts directories
    for additional_dir in ["/mnt/c/Intellicrack/models", "/mnt/c/Intellicrack/plugins", "/mnt/c/Intellicrack/scripts"]:
        if os.path.exists(additional_dir):
            issues.extend(detector.scan_directory(additional_dir))

    # Generate and save report
    report = detector.generate_report(issues)

    # Write to file
    report_file = "/mnt/c/Intellicrack/placeholder_code_report.md"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)

    print("✅ Scan complete!")
    print(f"📊 Found {detector.stats['total_issues']} potential issues across {detector.stats['files_scanned']} files")
    print(f"📄 Full report saved to: {report_file}")

    # Print summary to console
    print("\n" + "=" * 60)
    print("QUICK SUMMARY - TOP ISSUES:")
    print("=" * 60)

    # Group by file for quick summary
    issues_by_file = {}
    for issue in issues:
        file_path = issue['file'].replace('/mnt/c/Intellicrack/', '')
        if file_path not in issues_by_file:
            issues_by_file[file_path] = 0
        issues_by_file[file_path] += 1

    # Show top 10 most problematic files
    sorted_files = sorted(issues_by_file.items(), key=lambda x: x[1], reverse=True)
    for i, (file_path, count) in enumerate(sorted_files[:10], 1):
        print(f"{i:2d}. {file_path}: {count} issues")

if __name__ == "__main__":
    main()