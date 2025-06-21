#!/usr/bin/env python3
"""
Comprehensive Mock Data and Placeholder Scanner for Intellicrack

This script scans the entire Intellicrack codebase to identify:
- Mock data and hardcoded test values
- Simulated API calls and delays
- Placeholder functions
- TODO/FIXME comments
- Hardcoded URLs and configuration
- Functions with just 'pass' statements
- Placeholder return values
"""

import os
import re
import ast
from pathlib import Path
from typing import List, Dict, Tuple, Set

class MockDataScanner:
    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.findings = {
            'mock_data': [],
            'hardcoded_values': [],
            'simulated_delays': [],
            'placeholder_functions': [],
            'todo_comments': [],
            'hardcoded_urls': [],
            'pass_statements': [],
            'static_returns': [],
            'demo_references': [],
            'test_domains': []
        }
        
        # Patterns to search for
        self.patterns = {
            'mock_data': [
                r'(mock|fake|dummy|placeholder|demo|example).*=',
                r'return.*["\']mock',
                r'return.*["\']fake',
                r'return.*["\']demo',
                r'return.*["\']test',
                r'["\']example\.com["\']',
                r'["\']test\.com["\']',
                r'["\']sample\.exe["\']',
                r'["\']dummy["\']'
            ],
            'hardcoded_urls': [
                r'https?://(?:localhost|127\.0\.0\.1|example\.com|test\.com)',
                r'["\']localhost["\']',
                r'["\']127\.0\.0\.1["\']'
            ],
            'simulated_delays': [
                r'time\.sleep\s*\(',
                r'setTimeout\s*\(',
                r'\.delay\s*\(',
                r'await.*sleep'
            ],
            'todo_comments': [
                r'#.*(?:TODO|FIXME|XXX|HACK)',
                r'""".*(?:TODO|FIXME|XXX|HACK)',
                r"'''.*(?:TODO|FIXME|XXX|HACK)"
            ],
            'static_returns': [
                r'return\s+(True|False|None|\[\]|\{\}|""|\'\'|\d+)$',
                r'return\s+["\'][^"\']*["\']$'
            ],
            'pass_statements': [
                r'^\s*pass\s*$'
            ]
        }
        
        # Demo/test content indicators
        self.demo_indicators = [
            'demo', 'test', 'example', 'mock', 'fake', 'dummy', 'placeholder',
            'sample', 'trial', 'evaluation'
        ]

    def scan_file(self, file_path: Path) -> Dict:
        """Scan a single Python file for mock data and placeholders."""
        file_findings = {category: [] for category in self.findings.keys()}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            relative_path = str(file_path.relative_to(self.base_path))
            
            # Check each line for patterns
            for line_num, line in enumerate(lines, 1):
                line_stripped = line.strip()
                
                # Skip empty lines and imports
                if not line_stripped or line_stripped.startswith('import ') or line_stripped.startswith('from '):
                    continue
                
                # Check for TODO/FIXME comments
                for pattern in self.patterns['todo_comments']:
                    if re.search(pattern, line, re.IGNORECASE):
                        file_findings['todo_comments'].append({
                            'file': relative_path,
                            'line': line_num,
                            'content': line_stripped[:100],
                            'type': 'todo_comment'
                        })
                
                # Check for hardcoded URLs
                for pattern in self.patterns['hardcoded_urls']:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        file_findings['hardcoded_urls'].append({
                            'file': relative_path,
                            'line': line_num,
                            'content': line_stripped[:100],
                            'match': match.group(),
                            'type': 'hardcoded_url'
                        })
                
                # Check for simulated delays
                for pattern in self.patterns['simulated_delays']:
                    if re.search(pattern, line):
                        file_findings['simulated_delays'].append({
                            'file': relative_path,
                            'line': line_num,
                            'content': line_stripped[:100],
                            'type': 'simulated_delay'
                        })
                
                # Check for pass statements
                if re.match(self.patterns['pass_statements'][0], line_stripped):
                    file_findings['pass_statements'].append({
                        'file': relative_path,
                        'line': line_num,
                        'content': line_stripped,
                        'type': 'pass_statement'
                    })
                
                # Check for static returns
                for pattern in self.patterns['static_returns']:
                    if re.match(pattern, line_stripped):
                        file_findings['static_returns'].append({
                            'file': relative_path,
                            'line': line_num,
                            'content': line_stripped[:100],
                            'type': 'static_return'
                        })
                
                # Check for demo/test references
                for indicator in self.demo_indicators:
                    if indicator in line_stripped.lower() and ('=' in line_stripped or 'def ' in line_stripped):
                        file_findings['demo_references'].append({
                            'file': relative_path,
                            'line': line_num,
                            'content': line_stripped[:100],
                            'indicator': indicator,
                            'type': 'demo_reference'
                        })
            
            # Check for placeholder functions and mock data using AST
            try:
                tree = ast.parse(content)
                self._analyze_ast(tree, file_findings, relative_path)
            except (SyntaxError, UnicodeDecodeError):
                pass  # Skip files with syntax errors
                
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
        
        return file_findings

    def _analyze_ast(self, tree: ast.AST, file_findings: Dict, relative_path: str):
        """Analyze AST for more complex patterns."""
        for node in ast.walk(tree):
            # Check function definitions
            if isinstance(node, ast.FunctionDef):
                # Check for placeholder functions
                if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                    file_findings['placeholder_functions'].append({
                        'file': relative_path,
                        'line': node.lineno,
                        'function': node.name,
                        'type': 'placeholder_function'
                    })
                
                # Check for functions that only return static values
                elif (len(node.body) == 1 and 
                      isinstance(node.body[0], ast.Return) and
                      isinstance(node.body[0].value, (ast.Constant, ast.NameConstant, ast.Str, ast.Num))):
                    file_findings['placeholder_functions'].append({
                        'file': relative_path,
                        'line': node.lineno,
                        'function': node.name,
                        'type': 'static_return_function'
                    })
            
            # Check for hardcoded test/demo data in assignments
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(indicator in var_name for indicator in self.demo_indicators):
                            file_findings['mock_data'].append({
                                'file': relative_path,
                                'line': node.lineno,
                                'variable': target.id,
                                'type': 'mock_variable'
                            })
            
            # Check for hardcoded strings that look like test data
            elif isinstance(node, (ast.Str, ast.Constant)):
                if isinstance(node.s if hasattr(node, 's') else node.value, str):
                    value = node.s if hasattr(node, 's') else node.value
                    if any(indicator in value.lower() for indicator in self.demo_indicators):
                        if len(value) > 5:  # Ignore very short strings
                            file_findings['mock_data'].append({
                                'file': relative_path,
                                'line': node.lineno,
                                'value': value[:50],
                                'type': 'mock_string'
                            })

    def scan_directory(self, directory: Path = None) -> None:
        """Scan all Python files in the directory recursively."""
        if directory is None:
            directory = self.base_path
        
        python_files = list(directory.rglob("*.py"))
        total_files = len(python_files)
        
        print(f"Scanning {total_files} Python files...")
        
        for i, file_path in enumerate(python_files, 1):
            if i % 50 == 0:
                print(f"Progress: {i}/{total_files} files")
            
            file_findings = self.scan_file(file_path)
            
            # Merge findings
            for category, items in file_findings.items():
                self.findings[category].extend(items)

    def generate_report(self) -> str:
        """Generate a comprehensive report of findings."""
        report = []
        report.append("# COMPREHENSIVE MOCK DATA AND PLACEHOLDER ANALYSIS")
        report.append("=" * 60)
        report.append("")
        
        # Summary
        total_issues = sum(len(items) for items in self.findings.values())
        report.append(f"## SUMMARY")
        report.append(f"Total Issues Found: {total_issues}")
        report.append("")
        
        for category, items in self.findings.items():
            if items:
                report.append(f"- {category.replace('_', ' ').title()}: {len(items)}")
        report.append("")
        
        # Detailed findings by category
        for category, items in self.findings.items():
            if not items:
                continue
                
            report.append(f"## {category.replace('_', ' ').upper()}")
            report.append("-" * 40)
            
            # Group by file for better organization
            files_dict = {}
            for item in items:
                file_path = item['file']
                if file_path not in files_dict:
                    files_dict[file_path] = []
                files_dict[file_path].append(item)
            
            for file_path, file_items in sorted(files_dict.items()):
                report.append(f"\n### {file_path}")
                for item in file_items:
                    line_info = f"Line {item.get('line', 'N/A')}"
                    content = item.get('content', item.get('function', item.get('variable', item.get('value', 'N/A'))))
                    report.append(f"- **{line_info}**: {content}")
                    
                    # Add additional context
                    if 'match' in item:
                        report.append(f"  - Match: `{item['match']}`")
                    if 'indicator' in item:
                        report.append(f"  - Indicator: `{item['indicator']}`")
                    if 'function' in item:
                        report.append(f"  - Function: `{item['function']}`")
            
            report.append("")
        
        return "\n".join(report)

    def get_critical_issues(self) -> List[Dict]:
        """Return the most critical issues that need immediate attention."""
        critical = []
        
        # Placeholder functions are critical
        critical.extend([
            {**item, 'severity': 'HIGH', 'reason': 'Function only contains pass statement'}
            for item in self.findings['placeholder_functions']
            if item['type'] == 'placeholder_function'
        ])
        
        # Static return functions might be critical
        critical.extend([
            {**item, 'severity': 'MEDIUM', 'reason': 'Function only returns static value'}
            for item in self.findings['placeholder_functions']
            if item['type'] == 'static_return_function'
        ])
        
        # Hardcoded URLs are critical for security
        critical.extend([
            {**item, 'severity': 'HIGH', 'reason': 'Hardcoded URL/IP address'}
            for item in self.findings['hardcoded_urls']
        ])
        
        # Simulated delays might indicate mock behavior
        critical.extend([
            {**item, 'severity': 'MEDIUM', 'reason': 'Artificial delay - might be simulated behavior'}
            for item in self.findings['simulated_delays']
        ])
        
        return critical

def main():
    """Main function to run the comprehensive scan."""
    base_path = "/mnt/c/Intellicrack/intellicrack"
    
    scanner = MockDataScanner(base_path)
    scanner.scan_directory()
    
    # Generate and save report
    report = scanner.generate_report()
    
    output_file = "/mnt/c/Intellicrack/dev/comprehensive_mock_analysis_results.md"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\nReport saved to: {output_file}")
    
    # Show critical issues summary
    critical_issues = scanner.get_critical_issues()
    if critical_issues:
        print(f"\nCRITICAL ISSUES FOUND: {len(critical_issues)}")
        print("-" * 30)
        
        high_severity = [i for i in critical_issues if i['severity'] == 'HIGH']
        medium_severity = [i for i in critical_issues if i['severity'] == 'MEDIUM']
        
        print(f"High Severity: {len(high_severity)}")
        print(f"Medium Severity: {len(medium_severity)}")
        
        # Show top 10 critical issues
        print("\nTOP 10 CRITICAL ISSUES:")
        for i, issue in enumerate(critical_issues[:10], 1):
            print(f"{i}. {issue['file']}:{issue.get('line', 'N/A')} - {issue['reason']}")
    
    return scanner

if __name__ == "__main__":
    scanner = main()