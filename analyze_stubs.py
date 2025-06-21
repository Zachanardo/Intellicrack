#!/usr/bin/env python3
"""
Comprehensive stub analysis script for Intellicrack project.
Identifies all incomplete implementations, placeholders, and stubs.
"""

import os
import re
import ast
import sys
from typing import Dict, List, Tuple, Any
from collections import defaultdict

class StubAnalyzer:
    def __init__(self, project_root: str):
        self.project_root = project_root
        self.findings = defaultdict(list)
        
    def analyze_file(self, filepath: str) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze a single Python file for stubs and placeholders."""
        file_findings = defaultdict(list)
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Parse with AST for function analysis
            try:
                tree = ast.parse(content)
                self._analyze_ast(tree, filepath, file_findings, lines)
            except SyntaxError:
                file_findings['syntax_errors'].append({
                    'file': filepath,
                    'error': 'Could not parse file due to syntax errors'
                })
            
            # Text-based analysis for comments and patterns
            self._analyze_text_patterns(filepath, lines, file_findings)
            
        except Exception as e:
            file_findings['read_errors'].append({
                'file': filepath,
                'error': str(e)
            })
        
        return file_findings
    
    def _analyze_ast(self, tree: ast.AST, filepath: str, findings: Dict, lines: List[str]):
        """Analyze AST for function stubs."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_function(node, filepath, findings, lines)
            elif isinstance(node, ast.ClassDef):
                self._analyze_class(node, filepath, findings, lines)
    
    def _analyze_function(self, node: ast.FunctionDef, filepath: str, findings: Dict, lines: List[str]):
        """Analyze a function for stub patterns."""
        func_name = node.name
        start_line = node.lineno
        
        # Get function body
        body = node.body
        
        # Check for empty function body (only docstring or pass)
        non_docstring_body = [stmt for stmt in body if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Constant)]
        
        if not non_docstring_body:
            findings['empty_functions'].append({
                'file': filepath,
                'line': start_line,
                'function': func_name,
                'type': 'completely_empty'
            })
        elif len(non_docstring_body) == 1:
            stmt = non_docstring_body[0]
            
            # Check for pass statement
            if isinstance(stmt, ast.Pass):
                findings['pass_functions'].append({
                    'file': filepath,
                    'line': start_line,
                    'function': func_name,
                    'implementation': 'pass'
                })
            
            # Check for raise NotImplementedError
            elif isinstance(stmt, ast.Raise) and isinstance(stmt.exc, ast.Call):
                if isinstance(stmt.exc.func, ast.Name) and stmt.exc.func.id == 'NotImplementedError':
                    findings['not_implemented'].append({
                        'file': filepath,
                        'line': start_line,
                        'function': func_name,
                        'implementation': 'raise NotImplementedError'
                    })
            
            # Check for simple returns
            elif isinstance(stmt, ast.Return):
                return_value = self._get_return_value(stmt.value)
                if return_value in ['True', 'False', '[]', '{}', '""', "''", 'None']:
                    findings['simple_returns'].append({
                        'file': filepath,
                        'line': start_line,
                        'function': func_name,
                        'implementation': f'return {return_value}'
                    })
        
        # Check function content for placeholders
        if start_line < len(lines):
            func_lines = lines[start_line-1:start_line + 10]  # Get some context
            func_content = '\n'.join(func_lines)
            
            if any(keyword in func_content.lower() for keyword in ['todo', 'fixme', 'xxx', 'hack', 'placeholder']):
                findings['placeholder_functions'].append({
                    'file': filepath,
                    'line': start_line,
                    'function': func_name,
                    'context': func_content[:200]
                })
    
    def _analyze_class(self, node: ast.ClassDef, filepath: str, findings: Dict, lines: List[str]):
        """Analyze class for stub patterns."""
        class_name = node.name
        
        # Check if class has only pass statement
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            findings['empty_classes'].append({
                'file': filepath,
                'line': node.lineno,
                'class': class_name,
                'implementation': 'pass'
            })
    
    def _get_return_value(self, node):
        """Extract return value as string."""
        if node is None:
            return 'None'
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                return str(node.value)
            elif isinstance(node.value, str):
                return f'"{node.value}"' if node.value else '""'
            elif node.value is None:
                return 'None'
            else:
                return str(node.value)
        elif isinstance(node, ast.List) and len(node.elts) == 0:
            return '[]'
        elif isinstance(node, ast.Dict) and len(node.keys) == 0:
            return '{}'
        elif isinstance(node, ast.NameConstant):
            return str(node.value)
        elif isinstance(node, ast.Name):
            return node.id
        else:
            return 'complex_expression'
    
    def _analyze_text_patterns(self, filepath: str, lines: List[str], findings: Dict):
        """Analyze text patterns for comments and placeholders."""
        for i, line in enumerate(lines, 1):
            line_lower = line.lower().strip()
            
            # Check for TODO/FIXME/XXX/HACK comments
            if any(keyword in line_lower for keyword in ['todo', 'fixme', 'xxx', 'hack']):
                findings['todo_comments'].append({
                    'file': filepath,
                    'line': i,
                    'content': line.strip()
                })
            
            # Check for "not implemented" messages
            if 'not implemented' in line_lower or 'not supported' in line_lower:
                findings['not_implemented_messages'].append({
                    'file': filepath,
                    'line': i,
                    'content': line.strip()
                })
            
            # Check for hardcoded returns in single-line functions
            if re.match(r'^\s*return\s+(true|false|\[\]|\{\}|""|none)\s*$', line_lower):
                findings['hardcoded_returns'].append({
                    'file': filepath,
                    'line': i,
                    'content': line.strip()
                })
    
    def analyze_project(self) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze entire project for stubs."""
        all_findings = defaultdict(list)
        
        for root, dirs, files in os.walk(self.project_root):
            # Skip external tools
            if 'tools/' in root or '.git' in root:
                continue
                
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    file_findings = self.analyze_file(filepath)
                    
                    # Merge findings
                    for category, items in file_findings.items():
                        all_findings[category].extend(items)
        
        return all_findings
    
    def generate_report(self, findings: Dict[str, List[Dict[str, Any]]]) -> str:
        """Generate a comprehensive report."""
        report = []
        report.append("=" * 80)
        report.append("INTELLICRACK STUB ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Summary
        total_issues = sum(len(items) for items in findings.values())
        report.append(f"Total Issues Found: {total_issues}")
        report.append("")
        
        # Category breakdown
        for category, items in findings.items():
            if not items:
                continue
                
            report.append(f"\n{category.upper().replace('_', ' ')} ({len(items)} items)")
            report.append("-" * 60)
            
            for item in items:
                report.append(f"File: {item['file']}")
                report.append(f"Line: {item.get('line', 'N/A')}")
                
                if 'function' in item:
                    report.append(f"Function: {item['function']}")
                if 'class' in item:
                    report.append(f"Class: {item['class']}")
                if 'implementation' in item:
                    report.append(f"Implementation: {item['implementation']}")
                if 'content' in item:
                    report.append(f"Content: {item['content']}")
                if 'context' in item:
                    report.append(f"Context: {item['context'][:100]}...")
                
                report.append("")
        
        return "\n".join(report)

def main():
    if len(sys.argv) > 1:
        project_root = sys.argv[1]
    else:
        project_root = os.path.join(os.path.dirname(__file__), 'intellicrack')
    
    if not os.path.exists(project_root):
        print(f"Error: Project root '{project_root}' does not exist")
        return 1
    
    analyzer = StubAnalyzer(project_root)
    findings = analyzer.analyze_project()
    report = analyzer.generate_report(findings)
    
    # Write report to file
    report_file = 'stub_analysis_report.txt'
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"Analysis complete. Report written to {report_file}")
    print(f"Total issues found: {sum(len(items) for items in findings.values())}")
    
    # Print summary to console
    print("\nSUMMARY BY CATEGORY:")
    for category, items in findings.items():
        if items:
            print(f"  {category.replace('_', ' ').title()}: {len(items)}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())