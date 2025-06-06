#!/usr/bin/env python3
"""
Fix W0613 unused-argument warnings by prefixing with underscore.
This script is conservative and only fixes simple cases.
"""

import re
import os
import ast
import sys

class UnusedArgumentFixer(ast.NodeVisitor):
    """AST visitor to find and fix unused arguments."""
    
    def __init__(self, source_lines):
        self.source_lines = source_lines
        self.fixes = []
        self.current_function = None
        
    def visit_FunctionDef(self, node):
        """Visit function definitions."""
        self.current_function = node.name
        
        # Get function body as text to check for argument usage
        func_body_lines = []
        for child in ast.walk(node):
            if hasattr(child, 'lineno') and child.lineno > node.lineno:
                if child.lineno <= node.end_lineno:
                    line_idx = child.lineno - 1
                    if line_idx < len(self.source_lines):
                        func_body_lines.append(self.source_lines[line_idx])
        
        func_body = '\n'.join(func_body_lines)
        
        # Check each argument
        for arg in node.args.args:
            arg_name = arg.arg
            
            # Skip self, cls, and already underscored args
            if arg_name in ('self', 'cls') or arg_name.startswith('_'):
                continue
                
            # Check if argument is used in function body
            # Simple heuristic: look for the argument name as a whole word
            pattern = r'\b' + re.escape(arg_name) + r'\b'
            
            # Check if used in function body (excluding the def line)
            if not re.search(pattern, func_body):
                # Argument appears unused, suggest fix
                self.fixes.append({
                    'line': node.lineno,
                    'function': node.name,
                    'arg_name': arg_name,
                    'new_name': '_' + arg_name
                })
        
        self.generic_visit(node)
        self.current_function = None

def fix_unused_arguments_in_file(filepath, target_warnings):
    """Fix unused arguments in a single file based on pylint warnings."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.splitlines()
        
        # Parse the file
        try:
            tree = ast.parse(content)
        except SyntaxError:
            print(f"Syntax error in {filepath}, skipping")
            return False
            
        # Find unused arguments
        fixer = UnusedArgumentFixer(lines)
        fixer.visit(tree)
        
        # Apply fixes based on warnings
        modifications = []
        for warning in target_warnings:
            if warning['file'] == filepath:
                line_num = warning['line']
                arg_name = warning['arg']
                
                # Find the corresponding fix
                for fix in fixer.fixes:
                    if fix['arg_name'] == arg_name:
                        # We need to fix both the definition and any default value
                        line_idx = line_num - 1
                        if line_idx < len(lines):
                            old_line = lines[line_idx]
                            # Replace argument name with underscore version
                            # Be careful to match whole words only
                            new_line = re.sub(
                                r'\b' + re.escape(arg_name) + r'\b',
                                '_' + arg_name,
                                old_line
                            )
                            if new_line != old_line:
                                lines[line_idx] = new_line
                                modifications.append({
                                    'line': line_num,
                                    'old': old_line.strip(),
                                    'new': new_line.strip()
                                })
        
        if modifications:
            # Write back the file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines) + '\n')
            
            print(f"Fixed {len(modifications)} unused arguments in {filepath}")
            for mod in modifications:
                print(f"  Line {mod['line']}: {mod['old']} -> {mod['new']}")
            return True
            
        return False
        
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def parse_warnings_from_file(errors_file):
    """Parse W0613 warnings from the errors file."""
    warnings = []
    
    with open(errors_file, 'r') as f:
        for line in f:
            # Match lines like: intellicrack/ai/ai_assistant_enhanced.py:345:29: W0613: Unused argument 'message' (unused-argument)
            match = re.match(r'^(.+?):(\d+):\d+: W0613: Unused argument \'(.+?)\' \(unused-argument\)$', line.strip())
            if match:
                warnings.append({
                    'file': '/' + match.group(1).replace('\\', '/'),
                    'line': int(match.group(2)),
                    'arg': match.group(3)
                })
    
    return warnings

def main():
    """Main function to process files."""
    errors_file = '/mnt/c/Intellicrack/IntellicrackErrors.txt'
    
    print("Parsing W0613 warnings from errors file...")
    warnings = parse_warnings_from_file(errors_file)
    print(f"Found {len(warnings)} unused argument warnings")
    
    # Group warnings by file
    warnings_by_file = {}
    for warning in warnings:
        filepath = '/mnt/c/Intellicrack/' + warning['file'].lstrip('/')
        if filepath not in warnings_by_file:
            warnings_by_file[filepath] = []
        warnings_by_file[filepath].append(warning)
    
    print(f"\nProcessing {len(warnings_by_file)} files...")
    
    fixed_files = 0
    for filepath, file_warnings in warnings_by_file.items():
        if os.path.exists(filepath):
            if fix_unused_arguments_in_file(filepath, file_warnings):
                fixed_files += 1
        else:
            print(f"File not found: {filepath}")
    
    print(f"\nFixed unused arguments in {fixed_files} files")
    print("\nNote: Review changes carefully as some arguments might be used in ways not detected by this script")

if __name__ == "__main__":
    main()