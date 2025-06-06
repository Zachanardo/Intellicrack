#!/usr/bin/env python3
"""
Fix W0613 (unused-argument) issues in the codebase.
Prefixes unused arguments with underscore to indicate they're intentionally unused.
"""

import re
import ast
import os
import sys
from pathlib import Path

class UnusedArgumentFixer(ast.NodeVisitor):
    """AST visitor to find and fix unused arguments."""
    
    def __init__(self, source_lines):
        self.source_lines = source_lines
        self.modifications = []
        self.current_function = None
        self.used_names = set()
        
    def visit_FunctionDef(self, node):
        """Visit function definitions."""
        old_function = self.current_function
        old_used_names = self.used_names
        
        self.current_function = node
        self.used_names = set()
        
        # First pass: collect all used names in the function
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                self.used_names.add(child.id)
        
        # Check arguments
        all_args = []
        
        # Regular args
        for arg in node.args.args:
            all_args.append((arg, 'regular'))
        
        # *args
        if node.args.vararg:
            all_args.append((node.args.vararg, 'vararg'))
            
        # **kwargs  
        if node.args.kwarg:
            all_args.append((node.args.kwarg, 'kwarg'))
            
        # Keyword only args
        for arg in node.args.kwonlyargs:
            all_args.append((arg, 'kwonly'))
        
        # Check each argument
        for arg, arg_type in all_args:
            arg_name = arg.arg
            
            # Skip self and cls (common in methods)
            if arg_name in ('self', 'cls'):
                continue
                
            # Skip already prefixed with underscore
            if arg_name.startswith('_'):
                continue
            
            # Skip if used in function
            if arg_name in self.used_names:
                continue
                
            # Skip if it's a special method that requires specific signatures
            if (self.current_function.name.startswith('__') and 
                self.current_function.name.endswith('__')):
                continue
            
            # Mark for modification
            self.modifications.append({
                'line': arg.lineno,
                'col': arg.col_offset,
                'old_name': arg_name,
                'new_name': f'_{arg_name}',
                'node': arg
            })
        
        # Continue visiting
        self.generic_visit(node)
        
        self.current_function = old_function
        self.used_names = old_used_names

def fix_unused_arguments_ast(content):
    """Fix unused arguments using AST parsing."""
    try:
        tree = ast.parse(content)
        lines = content.split('\n')
        
        fixer = UnusedArgumentFixer(lines)
        fixer.visit(tree)
        
        if not fixer.modifications:
            return content, False
        
        # Sort modifications by line and column (reverse order for replacement)
        modifications = sorted(fixer.modifications, 
                             key=lambda x: (x['line'], x['col']), 
                             reverse=True)
        
        # Apply modifications
        for mod in modifications:
            line_idx = mod['line'] - 1
            if 0 <= line_idx < len(lines):
                line = lines[line_idx]
                # Use regex to replace the argument name
                old_pattern = r'\b' + re.escape(mod['old_name']) + r'\b'
                new_line = re.sub(old_pattern, mod['new_name'], line, count=1)
                if new_line != line:
                    lines[line_idx] = new_line
        
        return '\n'.join(lines), True
        
    except SyntaxError:
        # If AST parsing fails, return original content
        return content, False

def fix_unused_arguments_regex(content):
    """Fallback regex-based approach for fixing unused arguments."""
    # This is a simplified approach that only handles clear cases
    modified = False
    lines = content.split('\n')
    
    for i, line in enumerate(lines):
        # Skip if line doesn't contain function definition
        if 'def ' not in line:
            continue
            
        # Match function definitions
        match = re.match(r'^(\s*def\s+\w+\s*\()(.*)(\)\s*:.*)', line)
        if match:
            indent, args_str, suffix = match.groups()
            
            # Simple check: if argument is never used in following lines
            # This is very basic and won't catch all cases
            args = [arg.strip() for arg in args_str.split(',')]
            new_args = []
            
            for arg in args:
                # Extract argument name (handle type annotations)
                arg_match = re.match(r'(\w+)(\s*:\s*.+)?(\s*=\s*.+)?', arg.strip())
                if arg_match:
                    arg_name = arg_match.group(1)
                    rest = (arg_match.group(2) or '') + (arg_match.group(3) or '')
                    
                    if arg_name in ('self', 'cls') or arg_name.startswith('_'):
                        new_args.append(arg)
                    else:
                        # Check if used in next 50 lines (simple heuristic)
                        used = False
                        for j in range(i + 1, min(i + 51, len(lines))):
                            if re.search(r'\b' + arg_name + r'\b', lines[j]):
                                used = True
                                break
                        
                        if used:
                            new_args.append(arg)
                        else:
                            new_args.append(f'_{arg_name}{rest}')
                            modified = True
                else:
                    new_args.append(arg)
            
            if modified:
                lines[i] = f"{indent}{', '.join(new_args)}{suffix}"
    
    return '\n'.join(lines), modified

def process_file(filepath):
    """Process a single Python file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Try AST-based approach first
        new_content, modified = fix_unused_arguments_ast(content)
        
        # If AST approach didn't work, try regex approach
        if not modified:
            new_content, modified = fix_unused_arguments_regex(content)
        
        if modified:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    """Main function to process all Python files."""
    project_root = Path("/mnt/c/Intellicrack/Intellicrack_Project/Intellicrack_Project")
    intellicrack_dir = project_root / "intellicrack"
    scripts_dir = project_root / "scripts"
    
    if not intellicrack_dir.exists():
        print(f"Error: {intellicrack_dir} does not exist")
        return 1
    
    modified_files = []
    
    # Process all Python files in intellicrack and scripts directories
    for directory in [intellicrack_dir, scripts_dir]:
        if directory.exists():
            for py_file in directory.rglob("*.py"):
                if process_file(py_file):
                    modified_files.append(py_file)
                    print(f"Fixed: {py_file.relative_to(project_root)}")
    
    print(f"\nTotal files modified: {len(modified_files)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())