#!/usr/bin/env python3
"""
Fix W1203 (logging-fstring-interpolation) issues in the codebase.
Converts f-string formatting in logging functions to lazy % formatting.
"""

import re
import os
import sys
from pathlib import Path

def fix_logging_fstring(content):
    """Fix logging f-string issues in content."""
    
    # Pattern to match logging calls with f-strings
    # This will match logger.info(f"..."), logging.debug(f"..."), etc.
    patterns = [
        # Pattern for logger.method(f"...")
        (r'(logger\.\w+)\(f(["\'])(.+?)\2\)', r'\1(\3', 'logger_fstring'),
        # Pattern for logging.method(f"...")
        (r'(logging\.\w+)\(f(["\'])(.+?)\2\)', r'\1(\3', 'logging_fstring'),
        # Pattern for self.logger.method(f"...")
        (r'(self\.logger\.\w+)\(f(["\'])(.+?)\2\)', r'\1(\3', 'self_logger_fstring'),
    ]
    
    modified = False
    lines = content.split('\n')
    
    for i, line in enumerate(lines):
        original_line = line
        
        for pattern, replacement, pattern_type in patterns:
            if re.search(pattern, line):
                # Extract the f-string content
                match = re.search(pattern, line)
                if match:
                    # Convert f-string placeholders {var} to %s and collect variables
                    fstring_content = match.group(3)
                    variables = []
                    
                    # Find all {variable} or {expression} patterns
                    var_pattern = r'\{([^}]+)\}'
                    var_matches = list(re.finditer(var_pattern, fstring_content))
                    
                    if var_matches:
                        # Replace {var} with %s and collect variables
                        new_content = fstring_content
                        for var_match in reversed(var_matches):  # Process in reverse to maintain positions
                            var_expr = var_match.group(1)
                            # Handle special formatting like {var:.2f}
                            if ':' in var_expr:
                                var_name, format_spec = var_expr.split(':', 1)
                                # Convert format specifiers
                                if format_spec.endswith('f'):
                                    replacement_fmt = '%f'
                                elif format_spec.endswith('d'):
                                    replacement_fmt = '%d'
                                elif format_spec.endswith('s'):
                                    replacement_fmt = '%s'
                                else:
                                    replacement_fmt = '%s'
                                variables.insert(0, var_name.strip())
                            else:
                                replacement_fmt = '%s'
                                variables.insert(0, var_expr.strip())
                            
                            new_content = new_content[:var_match.start()] + replacement_fmt + new_content[var_match.end():]
                        
                        # Reconstruct the line
                        quote_char = match.group(2)
                        method_call = match.group(1)
                        
                        if variables:
                            # Create tuple of variables
                            var_tuple = ', '.join(variables)
                            if len(variables) == 1:
                                var_tuple += ','  # Single element tuple needs trailing comma
                            new_line = f'{method_call}({quote_char}{new_content}{quote_char}, {var_tuple})'
                        else:
                            new_line = f'{method_call}({quote_char}{new_content}{quote_char})'
                        
                        # Preserve indentation
                        indent = len(original_line) - len(original_line.lstrip())
                        line = ' ' * indent + new_line.strip()
                        
                        if line != original_line:
                            modified = True
                            lines[i] = line
                            break  # Only apply first matching pattern
    
    return '\n'.join(lines), modified

def process_file(filepath):
    """Process a single Python file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        new_content, modified = fix_logging_fstring(content)
        
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