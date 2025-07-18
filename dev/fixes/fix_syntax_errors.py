#!/usr/bin/env python3
"""Fix remaining syntax errors from duplicate docstring fixes."""

import re
from pathlib import Path

def fix_syntax_errors_in_file(file_path):
    """Fix syntax errors in a specific file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Fix: indented docstring followed by indented code
        # Pattern: """docstring""" followed by indented line that should be unindented
        lines = content.split('\n')
        new_lines = []
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # Check if this line ends a docstring and next line has wrong indentation
            if line.strip().endswith('"""') and i + 1 < len(lines):
                next_line = lines[i + 1]
                # If next line starts with extra spaces, fix it
                if next_line.startswith('        ') and not next_line.strip().startswith('"""'):
                    # Check if this should be dedented (common pattern)
                    if any(keyword in next_line for keyword in ['super().__init__', 'self.', 'import ', 'from ']):
                        # Dedent by 4 spaces
                        lines[i + 1] = next_line[4:]
            
            new_lines.append(lines[i])
            i += 1
        
        content = '\n'.join(new_lines)
        
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Fixed syntax errors in {file_path.relative_to(Path('C:/Intellicrack'))}")
            return True
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False
    
    return False

# Files with known syntax errors
files_to_fix = [
    "intellicrack/config.py",
    "intellicrack/core/ai_model_manager.py", 
    "intellicrack/core/analysis/analysis_orchestrator.py",
    "intellicrack/core/analysis/binary_analyzer.py"
]

base_path = Path("C:/Intellicrack")

for file_path in files_to_fix:
    full_path = base_path / file_path
    if full_path.exists():
        fix_syntax_errors_in_file(full_path)

print("Done fixing syntax errors!")