#!/usr/bin/env python3
"""Fix R1705 no-else-return errors by removing unnecessary elif/else after return."""

import re
import os

# Files to fix based on the error report
FILES_TO_FIX = [
    ('intellicrack/ai/ai_assistant_enhanced.py', [312, 325, 336, 385, 423]),
    ('intellicrack/ai/ai_tools.py', [82]),
    ('intellicrack/ai/coordination_layer.py', [162, 521]),
    ('intellicrack/ai/llm_backends.py', [384]),
    ('intellicrack/ai/ml_predictor.py', [138, 692]),
    ('intellicrack/ai/model_manager_module.py', [258]),
    ('intellicrack/ai/training_thread.py', [143, 366]),
    ('intellicrack/core/analysis/binary_similarity_search.py', [432]),
    ('intellicrack/core/analysis/cfg_explorer.py', [172]),
    ('intellicrack/core/analysis/concolic_executor.py', [290]),
    ('intellicrack/core/analysis/incremental_manager.py', [302, 325, 366]),
]

# pylint: disable=too-complex
def fix_file(filepath, line_numbers):
    """Fix no-else-return warnings by removing unnecessary elif/else."""
    try:
        # Read the file
        full_path = os.path.join('/mnt/c/Intellicrack', filepath)
        with open(full_path, 'r') as f:
            lines = f.readlines()
        
        # Process each line number
        for line_num in sorted(line_numbers, reverse=True):  # Process in reverse to avoid index issues
            # Adjust for 0-based indexing
            idx = line_num - 1
            if idx < len(lines):
                line = lines[idx]
                stripped = line.lstrip()
                indent = len(line) - len(stripped)
                
                # Check if it's elif or else
                if stripped.startswith('elif '):
                    # Replace elif with if
                    lines[idx] = ' ' * indent + 'if' + stripped[4:]
                elif stripped.startswith('else:'):
                    # Remove else line and de-indent following block
                    lines.pop(idx)
                    # De-indent the following lines
                    i = idx
                    while i < len(lines):
                        if lines[i].strip() == '':
                            i += 1
                            continue
                        current_indent = len(lines[i]) - len(lines[i].lstrip())
                        if current_indent > indent:
                            # This line is part of the else block, de-indent it
                            if lines[i].startswith(' ' * 4):
                                lines[i] = lines[i][4:]
                        else:
                            # We've reached the end of the else block
                            break
                        i += 1
        
        # Write back
        with open(full_path, 'w') as f:
            f.writelines(lines)
        
        print(f"Fixed {filepath}")
        
    except Exception as e:
        print(f"Error fixing {filepath}: {e}")

def main():
    """Main function."""
    for filepath, line_numbers in FILES_TO_FIX:
        fix_file(filepath, line_numbers)
    
    print("\nR1705 fixes applied!")

if __name__ == '__main__':
    main()