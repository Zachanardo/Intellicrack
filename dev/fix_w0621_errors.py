#!/usr/bin/env python3
"""Fix W0621 redefined-outer-name errors."""

import re
import os

# Files to fix based on the error report
FILES_TO_FIX = [
    ('intellicrack/ai/coordination_layer.py', [
        (336, 'threading', 'threading_module'),
    ]),
    ('intellicrack/ai/ml_predictor.py', [
        (693, 'RandomForestClassifier', 'RandomForestClassifierClass'),
    ]),
    ('intellicrack/ai/model_manager_module.py', [
        (1072, 'joblib', 'joblib_module'),
        (1080, 'torch', 'torch_module'),
    ]),
    ('intellicrack/core/network/protocol_fingerprinter.py', [
        (217, 'Counter', 'CounterClass'),
    ]),
    ('intellicrack/core/processing/qemu_emulator.py', [
        (680, 'os', 'os_module'),
    ]),
    ('intellicrack/core/reporting/pdf_generator.py', [
        (455, 'inch', 'inch_unit'),
        (456, 'Spacer', 'SpacerClass'),
        (637, 'pdfkit', 'pdfkit_module'),
    ]),
    ('intellicrack/hexview/api.py', [
        # These need special handling as they are function parameters
        (28, 'file_path', '_file_path'),
        (28, 'read_only', '_read_only'),
        (52, 'file_path', '_file_path'),
        (76, 'file_path', '_file_path'),
        (186, 'file_path', '_file_path'),
        (187, 'read_only', '_read_only'),
        (203, 'file_path', '_file_path'),
        (203, 'read_only', '_read_only'),
    ]),
    ('intellicrack/hexview/hex_widget.py', [
        (1815, 'QDialog', 'QDialogClass'),
    ]),
]

def fix_file(filepath, fixes):
    """Fix redefined-outer-name warnings in a file."""
    try:
        # Read the file
        full_path = os.path.join('/mnt/c/Intellicrack', filepath)
        with open(full_path, 'r') as f:
            lines = f.readlines()
        
        # Apply fixes by replacing variable names
        for line_num, old_name, new_name in fixes:
            # Adjust for 0-based indexing
            idx = line_num - 1
            if idx < len(lines):
                line = lines[idx]
                # Replace the old name with new name
                # Use word boundaries to avoid partial replacements
                pattern = r'\b' + re.escape(old_name) + r'\b'
                lines[idx] = re.sub(pattern, new_name, line)
        
        # Write back
        with open(full_path, 'w') as f:
            f.writelines(lines)
        
        print(f"Fixed {filepath}")
        
    except Exception as e:
        print(f"Error fixing {filepath}: {e}")

def main():
    """Main function."""
    for filepath, fixes in FILES_TO_FIX:
        fix_file(filepath, fixes)
    
    print("\nW0621 fixes applied!")

if __name__ == '__main__':
    main()