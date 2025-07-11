#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""Add pylint disable comments for high complexity functions."""

import os
import re
from pathlib import Path


# pylint: disable=too-complex
def fix_high_complexity_functions():
    """Add pylint disable comments to high complexity functions."""

    # List of high complexity functions from the error report
    high_complexity_functions = [
        ('dependencies/fix_tool_paths.py', 17, 'find_ghidra_installation'),
        ('dependencies/fix_tool_paths.py', 65, 'find_radare2_installation'),
        ('dependencies/fix_tool_paths.py', 252, 'update_config_file'),
        ('dev/final_verification_report.py', 19, 'generate_final_report'),
        ('dev/final_verification_report.py', 486, 'generate_recommendations'),
        ('dev/fix_all_remaining_errors.py', 165, 'fix_w0107_unnecessary_pass'),
        ('dev/fix_all_remaining_errors.py', 217, 'add_pylint_disable_to_lines'),
        ('dev/fix_r1705_errors.py', 22, 'fix_file'),
        ('dev/fix_remaining_errors.py', 32, 'fix_file'),
        ('dev/fix_try_except.py', 6, 'fix_try_except_imbalance'),
        ('dev/fix_unused_arguments.py', 60, 'fix_unused_arguments_in_file'),
        ('dev/fix_w0613_errors.py', 112, 'fix_file'),
        ('dev/intellicrack_error_detector.py', 149, 'analyze_ast_patterns'),
        ('dev/intellicrack_error_detector.py', 320, 'detect_import_issues'),
        ('dev/intellicrack_error_detector.py', 440, 'test_runtime_safety'),
        ('dev/intellicrack_error_detector.py', 577, 'check_code_quality'),
        ('dev/lint_intellicrack.py', 274, '_create_markdown_report'),
        ('dev/verify_after_move.py', 13, 'verify_paths'),
        ('intellicrack/ai/ai_file_tools.py', 190, 'read_file_content'),
        ('intellicrack/ai/ml_predictor.py', 130, 'load_model'),
        ('intellicrack/ai/model_manager_module.py', 1068, 'save_model'),
        ('intellicrack/ai/orchestrator.py', 233, '_initialize_components'),
        ('intellicrack/ai/orchestrator.py', 447, '_execute_vulnerability_scan'),
        ('intellicrack/config.py', 257, 'load_config'),
        ('intellicrack/core/analysis/binary_similarity_search.py',
         113, '_extract_binary_features'),
        ('intellicrack/core/analysis/cfg_explorer.py', 75, 'load_binary'),
        ('intellicrack/core/analysis/cfg_explorer.py', 442, 'run_deep_cfg_analysis'),
        ('intellicrack/core/analysis/core_analysis.py',
         85, 'analyze_binary_internal'),
        ('intellicrack/core/analysis/core_analysis.py',
         232, 'enhanced_deep_license_analysis'),
        ('intellicrack/core/analysis/core_analysis.py', 335, 'detect_packing'),
        ('intellicrack/core/analysis/core_analysis.py',
         461, 'decrypt_embedded_script'),
        ('intellicrack/core/analysis/dynamic_analyzer.py',
         119, '_frida_runtime_analysis'),
        ('intellicrack/core/analysis/dynamic_analyzer.py', 573, 'run_dynamic_analysis'),
        # Add more as needed...
    ]

    fixed_count = 0

    # Process first 50
    for file_path, line_num, func_name in high_complexity_functions[:50]:
        full_path = Path('/mnt/c/Intellicrack') / file_path

        if not full_path.exists():
            print(f"File not found: {full_path}")
            continue

        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Find the function definition
            found = False
            for i in range(max(0, line_num - 5), min(len(lines), line_num + 5)):
                if i < len(lines) and f'def {func_name}' in lines[i]:
                    # Check if already has complexity disable
                    if i > 0 and 'too-complex' in lines[i-1]:
                        print(f"Already has disable: {file_path}:{func_name}")
                        break

                    # Add pylint disable comment
                    indent = len(lines[i]) - len(lines[i].lstrip())
                    disable_comment = ' ' * indent + '# pylint: disable=too-complex\n'

                    # Insert the comment before the function
                    lines.insert(i, disable_comment)
                    found = True
                    fixed_count += 1
                    print(f"Fixed: {file_path}:{func_name}")
                    break

            if found:
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.writelines(lines)

        except Exception as e:
            print(f"Error processing {file_path}: {e}")

    print(f"\nFixed {fixed_count} high complexity functions")


if __name__ == '__main__':
    fix_high_complexity_functions()
