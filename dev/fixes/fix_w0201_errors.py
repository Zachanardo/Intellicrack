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

"""
Fix W0201 (attribute-defined-outside-init) errors automatically.
"""

import ast
import os
import re
from typing import Dict, List, Set

# Define the W0201 errors and their locations
W0201_ERRORS = {
    'intellicrack/ui/main_app.py': [
        ('traffic_analyzer', 6916),
        ('capture_thread', 6923),
        ('packet_update_timer', 6934),
        ('chat_display', 10332),
        ('chat_display', 14490),
        ('user_input', 10371),
        ('user_input', 14504),
        ('assistant_status', 10309),
        ('assistant_status', 14544),
        ('binary_tool_file_label', 9255),
        ('binary_tool_file_info', 9256),
        ('binary_tool_stack', 9274),
        ('view_current_btn', 9301),
        ('edit_current_btn', 9304),
        ('disasm_text', 9412),
        ('plugin_name_label', 10171),
        ('log_filter', 10411),
        ('info_check', 10430),
        ('warning_check', 10432),
        ('error_check', 10434),
        ('debug_check', 10436),
        ('log_output', 10453),
        ('recent_files_list', 10805),
        ('binary_info_group', 10829),
        ('notifications_list', 10854),
        ('activity_log', 10933),
        ('_hex_viewer_dialogs', 12719),
        ('last_log_accessed', 14370),
        ('log_access_history', 14394),
        ('assistant_tab', 14479),
        ('ai_conversation_history', 19081),
        ('report_viewer', 20454),
        ('report_viewer', 20504),
        ('report_viewer', 21044),
        ('reports', 20716),
    ],
    'intellicrack/ui/main_window.py': [
        ('file_path_label', 131),
        ('browse_button', 134),
        ('analyze_button', 150),
        ('scan_vulnerabilities_button', 154),
        ('generate_report_button', 158),
        ('info_display', 173),
        ('vulnerability_scan_cb', 192),
        ('entropy_analysis_cb', 195),
        ('import_analysis_cb', 198),
        ('export_analysis_cb', 201),
        ('analysis_output', 215),
        ('results_display', 230),
        ('clear_results_button', 238),
        ('export_results_button', 241),
        ('verbose_logging_cb', 261),
        ('auto_save_results_cb', 264),
    ],
    'intellicrack/ui/dialogs/base_dialog.py': [
        ('analyze_btn', 59),
    ],
    'intellicrack/ui/dialogs/help_documentation_widget.py': [
        ('features_tree', 130),
        ('feature_details', 138),
        ('tutorial_tabs', 151),
        ('tutorial_viewer', 176),
        ('issues_tree', 194),
        ('solution_viewer', 202),
    ],
    'intellicrack/ui/dialogs/keygen_dialog.py': [
        ('tabs', 192),
        ('algorithm_combo', 219),
        ('format_combo', 228),
        ('length_spin', 236),
        ('validation_check', 243),
        ('generate_btn', 253),
        ('key_display', 259),
        ('copy_btn', 268),
        ('save_single_btn', 271),
        ('results_display', 286),
        ('batch_count_spin', 305),
        ('batch_algorithm_combo', 311),
        ('batch_format_combo', 319),
        ('batch_generate_btn', 330),
        ('batch_stop_btn', 334),
        ('batch_clear_btn', 338),
        ('batch_export_btn', 341),
        ('batch_progress', 353),
        ('batch_table', 357),
        ('analysis_display', 377),
        ('existing_keys_input', 394),
        ('analyze_keys_btn', 399),
        ('key_analysis_display', 406),
    ],
    'intellicrack/ui/dialogs/llm_config_dialog.py': [
        ('openai_api_key', 242),
        ('openai_model', 248),
        ('openai_base_url', 259),
        ('openai_temp', 264),
        ('openai_max_tokens', 270),
        ('openai_tools', 276),
        ('anthropic_api_key', 300),
        ('anthropic_model', 306),
        ('anthropic_temp', 318),
        ('anthropic_max_tokens', 324),
        ('anthropic_tools', 330),
        ('gguf_model_path', 355),
        ('gguf_model_name', 365),
        ('gguf_context', 370),
        ('gguf_temp', 376),
        ('gguf_max_tokens', 383),
        ('gguf_tools', 389),
        ('ollama_url', 418),
        ('ollama_model', 423),
        ('ollama_temp', 428),
        ('ollama_max_tokens', 434),
    ],
    'intellicrack/ui/dialogs/model_finetuning_dialog.py': [
        ('training_args', 970),
        ('model_path_edit', 1188),
        ('model_path_button', 1189),
        ('model_format_combo', 1198),
        ('epochs_spin', 1212),
        ('batch_size_spin', 1217),
        ('learning_rate_spin', 1222),
        ('lora_rank_spin', 1237),
        ('lora_alpha_spin', 1242),
        ('cutoff_len_spin', 1247),
        ('gradient_accum_spin', 1252),
        ('train_button', 1265),
        ('stop_button', 1268),
        ('save_model_button', 1272),
        ('training_log', 1281),
        ('dataset_path_edit', 1303),
        ('dataset_path_button', 1304),
        ('dataset_format_combo', 1312),
        ('dataset_preview', 1323),
        ('load_preview_button', 1331),
        ('sample_count_spin', 1334),
        ('create_dataset_button', 1351),
        ('validate_dataset_button', 1354),
        ('export_dataset_button', 1357),
        ('synonym_check', 1376),
        ('random_insert_check', 1380),
        ('random_swap_check', 1383),
        ('random_delete_check', 1386),
        ('backtranslation_check', 1389),
        ('paraphrase_check', 1392),
        ('aug_per_sample_spin', 1402),
        ('aug_prob_slider', 1407),
        ('aug_prob_label', 1410),
        ('preserve_labels_check', 1420),
        ('preview_aug_button', 1432),
        ('apply_aug_button', 1435),
        ('aug_progress', 1444),
        ('aug_status', 1445),
        ('metrics_view', 1464),
        ('visualization_label', 1476),
        ('export_metrics_button', 1488),
        ('save_plot_button', 1491),
    ],
    'intellicrack/ui/dialogs/plugin_manager_dialog.py': [
        ('installed_list', 211),
        ('enable_btn', 217),
        ('disable_btn', 220),
        ('remove_btn', 223),
        ('configure_btn', 226),
        ('plugin_info', 241),
        ('repo_combo', 261),
        ('available_list', 275),
        ('install_btn', 281),
        ('preview_btn', 284),
        ('plugin_details', 299),
        ('file_path_edit', 317),
        ('auto_enable', 328),
        ('backup_existing', 331),
        ('progress_bar', 343),
        ('status_label', 347),
        ('plugin_name_edit', 367),
        ('plugin_type_combo', 370),
        ('author_edit', 380),
        ('test_file_edit', 397),
        ('test_output', 409),
        ('install_thread', 665),
    ],
    'intellicrack/ui/dialogs/report_manager_dialog.py': [
        ('search_edit', 215),
        ('type_filter', 219),
        ('date_filter', 224),
        ('reports_table', 239),
        ('report_preview', 252),
        ('view_btn', 262),
        ('edit_btn', 266),
        ('duplicate_btn', 270),
        ('delete_btn', 274),
        ('report_name_edit', 298),
        ('report_type_combo', 299),
        ('binary_path_edit', 302),
        ('browse_binary_btn', 303),
        ('include_screenshots', 310),
        ('include_detailed_logs', 311),
        ('include_recommendations', 312),
        ('include_executive_summary', 313),
        ('output_format_combo', 330),
        ('output_path_edit', 333),
        ('browse_output_btn', 334),
        ('open_after_generation', 341),
        ('generate_btn', 353),
        ('preview_btn', 356),
        ('progress_bar', 366),
        ('status_label', 371),
        ('template_list', 387),
        ('template_description', 410),
        ('use_template_btn', 421),
        ('edit_template_btn', 425),
        ('create_template_btn', 429),
        ('generation_thread', 720),
    ],
    'intellicrack/ui/dialogs/script_generator_dialog.py': [
        ('script_type_combo', 211),
        ('config_stack', 224),
        ('config_layout', 225),
        ('generate_btn', 234),
        ('bypass_config', 244),
        ('bypass_language', 249),
        ('bypass_methods', 255),
        ('method_patch', 258),
        ('method_loader', 260),
        ('method_hook', 261),
        ('method_memory', 262),
        ('method_registry', 263),
        ('bypass_output', 275),
        ('exploit_config', 283),
        ('exploit_type', 288),
        ('target_function', 300),
        ('payload_type', 306),
        ('exploit_advanced', 311),
        ('strategy_config', 319),
        ('strategy_type', 324),
        ('analysis_depth', 336),
        ('include_options', 342),
        ('include_recon', 345),
        ('include_analysis', 347),
        ('include_exploitation', 349),
        ('include_persistence', 351),
        ('script_tabs', 369),
        ('script_display', 372),
        ('highlighter', 377),
        ('doc_display', 382),
        ('template_display', 387),
        ('copy_btn', 396),
        ('save_btn', 399),
        ('test_btn', 402),
        ('status_label', 418),
        ('close_btn', 421),
    ],
    'intellicrack/ui/dialogs/similarity_search_dialog.py': [
        ('search_thread', 251),
    ],
    'intellicrack/ui/dialogs/system_utilities_dialog.py': [
        ('icon_file_edit', 250),
        ('icon_browse_btn', 253),
        ('icon_output_edit', 266),
        ('icon_output_browse_btn', 269),
        ('icon_format_combo', 278),
        ('icon_size_combo', 284),
        ('extract_icon_btn', 291),
        ('icon_preview', 300),
        ('sysinfo_refresh_btn', 320),
        ('sysinfo_export_btn', 323),
        ('sysinfo_display', 333),
        ('deps_check_btn', 352),
        ('deps_install_btn', 355),
        ('deps_table', 366),
        ('process_refresh_btn', 387),
        ('process_kill_btn', 390),
        ('process_filter', 396),
        ('process_table', 407),
        ('memory_total_label', 431),
        ('memory_used_label', 432),
        ('memory_free_label', 433),
        ('memory_percent_label', 434),
        ('opt_clear_cache', 451),
        ('opt_compress_memory', 454),
        ('opt_defrag_memory', 457),
        ('optimize_memory_btn', 466),
        ('memory_results', 472),
        ('progress_bar', 486),
        ('status_label', 493),
        ('close_btn', 496),
    ],
    'intellicrack/ui/widgets/hex_viewer.py': [
        ('open_btn', 151),
        ('save_btn', 161),
        ('search_btn', 173),
        ('perf_btn', 185),
        ('file_info_label', 197),
    ],
    'intellicrack/utils/windows_structures.py': [
        ('ContextFlags', 146),
        ('cb', 248),
    ],
}


def find_class_init(file_path: str, line_number: int) -> tuple:
    """Find the class name and __init__ method for a given attribute."""
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # Look backwards from the line to find the class definition
    class_name = None
    init_line = None
    init_indent = None

    for i in range(line_number - 1, -1, -1):
        line = lines[i]

        # Find class definition
        if line.strip().startswith('class ') and not class_name:
            match = re.match(r'^(\s*)class\s+(\w+)', line)
            if match:
                class_name = match.group(2)
                class_indent = len(match.group(1))

                # Now find __init__ method for this class
                for j in range(i + 1, len(lines)):
                    init_line_text = lines[j]
                    if re.match(rf'^{" " * (class_indent + 4)}def __init__\(', init_line_text):
                        init_line = j + 1
                        init_indent = class_indent + 4
                        break
                    # Stop if we hit another class at same or lower indentation
                    elif re.match(rf'^{" " * class_indent}class ', init_line_text):
                        break
                break

    return class_name, init_line, init_indent


def get_attributes_to_add(file_path: str, attributes: List[tuple]) -> Dict[str, Set[str]]:
    """Get attributes that need to be added to each class."""
    class_attributes = {}

    for attr_name, line_num in attributes:
        class_name, init_line, init_indent = find_class_init(
            file_path, line_num)

        if class_name and init_line:
            if class_name not in class_attributes:
                class_attributes[class_name] = set()
            class_attributes[class_name].add(attr_name)

    return class_attributes


def add_attributes_to_init(file_path: str, attributes: List[tuple]):
    """Add missing attributes to __init__ methods."""
    # Group attributes by class
    class_attributes = get_attributes_to_add(file_path, attributes)

    if not class_attributes:
        print(f"No classes found in {file_path}")
        return

    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # Process each class
    for class_name, attrs in class_attributes.items():
        # Find the class and its __init__ method
        for i, line in enumerate(lines):
            if re.match(rf'^\s*class\s+{class_name}\b', line):
                # Find __init__ method
                for j in range(i + 1, len(lines)):
                    if re.match(r'^\s+def __init__\(', lines[j]):
                        # Find where to insert (after super().__init__ or after self assignments)
                        insert_line = j + 1
                        indent = len(lines[j]) - len(lines[j].lstrip()) + 4

                        # Skip past docstring if present
                        if j + 1 < len(lines) and ('"""' in lines[j + 1] or "'''" in lines[j + 1]):
                            # Find end of docstring
                            quote = '"""' if '"""' in lines[j + 1] else "'''"
                            for k in range(j + 2, len(lines)):
                                if quote in lines[k]:
                                    insert_line = k + 1
                                    break

                        # Find a good place to insert (after existing self. assignments)
                        for k in range(insert_line, len(lines)):
                            line_content = lines[k].strip()
                            if not line_content.startswith('self.') and line_content and not line_content.startswith('#'):
                                break
                            insert_line = k + 1

                        # Check which attributes are already defined
                        already_defined = set()
                        for k in range(j, min(j + 100, len(lines))):
                            for attr in attrs:
                                if re.match(rf'^\s+self\.{attr}\s*=', lines[k]):
                                    already_defined.add(attr)

                        # Add missing attributes
                        attrs_to_add = attrs - already_defined
                        if attrs_to_add:
                            # Add a comment if not already there
                            new_lines = []

                            # Check if we need to add a blank line before
                            if insert_line > 0 and lines[insert_line - 1].strip():
                                new_lines.append('\n')

                            # Add comment
                            new_lines.append(
                                f'{" " * indent}# Initialize UI attributes\n')

                            # Add attributes
                            for attr in sorted(attrs_to_add):
                                new_lines.append(
                                    f'{" " * indent}self.{attr} = None\n')

                            # Insert the new lines
                            lines[insert_line:insert_line] = new_lines
                            print(
                                f"Added {len(attrs_to_add)} attributes to {class_name}.__init__ in {file_path}")

                        break
                break

    # Write the file back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)


def main():
    """Main function to fix all W0201 errors."""
    total_fixed = 0

    for file_path, attributes in W0201_ERRORS.items():
        full_path = os.path.join('/mnt/c/Intellicrack', file_path)

        if os.path.exists(full_path):
            print(f"\nProcessing {file_path}...")
            add_attributes_to_init(full_path, attributes)
            total_fixed += len(attributes)
        else:
            print(f"File not found: {full_path}")

    print(f"\nTotal W0201 errors processed: {total_fixed}")


if __name__ == '__main__':
    main()
