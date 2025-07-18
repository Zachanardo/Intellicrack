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

"""Fix W0613 unused-argument errors by adding pylint disable comments."""

import os
import re
import sys

# Files to fix based on the error report
FILES_TO_FIX = [
    ('intellicrack/core/analysis/dynamic_analyzer.py', [
        (460, 'def on_message(self, message, data):', 'data'),
        (742, 'def _report_result(self, data):', 'data'),
    ]),
    ('intellicrack/core/analysis/multi_format_analyzer.py', [
        (445, 'def _safe_get_segments(self, binary_path):', 'binary_path'),
    ]),
    ('intellicrack/core/analysis/vulnerability_engine.py', [
        (84, 'def _check_owasp_top10(self, binary_path, analysis_data):', 'binary_path'),
        (197, 'def _check_injection_vulns(self, binary_path, analysis_data):', 'binary_path'),
        (239, 'def _find_dangerous_patterns(self, pe, binary_data):', 'pe'),
        (293, 'def _find_unsafe_memory_operations(self, pe, binary_data):', 'pe'),
    ]),
    ('intellicrack/core/network/cloud_license_hooker.py', [
        (359, 'def _generate_flexnet_response(self, request):', 'request'),
        (391, 'def _generate_rlm_response(self, service, request):',
         ['service', 'request']),
        (601, 'def _generate_third_party_response(self, request):', 'request'),
        (796, 'def _handle_api_request(self, api_name, params):', 'api_name'),
        (822, 'def handle_custom_request(self, request_type, params):', 'params'),
    ]),
    ('intellicrack/core/network/license_server_emulator.py', [
        (381, 'def POST(self, request_data):', 'request_data'),
    ]),
    ('intellicrack/core/network/traffic_analyzer.py', [
        (445, 'def _signal_handler(self, sig, frame):', ['sig', 'frame']),
    ]),
    ('intellicrack/core/patching/payload_generator.py', [
        (317, 'def generate_auto_patch_script(target_binary, patches, **kwargs):', 'kwargs'),
    ]),
    ('intellicrack/core/processing/distributed_manager.py', [
        (618, 'def process_chunk_dask(binary_path, chunk_start, chunk_size, analysis_config):', 'chunk_size'),
        (674, 'def process_chunk_ray(binary_path, chunk_start, chunk_size, analysis_config):', 'chunk_size'),
    ]),
    ('intellicrack/core/processing/qemu_emulator.py', [
        (359, 'def emulate_with_instrumentation(self, target_path, timeout=60):', 'timeout'),
        (539, 'def _diff_memory(self, snap1, snap2):', ['snap1', 'snap2']),
        (549, 'def _diff_registers(self, snap1, snap2):', ['snap1', 'snap2']),
        (559, 'def _diff_files(self, snap1, snap2):', ['snap1', 'snap2']),
        (568, 'def _diff_network(self, snap1, snap2):', ['snap1', 'snap2']),
    ]),
    ('intellicrack/core/processing/qiling_emulator.py', [
        (197, 'def _get_emulation_info(ql):', 'ql'),
        (214, 'def setup_qiling_emulation(binary_path, rootfs=None, ostype=None, archtype=None, timeout=60):', 'timeout'),
    ]),
    ('intellicrack/core/protection_bypass/tpm_bypass.py', [
        (463, 'def inject_bypass(self, process_name):', 'process_name'),
    ]),
    ('intellicrack/core/reporting/pdf_generator.py', [
        (556, 'def generate_combined_report(self, report_type="all"):', 'report_type'),
    ]),
    ('intellicrack/hexview/advanced_search.py', [
        (348, 'def _validate_input(self, search_type, value):', 'search_type'),
    ]),
    ('intellicrack/hexview/ai_bridge.py', [
        (907, 'def _parse_analysis_response(self, response, binary_data):', 'binary_data'),
        (949, 'def _parse_pattern_response(self, response, binary_data):', 'binary_data'),
        (994, 'def _parse_edit_response(self, response, binary_data):', 'binary_data'),
        (1022, 'def _parse_explanation_response(self, response, binary_data):', 'binary_data'),
        (1050, 'def _parse_query_response(self, response, query):', 'query'),
        (1133, 'def analyze_pattern(self, pattern_data, known_patterns=None):',
         'known_patterns'),
    ]),
    ('intellicrack/hexview/hex_commands.py', [
        (78, 'def __eq__(self, other):', 'other'),
    ]),
    ('intellicrack/hexview/hex_renderer.py', [
        (92, 'def setup_display(self, start_offset=0, highlight_ranges=None):',
         'highlight_ranges'),
        (387, 'def _format_offset(self, offset, bytes_per_row=16):', 'bytes_per_row'),
    ]),
    ('intellicrack/hexview/hex_widget.py', [
        (1612, 'def handle_navigation_key(self, key, modifiers):', 'modifiers'),
    ]),
    ('intellicrack/hexview/integration.py', [
        (27, 'def wrapper_ai_binary_analyze(*args, **kwargs):',
         ['args', 'kwargs']),
        (29, 'def wrapper_ai_binary_pattern_search(*args, **kwargs):',
         ['args', 'kwargs']),
        (31, 'def wrapper_ai_binary_edit_suggest(*args, **kwargs):',
         ['args', 'kwargs']),
    ]),
    ('intellicrack/plugins/plugin_system.py', [
        (340, 'def on_message(message, data):', 'data'),
    ]),
    ('intellicrack/plugins/__init__.py', [
        (102, 'def load_plugins(*args, **kwargs):', ['args', 'kwargs']),
        (103, 'def run_plugin(*args, **kwargs):', ['args', 'kwargs']),
        (104, 'def run_custom_plugin(*args, **kwargs):', ['args', 'kwargs']),
        (105, 'def run_frida_plugin_from_file(*args, **kwargs):',
         ['args', 'kwargs']),
        (106, 'def run_ghidra_plugin_from_file(*args, **kwargs):',
         ['args', 'kwargs']),
        (107, 'def create_sample_plugins(*args, **kwargs):',
         ['args', 'kwargs']),
        (108, 'def run_plugin_in_sandbox(*args, **kwargs):',
         ['args', 'kwargs']),
        (109, 'def run_plugin_remotely(*args, **kwargs):', ['args', 'kwargs']),
    ]),
    ('intellicrack/ui/common_imports.py', [
        (105, 'def pyqtSignal(*args, **kwargs):', ['args', 'kwargs']),
    ]),
    ('intellicrack/ui/main_app.py', [
        (104, 'def sizeof(x):', 'x'),
        (149, 'def dummy_signal(*args, **kwargs):', ['args', 'kwargs']),
        (148, 'def pyqtSignal(*args, **kwargs):', ['args', 'kwargs']),
        (224, 'def run_analysis(self, app, *args, **kwargs):',
         ['app', 'args', 'kwargs']),
        (233, 'def open_settings(self, app, *args, **kwargs):',
         ['app', 'args', 'kwargs']),
        (236, 'def open_ai_dialog(self, app, *args, **kwargs):',
         ['app', 'args', 'kwargs']),
    ]),
]

# pylint: disable=too-complex


def fix_file(filepath, fixes):
    """Fix unused argument warnings in a file."""
    try:
        # Read the file
        full_path = os.path.join('/mnt/c/Intellicrack', filepath)
        with open(full_path, 'r') as f:
            lines = f.readlines()

        # Apply fixes
        for line_num, signature, unused_args in fixes:
            if isinstance(unused_args, str):
                unused_args = [unused_args]

            # Adjust for 0-based indexing
            idx = line_num - 1
            if idx < len(lines):
                line = lines[idx]
                # Check if already has pylint disable
                if 'pylint: disable=' in line:
                    continue

                # Add pylint disable comment
                if line.rstrip().endswith(':'):
                    lines[idx] = line.rstrip() + \
                        '  # pylint: disable=unused-argument\n'
                else:
                    # For multi-line signatures, find the colon
                    for i in range(idx, min(idx + 5, len(lines))):
                        if lines[i].rstrip().endswith(':'):
                            lines[i] = lines[i].rstrip() + \
                                '  # pylint: disable=unused-argument\n'
                            break

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

    print("\nW0613 fixes applied!")


if __name__ == '__main__':
    main()
