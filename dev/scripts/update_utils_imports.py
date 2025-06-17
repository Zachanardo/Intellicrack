#!/usr/bin/env python3
"""
Update all imports from intellicrack.utils to new structure

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import re
from pathlib import Path

# Map of moved files to their new locations
MOVED_FILES = {
    # Analysis
    'analysis_exporter': 'analysis.analysis_exporter',
    'analysis_stats': 'analysis.analysis_stats',
    'security_analysis': 'analysis.security_analysis',
    'severity_levels': 'analysis.severity_levels',
    
    # Binary
    'binary_io': 'binary.binary_io',
    'binary_utils': 'binary.binary_utils',
    'hex_utils': 'binary.hex_utils',
    'pe_analysis_common': 'binary.pe_analysis_common',
    'pe_common': 'binary.pe_common',
    
    # System
    'system_utils': 'system.system_utils',
    'process_common': 'system.process_common',
    'process_helpers': 'system.process_helpers',
    'process_utils': 'system.process_utils',
    'subprocess_utils': 'system.subprocess_utils',
    'driver_utils': 'system.driver_utils',
    'windows_common': 'system.windows_common',
    'windows_structures': 'system.windows_structures',
    'snapshot_common': 'system.snapshot_common',
    'snapshot_utils': 'system.snapshot_utils',
    
    # Protection
    'protection_detection': 'protection.protection_detection',
    'protection_helpers': 'protection.protection_helpers',
    'protection_utils': 'protection.protection_utils',
    'certificate_utils': 'protection.certificate_utils',
    'certificate_common': 'protection.certificate_common',
    
    # Patching
    'patch_generator': 'patching.patch_generator',
    'patch_utils': 'patching.patch_utils',
    'patch_verification': 'patching.patch_verification',
    
    # UI
    'ui_common': 'ui.ui_common',
    'ui_utils': 'ui.ui_utils',
    'ui_helpers': 'ui.ui_helpers',
    'ui_button_common': 'ui.ui_button_common',
    'ui_setup_functions': 'ui.ui_setup_functions',
    
    # Tools
    'tool_wrappers': 'tools.tool_wrappers',
    'ghidra_common': 'tools.ghidra_common',
    'ghidra_utils': 'tools.ghidra_utils',
    'ghidra_script_manager': 'tools.ghidra_script_manager',
    'radare2_utils': 'tools.radare2_utils',
    'pcapy_compat': 'tools.pcapy_compat',
    
    # Exploitation
    'exploit_common': 'exploitation.exploit_common',
    'exploitation': 'exploitation.exploitation',
    'payload_result_handler': 'exploitation.payload_result_handler',
    
    # Reporting
    'report_common': 'reporting.report_common',
    'report_generator': 'reporting.report_generator',
    'html_templates': 'reporting.html_templates',
    
    # Core
    'misc_utils': 'core.misc_utils',
    'string_utils': 'core.string_utils',
    'exception_utils': 'core.exception_utils',
    'internal_helpers': 'core.internal_helpers',
    'path_discovery': 'core.path_discovery',
    'plugin_paths': 'core.plugin_paths',
    'import_checks': 'core.import_checks',
    'import_patterns': 'core.import_patterns',
    
    # Runtime
    'runner_functions': 'runtime.runner_functions',
    'additional_runners': 'runtime.additional_runners',
    'performance_optimizer': 'runtime.performance_optimizer',
    'distributed_processing': 'runtime.distributed_processing',
    
    # Templates
    'license_response_templates': 'templates.license_response_templates',
    'network_api_common': 'templates.network_api_common',
}

def update_imports_in_file(file_path):
    """Update imports in a single file"""
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        changes_made = False
        
        # Update from intellicrack.utils.X import statements
        for old_module, new_path in MOVED_FILES.items():
            # Pattern 1: from intellicrack.utils.module import ...
            pattern1 = rf'from\s+intellicrack\.utils\.{re.escape(old_module)}\s+import'
            replacement1 = f'from intellicrack.utils.{new_path} import'
            content, n1 = re.subn(pattern1, replacement1, content)
            
            # Pattern 2: import intellicrack.utils.module
            pattern2 = rf'import\s+intellicrack\.utils\.{re.escape(old_module)}'
            replacement2 = f'import intellicrack.utils.{new_path}'
            content, n2 = re.subn(pattern2, replacement2, content)
            
            if n1 + n2 > 0:
                changes_made = True
        
        # Also handle relative imports within utils directory
        if '/intellicrack/utils/' in file_path:
            for old_module, new_path in MOVED_FILES.items():
                # Pattern: from .module import ...
                pattern = rf'from\s+\.{re.escape(old_module)}\s+import'
                replacement = f'from .{new_path} import'
                content, n = re.subn(pattern, replacement, content)
                if n > 0:
                    changes_made = True
        
        if changes_made:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
            
    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        return False
    
    return False

def update_all_imports(root_dir='/mnt/c/Intellicrack'):
    """Update imports in all Python files"""
    
    updated_files = []
    
    for root, dirs, files in os.walk(root_dir):
        # Skip directories we don't want to update
        if any(skip in root for skip in ['__pycache__', 'venv', 'node_modules', '.git', 'tools/ghidra', 'tools/radare2']):
            continue
            
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                if update_imports_in_file(file_path):
                    updated_files.append(file_path)
    
    return updated_files

def main():
    print("Updating imports throughout the codebase...")
    
    updated = update_all_imports()
    
    print(f"\nUpdated {len(updated)} files:")
    for file in sorted(updated):
        print(f"  {file}")

if __name__ == '__main__':
    main()