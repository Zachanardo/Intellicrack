"""
Tool wrappers - wrapper module to redirect to tools/tool_wrappers.py

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

# Import all functions from the tools/tool_wrappers module
try:
    from .tools.tool_wrappers import (
        log_message,
        wrapper_find_file,
        wrapper_load_binary,
        wrapper_list_relevant_files,
        wrapper_read_file_chunk,
        wrapper_get_file_metadata,
        wrapper_run_static_analysis,
        wrapper_deep_license_analysis,
        wrapper_detect_protections,
        wrapper_disassemble_address,
        wrapper_get_cfg,
        wrapper_launch_target,
        wrapper_attach_target,
        wrapper_run_frida_script,
        wrapper_detach,
        wrapper_propose_patch,
        wrapper_get_proposed_patches,
        wrapper_apply_confirmed_patch,
        wrapper_generate_launcher_script,
        dispatch_tool,
        run_external_tool,
        wrapper_deep_runtime_monitoring,
        run_ghidra_headless
    )
except ImportError:
    # Fallback if import fails
    def wrapper_run_frida_script(app_instance, parameters):
        """Fallback wrapper for Frida script execution."""
        logger = __import__('logging').getLogger(__name__)
        logger.debug(f"Frida wrapper fallback called with app_instance: {app_instance is not None}, parameters: {parameters}")
        return {"success": False, "error": "Frida wrapper not available"}
