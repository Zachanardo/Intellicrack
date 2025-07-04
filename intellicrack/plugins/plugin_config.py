"""
Plugin System Configuration and Exports

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

# Shared plugin system function exports
PLUGIN_SYSTEM_EXPORTS = [
    'load_plugins',
    'run_plugin',
    'run_custom_plugin',
    'run_frida_plugin_from_file',
    'run_ghidra_plugin_from_file',
    'create_sample_plugins',
    'run_plugin_in_sandbox',
    'run_plugin_remotely',
]
