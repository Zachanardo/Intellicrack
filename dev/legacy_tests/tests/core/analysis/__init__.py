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
Analysis module tests for Intellicrack.

This package contains tests for all analysis engines including:
- Vulnerability detection
- Symbolic execution
- Taint analysis
- Control flow graph analysis
- ROP chain generation
- Binary similarity search
- Dynamic analysis
- Multi-format analysis
"""

__all__ = [
    'test_vulnerability_engine',
    'test_symbolic_executor',
    'test_taint_analyzer',
    'test_cfg_explorer',
    'test_rop_generator',
    'test_similarity_searcher',
    'test_dynamic_analyzer',
    'test_multi_format_analyzer',
    'test_concolic_executor',
    'test_incremental_manager'
]
