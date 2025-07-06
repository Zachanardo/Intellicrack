"""
Analysis utility modules for Intellicrack.

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

# Import analysis utilities
from .analysis_exporter import AnalysisExporter
from .binary_analysis import (
    analyze_binary, analyze_binary_optimized, analyze_pe, analyze_elf, analyze_macho,
    analyze_patterns, analyze_traffic, identify_binary_format, extract_binary_info,
    extract_binary_features, extract_patterns_from_binary, scan_binary,
    get_quick_disassembly, disassemble_with_objdump
)
from .entropy_utils import (
    calculate_entropy, calculate_byte_entropy, calculate_string_entropy,
    safe_entropy_calculation, calculate_frequency_distribution, is_high_entropy,
    analyze_entropy_sections
)
from .pattern_search import (
    find_all_pattern_occurrences, search_patterns_in_binary,
    find_function_prologues, find_license_patterns
)

__all__ = ['binary_analysis', 'entropy_utils', 'pattern_search', 'analysis_exporter']
