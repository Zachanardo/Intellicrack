"""
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

# Import all functions from the templates network_api_common module
from .templates.network_api_common import (
    analyze_network_apis,
    detect_network_apis,
    get_network_api_categories,
    get_scapy_layers,
    process_network_api_results,
    summarize_network_capabilities,
)

__all__ = ['analyze_network_apis', 'process_network_api_results', 'get_scapy_layers',
           'detect_network_apis', 'get_network_api_categories', 'summarize_network_capabilities']
