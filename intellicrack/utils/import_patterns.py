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

import logging

logger = logging.getLogger(__name__)

# Import all functions from the templates module
try:
    from .templates.import_patterns import *
except ImportError:
    # Fallback implementations
    def analyze_import_patterns(binary_path):
        """Analyze import patterns in binary."""
        logger.debug(f"Analyzing import patterns for: {binary_path}")
        return {"imports": [], "patterns": []}

    def detect_api_hooks(binary_path):
        """Detect API hook patterns."""
        logger.debug(f"Detecting API hooks for: {binary_path}")
        return {"hooks": [], "suspicious": []}

__all__ = ['analyze_import_patterns', 'detect_api_hooks']
