"""Machine Learning components for Intellicrack.

This package provides machine learning capabilities for pattern recognition,
behavior analysis, and intelligent security research automation.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import logging

logger = logging.getLogger(__name__)

# Attempt to import available ML modules
try:
    from .pattern_evolution_tracker import PatternEvolutionTracker

    logger.debug("Pattern evolution tracker loaded successfully")
    HAS_PATTERN_TRACKER = True
except ImportError as e:
    logger.warning("Pattern evolution tracker not available: %s", e)
    PatternEvolutionTracker = None
    HAS_PATTERN_TRACKER = False


def get_ml_capabilities() -> list[str]:
    """Get list of available ML capabilities.

    Returns:
        List of available ML capabilities.

    """
    capabilities = []
    if HAS_PATTERN_TRACKER:
        capabilities.append("pattern_evolution")
    return capabilities


__all__ = []
if PatternEvolutionTracker:
    __all__.append("PatternEvolutionTracker")

__all__.extend(["get_ml_capabilities", "HAS_PATTERN_TRACKER"])
