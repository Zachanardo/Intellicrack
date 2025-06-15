"""
Core analysis and processing modules for Intellicrack. 

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


# Import all core modules
from . import analysis, network, patching, processing, protection_bypass, reporting

# Import new exploitation modules
try:
    from . import (
        c2_infrastructure,
        evasion,
        mitigation_bypass,
        payload_generation,
        post_exploitation,
        vulnerability_research,
    )
    EXPLOITATION_MODULES_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"Exploitation modules not available: {e}")
    payload_generation = None
    c2_infrastructure = None
    evasion = None
    mitigation_bypass = None
    post_exploitation = None
    vulnerability_research = None
    EXPLOITATION_MODULES_AVAILABLE = False

__all__ = [
    'analysis',
    'network',
    'patching',
    'processing',
    'protection_bypass',
    'reporting',
    'payload_generation',
    'c2_infrastructure',
    'evasion',
    'mitigation_bypass',
    'post_exploitation',
    'vulnerability_research',
    'EXPLOITATION_MODULES_AVAILABLE'
]
