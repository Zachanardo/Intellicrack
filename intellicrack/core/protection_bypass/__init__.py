"""Intellicrack Core Protection Bypass Package

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging

# Set up package logger
logger = logging.getLogger(__name__)

# Import protection bypass modules with error handling
try:
    from .tpm_bypass import (
        TPMAnalyzer,
        TPMProtectionBypass,
        analyze_tpm_protection,
        bypass_tpm_protection,
        detect_tpm_usage,
        tpm_research_tools,
    )
except ImportError as e:
    logger.warning("Failed to import tpm_bypass: %s", e)

try:
    from .vm_bypass import (
        VirtualizationAnalyzer,
        VirtualizationDetectionBypass,
        VMDetector,
        analyze_vm_protection,
        bypass_vm_detection,
        detect_virtualization,
    )
except ImportError as e:
    logger.warning("Failed to import vm_bypass: %s", e)

try:
    from .dongle_emulator import HardwareDongleEmulator, activate_hardware_dongle_emulation
except ImportError as e:
    logger.warning("Failed to import dongle_emulator: %s", e)

# Define package exports
__all__ = [
    # From tpm_bypass
    "TPMAnalyzer",
    "TPMProtectionBypass",
    "analyze_tpm_protection",
    "bypass_tpm_protection",
    "detect_tpm_usage",
    "tpm_research_tools",
    # From vm_bypass
    "VMDetector",
    "VirtualizationAnalyzer",
    "VirtualizationDetectionBypass",
    "detect_virtualization",
    "analyze_vm_protection",
    "bypass_vm_detection",
    # From dongle_emulator
    "HardwareDongleEmulator",
    "activate_hardware_dongle_emulation",
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
