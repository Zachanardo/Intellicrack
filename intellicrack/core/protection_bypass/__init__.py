"""
Intellicrack Core Protection Bypass Package

This package provides security research tools for analyzing and understanding various
software protection mechanisms. It includes modules for studying TPM-based protections
and virtualization-based security measures.

Modules:
    - tpm_bypass: Research tools for TPM protection analysis
    - vm_bypass: Virtual machine detection and analysis utilities

Key Features:
    - Protection mechanism analysis
    - Security research capabilities
    - Educational tools for understanding protections
    - Virtualization detection techniques

Note: This package is intended for security research and educational purposes only.
"""

import logging

# Set up package logger
logger = logging.getLogger(__name__)

# Import protection bypass modules with error handling
try:
    from .tpm_bypass import *
except ImportError as e:
    logger.warning(f"Failed to import tpm_bypass: {e}")

try:
    from .vm_bypass import *
except ImportError as e:
    logger.warning(f"Failed to import vm_bypass: {e}")

try:
    from .dongle_emulator import *
except ImportError as e:
    logger.warning(f"Failed to import dongle_emulator: {e}")

# Define package exports
__all__ = [
    # From tpm_bypass
    'TPMAnalyzer',
    'analyze_tpm_protection',
    'detect_tpm_usage',
    'tpm_research_tools',
    
    # From vm_bypass
    'VMDetector',
    'VirtualizationAnalyzer',
    'detect_virtualization',
    'analyze_vm_protection',
    
    # From dongle_emulator
    'HardwareDongleEmulator',
    'activate_hardware_dongle_emulation',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
