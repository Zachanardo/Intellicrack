"""
Core analysis and processing modules for Intellicrack.

This package contains the core functionality for binary analysis, including:
- Static and dynamic analysis engines
- Vulnerability detection and exploitation
- Network traffic analysis
- Patching and payload generation
- Protection bypass techniques
- Reporting and visualization

Modules:
    analysis: Advanced binary analysis engines
    network: Network traffic analysis and protocol handling
    patching: Automated patching and payload generation
    processing: GPU acceleration and distributed computing
    protection_bypass: Hardware and software protection bypass
    reporting: Report generation and visualization
"""

from . import analysis, network, patching, processing, protection_bypass, reporting

__all__ = [
    'analysis',
    'network',
    'patching',
    'processing',
    'protection_bypass',
    'reporting'
]
