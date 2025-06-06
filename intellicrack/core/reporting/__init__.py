"""
Intellicrack Core Reporting Package

This package provides comprehensive reporting capabilities for the Intellicrack framework.
It includes tools for generating detailed analysis reports in various formats, with a focus
on professional PDF generation and customizable report templates.

Modules:
    - pdf_generator: Generate professional PDF reports with analysis results

Key Features:
    - PDF report generation
    - Customizable report templates
    - Charts and visualization support
    - Multi-format export capabilities
    - Automated report creation
"""

import logging

# Set up package logger
logger = logging.getLogger(__name__)

# Import reporting modules with error handling
try:
    from .pdf_generator import PDFReportGenerator, run_report_generation
except ImportError as e:
    logger.warning("Failed to import pdf_generator: %s", e)

# Define package exports
__all__ = [
    # From pdf_generator
    'PDFReportGenerator',
    'run_report_generation',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
