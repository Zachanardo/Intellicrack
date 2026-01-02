"""Intellicrack Core Reporting Package.

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


logger: logging.Logger = logging.getLogger(__name__)

try:
    from .pdf_generator import PDFReportGenerator, run_report_generation
except ImportError as e:
    logger.warning("Failed to import pdf_generator: %s", e)

__all__: list[str] = [
    "PDFReportGenerator",
    "run_report_generation",
]

__all__ = [item for item in __all__ if item in locals()]

__version__: str = "0.1.0"
__author__: str = "Intellicrack Development Team"
