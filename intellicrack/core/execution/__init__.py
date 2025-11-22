"""Execution module initialization for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)

try:
    from .script_execution_manager import ScriptExecutionManager

    logger.debug("ScriptExecutionManager imported successfully")
except ImportError as e:
    logger.error(f"Execution manager import failed: {e}")

__all__ = ["ScriptExecutionManager"]

# Filter out items that are not available
__all__ = [item for item in __all__ if item in locals()]
