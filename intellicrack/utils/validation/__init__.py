"""Validation utilities for import checking and dependency verification.

This package provides validation capabilities to ensure proper imports,
dependency availability, and configuration validation throughout Intellicrack.

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
from collections.abc import Callable

logger: logging.Logger = logging.getLogger(__name__)

# Import validation modules
ImportValidator: type | None
validate_imports: Callable[..., bool] | None

try:
    from .import_validator import ImportValidator, validate_imports

    logger.debug("Import validator loaded successfully")
    HAS_IMPORT_VALIDATOR: bool = True
except ImportError as e:
    logger.warning("Import validator not available: %s", e)
    ImportValidator = None
    validate_imports = None
    HAS_IMPORT_VALIDATOR = False


def get_validation_capabilities() -> list[str]:
    """Get list of available validation capabilities.

    Returns:
        list[str]: List of available validation capability names.

    """
    capabilities: list[str] = []
    if HAS_IMPORT_VALIDATOR:
        capabilities.append("import_validation")
    return capabilities


def is_validation_available(validation_type: str) -> bool:
    """Check if a specific validation capability is available.

    Args:
        validation_type: Type of validation to check.

    Returns:
        True if validation is available, False otherwise.

    """
    return validation_type in get_validation_capabilities()


__all__ = [
    "get_validation_capabilities",
    "is_validation_available",
    "HAS_IMPORT_VALIDATOR",
]

if ImportValidator:
    __all__.extend(["ImportValidator", "validate_imports"])
