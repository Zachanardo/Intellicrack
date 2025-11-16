"""Analysis handlers for specialized analysis tasks.

This package provides specialized handlers for different types of analysis
tasks including LLM integration, report generation, and script generation.

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

logger = logging.getLogger(__name__)

# Import available handlers
_available_handlers = {}

# Handler modules with descriptions
_handler_modules = [
    ("llm_handler", "Large Language Model integration handler"),
    ("report_generation_handler", "Analysis report generation handler"),
    ("script_generation_handler", "Dynamic script generation handler"),
]

# Load handlers with error tolerance
for module_name, description in _handler_modules:
    try:
        module = __import__(f"{__name__}.{module_name}", fromlist=[module_name])
        _available_handlers[module_name] = module
        logger.debug("Loaded analysis handler: %s (%s)", module_name, description)
    except ImportError as e:
        logger.debug("Analysis handler not available: %s (%s) - %s", module_name, description, e)
    except Exception as e:
        logger.warning("Error loading analysis handler %s: %s", module_name, e)


def get_available_handlers():
    """Get list of successfully loaded analysis handlers."""
    return list(_available_handlers.keys())


def get_handler(handler_name: str):
    """Get a specific handler module if available.

    Args:
        handler_name (str): Name of the handler module

    Returns:
        module: The handler module, or None if not available

    """
    return _available_handlers.get(handler_name)


def is_handler_available(handler_name: str):
    """Check if a specific handler is available.

    Args:
        handler_name (str): Name of the handler to check

    Returns:
        bool: True if handler is available, False otherwise

    """
    return handler_name in _available_handlers


# Get all handler names and convert to list of strings
_handler_names: list[str] = [str(name) for name in _available_handlers]
__all__: list[str] = ["get_available_handlers", "get_handler", "is_handler_available"] + _handler_names  # noqa: RUF005
