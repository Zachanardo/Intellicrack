"""Analysis package for binary analysis and workflow management.

This package provides comprehensive analysis capabilities including result
orchestration, protection workflows, and specialized handlers for different
analysis tasks.

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

# Import core analysis modules
AnalysisResultOrchestrator: object | None = None
HAS_ORCHESTRATOR: bool = False
try:
    from .analysis_result_orchestrator import AnalysisResultOrchestrator

    logger.debug("Analysis result orchestrator loaded successfully")
    HAS_ORCHESTRATOR = True
except ImportError as e:
    logger.warning("Analysis result orchestrator not available: %s", e)
    AnalysisResultOrchestrator = None
    HAS_ORCHESTRATOR = False

ProtectionWorkflow: object | None = None
HAS_PROTECTION_WORKFLOW: bool = False
try:
    from .protection_workflow import ProtectionAnalysisWorkflow as ProtectionWorkflow

    logger.debug("Protection workflow loaded successfully")
    HAS_PROTECTION_WORKFLOW = True
except ImportError as e:
    logger.warning("Protection workflow not available: %s", e)
    ProtectionWorkflow = None
    HAS_PROTECTION_WORKFLOW = False

# Import from core.analysis for additional functionality
CORE_ANALYSIS_AVAILABLE: bool = False
try:
    from intellicrack.core.analysis import *

    CORE_ANALYSIS_AVAILABLE = True
    logger.debug("Core analysis modules loaded successfully")
except ImportError as e:
    logger.warning("Core analysis modules not available: %s", e)
    CORE_ANALYSIS_AVAILABLE = False

# Import analysis handlers
_handlers: dict[str, object] = {}
_handler_modules: list[tuple[str, str]] = [
    ("llm_handler", "LLM analysis handler"),
    ("report_generation_handler", "Report generation handler"),
    ("script_generation_handler", "Script generation handler"),
]

for module_name, description in _handler_modules:
    try:
        module = __import__(f"{__name__}.handlers.{module_name}", fromlist=[module_name])
        _handlers[module_name] = module
        logger.debug("Loaded analysis handler: %s (%s)", module_name, description)
    except ImportError as e:
        logger.debug("Analysis handler not available: %s (%s) - %s", module_name, description, e)
    except Exception as e:
        logger.warning("Error loading analysis handler %s: %s", module_name, e)


def get_available_capabilities() -> list[str]:
    """Get list of available analysis capabilities.

    Returns:
        list[str]: List of available capability names including result
            orchestration, protection workflows, and installed handlers.

    """
    capabilities = []
    if HAS_ORCHESTRATOR:
        capabilities.append("result_orchestration")
    if HAS_PROTECTION_WORKFLOW:
        capabilities.append("protection_workflow")
    capabilities.extend(_handlers.keys())
    return capabilities


def is_capability_available(capability_name: str) -> bool:
    """Check if a specific analysis capability is available.

    Args:
        capability_name: The name of the capability to check for availability.

    Returns:
        bool: True if the capability is available, False otherwise.

    """
    return capability_name in get_available_capabilities()


__all__ = [
    "CORE_ANALYSIS_AVAILABLE",
    "HAS_ORCHESTRATOR",
    "HAS_PROTECTION_WORKFLOW",
    "get_available_capabilities",
    "is_capability_available",
]

if AnalysisResultOrchestrator:
    __all__.append("AnalysisResultOrchestrator")
if ProtectionWorkflow:
    __all__.append("ProtectionWorkflow")

# Add core analysis modules to __all__ if available
if CORE_ANALYSIS_AVAILABLE:
    try:
        from intellicrack.core.analysis import __all__ as core_all

        __all__.extend(core_all)
    except (ImportError, AttributeError):
        pass
