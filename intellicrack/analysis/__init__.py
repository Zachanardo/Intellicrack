"""Analysis package for binary analysis and workflow management.

This package provides comprehensive analysis capabilities including result
orchestration, protection workflows, and specialized handlers for different
analysis tasks.
"""

import logging

logger = logging.getLogger(__name__)

# Import core analysis modules
try:
    from .analysis_result_orchestrator import AnalysisResultOrchestrator

    logger.debug("Analysis result orchestrator loaded successfully")
    HAS_ORCHESTRATOR = True
except ImportError as e:
    logger.warning("Analysis result orchestrator not available: %s", e)
    AnalysisResultOrchestrator = None
    HAS_ORCHESTRATOR = False

try:
    from .protection_workflow import ProtectionAnalysisWorkflow as ProtectionWorkflow

    logger.debug("Protection workflow loaded successfully")
    HAS_PROTECTION_WORKFLOW = True
except ImportError as e:
    logger.warning("Protection workflow not available: %s", e)
    ProtectionWorkflow = None
    HAS_PROTECTION_WORKFLOW = False

# Import analysis handlers
_handlers = {}
_handler_modules = [
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


def get_available_capabilities():
    """Get list of available analysis capabilities."""
    capabilities = []
    if HAS_ORCHESTRATOR:
        capabilities.append("result_orchestration")
    if HAS_PROTECTION_WORKFLOW:
        capabilities.append("protection_workflow")
    capabilities.extend(_handlers.keys())
    return capabilities


def is_capability_available(capability_name):
    """Check if a specific analysis capability is available."""
    return capability_name in get_available_capabilities()


__all__ = [
    "get_available_capabilities",
    "is_capability_available",
    "HAS_ORCHESTRATOR",
    "HAS_PROTECTION_WORKFLOW",
]

if AnalysisResultOrchestrator:
    __all__.append("AnalysisResultOrchestrator")
if ProtectionWorkflow:
    __all__.append("ProtectionWorkflow")
