"""Core analysis package for Intellicrack.

This package contains the core analysis components including binary analysis,
symbolic execution, memory forensics, and multi-format analysis capabilities.

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

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from intellicrack.utils.logger import logger


if TYPE_CHECKING:
    from types import ModuleType

    from intellicrack.core.analysis.cfg_explorer import CFGExplorer
    from intellicrack.core.analysis.control_flow_deobfuscation import (
        BasicBlock,
        ControlFlowDeobfuscator,
        DeobfuscationResult,
        DispatcherInfo,
    )
    from intellicrack.core.analysis.incremental_manager import IncrementalAnalysisManager
    from intellicrack.core.analysis.polymorphic_analyzer import (
        BehaviorPattern,
        CodeBlock,
        InstructionNode,
        MutationType,
        PolymorphicAnalysis,
        PolymorphicAnalyzer,
        PolymorphicEngine,
    )
    from intellicrack.core.analysis.securom_analyzer import (
        ActivationMechanism,
        ProductActivationKey,
        SecuROMAnalysis,
        SecuROMAnalyzer,
        TriggerPoint,
    )
    from intellicrack.core.analysis.similarity_searcher import SimilaritySearcher
    from intellicrack.core.analysis.stalker_manager import APICallEvent, CoverageEntry, StalkerSession, StalkerStats, TraceEvent
    from intellicrack.core.analysis.starforce_analyzer import StarForceAnalysis, StarForceAnalyzer


logger.debug("Core analysis module loaded")

"""
Advanced binary analysis engines for Intellicrack.

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

calculate_entropy: Callable[[bytes], float] | None
analyze_binary_internal: Callable[[str, list[str] | None], list[str]] | None
enhanced_deep_license_analysis: Callable[[str], dict[str, Any]] | None
detect_packing: Callable[[str], dict[str, Any]] | None

try:
    from .core_analysis import (  # type: ignore[attr-defined]
        analyze_binary_internal,
        calculate_entropy,
        detect_packing,
        enhanced_deep_license_analysis,
    )
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    calculate_entropy = None
    analyze_binary_internal = None
    enhanced_deep_license_analysis = None
    detect_packing = None

VulnerabilityEngine: type[Any] | None

try:
    from .vulnerability_engine import VulnerabilityEngine
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    VulnerabilityEngine = None

DynamicAnalyzer: type[Any] | None
AdvancedDynamicAnalyzer: type[Any] | None

try:
    from .dynamic_analyzer import AdvancedDynamicAnalyzer, DynamicAnalyzer
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    DynamicAnalyzer = None
    AdvancedDynamicAnalyzer = None

SymbolicExecutionEngine: type[Any] | None

try:
    from .symbolic_executor import SymbolicExecutionEngine
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    SymbolicExecutionEngine = None

ConcolicExecutionEngine: type[Any] | None

try:
    from .concolic_executor import ConcolicExecutionEngine
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    ConcolicExecutionEngine = None

TaintAnalysisEngine: type[Any] | None
run_taint_analysis: Callable[[object], None] | None

try:
    from .taint_analyzer import TaintAnalysisEngine, run_taint_analysis
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    TaintAnalysisEngine = None
    run_taint_analysis = None

ROPChainGenerator: type[Any] | None

try:
    from .rop_generator import ROPChainGenerator
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    ROPChainGenerator = None

MultiFormatBinaryAnalyzer: type[Any] | None

try:
    from .multi_format_analyzer import MultiFormatBinaryAnalyzer
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    MultiFormatBinaryAnalyzer = None

_lazy_imports: dict[str, tuple[str, list[str]]] = {
    "CFGExplorer": (".cfg_explorer", ["CFGExplorer"]),
    "IncrementalAnalysisManager": (".incremental_manager", ["IncrementalAnalysisManager"]),
    "SimilaritySearcher": (".similarity_searcher", ["SimilaritySearcher"]),
    "ControlFlowDeobfuscator": (".control_flow_deobfuscation", ["ControlFlowDeobfuscator"]),
    "DeobfuscationResult": (".control_flow_deobfuscation", ["DeobfuscationResult"]),
    "DispatcherInfo": (".control_flow_deobfuscation", ["DispatcherInfo"]),
    "BasicBlock": (".control_flow_deobfuscation", ["BasicBlock"]),
    "StalkerSession": (".stalker_manager", ["StalkerSession"]),
    "StalkerStats": (".stalker_manager", ["StalkerStats"]),
    "TraceEvent": (".stalker_manager", ["TraceEvent"]),
    "APICallEvent": (".stalker_manager", ["APICallEvent"]),
    "CoverageEntry": (".stalker_manager", ["CoverageEntry"]),
    "StarForceAnalyzer": (".starforce_analyzer", ["StarForceAnalyzer"]),
    "StarForceAnalysis": (".starforce_analyzer", ["StarForceAnalysis"]),
    "SecuROMAnalyzer": (".securom_analyzer", ["SecuROMAnalyzer"]),
    "SecuROMAnalysis": (".securom_analyzer", ["SecuROMAnalysis"]),
    "ActivationMechanism": (".securom_analyzer", ["ActivationMechanism"]),
    "TriggerPoint": (".securom_analyzer", ["TriggerPoint"]),
    "ProductActivationKey": (".securom_analyzer", ["ProductActivationKey"]),
    "PolymorphicAnalyzer": (".polymorphic_analyzer", ["PolymorphicAnalyzer"]),
    "PolymorphicAnalysis": (".polymorphic_analyzer", ["PolymorphicAnalysis"]),
    "MutationType": (".polymorphic_analyzer", ["MutationType"]),
    "PolymorphicEngine": (".polymorphic_analyzer", ["PolymorphicEngine"]),
    "BehaviorPattern": (".polymorphic_analyzer", ["BehaviorPattern"]),
    "InstructionNode": (".polymorphic_analyzer", ["InstructionNode"]),
    "CodeBlock": (".polymorphic_analyzer", ["CodeBlock"]),
}

_lazy_loaded: dict[str, Any] = {}


def __getattr__(name: str) -> object:
    """Lazy load heavy analysis modules on demand."""
    if name in _lazy_loaded:
        return _lazy_loaded[name]

    if name in _lazy_imports:
        module_path, attr_names = _lazy_imports[name]
        try:
            module: ModuleType
            if module_path == ".cfg_explorer":
                from . import cfg_explorer

                module = cfg_explorer
            elif module_path == ".incremental_manager":
                from . import incremental_manager

                module = incremental_manager
            elif module_path == ".similarity_searcher":
                from . import similarity_searcher

                module = similarity_searcher
            elif module_path == ".control_flow_deobfuscation":
                from . import control_flow_deobfuscation

                module = control_flow_deobfuscation
            elif module_path == ".stalker_manager":
                from . import stalker_manager

                module = stalker_manager
            elif module_path == ".starforce_analyzer":
                from . import starforce_analyzer

                module = starforce_analyzer
            elif module_path == ".securom_analyzer":
                from . import securom_analyzer

                module = securom_analyzer
            elif module_path == ".polymorphic_analyzer":
                from . import polymorphic_analyzer

                module = polymorphic_analyzer
            else:
                msg = f"Unknown module path: {module_path}"
                raise ImportError(msg)

            for attr_name in attr_names:
                if hasattr(module, attr_name):
                    _lazy_loaded[attr_name] = getattr(module, attr_name)
                else:
                    logger.error(f"Attribute {attr_name} not found in {module_path}")
                    _lazy_loaded[attr_name] = None

            if name in _lazy_loaded:
                return _lazy_loaded[name]
        except ImportError as e:
            logger.error("Import error in __getattr__ for %s: %s", name, e)
            _lazy_loaded[name] = None
            return None

    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


def __dir__() -> list[str]:
    """Return list of available attributes including lazy imports."""
    base_attrs = list(globals().keys())
    lazy_attrs = list(_lazy_imports.keys())
    return sorted(set(base_attrs + lazy_attrs))


__all__ = [
    "APICallEvent",
    "ActivationMechanism",
    "AdvancedDynamicAnalyzer",
    "BasicBlock",
    "BehaviorPattern",
    "CFGExplorer",
    "CodeBlock",
    "ConcolicExecutionEngine",
    "ControlFlowDeobfuscator",
    "CoverageEntry",
    "DeobfuscationResult",
    "DispatcherInfo",
    "DynamicAnalyzer",
    "IncrementalAnalysisManager",
    "InstructionNode",
    "MultiFormatBinaryAnalyzer",
    "MutationType",
    "PolymorphicAnalysis",
    "PolymorphicAnalyzer",
    "PolymorphicEngine",
    "ProductActivationKey",
    "ROPChainGenerator",
    "SecuROMAnalysis",
    "SecuROMAnalyzer",
    "SimilaritySearcher",
    "StalkerSession",
    "StalkerStats",
    "StarForceAnalysis",
    "StarForceAnalyzer",
    "SymbolicExecutionEngine",
    "TaintAnalysisEngine",
    "TraceEvent",
    "TriggerPoint",
    "VulnerabilityEngine",
    "analyze_binary_internal",
    "calculate_entropy",
    "detect_packing",
    "enhanced_deep_license_analysis",
    "run_taint_analysis",
]

__all__ = [item for item in __all__ if item in _lazy_imports or locals().get(item) is not None]
