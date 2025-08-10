"""Core analysis package for Intellicrack.

This package contains the core analysis components including binary analysis,
symbolic execution, memory forensics, and multi-format analysis capabilities.
"""

from intellicrack.logger import logger

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


# Import core analysis functions
try:
    from .core_analysis import (
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

try:
    from .vulnerability_engine import VulnerabilityEngine
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    VulnerabilityEngine = None

try:
    from .dynamic_analyzer import AdvancedDynamicAnalyzer, DynamicAnalyzer
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    DynamicAnalyzer = None
    AdvancedDynamicAnalyzer = None

try:
    from .symbolic_executor import SymbolicExecutionEngine
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    SymbolicExecutionEngine = None

try:
    from .concolic_executor import ConcolicExecutionEngine
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    ConcolicExecutionEngine = None

try:
    from .taint_analyzer import TaintAnalysisEngine, run_taint_analysis
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    TaintAnalysisEngine = None
    run_taint_analysis = None

try:
    from .rop_generator import ROPChainGenerator
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    ROPChainGenerator = None

try:
    from .multi_format_analyzer import MultiFormatBinaryAnalyzer
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    MultiFormatBinaryAnalyzer = None

try:
    from .cfg_explorer import CFGExplorer
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    CFGExplorer = None

try:
    from .incremental_manager import IncrementalAnalysisManager
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    IncrementalAnalysisManager = None

try:
    from .similarity_searcher import SimilaritySearcher
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    SimilaritySearcher = None

__all__ = [
    # Core analysis functions
    "calculate_entropy",
    "analyze_binary_internal",
    "enhanced_deep_license_analysis",
    "detect_packing",
    # Analysis engines
    "VulnerabilityEngine",
    "DynamicAnalyzer",
    "AdvancedDynamicAnalyzer",
    "SymbolicExecutionEngine",
    "ConcolicExecutionEngine",
    "TaintAnalysisEngine",
    "run_taint_analysis",
    "ROPChainGenerator",
    "MultiFormatBinaryAnalyzer",
    "CFGExplorer",
    "IncrementalAnalysisManager",
    "SimilaritySearcher",
]
