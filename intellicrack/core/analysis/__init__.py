"""
Advanced binary analysis engines for Intellicrack.

This package provides sophisticated analysis capabilities including:
- Core analysis functions (entropy, packing detection, deep analysis)
- Static vulnerability detection
- Dynamic runtime analysis
- Control flow graph exploration
- Symbolic and concolic execution
- Multi-format binary analysis
- Taint analysis and data flow tracking
- ROP chain generation
- Binary similarity search

Modules:
    core_analysis: Core analysis functions (entropy, packing, deep analysis)
    vulnerability_engine: Core vulnerability detection engine
    dynamic_analyzer: Runtime analysis and instrumentation
    symbolic_executor: Symbolic execution for path exploration
    concolic_executor: Concolic execution combining concrete and symbolic
    taint_analyzer: Data flow and taint analysis
    rop_generator: ROP chain generation and analysis
    multi_format_analyzer: Multi-format binary parsing and analysis
    cfg_explorer: Control flow graph generation and exploration
    similarity_searcher: Binary similarity detection and search
"""

# Import core analysis functions
try:
    from .core_analysis import (
        calculate_entropy, analyze_binary_internal, 
        enhanced_deep_license_analysis, detect_packing
    )
except ImportError:
    calculate_entropy = None
    analyze_binary_internal = None
    enhanced_deep_license_analysis = None
    detect_packing = None

try:
    from .vulnerability_engine import VulnerabilityEngine
except ImportError:
    VulnerabilityEngine = None

try:
    from .dynamic_analyzer import DynamicAnalyzer, AdvancedDynamicAnalyzer
except ImportError:
    DynamicAnalyzer = None
    AdvancedDynamicAnalyzer = None

try:
    from .symbolic_executor import SymbolicExecutionEngine
except ImportError:
    SymbolicExecutionEngine = None

try:
    from .concolic_executor import ConcolicExecutionEngine
except ImportError:
    ConcolicExecutionEngine = None

try:
    from .taint_analyzer import TaintAnalysisEngine, run_taint_analysis
except ImportError:
    TaintAnalysisEngine = None
    run_taint_analysis = None

try:
    from .rop_generator import ROPChainGenerator
except ImportError:
    ROPChainGenerator = None

try:
    from .multi_format_analyzer import MultiFormatBinaryAnalyzer
except ImportError:
    MultiFormatBinaryAnalyzer = None

try:
    from .cfg_explorer import CFGExplorer
except ImportError:
    CFGExplorer = None

try:
    from .incremental_manager import IncrementalAnalysisManager
except ImportError:
    IncrementalAnalysisManager = None

try:
    from .similarity_searcher import SimilaritySearcher
except ImportError:
    SimilaritySearcher = None

__all__ = [
    # Core analysis functions
    'calculate_entropy',
    'analyze_binary_internal', 
    'enhanced_deep_license_analysis',
    'detect_packing',
    # Analysis engines
    'VulnerabilityEngine',
    'DynamicAnalyzer',
    'AdvancedDynamicAnalyzer',
    'SymbolicExecutionEngine',
    'ConcolicExecutionEngine',
    'TaintAnalysisEngine',
    'run_taint_analysis',
    'ROPChainGenerator',
    'MultiFormatBinaryAnalyzer',
    'CFGExplorer',
    'IncrementalAnalysisManager',
    'SimilaritySearcher'
]
