"""Control Flow Graph (CFG) exploration and analysis module for binary analysis."""
import json
import logging
import os
import time
import traceback
from typing import Any, Dict, List, Optional

from intellicrack.logger import logger

from ...utils.tools.radare2_utils import R2Exception, r2_session
from .radare2_ai_integration import R2AIEngine

# Import our advanced radare2 analysis engines
from .radare2_decompiler import R2DecompilationEngine
from .radare2_imports import R2ImportExportAnalyzer
from .radare2_scripting import R2ScriptingEngine
from .radare2_strings import R2StringAnalyzer
from .radare2_vulnerability_engine import R2VulnerabilityEngine

"""
Control Flow Graph (CFG) Explorer for Binary Analysis

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""



try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in cfg_explorer: %s", e)
    np = None
    NUMPY_AVAILABLE = False

# Optional dependencies - graceful fallback if not available
# r2pipe is handled through r2_session in radare2_utils

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in cfg_explorer: %s", e)
    NETWORKX_AVAILABLE = False
    # Create a mock nx class for type annotations when not available
    class _MockNetworkX:
        class DiGraph:
            """Mock DiGraph class for type annotations."""
            pass
    nx = _MockNetworkX()

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in cfg_explorer: %s", e)
    MATPLOTLIB_AVAILABLE = False

try:
    import capstone
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    CAPSTONE_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in cfg_explorer: %s", e)
    capstone = None
    CS_ARCH_X86 = CS_MODE_32 = CS_MODE_64 = Cs = None
    CAPSTONE_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in cfg_explorer: %s", e)
    pefile = None
    PEFILE_AVAILABLE = False



try:
    import subprocess
    SUBPROCESS_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in cfg_explorer: %s", e)
    SUBPROCESS_AVAILABLE = False

# UI dependencies
try:
    from PyQt6.QtWidgets import QFileDialog, QInputDialog, QMessageBox
    PYQT_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in cfg_explorer: %s", e)
    PYQT_AVAILABLE = False


class CFGExplorer:
    """
    Advanced Visual CFG (Control Flow Graph) Explorer with radare2 integration.

    This class provides comprehensive control flow analysis including:
    - Advanced graph analysis using radare2
    - License validation detection
    - Vulnerability pattern recognition
    - AI-enhanced analysis
    - Cross-reference analysis
    - Function clustering and similarity
    - Multi-layer graph visualization
    """

    def __init__(self, binary_path: Optional[str] = None, radare2_path: Optional[str] = None):
        """Initialize the enhanced CFG explorer"""
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)

        # Legacy graph data for compatibility
        self.graph = None
        self.functions = {}
        self.current_function = None

        # Advanced analysis engines
        self.decompiler = None
        self.vulnerability_engine = None
        self.ai_engine = None
        self.string_analyzer = None
        self.import_analyzer = None
        self.scripting_engine = None

        # Advanced graph data
        self.function_graphs = {}
        self.call_graph = None
        self.cross_references = {}
        self.function_similarities = {}
        self.analysis_cache = {}

        # Initialize engines if binary path provided
        if self.binary_path:
            self._initialize_analysis_engines()

    def _initialize_analysis_engines(self) -> None:
        """Initialize all analysis engines with current binary path"""
        if not self.binary_path:
            return

        try:
            # Verify binary exists and is accessible
            if not os.path.exists(self.binary_path):
                self.logger.error(f"Binary path does not exist: {self.binary_path}")
                return
            
            if not os.access(self.binary_path, os.R_OK):
                self.logger.error(f"Cannot read binary file: {self.binary_path}")
                return
            
            # Initialize each engine with error handling
            initialization_results = {}
            
            # Initialize decompiler engine
            try:
                self.decompiler = R2DecompilationEngine(self.binary_path, self.radare2_path)
                initialization_results['decompiler'] = True
                self.logger.debug("Successfully initialized decompiler engine")
            except Exception as e:
                self.logger.warning(f"Failed to initialize decompiler: {e}")
                initialization_results['decompiler'] = False
                self.decompiler = None
            
            # Initialize vulnerability engine
            try:
                self.vulnerability_engine = R2VulnerabilityEngine(self.binary_path, self.radare2_path)
                initialization_results['vulnerability_engine'] = True
                self.logger.debug("Successfully initialized vulnerability engine")
            except Exception as e:
                self.logger.warning(f"Failed to initialize vulnerability engine: {e}")
                initialization_results['vulnerability_engine'] = False
                self.vulnerability_engine = None
            
            # Initialize AI engine
            try:
                self.ai_engine = R2AIEngine(self.binary_path, self.radare2_path)
                initialization_results['ai_engine'] = True
                self.logger.debug("Successfully initialized AI engine")
            except Exception as e:
                self.logger.warning(f"Failed to initialize AI engine: {e}")
                initialization_results['ai_engine'] = False
                self.ai_engine = None
            
            # Initialize string analyzer
            try:
                self.string_analyzer = R2StringAnalyzer(self.binary_path, self.radare2_path)
                initialization_results['string_analyzer'] = True
                self.logger.debug("Successfully initialized string analyzer")
            except Exception as e:
                self.logger.warning(f"Failed to initialize string analyzer: {e}")
                initialization_results['string_analyzer'] = False
                self.string_analyzer = None
            
            # Initialize import analyzer
            try:
                self.import_analyzer = R2ImportExportAnalyzer(self.binary_path, self.radare2_path)
                initialization_results['import_analyzer'] = True
                self.logger.debug("Successfully initialized import analyzer")
            except Exception as e:
                self.logger.warning(f"Failed to initialize import analyzer: {e}")
                initialization_results['import_analyzer'] = False
                self.import_analyzer = None
            
            # Initialize scripting engine
            try:
                self.scripting_engine = R2ScriptingEngine(self.binary_path, self.radare2_path)
                initialization_results['scripting_engine'] = True
                self.logger.debug("Successfully initialized scripting engine")
            except Exception as e:
                self.logger.warning(f"Failed to initialize scripting engine: {e}")
                initialization_results['scripting_engine'] = False
                self.scripting_engine = None
            
            # Log initialization summary
            successful_engines = sum(1 for result in initialization_results.values() if result)
            total_engines = len(initialization_results)
            
            if successful_engines == total_engines:
                self.logger.info(f"Successfully initialized all {total_engines} analysis engines")
            elif successful_engines > 0:
                self.logger.info(f"Initialized {successful_engines}/{total_engines} analysis engines")
                failed_engines = [name for name, result in initialization_results.items() if not result]
                self.logger.warning(f"Failed engines: {', '.join(failed_engines)}")
            else:
                self.logger.error("Failed to initialize any analysis engines")
                
            # Store initialization results for later reference
            self.analysis_cache['engine_initialization'] = initialization_results
            
        except Exception as e:
            self.logger.error(f"Critical error during engine initialization: {e}")
            # Set all engines to None to ensure clean state
            self.decompiler = None
            self.vulnerability_engine = None
            self.ai_engine = None
            self.string_analyzer = None
            self.import_analyzer = None
            self.scripting_engine = None

    def load_binary(self, binary_path: Optional[str] = None) -> bool:
        """Load a binary file and extract its enhanced CFG with advanced analysis"""
        if binary_path:
            self.binary_path = binary_path
            self._initialize_analysis_engines()

        if not self.binary_path:
            self.logger.error("No binary path specified")
            self._show_error_dialog("No binary path specified", "Please specify a valid binary file path.")
            return False

        if not NETWORKX_AVAILABLE:
            self.logger.error("NetworkX not available - please install networkx")
            self._show_error_dialog("Missing Dependency", "NetworkX not available - please install networkx package.")
            return False

        try:
            # Use our advanced radare2 session manager
            with r2_session(self.binary_path, self.radare2_path) as r2:
                self.logger.info(f"Loading binary with advanced CFG analysis: {self.binary_path}")

                # Get comprehensive function information
                functions = r2.get_functions()

                # Initialize call graph
                self.call_graph = nx.DiGraph()

                # Process each function with enhanced analysis
                for func in functions:
                    function_name = func.get('name', f"sub_{func.get('offset', 0):x}")
                    function_addr = func.get('offset', 0)

                    # Skip invalid functions
                    if not function_addr:
                        continue

                    try:
                        # Get advanced function graph with r2
                        graph_data = r2._execute_command(f'agfj @ {hex(function_addr)}', expect_json=True)

                        if not graph_data or not isinstance(graph_data, list) or not graph_data:
                            continue

                        # Create enhanced networkx graph
                        function_graph = self._create_enhanced_function_graph(graph_data[0], r2, function_addr)

                        # Store enhanced function data
                        self.functions[function_name] = {
                            'addr': function_addr,
                            'graph': function_graph,
                            'blocks': graph_data[0].get('blocks', []),
                            'size': func.get('size', 0),
                            'complexity': func.get('cc', 1),
                            'calls': func.get('calls', 0),
                            'type': func.get('type', 'fcn'),
                            'enhanced_data': {}
                        }

                        # Store in advanced graph storage
                        self.function_graphs[function_name] = function_graph

                        # Add to call graph
                        self.call_graph.add_node(function_name, **{
                            'addr': function_addr,
                            'size': func.get('size', 0),
                            'complexity': func.get('cc', 1)
                        })

                    except (R2Exception, json.JSONDecodeError) as e:
                        self.logger.debug(f"Failed to process function {function_name}: {e}")
                        continue

                # Build call graph edges
                self._build_call_graph(r2)

                # Perform advanced analysis
                self._perform_advanced_analysis()

                self.logger.info(f"Loaded {len(self.functions)} functions with enhanced analysis")
                return True

        except (R2Exception, OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Error loading binary with advanced analysis: {e}")
            return False

    def _create_enhanced_function_graph(self, graph_data: Dict[str, Any], r2, function_addr: int) -> nx.DiGraph:
        """Create enhanced function graph with comprehensive node data"""
        function_graph = nx.DiGraph()

        # Add function-level metadata using r2 and function_addr
        if r2 and function_addr:
            try:
                # Get function information from r2
                func_info = r2.cmdj(f"afij @ {function_addr}")
                if func_info:
                    function_graph.graph['function_name'] = func_info[0].get('name', f'func_{function_addr:x}')
                    function_graph.graph['function_size'] = func_info[0].get('realsz', 0)
                    function_graph.graph['function_addr'] = function_addr
            except Exception as e:
                self.logger.error("Exception in cfg_explorer: %s", e)
                # Fallback if r2 command fails
                function_graph.graph['function_addr'] = function_addr
                function_graph.graph['function_name'] = f'func_{function_addr:x}'

        blocks = graph_data.get('blocks', [])

        for block in blocks:
            block_addr = block.get('offset', 0)
            block_size = block.get('size', 0)
            block_ops = block.get('ops', [])

            # Calculate block characteristics
            instruction_count = len(block_ops)
            has_call = any('call' in op.get('disasm', '') for op in block_ops)
            has_jump = any(op.get('type', '') in ['jmp', 'cjmp'] for op in block_ops)
            has_return = any('ret' in op.get('disasm', '') for op in block_ops)

            # Analyze for security-relevant instructions
            crypto_ops = sum(1 for op in block_ops if any(kw in op.get('disasm', '').lower()
                           for kw in ['aes', 'crypt', 'hash', 'rsa']))

            license_ops = sum(1 for op in block_ops if any(kw in op.get('disasm', '').lower()
                            for kw in ['license', 'valid', 'check', 'trial', 'serial']))

            # Add enhanced node with comprehensive metadata
            function_graph.add_node(block_addr, **{
                'size': block_size,
                'ops': block_ops,
                'instruction_count': instruction_count,
                'label': f"0x{block_addr:x}",
                'has_call': has_call,
                'has_jump': has_jump,
                'has_return': has_return,
                'crypto_operations': crypto_ops,
                'license_operations': license_ops,
                'block_type': self._classify_block_type(block),
                'complexity_score': self._calculate_block_complexity(block)
            })

            # Add control flow edges with enhanced metadata
            if block.get('jump'):
                jump_target = block['jump']
                function_graph.add_edge(block_addr, jump_target, **{
                    'type': 'conditional_jump',
                    'condition': 'true'
                })

            if block.get('fail'):
                fail_target = block['fail']
                function_graph.add_edge(block_addr, fail_target, **{
                    'type': 'conditional_jump',
                    'condition': 'false'
                })

            # Add sequential flow edges
            next_block = block.get('next')
            if next_block and not has_return and not (block.get('jump') and not block.get('fail')):
                function_graph.add_edge(block_addr, next_block, **{
                    'type': 'sequential',
                    'condition': 'fallthrough'
                })

        return function_graph

    def _classify_block_type(self, block: Dict[str, Any]) -> str:
        """Classify block type based on its characteristics"""
        ops = block.get('ops', [])

        if not ops:
            return 'empty'

        # Check for return blocks
        if any('ret' in op.get('disasm', '') for op in ops):
            return 'return'

        # Check for call blocks
        if any('call' in op.get('disasm', '') for op in ops):
            return 'call'

        # Check for conditional blocks
        if block.get('jump') and block.get('fail'):
            return 'conditional'

        # Check for unconditional jump blocks
        if block.get('jump') and not block.get('fail'):
            return 'jump'

        return 'basic'

    def _calculate_block_complexity(self, block: Dict[str, Any]) -> float:
        """Calculate complexity score for a basic block"""
        ops = block.get('ops', [])

        if not ops:
            return 0.0

        complexity = len(ops)  # Base complexity from instruction count

        # Add complexity for different instruction types
        for op in ops:
            disasm = op.get('disasm', '').lower()

            if 'call' in disasm:
                complexity += 2
            elif any(jmp in disasm for jmp in ['jmp', 'je', 'jne', 'jz', 'jnz']):
                complexity += 1.5
            elif any(math_op in disasm for math_op in ['mul', 'div', 'imul', 'idiv']):
                complexity += 1.2
            elif any(crypto in disasm for crypto in ['aes', 'sha', 'md5']):
                complexity += 3

        return complexity

    def _build_call_graph(self, r2) -> None:
        """Build inter-function call graph"""
        try:
            # Get all cross-references
            xrefs = r2._execute_command('axtj', expect_json=True)

            if not isinstance(xrefs, list):
                return

            for xref in xrefs:
                from_addr = xref.get('from', 0)
                to_addr = xref.get('to', 0)
                xref_type = xref.get('type', '')

                if xref_type == 'CALL':
                    # Find functions containing these addresses
                    from_func = self._find_function_by_address(from_addr)
                    to_func = self._find_function_by_address(to_addr)

                    if from_func and to_func and from_func != to_func:
                        self.call_graph.add_edge(from_func, to_func, **{
                            'type': 'function_call',
                            'from_addr': hex(from_addr),
                            'to_addr': hex(to_addr)
                        })

        except (R2Exception, json.JSONDecodeError) as e:
            self.logger.debug(f"Failed to build call graph: {e}")

    def _find_function_by_address(self, address: int) -> Optional[str]:
        """Find function name containing the given address"""
        for func_name, func_data in self.functions.items():
            func_addr = func_data.get('addr', 0)
            func_size = func_data.get('size', 0)

            if func_addr <= address < func_addr + func_size:
                return func_name

        return None
    
    def find_loops(self, function_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Find all loops in the current function or a specified function.
        
        Implements real loop detection algorithms using graph cycle analysis.
        Detects various loop types: while loops, for loops, do-while loops.
        
        Args:
            function_name: Optional function name to analyze. If None, uses current function.
            
        Returns:
            List of detected loops with detailed information
        """
        # Use specified function or current function
        if function_name:
            if not self.set_current_function(function_name):
                self.logger.error(f"Function {function_name} not found")
                return []
        elif not self.current_function or not self.graph:
            self.logger.error("No function loaded for loop analysis")
            return []
        
        if not NETWORKX_AVAILABLE:
            self.logger.error("NetworkX not available for loop detection")
            return []
        
        loops = []
        
        try:
            # Find strongly connected components (potential loops)
            sccs = list(nx.strongly_connected_components(self.graph))
            
            # Filter out single-node SCCs (not loops)
            loop_sccs = [scc for scc in sccs if len(scc) > 1]
            
            # Analyze each potential loop
            for loop_idx, scc in enumerate(loop_sccs):
                loop_info = {
                    'loop_id': loop_idx,
                    'nodes': list(scc),
                    'entry_points': [],
                    'exit_points': [],
                    'back_edges': [],
                    'loop_type': 'unknown',
                    'complexity': len(scc),
                    'nested_loops': [],
                    'instructions': []
                }
                
                # Find entry points (nodes with incoming edges from outside the loop)
                for node in scc:
                    predecessors = list(self.graph.predecessors(node))
                    external_preds = [pred for pred in predecessors if pred not in scc]
                    if external_preds:
                        loop_info['entry_points'].append({
                            'node': node,
                            'external_predecessors': external_preds
                        })
                
                # Find exit points (nodes with outgoing edges to outside the loop)
                for node in scc:
                    successors = list(self.graph.successors(node))
                    external_succs = [succ for succ in successors if succ not in scc]
                    if external_succs:
                        loop_info['exit_points'].append({
                            'node': node,
                            'external_successors': external_succs
                        })
                
                # Find back edges (edges that go from later to earlier nodes)
                for node in scc:
                    for successor in self.graph.successors(node):
                        if successor in scc:
                            # Check if this is a back edge using DFS numbering
                            if self._is_back_edge(node, successor, scc):
                                loop_info['back_edges'].append({
                                    'from': node,
                                    'to': successor,
                                    'type': 'loop_back_edge'
                                })
                
                # Determine loop type based on structure
                loop_info['loop_type'] = self._classify_loop_type(loop_info)
                
                # Collect instructions from all nodes in the loop
                func_data = self.functions.get(self.current_function, {})
                blocks = func_data.get('blocks', [])
                
                for block in blocks:
                    if block.get('offset', 0) in scc:
                        for op in block.get('ops', []):
                            loop_info['instructions'].append({
                                'offset': op.get('offset', 0),
                                'disasm': op.get('disasm', ''),
                                'type': op.get('type', '')
                            })
                
                loops.append(loop_info)
            
            # Detect nested loops
            for i, loop1 in enumerate(loops):
                for j, loop2 in enumerate(loops):
                    if i != j:
                        # Check if loop2 is nested inside loop1
                        if set(loop2['nodes']).issubset(set(loop1['nodes'])):
                            loop1['nested_loops'].append(loop2['loop_id'])
            
            # Find natural loops using dominance analysis
            natural_loops = self._find_natural_loops()
            
            # Merge natural loop information
            for natural_loop in natural_loops:
                # Check if this natural loop corresponds to any detected SCC loop
                matched = False
                for loop in loops:
                    if set(natural_loop['nodes']) == set(loop['nodes']):
                        # Enhance existing loop info with natural loop data
                        loop['loop_header'] = natural_loop.get('header')
                        loop['is_natural_loop'] = True
                        matched = True
                        break
                
                if not matched:
                    # Add as a new loop if not already detected
                    loops.append(natural_loop)
            
            self.logger.info(f"Found {len(loops)} loops in function {self.current_function}")
            
        except Exception as e:
            self.logger.error(f"Error during loop detection: {e}")
            
        return loops
    
    def _is_back_edge(self, source: int, target: int, scc: set) -> bool:
        """Determine if an edge is a back edge using DFS ordering."""
        try:
            # Create a subgraph containing only the SCC nodes
            subgraph = self.graph.subgraph(scc)
            
            # Perform DFS to get discovery times
            discovery_times = {}
            time_counter = [0]
            
            def dfs(node, visited, discovery_times, time_counter):
                visited.add(node)
                discovery_times[node] = time_counter[0]
                time_counter[0] += 1
                
                for neighbor in subgraph.successors(node):
                    if neighbor not in visited:
                        dfs(neighbor, visited, discovery_times, time_counter)
            
            # Start DFS from any node in the SCC
            visited = set()
            start_node = next(iter(scc))
            dfs(start_node, visited, discovery_times, time_counter)
            
            # An edge is a back edge if target has lower discovery time than source
            return discovery_times.get(target, float('inf')) < discovery_times.get(source, float('inf'))
            
        except Exception as e:
            self.logger.debug(f"Error checking back edge: {e}")
            return False
    
    def _classify_loop_type(self, loop_info: Dict[str, Any]) -> str:
        """Classify the type of loop based on its structure."""
        entry_count = len(loop_info['entry_points'])
        exit_count = len(loop_info['exit_points'])
        back_edge_count = len(loop_info['back_edges'])
        
        # Simple while loop: single entry, single/multiple exits, single back edge
        if entry_count == 1 and back_edge_count == 1:
            if exit_count >= 1:
                # Check if exit is at the beginning (while loop) or end (do-while)
                if loop_info['entry_points'][0]['node'] in [be['to'] for be in loop_info['back_edges']]:
                    return 'while_loop'
                else:
                    return 'do_while_loop'
        
        # For loop pattern: typically has initialization, condition check, and increment
        if entry_count == 1 and back_edge_count == 1 and len(loop_info['nodes']) >= 3:
            # Look for increment pattern in instructions
            has_increment = False
            for inst in loop_info['instructions']:
                if any(op in inst['disasm'].lower() for op in ['inc', 'add', 'dec', 'sub']):
                    has_increment = True
                    break
            
            if has_increment:
                return 'for_loop'
        
        # Complex loop with multiple entries or exits
        if entry_count > 1 or exit_count > 1:
            return 'complex_loop'
        
        # Infinite loop (no exits)
        if exit_count == 0:
            return 'infinite_loop'
        
        return 'generic_loop'
    
    def _find_natural_loops(self) -> List[Dict[str, Any]]:
        """Find natural loops using dominance analysis."""
        natural_loops = []
        
        try:
            # Find dominator tree
            if hasattr(nx, 'immediate_dominators'):
                # Get entry point of the function
                entry_nodes = [node for node in self.graph.nodes() if self.graph.in_degree(node) == 0]
                if not entry_nodes:
                    # If no clear entry, use the node with minimum address
                    entry_nodes = [min(self.graph.nodes())]
                
                entry_node = entry_nodes[0]
                
                # Calculate immediate dominators
                idom = nx.immediate_dominators(self.graph, entry_node)
                
                # Find back edges based on dominance
                for edge in self.graph.edges():
                    source, target = edge
                    
                    # A back edge is one where target dominates source
                    if self._dominates(target, source, idom):
                        # Found a back edge, construct the natural loop
                        loop_nodes = self._get_natural_loop_nodes(source, target)
                        
                        natural_loop = {
                            'loop_id': len(natural_loops),
                            'nodes': list(loop_nodes),
                            'header': target,
                            'back_edge': {'from': source, 'to': target},
                            'loop_type': 'natural_loop',
                            'is_natural_loop': True,
                            'complexity': len(loop_nodes)
                        }
                        
                        natural_loops.append(natural_loop)
            
        except Exception as e:
            self.logger.debug(f"Error finding natural loops: {e}")
        
        return natural_loops
    
    def _dominates(self, dominator: int, node: int, idom: Dict[int, int]) -> bool:
        """Check if dominator dominates node using immediate dominator tree."""
        current = node
        while current in idom:
            if current == dominator:
                return True
            current = idom[current]
        return False
    
    def _get_natural_loop_nodes(self, tail: int, head: int) -> set:
        """Get all nodes in a natural loop given a back edge (tail -> head)."""
        loop_nodes = {head, tail}
        
        # Use BFS to find all nodes that can reach tail without going through head
        queue = [tail]
        visited = {tail}
        
        while queue:
            current = queue.pop(0)
            
            for predecessor in self.graph.predecessors(current):
                if predecessor != head and predecessor not in visited:
                    visited.add(predecessor)
                    loop_nodes.add(predecessor)
                    queue.append(predecessor)
        
        return loop_nodes
    
    def analyze_basic_blocks(self, function_name: Optional[str] = None) -> Dict[str, Any]:
        """Analyze basic blocks in the current or specified function.
        
        Performs comprehensive basic block analysis including:
        - Block size and instruction count statistics
        - Control flow patterns
        - Suspicious instruction sequences
        - Obfuscation detection
        - License check identification
        
        Args:
            function_name: Optional function name to analyze. If None, analyzes all functions.
            
        Returns:
            Dictionary containing detailed basic block analysis
        """
        analysis = {
            'total_functions': 0,
            'total_blocks': 0,
            'total_instructions': 0,
            'average_block_size': 0,
            'average_instructions_per_block': 0,
            'block_size_distribution': {},
            'control_flow_patterns': {
                'linear_blocks': 0,
                'conditional_blocks': 0,
                'call_blocks': 0,
                'return_blocks': 0,
                'jump_blocks': 0
            },
            'suspicious_patterns': {
                'obfuscated_blocks': [],
                'anti_debug_blocks': [],
                'crypto_blocks': [],
                'license_blocks': [],
                'packing_blocks': []
            },
            'complexity_metrics': {
                'high_complexity_blocks': [],
                'dead_code_blocks': [],
                'unreachable_blocks': []
            },
            'function_analysis': {}
        }
        
        try:
            # Determine which functions to analyze
            functions_to_analyze = []
            
            if function_name:
                if function_name in self.functions:
                    functions_to_analyze = [function_name]
                else:
                    self.logger.error(f"Function {function_name} not found")
                    return analysis
            else:
                functions_to_analyze = list(self.functions.keys())
            
            analysis['total_functions'] = len(functions_to_analyze)
            
            # Analyze each function
            for func_name in functions_to_analyze:
                func_data = self.functions[func_name]
                graph = func_data.get('graph')
                blocks = func_data.get('blocks', [])
                
                if not graph:
                    continue
                
                func_analysis = {
                    'name': func_name,
                    'address': func_data.get('addr', 0),
                    'block_count': len(blocks),
                    'instruction_count': 0,
                    'complexity': func_data.get('complexity', 1),
                    'suspicious_blocks': [],
                    'control_flow_anomalies': []
                }
                
                # Analyze each block in the function
                for block in blocks:
                    block_addr = block.get('offset', 0)
                    block_size = block.get('size', 0)
                    block_ops = block.get('ops', [])
                    instruction_count = len(block_ops)
                    
                    analysis['total_blocks'] += 1
                    analysis['total_instructions'] += instruction_count
                    func_analysis['instruction_count'] += instruction_count
                    
                    # Update block size distribution
                    size_category = self._categorize_block_size(instruction_count)
                    analysis['block_size_distribution'][size_category] = \
                        analysis['block_size_distribution'].get(size_category, 0) + 1
                    
                    # Analyze control flow pattern
                    if graph.nodes.get(block_addr):
                        node_data = graph.nodes[block_addr]
                        block_type = node_data.get('block_type', 'unknown')
                        
                        if block_type == 'basic':
                            analysis['control_flow_patterns']['linear_blocks'] += 1
                        elif block_type == 'conditional':
                            analysis['control_flow_patterns']['conditional_blocks'] += 1
                        elif block_type == 'call':
                            analysis['control_flow_patterns']['call_blocks'] += 1
                        elif block_type == 'return':
                            analysis['control_flow_patterns']['return_blocks'] += 1
                        elif block_type == 'jump':
                            analysis['control_flow_patterns']['jump_blocks'] += 1
                    
                    # Detect suspicious patterns
                    suspicious_info = self._analyze_block_for_patterns(block, block_addr)
                    
                    if suspicious_info['is_obfuscated']:
                        analysis['suspicious_patterns']['obfuscated_blocks'].append({
                            'function': func_name,
                            'address': hex(block_addr),
                            'reason': suspicious_info['obfuscation_reason'],
                            'confidence': suspicious_info['obfuscation_confidence']
                        })
                        func_analysis['suspicious_blocks'].append(block_addr)
                    
                    if suspicious_info['has_anti_debug']:
                        analysis['suspicious_patterns']['anti_debug_blocks'].append({
                            'function': func_name,
                            'address': hex(block_addr),
                            'techniques': suspicious_info['anti_debug_techniques']
                        })
                    
                    if suspicious_info['has_crypto']:
                        analysis['suspicious_patterns']['crypto_blocks'].append({
                            'function': func_name,
                            'address': hex(block_addr),
                            'algorithms': suspicious_info['crypto_algorithms']
                        })
                    
                    if suspicious_info['has_license_check']:
                        analysis['suspicious_patterns']['license_blocks'].append({
                            'function': func_name,
                            'address': hex(block_addr),
                            'keywords': suspicious_info['license_keywords'],
                            'confidence': suspicious_info['license_confidence']
                        })
                    
                    if suspicious_info['has_packing']:
                        analysis['suspicious_patterns']['packing_blocks'].append({
                            'function': func_name,
                            'address': hex(block_addr),
                            'indicators': suspicious_info['packing_indicators']
                        })
                    
                    # Check for high complexity blocks
                    if node_data and node_data.get('complexity_score', 0) > 20:
                        analysis['complexity_metrics']['high_complexity_blocks'].append({
                            'function': func_name,
                            'address': hex(block_addr),
                            'complexity': node_data.get('complexity_score', 0),
                            'instruction_count': instruction_count
                        })
                
                # Check for unreachable blocks
                if graph and NETWORKX_AVAILABLE:
                    reachable = set()
                    entry_nodes = [n for n in graph.nodes() if graph.in_degree(n) == 0]
                    
                    if entry_nodes:
                        # BFS from entry nodes
                        queue = list(entry_nodes)
                        reachable.update(entry_nodes)
                        
                        while queue:
                            current = queue.pop(0)
                            for successor in graph.successors(current):
                                if successor not in reachable:
                                    reachable.add(successor)
                                    queue.append(successor)
                        
                        # Find unreachable blocks
                        all_blocks = set(graph.nodes())
                        unreachable = all_blocks - reachable
                        
                        if unreachable:
                            for unreach_block in unreachable:
                                analysis['complexity_metrics']['unreachable_blocks'].append({
                                    'function': func_name,
                                    'address': hex(unreach_block)
                                })
                                func_analysis['control_flow_anomalies'].append({
                                    'type': 'unreachable_code',
                                    'address': hex(unreach_block)
                                })
                    
                    # Check for dead code (blocks with no successors except returns)
                    for node in graph.nodes():
                        if graph.out_degree(node) == 0:
                            node_data = graph.nodes[node]
                            if node_data.get('block_type') != 'return':
                                analysis['complexity_metrics']['dead_code_blocks'].append({
                                    'function': func_name,
                                    'address': hex(node),
                                    'reason': 'no_successors'
                                })
                
                analysis['function_analysis'][func_name] = func_analysis
            
            # Calculate averages
            if analysis['total_blocks'] > 0:
                analysis['average_block_size'] = analysis['total_instructions'] / analysis['total_blocks']
                analysis['average_instructions_per_block'] = analysis['total_instructions'] / analysis['total_blocks']
            
            # Generate summary
            analysis['summary'] = self._generate_block_analysis_summary(analysis)
            
            self.logger.info(f"Basic block analysis complete: {analysis['total_blocks']} blocks analyzed")
            
        except Exception as e:
            self.logger.error(f"Error during basic block analysis: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def _categorize_block_size(self, instruction_count: int) -> str:
        """Categorize block size based on instruction count."""
        if instruction_count == 0:
            return 'empty'
        elif instruction_count <= 5:
            return 'tiny'
        elif instruction_count <= 15:
            return 'small'
        elif instruction_count <= 50:
            return 'medium'
        elif instruction_count <= 100:
            return 'large'
        else:
            return 'huge'
    
    def _analyze_block_for_patterns(self, block: Dict[str, Any], block_addr: int) -> Dict[str, Any]:
        """Analyze a basic block for suspicious patterns."""
        result = {
            'is_obfuscated': False,
            'obfuscation_reason': '',
            'obfuscation_confidence': 0.0,
            'has_anti_debug': False,
            'anti_debug_techniques': [],
            'has_crypto': False,
            'crypto_algorithms': [],
            'has_license_check': False,
            'license_keywords': [],
            'license_confidence': 0.0,
            'has_packing': False,
            'packing_indicators': []
        }
        
        ops = block.get('ops', [])
        if not ops:
            return result
        
        # Count instruction types
        instruction_types = {}
        for op in ops:
            mnemonic = op.get('disasm', '').split()[0].lower() if op.get('disasm') else ''
            instruction_types[mnemonic] = instruction_types.get(mnemonic, 0) + 1
        
        # Obfuscation detection
        total_instructions = len(ops)
        if total_instructions > 10:
            # Check for excessive jumps
            jump_count = sum(count for mnem, count in instruction_types.items() 
                           if mnem.startswith('j') and mnem != 'jmp')
            if jump_count > total_instructions * 0.4:
                result['is_obfuscated'] = True
                result['obfuscation_reason'] = 'excessive_conditional_jumps'
                result['obfuscation_confidence'] = min(jump_count / total_instructions, 1.0)
            
            # Check for junk instructions
            junk_instructions = ['nop', 'push', 'pop', 'xchg', 'lea']
            junk_count = sum(instruction_types.get(junk, 0) for junk in junk_instructions)
            if junk_count > total_instructions * 0.3:
                result['is_obfuscated'] = True
                result['obfuscation_reason'] = 'junk_instructions'
                result['obfuscation_confidence'] = min(junk_count / total_instructions, 1.0)
        
        # Anti-debugging detection
        anti_debug_apis = [
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
            'GetTickCount', 'QueryPerformanceCounter', 'rdtsc', 'int3', 'int 2d'
        ]
        
        for op in ops:
            disasm = op.get('disasm', '').lower()
            
            # Check for anti-debug techniques
            for anti_debug in anti_debug_apis:
                if anti_debug.lower() in disasm:
                    result['has_anti_debug'] = True
                    if anti_debug not in result['anti_debug_techniques']:
                        result['anti_debug_techniques'].append(anti_debug)
            
            # Check for timing checks
            if 'rdtsc' in disasm or 'cpuid' in disasm:
                result['has_anti_debug'] = True
                if 'timing_check' not in result['anti_debug_techniques']:
                    result['anti_debug_techniques'].append('timing_check')
        
        # Cryptographic operations detection
        crypto_indicators = {
            'aes': ['aesenc', 'aesdec', 'aesimc', 'aeskeygenassist'],
            'sha': ['sha256rnds2', 'sha256msg1', 'sha256msg2'],
            'general': ['xor', 'ror', 'rol', 'shl', 'shr']
        }
        
        xor_count = instruction_types.get('xor', 0)
        if xor_count > 3:  # Multiple XOR operations might indicate encryption
            result['has_crypto'] = True
            result['crypto_algorithms'].append('xor_cipher')
        
        for algo, indicators in crypto_indicators.items():
            for indicator in indicators:
                if instruction_types.get(indicator, 0) > 0:
                    result['has_crypto'] = True
                    if algo not in result['crypto_algorithms']:
                        result['crypto_algorithms'].append(algo)
        
        # License check detection
        license_keywords = [
            'license', 'serial', 'key', 'activation', 'registration',
            'trial', 'expire', 'valid', 'check', 'verify', 'auth'
        ]
        
        license_score = 0
        for op in ops:
            disasm = op.get('disasm', '').lower()
            for keyword in license_keywords:
                if keyword in disasm:
                    if keyword not in result['license_keywords']:
                        result['license_keywords'].append(keyword)
                    license_score += 1
        
        if license_score > 0:
            result['has_license_check'] = True
            result['license_confidence'] = min(license_score / 10.0, 1.0)
        
        # Packing/unpacking detection
        packing_indicators = [
            'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
            'CreateRemoteThread', 'LoadLibrary', 'GetProcAddress'
        ]
        
        for op in ops:
            disasm = op.get('disasm', '')
            for indicator in packing_indicators:
                if indicator in disasm:
                    result['has_packing'] = True
                    if indicator not in result['packing_indicators']:
                        result['packing_indicators'].append(indicator)
        
        # Check for self-modifying code patterns
        if ('VirtualProtect' in str(result['packing_indicators']) and 
            any(mnem in instruction_types for mnem in ['stosb', 'stosd', 'movsb', 'movsd'])):
            result['has_packing'] = True
            if 'self_modifying_code' not in result['packing_indicators']:
                result['packing_indicators'].append('self_modifying_code')
        
        return result
    
    def _generate_block_analysis_summary(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of the basic block analysis."""
        summary = {
            'overview': f"Analyzed {analysis['total_functions']} functions containing {analysis['total_blocks']} basic blocks",
            'statistics': {
                'total_instructions': analysis['total_instructions'],
                'average_block_size': round(analysis.get('average_block_size', 0), 2),
                'most_common_block_size': max(analysis['block_size_distribution'].items(), 
                                             key=lambda x: x[1])[0] if analysis['block_size_distribution'] else 'unknown'
            },
            'suspicious_activity': {
                'obfuscated_blocks': len(analysis['suspicious_patterns']['obfuscated_blocks']),
                'anti_debug_blocks': len(analysis['suspicious_patterns']['anti_debug_blocks']),
                'crypto_blocks': len(analysis['suspicious_patterns']['crypto_blocks']),
                'license_blocks': len(analysis['suspicious_patterns']['license_blocks']),
                'packing_blocks': len(analysis['suspicious_patterns']['packing_blocks'])
            },
            'code_quality': {
                'high_complexity_blocks': len(analysis['complexity_metrics']['high_complexity_blocks']),
                'dead_code_blocks': len(analysis['complexity_metrics']['dead_code_blocks']),
                'unreachable_blocks': len(analysis['complexity_metrics']['unreachable_blocks'])
            },
            'recommendations': []
        }
        
        # Generate recommendations based on findings
        if summary['suspicious_activity']['obfuscated_blocks'] > 5:
            summary['recommendations'].append("High obfuscation detected - consider deobfuscation analysis")
        
        if summary['suspicious_activity']['anti_debug_blocks'] > 0:
            summary['recommendations'].append("Anti-debugging techniques detected - use advanced debugging tools")
        
        if summary['suspicious_activity']['license_blocks'] > 0:
            summary['recommendations'].append(f"Found {summary['suspicious_activity']['license_blocks']} potential license check locations")
        
        if summary['code_quality']['unreachable_blocks'] > 0:
            summary['recommendations'].append("Unreachable code detected - possible obfuscation or dead code")
        
        return summary

    def _perform_advanced_analysis(self) -> None:
        """Perform advanced analysis using integrated engines"""
        if not self.binary_path:
            return

        try:
            # Perform comprehensive string analysis
            if self.string_analyzer:
                string_analysis = self.string_analyzer.analyze_all_strings()
                self.analysis_cache['string_analysis'] = string_analysis

            # Perform import/export analysis
            if self.import_analyzer:
                import_analysis = self.import_analyzer.analyze_imports_exports()
                self.analysis_cache['import_analysis'] = import_analysis

            # Perform AI-enhanced analysis
            if self.ai_engine:
                ai_analysis = self.ai_engine.analyze_with_ai()
                self.analysis_cache['ai_analysis'] = ai_analysis

            # Calculate function similarities
            self._calculate_function_similarities()

            # Perform license analysis using scripting engine
            if self.scripting_engine:
                license_analysis = self.scripting_engine.execute_license_analysis_workflow()
                self.analysis_cache['license_analysis'] = license_analysis

            self.logger.info("Completed advanced analysis")

        except Exception as e:
            self.logger.warning(f"Advanced analysis partially failed: {e}")

    def _calculate_function_similarities(self) -> None:
        """Calculate similarities between functions using graph metrics"""
        if not NETWORKX_AVAILABLE:
            return

        function_names = list(self.function_graphs.keys())

        for i, func1 in enumerate(function_names):
            for _j, func2 in enumerate(function_names[i+1:], i+1):
                try:
                    graph1 = self.function_graphs[func1]
                    graph2 = self.function_graphs[func2]

                    # Calculate structural similarity
                    similarity = self._calculate_graph_similarity(graph1, graph2)

                    if similarity > 0.5:  # Only store significant similarities
                        self.function_similarities[f"{func1}:{func2}"] = similarity

                except Exception as e:
                    self.logger.debug(f"Failed to calculate similarity between {func1} and {func2}: {e}")

    def _calculate_graph_similarity(self, graph1: nx.DiGraph, graph2: nx.DiGraph) -> float:
        """Calculate similarity between two function graphs"""
        if graph1.number_of_nodes() == 0 or graph2.number_of_nodes() == 0:
            return 0.0

        # Simple structural similarity based on node/edge ratios
        node_ratio = min(graph1.number_of_nodes(), graph2.number_of_nodes()) / max(graph1.number_of_nodes(), graph2.number_of_nodes())

        # Calculate edge ratio with safe division
        max_edges = max(graph1.number_of_edges(), graph2.number_of_edges())
        if max_edges > 0:
            edge_ratio = min(graph1.number_of_edges(), graph2.number_of_edges()) / max_edges
        else:
            edge_ratio = 1.0

        # Calculate complexity similarity
        try:
            complexity1 = len(list(nx.simple_cycles(graph1))) + 1
            complexity2 = len(list(nx.simple_cycles(graph2))) + 1
            complexity_ratio = min(complexity1, complexity2) / max(complexity1, complexity2)
        except (nx.NetworkXError, ValueError, TypeError):
            complexity_ratio = 1.0

        return (node_ratio + edge_ratio + complexity_ratio) / 3.0

    def get_function_list(self) -> List[str]:
        """Get a list of all functions in the binary"""
        return list(self.functions.keys())

    def set_current_function(self, function_name: str) -> bool:
        """Set the current function for analysis"""
        if function_name in self.functions:
            self.current_function = function_name
            self.graph = self.functions[function_name]['graph']
            return True
        else:
            self.logger.error("Function %s not found", function_name)
            return False

    # Alias methods for compatibility
    def get_functions(self) -> List[Dict]:
        """Get list of functions (alias for get_function_list)."""
        function_list = []
        for func_name, func_data in self.functions.items():
            function_list.append({
                "name": func_name,
                "address": f"0x{func_data['addr']:x}"
            })
        return function_list

    def analyze_function(self, function_name: str) -> Optional[Dict]:
        """Analyze a specific function (compatibility method)."""
        if not self.set_current_function(function_name):
            return None

        func_data = self.functions.get(function_name)
        if not func_data:
            return None

        # Get complexity metrics
        complexity = self.get_complexity_metrics()

        # Find license patterns
        license_patterns = self.find_license_check_patterns()

        # Count basic blocks
        num_blocks = len(func_data.get('blocks', []))

        return {
            "name": function_name,
            "address": f"0x{func_data['addr']:x}",
            "graph": self.graph,
            "num_blocks": num_blocks,
            "complexity": complexity,
            "license_patterns": license_patterns,
            "has_license_checks": len(license_patterns) > 0
        }

    def visualize_cfg(self, function_name: str = None) -> bool:
        """Visualize CFG (compatibility method)."""
        if function_name and not self.set_current_function(function_name):
            return False
        return self.export_graph_image("cfg_visualization.png")

    def export_dot(self, output_file: str) -> bool:
        """Export DOT file (alias for export_dot_file)."""
        return self.export_dot_file(output_file)

    def analyze(self, binary_path: str = None) -> bool:
        """Analyze binary (compatibility method)."""
        if binary_path:
            return self.load_binary(binary_path)
        return True

    def get_complexity_metrics(self) -> Dict:
        """Get complexity metrics for the current function."""
        if not self.graph or not NETWORKX_AVAILABLE:
            return {"error": "No graph or NetworkX not available"}

        try:
            return {
                "nodes": self.graph.number_of_nodes(),
                "edges": self.graph.number_of_edges(),
                "cyclomatic_complexity": len(list(nx.simple_cycles(self.graph))) + 1
            }
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in cfg_explorer: %s", e)
            return {"error": str(e)}

    def get_graph_layout(self, layout_type: str = 'spring') -> Optional[Dict]:
        """Get a layout for the current function graph"""
        if not self.graph:
            self.logger.error("No graph loaded")
            return None

        if not NETWORKX_AVAILABLE:
            self.logger.error("NetworkX not available")
            return None

        # Choose layout algorithm
        if layout_type == 'spring':
            layout = nx.spring_layout(self.graph)
        elif layout_type == 'dot':
            try:
                layout = nx.nx_pydot.graphviz_layout(self.graph, prog='dot')
            except (ImportError, OSError, FileNotFoundError):
                self.logger.warning("Graphviz not available, falling back to spring layout")
                layout = nx.spring_layout(self.graph)
        elif layout_type == 'circular':
            layout = nx.circular_layout(self.graph)
        else:
            layout = nx.spring_layout(self.graph)

        return layout

    def get_graph_data(self, layout_type: str = 'spring') -> Optional[Dict[str, Any]]:
        """Get graph data for visualization"""
        if not self.graph:
            self.logger.error("No graph loaded")
            return None

        # Get layout
        layout = self.get_graph_layout(layout_type)
        if layout is None:
            self.logger.error("Failed to get graph layout")
            return None

        # Prepare nodes
        nodes = []
        if self.graph is not None:
            for _node in self.graph.nodes():
                node_data = self.graph.nodes[_node]
                nodes.append({
                    'id': _node,
                    'label': node_data.get('label', f"0x{_node:x}"),
                    'x': float(layout[_node][0]) if _node in layout else 0.0,
                    'y': float(layout[_node][1]) if _node in layout else 0.0,
                    'size': node_data.get('size', 0)
                })

        # Prepare edges
        edges = []
        if self.graph is not None:
            for source, target in self.graph.edges():
                edges.append({
                    'source': source,
                    'target': target
                })

        return {
            'nodes': nodes,
            'edges': edges,
            'function': self.current_function
        }

    def get_advanced_analysis_results(self) -> Dict[str, Any]:
        """Get comprehensive advanced analysis results"""
        return {
            'analysis_cache': self.analysis_cache,
            'function_similarities': self.function_similarities,
            'call_graph_metrics': self.get_call_graph_metrics(),
            'vulnerability_patterns': self.get_vulnerability_patterns(),
            'license_validation_analysis': self.get_license_validation_analysis(),
            'code_complexity_analysis': self.get_code_complexity_analysis(),
            'cross_reference_analysis': self.get_cross_reference_analysis()
        }

    def get_call_graph_metrics(self) -> Dict[str, Any]:
        """Get call graph analysis metrics"""
        if not self.call_graph or not NETWORKX_AVAILABLE:
            return {}

        try:
            metrics = {
                'total_functions': self.call_graph.number_of_nodes(),
                'total_calls': self.call_graph.number_of_edges(),
                'avg_calls_per_function': self.call_graph.number_of_edges() / max(1, self.call_graph.number_of_nodes()),
                'strongly_connected_components': len(list(nx.strongly_connected_components(self.call_graph))),
                'function_ranks': dict(nx.pagerank(self.call_graph)),
                'entry_points': [node for node in self.call_graph.nodes() if self.call_graph.in_degree(node) == 0],
                'leaf_functions': [node for node in self.call_graph.nodes() if self.call_graph.out_degree(node) == 0],
                'recursive_functions': self._find_recursive_functions()
            }

            # Calculate centrality measures
            if self.call_graph.number_of_nodes() > 0:
                metrics['betweenness_centrality'] = dict(nx.betweenness_centrality(self.call_graph))
                metrics['closeness_centrality'] = dict(nx.closeness_centrality(self.call_graph))

            return metrics
        except Exception as e:
            self.logger.debug(f"Failed to calculate call graph metrics: {e}")
            return {}

    def _find_recursive_functions(self) -> List[str]:
        """Find functions that call themselves directly or indirectly"""
        recursive_funcs = []

        if not self.call_graph:
            return recursive_funcs

        # Direct recursion
        for node in self.call_graph.nodes():
            if self.call_graph.has_edge(node, node):
                recursive_funcs.append(node)

        # Indirect recursion (cycles in call graph)
        try:
            cycles = list(nx.simple_cycles(self.call_graph))
            for cycle in cycles:
                recursive_funcs.extend(cycle)
        except Exception as e:
            self.logger.debug(f"Failed to detect indirect recursion cycles: {e}")

        return list(set(recursive_funcs))

    def get_vulnerability_patterns(self) -> Dict[str, Any]:
        """Get vulnerability patterns from advanced analysis"""
        patterns = {
            'buffer_overflow_candidates': [],
            'format_string_candidates': [],
            'integer_overflow_candidates': [],
            'use_after_free_candidates': [],
            'license_bypass_opportunities': []
        }

        # Extract patterns from each function
        for func_name, func_data in self.functions.items():
            graph = func_data.get('graph')
            if not graph:
                continue

            # Analyze nodes for vulnerability patterns
            for node, node_data in graph.nodes(data=True):
                ops = node_data.get('ops', [])

                for op in ops:
                    disasm = op.get('disasm', '').lower()

                    # Buffer overflow patterns
                    if any(unsafe_func in disasm for unsafe_func in ['strcpy', 'strcat', 'sprintf', 'gets']):
                        patterns['buffer_overflow_candidates'].append({
                            'function': func_name,
                            'address': hex(node),
                            'instruction': op.get('disasm', ''),
                            'type': 'unsafe_string_function'
                        })

                    # Format string patterns
                    if 'printf' in disasm and '%' not in disasm:
                        patterns['format_string_candidates'].append({
                            'function': func_name,
                            'address': hex(node),
                            'instruction': op.get('disasm', ''),
                            'type': 'printf_without_format'
                        })

                    # License bypass opportunities
                    if node_data.get('license_operations', 0) > 0:
                        patterns['license_bypass_opportunities'].append({
                            'function': func_name,
                            'address': hex(node),
                            'license_operations': node_data.get('license_operations', 0),
                            'block_type': node_data.get('block_type', 'unknown')
                        })

        return patterns

    def get_license_validation_analysis(self) -> Dict[str, Any]:
        """Get comprehensive license validation analysis"""
        analysis = {
            'license_functions': [],
            'validation_mechanisms': [],
            'bypass_opportunities': [],
            'complexity_assessment': 'unknown'
        }

        # Extract from cached analysis if available
        license_cache = self.analysis_cache.get('license_analysis', {})
        if license_cache:
            analysis.update({
                'license_functions': license_cache.get('license_functions', []),
                'validation_mechanisms': license_cache.get('validation_mechanisms', []),
                'bypass_opportunities': license_cache.get('bypass_opportunities', []),
                'analysis_confidence': license_cache.get('analysis_confidence', 0.0)
            })

        # Enhance with CFG-specific analysis
        license_related_functions = []
        for func_name, func_data in self.functions.items():
            graph = func_data.get('graph')
            if not graph:
                continue

            license_score = 0
            for _node, node_data in graph.nodes(data=True):
                license_score += node_data.get('license_operations', 0)

            if license_score > 0:
                license_related_functions.append({
                    'function': func_name,
                    'license_score': license_score,
                    'complexity': func_data.get('complexity', 1),
                    'size': func_data.get('size', 0)
                })

        analysis['cfg_license_functions'] = license_related_functions

        return analysis

    def get_code_complexity_analysis(self) -> Dict[str, Any]:
        """Get comprehensive code complexity analysis"""
        complexity_data = {
            'function_complexities': {},
            'overall_metrics': {},
            'complexity_distribution': {},
            'high_complexity_functions': []
        }

        complexities = []

        for func_name, func_data in self.functions.items():
            graph = func_data.get('graph')
            if not graph:
                continue

            # Calculate various complexity metrics
            cyclomatic_complexity = self._calculate_cyclomatic_complexity(graph)
            instruction_complexity = sum(node_data.get('instruction_count', 0)
                                       for _, node_data in graph.nodes(data=True))
            block_complexity = sum(node_data.get('complexity_score', 0)
                                 for _, node_data in graph.nodes(data=True))

            func_complexity = {
                'cyclomatic': cyclomatic_complexity,
                'instruction_count': instruction_complexity,
                'block_complexity': block_complexity,
                'combined_score': (cyclomatic_complexity * 2 + instruction_complexity * 0.1 + block_complexity)
            }

            complexity_data['function_complexities'][func_name] = func_complexity
            complexities.append(func_complexity['combined_score'])

            # Identify high complexity functions
            if func_complexity['combined_score'] > 50:  # Threshold for high complexity
                complexity_data['high_complexity_functions'].append({
                    'function': func_name,
                    'score': func_complexity['combined_score'],
                    'metrics': func_complexity
                })

        # Calculate overall metrics
        if complexities:
            if NUMPY_AVAILABLE:
                complexity_data['overall_metrics'] = {
                    'average_complexity': np.mean(complexities),
                    'max_complexity': np.max(complexities),
                    'min_complexity': np.min(complexities),
                    'std_deviation': np.std(complexities),
                    'total_functions': len(complexities)
                }
            else:
                # Use Python built-ins when numpy is not available
                import statistics
                complexity_data['overall_metrics'] = {
                    'average_complexity': statistics.mean(complexities),
                    'max_complexity': max(complexities),
                    'min_complexity': min(complexities),
                    'std_deviation': statistics.stdev(complexities) if len(complexities) > 1 else 0.0,
                    'total_functions': len(complexities)
                }

        return complexity_data

    def _calculate_cyclomatic_complexity(self, graph: nx.DiGraph) -> int:
        """Calculate cyclomatic complexity of a function graph"""
        if not graph or graph.number_of_nodes() == 0:
            return 1

        # McCabe's cyclomatic complexity: M = E - N + 2P
        # Where E = edges, N = nodes, P = connected components
        try:
            edges = graph.number_of_edges()
            nodes = graph.number_of_nodes()
            # For a single function, P = 1
            complexity = edges - nodes + 2
            return max(1, complexity)  # Minimum complexity is 1
        except (AttributeError, TypeError):
            return 1

    def get_cross_reference_analysis(self) -> Dict[str, Any]:
        """Get cross-reference analysis between functions"""
        xref_analysis = {
            'function_dependencies': {},
            'dependency_depth': {},
            'circular_dependencies': [],
            'isolated_functions': []
        }

        if not self.call_graph:
            return xref_analysis

        # Calculate dependencies for each function
        for func_name in self.call_graph.nodes():
            # Direct dependencies (functions this function calls)
            direct_deps = list(self.call_graph.successors(func_name))

            # Reverse dependencies (functions that call this function)
            reverse_deps = list(self.call_graph.predecessors(func_name))

            xref_analysis['function_dependencies'][func_name] = {
                'calls': direct_deps,
                'called_by': reverse_deps,
                'dependency_count': len(direct_deps),
                'reverse_dependency_count': len(reverse_deps)
            }

        # Find isolated functions
        for func_name in self.call_graph.nodes():
            if (self.call_graph.in_degree(func_name) == 0 and
                self.call_graph.out_degree(func_name) == 0):
                xref_analysis['isolated_functions'].append(func_name)

        # Find circular dependencies
        try:
            cycles = list(nx.simple_cycles(self.call_graph))
            xref_analysis['circular_dependencies'] = cycles
        except Exception as e:
            self.logger.debug(f"Failed to detect circular dependencies: {e}")

        return xref_analysis

    def find_license_check_patterns(self) -> List[Dict[str, Any]]:
        """Find potential license check patterns in the CFG"""
        if not self.graph:
            self.logger.error("No graph loaded")
            return []

        license_patterns = []

        # License-related keywords
        license_keywords = [
            'licen', 'key', 'activ', 'valid', 'check',
            'auth', 'verif', 'serial', 'regist'
        ]

        # Get function blocks
        blocks = self.functions[self.current_function]['blocks']

        # Check each block for license-related instructions
        for _block in blocks:
            for _op in _block.get('ops', []):
                disasm = _op.get('disasm', '').lower()

                # Check for license keywords in disassembly
                if any(_keyword in disasm for _keyword in license_keywords):
                    license_patterns.append({
                        'block_addr': _block['offset'],
                        'op_addr': _op['offset'],
                        'disasm': _op['disasm'],
                        'type': 'license_keyword'
                    })

                # Check for comparison followed by conditional jump
                if ('cmp' in disasm or 'test' in disasm) and _block.get('jump') and _block.get('fail'):
                    license_patterns.append({
                        'block_addr': _block['offset'],
                        'op_addr': _op['offset'],
                        'disasm': _op['disasm'],
                        'type': 'conditional_check'
                    })

        return license_patterns

    def generate_interactive_html(self, function_name: str, license_patterns: List[Dict], output_file: str) -> bool:
        """Generate an interactive HTML visualization of the CFG"""
        try:
            graph_data = self.get_graph_data(layout_type='spring')
            if not graph_data:
                return False

            from ...utils.reporting.html_templates import close_html, get_cfg_html_template

            # Create the HTML content using common template
            html_content = get_cfg_html_template(function_name) + f"""
                <style>
                    #controls {{
                        position: absolute;
                        top: 10px;
                        left: 10px;
                        background: rgba(255, 255, 255, 0.8);
                        padding: 10px;
                        border-radius: 4px;
                        z-index: 100;
                    }}
                </style>
            </head>
            <body>
                <div id="controls">
                    <h3>Control Flow Graph: {function_name}</h3>
                    <div>
                        <button id="zoom-in">Zoom In</button>
                        <button id="zoom-out">Zoom Out</button>
                        <button id="reset">Reset View</button>
                    </div>
                    <div style="margin-top: 10px;">
                        <p>Found {len(license_patterns)} potential license check points</p>
                        <ul style="font-size: 12px;">
                            {"".join(f'<li>{_pattern["type"]} at 0x{_pattern["op_addr"]:x}</li>' for _pattern in license_patterns[:5])}
                            {"<li>...</li>" if len(license_patterns) > 5 else ""}
                        </ul>
                    </div>
                </div>
                <div id="tooltip"></div>
                <script>
                    // Implementation would go here - simplified for brevity
                    console.log("CFG Visualization for {function_name}");
                </script>
            """ + close_html()

            # Write HTML to file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error generating HTML visualization: %s", e)
            return False

    def export_graph_image(self, output_file: str, format: str = 'png') -> bool:  # pylint: disable=redefined-builtin
        """Export the CFG as an image file"""
        if not MATPLOTLIB_AVAILABLE or not NETWORKX_AVAILABLE:
            self.logger.error("Matplotlib or NetworkX not available for image export")
            return False

        try:
            layout = self.get_graph_layout(layout_type='spring')
            if not layout:
                return False

            # Create matplotlib figure
            plt.figure(figsize=(12, 9))

            # Draw the graph
            nx.draw_networkx(
                self.graph,
                pos=layout,
                with_labels=True,
                node_color='lightblue',
                node_size=500,
                font_size=8,
                arrows=True,
                connectionstyle='arc3,rad=0.1'
            )

            # Add title
            plt.title(f"Control Flow Graph: {self.current_function}")

            # Remove axes
            plt.axis('off')

            # Save the figure
            plt.savefig(output_file, format=format, dpi=300, bbox_inches='tight')
            plt.close()

            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error exporting graph image: %s", e)
            return False

    def export_dot_file(self, output_file: str) -> bool:
        """Export the CFG as a DOT file"""
        if not NETWORKX_AVAILABLE:
            self.logger.error("NetworkX not available for DOT export")
            return False

        try:
            nx.drawing.nx_pydot.write_dot(self.graph, output_file)
            return True
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error exporting DOT file: %s", e)
            return False

    def analyze_cfg(self, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive advanced CFG analysis on a binary.

        Args:
            binary_path: Path to binary file to analyze (optional)

        Returns:
            Dictionary containing comprehensive CFG analysis results
        """
        results = {
            'binary_path': binary_path or self.binary_path,
            'functions_analyzed': 0,
            'complexity_metrics': {},
            'license_patterns': [],
            'graph_data': None,
            'advanced_analysis': {},
            'call_graph_analysis': {},
            'vulnerability_analysis': {},
            'similarity_analysis': {},
            'ai_analysis': {},
            'comprehensive_metrics': {},
            'errors': []
        }

        try:
            # Use provided path or existing path
            if binary_path:
                self.binary_path = binary_path

            if not self.binary_path:
                error_msg = "No binary path specified for advanced CFG analysis"
                self.logger.error(error_msg)
                results['errors'].append(error_msg)
                return results

            # Load the binary with advanced analysis
            if not self.load_binary(self.binary_path):
                error_msg = f"Failed to load binary for advanced CFG analysis: {self.binary_path}"
                self.logger.error(error_msg)
                results['errors'].append(error_msg)
                return results

            self.logger.info("Starting comprehensive CFG analysis for: %s", self.binary_path)

            # Get function list
            function_list = self.get_function_list()
            results['functions_analyzed'] = len(function_list)

            # Perform legacy license pattern analysis for compatibility
            all_license_patterns = []
            for function_name in function_list[:20]:  # Increased limit for advanced analysis
                try:
                    if self.set_current_function(function_name):
                        patterns = self.find_license_check_patterns()
                        if patterns:
                            all_license_patterns.extend(patterns)
                            self.logger.debug("Found %d patterns in function %s", len(patterns), function_name)
                except Exception as e:
                    self.logger.debug("Error analyzing function %s: %s", function_name, e)

            results['license_patterns'] = all_license_patterns

            # Get enhanced complexity metrics
            try:
                results['complexity_metrics'] = self.get_complexity_metrics()
                results['comprehensive_metrics'] = self.get_code_complexity_analysis()
            except Exception as e:
                self.logger.debug("Error getting complexity metrics: %s", e)
                results['complexity_metrics'] = {}

            # Get advanced analysis results
            try:
                results['advanced_analysis'] = self.get_advanced_analysis_results()
            except Exception as e:
                self.logger.debug("Error getting advanced analysis: %s", e)
                results['errors'].append(f"Advanced analysis error: {e}")

            # Get call graph analysis
            try:
                results['call_graph_analysis'] = self.get_call_graph_metrics()
            except Exception as e:
                self.logger.debug("Error getting call graph analysis: %s", e)

            # Get vulnerability analysis
            try:
                results['vulnerability_analysis'] = self.get_vulnerability_patterns()
            except Exception as e:
                self.logger.debug("Error getting vulnerability analysis: %s", e)

            # Get function similarity analysis
            try:
                results['similarity_analysis'] = {
                    'function_similarities': self.function_similarities,
                    'similarity_clusters': self._generate_similarity_clusters()
                }
            except Exception as e:
                self.logger.debug("Error getting similarity analysis: %s", e)

            # Get AI analysis results from cache
            try:
                ai_cache = self.analysis_cache.get('ai_analysis', {})
                if ai_cache:
                    results['ai_analysis'] = ai_cache
            except Exception as e:
                self.logger.debug("Error getting AI analysis: %s", e)

            # Get graph data for visualization
            try:
                if function_list and len(function_list) > 0:
                    # Get data for most complex function for visualization
                    complex_functions = results.get('comprehensive_metrics', {}).get('high_complexity_functions', [])
                    if complex_functions:
                        target_function = complex_functions[0]['function']
                    else:
                        target_function = function_list[0]

                    if self.set_current_function(target_function):
                        graph_data = self.get_graph_data()
                        if graph_data:
                            if isinstance(graph_data, dict):
                                graph_data['selected_function'] = target_function
                            results['graph_data'] = graph_data
            except Exception as e:
                self.logger.debug("Error getting graph data: %s", e)

            # Generate summary statistics
            try:
                results['summary'] = self._generate_analysis_summary(results)
            except Exception as e:
                self.logger.debug("Error generating summary: %s", e)

            self.logger.info("Advanced CFG analysis completed. Analyzed %d functions with comprehensive metrics",
                           results['functions_analyzed'])

        except Exception as e:
            error_msg = f"Advanced CFG analysis failed: {e}"
            self.logger.error(error_msg)
            results['errors'].append(error_msg)

        return results

    def _generate_similarity_clusters(self) -> List[List[str]]:
        """Generate clusters of similar functions"""
        clusters = []
        processed = set()

        for similarity_key, similarity_score in self.function_similarities.items():
            if similarity_score > 0.7:  # High similarity threshold
                func1, func2 = similarity_key.split(':')

                # Find existing cluster or create new one
                cluster_found = False
                for cluster in clusters:
                    if func1 in cluster or func2 in cluster:
                        if func1 not in cluster:
                            cluster.append(func1)
                        if func2 not in cluster:
                            cluster.append(func2)
                        cluster_found = True
                        break

                if not cluster_found:
                    clusters.append([func1, func2])

                processed.add(func1)
                processed.add(func2)

        return clusters

    def _generate_analysis_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive analysis summary"""
        summary = {
            'total_functions': results.get('functions_analyzed', 0),
            'license_related_functions': 0,
            'vulnerable_functions': 0,
            'high_complexity_functions': 0,
            'similar_function_clusters': 0,
            'call_graph_complexity': 'unknown',
            'overall_risk_assessment': 'unknown',
            'key_findings': []
        }

        # Count license-related functions
        license_analysis = results.get('advanced_analysis', {}).get('license_validation_analysis', {})
        summary['license_related_functions'] = len(license_analysis.get('cfg_license_functions', []))

        # Count vulnerable functions
        vuln_patterns = results.get('vulnerability_analysis', {})
        vulnerable_count = sum(len(patterns) for patterns in vuln_patterns.values())
        summary['vulnerable_functions'] = vulnerable_count

        # Count high complexity functions
        complexity_analysis = results.get('comprehensive_metrics', {})
        summary['high_complexity_functions'] = len(complexity_analysis.get('high_complexity_functions', []))

        # Count similarity clusters
        similarity_analysis = results.get('similarity_analysis', {})
        summary['similar_function_clusters'] = len(similarity_analysis.get('similarity_clusters', []))

        # Generate key findings
        findings = []

        if summary['license_related_functions'] > 0:
            findings.append(f"Identified {summary['license_related_functions']} license validation functions")

        if summary['vulnerable_functions'] > 0:
            findings.append(f"Found {summary['vulnerable_functions']} potential vulnerability patterns")

        if summary['high_complexity_functions'] > 0:
            findings.append(f"Detected {summary['high_complexity_functions']} high-complexity functions")

        if summary['similar_function_clusters'] > 0:
            findings.append(f"Found {summary['similar_function_clusters']} clusters of similar functions")

        # Assess call graph complexity
        call_graph_metrics = results.get('call_graph_analysis', {})
        if call_graph_metrics:
            avg_calls = call_graph_metrics.get('avg_calls_per_function', 0)
            if avg_calls > 5:
                summary['call_graph_complexity'] = 'high'
                findings.append("High inter-function connectivity detected")
            elif avg_calls > 2:
                summary['call_graph_complexity'] = 'medium'
            else:
                summary['call_graph_complexity'] = 'low'

        # Overall risk assessment
        risk_factors = 0
        if summary['vulnerable_functions'] > 5:
            risk_factors += 2
        elif summary['vulnerable_functions'] > 0:
            risk_factors += 1

        if summary['license_related_functions'] > 3:
            risk_factors += 1

        if summary['call_graph_complexity'] == 'high':
            risk_factors += 1

        if risk_factors >= 3:
            summary['overall_risk_assessment'] = 'high'
        elif risk_factors >= 1:
            summary['overall_risk_assessment'] = 'medium'
        else:
            summary['overall_risk_assessment'] = 'low'

        summary['key_findings'] = findings

        return summary

    def _show_error_dialog(self, title: str, message: str) -> None:
        """Show error dialog to user when in GUI mode."""
        if PYQT_AVAILABLE:
            try:
                QMessageBox.critical(None, title, message)
            except Exception as e:
                # Fallback to logging if dialog fails
                self.logger.error(f"Failed to show error dialog: {e}")
        # Always log the error regardless of dialog display
        self.logger.error(f"{title}: {message}")

    def export_json(self, output_path: str) -> bool:
        """Export comprehensive CFG analysis to JSON format.

        This exports all analysis data including:
        - Function graphs with full node/edge data
        - Call graph relationships
        - Complexity metrics
        - Vulnerability patterns
        - License validation analysis
        - AI analysis results
        - Cross-reference data

        Args:
            output_path: Path to save the JSON file

        Returns:
            bool: True if export successful, False otherwise
        """
        try:
            self.logger.info(f"Exporting CFG analysis to JSON: {output_path}")

            # Prepare comprehensive export data
            export_data = {
                "metadata": {
                    "binary_path": self.binary_path,
                    "export_timestamp": str(time.time()),
                    "export_version": "2.0",
                    "analysis_engines": {
                        "decompiler": self.decompiler is not None,
                        "vulnerability_engine": self.vulnerability_engine is not None,
                        "ai_engine": self.ai_engine is not None,
                        "string_analyzer": self.string_analyzer is not None,
                        "import_analyzer": self.import_analyzer is not None,
                        "scripting_engine": self.scripting_engine is not None
                    }
                },
                "functions": {},
                "call_graph": {},
                "cross_references": self.cross_references,
                "function_similarities": self.function_similarities,
                "analysis_results": self.analysis_cache,
                "comprehensive_metrics": {}
            }

            # Export function data with full graph information
            for func_name, func_data in self.functions.items():
                function_export = {
                    "address": func_data.get('addr', 0),
                    "size": func_data.get('size', 0),
                    "complexity": func_data.get('complexity', 1),
                    "calls": func_data.get('calls', 0),
                    "type": func_data.get('type', 'fcn'),
                    "blocks": [],
                    "edges": [],
                    "enhanced_data": func_data.get('enhanced_data', {})
                }

                # Export graph data if available
                graph = func_data.get('graph')
                if graph and NETWORKX_AVAILABLE:
                    # Export nodes with all attributes
                    for node, node_data in graph.nodes(data=True):
                        block_export = {
                            "address": node,
                            "size": node_data.get('size', 0),
                            "instruction_count": node_data.get('instruction_count', 0),
                            "has_call": node_data.get('has_call', False),
                            "has_jump": node_data.get('has_jump', False),
                            "has_return": node_data.get('has_return', False),
                            "crypto_operations": node_data.get('crypto_operations', 0),
                            "license_operations": node_data.get('license_operations', 0),
                            "block_type": node_data.get('block_type', 'unknown'),
                            "complexity_score": node_data.get('complexity_score', 0.0),
                            "instructions": []
                        }

                        # Export individual instructions
                        ops = node_data.get('ops', [])
                        for op in ops:
                            instruction_export = {
                                "offset": op.get('offset', 0),
                                "size": op.get('size', 0),
                                "disasm": op.get('disasm', ''),
                                "type": op.get('type', ''),
                                "bytes": op.get('bytes', '').hex() if 'bytes' in op and hasattr(op['bytes'], 'hex') else ''
                            }
                            block_export["instructions"].append(instruction_export)

                        function_export["blocks"].append(block_export)

                    # Export edges with attributes
                    for source, target, edge_data in graph.edges(data=True):
                        edge_export = {
                            "source": source,
                            "target": target,
                            "type": edge_data.get('type', 'unknown'),
                            "condition": edge_data.get('condition', '')
                        }
                        function_export["edges"].append(edge_export)

                export_data["functions"][func_name] = function_export

            # Export call graph
            if self.call_graph and NETWORKX_AVAILABLE:
                call_graph_export = {
                    "nodes": [],
                    "edges": []
                }

                # Export call graph nodes
                for node, node_data in self.call_graph.nodes(data=True):
                    call_graph_export["nodes"].append({
                        "function": node,
                        "address": node_data.get('addr', 0),
                        "size": node_data.get('size', 0),
                        "complexity": node_data.get('complexity', 1)
                    })

                # Export call graph edges
                for source, target, edge_data in self.call_graph.edges(data=True):
                    call_graph_export["edges"].append({
                        "source": source,
                        "target": target,
                        "type": edge_data.get('type', 'function_call'),
                        "from_addr": edge_data.get('from_addr', ''),
                        "to_addr": edge_data.get('to_addr', '')
                    })

                export_data["call_graph"] = call_graph_export

            # Get comprehensive metrics
            try:
                export_data["comprehensive_metrics"] = {
                    "complexity_metrics": self.get_code_complexity_analysis(),
                    "call_graph_metrics": self.get_call_graph_metrics(),
                    "vulnerability_patterns": self.get_vulnerability_patterns(),
                    "license_validation": self.get_license_validation_analysis(),
                    "cross_reference_analysis": self.get_cross_reference_analysis()
                }
            except Exception as e:
                self.logger.warning(f"Failed to export some metrics: {e}")

            # Handle special types in the export data
            def json_serializable(obj):
                """Convert non-serializable objects to JSON-friendly format."""
                if isinstance(obj, (nx.Graph, nx.DiGraph)):
                    # Convert NetworkX graphs to dict representation
                    return {
                        "nodes": list(obj.nodes()),
                        "edges": list(obj.edges()),
                        "graph_type": "networkx_graph"
                    }
                elif hasattr(obj, '__dict__'):
                    # Convert objects with __dict__ to dict
                    return obj.__dict__
                elif isinstance(obj, bytes):
                    # Convert bytes to hex string
                    return obj.hex()
                elif hasattr(obj, 'tolist'):
                    # Convert numpy arrays to lists
                    return obj.tolist()
                else:
                    # Default to string representation
                    return str(obj)

            # Write JSON file with proper formatting
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, sort_keys=True, default=json_serializable)

            # Verify the file was written successfully
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                self.logger.info(f"Successfully exported CFG analysis to {output_path}")

                # Log export statistics
                num_functions = len(export_data["functions"])
                num_blocks = sum(len(func.get("blocks", [])) for func in export_data["functions"].values())
                file_size_kb = os.path.getsize(output_path) / 1024

                self.logger.info(f"Export statistics: {num_functions} functions, {num_blocks} blocks, {file_size_kb:.2f} KB")
                return True
            else:
                self.logger.error("Export file verification failed")
                return False

        except Exception as e:
            self.logger.error(f"Failed to export CFG to JSON: {e}")
            self.logger.debug(f"Export error traceback: {traceback.format_exc()}")
            return False


async def run_deep_cfg_analysis(app):
    """Run deep CFG analysis."""
    if not app.binary_path:
        app.update_output.emit(
            log_message("[CFG Analysis] No binary selected."))
        return

    app.update_output.emit(
        log_message("[CFG Analysis] Starting deep CFG analysis..."))
    app.analyze_status.setText("Running CFG analysis...")

    try:
        if not PEFILE_AVAILABLE:
            app.update_output.emit(
                log_message("[CFG Analysis] pefile not available"))
            app.analyze_status.setText("pefile not available")
            return

        if not CAPSTONE_AVAILABLE:
            app.update_output.emit(
                log_message("[CFG Analysis] capstone not available"))
            app.analyze_status.setText("capstone not available")
            return

        if not NETWORKX_AVAILABLE:
            app.update_output.emit(
                log_message("[CFG Analysis] networkx not available"))
            app.analyze_status.setText("networkx not available")
            return

        pe = pefile.PE(app.binary_path)
        is_64bit = getattr(pe.FILE_HEADER, 'Machine', 0) == 0x8664
        if CAPSTONE_AVAILABLE and CS_MODE_64 is not None and CS_MODE_32 is not None:
            mode = CS_MODE_64 if is_64bit else CS_MODE_32
        else:
            mode = None

        # Find text section
        text_section = next(
            (_s for _s in pe.sections if b".text" in _s.Name), None)
        if not text_section:
            app.update_output.emit(
                log_message("[CFG Analysis] No .text section found"))
            app.analyze_status.setText("CFG analysis failed")
            return

        # Create disassembler
        code_data = text_section.get_data()
        code_addr = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress

        if CAPSTONE_AVAILABLE and mode is not None and Cs is not None and CS_ARCH_X86 is not None:
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True
        else:
            app.update_output.emit(
                log_message("[CFG Analysis] Capstone not available"))
            app.analyze_status.setText("Capstone not available")
            return

        # Disassemble
        app.update_output.emit(
            log_message("[CFG Analysis] Disassembling code..."))

        instructions = list(md.disasm(code_data, code_addr))
        app.update_output.emit(
            log_message(
                f"[CFG Analysis] Disassembled {len(instructions)} instructions"))

        # Build CFG
        app.update_output.emit(
            log_message("[CFG Analysis] Building control flow graph..."))

        G = nx.DiGraph()

        # Add nodes for _all instructions
        for _insn in instructions:
            G.add_node(
                _insn.address,
                instruction=f"{_insn.mnemonic} {_insn.op_str}")

        # Add edges
        for i, insn in enumerate(instructions):
            # Add normal flow edge
            if i + \
                    1 < len(instructions) and insn.mnemonic not in ["ret", "jmp"]:
                G.add_edge(insn.address,
                           instructions[i + 1].address,
                           type="normal")

            # Add jump edges
            if insn.mnemonic.startswith("j"):
                try:
                    # Extract jump target
                    if " 0x" in insn.op_str:
                        jump_target = int(insn.op_str.split("0x")[1], 16)
                        G.add_edge(insn.address, jump_target, type="jump")
                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error in cfg_explorer: %s", e)
                    app.update_output.emit(
                        log_message(
                            f"[CFG Analysis] Error parsing jump: {e}"))

        # Save full CFG
        app.update_output.emit(
            log_message("[CFG Analysis] Saving CFG visualization..."))

        # Use NetworkX to output DOT file
        try:
            nx.drawing.nx_pydot.write_dot(G, "full_cfg.dot")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in cfg_explorer: %s", e)
            app.update_output.emit(
                log_message(f"[CFG Analysis] Could not write DOT file: {e}"))

        # Generate a smaller CFG focused on license checks
        app.update_output.emit(
            log_message("[CFG Analysis] Analyzing for license checks..."))

        license_keywords = [
            "licens",
            "registr",
            "activ",
            "serial",
            "key",
            "trial",
            "valid"]

        # Find nodes with license-related instructions
        license_nodes = []
        for node, data in G.nodes(data=True):
            instruction = data.get("instruction", "").lower()
            if any(_keyword in instruction for _keyword in license_keywords):
                license_nodes.append(node)

        app.update_output.emit(
            log_message(
                f"[CFG Analysis] Found {len(license_nodes)} license-related nodes"))

        # Create a subgraph with these nodes and their neighbors
        if license_nodes:
            license_subgraph = G.subgraph(license_nodes).copy()

            # Add immediate predecessors and successors
            for _node in list(license_subgraph.nodes()):
                predecessors = list(G.predecessors(_node))
                successors = list(G.successors(_node))

                license_subgraph.add_nodes_from(predecessors)
                license_subgraph.add_nodes_from(successors)

                for _pred in predecessors:
                    license_subgraph.add_edge(
                        _pred, _node, **G.get_edge_data(_pred, _node, {}))

                for _succ in successors:
                    license_subgraph.add_edge(
                        _node, _succ, **G.get_edge_data(_node, _succ, {}))

            # Save license-focused CFG
            try:
                nx.drawing.nx_pydot.write_dot(license_subgraph, "license_cfg.dot")
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in cfg_explorer: %s", e)
                app.update_output.emit(
                    log_message(f"[CFG Analysis] Could not write license DOT file: {e}"))

            # Try to generate PDF or SVG if graphviz is available
            try:
                if SUBPROCESS_AVAILABLE:
                    from ...utils.system.subprocess_utils import async_run_subprocess
                    returncode, stdout, stderr = await async_run_subprocess(
                        ["dot", "-Tsvg", "-o", "license_cfg.svg", "license_cfg.dot"],
                        timeout=30,
                        capture_output=True,
                        text=True
                    )
                    app.update_output.emit(
                        log_message("[CFG Analysis] Generated license_cfg.svg"))
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in cfg_explorer: %s", e)
                app.update_output.emit(
                    log_message(
                        f"[CFG Analysis] Could not generate SVG: {e}"))

        app.update_output.emit(log_message("[CFG Analysis] Analysis complete"))
        app.analyze_status.setText("CFG analysis complete")

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in cfg_explorer: %s", e)
        app.update_output.emit(log_message(f"[CFG Analysis] Error: {e}"))
        app.analyze_status.setText(f"CFG analysis error: {str(e)}")


def run_cfg_explorer(app):
    """Initialize and run the CFG explorer with GUI integration"""
    if not PYQT_AVAILABLE:
        print("PyQt6 not available - cannot run GUI version")
        return

    app.update_output.emit(log_message("[CFG Explorer] Initializing CFG explorer..."))

    # Get binary path from UI
    if not app.binary_path:
        app.update_output.emit(log_message("[CFG Explorer] No binary path specified"))

        # Ask for binary path
        binary_path, _ = QFileDialog.getOpenFileName(
            app,
            "Select Binary",
            "",
            "All Files (*)"
        )

        if not binary_path:
            app.update_output.emit(log_message("[CFG Explorer] Cancelled"))
            return

        app.binary_path = binary_path

    # Create and configure the explorer
    explorer = CFGExplorer(app.binary_path)

    # Load the binary
    app.update_output.emit(log_message(f"[CFG Explorer] Loading binary: {app.binary_path}"))
    if explorer.load_binary():
        app.update_output.emit(log_message(f"[CFG Explorer] Loaded binary: {app.binary_path}"))
        app.cfg_explorer_instance = explorer

        # Get function list
        function_list = explorer.get_function_list()

        # Ask user to select a function
        function_name, ok = QInputDialog.getItem(
            app,
            "Select Function",
            "Select a function to analyze:",
            function_list,
            0,
            False
        )

        if not ok:
            app.update_output.emit(log_message("[CFG Explorer] Cancelled"))
            return

        # Set current function
        if explorer.set_current_function(function_name):
            app.update_output.emit(log_message(f"[CFG Explorer] Analyzing function: {function_name}"))

            # Find license check patterns
            license_patterns = explorer.find_license_check_patterns()

            if license_patterns:
                app.update_output.emit(log_message(f"[CFG Explorer] Found {len(license_patterns)} potential license check patterns in {function_name}"))

                # Display patterns
                for _pattern in license_patterns:
                    app.update_output.emit(log_message(
                        f"[CFG Explorer] {_pattern['type']} at 0x{_pattern['op_addr']:x}: {_pattern['disasm']}"
                    ))

            else:
                app.update_output.emit(log_message("[CFG Explorer] No license check patterns found"))
        else:
            app.update_output.emit(log_message(f"[CFG Explorer] Failed to set function: {function_name}"))
    else:
        app.update_output.emit(log_message(f"[CFG Explorer] Failed to load binary: {app.binary_path}"))


def log_message(message: str) -> str:
    """Helper function for log message formatting"""
    return message


__all__ = ['CFGExplorer', 'run_cfg_explorer', 'run_deep_cfg_analysis']
