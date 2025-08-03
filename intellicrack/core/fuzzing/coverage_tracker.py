"""
Coverage Tracker - Advanced coverage tracking for fuzzing optimization

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

import asyncio
import logging
import os
import time
import threading
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import json
import struct
import subprocess

from ...utils.logger import get_logger

logger = get_logger(__name__)


class CoverageType(Enum):
    """Types of coverage tracking."""
    BASIC_BLOCK = "basic_block"
    EDGE = "edge"
    FUNCTION = "function"
    LINE = "line"
    BRANCH = "branch"
    PATH = "path"


@dataclass
class BasicBlockCoverage:
    """Basic block coverage information."""
    address: int
    size: int
    hit_count: int = 0
    first_hit_time: Optional[float] = None
    last_hit_time: Optional[float] = None
    function_name: Optional[str] = None
    module_name: Optional[str] = None


@dataclass
class EdgeCoverage:
    """Edge coverage between basic blocks."""
    source_address: int
    target_address: int
    hit_count: int = 0
    first_hit_time: Optional[float] = None
    last_hit_time: Optional[float] = None
    edge_type: str = "direct"  # direct, conditional, call, return


@dataclass
class FunctionCoverage:
    """Function-level coverage tracking."""
    address: int
    name: str
    module_name: str
    hit_count: int = 0
    first_hit_time: Optional[float] = None
    last_hit_time: Optional[float] = None
    total_blocks: int = 0
    covered_blocks: int = 0
    complexity: int = 0


@dataclass
class CoverageData:
    """Comprehensive coverage data."""
    basic_blocks: Dict[int, BasicBlockCoverage] = field(default_factory=dict)
    edges: Dict[Tuple[int, int], EdgeCoverage] = field(default_factory=dict)
    functions: Dict[int, FunctionCoverage] = field(default_factory=dict)
    
    # Summary statistics
    total_blocks_hit: int = 0
    total_edges_hit: int = 0
    total_functions_hit: int = 0
    
    # New coverage tracking
    new_blocks_this_run: Set[int] = field(default_factory=set)
    new_edges_this_run: Set[Tuple[int, int]] = field(default_factory=set)
    new_functions_this_run: Set[int] = field(default_factory=set)
    
    # Metadata
    timestamp: float = field(default_factory=time.time)
    target_binary: str = ""
    
    def get_coverage_percentages(self, total_blocks: int, total_edges: int, total_functions: int) -> Dict[str, float]:
        """Calculate coverage percentages."""
        return {
            "block_coverage": (self.total_blocks_hit / max(1, total_blocks)) * 100,
            "edge_coverage": (self.total_edges_hit / max(1, total_edges)) * 100,
            "function_coverage": (self.total_functions_hit / max(1, total_functions)) * 100
        }


class CoverageTracker:
    """
    Advanced coverage tracking system for fuzzing optimization.
    
    This class provides comprehensive coverage tracking capabilities including
    basic block, edge, and function coverage with real-time analysis and
    optimization guidance for fuzzing campaigns.
    """
    
    def __init__(self, target_path: str, coverage_types: List[str]):
        """Initialize coverage tracker."""
        self.target_path = target_path
        self.coverage_types = [CoverageType(ct) for ct in coverage_types]
        self.logger = logging.getLogger(__name__)
        
        # Coverage data
        self.coverage_data = CoverageData(target_binary=target_path)
        self.baseline_coverage = None
        
        # Target analysis
        self.total_blocks = 0
        self.total_edges = 0
        self.total_functions = 0
        self.target_analysis = {}
        
        # Tracking state
        self.tracking_enabled = False
        self.coverage_lock = threading.Lock()
        
        # Performance optimization
        self.coverage_cache = {}
        self.cache_hit_ratio = 0.0
        
        # Analysis tools integration
        self.radare2_available = False
        self.ghidra_available = False
        self.frida_available = False
        
        self.logger.info(f"Coverage tracker initialized for {target_path}")
    
    async def initialize(self):
        """Initialize coverage tracking system."""
        try:
            # Check available analysis tools
            await self._check_analysis_tools()
            
            # Analyze target for static coverage information
            await self._analyze_target_static()
            
            # Initialize coverage tracking mechanisms
            await self._initialize_coverage_mechanisms()
            
            self.logger.info("Coverage tracker initialization complete")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize coverage tracker: {e}")
            raise
    
    async def _check_analysis_tools(self):
        """Check availability of analysis tools."""
        # Check for Radare2
        try:
            result = subprocess.run(["r2", "-v"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self.radare2_available = True
                self.logger.info("Radare2 available for coverage analysis")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Check for Frida
        try:
            import frida
            self.frida_available = True
            self.logger.info("Frida available for dynamic coverage tracking")
        except ImportError:
            pass
        
        # Note tool availability
        available_tools = []
        if self.radare2_available:
            available_tools.append("Radare2")
        if self.frida_available:
            available_tools.append("Frida")
        
        if available_tools:
            self.logger.info(f"Analysis tools available: {', '.join(available_tools)}")
        else:
            self.logger.warning("No analysis tools available - using fallback methods")
    
    async def _analyze_target_static(self):
        """Perform static analysis to determine coverage targets."""
        try:
            if self.radare2_available:
                await self._analyze_with_radare2()
            else:
                await self._analyze_with_fallback()
            
            self.logger.info(f"Target analysis: {self.total_blocks} blocks, "
                           f"{self.total_edges} edges, {self.total_functions} functions")
            
        except Exception as e:
            self.logger.error(f"Static analysis failed: {e}")
            # Use fallback values
            self.total_blocks = 1000
            self.total_edges = 1500
            self.total_functions = 100
    
    async def _analyze_with_radare2(self):
        """Analyze target using Radare2."""
        try:
            # Run Radare2 analysis
            cmd = [
                "r2", "-q", "-A", "-c",
                "aflc;agC;aflc~fcn;agC~?", 
                self.target_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                
                # Parse function count
                for line in lines:
                    if 'fcn.' in line:
                        self.total_functions = len([l for l in lines if 'fcn.' in l])
                        break
                
                # Estimate blocks and edges
                self.total_blocks = self.total_functions * 10  # Rough estimate
                self.total_edges = self.total_blocks * 1.5
                
                # Get more detailed analysis
                await self._get_detailed_radare2_analysis()
            
        except Exception as e:
            self.logger.warning(f"Radare2 analysis failed: {e}")
            await self._analyze_with_fallback()
    
    async def _get_detailed_radare2_analysis(self):
        """Get detailed analysis from Radare2."""
        try:
            # Get basic block information
            cmd = ["r2", "-q", "-A", "-c", "afb", self.target_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse basic block information
                blocks = []
                for line in result.stdout.split('\n'):
                    if line.strip() and 'addr=' in line:
                        # Extract block information
                        parts = line.split()
                        addr_part = [p for p in parts if p.startswith('addr=')]
                        if addr_part:
                            addr_str = addr_part[0].split('=')[1]
                            try:
                                addr = int(addr_str, 16)
                                blocks.append(addr)
                            except ValueError:
                                continue
                
                self.total_blocks = len(blocks)
                
                # Store block addresses for coverage tracking
                self.target_analysis['blocks'] = blocks
            
            # Get function information
            cmd = ["r2", "-q", "-A", "-c", "aflj", self.target_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                try:
                    functions_json = json.loads(result.stdout)
                    self.total_functions = len(functions_json)
                    
                    # Store function information
                    functions = {}
                    for func in functions_json:
                        addr = func.get('offset', 0)
                        name = func.get('name', f'fcn_{addr:x}')
                        functions[addr] = {
                            'name': name,
                            'size': func.get('size', 0),
                            'complexity': func.get('cc', 1)
                        }
                    
                    self.target_analysis['functions'] = functions
                    
                except json.JSONDecodeError:
                    pass
            
        except Exception as e:
            self.logger.warning(f"Detailed Radare2 analysis failed: {e}")
    
    async def _analyze_with_fallback(self):
        """Fallback analysis using basic file inspection."""
        try:
            file_size = os.path.getsize(self.target_path)
            
            # Rough estimates based on file size
            if file_size < 100 * 1024:  # < 100KB
                self.total_functions = 50
                self.total_blocks = 500
            elif file_size < 1024 * 1024:  # < 1MB
                self.total_functions = 200
                self.total_blocks = 2000
            elif file_size < 10 * 1024 * 1024:  # < 10MB
                self.total_functions = 1000
                self.total_blocks = 10000
            else:  # >= 10MB
                self.total_functions = 5000
                self.total_blocks = 50000
            
            self.total_edges = int(self.total_blocks * 1.3)
            
            self.logger.info("Using fallback analysis estimates")
            
        except Exception as e:
            self.logger.error(f"Fallback analysis failed: {e}")
            # Use minimal defaults
            self.total_functions = 100
            self.total_blocks = 1000
            self.total_edges = 1300
    
    async def _initialize_coverage_mechanisms(self):
        """Initialize coverage tracking mechanisms."""
        if self.frida_available and CoverageType.BASIC_BLOCK in self.coverage_types:
            await self._initialize_frida_coverage()
        else:
            await self._initialize_fallback_coverage()
    
    async def _initialize_frida_coverage(self):
        """Initialize Frida-based coverage tracking."""
        try:
            import frida
            
            # Create Frida script for coverage tracking
            self.frida_script = """
            var coverage_data = {};
            var block_hits = {};
            var edge_hits = {};
            var function_hits = {};
            
            // Hook basic block execution
            function track_basic_block(address) {
                var addr_str = address.toString();
                if (!(addr_str in block_hits)) {
                    block_hits[addr_str] = {
                        count: 0,
                        first_hit: Date.now()
                    };
                }
                block_hits[addr_str].count++;
                block_hits[addr_str].last_hit = Date.now();
            }
            
            // Hook function calls
            function track_function(address, name) {
                var addr_str = address.toString();
                if (!(addr_str in function_hits)) {
                    function_hits[addr_str] = {
                        name: name,
                        count: 0,
                        first_hit: Date.now()
                    };
                }
                function_hits[addr_str].count++;
                function_hits[addr_str].last_hit = Date.now();
            }
            
            // Export coverage data
            rpc.exports.getCoverageData = function() {
                return {
                    blocks: block_hits,
                    functions: function_hits,
                    edges: edge_hits
                };
            };
            
            rpc.exports.resetCoverage = function() {
                block_hits = {};
                edge_hits = {};
                function_hits = {};
            };
            """
            
            self.logger.info("Frida coverage tracking initialized")
            
        except Exception as e:
            self.logger.error(f"Frida initialization failed: {e}")
            await self._initialize_fallback_coverage()
    
    async def _initialize_fallback_coverage(self):
        """Initialize fallback coverage tracking."""
        # Simple coverage tracking using execution monitoring
        self.fallback_coverage = {
            "execution_count": 0,
            "estimated_coverage": 0.0,
            "coverage_history": []
        }
        
        self.logger.info("Fallback coverage tracking initialized")
    
    async def analyze_target(self, target_path: str) -> Dict[str, Any]:
        """
        Analyze target and return coverage information.
        
        Returns:
            Dictionary with total blocks, edges, and functions
        """
        return {
            "total_blocks": self.total_blocks,
            "total_edges": self.total_edges,
            "total_functions": self.total_functions,
            "analysis_method": "radare2" if self.radare2_available else "fallback"
        }
    
    async def update_coverage(self, execution_data: Dict[str, Any]) -> bool:
        """
        Update coverage data from execution.
        
        Args:
            execution_data: Execution data containing coverage information
            
        Returns:
            True if new coverage was found
        """
        new_coverage_found = False
        
        with self.coverage_lock:
            if self.frida_available:
                new_coverage_found = await self._update_frida_coverage(execution_data)
            else:
                new_coverage_found = await self._update_fallback_coverage(execution_data)
            
            # Update summary statistics
            self._update_coverage_statistics()
        
        return new_coverage_found
    
    async def _update_frida_coverage(self, execution_data: Dict[str, Any]) -> bool:
        """Update coverage using Frida data."""
        new_coverage = False
        
        # Extract coverage data from execution
        frida_data = execution_data.get("frida_coverage", {})
        
        # Update basic block coverage
        for addr_str, block_data in frida_data.get("blocks", {}).items():
            try:
                addr = int(addr_str)
                
                if addr not in self.coverage_data.basic_blocks:
                    # New basic block discovered
                    self.coverage_data.basic_blocks[addr] = BasicBlockCoverage(
                        address=addr,
                        size=block_data.get("size", 1),
                        hit_count=block_data["count"],
                        first_hit_time=block_data.get("first_hit", time.time())
                    )
                    self.coverage_data.new_blocks_this_run.add(addr)
                    new_coverage = True
                else:
                    # Update existing block
                    block = self.coverage_data.basic_blocks[addr]
                    block.hit_count += block_data["count"]
                    block.last_hit_time = block_data.get("last_hit", time.time())
                    
            except (ValueError, KeyError):
                continue
        
        # Update function coverage
        for addr_str, func_data in frida_data.get("functions", {}).items():
            try:
                addr = int(addr_str)
                
                if addr not in self.coverage_data.functions:
                    # New function discovered
                    self.coverage_data.functions[addr] = FunctionCoverage(
                        address=addr,
                        name=func_data.get("name", f"func_{addr:x}"),
                        module_name="main",
                        hit_count=func_data["count"],
                        first_hit_time=func_data.get("first_hit", time.time())
                    )
                    self.coverage_data.new_functions_this_run.add(addr)
                    new_coverage = True
                else:
                    # Update existing function
                    func = self.coverage_data.functions[addr]
                    func.hit_count += func_data["count"]
                    func.last_hit_time = func_data.get("last_hit", time.time())
                    
            except (ValueError, KeyError):
                continue
        
        return new_coverage
    
    async def _update_fallback_coverage(self, execution_data: Dict[str, Any]) -> bool:
        """Update coverage using fallback method."""
        # Simple heuristic-based coverage estimation
        execution_time = execution_data.get("execution_time", 0)
        api_calls = execution_data.get("api_calls", [])
        
        # Estimate coverage based on execution characteristics
        base_coverage = min(0.1, execution_time / 10.0)  # Time-based estimate
        api_coverage = min(0.2, len(api_calls) / 100.0)  # API call diversity
        
        estimated_coverage = base_coverage + api_coverage
        
        # Check if this represents new coverage
        current_max = max([entry["coverage"] for entry in 
                          self.fallback_coverage["coverage_history"]] or [0])
        
        new_coverage = estimated_coverage > current_max * 1.05  # 5% improvement threshold
        
        # Update fallback coverage data
        self.fallback_coverage["execution_count"] += 1
        self.fallback_coverage["estimated_coverage"] = max(
            self.fallback_coverage["estimated_coverage"],
            estimated_coverage
        )
        
        self.fallback_coverage["coverage_history"].append({
            "timestamp": time.time(),
            "coverage": estimated_coverage,
            "execution_time": execution_time,
            "api_calls": len(api_calls)
        })
        
        # Keep history manageable
        if len(self.fallback_coverage["coverage_history"]) > 1000:
            self.fallback_coverage["coverage_history"] = \
                self.fallback_coverage["coverage_history"][-500:]
        
        return new_coverage
    
    def _update_coverage_statistics(self):
        """Update coverage summary statistics."""
        self.coverage_data.total_blocks_hit = len(self.coverage_data.basic_blocks)
        self.coverage_data.total_edges_hit = len(self.coverage_data.edges)
        self.coverage_data.total_functions_hit = len(self.coverage_data.functions)
    
    def get_coverage_metrics(self) -> Dict[str, Any]:
        """Get current coverage metrics."""
        if self.frida_available:
            return self._get_frida_metrics()
        else:
            return self._get_fallback_metrics()
    
    def _get_frida_metrics(self) -> Dict[str, Any]:
        """Get coverage metrics from Frida data."""
        percentages = self.coverage_data.get_coverage_percentages(
            self.total_blocks, self.total_edges, self.total_functions
        )
        
        return {
            "basic_blocks": {
                "covered": self.coverage_data.total_blocks_hit,
                "total": self.total_blocks,
                "percentage": percentages["block_coverage"],
                "new_this_run": len(self.coverage_data.new_blocks_this_run)
            },
            "edges": {
                "covered": self.coverage_data.total_edges_hit,
                "total": self.total_edges,
                "percentage": percentages["edge_coverage"],
                "new_this_run": len(self.coverage_data.new_edges_this_run)
            },
            "functions": {
                "covered": self.coverage_data.total_functions_hit,
                "total": self.total_functions,
                "percentage": percentages["function_coverage"],
                "new_this_run": len(self.coverage_data.new_functions_this_run)
            },
            "overall_score": (
                percentages["block_coverage"] * 0.5 +
                percentages["function_coverage"] * 0.3 +
                percentages["edge_coverage"] * 0.2
            )
        }
    
    def _get_fallback_metrics(self) -> Dict[str, Any]:
        """Get coverage metrics from fallback method."""
        estimated_coverage = self.fallback_coverage["estimated_coverage"] * 100
        
        return {
            "basic_blocks": {
                "covered": int(self.total_blocks * estimated_coverage / 100),
                "total": self.total_blocks,
                "percentage": estimated_coverage,
                "new_this_run": 0
            },
            "edges": {
                "covered": int(self.total_edges * estimated_coverage / 100),
                "total": self.total_edges,
                "percentage": estimated_coverage,
                "new_this_run": 0
            },
            "functions": {
                "covered": int(self.total_functions * estimated_coverage / 100),
                "total": self.total_functions,
                "percentage": estimated_coverage,
                "new_this_run": 0
            },
            "overall_score": estimated_coverage,
            "execution_count": self.fallback_coverage["execution_count"],
            "method": "fallback_estimation"
        }
    
    def get_hot_spots(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Get most frequently hit coverage points."""
        hot_spots = []
        
        # Get top basic blocks by hit count
        sorted_blocks = sorted(
            self.coverage_data.basic_blocks.values(),
            key=lambda x: x.hit_count,
            reverse=True
        )
        
        for block in sorted_blocks[:top_n]:
            hot_spots.append({
                "type": "basic_block",
                "address": f"0x{block.address:x}",
                "hit_count": block.hit_count,
                "function": block.function_name or "unknown",
                "module": block.module_name or "main"
            })
        
        # Get top functions by hit count
        sorted_functions = sorted(
            self.coverage_data.functions.values(),
            key=lambda x: x.hit_count,
            reverse=True
        )
        
        for func in sorted_functions[:top_n]:
            hot_spots.append({
                "type": "function",
                "address": f"0x{func.address:x}",
                "name": func.name,
                "hit_count": func.hit_count,
                "module": func.module_name,
                "coverage_ratio": func.covered_blocks / max(1, func.total_blocks)
            })
        
        return hot_spots
    
    def get_cold_spots(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Get least frequently hit or uncovered areas."""
        cold_spots = []
        
        # Identify uncovered functions from static analysis
        static_functions = self.target_analysis.get("functions", {})
        for addr, func_info in static_functions.items():
            if addr not in self.coverage_data.functions:
                cold_spots.append({
                    "type": "uncovered_function",
                    "address": f"0x{addr:x}",
                    "name": func_info["name"],
                    "size": func_info["size"],
                    "complexity": func_info.get("complexity", 1)
                })
        
        # Get low-hit functions
        low_hit_functions = [
            func for func in self.coverage_data.functions.values()
            if func.hit_count <= 2
        ]
        
        sorted_low_hit = sorted(low_hit_functions, key=lambda x: x.hit_count)
        for func in sorted_low_hit[:top_n]:
            cold_spots.append({
                "type": "low_hit_function",
                "address": f"0x{func.address:x}",
                "name": func.name,
                "hit_count": func.hit_count,
                "module": func.module_name
            })
        
        return cold_spots[:top_n]
    
    def reset_session_coverage(self):
        """Reset coverage data for new session."""
        with self.coverage_lock:
            self.coverage_data.new_blocks_this_run.clear()
            self.coverage_data.new_edges_this_run.clear()
            self.coverage_data.new_functions_this_run.clear()
    
    def export_coverage_data(self, output_path: str):
        """Export coverage data to file."""
        try:
            export_data = {
                "target_binary": self.coverage_data.target_binary,
                "timestamp": self.coverage_data.timestamp,
                "totals": {
                    "blocks": self.total_blocks,
                    "edges": self.total_edges,
                    "functions": self.total_functions
                },
                "coverage": {
                    "blocks_hit": self.coverage_data.total_blocks_hit,
                    "edges_hit": self.coverage_data.total_edges_hit,
                    "functions_hit": self.coverage_data.total_functions_hit
                },
                "detailed_blocks": [
                    {
                        "address": f"0x{block.address:x}",
                        "size": block.size,
                        "hit_count": block.hit_count,
                        "function": block.function_name,
                        "module": block.module_name
                    }
                    for block in self.coverage_data.basic_blocks.values()
                ],
                "detailed_functions": [
                    {
                        "address": f"0x{func.address:x}",
                        "name": func.name,
                        "module": func.module_name,
                        "hit_count": func.hit_count,
                        "total_blocks": func.total_blocks,
                        "covered_blocks": func.covered_blocks,
                        "complexity": func.complexity
                    }
                    for func in self.coverage_data.functions.values()
                ]
            }
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.info(f"Coverage data exported to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to export coverage data: {e}")
    
    def get_coverage_guidance(self) -> Dict[str, Any]:
        """Get guidance for improving coverage."""
        metrics = self.get_coverage_metrics()
        guidance = {
            "recommendations": [],
            "priority_targets": [],
            "strategy_suggestions": []
        }
        
        # Analyze current coverage state
        block_coverage = metrics["basic_blocks"]["percentage"]
        function_coverage = metrics["functions"]["percentage"]
        
        # Generate recommendations
        if block_coverage < 30:
            guidance["recommendations"].append({
                "type": "exploration",
                "message": "Low basic block coverage - focus on exploration strategies",
                "suggested_mutations": ["random", "dictionary", "arithmetic"]
            })
        elif block_coverage < 70:
            guidance["recommendations"].append({
                "type": "targeted",
                "message": "Moderate coverage - use targeted mutation strategies",
                "suggested_mutations": ["structure_aware", "ai_guided"]
            })
        else:
            guidance["recommendations"].append({
                "type": "exploitation",
                "message": "High coverage achieved - focus on edge cases and exploitation",
                "suggested_mutations": ["boundary_testing", "format_fuzzing"]
            })
        
        # Identify priority targets
        cold_spots = self.get_cold_spots(5)
        for spot in cold_spots:
            guidance["priority_targets"].append({
                "address": spot["address"],
                "type": spot["type"],
                "reason": "Uncovered or low-hit area with potential for new discoveries"
            })
        
        # Strategy suggestions based on coverage patterns
        new_coverage_rate = len(self.coverage_data.new_blocks_this_run)
        if new_coverage_rate == 0:
            guidance["strategy_suggestions"].append({
                "strategy": "diversification",
                "reason": "No new coverage found - try different mutation strategies"
            })
        elif new_coverage_rate > 10:
            guidance["strategy_suggestions"].append({
                "strategy": "exploitation",
                "reason": "High new coverage rate - continue with current strategies"
            })
        
        return guidance