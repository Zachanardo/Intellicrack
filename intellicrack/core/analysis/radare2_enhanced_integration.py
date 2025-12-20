"""Enhanced Radare2 Integration with Comprehensive Error Handling and Recovery.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellirack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellirack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from ...utils.logger import get_logger
from .radare2_ai_integration import R2AIEngine
from .radare2_binary_diff import R2BinaryDiff
from .radare2_bypass_generator import R2BypassGenerator
from .radare2_decompiler import R2DecompilationEngine
from .radare2_error_handler import get_error_handler, r2_error_context
from .radare2_esil import ESILAnalysisEngine
from .radare2_graph_view import R2GraphGenerator
from .radare2_imports import R2ImportExportAnalyzer
from .radare2_json_standardizer import standardize_r2_result
from .radare2_performance_metrics import create_performance_monitor
from .radare2_scripting import R2ScriptingEngine
from .radare2_signatures import R2SignatureAnalyzer
from .radare2_strings import R2StringAnalyzer
from .radare2_vulnerability_engine import R2VulnerabilityEngine


logger = get_logger(__name__)

try:
    import r2pipe
except ImportError as e:
    logger.error("Import error in radare2_enhanced_integration: %s", e)
    r2pipe = None

error_handler = get_error_handler()


class EnhancedR2Integration:
    """Enhanced radare2 integration with comprehensive error handling, recovery,.

    performance optimization, and real-time capabilities.

    This class provides:
    - Robust error handling and automatic recovery
    - Performance monitoring and optimization
    - Real-time analysis capabilities
    - Comprehensive logging and metrics
    - Thread-safe operations
    - Circuit breaker pattern implementation
    """

    def __init__(self, binary_path: str, config: dict[str, Any] | None = None) -> None:
        """Initialize the enhanced Radare2 integration.

        Args:
            binary_path: Path to the binary file to analyze.
            config: Optional configuration dictionary for customizing behavior.

        """
        self.binary_path = binary_path
        self.config = config or {}
        self.logger = logger
        self.error_handler = error_handler

        # Check r2pipe availability
        if r2pipe is None:
            self.logger.warning("r2pipe not available, some functionality may be limited")
            self.r2pipe_available = False
        else:
            self.r2pipe_available = True

        # Performance and monitoring
        self.performance_stats = {
            "analysis_times": {},
            "cache_hits": 0,
            "cache_misses": 0,
            "errors_handled": 0,
            "recoveries_successful": 0,
        }

        # Initialize performance monitor
        self.performance_monitor = create_performance_monitor(enable_real_time=self.config.get("enable_performance_monitoring", True))
        self.performance_monitor.start_session(f"r2_session_{binary_path}")

        # Thread safety
        self._lock = threading.RLock()

        # Analysis components with error handling
        self.components = {}
        self._initialize_components()

        # Results cache with TTL
        self.results_cache = {}
        self.cache_ttl = self.config.get("cache_ttl", 300)  # 5 minutes default

        # Real-time monitoring
        self.monitoring_enabled = self.config.get("real_time_monitoring", False)
        self.monitoring_thread = None

        self.logger.info("EnhancedR2Integration initialized for %s", binary_path)

    def _initialize_components(self) -> None:
        """Initialize all analysis components with error handling."""
        if not self.r2pipe_available:
            self.logger.warning("r2pipe not available, skipping component initialization")
            return

        component_classes = {
            "decompiler": R2DecompilationEngine,
            "esil": ESILAnalysisEngine,
            "strings": R2StringAnalyzer,
            "signatures": R2SignatureAnalyzer,
            "imports": R2ImportExportAnalyzer,
            "vulnerability": R2VulnerabilityEngine,
            "ai": R2AIEngine,
            "bypass": R2BypassGenerator,
            "diff": R2BinaryDiff,
            "scripting": R2ScriptingEngine,
            "graph": R2GraphGenerator,
        }

        for name, component_class in component_classes.items():
            try:
                with r2_error_context(f"init_{name}_component", binary_path=self.binary_path):
                    if name == "diff":
                        # Initialize binary diff with primary binary only
                        self.components[name] = R2BinaryDiff(self.binary_path)
                    else:
                        self.components[name] = component_class(self.binary_path)
                    self.logger.debug("Initialized %s component", name)
            except Exception as e:
                self.logger.error("Failed to initialize %s component: %s", name, e)
                self.components[name] = None

    def run_comprehensive_analysis(self, analysis_types: list[str] | None = None) -> dict[str, Any]:
        """Run comprehensive analysis with error handling and recovery.

        Args:
            analysis_types: List of analysis types to run, or None for all

        Returns:
            Dict containing all analysis results

        """
        if analysis_types is None:
            analysis_types = list(self.components.keys())

        results = {
            "metadata": {
                "binary_path": self.binary_path,
                "analysis_start": time.time(),
                "analysis_types": analysis_types,
                "config": self.config,
            },
            "components": {},
            "errors": [],
            "performance": {},
        }

        # Use thread pool for parallel analysis where safe
        parallel_safe = ["strings", "imports", "signatures"]
        sequential_required = ["decompiler", "vulnerability", "esil", "ai", "bypass"]

        if parallel_types := [t for t in analysis_types if t in parallel_safe]:
            parallel_results = self._run_parallel_analysis(parallel_types)
            results["components"].update(parallel_results)

        # Run sequential analyses
        sequential_types = [t for t in analysis_types if t in sequential_required]
        for analysis_type in sequential_types:
            try:
                if component_result := self._run_single_analysis(analysis_type):
                    results["components"][analysis_type] = component_result
            except Exception as e:
                self.logger.error("Failed to run %s analysis: %s", analysis_type, e)
                results["errors"].append(
                    {
                        "component": analysis_type,
                        "error": str(e),
                        "timestamp": time.time(),
                    },
                )

        # Add performance metrics
        results["performance"] = self.get_performance_stats()
        results["metadata"]["analysis_end"] = time.time()
        results["metadata"]["total_duration"] = results["metadata"]["analysis_end"] - results["metadata"]["analysis_start"]

        return standardize_r2_result(
            "comprehensive",
            results,
            self.binary_path,
            {"enhanced_integration": True},
        )

    def _run_parallel_analysis(self, analysis_types: list[str]) -> dict[str, Any]:
        """Run analyses in parallel for performance."""
        results = {}
        max_workers = min(len(analysis_types), self.config.get("max_parallel_workers", 3))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_type = {executor.submit(self._run_single_analysis, analysis_type): analysis_type for analysis_type in analysis_types}

            # Collect results as they complete
            for future in as_completed(future_to_type, timeout=300):  # 5 minute timeout
                analysis_type = future_to_type[future]
                try:
                    if result := future.result():
                        results[analysis_type] = result
                except Exception as e:
                    self.logger.error("Parallel analysis %s failed: %s", analysis_type, e)
                    self.error_handler.handle_error(
                        e,
                        f"parallel_{analysis_type}",
                        {
                            "binary_path": self.binary_path,
                            "analysis_type": analysis_type,
                        },
                    )

        return results

    def _run_single_analysis(self, analysis_type: str) -> dict[str, Any] | None:
        """Run a single analysis with caching and error handling."""
        # Check cache first
        cache_key = f"{analysis_type}_{self.binary_path}"
        if cached_result := self._get_cached_result(cache_key):
            self.performance_stats["cache_hits"] += 1
            self.performance_monitor.record_cache_hit()
            return cached_result

        self.performance_stats["cache_misses"] += 1
        self.performance_monitor.record_cache_miss()

        # Check if component is available
        if analysis_type not in self.components or self.components[analysis_type] is None:
            self.logger.warning("Component %s not available", analysis_type)
            return None

        # Check if operation is degraded
        if self.error_handler.is_operation_degraded(f"r2_{analysis_type}"):
            self.logger.warning("Analysis %s is in degraded mode, skipping", analysis_type)
            return {"degraded": True, "reason": "Circuit breaker open"}

        start_time = time.time()

        # Start performance tracking
        operation_metrics = self.performance_monitor.start_operation(f"analysis_{analysis_type}")

        try:
            with r2_error_context(f"r2_{analysis_type}", binary_path=self.binary_path):
                component = self.components[analysis_type]

                # Run specific analysis
                if analysis_type == "decompiler":
                    result = component.analyze_license_functions()
                elif analysis_type == "esil":
                    result = component.run_emulation_analysis()
                elif analysis_type == "strings":
                    result = component.analyze_strings()
                elif analysis_type == "signatures":
                    result = component.analyze_signatures()
                elif analysis_type == "imports":
                    result = component.analyze_imports_exports()
                elif analysis_type == "vulnerability":
                    result = component.comprehensive_vulnerability_scan()
                elif analysis_type == "ai":
                    result = component.run_ai_analysis()
                elif analysis_type == "bypass":
                    result = component.generate_bypass_strategies()
                elif analysis_type == "scripting":
                    result = component.run_custom_analysis()
                else:
                    result = {"error": f"Unknown analysis type: {analysis_type}"}

                # Record performance
                duration = time.time() - start_time
                self._record_analysis_time(analysis_type, duration)

                # End performance tracking with success
                bytes_processed = len(str(result)) if result else 0
                self.performance_monitor.end_operation(operation_metrics, success=True, bytes_processed=bytes_processed)

                # Cache result
                self._cache_result(cache_key, result)

                return result

        except Exception as e:
            duration = time.time() - start_time
            self._record_analysis_time(analysis_type, duration, success=False)

            # End performance tracking with failure
            self.performance_monitor.end_operation(operation_metrics, success=False, error_message=str(e))

            self.logger.error("Analysis %s failed: %s", analysis_type, e)
            self.performance_stats["errors_handled"] += 1

            # Try recovery
            if self.error_handler.handle_error(
                e,
                f"r2_{analysis_type}",
                {
                    "binary_path": self.binary_path,
                    "analysis_type": analysis_type,
                    "component": component,
                },
            ):
                self.performance_stats["recoveries_successful"] += 1
                # Retry once after recovery
                try:
                    if analysis_type == "decompiler":
                        result = component.analyze_license_functions()
                    elif analysis_type == "esil":
                        result = component.run_emulation_analysis()
                    # ... (same pattern for other types)
                    else:
                        result = {"recovered": True, "original_error": str(e)}

                    self._cache_result(cache_key, result)
                    return result
                except Exception as retry_e:
                    self.logger.error("Retry failed for %s: %s", analysis_type, retry_e)

            return {"error": str(e), "failed_analysis": analysis_type}

    def _get_cached_result(self, cache_key: str) -> dict[str, Any] | None:
        """Get cached result if still valid."""
        with self._lock:
            if cache_key in self.results_cache:
                cached_data = self.results_cache[cache_key]
                if time.time() - cached_data["timestamp"] < self.cache_ttl:
                    return cached_data["result"]
                # Remove expired cache entry
                del self.results_cache[cache_key]
        return None

    def _cache_result(self, cache_key: str, result: dict[str, Any]) -> None:
        """Cache analysis result."""
        with self._lock:
            self.results_cache[cache_key] = {
                "result": result,
                "timestamp": time.time(),
            }

            # Limit cache size
            max_cache_size = self.config.get("max_cache_size", 100)
            if len(self.results_cache) > max_cache_size:
                # Remove oldest entries
                sorted_items = sorted(
                    self.results_cache.items(),
                    key=lambda x: x[1]["timestamp"],
                )
                for key, _ in sorted_items[:10]:  # Remove 10 oldest
                    del self.results_cache[key]

    def _record_analysis_time(self, analysis_type: str, duration: float, success: bool = True) -> None:
        """Record analysis performance."""
        with self._lock:
            if analysis_type not in self.performance_stats["analysis_times"]:
                self.performance_stats["analysis_times"][analysis_type] = {
                    "times": [],
                    "successes": 0,
                    "failures": 0,
                }

            stats = self.performance_stats["analysis_times"][analysis_type]
            stats["times"].append(duration)

            if success:
                stats["successes"] += 1
            else:
                stats["failures"] += 1

            # Keep only last 50 measurements
            if len(stats["times"]) > 50:
                stats["times"] = stats["times"][-50:]

    def start_real_time_monitoring(self, callback: Callable | None = None) -> None:
        """Start real-time monitoring of analysis results."""
        if self.monitoring_enabled and not self.monitoring_thread:
            self.monitoring_thread = threading.Thread(
                target=self._monitoring_loop,
                args=(callback,),
                daemon=True,
            )
            self.monitoring_thread.start()
            self.logger.info("Real-time monitoring started")

    def stop_real_time_monitoring(self) -> None:
        """Stop real-time monitoring."""
        self.monitoring_enabled = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
            self.monitoring_thread = None
            self.logger.info("Real-time monitoring stopped")

    def _monitoring_loop(self, callback: Callable | None) -> None:
        """Real-time monitoring loop."""
        while self.monitoring_enabled:
            try:
                # Run lightweight analysis
                quick_results = self._run_single_analysis("strings")

                if callback and quick_results:
                    callback(
                        {
                            "type": "real_time_update",
                            "results": quick_results,
                            "timestamp": time.time(),
                        },
                    )

                time.sleep(self.config.get("monitoring_interval", 30))  # 30 seconds default

            except Exception as e:
                self.logger.error("Monitoring loop error: %s", e)
                time.sleep(60)  # Wait longer on error

    def get_performance_stats(self) -> dict[str, Any]:
        """Get comprehensive performance statistics."""
        with self._lock:
            stats = self.performance_stats.copy()

            # Calculate averages and rates
            for analysis_type, data in stats["analysis_times"].items():
                if data["times"]:
                    data["avg_time"] = sum(data["times"]) / len(data["times"])
                    data["max_time"] = max(data["times"])
                    data["min_time"] = min(data["times"])
                    # Add analysis type metadata for reporting
                    data["analysis_type"] = analysis_type
                    data["total_time"] = sum(data["times"])

                total_attempts = data["successes"] + data["failures"]
                if total_attempts > 0:
                    data["success_rate"] = data["successes"] / total_attempts
                else:
                    data["success_rate"] = 0.0

            # Add error handler stats
            stats["error_handler"] = self.error_handler.get_error_statistics()

            return stats

    def optimize_performance(self) -> None:
        """Optimize performance based on collected metrics."""
        stats = self.get_performance_stats()

        # Adjust cache TTL based on hit rate
        total_cache_requests = stats["cache_hits"] + stats["cache_misses"]
        if total_cache_requests > 0:
            hit_rate = stats["cache_hits"] / total_cache_requests
            if hit_rate < 0.3:  # Low hit rate
                self.cache_ttl = min(self.cache_ttl * 1.5, 900)  # Increase TTL, max 15 min
            elif hit_rate > 0.8:  # High hit rate
                self.cache_ttl = max(self.cache_ttl * 0.8, 60)  # Decrease TTL, min 1 min

        # Reset circuit breakers for high-performing operations
        for analysis_type, data in stats["analysis_times"].items():
            if data.get("success_rate", 0) > 0.9:  # High success rate
                self.error_handler.reset_circuit_breaker(f"r2_{analysis_type}")

        self.logger.info("Performance optimized: cache_ttl=%s", self.cache_ttl)

    def clear_cache(self) -> None:
        """Clear results cache."""
        with self._lock:
            self.results_cache.clear()
            self.logger.info("Results cache cleared")

    def get_health_status(self) -> dict[str, Any]:
        """Get system health status."""
        stats = self.get_performance_stats()

        health = {
            "overall_health": "healthy",
            "r2pipe_available": self.r2pipe_available,
            "components_available": sum(bool(c is not None) for c in self.components.values()),
            "total_components": len(self.components),
            "cache_health": {
                "size": len(self.results_cache),
                "hit_rate": 0.0,
            },
            "error_health": {
                "total_errors": stats["errors_handled"],
                "recovery_rate": 0.0,
            },
        }

        # Calculate cache hit rate
        total_requests = stats["cache_hits"] + stats["cache_misses"]
        if total_requests > 0:
            health["cache_health"]["hit_rate"] = stats["cache_hits"] / total_requests

        # Calculate recovery rate
        if stats["errors_handled"] > 0:
            health["error_health"]["recovery_rate"] = stats["recoveries_successful"] / stats["errors_handled"]

        # Determine overall health
        if not health["r2pipe_available"] or health["components_available"] < health["total_components"] * 0.5:
            health["overall_health"] = "critical"
        elif health["error_health"]["recovery_rate"] < 0.5:
            health["overall_health"] = "degraded"
        elif health["cache_health"]["hit_rate"] < 0.2:
            health["overall_health"] = "warning"

        return health

    def set_secondary_binary(self, secondary_path: str) -> bool:
        """Set secondary binary for diff analysis.

        Args:
            secondary_path: Path to the secondary binary

        Returns:
            True if successfully set, False otherwise

        """
        try:
            if self.components.get("diff"):
                self.components["diff"].set_secondary_binary(secondary_path)
                self.logger.info("Set secondary binary for diff: %s", secondary_path)
                return True
            self.logger.error("Binary diff component not initialized")
            return False
        except Exception as e:
            self.logger.error("Failed to set secondary binary: %s", e, exc_info=True)
            return False

    def get_function_diffs(self) -> list[dict[str, Any]]:
        """Get function differences between primary and secondary binaries.

        Returns:
            List of function diff results

        """
        try:
            if self.components.get("diff"):
                diffs = self.components["diff"].get_function_diffs()
                # Convert dataclass objects to dictionaries
                return [
                    {
                        "name": d.name,
                        "status": d.status,
                        "primary_address": d.primary_address,
                        "secondary_address": d.secondary_address,
                        "primary_size": d.primary_size,
                        "secondary_size": d.secondary_size,
                        "size_diff": d.size_diff,
                        "similarity_score": d.similarity_score,
                        "opcodes_changed": d.opcodes_changed,
                        "calls_changed": d.calls_changed,
                        "basic_block_diff": d.basic_block_diff,
                    }
                    for d in diffs
                ]
            self.logger.error("Binary diff component not initialized")
            return []
        except Exception as e:
            self.logger.error("Failed to get function diffs: %s", e, exc_info=True)
            return []

    def get_basic_block_diffs(self, function_name: str) -> list[dict[str, Any]]:
        """Get basic block differences for a specific function.

        Args:
            function_name: Name of the function to analyze

        Returns:
            List of basic block diff results

        """
        try:
            if self.components.get("diff"):
                bb_diffs = self.components["diff"].get_basic_block_diffs(function_name)
                # Convert dataclass objects to dictionaries
                return [
                    {
                        "address": d.address,
                        "status": d.status,
                        "primary_size": d.primary_size,
                        "secondary_size": d.secondary_size,
                        "instruction_count_diff": d.instruction_count_diff,
                        "edges_added": d.edges_added,
                        "edges_removed": d.edges_removed,
                        "jump_targets_changed": d.jump_targets_changed,
                    }
                    for d in bb_diffs
                ]
            self.logger.error("Binary diff component not initialized")
            return []
        except Exception as e:
            self.logger.error("Failed to get basic block diffs: %s", e, exc_info=True)
            return []

    def get_performance_metrics(self) -> dict[str, Any]:
        """Get comprehensive performance metrics.

        Returns:
            Dictionary containing performance metrics and statistics

        """
        # Get metrics from the performance monitor
        current_metrics = self.performance_monitor.get_current_metrics()
        operation_stats = self.performance_monitor.get_operation_statistics()
        full_report = self.performance_monitor.get_performance_report()

        return {
            "current_session": current_metrics,
            "operation_statistics": operation_stats,
            "performance_stats": self.performance_stats,
            "full_report": full_report,
        }

    def export_performance_metrics(self, filepath: str) -> None:
        """Export performance metrics to a file.

        Args:
            filepath: Path to export file

        """
        self.performance_monitor.export_metrics(filepath)
        self.logger.info("Exported performance metrics to %s", filepath)

    def generate_control_flow_graph(self, function_name: str) -> dict[str, Any]:
        """Generate control flow graph for a function.

        Args:
            function_name: Name of the function

        Returns:
            Dictionary containing graph data

        """
        try:
            if self.components.get("graph"):
                graph_data = self.components["graph"].generate_control_flow_graph(function_name)
                return {
                    "nodes": [
                        {
                            "id": n.id,
                            "label": n.label,
                            "type": n.type,
                            "address": n.address,
                            "size": n.size,
                            "color": n.color,
                            "attributes": n.attributes,
                        }
                        for n in graph_data.nodes
                    ],
                    "edges": [
                        {
                            "source": e.source,
                            "target": e.target,
                            "type": e.type,
                            "label": e.label,
                            "color": e.color,
                            "style": e.style,
                        }
                        for e in graph_data.edges
                    ],
                    "metadata": graph_data.metadata,
                }
            self.logger.error("Graph component not initialized")
            return {}
        except Exception as e:
            self.logger.error("Failed to generate CFG: %s", e)
            return {}

    def generate_call_graph(self, max_depth: int = 3) -> dict[str, Any]:
        """Generate function call graph.

        Args:
            max_depth: Maximum depth for traversal

        Returns:
            Dictionary containing graph data

        """
        try:
            if self.components.get("graph"):
                graph_data = self.components["graph"].generate_call_graph(max_depth)
                return {
                    "nodes": [
                        {
                            "id": n.id,
                            "label": n.label,
                            "type": n.type,
                            "address": n.address,
                            "size": n.size,
                            "color": n.color,
                            "attributes": n.attributes,
                        }
                        for n in graph_data.nodes
                    ],
                    "edges": [
                        {
                            "source": e.source,
                            "target": e.target,
                            "type": e.type,
                            "label": e.label,
                            "color": e.color,
                            "style": e.style,
                        }
                        for e in graph_data.edges
                    ],
                    "metadata": graph_data.metadata,
                }
            self.logger.error("Graph component not initialized")
            return {}
        except Exception as e:
            self.logger.error("Failed to generate call graph: %s", e)
            return {}

    def generate_xref_graph(self, address: int) -> dict[str, Any]:
        """Generate cross-reference graph for an address.

        Args:
            address: Address to analyze

        Returns:
            Dictionary containing graph data

        """
        try:
            if self.components.get("graph"):
                graph_data = self.components["graph"].generate_xref_graph(address)
                return {
                    "nodes": [
                        {
                            "id": n.id,
                            "label": n.label,
                            "type": n.type,
                            "address": n.address,
                            "color": n.color,
                        }
                        for n in graph_data.nodes
                    ],
                    "edges": [
                        {
                            "source": e.source,
                            "target": e.target,
                            "type": e.type,
                            "label": e.label,
                            "color": e.color,
                            "style": e.style,
                        }
                        for e in graph_data.edges
                    ],
                    "metadata": graph_data.metadata,
                }
            self.logger.error("Graph component not initialized")
            return {}
        except Exception as e:
            self.logger.error("Failed to generate xref graph: %s", e)
            return {}

    def visualize_graph(self, graph_type: str, **kwargs: object) -> bool:
        """Visualize a graph.

        Args:
            graph_type: Type of graph ('cfg', 'call', 'xref', 'import')
            **kwargs: Additional arguments for specific graph types

        Returns:
            True if successful

        """
        try:
            if not self.components.get("graph"):
                self.logger.error("Graph component not initialized")
                return False

            graph_gen = self.components["graph"]

            if graph_type == "cfg":
                function_name = kwargs.get("function_name", "main")
                graph_data = graph_gen.generate_control_flow_graph(function_name)
            elif graph_type == "call":
                max_depth = kwargs.get("max_depth", 3)
                graph_data = graph_gen.generate_call_graph(max_depth)
            elif graph_type == "xref":
                address = kwargs.get("address", 0)
                graph_data = graph_gen.generate_xref_graph(address)
            elif graph_type == "import":
                graph_data = graph_gen.generate_import_dependency_graph()
            else:
                self.logger.error("Unknown graph type: %s", graph_type)
                return False

            output_path = kwargs.get("output_path")
            layout = kwargs.get("layout", "spring")

            return graph_gen.visualize_graph(graph_data, output_path, layout)

        except Exception as e:
            self.logger.error("Failed to visualize graph: %s", e)
            return False

    def cleanup(self) -> None:
        """Cleanup resources."""
        try:
            self.stop_real_time_monitoring()
            self.clear_cache()

            if final_metrics := self.performance_monitor.end_session():
                self.logger.info("Performance session ended: %s", final_metrics.session_id)
                self.logger.info(
                    "Total operations: %d, Success rate: %.2f%%",
                    final_metrics.total_operations,
                    100 * final_metrics.successful_operations / max(1, final_metrics.total_operations),
                )

            # Cleanup components
            for component in self.components.values():
                if component and hasattr(component, "cleanup"):
                    try:
                        component.cleanup()
                    except Exception as e:
                        self.logger.error("Component cleanup failed: %s", e)

            self.logger.info("EnhancedR2Integration cleanup completed")

        except Exception as e:
            self.logger.error("Cleanup failed: %s", e, exc_info=True)


def create_enhanced_r2_integration(binary_path: str, **config: object) -> EnhancedR2Integration:
    """Create enhanced radare2 integration instance.

    Args:
        binary_path: Path to binary file
        **config: Configuration options

    Returns:
        EnhancedR2Integration instance

    """
    return EnhancedR2Integration(binary_path, config)


__all__ = [
    "EnhancedR2Integration",
    "create_enhanced_r2_integration",
]
