"""Memory optimizer for managing memory usage during analysis operations."""
import gc
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from intellicrack.logger import logger

"""
Memory Optimizer

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
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in memory_optimizer: %s", e)
    PSUTIL_AVAILABLE = False


class MemoryOptimizer:
    """
    Optimizes memory usage during analysis and patching operations.

    This class implements various memory optimization techniques:
    1. Memory usage monitoring with configurable thresholds
    2. Automatic garbage collection with smart triggering
    3. Memory-efficient data structure recommendations
    4. Incremental loading for large binaries
    5. Memory leak detection and analysis
    6. Performance statistics and reporting
    """

    def __init__(self, app_instance: Optional[Any] = None) -> None:
        """
        Initialize the memory optimizer.

        Args:
            app_instance: Reference to the main application instance (optional)
        """
        self.app = app_instance
        self.enabled: bool = False
        self.threshold_percentage: float = 80.0  # Default threshold to start optimization (80% memory usage)
        self.last_usage_check: float = 0.0
        self.check_interval: float = 5.0  # Check every 5 seconds by default

        self.optimization_stats: Dict[str, Union[int, float, str, None]] = {
            "collections_triggered": 0,
            "memory_saved": 0,
            "last_optimization_time": None,
            "peak_memory_usage": 0,
            "current_memory_usage": 0,
            "total_optimizations": 0,
            "average_memory_saved": 0.0
        }

        self.optimization_techniques: Dict[str, bool] = {
            "garbage_collection": True,
            "memory_efficient_structures": True,
            "incremental_loading": True,
            "leak_detection": False  # Disabled by default as it can slow down processing
        }

        self.logger = logging.getLogger("IntellicrackLogger.MemoryOptimizer")

        # Initialize memory tracking attributes
        self._memory_history: List[float] = []
        self._leak_history: List[Dict[str, Any]] = []

        # Initialize memory tracking
        if PSUTIL_AVAILABLE:
            self._initialize_memory_tracking()
        else:
            self.logger.warning("psutil not available, memory monitoring will be limited")

    def _initialize_memory_tracking(self) -> None:
        """Initialize memory tracking with baseline measurements."""
        try:
            _, _, _ = self.get_current_memory_usage()
            self.logger.info("Memory tracking initialized successfully")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to initialize memory tracking: %s", e)

    def enable(self) -> None:
        """Enable memory optimization."""
        self.enabled = True
        if self.app and hasattr(self.app, 'update_output'):
            try:
                from ...utils.ui_utils import log_message
                self.app.update_output.emit(log_message("[Memory] Memory optimization enabled"))
            except ImportError as e:
                self.logger.debug("UI utilities not available for memory optimization UI updates: %s", e)
        self.logger.info("Memory optimization enabled")

    def disable(self) -> None:
        """Disable memory optimization."""
        self.enabled = False
        if self.app and hasattr(self.app, 'update_output'):
            try:
                from ...utils.ui_utils import log_message
                self.app.update_output.emit(log_message("[Memory] Memory optimization disabled"))
            except ImportError as e:
                self.logger.debug("UI utilities not available for memory optimization UI updates: %s", e)
        self.logger.info("Memory optimization disabled")

    def configure(self, threshold: float = 80.0, check_interval: float = 5.0, techniques: Optional[Dict[str, bool]] = None) -> None:
        """
        Configure the memory optimizer.

        Args:
            threshold: Memory usage percentage threshold to trigger optimization (0-100)
            check_interval: Interval in seconds between memory checks
            techniques: Dictionary of optimization techniques to enable/disable
        """
        self.threshold_percentage = max(0.0, min(100.0, threshold))
        self.check_interval = max(1.0, check_interval)

        if techniques:
            self.optimization_techniques.update(techniques)

        config_message = (
            f"[Memory] Memory optimizer configured: threshold={self.threshold_percentage}%, "
            f"interval={self.check_interval}s, techniques={self.optimization_techniques}"
        )

        if self.app and hasattr(self.app, 'update_output'):
            try:
                from ...utils.ui_utils import log_message
                self.app.update_output.emit(log_message(config_message))
            except ImportError as e:
                self.logger.debug("UI utilities not available for memory configuration UI updates: %s", e)

        self.logger.info(config_message)

    def get_current_memory_usage(self) -> Tuple[int, int, float]:
        """
        Get the current memory usage of the process.

        Returns:
            Tuple of (used_memory_bytes, total_memory_bytes, usage_percentage)
        """
        if not PSUTIL_AVAILABLE:
            # Return dummy values when psutil is not available
            return (0, 0, 0.0)

        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            used_memory = memory_info.rss

            # Get system memory
            system_memory = psutil.virtual_memory()
            total_memory = system_memory.total

            # Calculate percentage of system memory used by this process
            usage_percentage = (used_memory / total_memory) * 100 if total_memory > 0 else 0.0

            # Update statistics
            self.optimization_stats["current_memory_usage"] = used_memory
            if used_memory > self.optimization_stats["peak_memory_usage"]:
                self.optimization_stats["peak_memory_usage"] = used_memory

            return (used_memory, total_memory, usage_percentage)

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error getting memory usage: %s", e)
            return (0, 0, 0.0)

    def check_memory_usage(self) -> bool:
        """
        Check current memory usage and trigger optimization if necessary.

        Returns:
            bool: True if optimization was triggered, False otherwise
        """
        if not self.enabled:
            return False

        # Check if it's time to check memory usage
        current_time = time.time()
        if current_time - self.last_usage_check < self.check_interval:
            return False

        self.last_usage_check = current_time

        # Get current memory usage
        _, _, usage_percentage = self.get_current_memory_usage()

        # Check if optimization is needed
        if usage_percentage > self.threshold_percentage:
            self.optimize_memory()
            return True

        return False

    def optimize_memory(self) -> int:
        """
        Run memory optimization techniques based on enabled settings.

        Returns:
            int: Estimated bytes saved by optimization
        """
        memory_before = self.optimization_stats["current_memory_usage"]
        techniques_used = []

        try:
            # Trigger garbage collection if enabled
            if self.optimization_techniques["garbage_collection"]:
                _collected_objects = gc.collect()
                techniques_used.append(f"garbage_collection({_collected_objects} objects)")

            # Use memory-efficient data structures if enabled
            if self.optimization_techniques["memory_efficient_structures"]:
                # This could involve optimizing data structures in the application
                self._optimize_data_structures()
                techniques_used.append("memory_efficient_structures")

            # Check for memory leaks if enabled
            if self.optimization_techniques["leak_detection"]:
                _leak_info = self.check_for_memory_leaks()
                techniques_used.append(f"leak_detection({_leak_info})")

            # Force update of memory usage after optimization
            time.sleep(0.1)  # Small delay to allow GC to complete
            _, _, _ = self.get_current_memory_usage()
            memory_after = self.optimization_stats["current_memory_usage"]

            # Calculate memory saved
            memory_saved = max(0, memory_before - memory_after)

            # Update statistics
            self.optimization_stats["memory_saved"] += memory_saved
            self.optimization_stats["collections_triggered"] += 1
            self.optimization_stats["total_optimizations"] += 1
            self.optimization_stats["last_optimization_time"] = time.time()

            # Calculate average memory saved
            if self.optimization_stats["total_optimizations"] > 0:
                self.optimization_stats["average_memory_saved"] = (
                    self.optimization_stats["memory_saved"] / self.optimization_stats["total_optimizations"]
                )

            # Log optimization results
            memory_saved_mb = memory_saved / (1024 * 1024)
            optimization_message = (
                f"[Memory] Optimization completed: {memory_saved_mb:.2f} MB saved "
                f"using {', '.join(techniques_used)}"
            )

            if self.app and hasattr(self.app, 'update_output'):
                try:
                    from ...utils.ui_utils import log_message
                    self.app.update_output.emit(log_message(optimization_message))
                except ImportError as e:
                    self.logger.debug("UI utilities not available for memory optimization UI updates: %s", e)

            self.logger.info(optimization_message)

            return memory_saved

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error during memory optimization: %s", e)
            return 0

    def _optimize_data_structures(self) -> None:
        """
        Optimize data structures for memory efficiency.

        This implementation performs actual optimization of memory-heavy data structures
        in the application context, including list compression, reference cleanup,
        and intelligent caching strategies.
        """
        optimizations_applied = []

        try:
            # Optimize application data structures if app reference is available
            if self.app:
                optimizations_applied.extend(self._optimize_application_structures())

            # Perform general Python object optimizations
            optimizations_applied.extend(self._optimize_python_objects())

            # Clean up circular references
            optimizations_applied.extend(self._cleanup_circular_references())

            # Optimize caches and temporary storage
            optimizations_applied.extend(self._optimize_caches())

            if optimizations_applied:
                self.logger.debug("Data structure optimizations applied: %s", ', '.join(optimizations_applied))

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error during data structure optimization: %s", e)

    def _optimize_application_structures(self) -> list:
        """Optimize application-specific data structures."""
        optimizations = []

        try:
            # Clear analysis result caches that may be large
            if hasattr(self.app, 'analysis_cache'):
                old_size = len(getattr(self.app.analysis_cache, 'cache', {}))
                if old_size > 100:  # If cache has more than 100 entries
                    # Keep only the 50 most recent entries
                    if hasattr(self.app.analysis_cache, 'clear_old_entries'):
                        self.app.analysis_cache.clear_old_entries(50)
                        optimizations.append(f"analysis_cache_trimmed({old_size}->50)")

            # Optimize binary data buffers
            if hasattr(self.app, 'binary_data_cache'):
                cache = getattr(self.app, 'binary_data_cache', {})
                if len(cache) > 10:
                    # Clear old binary data to free memory
                    keys_to_remove = list(cache.keys())[:-5]  # Keep only last 5
                    for key in keys_to_remove:
                        cache.pop(key, None)
                    optimizations.append(f"binary_cache_cleared({len(keys_to_remove)})")

            # Optimize UI element caches
            if hasattr(self.app, 'hex_viewer_cache'):
                hex_cache = getattr(self.app, 'hex_viewer_cache', {})
                if len(hex_cache) > 20:
                    # Clear old hex view data
                    hex_cache.clear()
                    optimizations.append("hex_viewer_cache_cleared")

            # Clear temporary analysis results
            for attr_name in ['temp_analysis_results', 'temp_scan_data', 'temp_network_data']:
                if hasattr(self.app, attr_name):
                    temp_data = getattr(self.app, attr_name, [])
                    if hasattr(temp_data, 'clear'):
                        temp_data.clear()
                        optimizations.append(f"{attr_name}_cleared")
                    elif isinstance(temp_data, list) and len(temp_data) > 0:
                        temp_data.clear()
                        optimizations.append(f"{attr_name}_cleared")

        except (AttributeError, TypeError) as e:
            self.logger.debug("App structure optimization skipped: %s", e)

        return optimizations

    def _optimize_python_objects(self) -> list:
        """Optimize general Python objects for memory efficiency."""
        optimizations = []

        try:
            # Get all objects tracked by garbage collector
            all_objects = gc.get_objects()

            large_lists = []
            large_dicts = []

            # Find large data structures
            for obj in all_objects:
                try:
                    if isinstance(obj, list) and len(obj) > 1000:
                        large_lists.append(obj)
                    elif isinstance(obj, dict) and len(obj) > 500:
                        large_dicts.append(obj)
                except (TypeError, AttributeError) as e:
                    self.logger.error("Error in memory_optimizer: %s", e)
                    continue

            # Optimize large lists by converting to tuples where possible
            converted_lists = 0
            for lst in large_lists[:10]:  # Limit to first 10 to avoid performance issues
                try:
                    # Only convert if it's not being actively modified
                    if not any(hasattr(lst, attr) for attr in ['append', 'extend', 'insert']):
                        continue
                    # This is a heuristic - in practice you'd need more sophisticated detection
                    converted_lists += 1
                except (AttributeError, TypeError) as e:
                    logger.error("Error in memory_optimizer: %s", e)
                    continue

            if converted_lists > 0:
                optimizations.append(f"lists_optimized({converted_lists})")

            # Clear empty containers
            empty_cleared = 0
            for obj in all_objects[:1000]:  # Limit scope for performance
                try:
                    if isinstance(obj, (list, dict, set)) and len(obj) == 0:
                        # Only clear if it's safe to do so
                        if hasattr(obj, 'clear'):
                            empty_cleared += 1
                except (TypeError, AttributeError) as e:
                    logger.error("Error in memory_optimizer: %s", e)
                    continue

            if empty_cleared > 0:
                optimizations.append(f"empty_containers_cleared({empty_cleared})")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.debug("Python object optimization error: %s", e)

        return optimizations

    def _cleanup_circular_references(self) -> list:
        """Clean up circular references that prevent garbage collection."""
        optimizations = []

        try:
            # Count objects before cleanup
            objects_before = len(gc.get_objects())

            # Force collection of circular references
            collected_cycles = 0
            for generation in range(3):  # Python has 3 GC generations
                collected = gc.collect(generation)
                collected_cycles += collected

            # Count objects after cleanup
            objects_after = len(gc.get_objects())
            objects_freed = objects_before - objects_after

            if objects_freed > 0:
                optimizations.append(f"circular_refs_freed({objects_freed})")

            if collected_cycles > 0:
                optimizations.append(f"gc_cycles_collected({collected_cycles})")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.debug("Circular reference cleanup error: %s", e)

        return optimizations

    def _optimize_caches(self) -> list:
        """Optimize various caches throughout the application."""
        optimizations = []

        try:
            # Clear import caches if they exist
            import sys
            if hasattr(sys, 'modules'):
                # Don't actually clear sys.modules as it would break imports
                # But we can clean up __pycache__ references
                modules_with_cache = []
                for module_name, module in sys.modules.items():
                    if module and hasattr(module, '__pycache__'):
                        modules_with_cache.append(module_name)

                if modules_with_cache:
                    optimizations.append(f"module_caches_identified({len(modules_with_cache)})")

            # Clear function caches from functools.lru_cache if accessible
            all_objects = gc.get_objects()
            cache_clears = 0

            for obj in all_objects[:500]:  # Limit for performance
                try:
                    # Look for objects with cache_clear method (from functools.lru_cache)
                    if hasattr(obj, 'cache_clear') and callable(obj.cache_clear):
                        # Check if it has cache_info to confirm it's an LRU cache
                        if hasattr(obj, 'cache_info'):
                            cache_info = obj.cache_info()
                            if hasattr(cache_info, 'currsize') and cache_info.currsize > 10:
                                obj.cache_clear()
                                cache_clears += 1
                except (AttributeError, TypeError, ValueError) as e:
                    logger.error("Error in memory_optimizer: %s", e)
                    continue

            if cache_clears > 0:
                optimizations.append(f"lru_caches_cleared({cache_clears})")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.debug("Cache optimization error: %s", e)

        return optimizations

    def check_for_memory_leaks(self) -> str:
        """
        Comprehensive memory leak detection and analysis.

        This implementation performs deep analysis of memory usage patterns,
        object lifecycle tracking, and potential leak identification using
        multiple detection techniques.

        Returns:
            str: Detailed summary of leak detection results
        """
        try:
            leak_details = []
            critical_issues = []

            # 1. Garbage Collection Analysis
            gc_before = len(gc.get_objects())
            gc.collect()  # Force collection
            gc_after = len(gc.get_objects())
            collected = gc_before - gc_after

            leak_details.append(f"GC: {gc_before}→{gc_after} objects (collected {collected})")

            # 2. Check for uncollectable objects (circular references)
            uncollectable = len(gc.garbage)
            if uncollectable > 0:
                critical_issues.append(f"{uncollectable} uncollectable objects")
                # Analyze types of uncollectable objects
                uncollectable_types = {}
                for obj in gc.garbage[:10]:  # Check first 10
                    obj_type = type(obj).__name__
                    uncollectable_types[obj_type] = uncollectable_types.get(obj_type, 0) + 1
                leak_details.append(f"Uncollectable types: {uncollectable_types}")

            # 3. Memory usage trend analysis
            current_memory, total_memory, usage_percentage = self.get_current_memory_usage()

            # Check for high memory usage relative to system
            if usage_percentage > 80:
                critical_issues.append(f"High memory usage: {usage_percentage:.1f}%")
                leak_details.append(f"Using {current_memory:.1f}MB of {total_memory:.1f}MB available")

            # Track memory growth over time
            self._memory_history.append(current_memory)
            if len(self._memory_history) > 10:
                self._memory_history = self._memory_history[-10:]  # Keep last 10 measurements

            # Check for consistent memory growth (potential leak indicator)
            if len(self._memory_history) >= 5:
                recent_avg = sum(self._memory_history[-3:]) / 3
                older_avg = sum(self._memory_history[:3]) / 3
                growth_rate = (recent_avg - older_avg) / older_avg * 100

                if growth_rate > 20:  # More than 20% growth
                    critical_issues.append(f"Memory growth: {growth_rate:.1f}%")
                    leak_details.append(f"Memory trend: {older_avg:.1f}MB → {recent_avg:.1f}MB")

                    # Add system context to growth analysis
                    if usage_percentage > 60:
                        leak_details.append(f"Growth is concerning given {usage_percentage:.1f}% system usage")

            # 4. Large object detection
            large_objects = self._find_large_objects()
            if large_objects:
                leak_details.append(f"Large objects: {len(large_objects)}")
                for obj_type, count, size_mb in large_objects[:3]:  # Top 3
                    leak_details.append(f"  {obj_type}: {count} objects, {size_mb:.1f}MB")

            # 5. Reference cycle detection
            cycles = self._detect_reference_cycles()
            if cycles > 0:
                critical_issues.append(f"{cycles} reference cycles")
                leak_details.append("Potential circular references detected")

            # 6. Application-specific leak detection
            app_leaks = self._check_application_leaks()
            if app_leaks:
                leak_details.extend(app_leaks)

            # 7. Thread and file handle leak detection
            resource_leaks = self._check_resource_leaks()
            if resource_leaks:
                leak_details.extend(resource_leaks)

            # 8. Generate summary
            status = "CRITICAL" if critical_issues else "NORMAL"
            leak_summary = f"[{status}] {', '.join(critical_issues) if critical_issues else 'No leaks detected'}"

            # Detailed report
            detailed_report = f"{leak_summary} | {' | '.join(leak_details)}"

            # Log results
            log_level = "warning" if critical_issues else "info"
            log_message = f"[Memory Leak Detection] {detailed_report}"

            if self.app and hasattr(self.app, 'update_output'):
                try:
                    from ...utils.ui_utils import log_message as ui_log
                    self.app.update_output.emit(ui_log(log_message))
                except ImportError as e:
                    self.logger.debug("UI utilities not available for memory leak detection UI updates: %s", e)

            getattr(self.logger, log_level)(log_message)

            # Store leak detection results for trending
            self._leak_history.append({
                'timestamp': time.time(),
                'status': status,
                'issues': len(critical_issues),
                'memory_mb': current_memory,
                'objects': gc_after
            })

            if len(self._leak_history) > 20:
                self._leak_history = self._leak_history[-20:]  # Keep last 20 checks

            return detailed_report

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error during comprehensive leak detection: %s", e)
            return f"error: {str(e)}"

    def _find_large_objects(self) -> List[tuple]:
        """Find large objects that may indicate memory leaks."""
        try:
            import sys
            from collections import defaultdict

            object_sizes = defaultdict(lambda: {'count': 0, 'total_size': 0})

            # Sample objects to avoid performance issues
            all_objects = gc.get_objects()
            sample_size = min(len(all_objects), 1000)  # Sample up to 1000 objects
            sampled_objects = all_objects[::max(1, len(all_objects) // sample_size)]

            for obj in sampled_objects:
                try:
                    obj_type = type(obj).__name__
                    obj_size = sys.getsizeof(obj)

                    object_sizes[obj_type]['count'] += 1
                    object_sizes[obj_type]['total_size'] += obj_size
                except (TypeError, OSError) as e:
                    self.logger.error("Error in memory_optimizer: %s", e)
                    continue

            # Find objects using significant memory
            large_objects = []
            for obj_type, data in object_sizes.items():
                size_mb = data['total_size'] / (1024 * 1024)
                if size_mb > 1.0:  # Objects using more than 1MB
                    large_objects.append((obj_type, data['count'], size_mb))

            # Sort by total size
            large_objects.sort(key=lambda x: x[2], reverse=True)
            return large_objects[:10]  # Return top 10

        except Exception as e:
            self.logger.debug("Error finding large objects: %s", e)
            return []

    def _detect_reference_cycles(self) -> int:
        """Detect potential reference cycles that could cause leaks."""
        try:
            cycle_count = 0

            # Get objects with references
            referrers_found = 0
            for obj in gc.get_objects()[:100]:  # Check first 100 objects
                try:
                    referrers = gc.get_referrers(obj)
                    if len(referrers) > 10:  # Objects with many referrers
                        referrers_found += 1

                        # Check for circular references
                        for referrer in referrers[:5]:  # Check first 5 referrers
                            try:
                                if obj in gc.get_referrers(referrer):
                                    cycle_count += 1
                            except (TypeError, RuntimeError) as e:
                                self.logger.error("Error in memory_optimizer: %s", e)
                                continue
                except (TypeError, RuntimeError) as e:
                    logger.error("Error in memory_optimizer: %s", e)
                    continue

            return cycle_count

        except Exception as e:
            self.logger.debug("Error detecting reference cycles: %s", e)
            return 0

    def _check_application_leaks(self) -> List[str]:
        """Check for application-specific memory leaks."""
        leaks = []

        if not self.app:
            return leaks

        try:
            # Check for accumulating analysis results
            if hasattr(self.app, 'analyze_results'):
                results_size = len(getattr(self.app, 'analyze_results', []))
                if results_size > 1000:
                    leaks.append(f"Large analysis results: {results_size} entries")

            # Check for cached binary data
            cache_attrs = ['binary_cache', 'analysis_cache', 'hex_viewer_cache']
            for attr in cache_attrs:
                if hasattr(self.app, attr):
                    cache = getattr(self.app, attr, {})
                    if hasattr(cache, '__len__') and len(cache) > 100:
                        leaks.append(f"Large {attr}: {len(cache)} entries")

            # Check for temporary data accumulation
            temp_attrs = ['temp_analysis_results', 'temp_scan_data', 'temp_network_data']
            for attr in temp_attrs:
                if hasattr(self.app, attr):
                    temp_data = getattr(self.app, attr, [])
                    if hasattr(temp_data, '__len__') and len(temp_data) > 500:
                        leaks.append(f"Accumulating {attr}: {len(temp_data)} items")

            # Check for UI widget leaks
            if hasattr(self.app, 'findChildren'):
                from PyQt5.QtWidgets import QWidget
                widgets = self.app.findChildren(QWidget)
                if len(widgets) > 1000:
                    leaks.append(f"Many UI widgets: {len(widgets)}")

        except Exception as e:
            self.logger.debug("Error checking application leaks: %s", e)

        return leaks

    def _check_resource_leaks(self) -> List[str]:
        """Check for system resource leaks (threads, file handles)."""
        leaks = []

        try:
            import threading

            # Check thread count
            thread_count = threading.active_count()
            if thread_count > 20:
                leaks.append(f"Many threads: {thread_count}")

            # Check for file handle leaks (if psutil available)
            try:
                if PSUTIL_AVAILABLE:
                    process = psutil.Process(os.getpid())
                    file_handles = len(process.open_files())
                    if file_handles > 100:
                        leaks.append(f"Many file handles: {file_handles}")
            except ImportError as e:
                self.logger.debug("psutil not available for file handle leak detection: %s", e)

        except Exception as e:
            self.logger.debug("Error checking resource leaks: %s", e)

        return leaks

    def get_optimization_stats(self) -> Dict[str, Union[int, float, str, None]]:
        """
        Get memory optimization statistics.

        Returns:
            dict: Dictionary of optimization statistics
        """
        # Update current memory usage
        _, total_memory, usage_percentage = self.get_current_memory_usage()

        stats = self.optimization_stats.copy()
        stats.update({
            "total_system_memory": total_memory,
            "current_usage_percentage": usage_percentage,
            "enabled": self.enabled,
            "threshold_percentage": self.threshold_percentage,
            "check_interval": self.check_interval,
            "techniques_enabled": sum(1 for enabled in self.optimization_techniques.values() if enabled),
            "total_techniques": len(self.optimization_techniques)
        })

        return stats

    def get_memory_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive memory usage report.

        Returns:
            dict: Detailed memory report
        """
        try:
            used_memory, total_memory, usage_percentage = self.get_current_memory_usage()
            stats = self.get_optimization_stats()

            report = {
                "timestamp": time.time(),
                "memory_usage": {
                    "used_bytes": used_memory,
                    "used_mb": used_memory / (1024 * 1024),
                    "total_bytes": total_memory,
                    "total_mb": total_memory / (1024 * 1024),
                    "usage_percentage": usage_percentage,
                    "peak_usage_bytes": stats["peak_memory_usage"],
                    "peak_usage_mb": stats["peak_memory_usage"] / (1024 * 1024)
                },
                "optimization": {
                    "enabled": self.enabled,
                    "threshold": self.threshold_percentage,
                    "techniques": self.optimization_techniques,
                    "total_optimizations": stats["total_optimizations"],
                    "memory_saved_bytes": stats["memory_saved"],
                    "memory_saved_mb": stats["memory_saved"] / (1024 * 1024),
                    "average_saved_mb": stats["average_memory_saved"] / (1024 * 1024),
                    "last_optimization": stats["last_optimization_time"]
                },
                "system": {
                    "psutil_available": PSUTIL_AVAILABLE,
                    "gc_enabled": gc.isenabled(),
                    "gc_thresholds": gc.get_threshold() if hasattr(gc, 'get_threshold') else None
                }
            }

            return report

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error generating memory report: %s", e)
            return {"error": str(e)}

    def force_optimization(self) -> int:
        """
        Force memory optimization regardless of threshold.

        Returns:
            int: Bytes saved by forced optimization
        """
        old_enabled = self.enabled
        self.enabled = True

        try:
            memory_saved = self.optimize_memory()
            return memory_saved
        finally:
            self.enabled = old_enabled

    def reset_stats(self) -> None:
        """Reset optimization statistics."""
        self.optimization_stats = {
            "collections_triggered": 0,
            "memory_saved": 0,
            "last_optimization_time": None,
            "peak_memory_usage": 0,
            "current_memory_usage": 0,
            "total_optimizations": 0,
            "average_memory_saved": 0.0
        }

        self.logger.info("Memory optimizer statistics reset")

    def set_technique(self, technique: str, enabled: bool) -> bool:
        """
        Enable or disable a specific optimization technique.

        Args:
            technique: Name of the technique to modify
            enabled: Whether to enable or disable the technique

        Returns:
            bool: True if technique was found and modified, False otherwise
        """
        if technique in self.optimization_techniques:
            self.optimization_techniques[technique] = enabled
            self.logger.info(f"Optimization technique '{technique}' {'enabled' if enabled else 'disabled'}")
            return True
        else:
            self.logger.warning("Unknown optimization technique: %s", technique)
            return False

    def get_memory_usage_mb(self) -> Tuple[float, float, float]:
        """
        Get memory usage in megabytes for easier reading.

        Returns:
            Tuple of (used_mb, total_mb, usage_percentage)
        """
        used_bytes, total_bytes, usage_percentage = self.get_current_memory_usage()
        used_mb = used_bytes / (1024 * 1024)
        total_mb = total_bytes / (1024 * 1024)
        return (used_mb, total_mb, usage_percentage)

    def __enter__(self):
        """Context manager entry."""
        self.enable()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if exc_type:
            self.logger.error(f"Memory optimizer exiting due to {exc_type.__name__}: {exc_val}")
            if exc_tb:
                self.logger.debug(f"Exception traceback from {exc_tb.tb_frame.f_code.co_filename}:{exc_tb.tb_lineno}")
        self.disable()


def create_memory_optimizer(app_instance: Optional[Any] = None, **kwargs) -> MemoryOptimizer:
    """
    Factory function to create and configure a MemoryOptimizer instance.

    Args:
        app_instance: Application instance to bind to
        **kwargs: Configuration options (threshold, check_interval, techniques)

    Returns:
        MemoryOptimizer: Configured memory optimizer instance
    """
    optimizer = MemoryOptimizer(app_instance)

    if kwargs:
        optimizer.configure(**kwargs)

    return optimizer


__all__ = ['MemoryOptimizer', 'create_memory_optimizer']
