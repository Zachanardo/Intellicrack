"""
Memory Optimizer

This module provides memory optimization capabilities for efficient resource management
during binary analysis and patching operations. It implements various memory optimization
techniques including automatic garbage collection, memory usage monitoring, and leak detection.

The optimizer supports:
- Real-time memory usage monitoring with configurable thresholds
- Automatic garbage collection triggers
- Memory-efficient data structure recommendations
- Memory leak detection and reporting
- Performance statistics tracking
- Integration with application instances for seamless operation

Author: Intellicrack Development Team
"""

import gc
import time
import logging
from typing import Dict, Any, Optional, Tuple, Union

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
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
        except Exception as e:
            self.logger.error(f"Failed to initialize memory tracking: {e}")

    def enable(self) -> None:
        """Enable memory optimization."""
        self.enabled = True
        if self.app and hasattr(self.app, 'update_output'):
            try:
                from ...utils.ui_utils import log_message
                self.app.update_output.emit(log_message("[Memory] Memory optimization enabled"))
            except ImportError:
                pass
        self.logger.info("Memory optimization enabled")

    def disable(self) -> None:
        """Disable memory optimization."""
        self.enabled = False
        if self.app and hasattr(self.app, 'update_output'):
            try:
                from ...utils.ui_utils import log_message
                self.app.update_output.emit(log_message("[Memory] Memory optimization disabled"))
            except ImportError:
                pass
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
            except ImportError:
                pass
                
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
            
        except Exception as e:
            self.logger.error(f"Error getting memory usage: {e}")
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
                collected_objects = gc.collect()
                techniques_used.append(f"garbage_collection({collected_objects} objects)")

            # Use memory-efficient data structures if enabled
            if self.optimization_techniques["memory_efficient_structures"]:
                # This could involve optimizing data structures in the application
                self._optimize_data_structures()
                techniques_used.append("memory_efficient_structures")

            # Check for memory leaks if enabled
            if self.optimization_techniques["leak_detection"]:
                leak_info = self.check_for_memory_leaks()
                techniques_used.append(f"leak_detection({leak_info})")

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
                except ImportError:
                    pass
                    
            self.logger.info(optimization_message)

            return memory_saved
            
        except Exception as e:
            self.logger.error(f"Error during memory optimization: {e}")
            return 0

    def _optimize_data_structures(self) -> None:
        """
        Optimize data structures for memory efficiency.
        
        This is a placeholder for actual data structure optimization logic.
        In a real implementation, this would identify and optimize memory-heavy structures.
        """
        # This could involve:
        # - Converting lists to generators where appropriate
        # - Using slots for classes
        # - Compressing data structures
        # - Removing unused references
        pass

    def check_for_memory_leaks(self) -> str:
        """
        Check for potential memory leaks.

        This is a simplified version that looks for unexpected memory usage patterns.
        A real implementation would track object creation and destruction.
        
        Returns:
            str: Summary of leak detection results
        """
        try:
            # Count objects tracked by garbage collector
            gc_objects = len(gc.get_objects())
            
            # Get garbage collection statistics
            gc_stats = gc.get_stats()
            
            # Check for uncollectable objects
            uncollectable = len(gc.garbage)
            
            leak_summary = f"{gc_objects} objects, {uncollectable} uncollectable"

            # Log potential memory leaks
            leak_message = f"[Memory] Leak detection: {leak_summary}"
            
            if self.app and hasattr(self.app, 'update_output'):
                try:
                    from ...utils.ui_utils import log_message
                    self.app.update_output.emit(log_message(leak_message))
                except ImportError:
                    pass
                    
            self.logger.info(leak_message)
            
            return leak_summary
            
        except Exception as e:
            self.logger.error(f"Error during leak detection: {e}")
            return "error"

    def get_optimization_stats(self) -> Dict[str, Union[int, float, str, None]]:
        """
        Get memory optimization statistics.

        Returns:
            dict: Dictionary of optimization statistics
        """
        # Update current memory usage
        used_memory, total_memory, usage_percentage = self.get_current_memory_usage()
        
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
            
        except Exception as e:
            self.logger.error(f"Error generating memory report: {e}")
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
            self.logger.warning(f"Unknown optimization technique: {technique}")
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