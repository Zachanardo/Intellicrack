"""Radare2 Performance Optimization for Large Binary Analysis.

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

import gc
import multiprocessing
import os
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from intellicrack.handlers.psutil_handler import psutil

from ...utils.logger import get_logger

logger = get_logger(__name__)

try:
    import r2pipe
except ImportError as e:
    logger.error("Import error in radare2_performance_optimizer: %s", e)
    r2pipe = None


class OptimizationStrategy(Enum):
    """Available optimization strategies."""

    MEMORY_CONSERVATIVE = "memory_conservative"
    SPEED_OPTIMIZED = "speed_optimized"
    BALANCED = "balanced"
    LARGE_FILE_SPECIALIZED = "large_file_specialized"
    CUSTOM = "custom"


class AnalysisLevel(Enum):
    """Analysis depth levels for performance tuning."""

    MINIMAL = "a"  # Basic analysis
    LIGHT = "aa"  # Light analysis
    STANDARD = "aaa"  # Standard analysis
    COMPREHENSIVE = "aaaa"  # Full analysis
    DEEP = "aaaaa"  # Deep analysis


@dataclass
class PerformanceProfile:
    """Performance profile for different binary sizes and types."""

    name: str
    max_file_size: int  # In bytes
    analysis_level: AnalysisLevel
    memory_limit: int  # In MB
    timeout: int  # In seconds
    parallel_workers: int
    chunk_size: int  # For large file processing
    cache_enabled: bool
    optimization_flags: list[str]
    description: str


class R2PerformanceOptimizer:
    """Comprehensive performance optimizer for radare2 operations.

    This class provides:
    - Automatic performance profiling and optimization
    - Memory usage monitoring and management
    - Adaptive analysis strategies based on file size and system resources
    - Parallel processing capabilities
    - Caching and memoization
    - Resource cleanup and garbage collection
    """

    # Predefined performance profiles
    PERFORMANCE_PROFILES = {
        "small_files": PerformanceProfile(
            name="Small Files (<10MB)",
            max_file_size=10 * 1024 * 1024,  # 10MB
            analysis_level=AnalysisLevel.COMPREHENSIVE,
            memory_limit=500,  # 500MB
            timeout=300,  # 5 minutes
            parallel_workers=4,
            chunk_size=1024 * 1024,  # 1MB
            cache_enabled=True,
            optimization_flags=["-e", "anal.timeout=300"],
            description="Full analysis for small binaries",
        ),
        "medium_files": PerformanceProfile(
            name="Medium Files (10MB-100MB)",
            max_file_size=100 * 1024 * 1024,  # 100MB
            analysis_level=AnalysisLevel.STANDARD,
            memory_limit=1000,  # 1GB
            timeout=600,  # 10 minutes
            parallel_workers=3,
            chunk_size=5 * 1024 * 1024,  # 5MB
            cache_enabled=True,
            optimization_flags=["-e", "anal.timeout=600", "-e", "esil.timeout=60"],
            description="Balanced analysis for medium binaries",
        ),
        "large_files": PerformanceProfile(
            name="Large Files (100MB-1GB)",
            max_file_size=1024 * 1024 * 1024,  # 1GB
            analysis_level=AnalysisLevel.LIGHT,
            memory_limit=2000,  # 2GB
            timeout=1800,  # 30 minutes
            parallel_workers=2,
            chunk_size=10 * 1024 * 1024,  # 10MB
            cache_enabled=True,
            optimization_flags=[
                "-e",
                "anal.timeout=1800",
                "-e",
                "esil.timeout=30",
                "-e",
                "anal.depth=16",
                "-e",
                "anal.bb.maxsize=1024",
            ],
            description="Light analysis for large binaries",
        ),
        "huge_files": PerformanceProfile(
            name="Huge Files (>1GB)",
            max_file_size=float("inf"),
            analysis_level=AnalysisLevel.MINIMAL,
            memory_limit=4000,  # 4GB
            timeout=3600,  # 1 hour
            parallel_workers=1,
            chunk_size=50 * 1024 * 1024,  # 50MB
            cache_enabled=False,  # Disable cache for huge files
            optimization_flags=[
                "-e",
                "anal.timeout=3600",
                "-e",
                "esil.timeout=10",
                "-e",
                "anal.depth=8",
                "-e",
                "anal.bb.maxsize=512",
                "-e",
                "io.cache=false",
                "-e",
                "bin.cache=false",
            ],
            description="Minimal analysis for huge binaries",
        ),
    }

    def __init__(self, strategy: OptimizationStrategy = OptimizationStrategy.BALANCED) -> None:
        """Initialize the Radare2 performance optimizer.

        Args:
            strategy: The optimization strategy to use for resource management.

        """
        self.strategy = strategy
        self.logger = logger

        # System information
        self.system_info = self._get_system_info()

        # Performance monitoring
        self.performance_metrics = {
            "memory_usage": [],
            "cpu_usage": [],
            "analysis_times": {},
            "optimization_effectiveness": {},
            "resource_peaks": {"memory": 0, "cpu": 0},
        }

        # Resource monitoring
        self._monitoring = False
        self._monitor_thread = None

        # Cache for optimized configurations
        self._config_cache = {}

        # Adaptive thresholds
        self.adaptive_thresholds = {
            "memory_warning": 0.8,  # 80% of available memory
            "memory_critical": 0.9,  # 90% of available memory
            "cpu_throttle": 0.9,  # 90% CPU usage
            "analysis_timeout_multiplier": 1.5,
        }

        self.logger.info(f"R2PerformanceOptimizer initialized with {strategy.value} strategy")

    def _get_system_info(self) -> dict[str, Any]:
        """Get comprehensive system information.

        Returns:
            Dictionary containing CPU count, memory total, available, percent,
            CPU percent, and disk usage information.

        """
        return {
            "cpu_count": multiprocessing.cpu_count(),
            "memory_total": psutil.virtual_memory().total,
            "memory_available": psutil.virtual_memory().available,
            "memory_percent": psutil.virtual_memory().percent,
            "cpu_percent": psutil.cpu_percent(interval=1),
            "disk_usage": psutil.disk_usage("/").percent if os.name != "nt" else psutil.disk_usage("C:\\").percent,
        }

    def optimize_for_binary(self, binary_path: str) -> dict[str, Any]:
        """Create optimized configuration for specific binary.

        Args:
            binary_path: Path to binary file for optimization.

        Returns:
            Dictionary containing optimized configuration with analysis level,
            memory limits, timeout, worker count, chunk size, caching settings,
            and radare2 flags.

        """
        try:
            # Check cache first
            cache_key = f"{binary_path}_{Path(binary_path).stat().st_mtime}"
            if cache_key in self._config_cache:
                self.logger.debug(f"Using cached optimization for {binary_path}")
                return self._config_cache[cache_key]

            # Analyze binary characteristics
            binary_info = self._analyze_binary_characteristics(binary_path)

            # Select appropriate profile
            profile = self._select_performance_profile(binary_info)

            # Customize profile based on system resources
            optimized_config = self._customize_profile_for_system(profile, binary_info)

            # Apply strategy-specific optimizations
            optimized_config = self._apply_strategy_optimizations(optimized_config, binary_info)

            # Cache the configuration
            self._config_cache[cache_key] = optimized_config

            self.logger.info(f"Optimized configuration created for {binary_path}")
            return optimized_config

        except Exception as e:
            self.logger.error(f"Failed to optimize for binary {binary_path}: {e}")
            # Return safe default configuration
            return self._get_safe_default_config()

    def _analyze_binary_characteristics(self, binary_path: str) -> dict[str, Any]:
        """Analyze binary file characteristics for optimization.

        Args:
            binary_path: Path to binary file to analyze.

        Returns:
            Dictionary containing file size, type, architecture, packing status,
            symbol status, section count, import count, and complexity estimate.

        """
        characteristics = {
            "file_size": 0,
            "file_type": "unknown",
            "architecture": "unknown",
            "is_packed": False,
            "is_stripped": False,
            "section_count": 0,
            "import_count": 0,
            "complexity_estimate": "medium",
        }

        try:
            # Basic file information
            stat_info = Path(binary_path).stat()
            characteristics["file_size"] = stat_info.st_size

            # Quick r2 analysis for file type and architecture
            with r2pipe.open(binary_path, flags=["-nn"]) as r2:
                try:
                    # Get basic file info
                    info = r2.cmdj("ij")
                    if info:
                        characteristics["file_type"] = info.get("core", {}).get("type", "unknown")
                        characteristics["architecture"] = info.get("bin", {}).get("arch", "unknown")
                        characteristics["is_stripped"] = not info.get("bin", {}).get("stripped", True)

                        # Get section and import counts for complexity estimation
                        sections = r2.cmdj("iSj")
                        if sections:
                            characteristics["section_count"] = len(sections)

                        imports = r2.cmdj("iij")
                        if imports:
                            characteristics["import_count"] = len(imports)

                    # Estimate complexity
                    characteristics["complexity_estimate"] = self._estimate_complexity(characteristics)

                except Exception as e:
                    self.logger.warning(f"Failed to get detailed binary info: {e}")

        except Exception as e:
            self.logger.error(f"Failed to analyze binary characteristics: {e}")

        return characteristics

    def _estimate_complexity(self, characteristics: dict[str, Any]) -> str:
        """Estimate binary complexity for optimization purposes.

        Args:
            characteristics: Dictionary of analyzed binary characteristics.

        Returns:
            Complexity level as string: "low", "medium", "high", or "very_high".

        """
        size = characteristics["file_size"]
        section_count = characteristics["section_count"]
        import_count = characteristics["import_count"]

        # Multi-factor complexity analysis
        complexity_score = 0

        # Size-based scoring
        if size > 500 * 1024 * 1024:  # >500MB
            complexity_score += 4
        elif size > 100 * 1024 * 1024:  # >100MB
            complexity_score += 3
        elif size > 10 * 1024 * 1024:  # >10MB
            complexity_score += 2
        else:
            complexity_score += 1

        # Section count factor
        if section_count > 50:
            complexity_score += 2
        elif section_count > 20:
            complexity_score += 1

        # Import count factor
        if import_count > 1000:
            complexity_score += 2
        elif import_count > 500:
            complexity_score += 1

        # Determine final complexity based on total score
        if complexity_score >= 7:
            return "very_high"
        if complexity_score >= 5:
            return "high"
        if complexity_score >= 3:
            return "medium"
        return "low"

    def _select_performance_profile(self, binary_info: dict[str, Any]) -> PerformanceProfile:
        """Select appropriate performance profile based on binary characteristics.

        Args:
            binary_info: Dictionary of analyzed binary characteristics.

        Returns:
            PerformanceProfile object matching the binary size and complexity.

        """
        file_size = binary_info["file_size"]

        for profile_name, profile in self.PERFORMANCE_PROFILES.items():
            if file_size <= profile.max_file_size:
                self.logger.debug(f"Selected profile: {profile.name} (key: {profile_name})")
                # Log profile selection for monitoring and optimization
                self._track_profile_usage(profile_name, file_size)
                return profile

        # Default to huge files profile
        return self.PERFORMANCE_PROFILES["huge_files"]

    def _customize_profile_for_system(
        self, profile: PerformanceProfile, binary_info: dict[str, Any]
    ) -> dict[str, Any]:
        """Customize profile based on current system resources.

        Args:
            profile: Base performance profile to customize.
            binary_info: Dictionary of analyzed binary characteristics.

        Returns:
            Customized configuration dictionary adapted to current system state.

        """
        system_info = self._get_system_info()

        config = {
            "analysis_level": profile.analysis_level.value,
            "memory_limit": profile.memory_limit,
            "timeout": profile.timeout,
            "parallel_workers": profile.parallel_workers,
            "chunk_size": profile.chunk_size,
            "cache_enabled": profile.cache_enabled,
            "r2_flags": profile.optimization_flags.copy(),
            "profile_name": profile.name,
            "binary_info": binary_info,
        }

        # Adjust based on available memory
        available_memory_mb = system_info["memory_available"] // (1024 * 1024)
        if available_memory_mb < config["memory_limit"]:
            config["memory_limit"] = min(available_memory_mb * 0.8, config["memory_limit"])
            # Reduce analysis level if memory is very limited
            if available_memory_mb < 1000:  # Less than 1GB available
                if config["analysis_level"] == "aaaa":
                    config["analysis_level"] = "aaa"
                elif config["analysis_level"] == "aaa":
                    config["analysis_level"] = "aa"

        # Adjust parallel workers based on CPU count and current load
        cpu_load = system_info["cpu_percent"]
        if cpu_load > 80:  # High CPU load
            config["parallel_workers"] = max(1, config["parallel_workers"] // 2)
        elif system_info["cpu_count"] < config["parallel_workers"]:
            config["parallel_workers"] = max(1, system_info["cpu_count"] - 1)

        # Adjust timeout based on system performance
        if system_info["memory_percent"] > 80 or cpu_load > 80:
            config["timeout"] = int(config["timeout"] * 1.5)

        return config

    def _apply_strategy_optimizations(self, config: dict[str, Any], binary_info: dict[str, Any]) -> dict[str, Any]:
        """Apply strategy-specific optimizations.

        Args:
            config: Base configuration to optimize.
            binary_info: Dictionary of analyzed binary characteristics.

        Returns:
            Configuration dictionary with strategy-specific optimizations applied.

        """
        if self.strategy == OptimizationStrategy.MEMORY_CONSERVATIVE:
            config = self._apply_memory_conservative_optimizations(config)
        elif self.strategy == OptimizationStrategy.SPEED_OPTIMIZED:
            config = self._apply_speed_optimizations(config)
        elif self.strategy == OptimizationStrategy.LARGE_FILE_SPECIALIZED:
            config = self._apply_large_file_optimizations(config, binary_info)
        # BALANCED strategy uses the profile as-is

        return config

    def _apply_memory_conservative_optimizations(self, config: dict[str, Any]) -> dict[str, Any]:
        """Apply memory-conservative optimizations.

        Args:
            config: Base configuration to optimize for memory conservation.

        Returns:
            Configuration with reduced memory footprint and single-threaded execution.

        """
        # Reduce memory usage
        config["memory_limit"] = int(config["memory_limit"] * 0.7)
        config["parallel_workers"] = 1  # Single threaded to save memory
        config["cache_enabled"] = False  # Disable cache to save memory

        # Add memory-saving flags
        memory_flags = [
            "-e",
            "io.cache=false",
            "-e",
            "bin.cache=false",
            "-e",
            "anal.depth=8",  # Reduce analysis depth
            "-e",
            "anal.bb.maxsize=256",  # Smaller basic blocks
        ]
        config["r2_flags"].extend(memory_flags)

        # Use lighter analysis
        if config["analysis_level"] == "aaaa" or config["analysis_level"] == "aaa":
            config["analysis_level"] = "aa"

        return config

    def _apply_speed_optimizations(self, config: dict[str, Any]) -> dict[str, Any]:
        """Apply speed-focused optimizations.

        Args:
            config: Base configuration to optimize for speed.

        Returns:
            Configuration with increased parallelism, caching, and reduced timeouts.

        """
        # Increase parallel workers if system allows
        system_info = self._get_system_info()
        if system_info["memory_available"] > 4 * 1024 * 1024 * 1024:  # >4GB available
            config["parallel_workers"] = min(system_info["cpu_count"], 8)

        # Enable aggressive caching
        config["cache_enabled"] = True

        # Add speed optimization flags
        speed_flags = [
            "-e",
            "io.cache=true",
            "-e",
            "bin.cache=true",
            "-e",
            "anal.jmp.tbl=true",
            "-e",
            "anal.hasnext=true",
        ]
        config["r2_flags"].extend(speed_flags)

        # Reduce timeout for faster iterations
        config["timeout"] = int(config["timeout"] * 0.8)

        return config

    def _apply_large_file_optimizations(self, config: dict[str, Any], binary_info: dict[str, Any]) -> dict[str, Any]:
        """Apply optimizations specifically for large files.

        Args:
            config: Base configuration to optimize for large files.
            binary_info: Dictionary of analyzed binary characteristics.

        Returns:
            Configuration optimized for handling large binaries with minimal analysis depth.

        """
        file_size = binary_info["file_size"]

        # Use memory mapping for very large files
        if file_size > 500 * 1024 * 1024:  # >500MB
            large_file_flags = [
                "-e",
                "io.cache=false",
                "-e",
                "bin.cache=false",
                "-e",
                "anal.depth=4",
                "-e",
                "anal.bb.maxsize=128",
                "-e",
                "esil.timeout=5",
                "-e",
                "anal.timeout=" + str(config["timeout"]),
            ]
            config["r2_flags"].extend(large_file_flags)

            # Use minimal analysis for very large files
            config["analysis_level"] = "a"
            config["parallel_workers"] = 1
            config["cache_enabled"] = False

        # Increase chunk size for large files
        if file_size > 100 * 1024 * 1024:  # >100MB
            config["chunk_size"] = min(50 * 1024 * 1024, file_size // 10)

        return config

    def _get_safe_default_config(self) -> dict[str, Any]:
        """Get safe default configuration for fallback.

        Returns:
            Safe configuration dictionary with conservative settings.

        """
        return {
            "analysis_level": "aa",
            "memory_limit": 500,
            "timeout": 300,
            "parallel_workers": 1,
            "chunk_size": 1024 * 1024,
            "cache_enabled": True,
            "r2_flags": ["-e", "anal.timeout=300"],
            "profile_name": "Safe Default",
            "binary_info": {},
        }

    def start_monitoring(self, interval: float = 1.0) -> None:
        """Start resource monitoring.

        Args:
            interval: Monitoring interval in seconds. Defaults to 1.0.

        """
        if not self._monitoring:
            self._monitoring = True
            self._monitor_thread = threading.Thread(
                target=self._monitor_resources,
                args=(interval,),
                daemon=True,
            )
            self._monitor_thread.start()
            self.logger.info("Resource monitoring started")

    def stop_monitoring(self) -> None:
        """Stop resource monitoring."""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            self._monitor_thread = None
            self.logger.info("Resource monitoring stopped")

    def _monitor_resources(self, interval: float) -> None:
        """Monitor system resources during analysis.

        Args:
            interval: Monitoring interval in seconds.

        """
        while self._monitoring:
            try:
                # Get current resource usage
                memory = psutil.virtual_memory()
                cpu = psutil.cpu_percent(interval=0.1)

                # Record metrics
                self.performance_metrics["memory_usage"].append(memory.percent)
                self.performance_metrics["cpu_usage"].append(cpu)

                # Update peaks
                self.performance_metrics["resource_peaks"]["memory"] = max(
                    self.performance_metrics["resource_peaks"]["memory"],
                    memory.percent,
                )
                self.performance_metrics["resource_peaks"]["cpu"] = max(
                    self.performance_metrics["resource_peaks"]["cpu"],
                    cpu,
                )

                # Keep only last 100 measurements
                for metric in ["memory_usage", "cpu_usage"]:
                    if len(self.performance_metrics[metric]) > 100:
                        self.performance_metrics[metric] = self.performance_metrics[metric][-100:]

                # Check for resource pressure and trigger optimization
                if memory.percent > self.adaptive_thresholds["memory_critical"]:
                    self._trigger_emergency_optimization("memory_critical")
                elif cpu > self.adaptive_thresholds["cpu_throttle"]:
                    self._trigger_emergency_optimization("cpu_high")

                time.sleep(interval)

            except Exception as e:
                self.logger.error(f"Resource monitoring error: {e}")
                time.sleep(interval * 2)

    def _trigger_emergency_optimization(self, reason: str) -> None:
        """Trigger emergency optimization due to resource pressure.

        Args:
            reason: Reason for emergency optimization (e.g., "memory_critical", "cpu_high").

        """
        self.logger.warning(f"Emergency optimization triggered: {reason}")

        if reason == "memory_critical":
            # Force garbage collection
            gc.collect()

            # Clear caches
            self._config_cache.clear()

            # Reduce monitoring frequency
            time.sleep(2)

        elif reason == "cpu_high":
            # Throttle operations
            time.sleep(1)

    def optimize_r2_session(self, r2_session: object, config: dict[str, Any]) -> None:
        """Apply optimizations to active r2 session.

        Args:
            r2_session: Active radare2 session object.
            config: Configuration dictionary with optimization flags.

        """
        try:
            # Apply configuration flags
            for i in range(0, len(config["r2_flags"]), 2):
                if i + 1 < len(config["r2_flags"]):
                    flag = config["r2_flags"][i + 1]
                    r2_session.cmd(f"e {flag}")

            # Set memory limits
            r2_session.cmd(f"e anal.timeout={config['timeout']}")

            self.logger.debug("R2 session optimizations applied")

        except Exception as e:
            self.logger.error(f"Failed to optimize r2 session: {e}")

    def _track_profile_usage(self, profile_name: str, file_size: int) -> None:
        """Track profile usage for optimization insights.

        Args:
            profile_name: Name of the performance profile used.
            file_size: Size of the analyzed binary in bytes.

        """
        if not hasattr(self, "profile_usage_stats"):
            self.profile_usage_stats = {}

        if profile_name not in self.profile_usage_stats:
            self.profile_usage_stats[profile_name] = {
                "usage_count": 0,
                "total_file_size": 0,
                "avg_file_size": 0,
            }

        stats = self.profile_usage_stats[profile_name]
        stats["usage_count"] += 1
        stats["total_file_size"] += file_size
        stats["avg_file_size"] = stats["total_file_size"] / stats["usage_count"]

        self.logger.debug(f"Profile {profile_name} used {stats['usage_count']} times, avg file size: {stats['avg_file_size']:.2f} bytes")

    def get_performance_report(self) -> dict[str, Any]:
        """Generate comprehensive performance report.

        Returns:
            Dictionary containing system info, strategy, metrics, and recommendations.

        """
        report = {
            "system_info": self._get_system_info(),
            "strategy": self.strategy.value,
            "metrics": {
                "memory_usage": {
                    "current": self.performance_metrics["memory_usage"][-1] if self.performance_metrics["memory_usage"] else 0,
                    "average": sum(self.performance_metrics["memory_usage"]) / len(self.performance_metrics["memory_usage"])
                    if self.performance_metrics["memory_usage"]
                    else 0,
                    "peak": self.performance_metrics["resource_peaks"]["memory"],
                },
                "cpu_usage": {
                    "current": self.performance_metrics["cpu_usage"][-1] if self.performance_metrics["cpu_usage"] else 0,
                    "average": sum(self.performance_metrics["cpu_usage"]) / len(self.performance_metrics["cpu_usage"])
                    if self.performance_metrics["cpu_usage"]
                    else 0,
                    "peak": self.performance_metrics["resource_peaks"]["cpu"],
                },
                "analysis_times": self.performance_metrics["analysis_times"].copy(),
                "optimization_effectiveness": self.performance_metrics["optimization_effectiveness"].copy(),
            },
            "recommendations": self._generate_recommendations(),
        }

        return report

    def _generate_recommendations(self) -> list[str]:
        """Generate performance optimization recommendations.

        Returns:
            List of optimization recommendation strings.

        """
        recommendations = []

        # Memory recommendations
        if self.performance_metrics["resource_peaks"]["memory"] > 90:
            recommendations.append("Consider using memory-conservative strategy for future analyses")
            recommendations.append("Reduce parallel workers to decrease memory usage")

        # CPU recommendations
        if self.performance_metrics["resource_peaks"]["cpu"] > 90:
            recommendations.append("Consider reducing analysis depth for better CPU performance")

        # General recommendations
        if len(self._config_cache) > 50:
            recommendations.append("Clear configuration cache to free memory")

        system_info = self._get_system_info()
        if system_info["memory_available"] < 1024 * 1024 * 1024:  # <1GB available
            recommendations.append("Available memory is low, consider closing other applications")

        return recommendations

    def benchmark_analysis_types(self, binary_path: str, analysis_types: list[str]) -> dict[str, dict[str, float]]:
        """Benchmark different analysis types for performance comparison.

        Args:
            binary_path: Path to binary file for benchmarking.
            analysis_types: List of analysis type names to benchmark.

        Returns:
            Dictionary mapping analysis types to performance metrics (duration,
            memory delta, memory peak).

        """
        results = {}

        for analysis_type in analysis_types:
            try:
                start_time = time.time()
                start_memory = psutil.virtual_memory().percent

                # Run lightweight version of analysis for benchmarking
                with r2pipe.open(binary_path, flags=["-nn"]) as r2:
                    if analysis_type == "basic":
                        r2.cmd("a")
                    elif analysis_type == "functions":
                        r2.cmd("aa")
                    elif analysis_type == "comprehensive":
                        r2.cmd("aaa")
                    elif analysis_type == "strings":
                        r2.cmdj("izzj")
                    elif analysis_type == "imports":
                        r2.cmdj("iij")

                end_time = time.time()
                end_memory = psutil.virtual_memory().percent

                results[analysis_type] = {
                    "duration": end_time - start_time,
                    "memory_delta": end_memory - start_memory,
                    "memory_peak": max(start_memory, end_memory),
                }

            except Exception as e:
                self.logger.error(f"Benchmark failed for {analysis_type}: {e}")
                results[analysis_type] = {
                    "duration": float("inf"),
                    "memory_delta": 0,
                    "memory_peak": 0,
                    "error": str(e),
                }

        return results

    def cleanup(self) -> None:
        """Cleanup optimizer resources.

        Stops monitoring, clears caches, and resets metrics.

        """
        try:
            self.stop_monitoring()
            self._config_cache.clear()
            self.performance_metrics = {
                "memory_usage": [],
                "cpu_usage": [],
                "analysis_times": {},
                "optimization_effectiveness": {},
                "resource_peaks": {"memory": 0, "cpu": 0},
            }

            # Force garbage collection
            gc.collect()

            self.logger.info("R2PerformanceOptimizer cleanup completed")

        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")


def create_performance_optimizer(
    strategy: OptimizationStrategy = OptimizationStrategy.BALANCED,
) -> R2PerformanceOptimizer:
    """Create performance optimizer instance.

    Args:
        strategy: The optimization strategy to use. Defaults to BALANCED.

    Returns:
        Initialized R2PerformanceOptimizer instance.

    """
    return R2PerformanceOptimizer(strategy)


def optimize_for_large_binary(binary_path: str) -> dict[str, Any]:
    """Quick optimization for large binary files.

    Args:
        binary_path: Path to binary file for optimization.

    Returns:
        Optimized configuration dictionary with large-file-specialized settings.

    """
    optimizer = create_performance_optimizer(OptimizationStrategy.LARGE_FILE_SPECIALIZED)
    return optimizer.optimize_for_binary(binary_path)


__all__ = [
    "AnalysisLevel",
    "OptimizationStrategy",
    "PerformanceProfile",
    "R2PerformanceOptimizer",
    "create_performance_optimizer",
    "optimize_for_large_binary",
]
