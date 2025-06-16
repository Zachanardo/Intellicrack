"""
Radare2 Performance Optimization for Large Binary Analysis

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import gc
import multiprocessing
import os
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List

import psutil

try:
    import r2pipe
except ImportError:
    r2pipe = None

from ...utils.logger import get_logger

logger = get_logger(__name__)


class OptimizationStrategy(Enum):
    """Available optimization strategies"""
    MEMORY_CONSERVATIVE = "memory_conservative"
    SPEED_OPTIMIZED = "speed_optimized"
    BALANCED = "balanced"
    LARGE_FILE_SPECIALIZED = "large_file_specialized"
    CUSTOM = "custom"


class AnalysisLevel(Enum):
    """Analysis depth levels for performance tuning"""
    MINIMAL = "a"          # Basic analysis
    LIGHT = "aa"           # Light analysis
    STANDARD = "aaa"       # Standard analysis
    COMPREHENSIVE = "aaaa" # Full analysis
    DEEP = "aaaaa"         # Deep analysis


@dataclass
class PerformanceProfile:
    """Performance profile for different binary sizes and types"""
    name: str
    max_file_size: int  # In bytes
    analysis_level: AnalysisLevel
    memory_limit: int   # In MB
    timeout: int       # In seconds
    parallel_workers: int
    chunk_size: int    # For large file processing
    cache_enabled: bool
    optimization_flags: List[str]
    description: str


class R2PerformanceOptimizer:
    """
    Comprehensive performance optimizer for radare2 operations.
    
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
        'small_files': PerformanceProfile(
            name="Small Files (<10MB)",
            max_file_size=10 * 1024 * 1024,  # 10MB
            analysis_level=AnalysisLevel.COMPREHENSIVE,
            memory_limit=500,  # 500MB
            timeout=300,  # 5 minutes
            parallel_workers=4,
            chunk_size=1024 * 1024,  # 1MB
            cache_enabled=True,
            optimization_flags=['-e', 'anal.timeout=300'],
            description="Full analysis for small binaries"
        ),
        'medium_files': PerformanceProfile(
            name="Medium Files (10MB-100MB)",
            max_file_size=100 * 1024 * 1024,  # 100MB
            analysis_level=AnalysisLevel.STANDARD,
            memory_limit=1000,  # 1GB
            timeout=600,  # 10 minutes
            parallel_workers=3,
            chunk_size=5 * 1024 * 1024,  # 5MB
            cache_enabled=True,
            optimization_flags=['-e', 'anal.timeout=600', '-e', 'esil.timeout=60'],
            description="Balanced analysis for medium binaries"
        ),
        'large_files': PerformanceProfile(
            name="Large Files (100MB-1GB)",
            max_file_size=1024 * 1024 * 1024,  # 1GB
            analysis_level=AnalysisLevel.LIGHT,
            memory_limit=2000,  # 2GB
            timeout=1800,  # 30 minutes
            parallel_workers=2,
            chunk_size=10 * 1024 * 1024,  # 10MB
            cache_enabled=True,
            optimization_flags=[
                '-e', 'anal.timeout=1800',
                '-e', 'esil.timeout=30',
                '-e', 'anal.depth=16',
                '-e', 'anal.bb.maxsize=1024'
            ],
            description="Light analysis for large binaries"
        ),
        'huge_files': PerformanceProfile(
            name="Huge Files (>1GB)",
            max_file_size=float('inf'),
            analysis_level=AnalysisLevel.MINIMAL,
            memory_limit=4000,  # 4GB
            timeout=3600,  # 1 hour
            parallel_workers=1,
            chunk_size=50 * 1024 * 1024,  # 50MB
            cache_enabled=False,  # Disable cache for huge files
            optimization_flags=[
                '-e', 'anal.timeout=3600',
                '-e', 'esil.timeout=10',
                '-e', 'anal.depth=8',
                '-e', 'anal.bb.maxsize=512',
                '-e', 'io.cache=false',
                '-e', 'bin.cache=false'
            ],
            description="Minimal analysis for huge binaries"
        )
    }

    def __init__(self, strategy: OptimizationStrategy = OptimizationStrategy.BALANCED):
        self.strategy = strategy
        self.logger = logger

        # System information
        self.system_info = self._get_system_info()

        # Performance monitoring
        self.performance_metrics = {
            'memory_usage': [],
            'cpu_usage': [],
            'analysis_times': {},
            'optimization_effectiveness': {},
            'resource_peaks': {'memory': 0, 'cpu': 0}
        }

        # Resource monitoring
        self._monitoring = False
        self._monitor_thread = None

        # Cache for optimized configurations
        self._config_cache = {}

        # Adaptive thresholds
        self.adaptive_thresholds = {
            'memory_warning': 0.8,  # 80% of available memory
            'memory_critical': 0.9,  # 90% of available memory
            'cpu_throttle': 0.9,     # 90% CPU usage
            'analysis_timeout_multiplier': 1.5
        }

        self.logger.info(f"R2PerformanceOptimizer initialized with {strategy.value} strategy")

    def _get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information"""
        return {
            'cpu_count': multiprocessing.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'memory_available': psutil.virtual_memory().available,
            'memory_percent': psutil.virtual_memory().percent,
            'cpu_percent': psutil.cpu_percent(interval=1),
            'disk_usage': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent
        }

    def optimize_for_binary(self, binary_path: str) -> Dict[str, Any]:
        """
        Create optimized configuration for specific binary.
        
        Args:
            binary_path: Path to binary file
            
        Returns:
            Dict containing optimized configuration
        """
        try:
            # Check cache first
            cache_key = f"{binary_path}_{os.path.getmtime(binary_path)}"
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

    def _analyze_binary_characteristics(self, binary_path: str) -> Dict[str, Any]:
        """Analyze binary file characteristics for optimization"""
        characteristics = {
            'file_size': 0,
            'file_type': 'unknown',
            'architecture': 'unknown',
            'is_packed': False,
            'is_stripped': False,
            'section_count': 0,
            'import_count': 0,
            'complexity_estimate': 'medium'
        }

        try:
            # Basic file information
            stat_info = os.stat(binary_path)
            characteristics['file_size'] = stat_info.st_size

            # Quick r2 analysis for file type and architecture
            with r2pipe.open(binary_path, flags=['-nn']) as r2:
                try:
                    # Get basic file info
                    info = r2.cmdj('ij')
                    if info:
                        characteristics['file_type'] = info.get('core', {}).get('type', 'unknown')
                        characteristics['architecture'] = info.get('bin', {}).get('arch', 'unknown')
                        characteristics['is_stripped'] = not info.get('bin', {}).get('stripped', True)

                        # Get section and import counts for complexity estimation
                        sections = r2.cmdj('iSj')
                        if sections:
                            characteristics['section_count'] = len(sections)

                        imports = r2.cmdj('iij')
                        if imports:
                            characteristics['import_count'] = len(imports)

                    # Estimate complexity
                    characteristics['complexity_estimate'] = self._estimate_complexity(characteristics)

                except Exception as e:
                    self.logger.warning(f"Failed to get detailed binary info: {e}")

        except Exception as e:
            self.logger.error(f"Failed to analyze binary characteristics: {e}")

        return characteristics

    def _estimate_complexity(self, characteristics: Dict[str, Any]) -> str:
        """Estimate binary complexity for optimization purposes"""
        size = characteristics['file_size']
        section_count = characteristics['section_count']
        import_count = characteristics['import_count']

        # Size-based complexity
        if size > 500 * 1024 * 1024:  # >500MB
            return 'very_high'
        elif size > 100 * 1024 * 1024:  # >100MB
            return 'high'
        elif size > 10 * 1024 * 1024:  # >10MB
            return 'medium'
        else:
            return 'low'

    def _select_performance_profile(self, binary_info: Dict[str, Any]) -> PerformanceProfile:
        """Select appropriate performance profile based on binary characteristics"""
        file_size = binary_info['file_size']

        for profile_name, profile in self.PERFORMANCE_PROFILES.items():
            if file_size <= profile.max_file_size:
                self.logger.debug(f"Selected profile: {profile.name}")
                return profile

        # Default to huge files profile
        return self.PERFORMANCE_PROFILES['huge_files']

    def _customize_profile_for_system(self, profile: PerformanceProfile, binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """Customize profile based on current system resources"""
        system_info = self._get_system_info()

        config = {
            'analysis_level': profile.analysis_level.value,
            'memory_limit': profile.memory_limit,
            'timeout': profile.timeout,
            'parallel_workers': profile.parallel_workers,
            'chunk_size': profile.chunk_size,
            'cache_enabled': profile.cache_enabled,
            'r2_flags': profile.optimization_flags.copy(),
            'profile_name': profile.name,
            'binary_info': binary_info
        }

        # Adjust based on available memory
        available_memory_mb = system_info['memory_available'] // (1024 * 1024)
        if available_memory_mb < config['memory_limit']:
            config['memory_limit'] = min(available_memory_mb * 0.8, config['memory_limit'])
            # Reduce analysis level if memory is very limited
            if available_memory_mb < 1000:  # Less than 1GB available
                if config['analysis_level'] == 'aaaa':
                    config['analysis_level'] = 'aaa'
                elif config['analysis_level'] == 'aaa':
                    config['analysis_level'] = 'aa'

        # Adjust parallel workers based on CPU count and current load
        cpu_load = system_info['cpu_percent']
        if cpu_load > 80:  # High CPU load
            config['parallel_workers'] = max(1, config['parallel_workers'] // 2)
        elif system_info['cpu_count'] < config['parallel_workers']:
            config['parallel_workers'] = max(1, system_info['cpu_count'] - 1)

        # Adjust timeout based on system performance
        if system_info['memory_percent'] > 80 or cpu_load > 80:
            config['timeout'] = int(config['timeout'] * 1.5)

        return config

    def _apply_strategy_optimizations(self, config: Dict[str, Any], binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """Apply strategy-specific optimizations"""
        if self.strategy == OptimizationStrategy.MEMORY_CONSERVATIVE:
            config = self._apply_memory_conservative_optimizations(config)
        elif self.strategy == OptimizationStrategy.SPEED_OPTIMIZED:
            config = self._apply_speed_optimizations(config)
        elif self.strategy == OptimizationStrategy.LARGE_FILE_SPECIALIZED:
            config = self._apply_large_file_optimizations(config, binary_info)
        # BALANCED strategy uses the profile as-is

        return config

    def _apply_memory_conservative_optimizations(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply memory-conservative optimizations"""
        # Reduce memory usage
        config['memory_limit'] = int(config['memory_limit'] * 0.7)
        config['parallel_workers'] = 1  # Single threaded to save memory
        config['cache_enabled'] = False  # Disable cache to save memory

        # Add memory-saving flags
        memory_flags = [
            '-e', 'io.cache=false',
            '-e', 'bin.cache=false',
            '-e', 'anal.depth=8',  # Reduce analysis depth
            '-e', 'anal.bb.maxsize=256'  # Smaller basic blocks
        ]
        config['r2_flags'].extend(memory_flags)

        # Use lighter analysis
        if config['analysis_level'] == 'aaaa':
            config['analysis_level'] = 'aa'
        elif config['analysis_level'] == 'aaa':
            config['analysis_level'] = 'aa'

        return config

    def _apply_speed_optimizations(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply speed-focused optimizations"""
        # Increase parallel workers if system allows
        system_info = self._get_system_info()
        if system_info['memory_available'] > 4 * 1024 * 1024 * 1024:  # >4GB available
            config['parallel_workers'] = min(system_info['cpu_count'], 8)

        # Enable aggressive caching
        config['cache_enabled'] = True

        # Add speed optimization flags
        speed_flags = [
            '-e', 'io.cache=true',
            '-e', 'bin.cache=true',
            '-e', 'anal.jmp.tbl=true',
            '-e', 'anal.hasnext=true'
        ]
        config['r2_flags'].extend(speed_flags)

        # Reduce timeout for faster iterations
        config['timeout'] = int(config['timeout'] * 0.8)

        return config

    def _apply_large_file_optimizations(self, config: Dict[str, Any], binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """Apply optimizations specifically for large files"""
        file_size = binary_info['file_size']

        # Use memory mapping for very large files
        if file_size > 500 * 1024 * 1024:  # >500MB
            large_file_flags = [
                '-e', 'io.cache=false',
                '-e', 'bin.cache=false',
                '-e', 'anal.depth=4',
                '-e', 'anal.bb.maxsize=128',
                '-e', 'esil.timeout=5',
                '-e', 'anal.timeout=' + str(config['timeout'])
            ]
            config['r2_flags'].extend(large_file_flags)

            # Use minimal analysis for very large files
            config['analysis_level'] = 'a'
            config['parallel_workers'] = 1
            config['cache_enabled'] = False

        # Increase chunk size for large files
        if file_size > 100 * 1024 * 1024:  # >100MB
            config['chunk_size'] = min(50 * 1024 * 1024, file_size // 10)

        return config

    def _get_safe_default_config(self) -> Dict[str, Any]:
        """Get safe default configuration for fallback"""
        return {
            'analysis_level': 'aa',
            'memory_limit': 500,
            'timeout': 300,
            'parallel_workers': 1,
            'chunk_size': 1024 * 1024,
            'cache_enabled': True,
            'r2_flags': ['-e', 'anal.timeout=300'],
            'profile_name': 'Safe Default',
            'binary_info': {}
        }

    def start_monitoring(self, interval: float = 1.0):
        """Start resource monitoring"""
        if not self._monitoring:
            self._monitoring = True
            self._monitor_thread = threading.Thread(
                target=self._monitor_resources,
                args=(interval,),
                daemon=True
            )
            self._monitor_thread.start()
            self.logger.info("Resource monitoring started")

    def stop_monitoring(self):
        """Stop resource monitoring"""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            self._monitor_thread = None
            self.logger.info("Resource monitoring stopped")

    def _monitor_resources(self, interval: float):
        """Monitor system resources during analysis"""
        while self._monitoring:
            try:
                # Get current resource usage
                memory = psutil.virtual_memory()
                cpu = psutil.cpu_percent(interval=0.1)

                # Record metrics
                self.performance_metrics['memory_usage'].append(memory.percent)
                self.performance_metrics['cpu_usage'].append(cpu)

                # Update peaks
                self.performance_metrics['resource_peaks']['memory'] = max(
                    self.performance_metrics['resource_peaks']['memory'],
                    memory.percent
                )
                self.performance_metrics['resource_peaks']['cpu'] = max(
                    self.performance_metrics['resource_peaks']['cpu'],
                    cpu
                )

                # Keep only last 100 measurements
                for metric in ['memory_usage', 'cpu_usage']:
                    if len(self.performance_metrics[metric]) > 100:
                        self.performance_metrics[metric] = self.performance_metrics[metric][-100:]

                # Check for resource pressure and trigger optimization
                if memory.percent > self.adaptive_thresholds['memory_critical']:
                    self._trigger_emergency_optimization('memory_critical')
                elif cpu > self.adaptive_thresholds['cpu_throttle']:
                    self._trigger_emergency_optimization('cpu_high')

                time.sleep(interval)

            except Exception as e:
                self.logger.error(f"Resource monitoring error: {e}")
                time.sleep(interval * 2)

    def _trigger_emergency_optimization(self, reason: str):
        """Trigger emergency optimization due to resource pressure"""
        self.logger.warning(f"Emergency optimization triggered: {reason}")

        if reason == 'memory_critical':
            # Force garbage collection
            gc.collect()

            # Clear caches
            self._config_cache.clear()

            # Reduce monitoring frequency
            time.sleep(2)

        elif reason == 'cpu_high':
            # Throttle operations
            time.sleep(1)

    def optimize_r2_session(self, r2_session, config: Dict[str, Any]):
        """Apply optimizations to active r2 session"""
        try:
            # Apply configuration flags
            for i in range(0, len(config['r2_flags']), 2):
                if i + 1 < len(config['r2_flags']):
                    flag = config['r2_flags'][i+1]
                    r2_session.cmd(f"e {flag}")

            # Set memory limits
            r2_session.cmd(f"e anal.timeout={config['timeout']}")

            self.logger.debug("R2 session optimizations applied")

        except Exception as e:
            self.logger.error(f"Failed to optimize r2 session: {e}")

    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        report = {
            'system_info': self._get_system_info(),
            'strategy': self.strategy.value,
            'metrics': {
                'memory_usage': {
                    'current': self.performance_metrics['memory_usage'][-1] if self.performance_metrics['memory_usage'] else 0,
                    'average': sum(self.performance_metrics['memory_usage']) / len(self.performance_metrics['memory_usage']) if self.performance_metrics['memory_usage'] else 0,
                    'peak': self.performance_metrics['resource_peaks']['memory']
                },
                'cpu_usage': {
                    'current': self.performance_metrics['cpu_usage'][-1] if self.performance_metrics['cpu_usage'] else 0,
                    'average': sum(self.performance_metrics['cpu_usage']) / len(self.performance_metrics['cpu_usage']) if self.performance_metrics['cpu_usage'] else 0,
                    'peak': self.performance_metrics['resource_peaks']['cpu']
                },
                'analysis_times': self.performance_metrics['analysis_times'].copy(),
                'optimization_effectiveness': self.performance_metrics['optimization_effectiveness'].copy()
            },
            'recommendations': self._generate_recommendations()
        }

        return report

    def _generate_recommendations(self) -> List[str]:
        """Generate performance optimization recommendations"""
        recommendations = []

        # Memory recommendations
        if self.performance_metrics['resource_peaks']['memory'] > 90:
            recommendations.append("Consider using memory-conservative strategy for future analyses")
            recommendations.append("Reduce parallel workers to decrease memory usage")

        # CPU recommendations
        if self.performance_metrics['resource_peaks']['cpu'] > 90:
            recommendations.append("Consider reducing analysis depth for better CPU performance")

        # General recommendations
        if len(self._config_cache) > 50:
            recommendations.append("Clear configuration cache to free memory")

        system_info = self._get_system_info()
        if system_info['memory_available'] < 1024 * 1024 * 1024:  # <1GB available
            recommendations.append("Available memory is low, consider closing other applications")

        return recommendations

    def benchmark_analysis_types(self, binary_path: str, analysis_types: List[str]) -> Dict[str, Dict[str, float]]:
        """Benchmark different analysis types for performance comparison"""
        results = {}

        for analysis_type in analysis_types:
            try:
                start_time = time.time()
                start_memory = psutil.virtual_memory().percent

                # Run lightweight version of analysis for benchmarking
                with r2pipe.open(binary_path, flags=['-nn']) as r2:
                    if analysis_type == 'basic':
                        r2.cmd('a')
                    elif analysis_type == 'functions':
                        r2.cmd('aa')
                    elif analysis_type == 'comprehensive':
                        r2.cmd('aaa')
                    elif analysis_type == 'strings':
                        r2.cmdj('izzj')
                    elif analysis_type == 'imports':
                        r2.cmdj('iij')

                end_time = time.time()
                end_memory = psutil.virtual_memory().percent

                results[analysis_type] = {
                    'duration': end_time - start_time,
                    'memory_delta': end_memory - start_memory,
                    'memory_peak': max(start_memory, end_memory)
                }

            except Exception as e:
                self.logger.error(f"Benchmark failed for {analysis_type}: {e}")
                results[analysis_type] = {
                    'duration': float('inf'),
                    'memory_delta': 0,
                    'memory_peak': 0,
                    'error': str(e)
                }

        return results

    def cleanup(self):
        """Cleanup optimizer resources"""
        try:
            self.stop_monitoring()
            self._config_cache.clear()
            self.performance_metrics = {
                'memory_usage': [],
                'cpu_usage': [],
                'analysis_times': {},
                'optimization_effectiveness': {},
                'resource_peaks': {'memory': 0, 'cpu': 0}
            }

            # Force garbage collection
            gc.collect()

            self.logger.info("R2PerformanceOptimizer cleanup completed")

        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")


def create_performance_optimizer(strategy: OptimizationStrategy = OptimizationStrategy.BALANCED) -> R2PerformanceOptimizer:
    """Create performance optimizer instance"""
    return R2PerformanceOptimizer(strategy)


def optimize_for_large_binary(binary_path: str) -> Dict[str, Any]:
    """
    Quick optimization for large binary files.
    
    Args:
        binary_path: Path to binary file
        
    Returns:
        Optimized configuration
    """
    optimizer = create_performance_optimizer(OptimizationStrategy.LARGE_FILE_SPECIALIZED)
    return optimizer.optimize_for_binary(binary_path)


__all__ = [
    'R2PerformanceOptimizer',
    'OptimizationStrategy',
    'AnalysisLevel',
    'PerformanceProfile',
    'create_performance_optimizer',
    'optimize_for_large_binary'
]
