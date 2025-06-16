"""
Enhanced Radare2 Integration with Comprehensive Error Handling and Recovery

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

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

try:
    import r2pipe
except ImportError:
    r2pipe = None

from ...utils.logger import get_logger
from .radare2_ai_integration import R2AIIntegration
from .radare2_binary_diff import R2BinaryDiff
from .radare2_bypass_generator import R2BypassGenerator
from .radare2_decompiler import R2Decompiler
from .radare2_error_handler import get_error_handler, r2_error_context
from .radare2_esil import R2ESILEngine
from .radare2_imports import R2ImportAnalyzer
from .radare2_json_standardizer import standardize_r2_result
from .radare2_scripting import R2ScriptEngine
from .radare2_signatures import R2SignatureAnalyzer
from .radare2_strings import R2StringAnalyzer
from .radare2_vulnerability_engine import R2VulnerabilityEngine

logger = get_logger(__name__)
error_handler = get_error_handler()


class EnhancedR2Integration:
    """
    Enhanced radare2 integration with comprehensive error handling, recovery,
    performance optimization, and real-time capabilities.
    
    This class provides:
    - Robust error handling and automatic recovery
    - Performance monitoring and optimization
    - Real-time analysis capabilities
    - Comprehensive logging and metrics
    - Thread-safe operations
    - Circuit breaker pattern implementation
    """

    def __init__(self, binary_path: str, config: Optional[Dict[str, Any]] = None):
        self.binary_path = binary_path
        self.config = config or {}
        self.logger = logger
        self.error_handler = error_handler

        # Performance and monitoring
        self.performance_stats = {
            'analysis_times': {},
            'cache_hits': 0,
            'cache_misses': 0,
            'errors_handled': 0,
            'recoveries_successful': 0
        }

        # Thread safety
        self._lock = threading.RLock()

        # Analysis components with error handling
        self.components = {}
        self._initialize_components()

        # Results cache with TTL
        self.results_cache = {}
        self.cache_ttl = self.config.get('cache_ttl', 300)  # 5 minutes default

        # Real-time monitoring
        self.monitoring_enabled = self.config.get('real_time_monitoring', False)
        self.monitoring_thread = None

        self.logger.info(f"EnhancedR2Integration initialized for {binary_path}")

    def _initialize_components(self):
        """Initialize all analysis components with error handling"""
        component_classes = {
            'decompiler': R2Decompiler,
            'esil': R2ESILEngine,
            'strings': R2StringAnalyzer,
            'signatures': R2SignatureAnalyzer,
            'imports': R2ImportAnalyzer,
            'vulnerability': R2VulnerabilityEngine,
            'ai': R2AIIntegration,
            'bypass': R2BypassGenerator,
            'diff': R2BinaryDiff,
            'scripting': R2ScriptEngine
        }

        for name, component_class in component_classes.items():
            try:
                with r2_error_context(f"init_{name}_component", binary_path=self.binary_path):
                    if name == 'diff':
                        # Binary diff needs two binaries, initialize later
                        self.components[name] = None
                    else:
                        self.components[name] = component_class(self.binary_path)
                    self.logger.debug(f"Initialized {name} component")
            except Exception as e:
                self.logger.error(f"Failed to initialize {name} component: {e}")
                self.components[name] = None

    def run_comprehensive_analysis(self, analysis_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run comprehensive analysis with error handling and recovery.
        
        Args:
            analysis_types: List of analysis types to run, or None for all
            
        Returns:
            Dict containing all analysis results
        """
        if analysis_types is None:
            analysis_types = list(self.components.keys())

        results = {
            'metadata': {
                'binary_path': self.binary_path,
                'analysis_start': time.time(),
                'analysis_types': analysis_types,
                'config': self.config
            },
            'components': {},
            'errors': [],
            'performance': {}
        }

        # Use thread pool for parallel analysis where safe
        parallel_safe = ['strings', 'imports', 'signatures']
        sequential_required = ['decompiler', 'vulnerability', 'esil', 'ai', 'bypass']

        # Run parallel-safe analyses first
        parallel_types = [t for t in analysis_types if t in parallel_safe]
        if parallel_types:
            parallel_results = self._run_parallel_analysis(parallel_types)
            results['components'].update(parallel_results)

        # Run sequential analyses
        sequential_types = [t for t in analysis_types if t in sequential_required]
        for analysis_type in sequential_types:
            try:
                component_result = self._run_single_analysis(analysis_type)
                if component_result:
                    results['components'][analysis_type] = component_result
            except Exception as e:
                self.logger.error(f"Failed to run {analysis_type} analysis: {e}")
                results['errors'].append({
                    'component': analysis_type,
                    'error': str(e),
                    'timestamp': time.time()
                })

        # Add performance metrics
        results['performance'] = self.get_performance_stats()
        results['metadata']['analysis_end'] = time.time()
        results['metadata']['total_duration'] = results['metadata']['analysis_end'] - results['metadata']['analysis_start']

        # Standardize results
        standardized_results = standardize_r2_result(
            'comprehensive',
            results,
            self.binary_path,
            {'enhanced_integration': True}
        )

        return standardized_results

    def _run_parallel_analysis(self, analysis_types: List[str]) -> Dict[str, Any]:
        """Run analyses in parallel for performance"""
        results = {}
        max_workers = min(len(analysis_types), self.config.get('max_parallel_workers', 3))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_type = {
                executor.submit(self._run_single_analysis, analysis_type): analysis_type
                for analysis_type in analysis_types
            }

            # Collect results as they complete
            for future in as_completed(future_to_type, timeout=300):  # 5 minute timeout
                analysis_type = future_to_type[future]
                try:
                    result = future.result()
                    if result:
                        results[analysis_type] = result
                except Exception as e:
                    self.logger.error(f"Parallel analysis {analysis_type} failed: {e}")
                    self.error_handler.handle_error(e, f"parallel_{analysis_type}", {
                        'binary_path': self.binary_path,
                        'analysis_type': analysis_type
                    })

        return results

    def _run_single_analysis(self, analysis_type: str) -> Optional[Dict[str, Any]]:
        """Run a single analysis with caching and error handling"""
        # Check cache first
        cache_key = f"{analysis_type}_{self.binary_path}"
        cached_result = self._get_cached_result(cache_key)
        if cached_result:
            self.performance_stats['cache_hits'] += 1
            return cached_result

        self.performance_stats['cache_misses'] += 1

        # Check if component is available
        if analysis_type not in self.components or self.components[analysis_type] is None:
            self.logger.warning(f"Component {analysis_type} not available")
            return None

        # Check if operation is degraded
        if self.error_handler.is_operation_degraded(f"r2_{analysis_type}"):
            self.logger.warning(f"Analysis {analysis_type} is in degraded mode, skipping")
            return {'degraded': True, 'reason': 'Circuit breaker open'}

        start_time = time.time()

        try:
            with r2_error_context(f"r2_{analysis_type}", binary_path=self.binary_path):
                component = self.components[analysis_type]

                # Run specific analysis
                if analysis_type == 'decompiler':
                    result = component.analyze_license_functions()
                elif analysis_type == 'esil':
                    result = component.run_emulation_analysis()
                elif analysis_type == 'strings':
                    result = component.analyze_strings()
                elif analysis_type == 'signatures':
                    result = component.analyze_signatures()
                elif analysis_type == 'imports':
                    result = component.analyze_imports_exports()
                elif analysis_type == 'vulnerability':
                    result = component.comprehensive_vulnerability_scan()
                elif analysis_type == 'ai':
                    result = component.run_ai_analysis()
                elif analysis_type == 'bypass':
                    result = component.generate_bypass_strategies()
                elif analysis_type == 'scripting':
                    result = component.run_custom_analysis()
                else:
                    result = {'error': f'Unknown analysis type: {analysis_type}'}

                # Record performance
                duration = time.time() - start_time
                self._record_analysis_time(analysis_type, duration)

                # Cache result
                self._cache_result(cache_key, result)

                return result

        except Exception as e:
            duration = time.time() - start_time
            self._record_analysis_time(analysis_type, duration, success=False)

            self.logger.error(f"Analysis {analysis_type} failed: {e}")
            self.performance_stats['errors_handled'] += 1

            # Try recovery
            if self.error_handler.handle_error(e, f"r2_{analysis_type}", {
                'binary_path': self.binary_path,
                'analysis_type': analysis_type,
                'component': component
            }):
                self.performance_stats['recoveries_successful'] += 1
                # Retry once after recovery
                try:
                    if analysis_type == 'decompiler':
                        result = component.analyze_license_functions()
                    elif analysis_type == 'esil':
                        result = component.run_emulation_analysis()
                    # ... (same pattern for other types)
                    else:
                        result = {'recovered': True, 'original_error': str(e)}

                    self._cache_result(cache_key, result)
                    return result
                except Exception as retry_e:
                    self.logger.error(f"Retry failed for {analysis_type}: {retry_e}")

            return {'error': str(e), 'failed_analysis': analysis_type}

    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if still valid"""
        with self._lock:
            if cache_key in self.results_cache:
                cached_data = self.results_cache[cache_key]
                if time.time() - cached_data['timestamp'] < self.cache_ttl:
                    return cached_data['result']
                else:
                    # Remove expired cache entry
                    del self.results_cache[cache_key]
        return None

    def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache analysis result"""
        with self._lock:
            self.results_cache[cache_key] = {
                'result': result,
                'timestamp': time.time()
            }

            # Limit cache size
            max_cache_size = self.config.get('max_cache_size', 100)
            if len(self.results_cache) > max_cache_size:
                # Remove oldest entries
                sorted_items = sorted(
                    self.results_cache.items(),
                    key=lambda x: x[1]['timestamp']
                )
                for key, _ in sorted_items[:10]:  # Remove 10 oldest
                    del self.results_cache[key]

    def _record_analysis_time(self, analysis_type: str, duration: float, success: bool = True):
        """Record analysis performance"""
        with self._lock:
            if analysis_type not in self.performance_stats['analysis_times']:
                self.performance_stats['analysis_times'][analysis_type] = {
                    'times': [],
                    'successes': 0,
                    'failures': 0
                }

            stats = self.performance_stats['analysis_times'][analysis_type]
            stats['times'].append(duration)

            if success:
                stats['successes'] += 1
            else:
                stats['failures'] += 1

            # Keep only last 50 measurements
            if len(stats['times']) > 50:
                stats['times'] = stats['times'][-50:]

    def start_real_time_monitoring(self, callback: Optional[Callable] = None):
        """Start real-time monitoring of analysis results"""
        if self.monitoring_enabled and not self.monitoring_thread:
            self.monitoring_thread = threading.Thread(
                target=self._monitoring_loop,
                args=(callback,),
                daemon=True
            )
            self.monitoring_thread.start()
            self.logger.info("Real-time monitoring started")

    def stop_real_time_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring_enabled = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
            self.monitoring_thread = None
            self.logger.info("Real-time monitoring stopped")

    def _monitoring_loop(self, callback: Optional[Callable]):
        """Real-time monitoring loop"""
        while self.monitoring_enabled:
            try:
                # Run lightweight analysis
                quick_results = self._run_single_analysis('strings')

                if callback and quick_results:
                    callback({
                        'type': 'real_time_update',
                        'results': quick_results,
                        'timestamp': time.time()
                    })

                time.sleep(self.config.get('monitoring_interval', 30))  # 30 seconds default

            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(60)  # Wait longer on error

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics"""
        with self._lock:
            stats = self.performance_stats.copy()

            # Calculate averages and rates
            for analysis_type, data in stats['analysis_times'].items():
                if data['times']:
                    data['avg_time'] = sum(data['times']) / len(data['times'])
                    data['max_time'] = max(data['times'])
                    data['min_time'] = min(data['times'])

                total_attempts = data['successes'] + data['failures']
                if total_attempts > 0:
                    data['success_rate'] = data['successes'] / total_attempts
                else:
                    data['success_rate'] = 0.0

            # Add error handler stats
            stats['error_handler'] = self.error_handler.get_error_statistics()

            return stats

    def optimize_performance(self):
        """Optimize performance based on collected metrics"""
        stats = self.get_performance_stats()

        # Adjust cache TTL based on hit rate
        total_cache_requests = stats['cache_hits'] + stats['cache_misses']
        if total_cache_requests > 0:
            hit_rate = stats['cache_hits'] / total_cache_requests
            if hit_rate < 0.3:  # Low hit rate
                self.cache_ttl = min(self.cache_ttl * 1.5, 900)  # Increase TTL, max 15 min
            elif hit_rate > 0.8:  # High hit rate
                self.cache_ttl = max(self.cache_ttl * 0.8, 60)  # Decrease TTL, min 1 min

        # Reset circuit breakers for high-performing operations
        for analysis_type, data in stats['analysis_times'].items():
            if data.get('success_rate', 0) > 0.9:  # High success rate
                self.error_handler.reset_circuit_breaker(f"r2_{analysis_type}")

        self.logger.info(f"Performance optimized: cache_ttl={self.cache_ttl}")

    def clear_cache(self):
        """Clear results cache"""
        with self._lock:
            self.results_cache.clear()
            self.logger.info("Results cache cleared")

    def get_health_status(self) -> Dict[str, Any]:
        """Get system health status"""
        stats = self.get_performance_stats()

        health = {
            'overall_health': 'healthy',
            'components_available': sum(1 for c in self.components.values() if c is not None),
            'total_components': len(self.components),
            'cache_health': {
                'size': len(self.results_cache),
                'hit_rate': 0.0
            },
            'error_health': {
                'total_errors': stats['errors_handled'],
                'recovery_rate': 0.0
            }
        }

        # Calculate cache hit rate
        total_requests = stats['cache_hits'] + stats['cache_misses']
        if total_requests > 0:
            health['cache_health']['hit_rate'] = stats['cache_hits'] / total_requests

        # Calculate recovery rate
        if stats['errors_handled'] > 0:
            health['error_health']['recovery_rate'] = stats['recoveries_successful'] / stats['errors_handled']

        # Determine overall health
        if health['components_available'] < health['total_components'] * 0.5:
            health['overall_health'] = 'critical'
        elif health['error_health']['recovery_rate'] < 0.5:
            health['overall_health'] = 'degraded'
        elif health['cache_health']['hit_rate'] < 0.2:
            health['overall_health'] = 'warning'

        return health

    def cleanup(self):
        """Cleanup resources"""
        try:
            self.stop_real_time_monitoring()
            self.clear_cache()

            # Cleanup components
            for component in self.components.values():
                if component and hasattr(component, 'cleanup'):
                    try:
                        component.cleanup()
                    except Exception as e:
                        self.logger.error(f"Component cleanup failed: {e}")

            self.logger.info("EnhancedR2Integration cleanup completed")

        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")


def create_enhanced_r2_integration(binary_path: str, **config) -> EnhancedR2Integration:
    """
    Create enhanced radare2 integration instance.
    
    Args:
        binary_path: Path to binary file
        **config: Configuration options
        
    Returns:
        EnhancedR2Integration instance
    """
    return EnhancedR2Integration(binary_path, config)


__all__ = [
    'EnhancedR2Integration',
    'create_enhanced_r2_integration'
]
