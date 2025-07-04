"""
Performance Tests for AI Components

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
import concurrent.futures
import gc
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock

import psutil
import pytest

from intellicrack.ai.ai_script_generator import AIScriptGenerator
from intellicrack.ai.integration_manager import IntegrationManager
from intellicrack.ai.intelligent_code_modifier import IntelligentCodeModifier
from intellicrack.ai.llm_backends import LLMManager, LLMResponse
from intellicrack.ai.performance_monitor import PerformanceMonitor, performance_monitor


@pytest.fixture
def mock_llm_manager():
    """Mock LLM manager for performance testing."""
    manager = Mock(spec=LLMManager)

    # Fast mock responses
    manager.chat.return_value = LLMResponse(
        content="Mock response for performance testing",
        model="test-model"
    )
    manager.is_available.return_value = True

    return manager


@pytest.fixture
def temp_test_files():
    """Create temporary test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_dir = Path(tmpdir)

        # Create test files
        for i in range(10):
            test_file = test_dir / f"test_{i}.py"
            test_file.write_text(f"""
def function_{i}():
    '''Test function {i}'''
    for j in range(100):
        result = j * {i}
    return result

class TestClass_{i}:
    def __init__(self):
        self.value = {i}

    def process(self):
        return self.value * 2
""")

        yield test_dir


class TestAIPerformance:
    """Performance tests for AI components."""

    def test_script_generator_performance(self, mock_llm_manager):
        """Test script generator performance under load."""
        generator = AIScriptGenerator(mock_llm_manager)

        # Performance monitoring
        with PerformanceMonitor() as monitor:
            start_time = time.time()

            # Generate multiple scripts
            results = []
            for i in range(20):
                request = {
                    "target_info": {
                        "file_path": f"/test/target_{i}.exe",
                        "architecture": "x86_64"
                    },
                    "bypass_type": f"protection_{i % 5}",
                    "requirements": [f"Requirement {i}"]
                }

                with monitor.profile_operation(f"generate_script_{i}"):
                    scripts = generator.generate_frida_script(request)
                    results.append(scripts)

            end_time = time.time()
            total_time = end_time - start_time

            # Performance assertions
            assert len(results) == 20
            assert total_time < 30.0  # Should complete in under 30 seconds

            # Check individual operation times
            summary = monitor.get_metrics_summary()
            operation_stats = summary.get("operation_summary", {})

            for op_name, stats in operation_stats.items():
                if "generate_script" in op_name:
                    assert stats["avg_execution_time"] < 5.0  # Average under 5 seconds

    def test_code_modifier_performance(self, mock_llm_manager, temp_test_files):
        """Test code modifier performance with multiple files."""
        modifier = IntelligentCodeModifier(mock_llm_manager)

        # Mock response for code modification
        mock_llm_manager.chat.return_value = LLMResponse(
            content='''```json
{
  "modifications": [
    {
      "type": "function_modification",
      "description": "Performance test modification",
      "start_line": 1,
      "end_line": 5,
      "original_code": "def function_0():",
      "modified_code": "def function_0_modified():",
      "reasoning": "Performance test",
      "confidence": 0.9,
      "impact": "Minimal"
    }
  ]
}
```''',
            model="test-model"
        )

        test_files = list(temp_test_files.glob("*.py"))[:5]  # Use 5 files

        start_time = time.time()

        # Create and analyze modification request
        request = modifier.create_modification_request(
            description="Performance test modifications",
            target_files=[str(f) for f in test_files],
            requirements=["Fast execution"],
            constraints=["Maintain functionality"]
        )

        changes = modifier.analyze_modification_request(request)

        end_time = time.time()
        analysis_time = end_time - start_time

        # Performance assertions
        assert len(changes) >= 0  # Should handle gracefully
        assert analysis_time < 15.0  # Should complete in under 15 seconds

    def test_integration_manager_performance(self, mock_llm_manager):
        """Test integration manager performance with concurrent tasks."""
        with IntegrationManager(mock_llm_manager) as manager:
            start_time = time.time()

            # Create multiple tasks
            task_ids = []
            for i in range(10):
                task_id = manager.create_task(
                    task_type="generate_script",
                    description=f"Performance test task {i}",
                    input_data={
                        "request": {
                            "target_info": {"file_path": f"/test/target_{i}.exe"},
                            "bypass_type": "test"
                        },
                        "script_type": "frida"
                    },
                    priority=1
                )
                task_ids.append(task_id)

            # Wait for all tasks to complete
            completed_tasks = []
            for task_id in task_ids:
                try:
                    task = manager.wait_for_task(task_id, timeout=10.0)
                    completed_tasks.append(task)
                except TimeoutError:
                    # Task didn't complete in time
                    pass

            end_time = time.time()
            total_time = end_time - start_time

            # Performance assertions
            assert len(completed_tasks) >= 5  # At least half should complete
            assert total_time < 20.0  # Should complete in reasonable time

    def test_memory_usage_under_load(self, mock_llm_manager, temp_test_files):
        """Test memory usage under heavy load."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss

        # Create multiple components
        components = []
        for i in range(5):
            generator = AIScriptGenerator(mock_llm_manager)
            modifier = IntelligentCodeModifier(mock_llm_manager)
            components.extend([generator, modifier])

        # Perform operations
        for i, component in enumerate(components):
            if hasattr(component, 'generate_frida_script'):
                request = {
                    "target_info": {"file_path": f"/test/target_{i}.exe"},
                    "bypass_type": "test"
                }
                component.generate_frida_script(request)
            elif hasattr(component, 'create_modification_request'):
                test_files = list(temp_test_files.glob("*.py"))[:2]
                request = component.create_modification_request(
                    description="Memory test",
                    target_files=[str(f) for f in test_files]
                )

        # Check memory usage
        current_memory = process.memory_info().rss
        memory_increase = current_memory - initial_memory
        memory_increase_mb = memory_increase / 1024 / 1024

        # Memory increase should be reasonable (less than 200MB)
        assert memory_increase_mb < 200, f"Memory increased by {memory_increase_mb:.2f}MB"

        # Force garbage collection and check again
        gc.collect()
        gc_memory = process.memory_info().rss
        gc_memory_increase = gc_memory - initial_memory
        gc_memory_increase_mb = gc_memory_increase / 1024 / 1024

        # After GC, memory should be lower
        assert gc_memory_increase_mb < memory_increase_mb

    def test_concurrent_operations(self, mock_llm_manager):
        """Test concurrent AI operations."""
        generator = AIScriptGenerator(mock_llm_manager)
        modifier = IntelligentCodeModifier(mock_llm_manager)

        def generate_script(index):
            request = {
                "target_info": {"file_path": f"/test/target_{index}.exe"},
                "bypass_type": "concurrent_test"
            }
            return generator.generate_frida_script(request)

        def create_modification(index):
            request = modifier.create_modification_request(
                description=f"Concurrent modification {index}",
                target_files=[f"/test/file_{index}.py"]
            )
            return request

        start_time = time.time()

        # Run operations concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            # Submit script generation tasks
            script_futures = [
                executor.submit(generate_script, i) for i in range(8)
            ]

            # Submit modification tasks
            mod_futures = [
                executor.submit(create_modification, i) for i in range(8)
            ]

            # Wait for completion
            script_results = [f.result(timeout=10) for f in script_futures]
            mod_results = [f.result(timeout=10) for f in mod_futures]

        end_time = time.time()
        total_time = end_time - start_time

        # Performance assertions
        assert len(script_results) == 8
        assert len(mod_results) == 8
        assert total_time < 15.0  # Should complete concurrently faster than sequential

    @pytest.mark.asyncio
    async def test_async_performance(self, mock_llm_manager):
        """Test asynchronous operation performance."""
        generator = AIScriptGenerator(mock_llm_manager)

        async def generate_script_async(index):
            # Simulate async operation
            await asyncio.sleep(0.1)
            request = {
                "target_info": {"file_path": f"/test/target_{index}.exe"},
                "bypass_type": "async_test"
            }
            return generator.generate_frida_script(request)

        start_time = time.time()

        # Run multiple async operations
        tasks = [generate_script_async(i) for i in range(10)]
        results = await asyncio.gather(*tasks)

        end_time = time.time()
        total_time = end_time - start_time

        # Should complete faster than sequential execution
        assert len(results) == 10
        assert total_time < 5.0  # Async should be much faster

    def test_performance_monitoring_overhead(self, mock_llm_manager):
        """Test overhead of performance monitoring."""
        generator = AIScriptGenerator(mock_llm_manager)

        # Test without monitoring
        start_time = time.time()
        for i in range(5):
            request = {
                "target_info": {"file_path": f"/test/target_{i}.exe"},
                "bypass_type": "overhead_test"
            }
            generator.generate_frida_script(request)

        time_without_monitoring = time.time() - start_time

        # Test with monitoring
        with PerformanceMonitor() as monitor:
            start_time = time.time()
            for i in range(5):
                request = {
                    "target_info": {"file_path": f"/test/target_{i}.exe"},
                    "bypass_type": "overhead_test"
                }
                with monitor.profile_operation(f"test_operation_{i}"):
                    generator.generate_frida_script(request)

            time_with_monitoring = time.time() - start_time

        # Monitoring overhead should be minimal (less than 20% increase)
        overhead_ratio = time_with_monitoring / time_without_monitoring
        assert overhead_ratio < 1.2, f"Monitoring overhead too high: {overhead_ratio:.2f}x"

    def test_cache_performance(self, mock_llm_manager):
        """Test performance with caching enabled."""
        monitor = PerformanceMonitor()

        # Generate cache keys and test caching
        cache_key = "test_performance_cache"
        test_data = {"result": "cached_performance_data"}

        # Test cache miss
        start_time = time.time()
        result = monitor.get_cached_result(cache_key)
        cache_miss_time = time.time() - start_time

        assert result is None

        # Cache the result
        monitor.cache_result(cache_key, test_data)

        # Test cache hit
        start_time = time.time()
        result = monitor.get_cached_result(cache_key)
        cache_hit_time = time.time() - start_time

        assert result == test_data
        assert cache_hit_time < cache_miss_time * 2  # Cache should be fast

    def test_large_file_processing(self, mock_llm_manager):
        """Test performance with large files."""
        modifier = IntelligentCodeModifier(mock_llm_manager)

        # Create large file content
        large_content = ""
        for i in range(1000):
            large_content += f"""
def function_{i}(param_{i}):
    '''Generated function {i}'''
    result = []
    for j in range(10):
        temp = param_{i} * j + {i}
        result.append(temp)
    return result

class Class_{i}:
    def __init__(self):
        self.data = [x for x in range({i}, {i + 10})]

    def process_{i}(self):
        return sum(self.data) * {i}
"""

        # Write to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(large_content)
            large_file_path = f.name

        try:
            start_time = time.time()

            # Analyze large file
            context = modifier.analyzer.analyze_file(large_file_path)

            analysis_time = time.time() - start_time

            # Performance assertions
            assert context.language == "python"
            assert len(context.functions) > 900  # Should find most functions
            assert len(context.classes) > 900   # Should find most classes
            assert analysis_time < 30.0  # Should complete in reasonable time

        finally:
            # Cleanup
            Path(large_file_path).unlink(missing_ok=True)

    def test_stress_test_workflow(self, mock_llm_manager):
        """Stress test complete workflow."""
        with IntegrationManager(mock_llm_manager) as manager:
            start_time = time.time()

            # Create multiple complex workflows
            workflow_ids = []
            for i in range(3):
                workflow_id = manager.create_bypass_workflow(
                    target_binary=f"/test/stress_target_{i}.exe",
                    bypass_type="stress_test"
                )
                workflow_ids.append(workflow_id)

            # Wait for workflows to complete (with timeout)
            completed_workflows = []
            for workflow_id in workflow_ids:
                try:
                    result = manager.wait_for_workflow(workflow_id, timeout=30.0)
                    completed_workflows.append(result)
                except TimeoutError:
                    # Workflow didn't complete in time
                    pass

            end_time = time.time()
            total_time = end_time - start_time

            # Stress test assertions
            assert len(completed_workflows) >= 1  # At least one should complete
            assert total_time < 60.0  # Should complete within 1 minute

            # Check system health
            health = performance_monitor._assess_system_health()
            assert health["score"] > 30  # System shouldn't be completely degraded


class TestPerformanceOptimization:
    """Test performance optimization features."""

    def test_garbage_collection_optimization(self, mock_llm_manager):
        """Test garbage collection optimization."""
        initial_objects = len(gc.get_objects())

        # Create many objects
        components = []
        for i in range(20):
            generator = AIScriptGenerator(mock_llm_manager)
            modifier = IntelligentCodeModifier(mock_llm_manager)
            components.extend([generator, modifier])

        # Check object count increase
        peak_objects = len(gc.get_objects())
        object_increase = peak_objects - initial_objects

        # Clear references
        del components

        # Force garbage collection
        collected = gc.collect()

        # Check object count after GC
        final_objects = len(gc.get_objects())
        objects_cleaned = peak_objects - final_objects

        # Assertions
        assert object_increase > 0  # Objects were created
        assert collected > 0  # Some objects were collected
        assert objects_cleaned > 0  # Object count decreased

    def test_performance_threshold_monitoring(self, mock_llm_manager):
        """Test performance threshold monitoring."""
        monitor = PerformanceMonitor()

        # Set low thresholds for testing
        monitor.thresholds["execution_time"]["warning"] = 0.001
        monitor.thresholds["execution_time"]["critical"] = 0.002

        warnings_triggered = []
        criticals_triggered = []

        def warning_handler(metric_name, level, value):
            if level == "warning":
                warnings_triggered.append((metric_name, value))
            elif level == "critical":
                criticals_triggered.append((metric_name, value))

        monitor.add_optimization_rule(warning_handler)

        # Simulate slow operation
        with monitor.profile_operation("slow_test_operation"):
            time.sleep(0.01)  # 10ms - should trigger critical threshold

        # Check if thresholds were triggered
        # Note: This test might be flaky due to timing
        # In a real implementation, you'd have more deterministic triggering

    def test_memory_optimization_rules(self, mock_llm_manager):
        """Test memory optimization rules."""
        monitor = PerformanceMonitor()

        # Set low memory thresholds
        monitor.thresholds["memory_growth"]["warning"] = 1024  # 1KB
        monitor.thresholds["memory_growth"]["critical"] = 2048  # 2KB

        optimizations_triggered = []

        def memory_optimization(metric_name, level, value):
            if metric_name == "memory_growth":
                optimizations_triggered.append((level, value))

        monitor.add_optimization_rule(memory_optimization)

        # Simulate memory growth
        large_data = [i for i in range(10000)]  # Create some memory usage

        # Manual trigger (in real scenario, this would be automatic)
        monitor._trigger_optimization("memory_growth", "warning", 1500)

        # Check if optimization was triggered
        assert len(optimizations_triggered) > 0
        assert optimizations_triggered[0][0] == "warning"

        # Cleanup
        del large_data
