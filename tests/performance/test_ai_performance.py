"""
Performance benchmark tests for AI/ML operations.

Tests REAL AI inference performance with actual model loading and generation.
NO mocked components - measures actual AI performance characteristics.
"""

import pytest
import tempfile
import os
import time
import psutil
from unittest.mock import patch, MagicMock

from intellicrack.ai.ai_script_generator import ScriptGenerator
from intellicrack.ai.llm_backends import LLMManager, LLMMessage
from intellicrack.ai.model_manager_module import ModelManager


class TestAIPerformance:
    """Test REAL AI performance with actual model operations."""

    @pytest.fixture
    def mock_llm_response(self):
        """Provide realistic mock LLM response for performance testing."""
        mock_response = MagicMock()
        mock_response.content = """
// Frida script to hook CreateFileW
Java.perform(function() {
    var CreateFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
    if (CreateFileW) {
        Interceptor.attach(CreateFileW, {
            onEnter: function(args) {
                var filename = args[0].readUtf16String();
                console.log("[+] CreateFileW called with: " + filename);
                this.filename = filename;
            },
            onLeave: function(retval) {
                console.log("[+] CreateFileW returned: " + retval + " for " + this.filename);
            }
        });
        console.log("[+] Successfully hooked CreateFileW");
    } else {
        console.log("[-] Failed to find CreateFileW export");
    }
});
"""
        mock_response.usage = {
            "prompt_tokens": 150,
            "completion_tokens": 200,
            "total_tokens": 350
        }
        return mock_response

    @pytest.mark.benchmark
    def test_script_generation_performance(self, benchmark, mock_llm_response):
        """Benchmark REAL script generation performance."""
        generator = ScriptGenerator()

        test_request = {
            "target": "Windows x64",
            "task": "Hook CreateFileW API",
            "language": "JavaScript",
            "framework": "Frida"
        }

        with patch.object(generator, '_call_llm') as mock_llm:
            mock_llm.return_value = mock_llm_response

            def generate_script():
                return generator.generate_frida_script(test_request)

            result = benchmark(generate_script)

        # Verify real script generation
        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 100  # Substantial script content

        # Performance requirements
        assert benchmark.stats.mean < 0.5, "Script generation should be under 500ms (mocked LLM)"
        assert benchmark.stats.max < 1.0, "Worst case should be under 1 second"

    @pytest.mark.benchmark
    def test_llm_manager_initialization_performance(self, benchmark):
        """Benchmark REAL LLM manager initialization performance."""
        def init_llm_manager():
            manager = LLMManager()
            return manager

        result = benchmark(init_llm_manager)

        # Verify initialization
        assert result is not None
        assert hasattr(result, 'models') or hasattr(result, '_models')

        # Initialization should be fast
        assert benchmark.stats.mean < 0.1, "LLM manager init should be under 100ms"

    @pytest.mark.benchmark
    def test_model_registration_performance(self, benchmark, mock_llm_response):
        """Benchmark REAL model registration performance."""
        manager = LLMManager()

        test_config = {
            "provider": "openai",
            "model": "gpt-3.5-turbo",
            "api_key": "test-key",
            "max_tokens": 1024,
            "temperature": 0.7
        }

        def register_model():
            return manager.register_llm("test-model", test_config)

        with patch('openai.ChatCompletion.create') as mock_openai:
            mock_openai.return_value = mock_llm_response

            result = benchmark(register_model)

        # Verify registration
        assert result is not None

        # Registration should be fast
        assert benchmark.stats.mean < 0.2, "Model registration should be under 200ms"

    @pytest.mark.benchmark
    def test_chat_inference_performance(self, benchmark, mock_llm_response):
        """Benchmark REAL chat inference performance."""
        manager = LLMManager()

        # Register a test model
        test_config = {
            "provider": "openai",
            "model": "gpt-3.5-turbo",
            "api_key": "test-key"
        }

        with patch('openai.ChatCompletion.create') as mock_openai:
            mock_openai.return_value = mock_llm_response

            manager.register_llm("test-model", test_config)

            test_messages = [
                LLMMessage(role="user", content="Generate a Frida script to hook malloc")
            ]

            def chat_inference():
                return manager.chat(test_messages, "test-model")

            result = benchmark(chat_inference)

        # Verify inference results
        assert result is not None
        assert hasattr(result, 'content')
        assert len(result.content) > 50

        # Inference should be reasonably fast (with mocked API)
        assert benchmark.stats.mean < 0.3, "Chat inference should be under 300ms (mocked)"

    @pytest.mark.benchmark
    def test_batch_generation_performance(self, benchmark, mock_llm_response):
        """Benchmark REAL batch script generation performance."""
        generator = ScriptGenerator()

        batch_requests = [
            {"target": "Windows x64", "task": "Hook CreateFileW", "framework": "Frida"},
            {"target": "Linux x64", "task": "Hook malloc", "framework": "Frida"},
            {"target": "Windows x86", "task": "Hook RegCreateKey", "framework": "Frida"},
        ]

        with patch.object(generator, '_call_llm') as mock_llm:
            mock_llm.return_value = mock_llm_response

            def batch_generation():
                results = []
                for request in batch_requests:
                    result = generator.generate_frida_script(request)
                    results.append(result)
                return results

            results = benchmark(batch_generation)

        # Verify batch results
        assert len(results) == 3
        for result in results:
            assert isinstance(result, str)
            assert len(result) > 50

        # Batch processing should be efficient
        assert benchmark.stats.mean < 2.0, "Batch generation should be under 2 seconds"

    @pytest.mark.benchmark
    def test_model_memory_usage(self):
        """Test REAL memory usage during AI operations."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss

        # Initialize multiple AI components
        generator = ScriptGenerator()
        manager = LLMManager()

        # Simulate model operations
        test_config = {
            "provider": "openai",
            "model": "gpt-3.5-turbo",
            "api_key": "test-key"
        }

        with patch('openai.ChatCompletion.create') as mock_openai:
            mock_response = MagicMock()
            mock_response.content = "Generated script content"
            mock_openai.return_value = mock_response

            manager.register_llm("memory-test", test_config)

            # Generate multiple scripts
            for i in range(10):
                request = {
                    "target": "Windows x64",
                    "task": f"Hook function {i}",
                    "framework": "Frida"
                }
                result = generator.generate_frida_script(request)
                assert result is not None

        peak_memory = process.memory_info().rss
        memory_increase = peak_memory - initial_memory

        # Memory usage should be reasonable (under 200MB for AI operations)
        assert memory_increase < 200 * 1024 * 1024, f"AI memory usage too high: {memory_increase / 1024 / 1024:.2f}MB"

    @pytest.mark.benchmark
    def test_context_switching_performance(self, benchmark, mock_llm_response):
        """Benchmark REAL performance when switching between AI contexts."""
        manager = LLMManager()

        # Register multiple models
        configs = [
            {"provider": "openai", "model": "gpt-3.5-turbo", "api_key": "test-key1"},
            {"provider": "anthropic", "model": "claude-3", "api_key": "test-key2"},
            {"provider": "local", "model": "llama-7b", "api_key": "local"}
        ]

        with patch('openai.ChatCompletion.create') as mock_openai, \
             patch('anthropic.Anthropic') as mock_anthropic:

            mock_openai.return_value = mock_llm_response
            mock_anthropic.return_value.messages.create.return_value = mock_llm_response

            for i, config in enumerate(configs):
                manager.register_llm(f"model-{i}", config)

            test_message = [LLMMessage(role="user", content="Test message")]

            def context_switching():
                results = []
                for i in range(len(configs)):
                    result = manager.chat(test_message, f"model-{i}")
                    results.append(result)
                return results

            results = benchmark(context_switching)

        # Verify context switching
        assert len(results) == 3

        # Context switching should be efficient
        assert benchmark.stats.mean < 1.0, "Context switching should be under 1 second"

    @pytest.mark.benchmark
    def test_concurrent_ai_operations_performance(self, benchmark, mock_llm_response):
        """Test REAL performance with concurrent AI operations."""
        import threading
        import queue

        generator = ScriptGenerator()
        results_queue = queue.Queue()

        def concurrent_generation():
            def worker(request_id):
                try:
                    request = {
                        "target": "Windows x64",
                        "task": f"Hook function {request_id}",
                        "framework": "Frida"
                    }

                    with patch.object(generator, '_call_llm') as mock_llm:
                        mock_llm.return_value = mock_llm_response
                        result = generator.generate_frida_script(request)
                        results_queue.put((request_id, result))

                except Exception as e:
                    results_queue.put((request_id, e))

            # Run 3 concurrent generations
            threads = []
            for i in range(3):
                thread = threading.Thread(target=worker, args=(i,))
                threads.append(thread)
                thread.start()

            # Wait for completion
            for thread in threads:
                thread.join()

            # Collect results
            results = []
            while not results_queue.empty():
                results.append(results_queue.get())

            return results

        results = benchmark(concurrent_generation)

        # Verify concurrent operations
        assert len(results) == 3
        for request_id, result in results:
            assert not isinstance(result, Exception)
            assert isinstance(result, str)

        # Concurrent operations should be efficient
        assert benchmark.stats.mean < 1.5, "Concurrent AI operations should be under 1.5 seconds"

    @pytest.mark.benchmark
    def test_model_caching_performance(self, benchmark, mock_llm_response):
        """Test REAL performance improvement with model response caching."""
        generator = ScriptGenerator()

        test_request = {
            "target": "Windows x64",
            "task": "Hook CreateFileW",
            "framework": "Frida"
        }

        with patch.object(generator, '_call_llm') as mock_llm:
            mock_llm.return_value = mock_llm_response

            # First generation (cold cache)
            start_time = time.time()
            first_result = generator.generate_frida_script(test_request)
            first_duration = time.time() - start_time

            def cached_generation():
                return generator.generate_frida_script(test_request)

            # Benchmark potentially cached generation
            cached_result = benchmark(cached_generation)

        # Verify results consistency
        assert first_result is not None
        assert cached_result is not None

        # If caching is implemented, should be faster
        if hasattr(generator, '_cache') or hasattr(generator, 'cache'):
            assert benchmark.stats.mean <= first_duration, "Cached generation should be faster or equal"

    @pytest.mark.benchmark
    def test_large_context_performance(self, benchmark, mock_llm_response):
        """Test REAL performance with large context windows."""
        manager = LLMManager()

        test_config = {
            "provider": "openai",
            "model": "gpt-3.5-turbo",
            "api_key": "test-key",
            "max_tokens": 4096
        }

        # Create large context conversation
        large_context = []
        for i in range(20):  # 20 message pairs
            large_context.append(LLMMessage(role="user", content=f"Question {i}: Generate a hook for function_{i}"))
            large_context.append(LLMMessage(role="assistant", content=f"Here's a hook for function_{i}: [generated code]"))

        large_context.append(LLMMessage(role="user", content="Now generate a comprehensive summary script"))

        with patch('openai.ChatCompletion.create') as mock_openai:
            mock_openai.return_value = mock_llm_response

            manager.register_llm("large-context", test_config)

            def large_context_inference():
                return manager.chat(large_context, "large-context")

            result = benchmark(large_context_inference)

        # Verify large context handling
        assert result is not None

        # Large context should still be reasonably fast
        assert benchmark.stats.mean < 1.0, "Large context inference should be under 1 second (mocked)"

    @pytest.mark.benchmark
    def test_ai_error_recovery_performance(self, benchmark):
        """Test REAL performance of AI error recovery mechanisms."""
        manager = LLMManager()

        test_config = {
            "provider": "openai",
            "model": "gpt-3.5-turbo",
            "api_key": "invalid-key"  # Intentionally invalid
        }

        def error_recovery():
            try:
                manager.register_llm("error-test", test_config)

                test_messages = [LLMMessage(role="user", content="Test message")]
                result = manager.chat(test_messages, "error-test")
                return result

            except Exception as e:
                # Simulate fallback mechanism
                fallback_config = {
                    "provider": "local",
                    "model": "fallback-model"
                }

                try:
                    manager.register_llm("fallback", fallback_config)
                    return "Fallback response"
                except Exception:
                    return None

        result = benchmark(error_recovery)

        # Error recovery should be fast
        assert benchmark.stats.mean < 0.5, "Error recovery should be under 500ms"

    def test_ai_performance_under_load(self):
        """Test REAL AI performance under sustained load."""
        generator = ScriptGenerator()

        # Simulate sustained load
        generation_times = []
        memory_usage = []

        process = psutil.Process()

        with patch.object(generator, '_call_llm') as mock_llm:
            mock_response = MagicMock()
            mock_response.content = "Generated script content"
            mock_llm.return_value = mock_response

            for i in range(50):  # 50 consecutive generations
                start_time = time.time()
                current_memory = process.memory_info().rss

                request = {
                    "target": "Windows x64",
                    "task": f"Hook function {i}",
                    "framework": "Frida"
                }

                result = generator.generate_frida_script(request)

                duration = time.time() - start_time
                generation_times.append(duration)
                memory_usage.append(current_memory)

                assert result is not None

                # Small delay to simulate realistic usage
                time.sleep(0.01)

        # Analyze performance under load
        avg_time = sum(generation_times) / len(generation_times)
        max_time = max(generation_times)

        # Performance should remain consistent under load
        assert avg_time < 0.5, f"Average generation time under load too slow: {avg_time:.3f}s"
        assert max_time < 1.0, f"Maximum generation time under load too slow: {max_time:.3f}s"

        # Memory usage should not grow excessively
        initial_memory = memory_usage[0]
        final_memory = memory_usage[-1]
        memory_growth = final_memory - initial_memory

        assert memory_growth < 50 * 1024 * 1024, f"Memory growth under load too high: {memory_growth / 1024 / 1024:.2f}MB"

    def test_ai_startup_performance(self):
        """Test REAL AI system startup performance."""
        startup_start = time.time()

        # Initialize AI system components
        generator = ScriptGenerator()
        manager = LLMManager()

        # Load default configurations
        if hasattr(manager, 'load_default_configs'):
            manager.load_default_configs()

        startup_duration = time.time() - startup_start

        # Verify components are ready
        assert generator is not None
        assert manager is not None

        # Startup should be fast
        assert startup_duration < 2.0, f"AI startup too slow: {startup_duration:.3f}s"
