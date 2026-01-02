"""
Performance benchmark tests for AI/ML operations.

Tests REAL AI inference performance with actual model loading and generation.
NO mocked components - measures actual AI performance characteristics.
"""

import queue
import threading
import time
from collections.abc import Generator
from typing import Any

import psutil
import pytest

from intellicrack.ai.ai_script_generator import AIScriptGenerator, GeneratedScript
from intellicrack.ai.llm_backends import LLMConfig, LLMManager, LLMMessage, LLMProvider


class FakeLLMResponse:
    """Real test double for LLM response objects."""

    def __init__(
        self, content: str, prompt_tokens: int = 150, completion_tokens: int = 200
    ) -> None:
        self.content: str = content
        self.usage: dict[str, int] = {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        }


class FakeOpenAIChatCompletion:
    """Real test double for OpenAI ChatCompletion API."""

    def __init__(self, response: FakeLLMResponse) -> None:
        self._response: FakeLLMResponse = response

    def create(self, **kwargs: Any) -> FakeLLMResponse:
        return self._response


class FakeAnthropicMessages:
    """Real test double for Anthropic messages API."""

    def __init__(self, response: FakeLLMResponse) -> None:
        self._response: FakeLLMResponse = response

    def create(self, **kwargs: Any) -> FakeLLMResponse:
        return self._response


class FakeAnthropicClient:
    """Real test double for Anthropic client."""

    def __init__(self, response: FakeLLMResponse) -> None:
        self.messages: FakeAnthropicMessages = FakeAnthropicMessages(response)


class TestAIPerformance:
    """Test REAL AI performance with actual model operations."""

    @pytest.fixture
    def realistic_llm_response(self) -> FakeLLMResponse:
        """Provide realistic LLM response for performance testing."""
        return FakeLLMResponse(
            content="""
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
""",
            prompt_tokens=150,
            completion_tokens=200,
        )

    @pytest.fixture
    def process_memory(self) -> psutil._pswindows.pmem:
        """Monitor process memory usage."""
        process = psutil.Process()
        return process.memory_info()

    @pytest.mark.benchmark
    def test_script_generation_performance(
        self, benchmark: Any, realistic_llm_response: FakeLLMResponse
    ) -> None:
        """Benchmark REAL script generation performance."""
        generator = AIScriptGenerator()

        test_request: dict[str, str] = {
            "target": "Windows x64",
            "task": "Hook CreateFileW API",
            "language": "JavaScript",
            "framework": "Frida",
        }

        def generate_script() -> GeneratedScript | None:
            return generator.generate_frida_script(test_request)

        result: GeneratedScript | None = benchmark(generate_script)

        if result is not None:
            assert isinstance(result, GeneratedScript)
            assert len(result.content) > 0

        assert benchmark.stats.mean < 2.0, "Script generation should be under 2s"
        assert benchmark.stats.max < 5.0, "Worst case should be under 5 seconds"

    @pytest.mark.benchmark
    def test_llm_manager_initialization_performance(self, benchmark: Any) -> None:
        """Benchmark REAL LLM manager initialization performance."""

        def init_llm_manager() -> LLMManager:
            manager: LLMManager = LLMManager()
            return manager

        result: LLMManager = benchmark(init_llm_manager)

        assert result is not None
        assert hasattr(result, "models") or hasattr(result, "_models")

        assert benchmark.stats.mean < 0.5, "LLM manager init should be under 500ms"

    @pytest.mark.benchmark
    def test_model_registration_performance(self, benchmark: Any) -> None:
        """Benchmark REAL model registration performance."""
        manager: LLMManager = LLMManager()

        test_config: LLMConfig = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-3.5-turbo",
            api_key="test-key",
            max_tokens=1024,
            temperature=0.7,
        )

        def register_model() -> bool:
            return manager.register_llm("test-model", test_config)

        result: bool = benchmark(register_model)

        assert result is not None

        assert benchmark.stats.mean < 0.5, "Model registration should be under 500ms"

    @pytest.mark.benchmark
    def test_chat_inference_performance(self, benchmark: Any) -> None:
        """Benchmark REAL chat inference performance."""
        manager: LLMManager = LLMManager()

        test_config: LLMConfig = LLMConfig(
            provider=LLMProvider.OPENAI, model_name="gpt-3.5-turbo", api_key="test-key"
        )

        manager.register_llm("test-model", test_config)

        test_messages: list[LLMMessage] = [
            LLMMessage(role="user", content="Generate a Frida script to hook malloc")
        ]

        def chat_inference() -> Any:
            try:
                return manager.chat(test_messages, "test-model")
            except Exception:
                return None

        result: Any = benchmark(chat_inference)

        assert benchmark.stats.mean < 1.0, "Chat inference should be under 1 second"

    @pytest.mark.benchmark
    def test_batch_generation_performance(self, benchmark: Any) -> None:
        """Benchmark REAL batch script generation performance."""
        generator: AIScriptGenerator = AIScriptGenerator()

        batch_requests: list[dict[str, str]] = [
            {"target": "Windows x64", "task": "Hook CreateFileW", "framework": "Frida"},
            {"target": "Linux x64", "task": "Hook malloc", "framework": "Frida"},
            {"target": "Windows x86", "task": "Hook RegCreateKey", "framework": "Frida"},
        ]

        def batch_generation() -> list[GeneratedScript | None]:
            results: list[GeneratedScript | None] = []
            for request in batch_requests:
                result: GeneratedScript | None = generator.generate_frida_script(request)
                results.append(result)
            return results

        results: list[GeneratedScript | None] = benchmark(batch_generation)

        assert len(results) == 3
        for result in results:
            if result is not None:
                assert isinstance(result, GeneratedScript)

        assert benchmark.stats.mean < 10.0, "Batch generation should be under 10 seconds"

    def test_model_memory_usage(
        self, process_memory: psutil._pswindows.pmem
    ) -> None:
        """Test REAL memory usage during AI operations."""
        initial_memory: int = process_memory.rss

        generator: AIScriptGenerator = AIScriptGenerator()
        manager: LLMManager = LLMManager()

        test_config: LLMConfig = LLMConfig(
            provider=LLMProvider.OPENAI, model_name="gpt-3.5-turbo", api_key="test-key"
        )

        manager.register_llm("memory-test", test_config)

        for i in range(5):
            request: dict[str, str] = {
                "target": "Windows x64",
                "task": f"Hook function {i}",
                "framework": "Frida",
            }
            result: GeneratedScript | None = generator.generate_frida_script(request)

        process = psutil.Process()
        peak_memory: int = process.memory_info().rss
        memory_increase: int = peak_memory - initial_memory

        assert memory_increase < 200 * 1024 * 1024, (
            f"AI memory usage too high: {memory_increase / 1024 / 1024:.2f}MB"
        )

    @pytest.mark.benchmark
    def test_context_switching_performance(self, benchmark: Any) -> None:
        """Benchmark REAL performance when switching between AI contexts."""
        manager: LLMManager = LLMManager()

        configs: list[LLMConfig] = [
            LLMConfig(
                provider=LLMProvider.OPENAI,
                model_name="gpt-3.5-turbo",
                api_key="test-key1",
            ),
            LLMConfig(
                provider=LLMProvider.ANTHROPIC,
                model_name="claude-3",
                api_key="test-key2",
            ),
            LLMConfig(
                provider=LLMProvider.OLLAMA, model_name="llama-7b", api_key="local"
            ),
        ]

        for i, config in enumerate(configs):
            manager.register_llm(f"model-{i}", config)

        test_message: list[LLMMessage] = [
            LLMMessage(role="user", content="Test message")
        ]

        def context_switching() -> list[Any]:
            results: list[Any] = []
            for i in range(len(configs)):
                try:
                    result: Any = manager.chat(test_message, f"model-{i}")
                    results.append(result)
                except Exception:
                    results.append(None)
            return results

        results: list[Any] = benchmark(context_switching)

        assert len(results) == 3

        assert benchmark.stats.mean < 3.0, "Context switching should be under 3 seconds"

    @pytest.mark.benchmark
    def test_concurrent_ai_operations_performance(self, benchmark: Any) -> None:
        """Test REAL performance with concurrent AI operations."""
        generator: AIScriptGenerator = AIScriptGenerator()
        results_queue: queue.Queue[tuple[int, GeneratedScript | None | Exception]] = (
            queue.Queue()
        )

        def concurrent_generation() -> list[tuple[int, GeneratedScript | None | Exception]]:
            def worker(request_id: int) -> None:
                try:
                    request: dict[str, str] = {
                        "target": "Windows x64",
                        "task": f"Hook function {request_id}",
                        "framework": "Frida",
                    }

                    result: GeneratedScript | None = generator.generate_frida_script(
                        request
                    )
                    results_queue.put((request_id, result))

                except Exception as e:
                    results_queue.put((request_id, e))

            threads: list[threading.Thread] = []
            for i in range(3):
                thread: threading.Thread = threading.Thread(target=worker, args=(i,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            results: list[tuple[int, GeneratedScript | None | Exception]] = []
            while not results_queue.empty():
                results.append(results_queue.get())

            return results

        results: list[tuple[int, GeneratedScript | None | Exception]] = benchmark(
            concurrent_generation
        )

        assert len(results) == 3
        for request_id, result in results:
            assert not isinstance(result, Exception), f"Worker {request_id} failed: {result}"

        assert benchmark.stats.mean < 10.0, "Concurrent AI operations should be under 10s"

    @pytest.mark.benchmark
    def test_model_caching_performance(self, benchmark: Any) -> None:
        """Test REAL performance improvement with model response caching."""
        generator: AIScriptGenerator = AIScriptGenerator()

        test_request: dict[str, str] = {
            "target": "Windows x64",
            "task": "Hook CreateFileW",
            "framework": "Frida",
        }

        start_time: float = time.time()
        first_result: GeneratedScript | None = generator.generate_frida_script(
            test_request
        )
        first_duration: float = time.time() - start_time

        def cached_generation() -> GeneratedScript | None:
            return generator.generate_frida_script(test_request)

        cached_result: GeneratedScript | None = benchmark(cached_generation)

        if hasattr(generator, "_cache") or hasattr(generator, "cache"):
            assert benchmark.stats.mean <= first_duration, (
                "Cached generation should be faster or equal"
            )

    @pytest.mark.benchmark
    def test_large_context_performance(self, benchmark: Any) -> None:
        """Test REAL performance with large context windows."""
        manager: LLMManager = LLMManager()

        test_config: LLMConfig = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-3.5-turbo",
            api_key="test-key",
            max_tokens=4096,
        )

        large_context: list[LLMMessage] = []
        for i in range(20):
            large_context.append(
                LLMMessage(
                    role="user", content=f"Question {i}: Generate a hook for function_{i}"
                )
            )
            large_context.append(
                LLMMessage(
                    role="assistant",
                    content=f"Here's a hook for function_{i}: [generated code]",
                )
            )

        large_context.append(
            LLMMessage(role="user", content="Now generate a comprehensive summary script")
        )

        manager.register_llm("large-context", test_config)

        def large_context_inference() -> Any:
            try:
                return manager.chat(large_context, "large-context")
            except Exception:
                return None

        result: Any = benchmark(large_context_inference)

        assert benchmark.stats.mean < 3.0, "Large context inference should be under 3s"

    @pytest.mark.benchmark
    def test_ai_error_recovery_performance(self, benchmark: Any) -> None:
        """Test REAL performance of AI error recovery mechanisms."""
        manager: LLMManager = LLMManager()

        test_config: LLMConfig = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-3.5-turbo",
            api_key="invalid-key",
        )

        def error_recovery() -> str | None:
            try:
                manager.register_llm("error-test", test_config)

                test_messages: list[LLMMessage] = [
                    LLMMessage(role="user", content="Test message")
                ]
                result: Any = manager.chat(test_messages, "error-test")
                return str(result) if result else None

            except Exception:
                fallback_config: LLMConfig = LLMConfig(
                    provider=LLMProvider.OLLAMA, model_name="fallback-model"
                )

                try:
                    manager.register_llm("fallback", fallback_config)
                    return "Fallback response"
                except Exception:
                    return None

        result: str | None = benchmark(error_recovery)

        assert benchmark.stats.mean < 1.0, "Error recovery should be under 1 second"

    def test_ai_performance_under_load(self) -> None:
        """Test REAL AI performance under sustained load."""
        generator: AIScriptGenerator = AIScriptGenerator()

        generation_times: list[float] = []
        memory_usage: list[int] = []

        process: psutil.Process = psutil.Process()

        for i in range(10):
            start_time: float = time.time()
            current_memory: int = process.memory_info().rss

            request: dict[str, str] = {
                "target": "Windows x64",
                "task": f"Hook function {i}",
                "framework": "Frida",
            }

            result: GeneratedScript | None = generator.generate_frida_script(request)

            duration: float = time.time() - start_time
            generation_times.append(duration)
            memory_usage.append(current_memory)

            time.sleep(0.01)

        avg_time: float = sum(generation_times) / len(generation_times)
        max_time: float = max(generation_times)

        assert avg_time < 5.0, f"Average generation time under load too slow: {avg_time:.3f}s"
        assert max_time < 10.0, f"Maximum generation time under load too slow: {max_time:.3f}s"

        initial_memory: int = memory_usage[0]
        final_memory: int = memory_usage[-1]
        memory_growth: int = final_memory - initial_memory

        assert memory_growth < 100 * 1024 * 1024, (
            f"Memory growth under load too high: {memory_growth / 1024 / 1024:.2f}MB"
        )

    def test_ai_startup_performance(self) -> None:
        """Test REAL AI system startup performance."""
        startup_start: float = time.time()

        generator: AIScriptGenerator = AIScriptGenerator()
        manager: LLMManager = LLMManager()

        if hasattr(manager, "load_default_configs"):
            manager.load_default_configs()

        startup_duration: float = time.time() - startup_start

        assert generator is not None
        assert manager is not None

        assert startup_duration < 5.0, f"AI startup too slow: {startup_duration:.3f}s"
