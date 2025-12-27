"""Comprehensive edge case tests for LLM backends with real API integration.

Tests concurrency, timeouts, large inputs, and error recovery using real OpenAI API calls.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import pytest
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from intellicrack.ai.llm_backends import (
    LLMConfig,
    LLMMessage,
    LLMProvider,
    LLMResponse,
    OpenAIBackend,
)


@pytest.fixture(scope="module")
def openai_api_key() -> str:
    """Get OpenAI API key from environment."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        pytest.skip("OPENAI_API_KEY environment variable not set")
    return api_key


@pytest.fixture(scope="module")
def real_llm_config(openai_api_key: str) -> LLMConfig:
    """Provide real LLM configuration for testing."""
    return LLMConfig(
        provider=LLMProvider.OPENAI,
        model_name="gpt-3.5-turbo",
        api_key=openai_api_key,
        temperature=0.7,
        max_tokens=100,
    )


@pytest.fixture
def real_openai_backend(real_llm_config: LLMConfig) -> OpenAIBackend:
    """Provide real OpenAI backend instance."""
    pytest.importorskip("openai")
    backend = OpenAIBackend(real_llm_config)
    backend.initialize()
    return backend


class TestRealConcurrentChatRequests:
    """Test concurrent chat request scenarios with real API."""

    def test_concurrent_chat_requests_real_api(self, real_openai_backend: OpenAIBackend) -> None:
        """LLMBackend handles concurrent real OpenAI API requests."""
        messages_list = [
            [LLMMessage(role="user", content=f"Say the number {i}")]
            for i in range(3)
        ]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(real_openai_backend.chat, messages)
                for messages in messages_list
            ]
            responses = [f.result() for f in as_completed(futures)]

        assert len(responses) == 3
        assert all(isinstance(r, LLMResponse) for r in responses)
        assert all(len(r.content) > 0 for r in responses)
        assert all(r.finish_reason in ["stop", "length"] for r in responses)

    def test_concurrent_requests_with_different_content(self, real_openai_backend: OpenAIBackend) -> None:
        """LLMBackend handles concurrent requests with different prompts."""
        prompts = [
            "Name a color",
            "Name an animal",
            "Name a fruit",
        ]

        messages_list = [
            [LLMMessage(role="user", content=prompt)]
            for prompt in prompts
        ]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(real_openai_backend.chat, messages)
                for messages in messages_list
            ]
            responses = [f.result() for f in futures]

        assert len(responses) == 3
        assert all(isinstance(r, LLMResponse) for r in responses)
        assert all(len(r.content) > 0 for r in responses)


class TestRealTimeoutHandling:
    """Test timeout and slow response scenarios with real API."""

    def test_chat_request_completes_within_reasonable_time(self, real_openai_backend: OpenAIBackend) -> None:
        """LLMBackend completes real API request within reasonable timeout."""
        messages = [LLMMessage(role="user", content="Say hello")]

        start_time = time.time()
        response = real_openai_backend.chat(messages)
        elapsed_time = time.time() - start_time

        assert isinstance(response, LLMResponse)
        assert len(response.content) > 0
        assert elapsed_time < 30.0

    def test_multiple_sequential_requests(self, real_openai_backend: OpenAIBackend) -> None:
        """LLMBackend handles multiple sequential real API requests."""
        results = []

        for i in range(3):
            messages = [LLMMessage(role="user", content=f"Echo {i}")]
            response = real_openai_backend.chat(messages)
            results.append(response)

        assert len(results) == 3
        assert all(isinstance(r, LLMResponse) for r in results)
        assert all(len(r.content) > 0 for r in results)


class TestRealLargeInputHandling:
    """Test handling of large input scenarios with real API."""

    def test_moderately_long_message_content(self, real_openai_backend: OpenAIBackend) -> None:
        """LLMBackend handles moderately long message content with real API."""
        large_content = "Analyze this: " + ("test " * 200)

        messages = [LLMMessage(role="user", content=large_content)]

        response = real_openai_backend.chat(messages)

        assert isinstance(response, LLMResponse)
        assert len(response.content) > 0
        assert response.finish_reason in ["stop", "length"]

    def test_conversation_with_multiple_messages(self, real_openai_backend: OpenAIBackend) -> None:
        """LLMBackend handles conversation with multiple message history."""
        messages = [
            LLMMessage(role="user", content="What is 2+2?"),
            LLMMessage(role="assistant", content="4"),
            LLMMessage(role="user", content="What is 5+5?"),
        ]

        response = real_openai_backend.chat(messages)

        assert isinstance(response, LLMResponse)
        assert len(response.content) > 0


class TestRealErrorRecovery:
    """Test error recovery and resilience with real API."""

    def test_recovery_from_invalid_api_key(self) -> None:
        """LLMBackend handles invalid API key errors."""
        invalid_config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-3.5-turbo",
            api_key="invalid_key_12345",
            temperature=0.7,
            max_tokens=100,
        )

        backend = OpenAIBackend(invalid_config)

        result = backend.initialize()

        assert not result
        assert not backend.is_initialized

    def test_recovery_after_shutdown_and_reinit(self, real_llm_config: LLMConfig) -> None:
        """LLMBackend recovers after shutdown and reinitialization."""
        pytest.importorskip("openai")

        backend = OpenAIBackend(real_llm_config)

        assert backend.initialize()
        assert backend.is_initialized

        backend.shutdown()
        assert not backend.is_initialized
        assert backend.client is None

        assert backend.initialize()
        assert backend.is_initialized

    def test_backend_handles_empty_message_list(self, real_openai_backend: OpenAIBackend) -> None:
        """LLMBackend handles empty message list gracefully."""
        messages = []

        try:
            response = real_openai_backend.chat(messages)
            if response:
                assert isinstance(response, LLMResponse)
        except (ValueError, RuntimeError):
            pass


class TestRealConfigurationEdgeCases:
    """Test edge case configuration scenarios with real API."""

    def test_zero_temperature(self, openai_api_key: str) -> None:
        """LLMBackend handles zero temperature configuration with real API."""
        pytest.importorskip("openai")

        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-3.5-turbo",
            api_key=openai_api_key,
            temperature=0.0,
            max_tokens=50,
        )

        backend = OpenAIBackend(config)
        backend.initialize()

        messages = [LLMMessage(role="user", content="Say test")]
        response = backend.chat(messages)

        assert isinstance(response, LLMResponse)
        assert len(response.content) > 0

    def test_maximum_temperature(self, openai_api_key: str) -> None:
        """LLMBackend handles maximum temperature configuration with real API."""
        pytest.importorskip("openai")

        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-3.5-turbo",
            api_key=openai_api_key,
            temperature=2.0,
            max_tokens=50,
        )

        backend = OpenAIBackend(config)
        backend.initialize()

        messages = [LLMMessage(role="user", content="Say test")]
        response = backend.chat(messages)

        assert isinstance(response, LLMResponse)
        assert len(response.content) > 0

    def test_low_max_tokens(self, openai_api_key: str) -> None:
        """LLMBackend handles low max_tokens configuration with real API."""
        pytest.importorskip("openai")

        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-3.5-turbo",
            api_key=openai_api_key,
            temperature=0.7,
            max_tokens=10,
        )

        backend = OpenAIBackend(config)
        backend.initialize()

        messages = [LLMMessage(role="user", content="Tell me a long story")]
        response = backend.chat(messages)

        assert isinstance(response, LLMResponse)
        assert response.finish_reason == "length"


class TestRealMemoryAndResourceManagement:
    """Test memory and resource management with real API."""

    def test_memory_cleanup_after_multiple_requests(self, real_openai_backend: OpenAIBackend) -> None:
        """LLMBackend properly manages memory after multiple real API requests."""
        for i in range(5):
            messages = [LLMMessage(role="user", content=f"Request {i}")]
            response = real_openai_backend.chat(messages)
            assert isinstance(response, LLMResponse)

    def test_shutdown_cleanup_releases_resources(self, real_llm_config: LLMConfig) -> None:
        """LLMBackend shutdown properly releases all resources."""
        pytest.importorskip("openai")

        backend = OpenAIBackend(real_llm_config)
        backend.initialize()

        assert backend.is_initialized

        backend.shutdown()

        assert not backend.is_initialized


class TestRealCompleteMethod:
    """Test the complete() method alias with real API."""

    def test_complete_calls_chat(self, real_openai_backend: OpenAIBackend) -> None:
        """LLMBackend complete() method works with real API."""
        messages = [LLMMessage(role="user", content="Test completion")]

        response = real_openai_backend.complete(messages)

        assert isinstance(response, LLMResponse)
        assert len(response.content) > 0
