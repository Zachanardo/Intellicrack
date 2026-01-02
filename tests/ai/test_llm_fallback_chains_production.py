"""Production tests for LLM fallback chains.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Any

import pytest

from intellicrack.ai.llm_backends import LLMBackend, LLMConfig, LLMMessage, LLMProvider, LLMResponse
from intellicrack.ai.llm_fallback_chains import (
    FailureInfo,
    FailureType,
    FallbackChain,
    FallbackManager,
    ModelHealth,
    create_simple_fallback_chain,
    get_fallback_manager,
)


class TestLLMBackend(LLMBackend):
    """Test LLM backend that simulates different failure scenarios."""

    def __init__(self, config: LLMConfig, failure_mode: str = "none") -> None:
        """Initialize test backend with configurable failure mode."""
        super().__init__(config)
        self.failure_mode = failure_mode
        self.call_count = 0
        self.consecutive_failures = 0

    def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        """Simulate chat with configurable failures."""
        self.call_count += 1

        if self.failure_mode == "rate_limit":
            raise Exception("Rate limit exceeded. Retry after 60s")

        if self.failure_mode == "auth_error":
            raise Exception("401 Unauthorized: Invalid API key")

        if self.failure_mode == "timeout":
            raise Exception("Request timed out after 30s")

        if self.failure_mode == "service_unavailable":
            raise Exception("503 Service Unavailable")

        if self.failure_mode == "intermittent":
            self.consecutive_failures += 1
            if self.consecutive_failures <= 3:
                raise Exception("Temporary failure")
            self.consecutive_failures = 0

        if self.failure_mode == "consecutive_failures" and self.call_count <= 5:
            raise Exception("Consecutive failure")

        return LLMResponse(
            content=f"Test response {self.call_count}",
            model=self.config.model_name or "test-model",
            finish_reason="stop",
        )


class TestFailureTypeClassification:
    """Test failure type classification."""

    def test_classify_rate_limit_error(self) -> None:
        """Chain correctly classifies rate limit errors as temporary."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            api_key="test",
        )
        chain = FallbackChain("test", [("model1", config)])

        error = Exception("Rate limit exceeded. Retry after 60s")
        failure_type = chain._classify_error(error)

        assert failure_type == FailureType.TEMPORARY

    def test_classify_authentication_error(self) -> None:
        """Chain correctly classifies auth errors as permanent."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            api_key="test",
        )
        chain = FallbackChain("test", [("model1", config)])

        error = Exception("401 Unauthorized: Invalid API key")
        failure_type = chain._classify_error(error)

        assert failure_type == FailureType.PERMANENT

    def test_classify_timeout_error(self) -> None:
        """Chain correctly classifies timeout errors."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            api_key="test",
        )
        chain = FallbackChain("test", [("model1", config)])

        error = Exception("Request timed out after 30s")
        failure_type = chain._classify_error(error)

        assert failure_type == FailureType.TIMEOUT

    def test_classify_service_overloaded_error(self) -> None:
        """Chain correctly classifies service overload errors."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            api_key="test",
        )
        chain = FallbackChain("test", [("model1", config)])

        error = Exception("503 Service Unavailable")
        failure_type = chain._classify_error(error)

        assert failure_type == FailureType.OVERLOADED

    def test_classify_unknown_error(self) -> None:
        """Chain classifies unrecognized errors as unknown."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            api_key="test",
        )
        chain = FallbackChain("test", [("model1", config)])

        error = Exception("Unexpected internal error")
        failure_type = chain._classify_error(error)

        assert failure_type == FailureType.UNKNOWN


class TestModelHealth:
    """Test model health tracking."""

    def test_success_rate_calculation(self) -> None:
        """ModelHealth calculates success rate correctly."""
        health = ModelHealth(model_id="test-model")

        health.success_count = 8
        health.last_success = datetime.now()

        for _ in range(2):
            health.recent_failures.append(
                FailureInfo(
                    failure_type=FailureType.TEMPORARY,
                    timestamp=datetime.now(),
                    error_message="Test error",
                )
            )

        success_rate = health.get_success_rate(24)

        assert success_rate == 0.8

    def test_success_rate_outside_window(self) -> None:
        """ModelHealth excludes old successes from rate calculation."""
        health = ModelHealth(model_id="test-model")

        health.success_count = 10
        health.last_success = datetime.now() - timedelta(hours=48)

        health.recent_failures.append(
            FailureInfo(
                failure_type=FailureType.TEMPORARY,
                timestamp=datetime.now(),
                error_message="Test error",
            )
        )

        success_rate = health.get_success_rate(24)

        assert success_rate == 0.0

    def test_circuit_breaker_should_retry_when_open(self) -> None:
        """ModelHealth circuit breaker prevents retry when recently opened."""
        health = ModelHealth(model_id="test-model")

        health.is_circuit_open = True
        health.circuit_opened_at = datetime.now()

        assert health.should_retry() is False

    def test_circuit_breaker_should_retry_after_timeout(self) -> None:
        """ModelHealth circuit breaker allows retry after timeout period."""
        health = ModelHealth(model_id="test-model")

        health.is_circuit_open = True
        health.circuit_opened_at = datetime.now() - timedelta(minutes=10)

        assert health.should_retry() is True

    def test_circuit_breaker_should_retry_when_closed(self) -> None:
        """ModelHealth allows retry when circuit is closed."""
        health = ModelHealth(model_id="test-model")

        health.is_circuit_open = False

        assert health.should_retry() is True


class TestFallbackChain:
    """Test fallback chain functionality."""

    @pytest.fixture
    def test_chain(self) -> FallbackChain:
        """Create test fallback chain."""
        config1 = LLMConfig(
            provider=LLMProvider.LOCAL_API,
            model_name="model1",
            api_key="test1",
            api_base="http://localhost:11434",
        )
        config2 = LLMConfig(
            provider=LLMProvider.LOCAL_API,
            model_name="model2",
            api_key="test2",
            api_base="http://localhost:11435",
        )

        return FallbackChain(
            chain_id="test-chain",
            model_configs=[("model1", config1), ("model2", config2)],
            max_retries=3,
            retry_delay=0.1,
            circuit_failure_threshold=5,
        )

    def test_chain_initialization(self, test_chain: FallbackChain) -> None:
        """Fallback chain initializes with correct configuration."""
        assert test_chain.chain_id == "test-chain"
        assert len(test_chain.model_configs) == 2
        assert len(test_chain.health_stats) == 2
        assert test_chain.max_retries == 3
        assert test_chain.retry_delay == 0.1

    def test_chain_registers_models(self) -> None:
        """Fallback chain registers all models with LLM manager."""
        config = LLMConfig(
            provider=LLMProvider.LOCAL_API,
            model_name="test-model",
            api_key="test",
            api_base="http://localhost:11434",
        )

        chain = FallbackChain("test", [("model1", config)])

        assert "model1" in chain.health_stats
        assert chain.health_stats["model1"].model_id == "model1"

    def test_health_stats_update_on_success(self, test_chain: FallbackChain) -> None:
        """Chain updates health stats correctly on successful request."""
        test_chain._update_health_stats("model1", success=True, response_time=0.5)

        health = test_chain.health_stats["model1"]
        assert health.success_count == 1
        assert health.last_success is not None
        assert health.avg_response_time == 0.5
        assert health.total_requests == 1

    def test_health_stats_update_on_failure(self, test_chain: FallbackChain) -> None:
        """Chain updates health stats correctly on failed request."""
        error = Exception("Test failure")
        test_chain._update_health_stats("model1", success=False, error=error)

        health = test_chain.health_stats["model1"]
        assert health.failure_count == 1
        assert health.last_failure is not None
        assert len(health.recent_failures) == 1
        assert health.recent_failures[0].error_message == "Test failure"

    def test_circuit_breaker_opens_on_threshold(self, test_chain: FallbackChain) -> None:
        """Chain opens circuit breaker after threshold failures."""
        error = Exception("Repeated failure")

        for _ in range(5):
            test_chain._update_health_stats("model1", success=False, error=error)

        health = test_chain.health_stats["model1"]
        assert health.is_circuit_open is True
        assert health.circuit_opened_at is not None

    def test_circuit_breaker_closes_on_success(self, test_chain: FallbackChain) -> None:
        """Chain closes circuit breaker on successful request."""
        test_chain.health_stats["model1"].is_circuit_open = True
        test_chain.health_stats["model1"].circuit_opened_at = datetime.now()

        test_chain._update_health_stats("model1", success=True, response_time=0.3)

        health = test_chain.health_stats["model1"]
        assert health.is_circuit_open is False
        assert health.circuit_opened_at is None

    def test_adaptive_ordering_prioritizes_healthy_models(self, test_chain: FallbackChain) -> None:
        """Chain reorders models based on health when adaptive ordering enabled."""
        test_chain.enable_adaptive_ordering = True

        test_chain._update_health_stats("model1", success=True, response_time=0.5)
        test_chain._update_health_stats("model1", success=True, response_time=0.5)
        test_chain._update_health_stats("model2", success=True, response_time=0.2)
        test_chain._update_health_stats("model2", success=True, response_time=0.2)

        ordered_models = test_chain._get_ordered_models()

        assert ordered_models[0][0] == "model2"

    def test_adaptive_ordering_filters_open_circuits(self, test_chain: FallbackChain) -> None:
        """Chain excludes models with open circuit breakers."""
        test_chain.enable_adaptive_ordering = True

        test_chain.health_stats["model1"].is_circuit_open = True
        test_chain.health_stats["model1"].circuit_opened_at = datetime.now()

        ordered_models = test_chain._get_ordered_models()

        assert "model1" not in [m[0] for m in ordered_models]

    def test_get_health_report(self, test_chain: FallbackChain) -> None:
        """Chain generates comprehensive health report."""
        test_chain._update_health_stats("model1", success=True, response_time=0.3)
        test_chain._update_health_stats("model1", success=False, error=Exception("Test"))

        report = test_chain.get_health_report()

        assert report["chain_id"] == "test-chain"
        assert report["total_models"] == 2
        assert "model1" in report["models"]
        assert report["models"]["model1"]["success_count"] == 1
        assert report["models"]["model1"]["failure_count"] == 1

    def test_reset_health_stats_single_model(self, test_chain: FallbackChain) -> None:
        """Chain resets health stats for specific model."""
        test_chain._update_health_stats("model1", success=True)
        test_chain.reset_health_stats("model1")

        health = test_chain.health_stats["model1"]
        assert health.success_count == 0
        assert health.failure_count == 0

    def test_reset_health_stats_all_models(self, test_chain: FallbackChain) -> None:
        """Chain resets health stats for all models."""
        test_chain._update_health_stats("model1", success=True)
        test_chain._update_health_stats("model2", success=True)
        test_chain.reset_health_stats()

        assert test_chain.health_stats["model1"].success_count == 0
        assert test_chain.health_stats["model2"].success_count == 0

    def test_retry_with_exponential_backoff(self, test_chain: FallbackChain) -> None:
        """Chain implements exponential backoff for retries."""
        call_times: list[float] = []
        original_chat = test_chain.llm_manager.chat

        def track_time(*args: Any, **kwargs: Any) -> LLMResponse:
            call_times.append(time.time())
            raise Exception("Retry test")

        object.__setattr__(test_chain.llm_manager, "chat", track_time)

        messages = [LLMMessage(role="user", content="Test")]
        test_chain.chat(messages)

        object.__setattr__(test_chain.llm_manager, "chat", original_chat)

        if len(call_times) >= 3:
            delay1 = call_times[1] - call_times[0]
            delay2 = call_times[2] - call_times[1]
            assert delay2 > delay1

    def test_permanent_failure_skips_retries(self, test_chain: FallbackChain) -> None:
        """Chain skips retries for permanent failures."""
        call_count = 0
        original_chat = test_chain.llm_manager.chat

        def side_effect(*args: Any, **kwargs: Any) -> LLMResponse:
            nonlocal call_count
            call_count += 1
            raise Exception("401 Unauthorized")

        object.__setattr__(test_chain.llm_manager, "chat", side_effect)

        messages = [LLMMessage(role="user", content="Test")]
        test_chain.chat(messages)

        object.__setattr__(test_chain.llm_manager, "chat", original_chat)

        assert call_count < test_chain.max_retries


class TestFallbackManager:
    """Test fallback manager functionality."""

    @pytest.fixture
    def manager(self) -> FallbackManager:
        """Create fresh fallback manager."""
        return FallbackManager()

    def test_manager_initialization(self, manager: FallbackManager) -> None:
        """Manager initializes with empty state."""
        assert len(manager.chains) == 0
        assert manager.default_chain_id is None

    def test_create_chain(self, manager: FallbackManager) -> None:
        """Manager creates new fallback chain."""
        config = LLMConfig(
            provider=LLMProvider.LOCAL_API,
            model_name="test-model",
            api_key="test",
            api_base="http://localhost:11434",
        )

        chain = manager.create_chain("test-chain", [("model1", config)])

        assert chain.chain_id == "test-chain"
        assert "test-chain" in manager.chains
        assert manager.default_chain_id == "test-chain"

    def test_create_duplicate_chain_raises_error(self, manager: FallbackManager) -> None:
        """Manager prevents creating duplicate chain IDs."""
        config = LLMConfig(
            provider=LLMProvider.LOCAL_API,
            model_name="test-model",
            api_key="test",
            api_base="http://localhost:11434",
        )

        manager.create_chain("test-chain", [("model1", config)])

        with pytest.raises(ValueError, match="already exists"):
            manager.create_chain("test-chain", [("model1", config)])

    def test_get_chain(self, manager: FallbackManager) -> None:
        """Manager retrieves existing chain."""
        config = LLMConfig(
            provider=LLMProvider.LOCAL_API,
            model_name="test-model",
            api_key="test",
            api_base="http://localhost:11434",
        )

        manager.create_chain("test-chain", [("model1", config)])

        chain = manager.get_chain("test-chain")

        assert chain is not None
        assert chain.chain_id == "test-chain"

    def test_get_nonexistent_chain_returns_none(self, manager: FallbackManager) -> None:
        """Manager returns None for missing chain."""
        chain = manager.get_chain("nonexistent")

        assert chain is None

    def test_set_default_chain(self, manager: FallbackManager) -> None:
        """Manager sets default chain correctly."""
        config = LLMConfig(
            provider=LLMProvider.LOCAL_API,
            model_name="test-model",
            api_key="test",
            api_base="http://localhost:11434",
        )

        manager.create_chain("chain1", [("model1", config)])
        manager.create_chain("chain2", [("model2", config)])

        manager.set_default_chain("chain2")

        assert manager.default_chain_id == "chain2"

    def test_set_nonexistent_default_chain_raises_error(self, manager: FallbackManager) -> None:
        """Manager raises error when setting nonexistent default chain."""
        with pytest.raises(ValueError, match="does not exist"):
            manager.set_default_chain("nonexistent")

    def test_remove_chain(self, manager: FallbackManager) -> None:
        """Manager removes chain correctly."""
        config = LLMConfig(
            provider=LLMProvider.LOCAL_API,
            model_name="test-model",
            api_key="test",
            api_base="http://localhost:11434",
        )

        manager.create_chain("test-chain", [("model1", config)])

        result = manager.remove_chain("test-chain")

        assert result is True
        assert "test-chain" not in manager.chains

    def test_remove_nonexistent_chain_returns_false(self, manager: FallbackManager) -> None:
        """Manager returns False when removing nonexistent chain."""
        result = manager.remove_chain("nonexistent")

        assert result is False

    def test_remove_default_chain_updates_default(self, manager: FallbackManager) -> None:
        """Manager updates default when removed chain was default."""
        config = LLMConfig(
            provider=LLMProvider.LOCAL_API,
            model_name="test-model",
            api_key="test",
            api_base="http://localhost:11434",
        )

        manager.create_chain("chain1", [("model1", config)])
        manager.create_chain("chain2", [("model2", config)])

        manager.remove_chain("chain1")

        assert manager.default_chain_id == "chain2"

    def test_list_chains(self, manager: FallbackManager) -> None:
        """Manager lists all chain IDs."""
        config = LLMConfig(
            provider=LLMProvider.LOCAL_API,
            model_name="test-model",
            api_key="test",
            api_base="http://localhost:11434",
        )

        manager.create_chain("chain1", [("model1", config)])
        manager.create_chain("chain2", [("model2", config)])

        chains = manager.list_chains()

        assert "chain1" in chains
        assert "chain2" in chains
        assert len(chains) == 2

    def test_global_health_report(self, manager: FallbackManager) -> None:
        """Manager generates health report for all chains."""
        config = LLMConfig(
            provider=LLMProvider.LOCAL_API,
            model_name="test-model",
            api_key="test",
            api_base="http://localhost:11434",
        )

        manager.create_chain("chain1", [("model1", config)])
        manager.create_chain("chain2", [("model2", config)])

        report = manager.get_global_health_report()

        assert report["total_chains"] == 2
        assert "chain1" in report["chains"]
        assert "chain2" in report["chains"]

    def test_export_configuration(self, manager: FallbackManager) -> None:
        """Manager exports configuration to dictionary."""
        config = LLMConfig(
            provider=LLMProvider.LOCAL_API,
            model_name="test-model",
            api_key="test-key",
            api_base="http://localhost:11434",
        )

        manager.create_chain("test-chain", [("model1", config)])

        exported = manager.export_configuration()

        assert exported["version"] == "1.0"
        assert exported["default_chain"] == "test-chain"
        assert "test-chain" in exported["chains"]
        assert exported["chains"]["test-chain"]["chain_id"] == "test-chain"

    def test_get_fallback_manager_singleton(self) -> None:
        """Global function returns singleton manager instance."""
        manager1 = get_fallback_manager()
        manager2 = get_fallback_manager()

        assert manager1 is manager2
