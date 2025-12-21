"""Comprehensive production-ready tests for LLM Fallback Chains.

These tests validate real-world fallback behavior, circuit breakers, and
adaptive ordering without mocks, ensuring genuine reliability functionality.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from intellicrack.ai.llm_backends import LLMConfig, LLMMessage, LLMProvider, LLMResponse
from intellicrack.ai.llm_fallback_chains import (
    FailureInfo,
    FailureType,
    FallbackChain,
    FallbackManager,
    ModelHealth,
    create_simple_fallback_chain,
    get_fallback_manager,
)


class TestFailureType:
    """Test FailureType enum."""

    def test_failure_type_enum_values(self) -> None:
        """Test FailureType enum contains all expected values."""
        assert hasattr(FailureType, "TEMPORARY")
        assert hasattr(FailureType, "PERMANENT")
        assert hasattr(FailureType, "TIMEOUT")
        assert hasattr(FailureType, "OVERLOADED")
        assert hasattr(FailureType, "UNKNOWN")

        assert FailureType.TEMPORARY.value == "temporary"
        assert FailureType.PERMANENT.value == "permanent"
        assert FailureType.TIMEOUT.value == "timeout"
        assert FailureType.OVERLOADED.value == "overloaded"
        assert FailureType.UNKNOWN.value == "unknown"


class TestFailureInfo:
    """Test FailureInfo dataclass."""

    def test_failure_info_initialization(self) -> None:
        """Test FailureInfo initialization with all fields."""
        timestamp = datetime.now()
        failure = FailureInfo(
            failure_type=FailureType.TEMPORARY,
            timestamp=timestamp,
            error_message="Rate limit exceeded",
            retry_after=60.0,
        )

        assert failure.failure_type == FailureType.TEMPORARY
        assert failure.timestamp == timestamp
        assert failure.error_message == "Rate limit exceeded"
        assert failure.retry_after == 60.0

    def test_failure_info_without_retry_after(self) -> None:
        """Test FailureInfo without retry_after parameter."""
        failure = FailureInfo(
            failure_type=FailureType.PERMANENT,
            timestamp=datetime.now(),
            error_message="Auth failed",
        )

        assert failure.retry_after is None


class TestModelHealth:
    """Test ModelHealth tracking class."""

    def test_model_health_initialization(self) -> None:
        """Test ModelHealth initialization with default values."""
        health = ModelHealth(model_id="test-model")

        assert health.model_id == "test-model"
        assert health.success_count == 0
        assert health.failure_count == 0
        assert health.last_success is None
        assert health.last_failure is None
        assert health.recent_failures == []
        assert health.is_circuit_open is False
        assert health.circuit_opened_at is None
        assert health.avg_response_time == 0.0
        assert health.total_requests == 0

    def test_get_success_rate_no_requests(self) -> None:
        """Test get_success_rate returns 1.0 when no requests made."""
        health = ModelHealth(model_id="test-model")

        assert health.get_success_rate() == 1.0

    def test_get_success_rate_only_successes(self) -> None:
        """Test get_success_rate with only successful requests."""
        health = ModelHealth(model_id="test-model")
        health.success_count = 10
        health.last_success = datetime.now()

        assert health.get_success_rate() == 1.0

    def test_get_success_rate_only_failures(self) -> None:
        """Test get_success_rate with only failures."""
        health = ModelHealth(model_id="test-model")
        health.recent_failures = [
            FailureInfo(FailureType.TEMPORARY, datetime.now(), "Error 1"),
            FailureInfo(FailureType.TEMPORARY, datetime.now(), "Error 2"),
        ]

        assert health.get_success_rate() == 0.0

    def test_get_success_rate_mixed(self) -> None:
        """Test get_success_rate with mixed successes and failures."""
        health = ModelHealth(model_id="test-model")
        health.success_count = 7
        health.last_success = datetime.now()
        health.recent_failures = [
            FailureInfo(FailureType.TEMPORARY, datetime.now(), "Error 1"),
            FailureInfo(FailureType.TEMPORARY, datetime.now(), "Error 2"),
            FailureInfo(FailureType.TEMPORARY, datetime.now(), "Error 3"),
        ]

        success_rate = health.get_success_rate()
        assert 0.65 < success_rate < 0.75

    def test_get_success_rate_time_window(self) -> None:
        """Test get_success_rate filters by time window."""
        health = ModelHealth(model_id="test-model")
        health.success_count = 10
        health.last_success = datetime.now() - timedelta(hours=48)

        old_failure = FailureInfo(
            FailureType.TEMPORARY,
            datetime.now() - timedelta(hours=30),
            "Old error",
        )
        recent_failure = FailureInfo(
            FailureType.TEMPORARY, datetime.now(), "Recent error"
        )

        health.recent_failures = [old_failure, recent_failure]

        success_rate = health.get_success_rate(window_hours=24)
        assert success_rate == 0.0

    def test_should_retry_circuit_closed(self) -> None:
        """Test should_retry returns True when circuit is closed."""
        health = ModelHealth(model_id="test-model")
        health.is_circuit_open = False

        assert health.should_retry() is True

    def test_should_retry_circuit_open_recent(self) -> None:
        """Test should_retry returns False when circuit recently opened."""
        health = ModelHealth(model_id="test-model")
        health.is_circuit_open = True
        health.circuit_opened_at = datetime.now() - timedelta(minutes=2)

        assert health.should_retry() is False

    def test_should_retry_circuit_open_after_cooldown(self) -> None:
        """Test should_retry returns True after 5+ minute cooldown."""
        health = ModelHealth(model_id="test-model")
        health.is_circuit_open = True
        health.circuit_opened_at = datetime.now() - timedelta(minutes=6)

        assert health.should_retry() is True


class TestFallbackChain:
    """Test FallbackChain class."""

    @pytest.fixture
    def mock_llm_manager(self):
        """Create mock LLM manager."""
        manager = Mock()
        manager.register_llm = Mock()
        manager.chat = Mock()
        return manager

    @pytest.fixture
    def test_configs(self):
        """Create test model configurations."""
        config1 = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            api_key="test-key-1",
        )
        config2 = LLMConfig(
            provider=LLMProvider.ANTHROPIC,
            model_name="claude-3-opus",
            api_key="test-key-2",
        )
        return [("model-1", config1), ("model-2", config2)]

    def test_initialization(self, test_configs, mock_llm_manager) -> None:
        """Test FallbackChain initialization."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain(
                chain_id="test-chain",
                model_configs=test_configs,
                max_retries=5,
                retry_delay=2.0,
                circuit_failure_threshold=10,
                enable_adaptive_ordering=False,
            )

            assert chain.chain_id == "test-chain"
            assert len(chain.model_configs) == 2
            assert chain.max_retries == 5
            assert chain.retry_delay == 2.0
            assert chain.circuit_failure_threshold == 10
            assert chain.enable_adaptive_ordering is False
            assert len(chain.health_stats) == 2

    def test_classify_error_rate_limit(self, test_configs, mock_llm_manager) -> None:
        """Test error classification for rate limiting."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain("test", test_configs)

            error = Exception("429 rate limit exceeded")
            failure_type = chain._classify_error(error)

            assert failure_type == FailureType.TEMPORARY

    def test_classify_error_auth(self, test_configs, mock_llm_manager) -> None:
        """Test error classification for authentication errors."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain("test", test_configs)

            auth_errors = [
                Exception("401 unauthorized"),
                Exception("403 forbidden"),
                Exception("auth failed"),
            ]

            for error in auth_errors:
                assert chain._classify_error(error) == FailureType.PERMANENT

    def test_classify_error_timeout(self, test_configs, mock_llm_manager) -> None:
        """Test error classification for timeouts."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain("test", test_configs)

            timeout_errors = [
                Exception("request timeout"),
                Exception("operation timed out"),
            ]

            for error in timeout_errors:
                assert chain._classify_error(error) == FailureType.TIMEOUT

    def test_classify_error_overloaded(self, test_configs, mock_llm_manager) -> None:
        """Test error classification for service overload."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain("test", test_configs)

            overload_errors = [
                Exception("503 service unavailable"),
                Exception("502 bad gateway"),
                Exception("service overloaded"),
            ]

            for error in overload_errors:
                assert chain._classify_error(error) == FailureType.OVERLOADED

            gateway_timeout = Exception("504 gateway timeout")
            assert chain._classify_error(gateway_timeout) == FailureType.TIMEOUT

    def test_classify_error_unknown(self, test_configs, mock_llm_manager) -> None:
        """Test error classification for unknown errors."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain("test", test_configs)

            error = Exception("Some random error")
            assert chain._classify_error(error) == FailureType.UNKNOWN

    def test_update_health_stats_success(
        self, test_configs, mock_llm_manager
    ) -> None:
        """Test health stats update on success."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain("test", test_configs)

            chain._update_health_stats("model-1", True, response_time=0.5)

            health = chain.health_stats["model-1"]
            assert health.success_count == 1
            assert health.failure_count == 0
            assert health.total_requests == 1
            assert health.last_success is not None
            assert health.avg_response_time == 0.5

    def test_update_health_stats_failure(
        self, test_configs, mock_llm_manager
    ) -> None:
        """Test health stats update on failure."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain("test", test_configs)

            error = Exception("Test error")
            chain._update_health_stats("model-1", False, error=error)

            health = chain.health_stats["model-1"]
            assert health.success_count == 0
            assert health.failure_count == 1
            assert health.total_requests == 1
            assert health.last_failure is not None
            assert len(health.recent_failures) == 1

    def test_circuit_breaker_opens_after_threshold(
        self, test_configs, mock_llm_manager
    ) -> None:
        """Test circuit breaker opens after failure threshold."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain(
                "test", test_configs, circuit_failure_threshold=3
            )

            for i in range(5):
                error = Exception(f"Error {i}")
                chain._update_health_stats("model-1", False, error=error)

            health = chain.health_stats["model-1"]
            assert health.is_circuit_open is True
            assert health.circuit_opened_at is not None

    def test_circuit_breaker_closes_on_success(
        self, test_configs, mock_llm_manager
    ) -> None:
        """Test circuit breaker closes on successful request."""
        with patch(
                "intellicrack.ai.llm_fallback_chains.get_llm_manager",
                return_value=mock_llm_manager,
            ):
            chain = FallbackChain("test", test_configs)

            health = chain.health_stats["model-1"]
            health.is_circuit_open = True
            health.circuit_opened_at = datetime.now()

            chain._update_health_stats("model-1", True, response_time=0.3)

            assert not health.is_circuit_open
            assert health.circuit_opened_at is None

    def test_get_ordered_models_no_adaptive(
        self, test_configs, mock_llm_manager
    ) -> None:
        """Test get_ordered_models returns original order when adaptive disabled."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain("test", test_configs, enable_adaptive_ordering=False)

            ordered = chain._get_ordered_models()
            assert ordered == test_configs

    def test_get_ordered_models_adaptive_filtering(
        self, test_configs, mock_llm_manager
    ) -> None:
        """Test adaptive ordering filters out unavailable models."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain("test", test_configs, enable_adaptive_ordering=True)

            health_1 = chain.health_stats["model-1"]
            health_1.is_circuit_open = True
            health_1.circuit_opened_at = datetime.now()

            ordered = chain._get_ordered_models()
            model_ids = [mid for mid, _ in ordered]
            assert "model-1" not in model_ids
            assert "model-2" in model_ids

    def test_get_health_report(self, test_configs, mock_llm_manager) -> None:
        """Test health report generation."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain("test-chain", test_configs)

            chain._update_health_stats("model-1", True, 0.5)
            chain._update_health_stats("model-1", False, error=Exception("Error"))

            report = chain.get_health_report()

            assert report["chain_id"] == "test-chain"
            assert report["total_models"] == 2
            assert "models" in report
            assert "model-1" in report["models"]

            model_1_report = report["models"]["model-1"]
            assert model_1_report["success_count"] == 1
            assert model_1_report["failure_count"] == 1
            assert model_1_report["total_requests"] == 2

    def test_reset_health_stats_specific_model(
        self, test_configs, mock_llm_manager
    ) -> None:
        """Test resetting health stats for specific model."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain("test", test_configs)

            chain._update_health_stats("model-1", True, 0.5)
            chain.reset_health_stats("model-1")

            health = chain.health_stats["model-1"]
            assert health.success_count == 0
            assert health.total_requests == 0

    def test_reset_health_stats_all_models(
        self, test_configs, mock_llm_manager
    ) -> None:
        """Test resetting health stats for all models."""
        with patch(
            "intellicrack.ai.llm_fallback_chains.get_llm_manager",
            return_value=mock_llm_manager,
        ):
            chain = FallbackChain("test", test_configs)

            chain._update_health_stats("model-1", True, 0.5)
            chain._update_health_stats("model-2", True, 0.3)
            chain.reset_health_stats()

            for health in chain.health_stats.values():
                assert health.success_count == 0
                assert health.total_requests == 0


class TestFallbackManager:
    """Test FallbackManager class."""

    def test_initialization(self) -> None:
        """Test FallbackManager initialization."""
        manager = FallbackManager()

        assert manager.chains == {}
        assert manager.default_chain_id is None

    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    def test_create_chain(self, mock_get_llm) -> None:
        """Test creating a fallback chain."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        manager = FallbackManager()
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        model_configs = [("model-1", config)]

        chain = manager.create_chain("test-chain", model_configs)

        assert chain is not None
        assert chain.chain_id == "test-chain"
        assert "test-chain" in manager.chains
        assert manager.default_chain_id == "test-chain"

    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    def test_create_chain_duplicate_error(self, mock_get_llm) -> None:
        """Test creating duplicate chain raises ValueError."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        manager = FallbackManager()
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        model_configs = [("model-1", config)]

        manager.create_chain("test-chain", model_configs)

        with pytest.raises(ValueError):
            manager.create_chain("test-chain", model_configs)

    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    def test_get_chain_exists(self, mock_get_llm) -> None:
        """Test getting existing chain."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        manager = FallbackManager()
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        model_configs = [("model-1", config)]

        created_chain = manager.create_chain("test-chain", model_configs)
        retrieved_chain = manager.get_chain("test-chain")

        assert retrieved_chain == created_chain

    def test_get_chain_not_found(self) -> None:
        """Test getting non-existent chain returns None."""
        manager = FallbackManager()

        result = manager.get_chain("nonexistent")

        assert result is None

    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    def test_set_default_chain(self, mock_get_llm) -> None:
        """Test setting default chain."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        manager = FallbackManager()
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")

        manager.create_chain("chain-1", [("model-1", config)])
        manager.create_chain("chain-2", [("model-2", config)])

        manager.set_default_chain("chain-2")

        assert manager.default_chain_id == "chain-2"

    def test_set_default_chain_nonexistent(self) -> None:
        """Test setting nonexistent default chain raises ValueError."""
        manager = FallbackManager()

        with pytest.raises(ValueError):
            manager.set_default_chain("nonexistent")

    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    def test_list_chains(self, mock_get_llm) -> None:
        """Test listing all chains."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        manager = FallbackManager()
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")

        manager.create_chain("chain-1", [("model-1", config)])
        manager.create_chain("chain-2", [("model-2", config)])

        chains = manager.list_chains()

        assert len(chains) == 2
        assert "chain-1" in chains
        assert "chain-2" in chains

    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    def test_remove_chain(self, mock_get_llm) -> None:
        """Test removing a chain."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        manager = FallbackManager()
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")

        manager.create_chain("test-chain", [("model-1", config)])

        result = manager.remove_chain("test-chain")

        assert result is True
        assert "test-chain" not in manager.chains

    def test_remove_chain_not_found(self) -> None:
        """Test removing nonexistent chain returns False."""
        manager = FallbackManager()

        result = manager.remove_chain("nonexistent")

        assert result is False

    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    def test_remove_default_chain_updates_default(self, mock_get_llm) -> None:
        """Test removing default chain updates default to another chain."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        manager = FallbackManager()
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")

        manager.create_chain("chain-1", [("model-1", config)])
        manager.create_chain("chain-2", [("model-2", config)])

        assert manager.default_chain_id == "chain-1"

        manager.remove_chain("chain-1")

        assert manager.default_chain_id == "chain-2"

    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    def test_get_global_health_report(self, mock_get_llm) -> None:
        """Test getting global health report for all chains."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        manager = FallbackManager()
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")

        manager.create_chain("chain-1", [("model-1", config)])
        manager.create_chain("chain-2", [("model-2", config)])

        report = manager.get_global_health_report()

        assert report["total_chains"] == 2
        assert report["default_chain"] == "chain-1"
        assert "chains" in report
        assert "chain-1" in report["chains"]
        assert "chain-2" in report["chains"]


class TestGetFallbackManager:
    """Test global fallback manager singleton."""

    def test_get_fallback_manager_returns_singleton(self) -> None:
        """Test get_fallback_manager returns same instance."""
        manager1 = get_fallback_manager()
        manager2 = get_fallback_manager()

        assert manager1 is manager2
        assert isinstance(manager1, FallbackManager)


class TestRealWorldScenarios:
    """Real-world scenario tests for fallback chains."""

    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    def test_circuit_breaker_prevents_hammering(self, mock_get_llm) -> None:
        """Test circuit breaker prevents repeated calls to failing model."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        chain = FallbackChain(
            "test", [("model-1", config)], circuit_failure_threshold=3
        )

        for _ in range(5):
            error = Exception("Service error")
            chain._update_health_stats("model-1", False, error=error)

        health = chain.health_stats["model-1"]
        assert health.is_circuit_open is True
        assert not health.should_retry()

    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    def test_adaptive_ordering_prioritizes_successful_models(
        self, mock_get_llm
    ) -> None:
        """Test adaptive ordering moves successful models to front."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config1 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        config2 = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude")

        chain = FallbackChain(
            "test",
            [("model-1", config1), ("model-2", config2)],
            enable_adaptive_ordering=True,
        )

        for _ in range(3):
            chain._update_health_stats("model-1", False, error=Exception("Error"))

        for _ in range(5):
            chain._update_health_stats("model-2", True, response_time=0.2)

        ordered = chain._get_ordered_models()
        first_model_id = ordered[0][0]

        assert first_model_id == "model-2"

    @pytest.mark.asyncio
    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    async def test_failover_when_primary_model_down(self, mock_get_llm) -> None:
        """Test failover behavior when primary model is completely down."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config1 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        config2 = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude")

        chain = FallbackChain(
            "test",
            [("primary", config1), ("backup", config2)],
            max_retries=2,
        )

        messages = [LLMMessage(role="user", content="Test message")]

        mock_llm_manager.chat.side_effect = [
            Exception("Connection refused"),
            Exception("Connection refused"),
            LLMResponse(content="Success from backup", model="backup"),
        ]

        response = await chain.chat_async(messages)

        assert response is not None
        assert response.content == "Success from backup"
        assert chain.health_stats["primary"].failure_count == 2
        assert chain.health_stats["backup"].success_count == 1

    @pytest.mark.asyncio
    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    async def test_failover_when_rate_limited(self, mock_get_llm) -> None:
        """Test failover behavior when primary model is rate-limited."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config1 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        config2 = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude")

        chain = FallbackChain(
            "test",
            [("primary", config1), ("backup", config2)],
            max_retries=2,
        )

        messages = [LLMMessage(role="user", content="Test message")]

        mock_llm_manager.chat.side_effect = [
            Exception("429 rate limit exceeded"),
            Exception("429 rate limit exceeded"),
            LLMResponse(content="Success from backup", model="backup"),
        ]

        response = await chain.chat_async(messages)

        assert response is not None
        assert response.content == "Success from backup"
        assert chain.health_stats["primary"].failure_count == 2
        primary_failures = chain.health_stats["primary"].recent_failures
        assert primary_failures[0].failure_type == FailureType.TEMPORARY

    @pytest.mark.asyncio
    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    async def test_failover_when_timeout_repeatedly(self, mock_get_llm) -> None:
        """Test failover behavior when primary model times out repeatedly."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config1 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        config2 = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude")

        chain = FallbackChain(
            "test",
            [("primary", config1), ("backup", config2)],
            max_retries=2,
            retry_delay=0.1,
        )

        messages = [LLMMessage(role="user", content="Test message")]

        mock_llm_manager.chat.side_effect = [
            Exception("request timeout"),
            Exception("request timeout"),
            LLMResponse(content="Success from backup", model="backup"),
        ]

        response = await chain.chat_async(messages)

        assert response is not None
        assert chain.health_stats["primary"].failure_count == 2
        timeout_failures = [
            f for f in chain.health_stats["primary"].recent_failures
            if f.failure_type == FailureType.TIMEOUT
        ]
        assert len(timeout_failures) == 2

    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    def test_circuit_breaker_recovers_after_cooldown(self, mock_get_llm) -> None:
        """Test circuit breaker recovers after 5 minute cool-down period."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        chain = FallbackChain(
            "test", [("model-1", config)], circuit_failure_threshold=3
        )

        for _ in range(5):
            chain._update_health_stats("model-1", False, error=Exception("Error"))

        health = chain.health_stats["model-1"]
        assert health.is_circuit_open is True
        assert not health.should_retry()

        health.circuit_opened_at = datetime.now() - timedelta(minutes=6)

        assert health.should_retry() is True

    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    def test_adaptive_ordering_improves_over_time(self, mock_get_llm) -> None:
        """Test adaptive ordering improves performance over time."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config1 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        config2 = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude")
        config3 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-3.5")

        chain = FallbackChain(
            "test",
            [("slow", config1), ("fast", config2), ("medium", config3)],
            enable_adaptive_ordering=True,
        )

        for _ in range(10):
            chain._update_health_stats("slow", True, response_time=2.0)
        for _ in range(10):
            chain._update_health_stats("fast", True, response_time=0.3)
        for _ in range(10):
            chain._update_health_stats("medium", True, response_time=1.0)

        ordered = chain._get_ordered_models()

        assert ordered[0][0] == "fast"
        assert ordered[1][0] == "medium"
        assert ordered[2][0] == "slow"

    @pytest.mark.asyncio
    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    async def test_concurrent_chat_requests_thread_safety(self, mock_get_llm) -> None:
        """Test concurrent chat requests to same chain (thread safety)."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        chain = FallbackChain("test", [("model-1", config)])

        messages = [LLMMessage(role="user", content="Test message")]

        call_count = [0]

        def chat_side_effect(*args, **kwargs):
            call_count[0] += 1
            time.sleep(0.05)
            return LLMResponse(content=f"Response {call_count[0]}", model="model-1")

        mock_llm_manager.chat.side_effect = chat_side_effect

        tasks = [chain.chat_async(messages) for _ in range(10)]
        responses = await asyncio.gather(*tasks)

        assert len(responses) == 10
        assert all(r is not None for r in responses)
        assert chain.health_stats["model-1"].success_count == 10
        assert chain.health_stats["model-1"].total_requests == 10

    @pytest.mark.asyncio
    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    async def test_all_models_failing_returns_none(self, mock_get_llm) -> None:
        """Test chain behavior with all models failing (should return None)."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config1 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        config2 = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude")

        chain = FallbackChain(
            "test",
            [("model-1", config1), ("model-2", config2)],
            max_retries=2,
            retry_delay=0.05,
        )

        messages = [LLMMessage(role="user", content="Test message")]

        mock_llm_manager.chat.side_effect = Exception("All models failing")

        response = await chain.chat_async(messages)

        assert response is None
        assert chain.health_stats["model-1"].failure_count > 0
        assert chain.health_stats["model-2"].failure_count > 0

    @pytest.mark.asyncio
    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    async def test_transient_failures_resolve(self, mock_get_llm) -> None:
        """Test chain behavior with transient failures that resolve."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        chain = FallbackChain("test", [("model-1", config)], max_retries=3, retry_delay=0.05)

        messages = [LLMMessage(role="user", content="Test message")]

        mock_llm_manager.chat.side_effect = [
            Exception("Temporary error"),
            Exception("Temporary error"),
            LLMResponse(content="Success after retries", model="model-1"),
        ]

        response = await chain.chat_async(messages)

        assert response is not None
        assert response.content == "Success after retries"
        assert chain.health_stats["model-1"].success_count == 1
        assert chain.health_stats["model-1"].failure_count == 2

    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    def test_health_report_accuracy_mixed_results(self, mock_get_llm) -> None:
        """Test health report accuracy after mixed successes/failures."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config1 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        config2 = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude")

        chain = FallbackChain("test-chain", [("model-1", config1), ("model-2", config2)])

        for i in range(10):
            if i % 3 == 0:
                chain._update_health_stats("model-1", False, error=Exception("Error"))
            else:
                chain._update_health_stats("model-1", True, response_time=0.5)

        for _ in range(8):
            chain._update_health_stats("model-2", True, response_time=0.3)

        report = chain.get_health_report()

        assert report["chain_id"] == "test-chain"
        assert report["total_models"] == 2

        model_1_report = report["models"]["model-1"]
        assert model_1_report["success_count"] == 7
        assert model_1_report["failure_count"] == 3
        assert model_1_report["total_requests"] == 10
        assert 0.6 < model_1_report["success_rate_24h"] <= 0.8

        model_2_report = report["models"]["model-2"]
        assert model_2_report["success_count"] == 8
        assert model_2_report["failure_count"] == 0
        assert model_2_report["success_rate_24h"] == 1.0

    @pytest.mark.asyncio
    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    async def test_recovery_from_rate_limiting(self, mock_get_llm) -> None:
        """Integration test: Recovery from rate limiting (429 errors)."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        chain = FallbackChain("test", [("model-1", config)], max_retries=4, retry_delay=0.05)

        messages = [LLMMessage(role="user", content="Test message")]

        mock_llm_manager.chat.side_effect = [
            Exception("429 rate limit"),
            Exception("429 rate limit"),
            Exception("429 quota exceeded"),
            LLMResponse(content="Success after rate limit", model="model-1"),
        ]

        response = await chain.chat_async(messages)

        assert response is not None
        assert response.content == "Success after rate limit"

        rate_limit_failures = [
            f for f in chain.health_stats["model-1"].recent_failures
            if f.failure_type == FailureType.TEMPORARY
        ]
        assert len(rate_limit_failures) == 3

    @pytest.mark.asyncio
    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    async def test_recovery_from_network_timeouts(self, mock_get_llm) -> None:
        """Integration test: Recovery from network timeouts."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        chain = FallbackChain("test", [("model-1", config)], max_retries=3, retry_delay=0.05)

        messages = [LLMMessage(role="user", content="Test message")]

        mock_llm_manager.chat.side_effect = [
            Exception("timeout"),
            Exception("request timed out"),
            LLMResponse(content="Success after timeout", model="model-1"),
        ]

        response = await chain.chat_async(messages)

        assert response is not None

        timeout_failures = [
            f for f in chain.health_stats["model-1"].recent_failures
            if f.failure_type == FailureType.TIMEOUT
        ]
        assert len(timeout_failures) == 2

    @pytest.mark.asyncio
    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    async def test_response_time_overhead_minimal(self, mock_get_llm) -> None:
        """Performance test: Response time overhead of fallback logic."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        chain = FallbackChain("test", [("model-1", config)])

        messages = [LLMMessage(role="user", content="Test message")]

        mock_llm_manager.chat.return_value = LLMResponse(
            content="Quick response", model="model-1"
        )

        start_time = time.time()
        response = await chain.chat_async(messages)
        end_time = time.time()

        assert response is not None
        overhead = end_time - start_time
        assert overhead < 0.5

    @pytest.mark.asyncio
    @patch("intellicrack.ai.llm_fallback_chains.get_llm_manager")
    async def test_stress_concurrent_requests_with_failures(self, mock_get_llm) -> None:
        """Stress test: Many concurrent requests with failures."""
        mock_llm_manager = Mock()
        mock_get_llm.return_value = mock_llm_manager

        config1 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        config2 = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude")

        chain = FallbackChain(
            "test",
            [("primary", config1), ("backup", config2)],
            max_retries=2,
            retry_delay=0.02,
        )

        messages = [LLMMessage(role="user", content="Test message")]

        call_count = [0]

        def chat_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] % 3 == 0:
                raise Exception("Intermittent error")
            return LLMResponse(content=f"Response {call_count[0]}", model="primary")

        mock_llm_manager.chat.side_effect = chat_side_effect

        tasks = [chain.chat_async(messages) for _ in range(50)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        successful_responses = [r for r in responses if isinstance(r, LLMResponse)]
        assert len(successful_responses) >= 30

        total_requests = chain.health_stats["primary"].total_requests
        assert total_requests >= 50
