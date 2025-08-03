"""Model Fallback Chains for Intellicrack LLM System

Provides automatic failover between models and providers for improved reliability.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
import random
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from ..utils.logger import get_logger
from .llm_backends import LLMConfig, LLMMessage, LLMResponse, get_llm_manager

logger = get_logger(__name__)


class FailureType(Enum):
    """Types of LLM failures for classification."""

    TEMPORARY = "temporary"  # Rate limits, temporary network issues
    PERMANENT = "permanent"  # Auth failures, invalid models
    TIMEOUT = "timeout"      # Request timeouts
    OVERLOADED = "overloaded"  # Service overloaded/unavailable
    UNKNOWN = "unknown"      # Unclassified errors


@dataclass
class FailureInfo:
    """Information about a model failure."""

    failure_type: FailureType
    timestamp: datetime
    error_message: str
    retry_after: float | None = None  # Seconds to wait before retry


@dataclass
class ModelHealth:
    """Health tracking for a model in the chain."""

    model_id: str
    success_count: int = 0
    failure_count: int = 0
    last_success: datetime | None = None
    last_failure: datetime | None = None
    recent_failures: list[FailureInfo] = field(default_factory=list)
    is_circuit_open: bool = False
    circuit_opened_at: datetime | None = None
    avg_response_time: float = 0.0
    total_requests: int = 0

    def get_success_rate(self, window_hours: int = 24) -> float:
        """Get success rate within a time window."""
        cutoff = datetime.now() - timedelta(hours=window_hours)

        recent_successes = self.success_count
        if self.last_success and self.last_success < cutoff:
            recent_successes = 0

        recent_failures = len(
            [f for f in self.recent_failures if f.timestamp > cutoff])

        total = recent_successes + recent_failures
        return recent_successes / total if total > 0 else 1.0

    def should_retry(self) -> bool:
        """Check if the model should be retried based on circuit breaker logic."""
        if not self.is_circuit_open:
            return True

        # Circuit breaker logic - try to close circuit after some time
        if self.circuit_opened_at:
            time_since_open = datetime.now() - self.circuit_opened_at
            # Try to close after 5 minutes
            if time_since_open > timedelta(minutes=5):
                return True

        return False


class FallbackChain:
    """Manages a chain of LLM models with automatic failover."""

    def __init__(self,
                 chain_id: str,
                 model_configs: list[tuple[str, LLMConfig]],
                 max_retries: int = 3,
                 retry_delay: float = 1.0,
                 circuit_failure_threshold: int = 5,
                 enable_adaptive_ordering: bool = True):
        """Initialize fallback chain.

        Args:
            chain_id: Unique identifier for this chain
            model_configs: List of (model_id, config) tuples in priority order
            max_retries: Maximum retries per model
            retry_delay: Base delay between retries (with exponential backoff)
            circuit_failure_threshold: Failures needed to open circuit breaker
            enable_adaptive_ordering: Whether to reorder based on performance

        """
        self.chain_id = chain_id
        self.model_configs = model_configs
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.circuit_failure_threshold = circuit_failure_threshold
        self.enable_adaptive_ordering = enable_adaptive_ordering

        # Health tracking
        self.health_stats = {model_id: ModelHealth(
            model_id) for model_id, _ in model_configs}

        # Thread safety
        self.lock = threading.RLock()

        # LLM Manager
        self.llm_manager = get_llm_manager()

        # Register all models with LLM manager
        self._register_models()

        logger.info(
            f"Initialized fallback chain '{chain_id}' with {len(model_configs)} models")

    def _register_models(self):
        """Register all models in the chain with the LLM manager."""
        for model_id, config in self.model_configs:
            try:
                self.llm_manager.register_llm(model_id, config)
                logger.debug(
                    f"Registered model {model_id} for chain {self.chain_id}")
            except Exception as e:
                logger.warning(f"Failed to register model {model_id}: {e}")

    def _classify_error(self, error: Exception) -> FailureType:
        """Classify the type of error for appropriate handling."""
        error_str = str(error).lower()

        # Rate limiting
        if any(keyword in error_str for keyword in ["rate limit", "quota", "429"]):
            return FailureType.TEMPORARY

        # Authentication issues
        if any(keyword in error_str for keyword in ["auth", "401", "403", "unauthorized", "forbidden"]):
            return FailureType.PERMANENT

        # Timeouts
        if any(keyword in error_str for keyword in ["timeout", "timed out"]):
            return FailureType.TIMEOUT

        # Service overloaded
        if any(keyword in error_str for keyword in ["503", "502", "504", "overloaded", "unavailable"]):
            return FailureType.OVERLOADED

        return FailureType.UNKNOWN

    def _update_health_stats(self, model_id: str, success: bool, response_time: float = 0.0, error: Exception = None):
        """Update health statistics for a model."""
        with self.lock:
            health = self.health_stats[model_id]
            health.total_requests += 1

            if success:
                health.success_count += 1
                health.last_success = datetime.now()
                health.avg_response_time = (
                    health.avg_response_time * (health.success_count - 1) + response_time) / health.success_count

                # Close circuit breaker on success
                if health.is_circuit_open:
                    health.is_circuit_open = False
                    health.circuit_opened_at = None
                    logger.info(f"Circuit breaker closed for model {model_id}")

            else:
                health.failure_count += 1
                health.last_failure = datetime.now()

                if error:
                    failure_type = self._classify_error(error)
                    failure_info = FailureInfo(
                        failure_type=failure_type,
                        timestamp=datetime.now(),
                        error_message=str(error),
                    )
                    health.recent_failures.append(failure_info)

                    # Keep only last 50 failures
                    if len(health.recent_failures) > 50:
                        health.recent_failures = health.recent_failures[-50:]

                    # Open circuit breaker if too many recent failures
                    recent_failures = len([f for f in health.recent_failures
                                           if f.timestamp > datetime.now() - timedelta(minutes=10)])

                    if recent_failures >= self.circuit_failure_threshold and not health.is_circuit_open:
                        health.is_circuit_open = True
                        health.circuit_opened_at = datetime.now()
                        logger.warning(
                            f"Circuit breaker opened for model {model_id} after {recent_failures} failures")

    def _get_ordered_models(self) -> list[tuple[str, LLMConfig]]:
        """Get models ordered by current performance if adaptive ordering is enabled."""
        if not self.enable_adaptive_ordering:
            return self.model_configs

        # Sort by success rate and response time
        def model_score(item):
            model_id, _ = item
            health = self.health_stats[model_id]

            # Skip models with open circuit breakers that shouldn't be retried
            if health.is_circuit_open and not health.should_retry():
                return -1.0

            success_rate = health.get_success_rate()
            response_time_score = 1.0 / \
                (1.0 + health.avg_response_time)  # Lower is better

            return success_rate * 0.7 + response_time_score * 0.3

        sorted_models = sorted(
            self.model_configs, key=model_score, reverse=True)

        # Filter out models that shouldn't be retried
        available_models = []
        for model_id, config in sorted_models:
            health = self.health_stats[model_id]
            if health.should_retry():
                available_models.append((model_id, config))

        return available_models

    async def chat_async(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse | None:
        """Async version of chat with fallback logic."""
        ordered_models = self._get_ordered_models()

        if not ordered_models:
            logger.error(f"No available models in chain {self.chain_id}")
            return None

        last_error = None

        for model_id, _config in ordered_models:
            health = self.health_stats[model_id]

            # Skip if circuit breaker is open
            if health.is_circuit_open and not health.should_retry():
                logger.debug(
                    f"Skipping model {model_id} - circuit breaker open")
                continue

            for attempt in range(self.max_retries):
                try:
                    start_time = time.time()

                    # Use asyncio to handle potential blocking calls
                    response = await asyncio.get_event_loop().run_in_executor(
                        None, self.llm_manager.chat, messages, model_id, tools,
                    )

                    if response:
                        response_time = time.time() - start_time
                        self._update_health_stats(
                            model_id, True, response_time)

                        logger.debug(
                            f"Chain {self.chain_id}: Success with model {model_id} (attempt {attempt + 1})")
                        return response
                    raise RuntimeError("LLM returned None response")

                except Exception as e:
                    last_error = e
                    response_time = time.time() - start_time
                    self._update_health_stats(
                        model_id, False, response_time, e)

                    failure_type = self._classify_error(e)

                    # Don't retry on permanent failures
                    if failure_type == FailureType.PERMANENT:
                        logger.warning(
                            f"Permanent failure for model {model_id}: {e}")
                        break

                    # Calculate backoff delay
                    if attempt < self.max_retries - 1:
                        delay = self.retry_delay * \
                            (2 ** attempt) + random.uniform(0, 1)  # noqa: S311
                        logger.debug(
                            f"Retrying model {model_id} in {delay:.2f}s (attempt {attempt + 1})")
                        await asyncio.sleep(delay)
                    else:
                        logger.warning(
                            f"All retries exhausted for model {model_id}: {e}")

        logger.error(
            f"All models failed in chain {self.chain_id}. Last error: {last_error}")
        return None

    def chat(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse | None:
        """Synchronous chat with fallback logic."""
        try:
            # Run async version in event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self.chat_async(messages, tools))
            finally:
                loop.close()
        except Exception as e:
            logger.error(f"Error in fallback chain chat: {e}")
            return None

    def get_health_report(self) -> dict[str, Any]:
        """Get a comprehensive health report for the chain."""
        with self.lock:
            report = {
                "chain_id": self.chain_id,
                "total_models": len(self.model_configs),
                "available_models": len([h for h in self.health_stats.values() if h.should_retry()]),
                "models": {},
            }

            for model_id, health in self.health_stats.items():
                model_report = {
                    "success_count": health.success_count,
                    "failure_count": health.failure_count,
                    "success_rate_24h": health.get_success_rate(24),
                    "avg_response_time": health.avg_response_time,
                    "is_circuit_open": health.is_circuit_open,
                    "total_requests": health.total_requests,
                    "last_success": health.last_success.isoformat() if health.last_success else None,
                    "last_failure": health.last_failure.isoformat() if health.last_failure else None,
                    "recent_failure_count": len(health.recent_failures),
                }
                report["models"][model_id] = model_report

            return report

    def reset_health_stats(self, model_id: str | None = None):
        """Reset health statistics for specific model or all models."""
        with self.lock:
            if model_id:
                if model_id in self.health_stats:
                    self.health_stats[model_id] = ModelHealth(model_id)
                    logger.info(f"Reset health stats for model {model_id}")
            else:
                for mid in self.health_stats:
                    self.health_stats[mid] = ModelHealth(mid)
                logger.info(
                    f"Reset health stats for all models in chain {self.chain_id}")


class FallbackManager:
    """Manages multiple fallback chains for different use cases."""

    def __init__(self):
        """Initialize the fallback manager."""
        self.chains = {}
        self.default_chain_id = None
        self.lock = threading.RLock()

        logger.info("FallbackManager initialized")

    def create_chain(self,
                     chain_id: str,
                     model_configs: list[tuple[str, LLMConfig]],
                     **kwargs) -> FallbackChain:
        """Create a new fallback chain.

        Args:
            chain_id: Unique identifier for the chain
            model_configs: List of (model_id, config) tuples
            **kwargs: Additional arguments for FallbackChain

        Returns:
            Created FallbackChain instance

        """
        with self.lock:
            if chain_id in self.chains:
                raise ValueError(f"Chain {chain_id} already exists")

            chain = FallbackChain(chain_id, model_configs, **kwargs)
            self.chains[chain_id] = chain

            # Set as default if it's the first chain
            if not self.default_chain_id:
                self.default_chain_id = chain_id

            logger.info(f"Created fallback chain: {chain_id}")
            return chain

    def get_chain(self, chain_id: str) -> FallbackChain | None:
        """Get a fallback chain by ID."""
        return self.chains.get(chain_id)

    def set_default_chain(self, chain_id: str):
        """Set the default fallback chain."""
        if chain_id not in self.chains:
            raise ValueError(f"Chain {chain_id} does not exist")

        self.default_chain_id = chain_id
        logger.info(f"Set default chain to: {chain_id}")

    def chat(self,
             messages: list[LLMMessage],
             chain_id: str | None = None,
             tools: list[dict] | None = None) -> LLMResponse | None:
        """Chat using a specific chain or the default chain.

        Args:
            messages: Chat messages
            chain_id: Chain to use (uses default if None)
            tools: Available tools for function calling

        Returns:
            LLM response or None if all models fail

        """
        target_chain_id = chain_id or self.default_chain_id

        if not target_chain_id:
            logger.error("No default chain set and no chain_id provided")
            return None

        chain = self.get_chain(target_chain_id)
        if not chain:
            logger.error(f"Chain not found: {target_chain_id}")
            return None

        return chain.chat(messages, tools)

    async def chat_async(self,
                         messages: list[LLMMessage],
                         chain_id: str | None = None,
                         tools: list[dict] | None = None) -> LLMResponse | None:
        """Async chat using fallback chains."""
        target_chain_id = chain_id or self.default_chain_id

        if not target_chain_id:
            logger.error("No default chain set and no chain_id provided")
            return None

        chain = self.get_chain(target_chain_id)
        if not chain:
            logger.error(f"Chain not found: {target_chain_id}")
            return None

        return await chain.chat_async(messages, tools)

    def list_chains(self) -> list[str]:
        """List all available chain IDs."""
        return list(self.chains.keys())

    def get_global_health_report(self) -> dict[str, Any]:
        """Get health report for all chains."""
        report = {
            "total_chains": len(self.chains),
            "default_chain": self.default_chain_id,
            "chains": {},
        }

        for chain_id, chain in self.chains.items():
            report["chains"][chain_id] = chain.get_health_report()

        return report

    def remove_chain(self, chain_id: str) -> bool:
        """Remove a fallback chain.

        Args:
            chain_id: Chain to remove

        Returns:
            True if removed, False if not found

        """
        with self.lock:
            if chain_id not in self.chains:
                return False

            del self.chains[chain_id]

            # Update default if necessary
            if self.default_chain_id == chain_id:
                self.default_chain_id = next(
                    iter(self.chains.keys())) if self.chains else None

            logger.info(f"Removed fallback chain: {chain_id}")
            return True

    def create_chain_from_config(self, config: dict[str, Any]) -> FallbackChain:
        """Create a chain from configuration dictionary.

        Args:
            config: Configuration dictionary with chain settings

        Returns:
            Created FallbackChain instance

        """
        chain_id = config["chain_id"]
        model_configs = []

        # Convert model configurations
        for model_config in config["models"]:
            from .llm_backends import LLMProvider

            provider = LLMProvider(model_config["provider"])
            llm_config = LLMConfig(
                provider=provider,
                model_name=model_config["model_name"],
                api_key=model_config.get("api_key"),
                api_base=model_config.get("api_base"),
                model_path=model_config.get("model_path"),
                context_length=model_config.get("context_length", 4096),
                temperature=model_config.get("temperature", 0.7),
                max_tokens=model_config.get("max_tokens", 2048),
                tools_enabled=model_config.get("tools_enabled", True),
                custom_params=model_config.get("custom_params", {}),
            )

            model_id = model_config.get(
                "model_id", f"{chain_id}_{len(model_configs)}")
            model_configs.append((model_id, llm_config))

        # Extract chain settings
        chain_settings = {
            "max_retries": config.get("max_retries", 3),
            "retry_delay": config.get("retry_delay", 1.0),
            "circuit_failure_threshold": config.get("circuit_failure_threshold", 5),
            "enable_adaptive_ordering": config.get("enable_adaptive_ordering", True),
        }

        return self.create_chain(chain_id, model_configs, **chain_settings)

    def export_configuration(self) -> dict[str, Any]:
        """Export all chains configuration to a dictionary."""
        config = {
            "version": "1.0",
            "default_chain": self.default_chain_id,
            "chains": {},
        }

        for chain_id, chain in self.chains.items():
            chain_config = {
                "chain_id": chain_id,
                "max_retries": chain.max_retries,
                "retry_delay": chain.retry_delay,
                "circuit_failure_threshold": chain.circuit_failure_threshold,
                "enable_adaptive_ordering": chain.enable_adaptive_ordering,
                "models": [],
            }

            for model_id, llm_config in chain.model_configs:
                model_config = {
                    "model_id": model_id,
                    "provider": llm_config.provider.value,
                    "model_name": llm_config.model_name,
                    "api_key": llm_config.api_key,
                    "api_base": llm_config.api_base,
                    "model_path": llm_config.model_path,
                    "context_length": llm_config.context_length,
                    "temperature": llm_config.temperature,
                    "max_tokens": llm_config.max_tokens,
                    "tools_enabled": llm_config.tools_enabled,
                    "custom_params": llm_config.custom_params,
                }
                chain_config["models"].append(model_config)

            config["chains"][chain_id] = chain_config

        return config

    def import_configuration(self, config: dict[str, Any], replace: bool = False):
        """Import chains configuration from a dictionary.

        Args:
            config: Configuration dictionary
            replace: Whether to replace existing chains

        """
        if replace:
            self.chains.clear()
            self.default_chain_id = None

        for chain_id, chain_config in config.get("chains", {}).items():
            if chain_id not in self.chains:
                try:
                    self.create_chain_from_config(chain_config)
                except Exception as e:
                    logger.error(f"Failed to import chain {chain_id}: {e}")

        # Set default chain
        default_chain = config.get("default_chain")
        if default_chain and default_chain in self.chains:
            self.set_default_chain(default_chain)


# Global instance
_FALLBACK_MANAGER = None


def get_fallback_manager() -> FallbackManager:
    """Get the global fallback manager instance."""
    global _FALLBACK_MANAGER
    if _FALLBACK_MANAGER is None:
        _FALLBACK_MANAGER = FallbackManager()
    return _FALLBACK_MANAGER


def create_simple_fallback_chain(chain_id: str,
                                 model_ids: list[str],
                                 use_existing_configs: bool = True) -> FallbackChain:
    """Create a simple fallback chain from existing model IDs.

    Args:
        chain_id: Unique identifier for the chain
        model_ids: List of existing model IDs in priority order
        use_existing_configs: Whether to use existing LLM manager configs

    Returns:
        Created FallbackChain instance

    """
    manager = get_fallback_manager()
    llm_manager = get_llm_manager()

    model_configs = []
    for model_id in model_ids:
        if use_existing_configs:
            # Get existing config from LLM manager
            model_info = llm_manager.get_llm_info(model_id)
            if not model_info:
                logger.warning(f"Model {model_id} not found in LLM manager")
                continue

            # We'll use a placeholder config - the actual config is already registered
            from .llm_backends import LLMConfig, LLMProvider
            placeholder_config = LLMConfig(
                provider=LLMProvider.OPENAI,  # Placeholder
                model_name=model_id,
            )
            model_configs.append((model_id, placeholder_config))
        else:
            logger.warning(
                f"Model {model_id} not found in LLM manager and use_existing_configs=False not supported")
            continue

    return manager.create_chain(chain_id, model_configs)
