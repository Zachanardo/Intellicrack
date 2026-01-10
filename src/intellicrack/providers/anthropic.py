"""Anthropic Claude API provider implementation.

This module provides integration with Anthropic's Claude models for
chat completion and tool/function calling.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator
from datetime import datetime
from typing import TypedDict

import anthropic

from ..core.logging import get_logger, log_provider_request, log_provider_response
from ..core.types import (
    AuthenticationError,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    RateLimitError,
    ToolCall,
    ToolDefinition,
)
from .base import LLMProviderBase, create_anthropic_tool_schema


class AnthropicMessageParam(TypedDict, total=False):
    """Type definition for Anthropic message parameter."""

    role: str
    content: str | list[dict[str, object]]


class AnthropicToolParam(TypedDict):
    """Type definition for Anthropic tool parameter."""

    name: str
    description: str
    input_schema: dict[str, object]


class AnthropicProvider(LLMProviderBase):
    """Anthropic Claude API provider implementation.

    Provides integration with Anthropic's Claude models including
    support for tool/function calling and streaming responses.

    Attributes:
        _client: The async Anthropic client instance.
        _current_task: Reference to any in-flight async task.
    """

    KNOWN_MODELS: list[tuple[str, str, int, bool, bool]] = [
        ("claude-sonnet-4-20250514", "Claude Sonnet 4", 200000, True, True),
        ("claude-opus-4-20250514", "Claude Opus 4", 200000, True, True),
        ("claude-3-7-sonnet-20250219", "Claude 3.7 Sonnet", 200000, True, True),
        ("claude-3-5-sonnet-20241022", "Claude 3.5 Sonnet", 200000, True, True),
        ("claude-3-5-haiku-20241022", "Claude 3.5 Haiku", 200000, True, True),
        ("claude-3-opus-20240229", "Claude 3 Opus", 200000, True, True),
        ("claude-3-sonnet-20240229", "Claude 3 Sonnet", 200000, True, True),
        ("claude-3-haiku-20240307", "Claude 3 Haiku", 200000, True, True),
    ]

    def __init__(self) -> None:
        """Initialize the Anthropic provider."""
        super().__init__()
        self._client: anthropic.AsyncAnthropic | None = None
        self._current_task: asyncio.Task[object] | None = None
        self._logger = get_logger("providers.anthropic")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName.ANTHROPIC
        """
        return ProviderName.ANTHROPIC

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to Anthropic API.

        Args:
            credentials: Must contain api_key.

        Raises:
            AuthenticationError: If API key is invalid.
            ProviderError: If connection fails.
        """
        if not credentials.api_key:
            raise AuthenticationError("Anthropic API key is required")

        try:
            self._client = anthropic.AsyncAnthropic(
                api_key=credentials.api_key,
                base_url=credentials.api_base,
            )
            await self._client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=1,
                messages=[{"role": "user", "content": "test"}],
            )
            self._credentials = credentials
            self._connected = True
            self._logger.info("Connected to Anthropic API")
        except anthropic.AuthenticationError as e:
            raise AuthenticationError(f"Invalid Anthropic API key: {e}") from e
        except Exception as e:
            raise ProviderError(f"Failed to connect to Anthropic: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect from Anthropic API."""
        await super().disconnect()
        self._client = None
        self._current_task = None
        self._logger.info("Disconnected from Anthropic API")

    async def list_models(self) -> list[ModelInfo]:
        """Get available Claude models.

        Anthropic doesn't have a models endpoint, so we return known models.

        Returns:
            List of available Claude models.
        """
        models: list[ModelInfo] = []
        for model_id, display_name, context, tools, vision in self.KNOWN_MODELS:
            models.append(
                ModelInfo(
                    id=model_id,
                    name=display_name,
                    provider=ProviderName.ANTHROPIC,
                    context_window=context,
                    supports_tools=tools,
                    supports_vision=vision,
                    supports_streaming=True,
                    input_cost_per_1m_tokens=None,
                    output_cost_per_1m_tokens=None,
                )
            )
        return models

    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Send a chat completion request to Claude.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.

        Returns:
            Tuple of (assistant message, tool calls if any).

        Raises:
            ProviderError: If not connected or request fails.
            RateLimitError: If rate limited.
        """
        if not self._connected or self._client is None:
            raise ProviderError("Not connected to Anthropic API")

        self._cancel_requested = False

        anthropic_messages = self._convert_messages_to_provider_format(messages)
        anthropic_tools: list[dict[str, object]] | None = None
        if tools:
            anthropic_tools = self._convert_tools_to_provider_format(tools)

        log_provider_request(
            provider="anthropic",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        import time

        start_time = time.perf_counter()

        try:
            kwargs: dict[str, object] = {
                "model": model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": anthropic_messages,
            }
            if anthropic_tools:
                kwargs["tools"] = anthropic_tools

            response = await self._client.messages.create(**kwargs)

            duration_ms = (time.perf_counter() - start_time) * 1000

            content = ""
            tool_calls: list[ToolCall] = []

            for block in response.content:
                if block.type == "text":
                    content += block.text
                elif block.type == "tool_use":
                    tool_call = ToolCall(
                        id=block.id,
                        tool_name=block.name.split(".")[0] if "." in block.name else block.name,
                        function_name=block.name,
                        arguments=dict(block.input) if isinstance(block.input, dict) else {},
                    )
                    tool_calls.append(tool_call)

            message = Message(
                role="assistant",
                content=content,
                tool_calls=tool_calls if tool_calls else None,
                timestamp=datetime.now(),
            )

            log_provider_response(
                provider="anthropic",
                model=model,
                tool_calls_count=len(tool_calls),
                duration_ms=duration_ms,
            )

            return message, tool_calls if tool_calls else None

        except anthropic.RateLimitError as e:
            raise RateLimitError(f"Anthropic rate limit exceeded: {e}") from e
        except anthropic.APIError as e:
            raise ProviderError(f"Anthropic API error: {e}") from e
        except Exception as e:
            raise ProviderError(f"Anthropic request failed: {e}") from e

    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Stream a chat completion response from Claude.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.

        Yields:
            Text chunks as they arrive.

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self._connected or self._client is None:
            raise ProviderError("Not connected to Anthropic API")

        self._cancel_requested = False

        anthropic_messages = self._convert_messages_to_provider_format(messages)
        anthropic_tools: list[dict[str, object]] | None = None
        if tools:
            anthropic_tools = self._convert_tools_to_provider_format(tools)

        try:
            kwargs: dict[str, object] = {
                "model": model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": anthropic_messages,
            }
            if anthropic_tools:
                kwargs["tools"] = anthropic_tools

            async with self._client.messages.stream(**kwargs) as stream:
                async for text in stream.text_stream:
                    if self._cancel_requested:
                        break
                    yield text

        except anthropic.RateLimitError as e:
            raise RateLimitError(f"Anthropic rate limit exceeded: {e}") from e
        except anthropic.APIError as e:
            raise ProviderError(f"Anthropic API error: {e}") from e
        except Exception as e:
            if not self._cancel_requested:
                raise ProviderError(f"Anthropic stream failed: {e}") from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        if self._current_task is not None and not self._current_task.done():
            self._current_task.cancel()

    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to Anthropic format.

        Args:
            messages: List of Message objects.

        Returns:
            List of messages in Anthropic's format.
        """
        anthropic_messages: list[dict[str, object]] = []

        for msg in messages:
            if msg.role == "system":
                continue

            if msg.role == "user":
                anthropic_messages.append({
                    "role": "user",
                    "content": msg.content,
                })
            elif msg.role == "assistant":
                content: list[dict[str, object]] = []

                if msg.content:
                    content.append({"type": "text", "text": msg.content})

                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        content.append({
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.function_name,
                            "input": tc.arguments,
                        })

                anthropic_messages.append({
                    "role": "assistant",
                    "content": content if content else msg.content,
                })
            elif msg.role == "tool" and msg.tool_results:
                tool_results: list[dict[str, object]] = []
                for tr in msg.tool_results:
                    result_content: str
                    if isinstance(tr.result, str):
                        result_content = tr.result
                    else:
                        result_content = json.dumps(tr.result)

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tr.call_id,
                        "content": result_content,
                        "is_error": not tr.success,
                    })

                anthropic_messages.append({
                    "role": "user",
                    "content": tool_results,
                })

        return anthropic_messages

    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to Anthropic format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            List of tools in Anthropic's format.
        """
        anthropic_tools: list[dict[str, object]] = []
        for tool in tools:
            tool_schemas = create_anthropic_tool_schema(tool)
            anthropic_tools.extend(tool_schemas)
        return anthropic_tools

    def get_system_prompt(self, messages: list[Message]) -> str | None:
        """Extract system prompt from messages.

        Args:
            messages: List of messages.

        Returns:
            System prompt content or None.
        """
        for msg in messages:
            if msg.role == "system":
                return msg.content
        return None
