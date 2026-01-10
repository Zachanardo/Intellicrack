"""Ollama local LLM provider implementation.

This module provides integration with locally running Ollama models
for chat completion and tool/function calling.
"""

import asyncio
import json
import time
from collections.abc import AsyncIterator
from datetime import datetime

import httpx

from ..core.logging import get_logger, log_provider_request, log_provider_response
from ..core.types import (
    AuthenticationError,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    ToolCall,
    ToolDefinition,
)
from .base import LLMProviderBase


class OllamaProvider(LLMProviderBase):
    """Ollama local LLM provider implementation.

    Provides integration with locally running Ollama models.
    Tool calling support depends on the model being used.

    Attributes:
        _client: The httpx async client for API calls.
        _base_url: Base URL for Ollama API.
    """

    DEFAULT_BASE_URL = "http://localhost:11434"

    def __init__(self) -> None:
        """Initialize the Ollama provider."""
        super().__init__()
        self._client: httpx.AsyncClient | None = None
        self._base_url: str = self.DEFAULT_BASE_URL
        self._logger = get_logger("providers.ollama")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName.OLLAMA
        """
        return ProviderName.OLLAMA

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to Ollama API.

        Args:
            credentials: Can contain api_base for custom Ollama URL.

        Raises:
            ProviderError: If connection fails.
        """
        if credentials.api_base:
            self._base_url = credentials.api_base.rstrip("/")
        else:
            self._base_url = self.DEFAULT_BASE_URL

        try:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(300.0))
            response = await self._client.get(f"{self._base_url}/api/tags")
            response.raise_for_status()

            self._credentials = credentials
            self._connected = True
            self._logger.info("Connected to Ollama at %s", self._base_url)
        except httpx.ConnectError as e:
            raise ProviderError(
                f"Cannot connect to Ollama at {self._base_url}. "
                "Ensure Ollama is running."
            ) from e
        except Exception as e:
            raise ProviderError(f"Failed to connect to Ollama: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect from Ollama API."""
        await super().disconnect()
        if self._client:
            await self._client.aclose()
            self._client = None
        self._logger.info("Disconnected from Ollama")

    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available models from Ollama.

        Returns:
            List of available local models.

        Raises:
            ProviderError: If not connected.
        """
        if not self._connected or self._client is None:
            raise ProviderError("Not connected to Ollama")

        try:
            response = await self._client.get(f"{self._base_url}/api/tags")
            response.raise_for_status()
            data = response.json()

            models: list[ModelInfo] = []
            for model_data in data.get("models", []):
                model_name = model_data.get("name", "")
                size = model_data.get("size", 0)
                details = model_data.get("details", {})

                context_window = self._estimate_context_window(model_name, details)
                supports_tools = self._estimate_tool_support(model_name)

                models.append(
                    ModelInfo(
                        id=model_name,
                        name=model_name,
                        provider=ProviderName.OLLAMA,
                        context_window=context_window,
                        supports_tools=supports_tools,
                        supports_vision=self._estimate_vision_support(model_name),
                        supports_streaming=True,
                        input_cost_per_1m_tokens=None,
                        output_cost_per_1m_tokens=None,
                    )
                )

            return sorted(models, key=lambda m: m.name)
        except Exception as e:
            raise ProviderError(f"Failed to list Ollama models: {e}") from e

    def _estimate_context_window(
        self, model_name: str, details: dict[str, object]
    ) -> int:
        """Estimate context window for a model.

        Args:
            model_name: The model name.
            details: Model details from Ollama.

        Returns:
            Estimated context window in tokens.
        """
        name_lower = model_name.lower()
        if "128k" in name_lower:
            return 128000
        if "32k" in name_lower:
            return 32768
        if "llama3" in name_lower or "llama-3" in name_lower:
            return 8192
        if "mistral" in name_lower:
            return 32768
        if "qwen" in name_lower:
            return 32768
        if "deepseek" in name_lower:
            return 16384
        return 4096

    def _estimate_tool_support(self, model_name: str) -> bool:
        """Estimate if model supports tool calling.

        Args:
            model_name: The model name.

        Returns:
            True if model likely supports tools.
        """
        name_lower = model_name.lower()
        tool_capable = [
            "llama3", "llama-3",
            "mistral", "mixtral",
            "qwen", "deepseek",
            "codellama", "code-llama",
            "wizard", "openchat",
        ]
        return any(cap in name_lower for cap in tool_capable)

    def _estimate_vision_support(self, model_name: str) -> bool:
        """Estimate if model supports vision.

        Args:
            model_name: The model name.

        Returns:
            True if model likely supports vision.
        """
        name_lower = model_name.lower()
        return "vision" in name_lower or "llava" in name_lower

    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Send a chat completion request to Ollama.

        Args:
            messages: Conversation history.
            model: Model name to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.

        Returns:
            Tuple of (assistant message, tool calls if any).

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self._connected or self._client is None:
            raise ProviderError("Not connected to Ollama")

        self._cancel_requested = False

        ollama_messages = self._convert_messages_to_provider_format(messages)

        log_provider_request(
            provider="ollama",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        start_time = time.perf_counter()

        try:
            request_body: dict[str, object] = {
                "model": model,
                "messages": ollama_messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }

            if tools:
                request_body["tools"] = self._convert_tools_to_provider_format(tools)

            response = await self._client.post(
                f"{self._base_url}/api/chat",
                json=request_body,
            )
            response.raise_for_status()
            data = response.json()

            duration_ms = (time.perf_counter() - start_time) * 1000

            content = data.get("message", {}).get("content", "")
            tool_calls: list[ToolCall] = []

            if "message" in data and "tool_calls" in data["message"]:
                for idx, tc in enumerate(data["message"]["tool_calls"]):
                    func_data = tc.get("function", {})
                    func_name = func_data.get("name", "")
                    args = func_data.get("arguments", {})
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {}

                    tool_call = ToolCall(
                        id=f"call_{idx}",
                        tool_name=func_name.split(".")[0] if "." in func_name else func_name,
                        function_name=func_name,
                        arguments=args,
                    )
                    tool_calls.append(tool_call)

            message = Message(
                role="assistant",
                content=content,
                tool_calls=tool_calls if tool_calls else None,
                timestamp=datetime.now(),
            )

            log_provider_response(
                provider="ollama",
                model=model,
                tool_calls_count=len(tool_calls),
                duration_ms=duration_ms,
            )

            return message, tool_calls if tool_calls else None

        except httpx.HTTPStatusError as e:
            raise ProviderError(f"Ollama API error: {e}") from e
        except Exception as e:
            raise ProviderError(f"Ollama request failed: {e}") from e

    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Stream a chat completion response from Ollama.

        Args:
            messages: Conversation history.
            model: Model name to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.

        Yields:
            Text chunks as they arrive.

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self._connected or self._client is None:
            raise ProviderError("Not connected to Ollama")

        self._cancel_requested = False

        ollama_messages = self._convert_messages_to_provider_format(messages)

        try:
            request_body: dict[str, object] = {
                "model": model,
                "messages": ollama_messages,
                "stream": True,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }

            if tools:
                request_body["tools"] = self._convert_tools_to_provider_format(tools)

            async with self._client.stream(
                "POST",
                f"{self._base_url}/api/chat",
                json=request_body,
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if self._cancel_requested:
                        break
                    if line:
                        try:
                            chunk_data = json.loads(line)
                            content = chunk_data.get("message", {}).get("content", "")
                            if content:
                                yield content
                        except json.JSONDecodeError:
                            continue

        except Exception as e:
            if not self._cancel_requested:
                raise ProviderError(f"Ollama stream failed: {e}") from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True

    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to Ollama format.

        Args:
            messages: List of Message objects.

        Returns:
            List of messages in Ollama's format.
        """
        ollama_messages: list[dict[str, object]] = []

        for msg in messages:
            if msg.role == "system":
                ollama_messages.append({
                    "role": "system",
                    "content": msg.content,
                })
            elif msg.role == "user":
                ollama_messages.append({
                    "role": "user",
                    "content": msg.content,
                })
            elif msg.role == "assistant":
                assistant_msg: dict[str, object] = {
                    "role": "assistant",
                    "content": msg.content,
                }

                if msg.tool_calls:
                    tool_calls_list: list[dict[str, object]] = []
                    for tc in msg.tool_calls:
                        tool_calls_list.append({
                            "function": {
                                "name": tc.function_name,
                                "arguments": tc.arguments,
                            },
                        })
                    assistant_msg["tool_calls"] = tool_calls_list

                ollama_messages.append(assistant_msg)
            elif msg.role == "tool" and msg.tool_results:
                for tr in msg.tool_results:
                    result_content: str
                    if isinstance(tr.result, str):
                        result_content = tr.result
                    else:
                        result_content = json.dumps(tr.result)

                    ollama_messages.append({
                        "role": "tool",
                        "content": result_content,
                    })

        return ollama_messages

    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to Ollama format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            List of tools in Ollama's format.
        """
        ollama_tools: list[dict[str, object]] = []

        for tool in tools:
            for func in tool.functions:
                properties: dict[str, dict[str, object]] = {}
                required: list[str] = []

                for param in func.parameters:
                    prop: dict[str, object] = {
                        "type": param.type,
                        "description": param.description,
                    }
                    if param.enum:
                        prop["enum"] = param.enum
                    properties[param.name] = prop
                    if param.required:
                        required.append(param.name)

                ollama_tools.append({
                    "type": "function",
                    "function": {
                        "name": func.name,
                        "description": func.description,
                        "parameters": {
                            "type": "object",
                            "properties": properties,
                            "required": required,
                        },
                    },
                })

        return ollama_tools

    async def pull_model(self, model_name: str) -> AsyncIterator[str]:
        """Pull a model from Ollama library.

        Args:
            model_name: Name of model to pull.

        Yields:
            Progress status messages.

        Raises:
            ProviderError: If not connected or pull fails.
        """
        if not self._connected or self._client is None:
            raise ProviderError("Not connected to Ollama")

        try:
            async with self._client.stream(
                "POST",
                f"{self._base_url}/api/pull",
                json={"name": model_name},
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            status = data.get("status", "")
                            if status:
                                yield status
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            raise ProviderError(f"Failed to pull model {model_name}: {e}") from e
