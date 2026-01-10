"""Google Gemini API provider implementation.

This module provides integration with Google's Gemini models for
chat completion and tool/function calling.
"""

import asyncio
import json
import time
from collections.abc import AsyncIterator
from datetime import datetime

import google.generativeai as genai
from google.generativeai.types import GenerationConfig, Tool, FunctionDeclaration

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
from .base import LLMProviderBase


class GoogleProvider(LLMProviderBase):
    """Google Gemini API provider implementation.

    Provides integration with Google's Gemini models including
    support for tool/function calling and streaming responses.

    Attributes:
        _model: The currently loaded Gemini model.
        _current_task: Reference to any in-flight async task.
    """

    KNOWN_MODELS: list[tuple[str, str, int, bool, bool]] = [
        ("gemini-2.0-flash", "Gemini 2.0 Flash", 1048576, True, True),
        ("gemini-2.0-flash-thinking", "Gemini 2.0 Flash Thinking", 32767, True, True),
        ("gemini-1.5-pro", "Gemini 1.5 Pro", 2097152, True, True),
        ("gemini-1.5-flash", "Gemini 1.5 Flash", 1048576, True, True),
        ("gemini-1.5-flash-8b", "Gemini 1.5 Flash 8B", 1048576, True, True),
        ("gemini-1.0-pro", "Gemini 1.0 Pro", 32760, True, False),
    ]

    def __init__(self) -> None:
        """Initialize the Google provider."""
        super().__init__()
        self._model: genai.GenerativeModel | None = None
        self._current_task: asyncio.Task[object] | None = None
        self._logger = get_logger("providers.google")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName.GOOGLE
        """
        return ProviderName.GOOGLE

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to Google AI API.

        Args:
            credentials: Must contain api_key.

        Raises:
            AuthenticationError: If API key is invalid.
            ProviderError: If connection fails.
        """
        if not credentials.api_key:
            raise AuthenticationError("Google API key is required")

        try:
            genai.configure(api_key=credentials.api_key)
            test_model = genai.GenerativeModel("gemini-1.5-flash")
            await asyncio.to_thread(
                test_model.generate_content,
                "test",
                generation_config=GenerationConfig(max_output_tokens=1),
            )
            self._credentials = credentials
            self._connected = True
            self._logger.info("Connected to Google AI API")
        except Exception as e:
            error_msg = str(e).lower()
            if "api key" in error_msg or "authentication" in error_msg:
                raise AuthenticationError(f"Invalid Google API key: {e}") from e
            raise ProviderError(f"Failed to connect to Google AI: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect from Google AI API."""
        await super().disconnect()
        self._model = None
        self._current_task = None
        self._logger.info("Disconnected from Google AI API")

    async def list_models(self) -> list[ModelInfo]:
        """Get available Gemini models.

        Returns:
            List of available Gemini models.
        """
        models: list[ModelInfo] = []
        for model_id, display_name, context, tools, vision in self.KNOWN_MODELS:
            models.append(
                ModelInfo(
                    id=model_id,
                    name=display_name,
                    provider=ProviderName.GOOGLE,
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
        """Send a chat completion request to Gemini.

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
        if not self._connected:
            raise ProviderError("Not connected to Google AI API")

        self._cancel_requested = False

        gemini_contents = self._convert_messages_to_provider_format(messages)
        gemini_tools: list[Tool] | None = None
        if tools:
            gemini_tools = self._convert_tools_to_gemini_format(tools)

        log_provider_request(
            provider="google",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        start_time = time.perf_counter()

        try:
            generation_config = GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
            )

            self._model = genai.GenerativeModel(
                model_name=model,
                generation_config=generation_config,
                tools=gemini_tools,
            )

            response = await asyncio.to_thread(
                self._model.generate_content,
                gemini_contents,
            )

            duration_ms = (time.perf_counter() - start_time) * 1000

            content = ""
            tool_calls: list[ToolCall] = []

            if response.candidates:
                candidate = response.candidates[0]
                for part in candidate.content.parts:
                    if hasattr(part, "text") and part.text:
                        content += part.text
                    elif hasattr(part, "function_call"):
                        fc = part.function_call
                        func_name = fc.name
                        args = dict(fc.args) if fc.args else {}

                        tool_call = ToolCall(
                            id=f"call_{len(tool_calls)}",
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
                provider="google",
                model=model,
                tool_calls_count=len(tool_calls),
                duration_ms=duration_ms,
            )

            return message, tool_calls if tool_calls else None

        except Exception as e:
            error_msg = str(e).lower()
            if "quota" in error_msg or "rate" in error_msg:
                raise RateLimitError(f"Google rate limit exceeded: {e}") from e
            raise ProviderError(f"Google AI request failed: {e}") from e

    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Stream a chat completion response from Gemini.

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
        if not self._connected:
            raise ProviderError("Not connected to Google AI API")

        self._cancel_requested = False

        gemini_contents = self._convert_messages_to_provider_format(messages)
        gemini_tools: list[Tool] | None = None
        if tools:
            gemini_tools = self._convert_tools_to_gemini_format(tools)

        try:
            generation_config = GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
            )

            self._model = genai.GenerativeModel(
                model_name=model,
                generation_config=generation_config,
                tools=gemini_tools,
            )

            response = await asyncio.to_thread(
                self._model.generate_content,
                gemini_contents,
                stream=True,
            )

            for chunk in response:
                if self._cancel_requested:
                    break
                if chunk.text:
                    yield chunk.text

        except Exception as e:
            if not self._cancel_requested:
                raise ProviderError(f"Google AI stream failed: {e}") from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        if self._current_task is not None and not self._current_task.done():
            self._current_task.cancel()

    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to Gemini format.

        Args:
            messages: List of Message objects.

        Returns:
            List of content dicts for Gemini.
        """
        contents: list[dict[str, object]] = []

        for msg in messages:
            if msg.role == "system":
                contents.append({
                    "role": "user",
                    "parts": [{"text": f"[System Instruction]: {msg.content}"}],
                })
                contents.append({
                    "role": "model",
                    "parts": [{"text": "Understood. I will follow these instructions."}],
                })
            elif msg.role == "user":
                contents.append({
                    "role": "user",
                    "parts": [{"text": msg.content}],
                })
            elif msg.role == "assistant":
                parts: list[dict[str, object]] = []
                if msg.content:
                    parts.append({"text": msg.content})

                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        parts.append({
                            "function_call": {
                                "name": tc.function_name,
                                "args": tc.arguments,
                            }
                        })

                contents.append({
                    "role": "model",
                    "parts": parts,
                })
            elif msg.role == "tool" and msg.tool_results:
                parts_list: list[dict[str, object]] = []
                for tr in msg.tool_results:
                    result_data: str | dict[str, object]
                    if isinstance(tr.result, str):
                        result_data = tr.result
                    else:
                        result_data = tr.result

                    parts_list.append({
                        "function_response": {
                            "name": tr.call_id,
                            "response": {"result": result_data},
                        }
                    })

                contents.append({
                    "role": "user",
                    "parts": parts_list,
                })

        return contents

    def _convert_tools_to_gemini_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[Tool]:
        """Convert internal tools to Gemini format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            List of Gemini Tool objects.
        """
        function_declarations: list[FunctionDeclaration] = []

        for tool in tools:
            for func in tool.functions:
                properties: dict[str, dict[str, object]] = {}
                required: list[str] = []

                for param in func.parameters:
                    prop: dict[str, object] = {
                        "type": param.type.upper(),
                        "description": param.description,
                    }
                    if param.enum:
                        prop["enum"] = param.enum
                    properties[param.name] = prop
                    if param.required:
                        required.append(param.name)

                func_decl = FunctionDeclaration(
                    name=func.name,
                    description=func.description,
                    parameters={
                        "type": "OBJECT",
                        "properties": properties,
                        "required": required,
                    },
                )
                function_declarations.append(func_decl)

        return [Tool(function_declarations=function_declarations)]

    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to Gemini dict format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            List of tool dicts.
        """
        result: list[dict[str, object]] = []
        for tool in tools:
            for func in tool.functions:
                properties: dict[str, dict[str, object]] = {}
                required: list[str] = []

                for param in func.parameters:
                    prop: dict[str, object] = {
                        "type": param.type.upper(),
                        "description": param.description,
                    }
                    if param.enum:
                        prop["enum"] = param.enum
                    properties[param.name] = prop
                    if param.required:
                        required.append(param.name)

                result.append({
                    "name": func.name,
                    "description": func.description,
                    "parameters": {
                        "type": "OBJECT",
                        "properties": properties,
                        "required": required,
                    },
                })
        return result
