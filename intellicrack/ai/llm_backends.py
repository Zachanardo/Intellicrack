"""LLM Backend Support for Intellicrack Agentic AI.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""
# pylint: disable=cyclic-import

import hashlib
import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from ..core.exceptions import ConfigurationError
from .background_loader import LoadingTask, QueuedProgressCallback, get_background_loader
from .llm_types import LoadingState, ProgressCallback


if TYPE_CHECKING:
    from collections.abc import Callable as CallableType


logger = logging.getLogger(__name__)

# Optional imports for ML libraries
HAS_TORCH = False
HAS_TENSORFLOW = False
HAS_NUMPY = False
GPU_AUTOLOADER_AVAILABLE = False

torch: Any = None
tf: Any = None
np: Any = None

get_device: Any = None
get_gpu_info: Any = None
optimize_for_gpu: Any = None
to_device: Any = None

try:
    import torch as _torch_module

    torch = _torch_module
    HAS_TORCH = True

    try:
        from ..utils.gpu_autoloader import (
            get_device as _get_device,
            get_gpu_info as _get_gpu_info,
            optimize_for_gpu as _optimize_for_gpu,
            to_device as _to_device,
        )

        get_device = _get_device
        get_gpu_info = _get_gpu_info
        optimize_for_gpu = _optimize_for_gpu
        to_device = _to_device
        GPU_AUTOLOADER_AVAILABLE = True
    except ImportError:
        pass

except ImportError:
    logger.exception("Import error in llm_backends")

try:
    import os

    os.environ["MKL_THREADING_LAYER"] = "GNU"

    from intellicrack.handlers.tensorflow_handler import tf as _tf_module

    tf = _tf_module
    HAS_TENSORFLOW = True
except ImportError:
    logger.exception("Import error in llm_backends")

try:
    from intellicrack.handlers.numpy_handler import (
        HAS_NUMPY as _HAS_NUMPY,
        numpy as _np_module,
    )

    np = _np_module
    HAS_NUMPY = _HAS_NUMPY
except ImportError:
    logger.exception("Import error in llm_backends")


def _load_tokenizer(source: str, **kwargs: Any) -> Any:
    """Load a tokenizer using transformers. Wrapper to avoid mypy no-untyped-call.

    Args:
        source: Model name or path to load tokenizer from
        **kwargs: Additional keyword arguments passed to AutoTokenizer.from_pretrained

    Returns:
        Loaded tokenizer instance

    """
    from transformers import AutoTokenizer

    loader: CallableType[..., Any] = AutoTokenizer.from_pretrained
    return loader(source, **kwargs)


def _load_model_pretrained(model_class: Any, source: str, **kwargs: Any) -> Any:
    """Load a model using from_pretrained. Wrapper to avoid mypy no-untyped-call.

    Args:
        model_class: The model class with from_pretrained method
        source: Model name or path to load from
        **kwargs: Additional keyword arguments passed to from_pretrained

    Returns:
        Loaded model instance

    """
    loader: CallableType[..., Any] = model_class.from_pretrained
    return loader(source, **kwargs)


def _load_model_from_config(model_class: Any, config: Any, **kwargs: Any) -> Any:
    """Create a model from config. Wrapper to avoid mypy no-untyped-call.

    Args:
        model_class: The model class with from_config method
        config: Model configuration object
        **kwargs: Additional keyword arguments passed to from_config

    Returns:
        Model instance created from config

    """
    loader: CallableType[..., Any] = model_class.from_config
    return loader(config, **kwargs)


class LLMProvider(Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    LLAMACPP = "llamacpp"
    OLLAMA = "ollama"
    HUGGINGFACE = "huggingface"
    LOCAL_API = "local_api"
    LOCAL_GGUF = "local_gguf"
    PYTORCH = "pytorch"
    TENSORFLOW = "tensorflow"
    ONNX = "onnx"
    SAFETENSORS = "safetensors"
    GPTQ = "gptq"
    HUGGINGFACE_LOCAL = "huggingface_local"


@dataclass
class LLMConfig:
    """Configuration for LLM backends.

    This dataclass defines all configuration parameters needed to initialize and
    run an LLM backend for AI-assisted binary analysis and code generation.
    Attributes:
        provider: LLM provider enum (OpenAI, Anthropic, Google, etc.)
        model_name: Name or identifier of the model to load
        api_key: API key for authentication (if using cloud API)
        api_base: Custom API base URL for self-hosted or alternative endpoints
        model_path: Local filesystem path to model file or directory
        context_length: Maximum context window size in tokens (default 4096)
        temperature: Sampling temperature for generation (0.0-1.0, default 0.7)
        max_tokens: Maximum tokens to generate per request (default 2048)
        tools_enabled: Whether to enable function calling/tool use (default True)
        system_prompt: System prompt to prepend to all requests
        custom_params: Additional backend-specific parameters
        device: Device specification (cuda, cpu, auto, etc.)
        quantization: Quantization method if using quantized models
        model: Alias for model_name field
    """

    provider: LLMProvider
    model_name: str | None = None
    api_key: str | None = None
    api_base: str | None = None
    model_path: str | None = None
    context_length: int = 4096
    temperature: float = 0.7
    max_tokens: int = 2048
    tools_enabled: bool = True
    system_prompt: str | None = None
    custom_params: dict[str, Any] | None = None
    device: str | None = None
    quantization: str | None = None
    model: str | None = None

    def __post_init__(self) -> None:
        """Validate and normalize configuration after dataclass initialization.

        Handles the 'model' field as an alias for 'model_name' and ensures that
        at least one model identifier is specified.

        Raises:
            ValueError: If neither model_name nor model is specified
        """
        # Handle 'model' as alias for 'model_name'
        if self.model and not self.model_name:
            self.model_name = self.model
        elif not self.model_name:
            raise ValueError("Either 'model_name' or 'model' must be specified")

        # Set default custom_params if None
        if self.custom_params is None:
            self.custom_params = {}


@dataclass
class LLMMessage:
    """Message structure for LLM communication.

    Represents a single message in a chat conversation with an LLM, supporting
    role-based messaging and function calling.

    Attributes:
        role: Message role - "system", "user", "assistant", or "tool"
        content: The actual message text content
        tool_calls: Optional list of tool/function calls made by the model
        tool_call_id: Optional identifier for tool call responses
    """

    role: str
    content: str
    tool_calls: list[dict[str, Any]] | None = None
    tool_call_id: str | None = None


@dataclass
class LLMResponse:
    """Response structure from LLM.

    Encapsulates the complete response from an LLM backend, including generated
    content, usage statistics, and tool call results.

    Attributes:
        content: Generated response text content
        tool_calls: Optional list of tool calls made by the model
        usage: Optional dictionary with token usage stats (prompt_tokens, completion_tokens, total_tokens)
        finish_reason: Reason for generation stop (stop, length, tool_calls, error)
        model: Name or identifier of the model that generated this response
    """

    content: str
    tool_calls: list[dict[str, Any]] | None = None
    usage: dict[str, int] | None = None
    finish_reason: str = "stop"
    model: str | None = None


class LLMBackend:
    """Base class for LLM backends.

    Provides a common interface for different LLM providers (OpenAI, Anthropic, etc).
    Subclasses must implement the initialize() and chat() methods to support
    specific backend implementations.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize the LLM backend with configuration.

        Args:
            config: LLMConfig object with backend settings and model parameters

        """
        self.config = config
        self.is_initialized = False
        self.tools: list[dict[str, Any]] = []
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def initialize(self) -> bool:
        """Initialize the backend.

        This base implementation always returns False. Subclasses must override
        to provide actual initialization logic for their specific LLM providers.

        Returns:
            False to indicate initialization is not implemented in base class

        """
        logger.warning("Base LLMBackend.initialize() called - subclasses should override this method")
        self.is_initialized = False
        return False

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Send chat messages and get response.

        This base implementation returns an error response. Subclasses must override
        to provide actual chat functionality for their specific LLM providers.

        Args:
            messages: List of LLMMessage objects to send to the model
            tools: Optional list of tool/function definitions for function calling

        Returns:
            LLMResponse with error message indicating not implemented

        """
        logger.debug("Chat called with %d messages and %d tools", len(messages), len(tools or []))

        logger.error("Base LLMBackend.chat() called - this method must be implemented by subclasses")
        return LLMResponse(
            content="Error: LLM backend not properly initialized. Please use a concrete backend implementation.",
            finish_reason="error",
            model="base_backend_fallback",
        )

    def complete(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Send chat messages and get response (alias for chat).

        This method provides an alternative name for the chat() method for
        compatibility with different API styles.

        Args:
            messages: List of LLMMessage objects to send to the model
            tools: Optional list of tool/function definitions for function calling

        Returns:
            LLMResponse from the chat() method

        """
        return self.chat(messages, tools)

    def register_tools(self, tools: list[dict[str, Any]]) -> None:
        """Register tools for function calling.

        Stores a list of available tools that the LLM can call. The specific
        handling of these tools is backend-dependent.

        Args:
            tools: List of tool/function definitions in OpenAI format

        """
        self.tools = tools

    def shutdown(self) -> None:
        """Shutdown the backend and clean up resources.

        Clears initialization state and registered tools. Subclasses should override
        to release backend-specific resources like model memory or server connections.

        """
        self.is_initialized = False
        self.tools.clear()
        logger.debug("Backend shutdown: %s", self.__class__.__name__)


class OpenAIBackend(LLMBackend):
    """OpenAI API backend.

    Implements LLM backend using OpenAI's API endpoints. Supports all OpenAI models
    including GPT-4, GPT-3.5-turbo, and custom fine-tuned models through compatible APIs.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize OpenAI backend with configuration.

        Args:
            config: LLMConfig object with OpenAI-specific settings (api_key, api_base, etc)

        """
        super().__init__(config)
        self.client: Any = None

    def initialize(self) -> bool:
        """Initialize OpenAI client and verify connection.

        Loads API key from configuration, environment variables, or secrets manager.
        Tests the connection by listing available models.

        Returns:
            True if client initialized and connection verified, False otherwise

        """
        try:
            import openai

            from ..utils.secrets_manager import get_secret

            if not self.config.api_key:
                # Try secrets manager (checks env vars, keychain, encrypted storage)
                api_key = get_secret("OPENAI_API_KEY")
                if not api_key:
                    logger.error("OpenAI API key not provided")
                    return False
            else:
                api_key = self.config.api_key

            self.client = openai.OpenAI(
                api_key=api_key,
                base_url=self.config.api_base,
            )

            # Test connection
            self.client.models.list()
            self.is_initialized = True
            logger.info("OpenAI backend initialized with model: %s", self.config.model_name)
            return True

        except ImportError:
            logger.exception("OpenAI package not installed. Install with: pip install openai")
            return False
        except (OSError, ValueError, RuntimeError):
            logger.exception("Failed to initialize OpenAI backend")
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Send chat to OpenAI API.

        Args:
            messages: List of chat messages to send
            tools: Optional list of tools for function calling

        Returns:
            LLMResponse with content, tool calls, usage, finish reason, and model name

        Raises:
            RuntimeError: If backend is not initialized
            OSError: If API call fails
            ValueError: If response format is invalid

        """
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        openai_messages: list[dict[str, Any]] = []
        for msg in messages:
            openai_msg: dict[str, Any] = {"role": msg.role, "content": msg.content}
            if msg.tool_calls:
                openai_msg["tool_calls"] = msg.tool_calls
            if msg.tool_call_id:
                openai_msg["tool_call_id"] = msg.tool_call_id
            openai_messages.append(openai_msg)

        # Prepare request parameters
        request_params = {
            "model": self.config.model_name,
            "messages": openai_messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }

        # Add tools if provided and enabled
        if tools and self.config.tools_enabled:
            request_params["tools"] = [{"type": "function", "function": tool} for tool in tools]
            request_params["tool_choice"] = "auto"

        try:
            response = self.client.chat.completions.create(**request_params)

            choice = response.choices[0]
            return LLMResponse(
                content=choice.message.content or "",
                tool_calls=choice.message.tool_calls,
                usage=response.usage.dict() if response.usage else None,
                finish_reason=choice.finish_reason,
                model=response.model,
            )

        except (OSError, ValueError, RuntimeError):
            logger.exception("OpenAI API error")
            raise

    def shutdown(self) -> None:
        """Shutdown OpenAI backend.

        Closes the client connection and releases resources. Calls parent shutdown
        to clear tools and reset initialization state.

        """
        super().shutdown()
        self.client = None


class AnthropicBackend(LLMBackend):
    """Anthropic Claude API backend.

    Implements LLM backend using Anthropic's Claude API. Supports various Claude model
    versions and includes extended context windows for large-scale binary analysis.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize Anthropic backend with configuration.

        Args:
            config: LLMConfig object with Anthropic-specific settings (api_key, model_name, etc)

        """
        super().__init__(config)
        self.client: Any = None

    def initialize(self) -> bool:
        """Initialize Anthropic client and verify API connectivity.

        Loads API key from configuration, environment variables, or secure storage.
        Validates client initialization without making a test API call.

        Returns:
            True if client initialized successfully, False otherwise

        """
        try:
            import anthropic

            from ..utils.secrets_manager import get_secret

            if not self.config.api_key:
                # Try secrets manager (checks env vars, keychain, encrypted storage)
                api_key = get_secret("ANTHROPIC_API_KEY")
                if not api_key:
                    logger.error("Anthropic API key not provided")
                    return False
            else:
                api_key = self.config.api_key

            self.client = anthropic.Anthropic(api_key=api_key)
            self.is_initialized = True
            logger.info("Anthropic backend initialized with model: %s", self.config.model_name)
            return True

        except ImportError:
            logger.exception("Anthropic package not installed. Install with: pip install anthropic")
            return False
        except (OSError, ValueError, RuntimeError):
            logger.exception("Failed to initialize Anthropic backend")
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Send chat to Anthropic API.

        Args:
            messages: List of chat messages to send
            tools: Optional list of tools for function calling

        Returns:
            LLMResponse with content, tool calls, finish reason, and model name

        Raises:
            RuntimeError: If backend is not initialized
            OSError: If API call fails
            ValueError: If response format is invalid

        """
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        # Convert messages to Anthropic format
        system_message = ""
        anthropic_messages = []

        for msg in messages:
            if msg.role == "system":
                system_message = msg.content
            else:
                anthropic_messages.append({"role": msg.role, "content": msg.content})

        request_params = {
            "model": self.config.model_name,
            "messages": anthropic_messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        }

        if system_message:
            request_params["system"] = system_message

        if tools and self.config.tools_enabled:
            request_params["tools"] = tools

        try:
            response = self.client.messages.create(**request_params)

            return LLMResponse(
                content=response.content[0].text if response.content else "",
                tool_calls=getattr(response, "tool_calls", None),
                finish_reason=response.stop_reason,
                model=response.model,
            )

        except (OSError, ValueError, RuntimeError):
            logger.exception("Anthropic API error")
            raise

    def shutdown(self) -> None:
        """Shutdown Anthropic backend.

        Closes the client connection and releases resources. Calls parent shutdown
        to clear tools and reset initialization state.

        """
        super().shutdown()
        self.client = None


class GoogleBackend(LLMBackend):
    """Google AI (Gemini) API backend.

    Implements LLM backend using Google's Generative AI API. Supports various Gemini
    model versions with custom system instructions and generation configurations.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize Google AI backend with configuration.

        Args:
            config: LLMConfig object with Google AI-specific settings (api_key, model_name, etc)

        """
        super().__init__(config)
        self.client: Any = None
        self.model: Any = None

    def initialize(self) -> bool:
        """Initialize Google Generative AI client.

        Loads API key from configuration, environment variables, or secure storage.
        Initializes the GenerativeModel with the specified model identifier.

        Returns:
            True if client and model initialized successfully, False otherwise

        """
        try:
            import google.generativeai as genai

            from ..utils.secrets_manager import get_secret

            if not self.config.api_key:
                api_key = get_secret("GOOGLE_API_KEY")
                if not api_key:
                    logger.error("Google API key not provided")
                    return False
            else:
                api_key = self.config.api_key

            genai.configure(api_key=api_key)
            self.client = genai
            self.model = genai.GenerativeModel(self.config.model_name or "gemini-pro")
            self.is_initialized = True
            logger.info("Google AI backend initialized with model: %s", self.config.model_name)
            return True

        except ImportError:
            logger.exception("google-generativeai package not installed. Install with: pip install google-generativeai")
            return False
        except (OSError, ValueError, RuntimeError):
            logger.exception("Failed to initialize Google AI backend")
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Send chat to Google AI API.

        Args:
            messages: List of chat messages to send
            tools: Optional list of tools for function calling

        Returns:
            LLMResponse with content, finish reason, and model name

        Raises:
            RuntimeError: If backend is not initialized
            OSError: If API call fails
            ValueError: If response format is invalid

        """
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        try:
            history: list[dict[str, Any]] = []
            system_instruction = None

            for msg in messages:
                if msg.role == "system":
                    system_instruction = msg.content
                elif msg.role == "user":
                    history.append({"role": "user", "parts": [msg.content]})
                elif msg.role == "assistant":
                    history.append({"role": "model", "parts": [msg.content]})

            if system_instruction:
                self.model = self.client.GenerativeModel(
                    self.config.model_name or "gemini-pro",
                    system_instruction=system_instruction,
                )

            chat = self.model.start_chat(history=history[:-1] if history else [])
            last_message = history[-1]["parts"][0] if history else ""

            generation_config = {
                "temperature": self.config.temperature,
                "max_output_tokens": self.config.max_tokens,
            }

            response = chat.send_message(last_message, generation_config=generation_config)

            return LLMResponse(
                content=response.text if hasattr(response, "text") else str(response),
                finish_reason="stop",
                model=self.config.model_name,
            )

        except (OSError, ValueError, RuntimeError):
            logger.exception("Google AI API error")
            raise

    def shutdown(self) -> None:
        """Shutdown Google AI backend.

        Closes the client and model instances. Calls parent shutdown to clear
        tools and reset initialization state.

        """
        super().shutdown()
        self.client = None
        self.model = None


class LlamaCppBackend(LLMBackend):
    """llama.cpp backend for GGUF models.

    Implements LLM backend using llama.cpp for efficient local inference with
    quantized GGUF-format models. Provides CPU and GPU support for various architectures.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize llama.cpp backend with configuration.

        Args:
            config: LLMConfig object with model_path pointing to a GGUF file

        """
        super().__init__(config)
        self.llama: Any = None

    def initialize(self) -> bool:
        """Initialize llama.cpp and load GGUF model.

        Validates the GGUF model file exists and creates a llama.cpp Llama instance
        with the specified context length and threading configuration.

        Returns:
            True if llama.cpp initialized and model loaded successfully, False otherwise

        """
        try:
            from llama_cpp import Llama

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error("GGUF model file not found: %s", self.config.model_path)
                return False

            # Initialize llama.cpp with GGUF model
            self.llama = Llama(
                model_path=self.config.model_path,
                n_ctx=self.config.context_length,
                verbose=False,
                n_threads=4,  # Adjust based on system
            )

            self.is_initialized = True
            logger.info("llama.cpp backend initialized with GGUF model: %s", self.config.model_path)
            return True

        except ImportError:
            logger.exception("llama-cpp-python not installed. Install with: pip install llama-cpp-python")
            return False
        except (OSError, ValueError, RuntimeError):
            logger.exception("Failed to initialize llama.cpp backend")
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Chat with llama.cpp model.

        Args:
            messages: List of chat messages to send
            tools: Optional list of tools for function calling

        Returns:
            LLMResponse with generated content, finish reason, and model name

        Raises:
            RuntimeError: If backend is not initialized
            OSError: If generation fails
            ValueError: If invalid response format received

        """
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        # Convert messages to prompt format
        prompt = LlamaCppBackend._messages_to_prompt(messages)

        try:
            # Generate response
            response = self.llama(
                prompt,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                echo=False,
                stop=["</s>", "<|im_end|>", "<|end|>"],
            )

            content = response["choices"][0]["text"].strip()

            # Handle tool calls if tools are available (basic implementation)
            tool_calls = None
            if tools and self.config.tools_enabled:
                tool_calls = LlamaCppBackend._extract_tool_calls(content, tools)

            return LLMResponse(
                content=content,
                tool_calls=tool_calls,
                finish_reason=response["choices"][0]["finish_reason"],
                model=self.config.model_name,
            )

        except (OSError, ValueError, RuntimeError):
            logger.exception("llama.cpp generation error")
            raise

    @staticmethod
    def _messages_to_prompt(messages: list[LLMMessage]) -> str:
        """Convert chat messages to llama.cpp prompt format.

        Formats messages using the ChatML format with special tokens for different roles.
        Automatically appends the assistant prompt to prepare for generation.

        Args:
            messages: List of LLMMessage objects to format

        Returns:
            Formatted prompt string with ChatML role markers and special tokens

        """
        prompt_parts = []

        for msg in messages:
            if msg.role == "system":
                prompt_parts.append(f"<|im_start|>system\n{msg.content}<|im_end|>")
            elif msg.role == "user":
                prompt_parts.append(f"<|im_start|>user\n{msg.content}<|im_end|>")
            elif msg.role == "assistant":
                prompt_parts.append(f"<|im_start|>assistant\n{msg.content}<|im_end|>")

        prompt_parts.append("<|im_start|>assistant\n")
        return "\n".join(prompt_parts)

    @staticmethod
    def _extract_tool_calls(content: str, tools: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
        """Extract tool/function calls from generated content using regex matching.

        Parses generated text for function call patterns and extracts arguments as JSON.
        This is a simplified implementation suitable for llama.cpp model responses.

        Args:
            content: Generated content string to parse for tool calls
            tools: List of available tool/function definitions to match against

        Returns:
            List of tool call dictionaries in OpenAI format, or None if no calls found

        """
        # This is a simplified implementation
        # In practice, you'd want more sophisticated parsing
        tool_calls = []

        # Look for function call patterns
        for tool in tools:
            tool_name = tool["name"]
            pattern = rf"{tool_name}\((.*?)\)"
            matches = re.finditer(pattern, content, re.DOTALL)

            for match in matches:
                try:
                    args_str = match.group(1).strip()
                    # Try to parse as JSON
                    args = json.loads(args_str) if args_str else {}

                    tool_calls.append(
                        {
                            "id": f"call_{hashlib.sha256(match.group(0).encode()).hexdigest()[:8]}",
                            "type": "function",
                            "function": {
                                "name": tool_name,
                                "arguments": json.dumps(args),
                            },
                        },
                    )
                except (json.JSONDecodeError, KeyError, ValueError):
                    logger.exception("Error in llm_backends")
                    continue

        return tool_calls or None

    def shutdown(self) -> None:
        """Shutdown llama.cpp backend.

        Releases the llama.cpp model and associated resources. Calls parent shutdown
        to clear tools and reset initialization state.

        """
        super().shutdown()
        if self.llama is not None:
            # Clean up llama.cpp model
            del self.llama
            self.llama = None


class OllamaBackend(LLMBackend):
    """Ollama backend for local model serving.

    Implements LLM backend using Ollama's local HTTP API for running models
    on the same machine or local network. Supports all Ollama-compatible models.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize Ollama backend with configuration.

        Loads Ollama server URL from configuration, environment variables, or
        service configuration. Raises ConfigurationError if URL cannot be determined.

        Args:
            config: LLMConfig object with api_base or Ollama server URL

        Raises:
            ConfigurationError: If Ollama API URL cannot be located or configured
        """
        super().__init__(config)
        # Get URL from configuration first, then secrets, then service config
        from intellicrack.utils.service_utils import get_service_url

        from ..utils.secrets_manager import get_secret

        try:
            self.base_url = config.api_base or get_secret("OLLAMA_API_BASE") or get_service_url("ollama_api")
        except Exception as e:
            self.logger.exception("Failed to get Ollama API URL")
            raise ConfigurationError(
                "Ollama API URL not configured. Please set 'service_urls.ollama_api' in configuration or OLLAMA_API_BASE environment variable.",
            ) from e

    def initialize(self) -> bool:
        """Initialize and verify connection to Ollama server.

        Attempts to connect to the Ollama server by fetching the list of available models.
        Handles connection errors gracefully and logs warnings instead of failing loudly.

        Returns:
            True if Ollama server is accessible and responsive, False otherwise

        """
        try:
            try:
                import requests
            except ImportError:
                logger.exception("requests library not available for Ollama backend")
                return False

            # Test connection to Ollama with proper error handling
            try:
                response = requests.get(f"{self.base_url}/api/tags", timeout=5)
                if response.status_code == 200:
                    self.is_initialized = True
                    logger.info("Ollama backend initialized with model: %s", self.config.model_name)
                    return True
                logger.warning(
                    "Ollama server responded with status %d",
                    response.status_code,
                )
                return False
            except requests.exceptions.ConnectionError:
                logger.warning("Ollama server not running - skipping initialization")
                return False
            except requests.exceptions.Timeout:
                logger.warning("Ollama server timeout - skipping initialization")
                return False
            except requests.exceptions.RequestException:
                logger.warning("Ollama server connection failed - skipping initialization")
                return False

        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Failed to initialize Ollama backend: %s", e)
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Chat with Ollama model.

        Args:
            messages: List of chat messages to send
            tools: Optional list of tools for function calling

        Returns:
            LLMResponse with content, finish reason, and model name or error message

        """
        if not self.is_initialized:
            return LLMResponse(
                content="Ollama backend not initialized - please check if Ollama server is running",
                finish_reason="error",
            )

        try:
            import requests
        except ImportError:
            self.logger.exception("Import error in llm_backends")
            return LLMResponse(
                content="Ollama backend requires 'requests' library",
                finish_reason="error",
            )

        ollama_messages = [{"role": msg.role, "content": msg.content} for msg in messages]
        request_data = {
            "model": self.config.model_name,
            "messages": ollama_messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }

        # Add tools to request if provided
        if tools:
            request_data["tools"] = tools
            logger.debug("Adding %d tools to Ollama request", len(tools))

        try:
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=request_data,
                timeout=60,
            )
            response.raise_for_status()

            result = response.json()

            return LLMResponse(
                content=result.get("message", {}).get("content", ""),
                finish_reason="stop",
                model=self.config.model_name,
            )

        except requests.exceptions.ConnectionError:
            logger.exception("Ollama server connection lost during chat request")
            return LLMResponse(
                content="Ollama server connection lost - please check if Ollama is running",
                finish_reason="error",
                model=self.config.model_name,
            )
        except requests.exceptions.Timeout:
            logger.exception("Ollama server timeout during chat request")
            return LLMResponse(
                content="Ollama server timeout - request took too long to complete",
                finish_reason="error",
                model=self.config.model_name,
            )
        except requests.exceptions.RequestException as e:
            logger.exception("Ollama API request error")
            return LLMResponse(
                content=f"Ollama API error: {e}",
                finish_reason="error",
                model=self.config.model_name,
            )
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Ollama API error")
            return LLMResponse(
                content=f"Ollama API error: {e}",
                finish_reason="error",
                model=self.config.model_name,
            )

    def shutdown(self) -> None:
        """Shutdown Ollama backend.

        Closes connection to Ollama server. No persistent resources to release
        since HTTP connections are stateless. Calls parent shutdown to clear tools.

        """
        super().shutdown()
        # No specific cleanup needed for HTTP client


class LocalGGUFBackend(LLMBackend):
    """Local GGUF model backend using local inference server.

    Implements LLM backend using a local GGUF model server that runs on the same
    machine or local network. Supports model loading and unloading on demand.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize Local GGUF backend with configuration.

        Loads local server URL from configuration or service configuration.
        Raises ConfigurationError if server URL cannot be determined.

        Args:
            config: LLMConfig object with model_path for GGUF model files

        Raises:
            ConfigurationError: If local LLM server URL not configured
        """
        super().__init__(config)
        # Get URL from configuration first, then fallback
        from intellicrack.utils.service_utils import get_service_url

        try:
            self.server_url = config.api_base or get_service_url("local_llm_server")
        except Exception as e:
            self.logger.exception("Failed to get Local LLM server URL")
            raise ConfigurationError(
                "Local LLM server URL not configured. Please set 'service_urls.local_llm_server' in configuration.",
            ) from e
        self.gguf_manager: Any = None

    def initialize(self) -> bool:
        """Initialize GGUF backend and load model.

        Starts the local GGUF server if not already running and loads the specified
        model. Tests server connectivity before marking as initialized.

        Returns:
            True if GGUF server initialized and model loaded successfully, False otherwise

        """
        try:
            # Import the GGUF manager
            from .local_gguf_server import gguf_manager

            self.gguf_manager = gguf_manager

            # Check if server dependencies are available
            if not self.gguf_manager.server.can_run():
                logger.exception("GGUF server dependencies not available (need Flask and llama-cpp-python)")
                return False

            # Start server if not running
            if not self.gguf_manager.is_server_running():
                logger.info("Starting local GGUF server...")
                if not self.gguf_manager.start_server():
                    logger.exception("Failed to start GGUF server")
                    return False

            # Load model if specified and not already loaded
            if self.config.model_path and not self.gguf_manager.current_model:
                logger.info("Loading GGUF model: %s", self.config.model_path)

                # Extract model parameters from config
                model_params = {
                    "context_length": self.config.context_length,
                    "gpu_layers": getattr(self.config, "gpu_layers", 0),
                    "threads": getattr(self.config, "threads", None),
                    "batch_size": getattr(self.config, "batch_size", 512),
                    "temperature": self.config.temperature,
                }

                # Filter out custom params if they exist
                if hasattr(self.config, "custom_params") and self.config.custom_params:
                    model_params |= self.config.custom_params

                if not self.gguf_manager.server.load_model(self.config.model_path, **model_params):
                    logger.exception("Failed to load GGUF model")
                    return False

            # Test server connection
            try:
                import requests
            except ImportError:
                logger.exception("requests module required for GGUF backend")
                return False
            try:
                response = requests.get(f"{self.server_url}/health", timeout=5)
                if response.status_code == 200:
                    self.is_initialized = True
                    logger.info("Local GGUF backend initialized")
                    return True
                logger.exception("GGUF server not responding properly")
                return False
            except Exception:
                logger.exception("Failed to connect to GGUF server")
                return False

        except Exception:
            logger.exception("Failed to initialize GGUF backend")
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Chat with local GGUF model.

        Args:
            messages: List of chat messages to send
            tools: Optional list of tools for function calling

        Returns:
            LLMResponse with content, usage info, finish reason, and model name

        Raises:
            RuntimeError: If backend is not initialized or GGUF server returns error
            Exception: If API request fails or response parsing fails

        """
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        try:
            import requests
        except ImportError:
            self.logger.exception("Import error in llm_backends")
            return LLMResponse(
                content="GGUF backend requires 'requests' library",
                finish_reason="error",
            )

        openai_messages = [
            {
                "role": msg.role,
                "content": msg.content,
            }
            for msg in messages
        ]
        request_data = {
            "model": self.config.model_name,
            "messages": openai_messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "stream": False,
        }

        try:
            response = requests.post(
                f"{self.server_url}/v1/chat/completions",
                json=request_data,
                timeout=120,  # Longer timeout for local inference
            )
            response.raise_for_status()

            result = response.json()

            if "error" in result:
                raise RuntimeError(f"GGUF server error: {result['error']}")

            choice = result.get("choices", [{}])[0]
            message = choice.get("message", {})
            content = message.get("content", "")

            usage = result.get("usage", {})

            return LLMResponse(
                content=content,
                usage=usage,
                finish_reason=choice.get("finish_reason", "stop"),
                model=result.get("model", self.config.model_name),
            )

        except Exception:
            logger.exception("GGUF API error")
            raise

    def shutdown(self) -> None:
        """Shutdown GGUF backend.

        Calls parent shutdown to clear tools and reset state. Intentionally does not
        stop the server to allow other backend instances to continue using it.

        """
        super().shutdown()
        # Could stop the server here, but leave it running for other instances
        # self.gguf_manager.stop_server() if self.gguf_manager else None


class PyTorchLLMBackend(LLMBackend):
    """PyTorch model backend for loading .pth/.pt checkpoint files.

    Implements LLM backend using PyTorch for loading and running transformer models
    from checkpoint files. Supports device auto-detection, quantization, and GPU optimization.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize PyTorch backend with configuration.

        Args:
            config: LLMConfig object with model_path pointing to .pth/.pt checkpoint or directory

        """
        super().__init__(config)
        self.model: Any = None
        self.tokenizer: Any = None
        self.device: Any = None
        self.quantization_manager: Any = None

    def initialize(self) -> bool:
        """Initialize PyTorch model and tokenizer.

        Loads model architecture from directory config or model name, then loads checkpoint
        weights. Handles device selection (CPU/CUDA/GPU), quantization, and GPU optimization.
        Supports both pre-trained HuggingFace models and raw checkpoint files.

        Returns:
            True if model and tokenizer loaded successfully, False otherwise

        Raises:
            RuntimeError: If PyTorch is not installed
        """
        try:
            if not HAS_TORCH:
                raise RuntimeError("PyTorch is not installed")
            from transformers import AutoModelForCausalLM, AutoTokenizer

            from .quantization_manager import get_quantization_manager

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error("PyTorch model file not found: %s", self.config.model_path)
                return False

            # Get device from config or auto-detect
            device_str = self.config.custom_params.get("device", "auto") if self.config.custom_params else "auto"
            if device_str == "auto":
                if GPU_AUTOLOADER_AVAILABLE:
                    device_str = get_device()
                    gpu_info = get_gpu_info()
                    logger.info("Using %s device: %s", gpu_info.get("gpu_type", "unknown"), device_str)
                elif torch.cuda.is_available():
                    device_str = "cuda"
                    logger.info("Using CUDA device for PyTorch model")
                else:
                    device_str = "cpu"
                    logger.info("Using CPU for PyTorch model")
            else:
                logger.info("Using %s device for PyTorch model", device_str)

            self.device = torch.device(device_str)

            # Check for quantization settings
            quantization_type = self.config.custom_params.get("quantization", "none") if self.config.custom_params else "none"

            if quantization_type != "none":
                # Use quantization manager
                self.quantization_manager = get_quantization_manager()
                self.model = self.quantization_manager.load_quantized_model(
                    self.config.model_path,
                    quantization_type=quantization_type,
                    device=str(self.device),
                    trust_remote_code=True,
                )

                if self.model is None:
                    logger.error("Failed to load quantized model")
                    return False

                # Load tokenizer separately
                model_dir = os.path.dirname(self.config.model_path) if os.path.isfile(self.config.model_path) else self.config.model_path
                self.tokenizer = _load_tokenizer(model_dir, trust_remote_code=True)
            else:
                # Standard loading without quantization
                logger.info("Loading PyTorch model from: %s", self.config.model_path)

                # Try to load associated config.json for model architecture
                model_dir = os.path.dirname(self.config.model_path)
                config_path = os.path.join(model_dir, "config.json")

                if os.path.exists(config_path):
                    # Load from directory with config
                    self.model = AutoModelForCausalLM.from_pretrained(
                        model_dir,
                        torch_dtype=torch.float16 if self.device.type in {"cuda", "xpu"} else torch.float32,
                        device_map="auto" if self.device.type in {"cuda", "xpu"} else None,
                        trust_remote_code=True,
                    )
                    self.tokenizer = _load_tokenizer(model_dir, trust_remote_code=True)
                else:
                    # Load raw checkpoint - need model name for architecture
                    if not self.config.model_name:
                        logger.error("Model name required for loading raw PyTorch checkpoint")
                        return False

                    # Load tokenizer from model name
                    self.tokenizer = _load_tokenizer(self.config.model_name, trust_remote_code=True)

                    # Load model architecture and weights
                    self.model = AutoModelForCausalLM.from_pretrained(
                        self.config.model_name,
                        torch_dtype=torch.float16 if self.device.type in {"cuda", "xpu"} else torch.float32,
                        trust_remote_code=True,
                    )

                    # Load checkpoint weights
                    checkpoint = torch.load(self.config.model_path, map_location=self.device)
                    if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint:
                        self.model.load_state_dict(checkpoint["model_state_dict"])
                    else:
                        self.model.load_state_dict(checkpoint)

            # Move model to device
            if GPU_AUTOLOADER_AVAILABLE and to_device:
                self.model = to_device(self.model)
                if optimize_for_gpu:
                    self.model = optimize_for_gpu(self.model)
            else:
                self.model.to(self.device)
            self.model.eval()

            self.is_initialized = True
            logger.info("PyTorch backend initialized with model: %s", self.config.model_name or "custom")
            return True

        except ImportError:
            logger.exception("PyTorch or transformers not installed. Install with: pip install torch transformers")
            return False
        except Exception:
            logger.exception("Failed to initialize PyTorch backend")
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Generate response using PyTorch model.

        Args:
            messages: List of chat messages to send
            tools: Optional list of tools (limited tool support for PyTorch models)

        Returns:
            LLMResponse with generated content, finish reason, and model name

        Raises:
            RuntimeError: If backend is not initialized or PyTorch not available
            Exception: If generation fails

        """
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        # Log tool usage for PyTorch models (limited tool support)
        if tools:
            logger.warning("PyTorch backend has limited tool support. %d tools ignored.", len(tools))

        try:
            if not HAS_TORCH:
                raise RuntimeError("PyTorch is not installed")

            # Convert messages to prompt
            prompt = ""
            for msg in messages:
                if msg.role == "system":
                    prompt += f"System: {msg.content}\n\n"
                elif msg.role == "user":
                    prompt += f"User: {msg.content}\n\n"
                elif msg.role == "assistant":
                    prompt += f"Assistant: {msg.content}\n\n"

            prompt += "Assistant: "

            # Tokenize
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=self.config.context_length)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            # Generate
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    do_sample=self.config.temperature > 0,
                    pad_token_id=self.tokenizer.eos_token_id,
                )

            # Decode response
            response = self.tokenizer.decode(outputs[0][inputs["input_ids"].shape[-1] :], skip_special_tokens=True)

            return LLMResponse(
                content=response,
                finish_reason="stop",
                model=self.config.model_name or "pytorch_model",
            )

        except Exception:
            logger.exception("PyTorch generation error")
            raise

    def shutdown(self) -> None:
        """Shutdown PyTorch backend.

        Releases model and tokenizer objects and clears GPU cache if available.
        Calls parent shutdown to clear tools and reset initialization state.

        """
        super().shutdown()
        if self.model is not None:
            del self.model
            self.model = None
        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None

        # Clear GPU cache
        try:
            if HAS_TORCH and torch is not None and torch.cuda.is_available():
                torch.cuda.empty_cache()
        except Exception as e:
            logger.debug("Could not clear GPU cache: %s", e)


class TensorFlowLLMBackend(LLMBackend):
    """TensorFlow model backend for loading .h5 and SavedModel formats.

    Implements LLM backend using TensorFlow/Keras for loading and running models
    in SavedModel and HDF5 formats. Supports GPU acceleration and custom model architectures.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize TensorFlow backend with configuration.

        Args:
            config: LLMConfig object with model_path pointing to SavedModel directory or .h5 file

        """
        super().__init__(config)
        self.model: Any = None
        self.tokenizer: Any = None

    def initialize(self) -> bool:
        """Initialize TensorFlow model and tokenizer.

        Loads model from SavedModel directory or HDF5 file. Automatically detects
        available GPU devices and configures TensorFlow accordingly.

        Returns:
            True if model and tokenizer loaded successfully, False otherwise

        Raises:
            RuntimeError: If TensorFlow is not installed
        """
        try:
            if not HAS_TENSORFLOW:
                raise RuntimeError("TensorFlow is not installed")
            from transformers import AutoTokenizer, TFAutoModelForCausalLM

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error("TensorFlow model path not found: %s", self.config.model_path)
                return False

            if gpus := tf.config.list_physical_devices("GPU"):
                logger.info("Using GPU for TensorFlow model: %s", gpus[0])
            else:
                logger.info("Using CPU for TensorFlow model")

            # Load model
            logger.info("Loading TensorFlow model from: %s", self.config.model_path)

            if Path(self.config.model_path).is_dir():
                # SavedModel format
                if os.path.exists(os.path.join(self.config.model_path, "saved_model.pb")):
                    self.model = tf.keras.models.load_model(self.config.model_path)
                else:
                    # Try as transformers model directory
                    self.model = TFAutoModelForCausalLM.from_pretrained(self.config.model_path)
                    self.tokenizer = _load_tokenizer(self.config.model_path)
            # .h5 file
            elif self.config.model_path.endswith(".h5"):
                if not self.config.model_name:
                    logger.error("Model name required for loading .h5 files")
                    return False

                # Load base model and weights
                self.model = TFAutoModelForCausalLM.from_pretrained(self.config.model_name)
                self.model.load_weights(self.config.model_path)
                self.tokenizer = _load_tokenizer(self.config.model_name)

            if self.tokenizer is None and self.config.model_name:
                # Try to load tokenizer from model name
                self.tokenizer = _load_tokenizer(self.config.model_name)

            self.is_initialized = True
            logger.info("TensorFlow backend initialized")
            return True

        except ImportError:
            logger.exception("TensorFlow not installed. Install with: pip install tensorflow")
            return False
        except Exception:
            logger.exception("Failed to initialize TensorFlow backend")
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Generate response using TensorFlow model.

        Args:
            messages: List of chat messages to send
            tools: Optional list of tools (limited tool support for TensorFlow models)

        Returns:
            LLMResponse with generated content, finish reason, and model name

        Raises:
            RuntimeError: If backend is not initialized
            Exception: If generation fails

        """
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        # Log tool usage for TensorFlow models (limited tool support)
        if tools:
            logger.warning("TensorFlow backend has limited tool support. %d tools ignored.", len(tools))

        try:
            # Convert messages to prompt
            prompt = ""
            for msg in messages:
                if msg.role == "system":
                    prompt += f"System: {msg.content}\n\n"
                elif msg.role == "user":
                    prompt += f"User: {msg.content}\n\n"
                elif msg.role == "assistant":
                    prompt += f"Assistant: {msg.content}\n\n"

            prompt += "Assistant: "

            # Tokenize
            inputs = self.tokenizer(prompt, return_tensors="tf", truncation=True, max_length=self.config.context_length)

            # Generate
            outputs = self.model.generate(
                inputs.input_ids,
                max_new_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                do_sample=self.config.temperature > 0,
                pad_token_id=self.tokenizer.eos_token_id,
            )

            # Decode response
            response = self.tokenizer.decode(outputs[0][len(inputs.input_ids[0]) :], skip_special_tokens=True)

            return LLMResponse(
                content=response,
                finish_reason="stop",
                model=self.config.model_name or "tensorflow_model",
            )

        except Exception:
            logger.exception("TensorFlow generation error")
            raise

    def shutdown(self) -> None:
        """Shutdown TensorFlow backend.

        Releases model and tokenizer objects and clears TensorFlow session.
        Calls parent shutdown to clear tools and reset initialization state.

        Raises:
            RuntimeError: If TensorFlow is not installed

        """
        super().shutdown()
        if self.model is not None:
            del self.model
            self.model = None
        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None

        # Clear TensorFlow session
        try:
            if not HAS_TENSORFLOW:
                raise RuntimeError("TensorFlow is not installed")
            if tf is not None and hasattr(tf, "keras"):
                # pylint: disable=no-member
                tf.keras.backend.clear_session()
        except Exception as e:
            logger.debug("Could not clear TensorFlow session: %s", e)


class ONNXLLMBackend(LLMBackend):
    """ONNX model backend for loading .onnx files.

    Implements LLM backend using ONNX Runtime for efficient inference of models
    exported to ONNX format. Supports CPU and GPU execution providers.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize ONNX backend with configuration.

        Args:
            config: LLMConfig object with model_path pointing to .onnx model file

        """
        super().__init__(config)
        self.session: Any = None
        self.tokenizer: Any = None

    def initialize(self) -> bool:
        """Initialize ONNX Runtime inference session.

        Creates an ONNX Runtime session with CPU and GPU execution providers.
        Loads tokenizer from model name or model directory.

        Returns:
            True if ONNX session created and tokenizer loaded successfully, False otherwise

        """
        try:
            import onnxruntime as ort
            from transformers import AutoTokenizer

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error("ONNX model file not found: %s", self.config.model_path)
                return False

            # Create inference session
            providers = ["CUDAExecutionProvider", "CPUExecutionProvider"]
            self.session = ort.InferenceSession(self.config.model_path, providers=providers)

            # Log which provider is being used
            actual_provider = self.session.get_providers()[0]
            logger.info("Using %s for ONNX inference", actual_provider)

            # Load tokenizer
            if self.config.model_name:
                self.tokenizer = _load_tokenizer(self.config.model_name)
            else:
                # Try to load from same directory
                model_dir = os.path.dirname(self.config.model_path)
                tokenizer_files = ["tokenizer.json", "tokenizer_config.json"]
                if any(os.path.exists(os.path.join(model_dir, f)) for f in tokenizer_files):
                    self.tokenizer = _load_tokenizer(model_dir)
                else:
                    logger.error("Tokenizer not found. Specify model_name for tokenizer loading")
                    return False

            self.is_initialized = True
            logger.info("ONNX backend initialized")
            return True

        except ImportError:
            logger.exception("ONNX Runtime not installed. Install with: pip install onnxruntime")
            return False
        except Exception:
            logger.exception("Failed to initialize ONNX backend")
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Generate response using ONNX model.

        Args:
            messages: List of chat messages to send
            tools: Optional list of tools (limited tool support for ONNX models)

        Returns:
            LLMResponse with generated content, finish reason, and model name

        Raises:
            RuntimeError: If backend is not initialized or NumPy not available
            Exception: If generation fails

        """
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        # Log tool usage for ONNX models (limited tool support)
        if tools:
            logger.warning("ONNX backend has limited tool support. %d tools ignored.", len(tools))

        try:
            if not HAS_NUMPY:
                raise RuntimeError("NumPy is not installed")

            # Convert messages to prompt
            prompt = ""
            for msg in messages:
                if msg.role == "system":
                    prompt += f"System: {msg.content}\n\n"
                elif msg.role == "user":
                    prompt += f"User: {msg.content}\n\n"
                elif msg.role == "assistant":
                    prompt += f"Assistant: {msg.content}\n\n"

            prompt += "Assistant: "

            # Tokenize
            inputs = self.tokenizer(prompt, return_tensors="np", truncation=True, max_length=self.config.context_length)

            # Get input names from session
            input_names = [inp.name for inp in self.session.get_inputs()]
            output_names = [out.name for out in self.session.get_outputs()]

            # Prepare inputs
            ort_inputs = {}
            for name in input_names:
                if name == "input_ids":
                    ort_inputs[name] = inputs["input_ids"]
                elif name == "attention_mask":
                    ort_inputs[name] = inputs.get("attention_mask", np.ones_like(inputs["input_ids"]))

            # Iterative generation loop for proper text generation
            input_ids = inputs["input_ids"].copy()
            attention_mask = inputs.get("attention_mask", np.ones_like(input_ids))

            max_new_tokens = min(self.config.max_tokens, 512)  # Reasonable limit
            generated_tokens = []

            for _ in range(max_new_tokens):
                # Prepare current inputs
                current_ort_inputs = {}
                for name in input_names:
                    if name == "input_ids":
                        current_ort_inputs[name] = input_ids
                    elif name == "attention_mask":
                        current_ort_inputs[name] = attention_mask
                    elif name == "position_ids":
                        # Some models need position_ids
                        current_ort_inputs[name] = np.arange(input_ids.shape[-1])[None, :]

                # Run inference to get logits for next token
                outputs = self.session.run(output_names, current_ort_inputs)
                logits = outputs[0]  # Shape: (batch_size, seq_len, vocab_size)

                # Get logits for the last position (next token prediction)
                next_token_logits = logits[0, -1, :]  # Shape: (vocab_size,)

                # Apply temperature sampling if temperature > 0
                if self.config.temperature > 0:
                    # Apply temperature scaling
                    next_token_logits /= self.config.temperature

                    # Convert to probabilities
                    exp_logits = np.exp(next_token_logits - np.max(next_token_logits))
                    probabilities = exp_logits / np.sum(exp_logits)

                    # Sample from probability distribution
                    next_token_id = np.random.choice(len(probabilities), p=probabilities)
                else:
                    # Greedy decoding
                    next_token_id = np.argmax(next_token_logits)

                # Check for EOS token
                if next_token_id == self.tokenizer.eos_token_id:
                    break

                # Add generated token to sequence
                generated_tokens.append(next_token_id)

                # Update input_ids and attention_mask for next iteration
                next_token_array = np.array([[next_token_id]], dtype=input_ids.dtype)
                input_ids = np.concatenate([input_ids, next_token_array], axis=-1)
                attention_mask = np.concatenate([attention_mask, np.ones((1, 1), dtype=attention_mask.dtype)], axis=-1)

                # Check sequence length limits
                if input_ids.shape[-1] >= self.config.context_length:
                    break

            # Decode only the generated tokens
            if generated_tokens:
                response = self.tokenizer.decode(generated_tokens, skip_special_tokens=True)
            else:
                response = ""  # No tokens generated

            return LLMResponse(
                content=response,
                finish_reason="stop",
                model=self.config.model_name or "onnx_model",
            )

        except Exception:
            logger.exception("ONNX generation error")
            raise

    def shutdown(self) -> None:
        """Shutdown ONNX backend.

        Releases ONNX Runtime session and tokenizer. Calls parent shutdown
        to clear tools and reset initialization state.

        """
        super().shutdown()
        if self.session is not None:
            del self.session
            self.session = None
        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None


class SafetensorsBackend(LLMBackend):
    """Safetensors model backend for loading .safetensors files.

    Implements LLM backend using Safetensors format for secure and efficient
    model loading. Supports single-file and directory-based model structures.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize Safetensors backend with configuration.

        Args:
            config: LLMConfig object with model_path pointing to safetensors file or directory

        """
        super().__init__(config)
        self.model: Any = None
        self.tokenizer: Any = None
        self.device: Any = None

    def initialize(self) -> bool:
        """Initialize Safetensors model and tokenizer.

        Loads model from safetensors file or directory. Handles device selection,
        GPU optimization, and model architecture from config or model name.

        Returns:
            True if model and tokenizer loaded successfully, False otherwise

        Raises:
            RuntimeError: If PyTorch is not installed
        """
        try:
            if not HAS_TORCH:
                raise RuntimeError("PyTorch is not installed")
            from safetensors.torch import load_file
            from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error("Safetensors model file not found: %s", self.config.model_path)
                return False

            # Detect device
            if GPU_AUTOLOADER_AVAILABLE:
                device_str = get_device()
                gpu_info = get_gpu_info()
                self.device = torch.device(device_str)
                logger.info("Using %s device for Safetensors model: %s", gpu_info.get("gpu_type", "unknown"), device_str)
            elif torch.cuda.is_available():
                self.device = torch.device("cuda")
                logger.info("Using CUDA device for Safetensors model")
            else:
                self.device = torch.device("cpu")
                logger.info("Using CPU for Safetensors model")

            # Load model
            logger.info("Loading Safetensors model from: %s", self.config.model_path)

            # Check if this is a single file or directory
            if os.path.isfile(self.config.model_path):
                # Single safetensors file - need config
                model_dir = os.path.dirname(self.config.model_path)
                config_path = os.path.join(model_dir, "config.json")

                if os.path.exists(config_path):
                    config = AutoConfig.from_pretrained(model_dir)
                    self.model = _load_model_from_config(AutoModelForCausalLM, config)

                    # Load weights from safetensors
                    state_dict = load_file(self.config.model_path)
                    self.model.load_state_dict(state_dict)

                    # Load tokenizer
                    self.tokenizer = _load_tokenizer(model_dir)
                else:
                    # Need model name for architecture
                    if not self.config.model_name:
                        logger.error("Model name required for loading single safetensors file")
                        return False

                    # Initialize model from name
                    self.model = AutoModelForCausalLM.from_pretrained(
                        self.config.model_name,
                        torch_dtype=torch.float16 if self.device.type == "cuda" else torch.float32,
                    )

                    # Load weights
                    state_dict = load_file(self.config.model_path)
                    self.model.load_state_dict(state_dict)

                    # Load tokenizer
                    self.tokenizer = _load_tokenizer(self.config.model_name)
            else:
                # Directory with safetensors files
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.config.model_path,
                    torch_dtype=torch.float16 if self.device.type == "cuda" else torch.float32,
                    device_map="auto" if self.device.type in {"cuda", "xpu"} else None,
                )
                self.tokenizer = _load_tokenizer(self.config.model_path)

            # Move model to device
            if GPU_AUTOLOADER_AVAILABLE and to_device:
                self.model = to_device(self.model)
                if optimize_for_gpu:
                    self.model = optimize_for_gpu(self.model)
            else:
                self.model.to(self.device)
            self.model.eval()

            self.is_initialized = True
            logger.info("Safetensors backend initialized")
            return True

        except ImportError:
            logger.exception("safetensors not installed. Install with: pip install safetensors")
            return False
        except Exception:
            logger.exception("Failed to initialize Safetensors backend")
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Generate response using Safetensors model.

        Args:
            messages: List of chat messages to send
            tools: Optional list of tools (limited tool support for Safetensors models)

        Returns:
            LLMResponse with generated content, finish reason, and model name

        Raises:
            RuntimeError: If backend is not initialized or PyTorch not available
            Exception: If generation fails

        """
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        # Log tool usage for SafeTensors models (limited tool support)
        if tools:
            logger.warning("SafeTensors backend has limited tool support. %d tools ignored.", len(tools))

        try:
            if not HAS_TORCH:
                raise RuntimeError("PyTorch is not installed")

            # Convert messages to prompt
            prompt = ""
            for msg in messages:
                if msg.role == "system":
                    prompt += f"System: {msg.content}\n\n"
                elif msg.role == "user":
                    prompt += f"User: {msg.content}\n\n"
                elif msg.role == "assistant":
                    prompt += f"Assistant: {msg.content}\n\n"

            prompt += "Assistant: "

            # Tokenize
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=self.config.context_length)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            # Generate
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    do_sample=self.config.temperature > 0,
                    pad_token_id=self.tokenizer.eos_token_id,
                )

            # Decode response
            response = self.tokenizer.decode(outputs[0][inputs["input_ids"].shape[-1] :], skip_special_tokens=True)

            return LLMResponse(
                content=response,
                finish_reason="stop",
                model=self.config.model_name or "safetensors_model",
            )

        except Exception:
            logger.exception("Safetensors generation error")
            raise

    def shutdown(self) -> None:
        """Shutdown Safetensors backend.

        Releases model and tokenizer objects and clears GPU cache if available.
        Calls parent shutdown to clear tools and reset initialization state.

        """
        super().shutdown()
        if self.model is not None:
            del self.model
            self.model = None
        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None

        # Clear GPU cache
        try:
            if HAS_TORCH and torch is not None and torch.cuda.is_available():
                torch.cuda.empty_cache()
        except Exception as e:
            logger.debug("Could not clear GPU cache: %s", e)


class GPTQBackend(LLMBackend):
    """GPTQ quantized model backend.

    Implements LLM backend using GPTQ-quantized models loaded with auto-gptq.
    Provides efficient inference on GPUs with support for various quantization levels.
    Requires GPU availability for proper operation.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize GPTQ backend with configuration.

        Args:
            config: LLMConfig object with model_path pointing to GPTQ model directory

        """
        super().__init__(config)
        self.model: Any = None
        self.tokenizer: Any = None
        self.device: Any = None

    def initialize(self) -> bool:
        """Initialize GPTQ model.

        Loads GPTQ-quantized model from directory using auto-gptq library.
        Requires GPU availability for operation. Uses Triton optimizations if available.

        Returns:
            True if GPTQ model loaded successfully, False otherwise

        Raises:
            RuntimeError: If PyTorch is not installed
        """
        try:
            if not HAS_TORCH:
                raise RuntimeError("PyTorch is not installed")
            from auto_gptq import AutoGPTQForCausalLM
            from transformers import AutoTokenizer

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error("GPTQ model path not found: %s", self.config.model_path)
                return False

            # GPTQ requires GPU
            if GPU_AUTOLOADER_AVAILABLE:
                device_str = get_device()
                gpu_info = get_gpu_info()
                if not gpu_info["available"] or device_str == "cpu":
                    logger.error("GPTQ models require GPU")
                    return False
                self.device = torch.device(device_str)
                logger.info("Using %s device for GPTQ model: %s", gpu_info.get("gpu_type", "unknown"), device_str)
            elif torch.cuda.is_available():
                self.device = torch.device("cuda")
                logger.info("Using CUDA device for GPTQ model")
            else:
                logger.error("GPTQ models require GPU")
                return False

            # Load model
            logger.info("Loading GPTQ model from: %s", self.config.model_path)

            # GPTQ models are typically in directories
            if Path(self.config.model_path).is_dir():
                self.model = AutoGPTQForCausalLM.from_quantized(
                    self.config.model_path,
                    use_safetensors=True,
                    device=str(self.device),
                    use_triton=False,
                    quantize_config=None,
                )
                self.tokenizer = _load_tokenizer(self.config.model_path)
            else:
                logger.error("GPTQ models should be in a directory with config files")
                return False

            self.is_initialized = True
            logger.info("GPTQ backend initialized")
            return True

        except ImportError:
            logger.exception("auto-gptq not installed. Install with: pip install auto-gptq")
            return False
        except Exception:
            logger.exception("Failed to initialize GPTQ backend")
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Generate response using GPTQ model.

        Args:
            messages: List of chat messages to send
            tools: Optional list of tools (limited tool support for GPTQ models)

        Returns:
            LLMResponse with generated content, finish reason, and model name

        Raises:
            RuntimeError: If backend is not initialized
            Exception: If generation fails

        """
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        # Log tool usage for GPTQ models (limited tool support)
        if tools:
            logger.warning("GPTQ backend has limited tool support. %d tools ignored.", len(tools))

        try:
            # Convert messages to prompt
            prompt = ""
            for msg in messages:
                if msg.role == "system":
                    prompt += f"System: {msg.content}\n\n"
                elif msg.role == "user":
                    prompt += f"User: {msg.content}\n\n"
                elif msg.role == "assistant":
                    prompt += f"Assistant: {msg.content}\n\n"

            prompt += "Assistant: "

            # Tokenize
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=self.config.context_length)
            inputs = inputs.to(self.device)

            # Generate
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                do_sample=self.config.temperature > 0,
            )

            # Decode response
            response = self.tokenizer.decode(outputs[0][inputs.input_ids.shape[-1] :], skip_special_tokens=True)

            return LLMResponse(
                content=response,
                finish_reason="stop",
                model=self.config.model_name or "gptq_model",
            )

        except Exception:
            logger.exception("GPTQ generation error")
            raise

    def shutdown(self) -> None:
        """Shutdown GPTQ backend.

        Releases model and tokenizer objects and clears GPU cache.
        Calls parent shutdown to clear tools and reset initialization state.

        """
        super().shutdown()
        if self.model is not None:
            del self.model
            self.model = None
        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None

        # Clear GPU cache
        try:
            if HAS_TORCH and torch is not None and torch.cuda.is_available():
                torch.cuda.empty_cache()
        except Exception as e:
            logger.debug("Could not clear GPU cache: %s", e)


class HuggingFaceLocalBackend(LLMBackend):
    """Hugging Face local model backend for loading from directories.

    Implements LLM backend using transformers library for loading HuggingFace models
    from local directories. Supports large models with accelerate library features
    like device_map and checkpoint sharding.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize Hugging Face Local backend with configuration.

        Args:
            config: LLMConfig object with model_path pointing to model directory

        """
        super().__init__(config)
        self.model: Any = None
        self.tokenizer: Any = None
        self.device: Any = None
        self.quantization_manager: Any = None

    def initialize(self) -> bool:
        """Initialize Hugging Face model from local directory.

        Loads model and config from local directory. Supports device mapping for
        large models and automatic checkpoint sharding with accelerate library.

        Returns:
            True if model and tokenizer loaded successfully, False otherwise

        Raises:
            RuntimeError: If PyTorch is not installed
        """
        try:
            if not HAS_TORCH:
                raise RuntimeError("PyTorch is not installed")
            from accelerate import init_empty_weights, load_checkpoint_and_dispatch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error("Hugging Face model directory not found: %s", self.config.model_path)
                return False

            if not Path(self.config.model_path).is_dir():
                logger.error("Hugging Face models should be in a directory")
                return False

            # Check for config.json
            config_path = os.path.join(self.config.model_path, "config.json")
            if not os.path.exists(config_path):
                logger.error("config.json not found in model directory")
                return False

            # Detect device
            if GPU_AUTOLOADER_AVAILABLE:
                device_str = get_device()
                gpu_info = get_gpu_info()
                self.device = torch.device(device_str)
                logger.info("Using %s device for Hugging Face model: %s", gpu_info.get("gpu_type", "unknown"), device_str)
            elif torch.cuda.is_available():
                self.device = torch.device("cuda")
                logger.info("Using CUDA device for Hugging Face model")
            else:
                self.device = torch.device("cpu")
                logger.info("Using CPU for Hugging Face model")

            # Load model
            logger.info("Loading Hugging Face model from: %s", self.config.model_path)

            # Check model size and available memory
            model_size = sum(
                os.path.getsize(os.path.join(self.config.model_path, f))
                for f in os.listdir(self.config.model_path)
                if f.endswith((".bin", ".safetensors"))
            )

            logger.info("Model size: %.2f GB", model_size / 1e9)

            # Load with appropriate strategy
            gpu_available = (GPU_AUTOLOADER_AVAILABLE and get_gpu_info()["available"]) or torch.cuda.is_available()
            if model_size > 10e9 and gpu_available:
                # Large model - use device_map
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.config.model_path,
                    torch_dtype=torch.float16,
                    device_map="auto",
                    trust_remote_code=True,
                    low_cpu_mem_usage=True,
                )
            else:
                # Smaller model or CPU only
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.config.model_path,
                    torch_dtype=torch.float16 if self.device.type in {"cuda", "xpu"} else torch.float32,
                    trust_remote_code=True,
                    low_cpu_mem_usage=True,
                )
                # Move model to device
                if GPU_AUTOLOADER_AVAILABLE and to_device:
                    self.model = to_device(self.model)
                    if optimize_for_gpu:
                        self.model = optimize_for_gpu(self.model)
                else:
                    self.model.to(self.device)

            # Load tokenizer
            self.tokenizer = _load_tokenizer(self.config.model_path, trust_remote_code=True)

            # Set pad token if not set
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            # Use init_empty_weights and load_checkpoint_and_dispatch for very large models
            if model_size > 30e9 and gpu_available:
                logger.info("Using accelerate load_checkpoint_and_dispatch for very large model")
                with init_empty_weights():
                    from transformers import AutoConfig

                    config = AutoConfig.from_pretrained(self.config.model_path)
                    empty_model = _load_model_from_config(AutoModelForCausalLM, config)

                # Load model with checkpoint sharding
                self.model = load_checkpoint_and_dispatch(
                    empty_model,
                    self.config.model_path,
                    device_map="auto",
                    no_split_module_classes=["LlamaDecoderLayer", "MistralDecoderLayer"],
                    dtype=torch.float16,
                    offload_folder="offload",
                    offload_state_dict=True,
                )
                logger.info("Loaded very large model using checkpoint dispatch")

            self.model.eval()

            self.is_initialized = True
            logger.info("Hugging Face backend initialized")
            return True

        except ImportError:
            logger.exception("Required libraries not installed. Install with: pip install transformers accelerate")
            return False
        except Exception:
            logger.exception("Failed to initialize Hugging Face backend")
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Generate response using Hugging Face model.

        Args:
            messages: List of chat messages to send
            tools: Optional list of tools (limited tool support for HuggingFace models)

        Returns:
            LLMResponse with generated content, finish reason, and model name

        Raises:
            RuntimeError: If backend is not initialized or PyTorch not available
            Exception: If generation fails

        """
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        # Log tool usage for Hugging Face models (limited tool support)
        if tools:
            logger.warning("Hugging Face backend has limited tool support. %d tools ignored.", len(tools))

        try:
            if not HAS_TORCH:
                raise RuntimeError("PyTorch is not installed")

            # Check if model has chat template
            if hasattr(self.tokenizer, "apply_chat_template"):
                chat_messages = [{"role": msg.role, "content": msg.content} for msg in messages]
                prompt = self.tokenizer.apply_chat_template(
                    chat_messages,
                    tokenize=False,
                    add_generation_prompt=True,
                )
            else:
                # Fallback to simple format
                prompt = ""
                for msg in messages:
                    if msg.role == "assistant":
                        prompt += f"Assistant: {msg.content}\n\n"

                    elif msg.role == "system":
                        prompt += f"System: {msg.content}\n\n"
                    elif msg.role == "user":
                        prompt += f"User: {msg.content}\n\n"
                prompt += "Assistant: "

            # Tokenize
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=self.config.context_length)
            inputs = {k: v.to(self.model.device) for k, v in inputs.items()}

            # Generate
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    do_sample=self.config.temperature > 0,
                    pad_token_id=self.tokenizer.pad_token_id,
                    eos_token_id=self.tokenizer.eos_token_id,
                )

            # Decode response
            response = self.tokenizer.decode(outputs[0][inputs["input_ids"].shape[-1] :], skip_special_tokens=True)

            model_name = self.config.model_name
            if not model_name and self.config.model_path:
                model_name = os.path.basename(self.config.model_path)
            return LLMResponse(
                content=response,
                finish_reason="stop",
                model=model_name,
            )

        except Exception:
            logger.exception("Hugging Face generation error")
            raise

    def shutdown(self) -> None:
        """Shutdown Hugging Face backend.

        Releases model and tokenizer objects and clears GPU cache if available.
        Calls parent shutdown to clear tools and reset initialization state.

        """
        super().shutdown()
        if self.model is not None:
            del self.model
            self.model = None
        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None

        # Clear GPU cache
        try:
            if HAS_TORCH and torch is not None and torch.cuda.is_available():
                torch.cuda.empty_cache()
        except Exception as e:
            logger.debug("Could not clear GPU cache: %s", e)


class LLMManager:
    """Manager for LLM backends and configurations with lazy and background loading.

    Implements a singleton pattern to manage multiple LLM backend instances.
    Supports lazy loading (on-demand initialization) and background loading (asynchronous
    model loading) for efficient resource management during AI-assisted binary analysis.
    """

    _instance: "LLMManager | None" = None
    _lock = threading.Lock()
    _initialized: bool = False

    def __new__(cls, enable_lazy_loading: bool = True, enable_background_loading: bool = True) -> "LLMManager":
        """Create or retrieve singleton LLM manager instance.

        Implements singleton pattern with thread-safe instantiation. Validates that
        boolean parameters are actual booleans, not truthy values.

        Args:
            enable_lazy_loading: Enable lazy loading of models on first use
            enable_background_loading: Enable background model loading in separate threads

        Returns:
            Singleton LLMManager instance

        Raises:
            TypeError: If enable_lazy_loading or enable_background_loading are not boolean
        """
        if not isinstance(enable_lazy_loading, bool):
            raise TypeError("enable_lazy_loading must be a boolean")
        if not isinstance(enable_background_loading, bool):
            raise TypeError("enable_background_loading must be a boolean")
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, enable_lazy_loading: bool = True, enable_background_loading: bool = True) -> None:
        """Initialize LLM Manager with lazy and background loading options.

        Sets up internal state for managing LLM backends. Only runs once due to
        singleton pattern. Initializes lazy loading and background loading managers
        if enabled.

        Args:
            enable_lazy_loading: Whether to enable lazy loading of models on first access
            enable_background_loading: Whether to enable asynchronous background model loading

        """
        if self._initialized:
            return

        self.backends: dict[str, LLMBackend] = {}
        self.configs: dict[str, LLMConfig] = {}
        self.active_backend: str | None = None
        self.lock = threading.RLock()
        self.enable_lazy_loading = enable_lazy_loading
        self.enable_background_loading = enable_background_loading

        self.lazy_manager: Any = None
        self.lazy_wrappers: dict[str, Any] = {}
        self.background_loader: Any = None

        if enable_lazy_loading:
            try:
                from .lazy_model_loader import get_lazy_manager

                self.lazy_manager = get_lazy_manager()
                logger.info("LLM Manager initialized with lazy loading support")
            except ImportError as e:
                logger.warning("Lazy loading not available: %s", e)
                self.enable_lazy_loading = False

        if enable_background_loading:
            self.background_loader = get_background_loader(self)
            logger.info("LLM Manager initialized with background loading support")

        self.loading_tasks: dict[str, LoadingTask] = {}
        self.progress_callbacks: list[ProgressCallback] = []
        self._initialized = True
        logger.info("LLM Manager initialized")

    def register_llm(self, llm_id: str, config: LLMConfig, use_lazy_loading: bool | None = None) -> bool:
        """Register an LLM configuration with optional lazy loading.

        Initializes an LLM backend and registers it with a unique identifier.
        If lazy loading is enabled, the backend will be loaded on first use.
        Sets the registered LLM as active if it's the first one registered.

        Args:
            llm_id: Unique identifier for this LLM backend
            config: LLMConfig object with model settings and provider info
            use_lazy_loading: Override manager's lazy loading setting (None = use default)

        Returns:
            True if LLM registered and initialized successfully, False otherwise

        Raises:
            ValueError: If unsupported LLM provider specified in config
        """
        with self.lock:
            try:
                # Determine if we should use lazy loading
                use_lazy = use_lazy_loading if use_lazy_loading is not None else self.enable_lazy_loading

                if use_lazy and self.lazy_manager:
                    # Register with lazy loading
                    backend_class = LLMManager._get_backend_class(config.provider)
                    if backend_class is None:
                        raise ValueError(f"Unsupported LLM provider: {config.provider}")

                    wrapper = self.lazy_manager.register_model(llm_id, backend_class, config)
                    self.lazy_wrappers[llm_id] = wrapper
                    self.configs[llm_id] = config

                    # Set as active if first one
                    if not self.active_backend:
                        self.active_backend = llm_id

                    logger.info("Registered lazy LLM: %s (%s)", llm_id, config.provider.value)
                    return True
                # Standard immediate loading
                backend_class = LLMManager._get_backend_class(config.provider)
                if backend_class is None:
                    raise ValueError(f"Unsupported LLM provider: {config.provider}")

                backend = backend_class(config)

                # Initialize backend
                if not backend.initialize():
                    logger.error("Failed to initialize LLM backend: %s", llm_id)
                    return False

                self.backends[llm_id] = backend
                self.configs[llm_id] = config

                # Set as active if first one
                if not self.active_backend:
                    self.active_backend = llm_id

                logger.info("Registered LLM: %s (%s)", llm_id, config.provider.value)
                return True

            except (OSError, ValueError, RuntimeError):
                logger.exception("Failed to register LLM %s", llm_id)
                return False

    @staticmethod
    def _get_backend_class(provider: LLMProvider) -> type | None:
        """Get the backend class for a given LLM provider.

        Maps LLMProvider enum values to their corresponding backend implementation classes.
        Returns None if the provider is not supported.

        Args:
            provider: LLMProvider enum value specifying which backend to use

        Returns:
            Backend class type for the provider, or None if provider not supported

        """
        backend_classes = {
            LLMProvider.OPENAI: OpenAIBackend,
            LLMProvider.ANTHROPIC: AnthropicBackend,
            LLMProvider.GOOGLE: GoogleBackend,
            LLMProvider.LLAMACPP: LlamaCppBackend,
            LLMProvider.OLLAMA: OllamaBackend,
            LLMProvider.LOCAL_GGUF: LocalGGUFBackend,
            LLMProvider.PYTORCH: PyTorchLLMBackend,
            LLMProvider.TENSORFLOW: TensorFlowLLMBackend,
            LLMProvider.ONNX: ONNXLLMBackend,
            LLMProvider.SAFETENSORS: SafetensorsBackend,
            LLMProvider.GPTQ: GPTQBackend,
            LLMProvider.HUGGINGFACE_LOCAL: HuggingFaceLocalBackend,
        }
        return backend_classes.get(provider)

    def set_active_llm(self, llm_id: str) -> bool:
        """Set the active LLM for inference.

        Changes which registered LLM backend will be used for chat() calls when
        no specific llm_id is provided. Must be a previously registered backend.

        Args:
            llm_id: Identifier of registered LLM to make active

        Returns:
            True if LLM set successfully, False if llm_id not registered

        """
        with self.lock:
            if llm_id not in self.backends:
                logger.error("LLM not registered: %s", llm_id)
                return False

            self.active_backend = llm_id
            logger.info("Set active LLM: %s", llm_id)
            return True

    def chat(self, messages: list[LLMMessage], llm_id: str | None = None, tools: list[dict[str, Any]] | None = None) -> LLMResponse | None:
        """Send chat messages to an LLM backend.

        Sends a list of messages to the specified or active LLM backend and
        returns the model's response. Automatically adds system prompt if configured
        and not already present in messages.

        Args:
            messages: List of LLMMessage objects to send to the model
            llm_id: Optional ID of specific LLM to use (uses active LLM if None)
            tools: Optional list of tool/function definitions for function calling

        Returns:
            LLMResponse with generated content and metadata, or None on error

        """
        with self.lock:
            backend_id = llm_id or self.active_backend

            if not backend_id:
                logger.error("No active LLM backend available")
                return None

            backend: LLMBackend | None = None
            if backend_id in self.lazy_wrappers:
                if self.lazy_manager:
                    loaded_backend = self.lazy_manager.get_model(backend_id)
                    if loaded_backend is None:
                        logger.error("Failed to load lazy LLM backend: %s", backend_id)
                        return None
                    backend = loaded_backend
            elif backend_id in self.backends:
                backend = self.backends[backend_id]
            else:
                logger.error("LLM backend not found: %s", backend_id)
                return None

            if backend is None:
                logger.error("Backend is None after lookup: %s", backend_id)
                return None

            if backend.config.system_prompt and all(m.role != "system" for m in messages):
                messages.insert(0, LLMMessage(role="system", content=backend.config.system_prompt))

            try:
                response = backend.chat(messages, tools)
                logger.debug("LLM response from %s: %d chars", backend_id, len(response.content))
                return response

            except (OSError, ValueError, RuntimeError):
                logger.exception("LLM chat error")
                return None

    def get_available_llms(self) -> list[str]:
        """Get list of available LLM backend IDs.

        Returns all registered LLM identifiers, including both immediately-loaded
        and lazy-loaded backends.

        Returns:
            List of all registered LLM backend identifiers

        """
        # Combine both immediate and lazy-loaded backends
        immediate_llms = set(self.backends.keys())
        lazy_llms = set(self.lazy_wrappers.keys())
        return list(immediate_llms.union(lazy_llms))

    def get_llm_info(self, llm_id: str) -> dict[str, Any] | None:
        """Get information about a registered LLM backend.

        Returns detailed information about an LLM including provider, model name,
        initialization status, tool support, and lazy loading status.

        Args:
            llm_id: Identifier of the LLM to get information for

        Returns:
            Dictionary with LLM metadata (id, provider, model_name, is_initialized, etc.),
            or None if llm_id not registered

        """
        if llm_id not in self.configs:
            return None

        config = self.configs[llm_id]

        # Check if it's a lazy-loaded model
        if llm_id in self.lazy_wrappers:
            wrapper = self.lazy_wrappers[llm_id]
            wrapper_info = wrapper.get_info()
            return {
                "id": llm_id,
                "provider": config.provider.value,
                "model_name": config.model_name,
                "is_initialized": wrapper_info["is_loaded"],
                "is_loading": wrapper_info["is_loading"],
                "has_error": wrapper_info["has_error"],
                "tools_enabled": config.tools_enabled,
                "context_length": config.context_length,
                "lazy_loaded": True,
                "access_count": wrapper_info["access_count"],
                "memory_usage": wrapper_info["memory_usage"],
            }
        # Standard backend
        backend = self.backends.get(llm_id)
        return {
            "id": llm_id,
            "provider": config.provider.value,
            "model_name": config.model_name,
            "is_initialized": backend.is_initialized if backend else False,
            "tools_enabled": config.tools_enabled,
            "context_length": config.context_length,
            "lazy_loaded": False,
        }

    def register_tools_for_llm(self, llm_id: str, tools: list[dict[str, Any]]) -> None:
        """Register tools/functions for a specific LLM backend.

        Provides function calling capabilities to an LLM backend. Tools must be
        in OpenAI function schema format with name, description, and parameters.

        Args:
            llm_id: Identifier of the LLM backend to register tools for
            tools: List of tool/function definitions in OpenAI schema format

        """
        if llm_id in self.backends:
            self.backends[llm_id].register_tools(tools)
            logger.info("Registered %d tools for LLM: %s", len(tools), llm_id)

    def generate_script_content(
        self,
        prompt: str,
        script_type: str,
        context_data: dict[str, Any] | None = None,
        max_tokens: int = 4000,
        llm_id: str | None = None,
    ) -> str | None:
        """Generate script content using an LLM for bypass or analysis tasks.

        Uses an LLM to generate complete, production-ready scripts for binary analysis,
        protection bypass, or reverse engineering tasks. Includes context about binary
        analysis data if provided. Enforces requirement for fully functional code.

        Args:
            prompt: User prompt describing desired script functionality
            script_type: Programming language (e.g., 'python', 'javascript', 'frida')
            context_data: Optional dictionary with binary analysis context (entropy, functions, etc.)
            max_tokens: Maximum tokens to generate (default 4000)
            llm_id: Identifier of specific LLM to use (uses active backend if None)

        Returns:
            Generated script content as string, or None if generation failed

        """
        with self.lock:
            backend_id = llm_id or self.active_backend

            if not backend_id or backend_id not in self.backends:
                logger.error("No active LLM backend available for script generation")
                return None

            # Prepare system prompt for script generation
            system_prompt = f"""You are an expert {script_type} script developer for binary reverse engineering and protection bypass.

CRITICAL REQUIREMENTS:
- Generate ONLY real, functional {script_type} code
- NO incomplete or partially implemented sections
- Every function must be completely implemented
- All API calls must be correct and properly formatted
- Scripts must be production-ready and immediately executable

Your task: Generate a complete {script_type} script based on the user's requirements.
Return ONLY the script code, no explanations or markdown formatting."""

            # Add context if provided
            if context_data:
                context_info = f"\nContext Information:\n{json.dumps(context_data, indent=2)}\n"
                system_prompt += context_info

            # Create messages
            messages = [
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=prompt),
            ]

            # Update token limit for the backend if possible
            backend = self.backends[backend_id]
            original_max_tokens = backend.config.max_tokens
            backend.config.max_tokens = max_tokens

            try:
                response = backend.chat(messages)
                if response and response.content:
                    logger.info("Generated %s script: %d characters", script_type, len(response.content))
                    return response.content.strip()
                logger.error("LLM returned empty response for script generation")
                return None

            except Exception:
                logger.exception("Script generation failed")
                return None
            finally:
                # Restore original token limit
                backend.config.max_tokens = original_max_tokens

    def refine_script_content(
        self,
        original_script: str,
        error_feedback: str,
        test_results: dict[str, Any],
        script_type: str,
        llm_id: str | None = None,
    ) -> str | None:
        """Refine existing script based on test results and error feedback.

        Iteratively improves a generated script by providing LLM with execution errors
        and test results. Generates a complete refined version addressing all issues.

        Args:
            original_script: Original script to refine and fix
            error_feedback: Error message or feedback from script execution
            test_results: Dictionary with test execution results and metrics
            script_type: Programming language of the script
            llm_id: Identifier of specific LLM to use (uses active backend if None)

        Returns:
            Refined script content as string, or None if refinement failed

        """
        with self.lock:
            backend_id = llm_id or self.active_backend

            if not backend_id or backend_id not in self.backends:
                logger.error("No active LLM backend available for script refinement")
                return None

            # Prepare refinement prompt
            system_prompt = f"""You are an expert {script_type} script developer. Your task is to fix and improve existing scripts.

CRITICAL REQUIREMENTS:
- Generate ONLY real, functional {script_type} code
- NO incomplete or partially implemented sections
- Fix all errors and improve reliability
- Maintain the original script's purpose and structure
- Return ONLY the complete refined script code

Analyze the test results and errors, then provide a complete improved version of the script."""

            user_prompt = f"""Original {script_type} Script:
```{script_type.lower()}
{original_script}
```

Error Feedback:
{error_feedback}

Test Results:
{json.dumps(test_results, indent=2)}

Please provide the complete refined script that fixes these issues."""

            messages = [
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=user_prompt),
            ]

            try:
                response = self.backends[backend_id].chat(messages)
                if response and response.content:
                    logger.info("Refined %s script: %d characters", script_type, len(response.content))
                    return response.content.strip()
                logger.error("LLM returned empty response for script refinement")
                return None

            except Exception:
                logger.exception("Script refinement failed")
                return None

    def analyze_protection_patterns(self, binary_data: dict[str, Any], llm_id: str | None = None) -> dict[str, Any] | None:
        """Analyze binary data to identify protection patterns and bypass strategies.

        Uses an LLM to examine binary analysis data and identify licensing protections,
        anti-debugging mechanisms, VM detection, cryptographic validations, and other
        protection mechanisms. Returns detected patterns and recommended bypass approaches.

        Args:
            binary_data: Dictionary with binary analysis data (functions, strings, imports, etc.)
            llm_id: Identifier of specific LLM to use (uses active backend if None)

        Returns:
            Dictionary with detected patterns and bypass strategies in JSON format,
            or None if analysis failed

        """
        with self.lock:
            backend_id = llm_id or self.active_backend

            if not backend_id or backend_id not in self.backends:
                logger.error("No active LLM backend available for pattern analysis")
                return None

            system_prompt = """You are an expert binary analyst specializing in protection mechanism detection.

Analyze the provided binary data and identify:
1. License check mechanisms
2. Time-based protections (trial timers, expiration)
3. Network validation systems
4. Anti-debugging techniques
5. VM detection methods
6. Cryptographic validations

Return a JSON object with detected patterns and recommended bypass strategies."""

            user_prompt = f"""Binary Analysis Data:
{json.dumps(binary_data, indent=2)}

Please analyze this data and provide detailed protection pattern analysis in JSON format."""

            messages = [
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=user_prompt),
            ]

            try:
                response = self.backends[backend_id].chat(messages)
                if response and response.content:
                    try:
                        parsed: dict[str, Any] = json.loads(response.content)
                        logger.info("Protection pattern analysis completed")
                        return parsed
                    except json.JSONDecodeError:
                        logger.warning("LLM response was not valid JSON, returning as text")
                        return {"analysis": response.content}
                else:
                    logger.error("LLM returned empty response for pattern analysis")
                    return None

            except Exception:
                logger.exception("Protection pattern analysis failed")
                return None

    def stream_script_generation(
        self,
        prompt: str,
        script_type: str,
        context_data: dict[str, Any] | None = None,
        llm_id: str | None = None,
    ) -> str | None:
        """Generate script with streaming for extended generation times.

        Generates scripts with streaming enabled for better handling of long generation
        times. Backends automatically stream tokens when available. Functionally equivalent
        to generate_script_content() for backends that support streaming.

        Args:
            prompt: User prompt describing desired script functionality
            script_type: Programming language (e.g., 'python', 'javascript', 'frida')
            context_data: Optional dictionary with binary analysis context data
            llm_id: Identifier of specific LLM to use (uses active backend if None)

        Returns:
            Generated script content as string, or None if generation failed

        """
        # Direct streaming passthrough to standard generation for compatibility
        # All configured backends handle streaming internally when available
        logger.info("Streaming script generation requested, using backend streaming")
        return self.generate_script_content(prompt, script_type, context_data, llm_id=llm_id)

    def validate_script_syntax(self, script_content: str, script_type: str, llm_id: str | None = None) -> dict[str, Any]:
        """Use LLM to validate script syntax and detect common issues.

        Validates script syntax using LLM analysis. Checks for syntax errors,
        API usage errors, logic errors, and security issues. Returns structured
        validation results in JSON format.

        Args:
            script_content: Complete script content to validate
            script_type: Programming language of the script
            llm_id: Identifier of specific LLM to use (uses active backend if None)

        Returns:
            Dictionary with validation results including: valid (bool), errors (list),
            warnings (list), suggestions (list), or error message if validation failed

        """
        with self.lock:
            backend_id = llm_id or self.active_backend

            if not backend_id or backend_id not in self.backends:
                logger.error("No active LLM backend available for script validation")
                return {"valid": False, "errors": ["No LLM backend available"]}

            system_prompt = f"""You are a {script_type} code validator and syntax checker.

Analyze the provided {script_type} script and check for:
1. Syntax errors
2. API usage errors
3. Missing dependencies
4. Logic errors
5. Security issues
6. Best practice violations

Return a JSON object with validation results:
{{
    "valid": true/false,
    "errors": ["list of errors"],
    "warnings": ["list of warnings"],
    "suggestions": ["list of improvements"]
}}"""

            user_prompt = f"""{script_type} Script to Validate:
```{script_type.lower()}
{script_content}
```

Please analyze this script and return validation results in JSON format."""

            messages = [
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=user_prompt),
            ]

            try:
                response = self.backends[backend_id].chat(messages)
                if not response or not response.content:
                    return {"valid": False, "errors": ["Empty LLM response"]}

                try:
                    parsed: dict[str, Any] = json.loads(response.content)
                    logger.info("Script validation completed")
                    return parsed
                except json.JSONDecodeError:
                    logger.warning("LLM validation response was not valid JSON")
                    return {
                        "valid": False,
                        "errors": ["Failed to parse validation response"],
                        "raw_response": response.content,
                    }
            except Exception as e:
                logger.exception("Script validation failed")
                return {"valid": False, "errors": [str(e)]}

    def shutdown(self) -> None:
        """Shutdown all LLM backends and cleanup resources.

        Gracefully shuts down all registered LLM backends, stops background loading
        if enabled, and clears internal state. Safe to call multiple times.

        """
        with self.lock:
            # Shutdown background loader if enabled
            if self.background_loader:
                self.background_loader.shutdown()

            for backend in self.backends.values():
                try:
                    backend.shutdown()
                except Exception as e:
                    logger.warning("Error shutting down backend: %s", e)

            self.backends.clear()
            self.configs.clear()
            self.active_backend = None

            logger.info("LLM Manager shutdown complete")

    # Background loading methods
    def add_progress_callback(self, callback: ProgressCallback) -> None:
        """Add a progress callback for model loading events.

        Registers a callback function that receives progress updates during
        background model loading. Callback is invoked with progress percentage.

        Args:
            callback: Progress callback function (signature: callback(progress: float, message: str))

        """
        if self.background_loader:
            self.background_loader.add_progress_callback(callback)
            self.progress_callbacks.append(callback)

    def add_queued_progress_callback(self, callback: ProgressCallback | QueuedProgressCallback) -> None:
        """Add a queued progress callback that buffers progress updates.

        Registers a callback that queues progress updates instead of calling them
        immediately. Useful for UI updates that need to batch requests.

        Args:
            callback: Progress callback function or existing QueuedProgressCallback instance

        """
        if self.background_loader:
            queued_callback: QueuedProgressCallback
            if not isinstance(callback, QueuedProgressCallback):
                queued_callback = QueuedProgressCallback()
            else:
                queued_callback = callback
            self.background_loader.add_progress_callback(queued_callback)
            self.progress_callbacks.append(queued_callback)

    def remove_progress_callback(self, callback: ProgressCallback) -> None:
        """Remove a progress callback.

        Unregisters a previously added progress callback. Safe to call if callback
        not registered (no error raised).

        Args:
            callback: Progress callback function to unregister

        """
        if self.background_loader:
            self.background_loader.remove_progress_callback(callback)
            if callback in self.progress_callbacks:
                self.progress_callbacks.remove(callback)

    def load_model_in_background(
        self,
        llm_id: str,
        config: LLMConfig,
        priority: int = 0,
        callback: ProgressCallback | None = None,
    ) -> LoadingTask | None:
        """Load an LLM model in background with progress tracking.

        Initiates asynchronous model loading in a background thread. Allows
        application to remain responsive while large models load. Returns a
        LoadingTask that can be used to poll or wait for completion.

        Args:
            llm_id: Unique identifier for this LLM backend
            config: LLMConfig with model settings and provider information
            priority: Loading priority value (higher = earlier execution)
            callback: Optional progress callback for loading updates

        Returns:
            LoadingTask for tracking progress and checking status,
            or None if background loading is disabled

        Raises:
            ValueError: If unsupported LLM provider specified in config
        """
        if not self.background_loader:
            logger.warning("Background loading not enabled")
            return None

        with self.lock:
            try:
                backend_class = LLMManager._get_backend_class(config.provider)
                if backend_class is None:
                    raise ValueError(f"Unsupported LLM provider: {config.provider}")

                # Add global callbacks if any
                if callback:
                    self.add_progress_callback(callback)

                task: LoadingTask = self.background_loader.load_model_in_background(
                    model_id=llm_id,
                    backend_class=backend_class,
                    config=config,
                    priority=priority,
                )

                self.loading_tasks[llm_id] = task
                self.configs[llm_id] = config

                logger.info("Submitted background loading task for: %s", llm_id)
                return task

            except Exception:
                logger.exception("Failed to submit background loading task")
                return None

    def get_loading_progress(self, llm_id: str) -> LoadingTask | None:
        """Get loading progress for a model being loaded in the background.

        Queries the current progress and status of a model that is loading
        asynchronously. Returns the LoadingTask object with current state.

        Args:
            llm_id: Identifier of the model being loaded

        Returns:
            LoadingTask with progress info, or None if background loading disabled or not found

        """
        if self.background_loader:
            result: LoadingTask | None = self.background_loader.get_loading_progress(llm_id)
            return result
        return None

    def cancel_loading(self, llm_id: str) -> bool:
        """Cancel background loading of a model.

        Stops background model loading in progress. Cleans up the loading task
        from internal tracking.

        Args:
            llm_id: Identifier of the model to cancel loading

        Returns:
            True if loading was cancelled successfully, False if background loading disabled or task not found

        """
        if self.background_loader:
            success: bool = self.background_loader.cancel_loading(llm_id)
            if success and llm_id in self.loading_tasks:
                del self.loading_tasks[llm_id]
            return success
        return False

    def get_all_loading_tasks(self) -> dict[str, LoadingTask]:
        """Get all current background loading tasks.

        Returns all LoadingTask objects for models currently being loaded
        in the background, indexed by LLM identifier.

        Returns:
            Dictionary mapping LLM IDs to LoadingTask objects

        """
        if self.background_loader:
            result: dict[str, LoadingTask] = self.background_loader.get_all_loading_tasks()
            return result
        return {}

    def get_loading_statistics(self) -> dict[str, Any]:
        """Get background loading statistics.

        Returns summary statistics about background model loading including
        count of pending, active, and completed tasks plus overall success rate.

        Returns:
            Dictionary with keys: pending (int), active (int), completed (int), success_rate (float)

        """
        if self.background_loader:
            result: dict[str, Any] = self.background_loader.get_statistics()
            return result
        return {
            "pending": 0,
            "active": 0,
            "completed": 0,
            "success_rate": 0.0,
        }

    def register_background_loaded_model(self, llm_id: str, task: LoadingTask) -> bool:
        """Register a model that was successfully loaded in the background.

        Completes background loading workflow by registering the loaded model
        and making it available for inference. Sets as active if first registered.

        Args:
            llm_id: Identifier for the loaded LLM backend
            task: Completed LoadingTask containing the loaded backend

        Returns:
            True if model was successfully registered and is ready, False otherwise

        """
        if task.state == LoadingState.COMPLETED and task.result:
            with self.lock:
                self.backends[llm_id] = task.result

                # Set as active if first one
                if not self.active_backend:
                    self.active_backend = llm_id

                logger.info("Registered background-loaded LLM: %s", llm_id)
                return True
        return False

    def unload_llm(self, llm_id: str) -> bool:
        """Unload a specific LLM to free memory and resources.

        Unloads either a lazy-wrapped or immediately-loaded LLM, releasing
        associated memory and GPU resources. Automatically selects a new active
        backend if the unloaded backend was active.

        Args:
            llm_id: Identifier of the LLM to unload

        Returns:
            True if LLM was unloaded successfully, False if not found

        """
        with self.lock:
            if llm_id in self.lazy_wrappers:
                self.lazy_wrappers[llm_id].unload()
                logger.info("Unloaded lazy LLM: %s", llm_id)
                return True
            if llm_id in self.backends:
                # For immediate backends, we can remove them entirely
                del self.backends[llm_id]
                if self.active_backend == llm_id:
                    # Set a new active backend if available
                    available = self.get_available_llms()
                    self.active_backend = available[0] if available else None
                logger.info("Unloaded immediate LLM: %s", llm_id)
                return True
            return False

    def unload_all_llms(self) -> None:
        """Unload all LLMs to free memory and resources.

        Unloads all registered LLM backends (both lazy and immediate).
        Resets active backend state.

        """
        with self.lock:
            # Unload lazy models
            for wrapper in self.lazy_wrappers.values():
                wrapper.unload()

            # Clear immediate backends
            self.backends.clear()
            self.active_backend = None

            logger.info("Unloaded all LLMs")

    def get_memory_usage(self) -> dict[str, Any]:
        """Get memory usage information for all registered models.

        Returns information about which models are currently loaded and their
        memory status. Includes counts of immediate and lazy-loaded models.

        Returns:
            Dictionary with keys: immediate_models (dict), lazy_models (dict),
            total_loaded (int)

        """
        immediate_models: dict[str, str] = {}
        lazy_models: dict[str, dict[str, Any]] = {}
        total_loaded = 0

        for llm_id in self.backends:
            immediate_models[llm_id] = "Loaded"
            total_loaded += 1

        for llm_id, wrapper in self.lazy_wrappers.items():
            wrapper_info = wrapper.get_info()
            lazy_models[llm_id] = {
                "is_loaded": wrapper_info["is_loaded"],
                "memory_usage": wrapper_info["memory_usage"],
                "access_count": wrapper_info["access_count"],
            }
            if wrapper_info["is_loaded"]:
                total_loaded += 1

        return {
            "immediate_models": immediate_models,
            "lazy_models": lazy_models,
            "total_loaded": total_loaded,
        }

    def configure_lazy_loading(self, max_loaded_models: int = 3, idle_unload_time: int = 1800) -> None:
        """Configure lazy loading parameters for memory-efficient model management.

        Adjusts lazy loading behavior to balance memory usage and performance.
        Allows limiting the number of simultaneously-loaded models and setting
        idle time before automatic unloading.

        Args:
            max_loaded_models: Maximum number of models to keep loaded in memory (default 3)
            idle_unload_time: Time in seconds before unloading idle models (default 1800)

        """
        if self.lazy_manager:
            self.lazy_manager.max_loaded_models = max_loaded_models
            self.lazy_manager.idle_unload_time = idle_unload_time
            logger.info(
                "Updated lazy loading config: max_models=%d, idle_time=%d",
                max_loaded_models,
                idle_unload_time,
            )

    def preload_model(self, llm_id: str) -> bool:
        """Manually preload a lazy-loaded model into memory.

        Triggers immediate loading of a lazy-loaded model rather than waiting
        for first use. Useful for ensuring model is ready before analysis begins.

        Args:
            llm_id: Identifier of the lazy-loaded model to preload

        Returns:
            True if model preloaded successfully, False if not found or already loaded

        """
        if llm_id in self.lazy_wrappers:
            wrapper = self.lazy_wrappers[llm_id]
            backend = wrapper.get_backend()
            return backend is not None
        return False

    def add_llm(self, llm_id: str, config: LLMConfig) -> bool:
        """Add an LLM with the given configuration (convenience alias for register_llm).

        Registers a new LLM backend with the specified configuration. Identical to
        register_llm() - provided for API consistency.

        Args:
            llm_id: Unique identifier for this LLM backend
            config: LLMConfig object with model settings and provider

        Returns:
            True if LLM registered and initialized successfully, False otherwise

        """
        return self.register_llm(llm_id, config)

    def get_llm(self, llm_id: str) -> LLMBackend | None:
        """Get an LLM backend instance by identifier.

        Retrieves the backend object for a registered LLM. For lazy-loaded models,
        triggers loading if not already loaded.

        Args:
            llm_id: Identifier of the LLM to retrieve

        Returns:
            LLMBackend instance if found and accessible, None otherwise

        """
        with self.lock:
            if llm_id in self.backends:
                return self.backends[llm_id]

            if llm_id in self.lazy_wrappers and self.lazy_manager:
                result: LLMBackend | None = self.lazy_manager.get_model(llm_id)
                return result

            return None

    def list_llms(self) -> list[str]:
        """List all available LLM backend IDs (convenience alias for get_available_llms).

        Returns all registered LLM identifiers including both immediately-loaded
        and lazy-loaded backends.

        Returns:
            List of all registered LLM backend identifiers

        """
        return self.get_available_llms()

    def add_provider(self, provider: LLMProvider, config: LLMConfig) -> bool:
        """Add an LLM provider with the given configuration.

        Creates a unique LLM ID based on the provider and model name, then
        registers the backend using the standard registration process.

        Args:
            provider: The LLM provider type (e.g., LLMProvider.OPENAI).
            config: LLM configuration object with model settings.

        Returns:
            True if the provider was successfully added and registered.

        """
        with self.lock:
            llm_id = f"{provider.value}-{config.model_name}" if config.model_name else provider.value
            logger.info("Adding provider %s with ID: %s", provider.value, llm_id)
            return self.register_llm(llm_id, config)

    def get_provider(self, provider: str | LLMProvider) -> LLMBackend | None:
        """Get an LLM backend by provider name or type.

        Searches for a registered backend matching the given provider. If
        multiple backends exist for the same provider, returns the first match.

        Args:
            provider: Provider name as string or LLMProvider enum.

        Returns:
            The LLMBackend instance if found, None otherwise.

        """
        with self.lock:
            provider_value = provider.value if isinstance(provider, LLMProvider) else provider

            for llm_id, config in self.configs.items():
                if config.provider.value == provider_value:
                    return self.get_llm(llm_id)

            for llm_id in self.backends:
                if llm_id.startswith(provider_value):
                    return self.backends[llm_id]

            for llm_id in self.lazy_wrappers:
                if llm_id.startswith(provider_value) and self.lazy_manager:
                    return cast("LLMBackend | None", self.lazy_manager.get_model(llm_id))

            logger.debug("No backend found for provider: %s", provider_value)
            return None

    def list_models(self) -> list[str]:
        """List all available model names.

        Returns a list of model names from all registered LLM configurations.
        This includes both immediately loaded and lazy-loaded models.

        Returns:
            List of model name strings.

        """
        model_names: list[str] = []
        for config in self.configs.values():
            if config.model_name and config.model_name not in model_names:
                model_names.append(config.model_name)
        return model_names


# Convenience functions for creating common configurations
def create_openai_config(model_name: str = "gpt-4", api_key: str | None = None, **kwargs: Any) -> LLMConfig:
    """Create OpenAI configuration.

    Args:
        model_name: OpenAI model name (default: gpt-4)
        api_key: OpenAI API key (optional)
        **kwargs: Additional LLMConfig parameters

    Returns:
        LLMConfig configured for OpenAI provider

    """
    return LLMConfig(
        provider=LLMProvider.OPENAI,
        model_name=model_name,
        api_key=api_key,
        **kwargs,
    )


def create_anthropic_config(model_name: str = "claude-3-5-sonnet-20241022", api_key: str | None = None, **kwargs: Any) -> LLMConfig:
    """Create Anthropic configuration.

    Args:
        model_name: Anthropic model name (default: claude-3-5-sonnet-20241022)
        api_key: Anthropic API key (optional)
        **kwargs: Additional LLMConfig parameters

    Returns:
        LLMConfig configured for Anthropic provider

    """
    return LLMConfig(
        provider=LLMProvider.ANTHROPIC,
        model_name=model_name,
        api_key=api_key,
        **kwargs,
    )


def create_google_config(model_name: str = "gemini-pro", api_key: str | None = None, **kwargs: Any) -> LLMConfig:
    """Create Google AI configuration.

    Args:
        model_name: Google model name (default: gemini-pro)
        api_key: Google API key (optional)
        **kwargs: Additional LLMConfig parameters

    Returns:
        LLMConfig configured for Google provider

    """
    return LLMConfig(
        provider=LLMProvider.GOOGLE,
        model_name=model_name,
        api_key=api_key,
        **kwargs,
    )


def create_gguf_config(model_path: str, model_name: str | None = None, **kwargs: Any) -> LLMConfig:
    """Create GGUF model configuration.

    Args:
        model_path: Path to GGUF model file
        model_name: Optional model name (defaults to filename)
        **kwargs: Additional LLMConfig parameters

    Returns:
        LLMConfig configured for llama.cpp GGUF provider

    """
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.LLAMACPP,
        model_name=model_name,
        model_path=model_path,
        **kwargs,
    )


def create_ollama_config(model_name: str, api_base: str | None = None, **kwargs: Any) -> LLMConfig:
    """Create Ollama configuration.

    Args:
        model_name: Ollama model name
        api_base: Optional Ollama API base URL
        **kwargs: Additional LLMConfig parameters

    Returns:
        LLMConfig configured for Ollama provider

    """
    from intellicrack.utils.service_utils import get_service_url

    return LLMConfig(
        provider=LLMProvider.OLLAMA,
        model_name=model_name,
        api_base=api_base or get_service_url("ollama_api"),
        **kwargs,
    )


def create_pytorch_config(model_path: str, model_name: str | None = None, **kwargs: Any) -> LLMConfig:
    """Create PyTorch model configuration.

    Args:
        model_path: Path to PyTorch model file or directory
        model_name: Optional model name (defaults to filename)
        **kwargs: Additional LLMConfig parameters

    Returns:
        LLMConfig configured for PyTorch provider

    """
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.PYTORCH,
        model_name=model_name,
        model_path=model_path,
        **kwargs,
    )


def create_tensorflow_config(model_path: str, model_name: str | None = None, **kwargs: Any) -> LLMConfig:
    """Create TensorFlow model configuration.

    Args:
        model_path: Path to TensorFlow model file or SavedModel directory
        model_name: Optional model name (defaults to filename)
        **kwargs: Additional LLMConfig parameters

    Returns:
        LLMConfig configured for TensorFlow provider

    """
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.TENSORFLOW,
        model_name=model_name,
        model_path=model_path,
        **kwargs,
    )


def create_onnx_config(model_path: str, model_name: str | None = None, **kwargs: Any) -> LLMConfig:
    """Create ONNX model configuration.

    Args:
        model_path: Path to ONNX model file
        model_name: Optional model name (defaults to filename)
        **kwargs: Additional LLMConfig parameters

    Returns:
        LLMConfig configured for ONNX provider

    """
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.ONNX,
        model_name=model_name,
        model_path=model_path,
        **kwargs,
    )


def create_safetensors_config(model_path: str, model_name: str | None = None, **kwargs: Any) -> LLMConfig:
    """Create Safetensors model configuration.

    Args:
        model_path: Path to Safetensors model file or directory
        model_name: Optional model name (defaults to filename)
        **kwargs: Additional LLMConfig parameters

    Returns:
        LLMConfig configured for Safetensors provider

    """
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.SAFETENSORS,
        model_name=model_name,
        model_path=model_path,
        **kwargs,
    )


def create_gptq_config(model_path: str, model_name: str | None = None, **kwargs: Any) -> LLMConfig:
    """Create GPTQ model configuration.

    Args:
        model_path: Path to GPTQ quantized model directory
        model_name: Optional model name (defaults to filename)
        **kwargs: Additional LLMConfig parameters

    Returns:
        LLMConfig configured for GPTQ provider

    """
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.GPTQ,
        model_name=model_name,
        model_path=model_path,
        **kwargs,
    )


def create_huggingface_local_config(model_path: str, model_name: str | None = None, **kwargs: Any) -> LLMConfig:
    """Create Hugging Face local model configuration.

    Args:
        model_path: Path to Hugging Face model directory
        model_name: Optional model name (defaults to dirname)
        **kwargs: Additional LLMConfig parameters

    Returns:
        LLMConfig configured for Hugging Face local provider

    """
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.HUGGINGFACE_LOCAL,
        model_name=model_name,
        model_path=model_path,
        **kwargs,
    )


# Global LLM manager instance
_LLM_MANAGER = None


def _configure_default_llms(manager: LLMManager) -> None:
    """Auto-configure default LLMs for the manager to prevent 'no LLMs configured' warnings.

    This function sets up fallback LLM configurations to ensure the system is operational
    even without explicit configuration. It prioritizes local models and services that
    don't require API keys for security research environments.

    Args:
        manager: The LLM manager instance to configure

    """
    from ..utils.secrets_manager import get_secret

    logger.info("Auto-configuring default LLMs for security research environment")

    # Configuration priority: Local models > API-based models with fallbacks
    configured_count = 0

    # 1. Try to configure Ollama (local inference server) - highest priority
    try:
        from intellicrack.utils.service_utils import get_service_url

        if ollama_url := get_service_url("ollama_api", fallback="http://localhost:11434"):
            # Check if Ollama server is actually running before registering backends
            try:
                import requests

                # Quick check if Ollama is accessible
                response = requests.get(f"{ollama_url}/api/tags", timeout=2)
                if response.status_code == 200:
                    # Ollama is running, register the backends
                    ollama_config = create_ollama_config(
                        model_name="llama3.2:latest",  # Common Ollama model
                        api_base=ollama_url,
                        context_length=8192,
                        temperature=0.1,  # Lower temperature for more deterministic analysis
                    )

                    # Register with lazy loading to avoid blocking on initialization
                    if manager.register_llm("ollama-llama3.2", ollama_config, use_lazy_loading=True):
                        configured_count += 1
                        logger.info("Configured Ollama LLM: llama3.2:latest")

                    # Also register a smaller model as backup
                    ollama_small_config = create_ollama_config(
                        model_name="llama3.2:1b",  # Smaller Ollama model
                        api_base=ollama_url,
                        context_length=4096,
                        temperature=0.1,
                        system_prompt=None,
                    )

                    if manager.register_llm("ollama-llama3.2-1b", ollama_small_config, use_lazy_loading=True):
                        configured_count += 1
                        logger.info("Configured Ollama LLM: llama3.2:1b (backup)")
                else:
                    logger.debug(
                        "Ollama server not available (status %d), skipping configuration",
                        response.status_code,
                    )
            except (requests.ConnectionError, requests.Timeout):
                # Ollama is not running, skip registration entirely
                logger.debug("Ollama server not running at %s, skipping configuration", ollama_url)
            except ImportError:
                logger.debug("requests library not available, cannot check Ollama server status")

    except (ImportError, AttributeError, ConfigurationError, OSError, RuntimeError) as e:
        logger.debug("Ollama configuration failed: %s", e)

    # 2. Try to configure local GGUF models (if available in common paths)
    try:
        from intellicrack.core.config_manager import get_config

        config = get_config()
        cache_dir = config.get_cache_dir()

        # Common GGUF model paths to check
        gguf_paths = [
            cache_dir / "models" / "llama-3.2-3b-instruct-q4_0.gguf",
            cache_dir / "models" / "llama-3.2-1b-instruct-q4_0.gguf",
            cache_dir / "models" / "phi-3-mini-4k-instruct-q4.gguf",
            cache_dir / "models" / "gemma-2b-it-q4_0.gguf",
        ]

        for model_path in gguf_paths:
            if model_path.exists():
                model_name = model_path.stem
                gguf_config = create_gguf_config(str(model_path), model_name=model_name, context_length=4096, temperature=0.1)

                if manager.register_llm(f"local-gguf-{model_name}", gguf_config, use_lazy_loading=True):
                    configured_count += 1
                    logger.info("Configured GGUF LLM: %s", model_name)
                    break  # Only need one GGUF model

    except (ImportError, AttributeError, OSError, RuntimeError) as e:
        logger.debug("GGUF model configuration failed: %s", e)

    # 3. Configure OpenAI GPT if API key is available (via environment or secrets)
    try:
        if api_key := get_secret("OPENAI_API_KEY"):
            openai_config = create_openai_config(
                model_name="gpt-4o-mini",  # Cost-effective option
                api_key=api_key,
                context_length=16384,
                temperature=0.1,
                max_tokens=4096,
            )

            if manager.register_llm("openai-gpt4o-mini", openai_config, use_lazy_loading=True):
                configured_count += 1
                logger.info("Configured OpenAI LLM: gpt-4o-mini")

    except (ImportError, AttributeError, OSError, RuntimeError) as e:
        logger.debug("OpenAI configuration failed: %s", e)

    # 4. Configure Anthropic Claude if API key is available
    try:
        if api_key := get_secret("ANTHROPIC_API_KEY"):
            anthropic_config = create_anthropic_config(
                model_name="claude-3-5-haiku-20241022",  # Fast and cost-effective
                api_key=api_key,
                context_length=8192,
                temperature=0.1,
                max_tokens=4096,
            )

            if manager.register_llm("anthropic-claude-haiku", anthropic_config, use_lazy_loading=True):
                configured_count += 1
                logger.info("Configured Anthropic LLM: claude-3-5-haiku")

    except (ImportError, AttributeError, OSError, RuntimeError) as e:
        logger.debug("Anthropic configuration failed: %s", e)

    # 5. If no LLMs configured, that's fine - Intellicrack can operate without external LLMs
    if configured_count == 0:
        # Don't log warnings - LLMs are optional for Intellicrack
        logger.debug("No external LLMs configured - Intellicrack will use built-in analysis")
        # Don't try to register a fallback that will fail - just leave it unconfigured

    logger.info("Auto-configuration complete: %d LLM(s) configured", configured_count)


def get_llm_manager() -> LLMManager:
    """Get the global LLM manager instance.

    Returns:
        Global LLMManager singleton, configured with default LLMs

    """
    global _LLM_MANAGER  # pylint: disable=global-statement
    if _LLM_MANAGER is None:
        _LLM_MANAGER = LLMManager()
        _configure_default_llms(_LLM_MANAGER)
    return _LLM_MANAGER


def get_llm_backend() -> LLMManager:
    """Get the global LLM manager instance for backward compatibility.

    This function provides backward compatibility for code that expects
    a get_llm_backend() function. Returns the same LLMManager instance
    as get_llm_manager().

    Returns:
        The global LLMManager singleton instance

    """
    return get_llm_manager()


def shutdown_llm_manager() -> None:
    """Shutdown the global LLM manager and release all resources."""
    global _LLM_MANAGER  # pylint: disable=global-statement
    if _LLM_MANAGER:
        _LLM_MANAGER.shutdown()
        _LLM_MANAGER = None


# Aliases for backward compatibility
LocalModelBackend = HuggingFaceLocalBackend
ModelManager = LLMManager
