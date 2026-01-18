"""LLM Provider implementations for Intellicrack.

This module contains provider implementations for various LLM APIs including
Anthropic Claude, OpenAI GPT, Google Gemini, Ollama, and OpenRouter.
"""

from .anthropic import AnthropicProvider
from .base import (
    AnthropicToolSchema,
    ChatRequest,
    ChatResponse,
    GoogleFunctionDeclaration,
    JSONSchemaParameters,
    JSONSchemaProperty,
    LLMProvider,
    LLMProviderBase,
    MessageDict,
    OpenAIFunctionSchema,
    OpenAIToolSchema,
    ProviderCapabilities,
    ProviderState,
    create_anthropic_tool_schema,
    create_google_tool_schema,
    create_openai_tool_schema,
)
from .discovery import DiscoveryCache, DiscoveryEvent, DiscoveryFilter, ModelDiscovery
from .google import GoogleProvider
from .grok import GrokProvider
from .huggingface import HuggingFaceProvider
from .ollama import OllamaProvider
from .openai import OpenAIProvider
from .openrouter import OpenRouterProvider
from .registry import ProviderRegistry


__all__: list[str] = [
    "AnthropicProvider",
    "AnthropicToolSchema",
    "ChatRequest",
    "ChatResponse",
    "DiscoveryCache",
    "DiscoveryEvent",
    "DiscoveryFilter",
    "GoogleFunctionDeclaration",
    "GoogleProvider",
    "GrokProvider",
    "HuggingFaceProvider",
    "JSONSchemaParameters",
    "JSONSchemaProperty",
    "LLMProvider",
    "LLMProviderBase",
    "MessageDict",
    "ModelDiscovery",
    "OllamaProvider",
    "OpenAIFunctionSchema",
    "OpenAIProvider",
    "OpenAIToolSchema",
    "OpenRouterProvider",
    "ProviderCapabilities",
    "ProviderRegistry",
    "ProviderState",
    "create_anthropic_tool_schema",
    "create_google_tool_schema",
    "create_openai_tool_schema",
]
