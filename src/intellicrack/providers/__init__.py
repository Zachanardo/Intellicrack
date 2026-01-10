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
from .ollama import OllamaProvider
from .openai import OpenAIProvider
from .openrouter import OpenRouterProvider
from .registry import ProviderRegistry

__all__: list[str] = [
    # Base classes and types
    "LLMProviderBase",
    "ProviderCapabilities",
    "ProviderState",
    "ChatRequest",
    "ChatResponse",
    # TypedDict schemas
    "JSONSchemaProperty",
    "JSONSchemaParameters",
    "AnthropicToolSchema",
    "OpenAIToolSchema",
    "OpenAIFunctionSchema",
    "GoogleFunctionDeclaration",
    "MessageDict",
    # Schema creation functions
    "create_anthropic_tool_schema",
    "create_openai_tool_schema",
    "create_google_tool_schema",
    # Discovery
    "DiscoveryCache",
    "DiscoveryEvent",
    "DiscoveryFilter",
    "ModelDiscovery",
    # Provider implementations
    "AnthropicProvider",
    "OpenAIProvider",
    "GoogleProvider",
    "OllamaProvider",
    "OpenRouterProvider",
    # Registry
    "ProviderRegistry",
]
