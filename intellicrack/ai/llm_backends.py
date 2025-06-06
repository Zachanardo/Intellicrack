"""
LLM Backend Support for Intellicrack Agentic AI

This module provides support for Large Language Models including:
- GGUF models via llama.cpp
- API-based models (OpenAI, Anthropic, etc.)
- Local model serving
- Tool-calling capabilities for agentic workflows
"""

import hashlib
import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class LLMProvider(Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LLAMACPP = "llamacpp"
    OLLAMA = "ollama"
    HUGGINGFACE = "huggingface"
    LOCAL_API = "local_api"


@dataclass
class LLMConfig:
    """Configuration for LLM backends."""
    provider: LLMProvider
    model_name: str
    api_key: Optional[str] = None
    api_base: Optional[str] = None
    model_path: Optional[str] = None  # For local models
    context_length: int = 4096
    temperature: float = 0.7
    max_tokens: int = 2048
    tools_enabled: bool = True
    custom_params: Dict[str, Any] = None


@dataclass
class LLMMessage:
    """Message structure for LLM communication."""
    role: str  # "system", "user", "assistant", "tool"
    content: str
    tool_calls: Optional[List[Dict]] = None
    tool_call_id: Optional[str] = None


@dataclass
class LLMResponse:
    """Response structure from LLM."""
    content: str
    tool_calls: Optional[List[Dict]] = None
    usage: Optional[Dict[str, int]] = None
    finish_reason: str = "stop"
    model: str = ""


class LLMBackend:
    """Base class for LLM backends."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.is_initialized = False
        self.tools = []

    def initialize(self) -> bool:
        """Initialize the backend."""
        raise NotImplementedError

    def chat(self, messages: List[LLMMessage], tools: Optional[List[Dict]] = None) -> LLMResponse:
        """Send chat messages and get response."""
        raise NotImplementedError

    def register_tools(self, tools: List[Dict]):
        """Register tools for function calling."""
        self.tools = tools

    def shutdown(self):
        """Shutdown the backend."""
        pass


class OpenAIBackend(LLMBackend):
    """OpenAI API backend."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.client = None

    def initialize(self) -> bool:
        """Initialize OpenAI client."""
        try:
            import openai

            if not self.config.api_key:
                # Try environment variable
                api_key = os.getenv('OPENAI_API_KEY')
                if not api_key:
                    logger.error("OpenAI API key not provided")
                    return False
            else:
                api_key = self.config.api_key

            self.client = openai.OpenAI(
                api_key=api_key,
                base_url=self.config.api_base
            )

            # Test connection
            self.client.models.list()
            self.is_initialized = True
            logger.info(f"OpenAI backend initialized with model: {self.config.model_name}")
            return True

        except ImportError:
            logger.error("OpenAI package not installed. Install with: pip install openai")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI backend: {e}")
            return False

    def chat(self, messages: List[LLMMessage], tools: Optional[List[Dict]] = None) -> LLMResponse:
        """Send chat to OpenAI API."""
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        # Convert messages to OpenAI format
        openai_messages = []
        for msg in messages:
            openai_msg = {"role": msg.role, "content": msg.content}
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
            "max_tokens": self.config.max_tokens
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
                model=response.model
            )

        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise


class AnthropicBackend(LLMBackend):
    """Anthropic Claude API backend."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.client = None

    def initialize(self) -> bool:
        """Initialize Anthropic client."""
        try:
            import anthropic

            if not self.config.api_key:
                api_key = os.getenv('ANTHROPIC_API_KEY')
                if not api_key:
                    logger.error("Anthropic API key not provided")
                    return False
            else:
                api_key = self.config.api_key

            self.client = anthropic.Anthropic(api_key=api_key)
            self.is_initialized = True
            logger.info(f"Anthropic backend initialized with model: {self.config.model_name}")
            return True

        except ImportError:
            logger.error("Anthropic package not installed. Install with: pip install anthropic")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize Anthropic backend: {e}")
            return False

    def chat(self, messages: List[LLMMessage], tools: Optional[List[Dict]] = None) -> LLMResponse:
        """Send chat to Anthropic API."""
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
            "temperature": self.config.temperature
        }

        if system_message:
            request_params["system"] = system_message

        if tools and self.config.tools_enabled:
            request_params["tools"] = tools

        try:
            response = self.client.messages.create(**request_params)

            return LLMResponse(
                content=response.content[0].text if response.content else "",
                tool_calls=getattr(response, 'tool_calls', None),
                finish_reason=response.stop_reason,
                model=response.model
            )

        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            raise


class LlamaCppBackend(LLMBackend):
    """llama.cpp backend for GGUF models."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.llama = None

    def initialize(self) -> bool:
        """Initialize llama.cpp."""
        try:
            from llama_cpp import Llama

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error(f"GGUF model file not found: {self.config.model_path}")
                return False

            # Initialize llama.cpp with GGUF model
            self.llama = Llama(
                model_path=self.config.model_path,
                n_ctx=self.config.context_length,
                verbose=False,
                n_threads=4  # Adjust based on system
            )

            self.is_initialized = True
            logger.info(f"llama.cpp backend initialized with GGUF model: {self.config.model_path}")
            return True

        except ImportError:
            logger.error("llama-cpp-python not installed. Install with: pip install llama-cpp-python")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize llama.cpp backend: {e}")
            return False

    def chat(self, messages: List[LLMMessage], tools: Optional[List[Dict]] = None) -> LLMResponse:
        """Chat with llama.cpp model."""
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        # Convert messages to prompt format
        prompt = self._messages_to_prompt(messages)

        try:
            # Generate response
            response = self.llama(
                prompt,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                echo=False,
                stop=["</s>", "<|im_end|>", "<|end|>"]
            )

            content = response['choices'][0]['text'].strip()

            # Handle tool calls if tools are available (basic implementation)
            tool_calls = None
            if tools and self.config.tools_enabled:
                tool_calls = self._extract_tool_calls(content, tools)

            return LLMResponse(
                content=content,
                tool_calls=tool_calls,
                finish_reason=response['choices'][0]['finish_reason'],
                model=self.config.model_name
            )

        except Exception as e:
            logger.error(f"llama.cpp generation error: {e}")
            raise

    def _messages_to_prompt(self, messages: List[LLMMessage]) -> str:
        """Convert messages to prompt format."""
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

    def _extract_tool_calls(self, content: str, tools: List[Dict]) -> Optional[List[Dict]]:
        """Extract tool calls from generated content (basic implementation)."""
        # This is a simplified implementation
        # In practice, you'd want more sophisticated parsing
        tool_calls = []

        # Look for function call patterns
        for tool in tools:
            tool_name = tool['name']
            pattern = rf'{tool_name}\((.*?)\)'
            matches = re.finditer(pattern, content, re.DOTALL)

            for match in matches:
                try:
                    args_str = match.group(1).strip()
                    # Try to parse as JSON
                    args = json.loads(args_str) if args_str else {}

                    tool_calls.append({
                        "id": f"call_{hashlib.sha256(match.group(0).encode()).hexdigest()[:8]}",
                        "type": "function",
                        "function": {
                            "name": tool_name,
                            "arguments": json.dumps(args)
                        }
                    })
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

        return tool_calls if tool_calls else None


class OllamaBackend(LLMBackend):
    """Ollama backend for local model serving."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.base_url = config.api_base or "http://localhost:11434"

    def initialize(self) -> bool:
        """Initialize Ollama connection."""
        try:
            try:
                import requests
            except ImportError:
                logger.error("requests library not available for Ollama backend")
                return False

            # Test connection to Ollama
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                self.is_initialized = True
                logger.info(f"Ollama backend initialized with model: {self.config.model_name}")
                return True
            else:
                logger.error(f"Ollama not accessible at {self.base_url}")
                return False

        except Exception as e:
            logger.error(f"Failed to initialize Ollama backend: {e}")
            return False

    def chat(self, messages: List[LLMMessage], tools: Optional[List[Dict]] = None) -> LLMResponse:
        """Chat with Ollama model."""
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        try:
            import requests
        except ImportError:
            return LLMResponse(
                content="Ollama backend requires 'requests' library",
                raw_response={},
                tokens_used=0,
                success=False
            )

        # Convert messages to Ollama format
        ollama_messages = []
        for msg in messages:
            ollama_messages.append({"role": msg.role, "content": msg.content})

        request_data = {
            "model": self.config.model_name,
            "messages": ollama_messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens
            }
        }

        try:
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=request_data,
                timeout=60
            )
            response.raise_for_status()

            result = response.json()

            return LLMResponse(
                content=result.get("message", {}).get("content", ""),
                finish_reason="stop",
                model=self.config.model_name
            )

        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            raise


class LLMManager:
    """Manager for LLM backends and configurations."""

    def __init__(self):
        self.backends = {}
        self.configs = {}
        self.active_backend = None
        self.lock = threading.RLock()

        logger.info("LLM Manager initialized")

    def register_llm(self, llm_id: str, config: LLMConfig) -> bool:
        """Register an LLM configuration."""
        with self.lock:
            try:
                # Create backend based on provider
                if config.provider == LLMProvider.OPENAI:
                    backend = OpenAIBackend(config)
                elif config.provider == LLMProvider.ANTHROPIC:
                    backend = AnthropicBackend(config)
                elif config.provider == LLMProvider.LLAMACPP:
                    backend = LlamaCppBackend(config)
                elif config.provider == LLMProvider.OLLAMA:
                    backend = OllamaBackend(config)
                else:
                    raise ValueError(f"Unsupported LLM provider: {config.provider}")

                # Initialize backend
                if not backend.initialize():
                    logger.error(f"Failed to initialize LLM backend: {llm_id}")
                    return False

                self.backends[llm_id] = backend
                self.configs[llm_id] = config

                # Set as active if first one
                if not self.active_backend:
                    self.active_backend = llm_id

                logger.info(f"Registered LLM: {llm_id} ({config.provider.value})")
                return True

            except Exception as e:
                logger.error(f"Failed to register LLM {llm_id}: {e}")
                return False

    def set_active_llm(self, llm_id: str) -> bool:
        """Set the active LLM for inference."""
        with self.lock:
            if llm_id not in self.backends:
                logger.error(f"LLM not registered: {llm_id}")
                return False

            self.active_backend = llm_id
            logger.info(f"Set active LLM: {llm_id}")
            return True

    def chat(self, messages: List[LLMMessage], llm_id: Optional[str] = None,
             tools: Optional[List[Dict]] = None) -> Optional[LLMResponse]:
        """Send chat messages to LLM."""
        with self.lock:
            backend_id = llm_id or self.active_backend

            if not backend_id or backend_id not in self.backends:
                logger.error("No active LLM backend available")
                return None

            backend = self.backends[backend_id]

            try:
                response = backend.chat(messages, tools)
                logger.debug(f"LLM response from {backend_id}: {len(response.content)} chars")
                return response

            except Exception as e:
                logger.error(f"LLM chat error: {e}")
                return None

    def get_available_llms(self) -> List[str]:
        """Get list of available LLM IDs."""
        return list(self.backends.keys())

    def get_llm_info(self, llm_id: str) -> Optional[Dict[str, Any]]:
        """Get information about an LLM."""
        if llm_id not in self.configs:
            return None

        config = self.configs[llm_id]
        backend = self.backends.get(llm_id)

        return {
            "id": llm_id,
            "provider": config.provider.value,
            "model_name": config.model_name,
            "is_initialized": backend.is_initialized if backend else False,
            "tools_enabled": config.tools_enabled,
            "context_length": config.context_length
        }

    def register_tools_for_llm(self, llm_id: str, tools: List[Dict]):
        """Register tools for a specific LLM."""
        if llm_id in self.backends:
            self.backends[llm_id].register_tools(tools)
            logger.info(f"Registered {len(tools)} tools for LLM: {llm_id}")

    def shutdown(self):
        """Shutdown all LLM backends."""
        with self.lock:
            for backend in self.backends.values():
                try:
                    backend.shutdown()
                except (AttributeError, Exception) as e:
                    logger.warning(f"Error shutting down backend: {e}")

            self.backends.clear()
            self.configs.clear()
            self.active_backend = None

            logger.info("LLM Manager shutdown complete")


# Convenience functions for creating common configurations
def create_openai_config(model_name: str = "gpt-4", api_key: str = None, **kwargs) -> LLMConfig:
    """Create OpenAI configuration."""
    return LLMConfig(
        provider=LLMProvider.OPENAI,
        model_name=model_name,
        api_key=api_key,
        **kwargs
    )


def create_anthropic_config(model_name: str = "claude-3-5-sonnet-20241022", api_key: str = None, **kwargs) -> LLMConfig:
    """Create Anthropic configuration."""
    return LLMConfig(
        provider=LLMProvider.ANTHROPIC,
        model_name=model_name,
        api_key=api_key,
        **kwargs
    )


def create_gguf_config(model_path: str, model_name: str = None, **kwargs) -> LLMConfig:
    """Create GGUF model configuration."""
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.LLAMACPP,
        model_name=model_name,
        model_path=model_path,
        **kwargs
    )


def create_ollama_config(model_name: str, api_base: str = None, **kwargs) -> LLMConfig:
    """Create Ollama configuration."""
    return LLMConfig(
        provider=LLMProvider.OLLAMA,
        model_name=model_name,
        api_base=api_base or "http://localhost:11434",
        **kwargs
    )


# Global LLM manager instance
_llm_manager = None


def get_llm_manager() -> LLMManager:
    """Get the global LLM manager instance."""
    global _llm_manager
    if _llm_manager is None:
        _llm_manager = LLMManager()
    return _llm_manager


def shutdown_llm_manager():
    """Shutdown the global LLM manager."""
    global _llm_manager
    if _llm_manager:
        _llm_manager.shutdown()
        _llm_manager = None
