"""
LLM Backend Support for Intellicrack Agentic AI

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
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
    LOCAL_GGUF = "local_gguf"


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
        logger.warning("Base LLMBackend.initialize() called - subclasses should override this method")
        self.is_initialized = False
        return False

    def chat(self, messages: List[LLMMessage], tools: Optional[List[Dict]] = None) -> LLMResponse:
        """Send chat messages and get response."""
        # Log the messages and tools for debugging
        logger.debug(f"Chat called with {len(messages)} messages and {len(tools or [])} tools")

        logger.error("Base LLMBackend.chat() called - this method must be implemented by subclasses")
        return LLMResponse(
            content="Error: LLM backend not properly initialized. Please use a concrete backend implementation.",
            finish_reason="error",
            model="base_backend_fallback"
        )

    def register_tools(self, tools: List[Dict]):
        """Register tools for function calling."""
        self.tools = tools

    def shutdown(self):
        """Shutdown the backend and clean up resources."""
        self.is_initialized = False
        self.tools.clear()
        logger.debug("Backend shutdown: %s", self.__class__.__name__)


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
            logger.info("OpenAI backend initialized with model: %s", self.config.model_name)
            return True

        except ImportError:
            logger.error("OpenAI package not installed. Install with: pip install openai")
            return False
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize OpenAI backend: %s", e)
            return False

    def chat(self, messages: List[LLMMessage], tools: Optional[List[Dict]] = None) -> LLMResponse:
        """Send chat to OpenAI API."""
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        # Convert messages to OpenAI format
        openai_messages = []
        for _msg in messages:
            openai_msg = {"role": _msg.role, "content": _msg.content}
            if _msg.tool_calls:
                openai_msg["tool_calls"] = _msg.tool_calls
            if _msg.tool_call_id:
                openai_msg["tool_call_id"] = _msg.tool_call_id
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
            request_params["tools"] = [{"type": "function", "function": _tool} for _tool in tools]
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

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("OpenAI API error: %s", e)
            raise

    def shutdown(self):
        """Shutdown OpenAI backend."""
        super().shutdown()
        self.client = None


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
            logger.info("Anthropic backend initialized with model: %s", self.config.model_name)
            return True

        except ImportError:
            logger.error("Anthropic package not installed. Install with: pip install anthropic")
            return False
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize Anthropic backend: %s", e)
            return False

    def chat(self, messages: List[LLMMessage], tools: Optional[List[Dict]] = None) -> LLMResponse:
        """Send chat to Anthropic API."""
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        # Convert messages to Anthropic format
        system_message = ""
        anthropic_messages = []

        for _msg in messages:
            if _msg.role == "system":
                system_message = _msg.content
            else:
                anthropic_messages.append({"role": _msg.role, "content": _msg.content})

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

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Anthropic API error: %s", e)
            raise

    def shutdown(self):
        """Shutdown Anthropic backend."""
        super().shutdown()
        self.client = None


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
                logger.error("GGUF model file not found: %s", self.config.model_path)
                return False

            # Initialize llama.cpp with GGUF model
            self.llama = Llama(
                model_path=self.config.model_path,
                n_ctx=self.config.context_length,
                verbose=False,
                n_threads=4  # Adjust based on system
            )

            self.is_initialized = True
            logger.info("llama.cpp backend initialized with GGUF model: %s", self.config.model_path)
            return True

        except ImportError:
            logger.error("llama-cpp-python not installed. Install with: pip install llama-cpp-python")
            return False
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize llama.cpp backend: %s", e)
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

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("llama.cpp generation error: %s", e)
            raise

    def _messages_to_prompt(self, messages: List[LLMMessage]) -> str:
        """Convert messages to prompt format."""
        prompt_parts = []

        for _msg in messages:
            if _msg.role == "system":
                prompt_parts.append(f"<|im_start|>system\n{_msg.content}<|im_end|>")
            elif _msg.role == "user":
                prompt_parts.append(f"<|im_start|>user\n{_msg.content}<|im_end|>")
            elif _msg.role == "assistant":
                prompt_parts.append(f"<|im_start|>assistant\n{_msg.content}<|im_end|>")

        prompt_parts.append("<|im_start|>assistant\n")
        return "\n".join(prompt_parts)

    def _extract_tool_calls(self, content: str, tools: List[Dict]) -> Optional[List[Dict]]:
        """Extract tool calls from generated content (basic implementation)."""
        # This is a simplified implementation
        # In practice, you'd want more sophisticated parsing
        tool_calls = []

        # Look for function call patterns
        for _tool in tools:
            tool_name = _tool['name']
            pattern = rf'{tool_name}\((.*?)\)'
            matches = re.finditer(pattern, content, re.DOTALL)

            for _match in matches:
                try:
                    args_str = _match.group(1).strip()
                    # Try to parse as JSON
                    args = json.loads(args_str) if args_str else {}

                    tool_calls.append({
                        "id": f"call_{hashlib.sha256(_match.group(0).encode()).hexdigest()[:8]}",
                        "type": "function",
                        "function": {
                            "name": tool_name,
                            "arguments": json.dumps(args)
                        }
                    })
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

        return tool_calls if tool_calls else None

    def shutdown(self):
        """Shutdown llama.cpp backend."""
        super().shutdown()
        if self.llama is not None:
            # Clean up llama.cpp model
            del self.llama
            self.llama = None


class OllamaBackend(LLMBackend):
    """Ollama backend for local model serving."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.base_url = config.api_base or os.environ.get('OLLAMA_API_BASE', 'http://localhost:11434')

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
                logger.info("Ollama backend initialized with model: %s", self.config.model_name)
                return True
            else:
                logger.error("Ollama not accessible at %s", self.base_url)
                return False

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize Ollama backend: %s", e)
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
                finish_reason="error"
            )

        # Convert messages to Ollama format
        ollama_messages = []
        for _msg in messages:
            ollama_messages.append({"role": _msg.role, "content": _msg.content})

        request_data = {
            "model": self.config.model_name,
            "messages": ollama_messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens
            }
        }

        # Add tools to request if provided
        if tools:
            request_data["tools"] = tools
            logger.debug(f"Adding {len(tools)} tools to Ollama request")

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

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Ollama API error: %s", e)
            raise

    def shutdown(self):
        """Shutdown Ollama backend."""
        super().shutdown()
        # No specific cleanup needed for HTTP client


class LocalGGUFBackend(LLMBackend):
    """Local GGUF model backend using our local server."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.server_url = config.api_base or "http://127.0.0.1:8000"
        self.gguf_manager = None

    def initialize(self) -> bool:
        """Initialize GGUF backend."""
        try:
            # Import the GGUF manager
            from .local_gguf_server import gguf_manager
            self.gguf_manager = gguf_manager

            # Check if server dependencies are available
            if not self.gguf_manager.server.can_run():
                logger.error("GGUF server dependencies not available (need Flask and llama-cpp-python)")
                return False

            # Start server if not running
            if not self.gguf_manager.is_server_running():
                logger.info("Starting local GGUF server...")
                if not self.gguf_manager.start_server():
                    logger.error("Failed to start GGUF server")
                    return False

            # Load model if specified and not already loaded
            if self.config.model_path:
                if not self.gguf_manager.current_model:
                    logger.info(f"Loading GGUF model: {self.config.model_path}")

                    # Extract model parameters from config
                    model_params = {
                        "context_length": self.config.context_length,
                        "gpu_layers": getattr(self.config, 'gpu_layers', 0),
                        "threads": getattr(self.config, 'threads', None),
                        "batch_size": getattr(self.config, 'batch_size', 512),
                        "temperature": self.config.temperature
                    }

                    # Filter out custom params if they exist
                    if hasattr(self.config, 'custom_params') and self.config.custom_params:
                        model_params.update(self.config.custom_params)

                    if not self.gguf_manager.server.load_model(self.config.model_path, **model_params):
                        logger.error("Failed to load GGUF model")
                        return False

            # Test server connection
            try:
                import requests
            except ImportError:
                logger.error("requests module required for GGUF backend")
                return False
            try:
                response = requests.get(f"{self.server_url}/health", timeout=5)
                if response.status_code == 200:
                    self.is_initialized = True
                    logger.info("Local GGUF backend initialized")
                    return True
                else:
                    logger.error("GGUF server not responding properly")
                    return False
            except Exception as e:
                logger.error(f"Failed to connect to GGUF server: {e}")
                return False

        except Exception as e:
            logger.error(f"Failed to initialize GGUF backend: {e}")
            return False

    def chat(self, messages: List[LLMMessage], tools: Optional[List[Dict]] = None) -> LLMResponse:
        """Chat with local GGUF model."""
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        try:
            import requests
        except ImportError:
            return LLMResponse(
                content="GGUF backend requires 'requests' library",
                finish_reason="error"
            )

        # Convert messages to OpenAI-compatible format
        openai_messages = []
        for msg in messages:
            openai_messages.append({
                "role": msg.role,
                "content": msg.content
            })

        request_data = {
            "model": self.config.model_name,
            "messages": openai_messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "stream": False
        }

        # Add tools if supported (future enhancement)
        if tools and self.config.tools_enabled:
            # Tools support could be added here in the future
            pass

        try:
            response = requests.post(
                f"{self.server_url}/v1/chat/completions",
                json=request_data,
                timeout=120  # Longer timeout for local inference
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
                model=result.get("model", self.config.model_name)
            )

        except Exception as e:
            logger.error(f"GGUF API error: {e}")
            raise

    def shutdown(self):
        """Shutdown GGUF backend."""
        super().shutdown()
        # Could stop the server here, but leave it running for other instances
        # self.gguf_manager.stop_server() if self.gguf_manager else None


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
                elif config.provider == LLMProvider.LOCAL_GGUF:
                    backend = LocalGGUFBackend(config)
                else:
                    raise ValueError(f"Unsupported LLM provider: {config.provider}")

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

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Failed to register LLM %s: %s", llm_id, e)
                return False

    def set_active_llm(self, llm_id: str) -> bool:
        """Set the active LLM for inference."""
        with self.lock:
            if llm_id not in self.backends:
                logger.error("LLM not registered: %s", llm_id)
                return False

            self.active_backend = llm_id
            logger.info("Set active LLM: %s", llm_id)
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
                logger.debug("LLM response from %s: %d chars", backend_id, len(response.content))
                return response

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("LLM chat error: %s", e)
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
            logger.info("Registered %d tools for LLM: %s", len(tools), llm_id)

    def generate_script_content(self, prompt: str, script_type: str, context_data: Dict[str, Any] = None,
                               max_tokens: int = 4000, llm_id: Optional[str] = None) -> Optional[str]:
        """Generate script content using LLM."""
        with self.lock:
            backend_id = llm_id or self.active_backend

            if not backend_id or backend_id not in self.backends:
                logger.error("No active LLM backend available for script generation")
                return None

            # Prepare system prompt for script generation
            system_prompt = f"""You are an expert {script_type} script developer for binary reverse engineering and protection bypass.

CRITICAL REQUIREMENTS:
- Generate ONLY real, functional {script_type} code
- NO placeholders, stubs, or "TODO" comments
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
                LLMMessage(role="user", content=prompt)
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
                else:
                    logger.error("LLM returned empty response for script generation")
                    return None

            except Exception as e:
                logger.error("Script generation failed: %s", e)
                return None
            finally:
                # Restore original token limit
                backend.config.max_tokens = original_max_tokens

    def refine_script_content(self, original_script: str, error_feedback: str,
                             test_results: Dict[str, Any], script_type: str,
                             llm_id: Optional[str] = None) -> Optional[str]:
        """Refine existing script based on test results and feedback."""
        with self.lock:
            backend_id = llm_id or self.active_backend

            if not backend_id or backend_id not in self.backends:
                logger.error("No active LLM backend available for script refinement")
                return None

            # Prepare refinement prompt
            system_prompt = f"""You are an expert {script_type} script developer. Your task is to fix and improve existing scripts.

CRITICAL REQUIREMENTS:
- Generate ONLY real, functional {script_type} code
- NO placeholders, stubs, or "TODO" comments
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
                LLMMessage(role="user", content=user_prompt)
            ]

            try:
                response = self.backends[backend_id].chat(messages)
                if response and response.content:
                    logger.info("Refined %s script: %d characters", script_type, len(response.content))
                    return response.content.strip()
                else:
                    logger.error("LLM returned empty response for script refinement")
                    return None

            except Exception as e:
                logger.error("Script refinement failed: %s", e)
                return None

    def analyze_protection_patterns(self, binary_data: Dict[str, Any],
                                   llm_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Analyze binary data to identify protection patterns."""
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
                LLMMessage(role="user", content=user_prompt)
            ]

            try:
                response = self.backends[backend_id].chat(messages)
                if response and response.content:
                    # Try to parse as JSON
                    try:
                        result = json.loads(response.content)
                        logger.info("Protection pattern analysis completed")
                        return result
                    except json.JSONDecodeError:
                        # Return as text if not valid JSON
                        logger.warning("LLM response was not valid JSON, returning as text")
                        return {"analysis": response.content}
                else:
                    logger.error("LLM returned empty response for pattern analysis")
                    return None

            except Exception as e:
                logger.error("Protection pattern analysis failed: %s", e)
                return None

    def stream_script_generation(self, prompt: str, script_type: str,
                                context_data: Dict[str, Any] = None,
                                llm_id: Optional[str] = None):
        """Generate script with streaming support for long generation times."""
        # Note: Streaming implementation would depend on backend support
        # For now, fall back to regular generation
        logger.info("Streaming script generation requested, falling back to standard generation")
        return self.generate_script_content(prompt, script_type, context_data, llm_id=llm_id)

    def validate_script_syntax(self, script_content: str, script_type: str,
                              llm_id: Optional[str] = None) -> Dict[str, Any]:
        """Use LLM to validate script syntax and detect common issues."""
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
                LLMMessage(role="user", content=user_prompt)
            ]

            try:
                response = self.backends[backend_id].chat(messages)
                if response and response.content:
                    try:
                        result = json.loads(response.content)
                        logger.info("Script validation completed")
                        return result
                    except json.JSONDecodeError:
                        logger.warning("LLM validation response was not valid JSON")
                        return {
                            "valid": False,
                            "errors": ["Failed to parse validation response"],
                            "raw_response": response.content
                        }
                else:
                    return {"valid": False, "errors": ["Empty LLM response"]}

            except Exception as e:
                logger.error("Script validation failed: %s", e)
                return {"valid": False, "errors": [str(e)]}

    def shutdown(self):
        """Shutdown all LLM backends."""
        with self.lock:
            for _backend in self.backends.values():
                try:
                    _backend.shutdown()
                except (AttributeError, Exception) as e:
                    logger.warning("Error shutting down backend: %s", e)

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
_LLM_MANAGER = None


def get_llm_manager() -> LLMManager:
    """Get the global LLM manager instance."""
    global _LLM_MANAGER  # pylint: disable=global-statement
    if _LLM_MANAGER is None:
        _LLM_MANAGER = LLMManager()
    return _LLM_MANAGER


def shutdown_llm_manager():
    """Shutdown the global LLM manager."""
    global _LLM_MANAGER  # pylint: disable=global-statement
    if _LLM_MANAGER:
        _LLM_MANAGER.shutdown()
        _LLM_MANAGER = None
