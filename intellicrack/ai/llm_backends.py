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
from typing import Any

from ..utils.secrets_manager import get_secret
from .background_loader import LoadingTask, QueuedProgressCallback, get_background_loader
from .llm_types import LoadingState, ProgressCallback

logger = logging.getLogger(__name__)

# Optional imports for ML libraries
HAS_TORCH = False
HAS_TENSORFLOW = False
HAS_NUMPY = False

try:
    import torch
    HAS_TORCH = True

    # Import unified GPU system
    try:
        from ..utils.gpu_autoloader import get_device, get_gpu_info, optimize_for_gpu, to_device
        GPU_AUTOLOADER_AVAILABLE = True
    except ImportError:
        GPU_AUTOLOADER_AVAILABLE = False

except ImportError as e:
    logger.error("Import error in llm_backends: %s", e)
    torch = None
    GPU_AUTOLOADER_AVAILABLE = False

try:
    # Fix PyTorch + TensorFlow import conflict by using GNU threading layer
    import os
    os.environ["MKL_THREADING_LAYER"] = "GNU"

    import tensorflow as tf
    HAS_TENSORFLOW = True
except ImportError as e:
    logger.error("Import error in llm_backends: %s", e)
    tf = None

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError as e:
    logger.error("Import error in llm_backends: %s", e)
    np = None


class LLMProvider(Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
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
    """Configuration for LLM backends."""

    provider: LLMProvider
    model_name: str = None
    api_key: str | None = None
    api_base: str | None = None
    model_path: str | None = None  # For local models
    context_length: int = 4096
    temperature: float = 0.7
    max_tokens: int = 2048
    tools_enabled: bool = True
    custom_params: dict[str, Any] = None
    device: str | None = None  # For ML models
    quantization: str | None = None  # For quantized models
    model: str | None = None  # Alternative name for model_name

    def __post_init__(self):
        """Post-initialization to handle alternative parameter names."""
        # Handle 'model' as alias for 'model_name'
        if self.model and not self.model_name:
            self.model_name = self.model
        elif not self.model_name and not self.model:
            raise ValueError(
                "Either 'model_name' or 'model' must be specified")

        # Set default custom_params if None
        if self.custom_params is None:
            self.custom_params = {}


@dataclass
class LLMMessage:
    """Message structure for LLM communication."""

    role: str  # "system", "user", "assistant", "tool"
    content: str
    tool_calls: list[dict] | None = None
    tool_call_id: str | None = None


@dataclass
class LLMResponse:
    """Response structure from LLM."""

    content: str
    tool_calls: list[dict] | None = None
    usage: dict[str, int] | None = None
    finish_reason: str = "stop"
    model: str = ""


class LLMBackend:
    """Base class for LLM backends."""

    def __init__(self, config: LLMConfig):
        """Initialize the LLM backend with configuration.

        Args:
            config: LLM configuration object

        """
        self.config = config
        self.is_initialized = False
        self.tools = []
        self.logger = logging.getLogger(
            __name__ + "." + self.__class__.__name__)

    def initialize(self) -> bool:
        """Initialize the backend."""
        logger.warning(
            "Base LLMBackend.initialize() called - subclasses should override this method")
        self.is_initialized = False
        return False

    def chat(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse:
        """Send chat messages and get response."""
        # Log the messages and tools for debugging
        logger.debug(
            f"Chat called with {len(messages)} messages and {len(tools or [])} tools")

        logger.error(
            "Base LLMBackend.chat() called - this method must be implemented by subclasses")
        return LLMResponse(
            content="Error: LLM backend not properly initialized. Please use a concrete backend implementation.",
            finish_reason="error",
            model="base_backend_fallback",
        )

    def register_tools(self, tools: list[dict]):
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
        """Initialize OpenAI backend with configuration.

        Args:
            config: LLM configuration object

        """
        super().__init__(config)
        self.client = None

    def initialize(self) -> bool:
        """Initialize OpenAI client."""
        try:
            import openai

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
            logger.info("OpenAI backend initialized with model: %s",
                        self.config.model_name)
            return True

        except ImportError:
            logger.error(
                "OpenAI package not installed. Install with: pip install openai")
            return False
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize OpenAI backend: %s", e)
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse:
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
            "max_tokens": self.config.max_tokens,
        }

        # Add tools if provided and enabled
        if tools and self.config.tools_enabled:
            request_params["tools"] = [
                {"type": "function", "function": _tool} for _tool in tools]
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
        """Initialize Anthropic backend with configuration.

        Args:
            config: LLM configuration object

        """
        super().__init__(config)
        self.client = None

    def initialize(self) -> bool:
        """Initialize Anthropic client."""
        try:
            import anthropic

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
            logger.info("Anthropic backend initialized with model: %s",
                        self.config.model_name)
            return True

        except ImportError:
            logger.error(
                "Anthropic package not installed. Install with: pip install anthropic")
            return False
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize Anthropic backend: %s", e)
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse:
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
                anthropic_messages.append(
                    {"role": _msg.role, "content": _msg.content})

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
        """Initialize llama.cpp backend with configuration.

        Args:
            config: LLM configuration object

        """
        super().__init__(config)
        self.llama = None

    def initialize(self) -> bool:
        """Initialize llama.cpp."""
        try:
            from llama_cpp import Llama

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error("GGUF model file not found: %s",
                             self.config.model_path)
                return False

            # Initialize llama.cpp with GGUF model
            self.llama = Llama(
                model_path=self.config.model_path,
                n_ctx=self.config.context_length,
                verbose=False,
                n_threads=4,  # Adjust based on system
            )

            self.is_initialized = True
            logger.info(
                "llama.cpp backend initialized with GGUF model: %s", self.config.model_path)
            return True

        except ImportError:
            logger.error(
                "llama-cpp-python not installed. Install with: pip install llama-cpp-python")
            return False
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize llama.cpp backend: %s", e)
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse:
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
                stop=["</s>", "<|im_end|>", "<|end|>"],
            )

            content = response["choices"][0]["text"].strip()

            # Handle tool calls if tools are available (basic implementation)
            tool_calls = None
            if tools and self.config.tools_enabled:
                tool_calls = self._extract_tool_calls(content, tools)

            return LLMResponse(
                content=content,
                tool_calls=tool_calls,
                finish_reason=response["choices"][0]["finish_reason"],
                model=self.config.model_name,
            )

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("llama.cpp generation error: %s", e)
            raise

    def _messages_to_prompt(self, messages: list[LLMMessage]) -> str:
        """Convert messages to prompt format."""
        prompt_parts = []

        for _msg in messages:
            if _msg.role == "system":
                prompt_parts.append(
                    f"<|im_start|>system\n{_msg.content}<|im_end|>")
            elif _msg.role == "user":
                prompt_parts.append(
                    f"<|im_start|>user\n{_msg.content}<|im_end|>")
            elif _msg.role == "assistant":
                prompt_parts.append(
                    f"<|im_start|>assistant\n{_msg.content}<|im_end|>")

        prompt_parts.append("<|im_start|>assistant\n")
        return "\n".join(prompt_parts)

    def _extract_tool_calls(self, content: str, tools: list[dict]) -> list[dict] | None:
        """Extract tool calls from generated content (basic implementation)."""
        # This is a simplified implementation
        # In practice, you'd want more sophisticated parsing
        tool_calls = []

        # Look for function call patterns
        for _tool in tools:
            tool_name = _tool["name"]
            pattern = rf"{tool_name}\((.*?)\)"
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
                            "arguments": json.dumps(args),
                        },
                    })
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    logger.error("Error in llm_backends: %s", e)
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
        """Initialize Ollama backend with configuration.

        Args:
            config: LLM configuration object

        """
        super().__init__(config)
        self.base_url = config.api_base or get_secret(
            "OLLAMA_API_BASE", "http://localhost:11434")

    def initialize(self) -> bool:
        """Initialize Ollama connection."""
        try:
            try:
                import requests
            except ImportError:
                logger.error(
                    "requests library not available for Ollama backend")
                return False

            # Test connection to Ollama
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                self.is_initialized = True
                logger.info(
                    "Ollama backend initialized with model: %s", self.config.model_name)
                return True
            logger.error("Ollama not accessible at %s", self.base_url)
            return False

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize Ollama backend: %s", e)
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse:
        """Chat with Ollama model."""
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        try:
            import requests
        except ImportError as e:
            self.logger.error("Import error in llm_backends: %s", e)
            return LLMResponse(
                content="Ollama backend requires 'requests' library",
                finish_reason="error",
            )

        # Convert messages to Ollama format
        ollama_messages = []
        for _msg in messages:
            ollama_messages.append(
                {"role": _msg.role, "content": _msg.content})

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
            logger.debug(f"Adding {len(tools)} tools to Ollama request")

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
        """Initialize Local GGUF backend with configuration.

        Args:
            config: LLM configuration object

        """
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
                logger.error(
                    "GGUF server dependencies not available (need Flask and llama-cpp-python)")
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
                    logger.info(
                        f"Loading GGUF model: {self.config.model_path}")

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
                logger.error("GGUF server not responding properly")
                return False
            except Exception as e:
                logger.error(f"Failed to connect to GGUF server: {e}")
                return False

        except Exception as e:
            logger.error(f"Failed to initialize GGUF backend: {e}")
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse:
        """Chat with local GGUF model."""
        if not self.is_initialized:
            raise RuntimeError("Backend not initialized")

        try:
            import requests
        except ImportError as e:
            self.logger.error("Import error in llm_backends: %s", e)
            return LLMResponse(
                content="GGUF backend requires 'requests' library",
                finish_reason="error",
            )

        # Convert messages to OpenAI-compatible format
        openai_messages = []
        for msg in messages:
            openai_messages.append({
                "role": msg.role,
                "content": msg.content,
            })

        request_data = {
            "model": self.config.model_name,
            "messages": openai_messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "stream": False,
        }

        # Add tools if supported (future enhancement)
        if tools and self.config.tools_enabled:
            # Tools support could be added here in the future
            pass

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

        except Exception as e:
            logger.error(f"GGUF API error: {e}")
            raise

    def shutdown(self):
        """Shutdown GGUF backend."""
        super().shutdown()
        # Could stop the server here, but leave it running for other instances
        # self.gguf_manager.stop_server() if self.gguf_manager else None


class PyTorchLLMBackend(LLMBackend):
    """PyTorch model backend for loading .pth/.pt files."""

    def __init__(self, config: LLMConfig):
        """Initialize PyTorch backend with configuration.

        Args:
            config: LLM configuration object

        """
        super().__init__(config)
        self.model = None
        self.tokenizer = None
        self.device = None
        self.quantization_manager = None

    def initialize(self) -> bool:
        """Initialize PyTorch model and tokenizer."""
        try:
            if not HAS_TORCH:
                raise RuntimeError("PyTorch is not installed")
            from transformers import AutoModelForCausalLM, AutoTokenizer

            from .quantization_manager import get_quantization_manager

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error("PyTorch model file not found: %s",
                             self.config.model_path)
                return False

            # Get device from config or auto-detect
            device_str = self.config.custom_params.get(
                "device", "auto") if self.config.custom_params else "auto"
            if device_str == "auto":
                if GPU_AUTOLOADER_AVAILABLE:
                    device_str = get_device()
                    gpu_info = get_gpu_info()
                    logger.info(f"Using {gpu_info.get('gpu_type', 'unknown')} device: {device_str}")
                elif torch.cuda.is_available():
                    device_str = "cuda"
                    logger.info("Using CUDA device for PyTorch model")
                else:
                    device_str = "cpu"
                    logger.info("Using CPU for PyTorch model")
            else:
                logger.info(f"Using {device_str} device for PyTorch model")

            self.device = torch.device(device_str)

            # Check for quantization settings
            quantization_type = self.config.custom_params.get(
                "quantization", "none") if self.config.custom_params else "none"

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
                model_dir = os.path.dirname(self.config.model_path) if os.path.isfile(
                    self.config.model_path) else self.config.model_path
                self.tokenizer = AutoTokenizer.from_pretrained(
                    model_dir, trust_remote_code=True)
            else:
                # Standard loading without quantization
                logger.info("Loading PyTorch model from: %s",
                            self.config.model_path)

                # Try to load associated config.json for model architecture
                model_dir = os.path.dirname(self.config.model_path)
                config_path = os.path.join(model_dir, "config.json")

                if os.path.exists(config_path):
                    # Load from directory with config
                    self.model = AutoModelForCausalLM.from_pretrained(
                        model_dir,
                        torch_dtype=torch.float16 if self.device.type in ["cuda", "xpu"] else torch.float32,
                        device_map="auto" if self.device.type in ["cuda", "xpu"] else None,
                        trust_remote_code=True,
                    )
                    self.tokenizer = AutoTokenizer.from_pretrained(
                        model_dir, trust_remote_code=True)
                else:
                    # Load raw checkpoint - need model name for architecture
                    if not self.config.model_name:
                        logger.error(
                            "Model name required for loading raw PyTorch checkpoint")
                        return False

                    # Load tokenizer from model name
                    self.tokenizer = AutoTokenizer.from_pretrained(
                        self.config.model_name, trust_remote_code=True)

                    # Load model architecture and weights
                    self.model = AutoModelForCausalLM.from_pretrained(
                        self.config.model_name,
                        torch_dtype=torch.float16 if self.device.type in ["cuda", "xpu"] else torch.float32,
                        trust_remote_code=True,
                    )

                    # Load checkpoint weights
                    checkpoint = torch.load(
                        self.config.model_path, map_location=self.device)
                    if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint:
                        self.model.load_state_dict(
                            checkpoint["model_state_dict"])
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
            logger.info("PyTorch backend initialized with model: %s",
                        self.config.model_name or "custom")
            return True

        except ImportError:
            logger.error(
                "PyTorch or transformers not installed. Install with: pip install torch transformers")
            return False
        except Exception as e:
            logger.error("Failed to initialize PyTorch backend: %s", e)
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse:
        """Generate response using PyTorch model."""
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
            inputs = self.tokenizer(
                prompt, return_tensors="pt", truncation=True, max_length=self.config.context_length)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            # Generate
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    do_sample=True if self.config.temperature > 0 else False,
                    pad_token_id=self.tokenizer.eos_token_id,
                )

            # Decode response
            response = self.tokenizer.decode(
                outputs[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True)

            return LLMResponse(
                content=response,
                finish_reason="stop",
                model=self.config.model_name or "pytorch_model",
            )

        except Exception as e:
            logger.error("PyTorch generation error: %s", e)
            raise

    def shutdown(self):
        """Shutdown PyTorch backend."""
        super().shutdown()
        if self.model is not None:
            del self.model
            self.model = None
        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None

        # Clear GPU cache
        try:
            if GPU_AUTOLOADER_AVAILABLE:
                from ..utils.gpu_autoloader import empty_cache
                empty_cache()
            elif HAS_TORCH and torch.cuda.is_available():
                torch.cuda.empty_cache()
        except Exception as e:
            logger.debug(f"Could not clear GPU cache: {e}")


class TensorFlowLLMBackend(LLMBackend):
    """TensorFlow model backend for loading .h5 and SavedModel formats."""

    def __init__(self, config: LLMConfig):
        """Initialize TensorFlow backend with configuration.

        Args:
            config: LLM configuration object

        """
        super().__init__(config)
        self.model = None
        self.tokenizer = None

    def initialize(self) -> bool:
        """Initialize TensorFlow model."""
        try:
            if not HAS_TENSORFLOW:
                raise RuntimeError("TensorFlow is not installed")
            from transformers import AutoTokenizer, TFAutoModelForCausalLM

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error("TensorFlow model path not found: %s",
                             self.config.model_path)
                return False

            # Check GPU availability
            gpus = tf.config.list_physical_devices("GPU")
            if gpus:
                logger.info("Using GPU for TensorFlow model: %s", gpus[0])
            else:
                logger.info("Using CPU for TensorFlow model")

            # Load model
            logger.info("Loading TensorFlow model from: %s",
                        self.config.model_path)

            if os.path.isdir(self.config.model_path):
                # SavedModel format
                if os.path.exists(os.path.join(self.config.model_path, "saved_model.pb")):
                    self.model = tf.keras.models.load_model(
                        self.config.model_path)
                else:
                    # Try as transformers model directory
                    self.model = TFAutoModelForCausalLM.from_pretrained(
                        self.config.model_path)
                    self.tokenizer = AutoTokenizer.from_pretrained(
                        self.config.model_path)
            # .h5 file
            elif self.config.model_path.endswith(".h5"):
                if not self.config.model_name:
                    logger.error(
                        "Model name required for loading .h5 files")
                    return False

                # Load base model and weights
                self.model = TFAutoModelForCausalLM.from_pretrained(
                    self.config.model_name)
                self.model.load_weights(self.config.model_path)
                self.tokenizer = AutoTokenizer.from_pretrained(
                    self.config.model_name)

            if self.tokenizer is None and self.config.model_name:
                # Try to load tokenizer from model name
                self.tokenizer = AutoTokenizer.from_pretrained(
                    self.config.model_name)

            self.is_initialized = True
            logger.info("TensorFlow backend initialized")
            return True

        except ImportError:
            logger.error(
                "TensorFlow not installed. Install with: pip install tensorflow")
            return False
        except Exception as e:
            logger.error("Failed to initialize TensorFlow backend: %s", e)
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse:
        """Generate response using TensorFlow model."""
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
            inputs = self.tokenizer(
                prompt, return_tensors="tf", truncation=True, max_length=self.config.context_length)

            # Generate
            outputs = self.model.generate(
                inputs.input_ids,
                max_new_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                do_sample=True if self.config.temperature > 0 else False,
                pad_token_id=self.tokenizer.eos_token_id,
            )

            # Decode response
            response = self.tokenizer.decode(
                outputs[0][len(inputs.input_ids[0]):], skip_special_tokens=True)

            return LLMResponse(
                content=response,
                finish_reason="stop",
                model=self.config.model_name or "tensorflow_model",
            )

        except Exception as e:
            logger.error("TensorFlow generation error: %s", e)
            raise

    def shutdown(self):
        """Shutdown TensorFlow backend."""
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
            logger.debug(f"Could not clear TensorFlow session: {e}")


class ONNXLLMBackend(LLMBackend):
    """ONNX model backend for loading .onnx files."""

    def __init__(self, config: LLMConfig):
        """Initialize ONNX backend with configuration.

        Args:
            config: LLM configuration object

        """
        super().__init__(config)
        self.session = None
        self.tokenizer = None

    def initialize(self) -> bool:
        """Initialize ONNX model."""
        try:
            import onnxruntime as ort
            from transformers import AutoTokenizer

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error("ONNX model file not found: %s",
                             self.config.model_path)
                return False

            # Create inference session
            providers = ["CUDAExecutionProvider", "CPUExecutionProvider"]
            self.session = ort.InferenceSession(
                self.config.model_path, providers=providers)

            # Log which provider is being used
            actual_provider = self.session.get_providers()[0]
            logger.info("Using %s for ONNX inference", actual_provider)

            # Load tokenizer
            if self.config.model_name:
                self.tokenizer = AutoTokenizer.from_pretrained(
                    self.config.model_name)
            else:
                # Try to load from same directory
                model_dir = os.path.dirname(self.config.model_path)
                tokenizer_files = ["tokenizer.json", "tokenizer_config.json"]
                if any(os.path.exists(os.path.join(model_dir, f)) for f in tokenizer_files):
                    self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
                else:
                    logger.error(
                        "Tokenizer not found. Specify model_name for tokenizer loading")
                    return False

            self.is_initialized = True
            logger.info("ONNX backend initialized")
            return True

        except ImportError:
            logger.error(
                "ONNX Runtime not installed. Install with: pip install onnxruntime")
            return False
        except Exception as e:
            logger.error("Failed to initialize ONNX backend: %s", e)
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse:
        """Generate response using ONNX model."""
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
            inputs = self.tokenizer(
                prompt, return_tensors="np", truncation=True, max_length=self.config.context_length)

            # Get input names from session
            input_names = [inp.name for inp in self.session.get_inputs()]
            output_names = [out.name for out in self.session.get_outputs()]

            # Prepare inputs
            ort_inputs = {}
            for name in input_names:
                if name == "input_ids":
                    ort_inputs[name] = inputs["input_ids"]
                elif name == "attention_mask":
                    ort_inputs[name] = inputs.get(
                        "attention_mask", np.ones_like(inputs["input_ids"]))

            # Run inference
            outputs = self.session.run(output_names, ort_inputs)

            # Simple greedy decoding (for demonstration)
            # In practice, you'd want beam search or sampling
            logits = outputs[0]
            predicted_ids = np.argmax(logits, axis=-1)

            # Decode response
            response = self.tokenizer.decode(
                predicted_ids[0], skip_special_tokens=True)

            # Extract only the generated part
            if prompt in response:
                response = response[len(prompt):]

            return LLMResponse(
                content=response,
                finish_reason="stop",
                model=self.config.model_name or "onnx_model",
            )

        except Exception as e:
            logger.error("ONNX generation error: %s", e)
            raise

    def shutdown(self):
        """Shutdown ONNX backend."""
        super().shutdown()
        if self.session is not None:
            del self.session
            self.session = None
        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None


class SafetensorsBackend(LLMBackend):
    """Safetensors model backend for loading .safetensors files."""

    def __init__(self, config: LLMConfig):
        """Initialize Safetensors backend with configuration.

        Args:
            config: LLM configuration object

        """
        super().__init__(config)
        self.model = None
        self.tokenizer = None
        self.device = None

    def initialize(self) -> bool:
        """Initialize Safetensors model."""
        try:
            if not HAS_TORCH:
                raise RuntimeError("PyTorch is not installed")
            from safetensors.torch import load_file
            from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error("Safetensors model file not found: %s",
                             self.config.model_path)
                return False

            # Detect device
            if GPU_AUTOLOADER_AVAILABLE:
                device_str = get_device()
                gpu_info = get_gpu_info()
                self.device = torch.device(device_str)
                logger.info(f"Using {gpu_info.get('gpu_type', 'unknown')} device for Safetensors model: {device_str}")
            elif torch.cuda.is_available():
                self.device = torch.device("cuda")
                logger.info("Using CUDA device for Safetensors model")
            else:
                self.device = torch.device("cpu")
                logger.info("Using CPU for Safetensors model")

            # Load model
            logger.info("Loading Safetensors model from: %s",
                        self.config.model_path)

            # Check if this is a single file or directory
            if os.path.isfile(self.config.model_path):
                # Single safetensors file - need config
                model_dir = os.path.dirname(self.config.model_path)
                config_path = os.path.join(model_dir, "config.json")

                if os.path.exists(config_path):
                    # Load config and initialize model
                    config = AutoConfig.from_pretrained(model_dir)
                    self.model = AutoModelForCausalLM.from_config(config)

                    # Load weights from safetensors
                    state_dict = load_file(self.config.model_path)
                    self.model.load_state_dict(state_dict)

                    # Load tokenizer
                    self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
                else:
                    # Need model name for architecture
                    if not self.config.model_name:
                        logger.error(
                            "Model name required for loading single safetensors file")
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
                    self.tokenizer = AutoTokenizer.from_pretrained(
                        self.config.model_name)
            else:
                # Directory with safetensors files
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.config.model_path,
                    torch_dtype=torch.float16 if self.device.type == "cuda" else torch.float32,
                    device_map="auto" if self.device.type in ["cuda", "xpu"] else None,
                )
                self.tokenizer = AutoTokenizer.from_pretrained(
                    self.config.model_path)

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
            logger.error(
                "safetensors not installed. Install with: pip install safetensors")
            return False
        except Exception as e:
            logger.error("Failed to initialize Safetensors backend: %s", e)
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse:
        """Generate response using Safetensors model."""
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
            inputs = self.tokenizer(
                prompt, return_tensors="pt", truncation=True, max_length=self.config.context_length)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            # Generate
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    do_sample=True if self.config.temperature > 0 else False,
                    pad_token_id=self.tokenizer.eos_token_id,
                )

            # Decode response
            response = self.tokenizer.decode(
                outputs[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True)

            return LLMResponse(
                content=response,
                finish_reason="stop",
                model=self.config.model_name or "safetensors_model",
            )

        except Exception as e:
            logger.error("Safetensors generation error: %s", e)
            raise

    def shutdown(self):
        """Shutdown Safetensors backend."""
        super().shutdown()
        if self.model is not None:
            del self.model
            self.model = None
        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None

        # Clear GPU cache
        try:
            if GPU_AUTOLOADER_AVAILABLE:
                from ..utils.gpu_autoloader import empty_cache
                empty_cache()
            elif HAS_TORCH and torch.cuda.is_available():
                torch.cuda.empty_cache()
        except Exception as e:
            logger.debug(f"Could not clear GPU cache: {e}")


class GPTQBackend(LLMBackend):
    """GPTQ quantized model backend."""

    def __init__(self, config: LLMConfig):
        """Initialize GPTQ backend with configuration.

        Args:
            config: LLM configuration object

        """
        super().__init__(config)
        self.model = None
        self.tokenizer = None
        self.device = None

    def initialize(self) -> bool:
        """Initialize GPTQ model."""
        try:
            if not HAS_TORCH:
                raise RuntimeError("PyTorch is not installed")
            from auto_gptq import AutoGPTQForCausalLM
            from transformers import AutoTokenizer

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error("GPTQ model path not found: %s",
                             self.config.model_path)
                return False

            # GPTQ requires GPU
            if GPU_AUTOLOADER_AVAILABLE:
                device_str = get_device()
                gpu_info = get_gpu_info()
                if not gpu_info["available"] or device_str == "cpu":
                    logger.error("GPTQ models require GPU")
                    return False
                self.device = torch.device(device_str)
                logger.info(f"Using {gpu_info.get('gpu_type', 'unknown')} device for GPTQ model: {device_str}")
            elif torch.cuda.is_available():
                self.device = torch.device("cuda")
                logger.info("Using CUDA device for GPTQ model")
            else:
                logger.error("GPTQ models require GPU")
                return False

            # Load model
            logger.info("Loading GPTQ model from: %s", self.config.model_path)

            # GPTQ models are typically in directories
            if os.path.isdir(self.config.model_path):
                self.model = AutoGPTQForCausalLM.from_quantized(
                    self.config.model_path,
                    use_safetensors=True,
                    device=str(self.device),
                    use_triton=False,
                    quantize_config=None,
                )
                self.tokenizer = AutoTokenizer.from_pretrained(
                    self.config.model_path)
            else:
                logger.error(
                    "GPTQ models should be in a directory with config files")
                return False

            self.is_initialized = True
            logger.info("GPTQ backend initialized")
            return True

        except ImportError:
            logger.error(
                "auto-gptq not installed. Install with: pip install auto-gptq")
            return False
        except Exception as e:
            logger.error("Failed to initialize GPTQ backend: %s", e)
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse:
        """Generate response using GPTQ model."""
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
            inputs = self.tokenizer(
                prompt, return_tensors="pt", truncation=True, max_length=self.config.context_length)
            inputs = inputs.to(self.device)

            # Generate
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                do_sample=True if self.config.temperature > 0 else False,
            )

            # Decode response
            response = self.tokenizer.decode(
                outputs[0][inputs.input_ids.shape[-1]:], skip_special_tokens=True)

            return LLMResponse(
                content=response,
                finish_reason="stop",
                model=self.config.model_name or "gptq_model",
            )

        except Exception as e:
            logger.error("GPTQ generation error: %s", e)
            raise

    def shutdown(self):
        """Shutdown GPTQ backend."""
        super().shutdown()
        if self.model is not None:
            del self.model
            self.model = None
        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None

        # Clear GPU cache
        try:
            if GPU_AUTOLOADER_AVAILABLE:
                from ..utils.gpu_autoloader import empty_cache
                empty_cache()
            elif HAS_TORCH and torch.cuda.is_available():
                torch.cuda.empty_cache()
        except Exception as e:
            logger.debug(f"Could not clear GPU cache: {e}")


class HuggingFaceLocalBackend(LLMBackend):
    """Hugging Face local model backend for loading from directories."""

    def __init__(self, config: LLMConfig):
        """Initialize Hugging Face Local backend with configuration.

        Args:
            config: LLM configuration object

        """
        super().__init__(config)
        self.model = None
        self.tokenizer = None
        self.device = None
        self.quantization_manager = None

    def initialize(self) -> bool:
        """Initialize Hugging Face model from local directory."""
        try:
            if not HAS_TORCH:
                raise RuntimeError("PyTorch is not installed")
            from accelerate import init_empty_weights, load_checkpoint_and_dispatch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            if not self.config.model_path or not os.path.exists(self.config.model_path):
                logger.error(
                    "Hugging Face model directory not found: %s", self.config.model_path)
                return False

            if not os.path.isdir(self.config.model_path):
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
                logger.info(f"Using {gpu_info.get('gpu_type', 'unknown')} device for Hugging Face model: {device_str}")
            elif torch.cuda.is_available():
                self.device = torch.device("cuda")
                logger.info("Using CUDA device for Hugging Face model")
            else:
                self.device = torch.device("cpu")
                logger.info("Using CPU for Hugging Face model")

            # Load model
            logger.info("Loading Hugging Face model from: %s",
                        self.config.model_path)

            # Check model size and available memory
            model_size = sum(os.path.getsize(os.path.join(self.config.model_path, f))
                             for f in os.listdir(self.config.model_path)
                             if f.endswith((".bin", ".safetensors")))

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
                    torch_dtype=torch.float16 if self.device.type in ["cuda", "xpu"] else torch.float32,
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
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.config.model_path, trust_remote_code=True)

            # Set pad token if not set
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            # Use init_empty_weights and load_checkpoint_and_dispatch for very large models
            if model_size > 30e9 and gpu_available:
                logger.info("Using accelerate load_checkpoint_and_dispatch for very large model")
                with init_empty_weights():
                    # Initialize empty model skeleton
                    from transformers import AutoConfig
                    config = AutoConfig.from_pretrained(self.config.model_path)
                    empty_model = AutoModelForCausalLM.from_config(config)

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

        except ImportError as e:
            logger.error("Required libraries not installed: %s", e)
            logger.error("Install with: pip install transformers accelerate")
            return False
        except Exception as e:
            logger.error("Failed to initialize Hugging Face backend: %s", e)
            return False

    def chat(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> LLMResponse:
        """Generate response using Hugging Face model."""
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
                # Use chat template
                chat_messages = []
                for msg in messages:
                    chat_messages.append(
                        {"role": msg.role, "content": msg.content})

                prompt = self.tokenizer.apply_chat_template(
                    chat_messages,
                    tokenize=False,
                    add_generation_prompt=True,
                )
            else:
                # Fallback to simple format
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
            inputs = self.tokenizer(
                prompt, return_tensors="pt", truncation=True, max_length=self.config.context_length)
            inputs = {k: v.to(self.model.device) for k, v in inputs.items()}

            # Generate
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    do_sample=True if self.config.temperature > 0 else False,
                    pad_token_id=self.tokenizer.pad_token_id,
                    eos_token_id=self.tokenizer.eos_token_id,
                )

            # Decode response
            response = self.tokenizer.decode(
                outputs[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True)

            return LLMResponse(
                content=response,
                finish_reason="stop",
                model=self.config.model_name or os.path.basename(
                    self.config.model_path),
            )

        except Exception as e:
            logger.error("Hugging Face generation error: %s", e)
            raise

    def shutdown(self):
        """Shutdown Hugging Face backend."""
        super().shutdown()
        if self.model is not None:
            del self.model
            self.model = None
        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None

        # Clear GPU cache
        try:
            if GPU_AUTOLOADER_AVAILABLE:
                from ..utils.gpu_autoloader import empty_cache
                empty_cache()
            elif HAS_TORCH and torch.cuda.is_available():
                torch.cuda.empty_cache()
        except Exception as e:
            logger.debug(f"Could not clear GPU cache: {e}")


class LLMManager:
    """Manager for LLM backends and configurations with lazy loading support."""

    def __init__(self, enable_lazy_loading: bool = True, enable_background_loading: bool = True):
        """Initialize LLM Manager with lazy and background loading options.

        Args:
            enable_lazy_loading: Whether to enable lazy loading of models
            enable_background_loading: Whether to enable background loading

        """
        self.backends = {}
        self.configs = {}
        self.active_backend = None
        self.lock = threading.RLock()
        self.enable_lazy_loading = enable_lazy_loading
        self.enable_background_loading = enable_background_loading

        # Lazy loading support
        if enable_lazy_loading:
            try:
                from .lazy_model_loader import get_lazy_manager
                self.lazy_manager = get_lazy_manager()
                self.lazy_wrappers = {}
                logger.info(
                    "LLM Manager initialized with lazy loading support")
            except ImportError as e:
                logger.warning("Lazy loading not available: %s", e)
                self.enable_lazy_loading = False
                self.lazy_manager = None
                self.lazy_wrappers = {}
        else:
            self.lazy_manager = None
            self.lazy_wrappers = {}

        # Background loading support
        if enable_background_loading:
            self.background_loader = get_background_loader(self)
            self.progress_callbacks = []
            self.loading_tasks = {}
            logger.info("LLM Manager initialized with background loading support")
        else:
            self.background_loader = None
            self.progress_callbacks = []
            self.loading_tasks = {}

        logger.info("LLM Manager initialized")

    def register_llm(self, llm_id: str, config: LLMConfig, use_lazy_loading: bool | None = None) -> bool:
        """Register an LLM configuration with optional lazy loading."""
        with self.lock:
            try:
                # Determine if we should use lazy loading
                use_lazy = use_lazy_loading if use_lazy_loading is not None else self.enable_lazy_loading

                if use_lazy and self.lazy_manager:
                    # Register with lazy loading
                    backend_class = self._get_backend_class(config.provider)
                    if backend_class is None:
                        raise ValueError(
                            f"Unsupported LLM provider: {config.provider}")

                    wrapper = self.lazy_manager.register_model(
                        llm_id, backend_class, config)
                    self.lazy_wrappers[llm_id] = wrapper
                    self.configs[llm_id] = config

                    # Set as active if first one
                    if not self.active_backend:
                        self.active_backend = llm_id

                    logger.info("Registered lazy LLM: %s (%s)",
                                llm_id, config.provider.value)
                    return True
                # Standard immediate loading
                backend_class = self._get_backend_class(config.provider)
                if backend_class is None:
                    raise ValueError(
                        f"Unsupported LLM provider: {config.provider}")

                backend = backend_class(config)

                # Initialize backend
                if not backend.initialize():
                    logger.error(
                        "Failed to initialize LLM backend: %s", llm_id)
                    return False

                self.backends[llm_id] = backend
                self.configs[llm_id] = config

                # Set as active if first one
                if not self.active_backend:
                    self.active_backend = llm_id

                logger.info("Registered LLM: %s (%s)",
                            llm_id, config.provider.value)
                return True

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Failed to register LLM %s: %s", llm_id, e)
                return False

    def _get_backend_class(self, provider: LLMProvider):
        """Get the backend class for a given provider."""
        backend_classes = {
            LLMProvider.OPENAI: OpenAIBackend,
            LLMProvider.ANTHROPIC: AnthropicBackend,
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
        """Set the active LLM for inference."""
        with self.lock:
            if llm_id not in self.backends:
                logger.error("LLM not registered: %s", llm_id)
                return False

            self.active_backend = llm_id
            logger.info("Set active LLM: %s", llm_id)
            return True

    def chat(self, messages: list[LLMMessage], llm_id: str | None = None,
             tools: list[dict] | None = None) -> LLMResponse | None:
        """Send chat messages to LLM."""
        with self.lock:
            backend_id = llm_id or self.active_backend

            if not backend_id:
                logger.error("No active LLM backend available")
                return None

            # Try to get backend from lazy loading first
            backend = None
            if backend_id in self.lazy_wrappers:
                if self.lazy_manager:
                    backend = self.lazy_manager.get_model(backend_id)
                    if backend is None:
                        logger.error(
                            "Failed to load lazy LLM backend: %s", backend_id)
                        return None
            elif backend_id in self.backends:
                backend = self.backends[backend_id]
            else:
                logger.error("LLM backend not found: %s", backend_id)
                return None

            try:
                response = backend.chat(messages, tools)
                logger.debug("LLM response from %s: %d chars",
                             backend_id, len(response.content))
                return response

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("LLM chat error: %s", e)
                return None

    def get_available_llms(self) -> list[str]:
        """Get list of available LLM IDs."""
        # Combine both immediate and lazy-loaded backends
        immediate_llms = set(self.backends.keys())
        lazy_llms = set(self.lazy_wrappers.keys())
        return list(immediate_llms.union(lazy_llms))

    def get_llm_info(self, llm_id: str) -> dict[str, Any] | None:
        """Get information about an LLM."""
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

    def register_tools_for_llm(self, llm_id: str, tools: list[dict]):
        """Register tools for a specific LLM."""
        if llm_id in self.backends:
            self.backends[llm_id].register_tools(tools)
            logger.info("Registered %d tools for LLM: %s", len(tools), llm_id)

    def generate_script_content(self, prompt: str, script_type: str, context_data: dict[str, Any] = None,
                                max_tokens: int = 4000, llm_id: str | None = None) -> str | None:
        """Generate script content using LLM."""
        with self.lock:
            backend_id = llm_id or self.active_backend

            if not backend_id or backend_id not in self.backends:
                logger.error(
                    "No active LLM backend available for script generation")
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
                LLMMessage(role="user", content=prompt),
            ]

            # Update token limit for the backend if possible
            backend = self.backends[backend_id]
            original_max_tokens = backend.config.max_tokens
            backend.config.max_tokens = max_tokens

            try:
                response = backend.chat(messages)
                if response and response.content:
                    logger.info("Generated %s script: %d characters",
                                script_type, len(response.content))
                    return response.content.strip()
                logger.error(
                    "LLM returned empty response for script generation")
                return None

            except Exception as e:
                logger.error("Script generation failed: %s", e)
                return None
            finally:
                # Restore original token limit
                backend.config.max_tokens = original_max_tokens

    def refine_script_content(self, original_script: str, error_feedback: str,
                              test_results: dict[str, Any], script_type: str,
                              llm_id: str | None = None) -> str | None:
        """Refine existing script based on test results and feedback."""
        with self.lock:
            backend_id = llm_id or self.active_backend

            if not backend_id or backend_id not in self.backends:
                logger.error(
                    "No active LLM backend available for script refinement")
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
                LLMMessage(role="user", content=user_prompt),
            ]

            try:
                response = self.backends[backend_id].chat(messages)
                if response and response.content:
                    logger.info("Refined %s script: %d characters",
                                script_type, len(response.content))
                    return response.content.strip()
                logger.error(
                    "LLM returned empty response for script refinement")
                return None

            except Exception as e:
                logger.error("Script refinement failed: %s", e)
                return None

    def analyze_protection_patterns(self, binary_data: dict[str, Any],
                                    llm_id: str | None = None) -> dict[str, Any] | None:
        """Analyze binary data to identify protection patterns."""
        with self.lock:
            backend_id = llm_id or self.active_backend

            if not backend_id or backend_id not in self.backends:
                logger.error(
                    "No active LLM backend available for pattern analysis")
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
                    # Try to parse as JSON
                    try:
                        result = json.loads(response.content)
                        logger.info("Protection pattern analysis completed")
                        return result
                    except json.JSONDecodeError:
                        # Return as text if not valid JSON
                        logger.warning(
                            "LLM response was not valid JSON, returning as text")
                        return {"analysis": response.content}
                else:
                    logger.error(
                        "LLM returned empty response for pattern analysis")
                    return None

            except Exception as e:
                logger.error("Protection pattern analysis failed: %s", e)
                return None

    def stream_script_generation(self, prompt: str, script_type: str,
                                 context_data: dict[str, Any] = None,
                                 llm_id: str | None = None):
        """Generate script with streaming support for long generation times."""
        # Note: Streaming implementation would depend on backend support
        # For now, fall back to regular generation
        logger.info(
            "Streaming script generation requested, falling back to standard generation")
        return self.generate_script_content(prompt, script_type, context_data, llm_id=llm_id)

    def validate_script_syntax(self, script_content: str, script_type: str,
                               llm_id: str | None = None) -> dict[str, Any]:
        """Use LLM to validate script syntax and detect common issues."""
        with self.lock:
            backend_id = llm_id or self.active_backend

            if not backend_id or backend_id not in self.backends:
                logger.error(
                    "No active LLM backend available for script validation")
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
                if response and response.content:
                    try:
                        result = json.loads(response.content)
                        logger.info("Script validation completed")
                        return result
                    except json.JSONDecodeError:
                        logger.warning(
                            "LLM validation response was not valid JSON")
                        return {
                            "valid": False,
                            "errors": ["Failed to parse validation response"],
                            "raw_response": response.content,
                        }
                else:
                    return {"valid": False, "errors": ["Empty LLM response"]}

            except Exception as e:
                logger.error("Script validation failed: %s", e)
                return {"valid": False, "errors": [str(e)]}

    def shutdown(self):
        """Shutdown all LLM backends."""
        with self.lock:
            # Shutdown background loader if enabled
            if self.background_loader:
                self.background_loader.shutdown()

            for _backend in self.backends.values():
                try:
                    _backend.shutdown()
                except (AttributeError, Exception) as e:
                    logger.warning("Error shutting down backend: %s", e)

            self.backends.clear()
            self.configs.clear()
            self.active_backend = None

            logger.info("LLM Manager shutdown complete")

    # Background loading methods
    def add_progress_callback(self, callback: ProgressCallback):
        """Add a progress callback for model loading."""
        if self.background_loader:
            self.background_loader.add_progress_callback(callback)
            self.progress_callbacks.append(callback)

    def add_queued_progress_callback(self, callback: ProgressCallback | QueuedProgressCallback):
        """Add a queued progress callback that buffers progress updates."""
        if self.background_loader:
            # If it's a regular callback, wrap it in a QueuedProgressCallback
            if not isinstance(callback, QueuedProgressCallback):
                callback = QueuedProgressCallback(callback, update_interval=0.5)
            self.background_loader.add_progress_callback(callback)
            self.progress_callbacks.append(callback)

    def remove_progress_callback(self, callback: ProgressCallback):
        """Remove a progress callback."""
        if self.background_loader:
            self.background_loader.remove_progress_callback(callback)
            if callback in self.progress_callbacks:
                self.progress_callbacks.remove(callback)

    def load_model_in_background(self, llm_id: str, config: LLMConfig,
                                priority: int = 0, callback: ProgressCallback | None = None) -> LoadingTask | None:
        """Load a model in the background with progress tracking."""
        if not self.background_loader:
            logger.warning("Background loading not enabled")
            return None

        with self.lock:
            try:
                backend_class = self._get_backend_class(config.provider)
                if backend_class is None:
                    raise ValueError(f"Unsupported LLM provider: {config.provider}")

                # Add global callbacks if any
                if callback:
                    self.add_progress_callback(callback)

                # Submit loading task
                task = self.background_loader.load_model_in_background(
                    model_id=llm_id,
                    backend_class=backend_class,
                    config=config,
                    priority=priority,
                )

                self.loading_tasks[llm_id] = task

                # Store config for later reference
                self.configs[llm_id] = config

                logger.info("Submitted background loading task for: %s", llm_id)
                return task

            except Exception as e:
                logger.error("Failed to submit background loading task: %s", e)
                return None

    def get_loading_progress(self, llm_id: str) -> LoadingTask | None:
        """Get loading progress for a model."""
        if self.background_loader:
            return self.background_loader.get_loading_progress(llm_id)
        return None

    def cancel_loading(self, llm_id: str) -> bool:
        """Cancel loading a model."""
        if self.background_loader:
            success = self.background_loader.cancel_loading(llm_id)
            if success and llm_id in self.loading_tasks:
                del self.loading_tasks[llm_id]
            return success
        return False

    def get_all_loading_tasks(self) -> dict[str, LoadingTask]:
        """Get all loading tasks."""
        if self.background_loader:
            return self.background_loader.get_all_loading_tasks()
        return {}

    def get_loading_statistics(self) -> dict[str, Any]:
        """Get loading statistics."""
        if self.background_loader:
            return self.background_loader.get_statistics()
        return {
            "pending": 0,
            "active": 0,
            "completed": 0,
            "success_rate": 0.0,
        }

    def register_background_loaded_model(self, llm_id: str, task: LoadingTask) -> bool:
        """Register a model that was loaded in the background."""
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
        """Unload a specific LLM to free memory."""
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

    def unload_all_llms(self):
        """Unload all LLMs to free memory."""
        with self.lock:
            # Unload lazy models
            for wrapper in self.lazy_wrappers.values():
                wrapper.unload()

            # Clear immediate backends
            self.backends.clear()
            self.active_backend = None

            logger.info("Unloaded all LLMs")

    def get_memory_usage(self) -> dict[str, Any]:
        """Get memory usage information for all models."""
        memory_info = {
            "immediate_models": {},
            "lazy_models": {},
            "total_loaded": 0,
        }

        # Get info for immediate models
        for llm_id in self.backends:
            memory_info["immediate_models"][llm_id] = "Loaded"
            memory_info["total_loaded"] += 1

        # Get info for lazy models
        for llm_id, wrapper in self.lazy_wrappers.items():
            wrapper_info = wrapper.get_info()
            memory_info["lazy_models"][llm_id] = {
                "is_loaded": wrapper_info["is_loaded"],
                "memory_usage": wrapper_info["memory_usage"],
                "access_count": wrapper_info["access_count"],
            }
            if wrapper_info["is_loaded"]:
                memory_info["total_loaded"] += 1

        return memory_info

    def configure_lazy_loading(self,
                               max_loaded_models: int = 3,
                               idle_unload_time: int = 1800):
        """Configure lazy loading parameters."""
        if self.lazy_manager:
            self.lazy_manager.max_loaded_models = max_loaded_models
            self.lazy_manager.idle_unload_time = idle_unload_time
            logger.info("Updated lazy loading config: max_models=%d, idle_time=%d",
                        max_loaded_models, idle_unload_time)

    def preload_model(self, llm_id: str) -> bool:
        """Manually preload a lazy model."""
        if llm_id in self.lazy_wrappers:
            wrapper = self.lazy_wrappers[llm_id]
            backend = wrapper.get_backend()
            return backend is not None
        return False

    def add_llm(self, llm_id: str, config: LLMConfig) -> bool:
        """Add an LLM with the given configuration (alias for register_llm)."""
        return self.register_llm(llm_id, config)

    def get_llm(self, llm_id: str) -> Any | None:
        """Get an LLM backend by ID."""
        with self.lock:
            # First try to get from immediate backends
            if llm_id in self.backends:
                return self.backends[llm_id]

            # Try to get from lazy wrappers
            if llm_id in self.lazy_wrappers and self.lazy_manager:
                return self.lazy_manager.get_model(llm_id)

            return None

    def list_llms(self) -> list[str]:
        """List all available LLM IDs (alias for get_available_llms)."""
        return self.get_available_llms()


# Convenience functions for creating common configurations
def create_openai_config(model_name: str = "gpt-4", api_key: str = None, **kwargs) -> LLMConfig:
    """Create OpenAI configuration."""
    return LLMConfig(
        provider=LLMProvider.OPENAI,
        model_name=model_name,
        api_key=api_key,
        **kwargs,
    )


def create_anthropic_config(model_name: str = "claude-3-5-sonnet-20241022", api_key: str = None, **kwargs) -> LLMConfig:
    """Create Anthropic configuration."""
    return LLMConfig(
        provider=LLMProvider.ANTHROPIC,
        model_name=model_name,
        api_key=api_key,
        **kwargs,
    )


def create_gguf_config(model_path: str, model_name: str = None, **kwargs) -> LLMConfig:
    """Create GGUF model configuration."""
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.LLAMACPP,
        model_name=model_name,
        model_path=model_path,
        **kwargs,
    )


def create_ollama_config(model_name: str, api_base: str = None, **kwargs) -> LLMConfig:
    """Create Ollama configuration."""
    return LLMConfig(
        provider=LLMProvider.OLLAMA,
        model_name=model_name,
        api_base=api_base or "http://localhost:11434",
        **kwargs,
    )


def create_pytorch_config(model_path: str, model_name: str = None, **kwargs) -> LLMConfig:
    """Create PyTorch model configuration."""
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.PYTORCH,
        model_name=model_name,
        model_path=model_path,
        **kwargs,
    )


def create_tensorflow_config(model_path: str, model_name: str = None, **kwargs) -> LLMConfig:
    """Create TensorFlow model configuration."""
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.TENSORFLOW,
        model_name=model_name,
        model_path=model_path,
        **kwargs,
    )


def create_onnx_config(model_path: str, model_name: str = None, **kwargs) -> LLMConfig:
    """Create ONNX model configuration."""
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.ONNX,
        model_name=model_name,
        model_path=model_path,
        **kwargs,
    )


def create_safetensors_config(model_path: str, model_name: str = None, **kwargs) -> LLMConfig:
    """Create Safetensors model configuration."""
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.SAFETENSORS,
        model_name=model_name,
        model_path=model_path,
        **kwargs,
    )


def create_gptq_config(model_path: str, model_name: str = None, **kwargs) -> LLMConfig:
    """Create GPTQ model configuration."""
    if not model_name:
        model_name = os.path.basename(model_path)

    return LLMConfig(
        provider=LLMProvider.GPTQ,
        model_name=model_name,
        model_path=model_path,
        **kwargs,
    )


def create_huggingface_local_config(model_path: str, model_name: str = None, **kwargs) -> LLMConfig:
    """Create Hugging Face local model configuration."""
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
