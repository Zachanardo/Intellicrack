"""Dynamic AI Script Generator for Intellicrack.

This module provides true AI-powered script generation capabilities that:
1. Accept natural language prompts from users
2. Generate scripts dynamically based on binary analysis context
3. Connect to LLM backends for intelligent script creation
4. Save generated scripts to ai_scripts subfolder
5. Handle unforeseen circumstances not covered by existing scripts

NO TEMPLATES. ALL GENERATION IS DYNAMIC AND AI-DRIVEN.
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from intellicrack.core.config_manager import get_config
from intellicrack.logger import logger

try:
    from .script_editor import AIScriptEditor, EditType, ValidationResult

    SCRIPT_EDITOR_AVAILABLE = True
except ImportError:
    logger.warning("Script editor not available - editing features disabled")
    SCRIPT_EDITOR_AVAILABLE = False
    AIScriptEditor = None
    EditType = None
    ValidationResult = None


class ScriptType(Enum):
    """Enumeration of supported script types for AI generation."""
    FRIDA = "frida"
    GHIDRA = "ghidra"


@dataclass
class GeneratedScript:
    """Container for AI-generated scripts."""

    script_type: (
        str  # Dynamic type based on context (e.g., "frida", "custom_python", "memory_patcher")
    )
    content: str
    filename: str
    description: str
    natural_language_prompt: str
    binary_context: Dict[str, Any]
    generation_timestamp: str
    llm_model: str
    confidence_score: float
    tool_dependencies: List[str]  # Tools/libs used in script
    file_extension: Optional[str] = None  # AI can specify extension
    language: Optional[str] = None  # Programming language used


@dataclass
class ScriptGenerationRequest:
    """Request object for script generation."""

    prompt: str
    script_type: Optional[str] = None  # Auto-detect if not specified
    binary_path: Optional[str] = None
    binary_analysis: Optional[Dict[str, Any]] = None
    target_address: Optional[int] = None
    target_function: Optional[str] = None
    additional_context: Optional[Dict[str, Any]] = None
    available_tools: Optional[List[str]] = None  # Available tools in environment


@dataclass
class ScriptGenerationResult:
    """Result of script generation operation."""

    success: bool
    content: str = ""
    file_path: str = ""
    error: str = ""
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class ToolDiscovery:
    """Discovers available tools and capabilities in the environment."""

    def __init__(self):
        self.discovered_tools = {}
        self.capabilities = {}
        self._discover_tools()

    def _discover_tools(self):
        """Discover what tools are available in Intellicrack."""
        tools = {
            "frida": self._check_frida(),
            "ghidra": self._check_ghidra(),
            "radare2": self._check_radare2(),
            "qiling": self._check_qiling(),
            "capstone": self._check_capstone(),
            "pefile": self._check_pefile(),
            "lief": self._check_lief(),
            "qemu": self._check_qemu(),
        }
        self.discovered_tools = tools
        logger.info(f"Discovered tools: {[k for k,v in tools.items() if v]}")

    def _check_frida(self):
        """Check if Frida is available."""
        try:
            import frida

            _ = frida.__version__  # Verify frida is properly imported
            return True
        except (ImportError, AttributeError):
            return False

    def _check_ghidra(self):
        """Check if Ghidra utilities are available."""
        ghidra_path = Path("C:/Intellicrack/intellicrack/utils/tools/ghidra_utils.py")
        return ghidra_path.exists()

    def _check_radare2(self):
        """Check if Radare2 utilities are available."""
        r2_path = Path("C:/Intellicrack/intellicrack/utils/tools/radare2_utils.py")
        return r2_path.exists()

    def _check_qiling(self):
        """Check if Qiling is available."""
        qiling_path = Path("C:/Intellicrack/intellicrack/core/processing/qiling_emulator.py")
        return qiling_path.exists()

    def _check_capstone(self):
        """Check if Capstone is available."""
        try:
            import capstone

            _ = capstone.__version__  # Verify capstone is properly imported
            return True
        except (ImportError, AttributeError):
            return False

    def _check_pefile(self):
        """Check if pefile is available."""
        try:
            from intellicrack.handlers.pefile_handler import pefile

            _ = pefile.__version__  # Verify pefile is properly imported
            return True
        except (ImportError, AttributeError):
            return False

    def _check_lief(self):
        """Check if LIEF is available."""
        try:
            import lief

            _ = lief.__version__  # Verify lief is properly imported
            return True
        except (ImportError, AttributeError):
            return False

    def _check_qemu(self):
        """Check if QEMU emulator is available."""
        qemu_path = Path("C:/Intellicrack/intellicrack/core/processing/qemu_emulator.py")
        return qemu_path.exists()

    def get_context_for_llm(self):
        """Get tool context for LLM prompts."""
        available = [tool for tool, present in self.discovered_tools.items() if present]
        return {
            "available_tools": available,
            "capabilities": self.capabilities,
            "environment": "Intellicrack Security Research Platform",
        }


class PromptEngineer:
    """Transforms natural language into structured prompts for LLM."""

    def __init__(self):
        self.context_patterns = {
            "bypass": ["bypass", "crack", "patch", "remove", "disable", "skip"],
            "hook": ["hook", "intercept", "monitor", "trace", "log", "capture"],
            "analyze": ["analyze", "examine", "inspect", "investigate", "explore"],
            "dump": ["dump", "extract", "export", "save", "retrieve"],
            "modify": ["modify", "change", "alter", "replace", "edit"],
            "inject": ["inject", "insert", "add", "implant", "introduce"],
            "decrypt": ["decrypt", "decode", "decipher", "unpack", "decompress"],
            "keygen": ["keygen", "generate", "create", "produce", "calculate"],
        }
        self.tool_discovery = ToolDiscovery()

    def analyze_intent(self, prompt: str) -> Dict[str, Any]:
        """Analyze user intent from natural language prompt."""
        prompt_lower = prompt.lower()

        # Detect primary intent
        primary_intent = None
        for intent, keywords in self.context_patterns.items():
            if any(keyword in prompt_lower for keyword in keywords):
                primary_intent = intent
                break

        # Extract technical details
        addresses = re.findall(r"0x[0-9a-fA-F]+", prompt)
        functions = re.findall(r"\b(?:sub_|func_|FUN_)[0-9a-fA-F]+\b", prompt)
        api_calls = re.findall(r"\b[A-Z][a-zA-Z]+(?:Ex)?[AW]?\b", prompt)

        # Detect specific protection mechanisms
        protections = []
        if "license" in prompt_lower or "serial" in prompt_lower:
            protections.append("licensing")
        if "anti" in prompt_lower and "debug" in prompt_lower:
            protections.append("anti-debug")
        if "packer" in prompt_lower or "packed" in prompt_lower:
            protections.append("packing")
        if "obfuscat" in prompt_lower:
            protections.append("obfuscation")
        if "encrypt" in prompt_lower or "crypto" in prompt_lower:
            protections.append("encryption")

        return {
            "primary_intent": primary_intent,
            "addresses": addresses,
            "functions": functions,
            "api_calls": api_calls,
            "protections": protections,
            "original_prompt": prompt,
        }

    def build_llm_prompt(self, request: ScriptGenerationRequest) -> str:
        """Build comprehensive prompt for LLM with all context."""
        intent_analysis = self.analyze_intent(request.prompt)

        # Build the master prompt - let LLM determine best approach
        llm_prompt = f"""Generate a script to accomplish the following task: {request.prompt}

CONTEXT:
- Primary Intent: {intent_analysis['primary_intent']}
"""

        if request.binary_path:
            llm_prompt += f"- Target Binary: {request.binary_path}\n"

        if request.binary_analysis:
            llm_prompt += f"""
BINARY ANALYSIS:
- Architecture: {request.binary_analysis.get('arch', 'unknown')}
- Platform: {request.binary_analysis.get('platform', 'unknown')}
- Entry Point: {request.binary_analysis.get('entry_point', 'unknown')}
- Protections: {', '.join(request.binary_analysis.get('protections', []))}
"""

        if intent_analysis["addresses"]:
            llm_prompt += f"- Target Addresses: {', '.join(intent_analysis['addresses'])}\n"

        if intent_analysis["functions"]:
            llm_prompt += f"- Target Functions: {', '.join(intent_analysis['functions'])}\n"

        if intent_analysis["api_calls"]:
            llm_prompt += f"- Relevant APIs: {', '.join(intent_analysis['api_calls'])}\n"

        # Add environment context
        tool_context = self.tool_discovery.get_context_for_llm()
        llm_prompt += f"""
AVAILABLE TOOLS IN ENVIRONMENT:
{', '.join(tool_context['available_tools']) if tool_context['available_tools'] else 'Standard Python environment'}

NOTE: You can generate scripts for ANY tool or framework, not just those available.
You have complete freedom to determine the best approach, script type, and implementation.
"""

        llm_prompt += """

REQUIREMENTS:
1. Generate ONLY executable code, no explanations
2. Include error handling and edge cases
3. Make the script robust and production-ready
4. Handle the specific binary context provided
5. Adapt to runtime conditions dynamically
6. No placeholders or TODO comments
7. Include proper logging for debugging
8. Use the appropriate APIs and syntax for the target tool/framework

OUTPUT FORMAT:
Return your response as a JSON object with the following structure:
{
    "script_content": "The complete executable script code here",
    "file_extension": "The appropriate file extension for this script (e.g., 'js', 'py', 'java')"
}

Generate the complete script now:"""

        return llm_prompt


class LLMScriptInterface:
    """Dynamic interface for ANY LLM backend - no hardcoded constraints."""

    def __init__(self, model_path: str | None = None):
        self.llm_backend = None
        self.config = get_config()
        self.model_path = model_path
        self._initialize_backend()

    def _initialize_backend(self):
        """Initialize the most appropriate LLM backend dynamically."""
        # If model_path is provided, try to load it directly
        if self.model_path:
            if self._initialize_from_model_path(self.model_path):
                return

        # First try the standard llm_backends module if available
        try:
            from intellicrack.ai.llm_backends import get_llm_backend

            self.llm_backend = get_llm_backend()
            if self.llm_backend:
                logger.info("LLM backend initialized via llm_backends module")
                return
        except ImportError:
            pass

        # Dynamically discover and initialize ANY available LLM
        self._auto_discover_llm()

    def _initialize_from_model_path(self, model_path: str) -> bool:
        """Initialize LLM backend from a specific model path."""
        try:
            from intellicrack.ai.llm_backends import LLMConfig, get_llm_backend

            backend_manager = get_llm_backend()
            if not backend_manager or not hasattr(backend_manager, "register_llm"):
                return False

            provider_type, model_name = self._detect_model_format(model_path)
            if not provider_type:
                logger.error(f"Unsupported model format: {model_path}")
                return False

            config = LLMConfig(
                provider=provider_type,
                model_path=model_path,
                model_name=model_name,
                max_tokens=2048,
                temperature=0.7,
                context_length=4096,
            )

            llm_id = f"user_model_{hash(model_path) % 10000}"
            if backend_manager.register_llm(llm_id, config):
                backend_manager.set_active_llm(llm_id)
                self.llm_backend = backend_manager
                logger.info(f"Initialized model from path: {model_path} ({provider_type.value})")
                return True

        except Exception as e:
            logger.error(f"Failed to initialize model from path {model_path}: {e}")

        return False

    def _auto_discover_llm(self):
        """Automatically discover and initialize ANY available LLM without hardcoded constraints."""
        script_gen_config = self.config.get("ai_models.script_generation", {})
        api_keys = script_gen_config.get("api_keys", {})

        # Try to dynamically load any configured LLM provider
        for provider_name, api_key in api_keys.items():
            if api_key:  # Only try if API key is configured
                backend = self._try_initialize_provider(provider_name, api_key)
                if backend:
                    self.llm_backend = backend
                    logger.info(f"Initialized {provider_name} backend for script generation")
                    return

        # Also check environment variables for any LLM API keys
        for env_var in os.environ:
            if env_var.endswith("_API_KEY") or env_var.endswith("_API_TOKEN"):
                provider = env_var.replace("_API_KEY", "").replace("_API_TOKEN", "").lower()
                backend = self._try_initialize_provider(provider, os.environ[env_var])
                if backend:
                    self.llm_backend = backend
                    logger.info(f"Initialized {provider} backend from environment variable")
                    return

        # Try local/self-hosted models
        self._try_local_models()

        if not self.llm_backend:
            logger.warning("No LLM backend could be initialized - script generation may be limited")

    def _try_initialize_provider(self, provider_name: str, api_key: str):
        """Dynamically try to initialize ANY provider without hardcoding."""
        provider_lower = provider_name.lower()

        # Dynamic import based on common patterns
        import_attempts = [
            provider_lower,  # Direct module name
            f"{provider_lower}_sdk",  # Provider SDK pattern
            f"{provider_lower}ai",  # AI suffix pattern
            provider_lower.replace("_", ""),  # No underscores
            provider_lower.replace("-", "_"),  # Dash to underscore
        ]

        for module_name in import_attempts:
            try:
                module = __import__(module_name)

                # Try common client initialization patterns
                client_attempts = [
                    lambda m=module: m.Client(api_key=api_key),
                    lambda m=module: getattr(m, f"{provider_name.title()}Client")(api_key=api_key),
                    lambda m=module: m.APIClient(api_key=api_key),
                    lambda m=module: m.create_client(api_key),
                    lambda m=module: m.init(api_key),
                ]

                for attempt in client_attempts:
                    try:
                        client = attempt()
                        if client:
                            return {
                                "type": "dynamic",
                                "provider": provider_name,
                                "client": client,
                                "module": module,
                            }
                    except (AttributeError, TypeError):
                        continue

            except ImportError:
                continue

        return None

    def _try_local_models(self):
        """Try to connect to local models (files and self-hosted endpoints)."""
        # First try to find local model files
        model_path = self._discover_local_model_files()
        if model_path:
            try:
                # Initialize local model backend based on file type
                backend_manager = self.llm_backend
                if backend_manager and hasattr(backend_manager, "register_llm"):
                    provider_type, model_name = self._detect_model_format(model_path)
                    if provider_type:
                        from intellicrack.ai.llm_backends import LLMConfig

                        config = LLMConfig(
                            provider=provider_type,
                            model_path=model_path,
                            model_name=model_name,
                            max_tokens=2048,
                            temperature=0.7,
                            context_length=4096,
                        )

                        llm_id = f"local_{provider_type.value}_{hash(model_path) % 10000}"
                        if backend_manager.register_llm(llm_id, config):
                            backend_manager.set_active_llm(llm_id)
                            logger.info(f"Loaded local model: {model_path} ({provider_type.value})")
                            return
            except Exception as e:
                logger.debug(f"Failed to load local model {model_path}: {e}")

        # Fallback: Check for HTTP-based local model endpoints
        local_endpoints = [
            ("http://localhost:11434/api", "ollama"),
            ("http://localhost:8080/v1", "local_llm"),
            ("http://localhost:5000/v1", "custom"),
            ("http://127.0.0.1:8000/v1", "fastapi_llm"),
        ]

        import requests

        for endpoint, name in local_endpoints:
            try:
                response = requests.get(f"{endpoint}/models", timeout=1)
                if response.status_code == 200:
                    self.llm_backend = {"type": "local", "provider": name, "base_url": endpoint}
                    logger.info(f"Connected to local model at {endpoint}")
                    return
            except (ConnectionError, TimeoutError, OSError, ValueError) as e:
                logger.debug(f"Failed to connect to local model at {endpoint}: {e}")
                continue

    def _discover_local_model_files(self) -> str | None:
        """Discover local model files in common directories."""
        import os
        from pathlib import Path

        # Common model directories to search
        search_dirs = [
            os.path.expanduser("~/models"),
            os.path.expanduser("~/.cache/huggingface/transformers"),
            os.path.expanduser("~/.cache/huggingface/hub"),
            "./models",
            "./checkpoints",
            os.getcwd(),  # Current directory
        ]

        # Model file extensions to look for
        model_extensions = [".pth", ".pt", ".h5", ".onnx", ".safetensors"]

        for search_dir in search_dirs:
            if not os.path.exists(search_dir):
                continue

            try:
                # Look for individual model files
                for ext in model_extensions:
                    pattern = f"*{ext}"
                    for model_file in Path(search_dir).rglob(pattern):
                        if (
                            model_file.is_file() and model_file.stat().st_size > 1024 * 1024
                        ):  # At least 1MB
                            return str(model_file)

                # Look for HuggingFace model directories (contain config.json)
                for config_file in Path(search_dir).rglob("config.json"):
                    model_dir = config_file.parent
                    # Check if it has model files
                    has_model_files = any(
                        list(model_dir.glob(f"*{ext}")) for ext in [".bin", ".safetensors", ".h5"]
                    )
                    if has_model_files:
                        return str(model_dir)

            except (PermissionError, OSError):
                continue

        return None

    def _detect_model_format(self, model_path: str) -> tuple[any, str | None]:
        """Detect model format and return appropriate provider type."""
        import os

        from intellicrack.ai.llm_backends import LLMProvider

        model_path_lower = model_path.lower()

        # Directory-based detection (HuggingFace)
        if os.path.isdir(model_path):
            config_path = os.path.join(model_path, "config.json")
            if os.path.exists(config_path):
                return LLMProvider.HUGGINGFACE_LOCAL, os.path.basename(model_path)

        # File extension-based detection
        if model_path_lower.endswith((".pth", ".pt")):
            return LLMProvider.PYTORCH, None
        elif model_path_lower.endswith(".h5"):
            return LLMProvider.TENSORFLOW, None
        elif model_path_lower.endswith(".onnx"):
            return LLMProvider.ONNX, None
        elif model_path_lower.endswith(".safetensors"):
            return LLMProvider.SAFETENSORS, None

        return None, None

    def generate_script(
        self, request: ScriptGenerationRequest, prompt: str, model_name: Optional[str] = None
    ) -> Tuple[str, str]:
        """Generate script using ANY LLM backend dynamically - no hardcoded constraints.

        Returns:
            Tuple of (script_content, file_extension)
        """
        if not self.llm_backend:
            raise RuntimeError("No LLM backend available")

        # Use configured model if not specified
        if not model_name:
            script_gen_config = self.config.get("ai_models.script_generation", {})
            model_name = script_gen_config.get("default_model") or self.config.get(
                "ai_models.model_preferences.script_generation", None
            )

        # Get generation settings from config
        max_tokens = self.config.get("ai_models.max_tokens", 4000)
        temperature = self.config.get("ai_models.temperature", 0.3)

        try:
            # Dynamic generation based on backend type
            response = self._generate_dynamically(prompt, model_name, max_tokens, temperature)
            return self._parse_llm_response(response)
        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            raise

    def _generate_dynamically(
        self, prompt: str, model_name: Optional[str], max_tokens: int, temperature: float
    ) -> str:
        """Dynamically generate using ANY LLM backend without hardcoded methods."""
        backend_type = self.llm_backend.get("type")

        if backend_type == "dynamic":
            # For dynamically discovered providers
            return self._call_dynamic_provider(prompt, model_name, max_tokens, temperature)
        elif backend_type == "local":
            # For local/self-hosted models
            return self._call_local_model(prompt, model_name, max_tokens, temperature)
        elif hasattr(self.llm_backend, "chat"):
            # If backend has a chat method, use it
            return self.llm_backend.chat(prompt, max_tokens=max_tokens)
        elif "client" in self.llm_backend:
            # Try to use the client object generically
            return self._call_generic_client(prompt, model_name, max_tokens, temperature)
        else:
            raise RuntimeError(f"Unable to generate with backend type: {backend_type}")

    def _call_dynamic_provider(
        self, prompt: str, model_name: Optional[str], max_tokens: int, temperature: float
    ) -> str:
        """Call a dynamically discovered provider using reflection."""
        client = self.llm_backend["client"]
        self.llm_backend.get("module")
        provider = self.llm_backend["provider"]

        # Try common generation patterns
        generation_attempts = [
            # OpenAI-style
            lambda: self._try_openai_style(client, prompt, model_name, max_tokens, temperature),
            # Anthropic-style
            lambda: self._try_anthropic_style(client, prompt, model_name, max_tokens, temperature),
            # Generic chat method
            lambda: self._try_generic_chat(client, prompt, model_name, max_tokens, temperature),
            # Generate method
            lambda: self._try_generate_method(client, prompt, model_name, max_tokens, temperature),
            # Complete method
            lambda: self._try_complete_method(client, prompt, model_name, max_tokens, temperature),
        ]

        for attempt in generation_attempts:
            try:
                result = attempt()
                if result:
                    return result
            except Exception as e:
                logger.debug(f"Generation attempt failed for {provider}: {e}")
                continue

        raise RuntimeError(f"Could not find valid generation method for {provider}")

    def _try_openai_style(
        self, client, prompt: str, model: Optional[str], max_tokens: int, temp: float
    ) -> str:
        """Try OpenAI-style API calls."""
        if hasattr(client, "chat") and hasattr(client.chat, "completions"):
            response = client.chat.completions.create(
                model=model or "gpt-4",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temp,
            )
            return response.choices[0].message.content
        return None

    def _try_anthropic_style(
        self, client, prompt: str, model: Optional[str], max_tokens: int, temp: float
    ) -> str:
        """Try Anthropic-style API calls."""
        if hasattr(client, "messages") and hasattr(client.messages, "create"):
            response = client.messages.create(
                model=model or "claude-3-opus-20240229",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temp,
            )
            return response.content[0].text
        return None

    def _try_generic_chat(
        self, client, prompt: str, model: Optional[str], max_tokens: int, temp: float
    ) -> str:
        """Try generic chat method."""
        if hasattr(client, "chat"):
            kwargs = {"prompt": prompt}
            if model:
                kwargs["model"] = model
            kwargs["max_tokens"] = max_tokens
            kwargs["temperature"] = temp
            return client.chat(**kwargs)
        return None

    def _try_generate_method(
        self, client, prompt: str, model: Optional[str], max_tokens: int, temp: float
    ) -> str:
        """Try generate method."""
        if hasattr(client, "generate"):
            kwargs = {"prompt": prompt}
            if model:
                kwargs["model"] = model
            kwargs["max_tokens"] = max_tokens
            kwargs["temperature"] = temp
            return client.generate(**kwargs)
        return None

    def _try_complete_method(
        self, client, prompt: str, model: Optional[str], max_tokens: int, temp: float
    ) -> str:
        """Try complete/completion method."""
        for method_name in ["complete", "completion", "completions"]:
            if hasattr(client, method_name):
                method = getattr(client, method_name)
                kwargs = {"prompt": prompt}
                if model:
                    kwargs["model"] = model
                kwargs["max_tokens"] = max_tokens
                kwargs["temperature"] = temp
                return method(**kwargs)
        return None

    def _call_local_model(
        self, prompt: str, model_name: Optional[str], max_tokens: int, temperature: float
    ) -> str:
        """Call a local/self-hosted model via HTTP."""
        import requests

        base_url = self.llm_backend["base_url"]

        # Try different endpoint patterns
        endpoints = [
            f"{base_url}/chat/completions",  # OpenAI-compatible
            f"{base_url}/generate",  # Ollama-style
            f"{base_url}/completion",  # Generic
            f"{base_url}/v1/completions",  # Versioned API
        ]

        for endpoint in endpoints:
            try:
                response = requests.post(
                    endpoint,
                    json={
                        "model": model_name or "default",
                        "prompt": prompt,
                        "messages": [{"role": "user", "content": prompt}],  # For chat endpoints
                        "max_tokens": max_tokens,
                        "temperature": temperature,
                        "stream": False,
                    },
                    timeout=60,
                )

                if response.status_code == 200:
                    data = response.json()
                    # Extract response from various formats
                    if "choices" in data:
                        return data["choices"][0].get("message", {}).get("content", "") or data[
                            "choices"
                        ][0].get("text", "")
                    elif "response" in data:
                        return data["response"]
                    elif "output" in data:
                        return data["output"]
                    elif "text" in data:
                        return data["text"]
                    else:
                        return str(data)
            except Exception as e:
                logger.debug(f"Local model endpoint {endpoint} failed: {e}")
                continue

        raise RuntimeError(f"Could not generate response from local model at {base_url}")

    def _call_generic_client(
        self, prompt: str, model_name: Optional[str], max_tokens: int, temperature: float
    ) -> str:
        """Try to call a generic client object."""
        client = self.llm_backend["client"]

        # Try to find and call an appropriate method
        for method_name in ["generate", "chat", "complete", "create", "query", "ask"]:
            if hasattr(client, method_name):
                method = getattr(client, method_name)
                try:
                    # Try with various parameter combinations
                    result = method(
                        prompt, model=model_name, max_tokens=max_tokens, temperature=temperature
                    )
                    if result:
                        return str(result)
                except TypeError:
                    # Try with just prompt
                    try:
                        result = method(prompt)
                        if result:
                            return str(result)
                    except Exception as e:
                        logger.debug(f"Method {method.__name__} failed with prompt only: {e}")
                        continue
                except Exception as e:
                    logger.debug(f"Method {method.__name__} failed: {e}")
                    continue

        raise RuntimeError("Could not find valid method to generate response")

    def _parse_llm_response(self, response: str) -> Tuple[str, str]:
        """Parse LLM response to extract script content and file extension.

        Returns:
            Tuple of (script_content, file_extension)
        """
        try:
            # Try to parse as JSON
            result = json.loads(response)
            if isinstance(result, dict) and "script_content" in result:
                script_content = result.get("script_content", "")
                file_extension = result.get("file_extension", "txt")
                return script_content, file_extension
        except (json.JSONDecodeError, ValueError):
            # If not JSON, assume entire response is the script
            pass

        # Fallback: treat entire response as script content
        return response, "txt"


class ScriptStorageManager:
    """Manages storage and retrieval of AI-generated scripts."""

    def __init__(self):
        self.base_path = Path("C:/Intellicrack/intellicrack/scripts")
        self._ensure_directories()

    def _ensure_directories(self):
        """Ensure ai_scripts subdirectory exists."""
        ai_dir = self.base_path / "ai_scripts"
        ai_dir.mkdir(parents=True, exist_ok=True)

    def save_script(self, script: GeneratedScript) -> str:
        """Save generated script to appropriate directory."""
        # Create unique filename based on prompt hash and timestamp
        prompt_hash = hashlib.sha256(script.natural_language_prompt.encode()).hexdigest()[:8]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Use AI-specified extension if provided, otherwise default to .txt
        if script.file_extension:
            ext = (
                script.file_extension
                if script.file_extension.startswith(".")
                else f".{script.file_extension}"
            )
        else:
            # Default to .txt if AI didn't specify extension
            ext = ".txt"

        # Clean script type for filename (remove spaces and special chars)
        clean_type = re.sub(r"[^a-zA-Z0-9_-]", "_", script.script_type.lower())
        filename = f"ai_{clean_type}_{prompt_hash}_{timestamp}{ext}"

        # Save to ai_scripts folder
        filepath = self.base_path / "ai_scripts" / filename

        # Add metadata header
        metadata = f"""/*
 * AI-Generated Script
 * Prompt: {script.natural_language_prompt}
 * Generated: {script.generation_timestamp}
 * Model: {script.llm_model}
 * Confidence: {script.confidence_score}
 * Description: {script.description}
 */

"""

        # Write script with metadata
        with open(filepath, "w", encoding="utf-8") as f:
            # Format metadata based on script language
            script_type_lower = script.script_type.lower()
            if script_type_lower in ["frida", "ghidra"]:
                # JavaScript/Java style
                f.write(metadata)
            elif (
                script_type_lower
                in [
                    "ida",
                    "qiling",
                    "unicorn",
                    "angr",
                    "capstone",
                    "keystone",
                    "pwntools",
                    "binary_ninja",
                ]
                or ext == ".py"
            ):
                # Python style
                f.write(metadata.replace("/*", '"""').replace("*/", '"""'))
            elif script_type_lower == "radare2" or ext in [".r2", ".gdb", ".wdbg", ".odbg"]:
                # Shell/command style
                f.write(metadata.replace("/*", "#").replace("*/", "").replace(" *", "#"))
            else:
                # Default to comment style
                f.write(metadata.replace("/*", "//").replace("*/", "//").replace(" *", "//"))

            f.write(script.content)

        logger.info(f"Saved AI-generated script: {filepath}")
        return str(filepath)

    def list_ai_scripts(self, script_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all AI-generated scripts."""
        scripts = []
        ai_dir = self.base_path / "ai_scripts"

        if ai_dir.exists():
            for script_file in ai_dir.iterdir():
                if script_file.is_file():
                    # Filter by type if specified
                    if script_type and script_type.lower() not in script_file.name.lower():
                        continue

                    # Extract script type from filename
                    parts = script_file.stem.split("_")
                    detected_type = parts[1] if len(parts) > 1 else "unknown"

                    scripts.append(
                        {
                            "path": str(script_file),
                            "name": script_file.name,
                            "type": detected_type,
                            "size": script_file.stat().st_size,
                            "modified": datetime.fromtimestamp(
                                script_file.stat().st_mtime
                            ).isoformat(),
                        }
                    )

        return scripts


class DynamicScriptGenerator:
    """Main class for dynamic AI-powered script generation."""

    def __init__(self, model_path: str | None = None):
        self.prompt_engineer = PromptEngineer()
        self.llm_interface = LLMScriptInterface(model_path=model_path)
        self.storage_manager = ScriptStorageManager()
        self.binary_analyzer = None
        self._initialize_analyzer()

    def _initialize_analyzer(self):
        """Initialize binary analyzer for context extraction."""
        try:
            from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer

            self.binary_analyzer = BinaryAnalyzer()
        except ImportError:
            logger.warning("Binary analyzer not available")

    def generate_from_prompt(
        self, prompt: str, script_type: str = "auto", binary_path: Optional[str] = None
    ) -> GeneratedScript:
        """Generate script from natural language prompt.

        This is the main entry point for AI script generation.
        Takes a natural language prompt and generates a complete,
        production-ready script using LLM capabilities.

        script_type can be ANY string - not limited to predefined types.
        If "auto", the AI will determine the best script type.
        """
        logger.info(f"Generating {script_type} script from prompt: {prompt[:100]}...")

        # Analyze binary if provided
        binary_analysis = None
        if binary_path and self.binary_analyzer:
            try:
                binary_analysis = self._analyze_binary(binary_path)
            except Exception as e:
                logger.warning(f"Binary analysis failed: {e}")

        # Let LLM determine best approach if auto
        if script_type == "auto":
            script_type = "auto"  # Keep as auto - let LLM decide completely
            logger.info("LLM will determine best script type and approach")

        # Create generation request
        request = ScriptGenerationRequest(
            prompt=prompt,
            script_type=script_type,
            binary_path=binary_path,
            binary_analysis=binary_analysis,
        )

        # Build comprehensive LLM prompt
        llm_prompt = self.prompt_engineer.build_llm_prompt(request)

        # Generate script using LLM
        try:
            script_content, file_extension = self.llm_interface.generate_script(request, llm_prompt)
        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            # Return empty script with error message
            return GeneratedScript(
                script_type=script_type,
                content="",
                filename="",
                description=f"Script generation failed: {str(e)}",
                natural_language_prompt=prompt,
                binary_context=binary_analysis or {},
                generation_timestamp=datetime.now().isoformat(),
                llm_model="none",
                confidence_score=0.0,
                file_extension="txt",
            )

        # Clean and validate generated script
        script_content = self._clean_generated_script(script_content, script_type)

        # Create script object
        generated_script = GeneratedScript(
            script_type=script_type,
            content=script_content,
            filename="",  # Will be set by storage manager
            description=self._extract_description(prompt),
            natural_language_prompt=prompt,
            binary_context=binary_analysis or {},
            generation_timestamp=datetime.now().isoformat(),
            llm_model=self._get_llm_model_name(),
            confidence_score=self._calculate_confidence(script_content, request),
            file_extension=file_extension,
        )

        # Save script
        filepath = self.storage_manager.save_script(generated_script)
        generated_script.filename = os.path.basename(filepath)

        return generated_script

    def _analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """Extract binary context for script generation."""
        analysis = {
            "path": binary_path,
            "name": os.path.basename(binary_path),
            "size": os.path.getsize(binary_path),
        }

        # Use binary analyzer if available
        if self.binary_analyzer:
            try:
                detailed = self.binary_analyzer.analyze(binary_path)
                analysis.update(detailed)
            except Exception as e:
                logger.debug(f"Binary analyzer failed: {e}")
                pass

        # Basic analysis fallback
        try:
            import pefile

            pe = pefile.PE(binary_path)
            analysis["arch"] = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"
            analysis["platform"] = "windows"
            analysis["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            analysis["sections"] = [s.Name.decode().rstrip("\x00") for s in pe.sections]
        except (ImportError, OSError, pefile.PEFormatError) as e:
            logger.debug(f"PE analysis failed: {e}")
            pass

        return analysis

    def _clean_generated_script(self, content: str, script_type: str) -> str:
        """Clean and validate generated script content."""
        # Remove markdown code blocks if present
        content = re.sub(r"^```[\w]*\n", "", content)
        content = re.sub(r"\n```$", "", content)

        # Remove any explanation text before actual code
        lines = content.split("\n")
        code_start = 0

        # Find where actual code starts
        for i, line in enumerate(lines):
            if script_type == "frida" and ("Java.perform" in line or "Interceptor" in line):
                code_start = i
                break
            elif script_type == "ghidra" and ("import ghidra" in line or "public class" in line):
                code_start = i
                break
            elif script_type in ["ida", "qiling", "unicorn"] and (
                "import" in line or "from" in line
            ):
                code_start = i
                break
            elif script_type == "radare2" and any(cmd in line for cmd in ["s ", "aa", "pdf", "wx"]):
                code_start = i
                break

        # Return only actual code
        return "\n".join(lines[code_start:])

    def _extract_description(self, prompt: str) -> str:
        """Extract a concise description from the prompt."""
        # Take first sentence or first 100 characters
        sentences = prompt.split(".")
        if sentences:
            return sentences[0][:100]
        return prompt[:100]

    def _get_llm_model_name(self) -> str:
        """Get the name of the LLM model being used."""
        if not self.llm_interface.llm_backend:
            return "none"

        backend_type = self.llm_interface.llm_backend.get("type", "unknown")
        if backend_type == "openai":
            return "gpt-4-turbo"
        elif backend_type == "anthropic":
            return "claude-3-opus"
        elif backend_type == "ollama":
            return "codellama-34b"
        else:
            return backend_type

    def _calculate_confidence(self, script: str, request: ScriptGenerationRequest) -> float:
        """Calculate confidence score for generated script."""
        score = 0.5  # Base score

        # Check for key patterns based on intent
        intent = self.prompt_engineer.analyze_intent(request.prompt)

        if intent["primary_intent"] == "bypass":
            if "patch" in script.lower() or "nop" in script.lower():
                score += 0.2
        elif intent["primary_intent"] == "hook":
            if "interceptor" in script.lower() or "hook" in script.lower():
                score += 0.2

        # Check for error handling
        if "try" in script or "catch" in script or "except" in script:
            score += 0.1

        # Check for comments
        if "//" in script or "/*" in script or "#" in script:
            score += 0.1

        # Penalize for obvious placeholders
        if "TODO" in script or "PLACEHOLDER" in script:
            score -= 0.3

        return min(max(score, 0.0), 1.0)


class AIScriptGenerator:
    """Main interface for AI script generation in Intellicrack.

    This class provides the primary API for generating scripts dynamically
    using AI/LLM capabilities. NO TEMPLATES - everything is generated
    based on user prompts and binary context.
    """

    def __init__(self, model_path: str | None = None):
        self.generator = DynamicScriptGenerator(model_path=model_path)
        if SCRIPT_EDITOR_AVAILABLE:
            self.script_editor = AIScriptEditor()
            logger.info(
                "AIScriptGenerator initialized with dynamic LLM generation and editing capabilities"
            )
        else:
            self.script_editor = None
            logger.info(
                "AIScriptGenerator initialized with dynamic LLM generation (editing disabled)"
            )

    def generate_script_from_prompt(
        self,
        prompt: str,
        script_type: str = "auto",
        binary_path: Optional[str] = None,
        model_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Universal entry point for AI script generation.

        This method accepts ANY script type - not limited to predefined types.
        The AI will generate whatever type of script makes sense for the problem.

        Args:
            prompt: Natural language description of what the script should do
            script_type: ANY string describing the script type, or "auto" to let AI decide
            binary_path: Optional path to binary for context
            model_path: Optional path to specific model file to use for this generation

        Returns:
            Dict with generated script and metadata
        """
        # Don't constrain script type - use as-is or let AI determine
        if not script_type:
            script_type = "auto"

        try:
            # Use specific model if provided, otherwise use default generator
            if model_path:
                # Create temporary generator with specific model
                temp_generator = DynamicScriptGenerator(model_path=model_path)
                script = temp_generator.generate_from_prompt(
                    prompt=prompt, script_type=script_type, binary_path=binary_path
                )
            else:
                script = self.generator.generate_from_prompt(
                    prompt=prompt, script_type=script_type, binary_path=binary_path
                )

            # Build path using the actual script type (which may have been auto-determined)
            script_dir = script.script_type.replace(" ", "_").replace("/", "_")

            return {
                "success": True,
                "script": script.content,
                "filename": script.filename,
                "path": str(
                    Path(self.generator.storage_manager.base_path)
                    / script_dir
                    / "ai_scripts"
                    / script.filename
                ),
                "script_type": script.script_type,  # Return actual type used
                "description": script.description,
                "confidence": script.confidence_score,
                "model": script.llm_model,
                "timestamp": script.generation_timestamp,
            }
        except Exception as e:
            logger.error(f"Script generation failed: {e}")
            import traceback

            traceback.print_exc()
            return {"success": False, "error": str(e), "traceback": traceback.format_exc()}

    def list_generated_scripts(self, script_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all AI-generated scripts.

        Args:
            script_type: Optional filter by script type (can be ANY string)
                        Examples: "memory_patcher", "api_hooking_script",
                        "custom_debugger", or any other descriptive type

        Returns:
            List of script metadata dictionaries
        """
        # Don't constrain to specific types - pass through any filter
        return self.generator.storage_manager.list_ai_scripts(script_type)

    def edit_script(
        self,
        script_path: str,
        modification_prompt: str,
        edit_type: str = "enhancement",
        test_binary: Optional[str] = None,
        preserve_functionality: bool = True,
    ) -> Dict[str, Any]:
        """Edit an existing AI-generated script.

        Args:
            script_path: Path to the script to edit
            modification_prompt: Natural language description of changes needed
            edit_type: Type of edit (enhancement, bugfix, optimization, refactor)
            test_binary: Optional binary to test script against
            preserve_functionality: Whether to preserve existing functionality

        Returns:
            Dictionary with edit results
        """
        if not SCRIPT_EDITOR_AVAILABLE or not self.script_editor:
            return {
                "success": False,
                "error": "Script editing not available - script_editor.py not found",
            }

        # Map string edit type to enum
        edit_type_map = {
            "enhancement": EditType.ENHANCEMENT,
            "bugfix": EditType.BUGFIX,
            "optimization": EditType.OPTIMIZATION,
            "refactor": EditType.REFACTOR,
            "feature": EditType.FEATURE_ADD,
        }

        edit_enum = edit_type_map.get(edit_type.lower(), EditType.ENHANCEMENT)

        try:
            result = self.script_editor.edit_script(
                script_path=script_path,
                modification_prompt=modification_prompt,
                edit_type=edit_enum,
                test_binary=test_binary,
                preserve_functionality=preserve_functionality,
            )

            return {
                "success": True,
                "script_path": result.get("output_path"),
                "original_path": script_path,
                "changes_made": result.get("changes_made", []),
                "validation_result": result.get("validation_result"),
                "confidence": result.get("confidence_score", 0.0),
                "version_id": result.get("version_id"),
                "edit_summary": result.get("edit_summary"),
            }

        except Exception as e:
            logger.error(f"Script editing failed: {e}")
            return {"success": False, "error": str(e), "script_path": script_path}

    def improve_script_iteratively(
        self,
        script_path: str,
        improvement_goals: List[str],
        max_iterations: int = 3,
        test_binary: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Iteratively improve a script through multiple AI-driven refinements.

        Args:
            script_path: Path to the script to improve
            improvement_goals: List of improvement objectives
            max_iterations: Maximum number of improvement iterations
            test_binary: Optional binary to test against

        Returns:
            Dictionary with improvement results
        """
        if not SCRIPT_EDITOR_AVAILABLE or not self.script_editor:
            return {
                "success": False,
                "error": "Script editing not available - script_editor.py not found",
            }

        try:
            result = self.script_editor.iterative_improvement(
                script_path=script_path,
                improvement_goals=improvement_goals,
                max_iterations=max_iterations,
                test_binary=test_binary,
            )

            return {
                "success": True,
                "final_script_path": result.get("final_script_path"),
                "iterations_completed": result.get("iterations_completed", 0),
                "improvements_made": result.get("improvements_made", []),
                "final_confidence": result.get("final_confidence", 0.0),
                "performance_metrics": result.get("performance_metrics", {}),
                "version_history": result.get("version_history", []),
            }

        except Exception as e:
            logger.error(f"Iterative script improvement failed: {e}")
            return {"success": False, "error": str(e), "script_path": script_path}

    def get_script_versions(self, script_path: str) -> List[Dict[str, Any]]:
        """Get version history for a script.

        Args:
            script_path: Path to the script

        Returns:
            List of version information
        """
        if not SCRIPT_EDITOR_AVAILABLE or not self.script_editor:
            return []

        try:
            return self.script_editor.version_manager.get_version_history(script_path)
        except Exception as e:
            logger.error(f"Failed to get script versions: {e}")
            return []

    def rollback_script(self, script_path: str, version_id: str) -> Dict[str, Any]:
        """Rollback a script to a previous version.

        Args:
            script_path: Path to the script
            version_id: Version to rollback to

        Returns:
            Rollback operation result
        """
        if not SCRIPT_EDITOR_AVAILABLE or not self.script_editor:
            return {
                "success": False,
                "error": "Script editing not available - script_editor.py not found",
            }

        try:
            result = self.script_editor.rollback_to_version(script_path, version_id)

            return {
                "success": True,
                "script_path": script_path,
                "version_id": version_id,
                "rollback_details": result,
            }

        except Exception as e:
            logger.error(f"Script rollback failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "script_path": script_path,
                "version_id": version_id,
            }

    def test_script(self, script_path: str, test_binary: Optional[str] = None) -> Dict[str, Any]:
        """Test a script for functionality and correctness.

        Args:
            script_path: Path to the script to test
            test_binary: Optional binary to test against

        Returns:
            Test results
        """
        if not SCRIPT_EDITOR_AVAILABLE or not self.script_editor:
            return {
                "success": False,
                "error": "Script editing not available - script_editor.py not found",
            }

        try:
            # Determine script type from file extension or content
            script_type = self._determine_script_type(script_path)

            validation_result, details = self.script_editor.tester.validate_script(
                script_content=open(script_path, "r").read(),
                script_type=script_type,
                binary_path=test_binary,
            )

            return {
                "success": True,
                "validation_result": validation_result.value if validation_result else "unknown",
                "details": details,
                "script_path": script_path,
                "test_binary": test_binary,
            }

        except Exception as e:
            logger.error(f"Script testing failed: {e}")
            return {"success": False, "error": str(e), "script_path": script_path}

    def _determine_script_type(self, script_path: str) -> str:
        """Intelligently determine script type/purpose from content analysis.

        This is NOT limited to predefined types - it analyzes the script
        and returns a descriptive type based on what the script actually does.
        """
        try:
            with open(script_path, "r") as f:
                content = f.read(1000)  # Read first 1000 chars for analysis

            content_lower = content.lower()

            # Analyze script purpose and return descriptive type
            # These are just examples - ANY type can be returned
            if "interceptor" in content_lower and "attach" in content_lower:
                return "dynamic_hooking_script"
            elif "memory" in content_lower and (
                "patch" in content_lower or "write" in content_lower
            ):
                return "memory_manipulation_script"
            elif "unpack" in content_lower or "dump" in content_lower:
                return "unpacking_script"
            elif "decrypt" in content_lower or "crypto" in content_lower:
                return "cryptographic_analysis_script"
            elif "network" in content_lower or "socket" in content_lower:
                return "network_interception_script"
            elif "license" in content_lower or "registration" in content_lower:
                return "license_bypass_script"
            elif "debug" in content_lower or "breakpoint" in content_lower:
                return "debugging_automation_script"
            elif "disasm" in content_lower or "instruction" in content_lower:
                return "disassembly_analysis_script"
            else:
                # Return a generic but descriptive type
                ext = os.path.splitext(script_path)[1]
                return f"custom_{ext[1:]}_script" if ext else "custom_analysis_script"
        except Exception as e:
            logger.debug(f"Could not analyze script type: {e}")
            return "unanalyzed_script"


# Module exports
__all__ = [
    "AIScriptGenerator",
    "DynamicScriptGenerator",
    "GeneratedScript",
    "ScriptGenerationRequest",
    "PromptEngineer",
    "LLMScriptInterface",
    "ScriptStorageManager",
    "SCRIPT_EDITOR_AVAILABLE",
]
