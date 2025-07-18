"""
AI Model Manager for Intellicrack

Manages AI/LLM models for script generation, code analysis, and intelligent assistance.
Supports multiple model providers including OpenAI, Anthropic, Groq, and local models.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import json
import os
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from PyQt6.QtCore import QObject, pyqtSignal

from ...utils.logger import get_logger

logger = get_logger(__name__)


class ModelProvider(Enum):
    """Supported AI model providers"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GROQ = "groq"
    GOOGLE = "google"
    LOCAL = "local"
    OLLAMA = "ollama"


@dataclass
class ModelConfig:
    """Configuration for an AI model"""
    name: str
    provider: ModelProvider
    model_id: str
    api_key: Optional[str] = None
    endpoint: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 2000
    system_prompt: Optional[str] = None
    model_path: Optional[str] = None
    model_directory: Optional[str] = None
    context_length: Optional[int] = None
    threads: Optional[int] = None
    gpu_layers: Optional[int] = None
    gpu_enabled: bool = False
    quantization: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)


class AIModelManager(QObject):
    """
    Manages AI models for intelligent code generation and analysis
    """

    # Signals
    model_loaded = pyqtSignal(str)  # model_name
    model_unloaded = pyqtSignal(str)  # model_name
    response_received = pyqtSignal(str, str)  # model_name, response
    error_occurred = pyqtSignal(str, str)  # model_name, error

    def __init__(self):
        """Initialize the AI model manager.
        
        Sets up the model management system with empty model registries
        and initializes available AI model providers (OpenAI, Anthropic,
        Groq, etc.) for intelligent code generation and analysis.
        """
        super().__init__()
        self.models: Dict[str, ModelConfig] = {}
        self.active_models: Dict[str, Any] = {}
        self.providers: Dict[ModelProvider, Any] = {}
        self._initialize_providers()

    def _initialize_providers(self):
        """Initialize model provider interfaces"""
        # Try to import available providers
        try:
            import openai
            self.providers[ModelProvider.OPENAI] = openai
            logger.info("OpenAI provider initialized")
        except ImportError:
            logger.debug("OpenAI not available")

        try:
            import anthropic
            self.providers[ModelProvider.ANTHROPIC] = anthropic
            logger.info("Anthropic provider initialized")
        except ImportError:
            logger.debug("Anthropic not available")

        try:
            import groq
            self.providers[ModelProvider.GROQ] = groq
            logger.info("Groq provider initialized")
        except ImportError:
            logger.debug("Groq not available")

    def register_model(self, config: ModelConfig) -> bool:
        """
        Register a new AI model
        
        Args:
            config: Model configuration
            
        Returns:
            bool: Success status
        """
        try:
            self.models[config.name] = config
            logger.info(f"Model registered: {config.name} ({config.provider.value})")
            return True
        except Exception as e:
            logger.error(f"Failed to register model {config.name}: {e}")
            return False

    def load_model(self, model_name: str) -> bool:
        """
        Load and initialize a registered model
        
        Args:
            model_name: Name of the model to load
            
        Returns:
            bool: Success status
        """
        if model_name not in self.models:
            logger.error(f"Model not registered: {model_name}")
            return False

        config = self.models[model_name]

        try:
            if config.provider == ModelProvider.OPENAI:
                self._load_openai_model(config)
            elif config.provider == ModelProvider.ANTHROPIC:
                self._load_anthropic_model(config)
            elif config.provider == ModelProvider.GROQ:
                self._load_groq_model(config)
            elif config.provider == ModelProvider.LOCAL:
                self._load_local_model(config)
            else:
                logger.warning(f"Provider not implemented: {config.provider}")
                return False

            self.active_models[model_name] = config
            self.model_loaded.emit(model_name)
            return True

        except Exception as e:
            logger.error(f"Failed to load model {model_name}: {e}")
            self.error_occurred.emit(model_name, str(e))
            return False
    def _load_openai_model(self, config: ModelConfig):
        """Load OpenAI model"""
        if ModelProvider.OPENAI not in self.providers:
            raise ImportError("OpenAI library not installed")

        openai = self.providers[ModelProvider.OPENAI]
        if config.api_key:
            openai.api_key = config.api_key
        elif os.getenv('OPENAI_API_KEY'):
            openai.api_key = os.getenv('OPENAI_API_KEY')
        else:
            raise ValueError("OpenAI API key not provided")

    def _load_anthropic_model(self, config: ModelConfig):
        """Load Anthropic model"""
        if ModelProvider.ANTHROPIC not in self.providers:
            raise ImportError("Anthropic library not installed")

        anthropic = self.providers[ModelProvider.ANTHROPIC]
        api_key = config.api_key or os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            raise ValueError("Anthropic API key not provided")

        try:
            client = anthropic.Anthropic(api_key=api_key)
            self.active_models[config.model_id] = {
                'client': client,
                'config': config,
                'provider': ModelProvider.ANTHROPIC
            }
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Anthropic client: {e}")
            return False

    def _load_groq_model(self, config: ModelConfig):
        """Load Groq model"""
        if ModelProvider.GROQ not in self.providers:
            raise ImportError("Groq library not installed")

        api_key = config.api_key or os.getenv('GROQ_API_KEY')
        if not api_key:
            raise ValueError("Groq API key not provided")
    def _load_local_model(self, config: ModelConfig):
        """Load local model with comprehensive support for various frameworks"""
        logger.info(f"Loading local model: {config.model_id}")

        try:
            model_path = config.model_path or config.model_id

            # Detect model type based on file extension or config
            if model_path.endswith('.gguf') or 'llama' in config.model_id.lower():
                return self._load_llama_cpp_model(config)
            elif model_path.endswith('.onnx'):
                return self._load_onnx_model(config)
            elif model_path.endswith(('.pt', '.pth', '.bin')):
                return self._load_transformers_model(config)
            elif 'gpt4all' in config.model_id.lower():
                return self._load_gpt4all_model(config)
            else:
                # Try auto-detection
                return self._auto_detect_and_load_model(config)

        except Exception as e:
            logger.error(f"Failed to load local model {config.model_id}: {e}")
            self.error_occurred.emit(config.model_id, str(e))
            return False

    def _load_llama_cpp_model(self, config: ModelConfig):
        """Load GGUF models using llama-cpp-python"""
        try:
            from llama_cpp import Llama

            model_params = {
                'model_path': config.model_path,
                'n_ctx': config.context_length or 4096,
                'n_threads': config.threads or 4,
                'n_gpu_layers': config.gpu_layers or 0,
                'f16_kv': True,
                'logits_all': False,
                'vocab_only': False,
                'use_mmap': True,
                'use_mlock': False,
                'embedding': False,
                'n_batch': 512,
                'last_n_tokens_size': 64,
            }

            if config.gpu_enabled and config.gpu_layers > 0:
                model_params['n_gpu_layers'] = config.gpu_layers

            model = Llama(**model_params)
            self.active_models[config.model_id] = model
            self.model_loaded.emit(config.model_id)
            logger.info(f"Successfully loaded GGUF model: {config.model_id}")
            return True

        except ImportError:
            logger.error("llama-cpp-python not installed. Install with: pip install llama-cpp-python")
            return False
        except Exception as e:
            logger.error(f"Error loading GGUF model: {e}")
            return False

    def _load_onnx_model(self, config: ModelConfig):
        """Load ONNX models for inference"""
        try:
            import onnxruntime as ort

            providers = ['CPUExecutionProvider']
            if config.gpu_enabled:
                providers = ['CUDAExecutionProvider', 'DirectMLProvider'] + providers

            session_options = ort.SessionOptions()
            session_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

            model = ort.InferenceSession(
                config.model_path,
                sess_options=session_options,
                providers=providers
            )

            self.active_models[config.model_id] = model
            self.model_loaded.emit(config.model_id)
            logger.info(f"Successfully loaded ONNX model: {config.model_id}")
            return True

        except ImportError:
            logger.error("onnxruntime not installed. Install with: pip install onnxruntime")
            return False
        except Exception as e:
            logger.error(f"Error loading ONNX model: {e}")
            return False

    def _load_transformers_model(self, config: ModelConfig):
        """Load Hugging Face transformers models"""
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            device = "cuda" if config.gpu_enabled and torch.cuda.is_available() else "cpu"

            # Load tokenizer
            tokenizer = AutoTokenizer.from_pretrained(
                config.model_path,
                trust_remote_code=True,
                local_files_only=True
            )

            # Model loading arguments
            model_kwargs = {
                'pretrained_model_name_or_path': config.model_path,
                'trust_remote_code': True,
                'local_files_only': True,
                'device_map': 'auto' if config.gpu_enabled else None,
            }

            # Add quantization if specified
            if config.quantization == '8bit':
                model_kwargs['load_in_8bit'] = True
            elif config.quantization == '4bit':
                model_kwargs['load_in_4bit'] = True
            else:
                model_kwargs['torch_dtype'] = torch.float16 if config.gpu_enabled else torch.float32

            model = AutoModelForCausalLM.from_pretrained(**model_kwargs)

            if device == "cuda" and not config.quantization:
                model = model.to(device)

            # Store both model and tokenizer
            self.active_models[config.model_id] = {
                'model': model,
                'tokenizer': tokenizer,
                'device': device
            }

            self.model_loaded.emit(config.model_id)
            logger.info(f"Successfully loaded transformers model: {config.model_id}")
            return True

        except ImportError:
            logger.error("transformers not installed. Install with: pip install transformers")
            return False
        except Exception as e:
            logger.error(f"Error loading transformers model: {e}")
            return False

    def _load_gpt4all_model(self, config: ModelConfig):
        """Load GPT4All models"""
        try:
            from gpt4all import GPT4All

            model = GPT4All(
                model_name=config.model_path,
                model_path=config.model_directory or ".",
                allow_download=False,
                device='gpu' if config.gpu_enabled else 'cpu'
            )

            self.active_models[config.model_id] = model
            self.model_loaded.emit(config.model_id)
            logger.info(f"Successfully loaded GPT4All model: {config.model_id}")
            return True

        except ImportError:
            logger.error("gpt4all not installed. Install with: pip install gpt4all")
            return False
        except Exception as e:
            logger.error(f"Error loading GPT4All model: {e}")
            return False

    def _auto_detect_and_load_model(self, config: ModelConfig):
        """Automatically detect and load model based on available files"""
        model_path = Path(config.model_path)

        # Check if it's a directory
        if model_path.is_dir():
            # Look for common model files
            patterns = ['*.gguf', '*.bin', '*.pth', '*.onnx', 'config.json']
            for pattern in patterns:
                files = list(model_path.glob(pattern))
                if files:
                    if pattern == '*.gguf':
                        config.model_path = str(files[0])
                        return self._load_llama_cpp_model(config)
                    elif pattern == 'config.json':
                        # Likely a Hugging Face model
                        config.model_path = str(model_path)
                        return self._load_transformers_model(config)
                    elif pattern == '*.onnx':
                        config.model_path = str(files[0])
                        return self._load_onnx_model(config)

        logger.error(f"Could not auto-detect model type for: {config.model_path}")
        return False

    def _generate_local(self, model_id: str, prompt: str, **kwargs):
        """Generate response using local model"""
        if model_id not in self.active_models:
            logger.error(f"Model {model_id} not loaded")
            return None

        model_data = self.active_models[model_id]

        try:
            # Handle different model types
            if isinstance(model_data, dict) and 'model' in model_data:
                # Transformers model
                return self._generate_transformers(model_data, prompt, **kwargs)
            elif callable(model_data):
                # Llama.cpp model
                return self._generate_llama_cpp(model_data, prompt, **kwargs)
            elif hasattr(model_data, 'generate'):
                # GPT4All model
                return self._generate_gpt4all(model_data, prompt, **kwargs)
            else:
                logger.error(f"Unknown model type for {model_id}")
                return None

        except Exception as e:
            logger.error(f"Error generating with local model: {e}")
            self.error_occurred.emit(model_id, str(e))
            return None

    def _generate_llama_cpp(self, model, prompt: str, **kwargs):
        """Generate using llama.cpp model"""
        response = model(
            prompt,
            max_tokens=kwargs.get('max_tokens', 2048),
            temperature=kwargs.get('temperature', 0.7),
            top_p=kwargs.get('top_p', 0.95),
            echo=False,
            stop=kwargs.get('stop', [])
        )
        return response['choices'][0]['text']

    def _generate_transformers(self, model_data, prompt: str, **kwargs):
        """Generate using transformers model"""
        try:
            import torch
        except ImportError:
            raise ImportError("PyTorch is required for transformers models")

        model = model_data['model']
        tokenizer = model_data['tokenizer']
        device = model_data['device']

        inputs = tokenizer(prompt, return_tensors="pt").to(device)

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=kwargs.get('max_tokens', 2048),
                temperature=kwargs.get('temperature', 0.7),
                top_p=kwargs.get('top_p', 0.95),
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id
            )

        response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        # Remove the input prompt from response
        response = response[len(prompt):].strip()
        return response

    def _generate_gpt4all(self, model, prompt: str, **kwargs):
        """Generate using GPT4All model"""
        response = model.generate(
            prompt,
            max_tokens=kwargs.get('max_tokens', 2048),
            temp=kwargs.get('temperature', 0.7),
            top_p=kwargs.get('top_p', 0.95)
        )
        return response

    def generate_script(self, model_name: str, script_type: str,
                       target: str, requirements: str) -> Optional[str]:
        """
        Generate a script using the specified model
        
        Args:
            model_name: Name of the model to use
            script_type: Type of script (frida, ghidra, etc.)
            target: Target binary or function
            requirements: Additional requirements
            
        Returns:
            Generated script or None on error
        """
        if model_name not in self.active_models:
            logger.error(f"Model not loaded: {model_name}")
            return None

        config = self.active_models[model_name]

        # Build prompt
        prompt = self._build_script_prompt(script_type, target, requirements)

        try:
            if config.provider == ModelProvider.OPENAI:
                response = self._generate_openai(config, prompt)
            elif config.provider == ModelProvider.ANTHROPIC:
                response = self._generate_anthropic(config, prompt)
            elif config.provider == ModelProvider.GROQ:
                response = self._generate_groq(config, prompt)
            elif config.provider == ModelProvider.LOCAL:
                response = self._generate_local(model_name, prompt, max_tokens=4096)
            else:
                response = self._generate_template(script_type, target, requirements)

            self.response_received.emit(model_name, response)
            return response
        except Exception as e:
            logger.error(f"Script generation failed: {e}")
            self.error_occurred.emit(model_name, str(e))
            return None

    def _build_script_prompt(self, script_type: str, target: str, requirements: str) -> str:
        """Build prompt for script generation"""
        prompts = {
            "frida": f"""Generate a Frida hook script for the following:
Target: {target}
Requirements: {requirements}

The script should:
1. Hook the specified functions/methods
2. Log function calls and arguments
3. Allow modification of return values
4. Handle errors gracefully
5. Include comments explaining the hooks

Generate production-ready Frida JavaScript code.""",

            "ghidra": f"""Generate a Ghidra analysis script for:
Target: {target}
Requirements: {requirements}

The script should:
1. Analyze the binary structure
2. Identify functions and cross-references
3. Detect patterns and vulnerabilities
4. Generate meaningful comments
5. Export analysis results

Generate production-ready Ghidra Python script.""",

            "license_bypass": f"""Generate a license bypass script for:
Target: {target}
Requirements: {requirements}

The script should:
1. Identify license check mechanisms
2. Hook or patch validation functions
3. Bypass time-based restrictions
4. Handle multiple validation methods
5. Be stealthy and undetectable

Generate working bypass code with explanations.""",

            "api_hook": f"""Generate an API hooking script for:
Target: {target}
Requirements: {requirements}

The script should:
1. Hook specified API calls
2. Log parameters and return values
3. Allow modification of behavior
4. Support both user and kernel mode
5. Handle edge cases

Generate complete hooking implementation."""
        }

        return prompts.get(script_type.lower(), f"""Generate a {script_type} script for:
Target: {target}
Requirements: {requirements}

Generate complete, working code with proper error handling and documentation.""")

    def _generate_openai(self, config: ModelConfig, prompt: str) -> str:
        """Generate using OpenAI API"""
        if ModelProvider.OPENAI not in self.providers:
            raise ImportError("OpenAI not available")

        openai = self.providers[ModelProvider.OPENAI]

        system_prompt = config.system_prompt or "You are an expert reverse engineer and exploit developer. Generate working, production-ready code."

        try:
            response = openai.ChatCompletion.create(
                model=config.model_id,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                temperature=config.temperature,
                max_tokens=config.max_tokens
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI generation failed: {e}")
            raise

    def _generate_anthropic(self, config: ModelConfig, prompt: str) -> str:
        """Generate using Anthropic API"""
        if ModelProvider.ANTHROPIC not in self.providers:
            raise ImportError("Anthropic not available")

        anthropic = self.providers[ModelProvider.ANTHROPIC]
        api_key = config.api_key or os.getenv('ANTHROPIC_API_KEY')

        client = anthropic.Anthropic(api_key=api_key)

        system_prompt = config.system_prompt or "You are an expert reverse engineer and exploit developer. Generate working, production-ready code."

        try:
            response = client.messages.create(
                model=config.model_id,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}],
                temperature=config.temperature,
                max_tokens=config.max_tokens
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic generation failed: {e}")
            raise

    def _generate_groq(self, config: ModelConfig, prompt: str) -> str:
        """Generate using Groq API"""
        # Similar implementation for Groq
        return self._generate_template("generic", "", prompt)

    def _generate_template(self, script_type: str, target: str, requirements: str) -> str:
        """Fallback template-based generation"""
        templates = {
            "frida": f"""// Frida Hook Script for {target}
// Requirements: {requirements}

Java.perform(function() {{
    console.log("[+] Starting hooks for {target}");
    
    // Add your hooks here
    
    console.log("[+] Hooks installed");
}});""",

            "ghidra": f"""# Ghidra Analysis Script for {target}
# Requirements: {requirements}

from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function

def analyze():
    # Add analysis logic here
    pass

if __name__ == "__main__":
    analyze()"""
        }

        return templates.get(script_type.lower(), f"// Generated script for {target}\n// {requirements}")


    def get_available_models(self) -> List[str]:
        """Get list of registered models"""
        return list(self.models.keys())

    def get_loaded_models(self) -> List[str]:
        """Get list of currently loaded models"""
        return list(self.active_models.keys())

    def unload_model(self, model_name: str) -> bool:
        """Unload a model"""
        if model_name in self.active_models:
            del self.active_models[model_name]
            self.model_unloaded.emit(model_name)
            logger.info(f"Model unloaded: {model_name}")
            return True
        return False

    def save_model_config(self, config: ModelConfig, config_path: str) -> bool:
        """Save model configuration to JSON file"""
        try:
            config_data = {
                'name': config.name,
                'provider': config.provider.value,
                'model_id': config.model_id,
                'api_key': config.api_key,
                'endpoint': config.endpoint,
                'temperature': config.temperature,
                'max_tokens': config.max_tokens,
                'system_prompt': config.system_prompt,
                'model_path': config.model_path,
                'model_directory': config.model_directory,
                'context_length': config.context_length
            }

            with open(config_path, 'w') as f:
                json.dump(config_data, f, indent=2)

            logger.info(f"Model configuration saved to {config_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save model config: {e}")
            return False

    def validate_model_file(self, model_path: str) -> Union[bool, str]:
        """Validate model file integrity using hashlib and struct"""
        try:
            if not os.path.exists(model_path):
                return "Model file does not exist"

            # Calculate file hash for integrity checking
            file_hash = hashlib.sha256()
            with open(model_path, 'rb') as f:
                # Read file in chunks for large models
                while chunk := f.read(8192):
                    file_hash.update(chunk)

            # Check if it's a binary model file using struct
            with open(model_path, 'rb') as f:
                header = f.read(16)
                if len(header) >= 4:
                    # Try to unpack as different formats
                    try:
                        # Check for GGUF magic number
                        magic = struct.unpack('<I', header[:4])[0]
                        if magic == 0x46554747:  # GGUF magic
                            logger.info(f"Detected GGUF model format for {model_path}")
                    except struct.error:
                        pass

            # Store calculated hash for future verification
            hash_value = file_hash.hexdigest()
            logger.info(f"Model file hash: {hash_value}")

            return True
        except Exception as e:
            logger.error(f"Model validation failed: {e}")
            return f"Validation error: {str(e)}"

    def analyze_binary(self, model_name: str, binary_path: str) -> Optional[Dict[str, Any]]:
        """
        Analyze a binary using AI model with comprehensive feature extraction
        
        Args:
            model_name: Name of the model to use
            binary_path: Path to the binary
            
        Returns:
            Analysis results or None on error
        """
        if model_name not in self.active_models:
            logger.error(f"Model not loaded: {model_name}")
            return None

        try:
            features = self._extract_binary_features(binary_path)
            if not features:
                logger.error(f"Failed to extract features from {binary_path}")
                return None

            prompt = self._build_binary_analysis_prompt(features)
            config = self.models[model_name]
            analysis_result = None

            if config.provider == ModelProvider.OPENAI:
                analysis_result = self._generate_openai(config, prompt)
            elif config.provider == ModelProvider.ANTHROPIC:
                analysis_result = self._generate_anthropic(config, prompt)
            elif config.provider == ModelProvider.GROQ:
                analysis_result = self._generate_groq(config, prompt)
            elif config.provider == ModelProvider.LOCAL:
                analysis_result = self._generate_local(model_name, prompt, max_tokens=4096)
            else:
                analysis_result = self._analyze_binary_heuristic(features)

            structured_analysis = self._structure_analysis_results(
                features, analysis_result, binary_path
            )

            self.response_received.emit(model_name, str(structured_analysis))
            return structured_analysis

        except Exception as e:
            logger.error(f"Binary analysis failed: {e}")
            self.error_occurred.emit(model_name, str(e))
            return None

    def _extract_binary_features(self, binary_path: str) -> Optional[Dict[str, Any]]:
        """Extract comprehensive features from binary for AI analysis"""
        try:
            features = {
                'path': binary_path,
                'file_info': {},
                'pe_info': {},
                'sections': [],
                'imports': [],
                'exports': [],
                'strings': [],
                'entropy': {},
                'opcodes': [],
                'hashes': {},
                'metadata': {}
            }

            file_path = Path(binary_path)
            if not file_path.exists():
                return None

            features['file_info'] = {
                'size': file_path.stat().st_size,
                'name': file_path.name,
                'extension': file_path.suffix
            }

            features['hashes'] = self._calculate_hashes(binary_path)

            with open(binary_path, 'rb') as f:
                data = f.read()

            features['strings'] = self._extract_strings(data)
            features['entropy'] = self._calculate_entropy(data)

            if self._is_pe_file(data):
                features['pe_info'] = self._analyze_pe_structure(data)
                features['sections'] = self._extract_pe_sections(data)
                features['imports'] = self._extract_pe_imports(data)
                features['exports'] = self._extract_pe_exports(data)

            features['opcodes'] = self._extract_opcodes(data)
            features['metadata'] = self._analyze_metadata(data)

            return features

        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return None

    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate multiple hash values for the file"""
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            logger.error(f"Hash calculation failed: {e}")
        return hashes

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data"""
        strings = []
        current_string = ""
        for byte in data:
            if 32 <= byte <= 126:
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        if len(current_string) >= min_length:
            strings.append(current_string)
        return strings[:100]

    def _calculate_entropy(self, data: bytes) -> Dict[str, float]:
        """Calculate Shannon entropy for different data segments"""
        import math

        def shannon_entropy(data_segment):
            if not data_segment:
                return 0
            byte_counts = {}
            for byte in data_segment:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            entropy = 0
            data_len = len(data_segment)
            for count in byte_counts.values():
                probability = count / data_len
                entropy -= probability * math.log2(probability)
            return entropy

        total_entropy = shannon_entropy(data)
        segment_size = len(data) // 10 if len(data) > 1000 else len(data)
        segment_entropies = []

        for i in range(0, len(data), segment_size):
            segment = data[i:i + segment_size]
            if segment:
                segment_entropies.append(shannon_entropy(segment))

        return {
            'total': total_entropy,
            'segments': segment_entropies,
            'average_segment': sum(segment_entropies) / len(segment_entropies) if segment_entropies else 0,
            'max_segment': max(segment_entropies) if segment_entropies else 0
        }

    def _is_pe_file(self, data: bytes) -> bool:
        """Check if file is a PE (Portable Executable)"""
        if len(data) < 64:
            return False
        if data[:2] != b'MZ':
            return False
        pe_offset = struct.unpack('<I', data[60:64])[0]
        if pe_offset >= len(data) - 4:
            return False
        return data[pe_offset:pe_offset + 4] == b'PE\x00\x00'

    def _analyze_pe_structure(self, data: bytes) -> Dict[str, Any]:
        """Analyze PE structure and extract metadata"""
        try:
            pe_offset = struct.unpack('<I', data[60:64])[0]
            coff_header = data[pe_offset + 4:pe_offset + 24]
            machine = struct.unpack('<H', coff_header[0:2])[0]
            num_sections = struct.unpack('<H', coff_header[2:4])[0]
            timestamp = struct.unpack('<I', coff_header[4:8])[0]
            characteristics = struct.unpack('<H', coff_header[18:20])[0]
            opt_header_size = struct.unpack('<H', coff_header[16:18])[0]
            opt_header_start = pe_offset + 24

            pe_info = {
                'machine': machine,
                'num_sections': num_sections,
                'timestamp': timestamp,
                'characteristics': characteristics,
                'optional_header_size': opt_header_size
            }

            if opt_header_size > 0:
                magic = struct.unpack('<H', data[opt_header_start:opt_header_start + 2])[0]
                pe_info['magic'] = magic
                pe_info['is_64bit'] = magic == 0x20b
                if magic in [0x10b, 0x20b]:
                    entry_point = struct.unpack('<I', data[opt_header_start + 16:opt_header_start + 20])[0]
                    pe_info['entry_point'] = entry_point
            return pe_info
        except Exception as e:
            logger.error(f"PE analysis failed: {e}")
            return {}

    def _extract_pe_sections(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract PE section information"""
        sections = []
        try:
            pe_offset = struct.unpack('<I', data[60:64])[0]
            num_sections = struct.unpack('<H', data[pe_offset + 6:pe_offset + 8])[0]
            opt_header_size = struct.unpack('<H', data[pe_offset + 20:pe_offset + 22])[0]
            section_start = pe_offset + 24 + opt_header_size

            for i in range(num_sections):
                section_offset = section_start + (i * 40)
                if section_offset + 40 > len(data):
                    break
                section_data = data[section_offset:section_offset + 40]
                name = section_data[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                virtual_size = struct.unpack('<I', section_data[8:12])[0]
                virtual_address = struct.unpack('<I', section_data[12:16])[0]
                raw_size = struct.unpack('<I', section_data[16:20])[0]
                raw_address = struct.unpack('<I', section_data[20:24])[0]
                characteristics = struct.unpack('<I', section_data[36:40])[0]

                sections.append({
                    'name': name,
                    'virtual_size': virtual_size,
                    'virtual_address': virtual_address,
                    'raw_size': raw_size,
                    'raw_address': raw_address,
                    'characteristics': characteristics
                })
        except Exception as e:
            logger.error(f"Section extraction failed: {e}")
        return sections

    def _extract_pe_imports(self, data: bytes) -> List[str]:
        """Extract PE import table information"""
        imports = []
        try:
            common_dlls = [
                'kernel32.dll', 'user32.dll', 'advapi32.dll', 'ntdll.dll',
                'msvcrt.dll', 'shell32.dll', 'ws2_32.dll', 'wininet.dll'
            ]
            data_str = data.lower()
            for dll in common_dlls:
                if dll.encode() in data_str:
                    imports.append(dll)
        except Exception as e:
            logger.error(f"Import extraction failed: {e}")
        return imports

    def _extract_pe_exports(self, data: bytes) -> List[str]:
        """Extract PE export table information"""
        exports = []
        try:
            strings = self._extract_strings(data)
            for string in strings:
                if (len(string) > 3 and
                    any(c.isupper() for c in string) and
                    not any(c in string for c in [' ', '.', '\\', '/', ':'])):
                    exports.append(string)
            exports = exports[:50]
        except Exception as e:
            logger.error(f"Export extraction failed: {e}")
        return exports

    def _extract_opcodes(self, data: bytes) -> List[str]:
        """Extract common opcodes/instruction patterns"""
        opcodes = []
        try:
            common_patterns = {
                b'\x55': 'push ebp',
                b'\x8b\xec': 'mov ebp, esp',
                b'\x83\xec': 'sub esp, imm8',
                b'\x81\xec': 'sub esp, imm32',
                b'\xc3': 'ret',
                b'\xcc': 'int3',
                b'\x90': 'nop',
                b'\xe8': 'call',
                b'\xff\x15': 'call dword ptr',
                b'\x68': 'push imm32'
            }
            for pattern, description in common_patterns.items():
                count = data.count(pattern)
                if count > 0:
                    opcodes.append(f"{description}: {count}")
        except Exception as e:
            logger.error(f"Opcode extraction failed: {e}")
        return opcodes

    def _analyze_metadata(self, data: bytes) -> Dict[str, Any]:
        """Analyze file metadata and patterns"""
        metadata = {}
        try:
            if data[:2] == b'MZ':
                metadata['file_type'] = 'PE Executable'
            elif data[:4] == b'\x7fELF':
                metadata['file_type'] = 'ELF Binary'
            elif data[:4] == b'\xfe\xed\xfa\xce':
                metadata['file_type'] = 'Mach-O Binary'
            else:
                metadata['file_type'] = 'Unknown'

            packing_indicators = [
                b'UPX', b'VMProtect', b'Themida', b'Armadillo',
                b'ASProtect', b'PECompact', b'FSG'
            ]
            detected_packers = []
            for packer in packing_indicators:
                if packer in data:
                    detected_packers.append(packer.decode('ascii', errors='ignore'))
            metadata['potential_packers'] = detected_packers

            anti_analysis = []
            anti_patterns = [
                b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent',
                b'NtQueryInformationProcess', b'GetTickCount'
            ]
            for pattern in anti_patterns:
                if pattern in data:
                    anti_analysis.append(pattern.decode('ascii', errors='ignore'))
            metadata['anti_analysis_indicators'] = anti_analysis

            suspicious_patterns = [
                'cmd.exe', 'powershell', 'reg.exe', 'netsh',
                'http://', 'https://', 'ftp://',
                'CreateProcess', 'WriteProcessMemory', 'VirtualAlloc'
            ]
            found_suspicious = []
            data_str = data.decode('ascii', errors='ignore').lower()
            for pattern in suspicious_patterns:
                if pattern.lower() in data_str:
                    found_suspicious.append(pattern)
            metadata['suspicious_strings'] = found_suspicious
        except Exception as e:
            logger.error(f"Metadata analysis failed: {e}")
        return metadata

    def _build_binary_analysis_prompt(self, features: Dict[str, Any]) -> str:
        """Build comprehensive prompt for AI binary analysis"""
        return f"""Analyze this binary file and provide detailed security assessment:

**File Information:**
- Name: {features['file_info'].get('name', 'Unknown')}
- Size: {features['file_info'].get('size', 0)} bytes
- Type: {features['metadata'].get('file_type', 'Unknown')}

**Hashes:**
- MD5: {features['hashes'].get('md5', 'N/A')}
- SHA256: {features['hashes'].get('sha256', 'N/A')}

**Entropy Analysis:**
- Overall Entropy: {features['entropy'].get('total', 0):.2f}
- Max Segment Entropy: {features['entropy'].get('max_segment', 0):.2f}

**PE Structure:** {features.get('pe_info', {})}

**Sections:** {len(features.get('sections', []))} sections found
{chr(10).join([f"- {s['name']}: {s['raw_size']} bytes" for s in features.get('sections', [])[:5]])}

**Imports:** {', '.join(features.get('imports', [])[:10])}

**Security Indicators:**
- Potential Packers: {', '.join(features['metadata'].get('potential_packers', ['None']))}
- Anti-Analysis: {', '.join(features['metadata'].get('anti_analysis_indicators', ['None']))}
- Suspicious Strings: {', '.join(features['metadata'].get('suspicious_strings', ['None'])[:5])}

Please provide:
1. **Malware Classification** - Is this likely malicious?
2. **Functionality Assessment** - What does this binary likely do?
3. **Security Risks** - What threats does it pose?
4. **Analysis Recommendations** - How to investigate further?
5. **IOCs** - Key indicators of compromise
6. **Mitigation Strategies** - How to protect against this binary"""

    def _analyze_binary_heuristic(self, features: Dict[str, Any]) -> str:
        """Fallback heuristic analysis when AI is not available"""
        analysis = []
        file_type = features['metadata'].get('file_type', 'Unknown')
        analysis.append(f"File Type: {file_type}")

        size = features['file_info'].get('size', 0)
        if size > 10 * 1024 * 1024:
            analysis.append("Large file size - may contain embedded resources")
        elif size < 1024:
            analysis.append("Very small file - possibly a dropper or stub")

        max_entropy = features['entropy'].get('max_segment', 0)
        if max_entropy > 7.5:
            analysis.append("HIGH ENTROPY DETECTED - Likely packed or encrypted")
        elif max_entropy > 6.5:
            analysis.append("Moderate entropy - May contain compressed data")

        packers = features['metadata'].get('potential_packers', [])
        if packers:
            analysis.append(f"PACKING DETECTED: {', '.join(packers)}")

        anti_analysis = features['metadata'].get('anti_analysis_indicators', [])
        if anti_analysis:
            analysis.append(f"ANTI-ANALYSIS FEATURES: {', '.join(anti_analysis)}")

        suspicious = features['metadata'].get('suspicious_strings', [])
        if suspicious:
            analysis.append(f"SUSPICIOUS STRINGS: {', '.join(suspicious[:3])}")

        imports = features.get('imports', [])
        if 'ntdll.dll' in imports and 'kernel32.dll' in imports:
            analysis.append("Uses low-level Windows APIs - advanced functionality")
        if 'wininet.dll' in imports or 'ws2_32.dll' in imports:
            analysis.append("Network capabilities detected")

        return "\n".join(analysis) if analysis else "Basic binary - no obvious threats detected"

    def _structure_analysis_results(self, features: Dict[str, Any],
                                   ai_analysis: str, binary_path: str) -> Dict[str, Any]:
        """Structure the analysis results into a comprehensive report"""
        return {
            'binary_path': binary_path,
            'timestamp': os.path.getctime(binary_path),
            'file_info': features['file_info'],
            'hashes': features['hashes'],
            'entropy': features['entropy'],
            'pe_info': features.get('pe_info', {}),
            'sections': features.get('sections', []),
            'imports': features.get('imports', []),
            'exports': features.get('exports', []),
            'strings_sample': features.get('strings', [])[:20],
            'opcodes': features.get('opcodes', []),
            'metadata': features['metadata'],
            'ai_analysis': ai_analysis,
            'risk_score': self._calculate_risk_score(features),
            'recommendations': self._generate_recommendations(features)
        }

    def _calculate_risk_score(self, features: Dict[str, Any]) -> int:
        """Calculate risk score based on binary features (0-100)"""
        score = 0
        max_entropy = features['entropy'].get('max_segment', 0)
        if max_entropy > 7.5:
            score += 30
        elif max_entropy > 6.5:
            score += 15
        if features['metadata'].get('potential_packers'):
            score += 25
        if features['metadata'].get('anti_analysis_indicators'):
            score += 20
        suspicious_count = len(features['metadata'].get('suspicious_strings', []))
        score += min(suspicious_count * 5, 15)
        size = features['file_info'].get('size', 0)
        if size > 50 * 1024 * 1024 or size < 1024:
            score += 10
        return min(score, 100)

    def _generate_recommendations(self, features: Dict[str, Any]) -> List[str]:
        """Generate analysis recommendations based on features"""
        recommendations = []
        if features['entropy'].get('max_segment', 0) > 7.5:
            recommendations.append("Run unpacking tools (UPX, PEiD, Detect It Easy)")
            recommendations.append("Analyze in sandbox environment")
        if features['metadata'].get('potential_packers'):
            recommendations.append("Use specialized unpacking tools")
            recommendations.append("Dynamic analysis recommended")
        imports = features.get('imports', [])
        if any(dll in imports for dll in ['wininet.dll', 'ws2_32.dll']):
            recommendations.append("Monitor network traffic during analysis")
            recommendations.append("Check for C2 communication patterns")
        recommendations.extend([
            "Verify file signature and certificates",
            "Check against threat intelligence databases",
            "Perform static analysis with disassembler",
            "Run in isolated analysis environment"
        ])
        return recommendations
