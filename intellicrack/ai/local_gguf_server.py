"""
Local GGUF Model Server for Intellicrack AI

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

import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    requests = None

from ..utils.logger import get_logger

logger = get_logger(__name__)

try:
    from flask import Flask, jsonify, request
    from flask_cors import CORS
    HAS_FLASK = True
except ImportError:
    Flask = jsonify = request = CORS = None
    HAS_FLASK = False

try:
    import llama_cpp
    from llama_cpp import Llama
    HAS_LLAMA_CPP = True
except ImportError:
    llama_cpp = Llama = None
    HAS_LLAMA_CPP = False


class LocalGGUFServer:
    """Local GGUF model server using llama.cpp Python bindings."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8000):
        self.host = host
        self.port = port
        self.app = None
        self.model = None
        self.model_path = None
        self.server_thread = None
        self.is_running = False
        self.model_config = {}

        if not HAS_FLASK:
            logger.warning("Flask not available. Local GGUF server will be disabled.")

        if not HAS_LLAMA_CPP:
            logger.warning("llama-cpp-python not available. Local GGUF server will be disabled.")

    def can_run(self) -> bool:
        """Check if the server can run (dependencies available)."""
        return HAS_FLASK and HAS_LLAMA_CPP

    def load_model(self, model_path: str, **kwargs) -> bool:
        """Load a GGUF model."""
        if not self.can_run():
            logger.error("Cannot load model: missing dependencies")
            return False

        try:
            model_path = Path(model_path)
            if not model_path.exists():
                logger.error(f"Model file not found: {model_path}")
                return False

            # Default parameters for model loading
            default_params = {
                "n_ctx": kwargs.get("context_length", 4096),
                "n_batch": kwargs.get("batch_size", 512),
                "n_threads": kwargs.get("threads", None),  # Auto-detect
                "n_gpu_layers": kwargs.get("gpu_layers", 0),
                "use_mmap": kwargs.get("use_mmap", True),
                "use_mlock": kwargs.get("use_mlock", False),
                "seed": kwargs.get("seed", -1),
                "verbose": kwargs.get("verbose", False)
            }

            # Filter out None values
            model_params = {k: v for k, v in default_params.items() if v is not None}

            logger.info(f"Loading GGUF model: {model_path}")
            logger.info(f"Model parameters: {model_params}")

            # Load the model
            self.model = Llama(model_path=str(model_path), **model_params)
            self.model_path = str(model_path)
            self.model_config = {
                "model_path": str(model_path),
                "model_name": model_path.name,
                **model_params,
                **kwargs
            }

            logger.info(f"Successfully loaded GGUF model: {model_path.name}")
            return True

        except Exception as e:
            logger.error(f"Failed to load GGUF model: {e}")
            self.model = None
            self.model_path = None
            return False

    def unload_model(self):
        """Unload the current model."""
        if self.model:
            try:
                # llama.cpp doesn't have explicit unload, just delete reference
                del self.model
                self.model = None
                self.model_path = None
                self.model_config = {}
                logger.info("Model unloaded successfully")
            except Exception as e:
                logger.error(f"Error unloading model: {e}")

    def start_server(self) -> bool:
        """Start the local GGUF server."""
        if not self.can_run():
            logger.error("Cannot start server: missing dependencies")
            return False

        if self.is_running:
            logger.warning("Server is already running")
            return True

        try:
            self.app = Flask(__name__)
            CORS(self.app)  # Enable CORS for all routes

            # Setup routes
            self._setup_routes()

            # Start server in a separate thread
            self.server_thread = threading.Thread(
                target=self._run_server,
                daemon=True
            )
            self.server_thread.start()

            # Wait for server to start
            time.sleep(2)

            # Test server
            if self._test_server():
                self.is_running = True
                logger.info(f"Local GGUF server started at http://{self.host}:{self.port}")
                return True
            else:
                logger.error("Server failed to start properly")
                return False

        except Exception as e:
            logger.error(f"Failed to start GGUF server: {e}")
            return False

    def stop_server(self):
        """Stop the local GGUF server."""
        self.is_running = False
        if self.server_thread:
            # Flask doesn't have a clean shutdown method when run this way
            # In production, you'd use a proper WSGI server
            logger.info("Server stop requested (thread will continue until process ends)")

    def _setup_routes(self):
        """Setup Flask routes for the server."""

        @self.app.route('/health', methods=['GET'])
        def health():
            """Health check endpoint."""
            return jsonify({
                "status": "healthy",
                "model_loaded": self.model is not None,
                "model_path": self.model_path
            })

        @self.app.route('/models', methods=['GET'])
        def list_models():
            """List available models."""
            return jsonify({
                "models": [self.model_config] if self.model else [],
                "current_model": self.model_config.get("model_name", None)
            })

        @self.app.route('/v1/chat/completions', methods=['POST'])
        def chat_completions():
            """OpenAI-compatible chat completions endpoint."""
            try:
                if not self.model:
                    return jsonify({"error": "No model loaded"}), 400

                data = request.get_json()
                messages = data.get('messages', [])
                max_tokens = data.get('max_tokens', 2048)
                temperature = data.get('temperature', 0.7)
                top_p = data.get('top_p', 0.9)
                stop = data.get('stop', [])
                stream = data.get('stream', False)

                if not messages:
                    return jsonify({"error": "No messages provided"}), 400

                # Convert messages to prompt format
                prompt = self._messages_to_prompt(messages)

                # Generate response
                if stream:
                    return self._stream_response(prompt, max_tokens, temperature, top_p, stop)
                else:
                    return self._complete_response(prompt, max_tokens, temperature, top_p, stop)

            except Exception as e:
                logger.error(f"Chat completion error: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/v1/completions', methods=['POST'])
        def completions():
            """OpenAI-compatible completions endpoint."""
            try:
                if not self.model:
                    return jsonify({"error": "No model loaded"}), 400

                data = request.get_json()
                prompt = data.get('prompt', '')
                max_tokens = data.get('max_tokens', 2048)
                temperature = data.get('temperature', 0.7)
                top_p = data.get('top_p', 0.9)
                stop = data.get('stop', [])
                stream = data.get('stream', False)

                if not prompt:
                    return jsonify({"error": "No prompt provided"}), 400

                # Generate response
                if stream:
                    return self._stream_response(prompt, max_tokens, temperature, top_p, stop)
                else:
                    return self._complete_response(prompt, max_tokens, temperature, top_p, stop)

            except Exception as e:
                logger.error(f"Completion error: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/load_model', methods=['POST'])
        def load_model_endpoint():
            """Load a new model."""
            try:
                data = request.get_json()
                model_path = data.get('model_path')

                if not model_path:
                    return jsonify({"error": "model_path required"}), 400

                # Unload current model first
                if self.model:
                    self.unload_model()

                # Load new model
                success = self.load_model(model_path, **data)

                if success:
                    return jsonify({
                        "status": "success",
                        "model": self.model_config
                    })
                else:
                    return jsonify({"error": "Failed to load model"}), 500

            except Exception as e:
                logger.error(f"Model loading error: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/unload_model', methods=['POST'])
        def unload_model_endpoint():
            """Unload the current model."""
            try:
                self.unload_model()
                return jsonify({"status": "success", "message": "Model unloaded"})
            except Exception as e:
                logger.error(f"Model unloading error: {e}")
                return jsonify({"error": str(e)}), 500

    def _messages_to_prompt(self, messages: List[Dict]) -> str:
        """Convert OpenAI-style messages to a prompt."""
        prompt_parts = []

        for message in messages:
            role = message.get('role', 'user')
            content = message.get('content', '')

            if role == 'system':
                prompt_parts.append(f"System: {content}")
            elif role == 'user':
                prompt_parts.append(f"User: {content}")
            elif role == 'assistant':
                prompt_parts.append(f"Assistant: {content}")

        prompt_parts.append("Assistant:")
        return "\n\n".join(prompt_parts)

    def _complete_response(self, prompt: str, max_tokens: int, temperature: float,
                          top_p: float, stop: List[str]) -> Dict[str, Any]:
        """Generate a complete response."""
        try:
            # Generate completion
            response = self.model(
                prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                top_p=top_p,
                stop=stop,
                echo=False
            )

            content = response['choices'][0]['text']

            # Format as OpenAI-compatible response
            return jsonify({
                "id": f"chatcmpl-{int(time.time())}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": self.model_config.get("model_name", "local-gguf"),
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content
                    },
                    "finish_reason": response['choices'][0]['finish_reason']
                }],
                "usage": {
                    "prompt_tokens": response.get('usage', {}).get('prompt_tokens', 0),
                    "completion_tokens": response.get('usage', {}).get('completion_tokens', 0),
                    "total_tokens": response.get('usage', {}).get('total_tokens', 0)
                }
            })

        except Exception as e:
            logger.error(f"Response generation error: {e}")
            raise

    def _stream_response(self, prompt: str, max_tokens: int, temperature: float,
                        top_p: float, stop: List[str]):
        """Generate a streaming response."""
        try:
            def generate():
                response_iter = self.model(
                    prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    top_p=top_p,
                    stop=stop,
                    stream=True,
                    echo=False
                )

                for chunk in response_iter:
                    delta = chunk['choices'][0]['delta']

                    response_chunk = {
                        "id": f"chatcmpl-{int(time.time())}",
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": self.model_config.get("model_name", "local-gguf"),
                        "choices": [{
                            "index": 0,
                            "delta": delta,
                            "finish_reason": chunk['choices'][0].get('finish_reason')
                        }]
                    }

                    yield f"data: {json.dumps(response_chunk)}\n\n"

                # Send final chunk
                yield "data: [DONE]\n\n"

            return self.app.response_class(
                generate(),
                mimetype='text/plain',
                headers={
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                    'Content-Type': 'text/event-stream'
                }
            )

        except Exception as e:
            logger.error(f"Streaming error: {e}")
            raise

    def _run_server(self):
        """Run the Flask server."""
        try:
            self.app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,
                threaded=True
            )
        except Exception as e:
            logger.error(f"Server runtime error: {e}")

    def _test_server(self) -> bool:
        """Test if the server is responding."""
        if requests is None:
            logger.error("requests module not available")
            return False
        try:
            response = requests.get(
                f"http://{self.host}:{self.port}/health",
                timeout=5
            )
            return response.status_code == 200
        except Exception:
            return False

    def get_server_url(self) -> str:
        """Get the server URL."""
        return f"http://{self.host}:{self.port}"

    def is_healthy(self) -> bool:
        """Check if server is healthy."""
        if not self.is_running:
            return False

        if requests is None:
            return False
        try:
            response = requests.get(
                f"{self.get_server_url()}/health",
                timeout=2
            )
            return response.status_code == 200
        except Exception:
            return False


class GGUFModelManager:
    """Manager for GGUF models and local server."""

    def __init__(self, models_directory: Optional[str] = None):
        self.models_directory = Path(models_directory) if models_directory else Path.home() / ".intellicrack" / "models"
        self.models_directory.mkdir(parents=True, exist_ok=True)

        self.server = LocalGGUFServer()
        self.available_models = {}
        self.current_model = None

        self.scan_models()

    def scan_models(self):
        """Scan for available GGUF models."""
        self.available_models = {}

        if not self.models_directory.exists():
            return

        # Scan for .gguf files
        for model_file in self.models_directory.rglob("*.gguf"):
            try:
                file_size = model_file.stat().st_size

                model_info = {
                    "path": str(model_file),
                    "name": model_file.name,
                    "size_mb": round(file_size / (1024 * 1024), 2),
                    "directory": str(model_file.parent),
                    "modified": model_file.stat().st_mtime
                }

                self.available_models[model_file.name] = model_info

            except Exception as e:
                logger.warning(f"Error scanning model {model_file}: {e}")

        logger.info(f"Found {len(self.available_models)} GGUF models")

    def list_models(self) -> Dict[str, Dict[str, Any]]:
        """List available models."""
        return self.available_models.copy()

    def download_model(self, model_url: str, model_name: Optional[str] = None) -> bool:
        """Download a model from URL."""
        try:
            if not model_name:
                model_name = Path(model_url).name

            model_path = self.models_directory / model_name

            logger.info(f"Downloading model: {model_url}")

            # Use requests to download with progress
            if requests is None:
                logger.error("requests module required for model download")
                return False
            response = requests.get(model_url, stream=True)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            with open(model_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)

                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            logger.info(f"Download progress: {progress:.1f}%")

            logger.info(f"Model downloaded: {model_path}")
            self.scan_models()  # Refresh model list
            return True

        except Exception as e:
            logger.error(f"Failed to download model: {e}")
            return False

    def load_model(self, model_name: str, **kwargs) -> bool:
        """Load a model by name."""
        if model_name not in self.available_models:
            logger.error(f"Model not found: {model_name}")
            return False

        model_path = self.available_models[model_name]["path"]
        success = self.server.load_model(model_path, **kwargs)

        if success:
            self.current_model = model_name
            logger.info(f"Loaded model: {model_name}")

        return success

    def unload_model(self):
        """Unload the current model."""
        self.server.unload_model()
        self.current_model = None

    def start_server(self) -> bool:
        """Start the local GGUF server."""
        return self.server.start_server()

    def stop_server(self):
        """Stop the local GGUF server."""
        self.server.stop_server()

    def get_server_url(self) -> str:
        """Get the server URL."""
        return self.server.get_server_url()

    def is_server_running(self) -> bool:
        """Check if server is running."""
        return self.server.is_running and self.server.is_healthy()

    def get_recommended_models(self) -> List[Dict[str, str]]:
        """Get list of recommended models for download."""
        return [
            {
                "name": "CodeLlama-7B-Instruct.Q4_K_M.gguf",
                "description": "Code generation and analysis model (4-bit quantized)",
                "size": "4.2GB",
                "url": "https://huggingface.co/TheBloke/CodeLlama-7B-Instruct-GGUF/resolve/main/codellama-7b-instruct.q4_k_m.gguf",
                "use_case": "Code generation and debugging"
            },
            {
                "name": "Mistral-7B-Instruct-v0.2.Q4_K_M.gguf",
                "description": "General purpose instruction-following model",
                "size": "4.4GB",
                "url": "https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.q4_k_m.gguf",
                "use_case": "General assistance and analysis"
            },
            {
                "name": "deepseek-coder-6.7b-instruct.Q4_K_M.gguf",
                "description": "Specialized coding model with strong programming capabilities",
                "size": "3.8GB",
                "url": "https://huggingface.co/TheBloke/deepseek-coder-6.7b-instruct-GGUF/resolve/main/deepseek-coder-6.7b-instruct.q4_k_m.gguf",
                "use_case": "Advanced code analysis and generation"
            }
        ]


# Global instance for easy access
gguf_manager = GGUFModelManager()
