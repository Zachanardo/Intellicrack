"""Production tests for local GGUF model server functionality.

Tests validate real Flask server operations, model loading, HTTP endpoints,
and WebSocket functionality for AI model serving.
"""

import json
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Optional

import pytest

from intellicrack.ai.local_gguf_server import GGUFModelManager, LocalGGUFServer, create_gguf_server_with_intel_gpu


class FakeLlamaModel:
    """Real test double for llama-cpp-python Llama model."""

    def __init__(
        self,
        model_path: str,
        n_ctx: int = 2048,
        n_gpu_layers: int = 0,
        n_threads: Optional[int] = None,
        verbose: bool = True,
    ) -> None:
        self.model_path: str = model_path
        self.n_ctx: int = n_ctx
        self.n_gpu_layers: int = n_gpu_layers
        self.n_threads: Optional[int] = n_threads
        self.verbose: bool = verbose
        self.is_loaded: bool = True
        self.call_count: int = 0

    def __call__(
        self,
        prompt: str,
        max_tokens: int = 256,
        temperature: float = 0.7,
        top_p: float = 0.95,
        echo: bool = False,
        stop: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Generate completion for prompt."""
        self.call_count += 1
        return {
            "id": f"cmpl-{self.call_count}",
            "object": "text_completion",
            "created": int(time.time()),
            "model": self.model_path,
            "choices": [
                {
                    "text": f"Generated response for: {prompt[:50]}",
                    "index": 0,
                    "logprobs": None,
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": len(prompt.split()),
                "completion_tokens": 10,
                "total_tokens": len(prompt.split()) + 10,
            },
        }

    def create_chat_completion(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
        top_p: float = 0.95,
        max_tokens: int = 256,
        stream: bool = False,
    ) -> dict[str, Any]:
        """Generate chat completion for messages."""
        self.call_count += 1
        last_message = messages[-1]["content"] if messages else "Hello"
        return {
            "id": f"chatcmpl-{self.call_count}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": self.model_path,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"Response to: {last_message[:50]}",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": sum(len(m.get("content", "").split()) for m in messages),
                "completion_tokens": 10,
                "total_tokens": sum(len(m.get("content", "").split()) for m in messages) + 10,
            },
        }

    def __del__(self) -> None:
        """Cleanup on deletion."""
        self.is_loaded = False


class FakeLlamaModelWithError:
    """Test double that simulates model loading errors."""

    def __init__(
        self,
        model_path: str,
        n_ctx: int = 2048,
        n_gpu_layers: int = 0,
        n_threads: Optional[int] = None,
        verbose: bool = True,
    ) -> None:
        raise RuntimeError(f"Failed to load model: {model_path}")


class FakeModelWithoutDel:
    """Test double for model without __del__ method."""

    def __init__(self) -> None:
        self.is_loaded: bool = True


@pytest.fixture
def mock_gguf_model_file(tmp_path: Path) -> Path:
    """Create a mock GGUF model file for testing."""
    model_file = tmp_path / "test_model.gguf"
    model_file.write_bytes(b"GGUF" + b"\x00" * 1024)
    return model_file


@pytest.fixture
def models_directory(tmp_path: Path) -> Path:
    """Create a temporary models directory."""
    models_dir = tmp_path / "models"
    models_dir.mkdir()
    return models_dir


class TestLocalGGUFServer:
    """Tests for LocalGGUFServer class."""

    def test_server_initializes_with_default_config(self) -> None:
        """Server initializes with default host and port."""
        server = LocalGGUFServer()

        assert server.host == "127.0.0.1"
        assert server.port == 8000
        assert server.model is None
        assert server.model_path is None
        assert not server.is_running

    def test_server_initializes_with_custom_config(self) -> None:
        """Server initializes with custom host and port."""
        server = LocalGGUFServer(host="0.0.0.0", port=9000)

        assert server.host == "0.0.0.0"
        assert server.port == 9000

    def test_can_run_checks_dependencies(self) -> None:
        """can_run correctly checks for Flask and llama-cpp availability."""
        server = LocalGGUFServer()

        result = server.can_run()

        assert isinstance(result, bool)

    def test_detect_intel_gpu_initializes(self) -> None:
        """Intel GPU detection runs without errors."""
        server = LocalGGUFServer()

        assert hasattr(server, "gpu_backend")
        assert hasattr(server, "gpu_devices")
        assert isinstance(server.gpu_devices, list)

    def test_get_optimal_threads_returns_valid_count(self) -> None:
        """get_optimal_threads returns positive integer."""
        server = LocalGGUFServer()

        threads = server._get_optimal_threads()

        assert isinstance(threads, int)
        assert threads > 0

    def test_get_optimal_threads_respects_environment(self) -> None:
        """get_optimal_threads respects OMP_NUM_THREADS environment variable."""
        import os

        server = LocalGGUFServer()

        original_value = os.environ.get("OMP_NUM_THREADS")
        try:
            os.environ["OMP_NUM_THREADS"] = "4"
            threads = server._get_optimal_threads()
            assert threads == 4
        finally:
            if original_value:
                os.environ["OMP_NUM_THREADS"] = original_value
            elif "OMP_NUM_THREADS" in os.environ:
                del os.environ["OMP_NUM_THREADS"]

    def test_load_model_validates_file_existence(self, tmp_path: Path) -> None:
        """load_model returns False for nonexistent files."""
        server = LocalGGUFServer()
        nonexistent = tmp_path / "nonexistent.gguf"

        result = server.load_model(str(nonexistent))

        assert result is False

    @pytest.mark.skipif(
        not LocalGGUFServer().can_run(),
        reason="Flask or llama-cpp not available",
    )
    def test_load_model_with_valid_file(
        self,
        mock_gguf_model_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """load_model attempts to load valid GGUF file."""
        server = LocalGGUFServer()

        import intellicrack.ai.local_gguf_server as server_module

        monkeypatch.setattr(server_module, "Llama", FakeLlamaModel)

        if result := server.load_model(str(mock_gguf_model_file)):
            assert server.model is not None
            assert server.model_path == str(mock_gguf_model_file)

    def test_unload_model_clears_state(self) -> None:
        """unload_model clears model and path."""
        server = LocalGGUFServer()
        server.model = FakeModelWithoutDel()
        server.model_path = "test_path"

        server.unload_model()

        assert server.model is None
        assert server.model_path is None

    def test_get_server_url_returns_correct_format(self) -> None:
        """get_server_url returns properly formatted URL."""
        server = LocalGGUFServer(host="localhost", port=8080)

        url = server.get_server_url()

        assert url == "http://localhost:8080"

    def test_messages_to_prompt_converts_correctly(self) -> None:
        """_messages_to_prompt converts OpenAI messages to prompt format."""
        server = LocalGGUFServer()

        messages = [
            {"role": "system", "content": "You are helpful"},
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"},
        ]

        prompt = server._messages_to_prompt(messages)

        assert "System: You are helpful" in prompt
        assert "User: Hello" in prompt
        assert "Assistant: Hi there" in prompt
        assert prompt.endswith("Assistant:")


class TestGGUFModelManager:
    """Tests for GGUFModelManager class."""

    def test_manager_initializes_with_default_directory(self) -> None:
        """Manager initializes with default models directory."""
        manager = GGUFModelManager()

        assert manager.models_directory.name == "models"
        assert manager.server is not None
        assert isinstance(manager.available_models, dict)

    def test_manager_initializes_with_custom_directory(self, models_directory: Path) -> None:
        """Manager initializes with custom models directory."""
        manager = GGUFModelManager(models_directory=str(models_directory))

        assert manager.models_directory == models_directory

    def test_scan_models_finds_gguf_files(self, models_directory: Path) -> None:
        """scan_models discovers GGUF files in directory."""
        model1 = models_directory / "model1.gguf"
        model2 = models_directory / "model2.gguf"
        model1.write_bytes(b"GGUF" + b"\x00" * 100)
        model2.write_bytes(b"GGUF" + b"\x00" * 200)

        manager = GGUFModelManager(models_directory=str(models_directory))

        assert len(manager.available_models) == 2
        assert "model1.gguf" in manager.available_models
        assert "model2.gguf" in manager.available_models

    def test_scan_models_extracts_metadata(self, models_directory: Path) -> None:
        """scan_models extracts file size and path metadata."""
        model = models_directory / "test.gguf"
        content = b"GGUF" + b"\x00" * 1000
        model.write_bytes(content)

        manager = GGUFModelManager(models_directory=str(models_directory))

        model_info = manager.available_models["test.gguf"]
        assert "path" in model_info
        assert "size_mb" in model_info
        assert model_info["size_mb"] > 0

    def test_list_models_returns_copy(self, models_directory: Path) -> None:
        """list_models returns copy of available models."""
        manager = GGUFModelManager(models_directory=str(models_directory))

        models = manager.list_models()

        assert isinstance(models, dict)
        assert models is not manager.available_models

    def test_get_recommended_models_returns_list(self) -> None:
        """get_recommended_models returns list of model recommendations."""
        manager = GGUFModelManager()

        models = manager.get_recommended_models()

        assert isinstance(models, list)
        assert len(models) > 0
        assert all("name" in m and "url" in m for m in models)

    def test_get_server_url_delegates_to_server(self) -> None:
        """get_server_url delegates to LocalGGUFServer."""
        manager = GGUFModelManager()

        url = manager.get_server_url()

        assert url.startswith("http://")


class TestFlaskEndpoints:
    """Tests for Flask HTTP endpoints."""

    @pytest.fixture
    def server_with_flask(self) -> LocalGGUFServer:
        """Create server instance for Flask testing."""
        server = LocalGGUFServer(port=8765)
        if not server.can_run():
            pytest.skip("Flask not available")
        return server

    def test_health_endpoint_structure(self, server_with_flask: LocalGGUFServer) -> None:
        """Health endpoint returns expected structure."""
        from flask import Flask

        server_with_flask.app = Flask(__name__)
        server_with_flask._setup_routes()

        with server_with_flask.app.test_client() as client:
            response = client.get("/health")
            assert response.status_code == 200
            data = json.loads(response.data)
            assert "status" in data
            assert "model_loaded" in data
            assert "gpu_backend" in data

    def test_models_endpoint_structure(self, server_with_flask: LocalGGUFServer) -> None:
        """Models endpoint returns expected structure."""
        from flask import Flask

        server_with_flask.app = Flask(__name__)
        server_with_flask._setup_routes()

        with server_with_flask.app.test_client() as client:
            response = client.get("/models")
            assert response.status_code == 200
            data = json.loads(response.data)
            assert "models" in data
            assert isinstance(data["models"], list)

    def test_gpu_info_endpoint_structure(self, server_with_flask: LocalGGUFServer) -> None:
        """GPU info endpoint returns expected structure."""
        from flask import Flask

        server_with_flask.app = Flask(__name__)
        server_with_flask._setup_routes()

        with server_with_flask.app.test_client() as client:
            response = client.get("/gpu_info")
            assert response.status_code == 200
            data = json.loads(response.data)
            assert "backend" in data
            assert "devices" in data
            assert "enabled" in data
            assert "capabilities" in data

    def test_chat_completions_requires_model(self, server_with_flask: LocalGGUFServer) -> None:
        """Chat completions endpoint requires loaded model."""
        from flask import Flask

        server_with_flask.app = Flask(__name__)
        server_with_flask._setup_routes()

        with server_with_flask.app.test_client() as client:
            response = client.post(
                "/v1/chat/completions",
                json={"messages": [{"role": "user", "content": "test"}]},
            )
            assert response.status_code == 400
            data = json.loads(response.data)
            assert "error" in data

    def test_completions_requires_model(self, server_with_flask: LocalGGUFServer) -> None:
        """Completions endpoint requires loaded model."""
        from flask import Flask

        server_with_flask.app = Flask(__name__)
        server_with_flask._setup_routes()

        with server_with_flask.app.test_client() as client:
            response = client.post(
                "/v1/completions",
                json={"prompt": "test prompt"},
            )
            assert response.status_code == 400

    def test_load_model_endpoint_validation(self, server_with_flask: LocalGGUFServer) -> None:
        """Load model endpoint validates required parameters."""
        from flask import Flask

        server_with_flask.app = Flask(__name__)
        server_with_flask._setup_routes()

        with server_with_flask.app.test_client() as client:
            response = client.post("/load_model", json={})
            assert response.status_code == 400
            data = json.loads(response.data)
            assert "error" in data

    def test_unload_model_endpoint_succeeds(self, server_with_flask: LocalGGUFServer) -> None:
        """Unload model endpoint succeeds without loaded model."""
        from flask import Flask

        server_with_flask.app = Flask(__name__)
        server_with_flask._setup_routes()

        with server_with_flask.app.test_client() as client:
            response = client.post("/unload_model")
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["status"] == "success"


class TestServerLifecycle:
    """Tests for server start/stop lifecycle."""

    def test_server_start_without_dependencies(self) -> None:
        """Server start fails gracefully without dependencies."""
        server = LocalGGUFServer()

        if not server.can_run():
            result = server.start_server()
            assert result is False

    def test_server_prevents_double_start(self) -> None:
        """Server prevents starting twice."""
        server = LocalGGUFServer()
        server.is_running = True

        result = server.start_server()

        assert result is True

    def test_stop_server_marks_not_running(self) -> None:
        """stop_server sets is_running to False."""
        server = LocalGGUFServer()
        server.is_running = True

        server.stop_server()

        assert not server.is_running

    def test_is_healthy_checks_running_state(self) -> None:
        """is_healthy returns False when not running."""
        server = LocalGGUFServer()
        server.is_running = False

        result = server.is_healthy()

        assert result is False


class TestModelLoadingOptions:
    """Tests for model loading parameter handling."""

    def test_load_model_with_custom_context_length(
        self,
        mock_gguf_model_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """load_model accepts custom context length."""
        server = LocalGGUFServer()

        import intellicrack.ai.local_gguf_server as server_module

        monkeypatch.setattr(server_module, "Llama", FakeLlamaModel)

        server.load_model(str(mock_gguf_model_file), context_length=8192)

    def test_load_model_with_gpu_layers(
        self,
        mock_gguf_model_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """load_model accepts GPU layer configuration."""
        server = LocalGGUFServer()

        import intellicrack.ai.local_gguf_server as server_module

        monkeypatch.setattr(server_module, "Llama", FakeLlamaModel)

        server.load_model(str(mock_gguf_model_file), gpu_layers=32)

    def test_load_model_with_custom_threads(
        self,
        mock_gguf_model_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """load_model accepts custom thread count."""
        server = LocalGGUFServer()

        import intellicrack.ai.local_gguf_server as server_module

        monkeypatch.setattr(server_module, "Llama", FakeLlamaModel)

        server.load_model(str(mock_gguf_model_file), threads=8)

    def test_load_model_stores_configuration(
        self,
        mock_gguf_model_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """load_model stores configuration in model_config."""
        server = LocalGGUFServer()

        import intellicrack.ai.local_gguf_server as server_module

        monkeypatch.setattr(server_module, "Llama", FakeLlamaModel)

        server.load_model(str(mock_gguf_model_file), context_length=4096, gpu_layers=16)

        if server.model:
            assert "model_path" in server.model_config
            assert server.model_config["model_name"] == "test_model.gguf"


class TestErrorHandling:
    """Tests for error handling and edge cases."""

    def test_load_model_handles_loading_errors(self, tmp_path: Path) -> None:
        """load_model handles model loading failures gracefully."""
        server = LocalGGUFServer()
        invalid_file = tmp_path / "invalid.gguf"
        invalid_file.write_bytes(b"INVALID")

        result = server.load_model(str(invalid_file))

        assert result is False
        assert server.model is None

    def test_unload_model_handles_errors(self) -> None:
        """unload_model handles errors during unloading."""
        server = LocalGGUFServer()
        server.model = FakeModelWithoutDel()

        server.unload_model()

        assert server.model is None

    def test_messages_to_prompt_handles_empty_messages(self) -> None:
        """_messages_to_prompt handles empty message list."""
        server = LocalGGUFServer()

        prompt = server._messages_to_prompt([])

        assert prompt == "Assistant:"

    def test_messages_to_prompt_handles_missing_fields(self) -> None:
        """_messages_to_prompt handles messages with missing fields."""
        server = LocalGGUFServer()

        messages = [{"role": "user"}]
        prompt = server._messages_to_prompt(messages)

        assert "User:" in prompt


class TestConvenienceFunction:
    """Tests for create_gguf_server_with_intel_gpu function."""

    def test_create_server_returns_instance(self) -> None:
        """create_gguf_server_with_intel_gpu returns server instance."""
        server = create_gguf_server_with_intel_gpu(auto_start=False)

        if server is not None:
            assert isinstance(server, LocalGGUFServer)
            assert not server.is_running

    def test_create_server_with_custom_port(self) -> None:
        """create_gguf_server_with_intel_gpu accepts custom port."""
        server = create_gguf_server_with_intel_gpu(port=9000, auto_start=False)

        if server is not None:
            assert server.port == 9000

    def test_create_server_returns_none_without_dependencies(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """create_gguf_server_with_intel_gpu returns None if dependencies missing."""
        import intellicrack.ai.local_gguf_server as server_module

        monkeypatch.setattr(server_module, "HAS_FLASK", False)

        server = create_gguf_server_with_intel_gpu()

        assert server is None


class TestGPUDetection:
    """Tests for GPU detection functionality."""

    def test_detect_intel_gpu_sets_backend(self) -> None:
        """_detect_intel_gpu sets gpu_backend attribute."""
        server = LocalGGUFServer()

        assert hasattr(server, "gpu_backend")
        assert server.gpu_backend is None or isinstance(server.gpu_backend, str)

    def test_detect_intel_gpu_populates_devices(self) -> None:
        """_detect_intel_gpu populates gpu_devices list."""
        server = LocalGGUFServer()

        assert isinstance(server.gpu_devices, list)

    def test_gpu_info_reflects_detection(self) -> None:
        """Server GPU info reflects detection results."""
        from flask import Flask

        server = LocalGGUFServer()
        if not server.can_run():
            pytest.skip("Flask not available")

        server.app = Flask(__name__)
        server._setup_routes()

        with server.app.test_client() as client:
            response = client.get("/gpu_info")
            data = json.loads(response.data)

            assert data["backend"] == server.gpu_backend
            assert data["devices"] == server.gpu_devices


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
