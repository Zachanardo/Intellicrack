import json
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.api_provider_clients import ModelInfo
from intellicrack.ai.model_discovery_service import ModelDiscoveryService


@pytest.fixture
def temp_cache_file() -> Path:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        cache_path = Path(f.name)
    yield cache_path
    if cache_path.exists():
        cache_path.unlink()


@pytest.fixture
def sample_model_data() -> dict[str, list[ModelInfo]]:
    return {
        "OpenAI": [
            ModelInfo(
                id="gpt-4o",
                name="gpt-4o",
                provider="OpenAI",
                description="Most capable GPT-4 model",
                context_length=128000,
                capabilities=["text-generation", "chat", "function-calling", "vision"],
            ),
            ModelInfo(
                id="gpt-4-turbo",
                name="gpt-4-turbo",
                provider="OpenAI",
                description="High performance GPT-4 model",
                context_length=128000,
                capabilities=["text-generation", "chat", "function-calling", "vision"],
            ),
        ],
        "Anthropic": [
            ModelInfo(
                id="claude-3-5-sonnet-20241022",
                name="Claude 3.5 Sonnet",
                provider="Anthropic",
                description="Most intelligent Claude model",
                context_length=200000,
                capabilities=["text-generation", "chat", "vision", "tool-use"],
            ),
        ],
    }


@pytest.fixture
def sample_cache_json() -> dict[str, Any]:
    return {
        "version": "1.0",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "cache_ttl_seconds": 300,
        "auto_update_interval_hours": 6,
        "providers": {
            "OpenAI": [
                {
                    "id": "gpt-4o",
                    "name": "gpt-4o",
                    "provider": "OpenAI",
                    "description": "Most capable GPT-4 model",
                    "context_length": 128000,
                    "capabilities": ["text-generation", "chat", "function-calling", "vision"],
                    "pricing": None,
                },
                {
                    "id": "gpt-4-turbo",
                    "name": "gpt-4-turbo",
                    "provider": "OpenAI",
                    "description": "High performance GPT-4 model",
                    "context_length": 128000,
                    "capabilities": ["text-generation", "chat", "function-calling", "vision"],
                    "pricing": None,
                },
            ],
            "Anthropic": [
                {
                    "id": "claude-3-5-sonnet-20241022",
                    "name": "Claude 3.5 Sonnet",
                    "provider": "Anthropic",
                    "description": "Most intelligent Claude model",
                    "context_length": 200000,
                    "capabilities": ["text-generation", "chat", "vision", "tool-use"],
                    "pricing": None,
                },
            ],
        },
    }


class TestModelDiscoveryServiceCacheOperations:

    def test_load_cache_from_disk_success(
        self, temp_cache_file: Path, sample_cache_json: dict[str, Any]
    ) -> None:
        with open(temp_cache_file, "w", encoding="utf-8") as f:
            json.dump(sample_cache_json, f, indent=2)

        service = ModelDiscoveryService(cache_file=temp_cache_file)

        assert len(service._cached_models) == 2
        assert "OpenAI" in service._cached_models
        assert "Anthropic" in service._cached_models
        assert len(service._cached_models["OpenAI"]) == 2
        assert len(service._cached_models["Anthropic"]) == 1

        openai_model = service._cached_models["OpenAI"][0]
        assert openai_model.id == "gpt-4o"
        assert openai_model.context_length == 128000
        assert "vision" in openai_model.capabilities

    def test_load_cache_from_disk_missing_file(self, temp_cache_file: Path) -> None:
        if temp_cache_file.exists():
            temp_cache_file.unlink()

        service = ModelDiscoveryService(cache_file=temp_cache_file)

        assert len(service._cached_models) == 0
        assert service._cache_timestamp == 0

    def test_load_cache_from_disk_invalid_json(self, temp_cache_file: Path) -> None:
        with open(temp_cache_file, "w", encoding="utf-8") as f:
            f.write("{invalid json content")

        service = ModelDiscoveryService(cache_file=temp_cache_file)

        assert len(service._cached_models) == 0

    def test_save_cache_to_disk_success(
        self, temp_cache_file: Path, sample_model_data: dict[str, list[ModelInfo]]
    ) -> None:
        service = ModelDiscoveryService(cache_file=temp_cache_file)

        result = service._save_cache_to_disk(sample_model_data)

        assert result is True
        assert temp_cache_file.exists()

        with open(temp_cache_file, encoding="utf-8") as f:
            saved_data = json.load(f)

        assert saved_data["version"] == "1.0"
        assert "last_updated" in saved_data
        assert saved_data["cache_ttl_seconds"] == 300
        assert "providers" in saved_data
        assert "OpenAI" in saved_data["providers"]
        assert "Anthropic" in saved_data["providers"]
        assert len(saved_data["providers"]["OpenAI"]) == 2
        assert saved_data["providers"]["OpenAI"][0]["id"] == "gpt-4o"
        assert saved_data["providers"]["OpenAI"][0]["context_length"] == 128000

    def test_save_cache_to_disk_creates_parent_directory(
        self, sample_model_data: dict[str, list[ModelInfo]]
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "subdir" / "cache.json"
            assert not cache_path.parent.exists()

            service = ModelDiscoveryService(cache_file=cache_path)
            result = service._save_cache_to_disk(sample_model_data)

            assert result is True
            assert cache_path.parent.exists()
            assert cache_path.exists()


class TestModelDiscoveryServiceNewModelDetection:

    def test_detect_new_models_new_provider(
        self, temp_cache_file: Path, sample_cache_json: dict[str, Any]
    ) -> None:
        with open(temp_cache_file, "w", encoding="utf-8") as f:
            json.dump(sample_cache_json, f, indent=2)

        service = ModelDiscoveryService(cache_file=temp_cache_file)

        new_models = {
            "OpenAI": [
                ModelInfo(
                    id="gpt-4o",
                    name="gpt-4o",
                    provider="OpenAI",
                    description="Most capable GPT-4 model",
                    context_length=128000,
                    capabilities=["text-generation", "chat"],
                ),
            ],
            "Ollama": [
                ModelInfo(
                    id="llama3:latest",
                    name="llama3:latest",
                    provider="Ollama",
                    description="Local model",
                    context_length=8192,
                    capabilities=["text-generation"],
                ),
            ],
        }

        new_model_ids = service._detect_new_models(new_models)

        assert "Ollama" in new_model_ids
        assert "llama3:latest" in new_model_ids["Ollama"]

    def test_detect_new_models_existing_provider_new_model(
        self, temp_cache_file: Path, sample_cache_json: dict[str, Any]
    ) -> None:
        with open(temp_cache_file, "w", encoding="utf-8") as f:
            json.dump(sample_cache_json, f, indent=2)

        service = ModelDiscoveryService(cache_file=temp_cache_file)

        new_models = {
            "OpenAI": [
                ModelInfo(
                    id="gpt-4o",
                    name="gpt-4o",
                    provider="OpenAI",
                    description="Existing model",
                    context_length=128000,
                    capabilities=["text-generation"],
                ),
                ModelInfo(
                    id="gpt-5",
                    name="gpt-5",
                    provider="OpenAI",
                    description="Brand new model",
                    context_length=256000,
                    capabilities=["text-generation", "chat"],
                ),
            ],
        }

        new_model_ids = service._detect_new_models(new_models)

        assert "OpenAI" in new_model_ids
        assert "gpt-5" in new_model_ids["OpenAI"]
        assert "gpt-4o" not in new_model_ids["OpenAI"]

    def test_detect_new_models_no_changes(
        self, temp_cache_file: Path, sample_cache_json: dict[str, Any]
    ) -> None:
        with open(temp_cache_file, "w", encoding="utf-8") as f:
            json.dump(sample_cache_json, f, indent=2)

        service = ModelDiscoveryService(cache_file=temp_cache_file)

        new_models = {
            "OpenAI": [
                ModelInfo(
                    id="gpt-4o",
                    name="gpt-4o",
                    provider="OpenAI",
                    description="Existing model",
                    context_length=128000,
                    capabilities=["text-generation"],
                ),
                ModelInfo(
                    id="gpt-4-turbo",
                    name="gpt-4-turbo",
                    provider="OpenAI",
                    description="Existing model",
                    context_length=128000,
                    capabilities=["text-generation"],
                ),
            ],
        }

        new_model_ids = service._detect_new_models(new_models)

        assert len(new_model_ids) == 0

    def test_detect_new_models_empty_cache(self, temp_cache_file: Path) -> None:
        if temp_cache_file.exists():
            temp_cache_file.unlink()

        service = ModelDiscoveryService(cache_file=temp_cache_file)

        new_models = {
            "OpenAI": [
                ModelInfo(
                    id="gpt-4o",
                    name="gpt-4o",
                    provider="OpenAI",
                    description="Model",
                    context_length=128000,
                    capabilities=["text-generation"],
                ),
            ],
        }

        new_model_ids = service._detect_new_models(new_models)

        assert len(new_model_ids) == 0


class TestModelDiscoveryServiceBackgroundUpdater:

    def test_background_updater_start_stop(self, temp_cache_file: Path) -> None:
        service = ModelDiscoveryService(cache_file=temp_cache_file)

        assert service._update_thread is None

        service.start_background_updater()

        assert service._update_thread is not None
        assert service._update_thread.is_alive()
        assert service._update_thread.name == "ModelDiscoveryUpdater"
        assert service._update_thread.daemon is True

        service.stop_background_updater()

        assert service._update_thread is None

    def test_background_updater_already_running(self, temp_cache_file: Path) -> None:
        service = ModelDiscoveryService(cache_file=temp_cache_file)

        service.start_background_updater()
        thread1 = service._update_thread

        service.start_background_updater()
        thread2 = service._update_thread

        assert thread1 is thread2

        service.stop_background_updater()

    def test_background_updater_thread_safety(self, temp_cache_file: Path) -> None:
        service = ModelDiscoveryService(cache_file=temp_cache_file)

        assert isinstance(service._cache_lock, type(threading.RLock()))

        with service._cache_lock:
            assert service._cached_models is not None

        service.start_background_updater()
        service.stop_background_updater()


class TestModelDiscoveryServiceCacheClear:

    def test_clear_cache(
        self, temp_cache_file: Path, sample_cache_json: dict[str, Any]
    ) -> None:
        with open(temp_cache_file, "w", encoding="utf-8") as f:
            json.dump(sample_cache_json, f, indent=2)

        service = ModelDiscoveryService(cache_file=temp_cache_file)

        assert len(service._cached_models) > 0
        assert service._cache_timestamp > 0

        service.clear_cache()

        assert len(service._cached_models) == 0
        assert service._cache_timestamp == 0
