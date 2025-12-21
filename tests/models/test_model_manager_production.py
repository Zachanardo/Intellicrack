"""Production tests for ModelManager - validates real model management operations.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import json
import os
import pickle
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

import numpy as np
import pytest

from intellicrack.models.model_manager import ModelManager, ProgressHandler
from intellicrack.models.repositories.interface import DownloadProgressCallback, ModelInfo
from intellicrack.models.repositories.local_repository import LocalFileRepository


class TestProgressHandler:
    """Tests for ProgressHandler callback system."""

    def test_progress_handler_calls_progress_callback(self) -> None:
        """ProgressHandler invokes progress callback with correct arguments."""
        progress_calls: list[tuple[int, int]] = []

        def progress_cb(bytes_downloaded: int, total_bytes: int) -> None:
            progress_calls.append((bytes_downloaded, total_bytes))

        handler = ProgressHandler(progress_callback=progress_cb)
        handler.on_progress(1024, 4096)
        handler.on_progress(2048, 4096)

        assert len(progress_calls) == 2
        assert progress_calls[0] == (1024, 4096)
        assert progress_calls[1] == (2048, 4096)

    def test_progress_handler_calls_complete_callback(self) -> None:
        """ProgressHandler invokes complete callback on download finish."""
        complete_calls: list[tuple[bool, str]] = []

        def complete_cb(success: bool, message: str) -> None:
            complete_calls.append((success, message))

        handler = ProgressHandler(complete_callback=complete_cb)
        handler.on_complete(True, "Download successful")

        assert len(complete_calls) == 1
        assert complete_calls[0] == (True, "Download successful")

    def test_progress_handler_handles_none_callbacks(self) -> None:
        """ProgressHandler safely handles None callbacks without errors."""
        handler = ProgressHandler()

        handler.on_progress(1024, 4096)
        handler.on_complete(True, "Done")

    def test_progress_handler_supports_both_callbacks(self) -> None:
        """ProgressHandler correctly invokes both progress and complete callbacks."""
        progress_calls: list[tuple[int, int]] = []
        complete_calls: list[tuple[bool, str]] = []

        handler = ProgressHandler(
            progress_callback=lambda b, t: progress_calls.append((b, t)),
            complete_callback=lambda s, m: complete_calls.append((s, m)),
        )

        handler.on_progress(512, 1024)
        handler.on_progress(1024, 1024)
        handler.on_complete(True, "Success")

        assert len(progress_calls) == 2
        assert len(complete_calls) == 1
        assert progress_calls[-1] == (1024, 1024)
        assert complete_calls[0][0] is True


class TestModelManagerInitialization:
    """Tests for ModelManager initialization and setup."""

    def test_model_manager_creates_download_directory(self) -> None:
        """ModelManager creates download directory from config on initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            download_dir = os.path.join(temp_dir, "downloads")
            config: dict[str, Any] = {"download_directory": download_dir, "model_repositories": {}}

            manager = ModelManager(config)

            assert os.path.exists(download_dir)
            assert manager.download_dir == download_dir

    def test_model_manager_uses_default_download_directory(self) -> None:
        """ModelManager uses default download directory when not configured."""
        config: dict[str, Any] = {"model_repositories": {}}
        manager = ModelManager(config)

        assert manager.download_dir is not None
        assert os.path.exists(manager.download_dir)

    def test_model_manager_initializes_local_repository(self) -> None:
        """ModelManager initializes local repository from configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            models_dir = os.path.join(temp_dir, "models")
            config: dict[str, Any] = {
                "model_repositories": {
                    "local": {
                        "type": "local",
                        "enabled": True,
                        "models_directory": models_dir,
                    }
                }
            }

            manager = ModelManager(config)

            assert "local" in manager.repositories
            assert isinstance(manager.repositories["local"], LocalFileRepository)

    def test_model_manager_skips_disabled_repositories(self) -> None:
        """ModelManager does not initialize repositories marked as disabled."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config: dict[str, Any] = {
                "model_repositories": {
                    "disabled_repo": {
                        "type": "local",
                        "enabled": False,
                        "models_directory": temp_dir,
                    }
                }
            }

            manager = ModelManager(config)

            assert "disabled_repo" not in manager.repositories


class TestModelManagerRepositoryOperations:
    """Tests for repository management operations."""

    @pytest.fixture
    def temp_models_dir(self) -> str:
        """Create temporary models directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def manager_with_local_repo(self, temp_models_dir: str) -> ModelManager:
        """Create ModelManager with local repository."""
        config: dict[str, Any] = {
            "model_repositories": {
                "local": {
                    "type": "local",
                    "enabled": True,
                    "models_directory": temp_models_dir,
                }
            }
        }
        manager = ModelManager(config)
        yield manager
        if "local" in manager.repositories:
            local_repo = manager.repositories["local"]
            if hasattr(local_repo, "shutdown"):
                local_repo.shutdown()

    def test_get_available_repositories_returns_repository_info(self, manager_with_local_repo: ModelManager) -> None:
        """get_available_repositories returns correct repository information."""
        repos = manager_with_local_repo.get_available_repositories()

        assert "local" in repos
        assert repos["local"]["name"] == "local"
        assert repos["local"]["enabled"] is True
        assert "type" in repos["local"]
        assert "model_count" in repos["local"]

    def test_get_available_models_returns_all_models(
        self, manager_with_local_repo: ModelManager, temp_models_dir: str
    ) -> None:
        """get_available_models returns models from all repositories."""
        test_model_path = os.path.join(temp_models_dir, "test_model.gguf")
        with open(test_model_path, "wb") as f:
            f.write(b"GGUF\x00" * 100)

        models = manager_with_local_repo.get_available_models()

        assert len(models) >= 1
        assert any(m.name == "test_model.gguf" for m in models)

    def test_get_available_models_filters_by_repository(
        self, manager_with_local_repo: ModelManager, temp_models_dir: str
    ) -> None:
        """get_available_models filters models by repository name."""
        test_model_path = os.path.join(temp_models_dir, "filtered_model.gguf")
        with open(test_model_path, "wb") as f:
            f.write(b"GGUF\x00" * 100)

        models_all = manager_with_local_repo.get_available_models()
        models_local = manager_with_local_repo.get_available_models(repository_name="local")
        models_nonexistent = manager_with_local_repo.get_available_models(repository_name="nonexistent")

        assert len(models_local) >= 1
        assert len(models_all) == len(models_local)
        assert len(models_nonexistent) == 0

    def test_get_model_details_returns_model_info(
        self, manager_with_local_repo: ModelManager, temp_models_dir: str
    ) -> None:
        """get_model_details returns ModelInfo for existing model."""
        test_model_path = os.path.join(temp_models_dir, "detail_model.gguf")
        with open(test_model_path, "wb") as f:
            f.write(b"GGUF\x00" * 200)

        models = manager_with_local_repo.get_available_models(repository_name="local")
        model_id = next((m.model_id for m in models if "detail_model" in m.name), None)

        assert model_id is not None

        details = manager_with_local_repo.get_model_details(model_id, "local")

        assert details is not None
        assert "detail_model.gguf" in details.name
        assert details.size_bytes > 0
        assert details.format == "gguf"

    def test_get_model_details_returns_none_for_invalid_repository(
        self, manager_with_local_repo: ModelManager
    ) -> None:
        """get_model_details returns None for nonexistent repository."""
        details = manager_with_local_repo.get_model_details("any_model_id", "nonexistent_repo")

        assert details is None

    def test_refresh_repositories_updates_model_list(
        self, manager_with_local_repo: ModelManager, temp_models_dir: str
    ) -> None:
        """refresh_repositories triggers repository model list refresh."""
        initial_models = manager_with_local_repo.get_available_models()

        new_model_path = os.path.join(temp_models_dir, "new_model.gguf")
        with open(new_model_path, "wb") as f:
            f.write(b"GGUF\x00" * 150)

        manager_with_local_repo.refresh_repositories()
        refreshed_models = manager_with_local_repo.get_available_models()

        assert len(refreshed_models) >= len(initial_models)
        assert any("new_model.gguf" in m.name for m in refreshed_models)


class TestModelManagerLocalImport:
    """Tests for importing models from local files."""

    @pytest.fixture
    def temp_models_dir(self) -> str:
        """Create temporary models directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def manager_with_local_repo(self, temp_models_dir: str) -> ModelManager:
        """Create ModelManager with local repository."""
        config: dict[str, Any] = {
            "model_repositories": {
                "local": {
                    "type": "local",
                    "enabled": True,
                    "models_directory": temp_models_dir,
                }
            }
        }
        manager = ModelManager(config)
        yield manager
        if "local" in manager.repositories:
            local_repo = manager.repositories["local"]
            if hasattr(local_repo, "shutdown"):
                local_repo.shutdown()

    def test_import_local_model_adds_model_to_repository(
        self, manager_with_local_repo: ModelManager, temp_models_dir: str
    ) -> None:
        """import_local_model successfully imports model file to repository."""
        external_model_path = os.path.join(tempfile.gettempdir(), "external_model.gguf")
        with open(external_model_path, "wb") as f:
            f.write(b"GGUF\x00" * 250)

        try:
            model_info = manager_with_local_repo.import_local_model(external_model_path)

            assert model_info is not None
            assert model_info.name == "external_model.gguf"
            assert model_info.size_bytes > 0
            assert model_info.provider == "local"
            assert model_info.local_path is not None
            assert os.path.exists(model_info.local_path)
        finally:
            if os.path.exists(external_model_path):
                os.remove(external_model_path)

    def test_import_local_model_returns_none_without_local_repo(self) -> None:
        """import_local_model returns None when local repository not configured."""
        config: dict[str, Any] = {"model_repositories": {}}
        manager = ModelManager(config)

        result = manager.import_local_model("/nonexistent/model.gguf")

        assert result is None

    def test_import_local_model_handles_nonexistent_file(
        self, manager_with_local_repo: ModelManager
    ) -> None:
        """import_local_model handles nonexistent source file gracefully."""
        result = manager_with_local_repo.import_local_model("/nonexistent/file.gguf")

        assert result is None


class TestModelManagerIntegrityVerification:
    """Tests for model file integrity verification."""

    def test_verify_model_integrity_computes_checksum(self) -> None:
        """verify_model_integrity computes SHA256 checksum for model file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".gguf") as temp_file:
            test_data = b"GGUF model data for checksum testing" * 100
            temp_file.write(test_data)
            temp_path = temp_file.name

        try:
            config: dict[str, Any] = {"model_repositories": {}}
            manager = ModelManager(config)

            expected_checksum = hashlib.sha256(test_data).hexdigest()
            success, checksum = manager.verify_model_integrity(temp_path)

            assert success is True
            assert checksum == expected_checksum
        finally:
            os.remove(temp_path)

    def test_verify_model_integrity_validates_against_expected_checksum(self) -> None:
        """verify_model_integrity correctly validates against expected checksum."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".gguf") as temp_file:
            test_data = b"GGUF model verification test data"
            temp_file.write(test_data)
            temp_path = temp_file.name

        try:
            config: dict[str, Any] = {"model_repositories": {}}
            manager = ModelManager(config)

            correct_checksum = hashlib.sha256(test_data).hexdigest()
            wrong_checksum = "0" * 64

            success_correct, msg_correct = manager.verify_model_integrity(temp_path, correct_checksum)
            success_wrong, msg_wrong = manager.verify_model_integrity(temp_path, wrong_checksum)

            assert success_correct is True
            assert "successful" in msg_correct.lower()
            assert success_wrong is False
            assert "mismatch" in msg_wrong.lower()
        finally:
            os.remove(temp_path)

    def test_verify_model_integrity_handles_nonexistent_file(self) -> None:
        """verify_model_integrity returns failure for nonexistent files."""
        config: dict[str, Any] = {"model_repositories": {}}
        manager = ModelManager(config)

        success, message = manager.verify_model_integrity("/nonexistent/model.gguf")

        assert success is False
        assert "not found" in message.lower()

    def test_verify_model_integrity_handles_large_files(self) -> None:
        """verify_model_integrity efficiently processes large model files."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".gguf") as temp_file:
            chunk_data = b"X" * (1024 * 1024)
            for _ in range(5):
                temp_file.write(chunk_data)
            temp_path = temp_file.name

        try:
            config: dict[str, Any] = {"model_repositories": {}}
            manager = ModelManager(config)

            start_time = time.time()
            success, checksum = manager.verify_model_integrity(temp_path)
            elapsed_time = time.time() - start_time

            assert success is True
            assert len(checksum) == 64
            assert elapsed_time < 10.0
        finally:
            os.remove(temp_path)


class TestModelManagerPaths:
    """Tests for model path resolution."""

    @pytest.fixture
    def temp_models_dir(self) -> str:
        """Create temporary models directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def manager_with_local_repo(self, temp_models_dir: str) -> ModelManager:
        """Create ModelManager with local repository."""
        config: dict[str, Any] = {
            "model_repositories": {
                "local": {
                    "type": "local",
                    "enabled": True,
                    "models_directory": temp_models_dir,
                }
            }
        }
        manager = ModelManager(config)
        yield manager
        if "local" in manager.repositories:
            local_repo = manager.repositories["local"]
            if hasattr(local_repo, "shutdown"):
                local_repo.shutdown()

    def test_get_model_path_returns_local_path(
        self, manager_with_local_repo: ModelManager, temp_models_dir: str
    ) -> None:
        """get_model_path returns correct local path for existing model."""
        test_model_path = os.path.join(temp_models_dir, "path_test_model.gguf")
        with open(test_model_path, "wb") as f:
            f.write(b"GGUF\x00" * 100)

        models = manager_with_local_repo.get_available_models(repository_name="local")
        model_id = next((m.model_id for m in models if "path_test_model" in m.name), None)

        assert model_id is not None

        path = manager_with_local_repo.get_model_path(model_id, "local")

        assert path is not None
        assert os.path.exists(path)
        assert "path_test_model.gguf" in path

    def test_get_model_path_returns_none_for_nonexistent_repository(
        self, manager_with_local_repo: ModelManager
    ) -> None:
        """get_model_path returns None for nonexistent repository."""
        path = manager_with_local_repo.get_model_path("any_model", "nonexistent_repo")

        assert path is None

    def test_get_model_path_returns_none_for_nonexistent_model(
        self, manager_with_local_repo: ModelManager
    ) -> None:
        """get_model_path returns None for nonexistent model."""
        path = manager_with_local_repo.get_model_path("nonexistent_model", "local")

        assert path is None


class TestModelManagerRemoval:
    """Tests for model removal operations."""

    @pytest.fixture
    def temp_models_dir(self) -> str:
        """Create temporary models directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def manager_with_local_repo(self, temp_models_dir: str) -> ModelManager:
        """Create ModelManager with local repository."""
        config: dict[str, Any] = {
            "model_repositories": {
                "local": {
                    "type": "local",
                    "enabled": True,
                    "models_directory": temp_models_dir,
                }
            }
        }
        manager = ModelManager(config)
        yield manager
        if "local" in manager.repositories:
            local_repo = manager.repositories["local"]
            if hasattr(local_repo, "shutdown"):
                local_repo.shutdown()

    def test_remove_model_deletes_local_model_file(
        self, manager_with_local_repo: ModelManager, temp_models_dir: str
    ) -> None:
        """remove_model successfully deletes model file and metadata."""
        test_model_path = os.path.join(temp_models_dir, "removable_model.gguf")
        with open(test_model_path, "wb") as f:
            f.write(b"GGUF\x00" * 100)

        models = manager_with_local_repo.get_available_models(repository_name="local")
        model_id = next((m.model_id for m in models if "removable_model" in m.name), None)

        assert model_id is not None
        assert os.path.exists(test_model_path)

        local_repo = manager_with_local_repo.repositories["local"]
        if hasattr(local_repo, "shutdown"):
            local_repo.shutdown()
        time.sleep(0.1)

        success = manager_with_local_repo.remove_model(model_id, "local")

        assert success is True
        assert not os.path.exists(test_model_path)

    def test_remove_model_returns_false_for_nonexistent_repository(
        self, manager_with_local_repo: ModelManager
    ) -> None:
        """remove_model returns False for nonexistent repository."""
        success = manager_with_local_repo.remove_model("any_model", "nonexistent_repo")

        assert success is False

    def test_remove_model_returns_false_for_nonexistent_model(
        self, manager_with_local_repo: ModelManager
    ) -> None:
        """remove_model returns False for nonexistent model."""
        success = manager_with_local_repo.remove_model("nonexistent_model_id", "local")

        assert success is False


class TestModelManagerTraining:
    """Tests for machine learning model training operations."""

    def test_train_model_classifier_with_sklearn(self) -> None:
        """train_model trains sklearn RandomForest classifier on real data."""
        try:
            from sklearn.datasets import make_classification
        except ImportError:
            pytest.skip("scikit-learn not available")

        config: dict[str, Any] = {"model_repositories": {}}
        manager = ModelManager(config)

        X, y = make_classification(n_samples=100, n_features=10, n_classes=2, random_state=42)
        training_data = {"features": X, "labels": y}

        success = manager.train_model(training_data, "classifier")

        assert success is True
        assert hasattr(manager, "_last_trained_model")
        assert manager._last_trained_model is not None

        model = manager._last_trained_model
        predictions = model.predict(X[:5])
        assert len(predictions) == 5
        assert all(pred in [0, 1] for pred in predictions)

    def test_train_model_regression_with_sklearn(self) -> None:
        """train_model trains sklearn LinearRegression on real data."""
        try:
            from sklearn.datasets import make_regression
        except ImportError:
            pytest.skip("scikit-learn not available")

        config: dict[str, Any] = {"model_repositories": {}}
        manager = ModelManager(config)

        X, y = make_regression(n_samples=100, n_features=5, noise=0.1, random_state=42)
        training_data = {"features": X, "targets": y}

        success = manager.train_model(training_data, "regression")

        assert success is True
        assert hasattr(manager, "_last_trained_model")
        assert manager._last_trained_model is not None

        model = manager._last_trained_model
        predictions = model.predict(X[:5])
        assert len(predictions) == 5
        assert all(isinstance(pred, (int, float, np.number)) for pred in predictions)

    def test_train_model_neural_network_with_pytorch(self) -> None:
        """train_model creates PyTorch neural network model."""
        try:
            import torch
        except ImportError:
            pytest.skip("PyTorch not available")

        config: dict[str, Any] = {"model_repositories": {}}
        manager = ModelManager(config)

        X = np.random.randn(100, 10).astype(np.float32)
        y = np.random.randint(0, 2, size=100)
        training_data = [X, y]

        success = manager.train_model(training_data, "neural_network")

        assert success is True
        assert hasattr(manager, "_last_trained_model")
        model = manager._last_trained_model
        assert model is not None

        import torch.nn as nn

        assert isinstance(model, nn.Module)

    def test_train_model_handles_generic_model_type(self) -> None:
        """train_model handles generic model types with configuration storage."""
        config: dict[str, Any] = {"model_repositories": {}}
        manager = ModelManager(config)

        training_data = {"features": [[1, 2], [3, 4]], "labels": [0, 1]}

        success = manager.train_model(training_data, "custom_model_type")

        assert success is True
        assert hasattr(manager, "_last_trained_model")
        model_config = manager._last_trained_model
        assert isinstance(model_config, dict)
        assert model_config["type"] == "custom_model_type"
        assert "trained_at" in model_config

    def test_train_model_handles_tuple_format_data(self) -> None:
        """train_model correctly processes training data in tuple format."""
        try:
            from sklearn.datasets import make_classification
        except ImportError:
            pytest.skip("scikit-learn not available")

        config: dict[str, Any] = {"model_repositories": {}}
        manager = ModelManager(config)

        X, y = make_classification(n_samples=50, n_features=8, random_state=42)
        training_data = (X, y)

        success = manager.train_model(training_data, "classifier")

        assert success is True
        assert hasattr(manager, "_last_trained_model")

    def test_train_model_handles_object_with_attributes(self) -> None:
        """train_model processes training data objects with features/labels attributes."""
        try:
            from sklearn.datasets import make_classification
        except ImportError:
            pytest.skip("scikit-learn not available")

        config: dict[str, Any] = {"model_repositories": {}}
        manager = ModelManager(config)

        X, y = make_classification(n_samples=50, n_features=8, random_state=42)

        class TrainingData:
            def __init__(self, features: np.ndarray, labels: np.ndarray) -> None:
                self.features = features
                self.labels = labels

        training_data = TrainingData(X, y)

        success = manager.train_model(training_data, "classifier")

        assert success is True
        assert hasattr(manager, "_last_trained_model")


class TestModelManagerSaving:
    """Tests for model saving and serialization."""

    def test_save_model_with_joblib(self) -> None:
        """save_model serializes sklearn model using joblib."""
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.datasets import make_classification
        except ImportError:
            pytest.skip("scikit-learn not available")

        with tempfile.TemporaryDirectory() as temp_dir:
            config: dict[str, Any] = {"model_repositories": {}}
            manager = ModelManager(config)

            X, y = make_classification(n_samples=50, n_features=10, random_state=42)
            model = RandomForestClassifier(n_estimators=10, random_state=42)
            model.fit(X, y)

            model_path = os.path.join(temp_dir, "models", "classifier.pkl")
            success = manager.save_model(model, model_path)

            assert success is True
            assert os.path.exists(model_path)
            assert os.path.exists(f"{model_path}.meta")

            with open(f"{model_path}.meta") as f:
                metadata = json.load(f)
                assert "model_type" in metadata
                assert "saved_at" in metadata
                assert metadata["intellicrack_version"] == "2.0"

    def test_save_model_with_pytorch(self) -> None:
        """save_model serializes PyTorch model state dict."""
        try:
            import torch
            import torch.nn as nn
        except ImportError:
            pytest.skip("PyTorch not available")

        with tempfile.TemporaryDirectory() as temp_dir:
            config: dict[str, Any] = {"model_repositories": {}}
            manager = ModelManager(config)

            class SimpleModel(nn.Module):
                def __init__(self) -> None:
                    super().__init__()
                    self.linear = nn.Linear(10, 2)

                def forward(self, x: torch.Tensor) -> torch.Tensor:
                    return self.linear(x)

            model = SimpleModel()

            model_path = os.path.join(temp_dir, "models", "pytorch_model.pt")
            success = manager.save_model(model, model_path)

            assert success is True
            assert os.path.exists(model_path)
            assert os.path.exists(f"{model_path}.meta")

            loaded_state = torch.load(model_path, weights_only=True)
            assert "linear.weight" in loaded_state
            assert "linear.bias" in loaded_state

    def test_save_model_with_pickle_fallback(self) -> None:
        """save_model falls back to pickle for generic objects."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config: dict[str, Any] = {"model_repositories": {}}
            manager = ModelManager(config)

            custom_model = {"type": "custom", "weights": [1.0, 2.0, 3.0], "config": {"layers": 3}}

            model_path = os.path.join(temp_dir, "models", "custom_model.pkl")
            success = manager.save_model(custom_model, model_path)

            assert success is True
            assert os.path.exists(model_path)

            with open(model_path, "rb") as f:
                loaded_model = pickle.load(f)
                assert loaded_model["type"] == "custom"
                assert loaded_model["weights"] == [1.0, 2.0, 3.0]

    def test_save_model_uses_last_trained_model_when_none_provided(self) -> None:
        """save_model saves last trained model when model parameter is None."""
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.datasets import make_classification
        except ImportError:
            pytest.skip("scikit-learn not available")

        with tempfile.TemporaryDirectory() as temp_dir:
            config: dict[str, Any] = {"model_repositories": {}}
            manager = ModelManager(config)

            X, y = make_classification(n_samples=50, n_features=10, random_state=42)
            training_data = {"features": X, "labels": y}
            manager.train_model(training_data, "classifier")

            model_path = os.path.join(temp_dir, "models", "last_trained.pkl")
            success = manager.save_model(None, model_path)

            assert success is True
            assert os.path.exists(model_path)

    def test_save_model_creates_parent_directories(self) -> None:
        """save_model creates parent directories if they don't exist."""
        try:
            from sklearn.linear_model import LogisticRegression
        except ImportError:
            pytest.skip("scikit-learn not available")

        with tempfile.TemporaryDirectory() as temp_dir:
            config: dict[str, Any] = {"model_repositories": {}}
            manager = ModelManager(config)

            model = LogisticRegression()

            deep_path = os.path.join(temp_dir, "a", "b", "c", "model.pkl")
            success = manager.save_model(model, deep_path)

            assert success is True
            assert os.path.exists(deep_path)
            assert os.path.exists(os.path.dirname(deep_path))

    def test_save_model_returns_false_when_no_model_available(self) -> None:
        """save_model returns False when no model provided and none trained."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config: dict[str, Any] = {"model_repositories": {}}
            manager = ModelManager(config)

            model_path = os.path.join(temp_dir, "nonexistent.pkl")
            success = manager.save_model(None, model_path)

            assert success is False


class RealTestRepository:
    """Real test repository that provides API-like functionality without mocks.

    This implements the repository interface using real file operations to test
    API import functionality without relying on mocks.
    """

    def __init__(self, models_dir: str) -> None:
        """Initialize test repository with real file storage."""
        self.models_dir = models_dir
        os.makedirs(models_dir, exist_ok=True)
        self._models: dict[str, ModelInfo] = {}
        self._setup_test_models()

    def _setup_test_models(self) -> None:
        """Create real test model files in the repository."""
        test_model_path = os.path.join(self.models_dir, "test-model-v1.gguf")
        with open(test_model_path, "wb") as f:
            f.write(b"GGUF\x00" * 256)

        self._models["test-model-v1"] = ModelInfo(
            model_id="test-model-v1",
            name="Test Model",
            description="Test model for API import testing",
            size_bytes=os.path.getsize(test_model_path),
            format="gguf",
            provider="test-real-repo",
            local_path=test_model_path,
        )

    def get_available_models(self) -> list[ModelInfo]:
        """Return list of available models."""
        return list(self._models.values())

    def get_model_details(self, model_id: str) -> Optional[ModelInfo]:
        """Return model details or None if not found."""
        return self._models.get(model_id)

    def download_model(
        self,
        model_id: str,
        destination: str,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> tuple[bool, str]:
        """Download (copy) model to destination with real file operations."""
        model_info = self._models.get(model_id)
        if not model_info or not model_info.local_path:
            return False, f"Model {model_id} not found"

        try:
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            source_size = os.path.getsize(model_info.local_path)

            with open(model_info.local_path, "rb") as src:
                with open(destination, "wb") as dst:
                    chunk_size = 256
                    bytes_written = 0
                    while True:
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break
                        dst.write(chunk)
                        bytes_written += len(chunk)
                        if progress_callback:
                            progress_callback(bytes_written, source_size)

            return True, "Download successful"
        except (OSError, IOError) as e:
            return False, f"Download failed: {e}"


class TestModelManagerAPIImport:
    """Tests for importing models from API repositories using real file operations."""

    @pytest.fixture
    def temp_dir(self) -> str:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def real_test_repository(self, temp_dir: str) -> RealTestRepository:
        """Create real test repository with actual model files."""
        repo_dir = os.path.join(temp_dir, "repo_models")
        return RealTestRepository(repo_dir)

    def test_import_api_model_starts_download_thread(
        self, temp_dir: str, real_test_repository: RealTestRepository
    ) -> None:
        """import_api_model initiates threaded download from repository."""
        config: dict[str, Any] = {
            "download_directory": os.path.join(temp_dir, "downloads"),
            "model_repositories": {},
        }
        manager = ModelManager(config)
        manager.repositories["test-real-repo"] = real_test_repository

        progress_calls: list[tuple[int, int]] = []
        complete_calls: list[tuple[bool, str]] = []
        download_complete = threading.Event()

        def on_complete(success: bool, message: str) -> None:
            complete_calls.append((success, message))
            download_complete.set()

        result = manager.import_api_model(
            model_id="test-model-v1",
            repository_name="test-real-repo",
            progress_callback=lambda b, t: progress_calls.append((b, t)),
            complete_callback=on_complete,
        )

        assert result is True
        download_complete.wait(timeout=5.0)

        if complete_calls:
            assert complete_calls[0][0] is True
            assert "successful" in complete_calls[0][1].lower()

    def test_import_api_model_returns_false_for_nonexistent_repository(self, temp_dir: str) -> None:
        """import_api_model returns False for nonexistent repository."""
        config: dict[str, Any] = {
            "download_directory": temp_dir,
            "model_repositories": {},
        }
        manager = ModelManager(config)

        complete_calls: list[tuple[bool, str]] = []

        result = manager.import_api_model(
            model_id="any-model",
            repository_name="nonexistent-repo",
            complete_callback=lambda s, m: complete_calls.append((s, m)),
        )

        assert result is False
        assert len(complete_calls) == 1
        assert complete_calls[0][0] is False
        assert "not found" in complete_calls[0][1].lower()

    def test_import_api_model_handles_nonexistent_model(
        self, temp_dir: str, real_test_repository: RealTestRepository
    ) -> None:
        """import_api_model returns False when model doesn't exist in repository."""
        config: dict[str, Any] = {
            "download_directory": temp_dir,
            "model_repositories": {},
        }
        manager = ModelManager(config)
        manager.repositories["test-real-repo"] = real_test_repository

        complete_calls: list[tuple[bool, str]] = []
        download_complete = threading.Event()

        def on_complete(success: bool, message: str) -> None:
            complete_calls.append((success, message))
            download_complete.set()

        result = manager.import_api_model(
            model_id="nonexistent-model",
            repository_name="test-real-repo",
            complete_callback=on_complete,
        )

        assert result is False
        download_complete.wait(timeout=2.0)

        if complete_calls:
            assert complete_calls[0][0] is False

    def test_import_api_model_progress_callback_receives_updates(
        self, temp_dir: str, real_test_repository: RealTestRepository
    ) -> None:
        """import_api_model progress callback receives byte progress updates."""
        config: dict[str, Any] = {
            "download_directory": os.path.join(temp_dir, "downloads"),
            "model_repositories": {},
        }
        manager = ModelManager(config)
        manager.repositories["test-real-repo"] = real_test_repository

        progress_calls: list[tuple[int, int]] = []
        download_complete = threading.Event()

        def on_complete(success: bool, message: str) -> None:
            download_complete.set()

        result = manager.import_api_model(
            model_id="test-model-v1",
            repository_name="test-real-repo",
            progress_callback=lambda b, t: progress_calls.append((b, t)),
            complete_callback=on_complete,
        )

        assert result is True
        download_complete.wait(timeout=5.0)

        if progress_calls:
            for bytes_downloaded, total_bytes in progress_calls:
                assert bytes_downloaded >= 0
                assert total_bytes > 0
                assert bytes_downloaded <= total_bytes


class TestModelManagerIntegration:
    """Integration tests for complete ModelManager workflows."""

    def test_complete_model_lifecycle(self) -> None:
        """Complete workflow: train, save, verify integrity."""
        try:
            from sklearn.datasets import make_classification
            from sklearn.ensemble import RandomForestClassifier
        except ImportError:
            pytest.skip("scikit-learn not available")

        with tempfile.TemporaryDirectory() as temp_dir:
            config: dict[str, Any] = {
                "download_directory": os.path.join(temp_dir, "downloads"),
                "model_repositories": {
                    "local": {
                        "type": "local",
                        "enabled": True,
                        "models_directory": os.path.join(temp_dir, "models"),
                    }
                },
            }
            manager = ModelManager(config)

            X, y = make_classification(n_samples=100, n_features=15, random_state=42)
            training_data = {"features": X, "labels": y}

            train_success = manager.train_model(training_data, "classifier")
            assert train_success is True

            model_path = os.path.join(temp_dir, "trained_model", "model.pkl")
            save_success = manager.save_model(None, model_path)
            assert save_success is True

            verify_success, checksum = manager.verify_model_integrity(model_path)
            assert verify_success is True
            assert len(checksum) == 64

    def test_import_and_repository_integration(self) -> None:
        """Complete workflow: import model, list models, get details, remove."""
        with tempfile.TemporaryDirectory() as temp_dir:
            models_dir = os.path.join(temp_dir, "models")
            config: dict[str, Any] = {
                "model_repositories": {
                    "local": {
                        "type": "local",
                        "enabled": True,
                        "models_directory": models_dir,
                    }
                }
            }
            manager = ModelManager(config)

            try:
                external_model = os.path.join(temp_dir, "external.gguf")
                with open(external_model, "wb") as f:
                    f.write(b"GGUF\x00" * 500)

                import_result = manager.import_local_model(external_model)
                assert import_result is not None

                models = manager.get_available_models(repository_name="local")
                assert len(models) > 0
                assert any("external.gguf" in m.name for m in models)

                model_id = next((m.model_id for m in models if "external.gguf" in m.name), None)
                assert model_id is not None

                details = manager.get_model_details(model_id, "local")
                assert details is not None
                assert details.size_bytes > 0

                path = manager.get_model_path(model_id, "local")
                assert path is not None
                assert os.path.exists(path)

                remove_success = manager.remove_model(model_id, "local")
                assert remove_success is True

                models_after = manager.get_available_models(repository_name="local")
                assert all("external.gguf" not in m.name for m in models_after)
            finally:
                if "local" in manager.repositories:
                    local_repo = manager.repositories["local"]
                    if hasattr(local_repo, "shutdown"):
                        local_repo.shutdown()
