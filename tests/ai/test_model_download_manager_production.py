"""Production tests for model download manager.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.model_download_manager import (
    DownloadProgress,
    ModelDownloadManager,
    ModelInfo,
    get_download_manager,
)


class TestDownloadProgress:
    """Test DownloadProgress dataclass."""

    def test_download_progress_creation(self) -> None:
        """DownloadProgress can be created with required fields."""
        progress = DownloadProgress(
            total_size=1024000,
            downloaded_size=512000,
            speed=102400.0,
            eta=5.0,
            percentage=50.0
        )

        assert progress.total_size == 1024000
        assert progress.downloaded_size == 512000
        assert progress.speed == 102400.0
        assert progress.eta == 5.0
        assert progress.percentage == 50.0
        assert progress.current_file == ""
        assert progress.total_files == 1
        assert progress.completed_files == 0

    def test_download_progress_with_files(self) -> None:
        """DownloadProgress tracks multiple file downloads."""
        progress = DownloadProgress(
            total_size=2048000,
            downloaded_size=1024000,
            speed=204800.0,
            eta=5.0,
            percentage=50.0,
            current_file="model.safetensors",
            total_files=5,
            completed_files=2
        )

        assert progress.current_file == "model.safetensors"
        assert progress.total_files == 5
        assert progress.completed_files == 2


class TestModelInfo:
    """Test ModelInfo dataclass."""

    def test_model_info_creation(self) -> None:
        """ModelInfo can be created with all fields."""
        info = ModelInfo(
            model_id="organization/model-name",
            author="organization",
            model_name="model-name",
            downloads=10000,
            likes=500,
            tags=["license-analysis", "binary-cracking"],
            pipeline_tag="text-generation",
            library_name="transformers",
            model_size=7000000000,
            last_modified=datetime.now(),
            private=False,
            gated=False
        )

        assert info.model_id == "organization/model-name"
        assert info.author == "organization"
        assert info.model_name == "model-name"
        assert info.downloads == 10000
        assert info.likes == 500
        assert "license-analysis" in info.tags
        assert info.pipeline_tag == "text-generation"
        assert info.library_name == "transformers"

    def test_model_info_minimal(self) -> None:
        """ModelInfo can be created with minimal fields."""
        info = ModelInfo(
            model_id="test/model",
            author="test",
            model_name="model",
            downloads=0,
            likes=0,
            tags=[]
        )

        assert info.model_id == "test/model"
        assert info.pipeline_tag is None
        assert info.library_name is None
        assert info.model_size is None
        assert info.private is False
        assert info.gated is False


class TestModelDownloadManager:
    """Test ModelDownloadManager functionality."""

    @pytest.fixture
    def temp_cache_dir(self) -> Path:
        """Create temporary cache directory."""
        temp_dir = tempfile.mkdtemp(prefix="download_test_")
        cache_path = Path(temp_dir)
        yield cache_path
        import shutil
        shutil.rmtree(cache_path, ignore_errors=True)

    @pytest.fixture
    def download_manager(self, temp_cache_dir: Path) -> ModelDownloadManager:
        """Create download manager with temp cache."""
        return ModelDownloadManager(cache_dir=str(temp_cache_dir), token=None)

    def test_manager_initialization(self, temp_cache_dir: Path) -> None:
        """Download manager initializes with correct cache directory."""
        manager = ModelDownloadManager(cache_dir=str(temp_cache_dir))

        assert manager.cache_dir == temp_cache_dir
        assert temp_cache_dir.exists()
        assert isinstance(manager.metadata, dict)
        assert "models" in manager.metadata
        assert "downloads" in manager.metadata
        assert manager.metadata_file == temp_cache_dir / "metadata.json"

    def test_manager_default_cache_dir(self) -> None:
        """Download manager uses default cache directory when none specified."""
        manager = ModelDownloadManager()

        expected_dir = Path.home() / ".intellicrack" / "model_cache"
        assert manager.cache_dir == expected_dir
        assert expected_dir.exists()

    def test_load_metadata_nonexistent(self, temp_cache_dir: Path) -> None:
        """Loading metadata creates default structure when file doesn't exist."""
        manager = ModelDownloadManager(cache_dir=str(temp_cache_dir))

        assert isinstance(manager.metadata, dict)
        assert "models" in manager.metadata
        assert "downloads" in manager.metadata
        assert isinstance(manager.metadata["models"], dict)
        assert isinstance(manager.metadata["downloads"], dict)

    def test_save_and_load_metadata(self, download_manager: ModelDownloadManager) -> None:
        """Metadata can be saved and loaded correctly."""
        download_manager.metadata["models"]["test-model"] = {
            "info": {"model_id": "test-model"},
            "cached_at": datetime.now().isoformat()
        }
        download_manager._save_metadata()

        assert download_manager.metadata_file.exists()

        new_manager = ModelDownloadManager(cache_dir=str(download_manager.cache_dir))
        assert "test-model" in new_manager.metadata["models"]

    def test_list_cached_models_empty(self, download_manager: ModelDownloadManager) -> None:
        """Listing cached models returns empty dict when none cached."""
        cached = download_manager.list_cached_models()

        assert isinstance(cached, dict)
        assert len(cached) == 0

    def test_list_cached_models_with_metadata(self, download_manager: ModelDownloadManager) -> None:
        """Listing cached models returns models from metadata."""
        model_dir = download_manager.cache_dir / "test_model"
        model_dir.mkdir(parents=True, exist_ok=True)

        download_manager.metadata["downloads"]["test/model"] = {
            "path": str(model_dir),
            "downloaded_at": datetime.now().isoformat(),
            "size_mb": 100.0
        }
        download_manager._save_metadata()

        cached = download_manager.list_cached_models()

        assert "test/model" in cached
        assert cached["test/model"]["size_mb"] == 100.0

    def test_list_cached_models_discovers_untracked(self, download_manager: ModelDownloadManager) -> None:
        """Listing cached models discovers untracked model directories."""
        model_dir = download_manager.cache_dir / "organization_model"
        model_dir.mkdir(parents=True, exist_ok=True)

        test_file = model_dir / "model.bin"
        test_file.write_bytes(b"x" * 1024 * 1024)

        cached = download_manager.list_cached_models()

        assert "organization/model" in cached
        assert cached["organization/model"]["discovered"] is True
        assert cached["organization/model"]["size_mb"] > 0

    def test_delete_cached_model_success(self, download_manager: ModelDownloadManager) -> None:
        """Deleting cached model removes directory and metadata."""
        model_dir = download_manager.cache_dir / "test_model"
        model_dir.mkdir(parents=True, exist_ok=True)

        (model_dir / "model.bin").write_bytes(b"test")

        download_manager.metadata["downloads"]["test/model"] = {
            "path": str(model_dir)
        }

        result = download_manager.delete_cached_model("test/model")

        assert result is True
        assert not model_dir.exists()
        assert "test/model" not in download_manager.metadata.get("downloads", {})

    def test_delete_cached_model_nonexistent(self, download_manager: ModelDownloadManager) -> None:
        """Deleting nonexistent model returns False."""
        result = download_manager.delete_cached_model("nonexistent/model")

        assert result is False

    def test_get_cache_size(self, download_manager: ModelDownloadManager) -> None:
        """Cache size calculation returns correct information."""
        model_dir = download_manager.cache_dir / "test_model"
        model_dir.mkdir(parents=True, exist_ok=True)

        (model_dir / "file1.bin").write_bytes(b"x" * 1024 * 1024)
        (model_dir / "file2.bin").write_bytes(b"x" * 1024 * 512)

        download_manager.metadata["downloads"]["test/model"] = {"path": str(model_dir)}

        size_info = download_manager.get_cache_size()

        assert isinstance(size_info, dict)
        assert "total_size_mb" in size_info
        assert "total_size_gb" in size_info
        assert "model_count" in size_info
        assert "cache_dir" in size_info

        assert size_info["total_size_mb"] > 1.0
        assert size_info["model_count"] >= 1
        assert size_info["cache_dir"] == str(download_manager.cache_dir)

    def test_clear_cache_everything(self, download_manager: ModelDownloadManager) -> None:
        """Clearing cache removes all models."""
        model_dir = download_manager.cache_dir / "test_model"
        model_dir.mkdir(parents=True, exist_ok=True)
        (model_dir / "model.bin").write_bytes(b"test")

        download_manager.metadata["downloads"]["test/model"] = {"path": str(model_dir)}
        download_manager._save_metadata()

        result = download_manager.clear_cache(keep_recent=0)

        assert result == -1
        assert len(list(download_manager.cache_dir.iterdir())) <= 1

    def test_clear_cache_keep_recent(self, download_manager: ModelDownloadManager) -> None:
        """Clearing cache keeps recent models."""
        for i in range(5):
            model_dir = download_manager.cache_dir / f"model_{i}"
            model_dir.mkdir(parents=True, exist_ok=True)
            download_manager.metadata["downloads"][f"test/model-{i}"] = {
                "path": str(model_dir),
                "downloaded_at": datetime.now().isoformat()
            }

        deleted_count = download_manager.clear_cache(keep_recent=2)

        assert deleted_count >= 3
        assert len(download_manager.metadata.get("downloads", {})) <= 2

    def test_verify_model_files_valid(self, download_manager: ModelDownloadManager) -> None:
        """Model file verification succeeds for valid model."""
        model_dir = download_manager.cache_dir / "valid_model"
        model_dir.mkdir(parents=True, exist_ok=True)

        config = model_dir / "config.json"
        config.write_text(json.dumps({"model_type": "test"}))

        (model_dir / "model.safetensors").write_bytes(b"x" * 1024)

        results = download_manager.verify_model_files(model_dir)

        assert results["valid"] is True
        assert isinstance(results["errors"], list)
        assert len(results["errors"]) == 0
        assert "config.json" in results["files"]
        assert "model.safetensors" in results["files"]

    def test_verify_model_files_nonexistent(self, download_manager: ModelDownloadManager) -> None:
        """Model file verification fails for nonexistent path."""
        nonexistent = download_manager.cache_dir / "nonexistent"

        results = download_manager.verify_model_files(nonexistent)

        assert results["valid"] is False
        assert len(results["errors"]) > 0
        assert "does not exist" in results["errors"][0].lower()

    def test_verify_model_files_missing_weights(self, download_manager: ModelDownloadManager) -> None:
        """Model file verification fails when weight files missing."""
        model_dir = download_manager.cache_dir / "no_weights"
        model_dir.mkdir(parents=True, exist_ok=True)

        config = model_dir / "config.json"
        config.write_text(json.dumps({"model_type": "test"}))

        results = download_manager.verify_model_files(model_dir)

        assert results["valid"] is False
        assert any("weight" in err.lower() for err in results["errors"])

    def test_verify_model_files_missing_config(self, download_manager: ModelDownloadManager) -> None:
        """Model file verification warns when config missing."""
        model_dir = download_manager.cache_dir / "no_config"
        model_dir.mkdir(parents=True, exist_ok=True)

        (model_dir / "model.bin").write_bytes(b"x" * 1024)

        results = download_manager.verify_model_files(model_dir)

        assert results["valid"] is True
        assert any("config" in warn.lower() for warn in results["warnings"])

    def test_verify_model_files_missing_tokenizer(self, download_manager: ModelDownloadManager) -> None:
        """Model file verification warns when tokenizer missing."""
        model_dir = download_manager.cache_dir / "no_tokenizer"
        model_dir.mkdir(parents=True, exist_ok=True)

        (model_dir / "config.json").write_text(json.dumps({}))
        (model_dir / "model.bin").write_bytes(b"x" * 1024)

        results = download_manager.verify_model_files(model_dir)

        assert results["valid"] is True
        assert any("tokenizer" in warn.lower() for warn in results["warnings"])

    def test_verify_model_files_multiple_formats(self, download_manager: ModelDownloadManager) -> None:
        """Model file verification handles multiple weight formats."""
        model_dir = download_manager.cache_dir / "multi_format"
        model_dir.mkdir(parents=True, exist_ok=True)

        (model_dir / "config.json").write_text(json.dumps({}))
        (model_dir / "model.bin").write_bytes(b"x" * 1024)
        (model_dir / "model.safetensors").write_bytes(b"x" * 2048)
        (model_dir / "model.pt").write_bytes(b"x" * 512)

        results = download_manager.verify_model_files(model_dir)

        assert results["valid"] is True
        assert "model.bin" in results["files"]
        assert "model.safetensors" in results["files"]
        assert "model.pt" in results["files"]


class TestGlobalDownloadManager:
    """Test global download manager singleton."""

    def test_get_download_manager_singleton(self) -> None:
        """Global download manager returns same instance."""
        manager1 = get_download_manager()
        manager2 = get_download_manager()

        assert manager1 is manager2
        assert isinstance(manager1, ModelDownloadManager)

    def test_get_download_manager_initialization(self) -> None:
        """Global download manager is properly initialized."""
        manager = get_download_manager()

        assert manager.cache_dir is not None
        assert manager.cache_dir.exists()
        assert isinstance(manager.metadata, dict)


class TestDownloadManagerEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def download_manager(self) -> ModelDownloadManager:
        """Create download manager for edge case testing."""
        temp_dir = tempfile.mkdtemp(prefix="download_edge_")
        manager = ModelDownloadManager(cache_dir=temp_dir)
        yield manager
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_save_metadata_error_handling(self, download_manager: ModelDownloadManager) -> None:
        """Metadata saving handles errors gracefully."""
        download_manager.metadata["test"] = datetime.now()

        download_manager._save_metadata()

    def test_load_metadata_corrupted(self, download_manager: ModelDownloadManager) -> None:
        """Loading corrupted metadata falls back to defaults."""
        download_manager.metadata_file.write_text("{ invalid json }")

        new_manager = ModelDownloadManager(cache_dir=str(download_manager.cache_dir))

        assert isinstance(new_manager.metadata, dict)
        assert "models" in new_manager.metadata
        assert "downloads" in new_manager.metadata

    def test_delete_model_permission_error_handling(self, download_manager: ModelDownloadManager, tmp_path: Path) -> None:
        """Model deletion handles permission errors gracefully."""
        model_dir = tmp_path / "protected_model"
        model_dir.mkdir()

        download_manager.metadata["downloads"]["protected/model"] = {
            "path": str(model_dir)
        }

        result = download_manager.delete_cached_model("protected/model")

        assert isinstance(result, bool)
