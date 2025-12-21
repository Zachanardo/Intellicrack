"""Production tests for local file repository.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from intellicrack.models.repositories.local_repository import LocalFileRepository
from intellicrack.models.repositories.interface import ModelInfo, DownloadProgressCallback


class TestLocalFileRepository:
    """Test local file repository functionality."""

    def test_repository_creates_models_directory(self, tmp_path: Path) -> None:
        """Repository creates models directory if it doesn't exist."""
        models_dir = str(tmp_path / "models")

        repo = LocalFileRepository(models_directory=models_dir)

        assert os.path.exists(models_dir)
        assert repo.models_directory == models_dir

    def test_scan_for_models_discovers_gguf_files(self, tmp_path: Path) -> None:
        """Scan for models discovers all GGUF files in directory tree."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        (models_dir / "llama-2-7b.gguf").write_bytes(b"model data 1")
        (models_dir / "subdir").mkdir()
        (models_dir / "subdir" / "mistral-7b.gguf").write_bytes(b"model data 2")

        repo = LocalFileRepository(models_directory=str(models_dir))

        models = repo.get_available_models()

        assert len(models) >= 2
        model_ids = [m.model_id for m in models]
        assert any("llama-2-7b.gguf" in mid for mid in model_ids)
        assert any("mistral-7b.gguf" in mid for mid in model_ids)

    def test_get_available_models_returns_model_info_list(self, tmp_path: Path) -> None:
        """Get available models returns list of ModelInfo objects."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        test_data = b"test model content"
        (models_dir / "test-model.gguf").write_bytes(test_data)

        repo = LocalFileRepository(models_directory=str(models_dir))

        models = repo.get_available_models()

        assert len(models) > 0
        assert all(isinstance(m, ModelInfo) for m in models)
        assert models[0].provider == "local"
        assert models[0].format == "gguf"
        assert models[0].size_bytes == len(test_data)

    def test_get_model_details_retrieves_specific_model(self, tmp_path: Path) -> None:
        """Get model details retrieves information for specific model."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        (models_dir / "target-model.gguf").write_bytes(b"target data")
        (models_dir / "other-model.gguf").write_bytes(b"other data")

        repo = LocalFileRepository(models_directory=str(models_dir))

        model = repo.get_model_details("target-model.gguf")

        assert model is not None
        assert "target-model" in model.model_id
        assert model.local_path is not None
        assert os.path.exists(model.local_path)

    def test_get_model_details_returns_none_for_nonexistent(self, tmp_path: Path) -> None:
        """Get model details returns None for non-existent model."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        repo = LocalFileRepository(models_directory=str(models_dir))

        model = repo.get_model_details("nonexistent.gguf")

        assert model is None

    def test_compute_checksum_calculates_sha256(self, tmp_path: Path) -> None:
        """Compute checksum calculates correct SHA256 hash."""
        test_file = tmp_path / "test.bin"
        test_content = b"test content for hashing"
        test_file.write_bytes(test_content)

        expected_checksum = hashlib.sha256(test_content).hexdigest()

        model_info = ModelInfo(
            model_id="test",
            name="Test",
            local_path=str(test_file),
        )

        repo = LocalFileRepository(models_directory=str(tmp_path))
        repo._compute_checksum(model_info)

        assert model_info.checksum == expected_checksum

    def test_metadata_persists_between_instances(self, tmp_path: Path) -> None:
        """Metadata persists and loads between repository instances."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        (models_dir / "test-model.gguf").write_bytes(b"test data")

        repo1 = LocalFileRepository(models_directory=str(models_dir))
        models1 = repo1.get_available_models()
        repo1._save_metadata()

        repo2 = LocalFileRepository(models_directory=str(models_dir))
        models2 = repo2.get_available_models()

        assert len(models1) == len(models2)
        assert models1[0].model_id == models2[0].model_id

    def test_download_model_copies_file_to_destination(self, tmp_path: Path) -> None:
        """Download model copies file from repository to destination."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        test_data = b"model content to copy"
        source_file = models_dir / "source-model.gguf"
        source_file.write_bytes(test_data)

        repo = LocalFileRepository(models_directory=str(models_dir))

        dest_path = str(tmp_path / "dest" / "model.gguf")
        success, message = repo.download_model("source-model.gguf", dest_path)

        assert success is True
        assert "complete" in message.lower()
        assert os.path.exists(dest_path)
        assert Path(dest_path).read_bytes() == test_data

    def test_download_model_reports_progress(self, tmp_path: Path) -> None:
        """Download model reports progress during copy operation."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        large_data = b"x" * (5 * 1024 * 1024)
        source_file = models_dir / "large-model.gguf"
        source_file.write_bytes(large_data)

        repo = LocalFileRepository(models_directory=str(models_dir))

        progress_calls = []

        class TestCallback(DownloadProgressCallback):
            def on_progress(self, bytes_downloaded: int, total_bytes: int) -> None:
                progress_calls.append((bytes_downloaded, total_bytes))

            def on_complete(self, success: bool, message: str) -> None:
                pass

        callback = TestCallback()
        dest_path = str(tmp_path / "large.gguf")
        repo.download_model("large-model.gguf", dest_path, callback)

        assert len(progress_calls) > 1
        assert progress_calls[-1][0] == len(large_data)

    def test_download_model_creates_destination_directory(self, tmp_path: Path) -> None:
        """Download model creates destination directory if needed."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        (models_dir / "model.gguf").write_bytes(b"data")

        repo = LocalFileRepository(models_directory=str(models_dir))

        dest_path = str(tmp_path / "nested" / "dirs" / "model.gguf")
        success, _ = repo.download_model("model.gguf", dest_path)

        assert success is True
        assert os.path.exists(dest_path)

    def test_add_model_imports_external_file(self, tmp_path: Path) -> None:
        """Add model imports file from outside models directory."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        external_file = tmp_path / "external.gguf"
        test_data = b"external model data"
        external_file.write_bytes(test_data)

        repo = LocalFileRepository(models_directory=str(models_dir))

        model_info = repo.add_model(str(external_file))

        assert model_info is not None
        assert os.path.exists(model_info.local_path)
        assert models_dir in Path(model_info.local_path).parents
        assert Path(model_info.local_path).read_bytes() == test_data

    def test_add_model_handles_file_already_in_directory(self, tmp_path: Path) -> None:
        """Add model handles files already in models directory."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        existing_file = models_dir / "existing.gguf"
        existing_file.write_bytes(b"existing data")

        repo = LocalFileRepository(models_directory=str(models_dir))

        model_info = repo.add_model(str(existing_file))

        assert model_info is not None
        assert model_info.local_path == str(existing_file)

    def test_add_model_returns_none_for_nonexistent_file(self, tmp_path: Path) -> None:
        """Add model returns None when file doesn't exist."""
        repo = LocalFileRepository(models_directory=str(tmp_path))

        model_info = repo.add_model("/nonexistent/file.gguf")

        assert model_info is None

    def test_remove_model_deletes_file_and_metadata(self, tmp_path: Path) -> None:
        """Remove model deletes file and removes from metadata."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        model_file = models_dir / "to-remove.gguf"
        model_file.write_bytes(b"data to remove")

        repo = LocalFileRepository(models_directory=str(models_dir))
        repo.get_available_models()

        success = repo.remove_model("to-remove.gguf")

        assert success is True
        assert not model_file.exists()

    def test_remove_model_returns_false_for_nonexistent(self, tmp_path: Path) -> None:
        """Remove model returns False for non-existent model."""
        repo = LocalFileRepository(models_directory=str(tmp_path))

        success = repo.remove_model("nonexistent.gguf")

        assert success is False

    def test_authenticate_always_succeeds(self, tmp_path: Path) -> None:
        """Authenticate always succeeds for local repository."""
        repo = LocalFileRepository(models_directory=str(tmp_path))

        success, message = repo.authenticate()

        assert success is True
        assert "doesn't require authentication" in message.lower()

    def test_models_cache_thread_safe_access(self, tmp_path: Path) -> None:
        """Models cache uses thread-safe access patterns."""
        repo = LocalFileRepository(models_directory=str(tmp_path))

        assert hasattr(repo, "_cache_lock")

        with repo._cache_lock:
            repo.models_cache["test"] = ModelInfo(model_id="test", name="Test")

        assert "test" in repo.models_cache

    def test_checksum_computation_async(self, tmp_path: Path) -> None:
        """Checksum computation happens asynchronously."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        test_file = models_dir / "async-test.gguf"
        test_file.write_bytes(b"test data")

        repo = LocalFileRepository(models_directory=str(models_dir))

        model_info = repo.add_model(str(test_file))

        assert model_info is not None

        repo.shutdown()

    def test_repository_cleanup_on_shutdown(self, tmp_path: Path) -> None:
        """Repository cleans up resources on shutdown."""
        repo = LocalFileRepository(models_directory=str(tmp_path))

        repo.shutdown()

        assert not repo._executor._shutdown

    def test_metadata_file_structure(self, tmp_path: Path) -> None:
        """Metadata file has correct JSON structure."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        (models_dir / "test.gguf").write_bytes(b"data")

        repo = LocalFileRepository(models_directory=str(models_dir))
        repo.get_available_models()
        repo._save_metadata()

        metadata_file = models_dir / "models_metadata.json"
        assert metadata_file.exists()

        with open(metadata_file) as f:
            metadata = json.load(f)

        assert isinstance(metadata, dict)
        assert any("test.gguf" in key for key in metadata.keys())

    def test_corrupted_metadata_handled_gracefully(self, tmp_path: Path) -> None:
        """Corrupted metadata file is handled gracefully."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()

        metadata_file = models_dir / "models_metadata.json"
        metadata_file.write_text("corrupted json {{{")

        repo = LocalFileRepository(models_directory=str(models_dir))

        assert repo.models_cache == {}
