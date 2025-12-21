"""Production tests for LMStudio repository.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import socket

import pytest

from intellicrack.models.repositories.lmstudio_repository import LMStudioRepository


class TestLMStudioRepository:
    """Test LMStudio local API repository functionality."""

    def _is_lmstudio_running(self) -> bool:
        """Check if LMStudio server is running on localhost."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(("localhost", 1234))
            sock.close()
            return result == 0
        except Exception:
            return False

    def test_authenticate_fails_when_server_unavailable(self) -> None:
        """Authenticate fails when LMStudio server is not running."""
        repo = LMStudioRepository(api_endpoint="http://localhost:9999/v1")

        success, message = repo.authenticate()

        assert success is False
        assert "failed" in message.lower() or "connection" in message.lower()

    def test_authenticate_checks_connectivity(self) -> None:
        """Authenticate verifies connection to local LMStudio server."""
        if not self._is_lmstudio_running():
            pytest.skip("LMStudio server not running on localhost:1234")

        repo = LMStudioRepository()

        try:
            success, message = repo.authenticate()

            assert isinstance(success, bool)
            assert isinstance(message, str)
            if success:
                assert "successful" in message.lower() or "valid" in message.lower()
        except Exception as e:
            if "connection" in str(e).lower():
                pytest.skip(f"LMStudio server not accessible: {e}")
            raise

    def test_get_available_models_returns_local_models(self) -> None:
        """Get available models returns locally loaded models."""
        if not self._is_lmstudio_running():
            pytest.skip("LMStudio server not running on localhost:1234")

        repo = LMStudioRepository()

        try:
            models = repo.get_available_models()

            assert isinstance(models, list)
            if models:
                for model in models:
                    assert model.provider == "lmstudio"
                    assert model.format == "api"
                    assert "text-generation" in model.capabilities
        except Exception as e:
            if "connection" in str(e).lower():
                pytest.skip(f"LMStudio server not accessible: {e}")
            raise

    def test_get_model_details_retrieves_specific_model(self) -> None:
        """Get model details retrieves specific model information."""
        if not self._is_lmstudio_running():
            pytest.skip("LMStudio server not running on localhost:1234")

        repo = LMStudioRepository()

        try:
            models = repo.get_available_models()
            if not models:
                pytest.skip("No models loaded in LMStudio")

            first_model_id = models[0].model_id
            model = repo.get_model_details(first_model_id)

            if model:
                assert model.model_id == first_model_id
                assert model.provider == "lmstudio"
        except Exception as e:
            if "connection" in str(e).lower():
                pytest.skip(f"LMStudio server not accessible: {e}")
            raise

    def test_get_model_details_returns_none_for_nonexistent(self) -> None:
        """Get model details returns None for non-existent model."""
        if not self._is_lmstudio_running():
            pytest.skip("LMStudio server not running on localhost:1234")

        repo = LMStudioRepository()

        try:
            model = repo.get_model_details("nonexistent-model-12345")

            assert model is None
        except Exception as e:
            if "connection" in str(e).lower():
                pytest.skip(f"LMStudio server not accessible: {e}")
            raise

    def test_create_model_info_sets_lmstudio_provider(self) -> None:
        """Create model info sets provider to lmstudio."""
        repo = LMStudioRepository(api_endpoint="http://localhost:1234/v1")

        model_data = {"id": "test-model", "name": "Test Model"}

        model_info = repo._create_model_info("test-model", model_data)

        assert model_info is not None
        assert model_info.provider == "lmstudio"
        assert model_info.format == "api"

    def test_create_model_info_sets_text_generation_capability(self) -> None:
        """Create model info sets text-generation as default capability."""
        repo = LMStudioRepository(api_endpoint="http://localhost:1234/v1")

        model_data = {"id": "test-model"}

        model_info = repo._create_model_info("test-model", model_data)

        assert model_info is not None
        assert "text-generation" in model_info.capabilities

    def test_download_model_not_supported(self) -> None:
        """Download model returns error as LMStudio manages its own files."""
        repo = LMStudioRepository(api_endpoint="http://localhost:1234/v1")

        success, message = repo.download_model("test-model", "/tmp/model.bin")

        assert success is False
        assert "doesn't support" in message.lower() or "not supported" in message.lower()

    def test_repository_accepts_custom_endpoint(self) -> None:
        """Repository accepts custom endpoint override."""
        repo = LMStudioRepository(api_endpoint="http://custom:8080/v1")

        assert repo.api_endpoint == "http://custom:8080/v1"

    def test_get_available_models_handles_connection_errors(self) -> None:
        """Get available models handles server connection errors."""
        repo = LMStudioRepository(api_endpoint="http://nonexistent:9999/v1")

        models = repo.get_available_models()

        assert isinstance(models, list)
        assert len(models) == 0

    def test_create_model_info_handles_minimal_data(self) -> None:
        """Create model info handles minimal model data."""
        repo = LMStudioRepository(api_endpoint="http://localhost:1234/v1")

        minimal_data = {"id": "test"}

        model_info = repo._create_model_info("test", minimal_data)

        assert model_info is not None
        assert model_info.model_id == "test"
        assert isinstance(model_info.description, str)
        assert model_info.provider == "lmstudio"

    def test_repository_initializes_with_defaults(self) -> None:
        """Repository initializes with default configuration."""
        repo = LMStudioRepository()

        assert repo.provider_name == "lmstudio"
        assert isinstance(repo.api_endpoint, str)
        assert "localhost" in repo.api_endpoint or "127.0.0.1" in repo.api_endpoint
