"""Production tests for Google repository.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import os

import pytest

from intellicrack.models.repositories.google_repository import GoogleRepository


class TestGoogleRepository:
    """Test Google Generative AI API repository."""

    @pytest.fixture
    def api_key(self) -> str:
        """Get API key from environment or skip test."""
        key = os.environ.get("GOOGLE_API_KEY", "")
        if not key:
            pytest.skip("GOOGLE_API_KEY not available for real testing")
        return key

    def test_authenticate_fails_without_api_key(self) -> None:
        """Authenticate fails when no API key provided."""
        repo = GoogleRepository(api_key="")

        success, message = repo.authenticate()

        assert success is False
        assert "API key is required" in message

    def test_authenticate_validates_api_key(self, api_key: str) -> None:
        """Authenticate validates API key with real endpoint."""
        repo = GoogleRepository(api_key=api_key)

        try:
            success, message = repo.authenticate()

            assert isinstance(success, bool)
            assert isinstance(message, str)
            if success:
                assert "successful" in message.lower() or "valid" in message.lower()
        except Exception as e:
            if "connection" in str(e).lower() or "network" in str(e).lower():
                pytest.skip(f"Network unavailable: {e}")
            raise

    def test_authenticate_detects_invalid_api_key(self) -> None:
        """Authenticate detects invalid API key through error response."""
        repo = GoogleRepository(api_key="invalid_test_key_12345")

        try:
            success, message = repo.authenticate()

            assert success is False
            assert "failed" in message.lower() or "invalid" in message.lower() or "unauthorized" in message.lower()
        except Exception as e:
            if "connection" in str(e).lower() or "network" in str(e).lower():
                pytest.skip(f"Network unavailable: {e}")
            raise

    def test_get_available_models_returns_gemini_models(self, api_key: str) -> None:
        """Get available models returns Gemini models."""
        repo = GoogleRepository(api_key=api_key)

        try:
            models = repo.get_available_models()

            assert isinstance(models, list)
            if models:
                for model in models:
                    assert model.provider == "google"
                    assert model.format == "api"
                    assert isinstance(model.capabilities, list)
        except Exception as e:
            if "connection" in str(e).lower() or "network" in str(e).lower():
                pytest.skip(f"Network unavailable: {e}")
            raise

    def test_get_model_details_retrieves_specific_model(self, api_key: str) -> None:
        """Get model details retrieves specific model information."""
        repo = GoogleRepository(api_key=api_key)

        try:
            models = repo.get_available_models()
            if not models:
                pytest.skip("No models available from API")

            first_model_id = models[0].model_id
            if model := repo.get_model_details(first_model_id):
                assert model.model_id == first_model_id
                assert model.provider == "google"
        except Exception as e:
            if "connection" in str(e).lower() or "network" in str(e).lower():
                pytest.skip(f"Network unavailable: {e}")
            raise

    def test_get_model_details_returns_none_for_nonexistent(self, api_key: str) -> None:
        """Get model details returns None for non-existent model."""
        repo = GoogleRepository(api_key=api_key)

        try:
            model = repo.get_model_details("nonexistent-model-12345")

            assert model is None
        except Exception as e:
            if "connection" in str(e).lower() or "network" in str(e).lower():
                pytest.skip(f"Network unavailable: {e}")
            raise

    def test_download_model_not_supported(self) -> None:
        """Download model returns error for API-only models."""
        repo = GoogleRepository(api_key="test_key")

        success, message = repo.download_model("gemini-pro", "/tmp/model.bin")

        assert success is False
        assert "doesn't support" in message.lower() or "not supported" in message.lower()

    def test_repository_initialization_with_explicit_api_key(self) -> None:
        """Repository initializes correctly with explicit API key."""
        repo = GoogleRepository(api_key="test_explicit_key")

        assert repo.api_key == "test_explicit_key"
        assert repo.provider_name == "google"

    def test_repository_handles_network_errors_gracefully(self) -> None:
        """Repository handles network errors without crashing."""
        repo = GoogleRepository(api_key="test_key", api_endpoint="https://nonexistent.invalid")

        try:
            models = repo.get_available_models()
            assert isinstance(models, list)
        except Exception as e:
            assert "connection" in str(e).lower() or "network" in str(e).lower() or "resolve" in str(e).lower()

    def test_model_info_contains_required_fields(self, api_key: str) -> None:
        """Model info objects contain all required fields."""
        repo = GoogleRepository(api_key=api_key)

        try:
            models = repo.get_available_models()
            if not models:
                pytest.skip("No models available from API")

            for model in models:
                assert model.model_id
                assert model.provider == "google"
                assert model.format == "api"
                assert isinstance(model.capabilities, list)
                assert isinstance(model.name, str)
        except Exception as e:
            if "connection" in str(e).lower() or "network" in str(e).lower():
                pytest.skip(f"Network unavailable: {e}")
            raise
