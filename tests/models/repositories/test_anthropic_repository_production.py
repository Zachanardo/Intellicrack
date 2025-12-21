"""Production tests for Anthropic repository.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import os
from typing import Any

import pytest

from intellicrack.models.repositories.anthropic_repository import AnthropicRepository
from intellicrack.models.repositories.interface import ModelInfo


class TestAnthropicRepository:
    """Test Anthropic API repository functionality."""

    @pytest.fixture
    def api_key(self) -> str:
        """Get API key from environment or skip test."""
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            pytest.skip("ANTHROPIC_API_KEY not available for real testing")
        return key

    def test_authenticate_fails_without_api_key(self) -> None:
        """Authenticate fails when no API key is provided."""
        repo = AnthropicRepository(api_key="")

        success, message = repo.authenticate()

        assert success is False
        assert "API key is required" in message

    def test_authenticate_validates_api_key_with_real_endpoint(self, api_key: str) -> None:
        """Authenticate makes real API request to validate key."""
        repo = AnthropicRepository(api_key=api_key)

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
        repo = AnthropicRepository(api_key="sk-ant-invalid_test_key_12345")

        try:
            success, message = repo.authenticate()

            assert success is False
            assert "failed" in message.lower() or "invalid" in message.lower() or "unauthorized" in message.lower()
        except Exception as e:
            if "connection" in str(e).lower() or "network" in str(e).lower():
                pytest.skip(f"Network unavailable: {e}")
            raise

    def test_get_available_models_returns_correct_format(self, api_key: str) -> None:
        """Get available models parses API response into ModelInfo list."""
        repo = AnthropicRepository(api_key=api_key)

        try:
            models = repo.get_available_models()

            assert isinstance(models, list)
            if models:
                assert all(isinstance(m, ModelInfo) for m in models)
                assert all(m.provider == "anthropic" for m in models)
                assert all(m.model_id for m in models)
                assert all(m.context_length > 0 for m in models)
        except Exception as e:
            if "connection" in str(e).lower() or "network" in str(e).lower():
                pytest.skip(f"Network unavailable: {e}")
            raise

    def test_get_available_models_handles_api_errors(self) -> None:
        """Get available models handles API errors gracefully."""
        repo = AnthropicRepository(api_key="invalid_key")

        try:
            models = repo.get_available_models()
            assert isinstance(models, list)
        except Exception as e:
            if "connection" in str(e).lower() or "network" in str(e).lower():
                pytest.skip(f"Network unavailable: {e}")
            raise

    def test_get_model_details_retrieves_specific_model(self, api_key: str) -> None:
        """Get model details retrieves information for specific model."""
        repo = AnthropicRepository(api_key=api_key)

        try:
            models = repo.get_available_models()
            if not models:
                pytest.skip("No models available from API")

            first_model_id = models[0].model_id
            model = repo.get_model_details(first_model_id)

            assert model is not None
            assert model.model_id == first_model_id
            assert model.provider == "anthropic"
            assert model.context_length > 0
        except Exception as e:
            if "connection" in str(e).lower() or "network" in str(e).lower():
                pytest.skip(f"Network unavailable: {e}")
            raise

    def test_get_model_details_returns_none_for_nonexistent_model(self, api_key: str) -> None:
        """Get model details returns None for non-existent model."""
        repo = AnthropicRepository(api_key=api_key)

        try:
            model = repo.get_model_details("nonexistent-model-12345")

            assert model is None
        except Exception as e:
            if "connection" in str(e).lower() or "network" in str(e).lower():
                pytest.skip(f"Network unavailable: {e}")
            raise

    def test_create_model_info_extracts_capabilities(self) -> None:
        """Create model info correctly extracts model capabilities."""
        repo = AnthropicRepository(api_key="test_key")

        model_data: dict[str, Any] = {
            "id": "claude-3-opus-20240229",
            "name": "Claude 3 Opus",
            "max_tokens": 4096,
            "input_image_format": ["image/jpeg", "image/png"],
            "context_window": 200000,
        }

        model_info = repo._create_model_info("claude-3-opus-20240229", model_data)

        assert model_info is not None
        assert "text-generation" in model_info.capabilities
        assert "vision" in model_info.capabilities
        assert model_info.max_output_tokens == 4096
        assert model_info.context_length == 200000

    def test_create_model_info_sets_provider_correctly(self) -> None:
        """Create model info sets provider to anthropic."""
        repo = AnthropicRepository(api_key="test_key")

        model_data = {"id": "test-model", "name": "Test Model"}

        model_info = repo._create_model_info("test-model", model_data)

        assert model_info is not None
        assert model_info.provider == "anthropic"
        assert model_info.format == "api"
        assert model_info.model_id == "test-model"

    def test_create_model_info_handles_missing_fields(self) -> None:
        """Create model info handles missing optional fields gracefully."""
        repo = AnthropicRepository(api_key="test_key")

        minimal_data = {"id": "test-model"}

        model_info = repo._create_model_info("test-model", minimal_data)

        assert model_info is not None
        assert model_info.model_id == "test-model"
        assert isinstance(model_info.name, str)
        assert isinstance(model_info.description, str)
        assert model_info.provider == "anthropic"

    def test_download_model_returns_not_supported(self) -> None:
        """Download model returns error as Anthropic is API-only."""
        repo = AnthropicRepository(api_key="test_key")

        success, message = repo.download_model("claude-3-opus", "/tmp/model.bin")

        assert success is False
        assert "doesn't support" in message.lower() or "not supported" in message.lower()

    def test_repository_initialization_with_explicit_api_key(self) -> None:
        """Repository initializes correctly with explicit API key."""
        repo = AnthropicRepository(api_key="test_explicit_key")

        assert repo.api_key == "test_explicit_key"
        assert repo.provider_name == "anthropic"

    def test_repository_initialization_with_custom_endpoint(self) -> None:
        """Repository accepts custom API endpoint."""
        custom_endpoint = "https://custom.anthropic.com"
        repo = AnthropicRepository(api_key="test_key", api_endpoint=custom_endpoint)

        assert repo.api_endpoint == custom_endpoint

    def test_model_info_contains_required_fields(self, api_key: str) -> None:
        """Model info objects contain all required fields."""
        repo = AnthropicRepository(api_key=api_key)

        try:
            models = repo.get_available_models()
            if not models:
                pytest.skip("No models available from API")

            for model in models:
                assert model.model_id
                assert model.provider == "anthropic"
                assert model.format == "api"
                assert isinstance(model.capabilities, list)
                assert model.context_length >= 0
                assert isinstance(model.name, str)
        except Exception as e:
            if "connection" in str(e).lower() or "network" in str(e).lower():
                pytest.skip(f"Network unavailable: {e}")
            raise

    def test_repository_handles_network_errors_gracefully(self) -> None:
        """Repository handles network errors without crashing."""
        repo = AnthropicRepository(api_key="test_key", api_endpoint="https://nonexistent.invalid")

        try:
            models = repo.get_available_models()
            assert isinstance(models, list)
        except Exception as e:
            assert "connection" in str(e).lower() or "network" in str(e).lower() or "resolve" in str(e).lower()
