"""OpenAI repository for Intellicrack model repositories.

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

import logging
import os
from typing import Any

from .base import APIRepositoryBase, RateLimitConfig
from .interface import DownloadProgressCallback, ModelInfo


"""
OpenAI Repository Implementation

This module provides an implementation of the model repository interface for
accessing models via OpenAI's API.
"""

# Set up logging
logger = logging.getLogger(__name__)


class OpenAIRepository(APIRepositoryBase):
    """Repository implementation for OpenAI's API."""

    def __init__(
        self,
        repository_name: str = "openai",
        api_endpoint: str | None = None,
        api_key: str = "",
        timeout: int = 60,
        proxy: str = "",
        rate_limit_config: RateLimitConfig | None = None,
        cache_config: dict[str, Any] | None = None,
        download_dir: str = os.path.join(os.path.dirname(__file__), "..", "downloads"),
    ) -> None:
        """Initialize the OpenAI repository.

        Args:
            repository_name: Name of the repository
            api_endpoint: Base URL of the API (loaded from config if None)
            api_key: OpenAI API key (loaded from secrets if empty)
            timeout: Request timeout in seconds
            proxy: Proxy URL
            rate_limit_config: Rate limiting configuration
            cache_config: Cache configuration
            download_dir: Directory for downloaded models (unused for API-only repos)

        """
        # Get API endpoint from config if not provided
        if api_endpoint is None:
            from intellicrack.core.config_manager import get_config

            config = get_config()
            api_endpoint = config.get_api_endpoint("openai") or "https://api.openai.com/v1"

        # Get API key from secrets manager if not provided
        if not api_key:
            from intellicrack.utils.secrets_manager import SecretsManager

            secrets_manager = SecretsManager()
            api_key = secrets_manager.get("OPENAI_API_KEY") or ""

        super().__init__(
            repository_name=repository_name,
            api_endpoint=api_endpoint,
            api_key=api_key,
            timeout=timeout,
            proxy=proxy,
            rate_limit_config=rate_limit_config,
            cache_config=cache_config,
            download_dir=download_dir,
        )

    def authenticate(self) -> tuple[bool, str]:
        """Authenticate with the OpenAI API.

        Returns:
            Tuple of (success, message)

        """
        if not self.api_key:
            return False, "API key is required for OpenAI authentication"

        # Test the API key by making a simple request to list models
        success, _, error_message = self._make_request(
            endpoint="models",
            method="GET",
            use_cache=False,
        )

        if success:
            return True, "Authentication successful"
        return False, f"Authentication failed: {error_message}"

    def get_available_models(self) -> list[ModelInfo]:
        """Get a list of available models from OpenAI API.

        Returns:
            A list of ModelInfo objects representing the available models.

        """
        success, data, error_message = self._make_request(
            endpoint="models",
            method="GET",
        )

        if not success:
            logger.error("Failed to get models from OpenAI: %s", error_message)
            return []

        models = []

        try:
            if not isinstance(data, dict):
                logger.error("Unexpected response format from OpenAI API")
                return []
            # Extract model information from the response
            models_list = data.get("data", [])
            if not isinstance(models_list, list):
                logger.error("Unexpected 'data' format in OpenAI API response")
                return []
            for model_data in models_list:
                if not isinstance(model_data, dict):
                    continue
                model_id = model_data.get("id")
                if not isinstance(model_id, str):
                    continue

                # For most API usage we'll only care about chat and embedding models
                if not (model_id.startswith("gpt-") or "embedding" in model_id or model_id == "dall-e-3"):
                    continue

                if model_info := self._get_model_details(model_id):
                    models.append(model_info)

            return models

        except (KeyError, TypeError) as e:
            logger.exception("Error parsing OpenAI models response: %s", e)
            return []

    def get_model_details(self, model_id: str) -> ModelInfo | None:
        """Get detailed information about a specific model.

        Args:
            model_id: The ID of the model to get details for

        Returns:
            A ModelInfo object containing the model details, or None if the model is not found.

        """
        return self._get_model_details(model_id)

    def _get_model_details(self, model_id: str) -> ModelInfo | None:
        """Get detailed information about a model from the API.

        Args:
            model_id: The ID of the model

        Returns:
            ModelInfo object, or None if failed

        """
        success, data, error_message = self._make_request(
            endpoint=f"models/{model_id}",
            method="GET",
        )

        if not success:
            logger.error("Failed to get model details for %s: %s", model_id, error_message)
            return None

        try:
            if not isinstance(data, dict):
                logger.error("Unexpected response format for model details")
                return None
            # Determine model capabilities based on model ID
            capabilities: list[str] = []
            if model_id.startswith("gpt-"):
                capabilities.append("text-generation")
                if "vision" in model_id or model_id in {"gpt-4-turbo", "gpt-4o"}:
                    capabilities.append("vision")
            elif "embedding" in model_id:
                capabilities.append("embeddings")
            elif model_id == "dall-e-3":
                capabilities.append("image-generation")

            name_value = data.get("name")
            if not isinstance(name_value, str):
                name_value = model_id
            description_value = data.get("description")
            if not isinstance(description_value, str):
                description_value = ""
            context_length_value = data.get("context_length")
            version_value = data.get("version")
            if not isinstance(version_value, str):
                version_value = "1.0"

            return ModelInfo(
                model_id=model_id,
                name=name_value,
                description=description_value,
                size_bytes=0,
                format="api",
                provider="openai",
                parameters=None,
                context_length=context_length_value,
                capabilities=capabilities,
                version=version_value,
                checksum=None,
                download_url=None,
                local_path=None,
            )
        except (KeyError, TypeError) as e:
            logger.exception("Error creating ModelInfo for %s: %s", model_id, e)
            return None

    def download_model(
        self,
        model_id: str,
        destination_path: str,
        progress_callback: DownloadProgressCallback | None = None,
    ) -> tuple[bool, str]:
        """OpenAI doesn't support model downloads for most models, this is primarily an API-only service.

        Args:
            model_id: The ID of the model to download
            destination_path: The path where the model should be saved
            progress_callback: Optional callback for download progress

        Returns:
            Always returns (False, "OpenAI doesn't support model downloads")

        """
        logger.warning("Download requested for %s to %s, but not supported", model_id, destination_path)
        return False, "OpenAI doesn't support model downloads for this model"
