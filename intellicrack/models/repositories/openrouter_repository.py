"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

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
from .interface import ModelInfo

"""
OpenRouter Repository Implementation

This module provides an implementation of the model repository interface for
accessing models via OpenRouter's API.
"""

# Set up logging
logger = logging.getLogger(__name__)


class OpenRouterRepository(APIRepositoryBase):
    """Repository implementation for OpenRouter's API."""

    def __init__(
        self,
        repository_name: str = "openrouter",
        api_endpoint: str = "https://openrouter.ai/api",
        api_key: str = "",
        timeout: int = 60,
        proxy: str = "",
        rate_limit_config: RateLimitConfig | None = None,
        cache_config: dict[str, Any] | None = None,
        download_dir: str = os.path.join(os.path.dirname(__file__), "..", "downloads"),
    ):
        """Initialize the OpenRouter repository.

        Args:
            repository_name: Name of the repository
            api_endpoint: Base URL of the API
            api_key: OpenRouter API key
            timeout: Request timeout in seconds
            proxy: Proxy URL
            rate_limit_config: Rate limiting configuration
            cache_config: Cache configuration
            download_dir: Directory for downloaded models (unused for API-only repos)

        """
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
        self.logger = logging.getLogger(__name__)

    def authenticate(self) -> tuple[bool, str]:
        """Authenticate with the OpenRouter API.

        Returns:
            Tuple of (success, message)

        """
        if not self.api_key:
            return False, "API key is required for OpenRouter authentication"

        # Test the API key by making a simple request to list models
        success, _, error_message = self._make_request(
            endpoint="v1/models",
            method="GET",
            headers={"Authorization": f"Bearer {self.api_key}"},
            use_cache=False,
        )

        if success:
            return True, "Authentication successful"
        return False, f"Authentication failed: {error_message}"

    def get_available_models(self) -> list[ModelInfo]:
        """Get a list of available models from OpenRouter API.

        Returns:
            A list of ModelInfo objects representing the available models.

        """
        success, data, error_message = self._make_request(
            endpoint="v1/models",
            method="GET",
            headers={"Authorization": f"Bearer {self.api_key}"},
        )

        if not success:
            logger.error(f"Failed to get models from OpenRouter: {error_message}")
            return []

        models = []

        try:
            # Extract model information from the response
            for model_data in data.get("data", []):
                model_id = model_data.get("id")
                model_info = self._create_model_info(model_id, model_data)
                if model_info:
                    models.append(model_info)

            return models

        except (KeyError, TypeError) as e:
            logger.error(f"Error parsing OpenRouter models response: {e}")
            return []

    def get_model_details(self, model_id: str) -> ModelInfo | None:
        """Get detailed information about a specific model.

        Args:
            model_id: The ID of the model to get details for

        Returns:
            A ModelInfo object containing the model details, or None if the model is not found.

        """
        # OpenRouter doesn't have a specific endpoint for individual model details
        # So we'll get all models and filter for the one we want
        success, data, error_message = self._make_request(
            endpoint="v1/models",
            method="GET",
            headers={"Authorization": f"Bearer {self.api_key}"},
        )

        if not success:
            logger.error(f"Failed to get models from OpenRouter: {error_message}")
            return None

        try:
            # Find the specific model in the list
            for model_data in data.get("data", []):
                if model_data.get("id") == model_id:
                    return self._create_model_info(model_id, model_data)

            # Model not found
            return None

        except (KeyError, TypeError) as e:
            logger.error(f"Error parsing OpenRouter model details for {model_id}: {e}")
            return None

    def _create_model_info(self, model_id: str, model_data: dict[str, Any]) -> ModelInfo | None:
        """Create a ModelInfo object from the API data.

        Args:
            model_id: The ID of the model
            model_data: Model data from the API

        Returns:
            ModelInfo object, or None if failed

        """
        try:
            # Extract context window from model data
            context_length = None
            if "context_length" in model_data:
                context_length = model_data["context_length"]
            elif "context_window" in model_data:
                context_length = model_data["context_window"]

            # Extract capabilities from available model features
            capabilities = []
            if model_data.get("features", {}).get("tools", False):
                capabilities.append("tools")
            if model_data.get("features", {}).get("vision", False):
                capabilities.append("vision")
            if model_data.get("features", {}).get("json_mode", False):
                capabilities.append("json")

            # Extract model information
            model_info = ModelInfo(
                model_id=model_id,
                name=model_data.get("name", model_id),
                description=model_data.get("description", ""),
                size_bytes=0,  # Not relevant for API models
                format="api",
                provider=model_data.get("provider", "openrouter"),
                parameters=model_data.get("parameters"),
                context_length=context_length,
                capabilities=capabilities,
                version=model_data.get("version", "1.0"),
                checksum=None,
                download_url=None,
                local_path=None,
            )

            return model_info

        except (KeyError, TypeError) as e:
            logger.error(f"Error creating ModelInfo for {model_id}: {e}")
            return None

    def download_model(self, model_id: str, destination_path: str) -> tuple[bool, str]:
        """OpenRouter doesn't support model downloads, this is an API-only service.

        Returns:
            Always returns (False, "OpenRouter doesn't support model downloads")

        """
        self.logger.warning(
            f"Download requested for {model_id} to {destination_path}, but not supported"
        )
        return False, "OpenRouter doesn't support model downloads"
