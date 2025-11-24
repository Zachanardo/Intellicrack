"""LMStudio repository for Intellicrack model repositories.

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

from intellicrack.utils.service_utils import get_service_url

from .base import APIRepositoryBase, RateLimitConfig
from .interface import ModelInfo


"""
LMStudio Repository Implementation

This module provides an implementation of the model repository interface for
accessing models via LMStudio's API.
"""

# Set up logging
logger = logging.getLogger(__name__)


class LMStudioRepository(APIRepositoryBase):
    """Repository implementation for LMStudio's API."""

    def __init__(
        self,
        repository_name: str = "lmstudio",
        api_endpoint: str | None = None,
        api_key: str = "",
        timeout: int = 60,
        proxy: str = "",
        rate_limit_config: RateLimitConfig | None = None,
        cache_config: dict[str, Any] | None = None,
        download_dir: str = os.path.join(os.path.dirname(__file__), "..", "downloads"),
    ) -> None:
        """Initialize the LMStudio repository.

        Args:
            repository_name: Name of the repository
            api_endpoint: Base URL of the API (default is local LMStudio server)
            api_key: API key (usually not required for local LMStudio)
            timeout: Request timeout in seconds
            proxy: Proxy URL
            rate_limit_config: Rate limiting configuration
            cache_config: Cache configuration
            download_dir: Directory for downloaded models (unused for API-only repos)

        """
        # Use service health checker to get LMStudio URL if not provided
        if api_endpoint is None:
            api_endpoint = get_service_url("lmstudio_api") + "/v1"

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
        """Authenticate with the LMStudio API.

        Returns:
            Tuple of (success, message)

        """
        # Test connectivity by making a simple request to list models
        success, _, error_message = self._make_request(
            endpoint="models",
            method="GET",
            use_cache=False,
        )

        if success:
            return True, "Connection successful"
        return False, f"Connection failed: {error_message}"

    def get_available_models(self) -> list[ModelInfo]:
        """Get a list of available models from the LMStudio API.

        Returns:
            A list of ModelInfo objects representing the available models.

        """
        success, data, error_message = self._make_request(
            endpoint="models",
            method="GET",
        )

        if not success:
            logger.error(f"Failed to get models from LMStudio: {error_message}")
            return []

        models = []

        try:
            # Extract model information from the response
            for model_data in data.get("data", []):
                model_id = model_data.get("id")
                if model_info := self._create_model_info(model_id, model_data):
                    models.append(model_info)

            return models

        except (KeyError, TypeError) as e:
            logger.error(f"Error parsing LMStudio models response: {e}")
            return []

    def get_model_details(self, model_id: str) -> ModelInfo | None:
        """Get detailed information about a specific model.

        Args:
            model_id: The ID of the model to get details for

        Returns:
            A ModelInfo object containing the model details, or None if the model is not found.

        """
        # LMStudio follows OpenAI API format but doesn't always implement all endpoints
        # Try to get direct model info, but fall back to listing all models if needed
        success, data, error_message = self._make_request(
            endpoint=f"models/{model_id}",
            method="GET",
        )

        if success:
            try:
                return self._create_model_info(model_id, data)
            except (KeyError, TypeError) as e:
                logger.error(f"Error parsing LMStudio model details for {model_id}: {e}")
                return None

        # If direct model endpoint fails, fall back to looking through all models
        success, data, error_message = self._make_request(
            endpoint="models",
            method="GET",
        )

        if not success:
            logger.error(f"Failed to get models from LMStudio: {error_message}")
            return None

        try:
            return next(
                (self._create_model_info(model_id, model_data) for model_data in data.get("data", []) if model_data.get("id") == model_id),
                None,
            )
        except (KeyError, TypeError) as e:
            logger.error(f"Error parsing LMStudio model details for {model_id}: {e}")
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
            return ModelInfo(
                model_id=model_id,
                name=model_data.get("name", model_id),
                description=model_data.get("description", "Local LMStudio model"),
                size_bytes=0,  # Not typically provided by LMStudio API
                format="api",
                provider="lmstudio",
                parameters=None,  # Not typically provided
                context_length=model_data.get("context_length"),
                capabilities=["text-generation"],  # LMStudio typically serves text models
                version=model_data.get("version", "1.0"),
                checksum=None,
                download_url=None,
                local_path=None,  # We don't know the actual path of the local model
            )
        except (KeyError, TypeError) as e:
            logger.error(f"Error creating ModelInfo for {model_id}: {e}")
            return None

    def download_model(self, model_id: str, destination_path: str) -> tuple[bool, str]:
        """LMStudio doesn't support model downloads through its API.

        Returns:
            Always returns (False, "LMStudio doesn't support model downloads through API")

        """
        logger.warning(f"Download requested for {model_id} to {destination_path}, but not supported")
        return False, "LMStudio doesn't support model downloads through API"
