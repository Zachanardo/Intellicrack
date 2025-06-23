"""
Anthropic Repository Implementation

This module provides an implementation of the model repository interface for
accessing models via Anthropic's API.
"""

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from .base import APIRepositoryBase, RateLimitConfig
from .interface import ModelInfo

# Set up logging
logger = logging.getLogger(__name__)

class AnthropicRepository(APIRepositoryBase):
    """Repository implementation for Anthropic's API."""

    def __init__(self,
                 repository_name: str = "anthropic",
                 api_endpoint: str = "https://api.anthropic.com",
                 api_key: str = "",
                 timeout: int = 60,
                 proxy: str = "",
                 rate_limit_config: Optional[RateLimitConfig] = None,
                 cache_config: Optional[Dict[str, Any]] = None,
                 download_dir: str = os.path.join(os.path.dirname(__file__), "..", "downloads")):
        """
        Initialize the Anthropic repository.

        Args:
            repository_name: Name of the repository
            api_endpoint: Base URL of the API
            api_key: Anthropic API key
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
            download_dir=download_dir
        )

    def authenticate(self) -> Tuple[bool, str]:
        """
        Authenticate with the Anthropic API.

        Returns:
            Tuple of (success, message)
        """
        if not self.api_key:
            return False, "API key is required for Anthropic authentication"

        # Test the API key by making a simple request
        # Anthropic doesn't have a dedicated endpoint for checking API keys
        # so we'll use the models endpoint
        success, _, error_message = self._make_request(
            endpoint="v1/models",
            method="GET",
            headers={"x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01"},
            use_cache=False
        )

        if success:
            return True, "Authentication successful"
        else:
            return False, f"Authentication failed: {error_message}"

    def get_available_models(self) -> List[ModelInfo]:
        """
        Get a list of available models from Anthropic API.

        Returns:
            A list of ModelInfo objects representing the available models.
        """
        success, data, error_message = self._make_request(
            endpoint="v1/models",
            method="GET",
            headers={"x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01"}
        )

        if not success:
            logger.error(f"Failed to get models from Anthropic: {error_message}")
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
            logger.error(f"Error parsing Anthropic models response: {e}")
            return []

    def get_model_details(self, model_id: str) -> Optional[ModelInfo]:
        """
        Get detailed information about a specific model.

        Args:
            model_id: The ID of the model to get details for

        Returns:
            A ModelInfo object containing the model details, or None if the model is not found.
        """
        # Anthropic doesn't have a specific endpoint for individual model details
        # So we'll get all models and filter for the one we want
        success, data, error_message = self._make_request(
            endpoint="v1/models",
            method="GET",
            headers={"x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01"}
        )

        if not success:
            logger.error(f"Failed to get models from Anthropic: {error_message}")
            return None

        try:
            # Find the specific model in the list
            for model_data in data.get("data", []):
                if model_data.get("id") == model_id:
                    return self._create_model_info(model_id, model_data)

            # Model not found
            return None

        except (KeyError, TypeError) as e:
            logger.error(f"Error parsing Anthropic model details for {model_id}: {e}")
            return None

    def _create_model_info(self, model_id: str, model_data: Dict[str, Any]) -> Optional[ModelInfo]:
        """
        Create a ModelInfo object from the API data.

        Args:
            model_id: The ID of the model
            model_data: Model data from the API

        Returns:
            ModelInfo object, or None if failed
        """
        try:
            # Extract capabilities from model data
            capabilities = []
            if model_data.get("max_tokens", 0) > 0:
                capabilities.append("text-generation")
            if model_data.get("input_image_format") is not None:
                capabilities.append("vision")
            if model_data.get("input_audio_format") is not None:
                capabilities.append("audio")

            # Extract model information
            model_info = ModelInfo(
                model_id=model_id,
                name=model_data.get("name", model_id),
                description=model_data.get("description", ""),
                size_bytes=0,  # Not relevant for API models
                format="api",
                provider="anthropic",
                parameters=None,  # Not directly provided by Anthropic
                context_length=model_data.get("context_window", None),
                capabilities=capabilities,
                version=model_data.get("version", "1.0"),
                checksum=None,
                download_url=None,
                local_path=None
            )

            return model_info

        except (KeyError, TypeError) as e:
            logger.error(f"Error creating ModelInfo for {model_id}: {e}")
            return None

    def download_model(self, model_id: str, destination_path: str) -> Tuple[bool, str]:
        """
        Anthropic doesn't support model downloads, this is an API-only service.

        Returns:
            Always returns (False, "Anthropic doesn't support model downloads")
        """
        logger.warning(f"Download requested for {model_id} to {destination_path}, but not supported")
        return False, "Anthropic doesn't support model downloads"
