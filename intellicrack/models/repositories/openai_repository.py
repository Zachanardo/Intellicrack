"""
OpenAI Repository Implementation

This module provides an implementation of the model repository interface for
accessing models via OpenAI's API.
"""

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from .base import APIRepositoryBase, RateLimitConfig
from .interface import ModelInfo

# Set up logging
logger = logging.getLogger(__name__)

class OpenAIRepository(APIRepositoryBase):
    """Repository implementation for OpenAI's API."""

    def __init__(self,
                 repository_name: str = "openai",
                 api_endpoint: str = "https://api.openai.com/v1",
                 api_key: str = "",
                 timeout: int = 60,
                 proxy: str = "",
                 rate_limit_config: Optional[RateLimitConfig] = None,
                 cache_config: Optional[Dict[str, Any]] = None,
                 download_dir: str = os.path.join(os.path.dirname(__file__), "..", "downloads")):
        """
        Initialize the OpenAI repository.

        Args:
            repository_name: Name of the repository
            api_endpoint: Base URL of the API
            api_key: OpenAI API key
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
        Authenticate with the OpenAI API.

        Returns:
            Tuple of (success, message)
        """
        if not self.api_key:
            return False, "API key is required for OpenAI authentication"

        # Test the API key by making a simple request to list models
        success, _, error_message = self._make_request(
            endpoint="models",
            method="GET",
            use_cache=False
        )

        if success:
            return True, "Authentication successful"
        else:
            return False, f"Authentication failed: {error_message}"

    def get_available_models(self) -> List[ModelInfo]:
        """
        Get a list of available models from OpenAI API.

        Returns:
            A list of ModelInfo objects representing the available models.
        """
        success, data, error_message = self._make_request(
            endpoint="models",
            method="GET"
        )

        if not success:
            logger.error(f"Failed to get models from OpenAI: {error_message}")
            return []

        models = []

        try:
            # Extract model information from the response
            for model_data in data.get("data", []):
                model_id = model_data.get("id")

                # For most API usage we'll only care about chat and embedding models
                if not (model_id.startswith('gpt-') or 'embedding' in model_id or model_id == 'dall-e-3'):
                    continue

                # Get detailed model info
                model_info = self._get_model_details(model_id)
                if model_info:
                    models.append(model_info)

            return models

        except (KeyError, TypeError) as e:
            logger.error(f"Error parsing OpenAI models response: {e}")
            return []

    def get_model_details(self, model_id: str) -> Optional[ModelInfo]:
        """
        Get detailed information about a specific model.

        Args:
            model_id: The ID of the model to get details for

        Returns:
            A ModelInfo object containing the model details, or None if the model is not found.
        """
        return self._get_model_details(model_id)

    def _get_model_details(self, model_id: str) -> Optional[ModelInfo]:
        """
        Get detailed information about a model from the API.

        Args:
            model_id: The ID of the model

        Returns:
            ModelInfo object, or None if failed
        """
        success, data, error_message = self._make_request(
            endpoint=f"models/{model_id}",
            method="GET"
        )

        if not success:
            logger.error(f"Failed to get model details for {model_id}: {error_message}")
            return None

        try:
            # Determine model capabilities based on model ID
            capabilities = []
            if model_id.startswith('gpt-'):
                capabilities.append('text-generation')
                if 'vision' in model_id or model_id in ['gpt-4-turbo', 'gpt-4o']:
                    capabilities.append('vision')
            elif 'embedding' in model_id:
                capabilities.append('embeddings')
            elif model_id == 'dall-e-3':
                capabilities.append('image-generation')

            # Extract model information
            model_info = ModelInfo(
                model_id=model_id,
                name=data.get("name", model_id),
                description=data.get("description", ""),
                size_bytes=0,  # Not relevant for API-only models
                format="api",
                provider="openai",
                parameters=None,
                context_length=data.get("context_length"),
                capabilities=capabilities,
                version=data.get("version", "1.0"),
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
        OpenAI doesn't support model downloads for most models, this is primarily an API-only service.

        Returns:
            Always returns (False, "OpenAI doesn't support model downloads")
        """
        logger.warning(f"Download requested for {model_id} to {destination_path}, but not supported")
        return False, "OpenAI doesn't support model downloads for this model"
