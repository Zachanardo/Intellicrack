"""
LMStudio Repository Implementation

This module provides an implementation of the model repository interface for
accessing models via LMStudio's API.
"""

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from .base import APIRepositoryBase, RateLimitConfig
from .interface import ModelInfo

# Set up logging
logger = logging.getLogger(__name__)

class LMStudioRepository(APIRepositoryBase):
    """Repository implementation for LMStudio's API."""

    def __init__(self,
                 repository_name: str = "lmstudio",
                 api_endpoint: str = "http://localhost:1234/v1",
                 api_key: str = "",
                 timeout: int = 60,
                 proxy: str = "",
                 rate_limit_config: Optional[RateLimitConfig] = None,
                 cache_config: Optional[Dict[str, Any]] = None,
                 download_dir: str = os.path.join(os.path.dirname(__file__), "..", "downloads")):
        """
        Initialize the LMStudio repository.

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
        Authenticate with the LMStudio API.

        Returns:
            Tuple of (success, message)
        """
        # Test connectivity by making a simple request to list models
        success, _, error_message = self._make_request(
            endpoint="models",
            method="GET",
            use_cache=False
        )

        if success:
            return True, "Connection successful"
        else:
            return False, f"Connection failed: {error_message}"

    def get_available_models(self) -> List[ModelInfo]:
        """
        Get a list of available models from the LMStudio API.

        Returns:
            A list of ModelInfo objects representing the available models.
        """
        success, data, error_message = self._make_request(
            endpoint="models",
            method="GET"
        )

        if not success:
            logger.error(f"Failed to get models from LMStudio: {error_message}")
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
            logger.error(f"Error parsing LMStudio models response: {e}")
            return []

    def get_model_details(self, model_id: str) -> Optional[ModelInfo]:
        """
        Get detailed information about a specific model.

        Args:
            model_id: The ID of the model to get details for

        Returns:
            A ModelInfo object containing the model details, or None if the model is not found.
        """
        # LMStudio follows OpenAI API format but doesn't always implement all endpoints
        # Try to get direct model info, but fall back to listing all models if needed
        success, data, error_message = self._make_request(
            endpoint=f"models/{model_id}",
            method="GET"
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
            method="GET"
        )

        if not success:
            logger.error(f"Failed to get models from LMStudio: {error_message}")
            return None

        try:
            # Find the specific model in the list
            for model_data in data.get("data", []):
                if model_data.get("id") == model_id:
                    return self._create_model_info(model_id, model_data)

            # Model not found
            return None

        except (KeyError, TypeError) as e:
            logger.error(f"Error parsing LMStudio model details for {model_id}: {e}")
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
            # LMStudio typically serves local models loaded as GGUF files
            model_info = ModelInfo(
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
                local_path=None  # We don't know the actual path of the local model
            )

            return model_info

        except (KeyError, TypeError) as e:
            logger.error(f"Error creating ModelInfo for {model_id}: {e}")
            return None

    def download_model(self, model_id: str, destination_path: str) -> Tuple[bool, str]:
        """
        LMStudio doesn't support model downloads through its API.

        Returns:
            Always returns (False, "LMStudio doesn't support model downloads through API")
        """
        logger.warning(f"Download requested for {model_id} to {destination_path}, but not supported")
        return False, "LMStudio doesn't support model downloads through API"
