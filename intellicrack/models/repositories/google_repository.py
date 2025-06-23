"""
Google Repository Implementation

This module provides an implementation of the model repository interface for
accessing Google's Gemini models via their GenerativeAI API.
"""

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from .base import APIRepositoryBase, RateLimitConfig
from .interface import ModelInfo

# Set up logging
logger = logging.getLogger(__name__)

class GoogleRepository(APIRepositoryBase):
    """Repository implementation for Google's GenerativeAI API."""

    def __init__(self,
                 repository_name: str = "google",
                 api_endpoint: str = "https://generativelanguage.googleapis.com",
                 api_key: str = "",
                 timeout: int = 60,
                 proxy: str = "",
                 rate_limit_config: Optional[RateLimitConfig] = None,
                 cache_config: Optional[Dict[str, Any]] = None,
                 download_dir: str = os.path.join(os.path.dirname(__file__), "..", "downloads")):
        """
        Initialize the Google repository.

        Args:
            repository_name: Name of the repository
            api_endpoint: Base URL of the API
            api_key: Google API key
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

        # Google's API version
        self.api_version = "v1"

    def authenticate(self) -> Tuple[bool, str]:
        """
        Authenticate with the Google API.

        Returns:
            Tuple of (success, message)
        """
        if not self.api_key:
            return False, "API key is required for Google authentication"

        # Test the API key by making a simple request to list models
        success, _, error_message = self._make_request(
            endpoint=f"{self.api_version}/models",
            method="GET",
            params={"key": self.api_key},
            use_cache=False
        )

        if success:
            return True, "Authentication successful"
        else:
            return False, f"Authentication failed: {error_message}"

    def get_available_models(self) -> List[ModelInfo]:
        """
        Get a list of available models from Google's GenerativeAI API.

        Returns:
            A list of ModelInfo objects representing the available models.
        """
        success, data, error_message = self._make_request(
            endpoint=f"{self.api_version}/models",
            method="GET",
            params={"key": self.api_key}
        )

        if not success:
            logger.error(f"Failed to get models from Google: {error_message}")
            return []

        models = []

        try:
            # Extract model information from the response
            for model_data in data.get("models", []):
                model_id = model_data.get("name")
                if model_id:
                    # Extract just the model name from the full path
                    # Format is usually "models/gemini-pro" or similar
                    if "/" in model_id:
                        model_id = model_id.split("/")[-1]

                    model_info = self._create_model_info(model_id, model_data)
                    if model_info:
                        models.append(model_info)

            return models

        except (KeyError, TypeError) as e:
            logger.error(f"Error parsing Google models response: {e}")
            return []

    def get_model_details(self, model_id: str) -> Optional[ModelInfo]:
        """
        Get detailed information about a specific model.

        Args:
            model_id: The ID of the model to get details for

        Returns:
            A ModelInfo object containing the model details, or None if the model is not found.
        """
        # Create the full model name for the API
        full_model_name = model_id
        if not model_id.startswith("models/"):
            full_model_name = f"models/{model_id}"

        success, data, error_message = self._make_request(
            endpoint=f"{self.api_version}/{full_model_name}",
            method="GET",
            params={"key": self.api_key}
        )

        if not success:
            logger.error(f"Failed to get model details for {model_id}: {error_message}")
            return None

        try:
            return self._create_model_info(model_id, data)
        except (KeyError, TypeError) as e:
            logger.error(f"Error parsing Google model details for {model_id}: {e}")
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
            # Extract display name or use model_id
            name = model_data.get("displayName", model_id)

            # Extract description
            description = model_data.get("description", "")

            # Extract version
            version = model_data.get("version", "1.0")

            # Extract input/output token limits
            context_length = None
            if "inputTokenLimit" in model_data:
                context_length = model_data["inputTokenLimit"]

            # Extract capabilities
            capabilities = []
            supported_generation_methods = model_data.get("supportedGenerationMethods", [])

            if "generateContent" in supported_generation_methods:
                capabilities.append("text-generation")
            if "countTokens" in supported_generation_methods:
                capabilities.append("token-counting")
            if "embedContent" in supported_generation_methods:
                capabilities.append("embeddings")

            # Check for multimodal support
            input_features = []
            for input_feature in model_data.get("inputSchema", {}).get("properties", {}).get("parts", {}).get("items", {}).get("properties", {}).keys():
                input_features.append(input_feature)

            if "inlineData" in input_features:
                capabilities.append("vision")

            # Create ModelInfo
            model_info = ModelInfo(
                model_id=model_id,
                name=name,
                description=description,
                size_bytes=0,  # Not relevant for API-only models
                format="api",
                provider="google",
                parameters=None,  # Not provided by Google
                context_length=context_length,
                capabilities=capabilities,
                version=version,
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
        Google doesn't support model downloads, this is an API-only service.

        Returns:
            Always returns (False, "Google doesn't support model downloads")
        """
        logger.warning(f"Download requested for {model_id} to {destination_path}, but not supported")
        return False, "Google doesn't support model downloads"
