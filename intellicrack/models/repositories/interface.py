"""Repository interface for Intellicrack model repositories.

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
from abc import ABC, abstractmethod
from typing import Any

"""
Model Repository Interface Module

This module defines the interface and base classes for model repositories used in Intellicrack.
It provides a common interface for both local file repositories and various API-based repositories.
"""

# Set up logging
logger = logging.getLogger(__name__)


class ModelInfo:
    """Class representing metadata about an AI model."""

    def __init__(
        self,
        model_id: str,
        name: str,
        description: str = "",
        size_bytes: int = 0,
        format: str = "gguf",
        provider: str = "unknown",
        parameters: int | None = None,
        context_length: int | None = None,
        capabilities: list[str] = None,
        version: str = "1.0",
        checksum: str | None = None,
        download_url: str | None = None,
        local_path: str | None = None,
    ):
        """Initialize a ModelInfo object.

        Args:
            model_id: Unique identifier for the model
            name: Human-readable name of the model
            description: Description of the model's capabilities
            size_bytes: Size of the model file in bytes
            format: Model format (e.g., 'gguf', 'ggml', etc.)
            provider: Provider of the model (e.g., 'openai', 'anthropic', etc.)
            parameters: Number of parameters in the model
            context_length: Maximum context length supported by the model
            capabilities: List of capabilities (e.g., 'text-generation', 'embeddings', etc.)
            version: Version of the model
            checksum: SHA256 checksum of the model file for verification
            download_url: URL where the model can be downloaded from
            local_path: Path to the model file if it exists locally

        """
        self.model_id = model_id
        self.name = name
        self.description = description
        self.size_bytes = size_bytes
        self.format = format
        self.provider = provider
        self.parameters = parameters
        self.context_length = context_length
        self.capabilities = capabilities or []
        self.version = version
        self.checksum = checksum
        self.download_url = download_url
        self.local_path = local_path

    def is_downloaded(self) -> bool:
        """Check if the model is downloaded locally."""
        return self.local_path is not None and os.path.exists(self.local_path)

    def get_size_human_readable(self) -> str:
        """Return the size in a human-readable format."""
        if self.size_bytes < 1024:
            return f"{self.size_bytes} B"
        if self.size_bytes < 1024 * 1024:
            return f"{self.size_bytes / 1024:.1f} KB"
        if self.size_bytes < 1024 * 1024 * 1024:
            return f"{self.size_bytes / (1024 * 1024):.1f} MB"
        return f"{self.size_bytes / (1024 * 1024 * 1024):.1f} GB"

    def to_dict(self) -> dict[str, Any]:
        """Convert the model info to a dictionary for serialization."""
        return {
            "model_id": self.model_id,
            "name": self.name,
            "description": self.description,
            "size_bytes": self.size_bytes,
            "format": self.format,
            "provider": self.provider,
            "parameters": self.parameters,
            "context_length": self.context_length,
            "capabilities": self.capabilities,
            "version": self.version,
            "checksum": self.checksum,
            "download_url": self.download_url,
            "local_path": self.local_path,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModelInfo":
        """Create a ModelInfo instance from a dictionary."""
        return cls(
            model_id=data.get("model_id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            size_bytes=data.get("size_bytes", 0),
            format=data.get("format", "gguf"),
            provider=data.get("provider", "unknown"),
            parameters=data.get("parameters"),
            context_length=data.get("context_length"),
            capabilities=data.get("capabilities", []),
            version=data.get("version", "1.0"),
            checksum=data.get("checksum"),
            download_url=data.get("download_url"),
            local_path=data.get("local_path"),
        )


class ModelRepositoryInterface(ABC):
    """Base interface for model repositories."""

    @abstractmethod
    def get_available_models(self) -> list[ModelInfo]:
        """Get a list of available models from the repository.

        Returns:
            A list of ModelInfo objects representing the available models.

        """

    @abstractmethod
    def download_model(self, model_id: str, destination_path: str) -> tuple[bool, str]:
        """Download a model from the repository to the specified path.

        Args:
            model_id: The ID of the model to download
            destination_path: The path where the model should be saved

        Returns:
            A tuple of (success, message) where success is a boolean indicating if the
            download was successful, and message is a string with details.

        """

    @abstractmethod
    def get_model_details(self, model_id: str) -> ModelInfo | None:
        """Get detailed information about a specific model.

        Args:
            model_id: The ID of the model to get details for

        Returns:
            A ModelInfo object containing the model details, or None if the model is not found.

        """

    @abstractmethod
    def authenticate(self) -> tuple[bool, str]:
        """Authenticate with the repository.

        Returns:
            A tuple of (success, message) where success is a boolean indicating if the
            authentication was successful, and message is a string with details.

        """


class DownloadProgressCallback:
    """Interface for download progress callbacks."""

    def on_progress(self, bytes_downloaded: int, total_bytes: int):
        """Handle download progress updates.

        Args:
            bytes_downloaded: Number of bytes downloaded so far
            total_bytes: Total size of the file in bytes (may be 0 if unknown)

        """

    def on_complete(self, success: bool, message: str):
        """Handle download completion.

        Args:
            success: Whether the download was successful
            message: A message describing the result

        """
