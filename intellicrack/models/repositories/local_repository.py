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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Local File Repository Implementation

This module provides an implementation of the model repository interface for
locally stored model files. It adapts the existing file-based model system
to the repository interface.
"""

import glob
import hashlib
import json
import logging
import os

from .interface import DownloadProgressCallback, ModelInfo, ModelRepositoryInterface

# Set up logging
logger = logging.getLogger(__name__)

class LocalFileRepository(ModelRepositoryInterface):
    """Repository adapter for the local file system."""

    def __init__(self, models_directory: str = "models"):
        """Initialize the local file repository.

        Args:
            models_directory: Directory where models are stored

        """
        self.models_directory = models_directory
        self.models_metadata_file = os.path.join(models_directory, "models_metadata.json")
        self.models_cache = {}

        # Create models directory if it doesn't exist
        os.makedirs(models_directory, exist_ok=True)

        # Load existing metadata
        self._load_metadata()

    def _load_metadata(self):
        """Load metadata for local models."""
        if os.path.exists(self.models_metadata_file):
            try:
                with open(self.models_metadata_file) as f:
                    metadata = json.load(f)

                    # Convert metadata to ModelInfo objects
                    self.models_cache = {
                        model_id: ModelInfo.from_dict(model_data)
                        for model_id, model_data in metadata.items()
                    }

                logger.info(f"Loaded metadata for {len(self.models_cache)} local models")
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"Failed to load local models metadata: {e}")
                self.models_cache = {}

    def _save_metadata(self):
        """Save metadata for local models."""
        metadata = {
            model_id: model_info.to_dict()
            for model_id, model_info in self.models_cache.items()
        }

        try:
            with open(self.models_metadata_file, "w") as f:
                json.dump(metadata, f, indent=2)
        except OSError as e:
            logger.warning(f"Failed to save local models metadata: {e}")

    def _scan_for_models(self):
        """Scan the models directory for GGUF files that are not in the cache."""
        # Find all GGUF files in the models directory
        gguf_pattern = os.path.join(self.models_directory, "**", "*.gguf")
        model_files = glob.glob(gguf_pattern, recursive=True)

        # Create model entries for files not already in the cache
        for file_path in model_files:
            # Use the relative path as model_id
            rel_path = os.path.relpath(file_path, self.models_directory)
            model_id = rel_path.replace("\\", "/")  # Normalize path separators

            if model_id not in self.models_cache:
                # Get file information
                file_size = os.path.getsize(file_path)
                file_name = os.path.basename(file_path)

                # Create a ModelInfo object
                model_info = ModelInfo(
                    model_id=model_id,
                    name=file_name,
                    description=f"Local GGUF model: {file_name}",
                    size_bytes=file_size,
                    format="gguf",
                    provider="local",
                    local_path=file_path,
                )

                # Compute checksum asynchronously (not blocking the UI)
                # In a real implementation, this could be done in a background thread
                self._compute_checksum(model_info)

                # Add to cache
                self.models_cache[model_id] = model_info

        # Save metadata after scan
        self._save_metadata()

    def _compute_checksum(self, model_info: ModelInfo):
        """Compute the SHA256 checksum for a model file.

        Args:
            model_info: ModelInfo object to update with the checksum

        """
        if not model_info.local_path or not os.path.exists(model_info.local_path):
            return

        try:
            sha256_hash = hashlib.sha256()
            with open(model_info.local_path, "rb") as f:
                # Read and update hash in chunks
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)

            model_info.checksum = sha256_hash.hexdigest()
        except OSError as e:
            logger.warning(f"Failed to compute checksum for {model_info.name}: {e}")

    def get_available_models(self) -> list[ModelInfo]:
        """Get a list of available models from the local repository.

        Returns:
            A list of ModelInfo objects representing the available models.

        """
        # Scan for new models first
        self._scan_for_models()

        # Return all models
        return list(self.models_cache.values())

    def get_model_details(self, model_id: str) -> ModelInfo | None:
        """Get detailed information about a specific model.

        Args:
            model_id: The ID of the model to get details for

        Returns:
            A ModelInfo object containing the model details, or None if the model is not found.

        """
        # Check if the model is in our cache
        if model_id in self.models_cache:
            return self.models_cache[model_id]

        # If not, scan for models and check again
        self._scan_for_models()
        return self.models_cache.get(model_id)

    # pylint: disable=too-many-locals
    def download_model(self, model_id: str, destination_path: str,
                      progress_callback: DownloadProgressCallback | None = None) -> tuple[bool, str]:
        """"Download" a model from the local repository (copy the file).

        Args:
            model_id: ID of the model to download
            destination_path: Path where the model should be saved
            progress_callback: Optional callback for progress updates

        Returns:
            Tuple of (success, message)

        """
        # Get model details
        model_info = self.get_model_details(model_id)
        if not model_info:
            return False, f"Model {model_id} not found"

        if not model_info.local_path or not os.path.exists(model_info.local_path):
            return False, f"Local file for model {model_id} not found"

        # Create the destination directory if it doesn't exist
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)

        # For local repository, we're just copying the file
        try:
            # Get file size for progress reporting
            file_size = os.path.getsize(model_info.local_path)

            # Open source and destination files
            with open(model_info.local_path, "rb") as src, open(destination_path, "wb") as dst:
                # Copy in chunks for progress tracking
                copied = 0
                chunk_size = 1024 * 1024  # 1 MB chunks

                while True:
                    buf = src.read(chunk_size)
                    if not buf:
                        break

                    dst.write(buf)
                    copied += len(buf)

                    # Report progress
                    if progress_callback:
                        progress_callback.on_progress(copied, file_size)

            if progress_callback:
                progress_callback.on_complete(True, "Copy complete")

            return True, "Copy complete"

        except OSError as e:
            logger.error("IO error in local_repository: %s", e)
            if progress_callback:
                progress_callback.on_complete(False, f"Copy failed: {e!s}")
            return False, f"Copy failed: {e!s}"

    def add_model(self, file_path: str) -> ModelInfo | None:
        """Add a model file to the repository.

        Args:
            file_path: Path to the model file

        Returns:
            ModelInfo object for the added model, or None if failed

        """
        if not os.path.exists(file_path):
            logger.warning(f"Model file not found: {file_path}")
            return None

        # Get file information
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)

        # If the file is not in the models directory, copy it
        if not os.path.abspath(file_path).startswith(os.path.abspath(self.models_directory)):
            # Create a destination path in our models directory
            dest_path = os.path.join(self.models_directory, file_name)

            # Copy the file
            try:
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                with open(file_path, "rb") as src, open(dest_path, "wb") as dst:
                    dst.write(src.read())

                file_path = dest_path
            except OSError as e:
                logger.error(f"Failed to copy model file: {e}")
                return None

        # Create a relative path for the model_id
        rel_path = os.path.relpath(file_path, self.models_directory)
        model_id = rel_path.replace("\\", "/")  # Normalize path separators

        # Create a ModelInfo object
        model_info = ModelInfo(
            model_id=model_id,
            name=file_name,
            description=f"Local GGUF model: {file_name}",
            size_bytes=file_size,
            format="gguf",
            provider="local",
            local_path=file_path,
        )

        # Compute checksum asynchronously
        self._compute_checksum(model_info)

        # Add to cache
        self.models_cache[model_id] = model_info

        # Save metadata
        self._save_metadata()

        return model_info

    def authenticate(self) -> tuple[bool, str]:
        """Authenticate with the repository (no-op for local repository).

        Returns:
            Always returns (True, "Local repository doesn't require authentication")

        """
        return True, "Local repository doesn't require authentication"

    def remove_model(self, model_id: str) -> bool:
        """Remove a model from the repository.

        Args:
            model_id: ID of the model to remove

        Returns:
            True if the model was removed, False otherwise

        """
        if model_id not in self.models_cache:
            return False

        model_info = self.models_cache[model_id]

        # Remove the file if it exists
        if model_info.local_path and os.path.exists(model_info.local_path):
            try:
                os.remove(model_info.local_path)
            except OSError as e:
                logger.warning(f"Failed to remove model file: {e}")
                return False

        # Remove from cache
        del self.models_cache[model_id]

        # Save metadata
        self._save_metadata()

        return True
