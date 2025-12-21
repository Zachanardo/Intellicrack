"""Model Download Manager for Hugging Face Hub.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import json
import os
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger


logger = get_logger(__name__)

# Try to import huggingface_hub
try:
    from huggingface_hub import HfApi, ModelCard, hf_hub_download, list_models, snapshot_download
    from huggingface_hub.utils import RepositoryNotFoundError

    HAS_HF_HUB = True
except ImportError as e:
    logger.exception("Import error in model_download_manager: %s", e)
    HfApi = None
    ModelCard = None
    hf_hub_download = None
    list_models = None
    snapshot_download = None
    RepositoryNotFoundError = Exception
    HAS_HF_HUB = False

try:
    import requests

    HAS_REQUESTS = True
except ImportError as e:
    logger.exception("Import error in model_download_manager: %s", e)
    requests = None
    HAS_REQUESTS = False


@dataclass
class DownloadProgress:
    """Progress information for downloads."""

    total_size: int
    downloaded_size: int
    speed: float  # bytes per second
    eta: float  # seconds remaining
    percentage: float
    current_file: str = ""
    total_files: int = 1
    completed_files: int = 0


@dataclass
class ModelInfo:
    """Information about a model from Hugging Face Hub."""

    model_id: str
    author: str
    model_name: str
    downloads: int
    likes: int
    tags: list[str]
    pipeline_tag: str | None = None
    library_name: str | None = None
    model_size: int | None = None
    last_modified: datetime | None = None
    private: bool = False
    gated: bool = False


class ModelDownloadManager:
    """Manages downloading models from Hugging Face Hub."""

    def __init__(self, cache_dir: str | None = None, token: str | None = None) -> None:
        """Initialize the model download manager.

        Args:
            cache_dir: Directory to cache downloaded models
            token: Hugging Face API token for private/gated models

        """
        if cache_dir is None:
            cache_dir = Path.home() / ".intellicrack" / "model_cache"

        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.token = token or os.environ.get("HF_TOKEN")
        self.download_progress = {}
        self.active_downloads = {}

        # Cache metadata
        self.metadata_file = self.cache_dir / "metadata.json"
        self.metadata = self._load_metadata()

        if not HAS_HF_HUB:
            logger.warning("huggingface_hub not available - download functionality limited")

        # Initialize API
        self.api = HfApi(token=self.token) if HAS_HF_HUB else None

    def _load_metadata(self) -> dict[str, Any]:
        """Load cached metadata."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file) as f:
                    return json.load(f)
            except Exception as e:
                logger.exception("Failed to load metadata: %s", e)
        return {"models": {}, "downloads": {}}

    def _save_metadata(self) -> None:
        """Save metadata to cache."""
        try:
            with open(self.metadata_file, "w") as f:
                json.dump(self.metadata, f, indent=2, default=str)
        except Exception as e:
            logger.exception("Failed to save metadata: %s", e)

    def search_models(
        self,
        query: str,
        task: str | None = None,
        library: str | None = None,
        limit: int = 10,
        sort: str = "downloads",
    ) -> list[ModelInfo]:
        """Search for models on Hugging Face Hub.

        Args:
            query: Search query
            task: Filter by task (e.g., "text-generation", "text2text-generation")
            library: Filter by library (e.g., "transformers", "pytorch")
            limit: Maximum number of results
            sort: Sort by "downloads", "likes", or "lastModified"

        Returns:
            List of ModelInfo objects

        """
        if not HAS_HF_HUB:
            logger.exception("huggingface_hub required for model search")
            return []

        try:
            # Build filters
            filters = {}
            if task:
                filters["pipeline_tag"] = task
            if library:
                filters["library_name"] = library

            # Search models
            models = list(
                list_models(
                    search=query,
                    filter=filters,
                    limit=limit,
                    sort=sort,
                    direction=-1,  # Descending
                    token=self.token,
                ),
            )

            # Convert to ModelInfo
            results = []
            for model in models:
                info = ModelInfo(
                    model_id=model.modelId,
                    author=model.author or model.modelId.split("/")[0],
                    model_name=model.modelId.split("/")[-1],
                    downloads=model.downloads or 0,
                    likes=model.likes or 0,
                    tags=model.tags or [],
                    pipeline_tag=model.pipeline_tag,
                    library_name=model.library_name,
                    last_modified=model.lastModified,
                    private=model.private,
                    gated=model.gated,
                )
                results.append(info)

            return results

        except Exception as e:
            logger.exception("Failed to search models: %s", e)
            return []

    def get_model_info(self, model_id: str) -> ModelInfo | None:
        """Get detailed information about a specific model.

        Args:
            model_id: Hugging Face model ID (e.g., "meta-llama/Llama-2-7b")

        Returns:
            ModelInfo object or None

        """
        if not HAS_HF_HUB:
            logger.exception("huggingface_hub required for model info")
            return None

        try:
            # Get model info from API
            model = self.api.model_info(model_id, token=self.token)

            # Try to get model size
            model_size = None
            try:
                siblings = model.siblings or []
                for file in siblings:
                    if file.rfilename and file.size and file.rfilename.endswith((".bin", ".safetensors", ".pt", ".pth")):
                        model_size = (model_size or 0) + file.size
            except Exception as e:
                logger.debug("Could not calculate model size for %s: %s", model.modelId, e)

            info = ModelInfo(
                model_id=model.modelId,
                author=model.author or model.modelId.split("/")[0],
                model_name=model.modelId.split("/")[-1],
                downloads=model.downloads or 0,
                likes=model.likes or 0,
                tags=model.tags or [],
                pipeline_tag=model.pipeline_tag,
                library_name=model.library_name,
                model_size=model_size,
                last_modified=model.lastModified,
                private=model.private,
                gated=model.gated,
            )

            # Cache info
            self.metadata["models"][model_id] = {
                "info": info.__dict__,
                "cached_at": datetime.now().isoformat(),
            }
            self._save_metadata()

            return info

        except RepositoryNotFoundError:
            logger.exception("Model not found: %s", model_id)
            return None
        except Exception as e:
            logger.exception("Failed to get model info: %s", e)
            return None

    def get_model_card(self, model_id: str) -> dict[str, Any] | None:
        """Fetch and parse the model card for a given model.

        Args:
            model_id: Hugging Face model ID

        Returns:
            Dictionary containing model card content or None

        """
        if not HAS_HF_HUB or not ModelCard:
            logger.exception("ModelCard functionality not available")
            return None

        try:
            # Try to load model card
            card = ModelCard.load(model_id, token=self.token)

            # Extract useful information from the card
            card_data = {
                "content": card.content,
                "data": card.data.to_dict() if hasattr(card.data, "to_dict") else {},
                "metadata": {
                    "tags": getattr(card.data, "tags", []),
                    "license": getattr(card.data, "license", None),
                    "language": getattr(card.data, "language", []),
                    "datasets": getattr(card.data, "datasets", []),
                    "metrics": getattr(card.data, "metrics", []),
                    "model_type": getattr(card.data, "model_type", None),
                    "pipeline_tag": getattr(card.data, "pipeline_tag", None),
                    "library_name": getattr(card.data, "library_name", None),
                },
            }

            # Cache the model card data
            if model_id not in self.metadata["models"]:
                self.metadata["models"][model_id] = {}
            self.metadata["models"][model_id]["card"] = card_data
            self.metadata["models"][model_id]["card_cached_at"] = datetime.now().isoformat()
            self._save_metadata()

            logger.info("Successfully fetched model card for %s", model_id)
            return card_data

        except Exception as e:
            logger.exception("Failed to fetch model card for %s: %s", model_id, e)
            return None

    def get_model_readme(self, model_id: str) -> str | None:
        """Get the README content from a model's card.

        Args:
            model_id: Hugging Face model ID

        Returns:
            README content as string or None

        """
        card_data = self.get_model_card(model_id)
        return card_data["content"] if card_data and "content" in card_data else None

    def download_model(
        self,
        model_id: str,
        revision: str | None = None,
        allow_patterns: list[str] | None = None,
        ignore_patterns: list[str] | None = None,
        progress_callback: Callable[[DownloadProgress], None] | None = None,
        force_download: bool = False,
    ) -> Path | None:
        """Download a model from Hugging Face Hub.

        Args:
            model_id: Model ID to download
            revision: Specific revision/branch to download
            allow_patterns: Patterns of files to include
            ignore_patterns: Patterns of files to exclude
            progress_callback: Callback for progress updates
            force_download: Force re-download even if cached

        Returns:
            Path to downloaded model or None

        """
        if not HAS_HF_HUB:
            logger.exception("huggingface_hub required for model downloads")
            return None

        # Check if already downloaded
        model_dir = self.cache_dir / model_id.replace("/", "_")
        if model_dir.exists() and not force_download:
            logger.info("Model already cached: %s", model_dir)
            return model_dir

        try:
            # Track download
            download_id = f"{model_id}_{time.time()}"
            self.active_downloads[download_id] = {
                "model_id": model_id,
                "start_time": time.time(),
                "status": "downloading",
            }

            # Create progress tracker
            def progress_hook(progress_dict: dict[str, Any]) -> None:
                if progress_callback and "downloaded" in progress_dict:
                    prog = DownloadProgress(
                        total_size=progress_dict.get("total", 0),
                        downloaded_size=progress_dict.get("downloaded", 0),
                        speed=progress_dict.get("speed", 0),
                        eta=progress_dict.get("eta", 0),
                        percentage=progress_dict.get("percentage", 0),
                        current_file=progress_dict.get("filename", ""),
                    )
                    progress_callback(prog)

            # Download model
            logger.info("Downloading model: %s", model_id)

            # Note: huggingface_hub snapshot_download doesn't directly support progress callbacks
            # so we'll call progress_hook with a start notification
            if progress_callback:
                progress_hook({"downloaded": 0, "total": 0, "percentage": 0, "filename": model_id})
            local_path = snapshot_download(
                repo_id=model_id,
                revision=revision,
                cache_dir=str(self.cache_dir),
                local_dir=str(model_dir) if force_download else None,
                local_dir_use_symlinks=False,
                token=self.token,
                allow_patterns=allow_patterns,
                ignore_patterns=ignore_patterns or ["*.md", "*.txt", ".gitattributes"],
            )

            # Update metadata
            self.metadata["downloads"][model_id] = {
                "path": str(local_path),
                "downloaded_at": datetime.now().isoformat(),
                "revision": revision,
                "size_mb": sum(f.stat().st_size for f in Path(local_path).rglob("*") if f.is_file()) / (1024 * 1024),
            }
            self._save_metadata()

            # Clean up tracking
            del self.active_downloads[download_id]

            logger.info("Model downloaded successfully: %s", local_path)
            return Path(local_path)

        except Exception as e:
            logger.exception("Failed to download model: %s", e)
            if download_id in self.active_downloads:
                del self.active_downloads[download_id]
            return None

    def download_file(
        self,
        model_id: str,
        filename: str,
        revision: str | None = None,
        progress_callback: Callable[[DownloadProgress], None] | None = None,
    ) -> Path | None:
        """Download a specific file from a model repository.

        Args:
            model_id: Model ID
            filename: File to download
            revision: Specific revision
            progress_callback: Progress callback

        Returns:
            Path to downloaded file or None

        """
        if not HAS_HF_HUB:
            logger.exception("huggingface_hub required for file downloads")
            return None

        try:
            # Track download progress if callback provided
            if progress_callback:
                # Create progress tracking
                progress = DownloadProgress(
                    model_id=model_id,
                    file_name=filename,
                    total_bytes=0,
                    downloaded_bytes=0,
                    progress_percent=0.0,
                    download_speed=0.0,
                    status="starting",
                )
                progress_callback(progress)

            # Download file
            local_path = hf_hub_download(
                repo_id=model_id,
                filename=filename,
                revision=revision,
                cache_dir=str(self.cache_dir),
                token=self.token,
            )

            # Report completion if callback provided
            if progress_callback:
                progress.status = "completed"
                progress.progress_percent = 100.0
                progress_callback(progress)

            return Path(local_path)

        except Exception as e:
            logger.exception("Failed to download file: %s", e)
            return None

    def list_cached_models(self) -> dict[str, dict[str, Any]]:
        """List all cached models.

        Returns:
            Dictionary of model_id -> metadata

        """
        cached_models = {}

        # From metadata
        for model_id, download_info in self.metadata.get("downloads", {}).items():
            path = Path(download_info["path"])
            if path.exists():
                cached_models[model_id] = download_info

        # Scan cache directory
        for model_dir in self.cache_dir.iterdir():
            if model_dir.is_dir() and model_dir.name not in ["downloads", "tmp"]:
                model_id = model_dir.name.replace("_", "/", 1)
                if model_id not in cached_models:
                    size_mb = sum(f.stat().st_size for f in model_dir.rglob("*") if f.is_file()) / (1024 * 1024)
                    cached_models[model_id] = {
                        "path": str(model_dir),
                        "size_mb": size_mb,
                        "discovered": True,
                    }

        return cached_models

    def delete_cached_model(self, model_id: str) -> bool:
        """Delete a cached model.

        Args:
            model_id: Model ID to delete

        Returns:
            True if deleted, False otherwise

        """
        # Find model path
        if model_id in self.metadata.get("downloads", {}):
            model_path = Path(self.metadata["downloads"][model_id]["path"])
        else:
            model_path = self.cache_dir / model_id.replace("/", "_")

        if model_path.exists():
            try:
                shutil.rmtree(model_path)

                # Update metadata
                if model_id in self.metadata.get("downloads", {}):
                    del self.metadata["downloads"][model_id]
                    self._save_metadata()

                logger.info("Deleted cached model: %s", model_id)
                return True

            except Exception as e:
                logger.exception("Failed to delete model: %s", e)
                return False

        return False

    def get_cache_size(self) -> dict[str, float]:
        """Get total cache size information.

        Returns:
            Dictionary with size information in MB

        """
        model_count = 0

        total_size = sum(path.stat().st_size for path in self.cache_dir.rglob("*") if path.is_file())
        cached_models = self.list_cached_models()
        model_count = len(cached_models)

        return {
            "total_size_mb": total_size / (1024 * 1024),
            "total_size_gb": total_size / (1024 * 1024 * 1024),
            "model_count": model_count,
            "cache_dir": str(self.cache_dir),
        }

    def clear_cache(self, keep_recent: int = 0) -> int:
        """Clear the model cache.

        Args:
            keep_recent: Number of recently downloaded models to keep

        Returns:
            Number of models deleted

        """
        if keep_recent <= 0:
            # Clear everything
            try:
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                self.metadata = {"models": {}, "downloads": {}}
                self._save_metadata()
                logger.info("Cleared entire model cache")
                return -1  # All models
            except Exception as e:
                logger.exception("Failed to clear cache: %s", e)
                return 0

        # Keep recent models
        downloads = self.metadata.get("downloads", {})
        sorted_models = sorted(
            downloads.items(),
            key=lambda x: x[1].get("downloaded_at", ""),
            reverse=True,
        )

        return sum(bool(self.delete_cached_model(model_id)) for model_id, _ in sorted_models[keep_recent:])

    def verify_model_files(self, model_path: str | Path) -> dict[str, Any]:
        """Verify integrity of downloaded model files.

        Args:
            model_path: Path to model directory

        Returns:
            Verification results

        """
        model_path = Path(model_path)
        results = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "files": {},
        }

        if not model_path.exists():
            results["valid"] = False
            results["errors"].append("Model path does not exist")
            return results

        # Check for essential files
        essential_patterns = [
            "config.json",
            "*.bin",
            "*.safetensors",
            "*.pt",
            "*.pth",
            "*.onnx",
            "*.pb",
            "*.h5",
        ]

        has_weights = False
        has_config = False

        for pattern in essential_patterns:
            if files := list(model_path.glob(pattern)):
                if pattern == "config.json":
                    has_config = True
                else:
                    has_weights = True

                for file in files:
                    results["files"][file.name] = {
                        "size_mb": file.stat().st_size / (1024 * 1024),
                        "exists": True,
                    }

        if not has_config:
            results["warnings"].append("No config.json found")

        if not has_weights:
            results["valid"] = False
            results["errors"].append("No model weight files found")

        # Check tokenizer files
        tokenizer_files = ["tokenizer_config.json", "tokenizer.json", "vocab.json"]
        has_tokenizer = any((model_path / file).exists() for file in tokenizer_files)
        if not has_tokenizer:
            results["warnings"].append("No tokenizer files found")

        return results


# Global instance
_DOWNLOAD_MANAGER = None


def get_download_manager(token: str | None = None) -> ModelDownloadManager:
    """Get the global model download manager."""
    global _DOWNLOAD_MANAGER
    if _DOWNLOAD_MANAGER is None:
        _DOWNLOAD_MANAGER = ModelDownloadManager(token=token)
    return _DOWNLOAD_MANAGER
