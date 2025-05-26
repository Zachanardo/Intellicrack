"""
Model Manager Module

This module provides the central ModelManager class that coordinates
model repositories and handles model import, loading, and verification.
"""

import os
import logging
import json
import hashlib
import shutil
from typing import Dict, List, Optional, Any, Tuple, Callable
from threading import Thread

from models.repositories.interface import ModelRepositoryInterface, ModelInfo, DownloadProgressCallback
from models.repositories.factory import RepositoryFactory
from models.repositories.local_repository import LocalFileRepository

# Set up logging
logger = logging.getLogger(__name__)

class ProgressHandler(DownloadProgressCallback):
    """Handles progress updates during downloads."""
    
    def __init__(self, progress_callback: Optional[Callable[[int, int], None]] = None,
                complete_callback: Optional[Callable[[bool, str], None]] = None):
        """
        Initialize the progress handler.
        
        Args:
            progress_callback: Function to call with progress updates
            complete_callback: Function to call when download completes
        """
        self.progress_callback = progress_callback
        self.complete_callback = complete_callback
    
    def on_progress(self, bytes_downloaded: int, total_bytes: int):
        """Handle progress updates."""
        if self.progress_callback:
            self.progress_callback(bytes_downloaded, total_bytes)
    
    def on_complete(self, success: bool, message: str):
        """Handle download completion."""
        if self.complete_callback:
            self.complete_callback(success, message)


class ModelManager:
    """
    Manages model repositories and coordinates model operations.
    
    This class serves as the central point for all model-related operations,
    including importing models from files or APIs, managing repositories,
    and interacting with the existing model loading process.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the model manager.
        
        Args:
            config: Application configuration dictionary
        """
        self.config = config
        self.repositories: Dict[str, ModelRepositoryInterface] = {}
        self.download_dir = config.get("download_directory", "models/downloads")
        
        # Create download directory
        os.makedirs(self.download_dir, exist_ok=True)
        
        # Initialize repositories from config
        self._init_repositories()
    
    def _init_repositories(self):
        """Initialize repositories from configuration."""
        repositories_config = self.config.get("model_repositories", {})
        
        for repo_name, repo_config in repositories_config.items():
            # Skip disabled repositories
            if not repo_config.get("enabled", True):
                continue
            
            # Add the repository name to the config
            repo_config["name"] = repo_name
            
            # Create the repository
            repository = RepositoryFactory.create_repository(repo_config)
            if repository:
                self.repositories[repo_name] = repository
                logger.info(f"Initialized repository: {repo_name}")
            else:
                logger.warning(f"Failed to initialize repository: {repo_name}")
    
    def get_available_repositories(self) -> Dict[str, Dict[str, Any]]:
        """
        Get information about available repositories.
        
        Returns:
            Dictionary mapping repository names to information dictionaries
        """
        return {
            name: {
                "name": name,
                "type": repo.__class__.__name__,
                "enabled": True,
                "model_count": len(repo.get_available_models())
            }
            for name, repo in self.repositories.items()
        }
    
    def get_available_models(self, repository_name: Optional[str] = None) -> List[ModelInfo]:
        """
        Get available models from one or all repositories.
        
        Args:
            repository_name: Name of the repository to query, or None for all
            
        Returns:
            List of ModelInfo objects
        """
        models = []
        
        if repository_name:
            # Get models from a specific repository
            if repository_name in self.repositories:
                models.extend(self.repositories[repository_name].get_available_models())
        else:
            # Get models from all repositories
            for repo in self.repositories.values():
                models.extend(repo.get_available_models())
        
        return models
    
    def get_model_details(self, model_id: str, repository_name: str) -> Optional[ModelInfo]:
        """
        Get details for a specific model.
        
        Args:
            model_id: ID of the model
            repository_name: Name of the repository
            
        Returns:
            ModelInfo object, or None if not found
        """
        if repository_name not in self.repositories:
            return None
        
        return self.repositories[repository_name].get_model_details(model_id)
    
    def import_local_model(self, file_path: str) -> Optional[ModelInfo]:
        """
        Import a model from a local file.
        
        Args:
            file_path: Path to the model file
            
        Returns:
            ModelInfo object for the imported model, or None if import failed
        """
        # Ensure we have a local repository
        if "local" not in self.repositories:
            logger.error("Local repository not configured")
            return None
        
        local_repo = self.repositories["local"]
        if not isinstance(local_repo, LocalFileRepository):
            logger.error("Local repository is not of the expected type")
            return None
        
        # Import the model
        return local_repo.add_model(file_path)
    
    def import_api_model(self, model_id: str, repository_name: str,
                        progress_callback: Optional[Callable[[int, int], None]] = None,
                        complete_callback: Optional[Callable[[bool, str], None]] = None) -> bool:
        """
        Import a model from an API repository.
        
        Args:
            model_id: ID of the model to import
            repository_name: Name of the repository
            progress_callback: Function to call with progress updates
            complete_callback: Function to call when import completes
            
        Returns:
            True if the import was started successfully, False otherwise
        """
        if repository_name not in self.repositories:
            if complete_callback:
                complete_callback(False, f"Repository not found: {repository_name}")
            return False
        
        repository = self.repositories[repository_name]
        
        # Get model details
        model_info = repository.get_model_details(model_id)
        if not model_info:
            if complete_callback:
                complete_callback(False, f"Model not found: {model_id}")
            return False
        
        # Create a destination path
        destination_filename = f"{repository_name}_{model_id.replace('/', '_')}.gguf"
        destination_path = os.path.join(self.download_dir, destination_filename)
        
        # Create a progress handler
        progress_handler = ProgressHandler(progress_callback, complete_callback)
        
        # Start the download in a separate thread
        thread = Thread(
            target=self._download_model_thread,
            args=(repository, model_id, destination_path, progress_handler)
        )
        thread.daemon = True
        thread.start()
        
        return True
    
    def _download_model_thread(self, repository: ModelRepositoryInterface, model_id: str,
                             destination_path: str, progress_handler: ProgressHandler):
        """
        Thread function for downloading a model.
        
        Args:
            repository: Repository to download from
            model_id: ID of the model to download
            destination_path: Path to save the model to
            progress_handler: Handler for progress updates
        """
        # Download the model
        success, message = repository.download_model(
            model_id=model_id, 
            destination_path=destination_path,
            progress_callback=progress_handler
        )
        
        # If successful, add to local repository
        if success and os.path.exists(destination_path):
            if "local" in self.repositories:
                local_repo = self.repositories["local"]
                if isinstance(local_repo, LocalFileRepository):
                    local_repo.add_model(destination_path)
        
        # Call the completion handler
        progress_handler.on_complete(success, message)
    
    def verify_model_integrity(self, model_path: str, expected_checksum: Optional[str] = None) -> Tuple[bool, str]:
        """
        Verify the integrity of a model file.
        
        Args:
            model_path: Path to the model file
            expected_checksum: Expected SHA-256 checksum, or None to just compute it
            
        Returns:
            Tuple of (success, message/checksum)
        """
        if not os.path.exists(model_path):
            return False, f"Model file not found: {model_path}"
        
        try:
            # Compute the SHA-256 checksum
            sha256_hash = hashlib.sha256()
            with open(model_path, "rb") as f:
                # Read in chunks to handle large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            actual_checksum = sha256_hash.hexdigest()
            
            # If no expected checksum was provided, just return the computed one
            if not expected_checksum:
                return True, actual_checksum
            
            # Otherwise, compare with the expected checksum
            if actual_checksum == expected_checksum:
                return True, "Checksum verification successful"
            else:
                return False, f"Checksum mismatch: expected {expected_checksum}, got {actual_checksum}"
            
        except IOError as e:
            return False, f"Error reading model file: {str(e)}"
    
    def get_model_path(self, model_id: str, repository_name: str) -> Optional[str]:
        """
        Get the local path for a model.
        
        Args:
            model_id: ID of the model
            repository_name: Name of the repository
            
        Returns:
            Local path, or None if not available locally
        """
        if repository_name not in self.repositories:
            return None
        
        # Get model details
        model_info = self.repositories[repository_name].get_model_details(model_id)
        if not model_info or not model_info.local_path:
            return None
        
        return model_info.local_path if os.path.exists(model_info.local_path) else None
    
    def remove_model(self, model_id: str, repository_name: str) -> bool:
        """
        Remove a model from a repository.
        
        Args:
            model_id: ID of the model to remove
            repository_name: Name of the repository
            
        Returns:
            True if successful, False otherwise
        """
        if repository_name not in self.repositories:
            return False
        
        # Special handling for local repository
        if repository_name == "local" and isinstance(self.repositories[repository_name], LocalFileRepository):
            return self.repositories[repository_name].remove_model(model_id)
        
        # For API repositories, we just remove the local copy if it exists
        model_info = self.repositories[repository_name].get_model_details(model_id)
        if not model_info or not model_info.local_path:
            return False
        
        # Remove the file
        try:
            os.remove(model_info.local_path)
            return True
        except IOError as e:
            logger.error(f"Failed to remove model file: {e}")
            return False
    
    def refresh_repositories(self):
        """Refresh all repositories."""
        for repository in self.repositories.values():
            # This will trigger a refresh by calling get_available_models
            repository.get_available_models()