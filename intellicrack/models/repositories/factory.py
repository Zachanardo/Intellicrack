"""
Repository Factory Module

This module provides a factory for creating model repositories based on
their type and configuration.
"""

import logging
import os
from typing import Any, Dict, List, Optional, Type

from .base import APIRepositoryBase, RateLimitConfig
from .interface import ModelRepositoryInterface
from .local_repository import LocalFileRepository

# Set up logging
logger = logging.getLogger(__name__)

class RepositoryFactory:
    """Factory for creating model repositories."""

    # Registry of repository types
    _repository_types: Dict[str, Type[ModelRepositoryInterface]] = {}

    @classmethod
    def register_repository_type(cls, type_name: str, repository_class: Type[ModelRepositoryInterface]):
        """
        Register a repository type.

        Args:
            type_name: Name of the repository type
            repository_class: Class to instantiate for this type
        """
        cls._repository_types[type_name] = repository_class
        logger.debug(f"Registered repository type: {type_name}")

    @classmethod
    def create_repository(cls, config: Dict[str, Any]) -> Optional[ModelRepositoryInterface]:
        """
        Create a repository instance based on configuration.

        Args:
            config: Repository configuration

        Returns:
            Repository instance, or None if creation failed
        """
        repo_type = config.get("type")
        if not repo_type:
            logger.error("Repository configuration missing 'type' field")
            return None

        if repo_type not in cls._repository_types:
            logger.error(f"Unknown repository type: {repo_type}")
            return None

        try:
            # Get the repository class
            repo_class = cls._repository_types[repo_type]

            # Special handling for LocalFileRepository
            if repo_type == "local":
                models_directory = config.get("models_directory", "models")
                return LocalFileRepository(models_directory=models_directory)

            # Handle API repositories
            elif issubclass(repo_class, APIRepositoryBase):
                repository_name = config.get("name", repo_type)
                api_endpoint = config.get("endpoint", "")
                api_key = config.get("api_key", "")
                timeout = config.get("timeout", 60)
                proxy = config.get("proxy", "")

                # Create rate limit config
                rate_limit_config = config.get("rate_limit", {})
                rate_limit = RateLimitConfig(
                    requests_per_minute=rate_limit_config.get("requests_per_minute", 60),
                    requests_per_day=rate_limit_config.get("requests_per_day", 1000)
                )

                # Create cache config
                cache_config = config.get("cache", {})

                # Get download directory
                download_dir = config.get("download_directory", os.path.join(os.path.dirname(__file__), "..", "downloads"))

                return repo_class(
                    repository_name=repository_name,
                    api_endpoint=api_endpoint,
                    api_key=api_key,
                    timeout=timeout,
                    proxy=proxy,
                    rate_limit_config=rate_limit,
                    cache_config=cache_config,
                    download_dir=download_dir
                )

            # Generic case
            else:
                return repo_class(**config)

        except Exception as e:
            logger.error(f"Failed to create repository of type {repo_type}: {str(e)}")
            return None

    @classmethod
    def get_available_repository_types(cls) -> List[str]:
        """
        Get a list of available repository types.

        Returns:
            List of repository type names
        """
        return list(cls._repository_types.keys())


# Register the default repository types
RepositoryFactory.register_repository_type("local", LocalFileRepository)
