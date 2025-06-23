"""
Base Implementation for API Model Repositories

This module provides the base implementation for API-based model repositories,
including common functionality for rate limiting, caching, error handling,
and proxy support.
"""

import hashlib
import json
import logging
import os
import time
from abc import abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests

from .interface import DownloadProgressCallback, ModelInfo, ModelRepositoryInterface

# Set up logging
logger = logging.getLogger(__name__)

class CacheManager:
    """Manages caching of API responses and model metadata."""

    def __init__(self, cache_dir: str = os.path.join(os.path.dirname(__file__), "..", "cache"), ttl_seconds: int = 3600, max_size_mb: int = 100):
        """
        Initialize the cache manager.

        Args:
            cache_dir: Directory to store cache files
            ttl_seconds: Time-to-live for cached items in seconds
            max_size_mb: Maximum cache size in megabytes
        """
        self.cache_dir = cache_dir
        self.ttl_seconds = ttl_seconds
        self.max_size_mb = max_size_mb

        # Create cache directory if it doesn't exist
        os.makedirs(cache_dir, exist_ok=True)

        # Index file for tracking cache entries
        self.index_file = os.path.join(cache_dir, "index.json")
        self.cache_index = self._load_index()

        # Clean up expired entries on initialization
        self._cleanup_expired()

    def _load_index(self) -> Dict[str, Dict[str, Any]]:
        """Load the cache index from disk."""
        if os.path.exists(self.index_file):
            try:
                with open(self.index_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load cache index: {e}")

        return {}

    def _save_index(self):
        """Save the cache index to disk."""
        try:
            with open(self.index_file, 'w') as f:
                json.dump(self.cache_index, f, indent=2)
        except IOError as e:
            logger.warning(f"Failed to save cache index: {e}")

    def _get_cache_file_path(self, key: str) -> str:
        """Get the file path for a cache key."""
        # Create a hash of the key to use as filename
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{key_hash}.cache")

    def get_cached_item(self, key: str) -> Optional[Any]:
        """
        Get an item from the cache.

        Args:
            key: Cache key

        Returns:
            The cached item, or None if not found or expired
        """
        if key not in self.cache_index:
            return None

        entry = self.cache_index[key]
        expiry_time = entry.get('expiry_time', 0)

        # Check if the entry has expired
        if expiry_time < time.time():
            self._remove_entry(key)
            return None

        cache_file = self._get_cache_file_path(key)
        if not os.path.exists(cache_file):
            self._remove_entry(key)
            return None

        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
                return data
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to read cache file for {key}: {e}")
            self._remove_entry(key)
            return None

    def cache_item(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Store an item in the cache.

        Args:
            key: Cache key
            value: Value to cache (must be JSON serializable)
            ttl: Time-to-live in seconds (overrides default)

        Returns:
            True if caching was successful, False otherwise
        """
        # Check if we have room in the cache
        if self._check_cache_size() >= self.max_size_mb:
            self._manage_cache_size()

        ttl_value = ttl if ttl is not None else self.ttl_seconds
        expiry_time = time.time() + ttl_value

        cache_file = self._get_cache_file_path(key)

        try:
            with open(cache_file, 'w') as f:
                json.dump(value, f)

            self.cache_index[key] = {
                'file': cache_file,
                'expiry_time': expiry_time,
                'created_time': time.time(),
                'size': os.path.getsize(cache_file)
            }

            self._save_index()
            return True
        except (IOError, TypeError) as e:
            logger.warning(f"Failed to cache item {key}: {e}")
            return False

    def clear_cache(self):
        """Clear all cache entries."""
        for key in list(self.cache_index.keys()):
            self._remove_entry(key)

        self._save_index()

    def _remove_entry(self, key: str):
        """Remove a cache entry."""
        if key in self.cache_index:
            cache_file = self._get_cache_file_path(key)
            if os.path.exists(cache_file):
                try:
                    os.remove(cache_file)
                except IOError as e:
                    logger.warning(f"Failed to remove cache file for {key}: {e}")

            del self.cache_index[key]

    def _cleanup_expired(self):
        """Remove expired cache entries."""
        current_time = time.time()
        expired_keys = [
            key for key, entry in self.cache_index.items()
            if entry.get('expiry_time', 0) < current_time
        ]

        for key in expired_keys:
            self._remove_entry(key)

        if expired_keys:
            self._save_index()

    def _check_cache_size(self) -> float:
        """
        Check the current cache size in MB.

        Returns:
            Current size in megabytes
        """
        total_size = sum(
            entry.get('size', 0) for entry in self.cache_index.values()
        )
        return total_size / (1024 * 1024)  # Convert bytes to MB

    def _manage_cache_size(self):
        """Remove oldest entries until cache is under the maximum size."""
        if self._check_cache_size() <= self.max_size_mb:
            return

        # Sort entries by creation time (oldest first)
        sorted_entries = sorted(
            self.cache_index.items(),
            key=lambda x: x[1].get('created_time', 0)
        )

        # Remove entries until we're under the limit
        for key, _ in sorted_entries:
            self._remove_entry(key)
            if self._check_cache_size() <= self.max_size_mb * 0.9:  # 90% of max
                break

        self._save_index()


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    requests_per_minute: int = 60
    requests_per_day: int = 1000


class RateLimiter:
    """Manages API rate limiting."""

    def __init__(self, config: Optional[RateLimitConfig] = None):
        """
        Initialize the rate limiter.

        Args:
            config: Rate limit configuration
        """
        self.config = config or RateLimitConfig()
        self.minute_counters = {}  # Resource -> (count, timestamp)
        self.day_counters = {}     # Resource -> (count, timestamp)

    def check_limit(self, resource: str) -> Tuple[bool, str]:
        """
        Check if a request is allowed for the given resource.

        Args:
            resource: The resource identifier (e.g., API endpoint)

        Returns:
            Tuple of (allowed, message)
        """
        current_time = time.time()

        # Initialize counters if needed
        if resource not in self.minute_counters:
            self.minute_counters[resource] = (0, current_time)

        if resource not in self.day_counters:
            self.day_counters[resource] = (0, current_time)

        # Get current counters
        minute_count, minute_start = self.minute_counters[resource]
        day_count, day_start = self.day_counters[resource]

        # Reset minute counter if a minute has passed
        if current_time - minute_start >= 60:
            minute_count = 0
            minute_start = current_time

        # Reset day counter if a day has passed
        if current_time - day_start >= 86400:  # 24 hours in seconds
            day_count = 0
            day_start = current_time

        # Check limits
        if minute_count >= self.config.requests_per_minute:
            wait_time = 60 - (current_time - minute_start)
            return False, f"Rate limit exceeded for {resource}. Try again in {wait_time:.1f} seconds."

        if day_count >= self.config.requests_per_day:
            wait_time = 86400 - (current_time - day_start)
            hours = wait_time // 3600
            minutes = (wait_time % 3600) // 60
            return False, f"Daily rate limit exceeded for {resource}. Try again in {hours:.0f}h {minutes:.0f}m."

        return True, ""

    def record_request(self, resource: str):
        """
        Record a request to the given resource.

        Args:
            resource: The resource identifier
        """
        current_time = time.time()

        # Initialize counters if needed
        if resource not in self.minute_counters:
            self.minute_counters[resource] = (0, current_time)

        if resource not in self.day_counters:
            self.day_counters[resource] = (0, current_time)

        # Get current counters
        minute_count, minute_start = self.minute_counters[resource]
        day_count, day_start = self.day_counters[resource]

        # Reset minute counter if a minute has passed
        if current_time - minute_start >= 60:
            minute_count = 0
            minute_start = current_time

        # Reset day counter if a day has passed
        if current_time - day_start >= 86400:  # 24 hours in seconds
            day_count = 0
            day_start = current_time

        # Increment counters
        minute_count += 1
        day_count += 1

        # Update counters
        self.minute_counters[resource] = (minute_count, minute_start)
        self.day_counters[resource] = (day_count, day_start)


class APIRepositoryBase(ModelRepositoryInterface):
    """Base class for API-based model repositories."""

    def __init__(self,
                 repository_name: str,
                 api_endpoint: str,
                 api_key: str = "",
                 timeout: int = 60,
                 proxy: str = "",
                 rate_limit_config: Optional[RateLimitConfig] = None,
                 cache_config: Optional[Dict[str, Any]] = None,
                 download_dir: str = os.path.join(os.path.dirname(__file__), "..", "downloads")):
        """
        Initialize the API repository.

        Args:
            repository_name: Name of the repository
            api_endpoint: Base URL of the API
            api_key: API key for authentication
            timeout: Request timeout in seconds
            proxy: Proxy URL
            rate_limit_config: Rate limiting configuration
            cache_config: Cache configuration
            download_dir: Directory for downloaded models
        """
        self.repository_name = repository_name
        self.api_endpoint = api_endpoint.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.proxy = proxy

        # Initialize rate limiter
        self.rate_limiter = RateLimiter(rate_limit_config)

        # Initialize cache manager
        cache_params = cache_config or {}
        cache_dir = cache_params.get('cache_dir', os.path.join(os.path.dirname(__file__), "..", "cache", repository_name))
        ttl_seconds = cache_params.get('ttl', 3600)
        max_size_mb = cache_params.get('max_size_mb', 100)
        self.cache_manager = CacheManager(cache_dir, ttl_seconds, max_size_mb)

        # Create download directory
        self.download_dir = os.path.join(download_dir, repository_name)
        os.makedirs(self.download_dir, exist_ok=True)

        # Session for connection pooling
        self.session = requests.Session()

        # Set up proxy if provided
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }

    # pylint: disable=too-many-locals
    def _make_request(self,
                     endpoint: str,
                     method: str = "GET",
                     params: Optional[Dict[str, Any]] = None,
                     data: Optional[Dict[str, Any]] = None,
                     headers: Optional[Dict[str, str]] = None,
                     use_cache: bool = True,
                     cache_ttl: Optional[int] = None) -> Tuple[bool, Any, str]:
        """
        Make an API request with rate limiting, caching, and error handling.

        Args:
            endpoint: API endpoint path (will be appended to base URL)
            method: HTTP method (GET, POST, etc.)
            params: Query parameters
            data: Request body data
            headers: Request headers
            use_cache: Whether to use the cache for GET requests
            cache_ttl: Cache TTL override

        Returns:
            Tuple of (success, data, error_message)
        """
        url = f"{self.api_endpoint}/{endpoint.lstrip('/')}"
        cache_key = None

        # Only cache GET requests
        if method == "GET" and use_cache:
            # Create a cache key based on the request details
            cache_key_parts = [
                url,
                str(params) if params else "",
                str(headers) if headers else ""
            ]
            cache_key = hashlib.md5(":".join(cache_key_parts).encode()).hexdigest()

            # Check the cache
            cached_data = self.cache_manager.get_cached_item(cache_key)
            if cached_data:
                logger.debug(f"Cache hit for {url}")
                return True, cached_data, ""

        # Check rate limits
        allowed, message = self.rate_limiter.check_limit(url)
        if not allowed:
            logger.warning(f"Rate limit check failed: {message}")
            return False, None, message

        # Set default headers
        request_headers = {
            "User-Agent": "Intellicrack-ModelRepository/1.0",
            "Accept": "application/json"
        }

        # Add API key header if applicable (override in subclass if needed)
        if self.api_key and "Authorization" not in request_headers:
            request_headers["Authorization"] = f"Bearer {self.api_key}"

        # Update with custom headers
        if headers:
            request_headers.update(headers)

        try:
            # Make the request
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=data,
                headers=request_headers,
                timeout=self.timeout
            )

            # Record the request for rate limiting
            self.rate_limiter.record_request(url)

            # Handle response
            if response.status_code >= 400:
                logger.warning(f"API request failed: {response.status_code} - {response.text}")
                return False, None, f"API request failed: {response.status_code} - {response.text}"

            # Parse response data (assume JSON)
            try:
                response_data = response.json()
            except ValueError:
                # Not JSON, return raw text
                response_data = response.text

            # Cache successful GET responses
            if method == "GET" and use_cache and cache_key:
                self.cache_manager.cache_item(cache_key, response_data, cache_ttl)

            return True, response_data, ""

        except requests.RequestException as e:
            logger.error(f"Request error: {str(e)}")
            return False, None, f"Request error: {str(e)}"

    # pylint: disable=too-many-locals
    def download_model(self, model_id: str, destination_path: str,
                      progress_callback: Optional[DownloadProgressCallback] = None) -> Tuple[bool, str]:
        """
        Download a model from the repository.

        Args:
            model_id: ID of the model to download
            destination_path: Path where the model should be saved
            progress_callback: Optional callback for progress updates

        Returns:
            Tuple of (success, message)
        """
        # Get model details to get the download URL
        model_details = self.get_model_details(model_id)
        if not model_details:
            return False, f"Model {model_id} not found"

        if not model_details.download_url:
            return False, f"No download URL available for model {model_id}"

        # Create the destination directory if it doesn't exist
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)

        # Download the model
        try:
            # Make a streaming request to download the file
            with self.session.get(
                model_details.download_url,
                stream=True,
                timeout=self.timeout,
                headers={"Authorization": f"Bearer {self.api_key}"}
            ) as response:
                response.raise_for_status()

                # Get total file size if available
                total_size = int(response.headers.get('content-length', 0))

                # Create a temporary file
                temp_path = f"{destination_path}.download"

                # Download the file in chunks
                downloaded_bytes = 0
                with open(temp_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded_bytes += len(chunk)

                            # Report progress
                            if progress_callback:
                                progress_callback.on_progress(downloaded_bytes, total_size)

                # If we have a checksum, verify the download
                if model_details.checksum:
                    if not self._verify_checksum(temp_path, model_details.checksum):
                        if progress_callback:
                            progress_callback.on_complete(False, "Checksum verification failed")
                        os.remove(temp_path)
                        return False, "Checksum verification failed"

                # Move the temporary file to the final destination
                if os.path.exists(destination_path):
                    os.remove(destination_path)
                os.rename(temp_path, destination_path)

                # Update model details with local path
                model_details.local_path = destination_path

                if progress_callback:
                    progress_callback.on_complete(True, "Download complete")

                return True, "Download complete"

        except requests.RequestException as e:
            if progress_callback:
                progress_callback.on_complete(False, f"Download failed: {str(e)}")
            return False, f"Download failed: {str(e)}"
        except IOError as e:
            if progress_callback:
                progress_callback.on_complete(False, f"File I/O error: {str(e)}")
            return False, f"File I/O error: {str(e)}"

    def _verify_checksum(self, file_path: str, expected_checksum: str) -> bool:
        """
        Verify the checksum of a downloaded file.

        Args:
            file_path: Path to the file
            expected_checksum: Expected SHA256 checksum

        Returns:
            True if the checksum matches, False otherwise
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Read and update hash in chunks
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)

            actual_checksum = sha256_hash.hexdigest()
            return actual_checksum == expected_checksum
        except IOError as e:
            logger.error(f"Failed to compute checksum: {str(e)}")
            return False

    @abstractmethod
    def get_available_models(self) -> List[ModelInfo]:
        """
        Get a list of available models from the repository.

        Returns:
            A list of ModelInfo objects representing the available models.
        """
        pass

    @abstractmethod
    def get_model_details(self, model_id: str) -> Optional[ModelInfo]:
        """
        Get detailed information about a specific model.

        Args:
            model_id: The ID of the model to get details for

        Returns:
            A ModelInfo object containing the model details, or None if the model is not found.
        """
        pass

    @abstractmethod
    def authenticate(self) -> Tuple[bool, str]:
        """
        Authenticate with the repository.

        Returns:
            A tuple of (success, message) where success is a boolean indicating if the
            authentication was successful, and message is a string with details.
        """
        pass
