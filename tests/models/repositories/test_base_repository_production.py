"""Production tests for base model repository functionality.

This test module validates the base repository implementation for AI model
management, including:
- Cache management and expiration
- Rate limiting for API calls
- Request handling with retries
- Model download and verification
- Checksum validation
- Error handling and recovery

All tests validate real repository functionality for model management.
"""

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.models.repositories.base import (
    APIRepositoryBase,
    CacheManager,
    RateLimitConfig,
    RateLimiter,
)
from intellicrack.models.repositories.interface import ModelInfo


class TestCacheManager:
    """Test cache management functionality."""

    @pytest.fixture
    def cache_manager(self, tmp_path: Path) -> CacheManager:
        """Create a cache manager with temporary directory."""
        cache_dir = str(tmp_path / "cache")
        return CacheManager(cache_dir=cache_dir, ttl_seconds=60, max_size_mb=10)

    def test_cache_manager_initialization(self, cache_manager: CacheManager) -> None:
        """Cache manager initializes correctly."""
        assert cache_manager is not None
        assert os.path.exists(cache_manager.cache_dir)
        assert cache_manager.ttl_seconds == 60
        assert cache_manager.max_size_mb == 10

    def test_cache_item_storage(self, cache_manager: CacheManager) -> None:
        """Store and retrieve cached item."""
        test_data = {"model_id": "test-model", "size": 1024, "version": "1.0"}

        success = cache_manager.cache_item("test_key", test_data)

        assert success is True

        retrieved = cache_manager.get_cached_item("test_key")

        assert retrieved == test_data

    def test_cache_item_expiration(self, cache_manager: CacheManager) -> None:
        """Cached items expire after TTL."""
        cache_manager_short_ttl = CacheManager(
            cache_dir=cache_manager.cache_dir, ttl_seconds=1, max_size_mb=10
        )

        test_data = {"expires": "soon"}
        cache_manager_short_ttl.cache_item("expiring_key", test_data)

        retrieved_immediately = cache_manager_short_ttl.get_cached_item("expiring_key")
        assert retrieved_immediately == test_data

        time.sleep(1.5)

        retrieved_after_expiry = cache_manager_short_ttl.get_cached_item(
            "expiring_key"
        )
        assert retrieved_after_expiry is None

    def test_cache_custom_ttl(self, cache_manager: CacheManager) -> None:
        """Store item with custom TTL."""
        test_data = {"custom_ttl": True}

        cache_manager.cache_item("custom_ttl_key", test_data, ttl=120)

        assert cache_manager.get_cached_item("custom_ttl_key") == test_data

    def test_cache_nonexistent_key(self, cache_manager: CacheManager) -> None:
        """Return None for nonexistent cache key."""
        result = cache_manager.get_cached_item("nonexistent_key")

        assert result is None

    def test_cache_size_management(self, tmp_path: Path) -> None:
        """Cache removes old entries when size limit reached."""
        cache_dir = str(tmp_path / "size_test")
        small_cache = CacheManager(cache_dir=cache_dir, ttl_seconds=3600, max_size_mb=1)

        large_data = {"data": "x" * 500000}

        for i in range(10):
            small_cache.cache_item(f"key_{i}", large_data)

        current_size = small_cache._check_cache_size()

        assert current_size <= small_cache.max_size_mb

    def test_cache_clear(self, cache_manager: CacheManager) -> None:
        """Clear all cache entries."""
        cache_manager.cache_item("key1", {"data": "test1"})
        cache_manager.cache_item("key2", {"data": "test2"})
        cache_manager.cache_item("key3", {"data": "test3"})

        cache_manager.clear_cache()

        assert cache_manager.get_cached_item("key1") is None
        assert cache_manager.get_cached_item("key2") is None
        assert cache_manager.get_cached_item("key3") is None

    def test_cache_persistence(self, tmp_path: Path) -> None:
        """Cache persists across manager instances."""
        cache_dir = str(tmp_path / "persistent")

        manager1 = CacheManager(cache_dir=cache_dir)
        manager1.cache_item("persist_key", {"value": "persistent"})

        manager2 = CacheManager(cache_dir=cache_dir)
        retrieved = manager2.get_cached_item("persist_key")

        assert retrieved == {"value": "persistent"}

    def test_cache_corrupted_file_handling(self, cache_manager: CacheManager) -> None:
        """Handle corrupted cache files gracefully."""
        cache_manager.cache_item("corrupt_key", {"data": "original"})

        cache_file = cache_manager._get_cache_file_path("corrupt_key")
        with open(cache_file, "w") as f:
            f.write("CORRUPTED JSON{{{")

        result = cache_manager.get_cached_item("corrupt_key")

        assert result is None

    def test_cache_index_recovery(self, tmp_path: Path) -> None:
        """Recover from corrupted cache index."""
        cache_dir = str(tmp_path / "index_test")
        manager = CacheManager(cache_dir=cache_dir)

        index_file = os.path.join(cache_dir, "index.json")
        with open(index_file, "w") as f:
            f.write("INVALID JSON")

        manager2 = CacheManager(cache_dir=cache_dir)

        assert manager2.cache_index == {}


class TestRateLimiter:
    """Test rate limiting functionality."""

    @pytest.fixture
    def rate_limiter(self) -> RateLimiter:
        """Create a rate limiter with test configuration."""
        config = RateLimitConfig(requests_per_minute=10, requests_per_day=100)
        return RateLimiter(config)

    def test_rate_limiter_initialization(self, rate_limiter: RateLimiter) -> None:
        """Rate limiter initializes with configuration."""
        assert rate_limiter is not None
        assert rate_limiter.config.requests_per_minute == 10
        assert rate_limiter.config.requests_per_day == 100

    def test_rate_limiter_allows_initial_requests(
        self, rate_limiter: RateLimiter
    ) -> None:
        """Initial requests are allowed."""
        allowed, message = rate_limiter.check_limit("test_resource")

        assert allowed is True
        assert message == ""

    def test_rate_limiter_records_requests(self, rate_limiter: RateLimiter) -> None:
        """Rate limiter records requests correctly."""
        resource = "api/models"

        for _ in range(5):
            rate_limiter.record_request(resource)

        assert resource in rate_limiter.minute_counters
        assert rate_limiter.minute_counters[resource][0] == 5

    def test_rate_limiter_minute_limit(self, rate_limiter: RateLimiter) -> None:
        """Enforce per-minute rate limit."""
        resource = "api/models"

        for _ in range(10):
            rate_limiter.record_request(resource)

        allowed, message = rate_limiter.check_limit(resource)

        assert allowed is False
        assert "Rate limit exceeded" in message
        assert "seconds" in message

    def test_rate_limiter_day_limit(self) -> None:
        """Enforce daily rate limit."""
        config = RateLimitConfig(requests_per_minute=1000, requests_per_day=10)
        limiter = RateLimiter(config)

        resource = "api/download"

        for _ in range(10):
            limiter.record_request(resource)

        allowed, message = limiter.check_limit(resource)

        assert allowed is False
        assert "Daily rate limit exceeded" in message

    def test_rate_limiter_minute_reset(self) -> None:
        """Minute counter resets after 60 seconds."""
        config = RateLimitConfig(requests_per_minute=2, requests_per_day=100)
        limiter = RateLimiter(config)

        resource = "test_reset"

        limiter.record_request(resource)
        limiter.record_request(resource)

        allowed_before, _ = limiter.check_limit(resource)
        assert allowed_before is False

        limiter.minute_counters[resource] = (0, time.time() - 61)

        allowed_after, _ = limiter.check_limit(resource)
        assert allowed_after is True

    def test_rate_limiter_multiple_resources(self, rate_limiter: RateLimiter) -> None:
        """Rate limits are independent per resource."""
        for _ in range(10):
            rate_limiter.record_request("resource_a")

        allowed_a, _ = rate_limiter.check_limit("resource_a")
        allowed_b, _ = rate_limiter.check_limit("resource_b")

        assert allowed_a is False
        assert allowed_b is True


class MockAPIRepository(APIRepositoryBase):
    """Mock API repository for testing."""

    def __init__(self, **kwargs: Any) -> None:
        """Initialize mock repository."""
        super().__init__(
            repository_name="mock_repo",
            api_endpoint="https://api.example.com",
            **kwargs,
        )

    def get_available_models(self) -> list[ModelInfo]:
        """Return mock model list."""
        return [
            ModelInfo(
                model_id="test-model-1",
                name="Test Model 1",
                version="1.0",
                size=1024,
                download_url="https://example.com/model1.bin",
            )
        ]

    def get_model_details(self, model_id: str) -> ModelInfo | None:
        """Return mock model details."""
        if model_id == "test-model-1":
            return ModelInfo(
                model_id="test-model-1",
                name="Test Model 1",
                version="1.0",
                size=1024,
                download_url="https://example.com/model1.bin",
                checksum="abc123",
            )
        return None

    def authenticate(self) -> tuple[bool, str]:
        """Mock authentication."""
        return True, "Authenticated"


class TestAPIRepositoryBase:
    """Test base API repository functionality."""

    @pytest.fixture
    def mock_repo(self, tmp_path: Path) -> MockAPIRepository:
        """Create mock repository instance."""
        return MockAPIRepository(download_dir=str(tmp_path / "downloads"))

    def test_repository_initialization(self, mock_repo: MockAPIRepository) -> None:
        """Repository initializes with correct parameters."""
        assert mock_repo.repository_name == "mock_repo"
        assert mock_repo.api_endpoint == "https://api.example.com"
        assert mock_repo.timeout == 60
        assert os.path.exists(mock_repo.download_dir)

    def test_repository_with_proxy(self, tmp_path: Path) -> None:
        """Repository configures proxy correctly."""
        repo = MockAPIRepository(
            proxy="http://proxy.example.com:8080", download_dir=str(tmp_path)
        )

        assert repo.proxy == "http://proxy.example.com:8080"
        assert repo.session.proxies["http"] == "http://proxy.example.com:8080"
        assert repo.session.proxies["https"] == "http://proxy.example.com:8080"

    def test_repository_custom_timeout(self, tmp_path: Path) -> None:
        """Repository uses custom timeout."""
        repo = MockAPIRepository(timeout=120, download_dir=str(tmp_path))

        assert repo.timeout == 120

    def test_repository_rate_limiter_configured(
        self, mock_repo: MockAPIRepository
    ) -> None:
        """Repository has configured rate limiter."""
        assert mock_repo.rate_limiter is not None
        assert isinstance(mock_repo.rate_limiter, RateLimiter)

    def test_repository_cache_manager_configured(
        self, mock_repo: MockAPIRepository
    ) -> None:
        """Repository has configured cache manager."""
        assert mock_repo.cache_manager is not None
        assert isinstance(mock_repo.cache_manager, CacheManager)

    @patch("intellicrack.handlers.requests_handler.requests.Session.request")
    def test_make_request_success(
        self, mock_request: MagicMock, mock_repo: MockAPIRepository
    ) -> None:
        """Make successful API request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success"}
        mock_request.return_value = mock_response

        success, data, error = mock_repo._make_request("test/endpoint")

        assert success is True
        assert data == {"status": "success"}
        assert error == ""

    @patch("intellicrack.handlers.requests_handler.requests.Session.request")
    def test_make_request_caching(
        self, mock_request: MagicMock, mock_repo: MockAPIRepository
    ) -> None:
        """Subsequent GET requests use cache."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"cached": "data"}
        mock_request.return_value = mock_response

        success1, data1, _ = mock_repo._make_request("test/cached")

        assert success1 is True
        assert mock_request.call_count == 1

        success2, data2, _ = mock_repo._make_request("test/cached")

        assert success2 is True
        assert data1 == data2
        assert mock_request.call_count == 1

    @patch("intellicrack.handlers.requests_handler.requests.Session.request")
    def test_make_request_error_handling(
        self, mock_request: MagicMock, mock_repo: MockAPIRepository
    ) -> None:
        """Handle API errors gracefully."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_request.return_value = mock_response

        success, data, error = mock_repo._make_request("nonexistent/endpoint")

        assert success is False
        assert data is None
        assert "404" in error

    @patch("intellicrack.handlers.requests_handler.requests.Session.request")
    def test_make_request_rate_limiting(
        self, mock_request: MagicMock, tmp_path: Path
    ) -> None:
        """Rate limiting prevents excessive requests."""
        rate_config = RateLimitConfig(requests_per_minute=1, requests_per_day=100)
        repo = MockAPIRepository(
            rate_limit_config=rate_config, download_dir=str(tmp_path)
        )

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_request.return_value = mock_response

        success1, _, _ = repo._make_request("test", use_cache=False)
        assert success1 is True

        repo.rate_limiter.record_request(
            f"{repo.api_endpoint}/test"
        )

        success2, _, error2 = repo._make_request("test", use_cache=False)

        assert success2 is False
        assert "Rate limit" in error2

    def test_verify_checksum_valid(self, tmp_path: Path) -> None:
        """Verify valid file checksum."""
        test_file = tmp_path / "test.bin"
        test_data = b"test data for checksum verification"
        test_file.write_bytes(test_data)

        expected_checksum = hashlib.sha256(test_data).hexdigest()

        repo = MockAPIRepository(download_dir=str(tmp_path))
        result = repo._verify_checksum(str(test_file), expected_checksum)

        assert result is True

    def test_verify_checksum_invalid(self, tmp_path: Path) -> None:
        """Detect invalid file checksum."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"test data")

        repo = MockAPIRepository(download_dir=str(tmp_path))
        result = repo._verify_checksum(str(test_file), "wrong_checksum")

        assert result is False

    def test_verify_checksum_nonexistent_file(self, tmp_path: Path) -> None:
        """Handle nonexistent file in checksum verification."""
        repo = MockAPIRepository(download_dir=str(tmp_path))
        result = repo._verify_checksum("/nonexistent/file.bin", "checksum")

        assert result is False


class TestModelDownload:
    """Test model download functionality."""

    @pytest.fixture
    def download_repo(self, tmp_path: Path) -> MockAPIRepository:
        """Create repository for download tests."""
        return MockAPIRepository(download_dir=str(tmp_path / "downloads"))

    @patch("intellicrack.handlers.requests_handler.requests.Session.get")
    def test_download_model_success(
        self, mock_get: MagicMock, download_repo: MockAPIRepository, tmp_path: Path
    ) -> None:
        """Download model successfully."""
        test_data = b"model binary data" * 1000

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-length": str(len(test_data))}
        mock_response.iter_content = lambda chunk_size: [
            test_data[i : i + chunk_size]
            for i in range(0, len(test_data), chunk_size)
        ]
        mock_response.raise_for_status = Mock()
        mock_get.return_value.__enter__ = Mock(return_value=mock_response)
        mock_get.return_value.__exit__ = Mock(return_value=False)

        destination = str(tmp_path / "model.bin")

        success, message = download_repo.download_model(
            "test-model-1", destination, None
        )

        assert success is True
        assert "complete" in message.lower()
        assert os.path.exists(destination)

    @patch("intellicrack.handlers.requests_handler.requests.Session.get")
    def test_download_model_with_progress(
        self, mock_get: MagicMock, download_repo: MockAPIRepository, tmp_path: Path
    ) -> None:
        """Download model with progress callback."""
        test_data = b"x" * 10000

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-length": str(len(test_data))}
        mock_response.iter_content = lambda chunk_size: [
            test_data[i : i + chunk_size]
            for i in range(0, len(test_data), chunk_size)
        ]
        mock_response.raise_for_status = Mock()
        mock_get.return_value.__enter__ = Mock(return_value=mock_response)
        mock_get.return_value.__exit__ = Mock(return_value=False)

        progress_updates: list[tuple[int, int]] = []

        class MockProgressCallback:
            def on_progress(self, current: int, total: int) -> None:
                progress_updates.append((current, total))

            def on_complete(self, success: bool, message: str) -> None:
                pass

        destination = str(tmp_path / "model_progress.bin")

        success, _ = download_repo.download_model(
            "test-model-1", destination, MockProgressCallback()
        )

        assert success is True
        assert len(progress_updates) > 0

    def test_download_model_nonexistent(
        self, download_repo: MockAPIRepository, tmp_path: Path
    ) -> None:
        """Handle download of nonexistent model."""
        destination = str(tmp_path / "nonexistent.bin")

        success, message = download_repo.download_model(
            "nonexistent-model", destination, None
        )

        assert success is False
        assert "not found" in message.lower()

    def test_download_model_no_url(self, tmp_path: Path) -> None:
        """Handle model without download URL."""

        class NoURLRepo(MockAPIRepository):
            def get_model_details(self, model_id: str) -> ModelInfo | None:
                return ModelInfo(
                    model_id=model_id,
                    name="No URL Model",
                    version="1.0",
                    size=1024,
                    download_url=None,
                )

        repo = NoURLRepo(download_dir=str(tmp_path))
        destination = str(tmp_path / "no_url.bin")

        success, message = repo.download_model("test-model", destination, None)

        assert success is False
        assert "no download url" in message.lower()


class TestRepositoryIntegration:
    """Integration tests for complete repository workflows."""

    @pytest.fixture
    def integrated_repo(self, tmp_path: Path) -> MockAPIRepository:
        """Create repository with all components configured."""
        rate_config = RateLimitConfig(requests_per_minute=60, requests_per_day=1000)
        cache_config = {"ttl": 300, "max_size_mb": 50}

        return MockAPIRepository(
            api_key="test_api_key",
            timeout=30,
            rate_limit_config=rate_config,
            cache_config=cache_config,
            download_dir=str(tmp_path / "integrated"),
        )

    def test_complete_model_workflow(
        self, integrated_repo: MockAPIRepository
    ) -> None:
        """Test complete workflow: authenticate, list, get details."""
        auth_success, auth_message = integrated_repo.authenticate()

        assert auth_success is True
        assert auth_message == "Authenticated"

        models = integrated_repo.get_available_models()

        assert len(models) > 0
        assert models[0].model_id == "test-model-1"

        details = integrated_repo.get_model_details("test-model-1")

        assert details is not None
        assert details.model_id == "test-model-1"
        assert details.checksum == "abc123"

    @patch("intellicrack.handlers.requests_handler.requests.Session.request")
    def test_api_request_with_authentication(
        self, mock_request: MagicMock, integrated_repo: MockAPIRepository
    ) -> None:
        """API requests include authentication header."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_request.return_value = mock_response

        integrated_repo._make_request("authenticated/endpoint", use_cache=False)

        call_args = mock_request.call_args
        headers = call_args.kwargs["headers"]

        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer test_api_key"
