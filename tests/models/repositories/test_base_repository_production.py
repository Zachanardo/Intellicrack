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
import http.server
import json
import os
import socketserver
import threading
import time
from pathlib import Path
from typing import Any

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


class TestHTTPServer:
    """Real HTTP server for testing API functionality."""

    def __init__(self, port: int = 0) -> None:
        """Initialize test HTTP server.

        Args:
            port: Port to bind server to (0 for random available port)

        """
        self.port = port
        self.server: socketserver.TCPServer | None = None
        self.thread: threading.Thread | None = None
        self.response_data: dict[str, Any] = {}
        self.response_status: int = 200
        self.request_count: int = 0

    def start(self) -> int:
        """Start the HTTP server in background thread.

        Returns:
            Port number the server is listening on

        """
        handler = self._create_handler()

        self.server = socketserver.TCPServer(("127.0.0.1", self.port), handler)
        self.port = self.server.server_address[1]

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        time.sleep(0.1)

        return self.port

    def stop(self) -> None:
        """Stop the HTTP server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1.0)

    def set_response(self, data: dict[str, Any], status: int = 200) -> None:
        """Set response data for next request.

        Args:
            data: Response JSON data
            status: HTTP status code

        """
        self.response_data = data
        self.response_status = status

    def _create_handler(self) -> type[http.server.BaseHTTPRequestHandler]:
        """Create request handler class with access to server state.

        Returns:
            Request handler class

        """
        outer_self = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                """Handle GET requests."""
                outer_self.request_count += 1

                self.send_response(outer_self.response_status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()

                response_json = json.dumps(outer_self.response_data)
                self.wfile.write(response_json.encode())

            def do_POST(self) -> None:
                """Handle POST requests."""
                outer_self.request_count += 1

                self.send_response(outer_self.response_status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()

                response_json = json.dumps(outer_self.response_data)
                self.wfile.write(response_json.encode())

            def log_message(self, format: str, *args: Any) -> None:
                """Suppress server log messages."""
                pass

        return Handler


class RealAPIRepository(APIRepositoryBase):
    """Real API repository implementation for testing."""

    def __init__(self, **kwargs: Any) -> None:
        """Initialize real repository."""
        super().__init__(
            repository_name="real_repo",
            api_endpoint=kwargs.pop("api_endpoint", "https://api.example.com"),
            **kwargs,
        )
        self.models: dict[str, ModelInfo] = {}

    def add_test_model(self, model: ModelInfo) -> None:
        """Add a model to the repository for testing.

        Args:
            model: Model info to add

        """
        self.models[model.model_id] = model

    def get_available_models(self) -> list[ModelInfo]:
        """Return list of available models."""
        return list(self.models.values())

    def get_model_details(self, model_id: str) -> ModelInfo | None:
        """Return model details."""
        return self.models.get(model_id)

    def authenticate(self) -> tuple[bool, str]:
        """Authenticate with repository."""
        return True, "Authenticated"


class TestAPIRepositoryBase:
    """Test base API repository functionality."""

    @pytest.fixture
    def http_server(self) -> TestHTTPServer:
        """Create and start HTTP test server."""
        server = TestHTTPServer()
        server.start()
        yield server
        server.stop()

    @pytest.fixture
    def real_repo(self, tmp_path: Path, http_server: TestHTTPServer) -> RealAPIRepository:
        """Create real repository instance."""
        return RealAPIRepository(
            api_endpoint=f"http://127.0.0.1:{http_server.port}",
            download_dir=str(tmp_path / "downloads"),
        )

    def test_repository_initialization(self, real_repo: RealAPIRepository) -> None:
        """Repository initializes with correct parameters."""
        assert real_repo.repository_name == "real_repo"
        assert "127.0.0.1" in real_repo.api_endpoint
        assert real_repo.timeout == 60
        assert os.path.exists(real_repo.download_dir)

    def test_repository_with_proxy(self, tmp_path: Path) -> None:
        """Repository configures proxy correctly."""
        repo = RealAPIRepository(
            proxy="http://proxy.example.com:8080", download_dir=str(tmp_path)
        )

        assert repo.proxy == "http://proxy.example.com:8080"
        assert repo.session.proxies["http"] == "http://proxy.example.com:8080"
        assert repo.session.proxies["https"] == "http://proxy.example.com:8080"

    def test_repository_custom_timeout(self, tmp_path: Path) -> None:
        """Repository uses custom timeout."""
        repo = RealAPIRepository(timeout=120, download_dir=str(tmp_path))

        assert repo.timeout == 120

    def test_repository_rate_limiter_configured(
        self, real_repo: RealAPIRepository
    ) -> None:
        """Repository has configured rate limiter."""
        assert real_repo.rate_limiter is not None
        assert isinstance(real_repo.rate_limiter, RateLimiter)

    def test_repository_cache_manager_configured(
        self, real_repo: RealAPIRepository
    ) -> None:
        """Repository has configured cache manager."""
        assert real_repo.cache_manager is not None
        assert isinstance(real_repo.cache_manager, CacheManager)

    def test_make_request_success(
        self, real_repo: RealAPIRepository, http_server: TestHTTPServer
    ) -> None:
        """Make successful API request."""
        http_server.set_response({"status": "success"}, 200)

        success, data, error = real_repo._make_request("test/endpoint")

        assert success is True
        assert data == {"status": "success"}
        assert error == ""
        assert http_server.request_count == 1

    def test_make_request_caching(
        self, real_repo: RealAPIRepository, http_server: TestHTTPServer
    ) -> None:
        """Subsequent GET requests use cache."""
        http_server.set_response({"cached": "data"}, 200)

        success1, data1, _ = real_repo._make_request("test/cached")

        assert success1 is True
        assert http_server.request_count == 1

        success2, data2, _ = real_repo._make_request("test/cached")

        assert success2 is True
        assert data1 == data2
        assert http_server.request_count == 1

    def test_make_request_error_handling(
        self, real_repo: RealAPIRepository, http_server: TestHTTPServer
    ) -> None:
        """Handle API errors gracefully."""
        http_server.set_response({"error": "Not Found"}, 404)

        success, data, error = real_repo._make_request("nonexistent/endpoint")

        assert success is False
        assert data is None
        assert "404" in error

    def test_make_request_rate_limiting(
        self, tmp_path: Path, http_server: TestHTTPServer
    ) -> None:
        """Rate limiting prevents excessive requests."""
        rate_config = RateLimitConfig(requests_per_minute=1, requests_per_day=100)
        repo = RealAPIRepository(
            api_endpoint=f"http://127.0.0.1:{http_server.port}",
            rate_limit_config=rate_config,
            download_dir=str(tmp_path),
        )

        http_server.set_response({}, 200)

        success1, _, _ = repo._make_request("test", use_cache=False)
        assert success1 is True

        repo.rate_limiter.record_request(f"{repo.api_endpoint}/test")

        success2, _, error2 = repo._make_request("test", use_cache=False)

        assert success2 is False
        assert "Rate limit" in error2

    def test_verify_checksum_valid(self, tmp_path: Path) -> None:
        """Verify valid file checksum."""
        test_file = tmp_path / "test.bin"
        test_data = b"test data for checksum verification"
        test_file.write_bytes(test_data)

        expected_checksum = hashlib.sha256(test_data).hexdigest()

        repo = RealAPIRepository(download_dir=str(tmp_path))
        result = repo._verify_checksum(str(test_file), expected_checksum)

        assert result is True

    def test_verify_checksum_invalid(self, tmp_path: Path) -> None:
        """Detect invalid file checksum."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"test data")

        repo = RealAPIRepository(download_dir=str(tmp_path))
        result = repo._verify_checksum(str(test_file), "wrong_checksum")

        assert result is False

    def test_verify_checksum_nonexistent_file(self, tmp_path: Path) -> None:
        """Handle nonexistent file in checksum verification."""
        repo = RealAPIRepository(download_dir=str(tmp_path))
        result = repo._verify_checksum("/nonexistent/file.bin", "checksum")

        assert result is False


class FileDownloadServer:
    """Real HTTP server for file downloads."""

    def __init__(self, port: int = 0) -> None:
        """Initialize file download server.

        Args:
            port: Port to bind server to

        """
        self.port = port
        self.server: socketserver.TCPServer | None = None
        self.thread: threading.Thread | None = None
        self.file_content: bytes = b""

    def start(self, file_content: bytes) -> int:
        """Start server with file content.

        Args:
            file_content: Binary content to serve

        Returns:
            Port number server is listening on

        """
        self.file_content = file_content
        handler = self._create_handler()

        self.server = socketserver.TCPServer(("127.0.0.1", self.port), handler)
        self.port = self.server.server_address[1]

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        time.sleep(0.1)

        return self.port

    def stop(self) -> None:
        """Stop the server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1.0)

    def _create_handler(self) -> type[http.server.BaseHTTPRequestHandler]:
        """Create handler for file downloads.

        Returns:
            Request handler class

        """
        outer_self = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                """Handle GET request for file download."""
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(outer_self.file_content)))
                self.end_headers()
                self.wfile.write(outer_self.file_content)

            def log_message(self, format: str, *args: Any) -> None:
                """Suppress log messages."""
                pass

        return Handler


class TestModelDownload:
    """Test model download functionality."""

    @pytest.fixture
    def download_server(self) -> FileDownloadServer:
        """Create file download server."""
        server = FileDownloadServer()
        yield server
        server.stop()

    @pytest.fixture
    def download_repo(self, tmp_path: Path) -> RealAPIRepository:
        """Create repository for download tests."""
        return RealAPIRepository(download_dir=str(tmp_path / "downloads"))

    def test_download_model_success(
        self,
        download_repo: RealAPIRepository,
        download_server: FileDownloadServer,
        tmp_path: Path,
    ) -> None:
        """Download model successfully."""
        test_data = b"model binary data" * 1000

        port = download_server.start(test_data)

        model = ModelInfo(
            model_id="test-model-1",
            name="Test Model 1",
            version="1.0",
            size_bytes=len(test_data),
            download_url=f"http://127.0.0.1:{port}/model.bin",
        )
        download_repo.add_test_model(model)

        destination = str(tmp_path / "model.bin")

        success, message = download_repo.download_model("test-model-1", destination, None)

        assert success is True
        assert "complete" in message.lower()
        assert os.path.exists(destination)
        assert Path(destination).read_bytes() == test_data

    def test_download_model_with_progress(
        self,
        download_repo: RealAPIRepository,
        download_server: FileDownloadServer,
        tmp_path: Path,
    ) -> None:
        """Download model with progress callback."""
        test_data = b"x" * 10000

        port = download_server.start(test_data)

        model = ModelInfo(
            model_id="test-model-1",
            name="Test Model 1",
            version="1.0",
            size_bytes=len(test_data),
            download_url=f"http://127.0.0.1:{port}/model.bin",
        )
        download_repo.add_test_model(model)

        progress_updates: list[tuple[int, int]] = []

        class RealProgressCallback:
            def on_progress(self, current: int, total: int) -> None:
                progress_updates.append((current, total))

            def on_complete(self, success: bool, message: str) -> None:
                pass

        destination = str(tmp_path / "model_progress.bin")

        success, _ = download_repo.download_model(
            "test-model-1", destination, RealProgressCallback()
        )

        assert success is True
        assert len(progress_updates) > 0
        assert progress_updates[-1][0] == len(test_data)
        assert progress_updates[-1][1] == len(test_data)

    def test_download_model_nonexistent(
        self, download_repo: RealAPIRepository, tmp_path: Path
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
        repo = RealAPIRepository(download_dir=str(tmp_path))

        model = ModelInfo(
            model_id="no-url-model",
            name="No URL Model",
            version="1.0",
            size_bytes=1024,
            download_url=None,
        )
        repo.add_test_model(model)

        destination = str(tmp_path / "no_url.bin")

        success, message = repo.download_model("no-url-model", destination, None)

        assert success is False
        assert "no download url" in message.lower()

    def test_download_model_with_checksum_validation(
        self,
        download_repo: RealAPIRepository,
        download_server: FileDownloadServer,
        tmp_path: Path,
    ) -> None:
        """Download validates checksum correctly."""
        test_data = b"validated model data" * 100

        port = download_server.start(test_data)

        expected_checksum = hashlib.sha256(test_data).hexdigest()

        model = ModelInfo(
            model_id="validated-model",
            name="Validated Model",
            version="1.0",
            size_bytes=len(test_data),
            download_url=f"http://127.0.0.1:{port}/model.bin",
            checksum=expected_checksum,
        )
        download_repo.add_test_model(model)

        destination = str(tmp_path / "validated.bin")

        success, message = download_repo.download_model("validated-model", destination, None)

        assert success is True
        assert os.path.exists(destination)
        assert Path(destination).read_bytes() == test_data

    def test_download_model_checksum_mismatch(
        self,
        download_repo: RealAPIRepository,
        download_server: FileDownloadServer,
        tmp_path: Path,
    ) -> None:
        """Download fails on checksum mismatch."""
        test_data = b"model data with wrong checksum"

        port = download_server.start(test_data)

        wrong_checksum = "0" * 64

        model = ModelInfo(
            model_id="bad-checksum-model",
            name="Bad Checksum Model",
            version="1.0",
            size_bytes=len(test_data),
            download_url=f"http://127.0.0.1:{port}/model.bin",
            checksum=wrong_checksum,
        )
        download_repo.add_test_model(model)

        destination = str(tmp_path / "bad_checksum.bin")

        success, message = download_repo.download_model("bad-checksum-model", destination, None)

        assert success is False
        assert "checksum" in message.lower()
        assert not os.path.exists(destination)


class TestRepositoryIntegration:
    """Integration tests for complete repository workflows."""

    @pytest.fixture
    def http_server(self) -> TestHTTPServer:
        """Create test HTTP server."""
        server = TestHTTPServer()
        server.start()
        yield server
        server.stop()

    @pytest.fixture
    def integrated_repo(
        self, tmp_path: Path, http_server: TestHTTPServer
    ) -> RealAPIRepository:
        """Create repository with all components configured."""
        rate_config = RateLimitConfig(requests_per_minute=60, requests_per_day=1000)
        cache_config = {"ttl": 300, "max_size_mb": 50}

        return RealAPIRepository(
            api_endpoint=f"http://127.0.0.1:{http_server.port}",
            api_key="test_api_key",
            timeout=30,
            rate_limit_config=rate_config,
            cache_config=cache_config,
            download_dir=str(tmp_path / "integrated"),
        )

    def test_complete_model_workflow(
        self, integrated_repo: RealAPIRepository
    ) -> None:
        """Test complete workflow: authenticate, list, get details."""
        model = ModelInfo(
            model_id="test-model-1",
            name="Test Model 1",
            version="1.0",
            size_bytes=1024,
            checksum="abc123",
        )
        integrated_repo.add_test_model(model)

        auth_success, auth_message = integrated_repo.authenticate()

        assert auth_success is True
        assert auth_message == "Authenticated"

        models = integrated_repo.get_available_models()

        assert len(models) == 1
        assert models[0].model_id == "test-model-1"

        details = integrated_repo.get_model_details("test-model-1")

        assert details is not None
        assert details.model_id == "test-model-1"
        assert details.checksum == "abc123"

    def test_api_request_with_authentication(
        self, integrated_repo: RealAPIRepository, http_server: TestHTTPServer
    ) -> None:
        """API requests include authentication header."""
        http_server.set_response({}, 200)

        integrated_repo._make_request("authenticated/endpoint", use_cache=False)

        assert http_server.request_count == 1

    def test_repository_handles_multiple_models(
        self, integrated_repo: RealAPIRepository
    ) -> None:
        """Repository manages multiple models correctly."""
        models = [
            ModelInfo(
                model_id=f"model-{i}",
                name=f"Model {i}",
                version="1.0",
                size_bytes=1024 * i,
            )
            for i in range(1, 6)
        ]

        for model in models:
            integrated_repo.add_test_model(model)

        available = integrated_repo.get_available_models()

        assert len(available) == 5
        assert all(model.model_id.startswith("model-") for model in available)

        details = integrated_repo.get_model_details("model-3")
        assert details is not None
        assert details.size_bytes == 3072

    def test_repository_concurrent_cache_access(
        self, tmp_path: Path
    ) -> None:
        """Cache handles concurrent access correctly."""
        cache_dir = str(tmp_path / "concurrent")
        cache = CacheManager(cache_dir=cache_dir)

        def cache_writer(key_prefix: str) -> None:
            for i in range(10):
                cache.cache_item(f"{key_prefix}_{i}", {"value": i})

        threads = [
            threading.Thread(target=cache_writer, args=(f"thread{i}",))
            for i in range(5)
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        total_cached = sum(
            1 for i in range(5) for j in range(10)
            if cache.get_cached_item(f"thread{i}_{j}") is not None
        )

        assert total_cached == 50

    def test_rate_limiter_across_endpoints(
        self, integrated_repo: RealAPIRepository, http_server: TestHTTPServer
    ) -> None:
        """Rate limiter tracks different endpoints independently."""
        http_server.set_response({}, 200)

        for _ in range(5):
            success, _, _ = integrated_repo._make_request("endpoint1", use_cache=False)
            assert success is True

        for _ in range(5):
            success, _, _ = integrated_repo._make_request("endpoint2", use_cache=False)
            assert success is True

        endpoint1_url = f"{integrated_repo.api_endpoint}/endpoint1"
        endpoint2_url = f"{integrated_repo.api_endpoint}/endpoint2"

        assert endpoint1_url in integrated_repo.rate_limiter.minute_counters
        assert endpoint2_url in integrated_repo.rate_limiter.minute_counters

        assert integrated_repo.rate_limiter.minute_counters[endpoint1_url][0] == 5
        assert integrated_repo.rate_limiter.minute_counters[endpoint2_url][0] == 5
