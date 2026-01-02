"""Production tests for base repository functionality.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.models.repositories.base import (
    APIRepositoryBase,
    CacheManager,
    RateLimiter,
    RateLimitConfig,
)
from intellicrack.models.repositories.interface import ModelInfo


class FakeHTTPResponse:
    """Fake HTTP response for testing."""

    def __init__(
        self,
        status_code: int = 200,
        json_data: dict[str, Any] | None = None,
        text: str = "",
        headers: dict[str, str] | None = None,
        stream_content: list[bytes] | None = None,
    ) -> None:
        self.status_code = status_code
        self._json_data = json_data or {}
        self.text = text
        self.headers = headers or {}
        self._stream_content = stream_content or []
        self._raise_for_status_called = False

    def json(self) -> dict[str, Any]:
        return self._json_data

    def raise_for_status(self) -> None:
        self._raise_for_status_called = True
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size: int = 8192) -> list[bytes]:
        return self._stream_content

    def __enter__(self) -> "FakeHTTPResponse":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        return False


class FakeSession:
    """Fake HTTP session for testing."""

    def __init__(self) -> None:
        self.proxies: dict[str, str] = {}
        self.request_log: list[dict[str, Any]] = []
        self.get_log: list[dict[str, Any]] = []
        self._request_response: FakeHTTPResponse | None = None
        self._get_response: FakeHTTPResponse | None = None
        self._request_exception: Exception | None = None

    def set_request_response(self, response: FakeHTTPResponse) -> None:
        self._request_response = response

    def set_get_response(self, response: FakeHTTPResponse) -> None:
        self._get_response = response

    def set_request_exception(self, exception: Exception) -> None:
        self._request_exception = exception

    def request(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> FakeHTTPResponse:
        self.request_log.append(
            {
                "method": method,
                "url": url,
                "params": params,
                "json": json,
                "headers": headers,
                "timeout": timeout,
            }
        )

        if self._request_exception:
            raise self._request_exception

        if self._request_response:
            return self._request_response

        return FakeHTTPResponse()

    def get(
        self,
        url: str,
        stream: bool = False,
        timeout: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> FakeHTTPResponse:
        self.get_log.append(
            {"url": url, "stream": stream, "timeout": timeout, "headers": headers}
        )

        if self._get_response:
            return self._get_response

        return FakeHTTPResponse()


class FakeRepositoryForTesting(APIRepositoryBase):
    """Fake repository implementation for testing base functionality."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fake_session = FakeSession()
        self.session = self.fake_session
        self._model_details: dict[str, ModelInfo] = {}

    def set_model_details(self, model_id: str, model_info: ModelInfo) -> None:
        self._model_details[model_id] = model_info

    def get_available_models(self) -> list[ModelInfo]:
        return list(self._model_details.values())

    def get_model_details(self, model_id: str) -> ModelInfo | None:
        return self._model_details.get(model_id)

    def authenticate(self) -> tuple[bool, str]:
        return True, "Authenticated"


class TestCacheManager:
    """Test cache management functionality."""

    def test_cache_item_stores_and_retrieves_data(self, tmp_path: Path) -> None:
        """Cache stores items and retrieves them correctly."""
        cache_dir = str(tmp_path / "cache")
        manager = CacheManager(cache_dir=cache_dir, ttl_seconds=3600)

        test_data = {"model": "test", "params": 1000}
        success = manager.cache_item("test_key", test_data)

        assert success is True
        retrieved = manager.get_cached_item("test_key")
        assert retrieved == test_data

    def test_cache_expiry_removes_old_items(self, tmp_path: Path) -> None:
        """Expired cache items are removed and return None."""
        cache_dir = str(tmp_path / "cache")
        manager = CacheManager(cache_dir=cache_dir, ttl_seconds=1)

        manager.cache_item("test_key", {"data": "value"})
        time.sleep(1.1)

        retrieved = manager.get_cached_item("test_key")
        assert retrieved is None

    def test_cache_size_management_evicts_old_entries(self, tmp_path: Path) -> None:
        """Cache evicts oldest entries when size limit is exceeded."""
        cache_dir = str(tmp_path / "cache")
        manager = CacheManager(cache_dir=cache_dir, max_size_mb=0.001)

        large_data = {"data": "x" * 10000}
        manager.cache_item("key1", large_data)
        time.sleep(0.1)
        manager.cache_item("key2", large_data)
        time.sleep(0.1)
        manager.cache_item("key3", large_data)

        assert manager.get_cached_item("key1") is None
        assert manager.get_cached_item("key3") is not None

    def test_cache_clear_removes_all_entries(self, tmp_path: Path) -> None:
        """Clear cache removes all cached items."""
        cache_dir = str(tmp_path / "cache")
        manager = CacheManager(cache_dir=cache_dir)

        manager.cache_item("key1", {"data": "value1"})
        manager.cache_item("key2", {"data": "value2"})

        manager.clear_cache()

        assert manager.get_cached_item("key1") is None
        assert manager.get_cached_item("key2") is None

    def test_cache_handles_corrupted_index(self, tmp_path: Path) -> None:
        """Cache handles corrupted index file gracefully."""
        cache_dir = str(tmp_path / "cache")
        os.makedirs(cache_dir, exist_ok=True)

        index_file = os.path.join(cache_dir, "index.json")
        with open(index_file, "w") as f:
            f.write("corrupted json {{{")

        manager = CacheManager(cache_dir=cache_dir)
        assert manager.cache_index == {}

    def test_cache_persists_across_instances(self, tmp_path: Path) -> None:
        """Cache data persists between manager instances."""
        cache_dir = str(tmp_path / "cache")

        manager1 = CacheManager(cache_dir=cache_dir)
        manager1.cache_item("persistent_key", {"data": "persistent"})

        manager2 = CacheManager(cache_dir=cache_dir)
        retrieved = manager2.get_cached_item("persistent_key")
        assert retrieved == {"data": "persistent"}


class TestRateLimiter:
    """Test rate limiting functionality."""

    def test_rate_limiter_allows_requests_within_limit(self) -> None:
        """Rate limiter allows requests within configured limits."""
        config = RateLimitConfig(requests_per_minute=10, requests_per_day=100)
        limiter = RateLimiter(config)

        for _ in range(10):
            allowed, _ = limiter.check_limit("test_resource")
            assert allowed is True
            limiter.record_request("test_resource")

    def test_rate_limiter_blocks_requests_exceeding_minute_limit(self) -> None:
        """Rate limiter blocks requests exceeding per-minute limit."""
        config = RateLimitConfig(requests_per_minute=3, requests_per_day=100)
        limiter = RateLimiter(config)

        for _ in range(3):
            allowed, _ = limiter.check_limit("test_resource")
            assert allowed is True
            limiter.record_request("test_resource")

        allowed, message = limiter.check_limit("test_resource")
        assert allowed is False
        assert "Rate limit exceeded" in message
        assert "seconds" in message

    def test_rate_limiter_blocks_requests_exceeding_day_limit(self) -> None:
        """Rate limiter blocks requests exceeding daily limit."""
        config = RateLimitConfig(requests_per_minute=1000, requests_per_day=5)
        limiter = RateLimiter(config)

        for _ in range(5):
            limiter.record_request("test_resource")

        allowed, message = limiter.check_limit("test_resource")
        assert allowed is False
        assert "Daily rate limit exceeded" in message

    def test_rate_limiter_resets_minute_counter(self) -> None:
        """Rate limiter resets per-minute counter after time passes."""
        config = RateLimitConfig(requests_per_minute=2, requests_per_day=100)
        limiter = RateLimiter(config)

        limiter.record_request("test_resource")
        limiter.record_request("test_resource")

        limiter.minute_counters["test_resource"] = (2, time.time() - 61)

        allowed, _ = limiter.check_limit("test_resource")
        assert allowed is True

    def test_rate_limiter_tracks_multiple_resources(self) -> None:
        """Rate limiter tracks limits separately for different resources."""
        config = RateLimitConfig(requests_per_minute=2, requests_per_day=100)
        limiter = RateLimiter(config)

        limiter.record_request("resource1")
        limiter.record_request("resource1")

        allowed_r1, _ = limiter.check_limit("resource1")
        allowed_r2, _ = limiter.check_limit("resource2")

        assert allowed_r1 is False
        assert allowed_r2 is True


class TestAPIRepositoryBase:
    """Test base API repository functionality."""

    def test_repository_initialization_creates_directories(self, tmp_path: Path) -> None:
        """Repository initialization creates cache and download directories."""
        download_dir = str(tmp_path / "downloads")
        cache_dir = str(tmp_path / "cache" / "test_repo")

        repo = FakeRepositoryForTesting(
            repository_name="test_repo",
            api_endpoint="https://api.example.com",
            download_dir=download_dir,
            cache_config={"cache_dir": cache_dir},
        )

        assert os.path.exists(repo.download_dir)
        assert os.path.exists(repo.cache_manager.cache_dir)

    def test_make_request_uses_cache_for_get(self, tmp_path: Path) -> None:
        """Make request uses cache for GET requests."""
        cache_dir = str(tmp_path / "cache")
        repo = FakeRepositoryForTesting(
            repository_name="test",
            api_endpoint="https://api.example.com",
            cache_config={"cache_dir": cache_dir},
        )

        test_response = {"data": "cached"}
        fake_response = FakeHTTPResponse(status_code=200, json_data=test_response)
        repo.fake_session.set_request_response(fake_response)

        success1, data1, _ = repo._make_request("test", method="GET")
        success2, data2, _ = repo._make_request("test", method="GET")

        assert success1 is True
        assert success2 is True
        assert data1 == test_response
        assert data2 == test_response
        assert len(repo.fake_session.request_log) == 1

    def test_make_request_respects_rate_limits(self, tmp_path: Path) -> None:
        """Make request respects rate limiting configuration."""
        rate_config = RateLimitConfig(requests_per_minute=1, requests_per_day=10)
        repo = FakeRepositoryForTesting(
            repository_name="test",
            api_endpoint="https://api.example.com",
            rate_limit_config=rate_config,
        )

        fake_response = FakeHTTPResponse(status_code=200, json_data={"data": "test"})
        repo.fake_session.set_request_response(fake_response)

        success1, _, _ = repo._make_request("test", method="GET", use_cache=False)
        success2, _, msg2 = repo._make_request("test", method="GET", use_cache=False)

        assert success1 is True
        assert success2 is False
        assert "Rate limit exceeded" in msg2

    def test_make_request_handles_http_errors(self) -> None:
        """Make request handles HTTP error responses correctly."""
        repo = FakeRepositoryForTesting(
            repository_name="test",
            api_endpoint="https://api.example.com",
        )

        fake_response = FakeHTTPResponse(status_code=404, text="Not Found")
        repo.fake_session.set_request_response(fake_response)

        success, data, error = repo._make_request("test", method="GET", use_cache=False)

        assert success is False
        assert data is None
        assert "404" in error

    def test_make_request_handles_network_errors(self) -> None:
        """Make request handles network connectivity errors."""
        repo = FakeRepositoryForTesting(
            repository_name="test",
            api_endpoint="https://api.example.com",
        )

        repo.fake_session.set_request_exception(Exception("Network error"))
        success, data, error = repo._make_request("test", method="GET", use_cache=False)

        assert success is False
        assert data is None
        assert error == "Request error"

    def test_make_request_adds_api_key_header(self) -> None:
        """Make request adds API key to authorization header."""
        repo = FakeRepositoryForTesting(
            repository_name="test",
            api_endpoint="https://api.example.com",
            api_key="test_key_123",
        )

        fake_response = FakeHTTPResponse(status_code=200, json_data={})
        repo.fake_session.set_request_response(fake_response)

        repo._make_request("test", method="GET", use_cache=False)

        assert len(repo.fake_session.request_log) == 1
        request_headers = repo.fake_session.request_log[0]["headers"]
        assert request_headers is not None
        assert "Authorization" in request_headers
        assert request_headers["Authorization"] == "Bearer test_key_123"

    def test_make_request_uses_proxy_when_configured(self) -> None:
        """Make request uses proxy configuration."""
        repo = FakeRepositoryForTesting(
            repository_name="test",
            api_endpoint="https://api.example.com",
            proxy="http://proxy.example.com:8080",
        )

        assert repo.session.proxies["http"] == "http://proxy.example.com:8080"
        assert repo.session.proxies["https"] == "http://proxy.example.com:8080"

    def test_verify_checksum_validates_correct_hash(self, tmp_path: Path) -> None:
        """Verify checksum correctly validates file integrity."""
        test_file = tmp_path / "test.bin"
        test_content = b"test content for checksum validation"
        test_file.write_bytes(test_content)

        expected_checksum = hashlib.sha256(test_content).hexdigest()

        repo = FakeRepositoryForTesting(
            repository_name="test",
            api_endpoint="https://api.example.com",
        )

        result = repo._verify_checksum(str(test_file), expected_checksum)
        assert result is True

    def test_verify_checksum_detects_corrupted_file(self, tmp_path: Path) -> None:
        """Verify checksum detects file corruption."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"test content")

        wrong_checksum = hashlib.sha256(b"different content").hexdigest()

        repo = FakeRepositoryForTesting(
            repository_name="test",
            api_endpoint="https://api.example.com",
        )

        result = repo._verify_checksum(str(test_file), wrong_checksum)
        assert result is False

    def test_download_model_creates_destination_directory(self, tmp_path: Path) -> None:
        """Download model creates destination directory if it doesn't exist."""
        repo = FakeRepositoryForTesting(
            repository_name="test",
            api_endpoint="https://api.example.com",
        )

        model_info = ModelInfo(
            model_id="test-model",
            name="Test Model",
            download_url="https://example.com/model.bin",
        )

        repo.set_model_details("test-model", model_info)

        test_data = b"test" * 25
        fake_response = FakeHTTPResponse(
            status_code=200,
            headers={"content-length": "100"},
            stream_content=[test_data],
        )
        repo.fake_session.set_get_response(fake_response)

        dest_path = str(tmp_path / "subdir" / "model.bin")
        success, _ = repo.download_model("test-model", dest_path)

        assert os.path.exists(os.path.dirname(dest_path))

    def test_download_model_verifies_checksum_when_provided(self, tmp_path: Path) -> None:
        """Download model verifies checksum after download."""
        repo = FakeRepositoryForTesting(
            repository_name="test",
            api_endpoint="https://api.example.com",
        )

        test_data = b"test model data"
        correct_checksum = hashlib.sha256(test_data).hexdigest()

        model_info = ModelInfo(
            model_id="test-model",
            name="Test Model",
            download_url="https://example.com/model.bin",
            checksum=correct_checksum,
        )

        repo.set_model_details("test-model", model_info)

        fake_response = FakeHTTPResponse(
            status_code=200,
            headers={"content-length": str(len(test_data))},
            stream_content=[test_data],
        )
        repo.fake_session.set_get_response(fake_response)

        dest_path = str(tmp_path / "model.bin")
        success, message = repo.download_model("test-model", dest_path)

        assert success is True
        assert "complete" in message.lower()

    def test_download_model_fails_on_checksum_mismatch(self, tmp_path: Path) -> None:
        """Download model fails when checksum doesn't match."""
        repo = FakeRepositoryForTesting(
            repository_name="test",
            api_endpoint="https://api.example.com",
        )

        test_data = b"test model data"
        wrong_checksum = hashlib.sha256(b"different data").hexdigest()

        model_info = ModelInfo(
            model_id="test-model",
            name="Test Model",
            download_url="https://example.com/model.bin",
            checksum=wrong_checksum,
        )

        repo.set_model_details("test-model", model_info)

        fake_response = FakeHTTPResponse(
            status_code=200,
            headers={"content-length": str(len(test_data))},
            stream_content=[test_data],
        )
        repo.fake_session.set_get_response(fake_response)

        dest_path = str(tmp_path / "model.bin")
        success, message = repo.download_model("test-model", dest_path)

        assert success is False
        assert "Checksum verification failed" in message
        assert not os.path.exists(dest_path)
