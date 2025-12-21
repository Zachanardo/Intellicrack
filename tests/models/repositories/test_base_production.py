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
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.models.repositories.base import (
    APIRepositoryBase,
    CacheManager,
    RateLimiter,
    RateLimitConfig,
)
from intellicrack.models.repositories.interface import ModelInfo


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


class ConcreteRepository(APIRepositoryBase):
    """Concrete implementation of APIRepositoryBase for testing."""

    def get_available_models(self) -> list[ModelInfo]:
        return []

    def get_model_details(self, model_id: str) -> ModelInfo | None:
        return None

    def authenticate(self) -> tuple[bool, str]:
        return True, "Authenticated"


class TestAPIRepositoryBase:
    """Test base API repository functionality."""

    def test_repository_initialization_creates_directories(self, tmp_path: Path) -> None:
        """Repository initialization creates cache and download directories."""
        download_dir = str(tmp_path / "downloads")
        cache_dir = str(tmp_path / "cache" / "test_repo")

        repo = ConcreteRepository(
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
        repo = ConcreteRepository(
            repository_name="test",
            api_endpoint="https://api.example.com",
            cache_config={"cache_dir": cache_dir},
        )

        test_response = {"data": "cached"}
        with patch.object(repo.session, "request") as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = test_response
            mock_request.return_value = mock_response

            success1, data1, _ = repo._make_request("test", method="GET")
            success2, data2, _ = repo._make_request("test", method="GET")

            assert success1 is True
            assert success2 is True
            assert data1 == test_response
            assert data2 == test_response
            assert mock_request.call_count == 1

    def test_make_request_respects_rate_limits(self, tmp_path: Path) -> None:
        """Make request respects rate limiting configuration."""
        rate_config = RateLimitConfig(requests_per_minute=1, requests_per_day=10)
        repo = ConcreteRepository(
            repository_name="test",
            api_endpoint="https://api.example.com",
            rate_limit_config=rate_config,
        )

        with patch.object(repo.session, "request") as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": "test"}
            mock_request.return_value = mock_response

            success1, _, _ = repo._make_request("test", method="GET", use_cache=False)
            success2, _, msg2 = repo._make_request("test", method="GET", use_cache=False)

            assert success1 is True
            assert success2 is False
            assert "Rate limit exceeded" in msg2

    def test_make_request_handles_http_errors(self) -> None:
        """Make request handles HTTP error responses correctly."""
        repo = ConcreteRepository(
            repository_name="test",
            api_endpoint="https://api.example.com",
        )

        with patch.object(repo.session, "request") as mock_request:
            mock_response = Mock()
            mock_response.status_code = 404
            mock_response.text = "Not Found"
            mock_request.return_value = mock_response

            success, data, error = repo._make_request("test", method="GET", use_cache=False)

            assert success is False
            assert data is None
            assert "404" in error

    def test_make_request_handles_network_errors(self) -> None:
        """Make request handles network connectivity errors."""
        repo = ConcreteRepository(
            repository_name="test",
            api_endpoint="https://api.example.com",
        )

        with patch.object(repo.session, "request", side_effect=Exception("Network error")):
            success, data, error = repo._make_request("test", method="GET", use_cache=False)

            assert success is False
            assert data is None
            assert error == "Request error"

    def test_make_request_adds_api_key_header(self) -> None:
        """Make request adds API key to authorization header."""
        repo = ConcreteRepository(
            repository_name="test",
            api_endpoint="https://api.example.com",
            api_key="test_key_123",
        )

        with patch.object(repo.session, "request") as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {}
            mock_request.return_value = mock_response

            repo._make_request("test", method="GET", use_cache=False)

            call_kwargs = mock_request.call_args[1]
            assert "Authorization" in call_kwargs["headers"]
            assert call_kwargs["headers"]["Authorization"] == "Bearer test_key_123"

    def test_make_request_uses_proxy_when_configured(self) -> None:
        """Make request uses proxy configuration."""
        repo = ConcreteRepository(
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

        repo = ConcreteRepository(
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

        repo = ConcreteRepository(
            repository_name="test",
            api_endpoint="https://api.example.com",
        )

        result = repo._verify_checksum(str(test_file), wrong_checksum)
        assert result is False

    def test_download_model_creates_destination_directory(self, tmp_path: Path) -> None:
        """Download model creates destination directory if it doesn't exist."""
        repo = ConcreteRepository(
            repository_name="test",
            api_endpoint="https://api.example.com",
        )

        model_info = ModelInfo(
            model_id="test-model",
            name="Test Model",
            download_url="https://example.com/model.bin",
        )

        with patch.object(repo, "get_model_details", return_value=model_info):
            with patch.object(repo.session, "get") as mock_get:
                mock_response = MagicMock()
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_response.raise_for_status = Mock()
                mock_response.headers = {"content-length": "100"}
                mock_response.iter_content = Mock(return_value=[b"test" * 25])
                mock_get.return_value = mock_response

                dest_path = str(tmp_path / "subdir" / "model.bin")
                success, _ = repo.download_model("test-model", dest_path)

                assert os.path.exists(os.path.dirname(dest_path))

    def test_download_model_verifies_checksum_when_provided(self, tmp_path: Path) -> None:
        """Download model verifies checksum after download."""
        repo = ConcreteRepository(
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

        with patch.object(repo, "get_model_details", return_value=model_info):
            with patch.object(repo.session, "get") as mock_get:
                mock_response = MagicMock()
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_response.raise_for_status = Mock()
                mock_response.headers = {"content-length": str(len(test_data))}
                mock_response.iter_content = Mock(return_value=[test_data])
                mock_get.return_value = mock_response

                dest_path = str(tmp_path / "model.bin")
                success, message = repo.download_model("test-model", dest_path)

                assert success is True
                assert "complete" in message.lower()

    def test_download_model_fails_on_checksum_mismatch(self, tmp_path: Path) -> None:
        """Download model fails when checksum doesn't match."""
        repo = ConcreteRepository(
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

        with patch.object(repo, "get_model_details", return_value=model_info):
            with patch.object(repo.session, "get") as mock_get:
                mock_response = MagicMock()
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_response.raise_for_status = Mock()
                mock_response.headers = {"content-length": str(len(test_data))}
                mock_response.iter_content = Mock(return_value=[test_data])
                mock_get.return_value = mock_response

                dest_path = str(tmp_path / "model.bin")
                success, message = repo.download_model("test-model", dest_path)

                assert success is False
                assert "Checksum verification failed" in message
                assert not os.path.exists(dest_path)
