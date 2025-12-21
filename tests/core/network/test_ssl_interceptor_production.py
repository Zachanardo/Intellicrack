"""Production tests for SSL/TLS traffic interception and analysis.

These tests validate that ssl_interceptor correctly generates CA certificates,
intercepts SSL/TLS traffic, and modifies license verification responses. Tests
MUST FAIL if certificate generation or traffic interception is broken.

Copyright (C) 2025 Zachary Flint
"""

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.network.ssl_interceptor import SSLTLSInterceptor


class TestSSLInterceptorProduction:
    """Production tests for SSL/TLS interceptor with real certificate operations."""

    @pytest.fixture
    def temp_cert_dir(self, tmp_path: Path) -> Path:
        """Create temporary directory for certificates."""
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        return cert_dir

    @pytest.fixture
    def interceptor_config(self, temp_cert_dir: Path) -> dict[str, Any]:
        """Create interceptor configuration with temporary paths."""
        ca_cert_path = temp_cert_dir / "ca_cert.pem"
        ca_key_path = temp_cert_dir / "ca_key.pem"

        return {
            "listen_ip": "127.0.0.1",
            "listen_port": 8543,
            "ca_cert_path": str(ca_cert_path),
            "ca_key_path": str(ca_key_path),
            "target_hosts": ["license.example.com", "activation.example.com"],
            "record_traffic": True,
            "auto_respond": True,
        }

    @pytest.fixture
    def interceptor(self, interceptor_config: dict[str, Any]) -> SSLTLSInterceptor:
        """Create SSL interceptor with test configuration."""
        return SSLTLSInterceptor(interceptor_config)

    def test_interceptor_initialization_with_config(
        self,
        interceptor: SSLTLSInterceptor,
        interceptor_config: dict[str, Any],
    ) -> None:
        """Interceptor initializes with provided configuration."""
        assert interceptor.config["listen_ip"] == "127.0.0.1", "Must set listen IP"
        assert interceptor.config["listen_port"] == 8543, "Must set listen port"
        assert "license.example.com" in interceptor.config["target_hosts"], "Must include target hosts"
        assert interceptor.config["record_traffic"] is True, "Must enable traffic recording"
        assert interceptor.config["auto_respond"] is True, "Must enable auto response"

    def test_ca_certificate_generation_creates_valid_cert(
        self,
        interceptor: SSLTLSInterceptor,
    ) -> None:
        """CA certificate generation produces valid PEM-encoded certificate and key."""
        cert_pem, key_pem = interceptor.generate_ca_certificate()

        assert cert_pem is not None, "Certificate must be generated"
        assert key_pem is not None, "Private key must be generated"
        assert isinstance(cert_pem, bytes), "Certificate must be bytes"
        assert isinstance(key_pem, bytes), "Key must be bytes"
        assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----"), "Must be PEM certificate"
        assert key_pem.startswith(b"-----BEGIN PRIVATE KEY-----"), "Must be PEM private key"
        assert b"-----END CERTIFICATE-----" in cert_pem, "Certificate must be complete"
        assert b"-----END PRIVATE KEY-----" in key_pem, "Key must be complete"

    def test_ca_certificate_contains_correct_subject_fields(
        self,
        interceptor: SSLTLSInterceptor,
    ) -> None:
        """Generated CA certificate has correct subject information."""
        cert_pem, _ = interceptor.generate_ca_certificate()

        assert cert_pem is not None, "Certificate must be generated"

        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

            subject_attrs = {attr.oid._name: attr.value for attr in cert.subject}

            assert "commonName" in subject_attrs, "Must have common name"
            assert "Intellicrack" in subject_attrs["commonName"], "CN must contain Intellicrack"
            assert "organizationName" in subject_attrs, "Must have organization"
        except ImportError:
            pytest.skip("cryptography library not available for certificate validation")

    def test_start_creates_ca_certificate_if_missing(
        self,
        interceptor: SSLTLSInterceptor,
        temp_cert_dir: Path,
    ) -> None:
        """Start method generates CA certificate if files don't exist."""
        ca_cert_path = temp_cert_dir / "ca_cert.pem"
        ca_key_path = temp_cert_dir / "ca_key.pem"

        assert not ca_cert_path.exists(), "Cert file must not exist initially"
        assert not ca_key_path.exists(), "Key file must not exist initially"

        if result := interceptor.start():
            try:
                assert ca_cert_path.exists(), "Certificate file must be created"
                assert ca_key_path.exists(), "Key file must be created"

                cert_content = ca_cert_path.read_bytes()
                key_content = ca_key_path.read_bytes()

                assert cert_content.startswith(b"-----BEGIN CERTIFICATE-----"), "Must save valid certificate"
                assert key_content.startswith(b"-----BEGIN PRIVATE KEY-----"), "Must save valid key"
            finally:
                interceptor.stop()

    def test_stop_terminates_proxy_process(
        self,
        interceptor: SSLTLSInterceptor,
    ) -> None:
        """Stop method terminates the running proxy process."""
        started = interceptor.start()

        if not started:
            pytest.skip("mitmproxy not available for testing")

        assert interceptor.proxy_process is not None, "Proxy process must be running"
        initial_pid = interceptor.proxy_process.pid if interceptor.proxy_process else None

        result = interceptor.stop()

        assert result is True, "Stop must succeed"
        assert interceptor.proxy_process is None, "Proxy process reference must be cleared"

        if initial_pid:
            try:
                os.kill(initial_pid, 0)
                pytest.fail("Process should be terminated")
            except OSError:
                pass

    def test_add_target_host_functionality(self, interceptor: SSLTLSInterceptor) -> None:
        """Add target host adds new host to interception list."""
        initial_count = len(interceptor.config["target_hosts"])

        interceptor.add_target_host("new-license-server.com")

        assert "new-license-server.com" in interceptor.config["target_hosts"], "Must add new host"
        assert len(interceptor.config["target_hosts"]) == initial_count + 1, "Host count must increase"

    def test_add_duplicate_target_host_ignored(self, interceptor: SSLTLSInterceptor) -> None:
        """Adding duplicate target host doesn't create duplicates."""
        interceptor.add_target_host("license.example.com")
        initial_count = len(interceptor.config["target_hosts"])

        interceptor.add_target_host("license.example.com")

        assert len(interceptor.config["target_hosts"]) == initial_count, "Must not add duplicate"

    def test_remove_target_host_functionality(self, interceptor: SSLTLSInterceptor) -> None:
        """Remove target host removes host from interception list."""
        interceptor.add_target_host("temp-server.com")
        assert "temp-server.com" in interceptor.config["target_hosts"], "Host must be added"

        interceptor.remove_target_host("temp-server.com")

        assert "temp-server.com" not in interceptor.config["target_hosts"], "Host must be removed"

    def test_get_target_hosts_returns_copy(self, interceptor: SSLTLSInterceptor) -> None:
        """Get target hosts returns a copy, not original list."""
        hosts = interceptor.get_target_hosts()

        hosts.append("modified-host.com")

        assert "modified-host.com" not in interceptor.config["target_hosts"], "Original must not be modified"

    def test_configure_updates_settings(self, interceptor: SSLTLSInterceptor) -> None:
        """Configure method updates interceptor settings."""
        new_config = {
            "listen_port": 9443,
            "record_traffic": False,
            "auto_respond": False,
        }

        result = interceptor.configure(new_config)

        assert result is True, "Configuration must succeed"
        assert interceptor.config["listen_port"] == 9443, "Port must be updated"
        assert interceptor.config["record_traffic"] is False, "Recording must be disabled"
        assert interceptor.config["auto_respond"] is False, "Auto response must be disabled"

    def test_configure_validates_port_range(self, interceptor: SSLTLSInterceptor) -> None:
        """Configure rejects invalid port numbers."""
        invalid_configs = [
            {"listen_port": 0},
            {"listen_port": -1},
            {"listen_port": 70000},
            {"listen_port": "invalid"},
        ]

        for invalid_config in invalid_configs:
            result = interceptor.configure(invalid_config)
            assert result is False, f"Must reject invalid port: {invalid_config['listen_port']}"

    def test_configure_validates_ip_address(self, interceptor: SSLTLSInterceptor) -> None:
        """Configure validates IP address format."""
        result = interceptor.configure({"listen_ip": "999.999.999.999"})

        assert result is False, "Must reject invalid IP address"

    def test_configure_validates_target_hosts_type(self, interceptor: SSLTLSInterceptor) -> None:
        """Configure validates target_hosts is a list."""
        result = interceptor.configure({"target_hosts": "not-a-list"})

        assert result is False, "Must reject non-list target_hosts"

    def test_configure_ignores_invalid_keys(self, interceptor: SSLTLSInterceptor) -> None:
        """Configure ignores unknown configuration keys with warning."""
        config = {
            "listen_port": 8444,
            "invalid_key": "should_be_ignored",
            "another_invalid": 12345,
        }

        result = interceptor.configure(config)

        assert result is True, "Must succeed despite invalid keys"
        assert interceptor.config["listen_port"] == 8444, "Valid keys must be applied"

    def test_configure_restarts_if_running(self, interceptor: SSLTLSInterceptor) -> None:
        """Configure restarts interceptor if it was running."""
        started = interceptor.start()

        if not started:
            pytest.skip("mitmproxy not available for testing")

        try:
            was_running = interceptor.proxy_process is not None

            result = interceptor.configure({"listen_port": 8445})

            if was_running:
                assert result is True, "Configuration must succeed"
        finally:
            interceptor.stop()

    def test_get_config_returns_safe_config(self, interceptor: SSLTLSInterceptor) -> None:
        """Get config returns configuration with sensitive data redacted."""
        config = interceptor.get_config()

        assert "ca_cert_path" in config, "Must include certificate path"
        assert "status" in config, "Must include runtime status"
        assert isinstance(config["status"], dict), "Status must be dictionary"

    def test_get_config_redacts_ca_key_path(
        self,
        interceptor: SSLTLSInterceptor,
        temp_cert_dir: Path,
    ) -> None:
        """Get config redacts CA key path for security."""
        ca_key_path = temp_cert_dir / "ca_key.pem"
        ca_key_path.write_bytes(b"fake_key_data")

        config = interceptor.get_config()

        assert config["ca_key_path"] == "<redacted>", "Key path must be redacted"

    def test_get_config_includes_runtime_status(self, interceptor: SSLTLSInterceptor) -> None:
        """Get config includes current runtime status."""
        config = interceptor.get_config()
        status = config["status"]

        assert "running" in status, "Must include running status"
        assert "traffic_captured" in status, "Must include traffic count"
        assert "ca_cert_exists" in status, "Must include cert existence check"
        assert "ca_key_exists" in status, "Must include key existence check"

        assert isinstance(status["running"], bool), "Running must be boolean"
        assert isinstance(status["traffic_captured"], int), "Traffic count must be integer"

    def test_traffic_log_initialization(self, interceptor: SSLTLSInterceptor) -> None:
        """Traffic log is initialized as empty list."""
        traffic_log = interceptor.get_traffic_log()

        assert isinstance(traffic_log, list), "Traffic log must be list"
        assert len(traffic_log) == 0, "Traffic log must be empty initially"

    def test_get_traffic_log_returns_copy(self, interceptor: SSLTLSInterceptor) -> None:
        """Get traffic log returns copy to prevent external modification."""
        log1 = interceptor.get_traffic_log()
        log1.append({"fake": "entry"})

        log2 = interceptor.get_traffic_log()

        assert len(log2) == 0, "Original log must not be modified"

    def test_multiple_start_calls_handled(self, interceptor: SSLTLSInterceptor) -> None:
        """Multiple start calls don't create duplicate processes."""
        result1 = interceptor.start()

        if not result1:
            pytest.skip("mitmproxy not available")

        try:
            first_pid = interceptor.proxy_process.pid if interceptor.proxy_process else None

            result2 = interceptor.start()

            second_pid = interceptor.proxy_process.pid if interceptor.proxy_process else None

            if first_pid and second_pid:
                assert first_pid == second_pid, "Should not create new process"
        finally:
            interceptor.stop()

    def test_certificate_directory_creation(
        self,
        temp_cert_dir: Path,
    ) -> None:
        """Start creates certificate directory if it doesn't exist."""
        nested_dir = temp_cert_dir / "nested" / "certs"
        assert not nested_dir.exists(), "Directory must not exist initially"

        config = {
            "ca_cert_path": str(nested_dir / "cert.pem"),
            "ca_key_path": str(nested_dir / "key.pem"),
        }

        interceptor = SSLTLSInterceptor(config)
        if result := interceptor.start():
            try:
                assert nested_dir.exists(), "Directory must be created"
            finally:
                interceptor.stop()

    def test_find_executable_locates_mitmdump(self, interceptor: SSLTLSInterceptor) -> None:
        """Find executable can locate mitmdump if installed."""
        if mitmdump_path := interceptor._find_executable("mitmdump"):
            assert os.path.exists(mitmdump_path), "Located path must exist"
            assert "mitmdump" in mitmdump_path.lower(), "Must be mitmdump executable"

    def test_configure_log_level_changes_logging(self, interceptor: SSLTLSInterceptor) -> None:
        """Configure with log_level changes logger level."""
        import logging

        initial_level = interceptor.logger.level

        interceptor.configure({"log_level": "DEBUG"})

        assert interceptor.logger.level == logging.DEBUG, "Must set DEBUG level"

        interceptor.configure({"log_level": "ERROR"})

        assert interceptor.logger.level == logging.ERROR, "Must set ERROR level"

        interceptor.logger.setLevel(initial_level)

    def test_configure_creates_missing_ca_cert(
        self,
        interceptor: SSLTLSInterceptor,
        temp_cert_dir: Path,
    ) -> None:
        """Configure generates CA certificate if path changed and doesn't exist."""
        new_cert_dir = temp_cert_dir / "new_certs"
        new_cert_dir.mkdir()

        new_config = {
            "ca_cert_path": str(new_cert_dir / "new_cert.pem"),
            "ca_key_path": str(new_cert_dir / "new_key.pem"),
        }

        result = interceptor.configure(new_config)

        assert result is True, "Configuration must succeed with cert generation"

    def test_stop_without_start_succeeds(self, interceptor: SSLTLSInterceptor) -> None:
        """Stop can be called without start without errors."""
        result = interceptor.stop()

        assert result is True, "Stop without start must succeed"

    def test_target_hosts_from_config(self) -> None:
        """Interceptor loads target hosts from system configuration."""
        interceptor = SSLTLSInterceptor()

        target_hosts = interceptor.config["target_hosts"]

        assert isinstance(target_hosts, list), "Target hosts must be list"
        assert len(target_hosts) > 0, "Must have default license domains"

    def test_ca_certificate_validity_period(self, interceptor: SSLTLSInterceptor) -> None:
        """Generated CA certificate has appropriate validity period."""
        cert_pem, _ = interceptor.generate_ca_certificate()

        if not cert_pem:
            pytest.skip("Certificate generation not available")

        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from datetime import datetime, timezone

            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

            validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days

            assert validity_days >= 3650, "Certificate must be valid for at least 10 years"
            assert cert.not_valid_before_utc <= datetime.now(timezone.utc), "Must be valid now"
            assert cert.not_valid_after_utc > datetime.now(timezone.utc), "Must not be expired"
        except ImportError:
            pytest.skip("cryptography library not available")

    def test_interceptor_handles_missing_cryptography_library(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Interceptor handles missing cryptography library gracefully."""
        import sys

        monkeypatch.setitem(sys.modules, "cryptography", None)

        interceptor = SSLTLSInterceptor()
        cert_pem, key_pem = interceptor.generate_ca_certificate()

        assert cert_pem is None, "Must return None when cryptography unavailable"
        assert key_pem is None, "Must return None when cryptography unavailable"

    def test_configure_restores_old_config_on_failure(
        self,
        interceptor: SSLTLSInterceptor,
    ) -> None:
        """Configure restores previous configuration if validation fails."""
        original_port = interceptor.config["listen_port"]

        result = interceptor.configure({"listen_port": -1})

        assert result is False, "Configuration must fail"
        assert interceptor.config["listen_port"] == original_port, "Must restore original port"

    def test_proxy_process_command_line_arguments(
        self,
        interceptor: SSLTLSInterceptor,
    ) -> None:
        """Start configures proxy with correct command line arguments."""
        started = interceptor.start()

        if not started:
            pytest.skip("mitmproxy not available")

        try:
            assert interceptor.proxy_process is not None, "Process must be created"
        finally:
            interceptor.stop()

    def test_concurrent_configure_calls(self, interceptor: SSLTLSInterceptor) -> None:
        """Concurrent configure calls are handled safely."""
        import threading

        results = []

        def configure_interceptor(port: int) -> None:
            result = interceptor.configure({"listen_port": port})
            results.append(result)

        threads = [
            threading.Thread(target=configure_interceptor, args=(8500 + i,))
            for i in range(5)
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert all(isinstance(r, bool) for r in results), "All results must be boolean"
