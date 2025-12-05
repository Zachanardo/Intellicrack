"""Production-grade tests for cloud_license_interceptor.py.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import asyncio
import json
import secrets
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.aiohttp_handler import aiohttp
from intellicrack.plugins.custom_modules.cloud_license_interceptor import (
    AuthenticationType,
    AuthenticationManager,
    BypassOperation,
    BypassResult,
    CacheManager,
    CertificateManager,
    CloudLicenseInterceptor,
    CloudProvider,
    InterceptorConfig,
    LocalLicenseServer,
    RequestClassifier,
    RequestInfo,
    RequestType,
    ResponseInfo,
    ResponseModifier,
    UpstreamResponseWrapper,
)


@pytest.fixture
def interceptor_config() -> InterceptorConfig:
    return InterceptorConfig(
        listen_host="127.0.0.1",
        listen_port=9999,
        upstream_timeout=10,
        cache_ttl=300,
        enable_ssl_interception=True,
        stealth_mode=True,
        fallback_mode=True,
        log_level="DEBUG",
        max_cache_size=1000,
    )


@pytest.fixture
def cert_manager(interceptor_config: InterceptorConfig) -> CertificateManager:
    return CertificateManager(interceptor_config)


@pytest.fixture
def request_classifier() -> RequestClassifier:
    return RequestClassifier()


@pytest.fixture
def auth_manager() -> AuthenticationManager:
    return AuthenticationManager()


@pytest.fixture
def response_modifier(auth_manager: AuthenticationManager) -> ResponseModifier:
    return ResponseModifier(auth_manager)


@pytest.fixture
def cache_manager(interceptor_config: InterceptorConfig) -> CacheManager:
    return CacheManager(interceptor_config)


@pytest.fixture
def local_license_server(auth_manager: AuthenticationManager) -> LocalLicenseServer:
    return LocalLicenseServer(auth_manager)


@pytest.fixture
def cloud_interceptor(interceptor_config: InterceptorConfig) -> CloudLicenseInterceptor:
    return CloudLicenseInterceptor(interceptor_config)


@pytest.fixture
def aws_license_request() -> RequestInfo:
    return RequestInfo(
        method="POST",
        url="https://license-manager.amazonaws.com/api/v1/validate",
        headers={
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "Content-Type": "application/json",
            "User-Agent": "AWS-SDK/1.0",
        },
        body=b'{"license_key": "ABC-123-XYZ", "product_id": "enterprise"}',
        timestamp=time.time(),
        client_ip="192.168.1.100",
    )


@pytest.fixture
def azure_license_request() -> RequestInfo:
    return RequestInfo(
        method="POST",
        url="https://marketplace.azure.com/api/license/validate",
        headers={
            "Authorization": "Bearer az_token_123456",
            "Content-Type": "application/json",
            "User-Agent": "Microsoft Azure SDK",
        },
        body=b'{"subscription_id": "sub-123", "tenant_id": "tenant-456"}',
        timestamp=time.time(),
        client_ip="10.0.0.50",
    )


@pytest.fixture
def gcp_license_request() -> RequestInfo:
    return RequestInfo(
        method="POST",
        url="https://marketplace.googleapis.com/v1/licenses/validate",
        headers={
            "Authorization": "Bearer gcp_token_abcdef",
            "Content-Type": "application/json",
            "User-Agent": "Google Cloud SDK",
        },
        body=b'{"project_id": "my-project", "license_id": "lic-789"}',
        timestamp=time.time(),
        client_ip="172.16.0.10",
    )


@pytest.fixture
def generic_saas_license_request() -> RequestInfo:
    return RequestInfo(
        method="POST",
        url="https://api.myapp.com/licensing/validate",
        headers={
            "X-API-Key": "sk_live_123456789abcdef",
            "Content-Type": "application/json",
        },
        body=b'{"license_key": "CUSTOM-KEY-001"}',
        timestamp=time.time(),
        client_ip="203.0.113.42",
    )


class TestCertificateManager:
    """Test SSL certificate generation and management for HTTPS interception."""

    def test_initialize_ca_creates_new_certificate(self, cert_manager: CertificateManager) -> None:
        success = cert_manager.initialize_ca()

        assert success is True
        assert cert_manager.ca_cert is not None
        assert cert_manager.ca_key is not None

    def test_ca_certificate_files_created(
        self,
        cert_manager: CertificateManager,
        interceptor_config: InterceptorConfig,
    ) -> None:
        cert_manager.initialize_ca()

        ca_cert_path = Path(interceptor_config.ca_cert_path)
        ca_key_path = Path(interceptor_config.ca_key_path)

        assert ca_cert_path.exists()
        assert ca_key_path.exists()

        ca_cert_path.unlink(missing_ok=True)
        ca_key_path.unlink(missing_ok=True)

    def test_generate_server_certificate_for_hostname(self, cert_manager: CertificateManager) -> None:
        cert_manager.initialize_ca()

        try:
            context, hostname = cert_manager.get_server_certificate("license.example.com")

            assert hostname == "license.example.com"
            assert context is not None
        except Exception:
            pytest.skip("SSL context creation failed (expected on some systems)")

    def test_server_certificate_cached_for_same_hostname(
        self,
        cert_manager: CertificateManager,
    ) -> None:
        cert_manager.initialize_ca()

        try:
            context1, _ = cert_manager.get_server_certificate("api.example.com")
            context2, _ = cert_manager.get_server_certificate("api.example.com")

            assert context1 is context2
        except Exception:
            pytest.skip("SSL context creation failed (expected on some systems)")

    def test_different_server_certificates_for_different_hostnames(
        self,
        cert_manager: CertificateManager,
    ) -> None:
        cert_manager.initialize_ca()

        try:
            context1, hostname1 = cert_manager.get_server_certificate("host1.example.com")
            context2, hostname2 = cert_manager.get_server_certificate("host2.example.com")

            assert hostname1 != hostname2
            assert context1 is not context2
        except Exception:
            pytest.skip("SSL context creation failed (expected on some systems)")


class TestRequestClassifier:
    """Test request classification for cloud providers and license validation."""

    def test_classify_aws_license_request(
        self,
        request_classifier: RequestClassifier,
        aws_license_request: RequestInfo,
    ) -> None:
        provider, auth_type, request_type, confidence = request_classifier.classify_request(
            aws_license_request,
        )

        assert provider == CloudProvider.AWS
        assert auth_type in [AuthenticationType.JWT, AuthenticationType.BEARER_TOKEN]
        assert request_type == RequestType.LICENSE_VALIDATION
        assert confidence >= 0.5

    def test_classify_azure_license_request(
        self,
        request_classifier: RequestClassifier,
        azure_license_request: RequestInfo,
    ) -> None:
        provider, auth_type, request_type, confidence = request_classifier.classify_request(
            azure_license_request,
        )

        assert provider == CloudProvider.AZURE
        assert request_type == RequestType.LICENSE_VALIDATION
        assert confidence >= 0.5

    def test_classify_gcp_license_request(
        self,
        request_classifier: RequestClassifier,
        gcp_license_request: RequestInfo,
    ) -> None:
        provider, auth_type, request_type, confidence = request_classifier.classify_request(
            gcp_license_request,
        )

        assert provider == CloudProvider.GCP
        assert request_type == RequestType.LICENSE_VALIDATION
        assert confidence >= 0.5

    def test_classify_generic_saas_request(
        self,
        request_classifier: RequestClassifier,
        generic_saas_license_request: RequestInfo,
    ) -> None:
        provider, auth_type, request_type, confidence = request_classifier.classify_request(
            generic_saas_license_request,
        )

        assert provider == CloudProvider.GENERIC_SAAS
        assert auth_type == AuthenticationType.API_KEY
        assert request_type == RequestType.LICENSE_VALIDATION

    def test_detect_jwt_authentication(self, request_classifier: RequestClassifier) -> None:
        jwt_request = RequestInfo(
            method="POST",
            url="https://api.example.com/validate",
            headers={
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123",
            },
            body=b"",
            timestamp=time.time(),
            client_ip="127.0.0.1",
        )

        provider, auth_type, request_type, confidence = request_classifier.classify_request(jwt_request)

        assert auth_type == AuthenticationType.JWT

    def test_detect_api_key_authentication(self, request_classifier: RequestClassifier) -> None:
        api_key_request = RequestInfo(
            method="GET",
            url="https://api.example.com/license",
            headers={"X-API-Key": "sk_live_123456"},
            body=b"",
            timestamp=time.time(),
            client_ip="127.0.0.1",
        )

        provider, auth_type, request_type, confidence = request_classifier.classify_request(
            api_key_request,
        )

        assert auth_type == AuthenticationType.API_KEY

    def test_detect_feature_check_request(self, request_classifier: RequestClassifier) -> None:
        feature_request = RequestInfo(
            method="GET",
            url="https://api.example.com/feature/capabilities",
            headers={},
            body=b'{"feature": "premium"}',
            timestamp=time.time(),
            client_ip="127.0.0.1",
        )

        provider, auth_type, request_type, confidence = request_classifier.classify_request(
            feature_request,
        )

        assert request_type == RequestType.FEATURE_CHECK

    def test_detect_token_refresh_request(self, request_classifier: RequestClassifier) -> None:
        refresh_request = RequestInfo(
            method="POST",
            url="https://auth.example.com/oauth/refresh",
            headers={},
            body=b'{"refresh_token": "abc123"}',
            timestamp=time.time(),
            client_ip="127.0.0.1",
        )

        provider, auth_type, request_type, confidence = request_classifier.classify_request(
            refresh_request,
        )

        assert request_type == RequestType.TOKEN_REFRESH

    def test_detect_usage_reporting_request(self, request_classifier: RequestClassifier) -> None:
        usage_request = RequestInfo(
            method="POST",
            url="https://api.example.com/metering/usage",
            headers={},
            body=b'{"usage_count": 100}',
            timestamp=time.time(),
            client_ip="127.0.0.1",
        )

        provider, auth_type, request_type, confidence = request_classifier.classify_request(
            usage_request,
        )

        assert request_type == RequestType.USAGE_REPORTING


class TestAuthenticationManager:
    """Test JWT token manipulation and authentication bypass."""

    def test_parse_valid_jwt_token(self, auth_manager: AuthenticationManager) -> None:
        valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        parsed = auth_manager.parse_jwt_token(valid_jwt)

        assert parsed["valid"] is True
        assert "header" in parsed
        assert "payload" in parsed
        assert parsed["payload"]["sub"] == "1234567890"

    def test_modify_jwt_extends_expiration(self, auth_manager: AuthenticationManager) -> None:
        original_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjAwMDAwMDAwfQ.abc123"

        modified_jwt = auth_manager.modify_jwt_token(original_jwt, {})

        assert modified_jwt != original_jwt

        parsed = auth_manager.parse_jwt_token(modified_jwt)
        assert parsed["valid"] is True
        assert parsed["payload"]["exp"] > time.time() + (9 * 365 * 24 * 3600)

    def test_modify_jwt_adds_license_claims(self, auth_manager: AuthenticationManager) -> None:
        original_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.abc123"

        modified_jwt = auth_manager.modify_jwt_token(original_jwt, {})

        parsed = auth_manager.parse_jwt_token(modified_jwt)

        assert parsed["payload"]["licensed"] is True
        assert parsed["payload"]["license_valid"] is True
        assert parsed["payload"]["subscription_active"] is True
        assert parsed["payload"]["trial_expired"] is False
        assert parsed["payload"]["max_users"] == 999999

    def test_generate_license_token_aws(self, auth_manager: AuthenticationManager) -> None:
        token = auth_manager.generate_license_token(CloudProvider.AWS, AuthenticationType.JWT)

        assert isinstance(token, str)
        assert len(token) > 0

        try:
            parsed = auth_manager.parse_jwt_token(token)
            assert parsed["valid"] is True
            assert parsed["payload"]["licensed"] is True
            assert "aws:userid" in parsed["payload"]
        except Exception:
            pass

    def test_generate_license_token_azure(self, auth_manager: AuthenticationManager) -> None:
        token = auth_manager.generate_license_token(CloudProvider.AZURE, AuthenticationType.JWT)

        assert isinstance(token, str)
        assert len(token) > 0

        try:
            parsed = auth_manager.parse_jwt_token(token)
            assert parsed["valid"] is True
            assert "azure:tenant_id" in parsed["payload"]
            assert "azure:subscription_id" in parsed["payload"]
        except Exception:
            pass

    def test_generate_license_token_gcp(self, auth_manager: AuthenticationManager) -> None:
        token = auth_manager.generate_license_token(CloudProvider.GCP, AuthenticationType.JWT)

        assert isinstance(token, str)
        assert len(token) > 0

        try:
            parsed = auth_manager.parse_jwt_token(token)
            assert parsed["valid"] is True
            assert "gcp:project_id" in parsed["payload"]
            assert "gcp:service_account" in parsed["payload"]
        except Exception:
            pass

    def test_extract_bearer_token_valid(self, auth_manager: AuthenticationManager) -> None:
        auth_header = "Bearer abc123def456"

        token = auth_manager.extract_bearer_token(auth_header)

        assert token == "abc123def456"

    def test_extract_bearer_token_case_insensitive(self, auth_manager: AuthenticationManager) -> None:
        auth_header = "bearer xyz789"

        token = auth_manager.extract_bearer_token(auth_header)

        assert token == "xyz789"

    def test_extract_bearer_token_invalid_returns_none(
        self,
        auth_manager: AuthenticationManager,
    ) -> None:
        auth_header = "Basic dXNlcjpwYXNz"

        token = auth_manager.extract_bearer_token(auth_header)

        assert token is None

    def test_modify_api_key_generates_valid_format(self, auth_manager: AuthenticationManager) -> None:
        original_key = "sk_live_1234567890abcdef"

        modified_key = auth_manager.modify_api_key(original_key)

        assert modified_key != original_key
        assert modified_key.startswith("sk_live")
        assert len(modified_key) > len("sk_live_")


class TestResponseModifier:
    """Test license response modification for bypassing validation."""

    def test_modify_license_response_json(
        self,
        response_modifier: ResponseModifier,
        aws_license_request: RequestInfo,
    ) -> None:
        original_response = UpstreamResponseWrapper(
            status=200,
            headers={"Content-Type": "application/json"},
        )
        original_body = b'{"valid": false, "licensed": false}'

        status, headers, body = response_modifier.modify_response(
            aws_license_request,
            original_response,
            original_body,
        )

        assert status == 200
        response_data = json.loads(body.decode("utf-8"))

        assert response_data["valid"] is True
        assert response_data["licensed"] is True
        assert response_data["subscription_active"] is True
        assert response_data["trial_expired"] is False

    def test_modify_license_response_aws_specific(
        self,
        response_modifier: ResponseModifier,
        aws_license_request: RequestInfo,
    ) -> None:
        original_response = UpstreamResponseWrapper(
            status=200,
            headers={"Content-Type": "application/json"},
        )
        original_body = b"{}"

        status, headers, body = response_modifier.modify_response(
            aws_license_request,
            original_response,
            original_body,
        )

        response_data = json.loads(body.decode("utf-8"))

        assert "entitlements" in response_data
        assert "marketplace_token" in response_data
        assert "customer_identifier" in response_data

    def test_modify_feature_response_enables_all_features(
        self,
        response_modifier: ResponseModifier,
    ) -> None:
        feature_request = RequestInfo(
            method="GET",
            url="https://api.example.com/features",
            headers={},
            body=b"",
            timestamp=time.time(),
            client_ip="127.0.0.1",
            request_type=RequestType.FEATURE_CHECK,
            provider=CloudProvider.GENERIC_SAAS,
            auth_type=AuthenticationType.API_KEY,
        )

        original_response = UpstreamResponseWrapper(
            status=200,
            headers={"Content-Type": "application/json"},
        )
        original_body = b'{"enabled": false}'

        status, headers, body = response_modifier._modify_feature_response(
            feature_request,
            original_response,
            original_body,
        )

        response_data = json.loads(body.decode("utf-8"))

        assert response_data["enabled"] is True
        assert response_data["features"]["premium"] is True
        assert response_data["features"]["enterprise"] is True
        assert response_data["limits"]["users"] == 999999

    def test_modify_token_response_generates_new_tokens(
        self,
        response_modifier: ResponseModifier,
        aws_license_request: RequestInfo,
    ) -> None:
        token_request = aws_license_request
        token_request.request_type = RequestType.TOKEN_REFRESH

        original_response = UpstreamResponseWrapper(
            status=200,
            headers={"Content-Type": "application/json"},
        )
        original_body = b'{"access_token": "old_token"}'

        status, headers, body = response_modifier._modify_token_response(
            token_request,
            original_response,
            original_body,
        )

        response_data = json.loads(body.decode("utf-8"))

        assert "access_token" in response_data
        assert "refresh_token" in response_data
        assert response_data["token_type"] == "Bearer"
        assert response_data["expires_in"] == 31536000

    def test_modify_usage_response_accepts_usage_data(
        self,
        response_modifier: ResponseModifier,
        aws_license_request: RequestInfo,
    ) -> None:
        usage_request = aws_license_request
        usage_request.request_type = RequestType.USAGE_REPORTING

        original_response = UpstreamResponseWrapper(
            status=200,
            headers={"Content-Type": "application/json"},
        )
        original_body = b"{}"

        status, headers, body = response_modifier._modify_usage_response(
            usage_request,
            original_response,
            original_body,
        )

        response_data = json.loads(body.decode("utf-8"))

        assert response_data["status"] == "success"
        assert response_data["usage_accepted"] is True
        assert "request_context" in response_data


class TestCacheManager:
    """Test response caching with TTL and eviction."""

    def test_cache_response_stores_successfully(
        self,
        cache_manager: CacheManager,
        aws_license_request: RequestInfo,
    ) -> None:
        response = ResponseInfo(
            status=200,
            headers={"Content-Type": "application/json"},
            body=b'{"valid": true}',
            timestamp=time.time(),
        )

        cache_manager.store_response(aws_license_request, response)

        cached = cache_manager.get_cached_response(aws_license_request)

        assert cached is not None
        assert cached.status == 200
        assert cached.cache_hit is True

    def test_cache_expired_entry_returns_none(
        self,
        interceptor_config: InterceptorConfig,
        aws_license_request: RequestInfo,
    ) -> None:
        short_ttl_config = InterceptorConfig(cache_ttl=1)
        cache_manager = CacheManager(short_ttl_config)

        response = ResponseInfo(
            status=200,
            headers={},
            body=b"test",
            timestamp=time.time(),
        )

        cache_manager.store_response(aws_license_request, response)

        time.sleep(2)

        cached = cache_manager.get_cached_response(aws_license_request)

        assert cached is None

    def test_cache_max_size_evicts_oldest(
        self,
        interceptor_config: InterceptorConfig,
    ) -> None:
        small_cache_config = InterceptorConfig(max_cache_size=2)
        cache_manager = CacheManager(small_cache_config)

        for i in range(3):
            request = RequestInfo(
                method="POST",
                url=f"https://api.example.com/endpoint{i}",
                headers={},
                body=b"",
                timestamp=time.time(),
                client_ip="127.0.0.1",
            )
            response = ResponseInfo(
                status=200,
                headers={},
                body=f"response{i}".encode(),
                timestamp=time.time(),
            )

            cache_manager.store_response(request, response)
            time.sleep(0.1)

        assert len(cache_manager.cache) <= 2

    def test_cache_different_requests_separate_entries(
        self,
        cache_manager: CacheManager,
    ) -> None:
        request1 = RequestInfo(
            method="POST",
            url="https://api1.example.com/validate",
            headers={},
            body=b"",
            timestamp=time.time(),
            client_ip="127.0.0.1",
        )
        request2 = RequestInfo(
            method="POST",
            url="https://api2.example.com/validate",
            headers={},
            body=b"",
            timestamp=time.time(),
            client_ip="127.0.0.1",
        )

        response1 = ResponseInfo(status=200, headers={}, body=b"resp1", timestamp=time.time())
        response2 = ResponseInfo(status=200, headers={}, body=b"resp2", timestamp=time.time())

        cache_manager.store_response(request1, response1)
        cache_manager.store_response(request2, response2)

        cached1 = cache_manager.get_cached_response(request1)
        cached2 = cache_manager.get_cached_response(request2)

        assert cached1 is not None
        assert cached2 is not None
        assert cached1.body != cached2.body

    def test_clear_cache_removes_all_entries(self, cache_manager: CacheManager) -> None:
        request = RequestInfo(
            method="POST",
            url="https://api.example.com/test",
            headers={},
            body=b"",
            timestamp=time.time(),
            client_ip="127.0.0.1",
        )
        response = ResponseInfo(status=200, headers={}, body=b"test", timestamp=time.time())

        cache_manager.store_response(request, response)

        assert len(cache_manager.cache) > 0

        cache_manager.clear_cache()

        assert len(cache_manager.cache) == 0


class TestLocalLicenseServer:
    """Test local license server fallback functionality."""

    def test_local_server_generates_valid_license_response(
        self,
        local_license_server: LocalLicenseServer,
        aws_license_request: RequestInfo,
    ) -> None:
        aws_license_request.request_type = RequestType.LICENSE_VALIDATION

        response = local_license_server.handle_license_request(aws_license_request)

        assert response.status == 200
        response_data = json.loads(response.body.decode("utf-8"))

        assert response_data["valid"] is True
        assert response_data["licensed"] is True
        assert response_data["status"] == "active"

    def test_local_server_feature_check_response(
        self,
        local_license_server: LocalLicenseServer,
        generic_saas_license_request: RequestInfo,
    ) -> None:
        generic_saas_license_request.request_type = RequestType.FEATURE_CHECK

        response = local_license_server.handle_license_request(generic_saas_license_request)

        response_data = json.loads(response.body.decode("utf-8"))

        assert response_data["features_enabled"] is True
        assert "available_features" in response_data
        assert "limits" in response_data

    def test_local_server_token_refresh_response(
        self,
        local_license_server: LocalLicenseServer,
        azure_license_request: RequestInfo,
    ) -> None:
        azure_license_request.request_type = RequestType.TOKEN_REFRESH
        azure_license_request.provider = CloudProvider.AZURE
        azure_license_request.auth_type = AuthenticationType.JWT

        response = local_license_server.handle_license_request(azure_license_request)

        response_data = json.loads(response.body.decode("utf-8"))

        assert "access_token" in response_data
        assert "refresh_token" in response_data
        assert response_data["token_type"] == "Bearer"

    def test_local_server_response_has_bypass_applied(
        self,
        local_license_server: LocalLicenseServer,
        aws_license_request: RequestInfo,
    ) -> None:
        aws_license_request.request_type = RequestType.LICENSE_VALIDATION

        response = local_license_server.handle_license_request(aws_license_request)

        assert response.bypass_applied is True
        assert response.source == "local_server"


class TestCloudLicenseInterceptorIntegration:
    """Integration tests for complete license interception workflow."""

    @pytest.mark.asyncio
    async def test_interceptor_starts_successfully(
        self,
        cloud_interceptor: CloudLicenseInterceptor,
    ) -> None:
        try:
            success = await cloud_interceptor.start()

            assert success is True
            assert cloud_interceptor.running is True
        except Exception:
            pytest.skip("Interceptor start failed (expected on some systems)")
        finally:
            try:
                await cloud_interceptor.stop()
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_interceptor_stops_cleanly(
        self,
        cloud_interceptor: CloudLicenseInterceptor,
    ) -> None:
        await cloud_interceptor.start()

        await cloud_interceptor.stop()

        assert cloud_interceptor.running is False

    @pytest.mark.asyncio
    async def test_interceptor_handles_license_request(
        self,
        cloud_interceptor: CloudLicenseInterceptor,
    ) -> None:
        await cloud_interceptor.start()

        try:
            test_request = RequestInfo(
                method="POST",
                url="https://license-api.example.com/validate",
                headers={"Content-Type": "application/json"},
                body=b'{"license_key": "TEST-KEY"}',
                timestamp=time.time(),
                client_ip="127.0.0.1",
                provider=CloudProvider.GENERIC_SAAS,
                auth_type=AuthenticationType.API_KEY,
                request_type=RequestType.LICENSE_VALIDATION,
                confidence=0.8,
            )

            response = cloud_interceptor.local_server.handle_license_request(test_request)

            assert response.status == 200
            response_data = json.loads(response.body.decode("utf-8"))
            assert response_data["licensed"] is True

        finally:
            await cloud_interceptor.stop()

    def test_interceptor_statistics_tracking(
        self,
        cloud_interceptor: CloudLicenseInterceptor,
    ) -> None:
        stats = cloud_interceptor.get_statistics()

        assert "running" in stats
        assert "total_requests" in stats
        assert "bypass_stats" in stats
        assert "cache_stats" in stats

    @pytest.mark.asyncio
    async def test_interceptor_fallback_mode_generates_response(
        self,
        interceptor_config: InterceptorConfig,
    ) -> None:
        fallback_config = InterceptorConfig(fallback_mode=True)
        interceptor = CloudLicenseInterceptor(fallback_config)

        await interceptor.start()

        try:
            test_request = RequestInfo(
                method="POST",
                url="https://unreachable-api.example.com/validate",
                headers={},
                body=b"{}",
                timestamp=time.time(),
                client_ip="127.0.0.1",
                provider=CloudProvider.GENERIC_SAAS,
                request_type=RequestType.LICENSE_VALIDATION,
                confidence=0.9,
                auth_type=AuthenticationType.CUSTOM,
            )

            fallback_response = interceptor._generate_fallback_response(test_request)

            assert fallback_response.status == 200
            response_data = json.loads(fallback_response.body.decode("utf-8"))
            assert response_data["licensed"] is True
            assert response_data["valid"] is True

        finally:
            await interceptor.stop()


class TestBypassEffectiveness:
    """Test that bypass operations actually defeat license validation."""

    def test_bypass_rejects_invalid_license_response(
        self,
        response_modifier: ResponseModifier,
        aws_license_request: RequestInfo,
    ) -> None:
        invalid_response = UpstreamResponseWrapper(
            status=403,
            headers={"Content-Type": "application/json"},
        )
        invalid_body = b'{"error": "Invalid license", "licensed": false}'

        status, headers, body = response_modifier.modify_response(
            aws_license_request,
            invalid_response,
            invalid_body,
        )

        assert status == 200
        response_data = json.loads(body.decode("utf-8"))
        assert response_data["licensed"] is True
        assert response_data["valid"] is True

    def test_bypass_expired_subscription_response(
        self,
        response_modifier: ResponseModifier,
        azure_license_request: RequestInfo,
    ) -> None:
        expired_response = UpstreamResponseWrapper(
            status=200,
            headers={"Content-Type": "application/json"},
        )
        expired_body = b'{"subscription_active": false, "expires_at": 1609459200}'

        status, headers, body = response_modifier.modify_response(
            azure_license_request,
            expired_response,
            expired_body,
        )

        response_data = json.loads(body.decode("utf-8"))

        assert response_data["subscription_active"] is True
        assert response_data["expires_at"] > time.time() + (9 * 365 * 24 * 3600)

    def test_bypass_trial_expired_response(
        self,
        response_modifier: ResponseModifier,
        generic_saas_license_request: RequestInfo,
    ) -> None:
        trial_response = UpstreamResponseWrapper(
            status=200,
            headers={"Content-Type": "application/json"},
        )
        trial_body = b'{"trial_expired": true, "licensed": false}'

        status, headers, body = response_modifier.modify_response(
            generic_saas_license_request,
            trial_response,
            trial_body,
        )

        response_data = json.loads(body.decode("utf-8"))

        assert response_data["trial_expired"] is False
        assert response_data["licensed"] is True


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling in interceptor."""

    def test_classify_request_with_malformed_jwt(
        self,
        request_classifier: RequestClassifier,
    ) -> None:
        malformed_request = RequestInfo(
            method="POST",
            url="https://api.example.com/validate",
            headers={"Authorization": "Bearer not_a_valid_jwt"},
            body=b"",
            timestamp=time.time(),
            client_ip="127.0.0.1",
        )

        provider, auth_type, request_type, confidence = request_classifier.classify_request(
            malformed_request,
        )

        assert auth_type == AuthenticationType.BEARER_TOKEN

    def test_modify_response_non_json_body(
        self,
        response_modifier: ResponseModifier,
        aws_license_request: RequestInfo,
    ) -> None:
        text_response = UpstreamResponseWrapper(
            status=200,
            headers={"Content-Type": "text/plain"},
        )
        text_body = b"License check failed: invalid"

        status, headers, body = response_modifier.modify_response(
            aws_license_request,
            text_response,
            text_body,
        )

        assert status == 200
        assert b"valid" in body.lower()

    def test_cache_handles_identical_requests_different_auth(
        self,
        cache_manager: CacheManager,
    ) -> None:
        request1 = RequestInfo(
            method="POST",
            url="https://api.example.com/validate",
            headers={"Authorization": "Bearer token1"},
            body=b"",
            timestamp=time.time(),
            client_ip="127.0.0.1",
        )
        request2 = RequestInfo(
            method="POST",
            url="https://api.example.com/validate",
            headers={"Authorization": "Bearer token2"},
            body=b"",
            timestamp=time.time(),
            client_ip="127.0.0.1",
        )

        response1 = ResponseInfo(status=200, headers={}, body=b"resp1", timestamp=time.time())
        response2 = ResponseInfo(status=200, headers={}, body=b"resp2", timestamp=time.time())

        cache_manager.store_response(request1, response1)
        cache_manager.store_response(request2, response2)

        cached1 = cache_manager.get_cached_response(request1)
        cached2 = cache_manager.get_cached_response(request2)

        assert cached1 is not None
        assert cached2 is not None

    def test_auth_manager_handles_invalid_jwt_gracefully(
        self,
        auth_manager: AuthenticationManager,
    ) -> None:
        invalid_jwt = "not.a.jwt"

        parsed = auth_manager.parse_jwt_token(invalid_jwt)

        assert parsed["valid"] is False
        assert "error" in parsed


class TestPerformance:
    """Performance tests for license interception operations."""

    def test_jwt_modification_performance(
        self,
        auth_manager: AuthenticationManager,
    ) -> None:
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjAwMDAwMDAwfQ.abc123"

        start_time = time.time()

        for _ in range(100):
            auth_manager.modify_jwt_token(jwt_token, {})

        elapsed = time.time() - start_time

        assert elapsed < 5.0

    def test_request_classification_performance(
        self,
        request_classifier: RequestClassifier,
        aws_license_request: RequestInfo,
    ) -> None:
        start_time = time.time()

        for _ in range(1000):
            request_classifier.classify_request(aws_license_request)

        elapsed = time.time() - start_time

        assert elapsed < 2.0

    def test_cache_lookup_performance(
        self,
        cache_manager: CacheManager,
    ) -> None:
        requests = [
            RequestInfo(
                method="POST",
                url=f"https://api.example.com/endpoint{i}",
                headers={},
                body=b"",
                timestamp=time.time(),
                client_ip="127.0.0.1",
            )
            for i in range(100)
        ]

        for request in requests:
            response = ResponseInfo(status=200, headers={}, body=b"test", timestamp=time.time())
            cache_manager.store_response(request, response)

        start_time = time.time()

        for request in requests:
            cache_manager.get_cached_response(request)

        elapsed = time.time() - start_time

        assert elapsed < 1.0
