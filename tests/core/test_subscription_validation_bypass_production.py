"""Production tests for subscription validation bypass system.

Tests validate real JWT manipulation, OAuth token generation, API response forgery,
and cloud-based license bypassing without mocks or stubs.
"""

import base64
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from intellicrack.core.subscription_validation_bypass import (
    JWTManipulator,
    JWTPayload,
    OAuthProvider,
    OAuthTokenGenerator,
    SubscriptionTier,
    SubscriptionType,
    SubscriptionValidationBypass,
)


RSA_KEY_SIZE = 2048
EC_CURVE = ec.SECP256R1()
STANDARD_EXPONENT = 65537
ONE_HOUR = 3600
ONE_YEAR = 31536000


@pytest.fixture
def jwt_manipulator() -> JWTManipulator:
    """Create JWT manipulator instance."""
    return JWTManipulator()


@pytest.fixture
def oauth_generator() -> OAuthTokenGenerator:
    """Create OAuth token generator instance."""
    return OAuthTokenGenerator()


@pytest.fixture
def bypass_engine() -> SubscriptionBypassEngine:
    """Create subscription bypass engine instance."""
    return SubscriptionBypassEngine()


@pytest.fixture
def sample_rsa_key() -> rsa.RSAPrivateKey:
    """Generate sample RSA private key."""
    return rsa.generate_private_key(
        public_exponent=STANDARD_EXPONENT,
        key_size=RSA_KEY_SIZE,
        backend=default_backend(),
    )


@pytest.fixture
def sample_ec_key() -> ec.EllipticCurvePrivateKey:
    """Generate sample EC private key."""
    return ec.generate_private_key(
        EC_CURVE,
        backend=default_backend(),
    )


class TestJWTManipulator:
    """Test JWT token manipulation and signing."""

    def test_generate_rsa_keypair_produces_valid_keys(self, jwt_manipulator: JWTManipulator) -> None:
        """Generate RSA keypair with valid format."""
        private_pem, public_pem = jwt_manipulator.generate_rsa_keypair(key_size=RSA_KEY_SIZE)

        assert b"BEGIN PRIVATE KEY" in private_pem
        assert b"END PRIVATE KEY" in private_pem
        assert b"BEGIN PUBLIC KEY" in public_pem
        assert b"END PUBLIC KEY" in public_pem

        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None,
            backend=default_backend(),
        )
        assert isinstance(private_key, rsa.RSAPrivateKey)

        public_key = serialization.load_pem_public_key(
            public_pem,
            backend=default_backend(),
        )
        assert isinstance(public_key, rsa.RSAPublicKey)

    def test_generate_ec_keypair_produces_valid_keys(self, jwt_manipulator: JWTManipulator) -> None:
        """Generate EC keypair with valid P-256 curve."""
        private_pem, public_pem = jwt_manipulator.generate_ec_keypair()

        assert b"BEGIN PRIVATE KEY" in private_pem
        assert b"END PRIVATE KEY" in private_pem
        assert b"BEGIN PUBLIC KEY" in public_pem
        assert b"END PUBLIC KEY" in public_pem

        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None,
            backend=default_backend(),
        )
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)

    def test_parse_jwt_extracts_header_and_payload(self, jwt_manipulator: JWTManipulator, sample_rsa_key: rsa.RSAPrivateKey) -> None:
        """Parse JWT and extract header, payload, and signature."""
        payload = {
            "sub": "user123",
            "exp": int(time.time()) + ONE_HOUR,
            "iat": int(time.time()),
        }

        private_pem = sample_rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        token = jwt.encode(payload, private_pem, algorithm="RS256")

        header, parsed_payload, signature = jwt_manipulator.parse_jwt(token)

        assert header["alg"] == "RS256"
        assert parsed_payload["sub"] == "user123"
        assert "exp" in parsed_payload
        assert "iat" in parsed_payload
        assert isinstance(signature, str)
        assert len(signature) > 0

    def test_sign_jwt_rs256_creates_valid_token(self, jwt_manipulator: JWTManipulator, sample_rsa_key: rsa.RSAPrivateKey) -> None:
        """Sign JWT with RS256 algorithm."""
        payload = {
            "sub": "test_user",
            "role": "admin",
            "exp": int(time.time()) + ONE_HOUR,
            "iat": int(time.time()),
        }

        token = jwt_manipulator.sign_jwt_rs256(payload, sample_rsa_key)

        assert isinstance(token, str)
        assert token.count(".") == 2

        public_key_pem = sample_rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        decoded = jwt.decode(token, public_key_pem, algorithms=["RS256"])
        assert decoded["sub"] == "test_user"
        assert decoded["role"] == "admin"

    def test_sign_jwt_rs512_creates_valid_token(self, jwt_manipulator: JWTManipulator, sample_rsa_key: rsa.RSAPrivateKey) -> None:
        """Sign JWT with RS512 algorithm."""
        payload = {
            "sub": "test_user",
            "exp": int(time.time()) + ONE_HOUR,
            "iat": int(time.time()),
        }

        token = jwt_manipulator.sign_jwt_rs512(payload, sample_rsa_key)

        assert isinstance(token, str)

        public_key_pem = sample_rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        decoded = jwt.decode(token, public_key_pem, algorithms=["RS512"])
        assert decoded["sub"] == "test_user"

    def test_sign_jwt_es256_creates_valid_token(self, jwt_manipulator: JWTManipulator, sample_ec_key: ec.EllipticCurvePrivateKey) -> None:
        """Sign JWT with ES256 algorithm."""
        payload = {
            "sub": "test_user",
            "exp": int(time.time()) + ONE_HOUR,
            "iat": int(time.time()),
        }

        token = jwt_manipulator.sign_jwt_es256(payload, sample_ec_key)

        assert isinstance(token, str)

        public_key_pem = sample_ec_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        decoded = jwt.decode(token, public_key_pem, algorithms=["ES256"])
        assert decoded["sub"] == "test_user"

    def test_sign_jwt_hs256_creates_valid_token(self, jwt_manipulator: JWTManipulator) -> None:
        """Sign JWT with HS256 algorithm."""
        secret = "test_secret_key_12345"
        payload = {
            "sub": "test_user",
            "exp": int(time.time()) + ONE_HOUR,
            "iat": int(time.time()),
        }

        token = jwt_manipulator.sign_jwt_hs256(payload, secret)

        assert isinstance(token, str)

        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        assert decoded["sub"] == "test_user"

    def test_sign_jwt_hs512_creates_valid_token(self, jwt_manipulator: JWTManipulator) -> None:
        """Sign JWT with HS512 algorithm."""
        secret = "test_secret_key_67890"
        payload = {
            "sub": "test_user",
            "exp": int(time.time()) + ONE_HOUR,
            "iat": int(time.time()),
        }

        token = jwt_manipulator.sign_jwt_hs512(payload, secret)

        assert isinstance(token, str)

        decoded = jwt.decode(token, secret, algorithms=["HS512"])
        assert decoded["sub"] == "test_user"

    def test_brute_force_hs256_secret_finds_weak_secret(self, jwt_manipulator: JWTManipulator) -> None:
        """Brute force HS256 secret with wordlist."""
        secret = "password123"
        payload = {
            "sub": "user",
            "exp": int(time.time()) + ONE_HOUR,
            "iat": int(time.time()),
        }

        token = jwt_manipulator.sign_jwt_hs256(payload, secret)

        wordlist = ["admin", "test", "password", "password123", "secret"]

        found_secret = jwt_manipulator.brute_force_hs256_secret(token, wordlist)

        assert found_secret == "password123"

    def test_brute_force_hs256_secret_returns_none_when_not_found(self, jwt_manipulator: JWTManipulator) -> None:
        """Brute force returns None when secret not in wordlist."""
        secret = "very_strong_secret_999"
        payload = {
            "sub": "user",
            "exp": int(time.time()) + ONE_HOUR,
            "iat": int(time.time()),
        }

        token = jwt_manipulator.sign_jwt_hs256(payload, secret)

        wordlist = ["admin", "password", "test"]

        found_secret = jwt_manipulator.brute_force_hs256_secret(token, wordlist)

        assert found_secret is None

    def test_modify_jwt_claims_updates_payload(self, jwt_manipulator: JWTManipulator, sample_rsa_key: rsa.RSAPrivateKey) -> None:
        """Modify JWT claims and update timestamps."""
        original_payload = {
            "sub": "user123",
            "role": "user",
            "tier": "free",
            "exp": int(time.time()) + 100,
            "iat": int(time.time()),
        }

        private_pem = sample_rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        token = jwt.encode(original_payload, private_pem, algorithm="RS256")

        modifications = {
            "role": "admin",
            "tier": "enterprise",
        }

        modified_payload = jwt_manipulator.modify_jwt_claims(token, modifications)

        assert modified_payload["role"] == "admin"
        assert modified_payload["tier"] == "enterprise"
        assert modified_payload["sub"] == "user123"
        assert modified_payload["exp"] > int(time.time()) + 30000000

    def test_resign_jwt_creates_forged_token(self, jwt_manipulator: JWTManipulator, sample_rsa_key: rsa.RSAPrivateKey) -> None:
        """Resign JWT with modified claims."""
        original_payload = {
            "sub": "user123",
            "tier": "free",
            "exp": int(time.time()) + 100,
            "iat": int(time.time()),
        }

        private_pem = sample_rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        original_token = jwt.encode(original_payload, private_pem, algorithm="RS256")

        modifications = {
            "tier": "enterprise",
            "features": ["unlimited"],
        }

        forged_token = jwt_manipulator.resign_jwt(
            original_token,
            modifications,
            algorithm="RS256",
            key=sample_rsa_key,
        )

        assert forged_token != original_token

        public_key_pem = sample_rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        decoded = jwt.decode(forged_token, public_key_pem, algorithms=["RS256"])
        assert decoded["tier"] == "enterprise"
        assert decoded["features"] == ["unlimited"]


class TestOAuthTokenGenerator:
    """Test OAuth 2.0 token generation for various providers."""

    def test_generate_azure_ad_access_token(self, oauth_generator: OAuthTokenGenerator) -> None:
        """Generate Azure AD access token with correct claims."""
        token = oauth_generator.generate_access_token(
            provider=OAuthProvider.AZURE_AD,
            user_id="test@contoso.com",
            scopes=["openid", "profile", "email"],
        )

        header, payload, _signature = oauth_generator.jwt_manipulator.parse_jwt(token)

        assert header["alg"] == "RS256"
        assert "sts.windows.net" in payload["iss"]
        assert payload["sub"] == "test@contoso.com"
        assert "contoso.com" in payload["email"]
        assert "oid" in payload
        assert "tid" in payload
        assert payload["ver"] == "2.0"

    def test_generate_google_access_token(self, oauth_generator: OAuthTokenGenerator) -> None:
        """Generate Google access token with correct structure."""
        token = oauth_generator.generate_access_token(
            provider=OAuthProvider.GOOGLE,
            user_id="testuser",
            scopes=["openid", "email", "profile"],
        )

        _header, payload, _signature = oauth_generator.jwt_manipulator.parse_jwt(token)

        assert payload["iss"] == "https://accounts.google.com"
        assert payload["sub"] == "testuser"
        assert "@gmail.com" in payload["email"]
        assert payload["email_verified"] is True
        assert "scope" in payload

    def test_generate_aws_cognito_access_token(self, oauth_generator: OAuthTokenGenerator) -> None:
        """Generate AWS Cognito access token."""
        token = oauth_generator.generate_access_token(
            provider=OAuthProvider.AWS_COGNITO,
            user_id="cognito_user",
            scopes=["aws.cognito.signin.user.admin"],
        )

        _header, payload, _signature = oauth_generator.jwt_manipulator.parse_jwt(token)

        assert "cognito-idp" in payload["iss"]
        assert payload["token_use"] == "access"
        assert payload["sub"] == "cognito_user"
        assert payload["scope"] == "aws.cognito.signin.user.admin"

    def test_generate_okta_access_token(self, oauth_generator: OAuthTokenGenerator) -> None:
        """Generate Okta access token."""
        token = oauth_generator.generate_access_token(
            provider=OAuthProvider.OKTA,
            user_id="okta_user",
            scopes=["openid", "profile"],
        )

        _header, payload, _signature = oauth_generator.jwt_manipulator.parse_jwt(token)

        assert "okta.com" in payload["iss"]
        assert payload["sub"] == "okta_user"
        assert "scp" in payload

    def test_generate_auth0_access_token(self, oauth_generator: OAuthTokenGenerator) -> None:
        """Generate Auth0 access token."""
        token = oauth_generator.generate_access_token(
            provider=OAuthProvider.AUTH0,
            user_id="auth0_user",
            scopes=["openid", "email"],
        )

        _header, payload, _signature = oauth_generator.jwt_manipulator.parse_jwt(token)

        assert "auth0.com" in payload["iss"]
        assert payload["sub"] == "auth0_user"
        assert "scope" in payload

    def test_generate_refresh_token(self, oauth_generator: OAuthTokenGenerator) -> None:
        """Generate OAuth refresh token."""
        token = oauth_generator.generate_refresh_token(
            provider=OAuthProvider.GOOGLE,
        )

        assert len(token) > 0
        assert "-" in token

    def test_generate_id_token(self, oauth_generator: OAuthTokenGenerator) -> None:
        """Generate OAuth ID token with user claims."""
        token = oauth_generator.generate_id_token(
            provider=OAuthProvider.GOOGLE,
            user_id="id_token_user",
            email="user@example.com",
        )

        _header, payload, _signature = oauth_generator.jwt_manipulator.parse_jwt(token)

        assert payload["sub"] == "id_token_user"
        assert payload["email"] == "user@example.com"


class TestSubscriptionBypassEngine:
    """Test comprehensive subscription bypass operations."""

    def test_forge_cloud_license_response(self, bypass_engine: SubscriptionBypassEngine) -> None:
        """Forge cloud license server response with enterprise tier."""
        response = bypass_engine.forge_cloud_license_response(
            user_id="enterprise_user",
            tier=SubscriptionTier.ENTERPRISE,
            expiration_days=365,
        )

        assert response["status"] == "active"
        assert response["user_id"] == "enterprise_user"
        assert response["tier"] == "enterprise"
        assert response["features"]["unlimited_usage"] is True
        assert "license_key" in response

    def test_bypass_saas_subscription_check(self, bypass_engine: SubscriptionBypassEngine) -> None:
        """Bypass SaaS subscription validation."""
        original_response = {
            "subscription_status": "expired",
            "tier": "free",
            "valid_until": "2023-01-01",
        }

        bypassed = bypass_engine.bypass_saas_subscription_check(original_response)

        assert bypassed["subscription_status"] == "active"
        assert bypassed["tier"] == "enterprise"
        assert bypassed["features"]["all_features_enabled"] is True

    def test_generate_offline_activation_response(self, bypass_engine: SubscriptionBypassEngine) -> None:
        """Generate offline activation response for air-gapped systems."""
        machine_id = "MACHINE-12345"

        response = bypass_engine.generate_offline_activation_response(
            machine_id=machine_id,
            product_id="PRODUCT-XYZ",
        )

        assert response["machine_id"] == machine_id
        assert response["activation_status"] == "activated"
        assert "activation_code" in response
        assert len(response["activation_code"]) > 20

    def test_forge_license_validation_api_response(self, bypass_engine: SubscriptionBypassEngine) -> None:
        """Forge license validation API response."""
        response = bypass_engine.forge_license_validation_api_response(
            license_key="TEST-LICENSE-KEY",
            product_version="5.0",
        )

        assert response["valid"] is True
        assert response["license_key"] == "TEST-LICENSE-KEY"
        assert response["product_version"] == "5.0"
        assert response["features"]["all"] is True

    def test_bypass_time_based_subscription(self, bypass_engine: SubscriptionBypassEngine) -> None:
        """Bypass time-based subscription expiration."""
        original_check = {
            "start_date": "2023-01-01",
            "end_date": "2023-12-31",
            "status": "expired",
        }

        bypassed = bypass_engine.bypass_time_based_subscription(original_check)

        assert bypassed["status"] == "active"

        end_date = datetime.fromisoformat(bypassed["end_date"])
        assert end_date > datetime.now(UTC) + timedelta(days=300)

    def test_bypass_usage_based_subscription(self, bypass_engine: SubscriptionBypassEngine) -> None:
        """Bypass usage-based subscription limits."""
        original_check = {
            "usage_limit": 100,
            "current_usage": 99,
            "remaining": 1,
        }

        bypassed = bypass_engine.bypass_usage_based_subscription(original_check)

        assert bypassed["usage_limit"] == 999999
        assert bypassed["current_usage"] == 0
        assert bypassed["remaining"] == 999999

    def test_bypass_feature_based_subscription(self, bypass_engine: SubscriptionBypassEngine) -> None:
        """Bypass feature-based subscription restrictions."""
        original_features = {
            "export_pdf": False,
            "advanced_analytics": False,
            "api_access": False,
            "tier": "free",
        }

        bypassed = bypass_engine.bypass_feature_based_subscription(original_features)

        assert bypassed["export_pdf"] is True
        assert bypassed["advanced_analytics"] is True
        assert bypassed["api_access"] is True
        assert bypassed["tier"] == "enterprise"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_parse_invalid_jwt_format_raises_error(self, jwt_manipulator: JWTManipulator) -> None:
        """Parse invalid JWT format raises ValueError."""
        invalid_token = "invalid.token"

        with pytest.raises(ValueError, match="Invalid JWT token format"):
            jwt_manipulator.parse_jwt(invalid_token)

    def test_parse_malformed_jwt_structure(self, jwt_manipulator: JWTManipulator) -> None:
        """Parse JWT with wrong number of parts raises error."""
        malformed = "header.payload.signature.extra"

        with pytest.raises(ValueError):
            jwt_manipulator.parse_jwt(malformed)

    def test_brute_force_with_empty_wordlist(self, jwt_manipulator: JWTManipulator) -> None:
        """Brute force with empty wordlist returns None."""
        secret = "secret"
        payload = {"sub": "user", "exp": int(time.time()) + ONE_HOUR, "iat": int(time.time())}

        token = jwt_manipulator.sign_jwt_hs256(payload, secret)

        result = jwt_manipulator.brute_force_hs256_secret(token, [])

        assert result is None

    def test_resign_jwt_with_all_supported_algorithms(self, jwt_manipulator: JWTManipulator, sample_rsa_key: rsa.RSAPrivateKey, sample_ec_key: ec.EllipticCurvePrivateKey) -> None:
        """Resign JWT with all supported algorithms."""
        original_payload = {"sub": "user", "exp": int(time.time()) + 100, "iat": int(time.time())}

        private_pem = sample_rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        original_token = jwt.encode(original_payload, private_pem, algorithm="RS256")

        modifications = {"tier": "enterprise"}

        for algorithm in ["RS256", "RS512", "ES256", "HS256", "HS512"]:
            key: Any = sample_rsa_key if algorithm.startswith("RS") else sample_ec_key if algorithm == "ES256" else "secret_key"

            forged = jwt_manipulator.resign_jwt(original_token, modifications, algorithm=algorithm, key=key)

            assert isinstance(forged, str)
            assert forged.count(".") == 2
