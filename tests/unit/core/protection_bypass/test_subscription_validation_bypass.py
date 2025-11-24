"""Comprehensive tests for subscription validation bypass functionality."""

import base64
import json
import time
import uuid
from datetime import datetime, timedelta

import pytest

from intellicrack.core.subscription_validation_bypass import (
    APIResponseSynthesizer,
    JWTManipulator,
    JWTPayload,
    OAuthProvider,
    OAuthTokenGenerator,
    SubscriptionTier,
    SubscriptionType,
    SubscriptionValidationBypass,
)


class TestJWTManipulator:
    def test_parse_jwt_valid_token(self):
        manipulator = JWTManipulator()

        payload = {
            "sub": "user123",
            "iss": "test-issuer",
            "aud": "test-audience",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        token = manipulator.sign_jwt_rs256(payload)

        header, parsed_payload, signature = manipulator.parse_jwt(token)

        assert header is not None
        assert "alg" in header
        assert header["alg"] == "RS256"
        assert parsed_payload["sub"] == "user123"
        assert parsed_payload["iss"] == "test-issuer"
        assert parsed_payload["aud"] == "test-audience"
        assert signature != ""

    def test_modify_jwt_claims(self):
        manipulator = JWTManipulator()

        original_payload = {
            "sub": "user123",
            "iss": "test-issuer",
            "aud": "test-audience",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "tier": "free",
        }

        token = manipulator.sign_jwt_rs256(original_payload)

        modifications = {"tier": "enterprise", "features": ["all"]}

        modified_payload = manipulator.modify_jwt_claims(token, modifications)

        assert modified_payload["tier"] == "enterprise"
        assert modified_payload["features"] == ["all"]
        assert modified_payload["sub"] == "user123"
        assert modified_payload["exp"] > original_payload["exp"]

    def test_generate_rsa_keypair(self):
        manipulator = JWTManipulator()

        private_pem, public_pem = manipulator.generate_rsa_keypair(2048)

        assert b"BEGIN PRIVATE KEY" in private_pem
        assert b"END PRIVATE KEY" in private_pem
        assert b"BEGIN PUBLIC KEY" in public_pem
        assert b"END PUBLIC KEY" in public_pem
        assert len(private_pem) > 1000
        assert len(public_pem) > 300

    def test_generate_ec_keypair(self):
        manipulator = JWTManipulator()

        private_pem, public_pem = manipulator.generate_ec_keypair()

        assert b"BEGIN PRIVATE KEY" in private_pem
        assert b"END PRIVATE KEY" in private_pem
        assert b"BEGIN PUBLIC KEY" in public_pem
        assert b"END PUBLIC KEY" in public_pem

    def test_sign_jwt_rs256(self):
        manipulator = JWTManipulator()

        payload = {
            "sub": "test-user",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        token = manipulator.sign_jwt_rs256(payload)

        assert isinstance(token, str)
        assert len(token.split(".")) == 3

        header, parsed_payload, _ = manipulator.parse_jwt(token)
        assert header["alg"] == "RS256"
        assert parsed_payload["sub"] == "test-user"

    def test_sign_jwt_rs512(self):
        manipulator = JWTManipulator()

        payload = {
            "sub": "test-user",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        token = manipulator.sign_jwt_rs512(payload)

        assert isinstance(token, str)
        header, parsed_payload, _ = manipulator.parse_jwt(token)
        assert header["alg"] == "RS512"

    def test_sign_jwt_es256(self):
        manipulator = JWTManipulator()

        payload = {
            "sub": "test-user",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        token = manipulator.sign_jwt_es256(payload)

        assert isinstance(token, str)
        header, _, _ = manipulator.parse_jwt(token)
        assert header["alg"] == "ES256"

    def test_sign_jwt_hs256(self):
        manipulator = JWTManipulator()

        payload = {
            "sub": "test-user",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        secret = "test-secret-key"
        token = manipulator.sign_jwt_hs256(payload, secret)

        assert isinstance(token, str)
        header, _, _ = manipulator.parse_jwt(token)
        assert header["alg"] == "HS256"

    def test_sign_jwt_hs512(self):
        manipulator = JWTManipulator()

        payload = {
            "sub": "test-user",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        secret = "test-secret-key"
        token = manipulator.sign_jwt_hs512(payload, secret)

        assert isinstance(token, str)
        header, _, _ = manipulator.parse_jwt(token)
        assert header["alg"] == "HS512"

    def test_brute_force_hs256_secret(self):
        manipulator = JWTManipulator()

        payload = {
            "sub": "test-user",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        secret = "password123"
        token = manipulator.sign_jwt_hs256(payload, secret)

        wordlist = ["wrong1", "wrong2", "password123", "wrong3"]
        found_secret = manipulator.brute_force_hs256_secret(token, wordlist)

        assert found_secret == "password123"

    def test_brute_force_hs256_secret_not_found(self):
        manipulator = JWTManipulator()

        payload = {
            "sub": "test-user",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        secret = "correct-secret"
        token = manipulator.sign_jwt_hs256(payload, secret)

        wordlist = ["wrong1", "wrong2", "wrong3"]
        found_secret = manipulator.brute_force_hs256_secret(token, wordlist)

        assert found_secret is None

    def test_resign_jwt_rs256(self):
        manipulator = JWTManipulator()

        original_payload = {
            "sub": "user123",
            "tier": "free",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        original_token = manipulator.sign_jwt_rs256(original_payload)

        modifications = {"tier": "enterprise", "quota": {"api_calls": 999999}}

        new_token = manipulator.resign_jwt(original_token, modifications, algorithm="RS256")

        _, parsed_payload, _ = manipulator.parse_jwt(new_token)
        assert parsed_payload["tier"] == "enterprise"
        assert parsed_payload["quota"]["api_calls"] == 999999

    def test_resign_jwt_hs256(self):
        manipulator = JWTManipulator()

        original_payload = {
            "sub": "user123",
            "tier": "free",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        secret = "test-secret"
        original_token = manipulator.sign_jwt_hs256(original_payload, secret)

        modifications = {"tier": "premium"}

        new_token = manipulator.resign_jwt(
            original_token, modifications, algorithm="HS256", key=secret
        )

        _, parsed_payload, _ = manipulator.parse_jwt(new_token)
        assert parsed_payload["tier"] == "premium"


class TestOAuthTokenGenerator:
    def test_generate_access_token_azure_ad(self):
        generator = OAuthTokenGenerator()

        token = generator.generate_access_token(OAuthProvider.AZURE_AD)

        assert isinstance(token, str)

        manipulator = JWTManipulator()
        header, payload, _ = manipulator.parse_jwt(token)

        assert payload["aud"] == "00000003-0000-0000-c000-000000000000"
        assert "sts.windows.net" in payload["iss"]
        assert "email" in payload
        assert "oid" in payload

    def test_generate_access_token_google(self):
        generator = OAuthTokenGenerator()

        token = generator.generate_access_token(OAuthProvider.GOOGLE)

        manipulator = JWTManipulator()
        _, payload, _ = manipulator.parse_jwt(token)

        assert payload["iss"] == "https://accounts.google.com"
        assert "email" in payload
        assert payload["email_verified"] is True

    def test_generate_access_token_aws_cognito(self):
        generator = OAuthTokenGenerator()

        token = generator.generate_access_token(OAuthProvider.AWS_COGNITO)

        manipulator = JWTManipulator()
        _, payload, _ = manipulator.parse_jwt(token)

        from urllib.parse import urlparse
        iss_hostname = urlparse(payload["iss"]).hostname or payload["iss"]
        assert iss_hostname == "cognito-idp.us-east-1.amazonaws.com" or iss_hostname.endswith(".cognito-idp.us-east-1.amazonaws.com")
        assert payload["token_use"] == "access"

    def test_generate_access_token_okta(self):
        generator = OAuthTokenGenerator()

        token = generator.generate_access_token(OAuthProvider.OKTA)

        manipulator = JWTManipulator()
        _, payload, _ = manipulator.parse_jwt(token)

        from urllib.parse import urlparse
        iss_hostname = urlparse(payload["iss"]).hostname or payload["iss"]
        assert iss_hostname == "okta.com" or iss_hostname.endswith(".okta.com")
        assert payload["ver"] == 1

    def test_generate_access_token_auth0(self):
        generator = OAuthTokenGenerator()

        token = generator.generate_access_token(OAuthProvider.AUTH0)

        manipulator = JWTManipulator()
        _, payload, _ = manipulator.parse_jwt(token)

        from urllib.parse import urlparse
        iss_hostname = urlparse(payload["iss"]).hostname or payload["iss"]
        assert iss_hostname == "auth0.com" or iss_hostname.endswith(".auth0.com")
        assert payload["sub"].startswith("auth0|")

    def test_generate_refresh_token(self):
        generator = OAuthTokenGenerator()

        token = generator.generate_refresh_token(OAuthProvider.GENERIC)

        assert isinstance(token, str)
        assert len(token) > 50

    def test_generate_id_token_azure(self):
        generator = OAuthTokenGenerator()

        token = generator.generate_id_token(
            OAuthProvider.AZURE_AD, user_id="test-user", email="test@example.com"
        )

        manipulator = JWTManipulator()
        _, payload, _ = manipulator.parse_jwt(token)

        assert payload["email"] == "test@example.com"
        from urllib.parse import urlparse
        iss_hostname = urlparse(payload["iss"]).hostname or payload["iss"]
        assert iss_hostname == "login.microsoftonline.com" or iss_hostname.endswith(".login.microsoftonline.com")

    def test_generate_id_token_google(self):
        generator = OAuthTokenGenerator()

        token = generator.generate_id_token(
            OAuthProvider.GOOGLE, user_id="test-user", email="test@gmail.com"
        )

        manipulator = JWTManipulator()
        _, payload, _ = manipulator.parse_jwt(token)

        assert payload["email"] == "test@gmail.com"
        assert payload["email_verified"] is True

    def test_generate_full_oauth_flow(self):
        generator = OAuthTokenGenerator()

        tokens = generator.generate_full_oauth_flow(OAuthProvider.AZURE_AD, "test-user-id")

        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert "id_token" in tokens
        assert "token_type" in tokens
        assert "expires_in" in tokens
        assert tokens["token_type"] == "Bearer"
        assert tokens["expires_in"] == 3600


class TestAPIResponseSynthesizer:
    def test_synthesize_license_validation(self):
        synthesizer = APIResponseSynthesizer()

        response = synthesizer.synthesize_license_validation(
            "TestProduct", SubscriptionTier.ENTERPRISE
        )

        assert response["status"] == "valid"
        assert response["license"]["tier"] == "enterprise"
        assert response["license"]["activated"] is True
        assert response["features"]["all_features"] is True
        assert response["quotas"]["api_calls"] == 999999999

    def test_synthesize_feature_unlock(self):
        synthesizer = APIResponseSynthesizer()

        features = ["feature1", "feature2", "feature3"]
        response = synthesizer.synthesize_feature_unlock(features, SubscriptionTier.PREMIUM)

        assert response["status"] == "success"
        assert response["tier"] == "premium"
        assert response["enabled_features"] == features
        assert all(response["feature_flags"][f] is True for f in features)

    def test_synthesize_quota_validation(self):
        synthesizer = APIResponseSynthesizer()

        response = synthesizer.synthesize_quota_validation("api_calls", 999999, 100)

        assert response["status"] == "ok"
        assert response["resource"] == "api_calls"
        assert response["limit"] == 999999
        assert response["used"] == 100
        assert response["remaining"] == 999999 - 100

    def test_synthesize_subscription_check(self):
        synthesizer = APIResponseSynthesizer()

        response = synthesizer.synthesize_subscription_check(SubscriptionTier.PROFESSIONAL)

        assert response["subscription"]["status"] == "active"
        assert response["subscription"]["tier"] == "professional"
        assert response["payment"]["status"] == "paid"

    def test_synthesize_microsoft365_validation(self):
        synthesizer = APIResponseSynthesizer()

        response = synthesizer.synthesize_microsoft365_validation()

        assert response["LicenseStatus"] == "Licensed"
        assert response["SubscriptionStatus"] == "Active"
        assert response["LicenseType"] == "Subscription"

    def test_synthesize_adobe_validation(self):
        synthesizer = APIResponseSynthesizer()

        response = synthesizer.synthesize_adobe_validation()

        assert response["status"] == "ACTIVE"
        assert response["subscription"]["status"] == "ACTIVE"
        assert response["subscription"]["productId"] == "CreativeCloud"
        assert len(response["entitlements"]) == 6

    def test_synthesize_atlassian_validation(self):
        synthesizer = APIResponseSynthesizer()

        response = synthesizer.synthesize_atlassian_validation()

        assert response["license"]["active"] is True
        assert response["license"]["tier"] == "UNLIMITED"
        assert len(response["applications"]) == 3

    def test_synthesize_salesforce_validation(self):
        synthesizer = APIResponseSynthesizer()

        response = synthesizer.synthesize_salesforce_validation()

        assert response["licenseType"] == "Enterprise"
        assert response["status"] == "Active"
        assert response["userLicenses"]["total"] == 999999

    def test_synthesize_slack_validation(self):
        synthesizer = APIResponseSynthesizer()

        response = synthesizer.synthesize_slack_validation()

        assert response["ok"] is True
        assert response["team"]["plan"] == "enterprise"
        assert response["team"]["is_enterprise"] is True

    def test_synthesize_zoom_validation(self):
        synthesizer = APIResponseSynthesizer()

        response = synthesizer.synthesize_zoom_validation()

        assert response["plan_type"] == "Enterprise"
        assert response["status"] == "active"
        assert response["licenses"]["total"] == 999999

    def test_synthesize_graphql_response_subscription(self):
        synthesizer = APIResponseSynthesizer()

        response = synthesizer.synthesize_graphql_response("subscription", SubscriptionTier.PREMIUM)

        assert "data" in response
        assert "viewer" in response["data"]
        assert response["data"]["viewer"]["subscription"]["status"] == "ACTIVE"
        assert response["data"]["viewer"]["subscription"]["plan"]["tier"] == "premium"

    def test_synthesize_graphql_response_features(self):
        synthesizer = APIResponseSynthesizer()

        response = synthesizer.synthesize_graphql_response("features")

        assert "data" in response
        assert "features" in response["data"]
        assert len(response["data"]["features"]["edges"]) == 100

    def test_synthesize_grpc_metadata(self):
        synthesizer = APIResponseSynthesizer()

        metadata = synthesizer.synthesize_grpc_metadata(SubscriptionTier.ENTERPRISE)

        assert metadata["x-subscription-tier"] == "enterprise"
        assert metadata["x-license-status"] == "active"
        assert metadata["x-features-enabled"] == "all"


class TestSubscriptionValidationBypass:
    def test_initialization(self):
        bypass = SubscriptionValidationBypass()

        assert bypass.jwt_manipulator is not None
        assert bypass.oauth_generator is not None
        assert bypass.api_synthesizer is not None
        assert len(bypass.bypass_methods) == 8
        assert len(bypass.known_services) == 4

    def test_manipulate_jwt_subscription(self):
        bypass = SubscriptionValidationBypass()

        original_payload = {
            "sub": "user123",
            "tier": "free",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        original_token = bypass.jwt_manipulator.sign_jwt_rs256(original_payload)

        modified_token = bypass.manipulate_jwt_subscription(
            original_token,
            tier=SubscriptionTier.ENTERPRISE,
            features=["all"],
            quota_overrides={"api_calls": 999999999},
        )

        _, payload, _ = bypass.jwt_manipulator.parse_jwt(modified_token)

        assert payload["subscription"]["tier"] == "enterprise"
        assert payload["features"] == ["all"]
        assert payload["quota"]["api_calls"] == 999999999

    def test_generate_subscription_tokens(self):
        bypass = SubscriptionValidationBypass()

        tokens = bypass.generate_subscription_tokens(
            "TestProduct", OAuthProvider.GENERIC, SubscriptionTier.PREMIUM
        )

        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert "id_token" in tokens

        _, payload, _ = bypass.jwt_manipulator.parse_jwt(tokens["access_token"])
        assert payload["subscription"]["product"] == "TestProduct"
        assert payload["subscription"]["tier"] == "premium"

    def test_intercept_and_spoof_api_validate(self):
        bypass = SubscriptionValidationBypass()

        response = bypass.intercept_and_spoof_api(
            "/api/validate", "TestProduct", SubscriptionTier.PREMIUM
        )

        assert response["status"] == "valid"
        assert response["license"]["tier"] == "premium"

    def test_intercept_and_spoof_api_microsoft(self):
        bypass = SubscriptionValidationBypass()

        response = bypass.intercept_and_spoof_api("/api/license", "Microsoft Office")

        assert response["LicenseStatus"] == "Licensed"
        assert response["SubscriptionStatus"] == "Active"

    def test_intercept_and_spoof_api_adobe(self):
        bypass = SubscriptionValidationBypass()

        response = bypass.intercept_and_spoof_api("/api/entitlements", "Adobe Photoshop")

        assert response["status"] == "ACTIVE"
        assert len(response["entitlements"]) == 6

    def test_manipulate_per_seat_license(self):
        bypass = SubscriptionValidationBypass()

        result = bypass.manipulate_per_seat_license(current_seats=5, target_seats=1000)

        assert result["seats"]["total"] == 1000
        assert result["seats"]["used"] == 1
        assert result["status"] == "active"

    def test_manipulate_usage_based_billing(self):
        bypass = SubscriptionValidationBypass()

        result = bypass.manipulate_usage_based_billing("storage", 1000, 999999999)

        assert result["resource"] == "storage"
        assert result["limit"] == 999999999
        assert result["used"] == 0

    def test_unlock_feature_tier(self):
        bypass = SubscriptionValidationBypass()

        result = bypass.unlock_feature_tier(
            SubscriptionTier.FREE, SubscriptionTier.ENTERPRISE, ["all"]
        )

        assert result["tier"] == "enterprise"
        assert result["enabled_features"] == ["all"]

    def test_extend_time_based_subscription(self):
        bypass = SubscriptionValidationBypass()

        current_expiry = datetime.now() + timedelta(days=30)
        result = bypass.extend_time_based_subscription(current_expiry, extension_days=365)

        assert result["subscription"]["status"] == "active"
        assert result["subscription"]["extended_by_days"] == 365

    def test_detect_subscription_type_default(self):
        bypass = SubscriptionValidationBypass()

        sub_type = bypass.detect_subscription_type("NonExistentProduct")

        assert sub_type == SubscriptionType.CLOUD_BASED

    def test_bypass_subscription_cloud(self):
        bypass = SubscriptionValidationBypass()

        result = bypass.bypass_subscription("TestProduct", SubscriptionType.CLOUD_BASED)

        assert result is True

    def test_bypass_subscription_oauth(self):
        bypass = SubscriptionValidationBypass()

        result = bypass.bypass_subscription("TestProduct", SubscriptionType.OAUTH)

        assert result is True

    def test_bypass_subscription_token_based(self):
        bypass = SubscriptionValidationBypass()

        result = bypass.bypass_subscription("TestProduct", SubscriptionType.TOKEN_BASED)

        assert result is True


class TestProductionReadiness:
    def test_jwt_manipulation_works_with_real_libraries(self):
        try:
            import jwt
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric import rsa

            manipulator = JWTManipulator()

            payload = {
                "sub": "test",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
            }

            token = manipulator.sign_jwt_rs256(payload)
            assert token is not None

            header, parsed, _ = manipulator.parse_jwt(token)
            assert parsed["sub"] == "test"

        except ImportError:
            pytest.skip("PyJWT or cryptography not available")

    def test_oauth_tokens_have_correct_structure(self):
        generator = OAuthTokenGenerator()

        for provider in [
            OAuthProvider.AZURE_AD,
            OAuthProvider.GOOGLE,
            OAuthProvider.AWS_COGNITO,
            OAuthProvider.OKTA,
            OAuthProvider.AUTH0,
        ]:
            tokens = generator.generate_full_oauth_flow(provider)

            assert len(tokens["access_token"].split(".")) == 3
            assert len(tokens["id_token"].split(".")) == 3
            assert len(tokens["refresh_token"]) > 50
            assert tokens["token_type"] == "Bearer"

    def test_api_responses_match_real_service_formats(self):
        synthesizer = APIResponseSynthesizer()

        microsoft_response = synthesizer.synthesize_microsoft365_validation()
        assert "LicenseStatus" in microsoft_response
        assert "SubscriptionStatus" in microsoft_response

        adobe_response = synthesizer.synthesize_adobe_validation()
        assert "subscription" in adobe_response
        assert "entitlements" in adobe_response

        slack_response = synthesizer.synthesize_slack_validation()
        assert "ok" in slack_response
        assert "team" in slack_response

    def test_subscription_bypass_handles_all_types(self):
        bypass = SubscriptionValidationBypass()

        for sub_type in [
            SubscriptionType.CLOUD_BASED,
            SubscriptionType.OAUTH,
            SubscriptionType.TOKEN_BASED,
            SubscriptionType.SAAS,
        ]:
            result = bypass.bypass_subscription("TestProduct", sub_type)
            assert result is True

    def test_no_placeholders_in_responses(self):
        synthesizer = APIResponseSynthesizer()

        microsoft_resp = synthesizer.synthesize_microsoft365_validation()
        assert "TODO" not in str(microsoft_resp)
        assert "PLACEHOLDER" not in str(microsoft_resp)

        adobe_resp = synthesizer.synthesize_adobe_validation()
        assert "TODO" not in str(adobe_resp)

        license_resp = synthesizer.synthesize_license_validation("Product")
        assert "TODO" not in str(license_resp)
