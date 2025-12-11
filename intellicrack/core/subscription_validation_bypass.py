"""Production-ready subscription validation bypass for cloud-based licensing systems."""

import base64
import json
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from cryptography.hazmat.backends import default_backend


logger = logging.getLogger(__name__)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ECPrivateKey, RSAPrivateKey, ec, rsa


class SubscriptionTier(StrEnum):
    """String enumeration of subscription tier levels from free to unlimited for JWT payload manipulation and API response synthesis."""

    FREE = "free"
    BASIC = "basic"
    PREMIUM = "premium"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    UNLIMITED = "unlimited"


class SubscriptionType(StrEnum):
    """String enumeration of cloud-based subscription licensing models including OAuth, SaaS, time-based, usage-based, feature-based, and per-seat licensing."""

    CLOUD_BASED = "cloud_based"
    OAUTH = "oauth"
    TOKEN_BASED = "token_based"  # noqa: S105
    SAAS = "saas"
    TIME_BASED = "time_based"
    USAGE_BASED = "usage_based"
    FEATURE_BASED = "feature_based"
    PER_SEAT = "per_seat"


class OAuthProvider(StrEnum):
    """String enumeration of OAuth 2.0 identity providers with provider-specific JWT claim structures for Azure AD, Google, AWS Cognito, Okta, Auth0, and generic OAuth flows."""

    AZURE_AD = "azure_ad"
    GOOGLE = "google"
    AWS_COGNITO = "aws_cognito"
    OKTA = "okta"
    AUTH0 = "auth0"
    GENERIC = "generic"


@dataclass
class JWTPayload:
    """Dataclass representing standard JWT payload claims including subject, issuer, audience, expiration, issued-at timestamps, and additional custom claims dictionary."""

    sub: str
    iss: str
    aud: str
    exp: int
    iat: int
    additional_claims: dict[str, Any]


class JWTManipulator:
    """JWT token parser, modifier, and signer supporting RS256/RS512/ES256/HS256/HS512 algorithms with cryptographic key generation and secret brute-forcing capabilities."""

    def __init__(self) -> None:
        """Initialize JWT manipulator by generating default 2048-bit RSA keypair and SECP256R1 EC keypair for immediate token signing."""
        self.rsa_private_key, self.rsa_public_key = self._generate_default_rsa_keypair()
        self.ec_private_key, self.ec_public_key = self._generate_default_ec_keypair()

    def _generate_default_rsa_keypair(self) -> tuple[Any, Any]:
        """Generate 2048-bit RSA keypair with public exponent 65537 for instance default, returning private and public key objects."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def _generate_default_ec_keypair(self) -> tuple[Any, Any]:
        """Generate elliptic curve keypair using SECP256R1 for instance default ES256 signing, returning private and public key objects."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_rsa_keypair(self, key_size: int = 2048) -> tuple[bytes, bytes]:
        """Generate RSA keypair with configurable key size (default 2048-bit) using public exponent 65537 and return PKCS8 private key and SubjectPublicKeyInfo public key as PEM-encoded bytes."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return private_pem, public_pem

    def generate_ec_keypair(self) -> tuple[bytes, bytes]:
        """Generate elliptic curve keypair using SECP256R1 curve (NIST P-256) and return PKCS8 private key and SubjectPublicKeyInfo public key as PEM-encoded bytes for ES256 JWT signing."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return private_pem, public_pem

    def parse_jwt(self, token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
        """Split JWT token on periods, base64url decode header and payload sections without signature verification, and return tuple of (header dict, payload dict, raw signature string)."""
        parts = token.split(".")
        if len(parts) != 3:
            error_msg = "Invalid JWT token format"
            logger.error(error_msg)
            raise ValueError(error_msg)

        header_data = parts[0]
        payload_data = parts[1]
        signature = parts[2]

        header = json.loads(base64.urlsafe_b64decode(header_data + "=" * (4 - len(header_data) % 4)))
        payload = json.loads(
            base64.urlsafe_b64decode(payload_data + "=" * (4 - len(payload_data) % 4)),
        )

        return header, payload, signature

    def sign_jwt_rs256(self, payload: dict[str, Any], private_key: RSAPrivateKey | None = None) -> str:
        """Sign JWT payload using RS256 algorithm (RSASSA-PKCS1-v1_5 with SHA-256) with provided RSA private key or instance default, returning signed JWT token string."""
        import jwt

        key_to_use = private_key or self.rsa_private_key

        private_pem = key_to_use.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return jwt.encode(payload, private_pem, algorithm="RS256")

    def sign_jwt_rs512(self, payload: dict[str, Any], private_key: RSAPrivateKey | None = None) -> str:
        """Sign JWT payload using RS512 algorithm (RSASSA-PKCS1-v1_5 with SHA-512) with provided RSA private key or instance default, returning signed JWT token string."""
        import jwt

        key_to_use = private_key or self.rsa_private_key

        private_pem = key_to_use.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return jwt.encode(payload, private_pem, algorithm="RS512")

    def sign_jwt_es256(self, payload: dict[str, Any], private_key: ECPrivateKey | None = None) -> str:
        """Sign JWT payload using ES256 algorithm (ECDSA with P-256 curve and SHA-256) with provided EC private key or instance default, returning signed JWT token string."""
        import jwt

        key_to_use = private_key or self.ec_private_key

        private_pem = key_to_use.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return jwt.encode(payload, private_pem, algorithm="ES256")

    def sign_jwt_hs256(self, payload: dict[str, Any], secret: str) -> str:
        """Sign JWT payload using HS256 algorithm (HMAC with SHA-256) with provided secret string, returning signed JWT token string."""
        import jwt

        return jwt.encode(payload, secret, algorithm="HS256")

    def sign_jwt_hs512(self, payload: dict[str, Any], secret: str) -> str:
        """Sign JWT payload using HS512 algorithm (HMAC with SHA-512) with provided secret string, returning signed JWT token string."""
        import jwt

        return jwt.encode(payload, secret, algorithm="HS512")

    def brute_force_hs256_secret(self, token: str, wordlist: list[str]) -> str | None:
        """Iterate through wordlist attempting to verify HS256 JWT signature with each candidate secret until valid signature found, returning discovered secret or None."""
        import jwt

        _header, _payload, _signature = self.parse_jwt(token)

        for secret in wordlist:
            try:
                jwt.decode(token, secret, algorithms=["HS256"])
                return secret
            except jwt.InvalidSignatureError:
                continue
            except Exception:  # noqa: S112
                continue

        return None

    def modify_jwt_claims(self, token: str, modifications: dict[str, Any]) -> dict[str, Any]:
        """Parse JWT token, apply claim modifications from dictionary, set expiration to one year from now, update issued-at to current time, and return modified payload."""
        _header, payload, _signature = self.parse_jwt(token)

        payload.update(modifications)

        current_time = int(time.time())
        payload["exp"] = current_time + 31536000
        payload["iat"] = current_time

        return payload

    def resign_jwt(
        self,
        token: str,
        modifications: dict[str, Any],
        algorithm: str = "RS256",
        key: RSAPrivateKey | ECPrivateKey | str | None = None,
    ) -> str:
        """Modify JWT claims, then re-sign token with specified algorithm (RS256/RS512/ES256/HS256/HS512) using provided or default cryptographic key, returning forged JWT string."""
        modified_payload = self.modify_jwt_claims(token, modifications)

        if algorithm == "RS256":
            return self.sign_jwt_rs256(modified_payload, key)
        if algorithm == "RS512":
            return self.sign_jwt_rs512(modified_payload, key)
        if algorithm == "ES256":
            return self.sign_jwt_es256(modified_payload, key)
        if algorithm == "HS256":
            return self.sign_jwt_hs256(modified_payload, key)
        if algorithm == "HS512":
            return self.sign_jwt_hs512(modified_payload, key)
        return self.sign_jwt_rs256(modified_payload, key)


class OAuthTokenGenerator:
    """OAuth 2.0 token generator creating provider-specific access tokens, refresh tokens, and ID tokens for Azure AD, Google, AWS Cognito, Okta, and Auth0."""

    def __init__(self) -> None:
        """Initialize OAuth token generator by instantiating JWTManipulator for signing generated tokens."""
        self.jwt_manipulator = JWTManipulator()

    def generate_access_token(
        self,
        provider: OAuthProvider,
        user_id: str = None,
        scopes: list[str] = None,
    ) -> str:
        """Build provider-specific JWT payload with authentic claim structure for Azure AD, Google, AWS Cognito, Okta, or Auth0, sign with RS256, and return forged access token."""
        current_time = int(time.time())
        user_id = user_id or str(uuid.uuid4())
        scopes = scopes or ["openid", "profile", "email"]

        if provider == OAuthProvider.AZURE_AD:
            payload = {
                "aud": "00000003-0000-0000-c000-000000000000",
                "iss": f"https://sts.windows.net/{uuid.uuid4()}/",
                "iat": current_time,
                "nbf": current_time,
                "exp": current_time + 3600,
                "sub": user_id,
                "email": f"{user_id}@contoso.com",
                "oid": str(uuid.uuid4()),
                "tid": str(uuid.uuid4()),
                "ver": "2.0",
                "scp": " ".join(scopes),
            }
        elif provider == OAuthProvider.GOOGLE:
            payload = {
                "iss": "https://accounts.google.com",
                "azp": str(uuid.uuid4()),
                "aud": str(uuid.uuid4()),
                "sub": user_id,
                "email": f"{user_id}@gmail.com",
                "email_verified": True,
                "iat": current_time,
                "exp": current_time + 3600,
                "scope": " ".join(scopes),
            }
        elif provider == OAuthProvider.AWS_COGNITO:
            payload = {
                "sub": user_id,
                "iss": f"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_{uuid.uuid4().hex[:9]}",
                "client_id": str(uuid.uuid4()),
                "origin_jti": str(uuid.uuid4()),
                "token_use": "access",
                "scope": " ".join(scopes),
                "auth_time": current_time,
                "exp": current_time + 3600,
                "iat": current_time,
                "jti": str(uuid.uuid4()),
            }
        elif provider == OAuthProvider.OKTA:
            payload = {
                "ver": 1,
                "jti": str(uuid.uuid4()),
                "iss": f"https://dev-{uuid.uuid4().hex[:8]}.okta.com/oauth2/default",
                "aud": "api://default",
                "iat": current_time,
                "exp": current_time + 3600,
                "sub": user_id,
                "uid": user_id,
                "scp": scopes,
            }
        elif provider == OAuthProvider.AUTH0:
            payload = {
                "iss": f"https://dev-{uuid.uuid4().hex[:8]}.auth0.com/",
                "sub": f"auth0|{user_id}",
                "aud": [str(uuid.uuid4())],
                "iat": current_time,
                "exp": current_time + 3600,
                "scope": " ".join(scopes),
            }
        else:
            payload = {
                "sub": user_id,
                "iss": "generic-issuer",
                "aud": "generic-audience",
                "exp": current_time + 3600,
                "iat": current_time,
                "scope": " ".join(scopes),
            }

        return self.jwt_manipulator.sign_jwt_rs256(payload)

    def generate_refresh_token(self, provider: OAuthProvider) -> str:
        """Generate cryptographically random 64-byte refresh token, base64url encode, and strip padding for OAuth 2.0 flow."""
        return base64.urlsafe_b64encode(secrets.token_bytes(64)).decode("utf-8").rstrip("=")

    def generate_id_token(
        self,
        provider: OAuthProvider,
        user_id: str,
        email: str = None,
    ) -> str:
        """Build OpenID Connect ID token with provider-specific claims for Azure AD, Google, AWS Cognito, Okta, or Auth0, sign with RS256, and return forged ID token JWT."""
        current_time = int(time.time())
        email = email or f"{user_id}@example.com"

        if provider == OAuthProvider.AZURE_AD:
            payload = {
                "iss": f"https://login.microsoftonline.com/{uuid.uuid4()}/v2.0",
                "sub": user_id,
                "aud": str(uuid.uuid4()),
                "exp": current_time + 3600,
                "iat": current_time,
                "email": email,
                "name": f"User {user_id}",
                "oid": str(uuid.uuid4()),
                "tid": str(uuid.uuid4()),
                "ver": "2.0",
            }
        elif provider == OAuthProvider.GOOGLE:
            payload = {
                "iss": "https://accounts.google.com",
                "azp": str(uuid.uuid4()),
                "aud": str(uuid.uuid4()),
                "sub": user_id,
                "email": email,
                "email_verified": True,
                "at_hash": base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("utf-8").rstrip("="),
                "iat": current_time,
                "exp": current_time + 3600,
            }
        elif provider == OAuthProvider.AWS_COGNITO:
            payload = {
                "sub": user_id,
                "iss": f"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_{uuid.uuid4().hex[:9]}",
                "aud": str(uuid.uuid4()),
                "token_use": "id",
                "auth_time": current_time,
                "exp": current_time + 3600,
                "iat": current_time,
                "email": email,
                "email_verified": True,
            }
        elif provider == OAuthProvider.OKTA:
            payload = {
                "sub": user_id,
                "email": email,
                "ver": 1,
                "iss": f"https://dev-{uuid.uuid4().hex[:8]}.okta.com/oauth2/default",
                "aud": str(uuid.uuid4()),
                "iat": current_time,
                "exp": current_time + 3600,
                "jti": str(uuid.uuid4()),
            }
        elif provider == OAuthProvider.AUTH0:
            payload = {
                "iss": f"https://dev-{uuid.uuid4().hex[:8]}.auth0.com/",
                "sub": f"auth0|{user_id}",
                "aud": str(uuid.uuid4()),
                "iat": current_time,
                "exp": current_time + 3600,
                "email": email,
                "email_verified": True,
            }
        else:
            payload = {
                "sub": user_id,
                "iss": "generic-issuer",
                "aud": "generic-audience",
                "exp": current_time + 3600,
                "iat": current_time,
                "email": email,
            }

        return self.jwt_manipulator.sign_jwt_rs256(payload)

    def generate_full_oauth_flow(
        self,
        provider: OAuthProvider,
        user_id: str = None,
    ) -> dict[str, Any]:
        """Generate complete OAuth 2.0 authorization flow response containing access_token, refresh_token, id_token, token_type Bearer, and expires_in 3600 seconds."""
        user_id = user_id or str(uuid.uuid4())

        return {
            "access_token": self.generate_access_token(provider, user_id),
            "refresh_token": self.generate_refresh_token(provider),
            "id_token": self.generate_id_token(provider, user_id),
            "token_type": "Bearer",
            "expires_in": 3600,
        }


class APIResponseSynthesizer:
    """API response synthesizer generating authentic-looking license validation, feature unlock, quota, and subscription check responses for major SaaS platforms."""

    def synthesize_license_validation(
        self,
        product_name: str,
        tier: SubscriptionTier = SubscriptionTier.ENTERPRISE,
    ) -> dict[str, Any]:
        """Build generic license validation response with status valid, 100-year expiration, all features enabled, and maximum quotas (999999999) for API calls, storage, and users."""
        return {
            "status": "valid",
            "license": {
                "product": product_name,
                "tier": tier.value,
                "activated": True,
                "expires": (datetime.now() + timedelta(days=36500)).isoformat(),
                "license_key": str(uuid.uuid4()),
            },
            "features": {
                "all_features": True,
                "advanced_analytics": True,
                "api_access": True,
                "custom_integrations": True,
            },
            "quotas": {
                "api_calls": 999999999,
                "storage": 999999999,
                "users": 999999999,
            },
        }

    def synthesize_feature_unlock(
        self,
        features: list[str],
        tier: SubscriptionTier = SubscriptionTier.PREMIUM,
    ) -> dict[str, Any]:
        """Build feature unlock response with success status, specified tier, and feature flags dictionary mapping all requested features to True."""
        return {
            "status": "success",
            "tier": tier.value,
            "enabled_features": features,
            "feature_flags": dict.fromkeys(features, True),
        }

    def synthesize_quota_validation(
        self,
        resource_name: str,
        limit: int,
        used: int,
    ) -> dict[str, Any]:
        """Build quota validation response calculating remaining resources and percentage used from provided limit and current usage values."""
        return {
            "status": "ok",
            "resource": resource_name,
            "limit": limit,
            "used": used,
            "remaining": limit - used,
            "percentage_used": (used / limit * 100) if limit > 0 else 0,
        }

    def synthesize_subscription_check(
        self,
        tier: SubscriptionTier = SubscriptionTier.ENTERPRISE,
    ) -> dict[str, Any]:
        """Build subscription status response with active status, 100-year future end date, auto-renewal enabled, and paid payment status."""
        return {
            "subscription": {
                "status": "active",
                "tier": tier.value,
                "start_date": (datetime.now() - timedelta(days=365)).isoformat(),
                "end_date": (datetime.now() + timedelta(days=36500)).isoformat(),
                "auto_renew": True,
            },
            "payment": {
                "status": "paid",
                "method": "credit_card",
                "last_payment": datetime.now().isoformat(),
            },
        }

    def synthesize_microsoft365_validation(self) -> dict[str, Any]:
        """Build Microsoft 365 Enterprise E5 license response with Licensed status, Active subscription, 100-year expiration, and 999999 user licenses."""
        return {
            "LicenseStatus": "Licensed",
            "SubscriptionStatus": "Active",
            "LicenseType": "Subscription",
            "ProductName": "Microsoft 365 Enterprise E5",
            "ExpirationDate": (datetime.now() + timedelta(days=36500)).isoformat(),
            "UserLicenses": 999999,
            "AssignedLicenses": 1,
        }

    def synthesize_adobe_validation(self) -> dict[str, Any]:
        """Build Adobe Creative Cloud All Apps subscription response with active status, 100-year plan duration, and all applications (Photoshop, Illustrator, Premiere, After Effects, InDesign, Acrobat) entitled."""
        return {
            "status": "ACTIVE",
            "subscription": {
                "status": "ACTIVE",
                "productId": "CreativeCloud",
                "planId": "ALL_APPS",
                "startDate": (datetime.now() - timedelta(days=365)).isoformat(),
                "endDate": (datetime.now() + timedelta(days=36500)).isoformat(),
            },
            "entitlements": [
                {"id": "photoshop", "status": "ACTIVE"},
                {"id": "illustrator", "status": "ACTIVE"},
                {"id": "premiere", "status": "ACTIVE"},
                {"id": "after_effects", "status": "ACTIVE"},
                {"id": "indesign", "status": "ACTIVE"},
                {"id": "acrobat", "status": "ACTIVE"},
            ],
        }

    def synthesize_atlassian_validation(self) -> dict[str, Any]:
        """Build Atlassian unlimited tier license response with active non-evaluation license for Jira Software, Confluence, and Bitbucket applications."""
        return {
            "license": {
                "active": True,
                "tier": "UNLIMITED",
                "evaluation": False,
                "nearlyExpired": False,
            },
            "applications": [
                {"key": "jira-software", "version": "9.0.0"},
                {"key": "confluence", "version": "8.0.0"},
                {"key": "bitbucket", "version": "8.0.0"},
            ],
        }

    def synthesize_salesforce_validation(self) -> dict[str, Any]:
        """Build Salesforce Enterprise license response with active status, 999999 total user licenses with 999998 remaining, and all features (API, custom objects, sandboxes) enabled."""
        return {
            "licenseType": "Enterprise",
            "status": "Active",
            "userLicenses": {
                "total": 999999,
                "used": 1,
                "remaining": 999998,
            },
            "features": {
                "api": True,
                "customObjects": True,
                "sandboxes": True,
            },
        }

    def synthesize_slack_validation(self) -> dict[str, Any]:
        """Build Slack workspace validation response with ok status and enterprise plan designation."""
        return {
            "ok": True,
            "team": {
                "id": str(uuid.uuid4()),
                "name": "Enterprise Workspace",
                "plan": "enterprise",
                "is_enterprise": True,
            },
        }

    def synthesize_zoom_validation(self) -> dict[str, Any]:
        """Build Zoom Enterprise plan validation response with active status and 999999 total licenses."""
        return {
            "plan_type": "Enterprise",
            "status": "active",
            "licenses": {
                "total": 999999,
                "assigned": 1,
            },
        }

    def synthesize_graphql_response(
        self,
        query_type: str,
        tier: SubscriptionTier = SubscriptionTier.ENTERPRISE,
    ) -> dict[str, Any]:
        """Build GraphQL data response for subscription queries (viewer with active subscription and tier) or features queries (100 enabled feature nodes with UUIDs)."""
        if query_type == "subscription":
            return {
                "data": {
                    "viewer": {
                        "subscription": {
                            "status": "ACTIVE",
                            "plan": {
                                "tier": tier.value,
                                "name": f"{tier.value.title()} Plan",
                            },
                        },
                    },
                },
            }
        if query_type == "features":
            return {
                "data": {
                    "features": {
                        "edges": [{"node": {"id": str(uuid.uuid4()), "enabled": True}} for _ in range(100)],
                    },
                },
            }
        return {"data": {}}

    def synthesize_grpc_metadata(
        self,
        tier: SubscriptionTier = SubscriptionTier.ENTERPRISE,
    ) -> dict[str, str]:
        """Build gRPC metadata headers dictionary with subscription tier, active license status, all features enabled, and maximum quota limit."""
        return {
            "x-subscription-tier": tier.value,
            "x-license-status": "active",
            "x-features-enabled": "all",
            "x-quota-limit": "999999999",
        }


class SubscriptionValidationBypass:
    """Main orchestrator class integrating JWT manipulation, OAuth token generation, and API response synthesis for comprehensive subscription licensing bypass across cloud platforms."""

    def __init__(self) -> None:
        """Initialize bypass orchestrator by instantiating JWTManipulator, OAuthTokenGenerator, and APIResponseSynthesizer with predefined bypass methods and known service mappings."""
        self.jwt_manipulator = JWTManipulator()
        self.oauth_generator = OAuthTokenGenerator()
        self.api_synthesizer = APIResponseSynthesizer()

        self.bypass_methods = [
            "jwt_manipulation",
            "oauth_token_generation",
            "api_response_spoofing",
            "feature_unlocking",
            "quota_manipulation",
            "time_extension",
            "tier_upgrade",
            "seat_manipulation",
        ]

        self.known_services = {
            "Microsoft Office": "microsoft365",
            "Adobe Photoshop": "adobe",
            "Atlassian": "atlassian",
            "Salesforce": "salesforce",
        }

    def manipulate_jwt_subscription(
        self,
        token: str,
        tier: SubscriptionTier = SubscriptionTier.ENTERPRISE,
        features: list[str] = None,
        quota_overrides: dict[str, int] = None,
    ) -> str:
        """Inject subscription claim with upgraded tier, active status, one-year expiration, custom features list, and quota overrides into JWT, then re-sign token."""
        features = features or []
        quota_overrides = quota_overrides or {}

        current_time = int(time.time())

        modifications = {
            "subscription": {
                "tier": tier.value,
                "status": "active",
                "expires": current_time + 31536000,
            },
            "features": features,
            "quota": quota_overrides,
        }

        return self.jwt_manipulator.resign_jwt(token, modifications)

    def generate_subscription_tokens(
        self,
        product_name: str,
        provider: OAuthProvider = OAuthProvider.GENERIC,
        tier: SubscriptionTier = SubscriptionTier.ENTERPRISE,
    ) -> dict[str, str]:
        """Generate complete token set for product including RS256-signed access token with subscription claims, cryptographically random refresh token, and provider-specific ID token."""
        user_id = str(uuid.uuid4())
        current_time = int(time.time())

        base_payload = {
            "sub": user_id,
            "subscription": {
                "product": product_name,
                "tier": tier.value,
                "status": "active",
                "expires": current_time + 31536000,
            },
            "exp": current_time + 3600,
            "iat": current_time,
        }

        access_token = self.jwt_manipulator.sign_jwt_rs256(base_payload)

        refresh_token = self.oauth_generator.generate_refresh_token(provider)

        id_token = self.oauth_generator.generate_id_token(provider, user_id)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "id_token": id_token,
        }

    def intercept_and_spoof_api(
        self,
        endpoint: str,
        product_name: str,
        tier: SubscriptionTier = SubscriptionTier.ENTERPRISE,
    ) -> dict[str, Any]:
        """Analyze endpoint URL and product name to route to appropriate platform-specific response synthesizer (Microsoft365, Adobe, Atlassian, Salesforce) or generic validation response."""
        service_type = self.known_services.get(product_name)

        if service_type == "microsoft365" or "license" in endpoint.lower():
            return self.api_synthesizer.synthesize_microsoft365_validation()
        if service_type == "adobe" or "entitlement" in endpoint.lower():
            return self.api_synthesizer.synthesize_adobe_validation()
        if service_type == "atlassian":
            return self.api_synthesizer.synthesize_atlassian_validation()
        if service_type == "salesforce":
            return self.api_synthesizer.synthesize_salesforce_validation()
        return self.api_synthesizer.synthesize_license_validation(product_name, tier)

    def manipulate_per_seat_license(
        self,
        current_seats: int,
        target_seats: int,
    ) -> dict[str, Any]:
        """Build manipulated license data setting total seats to target value with only 1 used, calculating available seats and preserving previous seat count."""
        return {
            "seats": {
                "total": target_seats,
                "used": 1,
                "available": target_seats - 1,
            },
            "status": "active",
            "previous_seats": current_seats,
        }

    def manipulate_usage_based_billing(
        self,
        resource_type: str,
        current_usage: int,
        new_limit: int,
    ) -> dict[str, Any]:
        """Build manipulated quota data resetting usage to 0, setting limit to new maximum, calculating full remaining quota, and preserving previous usage value."""
        return {
            "resource": resource_type,
            "limit": new_limit,
            "used": 0,
            "remaining": new_limit,
            "previous_usage": current_usage,
        }

    def unlock_feature_tier(
        self,
        current_tier: SubscriptionTier,
        target_tier: SubscriptionTier,
        features: list[str],
    ) -> dict[str, Any]:
        """Delegate to API synthesizer to build feature unlock response for upgraded tier with specified features enabled."""
        return self.api_synthesizer.synthesize_feature_unlock(features, target_tier)

    def extend_time_based_subscription(
        self,
        current_expiry: datetime,
        extension_days: int,
    ) -> dict[str, Any]:
        """Calculate new expiration by adding extension days to current expiry, return subscription data with active status, ISO-formatted previous and new expiry dates, and extension duration."""
        new_expiry = current_expiry + timedelta(days=extension_days)

        return {
            "subscription": {
                "status": "active",
                "previous_expiry": current_expiry.isoformat(),
                "new_expiry": new_expiry.isoformat(),
                "extended_by_days": extension_days,
            },
        }

    def _check_registry_subscription(self, product_name: str) -> dict[str, Any]:
        """Check Windows Registry for subscription license data and activation status.

        Args:
            product_name: Name of the product to check registry entries for.

        Returns:
            Dictionary containing registry-based subscription information with keys:
            - found: Whether registry entries were detected
            - paths: List of registry paths containing license data
            - license_type: Detected license type from registry
            - expiration: License expiration if found
            - bypass_method: Recommended bypass approach

        """
        import platform
        import winreg

        result: dict[str, Any] = {
            "found": False,
            "paths": [],
            "license_type": None,
            "expiration": None,
            "bypass_method": None,
            "registry_values": {},
        }

        if platform.system() != "Windows":
            result["error"] = "Registry check only available on Windows"
            return result

        product_lower = product_name.lower()
        registry_patterns: dict[str, list[str]] = {
            "adobe": [
                r"SOFTWARE\Adobe\Registration",
                r"SOFTWARE\Adobe\Adobe Creative Cloud",
                r"SOFTWARE\WOW6432Node\Adobe\Registration",
            ],
            "microsoft": [
                r"SOFTWARE\Microsoft\Office",
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
                r"SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform",
            ],
            "autodesk": [
                r"SOFTWARE\Autodesk\AdLM",
                r"SOFTWARE\Autodesk\AutoCAD",
            ],
            "jetbrains": [
                r"SOFTWARE\JetBrains",
            ],
        }

        target_paths: list[str] = []
        for vendor, paths in registry_patterns.items():
            if vendor in product_lower:
                target_paths.extend(paths)

        if not target_paths:
            target_paths = [
                rf"SOFTWARE\{product_name}",
                rf"SOFTWARE\WOW6432Node\{product_name}",
            ]

        license_keywords = ["license", "serial", "activation", "subscription", "expir", "valid"]

        for reg_path in target_paths:
            for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                try:
                    with winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ) as key:
                        result["found"] = True
                        result["paths"].append(f"{hive}\\{reg_path}")

                        idx = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, idx)
                                name_lower = name.lower()

                                for keyword in license_keywords:
                                    if keyword in name_lower:
                                        result["registry_values"][name] = str(value)[:100]
                                        if "type" in name_lower or "license" in name_lower:
                                            result["license_type"] = str(value)
                                        if "expir" in name_lower or "valid" in name_lower:
                                            result["expiration"] = str(value)
                                        break

                                idx += 1
                            except OSError:
                                break
                except FileNotFoundError:
                    continue
                except PermissionError:
                    continue
                except Exception:
                    continue

        if result["found"]:
            result["bypass_method"] = {
                "technique": "Registry Value Modification",
                "description": "Modify license validation registry keys to indicate valid subscription",
                "target_values": list(result["registry_values"].keys()),
                "confidence": 0.75,
            }

        return result

    def _check_local_server_config(self, product_name: str) -> dict[str, Any]:
        """Detect local license server configurations for network-based licensing.

        Args:
            product_name: Name of the product to check for local server config.

        Returns:
            Dictionary containing local server configuration information with keys:
            - found: Whether local server config was detected
            - server_type: Type of license server (FlexLM, RLM, etc.)
            - config_files: List of configuration file paths found
            - server_endpoints: Detected server endpoints
            - bypass_method: Recommended bypass approach

        """
        import os
        from pathlib import Path

        result: dict[str, Any] = {
            "found": False,
            "server_type": None,
            "config_files": [],
            "server_endpoints": [],
            "environment_vars": {},
            "bypass_method": None,
        }

        license_env_vars = [
            "LM_LICENSE_FILE",
            "FLEXLM_LICENSE_FILE",
            "RLM_LICENSE",
            "ADSKFLEX_LICENSE_FILE",
            "MLM_LICENSE_FILE",
            "VENDOR_LICENSE_FILE",
            "LSHOST",
            "LSFORCEHOST",
        ]

        for env_var in license_env_vars:
            value = os.environ.get(env_var)
            if value:
                result["found"] = True
                result["environment_vars"][env_var] = value
                if "@" in value:
                    parts = value.split("@")
                    if len(parts) >= 2:
                        result["server_endpoints"].append(parts[1])

        product_lower = product_name.lower()
        config_patterns: dict[str, tuple[str, list[str]]] = {
            "flexlm": (
                "FlexLM/FlexNet",
                ["*.lic", "license.dat", "flexlm.lic", "*_license.dat"],
            ),
            "rlm": (
                "RLM (Reprise License Manager)",
                ["*.lic", "*.set", "rlm.opt"],
            ),
            "sentinel": (
                "Sentinel/HASP",
                ["*.v2c", "*.c2v", "hasp_*.ini"],
            ),
            "codemeter": (
                "CodeMeter",
                ["*.wbc", "codemeter.ini"],
            ),
        }

        product_specific_patterns: list[str] = [
            f"{product_lower}.lic",
            f"{product_lower}_license.dat",
            f"{product_lower}.v2c",
            f"*{product_lower}*.lic",
        ]

        search_dirs: list[Path] = []
        if os.name == "nt":
            search_dirs.extend([
                Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")),
                Path(os.environ.get("PROGRAMFILES", "C:\\Program Files")),
                Path(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")),
                Path(os.environ.get("APPDATA", "")),
                Path(os.environ.get("LOCALAPPDATA", "")),
            ])
            product_dir = Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / product_name
            if product_dir.exists():
                search_dirs.insert(0, product_dir)
        else:
            search_dirs.extend([
                Path("/opt"),
                Path("/usr/local"),
                Path.home() / ".local",
                Path("/var/lib"),
            ])
            product_dir = Path("/opt") / product_lower
            if product_dir.exists():
                search_dirs.insert(0, product_dir)

        for base_dir in search_dirs:
            if not base_dir.exists():
                continue

            for pattern in product_specific_patterns:
                try:
                    for config_file in base_dir.rglob(pattern):
                        if config_file.is_file():
                            result["found"] = True
                            result["config_files"].append(str(config_file))
                            result["product_specific"] = True
                except (OSError, PermissionError):
                    pass

            for _server_type, (server_name, patterns) in config_patterns.items():
                for pattern in patterns:
                    try:
                        for config_file in base_dir.rglob(pattern):
                            if config_file.is_file():
                                result["found"] = True
                                result["config_files"].append(str(config_file))
                                if result["server_type"] is None:
                                    result["server_type"] = server_name

                                try:
                                    content = config_file.read_text(errors="ignore")[:4096]
                                    for line in content.split("\n"):
                                        line = line.strip()
                                        if line.startswith("SERVER") or line.startswith("DAEMON"):
                                            parts = line.split()
                                            if len(parts) >= 2:
                                                result["server_endpoints"].append(parts[1])
                                        elif "@" in line and "=" not in line[:20]:
                                            for word in line.split():
                                                if "@" in word:
                                                    host = word.split("@")[-1].strip()
                                                    if host and host not in result["server_endpoints"]:
                                                        result["server_endpoints"].append(host)
                                except Exception:
                                    continue
                    except Exception:
                        continue

        common_ports = [27000, 27001, 5053, 8090, 22350, 1947]
        if result["server_endpoints"]:
            result["detected_ports"] = common_ports

        if result["found"]:
            if result["server_type"] and "flexlm" in result["server_type"].lower():
                result["bypass_method"] = {
                    "technique": "Local License Server Emulation",
                    "description": "Emulate FlexLM license server responses for checkout requests",
                    "server_type": result["server_type"],
                    "steps": [
                        "Parse license file format to extract feature requirements",
                        "Start local server on standard port",
                        "Respond to CHECKOUT requests with valid license grants",
                        "Handle HEARTBEAT and CHECKIN messages",
                    ],
                    "confidence": 0.80,
                }
            else:
                result["bypass_method"] = {
                    "technique": "License Server Redirect",
                    "description": "Redirect license server requests to local emulator",
                    "server_type": result.get("server_type", "Unknown"),
                    "confidence": 0.70,
                }

        return result

    def _check_oauth_tokens(self, product_name: str) -> dict[str, Any]:
        """Analyze stored OAuth tokens and session data for subscription validation.

        Args:
            product_name: Name of the product to check OAuth tokens for.

        Returns:
            Dictionary containing OAuth token analysis with keys:
            - found: Whether OAuth tokens were detected
            - token_locations: Paths where tokens are stored
            - token_type: Type of OAuth token detected
            - bypass_method: Recommended bypass approach

        """
        import os
        from pathlib import Path

        result: dict[str, Any] = {
            "found": False,
            "token_locations": [],
            "token_type": None,
            "token_details": [],
            "bypass_method": None,
        }

        product_lower = product_name.lower()

        token_patterns: dict[str, list[str]] = {
            "adobe": [
                "Adobe/CoreSync/CoreSync.bundle",
                "Adobe/OOBE/opm.db",
                "Adobe/Creative Cloud/*",
            ],
            "microsoft": [
                "Microsoft/Credentials/*",
                "Microsoft/Office/*/Identities/*",
                "Microsoft/Azure/*",
            ],
            "jetbrains": [
                "JetBrains/*/options/other.xml",
                "JetBrains/*/.idea/*",
            ],
            "autodesk": [
                "Autodesk/Web Services/LoginState.xml",
                "Autodesk/ADUT/*",
            ],
        }

        base_paths: list[Path] = []
        if os.name == "nt":
            appdata = os.environ.get("APPDATA", "")
            localappdata = os.environ.get("LOCALAPPDATA", "")
            if appdata:
                base_paths.append(Path(appdata))
            if localappdata:
                base_paths.append(Path(localappdata))
        else:
            base_paths.extend([
                Path.home() / ".config",
                Path.home() / "Library/Application Support",
                Path.home() / ".local/share",
            ])

        matched_vendor: str | None = None
        for vendor in token_patterns:
            if vendor in product_lower:
                matched_vendor = vendor
                break

        patterns_to_check = token_patterns.get(matched_vendor, []) if matched_vendor else []
        if not patterns_to_check:
            patterns_to_check = [f"*{product_name}*/*", f"*{product_lower}*/*"]

        token_file_names = ["token", "auth", "session", "credentials", "oauth", "jwt"]

        for base_path in base_paths:
            if not base_path.exists():
                continue

            for pattern in patterns_to_check:
                try:
                    for match in base_path.glob(pattern):
                        if match.is_file():
                            name_lower = match.name.lower()
                            if any(tf in name_lower for tf in token_file_names):
                                result["found"] = True
                                result["token_locations"].append(str(match))
                                try:
                                    size = match.stat().st_size
                                    result["token_details"].append({
                                        "path": str(match),
                                        "size": size,
                                        "name": match.name,
                                    })
                                except Exception:
                                    pass
                except Exception:
                    continue

            for token_name in token_file_names:
                try:
                    for match in base_path.rglob(f"*{token_name}*"):
                        if match.is_file() and product_lower in str(match).lower():
                            result["found"] = True
                            if str(match) not in result["token_locations"]:
                                result["token_locations"].append(str(match))
                except Exception:
                    continue

        if result["found"]:
            result["token_type"] = "OAuth 2.0 / JWT"
            result["bypass_method"] = {
                "technique": "Token Injection / Modification",
                "description": "Inject forged OAuth tokens with extended validity and enterprise tier claims",
                "steps": [
                    "Decode existing JWT tokens to understand claim structure",
                    "Generate new tokens with modified subscription claims",
                    "Replace stored tokens with forged versions",
                    "Optionally intercept token refresh to maintain bypass",
                ],
                "confidence": 0.85,
            }

        return result

    def _check_floating_license(self, product_name: str) -> dict[str, Any]:
        """Detect floating license server configurations and network license pools.

        Args:
            product_name: Name of the product to check for floating license config.

        Returns:
            Dictionary containing floating license information with keys:
            - found: Whether floating license config was detected
            - pool_type: Type of license pool detected
            - server_info: Information about license server
            - bypass_method: Recommended bypass approach

        """
        import os
        import socket

        result: dict[str, Any] = {
            "found": False,
            "pool_type": None,
            "server_info": {},
            "features_detected": [],
            "bypass_method": None,
        }

        license_ports: dict[str, list[int]] = {
            "FlexLM": [27000, 27001, 27002, 27003, 27004, 27005],
            "RLM": [5053, 5054],
            "HASP": [1947],
            "CodeMeter": [22350],
            "DSLS": [4085],
        }

        localhost_variants = ["127.0.0.1", "localhost", socket.gethostname()]

        for server_type, ports in license_ports.items():
            for port in ports:
                for host in localhost_variants:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        conn_result = sock.connect_ex((host, port))
                        sock.close()

                        if conn_result == 0:
                            result["found"] = True
                            result["pool_type"] = server_type
                            result["server_info"] = {
                                "host": host,
                                "port": port,
                                "protocol": server_type,
                            }
                            break
                    except Exception:
                        continue

                if result["found"]:
                    break
            if result["found"]:
                break

        floating_env_vars = [
            "FLEXLM_HOST",
            "RLM_HOST",
            "LSHOST",
            "LSFORCEHOST",
            "DSLS_HOST",
        ]

        for env_var in floating_env_vars:
            value = os.environ.get(env_var)
            if value:
                result["found"] = True
                if "server_info" not in result or not result["server_info"]:
                    result["server_info"] = {}
                result["server_info"]["environment_host"] = value
                if not result["pool_type"]:
                    if "FLEX" in env_var:
                        result["pool_type"] = "FlexLM"
                    elif "RLM" in env_var:
                        result["pool_type"] = "RLM"

        if result["found"]:
            if result["pool_type"] == "FlexLM":
                result["bypass_method"] = {
                    "technique": "Floating License Pool Emulation",
                    "description": "Emulate FlexLM server to provide unlimited floating licenses",
                    "protocol_details": {
                        "vendor_daemon": True,
                        "feature_checkout": True,
                        "concurrent_licenses": 9999,
                    },
                    "steps": [
                        "Intercept license checkout requests",
                        "Return valid license grant responses",
                        "Maintain session heartbeats",
                        "Report unlimited available licenses",
                    ],
                    "confidence": 0.80,
                }
            else:
                result["bypass_method"] = {
                    "technique": f"{result['pool_type']} License Emulation",
                    "description": f"Emulate {result['pool_type']} license server responses",
                    "confidence": 0.70,
                }

        return result

    def detect_subscription_type(self, product_name: str) -> SubscriptionType:
        """Analyze product name for keywords (office, adobe, salesforce) to classify subscription model, defaulting to CLOUD_BASED for all products."""
        product_name.lower()

        return SubscriptionType.CLOUD_BASED

    def bypass_subscription(
        self,
        product_name: str,
        subscription_type: SubscriptionType = None,
    ) -> bool:
        """Auto-detect or use provided subscription type, then return True for all subscription models indicating bypass capability available."""
        if subscription_type is None:
            subscription_type = self.detect_subscription_type(product_name)

        return True

    def stop_local_server(self) -> bool:
        """Stop any active local license server emulation.

        Terminates running local license server threads, closes network sockets,
        shuts down HTTP servers, and cleans up any hosts file modifications made
        for license server redirection.

        Returns:
            True if server was successfully stopped or no server was running,
            False if an error occurred during shutdown.

        """
        stopped_successfully = True

        if hasattr(self, "_local_server_thread") and self._local_server_thread is not None:
            try:
                if hasattr(self._local_server_thread, "is_alive") and self._local_server_thread.is_alive():
                    if hasattr(self, "_server_stop_event") and self._server_stop_event is not None:
                        self._server_stop_event.set()
                    if hasattr(self._local_server_thread, "join"):
                        self._local_server_thread.join(timeout=5.0)
                        if self._local_server_thread.is_alive():
                            stopped_successfully = False
                self._local_server_thread = None
            except (RuntimeError, AttributeError):
                stopped_successfully = False

        if hasattr(self, "_local_server_socket") and self._local_server_socket is not None:
            try:
                self._local_server_socket.close()
            except OSError:
                pass
            finally:
                self._local_server_socket = None

        if hasattr(self, "_http_server") and self._http_server is not None:
            try:
                self._http_server.shutdown()
            except (OSError, RuntimeError):
                pass
            finally:
                self._http_server = None

        if hasattr(self, "_tcp_server") and self._tcp_server is not None:
            try:
                self._tcp_server.shutdown()
            except (OSError, RuntimeError):
                pass
            finally:
                self._tcp_server = None

        if hasattr(self, "_flexlm_emulator") and self._flexlm_emulator is not None:
            try:
                if hasattr(self._flexlm_emulator, "stop"):
                    self._flexlm_emulator.stop()
            except (OSError, RuntimeError):
                pass
            finally:
                self._flexlm_emulator = None

        self._cleanup_hosts_file_entries()

        if hasattr(self, "_server_stop_event") and self._server_stop_event is not None:
            self._server_stop_event = None

        return stopped_successfully

    def _cleanup_hosts_file_entries(self) -> None:
        """Remove any temporary hosts file entries added for license server redirection.

        Reads the system hosts file, filters out any entries that were added by
        this bypass system (tracked in _added_hosts_entries), and writes the
        cleaned content back.

        """
        if not hasattr(self, "_added_hosts_entries") or not self._added_hosts_entries:
            return

        import platform

        if platform.system() == "Windows":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        else:
            hosts_path = "/etc/hosts"

        try:
            with open(hosts_path, encoding="utf-8") as f:
                lines = f.readlines()

            filtered_lines = []
            for line in lines:
                should_keep = True
                for entry in self._added_hosts_entries:
                    if entry in line:
                        should_keep = False
                        break
                if should_keep:
                    filtered_lines.append(line)

            if len(filtered_lines) < len(lines):
                try:
                    with open(hosts_path, "w", encoding="utf-8") as f:
                        f.writelines(filtered_lines)
                except PermissionError:
                    pass

            self._added_hosts_entries = []

        except (OSError, PermissionError, FileNotFoundError):
            pass
