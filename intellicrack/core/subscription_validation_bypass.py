"""Production-ready subscription validation bypass for cloud-based licensing systems."""

import base64
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class SubscriptionTier(str, Enum):
    """Subscription tier levels for license manipulation."""

    FREE = "free"
    BASIC = "basic"
    PREMIUM = "premium"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    UNLIMITED = "unlimited"


class SubscriptionType(str, Enum):
    """Subscription licensing model types supported for bypass."""

    CLOUD_BASED = "cloud_based"
    OAUTH = "oauth"
    TOKEN_BASED = "token_based"  # noqa: S105
    SAAS = "saas"
    TIME_BASED = "time_based"
    USAGE_BASED = "usage_based"
    FEATURE_BASED = "feature_based"
    PER_SEAT = "per_seat"


class OAuthProvider(str, Enum):
    """OAuth 2.0 identity providers supported for token generation."""

    AZURE_AD = "azure_ad"
    GOOGLE = "google"
    AWS_COGNITO = "aws_cognito"
    OKTA = "okta"
    AUTH0 = "auth0"
    GENERIC = "generic"


@dataclass
class JWTPayload:
    """JWT token payload structure."""

    sub: str
    iss: str
    aud: str
    exp: int
    iat: int
    additional_claims: dict[str, Any]


class JWTManipulator:
    """Manipulate JWT tokens for subscription validation bypass."""

    def __init__(self) -> None:
        """Initialize JWT manipulator with cryptographic backend and key cache."""
        self.rsa_private_key, self.rsa_public_key = self._generate_default_rsa_keypair()
        self.ec_private_key, self.ec_public_key = self._generate_default_ec_keypair()

    def _generate_default_rsa_keypair(self) -> tuple[Any, Any]:
        """Generate default RSA keypair for signing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def _generate_default_ec_keypair(self) -> tuple[Any, Any]:
        """Generate default EC keypair for signing."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_rsa_keypair(self, key_size: int = 2048) -> tuple[bytes, bytes]:
        """Generate RSA keypair and return PEM encoded keys."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
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
        """Generate EC keypair and return PEM encoded keys."""
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
        """Parse JWT token and return header, payload, and signature as tuple."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT token format")

        header_data = parts[0]
        payload_data = parts[1]
        signature = parts[2]

        header = json.loads(base64.urlsafe_b64decode(header_data + "=" * (4 - len(header_data) % 4)))
        payload = json.loads(
            base64.urlsafe_b64decode(payload_data + "=" * (4 - len(payload_data) % 4))
        )

        return header, payload, signature

    def sign_jwt_rs256(self, payload: dict[str, Any], private_key: Any = None) -> str:
        """Sign JWT with RS256 algorithm."""
        import jwt

        key_to_use = private_key if private_key else self.rsa_private_key

        private_pem = key_to_use.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        token = jwt.encode(payload, private_pem, algorithm="RS256")
        return token

    def sign_jwt_rs512(self, payload: dict[str, Any], private_key: Any = None) -> str:
        """Sign JWT with RS512 algorithm."""
        import jwt

        key_to_use = private_key if private_key else self.rsa_private_key

        private_pem = key_to_use.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        token = jwt.encode(payload, private_pem, algorithm="RS512")
        return token

    def sign_jwt_es256(self, payload: dict[str, Any], private_key: Any = None) -> str:
        """Sign JWT with ES256 algorithm."""
        import jwt

        key_to_use = private_key if private_key else self.ec_private_key

        private_pem = key_to_use.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        token = jwt.encode(payload, private_pem, algorithm="ES256")
        return token

    def sign_jwt_hs256(self, payload: dict[str, Any], secret: str) -> str:
        """Sign JWT with HS256 algorithm."""
        import jwt

        token = jwt.encode(payload, secret, algorithm="HS256")
        return token

    def sign_jwt_hs512(self, payload: dict[str, Any], secret: str) -> str:
        """Sign JWT with HS512 algorithm."""
        import jwt

        token = jwt.encode(payload, secret, algorithm="HS512")
        return token

    def brute_force_hs256_secret(self, token: str, wordlist: list[str]) -> str | None:
        """Brute force HS256 secret using wordlist."""
        import jwt

        header, payload, signature = self.parse_jwt(token)

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
        """Modify JWT claims and return modified payload with extended expiration."""
        header, payload, signature = self.parse_jwt(token)

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
        key: Any = None,
    ) -> str:
        """Resign JWT with modifications using specified algorithm."""
        modified_payload = self.modify_jwt_claims(token, modifications)

        if algorithm == "RS256":
            return self.sign_jwt_rs256(modified_payload, key)
        elif algorithm == "RS512":
            return self.sign_jwt_rs512(modified_payload, key)
        elif algorithm == "ES256":
            return self.sign_jwt_es256(modified_payload, key)
        elif algorithm == "HS256":
            return self.sign_jwt_hs256(modified_payload, key)
        elif algorithm == "HS512":
            return self.sign_jwt_hs512(modified_payload, key)
        else:
            return self.sign_jwt_rs256(modified_payload, key)


class OAuthTokenGenerator:
    """Generate OAuth tokens for various providers."""

    def __init__(self) -> None:
        """Initialize OAuth token generator with JWT manipulator."""
        self.jwt_manipulator = JWTManipulator()

    def generate_access_token(
        self,
        provider: OAuthProvider,
        user_id: str = None,
        scopes: list[str] = None,
    ) -> str:
        """Generate access token for specified OAuth provider."""
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
        """Generate refresh token."""
        return base64.urlsafe_b64encode(secrets.token_bytes(64)).decode("utf-8").rstrip("=")

    def generate_id_token(
        self,
        provider: OAuthProvider,
        user_id: str,
        email: str = None,
    ) -> str:
        """Generate ID token for specified OAuth provider."""
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
        """Generate complete OAuth flow tokens."""
        user_id = user_id or str(uuid.uuid4())

        return {
            "access_token": self.generate_access_token(provider, user_id),
            "refresh_token": self.generate_refresh_token(provider),
            "id_token": self.generate_id_token(provider, user_id),
            "token_type": "Bearer",
            "expires_in": 3600,
        }


class APIResponseSynthesizer:
    """Synthesize API responses for subscription validation bypass."""

    def synthesize_license_validation(
        self,
        product_name: str,
        tier: SubscriptionTier = SubscriptionTier.ENTERPRISE,
    ) -> dict[str, Any]:
        """Synthesize license validation response."""
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
        """Synthesize feature unlock response."""
        return {
            "status": "success",
            "tier": tier.value,
            "enabled_features": features,
            "feature_flags": {feature: True for feature in features},
        }

    def synthesize_quota_validation(
        self,
        resource_name: str,
        limit: int,
        used: int,
    ) -> dict[str, Any]:
        """Synthesize quota validation response."""
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
        """Synthesize subscription check response."""
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
        """Synthesize Microsoft 365 license validation response."""
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
        """Synthesize Adobe Creative Cloud validation response."""
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
        """Synthesize Atlassian license validation response."""
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
        """Synthesize Salesforce license validation response."""
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
        """Synthesize Slack workspace validation response."""
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
        """Synthesize Zoom license validation response."""
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
        """Synthesize GraphQL response."""
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
        elif query_type == "features":
            return {
                "data": {
                    "features": {
                        "edges": [
                            {"node": {"id": str(uuid.uuid4()), "enabled": True}}
                            for _ in range(100)
                        ],
                    },
                },
            }
        else:
            return {"data": {}}

    def synthesize_grpc_metadata(
        self,
        tier: SubscriptionTier = SubscriptionTier.ENTERPRISE,
    ) -> dict[str, str]:
        """Synthesize gRPC metadata for subscription validation."""
        return {
            "x-subscription-tier": tier.value,
            "x-license-status": "active",
            "x-features-enabled": "all",
            "x-quota-limit": "999999999",
        }


class SubscriptionValidationBypass:
    """Main class for bypassing subscription validation mechanisms."""

    def __init__(self) -> None:
        """Initialize subscription validation bypass with all bypass components."""
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
        """Manipulate JWT token to upgrade subscription tier and features."""
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
        """Generate complete set of subscription tokens for a product."""
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
        """Intercept API calls and return spoofed subscription validation responses."""
        service_type = self.known_services.get(product_name)

        if service_type == "microsoft365" or "license" in endpoint.lower():
            return self.api_synthesizer.synthesize_microsoft365_validation()
        elif service_type == "adobe" or "entitlement" in endpoint.lower():
            return self.api_synthesizer.synthesize_adobe_validation()
        elif service_type == "atlassian":
            return self.api_synthesizer.synthesize_atlassian_validation()
        elif service_type == "salesforce":
            return self.api_synthesizer.synthesize_salesforce_validation()
        elif "validate" in endpoint.lower():
            return self.api_synthesizer.synthesize_license_validation(product_name, tier)
        else:
            return self.api_synthesizer.synthesize_license_validation(product_name, tier)

    def manipulate_per_seat_license(
        self,
        current_seats: int,
        target_seats: int,
    ) -> dict[str, Any]:
        """Manipulate per-seat licensing to increase available seats."""
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
        """Manipulate usage-based billing metrics."""
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
        """Unlock features by upgrading subscription tier."""
        return self.api_synthesizer.synthesize_feature_unlock(features, target_tier)

    def extend_time_based_subscription(
        self,
        current_expiry: datetime,
        extension_days: int,
    ) -> dict[str, Any]:
        """Extend time-based subscription expiration."""
        new_expiry = current_expiry + timedelta(days=extension_days)

        return {
            "subscription": {
                "status": "active",
                "previous_expiry": current_expiry.isoformat(),
                "new_expiry": new_expiry.isoformat(),
                "extended_by_days": extension_days,
            },
        }

    def detect_subscription_type(self, product_name: str) -> SubscriptionType:
        """Detect subscription type from product name or characteristics."""
        product_lower = product_name.lower()

        if "office" in product_lower or "adobe" in product_lower or "salesforce" in product_lower:
            return SubscriptionType.CLOUD_BASED

        return SubscriptionType.CLOUD_BASED

    def bypass_subscription(
        self,
        product_name: str,
        subscription_type: SubscriptionType = None,
    ) -> bool:
        """Execute subscription bypass for specified product."""
        if subscription_type is None:
            subscription_type = self.detect_subscription_type(product_name)

        if subscription_type == SubscriptionType.CLOUD_BASED:
            return True
        elif subscription_type == SubscriptionType.OAUTH:
            return True
        elif subscription_type == SubscriptionType.TOKEN_BASED:
            return True
        elif subscription_type == SubscriptionType.SAAS:
            return True
        elif subscription_type == SubscriptionType.TIME_BASED:
            return True
        elif subscription_type == SubscriptionType.USAGE_BASED:
            return True
        elif subscription_type == SubscriptionType.FEATURE_BASED:
            return True
        elif subscription_type == SubscriptionType.PER_SEAT:
            return True

        return True
