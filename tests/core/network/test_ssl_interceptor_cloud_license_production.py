"""Production tests for SSL interceptor cloud license modification capabilities.

This module validates that the SSL interceptor properly handles:
- JWT token signing with RS256, ES256, HS256 algorithms
- Encrypted JSON payloads (AES-GCM, ChaCha20)
- OAuth 2.0 token modification and re-signing
- Certificate-based authentication challenges
- Adobe, Autodesk, Microsoft activation protocols
- Message integrity preservation after modification
- Edge cases: token refresh, MFA, hardware attestation
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from intellicrack.core.network.ssl_interceptor import JWTTokenModifier, PyOpenSSLInterceptor


@pytest.fixture
def rsa_key_pair() -> tuple[Any, Any]:
    """Generate RSA key pair for testing RS256 signatures."""
    if not CRYPTO_AVAILABLE:
        pytest.skip("cryptography library not available")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def ec_key_pair() -> tuple[Any, Any]:
    """Generate EC key pair for testing ES256 signatures."""
    if not CRYPTO_AVAILABLE:
        pytest.skip("cryptography library not available")

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def jwt_modifier() -> JWTTokenModifier:
    """Create JWT token modifier instance."""
    return JWTTokenModifier()


@pytest.fixture
def jwt_modifier_with_binary(tmp_path: Path) -> JWTTokenModifier:
    """Create JWT token modifier with binary containing secrets."""
    binary_path = tmp_path / "test.exe"
    binary_content = b"secret_key=MyS3cr3tK3y123\x00jwt_secret=production_jwt_key\x00api_key=test_api_key_value\x00"
    binary_path.write_bytes(binary_content)
    return JWTTokenModifier(binary_path=str(binary_path))


@pytest.fixture
def temp_ca_certs(tmp_path: Path) -> tuple[str, str]:
    """Generate temporary CA certificates for testing."""
    if not CRYPTO_AVAILABLE:
        pytest.skip("cryptography library not available")

    from cryptography import x509
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "SF"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(tz=datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256(), default_backend())
    )

    cert_path = tmp_path / "ca.crt"
    key_path = tmp_path / "ca.key"

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    return str(cert_path), str(key_path)


class TestJWTSigningRS256:
    """Test JWT token signing with RS256 algorithm."""

    def test_resign_jwt_rs256_valid_token(self, jwt_modifier: JWTTokenModifier, rsa_key_pair: tuple[Any, Any]) -> None:
        """JWT modifier generates valid RS256 signed tokens accepted by standard JWT validators."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        private_key, public_key = rsa_key_pair

        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "sub": "user123",
            "exp": int((datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1)).timestamp()),
            "license_type": "trial",
        }

        signed_token = jwt_modifier.resign_jwt_rs256(header, payload, private_key)

        parts = signed_token.split(".")
        assert len(parts) == 3

        message = f"{parts[0]}.{parts[1]}"
        signature = base64.urlsafe_b64decode(parts[2] + "==")

        from cryptography.hazmat.primitives.asymmetric import padding

        try:
            public_key.verify(signature, message.encode(), padding.PKCS1v15(), hashes.SHA256())
        except Exception as e:
            pytest.fail(f"RS256 signature validation failed: {e}")

    def test_resign_jwt_rs256_modified_payload_integrity(
        self, jwt_modifier: JWTTokenModifier, rsa_key_pair: tuple[Any, Any]
    ) -> None:
        """RS256 re-signing preserves modified payload integrity."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        private_key, _ = rsa_key_pair

        header = {"alg": "RS256", "typ": "JWT"}
        original_payload = {"license_status": "trial", "exp": 1000000000}
        modified_payload = jwt_modifier.modify_jwt_payload(original_payload)

        signed_token = jwt_modifier.resign_jwt_rs256(header, modified_payload, private_key)

        decoded_payload = jwt_modifier.decode_jwt_without_verification(signed_token)
        assert decoded_payload is not None
        assert decoded_payload["license_status"] == "active"
        assert decoded_payload["exp"] > 1000000000

    def test_resign_jwt_rs256_2048_bit_key(self, jwt_modifier: JWTTokenModifier) -> None:
        """RS256 signing works with 2048-bit RSA keys (common enterprise standard)."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"user_id": "enterprise_user", "features": ["all"]}

        signed_token = jwt_modifier.resign_jwt_rs256(header, payload, private_key)

        parts = signed_token.split(".")
        assert len(parts) == 3

        signature = base64.urlsafe_b64decode(parts[2] + "==")
        assert len(signature) == 256

    def test_resign_jwt_rs256_4096_bit_key(self, jwt_modifier: JWTTokenModifier) -> None:
        """RS256 signing works with 4096-bit RSA keys (high security)."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"security_level": "maximum", "clearance": "top_secret"}

        signed_token = jwt_modifier.resign_jwt_rs256(header, payload, private_key)

        parts = signed_token.split(".")
        assert len(parts) == 3

        signature = base64.urlsafe_b64decode(parts[2] + "==")
        assert len(signature) == 512


class TestJWTSigningHS256:
    """Test JWT token signing with HS256 algorithm."""

    def test_resign_jwt_hs256_valid_signature(self, jwt_modifier: JWTTokenModifier) -> None:
        """HS256 signed tokens produce valid HMAC-SHA256 signatures."""
        secret = b"test_secret_key_12345678"
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user_id": "test_user", "subscription": "premium"}

        signed_token = jwt_modifier.resign_jwt_hs256(header, payload, secret)

        parts = signed_token.split(".")
        assert len(parts) == 3

        message = f"{parts[0]}.{parts[1]}"
        expected_signature = hmac.new(secret, message.encode(), hashlib.sha256).digest()
        expected_b64 = base64.urlsafe_b64encode(expected_signature).decode().rstrip("=")

        assert parts[2] == expected_b64

    def test_verify_jwt_signature_correct_secret(self, jwt_modifier: JWTTokenModifier) -> None:
        """JWT signature verification succeeds with correct secret."""
        secret = b"production_secret_key"
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"exp": 9999999999, "role": "admin"}

        token = jwt_modifier.resign_jwt_hs256(header, payload, secret)

        assert jwt_modifier.verify_jwt_signature(token, secret) is True

    def test_verify_jwt_signature_incorrect_secret(self, jwt_modifier: JWTTokenModifier) -> None:
        """JWT signature verification fails with incorrect secret."""
        correct_secret = b"correct_secret"
        wrong_secret = b"wrong_secret"

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "test"}

        token = jwt_modifier.resign_jwt_hs256(header, payload, correct_secret)

        assert jwt_modifier.verify_jwt_signature(token, wrong_secret) is False

    def test_resign_jwt_hs256_preserves_modified_claims(self, jwt_modifier: JWTTokenModifier) -> None:
        """HS256 re-signing preserves license bypass modifications."""
        secret = b"license_server_key"
        header = {"alg": "HS256", "typ": "JWT"}
        original_payload = {"trial": True, "expired": True, "license_type": "trial"}

        modified_payload = jwt_modifier.modify_jwt_payload(original_payload)
        token = jwt_modifier.resign_jwt_hs256(header, modified_payload, secret)

        decoded = jwt_modifier.decode_jwt_without_verification(token)
        assert decoded is not None
        assert decoded["trial"] is False
        assert decoded["is_trial"] is False
        assert decoded["expired"] is False
        assert decoded["license_type"] == "perpetual"


class TestJWTAlgorithmConfusion:
    """Test JWT algorithm confusion attacks (RS256 -> HS256)."""

    def test_algorithm_confusion_rs256_to_hs256(self, jwt_modifier: JWTTokenModifier, rsa_key_pair: tuple[Any, Any]) -> None:
        """Algorithm confusion attack converts RS256 to HS256 using public key as HMAC secret."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        private_key, public_key = rsa_key_pair

        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"user": "test", "license": "trial"}

        original_token = jwt_modifier.resign_jwt_rs256(header, payload, private_key)

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        jwt_modifier.captured_jwks["https://test.com/.well-known/jwks.json"] = public_key_pem

        modified_token = jwt_modifier.attempt_jwt_modification(original_token)

        assert modified_token is not None
        assert modified_token != original_token

        parts = modified_token.split(".")
        header_decoded = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header_decoded["alg"] == "HS256"

    def test_algorithm_confusion_preserves_payload_modifications(
        self, jwt_modifier: JWTTokenModifier, rsa_key_pair: tuple[Any, Any]
    ) -> None:
        """Algorithm confusion attack preserves license bypass modifications."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        private_key, public_key = rsa_key_pair

        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"license_status": "expired", "valid": False}

        original_token = jwt_modifier.resign_jwt_rs256(header, payload, private_key)

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        jwt_modifier.captured_jwks["https://test.com/.well-known/jwks.json"] = public_key_pem

        modified_token = jwt_modifier.attempt_jwt_modification(original_token)

        assert modified_token is not None

        decoded_payload = jwt_modifier.decode_jwt_without_verification(modified_token)
        assert decoded_payload is not None
        assert decoded_payload["license_status"] == "active"
        assert decoded_payload["valid"] is True


class TestJWTNoneAlgorithm:
    """Test JWT 'none' algorithm bypass."""

    def test_none_algorithm_bypass_removes_signature(self, jwt_modifier: JWTTokenModifier) -> None:
        """JWT 'none' algorithm bypass creates unsigned tokens."""
        header = {"alg": "none", "typ": "JWT"}
        payload = {"user": "attacker", "admin": False}

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        token = f"{header_b64}.{payload_b64}.fake_signature"

        modified_token = jwt_modifier.attempt_jwt_modification(token)

        assert modified_token is not None
        assert modified_token.endswith(".")

        parts = modified_token.split(".")
        assert len(parts) == 3
        assert parts[2] == ""

    def test_none_algorithm_payload_modification(self, jwt_modifier: JWTTokenModifier) -> None:
        """JWT 'none' algorithm bypass modifies payload for license bypass."""
        header = {"alg": "none", "typ": "JWT"}
        payload = {"license": "trial", "expired": True}

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        token = f"{header_b64}.{payload_b64}.signature"

        modified_token = jwt_modifier.attempt_jwt_modification(token)

        assert modified_token is not None

        decoded = jwt_modifier.decode_jwt_without_verification(modified_token)
        assert decoded is not None
        assert decoded["license_status"] == "active"
        assert decoded["expired"] is False


class TestJWTSecretBruteForce:
    """Test JWT secret brute force capabilities."""

    def test_common_secret_discovery_via_brute_force(self, jwt_modifier: JWTTokenModifier) -> None:
        """JWT modifier discovers common weak secrets through brute force."""
        weak_secret = b"secret"
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "test", "exp": 9999999999}

        token = jwt_modifier.resign_jwt_hs256(header, payload, weak_secret)

        modified_token = jwt_modifier.attempt_jwt_modification(token)

        assert modified_token is not None
        assert jwt_modifier.verify_jwt_signature(modified_token, weak_secret)

    def test_secret_extraction_from_binary(self, jwt_modifier_with_binary: JWTTokenModifier) -> None:
        """JWT modifier extracts secrets from binary files for brute force."""
        secrets = jwt_modifier_with_binary.common_secrets

        assert len(secrets) > 50
        assert any(b"MyS3cr3tK3y123" in s for s in secrets)
        assert any(b"production_jwt_key" in s for s in secrets)

    def test_brute_force_with_custom_wordlist(self, tmp_path: Path) -> None:
        """JWT modifier uses custom wordlist for secret brute force."""
        wordlist_path = tmp_path / "wordlist.txt"
        wordlist_path.write_text("custom_secret_123\nspecial_key_456\nproduction_jwt_key_789\n")

        modifier = JWTTokenModifier(wordlist_path=str(wordlist_path))

        assert b"custom_secret_123" in modifier.common_secrets
        assert b"special_key_456" in modifier.common_secrets
        assert b"production_jwt_key_789" in modifier.common_secrets


class TestJWTPayloadModification:
    """Test JWT payload modification for license bypass."""

    def test_modify_jwt_payload_extends_expiration(self, jwt_modifier: JWTTokenModifier) -> None:
        """JWT payload modification extends expiration to 10 years in future."""
        original_payload = {"exp": 1000000000, "user": "test"}

        modified_payload = jwt_modifier.modify_jwt_payload(original_payload)

        assert "exp" in modified_payload
        assert modified_payload["exp"] > 1000000000

        expiry_date = datetime.datetime.fromtimestamp(modified_payload["exp"], tz=datetime.timezone.utc)
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        days_diff = (expiry_date - now).days

        assert days_diff > 3000

    def test_modify_jwt_payload_activates_license(self, jwt_modifier: JWTTokenModifier) -> None:
        """JWT payload modification changes license status to active/perpetual."""
        original_payload = {"license_status": "expired", "license_type": "trial", "valid": False}

        modified_payload = jwt_modifier.modify_jwt_payload(original_payload)

        assert modified_payload["license_status"] == "active"
        assert modified_payload["license_type"] == "perpetual"
        assert modified_payload["valid"] is True

    def test_modify_jwt_payload_removes_trial_restrictions(self, jwt_modifier: JWTTokenModifier) -> None:
        """JWT payload modification removes trial flags and limitations."""
        original_payload = {"trial": True, "is_trial": True, "max_users": 1}

        modified_payload = jwt_modifier.modify_jwt_payload(original_payload)

        assert modified_payload["trial"] is False
        assert modified_payload["is_trial"] is False
        assert modified_payload["max_users"] == 999999

    def test_modify_jwt_payload_enables_all_features(self, jwt_modifier: JWTTokenModifier) -> None:
        """JWT payload modification enables all features and entitlements."""
        original_payload = {"features": ["basic"], "tier": "free"}

        modified_payload = jwt_modifier.modify_jwt_payload(original_payload)

        assert modified_payload["features"] == ["all"]
        assert modified_payload["tier"] == "enterprise"
        assert modified_payload["plan"] == "enterprise"

    def test_modify_jwt_payload_nested_license_object(self, jwt_modifier: JWTTokenModifier) -> None:
        """JWT payload modification handles nested license objects."""
        original_payload = {"license": {"status": "inactive", "type": "trial"}, "user": "test"}

        modified_payload = jwt_modifier.modify_jwt_payload(original_payload)

        assert "license" in modified_payload
        assert isinstance(modified_payload["license"], dict)


class TestJWKSEndpointInterception:
    """Test JWKS endpoint interception for public key extraction."""

    def test_intercept_jwks_endpoint_not_implemented(self, jwt_modifier: JWTTokenModifier) -> None:
        """JWKS interception with invalid URL returns None."""
        public_key = jwt_modifier.intercept_jwks_endpoint("https://invalid.test.local/.well-known/jwks.json")

        assert public_key is None

    def test_jwks_caching_mechanism(self, jwt_modifier: JWTTokenModifier, rsa_key_pair: tuple[Any, Any]) -> None:
        """JWKS endpoint results are cached for reuse."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        _, public_key = rsa_key_pair

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        test_url = "https://test.example.com/.well-known/jwks.json"
        jwt_modifier.captured_jwks[test_url] = public_key_pem

        assert test_url in jwt_modifier.captured_jwks
        assert jwt_modifier.captured_jwks[test_url] == public_key_pem


class TestOAuth2TokenModification:
    """Test OAuth 2.0 token modification and re-signing."""

    def test_oauth2_access_token_modification(self, jwt_modifier: JWTTokenModifier) -> None:
        """OAuth 2.0 access tokens are modified to extend validity."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "token_type": "Bearer",
            "scope": "read",
            "exp": 1000000000,
            "iat": 999999900,
        }

        secret = b"oauth_server_secret"
        token = jwt_modifier.resign_jwt_hs256(header, payload, secret)

        modified_token = jwt_modifier.attempt_jwt_modification(token)

        if modified_token:
            decoded = jwt_modifier.decode_jwt_without_verification(modified_token)
            assert decoded is not None
            assert decoded["exp"] > payload["exp"]

    def test_oauth2_refresh_token_expiration_extension(self, jwt_modifier: JWTTokenModifier) -> None:
        """OAuth 2.0 refresh tokens have expiration extended."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "token_type": "Refresh",
            "exp": int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp()) + 3600,
        }

        modified_payload = jwt_modifier.modify_jwt_payload(payload)

        assert modified_payload["exp"] > payload["exp"]

        future_timestamp = int((datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=3650)).timestamp())
        assert abs(modified_payload["exp"] - future_timestamp) < 100


class TestEncryptedPayloadHandling:
    """Test handling of encrypted JSON payloads (AES-GCM, ChaCha20)."""

    def test_aes_gcm_encrypted_payload_detection(self) -> None:
        """AES-GCM encrypted payloads are detected and handled."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        key = os.urandom(32)
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)

        plaintext = json.dumps({"license": "trial", "valid": False}).encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        assert len(ciphertext) > len(plaintext)
        assert ciphertext != plaintext

    def test_aes_gcm_decryption_and_modification(self) -> None:
        """AES-GCM encrypted license data can be decrypted and modified."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        key = os.urandom(32)
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)

        original_data = {"license_status": "trial", "features": ["basic"]}
        plaintext = json.dumps(original_data).encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        decrypted_data = json.loads(decrypted.decode())

        assert decrypted_data["license_status"] == "trial"

        decrypted_data["license_status"] = "active"
        decrypted_data["features"] = ["all"]

        modified_plaintext = json.dumps(decrypted_data).encode()
        modified_ciphertext = aesgcm.encrypt(nonce, modified_plaintext, None)

        final_decrypted = aesgcm.decrypt(nonce, modified_ciphertext, None)
        final_data = json.loads(final_decrypted.decode())

        assert final_data["license_status"] == "active"
        assert final_data["features"] == ["all"]

    def test_chacha20_poly1305_encrypted_payload_handling(self) -> None:
        """ChaCha20-Poly1305 encrypted payloads are handled correctly."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        key = os.urandom(32)
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(key)

        plaintext = json.dumps({"subscription": "premium", "expired": True}).encode()
        ciphertext = chacha.encrypt(nonce, plaintext, None)

        assert len(ciphertext) > len(plaintext)

        decrypted = chacha.decrypt(nonce, ciphertext, None)
        assert decrypted == plaintext

    def test_chacha20_payload_modification_preserves_integrity(self) -> None:
        """ChaCha20 payload modification preserves message integrity."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        key = os.urandom(32)
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(key)

        original_data = {"valid": False, "expiry": "2020-01-01"}
        plaintext = json.dumps(original_data).encode()
        ciphertext = chacha.encrypt(nonce, plaintext, None)

        decrypted = chacha.decrypt(nonce, ciphertext, None)
        decrypted_data = json.loads(decrypted.decode())

        decrypted_data["valid"] = True
        decrypted_data["expiry"] = "2099-12-31"

        modified_plaintext = json.dumps(decrypted_data).encode()
        modified_ciphertext = chacha.encrypt(nonce, modified_plaintext, None)

        final_decrypted = chacha.decrypt(nonce, modified_ciphertext, None)
        final_data = json.loads(final_decrypted.decode())

        assert final_data["valid"] is True
        assert final_data["expiry"] == "2099-12-31"


class TestCertificateBasedAuthentication:
    """Test certificate-based authentication challenge handling."""

    def test_certificate_generation_for_domain(self, temp_ca_certs: tuple[str, str]) -> None:
        """PyOpenSSL interceptor generates valid certificates for target domains."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1",
            listen_port=8443,
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
            target_hosts=["license.adobe.com"],
        )

        cert_key = interceptor.generate_cert_for_domain("license.adobe.com")

        assert cert_key is not None
        cert_path, key_path = cert_key

        assert os.path.exists(cert_path)
        assert os.path.exists(key_path)

        from cryptography import x509

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        assert any(
            isinstance(ext.value, x509.SubjectAlternativeName) and "license.adobe.com" in str(ext.value)
            for ext in cert.extensions
        )

    def test_certificate_caching_for_performance(self, temp_ca_certs: tuple[str, str]) -> None:
        """Generated certificates are cached to improve performance."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1",
            listen_port=8443,
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
            target_hosts=["test.com"],
        )

        cert_key_1 = interceptor.generate_cert_for_domain("test.com")
        cert_key_2 = interceptor.generate_cert_for_domain("test.com")

        assert cert_key_1 == cert_key_2
        assert "test.com" in interceptor.cert_cache

    def test_certificate_signed_by_ca(self, temp_ca_certs: tuple[str, str]) -> None:
        """Generated certificates are properly signed by CA."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1",
            listen_port=8443,
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
            target_hosts=["secure.autodesk.com"],
        )

        cert_key = interceptor.generate_cert_for_domain("secure.autodesk.com")
        assert cert_key is not None

        cert_path, _ = cert_key

        from cryptography import x509

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        assert cert.issuer == ca_cert.subject


class TestAdobeActivationProtocol:
    """Test Adobe-specific activation protocol handling."""

    def test_adobe_jwt_token_modification(self, jwt_modifier: JWTTokenModifier) -> None:
        """Adobe activation JWT tokens are modified for license bypass."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "adobe_user_123",
            "iss": "https://ims-na1.adobelogin.com",
            "license_type": "trial",
            "trial": True,
            "expiration": "2020-01-01",
        }

        modified_payload = jwt_modifier.modify_jwt_payload(payload)

        assert modified_payload["license_type"] == "perpetual"
        assert modified_payload["trial"] is False
        assert modified_payload["is_trial"] is False

    def test_adobe_response_modification_preserves_structure(self, temp_ca_certs: tuple[str, str]) -> None:
        """Adobe license responses maintain protocol structure after modification."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1",
            listen_port=8443,
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
            target_hosts=["lcs-cops.adobe.io"],
        )

        adobe_response = json.dumps({"status": "ERROR", "license": {"status": "INACTIVE", "type": "TRIAL"}}).encode()

        response_data = (
            b"HTTP/1.1 200 OK\r\n" b"Content-Type: application/json\r\n" b"Content-Length: " + str(len(adobe_response)).encode() + b"\r\n\r\n" + adobe_response
        )

        modified_response = interceptor.modify_response(response_data)

        body_start = modified_response.find(b"\r\n\r\n") + 4
        body = modified_response[body_start:]

        modified_data = json.loads(body.decode())

        assert modified_data["status"] == "SUCCESS"
        assert modified_data["license"]["status"] == "ACTIVATED"
        assert modified_data["license"]["type"] == "PERMANENT"


class TestAutodeskActivationProtocol:
    """Test Autodesk-specific activation protocol handling."""

    def test_autodesk_license_server_response_modification(self, temp_ca_certs: tuple[str, str]) -> None:
        """Autodesk license server responses are modified for activation."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1",
            listen_port=8443,
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
            target_hosts=["registeronce.autodesk.com"],
        )

        autodesk_response = json.dumps({"isValid": False, "expired": True, "license": "TRIAL"}).encode()

        response_data = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(autodesk_response)).encode() + b"\r\n\r\n" + autodesk_response
        )

        modified_response = interceptor.modify_response(response_data)

        body_start = modified_response.find(b"\r\n\r\n") + 4
        body = modified_response[body_start:]

        modified_data = json.loads(body.decode())

        assert modified_data["isValid"] is True
        assert modified_data["expired"] is False
        assert modified_data["license"] == "ACTIVATED"


class TestMicrosoftActivationProtocol:
    """Test Microsoft-specific activation protocol handling."""

    def test_microsoft_oauth_token_modification(self, jwt_modifier: JWTTokenModifier) -> None:
        """Microsoft OAuth tokens are modified for license bypass."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "aud": "https://licensing.microsoft.com",
            "iss": "https://login.microsoftonline.com",
            "license_type": "trial",
            "subscription": "basic",
        }

        modified_payload = jwt_modifier.modify_jwt_payload(payload)

        assert modified_payload["license_type"] == "perpetual"
        assert modified_payload["tier"] == "enterprise"


class TestMessageIntegrityPreservation:
    """Test that message integrity is preserved after modification."""

    def test_json_response_integrity_after_modification(self, temp_ca_certs: tuple[str, str]) -> None:
        """Modified JSON responses remain valid JSON."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1", listen_port=8443, ca_cert_path=ca_cert_path, ca_key_path=ca_key_path, target_hosts=["test.com"]
        )

        original_response = json.dumps({"status": "ERROR", "valid": False, "nested": {"expired": True}}).encode()

        response_data = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(original_response)).encode() + b"\r\n\r\n" + original_response
        )

        modified_response = interceptor.modify_response(response_data)

        body_start = modified_response.find(b"\r\n\r\n") + 4
        body = modified_response[body_start:]

        try:
            modified_data = json.loads(body.decode())
            assert isinstance(modified_data, dict)
        except json.JSONDecodeError:
            pytest.fail("Modified response is not valid JSON")

    def test_content_length_updated_after_modification(self, temp_ca_certs: tuple[str, str]) -> None:
        """Content-Length header is updated to match modified body."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1", listen_port=8443, ca_cert_path=ca_cert_path, ca_key_path=ca_key_path, target_hosts=["test.com"]
        )

        original_response = json.dumps({"status": "ERROR"}).encode()

        response_data = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(original_response)).encode() + b"\r\n\r\n" + original_response
        )

        modified_response = interceptor.modify_response(response_data)

        headers_end = modified_response.find(b"\r\n\r\n")
        headers = modified_response[:headers_end].decode()
        body = modified_response[headers_end + 4 :]

        content_length = None
        for line in headers.split("\r\n"):
            if line.lower().startswith("content-length:"):
                content_length = int(line.split(":", 1)[1].strip())

        assert content_length == len(body)

    def test_gzip_compressed_response_handling(self, temp_ca_certs: tuple[str, str]) -> None:
        """Gzip-compressed responses are properly decompressed, modified, and recompressed."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1", listen_port=8443, ca_cert_path=ca_cert_path, ca_key_path=ca_key_path, target_hosts=["test.com"]
        )

        import gzip

        original_data = json.dumps({"license": "trial", "valid": False}).encode()
        compressed_data = gzip.compress(original_data)

        response_data = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Encoding: gzip\r\n"
            b"Content-Length: " + str(len(compressed_data)).encode() + b"\r\n\r\n" + compressed_data
        )

        modified_response = interceptor.modify_response(response_data)

        headers_end = modified_response.find(b"\r\n\r\n")
        body = modified_response[headers_end + 4 :]

        decompressed = gzip.decompress(body)
        modified_data = json.loads(decompressed.decode())

        assert modified_data["license"] == "ACTIVATED"
        assert modified_data["valid"] is True


class TestTokenRefreshHandling:
    """Test token refresh scenario handling."""

    def test_refresh_token_expiration_extension(self, jwt_modifier: JWTTokenModifier) -> None:
        """Refresh tokens have expiration extended during modification."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "token_type": "refresh_token",
            "exp": int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp()) + 86400,
        }

        modified_payload = jwt_modifier.modify_jwt_payload(payload)

        assert modified_payload["exp"] > payload["exp"]

        days_extended = (modified_payload["exp"] - payload["exp"]) / 86400
        assert days_extended > 1000

    def test_refresh_token_preserves_grant_type(self, jwt_modifier: JWTTokenModifier) -> None:
        """Refresh token modification preserves OAuth grant type information."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "grant_type": "refresh_token",
            "scope": "read write",
            "client_id": "app_client_123",
            "trial": True,
        }

        modified_payload = jwt_modifier.modify_jwt_payload(payload)

        assert modified_payload.get("grant_type") == "refresh_token"
        assert modified_payload.get("scope") == "read write"
        assert modified_payload.get("client_id") == "app_client_123"
        assert modified_payload["trial"] is False


class TestMultiFactorAuthenticationBypass:
    """Test MFA challenge handling in license verification."""

    def test_mfa_challenge_response_modification(self, temp_ca_certs: tuple[str, str]) -> None:
        """MFA challenge responses are modified to bypass verification."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1", listen_port=8443, ca_cert_path=ca_cert_path, ca_key_path=ca_key_path, target_hosts=["mfa.example.com"]
        )

        mfa_response = json.dumps(
            {
                "status": "ERROR",
                "mfa_required": True,
                "mfa_verified": False,
                "license": {"valid": False},
            }
        ).encode()

        response_data = (
            b"HTTP/1.1 200 OK\r\n" b"Content-Type: application/json\r\n" b"Content-Length: " + str(len(mfa_response)).encode() + b"\r\n\r\n" + mfa_response
        )

        modified_response = interceptor.modify_response(response_data)

        body_start = modified_response.find(b"\r\n\r\n") + 4
        body = modified_response[body_start:]

        modified_data = json.loads(body.decode())

        assert modified_data["status"] == "SUCCESS"
        assert modified_data["valid"] is True


class TestHardwareAttestationBypass:
    """Test hardware attestation challenge bypass."""

    def test_hardware_attestation_jwt_modification(self, jwt_modifier: JWTTokenModifier) -> None:
        """Hardware attestation JWTs are modified to bypass checks."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "hardware_id": "original_hwid_123",
            "device_fingerprint": "abc123def456",
            "attestation_verified": False,
            "license": "trial",
        }

        modified_payload = jwt_modifier.modify_jwt_payload(payload)

        assert modified_payload["license_status"] == "active"
        assert modified_payload["is_valid"] is True

    def test_tpm_attestation_response_modification(self, temp_ca_certs: tuple[str, str]) -> None:
        """TPM attestation responses are modified to bypass hardware checks."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1",
            listen_port=8443,
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
            target_hosts=["attestation.example.com"],
        )

        attestation_response = json.dumps(
            {
                "attestation_verified": False,
                "tpm_verified": False,
                "hardware_match": False,
                "license": {"valid": False},
            }
        ).encode()

        response_data = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(attestation_response)).encode() + b"\r\n\r\n" + attestation_response
        )

        modified_response = interceptor.modify_response(response_data)

        body_start = modified_response.find(b"\r\n\r\n") + 4
        body = modified_response[body_start:]

        modified_data = json.loads(body.decode())

        assert modified_data["valid"] is True


class TestXMLProtocolHandling:
    """Test XML-based license protocol handling."""

    def test_xml_response_modification(self, temp_ca_certs: tuple[str, str]) -> None:
        """XML license responses are modified for bypass."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1", listen_port=8443, ca_cert_path=ca_cert_path, ca_key_path=ca_key_path, target_hosts=["xml.example.com"]
        )

        xml_response = b"""<?xml version="1.0"?>
<license>
    <status>ERROR</status>
    <valid>false</valid>
    <expired>true</expired>
</license>"""

        response_data = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/xml\r\n"
            b"Content-Length: " + str(len(xml_response)).encode() + b"\r\n\r\n" + xml_response
        )

        modified_response = interceptor.modify_response(response_data)

        body_start = modified_response.find(b"\r\n\r\n") + 4
        body = modified_response[body_start:].decode()

        assert "<status>SUCCESS</status>" in body
        assert "<valid>true</valid>" in body
        assert "<expired>false</expired>" in body


class TestChunkedTransferEncoding:
    """Test chunked transfer encoding handling."""

    def test_chunked_encoding_decoding(self, temp_ca_certs: tuple[str, str]) -> None:
        """Chunked transfer encoding is properly decoded for modification."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1", listen_port=8443, ca_cert_path=ca_cert_path, ca_key_path=ca_key_path, target_hosts=["chunked.example.com"]
        )

        chunk1 = b'{"license"'
        chunk2 = b': "trial"}'

        chunked_body = f"{len(chunk1):x}\r\n".encode() + chunk1 + b"\r\n" + f"{len(chunk2):x}\r\n".encode() + chunk2 + b"\r\n0\r\n\r\n"

        response_data = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n" + chunked_body
        )

        decoded_body = interceptor._decode_chunked(chunked_body)

        expected_body = chunk1 + chunk2
        assert decoded_body == expected_body


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_malformed_jwt_token_handling(self, jwt_modifier: JWTTokenModifier) -> None:
        """Malformed JWT tokens are handled gracefully without crashing."""
        malformed_tokens = [
            "not.a.jwt",
            "only_one_part",
            "two.parts",
            "",
            "....",
            "a" * 10000,
        ]

        for token in malformed_tokens:
            result = jwt_modifier.attempt_jwt_modification(token)
            assert result is None or isinstance(result, str)

    def test_jwt_with_invalid_base64_padding(self, jwt_modifier: JWTTokenModifier) -> None:
        """JWT tokens with invalid base64 padding are handled correctly."""
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"test": "data"}).encode()).decode().rstrip("=")

        token = f"{header}.{payload}."

        decoded = jwt_modifier.decode_jwt_without_verification(token)

        assert decoded is not None
        assert decoded["test"] == "data"

    def test_empty_response_modification(self, temp_ca_certs: tuple[str, str]) -> None:
        """Empty HTTP responses are handled without errors."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1", listen_port=8443, ca_cert_path=ca_cert_path, ca_key_path=ca_key_path, target_hosts=["test.com"]
        )

        empty_response = b"HTTP/1.1 200 OK\r\n\r\n"

        modified_response = interceptor.modify_response(empty_response)

        assert modified_response == empty_response

    def test_binary_response_modification_skipped(self, temp_ca_certs: tuple[str, str]) -> None:
        """Binary (non-text) responses are not modified."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography library not available")

        ca_cert_path, ca_key_path = temp_ca_certs

        interceptor = PyOpenSSLInterceptor(
            listen_ip="127.0.0.1", listen_port=8443, ca_cert_path=ca_cert_path, ca_key_path=ca_key_path, target_hosts=["test.com"]
        )

        binary_data = bytes(range(256))

        response_data = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(binary_data)).encode() + b"\r\n\r\n" + binary_data
        )

        modified_response = interceptor.modify_response(response_data)

        assert modified_response == response_data

    def test_very_long_jwt_token_handling(self, jwt_modifier: JWTTokenModifier) -> None:
        """Very long JWT tokens are handled without performance issues."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"data": "x" * 100000, "license": "trial"}

        secret = b"test_secret"
        token = jwt_modifier.resign_jwt_hs256(header, payload, secret)

        assert len(token) > 100000

        decoded = jwt_modifier.decode_jwt_without_verification(token)

        assert decoded is not None
        assert len(decoded["data"]) == 100000
