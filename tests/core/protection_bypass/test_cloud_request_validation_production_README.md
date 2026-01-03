# Cloud License Request Validation Production Tests

## Test File Location
`D:\Intellicrack\tests\core\protection_bypass\test_cloud_request_validation_production.py`

## Implementation Target
`D:\Intellicrack\intellicrack\core\protection_bypass\cloud_license_analyzer.py:1046-1111`

## Critical Issue Being Tested
The cloud license server emulation currently accepts ALL requests without any authentication validation:
- No JWT signature verification
- No HMAC token validation
- No timestamp checking (replay attack vulnerability)
- No client certificate validation
- No logging of authentication failures

## Test Coverage

### 1. JWT Signature Verification (TestJWTSignatureVerification)
**Tests: 8 test cases**

- `test_rs256_jwt_valid_signature_accepted`: Validates RS256 (RSA-2048) JWT signature verification
- `test_rs256_jwt_invalid_signature_rejected`: Ensures tampered RS256 signatures are rejected
- `test_rs256_jwt_wrong_key_rejected`: Verifies signature validation catches key mismatches
- `test_es256_jwt_valid_signature_accepted`: Tests ECDSA P-256 signature verification
- `test_es256_jwt_invalid_signature_rejected`: Ensures tampered ES256 signatures are rejected
- `test_hs256_jwt_valid_signature_accepted`: Validates HMAC-SHA256 symmetric signatures
- `test_hs256_jwt_wrong_secret_rejected`: Ensures wrong HMAC secrets are detected
- `test_expired_jwt_rejected`: Validates expiration timestamp checking
- `test_jwt_nbf_not_yet_valid_rejected`: Tests not-before timestamp validation

**Expected Implementation Methods:**
```python
def verify_jwt_token(
    self,
    token: str,
    algorithm: str,
    key_id: str = "default"
) -> dict[str, Any] | None:
    """Verify JWT signature and return decoded payload."""
```

**Required Attributes:**
- `self.jwt_public_keys: dict[str, bytes]` - RSA/EC public keys
- `self.jwt_secret_keys: dict[str, bytes]` - HMAC secret keys

### 2. HMAC Authentication Validation (TestHMACAuthenticationValidation)
**Tests: 5 test cases**

- `test_valid_hmac_token_accepted`: Validates HMAC-SHA256 signature verification
- `test_invalid_hmac_signature_rejected`: Ensures tampered HMAC signatures are rejected
- `test_hmac_with_wrong_secret_rejected`: Verifies wrong secrets are detected
- `test_hmac_sha1_signature_validation`: Tests legacy HMAC-SHA1 support
- `test_hmac_sha512_signature_validation`: Tests HMAC-SHA512 support

**Expected Implementation Methods:**
```python
def verify_hmac_signature(
    self,
    request_body: str,
    signature: str,
    algorithm: str,
    key_id: str = "default"
) -> bool:
    """Verify HMAC signature for request authentication."""
```

**Required Attributes:**
- `self.hmac_secret_keys: dict[str, bytes]` - HMAC secret keys by ID

### 3. Timestamp Replay Protection (TestTimestampReplayProtection)
**Tests: 7 test cases**

- `test_current_timestamp_accepted`: Validates current timestamps are accepted
- `test_old_timestamp_rejected_replay_attack`: Ensures old timestamps are rejected
- `test_future_timestamp_rejected`: Tests clock skew protection
- `test_timestamp_within_tolerance_accepted`: Validates tolerance windows
- `test_nonce_prevents_duplicate_requests`: Tests nonce-based replay protection
- `test_expired_nonces_cleared`: Validates nonce cache cleanup
- `test_jwt_timestamp_validation`: Tests JWT iat claim validation

**Expected Implementation Methods:**
```python
def validate_request_timestamp(
    self,
    timestamp: int,
    max_age_seconds: int = 300,
    max_future_seconds: int = 60
) -> bool:
    """Validate request timestamp for replay protection."""

def validate_request_nonce(
    self,
    nonce: str,
    timestamp: int
) -> bool:
    """Validate and track request nonce."""

def cleanup_expired_nonces(
    self,
    max_age_seconds: int = 3600
) -> None:
    """Remove expired nonces from tracking."""

def validate_jwt_timestamp(
    self,
    decoded_jwt: dict[str, Any],
    max_iat_age_seconds: int = 3600
) -> bool:
    """Validate JWT issued-at timestamp."""
```

**Required Attributes:**
- Nonce tracking dictionary with timestamp expiration

### 4. Client Certificate Validation (TestClientCertificateValidation)
**Tests: 5 test cases**

- `test_valid_client_certificate_accepted`: Validates proper certificate acceptance
- `test_expired_client_certificate_rejected`: Ensures expired certificates are rejected
- `test_not_yet_valid_certificate_rejected`: Tests validity period checking
- `test_certificate_chain_validation`: Validates certificate chain trust
- `test_certificate_common_name_validation`: Tests CN pattern matching

**Expected Implementation Methods:**
```python
def validate_client_certificate(
    self,
    cert: x509.Certificate
) -> bool:
    """Validate client certificate for mutual TLS."""

def validate_certificate_chain(
    self,
    cert: x509.Certificate,
    trusted_cas: list[x509.Certificate]
) -> bool:
    """Validate certificate chain against trusted CAs."""

def validate_certificate_common_name(
    self,
    cert: x509.Certificate
) -> bool:
    """Validate certificate CN against allowed patterns."""
```

**Required Attributes:**
- `self.trusted_ca_certificates: list[x509.Certificate]`
- `self.allowed_client_cn_patterns: list[str]`

### 5. Authentication Logging and Rejection (TestAuthenticationLoggingAndRejection)
**Tests: 5 test cases**

- `test_invalid_jwt_logged`: Validates JWT failures are logged
- `test_invalid_hmac_logged`: Ensures HMAC failures are logged
- `test_replay_attack_logged`: Tests replay attempt logging
- `test_authentication_failure_counter`: Validates failure tracking
- `test_rate_limiting_after_failures`: Tests brute force protection

**Expected Implementation Methods:**
```python
def record_authentication_failure(
    self,
    client_id: str
) -> None:
    """Record authentication failure for client."""

def get_authentication_failures(
    self,
    client_id: str
) -> int:
    """Get failure count for client."""

def is_client_rate_limited(
    self,
    client_id: str,
    threshold: int = 5
) -> bool:
    """Check if client is rate limited."""
```

**Required:**
- Logging at ERROR/WARNING level for auth failures
- Failure tracking dictionary by client ID

### 6. Token Refresh Flow (TestTokenRefreshFlow)
**Tests: 3 test cases**

- `test_valid_refresh_token_generates_new_access_token`: Tests token refresh
- `test_expired_refresh_token_rejected`: Validates refresh token expiration
- `test_access_token_cannot_refresh`: Ensures access tokens can't refresh

**Expected Implementation Methods:**
```python
def refresh_access_token(
    self,
    refresh_token: str,
    algorithm: str
) -> str:
    """Generate new access token from refresh token."""
```

**Required Attributes:**
- `self.jwt_private_keys: dict[str, bytes]` - For signing new tokens

### 7. Multi-Factor Authentication (TestMultiFactorAuthentication)
**Tests: 4 test cases**

- `test_mfa_token_required_after_password`: Tests MFA enforcement
- `test_valid_totp_code_accepted`: Validates TOTP verification
- `test_invalid_totp_code_rejected`: Ensures invalid TOTP is rejected
- `test_backup_code_authentication`: Tests backup code support

**Expected Implementation Methods:**
```python
def enable_mfa_for_user(self, user_id: str) -> None:
    """Enable MFA requirement for user."""

def check_mfa_required(self, user_id: str, password_token: str) -> bool:
    """Check if MFA is required for user."""

def set_totp_secret(self, user_id: str, secret: str) -> None:
    """Set TOTP secret for user."""

def verify_totp_code(self, user_id: str, code: str) -> bool:
    """Verify TOTP code for user."""

def set_backup_codes(self, user_id: str, codes: list[str]) -> None:
    """Set backup codes for user."""

def verify_backup_code(self, user_id: str, code: str) -> bool:
    """Verify backup code (single-use)."""
```

**Required Dependency:**
- `pyotp` library for TOTP generation/validation

## Test Execution

### Running Tests
```bash
pixi run pytest tests/core/protection_bypass/test_cloud_request_validation_production.py -v
```

### Expected Result (Before Implementation)
**ALL TESTS WILL FAIL** - This is correct behavior. Tests validate that authentication
methods are implemented. Current code has no authentication validation.

### Expected Result (After Implementation)
**ALL TESTS MUST PASS** - Tests verify:
- Real cryptographic signature validation
- Actual timestamp checking with replay protection
- Proper certificate validation for mTLS
- Complete authentication logging
- Token refresh and MFA flows

## Dependencies Required
```toml
[project]
dependencies = [
    "pyjwt[crypto]>=2.8.0",
    "cryptography>=41.0.0",
    "pyotp>=2.9.0",  # For TOTP MFA testing
]
```

## Coverage Metrics
- **Total Test Cases:** 41
- **Authentication Mechanisms:** JWT (RS256/ES256/HS256), HMAC (SHA1/SHA256/SHA512), mTLS
- **Security Features:** Replay protection, rate limiting, MFA, token refresh
- **Edge Cases:** Expired tokens, invalid signatures, clock skew, certificate chains

## Critical Test Validation
These tests will ONLY pass when:
1. JWT signatures are verified using proper cryptographic algorithms
2. HMAC signatures are validated with correct secret keys
3. Timestamps are checked with replay attack prevention
4. Client certificates are validated for mTLS
5. Authentication failures are logged and tracked
6. Token refresh maintains security
7. MFA flows work correctly

## Current Implementation Gap
Lines 1046-1111 in `cloud_license_analyzer.py` currently:
- Accept all license verification requests (returns `valid: True`)
- Accept all activation requests without validation
- Generate tokens without verifying refresh token authenticity
- No authentication checking whatsoever

This creates a critical security gap that these tests expose and validate against.
