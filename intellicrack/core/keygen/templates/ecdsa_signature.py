
import base64
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from ..base import KeygenTemplate, KeygenParameter, ParamType, KeygenResult

# --- Key Generation and Management Utilities ---

def generate_key_pair() -> (bytes, bytes):
    """Generates a new ECDSA private and public key pair."""
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def save_key_pair(private_pem: bytes, public_pem: bytes, private_path: str = "private_key.pem", public_path: str = "public_key.pem"):
    """Saves the key pair to the specified files."""
    with open(private_path, "wb") as f:
        f.write(private_pem)
    with open(public_path, "wb") as f:
        f.write(public_pem)

def load_private_key(path: str) -> ec.EllipticCurvePrivateKey:
    """Loads a private key from a PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path: str) -> ec.EllipticCurvePublicKey:
    """Loads a public key from a PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

# --- Keygen Template Implementation ---

class ECDSAKeygen(KeygenTemplate):
    """Generates secure, verifiable license keys using ECDSA digital signatures."""

    @property
    def name(self) -> str:
        return "ECDSA Digital Signature Keygen"

    @property
    def description(self) -> str:
        return "Creates a license key containing user data, signed with a private key."

    def get_parameters(self) -> List[KeygenParameter]:
        return [
            KeygenParameter(
                name="private_key_path",
                param_type=ParamType.FILE,
                description="Path to the PEM-encoded private key file for signing.",
                required=True
            ),
            KeygenParameter(
                name="user_id",
                param_type=ParamType.STRING,
                description="A unique identifier for the user (e.g., username or email).",
                required=True
            ),
            KeygenParameter(
                name="expiry_days",
                param_type=ParamType.INTEGER,
                description="Number of days until the license expires (0 for no expiry).",
                required=True,
                default=365
            ),
            KeygenParameter(
                name="features",
                param_type=ParamType.STRING,
                description="A comma-separated list of features to enable (e.g., 'pro,updates').",
                required=False
            )
        ]

    def generate(self, params: Dict[str, Any]) -> KeygenResult:
        private_key_path = params.get("private_key_path")
        user_id = params.get("user_id")
        expiry_days = params.get("expiry_days")
        features_str = params.get("features", "")

        if not all([private_key_path, user_id, expiry_days is not None]):
            return KeygenResult(success=False, error="Missing required parameters.")

        log = []

        try:
            private_key = load_private_key(private_key_path)
            log.append(f"Successfully loaded private key from {private_key_path}")
        except Exception as e:
            return KeygenResult(success=False, error=f"Failed to load private key: {e}")

        # 1. Construct the license data payload
        expiry_date = (datetime.utcnow() + timedelta(days=int(expiry_days))).isoformat() if int(expiry_days) > 0 else "never"
        features = [f.strip() for f in features_str.split(",") if f.strip()]

        license_payload = {
            "user_id": user_id,
            "issued_at": datetime.utcnow().isoformat(),
            "expires_at": expiry_date,
            "features": features,
            "version": 1
        }
        payload_json = json.dumps(license_payload, sort_keys=True).encode('utf-8')
        log.append(f"Generated license payload: {payload_json.decode()}")

        # 2. Sign the payload with the private key
        try:
            signature = private_key.sign(
                payload_json,
                ec.ECDSA(hashes.SHA256())
            )
            log.append(f"Payload signed successfully. Signature length: {len(signature)} bytes")
        except Exception as e:
            return KeygenResult(success=False, error=f"Failed to sign payload: {e}")

        # 3. Create the final license key string
        payload_b64 = base64.urlsafe_b64encode(payload_json).rstrip(b'=').decode('utf-8')
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

        final_key = f"{payload_b64}.{signature_b64}"
        log.append(f"Generated final license key.")

        return KeygenResult(success=True, keys=[final_key], log=log)

# --- Verification Logic (for demonstration in the client application) ---

def verify_license_key(public_key_pem: bytes, license_key: str) -> (bool, Optional[Dict[str, Any]], str):
    """
    Verifies a license key using the public key.
    This function would be used inside the client application.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except Exception as e:
        return False, None, f"Invalid public key: {e}"

    try:
        payload_b64, signature_b64 = license_key.split('.')
        
        # Add padding back before decoding
        payload_json = base64.urlsafe_b64decode(payload_b64 + '==')
        signature = base64.urlsafe_b64decode(signature_b64 + '==')

    except (ValueError, IndexError):
        return False, None, "Invalid license key format."

    try:
        public_key.verify(
            signature,
            payload_json,
            ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        return False, None, "Signature verification failed. The key is invalid or has been tampered with."
    except Exception as e:
        return False, None, f"An unexpected error occurred during verification: {e}"

    try:
        license_data = json.loads(payload_json)
    except json.JSONDecodeError:
        return False, None, "Invalid license data format."

    # Check expiry date
    expiry_str = license_data.get("expires_at")
    if expiry_str and expiry_str != "never":
        try:
            expiry_date = datetime.fromisoformat(expiry_str)
            if datetime.utcnow() > expiry_date:
                return False, license_data, "License has expired."
        except ValueError:
            return False, license_data, "Invalid expiry date format."

    return True, license_data, "License is valid."

# --- Example Usage (for command-line key generation) ---

if __name__ == '__main__':
    # 1. Generate and save a new key pair (only needs to be done once)
    print("Generating new ECDSA key pair...")
    priv_key_pem, pub_key_pem = generate_key_pair()
    save_key_pair(priv_key_pem, pub_key_pem)
    print("Saved private_key.pem and public_key.pem to the current directory.")
    print("--- KEEP private_key.pem SECRET! ---")
    print("--- DISTRIBUTE public_key.pem with your application. ---")

    # 2. Generate a license key using the new private key
    print("\nGenerating a sample license key...")
    keygen = ECDSAKeygen()
    params = {
        "private_key_path": "private_key.pem",
        "user_id": "test-user@example.com",
        "expiry_days": 30,
        "features": "pro,updates,support"
    }
    result = keygen.generate(params)

    if result.success:
        generated_key = result.keys[0]
        print(f"Generated Key: {generated_key}")
        print("\n--- Verification Example ---")
        
        # 3. Verify the generated key with the public key
        is_valid, data, message = verify_license_key(pub_key_pem, generated_key)
        print(f"Verification Status: {'VALID' if is_valid else 'INVALID'}")
        print(f"Message: {message}")
        if data:
            print(f"License Data: {data}")
    else:
        print(f"Key generation failed: {result.error}")
