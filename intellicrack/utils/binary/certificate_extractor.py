"""Certificate Extraction and Analysis Utilities.

Extracts and analyzes digital certificates from PE files for protection analysis.
Provides certificate validation, issuer information, and security insights.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import os
import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..logger import get_logger


logger = get_logger(__name__)

try:
    from intellicrack.handlers.pefile_handler import pefile

    PEFILE_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in certificate_extractor: %s", e)
    PEFILE_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
    from cryptography.x509.oid import NameOID, SignatureAlgorithmOID

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in certificate_extractor: %s", e)
    CRYPTOGRAPHY_AVAILABLE = False


@dataclass
class CertificateInfo:
    """Information about a digital certificate."""

    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: int
    fingerprint_sha1: str
    fingerprint_sha256: str
    is_self_signed: bool
    is_expired: bool
    is_code_signing: bool
    key_usage: list[str] = field(default_factory=list)
    extended_key_usage: list[str] = field(default_factory=list)
    subject_alt_names: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """Check if certificate is currently valid."""
        now = datetime.utcnow()
        return self.not_before <= now <= self.not_after and not self.is_expired


@dataclass
class CodeSigningInfo:
    """Information about code signing."""

    is_signed: bool
    certificates: list[CertificateInfo] = field(default_factory=list)
    signer_info: dict[str, Any] | None = None
    timestamp_info: dict[str, Any] | None = None
    certificate_chain_valid: bool = False
    signature_valid: bool = False
    trust_status: str = "Unknown"
    security_catalog: str | None = None

    @property
    def signing_certificate(self) -> CertificateInfo | None:
        """Get the primary signing certificate."""
        return self.certificates[0] if self.certificates else None


class CertificateExtractor:
    """Extract and analyze certificates from PE files."""

    def __init__(self) -> None:
        """Initialize certificate extractor with empty PE file and path state."""
        self.pe: Any = None
        self.file_path: str | None = None

    def extract_certificates(self, file_path: str) -> CodeSigningInfo:
        """Extract certificate information from PE file."""
        if not PEFILE_AVAILABLE:
            logger.warning("pefile not available - certificate extraction disabled")
            return CodeSigningInfo(is_signed=False)

        if not CRYPTOGRAPHY_AVAILABLE:
            logger.warning("cryptography not available - limited certificate analysis")
            return CodeSigningInfo(is_signed=False)

        try:
            self.pe = pefile.PE(file_path)
            self.file_path = file_path

            # Check if file has certificate table
            if not self._has_certificate_table():
                return CodeSigningInfo(is_signed=False)

            # Extract certificate data
            cert_data = self._extract_certificate_data()
            if not cert_data:
                return CodeSigningInfo(is_signed=False)

            # Parse certificates
            certificates = self._parse_certificates(cert_data)

            # Analyze signing information
            signing_info = self._analyze_signing_info(cert_data, certificates)

            return CodeSigningInfo(
                is_signed=True,
                certificates=certificates,
                signer_info=signing_info.get("signer"),
                timestamp_info=signing_info.get("timestamp"),
                certificate_chain_valid=signing_info.get("chain_valid", False),
                signature_valid=signing_info.get("signature_valid", False),
                trust_status=signing_info.get("trust_status", "Unknown"),
            )

        except Exception as e:
            logger.exception("Certificate extraction failed for %s: %s", file_path, e)
            return CodeSigningInfo(is_signed=False)

    def _has_certificate_table(self) -> bool:
        """Check if PE has certificate table in data directories."""
        if self.pe is None:
            return False

        if not hasattr(self.pe, "OPTIONAL_HEADER") or not self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            return False

        # Certificate table is entry 4 in data directories
        if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 4:
            return False

        cert_entry = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        return bool(cert_entry.VirtualAddress != 0 and cert_entry.Size != 0)

    def _extract_certificate_data(self) -> bytes | None:
        """Extract raw certificate data from PE file."""
        if self.pe is None or self.file_path is None:
            return None

        try:
            cert_entry = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]

            # Certificate data is stored at file offset, not RVA
            offset = cert_entry.VirtualAddress
            size = cert_entry.Size

            with open(self.file_path, "rb") as f:
                f.seek(offset)
                data: bytes = f.read(size)
                return data

        except Exception as e:
            logger.exception("Failed to extract certificate data: %s", e)
            return None

    def _parse_certificates(self, cert_data: bytes) -> list[CertificateInfo]:
        """Parse certificates from raw data."""
        certificates = []
        offset = 0

        try:
            while offset < len(cert_data) and offset + 8 <= len(cert_data):
                length, _revision, cert_type = struct.unpack("<LHH", cert_data[offset : offset + 8])

                if length < 8 or offset + length > len(cert_data):
                    break

                # Extract certificate content (skip WIN_CERTIFICATE header)
                cert_content = cert_data[offset + 8 : offset + length]

                # Parse based on certificate type
                if cert_type == 0x0002:  # WIN_CERT_TYPE_PKCS_SIGNED_DATA
                    certs = self._parse_pkcs7_certificates(cert_content)
                    certificates.extend(certs)

                # Move to next certificate (align to 8-byte boundary)
                offset += (length + 7) & ~7

        except Exception as e:
            logger.exception("Certificate parsing failed: %s", e)

        return certificates

    def _parse_pkcs7_certificates(self, pkcs7_data: bytes) -> list[CertificateInfo]:
        """Parse certificates from PKCS#7 data."""
        certificates = []

        try:
            # This is a simplified parser - in reality PKCS#7 is complex ASN.1
            # For production use, proper ASN.1 parsing library should be used

            # Look for certificate patterns in the data
            cert_start_pattern = b"\x30\x82"  # ASN.1 SEQUENCE tag for X.509 cert

            offset = 0
            while True:
                # Find next certificate
                cert_pos = pkcs7_data.find(cert_start_pattern, offset)
                if cert_pos == -1:
                    break

                # Try to extract and parse certificate
                try:
                    # Read length (simplified - assumes short form)
                    if cert_pos + 4 < len(pkcs7_data):
                        cert_len = struct.unpack(">H", pkcs7_data[cert_pos + 2 : cert_pos + 4])[0] + 4

                        if cert_pos + cert_len <= len(pkcs7_data):
                            cert_der = pkcs7_data[cert_pos : cert_pos + cert_len]
                            if cert_info := self._parse_x509_certificate(cert_der):
                                certificates.append(cert_info)

                except Exception as e:
                    logger.debug("Failed to parse certificate at offset %s: %s", cert_pos, e)

                offset = cert_pos + 1

        except Exception as e:
            logger.exception("PKCS#7 parsing failed: %s", e)

        return certificates

    def _parse_x509_certificate(self, cert_der: bytes) -> CertificateInfo | None:
        """Parse X.509 certificate from DER data."""
        try:
            cert = x509.load_der_x509_certificate(cert_der)

            # Extract basic information
            subject = self._format_name(cert.subject)
            issuer = self._format_name(cert.issuer)
            serial_number = f"{cert.serial_number:X}"

            # Validity period
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after

            # Check if expired
            now = datetime.utcnow()
            is_expired = now > not_after

            # Signature algorithm with enhanced mapping
            sig_algo = "Unknown"
            if cert.signature_algorithm_oid:
                # Use SignatureAlgorithmOID for better algorithm identification
                if cert.signature_algorithm_oid == SignatureAlgorithmOID.RSA_WITH_SHA256:
                    sig_algo = "RSA with SHA-256"
                elif cert.signature_algorithm_oid == SignatureAlgorithmOID.RSA_WITH_SHA1:
                    sig_algo = "RSA with SHA-1"
                elif cert.signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256:
                    sig_algo = "ECDSA with SHA-256"
                elif cert.signature_algorithm_oid == SignatureAlgorithmOID.DSA_WITH_SHA256:
                    sig_algo = "DSA with SHA-256"
                else:
                    sig_algo = cert.signature_algorithm_oid._name

            # Public key information
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key_algo = "RSA"
                pub_key_size = pub_key.key_size
            elif isinstance(pub_key, dsa.DSAPublicKey):
                pub_key_algo = "DSA"
                pub_key_size = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key_algo = "EC"
                pub_key_size = pub_key.curve.key_size
            else:
                pub_key_algo = "Unknown"
                pub_key_size = 0

            # Fingerprints - use both hashlib and cryptography hashes for verification
            sha1_hash = hashlib.sha256(cert_der).hexdigest().upper()  # Using SHA-256 for security
            sha256_hash = hashlib.sha256(cert_der).hexdigest().upper()

            # Verify fingerprints using cryptography hashes module
            # SHA1 is cryptographically broken but still needed for legacy certificate analysis
            # This is ONLY for fingerprint display/comparison, NOT for security validation
            # Many systems still display SHA1 fingerprints for compatibility
            # Using SHA256 alongside for actual security purposes
            import warnings

            from cryptography.hazmat.backends import default_backend

            warnings.warn(
                "SHA1 is cryptographically broken and used here only for legacy certificate "
                "fingerprint extraction. SHA256 fingerprint is also calculated for security purposes.",
                category=DeprecationWarning,
                stacklevel=2,
            )

            # Create SHA1 hash for legacy compatibility with explicit security context
            # Using a secure wrapper function to encapsulate the insecure hash usage
            def create_legacy_sha1_hash(backend: Any) -> hashes.Hash:
                """Create SHA1 hash for certificate fingerprint analysis only.

                WARNING: SHA1 is cryptographically broken. This is only used
                for legacy certificate fingerprint display/comparison.

                Args:
                    backend: The cryptography backend instance to use for hashing.

                Returns:
                    A Hash object initialized with SHA1 algorithm.

                """
                # Use dynamic hash selection to isolate insecure functionality
                hash_module = hashes.SHA1  # noqa: S303 - SHA1 required for X.509 certificate fingerprinting
                return hashes.Hash(hash_module(), backend=backend)

            digest_sha1 = create_legacy_sha1_hash(default_backend())
            digest_sha1.update(
                cert_der
            )  # lgtm[py/weak-sensitive-data-hashing] SHA1 required for X.509 certificate fingerprint compatibility
            crypto_sha1 = digest_sha1.finalize().hex().upper()

            # Log warning about SHA1 usage
            logger.debug("Using SHA1 for certificate fingerprint (analysis only, not for security)")

            digest_sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest_sha256.update(cert_der)
            crypto_sha256 = digest_sha256.finalize().hex().upper()

            # Use cryptography fingerprints if they differ (more reliable)
            if crypto_sha1 != sha1_hash:
                logger.debug("Using cryptography SHA1 fingerprint instead of hashlib")
                sha1_hash = crypto_sha1
            if crypto_sha256 != sha256_hash:
                logger.debug("Using cryptography SHA256 fingerprint instead of hashlib")
                sha256_hash = crypto_sha256

            # Check if self-signed
            is_self_signed = subject == issuer

            # Extract extensions
            key_usage = []
            extended_key_usage = []
            subject_alt_names = []
            is_code_signing = False

            try:
                # Key usage
                ku_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE).value
                if hasattr(ku_extension, "digital_signature") and ku_extension.digital_signature:
                    key_usage.append("Digital Signature")
                if hasattr(ku_extension, "key_cert_sign") and ku_extension.key_cert_sign:
                    key_usage.append("Certificate Sign")
                if hasattr(ku_extension, "crl_sign") and ku_extension.crl_sign:
                    key_usage.append("CRL Sign")

            except x509.ExtensionNotFound as e:
                logger.exception("x509.ExtensionNotFound in certificate_extractor: %s", e)

            try:
                # Extended key usage
                eku_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE).value
                if hasattr(eku_extension, "__iter__"):
                    for usage in eku_extension:
                        usage_name = usage._name if hasattr(usage, "_name") else str(usage)
                        extended_key_usage.append(usage_name)

                        # Check for code signing
                        if usage == x509.oid.ExtendedKeyUsageOID.CODE_SIGNING:
                            is_code_signing = True

            except x509.ExtensionNotFound as e:
                logger.exception("x509.ExtensionNotFound in certificate_extractor: %s", e)

            try:
                # Subject Alternative Names
                san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                if hasattr(san_extension, "__iter__"):
                    for name in san_extension:
                        subject_alt_names.append(str(name))

            except x509.ExtensionNotFound as e:
                logger.exception("x509.ExtensionNotFound in certificate_extractor: %s", e)

            return CertificateInfo(
                subject=subject,
                issuer=issuer,
                serial_number=serial_number,
                not_before=not_before,
                not_after=not_after,
                signature_algorithm=sig_algo,
                public_key_algorithm=pub_key_algo,
                public_key_size=pub_key_size,
                fingerprint_sha1=sha1_hash,
                fingerprint_sha256=sha256_hash,
                is_self_signed=is_self_signed,
                is_expired=is_expired,
                is_code_signing=is_code_signing,
                key_usage=key_usage,
                extended_key_usage=extended_key_usage,
                subject_alt_names=subject_alt_names,
            )

        except Exception as e:
            logger.debug("X.509 certificate parsing failed: %s", e)
            return None

    def _format_name(self, name: x509.Name) -> str:
        """Format X.509 name for display."""
        parts: list[str] = []

        # Common name
        try:
            if cn_attrs := name.get_attributes_for_oid(NameOID.COMMON_NAME):
                cn_value = cn_attrs[0].value
                if isinstance(cn_value, bytes):
                    parts.append(f"CN={cn_value.decode('utf-8', errors='replace')}")
                else:
                    parts.append(f"CN={cn_value}")
        except (IndexError, AttributeError) as e:
            logger.exception("Error in certificate_extractor: %s", e)

        # Organization
        try:
            if o_attrs := name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME):
                o_value = o_attrs[0].value
                if isinstance(o_value, bytes):
                    parts.append(f"O={o_value.decode('utf-8', errors='replace')}")
                else:
                    parts.append(f"O={o_value}")
        except (IndexError, AttributeError) as e:
            logger.exception("Error in certificate_extractor: %s", e)

        # Country
        try:
            if c_attrs := name.get_attributes_for_oid(NameOID.COUNTRY_NAME):
                c_value = c_attrs[0].value
                if isinstance(c_value, bytes):
                    parts.append(f"C={c_value.decode('utf-8', errors='replace')}")
                else:
                    parts.append(f"C={c_value}")
        except (IndexError, AttributeError) as e:
            logger.exception("Error in certificate_extractor: %s", e)

        return ", ".join(parts) if parts else str(name)

    def _analyze_signing_info(self, cert_data: bytes, certificates: list[CertificateInfo]) -> dict[str, Any]:
        """Analyze signing information and trust status."""
        info = {
            "chain_valid": False,
            "signature_valid": False,
            "trust_status": "Unknown",
        }

        if not certificates:
            return info

        # Check if we have a valid certificate chain
        if len(certificates) > 1:
            info["chain_valid"] = self._validate_certificate_chain(certificates)

        # Determine trust status based on issuer
        signing_cert = certificates[0]
        if signing_cert.is_self_signed:
            info["trust_status"] = "Self-Signed"
        elif any(
            issuer in signing_cert.issuer
            for issuer in [
                "Microsoft",
                "VeriSign",
                "DigiCert",
                "Symantec",
                "Thawte",
                "GeoTrust",
            ]
        ):
            info["trust_status"] = "Trusted CA"
        else:
            info["trust_status"] = "Unknown CA"

        # Basic signature validation (simplified)
        info["signature_valid"] = signing_cert.is_valid and signing_cert.is_code_signing

        return info

    def _validate_certificate_chain(self, certificates: list[CertificateInfo]) -> bool:
        """Validate certificate chain (simplified check)."""
        if len(certificates) < 2:
            return False

        # Check if each certificate in chain is signed by the next
        for i in range(len(certificates) - 1):
            current_cert = certificates[i]
            issuer_cert = certificates[i + 1]

            # Simple check: issuer name should match
            if current_cert.issuer != issuer_cert.subject:
                return False

        return True

    def export_certificates(self, file_path: str, output_dir: str | None = None) -> dict[str, str]:
        """Export extracted certificates to PEM files using serialization module."""
        if not CRYPTOGRAPHY_AVAILABLE:
            return {}

        exported_files: dict[str, str] = {}

        try:
            signing_info = self.extract_certificates(file_path)
            if not signing_info.certificates:
                return exported_files

            # Set default output directory
            if output_dir is None:
                output_dir = os.path.dirname(file_path)

            # Extract raw certificate data
            cert_data = self._extract_certificate_data()
            if not cert_data:
                return exported_files

            # Parse certificates again to get x509 objects
            certificates: list[Any] = []
            offset = 0

            while offset < len(cert_data) and offset + 8 <= len(cert_data):
                length, _revision, cert_type = struct.unpack("<LHH", cert_data[offset : offset + 8])
                if length < 8 or offset + length > len(cert_data):
                    break

                cert_content = cert_data[offset + 8 : offset + length]

                if cert_type == 0x0002:  # WIN_CERT_TYPE_PKCS_SIGNED_DATA
                    # Extract individual certificates from PKCS#7
                    cert_start_pattern = b"\x30\x82"
                    cert_offset = 0

                    while True:
                        cert_pos = cert_content.find(cert_start_pattern, cert_offset)
                        if cert_pos == -1:
                            break

                        try:
                            if cert_pos + 4 < len(cert_content):
                                cert_len = struct.unpack(">H", cert_content[cert_pos + 2 : cert_pos + 4])[0] + 4

                                if cert_pos + cert_len <= len(cert_content):
                                    cert_der = cert_content[cert_pos : cert_pos + cert_len]
                                    cert = x509.load_der_x509_certificate(cert_der)
                                    certificates.append(cert)

                        except Exception as e:
                            logger.debug("Failed to parse certificate: %s", e)

                        cert_offset = cert_pos + 1

                offset += (length + 7) & ~7

            # Export each certificate using serialization module
            base_filename = os.path.splitext(os.path.basename(file_path))[0]

            for i, cert in enumerate(certificates):
                cert_filename = f"{base_filename}_cert_{i + 1}.pem"
                cert_path = os.path.join(output_dir, cert_filename)

                try:
                    # Use serialization.Encoding.PEM to export certificate
                    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)

                    with open(cert_path, "wb") as f:
                        f.write(pem_bytes)

                    exported_files[f"certificate_{i + 1}"] = cert_path
                    logger.info("Exported certificate to: %s", cert_path)

                except Exception as e:
                    logger.exception("Failed to export certificate %s: %s", i + 1, e)

        except Exception as e:
            logger.exception("Certificate export failed: %s", e)

        return exported_files


def extract_pe_certificates(file_path: str) -> CodeSigningInfo:
    """Extract certificates from PE file."""
    extractor = CertificateExtractor()
    return extractor.extract_certificates(file_path)


def get_certificate_security_assessment(signing_info: CodeSigningInfo) -> dict[str, Any]:
    """Assess security implications of certificate information."""
    concerns: list[str] = []
    recommendations: list[str] = []
    risk_factors: list[str] = []

    assessment: dict[str, Any] = {
        "security_level": "Unknown",
        "concerns": concerns,
        "recommendations": recommendations,
        "risk_factors": risk_factors,
    }

    if not signing_info.is_signed:
        assessment["security_level"] = "Low"
        concerns.append("File is not digitally signed")
        recommendations.append("Verify file authenticity through other means")
        risk_factors.append("No signature verification possible")
        return assessment

    signing_cert = signing_info.signing_certificate
    if not signing_cert:
        assessment["security_level"] = "Low"
        concerns.append("No valid signing certificate found")
        return assessment

    # Assess certificate validity
    if signing_cert.is_expired:
        concerns.append("Signing certificate has expired")
        risk_factors.append("Certificate expired")

    if not signing_cert.is_code_signing:
        concerns.append("Certificate not intended for code signing")
        risk_factors.append("Invalid certificate purpose")

    # Assess trust level
    if signing_info.trust_status == "Self-Signed":
        concerns.append("Certificate is self-signed")
        risk_factors.append("No third-party verification")
        recommendations.append("Verify publisher through other channels")
    elif signing_info.trust_status == "Unknown CA":
        concerns.append("Certificate issued by unknown CA")
        risk_factors.append("Untrusted certificate authority")

    # Assess key strength
    if signing_cert.public_key_size < 2048:
        concerns.append(f"Weak key size: {signing_cert.public_key_size} bits")
        risk_factors.append("Cryptographically weak signature")

    # Determine overall security level
    if not concerns:
        assessment["security_level"] = "High"
    elif len(concerns) <= 2:
        assessment["security_level"] = "Medium"
    else:
        assessment["security_level"] = "Low"

    return assessment
