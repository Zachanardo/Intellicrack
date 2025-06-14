"""
Certificate generation utilities for Intellicrack.

This module provides shared utilities for generating X.509 certificates.
"""

import datetime
import logging
from typing import Optional, Tuple

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    x509 = None
    NameOID = None
    hashes = None
    rsa = None
    serialization = None


logger = logging.getLogger(__name__)


def generate_self_signed_cert(
    common_name: str,
    organization: str = "Test Organization",
    country: str = "US",
    state: str = "Test State",
    locality: str = "Test City",
    valid_days: int = 365,
    key_size: int = 2048,
    is_ca: bool = False
) -> Optional[Tuple[bytes, bytes]]:
    """
    Generate a self-signed certificate.
    
    Args:
        common_name: Common name for the certificate
        organization: Organization name
        country: Country code
        state: State/Province name
        locality: City/Locality name
        valid_days: Number of days the certificate is valid
        key_size: RSA key size in bits
        is_ca: Whether to generate a CA certificate with BasicConstraints
        
    Returns:
        Tuple of (certificate_pem, private_key_pem) or None if failed
    """
    if not CRYPTO_AVAILABLE:
        logger.error("Cryptography library not available")
        return None
        
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Create certificate subject and issuer
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Build certificate
        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=valid_days)
        )
        
        # Add CA extension if requested
        if is_ca:
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True
            )
        else:
            # Add Subject Alternative Names for non-CA certificates
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(common_name),
                    x509.DNSName("localhost"),
                    x509.DNSName("*.localhost"),
                ]),
                critical=False,
            )
            
        cert = cert_builder.sign(private_key, hashes.SHA256())
        
        # Serialize certificate and key
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return (cert_pem, key_pem)
        
    except Exception as e:
        logger.error("Error generating certificate: %s", e)
        return None