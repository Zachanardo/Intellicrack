"""Certificate Generation and Management Utilities.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import datetime
import logging
from typing import Any, cast

from intellicrack.utils.logger import logger


try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    HAS_CRYPTOGRAPHY = True
except ImportError as e:
    logger.error("Import error in certificate_utils: %s", e)
    HAS_CRYPTOGRAPHY = False

    class X509:
        class Certificate:
            pass


def generate_self_signed_cert(
    common_name: str = "localhost",
    organization: str = "IntelliCrack",
    country: str = "US",
    state: str = "State",
    locality: str = "City",
    valid_days: int = 365,
) -> tuple[bytes, bytes] | None:
    """Generate a self-signed certificate for SSL/TLS operations.

    Args:
        common_name: Common name for the certificate
        organization: Organization name
        country: Country code
        state: State or province
        locality: City or locality
        valid_days: Number of days the certificate should be valid

    Returns:
        Tuple of (certificate_pem, private_key_pem) or None if generation fails

    """
    logger = logging.getLogger("IntellicrackLogger.CertUtils")

    if not HAS_CRYPTOGRAPHY:
        logger.error("cryptography library not available for certificate generation")
        return None

    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create certificate subject
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ],
        )

        # Create certificate builder
        cert_builder = (
            x509
            .CertificateBuilder()
            .subject_name(
                subject,
            )
            .issuer_name(
                issuer,
            )
            .public_key(
                private_key.public_key(),
            )
            .serial_number(
                x509.random_serial_number(),
            )
        )

        # Set validity dates
        from .certificate_common import get_certificate_validity_dates

        not_valid_before, not_valid_after = get_certificate_validity_dates(valid_days)
        cert_builder = (
            cert_builder
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(common_name),
                        x509.DNSName("localhost"),
                        x509.DNSName("127.0.0.1"),
                    ],
                ),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )

        # Sign and get final certificate object
        cert: x509.Certificate = cert_builder.sign(private_key, hashes.SHA256())

        # Serialize certificate and key to PEM format
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        logger.info("Generated self-signed certificate for %s", common_name)
        return cert_pem, key_pem

    except Exception as e:
        logger.exception("Failed to generate self-signed certificate: %s", e)
        return None


def load_certificate_from_file(cert_path: str) -> x509.Certificate | None:
    """Load certificate from PEM file.

    Args:
        cert_path: Path to certificate file

    Returns:
        Certificate object or None if loading fails

    """
    logger = logging.getLogger("IntellicrackLogger.CertUtils")

    if not HAS_CRYPTOGRAPHY:
        logger.error("cryptography library not available")
        return None

    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()

        cert = x509.load_pem_x509_certificate(cert_data)
        logger.info("Loaded certificate from %s", cert_path)
        return cert

    except Exception as e:
        logger.exception("Failed to load certificate from %s: %s", cert_path, e)
        return None


def verify_certificate_validity(cert: x509.Certificate) -> bool:
    """Verify if certificate is currently valid.

    Args:
        cert: Certificate to verify

    Returns:
        True if certificate is valid, False otherwise

    """
    try:
        now = datetime.datetime.now(datetime.UTC)
        return cert.not_valid_before <= now <= cert.not_valid_after

    except Exception as e:
        logger.error("Exception in certificate_utils: %s", e, exc_info=True)
        return False


def get_certificate_info(cert: x509.Certificate) -> dict[str, Any]:
    """Extract information from certificate.

    Args:
        cert: Certificate to analyze

    Returns:
        Dictionary containing certificate information

    """
    try:
        subject_dict: dict[str, Any] = {}
        issuer_dict: dict[str, Any] = {}
        extensions_list: list[dict[str, Any]] = []

        info: dict[str, Any] = {
            "subject": subject_dict,
            "issuer": issuer_dict,
            "serial_number": str(cert.serial_number),
            "not_valid_before": cert.not_valid_before.isoformat(),
            "not_valid_after": cert.not_valid_after.isoformat(),
            "is_valid": verify_certificate_validity(cert),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "extensions": extensions_list,
        }

        # Extract subject information
        for attribute in cert.subject:
            subject_dict[attribute.oid._name] = attribute.value

        # Extract issuer information
        for attribute in cert.issuer:
            issuer_dict[attribute.oid._name] = attribute.value

        # Extract extensions
        for extension in cert.extensions:
            ext_info: dict[str, Any] = {
                "oid": extension.oid._name,
                "critical": extension.critical,
                "value": str(extension.value),
            }
            extensions_list.append(ext_info)

        return info

    except Exception as e:
        logger.error("Exception in certificate_utils: %s", e, exc_info=True)
        return {"error": str(e)}


__all__ = [
    "generate_self_signed_cert",
    "get_certificate_info",
    "load_certificate_from_file",
    "verify_certificate_validity",
]
