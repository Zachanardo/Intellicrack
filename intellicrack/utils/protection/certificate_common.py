"""
Common certificate generation utilities.

This module consolidates certificate creation patterns.
"""

import datetime
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

def create_certificate_builder():
    """
    Create a certificate builder with common settings.

    Returns:
        Certificate builder object or None if cryptography not available
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        builder = x509.CertificateBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
        ).issuer_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
        ).serial_number(
            x509.random_serial_number()
        )

        # Set validity dates
        not_valid_before, not_valid_after = get_certificate_validity_dates(365)
        builder = builder.not_valid_before(not_valid_before).not_valid_after(not_valid_after)

        return builder
    except ImportError:
        logger.warning("cryptography library not available for certificate generation")
        return None


def get_certificate_validity_dates(valid_days: int = 365) -> Tuple[datetime.datetime, datetime.datetime]:
    """
    Get certificate validity dates.

    Args:
        valid_days: Number of days the certificate should be valid

    Returns:
        Tuple of (not_valid_before, not_valid_after) datetimes
    """
    not_valid_before = datetime.datetime.utcnow()
    not_valid_after = not_valid_before + datetime.timedelta(days=valid_days)
    return not_valid_before, not_valid_after
