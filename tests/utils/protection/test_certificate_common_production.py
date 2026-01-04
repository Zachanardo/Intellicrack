"""Production tests for certificate_common module.

Tests common certificate generation utilities including validity date calculation
and certificate builder configuration used across certificate management.
"""

from __future__ import annotations

import datetime

import pytest


try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

from intellicrack.utils.protection.certificate_common import (
    create_certificate_builder,
    get_certificate_validity_dates,
)


pytestmark = pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="cryptography library required")


class TestCertificateValidityDates:
    """Test certificate validity date calculation."""

    def test_get_certificate_validity_dates_returns_tuple(self) -> None:
        """get_certificate_validity_dates returns tuple of two datetimes."""
        not_before, not_after = get_certificate_validity_dates(365)

        assert isinstance(not_before, datetime.datetime)
        assert isinstance(not_after, datetime.datetime)

    def test_validity_dates_not_before_is_now(self) -> None:
        """Validity not_before date is approximately current time."""
        not_before, _ = get_certificate_validity_dates(365)

        now = datetime.datetime.now(datetime.UTC)
        time_diff = abs((not_before - now).total_seconds())

        assert time_diff < 5

    def test_validity_dates_not_after_matches_duration(self) -> None:
        """Validity not_after date is correct number of days from not_before."""
        valid_days = 730
        not_before, not_after = get_certificate_validity_dates(valid_days)

        duration = not_after - not_before
        assert duration.days == valid_days

    def test_validity_dates_with_one_day(self) -> None:
        """Validity dates work correctly for 1 day duration."""
        not_before, not_after = get_certificate_validity_dates(1)

        duration = not_after - not_before
        assert duration.days == 1

    def test_validity_dates_with_very_long_duration(self) -> None:
        """Validity dates work for very long durations (10 years)."""
        valid_days = 3650
        not_before, not_after = get_certificate_validity_dates(valid_days)

        duration = not_after - not_before
        assert duration.days == valid_days

    def test_validity_dates_are_timezone_aware(self) -> None:
        """Validity dates are timezone-aware using UTC."""
        not_before, not_after = get_certificate_validity_dates(365)

        assert not_before.tzinfo is not None
        assert not_after.tzinfo is not None
        assert not_before.tzinfo.tzname(None) == "UTC"
        assert not_after.tzinfo.tzname(None) == "UTC"

    def test_validity_dates_not_after_is_future(self) -> None:
        """Validity not_after date is in the future."""
        _, not_after = get_certificate_validity_dates(365)

        now = datetime.datetime.now(datetime.UTC)
        assert not_after > now

    def test_validity_dates_with_default_parameter(self) -> None:
        """Validity dates use default 365 days when not specified."""
        not_before, not_after = get_certificate_validity_dates()

        duration = not_after - not_before
        assert duration.days == 365

    def test_validity_dates_multiple_calls_produce_different_times(self) -> None:
        """Multiple calls to get_certificate_validity_dates produce slightly different times."""
        import time

        not_before1, _ = get_certificate_validity_dates(365)
        time.sleep(0.1)
        not_before2, _ = get_certificate_validity_dates(365)

        assert not_before1 != not_before2

    def test_validity_dates_consistent_duration_calculation(self) -> None:
        """Duration calculation is consistent across different valid_days values."""
        for days in [30, 90, 180, 365, 730, 1825]:
            not_before, not_after = get_certificate_validity_dates(days)
            duration = not_after - not_before
            assert duration.days == days


class TestCertificateBuilder:
    """Test certificate builder creation."""

    def test_create_certificate_builder_returns_builder(self) -> None:
        """create_certificate_builder returns valid CertificateBuilder instance."""
        builder = create_certificate_builder()

        assert builder is not None

    def test_certificate_builder_has_default_subject(self) -> None:
        """Certificate builder has default subject name configured."""
        builder = create_certificate_builder()

        if builder is None:
            pytest.skip("cryptography not available")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = builder.public_key(private_key.public_key()).sign(private_key, hashes.SHA256())  # type: ignore[attr-defined]

        subject_dict = {attr.oid._name: attr.value for attr in cert.subject}

        assert subject_dict["countryName"] == "US"
        assert subject_dict["stateOrProvinceName"] == "CA"
        assert subject_dict["localityName"] == "San Francisco"
        assert subject_dict["organizationName"] == "Test Org"
        assert subject_dict["commonName"] == "localhost"

    def test_certificate_builder_has_default_issuer(self) -> None:
        """Certificate builder has default issuer name configured."""
        builder = create_certificate_builder()

        if builder is None:
            pytest.skip("cryptography not available")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = builder.public_key(private_key.public_key()).sign(private_key, hashes.SHA256())  # type: ignore[attr-defined]

        issuer_dict = {attr.oid._name: attr.value for attr in cert.issuer}

        assert issuer_dict["countryName"] == "US"
        assert issuer_dict["stateOrProvinceName"] == "CA"
        assert issuer_dict["commonName"] == "localhost"

    def test_certificate_builder_has_random_serial_number(self) -> None:
        """Certificate builder uses random serial numbers."""
        builder1 = create_certificate_builder()
        builder2 = create_certificate_builder()

        if builder1 is None or builder2 is None:
            pytest.skip("cryptography not available")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert1 = builder1.public_key(private_key.public_key()).sign(private_key, hashes.SHA256())  # type: ignore[attr-defined]

        cert2 = builder2.public_key(private_key.public_key()).sign(private_key, hashes.SHA256())  # type: ignore[attr-defined]

        assert cert1.serial_number != cert2.serial_number

    def test_certificate_builder_has_validity_dates(self) -> None:
        """Certificate builder has validity dates configured."""
        builder = create_certificate_builder()

        if builder is None:
            pytest.skip("cryptography not available")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = builder.public_key(private_key.public_key()).sign(private_key, hashes.SHA256())  # type: ignore[attr-defined]

        now = datetime.datetime.now(datetime.UTC)
        assert cert.not_valid_before <= now
        assert cert.not_valid_after > now

    def test_certificate_builder_default_validity_is_365_days(self) -> None:
        """Certificate builder uses 365 days as default validity period."""
        builder = create_certificate_builder()

        if builder is None:
            pytest.skip("cryptography not available")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = builder.public_key(private_key.public_key()).sign(private_key, hashes.SHA256())  # type: ignore[attr-defined]

        duration = cert.not_valid_after - cert.not_valid_before
        assert duration.days == 365

    def test_certificate_builder_can_be_extended(self) -> None:
        """Certificate builder can be further customized after creation."""
        builder = create_certificate_builder()

        if builder is None:
            pytest.skip("cryptography not available")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        extended_builder = builder.add_extension(  # type: ignore[attr-defined]
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )

        cert = extended_builder.public_key(private_key.public_key()).sign(private_key, hashes.SHA256())

        basic_constraints = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
        assert basic_constraints.value.ca is True


class TestCertificateBuilderIntegration:
    """Test certificate builder integration with full certificate generation."""

    def test_builder_creates_self_signed_certificate(self) -> None:
        """Certificate builder can create complete self-signed certificate."""
        builder = create_certificate_builder()

        if builder is None:
            pytest.skip("cryptography not available")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = (
            builder.public_key(private_key.public_key())  # type: ignore[attr-defined]
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        assert cert is not None
        assert cert.subject == cert.issuer

    def test_builder_certificate_is_currently_valid(self) -> None:
        """Certificate created from builder is currently valid."""
        builder = create_certificate_builder()

        if builder is None:
            pytest.skip("cryptography not available")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = builder.public_key(private_key.public_key()).sign(private_key, hashes.SHA256())  # type: ignore[attr-defined]

        now = datetime.datetime.now(datetime.UTC)
        assert cert.not_valid_before <= now <= cert.not_valid_after

    def test_builder_can_create_multiple_certificates(self) -> None:
        """Certificate builder can be used to create multiple different certificates."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        certs = []
        for _ in range(3):
            builder = create_certificate_builder()
            if builder is None:
                pytest.skip("cryptography not available")

            cert = builder.public_key(private_key.public_key()).sign(private_key, hashes.SHA256())  # type: ignore[attr-defined]
            certs.append(cert)

        serial_numbers = [cert.serial_number for cert in certs]
        assert len(set(serial_numbers)) == 3

    def test_builder_with_custom_extensions(self) -> None:
        """Certificate builder works with custom extensions."""
        builder = create_certificate_builder()

        if builder is None:
            pytest.skip("cryptography not available")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = (
            builder.public_key(private_key.public_key())  # type: ignore[attr-defined]
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        key_usage_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        assert key_usage_ext.value.digital_signature is True
        assert key_usage_ext.value.key_encipherment is True


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_validity_dates_with_zero_days(self) -> None:
        """Validity dates handle zero days (expires immediately)."""
        not_before, not_after = get_certificate_validity_dates(0)

        duration = not_after - not_before
        assert duration.days == 0

    def test_validity_dates_with_large_number(self) -> None:
        """Validity dates handle very large valid_days values."""
        valid_days = 36500
        not_before, not_after = get_certificate_validity_dates(valid_days)

        duration = not_after - not_before
        assert duration.days == valid_days

    def test_certificate_builder_multiple_creations_independent(self) -> None:
        """Multiple certificate builder creations are independent."""
        builder1 = create_certificate_builder()
        builder2 = create_certificate_builder()

        if builder1 is None or builder2 is None:
            pytest.skip("cryptography not available")

        assert builder1 is not builder2

    def test_validity_dates_precision(self) -> None:
        """Validity dates maintain precision beyond day level."""
        not_before, not_after = get_certificate_validity_dates(1)

        duration_seconds = (not_after - not_before).total_seconds()
        expected_seconds = 24 * 60 * 60

        assert abs(duration_seconds - expected_seconds) < 1

    def test_certificate_builder_none_when_cryptography_unavailable(self) -> None:
        """Certificate builder returns None when cryptography is unavailable."""
        if not HAS_CRYPTOGRAPHY:
            builder = create_certificate_builder()

            assert builder is None


class TestCertificateCommonIntegration:
    """Test integration between validity dates and certificate builder."""

    def test_builder_uses_validity_dates_function(self) -> None:
        """Certificate builder internally uses get_certificate_validity_dates."""
        builder = create_certificate_builder()

        if builder is None:
            pytest.skip("cryptography not available")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = builder.public_key(private_key.public_key()).sign(private_key, hashes.SHA256())  # type: ignore[attr-defined]

        not_before_manual, not_after_manual = get_certificate_validity_dates(365)

        cert_not_before = cert.not_valid_before
        cert_not_after = cert.not_valid_after

        time_diff_before = abs((cert_not_before - not_before_manual).total_seconds())
        time_diff_after = abs((cert_not_after - not_after_manual).total_seconds())

        assert time_diff_before < 60
        assert time_diff_after < 60

    def test_custom_validity_in_builder(self) -> None:
        """Certificate builder can be customized with different validity periods."""
        from intellicrack.utils.protection.certificate_common import (
            get_certificate_validity_dates,
        )

        not_before_custom, not_after_custom = get_certificate_validity_dates(90)

        builder = create_certificate_builder()

        if builder is None:
            pytest.skip("cryptography not available")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        custom_builder = (
            builder.not_valid_before(not_before_custom)  # type: ignore[attr-defined]
            .not_valid_after(not_after_custom)
        )

        cert = custom_builder.public_key(private_key.public_key()).sign(private_key, hashes.SHA256())

        duration = cert.not_valid_after - cert.not_valid_before
        assert duration.days == 90
