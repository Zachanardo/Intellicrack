"""Production tests for certificate chain generation.

Tests validate that CertificateChainGenerator produces cryptographically valid
X.509 certificates that can be used for actual TLS connections and MITM operations.

All tests use REAL cryptographic operations - no mocks or stubs.
Tests MUST FAIL if generated certificates are invalid or chains don't verify.
"""

import base64
import datetime
import hashlib
import socket
import ssl
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.x509.oid import ExtensionOID, NameOID

from intellicrack.core.certificate.cert_chain_generator import (
    CertificateChain,
    CertificateChainGenerator,
)


class TestRootCAGeneration:
    """Tests for root CA certificate generation."""

    def test_generate_root_ca_returns_valid_certificate_and_key(self) -> None:
        """Root CA generation produces valid self-signed certificate with correct key."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()

        assert isinstance(root_cert, x509.Certificate)
        assert isinstance(root_key, rsa.RSAPrivateKey)
        assert root_cert.signature is not None
        assert len(root_cert.signature) > 0

    def test_root_ca_is_self_signed(self) -> None:
        """Root CA certificate is self-signed (issuer equals subject)."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()

        assert root_cert.issuer == root_cert.subject

    def test_root_ca_signature_verifies_with_own_public_key(self) -> None:
        """Root CA signature can be verified using its own public key."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()

        public_key = root_cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)

        try:
            public_key.verify(
                root_cert.signature,
                root_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                root_cert.signature_hash_algorithm,
            )
        except Exception as e:
            pytest.fail(f"Root CA signature verification failed: {e}")

    def test_root_ca_has_correct_subject_fields(self) -> None:
        """Root CA has proper subject fields including CN, O, and OU."""
        generator = CertificateChainGenerator()
        root_cert, _ = generator.generate_root_ca()

        subject_attrs: Dict[Any, Any] = {attr.oid: attr.value for attr in root_cert.subject}

        assert subject_attrs[NameOID.COMMON_NAME] == "Intellicrack Root CA"
        assert subject_attrs[NameOID.ORGANIZATION_NAME] == "Intellicrack"
        assert subject_attrs[NameOID.ORGANIZATIONAL_UNIT_NAME] == "Security Research"

    def test_root_ca_uses_4096_bit_rsa_key(self) -> None:
        """Root CA private key is 4096-bit RSA for strong security."""
        generator = CertificateChainGenerator()
        _, root_key = generator.generate_root_ca()

        assert root_key.key_size == 4096

    def test_root_ca_has_ca_basic_constraints(self) -> None:
        """Root CA certificate has CA=TRUE basic constraints with pathlen=2."""
        generator = CertificateChainGenerator()
        root_cert, _ = generator.generate_root_ca()

        basic_constraints = root_cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        assert isinstance(basic_constraints, x509.BasicConstraints)
        assert basic_constraints.ca is True
        assert basic_constraints.path_length == 2

    def test_root_ca_has_correct_key_usage(self) -> None:
        """Root CA has keyCertSign and cRLSign key usage."""
        generator = CertificateChainGenerator()
        root_cert, _ = generator.generate_root_ca()

        key_usage = root_cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
        assert isinstance(key_usage, x509.KeyUsage)
        assert key_usage.key_cert_sign is True
        assert key_usage.crl_sign is True
        assert key_usage.digital_signature is False
        assert key_usage.key_encipherment is False

    def test_root_ca_has_subject_key_identifier(self) -> None:
        """Root CA has subject key identifier extension."""
        generator = CertificateChainGenerator()
        root_cert, _ = generator.generate_root_ca()

        ski = root_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value
        assert isinstance(ski, x509.SubjectKeyIdentifier)
        assert len(ski.digest) == 20

    def test_root_ca_validity_period_is_10_years(self) -> None:
        """Root CA is valid for approximately 10 years (3650 days)."""
        generator = CertificateChainGenerator()
        root_cert, _ = generator.generate_root_ca()

        validity_days = (
            root_cert.not_valid_after_utc - root_cert.not_valid_before_utc
        ).days
        assert 3648 <= validity_days <= 3652

    def test_root_ca_uses_sha256_signature(self) -> None:
        """Root CA uses SHA-256 signature algorithm."""
        generator = CertificateChainGenerator()
        root_cert, _ = generator.generate_root_ca()

        assert isinstance(root_cert.signature_hash_algorithm, hashes.SHA256)

    def test_root_ca_serial_number_is_unique(self) -> None:
        """Each generated root CA has unique serial number."""
        generator = CertificateChainGenerator()
        root_cert1, _ = generator.generate_root_ca()
        root_cert2, _ = generator.generate_root_ca()

        assert root_cert1.serial_number != root_cert2.serial_number
        assert root_cert1.serial_number > 0
        assert root_cert2.serial_number > 0

    def test_root_ca_not_valid_before_is_current_time(self) -> None:
        """Root CA not_valid_before is approximately current UTC time."""
        generator = CertificateChainGenerator()
        before_generation: datetime.datetime = datetime.datetime.now(datetime.UTC)
        root_cert, _ = generator.generate_root_ca()
        after_generation: datetime.datetime = datetime.datetime.now(datetime.UTC)

        assert before_generation <= root_cert.not_valid_before_utc <= after_generation


class TestIntermediateCAGeneration:
    """Tests for intermediate CA certificate generation."""

    def test_generate_intermediate_ca_returns_valid_certificate_and_key(self) -> None:
        """Intermediate CA generation produces valid certificate signed by root."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )

        assert isinstance(intermediate_cert, x509.Certificate)
        assert isinstance(intermediate_key, rsa.RSAPrivateKey)
        assert intermediate_cert.signature is not None

    def test_intermediate_ca_is_signed_by_root(self) -> None:
        """Intermediate CA issuer matches root CA subject."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, _ = generator.generate_intermediate_ca(root_cert, root_key)

        assert intermediate_cert.issuer == root_cert.subject

    def test_intermediate_ca_signature_verifies_with_root_public_key(self) -> None:
        """Intermediate CA signature verifies with root CA public key."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, _ = generator.generate_intermediate_ca(root_cert, root_key)

        root_public_key = root_cert.public_key()
        assert isinstance(root_public_key, rsa.RSAPublicKey)

        try:
            root_public_key.verify(
                intermediate_cert.signature,
                intermediate_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                intermediate_cert.signature_hash_algorithm,
            )
        except Exception as e:
            pytest.fail(f"Intermediate CA signature verification failed: {e}")

    def test_intermediate_ca_has_correct_subject_fields(self) -> None:
        """Intermediate CA has proper subject with CN and O."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, _ = generator.generate_intermediate_ca(root_cert, root_key)

        subject_attrs: Dict[Any, Any] = {attr.oid: attr.value for attr in intermediate_cert.subject}

        assert subject_attrs[NameOID.COMMON_NAME] == "Intellicrack Intermediate CA"
        assert subject_attrs[NameOID.ORGANIZATION_NAME] == "Intellicrack"

    def test_intermediate_ca_uses_2048_bit_rsa_key(self) -> None:
        """Intermediate CA private key is 2048-bit RSA."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        _, intermediate_key = generator.generate_intermediate_ca(root_cert, root_key)

        assert intermediate_key.key_size == 2048

    def test_intermediate_ca_has_ca_basic_constraints_with_pathlen_zero(self) -> None:
        """Intermediate CA has CA=TRUE with pathlen=0."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, _ = generator.generate_intermediate_ca(root_cert, root_key)

        basic_constraints = intermediate_cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        assert isinstance(basic_constraints, x509.BasicConstraints)
        assert basic_constraints.ca is True
        assert basic_constraints.path_length == 0

    def test_intermediate_ca_has_correct_key_usage(self) -> None:
        """Intermediate CA has keyCertSign, cRLSign, and digitalSignature."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, _ = generator.generate_intermediate_ca(root_cert, root_key)

        key_usage = intermediate_cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
        assert isinstance(key_usage, x509.KeyUsage)
        assert key_usage.key_cert_sign is True
        assert key_usage.crl_sign is True
        assert key_usage.digital_signature is True
        assert key_usage.key_encipherment is False

    def test_intermediate_ca_has_authority_key_identifier(self) -> None:
        """Intermediate CA has authority key identifier matching root."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, _ = generator.generate_intermediate_ca(root_cert, root_key)

        root_ski_ext = root_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value
        assert isinstance(root_ski_ext, x509.SubjectKeyIdentifier)
        intermediate_aki = intermediate_cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value

        assert isinstance(intermediate_aki, x509.AuthorityKeyIdentifier)
        assert intermediate_aki.key_identifier == root_ski_ext.digest

    def test_intermediate_ca_has_subject_key_identifier(self) -> None:
        """Intermediate CA has subject key identifier extension."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, _ = generator.generate_intermediate_ca(root_cert, root_key)

        ski = intermediate_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value
        assert isinstance(ski, x509.SubjectKeyIdentifier)
        assert len(ski.digest) == 20

    def test_intermediate_ca_validity_period_is_5_years(self) -> None:
        """Intermediate CA is valid for approximately 5 years (1825 days)."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, _ = generator.generate_intermediate_ca(root_cert, root_key)

        validity_days = (
            intermediate_cert.not_valid_after_utc
            - intermediate_cert.not_valid_before_utc
        ).days
        assert 1823 <= validity_days <= 1827


class TestLeafCertificateGeneration:
    """Tests for end entity (leaf) certificate generation."""

    def test_generate_leaf_cert_returns_valid_certificate_and_key(self) -> None:
        """Leaf certificate generation produces valid cert signed by intermediate."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )
        leaf_cert, leaf_key = generator.generate_leaf_cert(
            "example.com", intermediate_cert, intermediate_key
        )

        assert isinstance(leaf_cert, x509.Certificate)
        assert isinstance(leaf_key, rsa.RSAPrivateKey)
        assert leaf_cert.signature is not None

    def test_leaf_cert_is_signed_by_intermediate(self) -> None:
        """Leaf certificate issuer matches intermediate CA subject."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )
        leaf_cert, _ = generator.generate_leaf_cert(
            "example.com", intermediate_cert, intermediate_key
        )

        assert leaf_cert.issuer == intermediate_cert.subject

    def test_leaf_cert_signature_verifies_with_intermediate_public_key(self) -> None:
        """Leaf certificate signature verifies with intermediate CA public key."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )
        leaf_cert, _ = generator.generate_leaf_cert(
            "secure.example.com", intermediate_cert, intermediate_key
        )

        intermediate_public_key = intermediate_cert.public_key()
        assert isinstance(intermediate_public_key, rsa.RSAPublicKey)

        try:
            intermediate_public_key.verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                leaf_cert.signature_hash_algorithm,
            )
        except Exception as e:
            pytest.fail(f"Leaf certificate signature verification failed: {e}")

    def test_leaf_cert_has_correct_common_name(self) -> None:
        """Leaf certificate CN matches requested domain."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )
        domain = "api.example.com"
        leaf_cert, _ = generator.generate_leaf_cert(
            domain, intermediate_cert, intermediate_key
        )

        subject_attrs: Dict[Any, Any] = {attr.oid: attr.value for attr in leaf_cert.subject}
        assert subject_attrs[NameOID.COMMON_NAME] == domain

    def test_leaf_cert_has_subject_alternative_name_with_domain(self) -> None:
        """Leaf certificate has SAN extension with requested domain."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )
        domain = "test.example.com"
        leaf_cert, _ = generator.generate_leaf_cert(
            domain, intermediate_cert, intermediate_key
        )

        san = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        assert isinstance(san, x509.SubjectAlternativeName)
        dns_names: List[Any] = list(san.get_values_for_type(x509.DNSName))
        assert domain in dns_names

    def test_leaf_cert_includes_wildcard_in_san_for_non_wildcard_domains(self) -> None:
        """Leaf cert for non-wildcard domain includes wildcard SAN entry."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )
        domain = "example.com"
        leaf_cert, _ = generator.generate_leaf_cert(
            domain, intermediate_cert, intermediate_key
        )

        san = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        dns_names: List[Any] = list(san.get_values_for_type(x509.DNSName))
        assert "example.com" in dns_names
        assert "*.example.com" in dns_names

    def test_leaf_cert_wildcard_domain_does_not_duplicate_wildcard(self) -> None:
        """Leaf cert for wildcard domain doesn't add duplicate wildcard."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )
        domain = "*.example.com"
        leaf_cert, _ = generator.generate_leaf_cert(
            domain, intermediate_cert, intermediate_key
        )

        san = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        dns_names: List[Any] = list(san.get_values_for_type(x509.DNSName))
        assert dns_names.count("*.example.com") == 1

    def test_leaf_cert_uses_2048_bit_rsa_key(self) -> None:
        """Leaf certificate private key is 2048-bit RSA."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )
        _, leaf_key = generator.generate_leaf_cert(
            "example.com", intermediate_cert, intermediate_key
        )

        assert leaf_key.key_size == 2048

    def test_leaf_cert_has_ca_false_basic_constraints(self) -> None:
        """Leaf certificate has CA=FALSE basic constraints."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )
        leaf_cert, _ = generator.generate_leaf_cert(
            "example.com", intermediate_cert, intermediate_key
        )

        basic_constraints = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        assert isinstance(basic_constraints, x509.BasicConstraints)
        assert basic_constraints.ca is False
        assert basic_constraints.path_length is None

    def test_leaf_cert_has_correct_key_usage(self) -> None:
        """Leaf certificate has digitalSignature and keyEncipherment."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )
        leaf_cert, _ = generator.generate_leaf_cert(
            "example.com", intermediate_cert, intermediate_key
        )

        key_usage = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
        assert isinstance(key_usage, x509.KeyUsage)
        assert key_usage.digital_signature is True
        assert key_usage.key_encipherment is True
        assert key_usage.key_cert_sign is False
        assert key_usage.crl_sign is False

    def test_leaf_cert_has_extended_key_usage_for_tls(self) -> None:
        """Leaf certificate has serverAuth and clientAuth extended key usage."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )
        leaf_cert, _ = generator.generate_leaf_cert(
            "example.com", intermediate_cert, intermediate_key
        )

        eku = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
        assert isinstance(eku, x509.ExtendedKeyUsage)
        assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku
        assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku

    def test_leaf_cert_has_authority_key_identifier_matching_intermediate(
        self,
    ) -> None:
        """Leaf certificate AKI matches intermediate CA SKI."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )
        leaf_cert, _ = generator.generate_leaf_cert(
            "example.com", intermediate_cert, intermediate_key
        )

        intermediate_ski = intermediate_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value
        leaf_aki = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value

        assert isinstance(leaf_aki, x509.AuthorityKeyIdentifier)
        assert leaf_aki.key_identifier == intermediate_ski.digest

    def test_leaf_cert_validity_period_is_1_year(self) -> None:
        """Leaf certificate is valid for approximately 1 year (365 days)."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        intermediate_cert, intermediate_key = generator.generate_intermediate_ca(
            root_cert, root_key
        )
        leaf_cert, _ = generator.generate_leaf_cert(
            "example.com", intermediate_cert, intermediate_key
        )

        validity_days = (
            leaf_cert.not_valid_after_utc - leaf_cert.not_valid_before_utc
        ).days
        assert 364 <= validity_days <= 366


class TestFullChainGeneration:
    """Tests for complete certificate chain generation."""

    def test_generate_full_chain_returns_complete_chain(self) -> None:
        """Full chain generation returns CertificateChain with all components."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("example.com")

        assert isinstance(chain, CertificateChain)
        assert isinstance(chain.leaf_cert, x509.Certificate)
        assert isinstance(chain.intermediate_cert, x509.Certificate)
        assert isinstance(chain.root_cert, x509.Certificate)
        assert isinstance(chain.leaf_key, rsa.RSAPrivateKey)
        assert isinstance(chain.intermediate_key, rsa.RSAPrivateKey)
        assert isinstance(chain.root_key, rsa.RSAPrivateKey)

    def test_full_chain_certificates_form_valid_hierarchy(self) -> None:
        """Full chain forms valid PKI hierarchy: leaf → intermediate → root."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("secure.example.com")

        assert chain.leaf_cert.issuer == chain.intermediate_cert.subject
        assert chain.intermediate_cert.issuer == chain.root_cert.subject
        assert chain.root_cert.issuer == chain.root_cert.subject

    def test_full_chain_all_signatures_verify(self) -> None:
        """All certificates in chain have valid signatures."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("api.example.com")

        root_public = chain.root_cert.public_key()
        assert isinstance(root_public, rsa.RSAPublicKey)
        intermediate_public = chain.intermediate_cert.public_key()
        assert isinstance(intermediate_public, rsa.RSAPublicKey)

        try:
            root_public.verify(
                chain.root_cert.signature,
                chain.root_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                chain.root_cert.signature_hash_algorithm,
            )
        except Exception as e:
            pytest.fail(f"Root CA signature verification failed: {e}")

        try:
            root_public.verify(
                chain.intermediate_cert.signature,
                chain.intermediate_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                chain.intermediate_cert.signature_hash_algorithm,
            )
        except Exception as e:
            pytest.fail(f"Intermediate CA signature verification failed: {e}")

        try:
            intermediate_public.verify(
                chain.leaf_cert.signature,
                chain.leaf_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                chain.leaf_cert.signature_hash_algorithm,
            )
        except Exception as e:
            pytest.fail(f"Leaf certificate signature verification failed: {e}")

    def test_full_chain_leaf_cert_matches_requested_domain(self) -> None:
        """Full chain leaf certificate CN matches requested domain."""
        generator = CertificateChainGenerator()
        domain = "test.intellicrack.local"
        chain = generator.generate_full_chain(domain)

        subject_attrs: Dict[Any, Any] = {attr.oid: attr.value for attr in chain.leaf_cert.subject}
        assert subject_attrs[NameOID.COMMON_NAME] == domain

    def test_full_chain_generates_unique_certificates(self) -> None:
        """Multiple full chain generations produce unique certificates."""
        generator = CertificateChainGenerator()
        chain1 = generator.generate_full_chain("example.com")
        chain2 = generator.generate_full_chain("example.com")

        assert chain1.root_cert.serial_number != chain2.root_cert.serial_number
        assert (
            chain1.intermediate_cert.serial_number
            != chain2.intermediate_cert.serial_number
        )
        assert chain1.leaf_cert.serial_number != chain2.leaf_cert.serial_number

    def test_full_chain_wildcard_domain_creates_valid_wildcard_cert(self) -> None:
        """Full chain generation with wildcard domain produces valid wildcard cert."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("*.example.com")

        subject_attrs: Dict[Any, Any] = {attr.oid: attr.value for attr in chain.leaf_cert.subject}
        assert subject_attrs[NameOID.COMMON_NAME] == "*.example.com"

        san = chain.leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        dns_names: List[Any] = list(san.get_values_for_type(x509.DNSName))
        assert "*.example.com" in dns_names

    def test_full_chain_validity_periods_are_nested(self) -> None:
        """Leaf validity is within intermediate, intermediate within root."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("example.com")

        assert (
            chain.root_cert.not_valid_before_utc
            <= chain.intermediate_cert.not_valid_before_utc
        )
        assert (
            chain.intermediate_cert.not_valid_before_utc
            <= chain.leaf_cert.not_valid_before_utc
        )
        assert (
            chain.leaf_cert.not_valid_after_utc
            <= chain.intermediate_cert.not_valid_after_utc
        )
        assert (
            chain.intermediate_cert.not_valid_after_utc
            <= chain.root_cert.not_valid_after_utc
        )


class TestCertificateExport:
    """Tests for certificate and key export functionality."""

    def test_export_chain_pem_produces_valid_pem_format(self) -> None:
        """Chain PEM export produces valid PEM-formatted string."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("example.com")
        pem_chain = generator.export_chain_pem(chain)

        assert isinstance(pem_chain, str)
        assert pem_chain.count("-----BEGIN CERTIFICATE-----") == 3
        assert pem_chain.count("-----END CERTIFICATE-----") == 3

    def test_export_chain_pem_orders_certificates_correctly(self) -> None:
        """Chain PEM export orders certificates as leaf → intermediate → root."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("example.com")
        pem_chain = generator.export_chain_pem(chain)

        leaf_pem = chain.leaf_cert.public_bytes(serialization.Encoding.PEM).decode()
        intermediate_pem = chain.intermediate_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode()
        root_pem = chain.root_cert.public_bytes(serialization.Encoding.PEM).decode()

        leaf_pos = pem_chain.index(leaf_pem)
        intermediate_pos = pem_chain.index(intermediate_pem)
        root_pos = pem_chain.index(root_pem)

        assert leaf_pos < intermediate_pos < root_pos

    def test_export_chain_pem_can_be_loaded_back(self) -> None:
        """Exported PEM chain can be loaded back as certificates."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("example.com")
        pem_chain = generator.export_chain_pem(chain)

        cert_blocks = pem_chain.split("-----BEGIN CERTIFICATE-----")[1:]
        loaded_certs: List[x509.Certificate] = []
        for block in cert_blocks:
            cert_pem = f"-----BEGIN CERTIFICATE-----{block}"
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            loaded_certs.append(cert)

        assert len(loaded_certs) == 3
        assert loaded_certs[0].serial_number == chain.leaf_cert.serial_number
        assert loaded_certs[1].serial_number == chain.intermediate_cert.serial_number
        assert loaded_certs[2].serial_number == chain.root_cert.serial_number

    def test_export_cert_der_produces_valid_der_bytes(self) -> None:
        """Certificate DER export produces valid DER-encoded bytes."""
        generator = CertificateChainGenerator()
        root_cert, _ = generator.generate_root_ca()
        der_bytes = generator.export_cert_der(root_cert)

        assert isinstance(der_bytes, bytes)
        assert len(der_bytes) > 100

        loaded_cert = x509.load_der_x509_certificate(der_bytes)
        assert loaded_cert.serial_number == root_cert.serial_number

    def test_export_private_key_pem_produces_valid_key(self) -> None:
        """Private key PEM export produces valid PEM-formatted key."""
        generator = CertificateChainGenerator()
        _, root_key = generator.generate_root_ca()
        key_pem = generator.export_private_key_pem(root_key)

        assert isinstance(key_pem, str)
        assert "-----BEGIN RSA PRIVATE KEY-----" in key_pem
        assert "-----END RSA PRIVATE KEY-----" in key_pem

        loaded_key: Any = load_pem_private_key(key_pem.encode(), password=None)
        assert isinstance(loaded_key, rsa.RSAPrivateKey)
        assert loaded_key.key_size == root_key.key_size

    def test_export_public_key_pem_produces_valid_key(self) -> None:
        """Public key PEM export produces valid PEM-formatted public key."""
        generator = CertificateChainGenerator()
        root_cert, root_key = generator.generate_root_ca()
        public_key = root_key.public_key()
        pub_key_pem = generator.export_public_key_pem(public_key)

        assert isinstance(pub_key_pem, str)
        assert "-----BEGIN PUBLIC KEY-----" in pub_key_pem
        assert "-----END PUBLIC KEY-----" in pub_key_pem

        loaded_public_key: Any = load_pem_public_key(pub_key_pem.encode())
        assert isinstance(loaded_public_key, rsa.RSAPublicKey)

    def test_exported_private_key_can_decrypt_data_encrypted_with_public_key(
        self,
    ) -> None:
        """Exported private key can decrypt data encrypted with corresponding public key."""
        generator = CertificateChainGenerator()
        _, leaf_key = generator.generate_root_ca()
        public_key = leaf_key.public_key()

        plaintext = b"Test data for encryption"
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        key_pem = generator.export_private_key_pem(leaf_key)
        loaded_key: Any = load_pem_private_key(key_pem.encode(), password=None)
        assert isinstance(loaded_key, rsa.RSAPrivateKey)

        decrypted = loaded_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        assert decrypted == plaintext


class TestCertificatePinningBypass:
    """Tests for certificate pinning bypass scenarios."""

    def test_leaf_cert_public_key_can_be_extracted_for_pinning(self) -> None:
        """Leaf certificate public key can be extracted for pin calculation."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("pinned.example.com")

        public_key = chain.leaf_cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert len(public_key_bytes) > 0

    def test_leaf_cert_spki_sha256_hash_matches_expected_pin_format(self) -> None:
        """Leaf cert SPKI SHA-256 hash produces valid pin format."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("pinned.example.com")

        public_key = chain.leaf_cert.public_key()
        spki_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        pin_sha256 = hashlib.sha256(spki_bytes).digest()
        assert len(pin_sha256) == 32

        import base64

        pin_base64 = base64.b64encode(pin_sha256).decode()
        assert len(pin_base64) == 44

    def test_root_ca_can_be_used_to_sign_arbitrary_leaf_certs(self) -> None:
        """Generated root CA can sign arbitrary leaf certificates for pinning bypass."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("original.example.com")

        new_leaf_cert, new_leaf_key = generator.generate_leaf_cert(
            "bypassed.example.com", chain.intermediate_cert, chain.intermediate_key
        )

        intermediate_public = chain.intermediate_cert.public_key()
        assert isinstance(intermediate_public, rsa.RSAPublicKey)

        try:
            intermediate_public.verify(
                new_leaf_cert.signature,
                new_leaf_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                new_leaf_cert.signature_hash_algorithm,
            )
        except Exception as e:
            pytest.fail(f"New leaf certificate signature verification failed: {e}")

    def test_multiple_leaf_certs_can_share_same_ca_chain(self) -> None:
        """Multiple leaf certificates can be generated using same CA chain."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("example.com")

        domains = ["api.example.com", "cdn.example.com", "secure.example.com"]
        leaf_certs = []

        for domain in domains:
            leaf_cert, _ = generator.generate_leaf_cert(
                domain, chain.intermediate_cert, chain.intermediate_key
            )
            leaf_certs.append(leaf_cert)

        assert len(leaf_certs) == 3
        for cert in leaf_certs:
            assert cert.issuer == chain.intermediate_cert.subject

    def test_generated_chain_can_be_used_for_https_server_configuration(
        self,
    ) -> None:
        """Generated certificate chain has all components needed for HTTPS server."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("server.example.com")

        leaf_cert_pem = chain.leaf_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode()
        leaf_key_pem = generator.export_private_key_pem(chain.leaf_key)
        chain_pem = generator.export_chain_pem(chain)

        assert "-----BEGIN CERTIFICATE-----" in leaf_cert_pem
        assert "-----BEGIN RSA PRIVATE KEY-----" in leaf_key_pem
        assert chain_pem.count("-----BEGIN CERTIFICATE-----") == 3

        assert chain.leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )
        eku = chain.leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
        assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku


class TestCryptographicOperations:
    """Tests for cryptographic operations with generated certificates."""

    def test_leaf_private_key_can_sign_data(self) -> None:
        """Leaf certificate private key can sign data."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("example.com")

        data = b"Test data to be signed"
        signature = chain.leaf_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        assert len(signature) == 256

    def test_leaf_public_key_can_verify_signature_from_private_key(self) -> None:
        """Leaf certificate public key verifies signatures from private key."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("example.com")

        data = b"Data to sign and verify"
        signature = chain.leaf_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        public_key = chain.leaf_cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)

        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except Exception as e:
            pytest.fail(f"Signature verification failed: {e}")

    def test_private_key_and_certificate_public_key_match(self) -> None:
        """Private key and certificate public key are cryptographically linked."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("example.com")

        private_key_public = chain.leaf_key.public_key()
        cert_public = chain.leaf_cert.public_key()

        private_public_numbers = private_key_public.public_numbers()
        cert_public_numbers = cert_public.public_numbers()

        assert private_public_numbers.n == cert_public_numbers.n
        assert private_public_numbers.e == cert_public_numbers.e

    def test_root_ca_can_verify_complete_chain(self) -> None:
        """Root CA public key can verify intermediate, intermediate verifies leaf."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("example.com")

        root_public = chain.root_cert.public_key()
        assert isinstance(root_public, rsa.RSAPublicKey)
        intermediate_public = chain.intermediate_cert.public_key()
        assert isinstance(intermediate_public, rsa.RSAPublicKey)

        try:
            root_public.verify(
                chain.root_cert.signature,
                chain.root_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                chain.root_cert.signature_hash_algorithm,
            )
            root_public.verify(
                chain.intermediate_cert.signature,
                chain.intermediate_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                chain.intermediate_cert.signature_hash_algorithm,
            )
            intermediate_public.verify(
                chain.leaf_cert.signature,
                chain.leaf_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                chain.leaf_cert.signature_hash_algorithm,
            )
        except Exception as e:
            pytest.fail(f"Chain verification failed: {e}")


class TestEdgeCasesAndVariations:
    """Tests for edge cases and domain variations."""

    def test_subdomain_certificate_generation(self) -> None:
        """Certificate can be generated for deeply nested subdomains."""
        generator = CertificateChainGenerator()
        domain = "deeply.nested.subdomain.example.com"
        chain = generator.generate_full_chain(domain)

        subject_attrs: Dict[Any, Any] = {attr.oid: attr.value for attr in chain.leaf_cert.subject}
        assert subject_attrs[NameOID.COMMON_NAME] == domain

    def test_international_domain_name_support(self) -> None:
        """Certificate can be generated for IDN domains using A-label encoding."""
        generator = CertificateChainGenerator()
        unicode_domain = "例え.jp"
        a_label_domain = unicode_domain.encode('idna').decode('ascii')
        chain = generator.generate_full_chain(a_label_domain)

        subject_attrs: Dict[Any, Any] = {attr.oid: attr.value for attr in chain.leaf_cert.subject}
        cn = subject_attrs[NameOID.COMMON_NAME]
        assert cn == a_label_domain

    def test_single_letter_domain_name(self) -> None:
        """Certificate can be generated for single-letter domains."""
        generator = CertificateChainGenerator()
        domain = "x.com"
        chain = generator.generate_full_chain(domain)

        subject_attrs: Dict[Any, Any] = {attr.oid: attr.value for attr in chain.leaf_cert.subject}
        assert subject_attrs[NameOID.COMMON_NAME] == domain

    def test_domain_with_hyphens(self) -> None:
        """Certificate can be generated for domains with hyphens."""
        generator = CertificateChainGenerator()
        domain = "my-test-domain.example.com"
        chain = generator.generate_full_chain(domain)

        subject_attrs: Dict[Any, Any] = {attr.oid: attr.value for attr in chain.leaf_cert.subject}
        assert subject_attrs[NameOID.COMMON_NAME] == domain

    def test_numeric_subdomain(self) -> None:
        """Certificate can be generated for numeric subdomains."""
        generator = CertificateChainGenerator()
        domain = "123.example.com"
        chain = generator.generate_full_chain(domain)

        subject_attrs = {attr.oid: attr.value for attr in chain.leaf_cert.subject}
        assert subject_attrs[NameOID.COMMON_NAME] == domain

    def test_localhost_certificate(self) -> None:
        """Certificate can be generated for localhost."""
        generator = CertificateChainGenerator()
        domain = "localhost"
        chain = generator.generate_full_chain(domain)

        subject_attrs = {attr.oid: attr.value for attr in chain.leaf_cert.subject}
        assert subject_attrs[NameOID.COMMON_NAME] == domain

    def test_ip_address_as_common_name(self) -> None:
        """Certificate can be generated with IP address as CN."""
        generator = CertificateChainGenerator()
        domain = "192.168.1.1"
        chain = generator.generate_full_chain(domain)

        subject_attrs = {attr.oid: attr.value for attr in chain.leaf_cert.subject}
        assert subject_attrs[NameOID.COMMON_NAME] == domain

    def test_very_long_domain_name(self) -> None:
        """Certificate can be generated for very long domain names."""
        generator = CertificateChainGenerator()
        domain = "very.long.subdomain.name.with.many.levels.example.com"
        chain = generator.generate_full_chain(domain)

        subject_attrs = {attr.oid: attr.value for attr in chain.leaf_cert.subject}
        assert subject_attrs[NameOID.COMMON_NAME] == domain

    def test_uppercase_domain_name(self) -> None:
        """Certificate preserves domain name case."""
        generator = CertificateChainGenerator()
        domain = "UPPERCASE.EXAMPLE.COM"
        chain = generator.generate_full_chain(domain)

        subject_attrs = {attr.oid: attr.value for attr in chain.leaf_cert.subject}
        assert subject_attrs[NameOID.COMMON_NAME] == domain


class TestRealWorldUsageScenarios:
    """Tests for real-world usage scenarios in certificate bypass operations."""

    def test_mitm_proxy_certificate_chain_export(self, tmp_path: Path) -> None:
        """Complete workflow: generate chain and export for MITM proxy use."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("target.example.com")

        cert_file: Path = tmp_path / "server.crt"
        key_file: Path = tmp_path / "server.key"
        ca_file: Path = tmp_path / "ca.crt"

        leaf_pem = chain.leaf_cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = generator.export_private_key_pem(chain.leaf_key)
        root_pem = chain.root_cert.public_bytes(serialization.Encoding.PEM).decode()

        cert_file.write_text(leaf_pem)
        key_file.write_text(key_pem)
        ca_file.write_text(root_pem)

        assert cert_file.exists()
        assert key_file.exists()
        assert ca_file.exists()

        loaded_cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        loaded_key: Any = load_pem_private_key(key_file.read_bytes(), password=None)
        loaded_ca = x509.load_pem_x509_certificate(ca_file.read_bytes())

        assert loaded_cert.serial_number == chain.leaf_cert.serial_number
        assert isinstance(loaded_key, rsa.RSAPrivateKey)
        assert loaded_ca.serial_number == chain.root_cert.serial_number

    def test_multiple_domain_mitm_scenario(self) -> None:
        """Generate certificates for multiple target domains using shared CA."""
        generator = CertificateChainGenerator()
        base_chain = generator.generate_full_chain("base.example.com")

        target_domains = [
            "api.target.com",
            "cdn.target.com",
            "secure.target.com",
            "admin.target.com",
        ]

        generated_certs: Dict[str, Tuple[x509.Certificate, rsa.RSAPrivateKey]] = {}
        for domain in target_domains:
            leaf_cert, leaf_key = generator.generate_leaf_cert(
                domain, base_chain.intermediate_cert, base_chain.intermediate_key
            )
            generated_certs[domain] = (leaf_cert, leaf_key)

        assert len(generated_certs) == len(target_domains)
        for domain, (cert, key) in generated_certs.items():
            subject_attrs: Dict[Any, Any] = {attr.oid: attr.value for attr in cert.subject}
            assert subject_attrs[NameOID.COMMON_NAME] == domain
            assert cert.issuer == base_chain.intermediate_cert.subject

    def test_certificate_trust_chain_verification_simulation(self) -> None:
        """Simulate trust chain verification as performed by TLS clients."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("verified.example.com")

        root_public = chain.root_cert.public_key()
        assert isinstance(root_public, rsa.RSAPublicKey)
        intermediate_public = chain.intermediate_cert.public_key()
        assert isinstance(intermediate_public, rsa.RSAPublicKey)

        root_self_signed = chain.root_cert.issuer == chain.root_cert.subject
        assert root_self_signed

        try:
            root_public.verify(
                chain.intermediate_cert.signature,
                chain.intermediate_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                chain.intermediate_cert.signature_hash_algorithm,
            )
        except Exception as e:
            pytest.fail(f"Step 1: Root verification of intermediate failed: {e}")

        try:
            intermediate_public.verify(
                chain.leaf_cert.signature,
                chain.leaf_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                chain.leaf_cert.signature_hash_algorithm,
            )
        except Exception as e:
            pytest.fail(f"Step 2: Intermediate verification of leaf failed: {e}")

        leaf_not_ca = (
            chain.leaf_cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value.ca
            is False
        )
        assert leaf_not_ca

    def test_wildcard_certificate_for_multiple_subdomains(self) -> None:
        """Wildcard certificate covers multiple subdomains correctly."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("*.example.com")

        san = chain.leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        dns_names: List[Any] = list(san.get_values_for_type(x509.DNSName))

        assert "*.example.com" in dns_names

        subject_attrs: Dict[Any, Any] = {attr.oid: attr.value for attr in chain.leaf_cert.subject}
        assert subject_attrs[NameOID.COMMON_NAME] == "*.example.com"

    def test_certificate_renewal_workflow(self) -> None:
        """Simulate certificate renewal by generating new leaf with same CA."""
        generator = CertificateChainGenerator()
        original_chain = generator.generate_full_chain("renewable.example.com")

        renewed_leaf, renewed_key = generator.generate_leaf_cert(
            "renewable.example.com",
            original_chain.intermediate_cert,
            original_chain.intermediate_key,
        )

        assert renewed_leaf.serial_number != original_chain.leaf_cert.serial_number
        assert renewed_leaf.issuer == original_chain.leaf_cert.issuer

        subject_attrs_original: Dict[Any, Any] = {
            attr.oid: attr.value for attr in original_chain.leaf_cert.subject
        }
        subject_attrs_renewed: Dict[Any, Any] = {attr.oid: attr.value for attr in renewed_leaf.subject}
        assert (
            subject_attrs_original[NameOID.COMMON_NAME]
            == subject_attrs_renewed[NameOID.COMMON_NAME]
        )

    def test_export_for_different_server_formats(self, tmp_path: Path) -> None:
        """Export certificates in various formats for different server types."""
        generator = CertificateChainGenerator()
        chain = generator.generate_full_chain("multi-format.example.com")

        pem_cert = chain.leaf_cert.public_bytes(serialization.Encoding.PEM)
        der_cert = generator.export_cert_der(chain.leaf_cert)
        pem_key = generator.export_private_key_pem(chain.leaf_key)
        full_chain_pem = generator.export_chain_pem(chain)

        (tmp_path / "cert.pem").write_bytes(pem_cert)
        (tmp_path / "cert.der").write_bytes(der_cert)
        (tmp_path / "key.pem").write_text(pem_key)
        (tmp_path / "fullchain.pem").write_text(full_chain_pem)

        assert (tmp_path / "cert.pem").exists()
        assert (tmp_path / "cert.der").exists()
        assert (tmp_path / "key.pem").exists()
        assert (tmp_path / "fullchain.pem").exists()

        loaded_pem = x509.load_pem_x509_certificate((tmp_path / "cert.pem").read_bytes())
        loaded_der = x509.load_der_x509_certificate((tmp_path / "cert.der").read_bytes())

        assert loaded_pem.serial_number == loaded_der.serial_number
        assert loaded_pem.serial_number == chain.leaf_cert.serial_number
