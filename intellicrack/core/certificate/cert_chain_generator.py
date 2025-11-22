"""Certificate chain generation for MITM certificate bypass and trust injection.

CAPABILITIES:
- Complete certificate chain generation (root CA → intermediate CA → leaf cert)
- RSA key pair generation (4096-bit root, 2048-bit intermediate/leaf)
- X.509 v3 certificate creation with proper extensions
- Self-signed root CA with CA=TRUE, pathlen=2
- Intermediate CA with proper constraints and authority identifiers
- Leaf certificates with Subject Alternative Names (SAN)
- Wildcard certificate support (*.domain.com)
- PEM/DER export for certificates and keys
- SHA-256 signature algorithm
- Proper validity periods (10 years root, 5 years intermediate, 1 year leaf)
- Correct key usage and extended key usage extensions

LIMITATIONS:
- Only RSA keys (no ECDSA/Ed25519 support yet)
- Fixed key sizes (no customization)
- No certificate revocation list (CRL) generation
- No OCSP responder support
- No custom certificate extensions
- Validity periods are fixed (not configurable)
- No certificate pinning hash generation
- Cannot import existing CA keys

USAGE EXAMPLES:
    # Generate complete certificate chain
    from intellicrack.core.certificate.cert_chain_generator import (
        CertificateChainGenerator
    )

    generator = CertificateChainGenerator()
    chain = generator.generate_full_chain("example.com")

    print(f"Leaf: {chain.leaf_cert.subject}")
    print(f"Intermediate: {chain.intermediate_cert.subject}")
    print(f"Root: {chain.root_cert.subject}")

    # Export to PEM format
    pem_chain = generator.export_chain_pem(chain)
    with open("certificate_chain.pem", "w") as f:
        f.write(pem_chain)

    # Export individual components
    leaf_pem = generator.export_cert_pem(chain.leaf_cert)
    key_pem = generator.export_private_key_pem(chain.leaf_key)

    with open("server.crt", "w") as f:
        f.write(leaf_pem)
    with open("server.key", "w") as f:
        f.write(key_pem)

    # Generate DER format (for binary import)
    cert_der = generator.export_cert_der(chain.leaf_cert)
    with open("certificate.der", "wb") as f:
        f.write(cert_der)

    # Generate wildcard certificate
    wildcard_chain = generator.generate_full_chain("*.example.com")
    # Works for any subdomain: test.example.com, api.example.com, etc.

    # Generate for multiple domains
    multi_chain = generator.generate_leaf_cert(
        "example.com",
        chain.intermediate_cert,
        chain.intermediate_key,
        alt_names=["www.example.com", "api.example.com"]
    )

RELATED MODULES:
- cert_cache.py: Caches generated certificate chains
- bypass_orchestrator.py: Uses generated certs for MITM bypass
- frida_cert_hooks.py: May inject generated certificates

CERTIFICATE HIERARCHY:
    Root CA (Intellicrack Root CA)
      ↓ signs
    Intermediate CA (Intellicrack Intermediate CA)
      ↓ signs
    Leaf Certificate (target domain)

CERTIFICATE EXTENSIONS:
    Root CA:
        - basicConstraints: CA=TRUE, pathlen=2
        - keyUsage: keyCertSign, cRLSign
        - subjectKeyIdentifier: hash of public key

    Intermediate CA:
        - basicConstraints: CA=TRUE, pathlen=0
        - keyUsage: keyCertSign, cRLSign, digitalSignature
        - authorityKeyIdentifier: from root CA
        - subjectKeyIdentifier: hash of public key

    Leaf Certificate:
        - basicConstraints: CA=FALSE
        - keyUsage: digitalSignature, keyEncipherment
        - extendedKeyUsage: serverAuth, clientAuth
        - subjectAltName: DNS:domain, DNS:*.domain
        - authorityKeyIdentifier: from intermediate CA
        - subjectKeyIdentifier: hash of public key

USAGE IN BYPASS:
    1. Generate certificate chain for target domain
    2. Install root CA in system trust store
    3. Use leaf cert+key for MITM proxy (mitmproxy)
    4. Target application trusts our certificates
    5. Intercept and modify HTTPS traffic
"""

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@dataclass
class CertificateChain:
    """Complete certificate chain with keys."""

    leaf_cert: x509.Certificate
    intermediate_cert: x509.Certificate
    root_cert: x509.Certificate
    leaf_key: rsa.RSAPrivateKey
    intermediate_key: rsa.RSAPrivateKey
    root_key: rsa.RSAPrivateKey


class CertificateChainGenerator:
    """Generates complete certificate chains for MITM proxying."""

    def generate_root_ca(self) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Generate self-signed root CA certificate.

        Returns:
            Tuple of (root certificate, root private key)

        """
        root_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Intellicrack Root CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intellicrack"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security Research"),
            ]
        )

        root_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650),
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=2),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )

        return root_cert, root_key

    def generate_intermediate_ca(
        self,
        root_ca: x509.Certificate,
        root_key: rsa.RSAPrivateKey,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Generate intermediate CA certificate signed by root CA.

        Args:
            root_ca: Root CA certificate
            root_key: Root CA private key

        Returns:
            Tuple of (intermediate certificate, intermediate private key)

        """
        intermediate_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Intellicrack Intermediate CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intellicrack"),
            ]
        )

        intermediate_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(root_ca.subject)
            .public_key(intermediate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1825),
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )

        return intermediate_cert, intermediate_key

    def generate_leaf_cert(
        self,
        domain: str,
        intermediate_ca: x509.Certificate,
        intermediate_key: rsa.RSAPrivateKey,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Generate leaf certificate for specific domain.

        Args:
            domain: Domain name for certificate (e.g., "example.com")
            intermediate_ca: Intermediate CA certificate
            intermediate_key: Intermediate CA private key

        Returns:
            Tuple of (leaf certificate, leaf private key)

        """
        leaf_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intellicrack"),
            ]
        )

        san_entries = [
            x509.DNSName(domain),
        ]
        if not domain.startswith("*."):
            san_entries.append(x509.DNSName(f"*.{domain}"))

        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(intermediate_ca.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365),
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    intermediate_key.public_key(),
                ),
                critical=False,
            )
            .sign(intermediate_key, hashes.SHA256())
        )

        return leaf_cert, leaf_key

    def generate_full_chain(self, domain: str) -> CertificateChain:
        """Generate complete certificate chain for domain.

        This creates a full PKI hierarchy: root CA → intermediate CA → leaf cert
        for the specified domain. All certificates and keys are generated fresh.

        Args:
            domain: Domain name for the leaf certificate

        Returns:
            CertificateChain containing all certificates and private keys

        """
        root_cert, root_key = self.generate_root_ca()

        intermediate_cert, intermediate_key = self.generate_intermediate_ca(
            root_cert,
            root_key,
        )

        leaf_cert, leaf_key = self.generate_leaf_cert(
            domain,
            intermediate_cert,
            intermediate_key,
        )

        return CertificateChain(
            leaf_cert=leaf_cert,
            intermediate_cert=intermediate_cert,
            root_cert=root_cert,
            leaf_key=leaf_key,
            intermediate_key=intermediate_key,
            root_key=root_key,
        )

    def export_chain_pem(self, chain: CertificateChain) -> str:
        """Export full certificate chain as PEM.

        The chain is formatted as: leaf cert + intermediate cert + root cert
        in a single PEM string, which is the standard format for web servers.

        Args:
            chain: Certificate chain to export

        Returns:
            PEM-encoded certificate chain

        """
        leaf_pem = chain.leaf_cert.public_bytes(serialization.Encoding.PEM).decode()
        intermediate_pem = chain.intermediate_cert.public_bytes(
            serialization.Encoding.PEM,
        ).decode()
        root_pem = chain.root_cert.public_bytes(serialization.Encoding.PEM).decode()

        return f"{leaf_pem}{intermediate_pem}{root_pem}"

    def export_cert_der(self, cert: x509.Certificate) -> bytes:
        """Export certificate as DER.

        Args:
            cert: Certificate to export

        Returns:
            DER-encoded certificate bytes

        """
        return cert.public_bytes(serialization.Encoding.DER)

    def export_private_key_pem(self, key: rsa.RSAPrivateKey) -> str:
        """Export private key as PEM.

        Args:
            key: Private key to export

        Returns:
            PEM-encoded private key

        """
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    def export_public_key_pem(self, key: rsa.RSAPublicKey) -> str:
        """Export public key as PEM.

        Args:
            key: Public key to export

        Returns:
            PEM-encoded public key

        """
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
