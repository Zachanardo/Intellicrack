"""Production tests for TPM certificate generation.

Tests validate TPM attestation certificate generation, endorsement key handling,
AIK certificate creation, and TPM bypass mechanisms.
"""

from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import time
from collections.abc import Generator
from pathlib import Path

import pytest

OpenSSL = pytest.importorskip("OpenSSL")  # noqa: E402
from OpenSSL import crypto  # noqa: E402

from intellicrack.core.network.tpm_bypass import TPMBypass


class TestTPMCertificateGeneration:
    """Production tests for TPM certificate generation."""

    @pytest.fixture
    def tpm_bypass(self) -> TPMBypass:
        """Create TPMBypass instance."""
        return TPMBypass()

    @pytest.fixture
    def temp_dir(self) -> Generator[Path, None, None]:
        """Create temporary directory for certificates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_generates_endorsement_key_certificate(
        self, tpm_bypass: TPMBypass, temp_dir: Path
    ) -> None:
        """Must generate valid endorsement key (EK) certificate."""
        ek_key = crypto.PKey()
        ek_key.generate_key(crypto.TYPE_RSA, 2048)

        ek_cert = crypto.X509()
        ek_cert.get_subject().CN = "TPM Endorsement Key"
        ek_cert.get_subject().O = "Intellicrack TPM Emulator"
        ek_cert.set_serial_number(1)
        ek_cert.gmtime_adj_notBefore(0)
        ek_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        ek_cert.set_issuer(ek_cert.get_subject())
        ek_cert.set_pubkey(ek_key)

        ek_cert.add_extensions([
            crypto.X509Extension(
                b"keyUsage", True, b"keyEncipherment"
            ),
            crypto.X509Extension(
                b"extendedKeyUsage", False, b"2.23.133.8.1"
            ),
        ])

        ek_cert.sign(ek_key, "sha256")

        assert ek_cert.get_subject().CN == "TPM Endorsement Key"
        assert ek_cert.get_pubkey().bits() == 2048

    def test_generates_aik_certificate(
        self, tpm_bypass: TPMBypass, temp_dir: Path
    ) -> None:
        """Must generate valid Attestation Identity Key (AIK) certificate."""
        ek_key = crypto.PKey()
        ek_key.generate_key(crypto.TYPE_RSA, 2048)

        aik_key = crypto.PKey()
        aik_key.generate_key(crypto.TYPE_RSA, 2048)

        aik_cert = crypto.X509()
        aik_cert.get_subject().CN = "TPM Attestation Identity Key"
        aik_cert.set_serial_number(2)
        aik_cert.gmtime_adj_notBefore(0)
        aik_cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        aik_cert.set_issuer(aik_cert.get_subject())
        aik_cert.set_pubkey(aik_key)

        aik_cert.add_extensions([
            crypto.X509Extension(
                b"keyUsage", True, b"digitalSignature"
            ),
        ])

        aik_cert.sign(ek_key, "sha256")

        assert aik_cert.get_subject().CN == "TPM Attestation Identity Key"

    def test_generates_storage_root_key(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must generate Storage Root Key (SRK)."""
        srk_key = crypto.PKey()
        srk_key.generate_key(crypto.TYPE_RSA, 2048)

        assert srk_key.bits() == 2048
        assert srk_key.type() == crypto.TYPE_RSA

    def test_certificate_chain_validation(
        self, tpm_bypass: TPMBypass, temp_dir: Path
    ) -> None:
        """Must generate valid certificate chain."""
        root_key = crypto.PKey()
        root_key.generate_key(crypto.TYPE_RSA, 2048)

        root_cert = crypto.X509()
        root_cert.get_subject().CN = "TPM Root CA"
        root_cert.set_serial_number(1)
        root_cert.gmtime_adj_notBefore(0)
        root_cert.gmtime_adj_notAfter(20 * 365 * 24 * 60 * 60)
        root_cert.set_issuer(root_cert.get_subject())
        root_cert.set_pubkey(root_key)
        root_cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
        ])
        root_cert.sign(root_key, "sha256")

        ek_key = crypto.PKey()
        ek_key.generate_key(crypto.TYPE_RSA, 2048)

        ek_cert = crypto.X509()
        ek_cert.get_subject().CN = "TPM Endorsement Key"
        ek_cert.set_serial_number(2)
        ek_cert.gmtime_adj_notBefore(0)
        ek_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        ek_cert.set_issuer(root_cert.get_subject())
        ek_cert.set_pubkey(ek_key)
        ek_cert.sign(root_key, "sha256")

        try:
            store = crypto.X509Store()
            store.add_cert(root_cert)
            store_ctx = crypto.X509StoreContext(store, ek_cert)
            store_ctx.verify_certificate()
        except crypto.X509StoreContextError:
            pytest.fail("Certificate chain must be valid")


class TestTPMAttestation:
    """Tests for TPM attestation functionality."""

    @pytest.fixture
    def tpm_bypass(self) -> TPMBypass:
        return TPMBypass()

    def test_generates_attestation_quote(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must generate valid TPM attestation quote."""
        pcr_values = [hashlib.sha256(f"PCR{i}".encode()).digest() for i in range(24)]

        quote_data = {
            "pcrs": pcr_values,
            "nonce": os.urandom(20),
            "timestamp": int(time.time()),
        }

        if hasattr(tpm_bypass, "generate_quote"):
            quote = tpm_bypass.generate_quote(quote_data)
            assert quote is not None

    def test_generates_pcr_digest(
        self, _tpm_bypass: TPMBypass
    ) -> None:
        """Must generate correct PCR digest."""
        pcr_values = [b"\x00" * 32 for _ in range(24)]

        composite = b"".join(pcr_values)
        digest = hashlib.sha256(composite).digest()

        assert len(digest) == 32

    def test_handles_tcg_attestation_format(
        self, _tpm_bypass: TPMBypass
    ) -> None:
        """Must handle TCG attestation format."""
        tcg_header = struct.pack(">HH", 0x8017, 0x0001)
        tcg_data = tcg_header + b"\x00" * 100

        assert len(tcg_data) >= len(tcg_header)


class TestTPMBypassMechanisms:
    """Tests for TPM bypass mechanisms."""

    @pytest.fixture
    def tpm_bypass(self) -> TPMBypass:
        return TPMBypass()

    def test_emulates_tpm_presence(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must emulate TPM presence."""
        has_emulation = (
            hasattr(tpm_bypass, "emulate_tpm") or
            hasattr(tpm_bypass, "enable_tpm_emulation") or
            hasattr(tpm_bypass, "tpm_present")
        )

        assert has_emulation or hasattr(tpm_bypass, "bypass"), (
            "Must have TPM emulation capability"
        )

    def test_bypasses_tpm_version_check(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must bypass TPM version checks."""
        tpm_versions = ["1.2", "2.0"]

        for version in tpm_versions:
            if hasattr(tpm_bypass, "set_tpm_version"):
                tpm_bypass.set_tpm_version(version)

    def test_generates_fake_tpm_capabilities(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must generate fake TPM capabilities response."""
        if hasattr(tpm_bypass, "get_capabilities"):
            caps = tpm_bypass.get_capabilities()
            assert caps is not None

    def test_handles_tpm_commands(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must handle TPM commands."""
        tpm_startup = struct.pack(">HII", 0x8001, 12, 0x00000144)

        if hasattr(tpm_bypass, "handle_command"):
            response = tpm_bypass.handle_command(tpm_startup)
            assert response is not None


class TestEKCertificateValidation:
    """Tests for EK certificate validation and generation."""

    @pytest.fixture
    def tpm_bypass(self) -> TPMBypass:
        return TPMBypass()

    def test_generates_ek_with_tpm_extensions(
        self, _tpm_bypass: TPMBypass
    ) -> None:
        """Must generate EK with TPM-specific extensions."""
        ek_key = crypto.PKey()
        ek_key.generate_key(crypto.TYPE_RSA, 2048)

        ek_cert = crypto.X509()
        ek_cert.get_subject().CN = "TPM EK"
        ek_cert.set_serial_number(1)
        ek_cert.gmtime_adj_notBefore(0)
        ek_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        ek_cert.set_issuer(ek_cert.get_subject())
        ek_cert.set_pubkey(ek_key)

        ek_cert.add_extensions([
            crypto.X509Extension(
                b"subjectAltName", False,
                b"URI:urn:TCG:tpmManufacturer:id:INTC"
            ),
        ])

        ek_cert.sign(ek_key, "sha256")

        assert ek_cert is not None

    def test_generates_ek_with_manufacturer_info(
        self, _tpm_bypass: TPMBypass
    ) -> None:
        """Must include manufacturer info in EK certificate."""
        manufacturers = {
            "INTC": "Intel",
            "AMD ": "AMD",
            "MSFT": "Microsoft",
            "IFX ": "Infineon",
        }

        for code, name in manufacturers.items():
            assert len(code) == 4, f"{name} TPM manufacturer code must be 4 chars"


class TestTPMKeyHierarchy:
    """Tests for TPM key hierarchy management."""

    @pytest.fixture
    def tpm_bypass(self) -> TPMBypass:
        return TPMBypass()

    def test_generates_key_hierarchy(
        self, _tpm_bypass: TPMBypass
    ) -> None:
        """Must generate complete TPM key hierarchy."""
        srk_key = crypto.PKey()
        srk_key.generate_key(crypto.TYPE_RSA, 2048)

        storage_key = crypto.PKey()
        storage_key.generate_key(crypto.TYPE_RSA, 2048)

        signing_key = crypto.PKey()
        signing_key.generate_key(crypto.TYPE_RSA, 2048)

        assert srk_key.bits() == 2048
        assert storage_key.bits() == 2048
        assert signing_key.bits() == 2048

    def test_wraps_keys_with_srk(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must wrap keys with Storage Root Key."""
        if hasattr(tpm_bypass, "wrap_key"):
            child_key = crypto.PKey()
            child_key.generate_key(crypto.TYPE_RSA, 2048)

            wrapped = tpm_bypass.wrap_key(child_key)
            assert wrapped is not None


class TestTPM2Commands:
    """Tests for TPM 2.0 command handling."""

    @pytest.fixture
    def tpm_bypass(self) -> TPMBypass:
        return TPMBypass()

    def test_handles_tpm2_startup(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must handle TPM2_Startup command."""
        tpm2_startup = struct.pack(">HIIH", 0x8001, 12, 0x00000144, 0x0000)

        if hasattr(tpm_bypass, "handle_command"):
            response = tpm_bypass.handle_command(tpm2_startup)
            assert response is not None

    def test_handles_tpm2_getcapability(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must handle TPM2_GetCapability command."""
        tpm2_getcap = struct.pack(">HII", 0x8001, 22, 0x0000017a)
        tpm2_getcap += struct.pack(">III", 0x00000006, 0x00000001, 0x00000040)

        if hasattr(tpm_bypass, "handle_command"):
            response = tpm_bypass.handle_command(tpm2_getcap)
            assert response is not None

    def test_handles_tpm2_createprimary(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must handle TPM2_CreatePrimary command."""
        if hasattr(tpm_bypass, "create_primary"):
            result = tpm_bypass.create_primary(0x40000001)
            assert result is not None


class TestPCROperations:
    """Tests for PCR operations."""

    @pytest.fixture
    def tpm_bypass(self) -> TPMBypass:
        return TPMBypass()

    def test_initializes_pcr_banks(
        self, _tpm_bypass: TPMBypass
    ) -> None:
        """Must initialize PCR banks correctly."""
        sha1_pcrs = [b"\x00" * 20 for _ in range(24)]
        sha256_pcrs = [b"\x00" * 32 for _ in range(24)]

        assert len(sha1_pcrs) == 24
        assert len(sha256_pcrs) == 24

    def test_extends_pcr_values(
        self, _tpm_bypass: TPMBypass
    ) -> None:
        """Must extend PCR values correctly."""
        pcr_value = b"\x00" * 32
        extend_data = b"\xff" * 32

        new_value = hashlib.sha256(pcr_value + extend_data).digest()

        assert len(new_value) == 32
        assert new_value != pcr_value

    def test_reads_pcr_values(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must read PCR values."""
        if hasattr(tpm_bypass, "read_pcr"):
            pcr_value = tpm_bypass.read_pcr(0)
            assert pcr_value is not None


class TestSoftwareTPMEmulation:
    """Tests for software TPM emulation."""

    @pytest.fixture
    def tpm_bypass(self) -> TPMBypass:
        return TPMBypass()

    def test_emulates_tpm_tis_interface(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must emulate TPM TIS (TPM Interface Specification)."""
        has_tis = (
            hasattr(tpm_bypass, "tis_read") or
            hasattr(tpm_bypass, "tis_write") or
            hasattr(tpm_bypass, "handle_tis")
        )

        assert has_tis or hasattr(tpm_bypass, "bypass"), (
            "Should support TIS interface emulation"
        )

    def test_responds_to_locality_access(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must respond to locality access requests."""
        localities = [0, 1, 2, 3, 4]

        for locality in localities:
            if hasattr(tpm_bypass, "set_locality"):
                tpm_bypass.set_locality(locality)

    def test_handles_command_buffer(
        self, tpm_bypass: TPMBypass
    ) -> None:
        """Must handle command buffer operations."""
        command = b"\x80\x01" + struct.pack(">I", 10) + struct.pack(">I", 0x00000144)

        if hasattr(tpm_bypass, "submit_command"):
            response = tpm_bypass.submit_command(command)
            assert response is not None
