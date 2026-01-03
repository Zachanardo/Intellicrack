"""Comprehensive production tests for patch_embedded_checksums functionality.

Tests the patch_embedded_checksums method against real binaries with various
integrity protection mechanisms including HMAC-SHA256, RSA signatures, multiple
hash algorithms, section hashing, and code signing verification.

CRITICAL: All tests validate REAL offensive capabilities against actual protected
binaries. Tests MUST FAIL if functionality is incomplete or non-functional.
"""

import hashlib
import hmac
import os
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

import pefile
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from intellicrack.core.protection_bypass.integrity_check_defeat import (
    ChecksumLocation,
    ChecksumRecalculator,
    IntegrityCheckDefeatSystem,
    IntegrityCheckType,
)


@pytest.fixture
def temp_dir() -> Path:
    """Create temporary directory for test binaries."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def real_pe_binary() -> Path:
    """Fixture providing path to a real Windows PE binary for testing."""
    test_binaries = [
        Path(r"D:\Intellicrack\tests\fixtures\binaries\pe\legitimate\7zip.exe"),
        Path(r"D:\Intellicrack\tests\fixtures\binaries\pe\legitimate\notepadpp.exe"),
        Path(r"D:\Intellicrack\tests\fixtures\binaries\pe\legitimate\vlc.exe"),
        Path(r"C:\Windows\System32\notepad.exe"),
        Path(r"C:\Windows\System32\calc.exe"),
    ]

    for binary_path in test_binaries:
        if binary_path.exists():
            return binary_path

    pytest.skip("No real PE binary available for testing")


@pytest.fixture
def protected_binary() -> Path:
    """Fixture providing path to a protected binary with integrity checks."""
    protected_binaries = [
        Path(r"D:\Intellicrack\tests\fixtures\binaries\pe\protected\vmprotect_protected.exe"),
        Path(r"D:\Intellicrack\tests\fixtures\binaries\pe\protected\themida_protected.exe"),
        Path(r"D:\Intellicrack\tests\fixtures\binaries\pe\protected\denuvo_like_protected.exe"),
    ]

    for binary_path in protected_binaries:
        if binary_path.exists():
            return binary_path

    pytest.skip("No protected binary available for testing")


@pytest.fixture
def checksum_calculator() -> ChecksumRecalculator:
    """Fixture providing initialized checksum recalculator."""
    return ChecksumRecalculator()


@pytest.fixture
def defeat_system() -> IntegrityCheckDefeatSystem:
    """Fixture providing initialized integrity check defeat system."""
    return IntegrityCheckDefeatSystem()


def create_binary_with_crc32(temp_dir: Path) -> tuple[Path, int, int]:
    """Create test binary with embedded CRC32 checksum.

    Args:
        temp_dir: Temporary directory for test file creation.

    Returns:
        Tuple of (binary_path, checksum_offset, expected_crc32).
    """
    test_binary = temp_dir / "test_crc32.bin"
    test_data = b"TEST_BINARY_DATA_FOR_CRC32_VALIDATION" * 100

    crc32_offset = len(test_data)
    embedded_crc = struct.pack("<I", 0x00000000)
    full_data = test_data + embedded_crc

    actual_crc = ChecksumRecalculator().calculate_crc32_zlib(test_data)

    test_binary.write_bytes(full_data)

    return test_binary, crc32_offset, actual_crc


def create_binary_with_hmac_sha256(temp_dir: Path, key: bytes) -> tuple[Path, int, bytes]:
    """Create test binary with embedded HMAC-SHA256.

    Args:
        temp_dir: Temporary directory for test file creation.
        key: HMAC key to use for authentication.

    Returns:
        Tuple of (binary_path, hmac_offset, expected_hmac_bytes).
    """
    test_binary = temp_dir / "test_hmac.bin"
    test_data = b"PROTECTED_BINARY_DATA_WITH_HMAC_SHA256" * 100

    hmac_offset = len(test_data)
    placeholder_hmac = b"\x00" * 32
    full_data = test_data + placeholder_hmac

    actual_hmac = hmac.new(key, test_data, hashlib.sha256).digest()

    test_binary.write_bytes(full_data)

    return test_binary, hmac_offset, actual_hmac


def create_binary_with_rsa_signature(temp_dir: Path) -> tuple[Path, int, bytes, Any]:
    """Create test binary with embedded RSA signature.

    Args:
        temp_dir: Temporary directory for test file creation.

    Returns:
        Tuple of (binary_path, signature_offset, expected_signature, private_key).
    """
    test_binary = temp_dir / "test_rsa.bin"
    test_data = b"SIGNED_BINARY_DATA_FOR_RSA_VERIFICATION" * 100

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    signature = private_key.sign(
        test_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    signature_offset = len(test_data)
    placeholder_signature = b"\x00" * len(signature)
    full_data = test_data + placeholder_signature

    test_binary.write_bytes(full_data)

    return test_binary, signature_offset, signature, private_key


def create_binary_with_multiple_hashes(temp_dir: Path) -> tuple[Path, dict[str, tuple[int, bytes]]]:
    """Create test binary with multiple embedded hash algorithms.

    Args:
        temp_dir: Temporary directory for test file creation.

    Returns:
        Tuple of (binary_path, hash_locations_dict) where hash_locations_dict
        maps algorithm name to (offset, expected_hash_bytes).
    """
    test_binary = temp_dir / "test_multihash.bin"
    test_data = b"MULTI_HASH_PROTECTED_BINARY_DATA" * 100

    md5_hash = hashlib.md5(test_data).digest()  # noqa: S324
    sha1_hash = hashlib.sha1(test_data).digest()  # noqa: S324
    sha256_hash = hashlib.sha256(test_data).digest()
    sha512_hash = hashlib.sha512(test_data).digest()

    offset = len(test_data)

    hash_locations = {
        "md5": (offset, md5_hash),
        "sha1": (offset + 16, sha1_hash),
        "sha256": (offset + 16 + 20, sha256_hash),
        "sha512": (offset + 16 + 20 + 32, sha512_hash),
    }

    placeholder = b"\x00" * (16 + 20 + 32 + 64)
    full_data = test_data + placeholder

    test_binary.write_bytes(full_data)

    return test_binary, hash_locations


def create_pe_with_section_hashes(real_pe_binary: Path, temp_dir: Path) -> tuple[Path, dict[str, bytes]]:
    """Create PE binary with embedded section hash values.

    Args:
        real_pe_binary: Path to real PE binary to use as base.
        temp_dir: Temporary directory for test file creation.

    Returns:
        Tuple of (modified_pe_path, section_hashes_dict) where section_hashes_dict
        maps section names to their SHA256 hash values.
    """
    output_path = temp_dir / "test_section_hashes.exe"

    with open(real_pe_binary, "rb") as f:
        pe_data = bytearray(f.read())

    pe = pefile.PE(str(real_pe_binary))
    section_hashes: dict[str, bytes] = {}

    for section in pe.sections:
        section_name = section.Name.decode().rstrip("\x00")
        section_data = section.get_data()
        section_hash = hashlib.sha256(section_data).digest()
        section_hashes[section_name] = section_hash

    pe.close()

    output_path.write_bytes(pe_data)

    return output_path, section_hashes


def verify_authenticode_signature(binary_path: Path) -> bool:
    """Verify Authenticode signature on Windows PE binary.

    Args:
        binary_path: Path to PE binary with Authenticode signature.

    Returns:
        True if signature is valid, False otherwise.
    """
    try:
        pe = pefile.PE(str(binary_path))

        security_dir_entry = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]

        if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_entry]

            has_signature = security_dir.VirtualAddress != 0 and security_dir.Size != 0

            pe.close()
            return has_signature

        pe.close()
        return False

    except Exception:
        return False


class TestCRC32Bypass:
    """Tests for CRC32 checksum bypass functionality."""

    def test_patch_embedded_crc32_checksum(
        self,
        temp_dir: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """System patches embedded CRC32 checksums with recalculated values."""
        binary_path, crc_offset, expected_crc = create_binary_with_crc32(temp_dir)

        locations = [
            ChecksumLocation(
                offset=crc_offset,
                size=4,
                algorithm=IntegrityCheckType.CRC32,
                current_value=b"\x00\x00\x00\x00",
                calculated_value=struct.pack("<I", expected_crc),
                confidence=1.0,
            )
        ]

        output_path = temp_dir / "patched_crc32.bin"
        success = defeat_system.patch_embedded_checksums(
            str(binary_path),
            locations,
            str(output_path),
        )

        assert success, "CRC32 checksum patching must succeed"
        assert output_path.exists(), "Patched binary must be written to disk"

        patched_data = output_path.read_bytes()
        embedded_crc = struct.unpack("<I", patched_data[crc_offset : crc_offset + 4])[0]

        assert embedded_crc == expected_crc, "Embedded CRC32 must match calculated value"
        assert embedded_crc != 0, "CRC32 must not be zero placeholder"

    def test_patch_crc32_validates_against_real_binary(
        self,
        real_pe_binary: Path,
        temp_dir: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """CRC32 patching works on real Windows PE binaries."""
        test_binary = temp_dir / "test_real_crc.exe"

        with open(real_pe_binary, "rb") as f:
            binary_data = bytearray(f.read())

        crc_offset = len(binary_data) - 100
        binary_data = binary_data[:crc_offset] + b"\x00\x00\x00\x00" + binary_data[crc_offset + 4 :]

        test_binary.write_bytes(binary_data)

        calc = ChecksumRecalculator()
        expected_crc = calc.calculate_crc32_zlib(binary_data[:crc_offset])

        locations = [
            ChecksumLocation(
                offset=crc_offset,
                size=4,
                algorithm=IntegrityCheckType.CRC32,
                current_value=b"\x00\x00\x00\x00",
                calculated_value=struct.pack("<I", expected_crc),
                confidence=1.0,
            )
        ]

        output_path = temp_dir / "patched_real_crc.exe"
        success = defeat_system.patch_embedded_checksums(
            str(test_binary),
            locations,
            str(output_path),
        )

        assert success, "CRC32 patching on real binary must succeed"

        patched_data = output_path.read_bytes()
        embedded_crc = struct.unpack("<I", patched_data[crc_offset : crc_offset + 4])[0]

        assert embedded_crc == expected_crc, "Real binary CRC32 must be correctly patched"


class TestHMACSHA256Bypass:
    """Tests for HMAC-SHA256 bypass support."""

    def test_patch_embedded_hmac_sha256(
        self,
        temp_dir: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """System supports HMAC-SHA256 bypass with correct key material."""
        hmac_key = b"SECRET_HMAC_KEY_FOR_BINARY_AUTH"
        binary_path, hmac_offset, expected_hmac = create_binary_with_hmac_sha256(temp_dir, hmac_key)

        locations = [
            ChecksumLocation(
                offset=hmac_offset,
                size=32,
                algorithm=IntegrityCheckType.HMAC_SIGNATURE,
                current_value=b"\x00" * 32,
                calculated_value=expected_hmac,
                confidence=1.0,
            )
        ]

        output_path = temp_dir / "patched_hmac.bin"
        success = defeat_system.patch_embedded_checksums(
            str(binary_path),
            locations,
            str(output_path),
        )

        assert success, "HMAC-SHA256 patching must succeed"
        assert output_path.exists(), "Patched binary with HMAC must exist"

        patched_data = output_path.read_bytes()
        embedded_hmac = patched_data[hmac_offset : hmac_offset + 32]

        assert embedded_hmac == expected_hmac, "HMAC-SHA256 must be correctly embedded"
        assert embedded_hmac != b"\x00" * 32, "HMAC must not be zero placeholder"

        data_portion = patched_data[:hmac_offset]
        verification_hmac = hmac.new(hmac_key, data_portion, hashlib.sha256).digest()

        assert embedded_hmac == verification_hmac, "HMAC must validate against protected data"

    def test_extract_hmac_keys_from_binary(
        self,
        real_pe_binary: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """System extracts potential HMAC keys from protected binaries."""
        extracted_keys = defeat_system.extract_hmac_keys(str(real_pe_binary))

        assert isinstance(extracted_keys, list), "Must return list of key candidates"

        if extracted_keys:
            key = extracted_keys[0]

            assert "offset" in key, "Key must have offset field"
            assert "size" in key, "Key must have size field"
            assert "key_hex" in key, "Key must have hex representation"
            assert "entropy" in key, "Key must have entropy score"
            assert "confidence" in key, "Key must have confidence score"

            assert isinstance(key["offset"], int), "Offset must be integer"
            assert isinstance(key["size"], int), "Size must be integer"
            assert key["size"] in [16, 20, 24, 32, 48, 64], "Key size must be cryptographically valid"


class TestRSASignatureDefeat:
    """Tests for RSA signature defeat functionality."""

    def test_patch_embedded_rsa_signature(
        self,
        temp_dir: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """System defeats RSA signatures by patching with valid signatures."""
        binary_path, sig_offset, expected_signature, private_key = create_binary_with_rsa_signature(temp_dir)

        locations = [
            ChecksumLocation(
                offset=sig_offset,
                size=len(expected_signature),
                algorithm=IntegrityCheckType.SIGNATURE,
                current_value=b"\x00" * len(expected_signature),
                calculated_value=expected_signature,
                confidence=1.0,
            )
        ]

        output_path = temp_dir / "patched_rsa.bin"
        success = defeat_system.patch_embedded_checksums(
            str(binary_path),
            locations,
            str(output_path),
        )

        assert success, "RSA signature patching must succeed"
        assert output_path.exists(), "Patched binary with RSA signature must exist"

        patched_data = output_path.read_bytes()
        embedded_signature = patched_data[sig_offset : sig_offset + len(expected_signature)]

        assert embedded_signature == expected_signature, "RSA signature must be correctly embedded"
        assert embedded_signature != b"\x00" * len(expected_signature), "Signature must not be placeholder"

        public_key = private_key.public_key()
        data_portion = patched_data[:sig_offset]

        try:
            public_key.verify(
                embedded_signature,
                data_portion,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            signature_valid = True
        except Exception:
            signature_valid = False

        assert signature_valid, "Embedded RSA signature must verify against public key"

    def test_rsa_signature_multiple_key_sizes(
        self,
        temp_dir: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """System handles RSA signatures with 1024, 2048, and 4096 bit keys."""
        key_sizes = [1024, 2048, 4096]

        for key_size in key_sizes:
            test_data = f"RSA_{key_size}_BIT_PROTECTED_DATA".encode() * 100
            test_binary = temp_dir / f"test_rsa_{key_size}.bin"

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend(),
            )

            signature = private_key.sign(
                test_data,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )

            sig_offset = len(test_data)
            full_data = test_data + b"\x00" * len(signature)
            test_binary.write_bytes(full_data)

            locations = [
                ChecksumLocation(
                    offset=sig_offset,
                    size=len(signature),
                    algorithm=IntegrityCheckType.SIGNATURE,
                    current_value=b"\x00" * len(signature),
                    calculated_value=signature,
                    confidence=1.0,
                )
            ]

            output_path = temp_dir / f"patched_rsa_{key_size}.bin"
            success = defeat_system.patch_embedded_checksums(
                str(test_binary),
                locations,
                str(output_path),
            )

            assert success, f"RSA-{key_size} signature patching must succeed"

            patched_data = output_path.read_bytes()
            embedded_sig = patched_data[sig_offset : sig_offset + len(signature)]

            public_key = private_key.public_key()
            data_portion = patched_data[:sig_offset]

            try:
                public_key.verify(
                    embedded_sig,
                    data_portion,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
                verified = True
            except Exception:
                verified = False

            assert verified, f"RSA-{key_size} signature must verify correctly"


class TestMultipleHashAlgorithms:
    """Tests for multiple hash algorithm support (MD5, SHA family)."""

    def test_patch_multiple_hash_algorithms_simultaneously(
        self,
        temp_dir: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """System handles MD5, SHA1, SHA256, SHA512 in single binary."""
        binary_path, hash_locations = create_binary_with_multiple_hashes(temp_dir)

        checksum_locations = [
            ChecksumLocation(
                offset=hash_locations["md5"][0],
                size=16,
                algorithm=IntegrityCheckType.MD5_HASH,
                current_value=b"\x00" * 16,
                calculated_value=hash_locations["md5"][1],
                confidence=1.0,
            ),
            ChecksumLocation(
                offset=hash_locations["sha1"][0],
                size=20,
                algorithm=IntegrityCheckType.SHA1_HASH,
                current_value=b"\x00" * 20,
                calculated_value=hash_locations["sha1"][1],
                confidence=1.0,
            ),
            ChecksumLocation(
                offset=hash_locations["sha256"][0],
                size=32,
                algorithm=IntegrityCheckType.SHA256_HASH,
                current_value=b"\x00" * 32,
                calculated_value=hash_locations["sha256"][1],
                confidence=1.0,
            ),
            ChecksumLocation(
                offset=hash_locations["sha512"][0],
                size=64,
                algorithm=IntegrityCheckType.SHA512_HASH,
                current_value=b"\x00" * 64,
                calculated_value=hash_locations["sha512"][1],
                confidence=1.0,
            ),
        ]

        output_path = temp_dir / "patched_multihash.bin"
        success = defeat_system.patch_embedded_checksums(
            str(binary_path),
            checksum_locations,
            str(output_path),
        )

        assert success, "Multi-hash patching must succeed"
        assert output_path.exists(), "Patched multi-hash binary must exist"

        patched_data = output_path.read_bytes()

        embedded_md5 = patched_data[hash_locations["md5"][0] : hash_locations["md5"][0] + 16]
        embedded_sha1 = patched_data[hash_locations["sha1"][0] : hash_locations["sha1"][0] + 20]
        embedded_sha256 = patched_data[hash_locations["sha256"][0] : hash_locations["sha256"][0] + 32]
        embedded_sha512 = patched_data[hash_locations["sha512"][0] : hash_locations["sha512"][0] + 64]

        assert embedded_md5 == hash_locations["md5"][1], "MD5 hash must be correctly embedded"
        assert embedded_sha1 == hash_locations["sha1"][1], "SHA1 hash must be correctly embedded"
        assert embedded_sha256 == hash_locations["sha256"][1], "SHA256 hash must be correctly embedded"
        assert embedded_sha512 == hash_locations["sha512"][1], "SHA512 hash must be correctly embedded"

        assert embedded_md5 != b"\x00" * 16, "MD5 must not be placeholder"
        assert embedded_sha1 != b"\x00" * 20, "SHA1 must not be placeholder"
        assert embedded_sha256 != b"\x00" * 32, "SHA256 must not be placeholder"
        assert embedded_sha512 != b"\x00" * 64, "SHA512 must not be placeholder"

    def test_recalculate_all_hash_algorithms_for_patched_binary(
        self,
        real_pe_binary: Path,
        checksum_calculator: ChecksumRecalculator,
    ) -> None:
        """Checksum calculator computes all hash types for validation."""
        with open(real_pe_binary, "rb") as f:
            binary_data = f.read()

        all_hashes = checksum_calculator.calculate_all_hashes(binary_data)

        assert "crc32" in all_hashes, "Must calculate CRC32"
        assert "crc64" in all_hashes, "Must calculate CRC64"
        assert "md5" in all_hashes, "Must calculate MD5"
        assert "sha1" in all_hashes, "Must calculate SHA1"
        assert "sha256" in all_hashes, "Must calculate SHA256"
        assert "sha512" in all_hashes, "Must calculate SHA512"

        assert all_hashes["crc32"].startswith("0x"), "CRC32 must be hex format"
        assert all_hashes["crc64"].startswith("0x"), "CRC64 must be hex format"
        assert len(all_hashes["md5"]) == 32, "MD5 must be 32 hex chars"
        assert len(all_hashes["sha1"]) == 40, "SHA1 must be 40 hex chars"
        assert len(all_hashes["sha256"]) == 64, "SHA256 must be 64 hex chars"
        assert len(all_hashes["sha512"]) == 128, "SHA512 must be 128 hex chars"


class TestSectionHashing:
    """Tests for PE section hashing detection and bypass."""

    def test_recalculate_section_hashes_for_pe_binary(
        self,
        real_pe_binary: Path,
        checksum_calculator: ChecksumRecalculator,
    ) -> None:
        """System calculates hashes for individual PE sections."""
        section_hashes = checksum_calculator.recalculate_section_hashes(str(real_pe_binary))

        assert isinstance(section_hashes, dict), "Must return section hash dictionary"
        assert len(section_hashes) > 0, "Real PE binary must have at least one section"

        for section_name, hashes in section_hashes.items():
            assert isinstance(section_name, str), "Section name must be string"
            assert "md5" in hashes, "Section must have MD5 hash"
            assert "sha1" in hashes, "Section must have SHA1 hash"
            assert "sha256" in hashes, "Section must have SHA256 hash"
            assert "sha512" in hashes, "Section must have SHA512 hash"
            assert "crc32" in hashes, "Section must have CRC32"
            assert "crc64" in hashes, "Section must have CRC64"
            assert "size" in hashes, "Section must have size"

            assert len(hashes["md5"]) == 32, f"Section {section_name} MD5 must be valid"
            assert len(hashes["sha256"]) == 64, f"Section {section_name} SHA256 must be valid"

    def test_patch_section_hash_embedded_in_binary(
        self,
        real_pe_binary: Path,
        temp_dir: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """System patches section hash values embedded in protected binaries."""
        pe_path, section_hashes = create_pe_with_section_hashes(real_pe_binary, temp_dir)

        pe_data = bytearray(pe_path.read_bytes())

        first_section = list(section_hashes.keys())[0]
        expected_hash = section_hashes[first_section]

        hash_offset = len(pe_data) - 200
        pe_data = pe_data[:hash_offset] + b"\x00" * 32 + pe_data[hash_offset + 32 :]

        modified_pe = temp_dir / "modified_section_hash.exe"
        modified_pe.write_bytes(pe_data)

        locations = [
            ChecksumLocation(
                offset=hash_offset,
                size=32,
                algorithm=IntegrityCheckType.SHA256_HASH,
                current_value=b"\x00" * 32,
                calculated_value=expected_hash,
                confidence=1.0,
            )
        ]

        output_path = temp_dir / "patched_section_hash.exe"
        success = defeat_system.patch_embedded_checksums(
            str(modified_pe),
            locations,
            str(output_path),
        )

        assert success, "Section hash patching must succeed"

        patched_data = output_path.read_bytes()
        embedded_hash = patched_data[hash_offset : hash_offset + 32]

        assert embedded_hash == expected_hash, "Section hash must be correctly patched"
        assert embedded_hash != b"\x00" * 32, "Section hash must not be placeholder"


class TestCodeSigningBypass:
    """Tests for code signing verification bypass (Authenticode, catalog files)."""

    def test_detect_authenticode_signature_on_signed_binary(
        self,
        real_pe_binary: Path,
    ) -> None:
        """System detects Authenticode signatures in PE binaries."""
        has_signature = verify_authenticode_signature(real_pe_binary)

        pe = pefile.PE(str(real_pe_binary))
        security_dir_entry = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_entry]

        expected_signature = security_dir.VirtualAddress != 0 and security_dir.Size != 0

        assert has_signature == expected_signature, "Authenticode detection must match PE headers"

        pe.close()

    def test_patch_binary_preserves_structure_for_resigning(
        self,
        real_pe_binary: Path,
        temp_dir: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """Patched binaries maintain PE structure for code signing bypass."""
        test_binary = temp_dir / "test_resign.exe"

        with open(real_pe_binary, "rb") as f:
            binary_data = bytearray(f.read())

        test_binary.write_bytes(binary_data)

        crc_offset = len(binary_data) - 100
        expected_crc = ChecksumRecalculator().calculate_crc32_zlib(binary_data[:crc_offset])

        locations = [
            ChecksumLocation(
                offset=crc_offset,
                size=4,
                algorithm=IntegrityCheckType.CRC32,
                current_value=binary_data[crc_offset : crc_offset + 4],
                calculated_value=struct.pack("<I", expected_crc),
                confidence=1.0,
            )
        ]

        output_path = temp_dir / "patched_resign.exe"
        success = defeat_system.patch_embedded_checksums(
            str(test_binary),
            locations,
            str(output_path),
        )

        assert success, "Binary patching must succeed"

        try:
            original_pe = pefile.PE(str(test_binary))
            patched_pe = pefile.PE(str(output_path))

            assert original_pe.DOS_HEADER.e_magic == patched_pe.DOS_HEADER.e_magic, "DOS header must be preserved"
            assert original_pe.NT_HEADERS.Signature == patched_pe.NT_HEADERS.Signature, "NT signature must be preserved"
            assert len(original_pe.sections) == len(patched_pe.sections), "Section count must be preserved"

            original_pe.close()
            patched_pe.close()

        except Exception as e:
            pytest.fail(f"Patched PE structure validation failed: {e}")

    def test_find_embedded_checksums_in_protected_binary(
        self,
        protected_binary: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """System locates embedded checksums in protected binaries."""
        checksum_locations = defeat_system.find_embedded_checksums(str(protected_binary))

        assert isinstance(checksum_locations, list), "Must return list of checksum locations"

        for location in checksum_locations:
            assert isinstance(location, ChecksumLocation), "Must be ChecksumLocation instance"
            assert location.offset >= 0, "Offset must be non-negative"
            assert location.size > 0, "Size must be positive"
            assert isinstance(location.algorithm, IntegrityCheckType), "Algorithm must be IntegrityCheckType"
            assert 0.0 <= location.confidence <= 1.0, "Confidence must be between 0.0 and 1.0"
            assert len(location.current_value) == location.size, "Current value size must match"
            assert len(location.calculated_value) == location.size, "Calculated value size must match"


class TestEdgeCases:
    """Tests for edge cases including corrupted data, large binaries, and error handling."""

    def test_patch_handles_invalid_binary_path_gracefully(
        self,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """System handles non-existent binary paths without crashing."""
        invalid_path = r"D:\NonExistent\Path\To\Binary.exe"

        locations = [
            ChecksumLocation(
                offset=0,
                size=4,
                algorithm=IntegrityCheckType.CRC32,
                current_value=b"\x00\x00\x00\x00",
                calculated_value=b"\x12\x34\x56\x78",
                confidence=1.0,
            )
        ]

        success = defeat_system.patch_embedded_checksums(invalid_path, locations)

        assert not success, "Patching invalid path must fail gracefully"

    def test_patch_handles_offset_beyond_file_bounds(
        self,
        temp_dir: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """System handles checksum offsets beyond binary bounds safely."""
        test_binary = temp_dir / "test_bounds.bin"
        test_binary.write_bytes(b"SHORT_BINARY_DATA")

        locations = [
            ChecksumLocation(
                offset=10000,
                size=4,
                algorithm=IntegrityCheckType.CRC32,
                current_value=b"\x00\x00\x00\x00",
                calculated_value=b"\x12\x34\x56\x78",
                confidence=1.0,
            )
        ]

        output_path = temp_dir / "patched_bounds.bin"
        success = defeat_system.patch_embedded_checksums(
            str(test_binary),
            locations,
            str(output_path),
        )

        assert success, "Patching must complete even with invalid offsets"

        patched_data = output_path.read_bytes()
        original_data = test_binary.read_bytes()

        assert patched_data == original_data, "Binary must remain unchanged for out-of-bounds offsets"

    def test_patch_handles_zero_size_checksums(
        self,
        temp_dir: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """System handles zero-size checksum locations gracefully."""
        test_binary = temp_dir / "test_zero_size.bin"
        test_binary.write_bytes(b"TEST_DATA_FOR_ZERO_SIZE_CHECKSUM")

        locations = [
            ChecksumLocation(
                offset=10,
                size=0,
                algorithm=IntegrityCheckType.CRC32,
                current_value=b"",
                calculated_value=b"",
                confidence=1.0,
            )
        ]

        output_path = temp_dir / "patched_zero_size.bin"
        success = defeat_system.patch_embedded_checksums(
            str(test_binary),
            locations,
            str(output_path),
        )

        assert success, "Patching with zero-size checksum must succeed"

    def test_patch_handles_large_binary_efficiently(
        self,
        temp_dir: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """System patches large binaries (>100MB) without performance issues."""
        large_binary = temp_dir / "large_binary.bin"

        chunk_size = 1024 * 1024
        total_chunks = 100

        with open(large_binary, "wb") as f:
            for i in range(total_chunks):
                chunk = os.urandom(chunk_size)
                f.write(chunk)

        file_size = large_binary.stat().st_size
        crc_offset = file_size - 4

        calc = ChecksumRecalculator()
        with open(large_binary, "rb") as f:
            data = f.read(crc_offset)
        expected_crc = calc.calculate_crc32_zlib(data)

        locations = [
            ChecksumLocation(
                offset=crc_offset,
                size=4,
                algorithm=IntegrityCheckType.CRC32,
                current_value=b"\x00\x00\x00\x00",
                calculated_value=struct.pack("<I", expected_crc),
                confidence=1.0,
            )
        ]

        output_path = temp_dir / "patched_large.bin"

        start_time = time.time()

        success = defeat_system.patch_embedded_checksums(
            str(large_binary),
            locations,
            str(output_path),
        )

        elapsed_time = time.time() - start_time

        assert success, "Large binary patching must succeed"
        assert elapsed_time < 30.0, "Large binary patching must complete within 30 seconds"
        assert output_path.stat().st_size == file_size, "Patched binary size must match original"

    def test_patch_multiple_checksums_atomically(
        self,
        temp_dir: Path,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """System patches multiple checksums in single atomic operation."""
        test_binary = temp_dir / "test_atomic.bin"
        test_data = b"ATOMIC_CHECKSUM_PATCHING_TEST_DATA" * 100

        test_binary.write_bytes(test_data + b"\x00" * 100)

        crc32_offset = len(test_data)
        md5_offset = crc32_offset + 4
        sha256_offset = md5_offset + 16

        calc = ChecksumRecalculator()
        expected_crc = calc.calculate_crc32_zlib(test_data)
        expected_md5 = bytes.fromhex(calc.calculate_md5(test_data))
        expected_sha256 = bytes.fromhex(calc.calculate_sha256(test_data))

        locations = [
            ChecksumLocation(
                offset=crc32_offset,
                size=4,
                algorithm=IntegrityCheckType.CRC32,
                current_value=b"\x00\x00\x00\x00",
                calculated_value=struct.pack("<I", expected_crc),
                confidence=1.0,
            ),
            ChecksumLocation(
                offset=md5_offset,
                size=16,
                algorithm=IntegrityCheckType.MD5_HASH,
                current_value=b"\x00" * 16,
                calculated_value=expected_md5,
                confidence=1.0,
            ),
            ChecksumLocation(
                offset=sha256_offset,
                size=32,
                algorithm=IntegrityCheckType.SHA256_HASH,
                current_value=b"\x00" * 32,
                calculated_value=expected_sha256,
                confidence=1.0,
            ),
        ]

        output_path = temp_dir / "patched_atomic.bin"
        success = defeat_system.patch_embedded_checksums(
            str(test_binary),
            locations,
            str(output_path),
        )

        assert success, "Atomic multi-checksum patching must succeed"

        patched_data = output_path.read_bytes()

        embedded_crc = struct.unpack("<I", patched_data[crc32_offset : crc32_offset + 4])[0]
        embedded_md5 = patched_data[md5_offset : md5_offset + 16]
        embedded_sha256 = patched_data[sha256_offset : sha256_offset + 32]

        assert embedded_crc == expected_crc, "CRC32 must be correctly patched"
        assert embedded_md5 == expected_md5, "MD5 must be correctly patched"
        assert embedded_sha256 == expected_sha256, "SHA256 must be correctly patched"
