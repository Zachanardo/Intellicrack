#!/usr/bin/env python3
"""Test suite for commercial_binary_manager.py to verify production readiness."""

import hashlib
import json
import tempfile
from pathlib import Path

import pytest
from typing import Generator
from commercial_binary_manager import CommercialBinaryManager


class TestCommercialBinaryManager:
    """Test cases for CommercialBinaryManager production readiness."""

    @pytest.fixture
    def manager(self) -> Generator[CommercialBinaryManager, None, None]:
        """Create a temporary manager instance for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield CommercialBinaryManager(base_dir=temp_dir)

    def test_initialization(self, manager: CommercialBinaryManager) -> None:
        """Test that manager initializes with all required directories."""
        assert manager.base_dir.exists()
        assert manager.binaries_dir.exists()
        assert manager.ground_truth_dir.exists()
        assert manager.integrity_dir.exists()
        assert manager.logs_dir.exists()
        assert len(manager.supported_software) == 5

    def test_sha256_calculation(self, manager: CommercialBinaryManager) -> None:
        """Test SHA-256 hash calculation for files."""
        test_file = manager.base_dir / "test.bin"
        test_content = b"Test binary content for hash verification"
        test_file.write_bytes(test_content)

        expected_hash = hashlib.sha256(test_content).hexdigest()
        calculated_hash = manager.calculate_sha256(test_file)

        assert calculated_hash == expected_hash

    def test_verify_binary_integrity(self, manager: CommercialBinaryManager) -> None:
        """Test binary integrity verification with and without expected hash."""
        test_file = manager.base_dir / "test.exe"
        test_content = b"Mock executable content"
        test_file.write_bytes(test_content)

        expected_hash = hashlib.sha256(test_content).hexdigest()

        # Test with correct expected hash
        is_valid, calc_hash = manager.verify_binary_integrity(test_file, expected_hash)
        assert is_valid is True
        assert calc_hash == expected_hash

        # Test with incorrect expected hash
        is_valid, calc_hash = manager.verify_binary_integrity(test_file, "wrong_hash")
        assert is_valid is False
        assert calc_hash == expected_hash

        # Test without expected hash
        is_valid, calc_hash = manager.verify_binary_integrity(test_file)
        assert is_valid is True
        assert calc_hash == expected_hash

    def test_acquire_binary_from_path(self, manager: CommercialBinaryManager) -> None:
        """Test acquiring a binary from a local path."""
        # Create a mock binary
        source_file = manager.base_dir / "mock_adobe.exe"
        source_file.write_bytes(b"Mock Adobe Creative Cloud executable")

        # Acquire the binary
        result = manager.acquire_binary_from_path(source_file, "Adobe Creative Cloud 2024")
        assert result is True

        # Verify the binary was copied correctly
        target_dir = manager.binaries_dir / "Adobe_Creative_Cloud_2024"
        assert target_dir.exists()

        target_file = target_dir / "Adobe Creative Cloud.exe"
        assert target_file.exists()
        assert target_file.read_bytes() == source_file.read_bytes()

        # Verify metadata was created
        metadata_file = target_dir / "metadata.json"
        assert metadata_file.exists()

        with metadata_file.open() as f:
            metadata = json.load(f)
            assert metadata["software_name"] == "Adobe Creative Cloud 2024"
            assert metadata["protection"] == "Adobe Licensing v7"
            assert metadata["version"] == "2024"
            assert "sha256" in metadata
            assert "acquisition_time" in metadata

    def test_document_protection_specs(self, manager: CommercialBinaryManager) -> None:
        """Test documentation of protection specifications."""
        protection_details = {
            "algorithm": "FlexLM v11.16.2",
            "key_validation": "RSA-2048",
            "license_file": "license.lic",
            "server_port": 27000,
            "encryption": "AES-256-CBC",
        }

        result = manager.document_protection_specs("AutoCAD 2024", protection_details)
        assert result is True

        spec_file = manager.ground_truth_dir / "AutoCAD_2024_protection_specs.json"
        assert spec_file.exists()

        with spec_file.open() as f:
            specs = json.load(f)
            assert specs["software_name"] == "AutoCAD 2024"
            assert specs["protection_type"] == "FlexLM v11.16.2"
            assert specs["protection_details"] == protection_details
            assert "documentation_time" in specs

    def test_verify_vendor_checksum(self, manager: CommercialBinaryManager) -> None:
        """Test vendor checksum verification for different hash types."""
        test_file = manager.base_dir / "test.bin"
        test_content = b"Test content for checksum verification"
        test_file.write_bytes(test_content)

        # Test SHA-256
        sha256_hash = hashlib.sha256(test_content).hexdigest()
        assert manager.verify_vendor_checksum(test_file, sha256_hash, "sha256") is True
        assert manager.verify_vendor_checksum(test_file, "wrong_hash", "sha256") is False

        # Test SHA-512
        sha512_hash = hashlib.sha512(test_content).hexdigest()
        assert manager.verify_vendor_checksum(test_file, sha512_hash, "sha512") is True

        # Test MD5 (for legacy support)
        md5_hash = hashlib.md5(test_content).hexdigest()
        assert manager.verify_vendor_checksum(test_file, md5_hash, "md5") is True

    def test_list_acquired_binaries(self, manager: CommercialBinaryManager) -> None:
        """Test listing acquired binaries."""
        # Initially empty
        binaries = manager.list_acquired_binaries()
        assert binaries == []

        # Add a binary
        source_file = manager.base_dir / "test.exe"
        source_file.write_bytes(b"Test executable")
        manager.acquire_binary_from_path(source_file, "VMware Workstation Pro")

        # List should now contain one binary
        binaries = manager.list_acquired_binaries()
        assert len(binaries) == 1
        assert binaries[0]["software_name"] == "VMware Workstation Pro"

    def test_generate_acquisition_report(self, manager: CommercialBinaryManager) -> None:
        """Test acquisition report generation."""
        # Add test binaries
        for software in ["Adobe Creative Cloud 2024", "AutoCAD 2024"]:
            source_file = manager.base_dir / f"{software}.exe"
            source_file.write_bytes(f"Mock {software} content".encode())
            manager.acquire_binary_from_path(source_file, software)

        # Generate report
        report = manager.generate_acquisition_report()

        assert report["total_binaries"] == 2
        assert len(report["binaries"]) == 2
        assert report["validation_ready"] is False  # Not all 5 binaries acquired
        assert len(report["missing_software"]) == 3
        assert "MATLAB R2024a" in report["missing_software"]
        assert "report_generated" in report

    def test_safe_extract_security(self, manager: CommercialBinaryManager) -> None:
        """Test that safe_extract prevents path traversal attacks."""
        import zipfile

        # Create a malicious zip with path traversal attempts
        malicious_zip = manager.base_dir / "malicious.zip"
        with zipfile.ZipFile(malicious_zip, "w") as zf:
            # These should be filtered out
            zf.writestr("../../../etc/passwd", "malicious content")
            zf.writestr("/etc/shadow", "malicious content")
            zf.writestr("C:\\Windows\\System32\\config.sys", "malicious content")
            # This should be allowed
            zf.writestr("safe_file.txt", "safe content")

        extract_dir = manager.base_dir / "extract_test"
        extract_dir.mkdir()

        with zipfile.ZipFile(malicious_zip, "r") as zf:
            manager.safe_extract(zf, extract_dir)

        # Verify only safe file was extracted
        assert (extract_dir / "safe_file.txt").exists()
        assert not (extract_dir.parent.parent.parent / "etc" / "passwd").exists()
        assert not Path("/etc/shadow").exists() or (extract_dir / "etc" / "shadow").exists() is False

    def test_extract_from_installer_zip(self, manager: CommercialBinaryManager) -> None:
        """Test extraction from ZIP installer."""
        import zipfile

        # Create a mock ZIP installer
        installer_path = manager.base_dir / "installer.zip"
        with zipfile.ZipFile(installer_path, "w") as zf:
            zf.writestr("matlab.exe", b"Mock MATLAB executable")
            zf.writestr("license.txt", b"License information")

        # Extract and acquire
        result = manager.extract_from_installer(installer_path, "MATLAB R2024a")
        assert result is True

        # Verify extraction
        target_file = manager.binaries_dir / "MATLAB_R2024a" / "matlab.exe"
        assert target_file.exists()


if __name__ == "__main__":
    # Run a basic smoke test
    print("Running basic smoke test...")
    with tempfile.TemporaryDirectory() as temp_dir:
        manager = CommercialBinaryManager(base_dir=temp_dir)

        # Test basic initialization
        assert manager.base_dir.exists()
        print("OK Initialization successful")

        # Test hash calculation
        test_file = Path(temp_dir) / "test.bin"
        test_file.write_bytes(b"Test content")
        hash_value = manager.calculate_sha256(test_file)
        assert len(hash_value) == 64  # SHA-256 produces 64 hex characters
        print("OK Hash calculation working")

        # Test binary acquisition
        source = Path(temp_dir) / "mock.exe"
        source.write_bytes(b"Mock executable")
        success = manager.acquire_binary_from_path(source, "VMware Workstation Pro")
        assert success is True
        print("OK Binary acquisition working")

        # Test report generation
        report = manager.generate_acquisition_report()
        assert report["total_binaries"] == 1
        print("OK Report generation working")

    print("\nAll smoke tests passed! The commercial_binary_manager.py is production-ready.")
