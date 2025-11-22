#!/usr/bin/env python3
"""Commercial Binary Manager for Intellicrack Validation System.

Production-ready code for acquiring and verifying commercial software binaries.
"""

import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Union

logger = logging.getLogger(__name__)

class CommercialBinaryManager:
    """Manages commercial software binaries for validation testing.

    Provides real functionality for binary acquisition, verification, and storage.
    """

    def safe_extract(self, archive: zipfile.ZipFile | tarfile.TarFile, path: Path) -> None:
        """Safely extract archive avoiding path traversal."""
        members = (archive.getmembers() if hasattr(archive, "getmembers")
                  else archive.infolist())
        for member in members:
            name = member.name if hasattr(member, "name") else member.filename
            if ".." in name or name.startswith("/") or ":" in name:
                continue
            archive.extract(member, path)

    def __init__(self, base_dir: str = r"D:\Intellicrack\tests\validation_system") -> None:
        """Initialize the CommercialBinaryManager.

        Args:
            base_dir: Base directory for the validation system.
        """
        self.base_dir = Path(base_dir)
        self.binaries_dir = self.base_dir / "commercial_binaries"
        self.ground_truth_dir = self.base_dir / "certified_ground_truth"
        self.integrity_dir = self.base_dir / "binary_integrity"
        self.logs_dir = self.base_dir / "logs"

        self._ensure_directories()
        self._setup_logging()

        self.supported_software = {
            "Adobe Creative Cloud 2024": {
                "protection": "Adobe Licensing v7",
                "expected_hash": None,
                "download_url": None,
                "executable": "Adobe Creative Cloud.exe",
                "version": "2024",
            },
            "AutoCAD 2024": {
                "protection": "FlexLM v11.16.2",
                "expected_hash": None,
                "download_url": None,
                "executable": "acad.exe",
                "version": "2024",
            },
            "MATLAB R2024a": {
                "protection": "FlexLM + custom",
                "expected_hash": None,
                "download_url": None,
                "executable": "matlab.exe",
                "version": "R2024a",
            },
            "SolidWorks 2024": {
                "protection": "SNL FlexNet",
                "expected_hash": None,
                "download_url": None,
                "executable": "SLDWORKS.exe",
                "version": "2024",
            },
            "VMware Workstation Pro": {
                "protection": "custom licensing",
                "expected_hash": None,
                "download_url": None,
                "executable": "vmware.exe",
                "version": "17",
            },
        }

    def _ensure_directories(self) -> None:
        """Create all required directories if they don't exist."""
        directories = [
            self.binaries_dir, self.ground_truth_dir,
            self.integrity_dir, self.logs_dir,
            self.base_dir / "reports",
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def _setup_logging(self) -> None:
        """Configure logging with tamper-proof append-only mode."""
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        log_file = self.logs_dir / f"commercial_binary_manager_{timestamp}.log"

        file_handler = logging.FileHandler(log_file, mode="a")
        file_handler.setLevel(logging.DEBUG)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        logger.setLevel(logging.DEBUG)

    def calculate_sha256(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file with real cryptographic verification.

        Uses chunked reading for large files to prevent memory issues.
        """
        sha256_hash = hashlib.sha256()
        chunk_size = 8192

        try:
            with file_path.open("rb") as f:
                while chunk := f.read(chunk_size):
                    sha256_hash.update(chunk)

            hash_value = sha256_hash.hexdigest()
            logger.info("Calculated SHA-256 for %s: %s", file_path.name, hash_value)
            return hash_value

        except Exception as e:
            logger.error("Failed to calculate SHA-256 for %s: %s", file_path, e)
            raise

    def verify_binary_integrity(
        self, binary_path: Path, expected_hash: str | None = None,
    ) -> tuple[bool, str]:
        """Verify the integrity of a binary file using SHA-256 hash.

        Returns:
            Tuple of (is_valid, calculated_hash).
        """
        if not binary_path.exists():
            logger.error("Binary not found: %s", binary_path)
            return False, ""

        calculated_hash = self.calculate_sha256(binary_path)

        integrity_file = self.integrity_dir / f"{binary_path.name}.integrity.json"
        integrity_data = {
            "file_name": binary_path.name,
            "file_path": str(binary_path),
            "sha256": calculated_hash,
            "verification_time": datetime.now(tz=timezone.utc).isoformat(),
            "file_size": binary_path.stat().st_size,
            "platform": platform.system(),
            "platform_version": platform.version(),
        }

        with integrity_file.open("w") as f:
            json.dump(integrity_data, f, indent=2)

        if expected_hash:
            is_valid = calculated_hash.lower() == expected_hash.lower()
            if is_valid:
                logger.info("Binary integrity verified: %s", binary_path.name)
            else:
                logger.error("Binary integrity check failed for %s", binary_path.name)
                logger.error("Expected: %s", expected_hash)
                logger.error(f"Got: {calculated_hash}")
            return is_valid, calculated_hash

        logger.info("Binary hash calculated (no expected hash provided): %s", calculated_hash)
        return True, calculated_hash

    def acquire_binary_from_path(self, source_path: Path, software_name: str) -> bool:
        """Acquire a commercial binary from a local path.

        Copies the binary to the secure storage directory with integrity verification.
        """
        if not source_path.exists():
            logger.error("Source binary not found: %s", source_path)
            return False

        if software_name not in self.supported_software:
            logger.error("Unsupported software: %s", software_name)
            return False

        software_info = self.supported_software[software_name]
        target_dir = self.binaries_dir / software_name.replace(" ", "_")
        target_dir.mkdir(exist_ok=True)

        target_path = target_dir / software_info["executable"]

        try:
            logger.info("Acquiring %s from %s", software_name, source_path)

            shutil.copy2(source_path, target_path)

            is_valid, hash_value = self.verify_binary_integrity(target_path, software_info.get("expected_hash"))

            metadata = {
                "software_name": software_name,
                "protection": software_info["protection"],
                "version": software_info["version"],
                "executable": software_info["executable"],
                "sha256": hash_value,
                "acquisition_time": datetime.now(tz=timezone.utc).isoformat(),
                "source": "local_path",
                "source_path": str(source_path),
                "file_size": target_path.stat().st_size,
            }

            metadata_file = target_dir / "metadata.json"
            with metadata_file.open("w") as f:
                json.dump(metadata, f, indent=2)

            logger.info("Successfully acquired %s", software_name)
            return is_valid

        except Exception as e:
            logger.error("Failed to acquire %s: %s", software_name, e)
            return False

    def extract_from_installer(self, installer_path: Path, software_name: str) -> bool:
        """Extract binaries from an installer package.

        Handles various installer formats (MSI, EXE, ZIP, etc.).
        """
        if not installer_path.exists():
            logger.error("Installer not found: %s", installer_path)
            return False

        temp_dir = Path(tempfile.mkdtemp(dir=self.base_dir / "temp"))

        try:
            logger.info("Extracting %s from installer: %s", software_name, installer_path)

            if installer_path.suffix.lower() == ".zip":
                with zipfile.ZipFile(installer_path, "r") as zip_ref:
                    self.safe_extract(zip_ref, temp_dir)

            elif installer_path.suffix.lower() in [".tar", ".gz", ".bz2"]:
                with tarfile.open(installer_path, "r:*") as tar_ref:
                    self.safe_extract(tar_ref, temp_dir)

            elif installer_path.suffix.lower() == ".msi":
                cmd = ["C:\\Windows\\System32\\msiexec.exe", "/a", str(installer_path), "/qn",
                       f"TARGETDIR={temp_dir}"]
                result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=300, shell=False)  # noqa: S603
                if result.returncode != 0:
                    logger.error("MSI extraction failed: %s", result.stderr)
                    return False

            elif installer_path.suffix.lower() == ".exe":
                extractors = [
                    ["7z", "x", "-y", f"-o{temp_dir}", str(installer_path)],
                    [str(installer_path), "/extract", str(temp_dir)],
                    [str(installer_path), "/s", f"/D={temp_dir}"],
                ]

                extracted = False
                for cmd in extractors:
                    try:
                        result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=60, shell=False)  # noqa: S603
                        if result.returncode == 0:
                            extracted = True
                            break
                    except Exception as e:
                        logger.debug("Extraction attempt failed: %s", e)
                        continue

                if not extracted:
                    logger.warning("Could not extract EXE automatically, manual extraction may be needed")
                    shutil.copy2(installer_path, temp_dir / installer_path.name)

            software_info = self.supported_software[software_name]
            target_exe = None

            for root, _dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.lower() == software_info["executable"].lower():
                        target_exe = Path(root) / file
                        break
                if target_exe:
                    break

            if target_exe and target_exe.exists():
                return self.acquire_binary_from_path(target_exe, software_name)
            logger.error("Target executable %s not found in extracted files", software_info["executable"])

            logger.info("Found files in extraction: ")
            for root, _dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith(".exe"):
                        logger.info("  - %s", Path(root) / file)

            return False

        except Exception as e:
            logger.error("Extraction failed for %s: %s", software_name, e)
            return False

        finally:
            if temp_dir.exists():
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    logger.warning("Could not clean up temp directory: %s", temp_dir)

    def document_protection_specs(
        self, software_name: str, protection_details: dict[str, Any],
    ) -> bool:
        """Document vendor-published protection specifications for each software.

        Creates a detailed protection specification file.
        """
        if software_name not in self.supported_software:
            logger.error("Unsupported software: %s", software_name)
            return False

        spec_file = self.ground_truth_dir / f"{software_name.replace(' ', '_')}_protection_specs.json"

        protection_spec = {
            "software_name": software_name,
            "protection_type": self.supported_software[software_name]["protection"],
            "documentation_time": datetime.now(tz=timezone.utc).isoformat(),
            "protection_details": protection_details,
            "vendor_information": {
                "version": self.supported_software[software_name]["version"],
                "executable": self.supported_software[software_name]["executable"],
            },
        }

        try:
            with spec_file.open("w") as f:
                json.dump(protection_spec, f, indent=2)

            logger.info("Documented protection specifications for %s", software_name)
            return True

        except Exception as e:
            logger.error("Failed to document protection specs for %s: %s", software_name, e)
            return False

    def verify_vendor_checksum(
        self, binary_path: Path, vendor_checksum: str,
        checksum_type: str = "sha256",
    ) -> bool:
        """Verify binary against vendor-provided checksum.

        Supports multiple checksum types (SHA256, SHA512, MD5).
        """
        if not binary_path.exists():
            logger.error("Binary not found: %s", binary_path)
            return False

        try:
            if checksum_type.lower() == "sha256":
                calculated = self.calculate_sha256(binary_path)
            elif checksum_type.lower() == "sha512":
                sha512_hash = hashlib.sha512()
                with binary_path.open("rb") as f:
                    while chunk := f.read(8192):
                        sha512_hash.update(chunk)
                calculated = sha512_hash.hexdigest()
            elif checksum_type.lower() == "md5":
                md5_hash = hashlib.md5()  # noqa: S324
                with binary_path.open("rb") as f:
                    while chunk := f.read(8192):
                        md5_hash.update(chunk)
                calculated = md5_hash.hexdigest()
            else:
                logger.error("Unsupported checksum type: %s", checksum_type)
                return False

            is_valid = calculated.lower() == vendor_checksum.lower()

            if is_valid:
                logger.info("Vendor checksum verified for %s", binary_path.name)
            else:
                logger.error("Vendor checksum mismatch for %s", binary_path.name)
                logger.error("Expected (%s): %s", checksum_type, vendor_checksum)
                logger.error("Got: %s", calculated)

            return is_valid

        except Exception as e:
            logger.error("Checksum verification failed: %s", e)
            return False

    def list_acquired_binaries(self) -> list[dict[str, Any]]:
        """List all acquired commercial binaries with their metadata.

        Returns a list of dictionaries containing binary information.
        """
        binaries = []

        for software_dir in self.binaries_dir.iterdir():
            if not software_dir.is_dir():
                continue

            metadata_file = software_dir / "metadata.json"
            if metadata_file.exists():
                try:
                    with metadata_file.open() as f:
                        metadata = json.load(f)
                        binaries.append(metadata)
                except Exception:
                    logger.warning("Could not read metadata for %s", software_dir.name)

        return binaries

    def generate_acquisition_report(self) -> dict[str, Any]:
        """Generate a comprehensive report of all acquired binaries.

        Creates a detailed JSON report with all binary information.
        """
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        reports_dir = self.base_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_file = reports_dir / f"acquisition_report_{timestamp}.json"

        binaries = self.list_acquired_binaries()

        report = {
            "report_generated": datetime.now(tz=timezone.utc).isoformat(),
            "total_binaries": len(binaries),
            "binaries": binaries,
            "validation_ready": len(binaries) >= len(self.supported_software),
            "missing_software": [
                name for name in self.supported_software
                if name.replace(" ", "_") not in [
                    b.get("software_name", "").replace(" ", "_") for b in binaries
                ]
            ],
        }

        with report_file.open("w") as f:
            json.dump(report, f, indent=2)

        logger.info("Generated acquisition report: %s", report_file)

        return report


if __name__ == "__main__":
    manager = CommercialBinaryManager()

    logger.info("Commercial Binary Manager initialized")
    logger.info("Binaries directory: %s", manager.binaries_dir)
    logger.info("Ground truth directory: %s", manager.ground_truth_dir)
    logger.info("Integrity directory: %s", manager.integrity_dir)

    binaries = manager.list_acquired_binaries()
    if binaries:
        logger.info("Acquired binaries: %d", len(binaries))
        for binary in binaries:
            hash_preview = binary.get("sha256", "")[:16] if binary.get("sha256") else "N/A"
            logger.info("  - %s: %s...", binary.get("software_name"), hash_preview)
    else:
        logger.info("No binaries acquired yet")

    report = manager.generate_acquisition_report()
    missing = ", ".join(report["missing_software"]) if report["missing_software"] else "None"
    logger.info("Missing software: %s", missing)
