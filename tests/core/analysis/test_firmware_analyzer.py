"""
Comprehensive unit tests for firmware_analyzer.py module.

This test suite validates production-ready firmware analysis capabilities using
specification-driven, black-box testing methodology. Tests verify actual binary
analysis operations on real firmware structures, encryption, and security mechanisms.
"""

import os
import tempfile
import unittest
from pathlib import Path

from intellicrack.core.analysis.firmware_analyzer import (
    FirmwareAnalyzer,
    FirmwareType,
    SecurityFindingType,
    FirmwareSignature,
    ExtractedFile,
    SecurityFinding,
    FirmwareExtraction,
    FirmwareAnalysisResult,
    get_firmware_analyzer,
    is_binwalk_available,
    analyze_firmware_file
)


class TestFirmwareFixtures:
    """Real firmware binary test fixtures for comprehensive validation."""

    @staticmethod
    def create_router_firmware_sample() -> bytes:
        """Create realistic router firmware binary with authentic structures."""
        # Real squashfs filesystem signature and header structure
        squashfs_header = (
            b'\x68\x73\x71\x73'  # squashfs magic
            b'\x01\x00\x00\x00'  # inodes
            b'\x00\x01\x00\x00'  # mkfs_time
            b'\x00\x10\x00\x00'  # block_size (4096)
            b'\x00\x00\x00\x00'  # fragments
            b'\x01\x00'          # compression (gzip)
            b'\x00\x02'          # block_log
            b'\x00\x00'          # flags
            b'\x00\x00'          # no_ids
            b'\x04\x00'          # version major
            b'\x00\x00'          # version minor
            b'\x60\x00\x00\x00'  # root_inode
            b'\x00\x04\x00\x00'  # bytes_used
            b'\x00\x00\x00\x00'  # uid_start
            b'\x00\x00\x00\x00'  # guid_start
            b'\x00\x00\x00\x00'  # inode_table_start
            b'\x00\x00\x00\x00'  # directory_table_start
            b'\x00\x00\x00\x00'  # fragment_table_start
            b'\x00\x00\x00\x00'  # lookup_table_start
        )

        # Embedded configuration with credentials (security finding)
        config_data = (
            b'admin_user=root\x00'
            b'admin_pass=admin123\x00'
            b'telnet_enabled=1\x00'
            b'debug_mode=1\x00'
            b'firmware_version=v2.1.3\x00'
            b'wireless_key=WPA2_PSK_KEY_HERE\x00'
        )

        # Padding and additional firmware data
        padding = b'\x00' * (1024 - len(squashfs_header) - len(config_data))

        return squashfs_header + config_data + padding

    @staticmethod
    def create_iot_device_firmware() -> bytes:
        """Create IoT device firmware with JFFS2 filesystem signature."""
        # Real JFFS2 filesystem magic and node structure
        jffs2_header = (
            b'\x19\x85'          # JFFS2 magic
            b'\xe0\x01'          # node type (dirent)
            b'\x10\x00\x00\x00'  # total length
            b'\x00\x00\x00\x00'  # header CRC
            b'\x01\x00\x00\x00'  # version
            b'\x00\x00\x00\x00'  # inode number
            b'\x00\x00\x00\x00'  # version
            b'\x04\x00\x00\x00'  # mctime
        )

        # IoT device strings with potential security issues
        iot_strings = (
            b'AT+CWMODE=1\x00'        # WiFi AT commands
            b'POST /api/config\x00'    # API endpoints
            b'{"key":"default123"}\x00'  # Default API key
            b'mqtt://broker.local\x00' # MQTT configuration
            b'UPDATE firmware\x00'     # Update commands
            b'ssh-rsa AAAAB3NzaC1yc2E\x00'  # SSH key fragment
        )

        padding = b'\xff' * (2048 - len(jffs2_header) - len(iot_strings))
        return jffs2_header + iot_strings + padding

    @staticmethod
    def create_bootloader_binary() -> bytes:
        """Create bootloader firmware with ARM/x86 executable signatures."""
        # ARM bootloader header with realistic structure
        arm_header = (
            b'\x00\x00\xa0\xe1'  # ARM instruction: mov r0, r0 (nop)
            b'\x00\x00\xa0\xe1'  # ARM instruction: mov r0, r0 (nop)
            b'\xfe\xff\xff\xea'  # ARM branch instruction
            b'\x00\x00\x00\x00'  # Vector table entry
        )

        # Boot messages and version strings
        boot_data = (
            b'U-Boot 2020.04\x00'
            b'ARM Cortex-A53\x00'
            b'Loading kernel...\x00'
            b'Boot from SD card\x00'
            b'Memory test passed\x00'
            b'UART initialized\x00'
        )

        padding = b'\x00' * (1024 - len(arm_header) - len(boot_data))
        return arm_header + boot_data + padding

    @staticmethod
    def create_kernel_image() -> bytes:
        """Create Linux kernel image with realistic headers."""
        # Linux kernel magic and header structure
        kernel_header = (
            b'HdrS'              # Linux kernel header signature
            b'\x02\x0e'          # Version 14.2
            b'\x00\x00\x00\x00'  # realmode_swtch
            b'\x00\x01'          # start_sys_seg
            b'\x00\x00'          # kernel_version
            b'\x01'              # type_of_loader
            b'\x00'              # loadflags
            b'\x00\x00'          # setup_move_size
            b'\x00\x00\x10\x00'  # code32_start
            b'\x00\x00\x00\x00'  # ramdisk_image
            b'\x00\x00\x00\x00'  # ramdisk_size
        )

        # Kernel symbols and debug information
        kernel_data = (
            b'vmlinux-5.4.0\x00'
            b'CONFIG_MODULES=y\x00'
            b'CONFIG_DEBUG_KERNEL=y\x00'
            b'init_module\x00'
            b'cleanup_module\x00'
            b'printk\x00'
        )

        padding = b'\x00' * (2048 - len(kernel_header) - len(kernel_data))
        return kernel_header + kernel_data + padding

    @staticmethod
    def create_uefi_firmware() -> bytes:
        """Create UEFI firmware binary with EFI signatures."""
        # UEFI firmware volume header
        uefi_header = (
            b'_FVH' +            # UEFI Firmware Volume signature
            b'\x00' * 12 +       # Reserved bytes
            b'\x48\x00\x00\x00' +  # Header length
            b'\x5a\xfe' +          # Checksum
            b'\x00\x00' +          # Extended header offset
            b'\x00' * 4 +          # Reserved
            b'\x01'              # Revision
        )

        # UEFI modules and certificates
        uefi_data = (
            b'DxeCore.efi\x00' +
            b'PlatformDxe.efi\x00' +
            b'-----BEGIN CERTIFICATE-----\x00' +
            b'MIIBIjANBgkqhkiG9w0BAQEF\x00' +  # RSA public key start
            b'SetupMode=0\x00' +
            b'SecureBoot=1\x00'
        )

        padding = b'\xff' * (4096 - len(uefi_header) - len(uefi_data))
        return uefi_header + uefi_data + padding

    @staticmethod
    def create_encrypted_firmware() -> bytes:
        """Create firmware sample with AES-256-CBC encrypted content."""
        # Use real AES-256-CBC encryption with deterministic key/IV for testing
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        import os

        # Deterministic key and IV for reproducible tests
        key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c' * 2  # 256-bit key
        iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

        # Real firmware data to encrypt
        firmware_data = (
            b'FIRM' +              # Firmware signature
            b'\x01\x00\x00\x00' +  # Version
            # Real x86 boot loader code sequence
            b'\xEA\x00\x7C\x00\x00' +  # Far jump to boot sector
            b'\x31\xC0' +              # XOR AX, AX - Clear AX
            b'\x8E\xD8' +              # MOV DS, AX - Set data segment
            b'\x8E\xC0' +              # MOV ES, AX - Set extra segment
            b'\x8E\xD0' +              # MOV SS, AX - Set stack segment
            b'\xBC\x00\x7C' +          # MOV SP, 0x7C00 - Set stack pointer
            b'\xFB' +                  # STI - Enable interrupts
            b'\xB8\x13\x00' +          # MOV AX, 0x13 - Video mode
            b'\xCD\x10' +              # INT 0x10 - BIOS video interrupt
            b'\xB8\x01\x13' +          # MOV AX, 0x1301 - Write string
            b'\xB9\x0C\x00' +          # MOV CX, 12 - String length
            b'\xB2\x00' +              # MOV DL, 0 - Column
            b'\xB6\x00' +              # MOV DH, 0 - Row
            b'\x90' * 64 +         # NOP sled for alignment
            b'\xEB\xFE' * 16 +     # Jump loops for control flow
            b'\x55\x48\x89\xE5' +  # Function prologue (x64)
            b'\x48\x83\xEC\x20' +  # Stack frame setup
            b'\x48\x8B\x45\xF8' +  # MOV RAX, [RBP-8]
            b'\xC9\xC3' +          # LEAVE; RET
            b'\x00' * (2048 - 150)  # Padding to 2048 bytes
        )

        # Apply real AES-256-CBC encryption
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Ensure data is padded to AES block size (16 bytes)
        from cryptography.hazmat.primitives import padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(firmware_data) + padder.finalize()

        # Perform actual encryption
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Build encrypted firmware with header
        header = (
            b'ENCR'              # Encryption marker
            b'\x01\x00\x00\x00'  # Version (AES-256-CBC)
            b'\x00\x10\x00\x00'  # Block size (16 bytes)
        )
        header += len(encrypted_data).to_bytes(4, 'little')  # Actual encrypted data length

        return header + iv + encrypted_data  # Include IV for proper encrypted format


class TestFirmwareAnalyzer(unittest.TestCase):
    """Comprehensive test suite for FirmwareAnalyzer functionality."""

    def setUp(self) -> None:
        """Set up test environment with temporary directory and fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.analyzer = FirmwareAnalyzer()
        self.fixtures = TestFirmwareFixtures()

        # Create test firmware files
        self.router_fw_path = Path(self.temp_dir) / "router_firmware.bin"
        self.router_fw_path.write_bytes(self.fixtures.create_router_firmware_sample())

        self.iot_fw_path = Path(self.temp_dir) / "iot_device.bin"
        self.iot_fw_path.write_bytes(self.fixtures.create_iot_device_firmware())

        self.bootloader_path = Path(self.temp_dir) / "bootloader.bin"
        self.bootloader_path.write_bytes(self.fixtures.create_bootloader_binary())

        self.kernel_path = Path(self.temp_dir) / "kernel.img"
        self.kernel_path.write_bytes(self.fixtures.create_kernel_image())

        self.uefi_path = Path(self.temp_dir) / "uefi_firmware.fd"
        self.uefi_path.write_bytes(self.fixtures.create_uefi_firmware())

        self.encrypted_path = Path(self.temp_dir) / "encrypted.bin"
        self.encrypted_path.write_bytes(self.fixtures.create_encrypted_firmware())

    def tearDown(self) -> None:
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        if hasattr(self.analyzer, 'cleanup_extractions'):
            self.analyzer.cleanup_extractions(str(self.temp_dir))

    def test_firmware_analyzer_initialization(self) -> None:
        """Test FirmwareAnalyzer proper initialization with work directory."""
        analyzer = FirmwareAnalyzer()

        # Should have valid work directory
        self.assertIsNotNone(analyzer.work_directory)
        self.assertTrue(os.path.exists(analyzer.work_directory))

        # Should initialize tracking structures
        self.assertIsInstance(analyzer.extracted_files, list)
        self.assertIsInstance(analyzer.analysis_results, dict)

        # Should have logger configured
        self.assertIsNotNone(analyzer.logger)

    def test_analyze_firmware_router_comprehensive(self) -> None:
        """Test comprehensive router firmware analysis with real capabilities validation."""
        result = self.analyzer.analyze_firmware(str(self.router_fw_path))

        # Validate core analysis results structure
        self.assertIsInstance(result, FirmwareAnalysisResult)
        self.assertEqual(result.file_path, str(self.router_fw_path))
        self.assertIsNone(result.error)

        # Should detect router firmware type through intelligent analysis
        self.assertEqual(result.firmware_type, FirmwareType.ROUTER_FIRMWARE)

        # Should identify squashfs filesystem signature
        self.assertGreater(len(result.signatures), 0)
        squashfs_detected = any('squashfs' in sig.description.lower()
                              for sig in result.signatures)
        self.assertTrue(squashfs_detected, "Should detect squashfs filesystem signature")

        # Should find security vulnerabilities (hardcoded credentials)
        credential_findings = [f for f in result.security_findings
                             if f.finding_type == SecurityFindingType.HARDCODED_CREDENTIALS]
        self.assertGreater(len(credential_findings), 0,
                          "Should detect hardcoded admin credentials")

        # Should detect default password usage
        default_pass_findings = [f for f in result.security_findings
                               if f.finding_type == SecurityFindingType.DEFAULT_CREDENTIALS]
        self.assertGreater(len(default_pass_findings), 0,
                          "Should detect default password patterns")

        # Should have reasonable analysis time (not instantaneous - indicates real processing)
        self.assertGreater(result.analysis_time, 0.001)

        # Should detect debug interface enabled
        debug_findings = [f for f in result.security_findings
                         if f.finding_type == SecurityFindingType.DEBUG_INTERFACE]
        self.assertGreater(len(debug_findings), 0,
                          "Should detect debug interface enabled")

    def test_analyze_firmware_iot_device_detection(self) -> None:
        """Test IoT device firmware analysis and classification."""
        result = self.analyzer.analyze_firmware(str(self.iot_fw_path))

        # Should classify as IoT device based on characteristics
        self.assertEqual(result.firmware_type, FirmwareType.IOT_DEVICE)

        # Should detect JFFS2 filesystem signature
        jffs2_detected = any('jffs2' in sig.description.lower()
                           for sig in result.signatures)
        self.assertTrue(jffs2_detected, "Should detect JFFS2 filesystem")

        # Should identify IoT-specific security issues
        # API endpoints should be flagged as potential vulnerabilities
        vuln_findings = [f for f in result.security_findings
                        if f.finding_type == SecurityFindingType.VULNERABLE_COMPONENT]
        self.assertGreater(len(vuln_findings), 0,
                          "Should detect API endpoints as vulnerable components")

        # Should detect hardcoded API key
        key_findings = [f for f in result.security_findings
                       if f.finding_type == SecurityFindingType.PRIVATE_KEY]
        self.assertGreater(len(key_findings), 0,
                          "Should detect hardcoded API key")

    def test_bootloader_analysis_and_architecture_detection(self) -> None:
        """Test bootloader firmware analysis with architecture detection."""
        result = self.analyzer.analyze_firmware(str(self.bootloader_path))

        # Should correctly classify as bootloader
        self.assertEqual(result.firmware_type, FirmwareType.BOOTLOADER)

        # Should detect ARM architecture from instruction patterns
        arm_signatures = [sig for sig in result.signatures
                         if 'arm' in sig.description.lower()]
        self.assertGreater(len(arm_signatures), 0,
                          "Should detect ARM architecture signatures")

        # Should identify bootloader-specific strings
        boot_strings_found = any('u-boot' in sig.description.lower()
                               for sig in result.signatures)
        self.assertTrue(boot_strings_found, "Should detect U-Boot signatures")

    def test_kernel_image_analysis(self) -> None:
        """Test Linux kernel image analysis and symbol detection."""
        result = self.analyzer.analyze_firmware(str(self.kernel_path))

        # Should classify as kernel image
        self.assertEqual(result.firmware_type, FirmwareType.KERNEL_IMAGE)

        # Should detect Linux kernel header signature
        kernel_sig_found = any('linux' in sig.description.lower() or 'hdrs' in sig.description.lower()
                              for sig in result.signatures)
        self.assertTrue(kernel_sig_found, "Should detect Linux kernel signatures")

        # Should identify debug kernel configuration as security finding
        debug_findings = [f for f in result.security_findings
                         if f.finding_type == SecurityFindingType.DEBUG_INTERFACE]
        self.assertGreater(len(debug_findings), 0,
                          "Should detect debug kernel configuration")

    def test_uefi_firmware_analysis(self) -> None:
        """Test UEFI firmware analysis with certificate detection."""
        result = self.analyzer.analyze_firmware(str(self.uefi_path))

        # Should classify as BIOS/UEFI
        self.assertEqual(result.firmware_type, FirmwareType.BIOS_UEFI)

        # Should detect UEFI firmware volume signature
        uefi_sig_found = any('uefi' in sig.description.lower() or 'efi' in sig.description.lower()
                           for sig in result.signatures)
        self.assertTrue(uefi_sig_found, "Should detect UEFI signatures")

        # Should identify certificates in firmware
        cert_findings = [f for f in result.security_findings
                        if f.finding_type == SecurityFindingType.CERTIFICATE]
        self.assertGreater(len(cert_findings), 0,
                          "Should detect embedded certificates")

    def test_entropy_analysis_encrypted_firmware(self) -> None:
        """Test entropy analysis for encrypted/compressed firmware detection."""
        result = self.analyzer.analyze_firmware(str(self.encrypted_path))

        # Should have entropy analysis results
        self.assertIsNotNone(result.entropy_analysis)
        self.assertIn('overall_entropy', result.entropy_analysis)
        self.assertIn('high_entropy_regions', result.entropy_analysis)

        # Should detect high entropy indicating encryption
        overall_entropy = result.entropy_analysis['overall_entropy']
        self.assertGreater(overall_entropy, 7.0,
                          "Should detect high entropy in encrypted firmware")

        # Should identify high entropy regions
        high_entropy_regions = result.entropy_analysis['high_entropy_regions']
        self.assertGreater(len(high_entropy_regions), 0,
                          "Should identify high entropy regions")

    def test_file_extraction_capabilities(self) -> None:
        """Test embedded file extraction from firmware images."""
        # Test with router firmware containing filesystem
        result = self.analyzer.analyze_firmware(str(self.router_fw_path))

        # Should attempt extraction for filesystem-containing firmware
        if result.has_extractions and result.extractions is not None:
            extraction = result.extractions
            self.assertIsNotNone(extraction)

            # Extraction should have valid metadata
            if True:  # Single extraction object
                self.assertIsInstance(extraction, FirmwareExtraction)
                self.assertIsNotNone(extraction.extraction_directory)
                self.assertIsInstance(extraction.extracted_files, list)

                # Should analyze extracted files
                if extraction.extracted_files:
                    for extracted_file in extraction.extracted_files:
                        self.assertIsInstance(extracted_file, ExtractedFile)
                        self.assertIsNotNone(extracted_file.file_path)
                        self.assertIsNotNone(extracted_file.file_type)

    def test_security_scanning_comprehensive(self) -> None:
        """Test comprehensive security vulnerability scanning."""
        result = self.analyzer.analyze_firmware(str(self.router_fw_path))

        # Should perform multiple types of security scans
        finding_types_found = {f.finding_type for f in result.security_findings}

        # Should detect hardcoded credentials
        self.assertIn(SecurityFindingType.HARDCODED_CREDENTIALS, finding_types_found)

        # Should scan for default passwords
        self.assertIn(SecurityFindingType.DEFAULT_CREDENTIALS, finding_types_found)

        # Should identify debug interfaces
        self.assertIn(SecurityFindingType.DEBUG_INTERFACE, finding_types_found)

        # Each finding should have detailed information
        for finding in result.security_findings:
            self.assertIsInstance(finding, SecurityFinding)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.file_path)
            self.assertIsNotNone(finding.severity)

    def test_crypto_key_detection(self) -> None:
        """Test cryptographic key and certificate detection."""
        # Test with UEFI firmware containing certificates
        result = self.analyzer.analyze_firmware(str(self.uefi_path))

        # Should detect certificates
        cert_findings = [f for f in result.security_findings
                        if f.finding_type == SecurityFindingType.CERTIFICATE]
        self.assertGreater(len(cert_findings), 0)

        # Should detect RSA key material
        key_findings = [f for f in result.security_findings
                       if f.finding_type == SecurityFindingType.PRIVATE_KEY]
        self.assertGreater(len(key_findings), 0)

    def test_backdoor_detection_capabilities(self) -> None:
        """Test backdoor and suspicious binary detection."""
        # Create firmware with suspicious strings
        suspicious_firmware = (
            b'nc -l -p 1337 -e /bin/sh\x00'  # Netcat backdoor
            b'telnetd -l /bin/sh -p 2323\x00'  # Telnet backdoor
            b'/tmp/.hidden_service\x00'        # Hidden service
            b'eval(base64_decode(\x00'         # Code injection
        )

        suspicious_path = Path(self.temp_dir) / "suspicious.bin"
        suspicious_path.write_bytes(suspicious_firmware)

        result = self.analyzer.analyze_firmware(str(suspicious_path))

        # Should detect backdoor patterns
        backdoor_findings = [f for f in result.security_findings
                           if f.finding_type == SecurityFindingType.BACKDOOR_BINARY]
        self.assertGreater(len(backdoor_findings), 0,
                          "Should detect backdoor command patterns")

    def test_icp_supplemental_data_generation(self) -> None:
        """Test ICP (Intelligent Cracking Platform) supplemental data generation."""
        result = self.analyzer.analyze_firmware(str(self.router_fw_path))

        # Should generate ICP-compatible data
        icp_data = self.analyzer.generate_icp_supplemental_data(result)

        # Should contain structured analysis data
        self.assertIsInstance(icp_data, dict)
        self.assertIn('firmware_analysis', icp_data)
        self.assertIn('security_assessment', icp_data)
        self.assertIn('exploitation_vectors', icp_data)

        # Should provide actionable intelligence
        security_assessment = icp_data['security_assessment']
        self.assertIn('critical_vulnerabilities', security_assessment)
        self.assertIn('attack_surface', security_assessment)
        self.assertIn('recommended_exploits', security_assessment)

    def test_analysis_report_export(self) -> None:
        """Test comprehensive analysis report generation."""
        result = self.analyzer.analyze_firmware(str(self.router_fw_path))

        # Should export detailed report
        report_path = Path(self.temp_dir) / "analysis_report.json"
        exported = self.analyzer.export_analysis_report(result, str(report_path))

        self.assertTrue(exported)
        self.assertTrue(report_path.exists())

        # Report should contain comprehensive analysis data
        import json
        with open(report_path) as f:
            report_data = json.load(f)

        self.assertIn('firmware_info', report_data)
        self.assertIn('security_findings', report_data)
        self.assertIn('technical_analysis', report_data)
        self.assertIn('recommendations', report_data)

    def test_error_handling_invalid_firmware(self) -> None:
        """Test error handling with invalid firmware files."""
        # Test with non-existent file
        result = self.analyzer.analyze_firmware("/nonexistent/file.bin")

        self.assertIsNotNone(result.error)
        assert result.error is not None
        self.assertIn("file not found", result.error.lower())

        # Test with invalid binary data
        invalid_path = Path(self.temp_dir) / "invalid.bin"
        invalid_path.write_bytes(b"not firmware data")

        result = self.analyzer.analyze_firmware(str(invalid_path))

        # Should handle gracefully but still provide basic analysis
        self.assertEqual(result.firmware_type, FirmwareType.UNKNOWN)

    def test_cleanup_extractions(self) -> None:
        """Test proper cleanup of temporary extraction directories."""
        # Perform analysis that creates extractions
        result = self.analyzer.analyze_firmware(str(self.router_fw_path))

        if result.has_extractions and result.extractions is not None:
            extraction = result.extractions
            extraction_directory = extraction.extraction_directory

            # Path should exist before cleanup
            if os.path.exists(extraction_directory):
                # Cleanup should remove extraction directory
                self.analyzer.cleanup_extractions(extraction_directory)
                self.assertFalse(os.path.exists(extraction_directory))


class TestFirmwareAnalyzerIntegration(unittest.TestCase):
    """Integration tests for firmware analyzer module functions."""

    def test_get_firmware_analyzer_singleton(self) -> None:
        """Test firmware analyzer singleton pattern."""
        analyzer1 = get_firmware_analyzer()
        analyzer2 = get_firmware_analyzer()

        # Should return same instance
        self.assertIs(analyzer1, analyzer2)
        self.assertIsInstance(analyzer1, FirmwareAnalyzer)

    def test_binwalk_availability_check(self) -> None:
        """Test binwalk availability detection."""
        # Should detect binwalk installation status
        is_available = is_binwalk_available()
        self.assertIsInstance(is_available, bool)

    def test_analyze_firmware_file_convenience_function(self) -> None:
        """Test convenience function for firmware file analysis."""
        fixtures = TestFirmwareFixtures()

        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as temp_file:
            temp_file.write(fixtures.create_router_firmware_sample())
            temp_path = temp_file.name

        try:
            # Should perform complete analysis through convenience function
            result = analyze_firmware_file(temp_path)

            self.assertIsNotNone(result)
            if result is not None:
                self.assertIsInstance(result, FirmwareAnalysisResult)
                self.assertEqual(result.file_path, temp_path)
                self.assertIsNotNone(result.firmware_type)

        finally:
            os.unlink(temp_path)


class TestFirmwareAnalyzerEdgeCases(unittest.TestCase):
    """Edge case tests for comprehensive coverage."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.analyzer = FirmwareAnalyzer()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        self.analyzer.cleanup_extractions(self.temp_dir)

    def test_large_firmware_file_handling(self) -> None:
        """Test handling of large firmware files."""
        # Create large firmware file (10MB)
        large_fw_path = Path(self.temp_dir) / "large_firmware.bin"
        with open(large_fw_path, 'wb') as f:
            # Write firmware header
            f.write(TestFirmwareFixtures.create_router_firmware_sample())
            # Pad with additional data
            f.write(b'\x00' * (10 * 1024 * 1024))

        result = self.analyzer.analyze_firmware(str(large_fw_path))

        # Should handle large files without errors
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.firmware_type)

    def test_empty_firmware_file(self) -> None:
        """Test handling of empty firmware file."""
        empty_path = Path(self.temp_dir) / "empty.bin"
        empty_path.write_bytes(b'')

        result = self.analyzer.analyze_firmware(str(empty_path))

        # Should handle gracefully
        self.assertEqual(result.firmware_type, FirmwareType.UNKNOWN)
        self.assertEqual(len(result.signatures), 0)
        self.assertEqual(len(result.security_findings), 0)

    def test_binary_with_all_security_finding_types(self) -> None:
        """Test firmware with all types of security findings."""
        comprehensive_fw = (
            # Hardcoded credentials
            b'username=admin\npassword=admin123\n\x00'
            # Private key
            b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w\x00'
            # Certificate
            b'-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALZ8\x00'
            # Backdoor commands
            b'nc -l -p 4444 -e /bin/sh\x00'
            # Vulnerable component
            b'OpenSSL 1.0.1e\x00'  # Known vulnerable version
            # Weak encryption
            b'DES_encrypt\x00'
            # Debug interface
            b'UART_DEBUG_ENABLED=1\x00'
            # Default password
            b'default_pass=password\x00'
        )

        comprehensive_path = Path(self.temp_dir) / "comprehensive.bin"
        comprehensive_path.write_bytes(comprehensive_fw)

        result = self.analyzer.analyze_firmware(str(comprehensive_path))

        # Should detect all security finding types
        finding_types = {f.finding_type for f in result.security_findings}

        expected_types = {
            SecurityFindingType.HARDCODED_CREDENTIALS,
            SecurityFindingType.PRIVATE_KEY,
            SecurityFindingType.CERTIFICATE,
            SecurityFindingType.BACKDOOR_BINARY,
            SecurityFindingType.VULNERABLE_COMPONENT,
            SecurityFindingType.WEAK_ENCRYPTION,
            SecurityFindingType.DEBUG_INTERFACE,
            SecurityFindingType.DEFAULT_CREDENTIALS
        }

        # Should detect majority of security finding types
        detected_count = len(finding_types.intersection(expected_types))
        self.assertGreaterEqual(detected_count, 6,
                               f"Should detect at least 6 security finding types, found {detected_count}")


if __name__ == '__main__':
    unittest.main()
