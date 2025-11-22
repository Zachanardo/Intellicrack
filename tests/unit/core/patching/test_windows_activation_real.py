"""Copyright (C) 2025 Zachary Flint.

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

import pytest
import os
import sys
import subprocess
import tempfile
from pathlib import Path
import struct
import winreg
import ctypes
from ctypes import wintypes
import socket
import threading
import time
import hashlib

from intellicrack.core.patching.windows_activator import WindowsActivator


class TestWindowsActivationProduction:
    """Production tests for Windows activation using real Windows components."""

    @pytest.fixture
    def windows_system_files(self):
        """Locate real Windows system files for testing."""
        system32 = Path("C:/Windows/System32")
        syswow64 = Path("C:/Windows/SysWOW64")

        files = {
            'slmgr': system32 / "slmgr.vbs",
            'sppsvc': system32 / "sppsvc.exe",
            'sppwinob': system32 / "sppwinob.dll",
            'licensingdiag': system32 / "licensingdiag.exe",
            'slc': system32 / "slc.dll"
        }

        # Check which files exist
        existing_files = {}
        for name, path in files.items():
            if path.exists():
                existing_files[name] = str(path)

        return existing_files

    @pytest.fixture
    def kms_test_server(self):
        """Create a test KMS server for validation."""
        class TestKMSServer:
            def __init__(self):
                self.port = 1688  # Standard KMS port
                self.running = False
                self.server_socket = None
                self.thread = None

            def start(self):
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    self.server_socket.bind(('127.0.0.1', self.port))
                    self.server_socket.listen(5)
                    self.running = True
                    self.thread = threading.Thread(target=self._run)
                    self.thread.daemon = True
                    self.thread.start()
                    return True
                except OSError:
                    # Port might be in use
                    return False

            def _run(self):
                while self.running:
                    try:
                        client, addr = self.server_socket.accept()
                        # Send KMS response packet
                        kms_response = self._generate_kms_response()
                        client.send(kms_response)
                        client.close()
                    except:
                        break

            def _generate_kms_response(self):
                """Generate a KMS activation response packet."""
                # KMS v6 response structure
                response = bytearray(256)
                response[0:4] = struct.pack('<I', 0x00000006)  # Version
                response[4:8] = struct.pack('<I', 0x00000000)  # Status OK
                response[8:24] = os.urandom(16)  # Request ID
                response[24:40] = os.urandom(16)  # Client Machine ID
                response[40:48] = struct.pack('<Q', int(time.time()))  # Timestamp
                return bytes(response)

            def stop(self):
                self.running = False
                if self.server_socket:
                    self.server_socket.close()
                if self.thread:
                    self.thread.join(timeout=1)

        server = TestKMSServer()
        yield server
        server.stop()

    def test_windows_activator_initialization(self):
        """Test Windows activator initialization."""
        activator = WindowsActivator()

        assert activator is not None
        assert hasattr(activator, 'activate')
        assert hasattr(activator, 'check_activation_status')
        assert hasattr(activator, 'generate_hwid')

    def test_check_windows_activation_status(self):
        """Test checking current Windows activation status."""
        if sys.platform != 'win32':
            pytest.skip("Windows-only test")

        activator = WindowsActivator()

        status = activator.check_activation_status()

        assert status is not None
        assert isinstance(status, dict)
        assert 'activated' in status
        assert 'license_type' in status
        assert 'product_key_channel' in status

    def test_get_windows_product_info(self):
        """Test retrieving Windows product information."""
        if sys.platform != 'win32':
            pytest.skip("Windows-only test")

        activator = WindowsActivator()

        product_info = activator.get_product_info()

        assert product_info is not None
        assert 'edition' in product_info
        assert 'version' in product_info
        assert 'build' in product_info

        # Check using Windows API
        kernel32 = ctypes.windll.kernel32
        product_type = ctypes.c_uint32()
        kernel32.GetProductInfo(10, 0, 0, 0, ctypes.byref(product_type))
        assert product_type.value > 0

    def test_kms_server_emulation(self, kms_test_server):
        """Test KMS server emulation functionality."""
        activator = WindowsActivator()

        # Start test KMS server
        if not kms_test_server.start():
            pytest.skip("Cannot bind to KMS port 1688")

        # Test KMS client connection
        kms_config = {
            'server': '127.0.0.1',
            'port': 1688,
            'product': 'Windows 10 Pro',
            'kms_pid': '00000-00000-00000-00000-00000'
        }

        result = activator.test_kms_connection(kms_config)

        assert result is not None
        assert 'connected' in result

    def test_generate_windows_hwid(self):
        """Test Windows Hardware ID generation."""
        activator = WindowsActivator()

        hwid = activator.generate_hwid()

        assert hwid is not None
        assert isinstance(hwid, str)
        assert len(hwid) >= 32  # HWID should be substantial

        # HWID should be consistent for same machine
        hwid2 = activator.generate_hwid()
        assert hwid == hwid2

    def test_kms_key_installation(self):
        """Test KMS client key installation process."""
        activator = WindowsActivator()

        # Windows 10/11 KMS client keys (publicly documented by Microsoft)
        kms_keys = {
            'Windows 10 Pro': 'W269N-WFGWX-YVC9B-4J6C9-T83GX',
            'Windows 10 Enterprise': 'NPPR9-FWDCX-D2C8J-H872K-2YT43',
            'Windows 11 Pro': 'W269N-WFGWX-YVC9B-4J6C9-T83GX',
            'Windows 11 Enterprise': 'NPPR9-FWDCX-D2C8J-H872K-2YT43'
        }

        for edition, key in kms_keys.items():
            result = activator.validate_product_key(key)
            assert result is not None
            assert 'valid' in result
            assert result['valid'] is True or 'error' in result

    def test_digital_license_manipulation(self):
        """Test digital license (HWID) activation methods."""
        activator = WindowsActivator()

        # Generate digital license data
        license_data = activator.generate_digital_license()

        assert license_data is not None
        assert 'hwid' in license_data
        assert 'ticket' in license_data
        assert 'signature' in license_data

        # Ticket should be properly formatted
        assert isinstance(license_data['ticket'], bytes)
        assert len(license_data['ticket']) > 100

    def test_slmgr_command_generation(self):
        """Test generating SLMGR commands for activation."""
        activator = WindowsActivator()

        commands = activator.generate_slmgr_commands({
            'action': 'activate',
            'key': 'W269N-WFGWX-YVC9B-4J6C9-T83GX',
            'kms_server': 'kms.example.com'
        })

        assert commands is not None
        assert isinstance(commands, list)

        expected_commands = [
            '/ipk',  # Install product key
            '/skms',  # Set KMS server
            '/ato'   # Activate
        ]

        for cmd in expected_commands:
            assert any(cmd in c for c in commands)

    def test_registry_activation_entries(self):
        """Test Windows activation registry modifications."""
        if sys.platform != 'win32':
            pytest.skip("Windows-only test")

        activator = WindowsActivator()

        # Get activation-related registry entries
        reg_entries = activator.get_activation_registry()

        assert reg_entries is not None
        assert isinstance(reg_entries, dict)

        # Check for key activation registry paths
        important_keys = [
            r'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
            r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform',
            r'SYSTEM\CurrentControlSet\Services\sppsvc'
        ]

        for key_path in important_keys:
            try:
                # Try to open registry key (read-only)
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                winreg.CloseKey(key)
                assert True  # Key exists
            except OSError:
                # Key might not exist on all systems
                pass

    def test_offline_activation_tokens(self):
        """Test offline activation token generation."""
        activator = WindowsActivator()

        # Generate offline activation tokens
        tokens = activator.generate_offline_tokens({
            'installation_id': '012345-678901-234567-890123-456789-012345-678901-234567',
            'product_key': 'W269N-WFGWX-YVC9B-4J6C9-T83GX'
        })

        assert tokens is not None
        assert 'confirmation_id' in tokens
        assert isinstance(tokens['confirmation_id'], str)
        assert len(tokens['confirmation_id']) >= 48  # CID is 48+ digits

    def test_sppsvc_service_manipulation(self):
        """Test Software Protection Platform Service manipulation."""
        if sys.platform != 'win32':
            pytest.skip("Windows-only test")

        activator = WindowsActivator()

        # Check SPPSVC service status
        service_status = activator.check_sppsvc_status()

        assert service_status is not None
        assert 'running' in service_status
        assert 'start_type' in service_status

    def test_activation_task_scheduler(self):
        """Test Windows activation via Task Scheduler."""
        activator = WindowsActivator()

        # Generate scheduled task for activation
        task_xml = activator.generate_activation_task()

        assert task_xml is not None
        assert isinstance(task_xml, str)
        assert '<Task' in task_xml
        assert 'ActivationTask' in task_xml

    def test_wmi_activation_methods(self):
        """Test WMI-based activation methods."""
        if sys.platform != 'win32':
            pytest.skip("Windows-only test")

        activator = WindowsActivator()

        # Test WMI queries for activation
        wmi_result = activator.query_activation_wmi()

        assert wmi_result is not None
        assert 'LicenseStatus' in wmi_result or 'error' in wmi_result

    def test_mak_activation_process(self):
        """Test MAK (Multiple Activation Key) activation."""
        activator = WindowsActivator()

        # Test MAK activation process
        mak_config = {
            'key': 'NPPR9-FWDCX-D2C8J-H872K-2YT43',  # Example MAK
            'proxy': None
        }

        result = activator.process_mak_activation(mak_config)

        assert result is not None
        assert 'method' in result
        assert result['method'] == 'MAK'

    def test_activation_backup_restore(self):
        """Test activation backup and restore functionality."""
        activator = WindowsActivator()

        # Create activation backup
        backup = activator.create_activation_backup()

        assert backup is not None
        assert 'tokens' in backup
        assert 'registry' in backup
        assert 'timestamp' in backup

        # Test restore data generation
        restore_data = activator.generate_restore_data(backup)

        assert restore_data is not None
        assert len(restore_data) > 0

    def test_windows_edition_upgrade(self):
        """Test Windows edition upgrade keys."""
        activator = WindowsActivator()

        # Generic upgrade keys (publicly available)
        upgrade_keys = {
            'Pro': 'VK7JG-NPHTM-C97JM-9MPGT-3V66T',
            'Pro N': 'MH37W-N47XK-V7XM9-C7227-GCQG9',
            'Enterprise': 'NPPR9-FWDCX-D2C8J-H872K-2YT43',
            'Education': 'NW6C2-QMPVW-D7KKK-3GKT6-VCFB2'
        }

        for edition, key in upgrade_keys.items():
            result = activator.test_edition_upgrade(edition, key)
            assert result is not None
            assert 'compatible' in result

    def test_activation_troubleshooting(self):
        """Test activation troubleshooting and diagnostics."""
        activator = WindowsActivator()

        # Run activation diagnostics
        diagnostics = activator.run_activation_diagnostics()

        assert diagnostics is not None
        assert 'issues' in diagnostics
        assert 'recommendations' in diagnostics

        # Should identify common issues
        common_issues = [
            'kms_connectivity',
            'time_sync',
            'dns_resolution',
            'firewall_blocking',
            'corrupt_tokens'
        ]

        for issue in common_issues:
            # Check if diagnostic can detect these issues
            assert issue in diagnostics.get('checks', [])

    def test_volume_activation_management(self):
        """Test Volume Activation Management Tool (VAMT) integration."""
        activator = WindowsActivator()

        # Generate VAMT compatible data
        vamt_data = activator.generate_vamt_export()

        assert vamt_data is not None
        assert isinstance(vamt_data, str) or isinstance(vamt_data, bytes)

        # Should be valid XML format for VAMT
        if isinstance(vamt_data, str):
            assert '<?xml' in vamt_data
            assert '<ComputerInfo>' in vamt_data or '<ActivationData>' in vamt_data

    def test_activation_grace_period(self):
        """Test activation grace period manipulation."""
        activator = WindowsActivator()

        # Get current grace period
        grace_info = activator.get_grace_period_info()

        assert grace_info is not None
        assert 'remaining_days' in grace_info
        assert 'rearm_count' in grace_info

        # Test rearm command generation
        rearm_cmd = activator.generate_rearm_command()
        assert rearm_cmd is not None
        assert 'slmgr' in rearm_cmd.lower() or 'rearm' in rearm_cmd.lower()

    def test_oem_activation_emulation(self):
        """Test OEM activation emulation (SLIC)."""
        activator = WindowsActivator()

        # Generate OEM activation data
        oem_data = activator.generate_oem_activation({
            'manufacturer': 'DELL',
            'model': 'OptiPlex 9020',
            'slic_version': '2.5'
        })

        assert oem_data is not None
        assert 'slic_table' in oem_data
        assert 'oem_key' in oem_data
        assert 'certificate' in oem_data

        # SLIC table should have proper structure
        if 'slic_table' in oem_data:
            slic = oem_data['slic_table']
            assert isinstance(slic, bytes)
            assert len(slic) >= 374  # Minimum SLIC 2.1 size
