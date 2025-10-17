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
import struct
import hashlib
import hmac
import time
from pathlib import Path
import ctypes
import usb.core
import usb.util

from intellicrack.core.protection_bypass.dongle_emulator import DongleEmulator


class TestDongleEmulationProduction:
    """Production tests for hardware dongle emulation against real protection systems."""

    @pytest.fixture
    def usb_devices(self):
        """Enumerate real USB devices for testing."""
        try:
            devices = usb.core.find(find_all=True)
            device_list = []
            for device in devices:
                device_list.append({
                    'vendor_id': device.idVendor,
                    'product_id': device.idProduct,
                    'manufacturer': self._get_string(device, device.iManufacturer),
                    'product': self._get_string(device, device.iProduct)
                })
            return device_list
        except Exception:
            return []

    def _get_string(self, device, index):
        """Get USB string descriptor."""
        try:
            if index:
                return usb.util.get_string(device, index)
        except:
            pass
        return None

    def test_dongle_emulator_initialization(self):
        """Test dongle emulator initialization."""
        emulator = DongleEmulator()

        assert emulator is not None
        assert hasattr(emulator, 'emulate_hasp')
        assert hasattr(emulator, 'emulate_sentinel')
        assert hasattr(emulator, 'emulate_codemeter')

    def test_hasp_dongle_emulation(self):
        """Test HASP/SafeNet dongle emulation."""
        emulator = DongleEmulator()

        # HASP dongle configuration
        hasp_config = {
            'dongle_id': 0x12345678,
            'vendor_id': 0x0529,  # Aladdin/SafeNet
            'product_id': 0x0001,
            'memory_size': 112,  # HASP HL Basic has 112 bytes
            'algorithm': 'AES'
        }

        # Generate HASP emulation
        hasp_emulation = emulator.emulate_hasp(hasp_config)

        assert hasp_emulation is not None
        assert 'driver_hooks' in hasp_emulation
        assert 'api_responses' in hasp_emulation
        assert 'memory_map' in hasp_emulation

        # Verify HASP API responses
        api_functions = [
            'hasp_login',
            'hasp_logout',
            'hasp_encrypt',
            'hasp_decrypt',
            'hasp_read',
            'hasp_write',
            'hasp_get_info'
        ]

        for func in api_functions:
            assert func in hasp_emulation['api_responses']

    def test_sentinel_superpro_emulation(self):
        """Test Sentinel SuperPro dongle emulation."""
        emulator = DongleEmulator()

        # Sentinel configuration
        sentinel_config = {
            'dongle_id': 'ABCD-1234-5678-90EF',
            'developer_id': 0x1234,
            'algorithm_descriptor': 0x0001,
            'memory_cells': 64,
            'query_responses': {}
        }

        # Generate Sentinel emulation
        sentinel_emulation = emulator.emulate_sentinel(sentinel_config)

        assert sentinel_emulation is not None
        assert 'packet_responses' in sentinel_emulation
        assert 'algorithm_implementation' in sentinel_emulation
        assert 'cell_memory' in sentinel_emulation

        # Check memory cells
        assert len(sentinel_emulation['cell_memory']) == 64

    def test_codemeter_emulation(self):
        """Test CodeMeter dongle emulation."""
        emulator = DongleEmulator()

        # CodeMeter configuration
        codemeter_config = {
            'firm_code': 0x12345678,
            'product_code': 0x100001,
            'feature_map': 0xFFFFFFFF,
            'license_quantity': 1,
            'expiration_date': None  # Perpetual
        }

        # Generate CodeMeter emulation
        cm_emulation = emulator.emulate_codemeter(codemeter_config)

        assert cm_emulation is not None
        assert 'cmstick_responses' in cm_emulation
        assert 'license_entries' in cm_emulation
        assert 'crypto_context' in cm_emulation

    def test_dongle_memory_emulation(self):
        """Test dongle memory read/write emulation."""
        emulator = DongleEmulator()

        # Create memory map
        memory_size = 256
        memory = emulator.create_dongle_memory(memory_size)

        assert memory is not None
        assert len(memory) == memory_size

        # Test write operation
        offset = 0x10
        data = b'TEST_DATA_123'
        result = emulator.write_dongle_memory(memory, offset, data)

        assert result is True
        assert memory[offset:offset+len(data)] == data

        # Test read operation
        read_data = emulator.read_dongle_memory(memory, offset, len(data))
        assert read_data == data

    def test_dongle_crypto_operations(self):
        """Test dongle cryptographic operations."""
        emulator = DongleEmulator()

        # Test data
        plaintext = b'This is test data for dongle crypto'
        key = b'0123456789ABCDEF'  # 128-bit key

        # Test HASP-style encryption
        hasp_encrypted = emulator.hasp_encrypt(plaintext, key)
        assert hasp_encrypted is not None
        assert hasp_encrypted != plaintext

        # Test decryption
        hasp_decrypted = emulator.hasp_decrypt(hasp_encrypted, key)
        assert hasp_decrypted == plaintext

        # Test Sentinel-style algorithm
        sentinel_result = emulator.sentinel_algorithm(
            query=0x12345678,
            algorithm_id=1,
            seed=0xABCDEF
        )
        assert sentinel_result is not None
        assert isinstance(sentinel_result, int)

    def test_usb_dongle_enumeration(self, usb_devices):
        """Test USB dongle detection and enumeration."""
        emulator = DongleEmulator()

        # Known dongle vendor IDs
        dongle_vendors = {
            0x0529: 'Aladdin/SafeNet',
            0x04B9: 'Rainbow Technologies',
            0x096E: 'Feitian',
            0x1BC0: 'Sentinel',
            0x064F: 'WIBU-SYSTEMS'
        }

        # Check for real dongles
        detected_dongles = emulator.detect_dongles()

        assert detected_dongles is not None
        assert isinstance(detected_dongles, list)

        # If real dongles present, verify detection
        for device in usb_devices:
            if device['vendor_id'] in dongle_vendors:
                # Should be detected as dongle
                assert any(d['vendor_id'] == device['vendor_id']
                          for d in detected_dongles)

    def test_parallel_port_dongle_emulation(self):
        """Test parallel port (LPT) dongle emulation."""
        emulator = DongleEmulator()

        # Parallel port dongle config
        lpt_config = {
            'port': 'LPT1',
            'base_address': 0x378,
            'dongle_type': 'sentinel_superpro',
            'response_delays': True
        }

        # Generate LPT emulation
        lpt_emulation = emulator.emulate_parallel_dongle(lpt_config)

        assert lpt_emulation is not None
        assert 'port_hooks' in lpt_emulation
        assert 'io_responses' in lpt_emulation

        # Test I/O operations
        test_value = 0xAA
        response = emulator.parallel_port_io(
            port=0x378,
            value=test_value,
            operation='write'
        )
        assert response is not None

    def test_network_dongle_emulation(self):
        """Test network-based license dongle emulation."""
        emulator = DongleEmulator()

        # Network dongle config (FlexLM style)
        network_config = {
            'server': 'localhost',
            'port': 27000,
            'vendor_daemon': 'vendor_daemon',
            'features': ['feature1', 'feature2'],
            'float_licenses': 10
        }

        # Generate network license emulation
        network_emulation = emulator.emulate_network_license(network_config)

        assert network_emulation is not None
        assert 'license_server' in network_emulation
        assert 'checkout_responses' in network_emulation
        assert 'heartbeat_handler' in network_emulation

    def test_dongle_driver_hooks(self):
        """Test dongle driver hooking for emulation."""
        emulator = DongleEmulator()

        # Generate driver hooks
        drivers = [
            'hasp_windows_x64.dll',
            'haspdll.dll',
            'SentinelKeys.dll',
            'spromeps.dll',
            'CmDongle.dll'
        ]

        for driver in drivers:
            hooks = emulator.generate_driver_hooks(driver)

            assert hooks is not None
            assert 'functions' in hooks
            assert len(hooks['functions']) > 0

            # Each hook should have address and detour
            for hook in hooks['functions']:
                assert 'name' in hook
                assert 'original' in hook or 'address' in hook
                assert 'detour' in hook

    def test_dongle_time_based_features(self):
        """Test time-based licensing features."""
        emulator = DongleEmulator()

        # Time-limited license
        time_config = {
            'start_date': time.time() - 86400,  # Yesterday
            'expiry_date': time.time() + 86400,  # Tomorrow
            'grace_period': 7,  # days
            'clock_tamper_detection': True
        }

        # Check license validity
        is_valid = emulator.check_time_license(time_config)
        assert is_valid is True

        # Test expired license
        expired_config = {
            'start_date': time.time() - 172800,
            'expiry_date': time.time() - 86400,  # Yesterday
            'grace_period': 0
        }

        is_expired = emulator.check_time_license(expired_config)
        assert is_expired is False

    def test_dongle_feature_bits(self):
        """Test dongle feature bit emulation."""
        emulator = DongleEmulator()

        # Feature configuration
        features = {
            'basic': 0x0001,
            'pro': 0x0002,
            'enterprise': 0x0004,
            'unlimited': 0x0008,
            'export_enabled': 0x0010,
            'debug_mode': 0x0020
        }

        # Set features
        feature_mask = features['pro'] | features['export_enabled']
        emulator.set_feature_bits(feature_mask)

        # Check features
        assert emulator.has_feature(features['pro']) is True
        assert emulator.has_feature(features['enterprise']) is False
        assert emulator.has_feature(features['export_enabled']) is True

    def test_dongle_anti_debugging(self):
        """Test anti-debugging bypass in dongle emulation."""
        emulator = DongleEmulator()

        # Generate anti-debug bypasses
        bypasses = emulator.generate_antidbg_bypasses()

        assert bypasses is not None
        assert 'timing_checks' in bypasses
        assert 'debugger_detection' in bypasses
        assert 'integrity_checks' in bypasses

    def test_dongle_communication_protocol(self):
        """Test dongle communication protocol emulation."""
        emulator = DongleEmulator()

        # Test HASP protocol packet
        hasp_packet = emulator.create_hasp_packet(
            command=0x01,  # Login
            dongle_id=0x12345678,
            data=b'LOGIN_DATA'
        )

        assert hasp_packet is not None
        assert len(hasp_packet) >= 16  # Minimum packet size

        # Parse response
        response = emulator.parse_hasp_response(hasp_packet)
        assert response is not None
        assert 'status' in response

    def test_virtual_usb_device_creation(self):
        """Test virtual USB device creation for dongle emulation."""
        emulator = DongleEmulator()

        # Virtual USB device descriptor
        device_desc = emulator.create_virtual_usb_device({
            'vendor_id': 0x0529,
            'product_id': 0x0001,
            'manufacturer': 'SafeNet Inc.',
            'product': 'HASP HL 3.25',
            'serial': '12-34567890'
        })

        assert device_desc is not None
        assert 'descriptor' in device_desc
        assert 'endpoints' in device_desc
        assert 'interfaces' in device_desc

    def test_dongle_clone_detection(self):
        """Test dongle clone detection evasion."""
        emulator = DongleEmulator()

        # Generate unique identifiers
        clone_evasion = emulator.generate_clone_evasion({
            'randomize_timing': True,
            'unique_serial': True,
            'hardware_fingerprint': True
        })

        assert clone_evasion is not None
        assert 'serial' in clone_evasion
        assert 'timing_variance' in clone_evasion
        assert 'fingerprint' in clone_evasion

        # Serials should be unique
        serial1 = clone_evasion['serial']
        clone_evasion2 = emulator.generate_clone_evasion({
            'unique_serial': True
        })
        serial2 = clone_evasion2['serial']
        assert serial1 != serial2
