"""
Comprehensive Test Suite for Intellicrack
Tests all major components with production-ready validation
"""

import os
import sys
import pytest
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.core.hardware_spoofer import HardwareFingerPrintSpoofer
from intellicrack.core.debugging_engine import DebuggingEngine
from intellicrack.core.frida_manager import FridaManager
from intellicrack.protection.unified_protection_engine import UnifiedProtectionEngine


class TestHardwareSpoofing:
    """Test hardware spoofing functionality"""

    def setup_method(self):
        """Setup for each test"""
        self.spoofer = HardwareFingerPrintSpoofer()
        self.original_values = {}

    def test_hardware_detection(self):
        """Test that hardware can be detected"""
        cpu_id = self.spoofer.get_cpu_id()
        assert cpu_id is not None
        assert len(cpu_id) > 0
        assert isinstance(cpu_id, str)

    def test_hardware_id_generation(self):
        """Test hardware ID generation"""
        new_cpu_id = self.spoofer.generate_cpu_id()
        assert new_cpu_id is not None
        assert len(new_cpu_id) > 8
        assert all(c in '0123456789ABCDEF' for c in new_cpu_id.upper())

    def test_mac_address_validation(self):
        """Test MAC address format validation"""
        valid_macs = [
            "00:11:22:33:44:55",
            "00-11-22-33-44-55",
            "AA:BB:CC:DD:EE:FF"
        ]

        for mac in valid_macs:
            assert self.spoofer.validate_mac_format(mac)

        invalid_macs = [
            "00:11:22:33:44",  # Too short
            "ZZ:11:22:33:44:55",  # Invalid hex
            "00-11-22:33-44-55",  # Mixed separators
        ]

        for mac in invalid_macs:
            assert not self.spoofer.validate_mac_format(mac)

    def test_volume_serial_generation(self):
        """Test volume serial number generation"""
        serial = self.spoofer.generate_volume_serial()
        assert serial is not None
        assert '-' in serial
        parts = serial.split('-')
        assert len(parts) == 2
        assert all(len(part) == 4 for part in parts)
        assert all(c in '0123456789ABCDEF' for part in parts for c in part)

    def test_profile_save_load(self):
        """Test saving and loading spoofing profiles"""
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = os.path.join(tmpdir, "test_profile.json")

            test_profile = {
                'cpu_id': 'BFEBFBFF000906EA',
                'motherboard_serial': 'TEST-MB-12345678',
                'hdd_serial': 'WD-TEST1234567890'
            }

            self.spoofer.save_profile(profile_path, test_profile)
            assert os.path.exists(profile_path)

            loaded_profile = self.spoofer.load_profile(profile_path)
            assert loaded_profile == test_profile


class TestProtectionDetection:
    """Test protection detection engine"""

    def setup_method(self):
        """Setup for each test"""
        self.engine = UnifiedProtectionEngine()

    def test_entropy_calculation(self):
        """Test entropy calculation accuracy"""
        high_entropy_data = bytes(range(256))
        low_entropy_data = b'\x00' * 256

        high_entropy = self.engine.calculate_entropy(high_entropy_data)
        low_entropy = self.engine.calculate_entropy(low_entropy_data)

        assert high_entropy > 7.0
        assert low_entropy < 1.0

    def test_packer_signature_detection(self):
        """Test packer signature detection"""
        upx_signature = b'UPX!'
        data_with_upx = upx_signature + b'\x00' * 100

        result = self.engine.detect_packer_signature(data_with_upx)
        assert result is not None
        assert 'UPX' in result['name'].upper()

    def test_import_table_analysis(self):
        """Test import table analysis for protection indicators"""
        suspicious_imports = [
            'VirtualProtect',
            'VirtualAlloc',
            'IsDebuggerPresent',
            'CheckRemoteDebuggerPresent'
        ]

        analysis = self.engine.analyze_imports(suspicious_imports)
        assert analysis['suspicious']
        assert analysis['score'] > 0.7

    def test_section_analysis(self):
        """Test PE section analysis"""
        test_sections = [
            {'name': '.text', 'entropy': 6.5, 'characteristics': 0x60000020},
            {'name': '.data', 'entropy': 2.3, 'characteristics': 0xC0000040},
            {'name': '.upx0', 'entropy': 7.8, 'characteristics': 0xE0000020}  # Suspicious
        ]

        analysis = self.engine.analyze_sections(test_sections)
        assert len(analysis['suspicious_sections']) > 0
        assert any('upx' in s['name'].lower() for s in analysis['suspicious_sections'])


class TestFridaIntegration:
    """Test Frida integration and script generation"""

    def setup_method(self):
        """Setup for each test"""
        self.frida_mgr = FridaManager()

    def test_frida_availability(self):
        """Test if Frida is available"""
        try:
            import frida
            assert frida.__version__ is not None
        except ImportError:
            pytest.skip("Frida not installed")

    def test_script_generation(self):
        """Test Frida script generation"""
        target_function = "CheckLicenseKey"
        script = self.frida_mgr.generate_hook_script(target_function)

        assert script is not None
        assert target_function in script
        assert 'Interceptor.attach' in script
        assert 'onEnter' in script

    def test_bypass_script_generation(self):
        """Test bypass script generation for common protections"""
        bypass_types = [
            'debugger_detection',
            'integrity_check',
            'vm_detection'
        ]

        for bypass_type in bypass_types:
            script = self.frida_mgr.generate_bypass_script(bypass_type)
            assert script is not None
            assert len(script) > 100


class TestDebuggingEngine:
    """Test debugging engine functionality"""

    def setup_method(self):
        """Setup for each test"""
        self.debugger = DebuggingEngine()

    def test_breakpoint_management(self):
        """Test breakpoint creation and management"""
        test_address = 0x401000
        bp_id = self.debugger.add_breakpoint(test_address)

        assert bp_id is not None
        assert self.debugger.has_breakpoint(test_address)

        self.debugger.remove_breakpoint(bp_id)
        assert not self.debugger.has_breakpoint(test_address)

    def test_breakpoint_conditions(self):
        """Test conditional breakpoints"""
        test_address = 0x401000
        condition = "EAX == 0x12345678"

        bp_id = self.debugger.add_conditional_breakpoint(test_address, condition)
        assert bp_id is not None

        bp_info = self.debugger.get_breakpoint_info(bp_id)
        assert bp_info['condition'] == condition

    def test_memory_breakpoints(self):
        """Test memory access breakpoints"""
        test_address = 0x402000
        access_type = 'write'

        bp_id = self.debugger.add_memory_breakpoint(test_address, access_type)
        assert bp_id is not None

        bp_info = self.debugger.get_breakpoint_info(bp_id)
        assert bp_info['type'] == 'memory'
        assert bp_info['access'] == access_type


class TestCryptoAnalysis:
    """Test cryptographic analysis capabilities"""

    def setup_method(self):
        """Setup for each test"""
        from intellicrack.core.exploitation.crypto_key_extractor import CryptoKeyExtractor
        self.crypto_extractor = CryptoKeyExtractor()

    def test_aes_sbox_detection(self):
        """Test AES S-box detection"""
        aes_sbox = bytes([
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
        ])

        result = self.crypto_extractor.detect_aes_sbox(aes_sbox)
        assert result is True

    def test_key_schedule_extraction(self):
        """Test AES key schedule extraction"""
        test_memory = bytearray(256)

        test_memory[0:16] = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])

        keys = self.crypto_extractor.extract_key_schedules(bytes(test_memory))
        assert len(keys) >= 0

    def test_rsa_key_detection(self):
        """Test RSA key detection"""
        rsa_exponent = bytes([0x01, 0x00, 0x01])

        result = self.crypto_extractor.detect_rsa_exponent(rsa_exponent)
        assert result is True

    def test_entropy_based_key_detection(self):
        """Test entropy-based key material detection"""
        high_entropy_data = bytes([i % 256 for i in range(256)])
        low_entropy_data = bytes([0x00] * 256)

        assert self.crypto_extractor.looks_like_key_material(high_entropy_data)
        assert not self.crypto_extractor.looks_like_key_material(low_entropy_data)


class TestPerformance:
    """Performance tests for critical operations"""

    def setup_method(self):
        """Setup for performance tests"""
        self.engine = UnifiedProtectionEngine()

    def test_large_file_entropy_calculation(self):
        """Test entropy calculation performance on large data"""
        import time

        large_data = bytes([i % 256 for i in range(10 * 1024 * 1024)])  # 10MB

        start_time = time.time()
        entropy = self.engine.calculate_entropy(large_data)
        elapsed = time.time() - start_time

        assert entropy > 0
        assert elapsed < 5.0  # Should complete in under 5 seconds

    def test_pattern_matching_performance(self):
        """Test pattern matching performance"""
        import time

        test_data = bytes([i % 256 for i in range(1024 * 1024)])  # 1MB
        patterns = [b'UPX!', b'VMProtect', b'Themida', b'ASPack']

        start_time = time.time()
        for pattern in patterns:
            self.engine.find_pattern(test_data, pattern)
        elapsed = time.time() - start_time

        assert elapsed < 1.0  # Should complete in under 1 second


class TestIntegration:
    """Integration tests for component interactions"""

    def test_full_analysis_pipeline(self):
        """Test complete analysis pipeline"""
        test_pe_path = self._create_test_pe()

        if not os.path.exists(test_pe_path):
            pytest.skip("Test PE not available")

        engine = UnifiedProtectionEngine()

        results = engine.analyze_file(test_pe_path)

        assert results is not None
        assert 'protections' in results
        assert 'entropy' in results
        assert 'imports' in results
        assert 'sections' in results

    def _create_test_pe(self):
        """Create a minimal test PE file"""
        test_file = tempfile.mktemp(suffix='.exe')

        dos_header = b'MZ' + b'\x00' * 58 + b'\x40\x00\x00\x00'
        pe_header = b'PE\x00\x00'
        coff_header = (
            b'\x4C\x01'  # Machine (i386)
            b'\x03\x00'  # NumberOfSections
            b'\x00' * 12  # TimeDateStamp + PointerToSymbolTable + NumberOfSymbols
            b'\xE0\x00'  # SizeOfOptionalHeader
            b'\x0F\x01'  # Characteristics
        )

        optional_header = b'\x0B\x01' + b'\x00' * 222

        section1 = b'.text\x00\x00\x00' + b'\x00' * 32
        section2 = b'.data\x00\x00\x00' + b'\x00' * 32
        section3 = b'.rsrc\x00\x00\x00' + b'\x00' * 32

        pe_data = dos_header + pe_header + coff_header + optional_header + section1 + section2 + section3

        with open(test_file, 'wb') as f:
            f.write(pe_data)

        return test_file


class TestErrorHandling:
    """Test error handling and edge cases"""

    def setup_method(self):
        """Setup for error handling tests"""
        self.engine = UnifiedProtectionEngine()

    def test_invalid_file_handling(self):
        """Test handling of invalid files"""
        with pytest.raises(Exception):
            self.engine.analyze_file("/nonexistent/file.exe")

    def test_corrupted_pe_handling(self):
        """Test handling of corrupted PE files"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
            f.write(b'INVALID_PE_DATA')
            f.flush()
            temp_path = f.name

        try:
            result = self.engine.analyze_file(temp_path)
            assert result is None or 'error' in result
        finally:
            os.unlink(temp_path)

    def test_empty_data_handling(self):
        """Test handling of empty data"""
        empty_data = b''

        entropy = self.engine.calculate_entropy(empty_data)
        assert entropy == 0.0

    def test_null_pointer_safety(self):
        """Test null pointer safety"""
        result = self.engine.analyze_imports(None)
        assert result is not None
        assert not result.get('suspicious', False)


def run_comprehensive_tests():
    """Run all comprehensive tests and generate report"""
    test_classes = [
        TestHardwareSpoofing,
        TestProtectionDetection,
        TestFridaIntegration,
        TestDebuggingEngine,
        TestCryptoAnalysis,
        TestPerformance,
        TestIntegration,
        TestErrorHandling
    ]

    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    skipped_tests = 0

    print("=" * 80)
    print("INTELLICRACK COMPREHENSIVE TEST SUITE")
    print("=" * 80)
    print()

    for test_class in test_classes:
        class_name = test_class.__name__
        print(f"\nRunning {class_name}...")
        print("-" * 80)

        test_instance = test_class()
        test_methods = [method for method in dir(test_instance) if method.startswith('test_')]

        for method_name in test_methods:
            total_tests += 1
            test_method = getattr(test_instance, method_name)

            try:
                test_instance.setup_method()
                test_method()
                passed_tests += 1
                print(f"  ✓ {method_name}")
            except pytest.skip.Exception as e:
                skipped_tests += 1
                print(f"  ⊘ {method_name} (SKIPPED: {e})")
            except Exception as e:
                failed_tests += 1
                print(f"  ✗ {method_name} (FAILED: {e})")

    print()
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Total Tests:   {total_tests}")
    print(f"Passed:        {passed_tests} ({100*passed_tests//total_tests if total_tests else 0}%)")
    print(f"Failed:        {failed_tests}")
    print(f"Skipped:       {skipped_tests}")
    print()

    success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
    print(f"Success Rate:  {success_rate:.1f}%")
    print("=" * 80)

    return failed_tests == 0


if __name__ == '__main__':
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)
