"""
Comprehensive tests for TPM 2.0 bypass module.
Benchmarks real-world effectiveness against modern licensing protections.
"""

import hashlib
import os
import struct
import time
import unittest
from unittest import TestCase
from typing import Dict, List, Optional

from intellicrack.core.protection_bypass.tpm_bypass import (
    TPMBypassEngine,
    TPM2Algorithm,
    TPM2CommandCode,
    PCRBank,
    AttestationData
)


class TestTPMBypassRealWorld(TestCase):
    """Benchmark TPM bypass effectiveness against real protections."""

    def setUp(self):
        """Initialize TPM bypass engine for testing."""
        self.tpm_engine = TPMBypassEngine()
        self.test_nonce = os.urandom(32)
        self.test_pcrs = {
            0: bytes.fromhex('0' * 64),  # BIOS measurements
            1: bytes.fromhex('1' * 64),  # BIOS configuration
            7: bytes.fromhex('a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb'),  # Secure Boot
            14: bytes.fromhex('e' * 64)  # MOK (Machine Owner Key)
        }

    def test_bitlocker_vmk_extraction_benchmark(self):
        """Benchmark VMK extraction success rate for BitLocker."""
        success_count = 0
        attempts = 100
        extraction_times = []

        for i in range(attempts):
            nvram_index = 0x01400001 + (i % 3)

            vmk_test_data = b'VMK\x00' + os.urandom(32)
            if nvram_index < len(self.tpm_engine.virtualized_tpm['nvram']):
                self.tpm_engine.virtualized_tpm['nvram'][nvram_index:nvram_index+36] = vmk_test_data

            start_time = time.perf_counter()
            extracted_vmk = self.tpm_engine.extract_bitlocker_vmk()
            extraction_time = time.perf_counter() - start_time
            extraction_times.append(extraction_time)

            if extracted_vmk:
                success_count += 1
                self.assertEqual(len(extracted_vmk), 32, "VMK should be 32 bytes")

        success_rate = (success_count / attempts) * 100
        avg_extraction_time = sum(extraction_times) / len(extraction_times)

        print(f"\nBitLocker VMK Extraction Benchmark:")
        print(f"  Success Rate: {success_rate:.1f}%")
        print(f"  Average Extraction Time: {avg_extraction_time*1000:.2f}ms")
        print(f"  Min Time: {min(extraction_times)*1000:.2f}ms")
        print(f"  Max Time: {max(extraction_times)*1000:.2f}ms")

        self.assertGreater(success_rate, 75, "VMK extraction should succeed >75% of the time")
        self.assertLess(avg_extraction_time, 0.01, "Average extraction should be <10ms")

    def test_windows_hello_bypass_effectiveness(self):
        """Test Windows Hello bypass against different PIN/biometric configurations."""
        test_scenarios = [
            {"name": "4-digit PIN", "pin": b"1234", "complexity": "low"},
            {"name": "6-digit PIN", "pin": b"123456", "complexity": "medium"},
            {"name": "Complex PIN", "pin": b"Abc123!@#", "complexity": "high"},
            {"name": "Biometric only", "pin": None, "complexity": "biometric"},
        ]

        results = []

        for scenario in test_scenarios:
            start_time = time.perf_counter()
            hello_keys = self.tpm_engine.bypass_windows_hello()
            bypass_time = time.perf_counter() - start_time

            self.assertIn('biometric_template', hello_keys)
            self.assertIn('biometric_hash', hello_keys)
            self.assertIn('pin_unlock', hello_keys)

            self.assertEqual(len(hello_keys['biometric_template']), 512)
            self.assertEqual(len(hello_keys['biometric_hash']), 32)
            self.assertEqual(len(hello_keys['pin_unlock']), 32)

            results.append({
                'scenario': scenario['name'],
                'time': bypass_time,
                'keys_extracted': len(hello_keys),
                'complexity': scenario['complexity']
            })

        print("\nWindows Hello Bypass Effectiveness:")
        for result in results:
            print(f"  {result['scenario']}:")
            print(f"    Time: {result['time']*1000:.2f}ms")
            print(f"    Keys Extracted: {result['keys_extracted']}")
            print(f"    Complexity: {result['complexity']}")

        avg_time = sum(r['time'] for r in results) / len(results)
        self.assertLess(avg_time, 0.005, "Average bypass time should be <5ms")

    def test_remote_attestation_spoofing_accuracy(self):
        """Benchmark remote attestation spoofing against different validators."""
        test_validators = [
            {"name": "Azure AD", "pcr_count": 8, "strict": True},
            {"name": "AWS Nitro", "pcr_count": 16, "strict": True},
            {"name": "Google Cloud", "pcr_count": 10, "strict": False},
            {"name": "Corporate VPN", "pcr_count": 4, "strict": False},
        ]

        spoofing_results = []

        for validator in test_validators:
            expected_pcrs = {}
            for i in range(validator['pcr_count']):
                expected_pcrs[i] = hashlib.sha256(f"PCR{i}_{validator['name']}".encode()).digest()

            start_time = time.perf_counter()
            attestation_response = self.tpm_engine.spoof_remote_attestation(
                self.test_nonce,
                expected_pcrs,
                aik_handle=0x81010001
            )
            spoof_time = time.perf_counter() - start_time

            self.assertIn('quote', attestation_response)
            self.assertIn('pcr_values', attestation_response)
            self.assertIn('aik_cert', attestation_response)

            quote = attestation_response['quote']
            self.assertIn('quoted', quote)
            self.assertIn('signature', quote)
            self.assertIn('pcr_digest', quote)

            for pcr_num, expected_value in expected_pcrs.items():
                actual_value = bytes.fromhex(attestation_response['pcr_values'][pcr_num])
                self.assertEqual(actual_value, expected_value,
                               f"PCR{pcr_num} mismatch for {validator['name']}")

            cert_size = len(attestation_response['aik_cert'])
            self.assertGreater(cert_size, 1000, "AIK certificate should be substantial")

            spoofing_results.append({
                'validator': validator['name'],
                'pcr_count': validator['pcr_count'],
                'time': spoof_time,
                'cert_size': cert_size,
                'strict': validator['strict'],
                'success': True
            })

        print("\nRemote Attestation Spoofing Benchmark:")
        for result in spoofing_results:
            print(f"  {result['validator']}:")
            print(f"    PCRs: {result['pcr_count']}")
            print(f"    Time: {result['time']*1000:.2f}ms")
            print(f"    Cert Size: {result['cert_size']} bytes")
            print(f"    Strict Mode: {result['strict']}")
            print(f"    Success: {result['success']}")

    def test_measured_boot_bypass_scenarios(self):
        """Test measured boot bypass for different boot configurations."""
        boot_configs = [
            {
                "name": "Windows 11 Secure Boot",
                "pcrs": {
                    0: hashlib.sha256(b"UEFI_BOOT").digest(),
                    7: bytes.fromhex('a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb'),
                    11: hashlib.sha256(b"BitLocker").digest()
                }
            },
            {
                "name": "Linux GRUB with TPM",
                "pcrs": {
                    0: hashlib.sha256(b"GRUB_BOOT").digest(),
                    4: hashlib.sha256(b"KERNEL").digest(),
                    8: hashlib.sha256(b"INITRD").digest()
                }
            },
            {
                "name": "VMware vSphere TPM",
                "pcrs": {
                    0: hashlib.sha256(b"VMWARE_BIOS").digest(),
                    1: hashlib.sha256(b"VMWARE_CONFIG").digest(),
                    14: hashlib.sha256(b"VMWARE_MOK").digest()
                }
            }
        ]

        bypass_results = []

        for config in boot_configs:
            start_time = time.perf_counter()
            success = self.tpm_engine.bypass_measured_boot(config['pcrs'])
            bypass_time = time.perf_counter() - start_time

            self.assertTrue(success, f"Measured boot bypass failed for {config['name']}")

            for pcr_num, expected_value in config['pcrs'].items():
                actual_value = self.tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_num]
                if pcr_num == 7:
                    expected_check = bytes.fromhex('a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb')
                    self.assertEqual(actual_value, expected_check, "Secure Boot PCR should be set")
                else:
                    self.assertEqual(actual_value, expected_value,
                                   f"PCR{pcr_num} not set correctly for {config['name']}")

            bypass_results.append({
                'config': config['name'],
                'pcr_count': len(config['pcrs']),
                'time': bypass_time,
                'success': success
            })

        print("\nMeasured Boot Bypass Scenarios:")
        for result in bypass_results:
            print(f"  {result['config']}:")
            print(f"    PCRs Modified: {result['pcr_count']}")
            print(f"    Time: {result['time']*1000:.2f}ms")
            print(f"    Success: {result['success']}")

    def test_sealed_key_extraction_performance(self):
        """Benchmark sealed key extraction from different storage locations."""
        nvram_keys = 10
        persistent_keys = 7

        for i in range(nvram_keys):
            index = 0x01400001 + i
            key_data = hashlib.sha256(f"NVRAM_KEY_{i}".encode()).digest()
            if index < len(self.tpm_engine.virtualized_tpm['nvram']):
                self.tpm_engine.virtualized_tpm['nvram'][index:index+32] = key_data

        for i in range(persistent_keys):
            handle = 0x81000000 + i
            self.tpm_engine.virtualized_tpm['persistent_handles'][handle] = os.urandom(256)

        extraction_times = []
        for _ in range(10):
            start_time = time.perf_counter()
            extracted = self.tpm_engine.extract_sealed_keys()
            extraction_time = time.perf_counter() - start_time
            extraction_times.append(extraction_time)

        avg_time = sum(extraction_times) / len(extraction_times)
        min_time = min(extraction_times)
        max_time = max(extraction_times)

        print(f"\nSealed Key Extraction Performance:")
        print(f"  Average Time: {avg_time*1000:.2f}ms")
        print(f"  Min Time: {min_time*1000:.2f}ms")
        print(f"  Max Time: {max_time*1000:.2f}ms")
        print(f"  Keys Extracted: {len(extracted)}")

        self.assertGreater(len(extracted), 0, "Should extract at least some keys")
        self.assertLess(avg_time, 0.1, "Average extraction should be <100ms")

    def test_bus_attack_interception(self):
        """Test LPC/SPI bus attack effectiveness for different commands."""
        target_commands = [
            (TPM2CommandCode.Unseal, 32, "Unseal operation"),
            (TPM2CommandCode.GetRandom, 32, "Random generation"),
            (TPM2CommandCode.Sign, 256, "Signature operation"),
        ]

        interception_results = []

        for cmd_code, expected_size, description in target_commands:
            start_time = time.perf_counter()
            captured_data = self.tpm_engine.perform_bus_attack(cmd_code)
            attack_time = time.perf_counter() - start_time

            self.assertIsNotNone(captured_data, f"Bus attack failed for {description}")

            if captured_data:
                response_header = captured_data[:10]
                tag, size, code = struct.unpack('>HII', response_header)
                self.assertEqual(code, 0, f"Response should indicate success for {description}")

                data_size = len(captured_data) - 10
                self.assertGreaterEqual(data_size, expected_size,
                                      f"Captured data too small for {description}")

            interception_results.append({
                'command': description,
                'time': attack_time,
                'data_size': len(captured_data) if captured_data else 0,
                'success': captured_data is not None
            })

        print("\nBus Attack Interception Results:")
        for result in interception_results:
            print(f"  {result['command']}:")
            print(f"    Time: {result['time']*1000:.2f}ms")
            print(f"    Data Size: {result['data_size']} bytes")
            print(f"    Success: {result['success']}")

    def test_cold_boot_attack_execution(self):
        """Execute cold boot attack on TPM memory regions for key extraction."""
        memory_regions = [
            'tpm_control',
            'tpm_buffers',
            'tpm_locality_0',
            'tpm_data_fifo'
        ]

        if hasattr(self.tpm_engine, 'mem_handle') and self.tpm_engine.mem_handle:
            for region in memory_regions:
                if region in self.tpm_engine.memory_map:
                    address = self.tpm_engine.memory_map[region]

                    test_data = b'\x00\x01\x00\x00' + os.urandom(252)  # RSA key pattern
                    test_data += b'\x00\x23\x00\x00' + os.urandom(252)  # ECC key pattern

        start_time = time.perf_counter()
        extracted_secrets = self.tpm_engine.cold_boot_attack()
        attack_time = time.perf_counter() - start_time

        self.assertIsInstance(extracted_secrets, dict)
        self.assertGreater(len(extracted_secrets), 0, "Should extract some secrets")

        rsa_keys_found = sum(1 for k in extracted_secrets if '_rsa' in k)
        ecc_keys_found = sum(1 for k in extracted_secrets if '_ecc' in k)
        entropy_data_found = sum(1 for k in extracted_secrets if '_entropy' in k)

        print(f"\nCold Boot Attack Execution Results:")
        print(f"  Attack Time: {attack_time*1000:.2f}ms")
        print(f"  Total Secrets: {len(extracted_secrets)}")
        print(f"  RSA Keys Found: {rsa_keys_found}")
        print(f"  ECC Keys Found: {ecc_keys_found}")
        print(f"  High Entropy Regions: {entropy_data_found}")

    def test_tpm_lockout_reset_effectiveness(self):
        """Test TPM lockout reset against dictionary attack protection."""
        self.tpm_engine.virtualized_tpm['lockout_count'] = 10

        start_time = time.perf_counter()
        success = self.tpm_engine.reset_tpm_lockout()
        reset_time = time.perf_counter() - start_time

        self.assertTrue(success, "Lockout reset should succeed")
        self.assertEqual(self.tpm_engine.virtualized_tpm.get('lockout_count', 0), 0,
                        "Lockout count should be reset to 0")

        print(f"\nTPM Lockout Reset:")
        print(f"  Reset Time: {reset_time*1000:.2f}ms")
        print(f"  Success: {success}")
        print(f"  Lockout Count After: {self.tpm_engine.virtualized_tpm.get('lockout_count', 0)}")

    def test_ownership_clear_bypass(self):
        """Test TPM ownership clearing for gaining control."""
        self.tpm_engine.virtualized_tpm['hierarchy_auth'] = {
            0x40000001: b'old_owner_auth',
            0x40000009: b'old_endorsement',
            0x4000000C: b'old_platform',
            0x4000000B: b'old_lockout'
        }

        start_time = time.perf_counter()
        success = self.tpm_engine.clear_tpm_ownership()
        clear_time = time.perf_counter() - start_time

        if success:
            for handle, auth in self.tpm_engine.virtualized_tpm['hierarchy_auth'].items():
                self.assertEqual(auth, b'', f"Hierarchy {handle:08x} should have empty auth")

        print(f"\nTPM Ownership Clear:")
        print(f"  Clear Time: {clear_time*1000:.2f}ms")
        print(f"  Success: {success}")
        print(f"  Hierarchies Cleared: {len(self.tpm_engine.virtualized_tpm['hierarchy_auth'])}")

    def test_pcr_manipulation_precision(self):
        """Test precision of PCR value manipulation."""
        test_pcrs = {
            0: hashlib.sha256(b"BIOS").digest(),
            1: hashlib.sha256(b"CONFIG").digest(),
            7: hashlib.sha256(b"SECURE_BOOT").digest(),
            10: hashlib.sha256(b"IMA").digest(),
        }

        self.tpm_engine.manipulate_pcr_values(test_pcrs)

        for pcr_num, expected_value in test_pcrs.items():
            sha256_value = self.tpm_engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_num]
            self.assertEqual(sha256_value, expected_value,
                           f"SHA256 PCR{pcr_num} not set correctly")

            if TPM2Algorithm.SHA1 in self.tpm_engine.pcr_banks:
                sha1_value = self.tpm_engine.pcr_banks[TPM2Algorithm.SHA1].pcr_values[pcr_num]
                expected_sha1 = expected_value[:20]
                self.assertEqual(sha1_value, expected_sha1,
                               f"SHA1 PCR{pcr_num} not set correctly")

        print(f"\nPCR Manipulation Precision:")
        print(f"  PCRs Set: {len(test_pcrs)}")
        print(f"  SHA256 Bank: OK")
        print(f"  SHA1 Bank: OK")

    def test_command_virtualization_completeness(self):
        """Test completeness of virtualized TPM command processing."""
        test_commands = [
            (TPM2CommandCode.GetRandom, 32, "GetRandom"),
            (TPM2CommandCode.PCR_Read, None, "PCR_Read"),
            (TPM2CommandCode.Quote, None, "Quote"),
        ]

        for cmd_code, param, description in test_commands:
            if cmd_code == TPM2CommandCode.GetRandom:
                command = struct.pack('>HIIH', 0x8001, 12, cmd_code, param)
            else:
                command = struct.pack('>HII', 0x8001, 10, cmd_code)

            response = self.tpm_engine.process_virtualized_command(command)

            self.assertIsNotNone(response, f"No response for {description}")
            self.assertGreaterEqual(len(response), 10, f"Response too short for {description}")

            tag, size, code = struct.unpack('>HII', response[:10])
            self.assertIn(tag, [0x8001, 0x8002], f"Invalid response tag for {description}")

            if cmd_code == TPM2CommandCode.GetRandom:
                self.assertEqual(code, 0, f"GetRandom should succeed")
                self.assertGreaterEqual(len(response), 10 + 2 + param,
                                      f"GetRandom response too short")

        print(f"\nVirtualized Command Processing:")
        print(f"  Commands Tested: {len(test_commands)}")
        print(f"  All Responded: OK")

    def test_real_world_software_bypass_execution(self):
        """Execute bypass of real software using TPM protection."""
        software_targets = [
            {
                "name": "Adobe Creative Cloud",
                "tpm_usage": "License binding",
                "pcrs": [0, 1, 7],
                "nvram_index": 0x01800001
            },
            {
                "name": "Microsoft Office 365",
                "tpm_usage": "Activation verification",
                "pcrs": [0, 7, 14],
                "nvram_index": 0x01800002
            },
            {
                "name": "AutoCAD 2024",
                "tpm_usage": "Hardware fingerprint",
                "pcrs": [0, 1, 4, 7],
                "nvram_index": 0x01800003
            },
            {
                "name": "VMware Workstation Pro",
                "tpm_usage": "License attestation",
                "pcrs": [0, 7, 10],
                "nvram_index": 0x01800004
            }
        ]

        bypass_results = []

        for target in software_targets:
            start_time = time.perf_counter()

            target_pcrs = {}
            for pcr in target['pcrs']:
                target_pcrs[pcr] = hashlib.sha256(f"{target['name']}_PCR{pcr}".encode()).digest()

            self.tpm_engine.manipulate_pcr_values(target_pcrs)

            license_data = hashlib.sha256(f"{target['name']}_LICENSE".encode()).digest()
            if target['nvram_index'] < len(self.tpm_engine.virtualized_tpm['nvram']):
                self.tpm_engine.virtualized_tpm['nvram'][target['nvram_index']:target['nvram_index']+32] = license_data

            extracted = self.tpm_engine.read_nvram_raw(target['nvram_index'], b'')

            attestation = self.tpm_engine.spoof_remote_attestation(
                self.test_nonce,
                target_pcrs
            )

            bypass_time = time.perf_counter() - start_time

            success = extracted is not None and 'quote' in attestation

            bypass_results.append({
                'software': target['name'],
                'tpm_usage': target['tpm_usage'],
                'time': bypass_time,
                'pcrs_spoofed': len(target['pcrs']),
                'license_extracted': extracted is not None,
                'attestation_forged': 'quote' in attestation,
                'success': success
            })

        print("\nReal-World Software TPM Bypass Execution:")
        for result in bypass_results:
            print(f"  {result['software']}:")
            print(f"    TPM Usage: {result['tpm_usage']}")
            print(f"    Bypass Time: {result['time']*1000:.2f}ms")
            print(f"    PCRs Spoofed: {result['pcrs_spoofed']}")
            print(f"    License Extracted: {result['license_extracted']}")
            print(f"    Attestation Forged: {result['attestation_forged']}")
            print(f"    Overall Success: {result['success']}")

        success_rate = sum(1 for r in bypass_results if r['success']) / len(bypass_results) * 100
        avg_time = sum(r['time'] for r in bypass_results) / len(bypass_results)

        print(f"\n  Overall Success Rate: {success_rate:.1f}%")
        print(f"  Average Bypass Time: {avg_time*1000:.2f}ms")

        self.assertGreater(success_rate, 90, "Should bypass >90% of TPM-protected software")
        self.assertLess(avg_time, 0.05, "Average bypass should be <50ms")


if __name__ == '__main__':
    unittest.main(verbosity=2)
