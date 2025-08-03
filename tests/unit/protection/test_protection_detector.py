"""
Unit tests for ProtectionDetector with REAL protection analysis.
Tests REAL anti-debugging, packing, and obfuscation detection.
NO MOCKS - ALL TESTS USE REAL PROTECTED BINARIES AND PRODUCE REAL RESULTS.
"""

import pytest
from pathlib import Path

from intellicrack.protection.protection_detector import ProtectionDetector
from tests.base_test import BaseIntellicrackTest


class TestProtectionDetector(BaseIntellicrackTest):
    """Test protection detection with REAL protected binaries."""

    @pytest.fixture(autouse=True)
    def setup(self, real_protected_binary, real_packed_binary):
        """Set up test with real protected binaries."""
        self.detector = ProtectionDetector()
        self.protected_binary = real_protected_binary
        self.packed_binary = real_packed_binary

    def test_anti_debug_detection_real(self):
        """Test REAL anti-debugging technique detection."""
        # Detect anti-debug in real protected binary
        anti_debug = self.detector.detect_anti_debug(self.protected_binary)

        # Validate real detection results
        self.assert_real_output(anti_debug)
        assert 'techniques' in anti_debug
        assert 'confidence' in anti_debug
        assert 'indicators' in anti_debug

        # Check technique details
        for technique in anti_debug['techniques']:
            assert 'name' in technique
            assert 'type' in technique
            assert 'location' in technique
            assert 'severity' in technique

            # Real anti-debug techniques
            valid_techniques = [
                'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                'NtQueryInformationProcess', 'OutputDebugString',
                'Hardware Breakpoint', 'Timing Check', 'Exception Based',
                'TLS Callback', 'Parent Process Check'
            ]
            assert any(t in technique['name'] for t in valid_techniques)

    def test_packer_identification_real(self):
        """Test REAL packer/protector identification."""
        # Identify packer in real packed binary
        packer_info = self.detector.identify_packer(self.packed_binary)

        # Validate real packer detection
        self.assert_real_output(packer_info)
        assert 'detected' in packer_info
        assert 'packers' in packer_info
        assert 'entropy_score' in packer_info
        assert 'signatures_matched' in packer_info

        # If packer detected, validate details
        if packer_info['detected']:
            assert len(packer_info['packers']) > 0
            for packer in packer_info['packers']:
                assert 'name' in packer
                assert 'version' in packer
                assert 'confidence' in packer
                # Real packer names
                known_packers = [
                    'UPX', 'ASPack', 'PECompact', 'Themida', 'VMProtect',
                    'Enigma', 'Armadillo', 'ASProtect', 'PESpin', 'Obsidium'
                ]
                assert any(p in packer['name'] for p in known_packers)

    def test_obfuscation_analysis_real(self):
        """Test REAL code obfuscation analysis."""
        # Analyze obfuscation in real binary
        obfuscation = self.detector.analyze_obfuscation(self.protected_binary)

        # Validate real obfuscation data
        self.assert_real_output(obfuscation)
        assert 'level' in obfuscation  # none, low, medium, high
        assert 'techniques' in obfuscation
        assert 'metrics' in obfuscation

        # Check obfuscation techniques
        for technique in obfuscation['techniques']:
            assert 'type' in technique
            assert 'description' in technique
            assert 'impact' in technique

            # Real obfuscation types
            valid_types = [
                'control_flow', 'data_encoding', 'string_encryption',
                'api_hashing', 'junk_code', 'opaque_predicates',
                'virtualization', 'metamorphism'
            ]
            assert technique['type'] in valid_types

    def test_encryption_detection_real(self):
        """Test REAL encryption/encoding detection."""
        # Detect encryption in real binary
        encryption = self.detector.detect_encryption(self.protected_binary)

        # Validate real encryption detection
        self.assert_real_output(encryption)
        assert 'encrypted_sections' in encryption
        assert 'encryption_algorithms' in encryption
        assert 'key_locations' in encryption

        # Check encrypted sections
        for section in encryption['encrypted_sections']:
            assert 'name' in section
            assert 'offset' in section
            assert 'size' in section
            assert 'entropy' in section
            # High entropy indicates encryption
            if section['name'] != '.rsrc':  # Resources can have high entropy
                assert section['entropy'] > 7.0

    def test_anti_tampering_detection_real(self):
        """Test REAL anti-tampering mechanism detection."""
        # Detect anti-tampering in real protected binary
        anti_tamper = self.detector.detect_anti_tampering(self.protected_binary)

        # Validate real anti-tampering data
        self.assert_real_output(anti_tamper)
        assert 'mechanisms' in anti_tamper
        assert 'checksum_validation' in anti_tamper
        assert 'integrity_checks' in anti_tamper

        # Check mechanisms
        for mechanism in anti_tamper['mechanisms']:
            assert 'type' in mechanism
            assert 'location' in mechanism
            assert 'protected_range' in mechanism

            # Real anti-tampering types
            valid_types = [
                'crc_check', 'hash_validation', 'signature_check',
                'self_modifying_code', 'code_guards', 'memory_checksums'
            ]
            assert mechanism['type'] in valid_types

    def test_virtualization_detection_real(self):
        """Test REAL code virtualization detection."""
        # Detect virtualization in real binary
        virtualization = self.detector.detect_virtualization(self.protected_binary)

        # Validate real virtualization data
        self.assert_real_output(virtualization)
        assert 'virtualized' in virtualization
        assert 'vm_type' in virtualization
        assert 'virtualized_functions' in virtualization
        assert 'vm_handlers' in virtualization

        # If virtualized, check details
        if virtualization['virtualized']:
            assert virtualization['vm_type'] in [
                'VMProtect', 'Themida', 'Code Virtualizer',
                'Custom VM', 'Unknown VM'
            ]
            assert len(virtualization['vm_handlers']) > 0

    def test_anti_analysis_detection_real(self):
        """Test REAL anti-analysis technique detection."""
        # Detect anti-analysis in real binary
        anti_analysis = self.detector.detect_anti_analysis(self.protected_binary)

        # Validate real anti-analysis data
        self.assert_real_output(anti_analysis)
        assert 'techniques' in anti_analysis
        assert 'api_hooks' in anti_analysis
        assert 'environment_checks' in anti_analysis

        # Check techniques
        for technique in anti_analysis['techniques']:
            assert 'category' in technique
            assert 'method' in technique
            assert 'target' in technique

            # Real anti-analysis categories
            valid_categories = [
                'anti_disassembly', 'anti_dump', 'anti_attach',
                'anti_instrumentation', 'anti_sandbox', 'anti_emulation'
            ]
            assert technique['category'] in valid_categories

    def test_license_check_detection_real(self):
        """Test REAL license/registration check detection."""
        # Detect license checks in real binary
        license_checks = self.detector.detect_license_checks(self.protected_binary)

        # Validate real license detection
        self.assert_real_output(license_checks)
        assert 'found' in license_checks
        assert 'check_types' in license_checks
        assert 'key_algorithms' in license_checks
        assert 'validation_routines' in license_checks

        # If license checks found
        if license_checks['found']:
            for check in license_checks['check_types']:
                assert check in [
                    'serial_key', 'hardware_id', 'online_activation',
                    'file_license', 'registry_license', 'time_trial',
                    'feature_flags', 'dongle_check'
                ]

    def test_import_obfuscation_detection_real(self):
        """Test REAL import table obfuscation detection."""
        # Detect import obfuscation
        import_obf = self.detector.detect_import_obfuscation(self.protected_binary)

        # Validate real import obfuscation data
        self.assert_real_output(import_obf)
        assert 'obfuscated' in import_obf
        assert 'techniques' in import_obf
        assert 'resolved_imports' in import_obf

        # Check obfuscation techniques
        if import_obf['obfuscated']:
            for technique in import_obf['techniques']:
                assert technique in [
                    'iat_encryption', 'dynamic_loading', 'api_hashing',
                    'proxy_functions', 'delayed_imports', 'manual_mapping'
                ]

    def test_string_protection_detection_real(self):
        """Test REAL string protection/encryption detection."""
        # Detect string protection
        string_protection = self.detector.detect_string_protection(self.protected_binary)

        # Validate real string protection data
        self.assert_real_output(string_protection)
        assert 'protected' in string_protection
        assert 'encryption_type' in string_protection
        assert 'encrypted_strings_count' in string_protection
        assert 'decryption_routines' in string_protection

        # If strings are protected
        if string_protection['protected']:
            assert string_protection['encryption_type'] in [
                'xor', 'aes', 'custom', 'stack_strings',
                'encoded', 'compressed'
            ]
            assert string_protection['encrypted_strings_count'] > 0

    def test_comprehensive_protection_scan_real(self):
        """Test REAL comprehensive protection scanning."""
        # Perform full protection scan
        full_scan = self.detector.comprehensive_scan(self.protected_binary)

        # Validate comprehensive scan results
        self.assert_real_output(full_scan)
        assert 'protection_score' in full_scan
        assert 'protection_layers' in full_scan
        assert 'bypass_difficulty' in full_scan
        assert 'recommendations' in full_scan

        # Check protection score
        assert 0 <= full_scan['protection_score'] <= 100
        assert full_scan['bypass_difficulty'] in [
            'trivial', 'easy', 'medium', 'hard', 'extreme'
        ]

        # Check recommendations are practical
        assert len(full_scan['recommendations']) > 0
        for rec in full_scan['recommendations']:
            assert 'technique' in rec
            assert 'tool' in rec
            assert 'success_rate' in rec
            # Real tools/techniques
            assert rec['tool'] in [
                'x64dbg', 'ScyllaHide', 'Frida', 'Intel Pin',
                'Unicorn Engine', 'QEMU', 'Manual', 'Custom Script'
            ]

    def test_protection_timeline_real(self):
        """Test REAL protection technique timeline analysis."""
        # Analyze when protections are applied
        timeline = self.detector.analyze_protection_timeline(self.protected_binary)

        # Validate real timeline data
        self.assert_real_output(timeline)
        assert 'load_time_protections' in timeline
        assert 'runtime_protections' in timeline
        assert 'periodic_checks' in timeline

        # Check protection timing
        for protection in timeline['load_time_protections']:
            assert 'name' in protection
            assert 'trigger' in protection
            assert protection['trigger'] in [
                'process_create', 'dll_load', 'tls_callback',
                'entry_point', 'seh_setup'
            ]
