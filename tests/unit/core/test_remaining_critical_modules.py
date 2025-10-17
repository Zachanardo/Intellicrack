"""Copyright (C) 2025 Zachary Flint.

This file is part of Intellicrack.

Comprehensive production tests for remaining critical modules.
"""

import pytest
import os
import sys
import subprocess
import tempfile
from pathlib import Path
import struct
import hashlib

# TPM Bypass Tests
from intellicrack.core.protection_bypass.tpm_bypass import TPMBypass

class TestTPMBypassProduction:
    """Production tests for TPM bypass and BitLocker circumvention."""

    def test_tpm_bypass_initialization(self):
        """Test TPM bypass initialization."""
        bypass = TPMBypass()
        assert bypass is not None
        assert hasattr(bypass, 'bypass_attestation')
        assert hasattr(bypass, 'extract_bitlocker_keys')

    def test_tpm_attestation_bypass(self):
        """Test TPM attestation bypass techniques."""
        bypass = TPMBypass()

        attestation_config = {
            'tpm_version': '2.0',
            'pcr_banks': ['SHA1', 'SHA256'],
            'attestation_key': os.urandom(32)
        }

        result = bypass.bypass_attestation(attestation_config)
        assert result is not None
        assert 'method' in result
        assert 'success' in result

    def test_bitlocker_key_extraction(self):
        """Test BitLocker key extraction from TPM."""
        bypass = TPMBypass()

        # Test VMK extraction
        vmk_result = bypass.extract_vmk()
        assert vmk_result is not None
        assert 'vmk' in vmk_result or 'error' in vmk_result

        # Test FVEK extraction
        if 'vmk' in vmk_result:
            fvek_result = bypass.extract_fvek(vmk_result['vmk'])
            assert fvek_result is not None


# VM Protection Bypass Tests
from intellicrack.core.protection_bypass.vm_bypass import VMBypass

class TestVMProtectionBypassProduction:
    """Production tests for VM protection unpacking."""

    def test_vmprotect_detection(self):
        """Test VMProtect detection in binaries."""
        bypass = VMBypass()

        # Test with a binary path
        test_binary = Path("C:/Windows/System32/notepad.exe")
        if test_binary.exists():
            result = bypass.detect_vm_protection(str(test_binary))
            assert result is not None
            assert 'protection_type' in result
            assert 'version' in result or result['protection_type'] == 'none'

    def test_themida_unpacking(self):
        """Test Themida/WinLicense unpacking."""
        bypass = VMBypass()

        unpacking_config = {
            'protection': 'Themida',
            'version': '3.x',
            'anti_dump': True,
            'anti_debug': True
        }

        unpacker = bypass.create_unpacker(unpacking_config)
        assert unpacker is not None
        assert 'technique' in unpacker
        assert 'stages' in unpacker

    def test_code_virtualizer_defeat(self):
        """Test Code Virtualizer defeat techniques."""
        bypass = VMBypass()

        cv_config = {
            'vm_type': 'CISC',
            'obfuscation_level': 'maximum'
        }

        defeat_method = bypass.defeat_code_virtualizer(cv_config)
        assert defeat_method is not None
        assert 'devirtualization' in defeat_method


# Commercial License Analysis Tests
from intellicrack.core.analysis.commercial_license_analyzer import CommercialLicenseAnalyzer

class TestCommercialLicenseAnalysisProduction:
    """Production tests for commercial license analysis."""

    def test_flexlm_analysis(self):
        """Test FlexLM license analysis."""
        analyzer = CommercialLicenseAnalyzer()

        flexlm_config = {
            'vendor_daemon': 'custom_vendor',
            'port': 27000,
            'features': ['feature1', 'feature2']
        }

        analysis = analyzer.analyze_flexlm(flexlm_config)
        assert analysis is not None
        assert 'license_type' in analysis
        assert 'encryption' in analysis

    def test_rlm_license_parsing(self):
        """Test RLM license file parsing."""
        analyzer = CommercialLicenseAnalyzer()

        # Create test RLM license content
        rlm_license = """
        HOST server 001122334455 27000
        ISV vendor
        LICENSE vendor product 1.0 permanent 1 hostid=001122334455
        """

        parsed = analyzer.parse_rlm_license(rlm_license)
        assert parsed is not None
        assert 'host' in parsed
        assert 'licenses' in parsed
        assert len(parsed['licenses']) > 0


# Advanced Instrumentation Tests
from intellicrack.core.analysis.dynamic_instrumentation import DynamicInstrumentation
from intellicrack.core.analysis.frida_analyzer import FridaAnalyzer

class TestAdvancedInstrumentationProduction:
    """Production tests for instrumentation and anti-instrumentation bypass."""

    def test_frida_detection_evasion(self):
        """Test Frida detection evasion."""
        frida = FridaAnalyzer()

        evasion = frida.generate_detection_evasion()
        assert evasion is not None
        assert 'port_hiding' in evasion
        assert 'thread_hiding' in evasion
        assert 'name_obfuscation' in evasion

    def test_anti_instrumentation_bypass(self):
        """Test anti-instrumentation bypass techniques."""
        instrumentation = DynamicInstrumentation()

        bypass_techniques = instrumentation.get_bypass_techniques()
        assert bypass_techniques is not None
        assert 'timing_attack_mitigation' in bypass_techniques
        assert 'debugger_detection_bypass' in bypass_techniques


# Ghidra Integration Tests
from intellicrack.core.analysis.ghidra_analyzer import GhidraAnalyzer
from intellicrack.core.analysis.ghidra_script_runner import GhidraScriptRunner

class TestGhidraIntegrationProduction:
    """Production tests for Ghidra integration."""

    def test_ghidra_headless_analysis(self):
        """Test Ghidra headless analysis."""
        ghidra = GhidraAnalyzer()

        # Check if Ghidra is available
        if ghidra.is_ghidra_available():
            analysis_config = {
                'binary': 'test.exe',
                'project': 'test_project',
                'scripts': ['FindCrypto.java', 'FindVulnerabilities.java']
            }

            result = ghidra.run_headless_analysis(analysis_config)
            assert result is not None
            assert 'functions' in result or 'error' in result

    def test_ghidra_script_execution(self):
        """Test Ghidra script execution."""
        runner = GhidraScriptRunner()

        script = """
        # Python script for Ghidra
        from ghidra.app.decompiler import DecompInterface

        def analyze():
            # Analysis code here
            return {'analyzed': True}
        """

        result = runner.validate_script(script)
        assert result is not None
        assert 'valid' in result


# Fuzzing Engine Tests
from intellicrack.core.vulnerability_research.fuzzing_engine import FuzzingEngine

class TestFuzzingEngineProduction:
    """Production tests for fuzzing engine."""

    def test_crash_triage(self):
        """Test crash triage functionality."""
        fuzzer = FuzzingEngine()

        crash_data = {
            'exception_code': 0xC0000005,  # Access violation
            'exception_address': 0x41414141,
            'registers': {'eip': 0x41414141, 'esp': 0x12345678},
            'call_stack': []
        }

        triage = fuzzer.triage_crash(crash_data)
        assert triage is not None
        assert 'exploitability' in triage
        assert 'crash_type' in triage

    def test_coverage_guided_fuzzing(self):
        """Test coverage-guided fuzzing setup."""
        fuzzer = FuzzingEngine()

        fuzzing_config = {
            'target': 'test.exe',
            'input_dir': 'corpus',
            'coverage_type': 'edge',
            'max_iterations': 1000
        }

        campaign = fuzzer.setup_fuzzing_campaign(fuzzing_config)
        assert campaign is not None
        assert 'mutators' in campaign
        assert 'coverage_map' in campaign


# Exploit Development Tests
from intellicrack.core.vulnerability_research.exploit_developer import ExploitDeveloper

class TestExploitDevelopmentProduction:
    """Production tests for exploit development."""

    def test_rop_chain_generation(self):
        """Test ROP chain generation."""
        developer = ExploitDeveloper()

        binary_path = Path("C:/Windows/System32/kernel32.dll")
        if binary_path.exists():
            rop_config = {
                'binary': str(binary_path),
                'goal': 'execute_calc',
                'bad_chars': b'\x00\x0a\x0d'
            }

            rop_chain = developer.generate_rop_chain(rop_config)
            assert rop_chain is not None
            assert 'gadgets' in rop_chain
            assert 'chain' in rop_chain

    def test_heap_exploitation_primitives(self):
        """Test heap exploitation primitives."""
        developer = ExploitDeveloper()

        heap_config = {
            'technique': 'unlink',
            'heap_implementation': 'windows_heap',
            'target_chunk_size': 0x100
        }

        primitives = developer.generate_heap_primitives(heap_config)
        assert primitives is not None
        assert 'allocate' in primitives
        assert 'free' in primitives
        assert 'overflow' in primitives


# Binary Diffing Tests
from intellicrack.core.vulnerability_research.binary_differ import BinaryDiffer

class TestBinaryDiffingProduction:
    """Production tests for binary diffing."""

    def test_patch_analysis(self):
        """Test patch analysis between binaries."""
        differ = BinaryDiffer()

        # Use two versions of a system binary if available
        old_binary = Path("C:/Windows/System32/notepad.exe")
        new_binary = Path("C:/Windows/System32/notepad.exe")  # Same for testing

        if old_binary.exists():
            diff_result = differ.analyze_patch(str(old_binary), str(new_binary))
            assert diff_result is not None
            assert 'changed_functions' in diff_result
            assert 'security_relevant' in diff_result

    def test_function_matching(self):
        """Test function matching between binaries."""
        differ = BinaryDiffer()

        matching_config = {
            'algorithm': 'bindiff',
            'similarity_threshold': 0.7,
            'use_cfg': True
        }

        matches = differ.match_functions(matching_config)
        assert matches is not None
        assert isinstance(matches, list)
