"""
Unit tests for Protection Detector with REAL protected binaries.
Tests REAL protection detection including packers, obfuscators, and anti-debug.
NO MOCKS - ALL TESTS USE REAL BINARIES AND PRODUCE REAL RESULTS.
"""

import pytest
from pathlib import Path

from intellicrack.core.analysis.protection_detector import ProtectionDetector
from tests.base_test import IntellicrackTestBase


class TestProtectionDetector(IntellicrackTestBase):
    """Test protection detection with REAL protected binaries."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real protected binaries."""
        self.detector = ProtectionDetector()
        self.test_dir = Path(__file__).parent.parent.parent / 'fixtures' / 'binaries'
        
        # Simple unprotected binary
        self.simple_pe = self.test_dir / 'pe' / 'simple_hello_world.exe'
        
        # Protected binaries we generated
        self.protected_dir = self.test_dir / 'protected'
        self.upx_binary = self.protected_dir / 'upx_packed_0.exe'
        self.themida_binary = self.protected_dir / 'themida_protected.exe'
        self.vmprotect_binary = self.protected_dir / 'vmprotect_protected.exe'
        self.aspack_binary = self.protected_dir / 'aspack_packed.exe'
        self.enigma_binary = self.protected_dir / 'enigma_packed.exe'
        
    def test_no_protection_detection(self):
        """Test that simple binary shows no protection."""
        result = self.detector.analyze(self.simple_pe)
        
        self.assert_real_output(result)
        assert isinstance(result, dict)
        assert 'protections' in result
        assert 'confidence' in result
        assert 'indicators' in result
        
        # Simple binary should have no protections
        assert len(result['protections']) == 0 or result['confidence'] < 0.3
        
    def test_upx_detection(self):
        """Test UPX packer detection."""
        if not self.upx_binary.exists():
            pytest.skip("UPX binary not found")
            
        result = self.detector.analyze(self.upx_binary)
        
        self.assert_real_output(result)
        assert 'protections' in result
        assert len(result['protections']) > 0
        
        # Check for UPX detection
        protection_names = [p['name'].lower() for p in result['protections']]
        assert any('upx' in name for name in protection_names)
        
        # Check indicators
        assert len(result['indicators']) > 0
        indicator_types = [i['type'] for i in result['indicators']]
        
        # UPX specific indicators
        expected_indicators = ['section_name', 'entropy', 'signature']
        assert any(ind in indicator_types for ind in expected_indicators)
        
    def test_themida_detection(self):
        """Test Themida protector detection."""
        if not self.themida_binary.exists():
            pytest.skip("Themida binary not found")
            
        result = self.detector.analyze(self.themida_binary)
        
        self.assert_real_output(result)
        assert len(result['protections']) > 0
        
        # Should detect advanced protection
        for protection in result['protections']:
            assert 'name' in protection
            assert 'type' in protection
            assert 'confidence' in protection
            
        # High entropy sections
        entropy_indicators = [i for i in result['indicators'] if i['type'] == 'entropy']
        assert len(entropy_indicators) > 0
        
        # Anti-debug indicators
        antidebug_indicators = [i for i in result['indicators'] if 'debug' in i['type']]
        assert len(antidebug_indicators) > 0
        
    def test_vmprotect_detection(self):
        """Test VMProtect detection."""
        if not self.vmprotect_binary.exists():
            pytest.skip("VMProtect binary not found")
            
        result = self.detector.analyze(self.vmprotect_binary)
        
        self.assert_real_output(result)
        assert len(result['protections']) > 0
        
        # VMProtect characteristics
        has_virtualization = any(
            'virtualiz' in p['type'].lower() 
            for p in result['protections']
        )
        assert has_virtualization or result['confidence'] > 0.7
        
        # Check for VM handlers
        vm_indicators = [
            i for i in result['indicators'] 
            if 'vm' in i['description'].lower()
        ]
        assert len(vm_indicators) > 0
        
    def test_multiple_protection_layers(self):
        """Test detection of multiple protection layers."""
        # Some protectors apply multiple techniques
        if self.vmprotect_binary.exists():
            result = self.detector.analyze(self.vmprotect_binary)
            
            protection_types = set(p['type'] for p in result['protections'])
            # May include: packer, virtualizer, obfuscator, anti-debug
            assert len(protection_types) >= 1
            
    def test_anti_debug_detection(self):
        """Test anti-debugging technique detection."""
        # Check protected binaries for anti-debug
        for binary in [self.themida_binary, self.vmprotect_binary]:
            if not binary.exists():
                continue
                
            result = self.detector.detect_anti_debug(binary)
            
            assert isinstance(result, list)
            if result:  # Protected binaries should have anti-debug
                self.assert_real_output(result)
                for technique in result:
                    assert 'name' in technique
                    assert 'description' in technique
                    assert 'offset' in technique or 'pattern' in technique
                    
    def test_obfuscation_detection(self):
        """Test code obfuscation detection."""
        if not self.vmprotect_binary.exists():
            pytest.skip("Protected binary not found")
            
        result = self.detector.detect_obfuscation(self.vmprotect_binary)
        
        self.assert_real_output(result)
        assert isinstance(result, dict)
        assert 'score' in result
        assert 'techniques' in result
        assert 'indicators' in result
        
        # Protected binaries should show obfuscation
        assert result['score'] > 0.5
        assert len(result['techniques']) > 0
        
    def test_signature_based_detection(self):
        """Test signature-based protection detection."""
        signatures = self.detector.scan_signatures(self.upx_binary)
        
        assert isinstance(signatures, list)
        if signatures:
            self.assert_real_output(signatures)
            for sig in signatures:
                assert 'name' in sig
                assert 'offset' in sig
                assert 'pattern' in sig
                assert 'confidence' in sig
                
    def test_entropy_analysis(self):
        """Test entropy-based protection detection."""
        # Compare simple vs protected
        simple_entropy = self.detector.analyze_entropy(self.simple_pe)
        
        self.assert_real_output(simple_entropy)
        assert isinstance(simple_entropy, dict)
        assert 'overall' in simple_entropy
        assert 'sections' in simple_entropy
        
        # Simple binary should have normal entropy
        assert 3.0 <= simple_entropy['overall'] <= 6.5
        
        # Protected binary should have high entropy
        if self.enigma_binary.exists():
            protected_entropy = self.detector.analyze_entropy(self.enigma_binary)
            assert protected_entropy['overall'] > 6.0
            
            # Check section entropies
            high_entropy_sections = [
                s for s, e in protected_entropy['sections'].items() 
                if e > 7.0
            ]
            assert len(high_entropy_sections) > 0
            
    def test_import_obfuscation_detection(self):
        """Test import table obfuscation detection."""
        if not self.themida_binary.exists():
            pytest.skip("Protected binary not found")
            
        result = self.detector.detect_import_obfuscation(self.themida_binary)
        
        assert isinstance(result, dict)
        assert 'obfuscated' in result
        assert 'indicators' in result
        
        # Protected binaries often obfuscate imports
        if result['obfuscated']:
            self.assert_real_output(result)
            assert len(result['indicators']) > 0
            
    def test_code_virtualization_detection(self):
        """Test code virtualization detection."""
        if not self.vmprotect_binary.exists():
            pytest.skip("VMProtect binary not found")
            
        result = self.detector.detect_virtualization(self.vmprotect_binary)
        
        self.assert_real_output(result)
        assert isinstance(result, dict)
        assert 'virtualized' in result
        assert 'vm_handlers' in result
        assert 'confidence' in result
        
        # VMProtect uses virtualization
        assert result['virtualized'] == True
        assert result['confidence'] > 0.7
        
    def test_anti_tampering_detection(self):
        """Test anti-tampering mechanism detection."""
        for binary in [self.themida_binary, self.enigma_binary]:
            if not binary.exists():
                continue
                
            result = self.detector.detect_anti_tampering(binary)
            
            assert isinstance(result, dict)
            assert 'has_anti_tamper' in result
            assert 'mechanisms' in result
            
            if result['has_anti_tamper']:
                self.assert_real_output(result)
                assert len(result['mechanisms']) > 0
                
    def test_certificate_pinning_detection(self):
        """Test certificate/license pinning detection."""
        # Some protectors pin to hardware/license
        result = self.detector.detect_license_checks(self.enigma_binary)
        
        assert isinstance(result, dict)
        assert 'has_license_check' in result
        assert 'indicators' in result
        
    def test_protection_strength_scoring(self):
        """Test protection strength scoring."""
        # Simple binary - low score
        simple_score = self.detector.calculate_protection_score(self.simple_pe)
        assert isinstance(simple_score, float)
        assert 0.0 <= simple_score <= 1.0
        assert simple_score < 0.3  # Low protection
        
        # Protected binary - high score
        if self.vmprotect_binary.exists():
            protected_score = self.detector.calculate_protection_score(self.vmprotect_binary)
            assert protected_score > 0.7  # High protection
            
    def test_bypass_recommendations(self):
        """Test bypass recommendation generation."""
        if not self.upx_binary.exists():
            pytest.skip("Protected binary not found")
            
        result = self.detector.analyze(self.upx_binary)
        recommendations = self.detector.generate_bypass_recommendations(result)
        
        self.assert_real_output(recommendations)
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        
        for rec in recommendations:
            assert 'technique' in rec
            assert 'description' in rec
            assert 'difficulty' in rec
            assert 'tools' in rec
            
            # UPX is easy to unpack
            if 'upx' in rec['technique'].lower():
                assert rec['difficulty'] in ['easy', 'medium']