"""
Test suite for comprehensive obfuscation pattern recognition system

Tests all components of the obfuscation analysis framework including:
- Control flow obfuscation detection
- String obfuscation analysis
- API call obfuscation detection
- Virtualization pattern recognition
- ML-based classification
- Unified model integration

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from intellicrack.core.analysis.obfuscation_pattern_analyzer import (
    ObfuscationPatternAnalyzer, ObfuscationType, ObfuscationSeverity,
    ObfuscationPattern, ControlFlowAnalysis, StringObfuscationAnalysis,
    APIObfuscationAnalysis, AdvancedTechniquesAnalysis
)
from intellicrack.core.analysis.unified_model import (
    ObfuscationAnalysis, ObfuscationPattern as UnifiedObfuscationPattern,
    AnalysisSource
)


class TestObfuscationPatternAnalyzer:
    """Test the main obfuscation pattern analyzer"""
    
    @pytest.fixture
    def mock_binary(self):
        """Create a mock binary file for testing"""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ\x90\x00' + b'\x00' * 100)  # Simple PE header
            return f.name
    
    @pytest.fixture
    def analyzer(self, mock_binary):
        """Create analyzer instance with mock binary"""
        config = {
            'enable_ml': False,  # Disable ML for basic tests
            'parallel_analysis': False,
            'confidence_threshold': 0.5
        }
        return ObfuscationPatternAnalyzer(mock_binary, config)
    
    @pytest.fixture
    def mock_r2_session(self):
        """Create a mock radare2 session"""
        mock_r2 = Mock()
        
        # Mock function list
        mock_r2.cmdj.return_value = [
            {'offset': 0x1000, 'size': 100, 'name': 'main'},
            {'offset': 0x1100, 'size': 50, 'name': 'sub_1100'},
        ]
        
        # Mock disassembly
        mock_r2.cmd.return_value = """
        0x1000      push ebp
        0x1001      mov ebp, esp
        0x1003      jmp 0x1020
        0x1005      jne 0x1010
        0x1007      xor eax, 0x12345678
        0x100c      call GetProcAddress
        0x1011      nop
        0x1012      nop
        """
        
        return mock_r2
    
    def test_analyzer_initialization(self, mock_binary):
        """Test analyzer initialization"""
        analyzer = ObfuscationPatternAnalyzer(mock_binary)
        
        assert analyzer.binary_path == mock_binary
        assert analyzer.config is not None
        assert not analyzer.enable_ml  # Should be False when sklearn unavailable
        assert analyzer.confidence_threshold == 0.6  # Default value
    
    def test_analyzer_with_config(self, mock_binary):
        """Test analyzer initialization with custom config"""
        config = {
            'enable_ml': True,
            'parallel_analysis': False,
            'confidence_threshold': 0.8,
            'max_workers': 2
        }
        
        analyzer = ObfuscationPatternAnalyzer(mock_binary, config)
        
        assert analyzer.confidence_threshold == 0.8
        assert analyzer.max_workers == 2
        assert not analyzer.parallel_analysis
    
    @patch('intellicrack.core.analysis.obfuscation_pattern_analyzer.r2pipe')
    def test_r2_session_initialization(self, mock_r2pipe, analyzer):
        """Test radare2 session initialization"""
        mock_r2pipe.open.return_value = Mock()
        
        analyzer._initialize_r2_session()
        
        mock_r2pipe.open.assert_called_once_with(analyzer.binary_path)
        analyzer.r2.cmd.assert_called_once_with("aaa")
    
    def test_pattern_creation(self):
        """Test obfuscation pattern creation"""
        pattern = ObfuscationPattern(
            type=ObfuscationType.CONTROL_FLOW_FLATTENING,
            severity=ObfuscationSeverity.HIGH,
            confidence=0.8,
            addresses=[0x1000, 0x1100],
            description="Control flow flattening detected",
            indicators=["switch_table", "indirect_jumps"],
            metadata={"complexity": 0.7}
        )
        
        assert pattern.type == ObfuscationType.CONTROL_FLOW_FLATTENING
        assert pattern.severity == ObfuscationSeverity.HIGH
        assert pattern.confidence == 0.8
        assert len(pattern.addresses) == 2
        assert "switch_table" in pattern.indicators
        
        # Test conversion to dict
        pattern_dict = pattern.to_dict()
        assert pattern_dict['type'] == 'control_flow_flattening'
        assert pattern_dict['severity'] == 'high'
        assert pattern_dict['confidence'] == 0.8


class TestControlFlowDetection:
    """Test control flow obfuscation detection"""
    
    @pytest.fixture
    def control_flow_detector(self):
        """Create control flow detector with mock r2 session"""
        from intellicrack.core.analysis.obfuscation_detectors.control_flow_detector import (
            ControlFlowObfuscationDetector
        )
        
        mock_r2 = Mock()
        return ControlFlowObfuscationDetector(mock_r2)
    
    def test_control_flow_flattening_detection(self, control_flow_detector):
        """Test detection of control flow flattening"""
        # Mock function with flattening pattern
        mock_function = {
            'offset': 0x1000,
            'size': 200,
            'name': 'flattened_function'
        }
        
        # Mock basic blocks with flattening pattern
        control_flow_detector.r2.cmdj.return_value = [
            {'addr': 0x1000, 'size': 10, 'jump': 0x1020, 'fail': 0},
            {'addr': 0x1010, 'size': 8, 'jump': 0x1020, 'fail': 0},
            {'addr': 0x1020, 'size': 15, 'jump': 0x1030, 'fail': 0x1040},  # Dispatcher
            {'addr': 0x1030, 'size': 12, 'jump': 0x1020, 'fail': 0},
            {'addr': 0x1040, 'size': 10, 'jump': 0x1020, 'fail': 0},
        ]
        
        result = control_flow_detector._analyze_control_flow_flattening(mock_function)
        
        assert result is not None
        assert result['confidence'] > 0.5
        assert 'dispatcher_candidate' in result['indicators']
    
    def test_opaque_predicate_detection(self, control_flow_detector):
        """Test detection of opaque predicates"""
        # Mock disassembly with opaque predicate patterns
        mock_disasm = """
        0x1000      mov eax, 1
        0x1002      imul eax, eax
        0x1005      and eax, 1
        0x1008      test eax, eax
        0x100a      jz 0x1020
        0x100c      ; This branch is never taken
        0x1020      ; Normal execution continues
        """
        
        control_flow_detector.r2.cmd.return_value = mock_disasm
        
        result = control_flow_detector._detect_opaque_predicates(0x1000)
        
        assert len(result) > 0
        predicate = result[0]
        assert predicate['type'] == 'mathematical_identity'
        assert predicate['confidence'] > 0.6


class TestStringObfuscation:
    """Test string obfuscation detection"""
    
    @pytest.fixture
    def string_detector(self):
        """Create string obfuscation detector"""
        from intellicrack.core.analysis.obfuscation_detectors.string_obfuscation_detector import (
            StringObfuscationDetector
        )
        
        mock_r2 = Mock()
        return StringObfuscationDetector(mock_r2)
    
    def test_string_entropy_calculation(self, string_detector):
        """Test string entropy calculation"""
        # High entropy string (likely encrypted)
        high_entropy_string = "aB3$mK9&pL2@nR7*qS8%tU4#vW1!"
        entropy_high = string_detector._calculate_string_entropy(high_entropy_string)
        
        # Low entropy string (likely plain text)
        low_entropy_string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        entropy_low = string_detector._calculate_string_entropy(low_entropy_string)
        
        assert entropy_high > entropy_low
        assert entropy_high > 4.0  # Threshold for suspicious entropy
        assert entropy_low < 2.0
    
    def test_xor_pattern_detection(self, string_detector):
        """Test XOR encryption pattern detection"""
        # Mock strings with XOR patterns
        test_strings = [
            "Hello World!",  # Plain text
            "\x48\x65\x6C\x6C\x6F\x20\x57\x6F\x72\x6C\x64\x21",  # Original
            "\x01\x04\x0D\x0D\x0E\x51\x16\x0E\x13\x0D\x05\x50",  # XORed with 0x49
        ]
        
        string_detector.r2.cmdj.return_value = [
            {'string': s, 'vaddr': 0x2000 + i * 20} 
            for i, s in enumerate(test_strings)
        ]
        
        patterns = string_detector._detect_xor_encryption()
        
        # Should detect XOR patterns
        assert len(patterns) > 0
        assert any(p['pattern_type'] == 'xor_encryption' for p in patterns)
    
    def test_base64_detection(self, string_detector):
        """Test Base64 encoding detection"""
        # Mock strings with Base64 patterns
        base64_strings = [
            "SGVsbG8gV29ybGQh",  # "Hello World!" in Base64
            "VGhpcyBpcyBhIHRlc3Q=",  # "This is a test" in Base64
            "normal_string_123",  # Not Base64
        ]
        
        string_detector.r2.cmdj.return_value = [
            {'string': s, 'vaddr': 0x3000 + i * 30}
            for i, s in enumerate(base64_strings)
        ]
        
        patterns = string_detector._detect_base64_encoding()
        
        # Should detect Base64 patterns
        assert len(patterns) >= 2  # Two Base64 strings
        for pattern in patterns[:2]:
            assert pattern['encoding_type'] == 'base64'
            assert pattern['confidence'] > 0.7


class TestAPIObfuscation:
    """Test API obfuscation detection"""
    
    @pytest.fixture
    def api_detector(self):
        """Create API obfuscation detector"""
        from intellicrack.core.analysis.obfuscation_detectors.api_obfuscation_detector import (
            APIObfuscationDetector
        )
        
        mock_r2 = Mock()
        return APIObfuscationDetector(mock_r2)
    
    def test_dynamic_api_loading_detection(self, api_detector):
        """Test detection of dynamic API loading"""
        # Mock disassembly with dynamic loading pattern
        mock_disasm = """
        0x1000      push offset aKernel32_dll ; "kernel32.dll"
        0x1005      call LoadLibraryA
        0x100a      mov [ebp+hModule], eax
        0x100d      push offset aGetprocaddres ; "GetProcAddress"
        0x1012      push [ebp+hModule]
        0x1015      call GetProcAddress
        0x101a      mov [ebp+pfnGetProcAddr], eax
        """
        
        api_detector.r2.cmd.return_value = mock_disasm
        api_detector.r2.cmdj.return_value = [{'offset': 0x1000}]
        
        patterns = api_detector.detect_dynamic_api_loading()
        
        assert len(patterns) > 0
        pattern = patterns[0]
        assert pattern.pattern_type == 'dynamic_api_loading'
        assert 'calls_LoadLibrary' in pattern.indicators
        assert 'calls_GetProcAddress' in pattern.indicators
    
    def test_api_hashing_detection(self, api_detector):
        """Test detection of API hashing"""
        # Mock disassembly with hash calculation
        mock_disasm = """
        0x1000      mov eax, [ebp+api_name]
        0x1003      xor edx, edx
        0x1005      cld
        0x1006      lodsb
        0x1007      test al, al
        0x1009      jz short hash_done
        0x100b      ror edx, 13        ; ROR13 hash algorithm
        0x100e      add edx, eax
        0x1010      jmp short 0x1006
        0x1012  hash_done:
        0x1012      cmp edx, 0x726774C  ; Hash value
        0x1018      jz api_found
        """
        
        api_detector.r2.cmd.return_value = mock_disasm
        api_detector.r2.cmdj.return_value = [{'offset': 0x1000}]
        
        patterns = api_detector.detect_api_hashing()
        
        assert len(patterns) > 0
        pattern = patterns[0]
        assert pattern.pattern_type == 'api_hashing'
        assert any('ror13' in indicator for indicator in pattern.indicators)


class TestVirtualizationDetection:
    """Test virtualization protection detection"""
    
    @pytest.fixture
    def vm_detector(self):
        """Create virtualization detector"""
        from intellicrack.core.analysis.obfuscation_detectors.virtualization_detector import (
            VirtualizationDetector
        )
        
        mock_r2 = Mock()
        return VirtualizationDetector(mock_r2)
    
    def test_vm_dispatch_detection(self, vm_detector):
        """Test VM dispatcher pattern detection"""
        # Mock disassembly with VM dispatch pattern
        mock_disasm = """
        0x1000      mov al, [esi]        ; Fetch opcode
        0x1002      inc esi              ; Advance PC
        0x1003      movzx eax, al
        0x1006      jmp [dispatch_table + eax*4]  ; Dispatch
        
        ; Dispatch table follows
        0x1010      dd handler_0
        0x1014      dd handler_1
        0x1018      dd handler_2
        """
        
        vm_detector.r2.cmd.return_value = mock_disasm
        vm_detector.r2.cmdj.return_value = [{'offset': 0x1000, 'size': 100}]
        
        patterns = vm_detector.detect_code_virtualization()
        
        assert len(patterns) > 0
        pattern = patterns[0]
        assert pattern.vm_type == 'vm_dispatcher'
        assert 'opcode_fetching' in pattern.indicators
    
    def test_bytecode_section_detection(self, vm_detector):
        """Test bytecode section detection"""
        # Mock sections with potential bytecode
        vm_detector.r2.cmdj.return_value = [
            {'name': '.text', 'vaddr': 0x1000, 'vsize': 2048, 'flags': 'rx'},
            {'name': '.vmp0', 'vaddr': 0x3000, 'vsize': 1024, 'flags': 'r'},  # VMProtect section
            {'name': '.data', 'vaddr': 0x4000, 'vsize': 512, 'flags': 'rw'},
        ]
        
        # Mock bytecode data
        vm_detector.r2.cmd.return_value = "deadbeefcafebabe" * 32  # Hex data
        
        patterns = vm_detector.detect_bytecode_interpretation()
        
        assert len(patterns) > 0
        pattern = patterns[0]
        assert pattern.vm_type == 'bytecode_interpreter'


class TestMLClassification:
    """Test ML-based obfuscation classification"""
    
    @pytest.fixture
    def ml_classifier(self):
        """Create ML classifier"""
        from intellicrack.core.analysis.obfuscation_detectors.ml_obfuscation_classifier import (
            MLObfuscationClassifier
        )
        
        # Mock classifier without actual sklearn dependency
        with patch('intellicrack.core.analysis.obfuscation_detectors.ml_obfuscation_classifier.SKLEARN_AVAILABLE', False):
            classifier = MLObfuscationClassifier()
            classifier.enabled = False  # Simulate disabled state
            return classifier
    
    def test_feature_extraction_disabled(self, ml_classifier):
        """Test feature extraction when ML is disabled"""
        features = ml_classifier.extract_features()
        
        assert features is None  # Should return None when disabled
    
    def test_classification_disabled(self, ml_classifier):
        """Test classification when ML is disabled"""
        from intellicrack.core.analysis.obfuscation_detectors.ml_obfuscation_classifier import (
            ObfuscationFeatures
        )
        
        # Create mock features
        features = ObfuscationFeatures(
            cfg_complexity=0.8,
            cyclomatic_complexity=15,
            string_entropy=6.5
        )
        
        result = ml_classifier.classify_obfuscation(features)
        
        assert result is None  # Should return None when disabled


class TestUnifiedModelIntegration:
    """Test integration with unified model system"""
    
    def test_obfuscation_pattern_conversion(self):
        """Test conversion of patterns to unified model format"""
        # Create original pattern
        original_pattern = ObfuscationPattern(
            type=ObfuscationType.STRING_ENCRYPTION,
            severity=ObfuscationSeverity.MEDIUM,
            confidence=0.75,
            addresses=[0x2000, 0x2010],
            description="String encryption detected",
            indicators=["high_entropy", "xor_patterns"],
            metadata={"algorithm": "xor"}
        )
        
        # Convert to unified format
        unified_pattern = UnifiedObfuscationPattern(
            type=original_pattern.type.value,
            severity=original_pattern.severity.value,
            confidence=original_pattern.confidence,
            addresses=original_pattern.addresses,
            description=original_pattern.description,
            indicators=original_pattern.indicators,
            metadata=original_pattern.metadata
        )
        
        assert unified_pattern.type == 'string_encryption'
        assert unified_pattern.severity == 'medium'
        assert unified_pattern.confidence == 0.75
        assert len(unified_pattern.addresses) == 2
    
    def test_unified_obfuscation_analysis(self):
        """Test unified obfuscation analysis functionality"""
        analysis = ObfuscationAnalysis()
        
        # Add a test pattern
        pattern = UnifiedObfuscationPattern(
            type='control_flow_flattening',
            severity='high',
            confidence=0.85,
            addresses=[0x1000],
            description="Control flow flattening detected",
            indicators=["switch_table", "dispatcher"]
        )
        
        analysis.add_pattern(pattern, AnalysisSource.OBFUSCATION_ANALYZER)
        
        # Check analysis results
        assert len(analysis.patterns) == 1
        assert analysis.control_flow_obfuscation is True
        assert analysis.obfuscation_level != "none"
        assert analysis.total_patterns_detected == 1
        assert AnalysisSource.OBFUSCATION_ANALYZER in analysis.sources
    
    def test_obfuscation_level_assessment(self):
        """Test obfuscation level assessment logic"""
        analysis = ObfuscationAnalysis()
        
        # Add multiple high-confidence patterns
        patterns = [
            ('control_flow_flattening', 'high', 0.9),
            ('string_encryption', 'medium', 0.8),
            ('api_hashing', 'medium', 0.75),
            ('code_virtualization', 'critical', 0.95),
        ]
        
        for pattern_type, severity, confidence in patterns:
            pattern = UnifiedObfuscationPattern(
                type=pattern_type,
                severity=severity,
                confidence=confidence,
                addresses=[0x1000],
                description=f"{pattern_type} detected"
            )
            analysis.add_pattern(pattern, AnalysisSource.OBFUSCATION_ANALYZER)
        
        # Check final assessment
        assert analysis.obfuscation_level == "extreme"  # VM protection should trigger extreme
        assert analysis.virtualization_protection is True
        assert analysis.obfuscation_complexity > 0.8
        assert analysis.estimated_analysis_time > 3000  # Should be significant


class TestAnalysisIntegration:
    """Test full analysis integration"""
    
    @patch('intellicrack.core.analysis.obfuscation_pattern_analyzer.r2pipe')
    def test_full_analysis_flow(self, mock_r2pipe, mock_binary):
        """Test complete analysis flow"""
        # Setup mock r2 session
        mock_r2 = Mock()
        mock_r2pipe.open.return_value = mock_r2
        
        # Mock analysis results
        mock_r2.cmdj.return_value = [
            {'offset': 0x1000, 'size': 100, 'name': 'main'}
        ]
        mock_r2.cmd.return_value = "push ebp\nmov ebp, esp\nret"
        
        # Create analyzer and run analysis
        config = {'enable_ml': False, 'parallel_analysis': False}
        analyzer = ObfuscationPatternAnalyzer(mock_binary, config)
        
        with patch.object(analyzer, '_parallel_analysis') as mock_parallel:
            mock_parallel.return_value = {
                'control_flow': {'patterns': []},
                'string_obfuscation': {'patterns': []},
                'api_obfuscation': {'patterns': []},
                'advanced_techniques': {'patterns': []}
            }
            
            results = analyzer.analyze()
        
        # Verify results structure
        assert 'metadata' in results
        assert 'summary' in results
        assert 'detailed_results' in results
        assert 'unified_model' in results
        assert isinstance(results['unified_model'], ObfuscationAnalysis)
    
    @pytest.fixture(autouse=True)
    def cleanup_temp_files(self, mock_binary):
        """Clean up temporary files after tests"""
        yield
        try:
            Path(mock_binary).unlink(missing_ok=True)
        except Exception:
            pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])