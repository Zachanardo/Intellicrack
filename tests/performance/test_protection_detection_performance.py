import pytest
import time
import threading
import tempfile
import os
import psutil

from intellicrack.core.protection.protection_detector import ProtectionDetector
from intellicrack.core.protection.packer_detector import PackerDetector
from intellicrack.core.protection.anti_debug_detector import AntiDebugDetector
from intellicrack.core.protection.obfuscation_detector import ObfuscationDetector
from intellicrack.core.protection.encryption_detector import EncryptionDetector
from intellicrack.core.protection.signature_scanner import SignatureScanner
from intellicrack.core.protection.entropy_analyzer import EntropyAnalyzer
from tests.base_test import IntellicrackTestBase


class TestProtectionDetectionPerformance(IntellicrackTestBase):
    """Performance benchmarks for protection detection operations."""

    @pytest.fixture
    def sample_packed_binary(self):
        """Generate REAL packed binary data for testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            # DOS header
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'  # PE offset
            dos_header += b'\x00' * 60
            
            # PE header
            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220
            
            # UPX-like packed section
            packed_data = b'UPX0\x00\x00\x00\x00'
            packed_data += b'\x55\x50\x58\x21'  # UPX signature
            packed_data += os.urandom(1000)  # Random compressed data
            
            temp_file.write(dos_header + pe_signature + coff_header + optional_header + packed_data)
            temp_file.flush()
            yield temp_file.name
        
        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def sample_obfuscated_binary(self):
        """Generate REAL obfuscated binary data for testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            # Standard PE headers
            headers = b'MZ' + b'\x00' * 58 + b'\x80\x00\x00\x00'
            headers += b'\x00' * 64
            headers += b'PE\x00\x00'
            headers += b'\x4c\x01\x03\x00' + b'\x00' * 240
            
            # Obfuscated code section
            obfuscated_code = bytearray()
            for i in range(500):
                # Generate obfuscated patterns
                obfuscated_code.extend([
                    0xEB, 0x02,  # jmp +2
                    0x90, 0x90,  # nops
                    0x74, 0x00,  # jz +0
                    0x75, 0x00,  # jnz +0
                    0xE8, 0x00, 0x00, 0x00, 0x00,  # call
                    0x58,  # pop eax
                ])
            
            temp_file.write(headers + bytes(obfuscated_code))
            temp_file.flush()
            yield temp_file.name
        
        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def process_memory(self):
        """Monitor process memory usage."""
        process = psutil.Process()
        return process.memory_info()

    @pytest.mark.benchmark
    def test_protection_detection_performance(self, benchmark, sample_packed_binary):
        """Benchmark REAL protection detection speed."""
        def detect_protections():
            detector = ProtectionDetector()
            return detector.detect_all_protections(sample_packed_binary)
        
        result = benchmark(detect_protections)
        
        self.assert_real_output(result)
        assert 'protections' in result, "Result must contain protections list"
        assert len(result['protections']) > 0, "Must detect at least one protection"
        assert benchmark.stats.mean < 1.0, "Protection detection should be under 1 second"

    @pytest.mark.benchmark
    def test_packer_detection_performance(self, benchmark, sample_packed_binary):
        """Benchmark REAL packer detection speed."""
        def detect_packer():
            detector = PackerDetector()
            return detector.detect_packer(sample_packed_binary)
        
        result = benchmark(detect_packer)
        
        self.assert_real_output(result)
        assert 'packer' in result, "Result must identify packer"
        assert result['packer'] is not None, "Must detect packer type"
        assert benchmark.stats.mean < 0.1, "Packer detection should be under 100ms"

    @pytest.mark.benchmark
    def test_anti_debug_detection_performance(self, benchmark, sample_obfuscated_binary):
        """Benchmark REAL anti-debug detection speed."""
        def detect_anti_debug():
            detector = AntiDebugDetector()
            return detector.detect_anti_debug_techniques(sample_obfuscated_binary)
        
        result = benchmark(detect_anti_debug)
        
        self.assert_real_output(result)
        assert 'techniques' in result, "Result must contain techniques list"
        assert benchmark.stats.mean < 0.5, "Anti-debug detection should be under 500ms"

    @pytest.mark.benchmark
    def test_obfuscation_detection_performance(self, benchmark, sample_obfuscated_binary):
        """Benchmark REAL obfuscation detection speed."""
        def detect_obfuscation():
            detector = ObfuscationDetector()
            return detector.detect_obfuscation(sample_obfuscated_binary)
        
        result = benchmark(detect_obfuscation)
        
        self.assert_real_output(result)
        assert 'obfuscation_level' in result, "Result must contain obfuscation level"
        assert 'techniques' in result, "Result must list obfuscation techniques"
        assert benchmark.stats.mean < 0.3, "Obfuscation detection should be under 300ms"

    @pytest.mark.benchmark
    def test_encryption_detection_performance(self, benchmark, sample_packed_binary):
        """Benchmark REAL encryption detection speed."""
        def detect_encryption():
            detector = EncryptionDetector()
            return detector.detect_encryption(sample_packed_binary)
        
        result = benchmark(detect_encryption)
        
        self.assert_real_output(result)
        assert 'encrypted' in result, "Result must indicate encryption status"
        assert 'algorithms' in result, "Result must list potential algorithms"
        assert benchmark.stats.mean < 0.2, "Encryption detection should be under 200ms"

    @pytest.mark.benchmark
    def test_signature_scanning_performance(self, benchmark, sample_packed_binary):
        """Benchmark REAL signature scanning speed."""
        def scan_signatures():
            scanner = SignatureScanner()
            scanner.load_signatures()  # Load signature database
            return scanner.scan_file(sample_packed_binary)
        
        result = benchmark(scan_signatures)
        
        self.assert_real_output(result)
        assert 'matches' in result, "Result must contain signature matches"
        assert benchmark.stats.mean < 0.5, "Signature scanning should be under 500ms"

    @pytest.mark.benchmark
    def test_entropy_analysis_performance(self, benchmark, sample_packed_binary):
        """Benchmark REAL entropy analysis speed."""
        def analyze_entropy():
            analyzer = EntropyAnalyzer()
            with open(sample_packed_binary, 'rb') as f:
                data = f.read()
            return analyzer.analyze_entropy(data)
        
        result = benchmark(analyze_entropy)
        
        self.assert_real_output(result)
        assert 'entropy' in result, "Result must contain entropy value"
        assert 0 <= result['entropy'] <= 8, "Entropy must be between 0 and 8"
        assert benchmark.stats.mean < 0.1, "Entropy analysis should be under 100ms"

    def test_concurrent_protection_detection(self, sample_packed_binary):
        """Test REAL concurrent protection detection performance."""
        results = []
        errors = []
        
        def detect_protections(thread_id):
            try:
                detector = ProtectionDetector()
                result = detector.detect_all_protections(sample_packed_binary)
                results.append((thread_id, result))
            except Exception as e:
                errors.append((thread_id, str(e)))
        
        threads = []
        start_time = time.time()
        
        for i in range(4):
            thread = threading.Thread(target=detect_protections, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(timeout=5.0)
        
        end_time = time.time()
        
        assert len(errors) == 0, f"Concurrent detection errors: {errors}"
        assert len(results) == 4, f"Expected 4 results, got {len(results)}"
        assert end_time - start_time < 2.0, "Concurrent detection should complete under 2 seconds"

    def test_protection_database_loading_performance(self):
        """Test REAL protection database loading performance."""
        scanner = SignatureScanner()
        
        start_time = time.time()
        
        # Load signature database
        result = scanner.load_signatures()
        
        end_time = time.time()
        
        self.assert_real_output(result)
        assert result['signatures_loaded'] > 0, "Must load some signatures"
        assert end_time - start_time < 1.0, "Database loading should be under 1 second"

    def test_multi_layer_protection_detection(self, sample_packed_binary):
        """Test REAL multi-layer protection detection performance."""
        detector = ProtectionDetector()
        
        start_time = time.time()
        
        # Detect multiple protection layers
        layers = []
        current_file = sample_packed_binary
        
        for i in range(3):  # Check up to 3 layers
            result = detector.detect_protection_layer(current_file, layer=i)
            if result['has_protection']:
                layers.append(result)
            else:
                break
        
        end_time = time.time()
        
        assert len(layers) >= 1, "Must detect at least one protection layer"
        assert end_time - start_time < 2.0, "Multi-layer detection should be under 2 seconds"

    def test_heuristic_detection_performance(self, sample_obfuscated_binary):
        """Test REAL heuristic detection performance."""
        detector = ObfuscationDetector()
        
        start_time = time.time()
        
        # Run heuristic analysis
        heuristics = detector.run_heuristic_analysis(sample_obfuscated_binary)
        
        end_time = time.time()
        
        self.assert_real_output(heuristics)
        assert 'score' in heuristics, "Must provide heuristic score"
        assert 'indicators' in heuristics, "Must list suspicious indicators"
        assert end_time - start_time < 0.5, "Heuristic analysis should be under 500ms"

    @pytest.mark.benchmark
    def test_batch_protection_detection_performance(self, benchmark, sample_packed_binary, sample_obfuscated_binary):
        """Benchmark REAL batch protection detection speed."""
        def batch_detect():
            detector = ProtectionDetector()
            files = [sample_packed_binary, sample_obfuscated_binary] * 5  # 10 files
            
            results = []
            for file_path in files:
                result = detector.detect_all_protections(file_path)
                results.append(result)
            
            return results
        
        results = benchmark(batch_detect)
        
        assert len(results) == 10, "Must process all 10 files"
        assert benchmark.stats.mean < 5.0, "Batch detection should be under 5 seconds"

    def test_protection_removal_simulation_performance(self, sample_packed_binary):
        """Test REAL protection removal simulation performance."""
        detector = ProtectionDetector()
        
        start_time = time.time()
        
        # Detect protection
        protection_info = detector.detect_all_protections(sample_packed_binary)
        
        # Simulate removal process
        if protection_info['protections']:
            removal_strategy = detector.get_removal_strategy(protection_info['protections'][0])
            self.assert_real_output(removal_strategy)
            assert 'steps' in removal_strategy, "Must provide removal steps"
        
        end_time = time.time()
        
        assert end_time - start_time < 1.0, "Protection analysis should be under 1 second"

    def test_memory_usage_during_detection(self, sample_packed_binary, process_memory):
        """Test REAL memory usage during protection detection."""
        initial_memory = process_memory.rss
        
        detector = ProtectionDetector()
        
        # Perform multiple detections
        for i in range(20):
            result = detector.detect_all_protections(sample_packed_binary)
            self.assert_real_output(result)
        
        current_process = psutil.Process()
        final_memory = current_process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        assert memory_increase < 100 * 1024 * 1024, "Memory increase should be under 100MB"

    def test_custom_protection_detection(self):
        """Test REAL custom protection detection performance."""
        detector = ProtectionDetector()
        
        # Add custom protection signatures
        custom_signatures = [
            {'name': 'CustomPacker1', 'pattern': b'\x12\x34\x56\x78'},
            {'name': 'CustomPacker2', 'pattern': b'\xDE\xAD\xBE\xEF'},
            {'name': 'CustomPacker3', 'pattern': b'\xCA\xFE\xBA\xBE'},
        ]
        
        start_time = time.time()
        
        for sig in custom_signatures:
            detector.add_custom_signature(sig)
        
        # Test detection with custom signatures
        test_data = b'\x00' * 100 + b'\xDE\xAD\xBE\xEF' + b'\x00' * 100
        result = detector.detect_custom_protections(test_data)
        
        end_time = time.time()
        
        self.assert_real_output(result)
        assert 'CustomPacker2' in str(result), "Must detect custom protection"
        assert end_time - start_time < 0.1, "Custom detection should be fast"

    @pytest.mark.benchmark
    def test_protection_fingerprinting_performance(self, benchmark, sample_packed_binary):
        """Benchmark REAL protection fingerprinting speed."""
        def fingerprint_protection():
            detector = ProtectionDetector()
            return detector.generate_protection_fingerprint(sample_packed_binary)
        
        result = benchmark(fingerprint_protection)
        
        self.assert_real_output(result)
        assert 'fingerprint' in result, "Must generate fingerprint"
        assert len(result['fingerprint']) > 0, "Fingerprint must not be empty"
        assert benchmark.stats.mean < 0.2, "Fingerprinting should be under 200ms"