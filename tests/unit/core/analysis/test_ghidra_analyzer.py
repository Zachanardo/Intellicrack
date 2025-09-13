"""
Comprehensive unit tests for Ghidra analyzer module.

Tests validate production-ready Ghidra integration capabilities including:
- Advanced binary analysis with real-world samples
- Sophisticated reverse engineering functionality
- Comprehensive vulnerability detection
- Protection mechanism identification
- Cross-platform binary format support

All tests assume genuine Ghidra integration and will fail for placeholder implementations.
"""

import unittest
import threading
import time
import tempfile
import os
from pathlib import Path

from intellicrack.core.analysis.ghidra_analyzer import run_advanced_ghidra_analysis, _run_ghidra_thread


class TestGhidraAnalyzerProductionCapabilities(unittest.TestCase):
    """Tests validating production-ready Ghidra analysis capabilities."""

    def setUp(self):
        """Set up test fixtures with real binary samples."""
        # Create realistic test binary samples that would require genuine analysis
        self.test_binaries = {
            'pe_sample': self._create_pe_test_binary(),
            'elf_sample': self._create_elf_test_binary(),
            'protected_sample': self._create_protected_binary(),
            'malformed_sample': self._create_malformed_binary()
        }

    def _create_pe_test_binary(self):
        """Create realistic PE binary test sample."""
        # MZ header with realistic structure requiring real parsing
        pe_header = (
            b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00'
            b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21'
        )
        # Add PE header with import table and sections
        pe_signature = b'PE\x00\x00'
        coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16  # Machine type, sections, timestamp

        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(pe_header + b'\x00' * (0x80 - len(pe_header)) + pe_signature + coff_header)
            # Add realistic sections with code patterns
            f.write(b'\x55\x8b\xec\x83\xec\x40')  # Common function prologue
            f.write(b'\x68\x00\x10\x40\x00')      # Push address pattern
            f.write(b'\xff\x15\x00\x20\x40\x00')  # Call import pattern
            return f.name

    def _create_elf_test_binary(self):
        """Create realistic ELF binary test sample."""
        # ELF header with realistic structure
        elf_header = (
            b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x02\x00\x3e\x00\x01\x00\x00\x00\x00\x10\x40\x00\x00\x00\x00\x00'
            b'\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x40\x00\x38\x00\x01\x00\x40\x00\x00\x00\x00\x00'
        )

        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(elf_header)
            # Add realistic x86-64 instructions
            f.write(b'\x48\x89\xe5')      # mov rbp, rsp
            f.write(b'\x48\x83\xec\x10')  # sub rsp, 16
            f.write(b'\xc7\x45\xfc\x00\x00\x00\x00')  # mov dword ptr [rbp-4], 0
            return f.name

    def _create_protected_binary(self):
        """Create binary with packing/obfuscation patterns."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            # UPX-like packing signature
            f.write(b'UPX!')
            # Encrypted/compressed section
            f.write(b'\x00' * 100 + b'UPX!' + b'\x00' * 100)
            # Anti-debug patterns
            f.write(b'\x64\xa1\x30\x00\x00\x00')  # mov eax, fs:[30h] (PEB access)
            f.write(b'\x0f\x31')                  # rdtsc instruction
            return f.name

    def _create_malformed_binary(self):
        """Create malformed binary to test error handling."""
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            # Truncated headers and invalid structures
            f.write(b'MZ\x90\x00' + b'\xff' * 20)  # Invalid PE structure
            return f.name

    def tearDown(self):
        """Clean up test files."""
        for binary_path in self.test_binaries.values():
            if os.path.exists(binary_path):
                os.unlink(binary_path)


class TestAdvancedGhidraAnalysis(TestGhidraAnalyzerProductionCapabilities):
    """Tests for run_advanced_ghidra_analysis function."""

    def test_pe_binary_comprehensive_analysis(self):
        """Test comprehensive analysis of PE binary with real-world expectations."""
        binary_path = self.test_binaries['pe_sample']

        # Test requires genuine Ghidra integration to pass
        result = run_advanced_ghidra_analysis(binary_path)

        # Validate sophisticated analysis results structure
        self.assertIsInstance(result, dict)
        self.assertIn('binary_format', result)
        self.assertEqual(result['binary_format'], 'PE')

        # Validate comprehensive function analysis
        self.assertIn('functions', result)
        self.assertIsInstance(result['functions'], list)
        for func in result['functions']:
            self.assertIn('address', func)
            self.assertIn('name', func)
            self.assertIn('size', func)
            self.assertIn('instructions', func)
            # Production implementation should identify actual functions
            self.assertGreater(func['size'], 0)

        # Validate import analysis capabilities
        self.assertIn('imports', result)
        self.assertIsInstance(result['imports'], list)

        # Validate string analysis
        self.assertIn('strings', result)
        self.assertIsInstance(result['strings'], list)

        # Validate vulnerability detection
        self.assertIn('vulnerabilities', result)
        self.assertIsInstance(result['vulnerabilities'], list)

        # Validate analysis metadata indicating real processing
        self.assertIn('analysis_time', result)
        self.assertGreater(result['analysis_time'], 0.0)
        self.assertIn('analyzed_bytes', result)
        self.assertGreater(result['analyzed_bytes'], 0)

    def test_elf_binary_analysis_capabilities(self):
        """Test ELF binary analysis with architecture-specific validation."""
        binary_path = self.test_binaries['elf_sample']

        result = run_advanced_ghidra_analysis(binary_path)

        # Validate ELF-specific analysis
        self.assertIsInstance(result, dict)
        self.assertIn('binary_format', result)
        self.assertEqual(result['binary_format'], 'ELF')

        # Validate architecture detection
        self.assertIn('architecture', result)
        self.assertIn(result['architecture'], ['x86', 'x64', 'ARM', 'MIPS'])

        # Validate section analysis
        self.assertIn('sections', result)
        self.assertIsInstance(result['sections'], list)
        for section in result['sections']:
            self.assertIn('name', section)
            self.assertIn('address', section)
            self.assertIn('size', section)
            self.assertIn('permissions', section)

    def test_protected_binary_detection_capabilities(self):
        """Test detection of packing and protection mechanisms."""
        binary_path = self.test_binaries['protected_sample']

        result = run_advanced_ghidra_analysis(binary_path)

        # Validate protection detection
        self.assertIn('protections', result)
        self.assertIsInstance(result['protections'], list)

        # Production implementation should detect UPX packing
        protection_types = [p['type'] for p in result['protections']]
        self.assertIn('packer', [p.lower() for p in protection_types])

        # Validate anti-analysis technique detection
        self.assertIn('anti_analysis', result)
        self.assertIsInstance(result['anti_analysis'], list)

        # Should detect PEB access and timing checks
        anti_techniques = [t['technique'] for t in result['anti_analysis']]
        self.assertTrue(any('debug' in t.lower() for t in anti_techniques))

    def test_analysis_with_custom_options(self):
        """Test analysis with advanced configuration options."""
        binary_path = self.test_binaries['pe_sample']

        options = {
            'deep_analysis': True,
            'timeout': 300,
            'extract_strings': True,
            'analyze_crypto': True,
            'detect_packers': True,
            'generate_graph': True
        }

        result = run_advanced_ghidra_analysis(binary_path, options=options)

        # Validate option-specific results
        self.assertIn('control_flow_graph', result)
        self.assertIn('cryptographic_patterns', result)
        self.assertIn('deep_analysis_results', result)

        # Validate enhanced string extraction
        strings = result['strings']
        self.assertTrue(any(len(s['value']) > 4 for s in strings))

    def test_concurrent_analysis_support(self):
        """Test concurrent analysis capabilities."""
        binary_paths = [self.test_binaries['pe_sample'], self.test_binaries['elf_sample']]
        results = []
        threads = []

        def analyze_binary(path):
            result = run_advanced_ghidra_analysis(path)
            results.append(result)

        for path in binary_paths:
            thread = threading.Thread(target=analyze_binary, args=(path,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join(timeout=30)

        # Validate concurrent analysis completed successfully
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertIsInstance(result, dict)
            self.assertIn('binary_format', result)

    def test_large_binary_performance(self):
        """Test performance with larger binary files."""
        # Create larger test binary
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            # Write realistic PE with multiple sections
            f.write(b'MZ\x90\x00')
            f.write(b'\x00' * 1000)  # DOS stub
            f.write(b'PE\x00\x00')
            f.write(b'\x00' * 10000)  # Large code section with patterns
            large_binary = f.name

        try:
            start_time = time.time()
            result = run_advanced_ghidra_analysis(large_binary)
            analysis_time = time.time() - start_time

            # Validate reasonable performance (should complete in reasonable time)
            self.assertLess(analysis_time, 60)  # Should complete within 1 minute

            # Validate comprehensive analysis despite size
            self.assertIn('functions', result)
            self.assertIn('analysis_time', result)

        finally:
            os.unlink(large_binary)

    def test_malformed_binary_error_handling(self):
        """Test graceful handling of malformed binaries."""
        binary_path = self.test_binaries['malformed_sample']

        # Should handle gracefully, not crash
        result = run_advanced_ghidra_analysis(binary_path)

        # Should return error information
        self.assertIn('error', result)
        self.assertIn('status', result)
        self.assertEqual(result['status'], 'failed')

        # Should provide meaningful error context
        self.assertIn('error_type', result)
        self.assertIn('error_message', result)

    def test_invalid_file_path_handling(self):
        """Test handling of invalid file paths."""
        invalid_path = "C:\\nonexistent\\file.exe"

        result = run_advanced_ghidra_analysis(invalid_path)

        self.assertIn('error', result)
        self.assertIn('file_not_found', result['error'].lower())
        self.assertEqual(result['status'], 'failed')

    def test_analysis_progress_reporting(self):
        """Test progress reporting during analysis."""
        binary_path = self.test_binaries['pe_sample']
        progress_updates = []

        def progress_callback(stage, progress):
            progress_updates.append({'stage': stage, 'progress': progress})

        result = run_advanced_ghidra_analysis(
            binary_path,
            progress_callback=progress_callback
        )

        # Validate progress reporting
        self.assertGreater(len(progress_updates), 0)

        # Validate progress stages
        stages = [update['stage'] for update in progress_updates]
        expected_stages = ['loading', 'analyzing', 'finalizing']
        self.assertTrue(any(stage in stages for stage in expected_stages))

    def test_vulnerability_detection_accuracy(self):
        """Test sophisticated vulnerability detection capabilities."""
        # Create binary with known vulnerability patterns
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            # Buffer overflow pattern
            f.write(b'strcpy')
            f.write(b'\x00' * 100)
            # Format string vulnerability pattern
            f.write(b'printf')
            f.write(b'\x00' * 100)
            vuln_binary = f.name

        try:
            result = run_advanced_ghidra_analysis(vuln_binary)

            # Validate vulnerability detection
            self.assertIn('vulnerabilities', result)
            vulns = result['vulnerabilities']

            # Should detect buffer overflow risks
            vuln_types = [v['type'] for v in vulns]
            self.assertTrue(any('buffer' in vtype.lower() for vtype in vuln_types))

            # Validate vulnerability details
            for vuln in vulns:
                self.assertIn('severity', vuln)
                self.assertIn('confidence', vuln)
                self.assertIn('description', vuln)
                self.assertIn('location', vuln)

        finally:
            os.unlink(vuln_binary)


class TestGhidraThreadManagement(TestGhidraAnalyzerProductionCapabilities):
    """Tests for _run_ghidra_thread function."""

    def test_threaded_analysis_execution(self):
        """Test asynchronous Ghidra analysis execution."""
        binary_path = self.test_binaries['pe_sample']
        result_container = {'result': None, 'error': None}

        def completion_callback(result, error=None):
            result_container['result'] = result
            result_container['error'] = error

        # Test threaded execution
        thread_id = _run_ghidra_thread(
            binary_path,
            callback=completion_callback
        )

        # Validate thread management
        self.assertIsInstance(thread_id, (str, int))

        # Wait for completion (production implementation should complete)
        time.sleep(5)

        # Validate callback execution
        self.assertIsNotNone(result_container['result'])
        self.assertIsNone(result_container['error'])

        # Validate analysis results
        result = result_container['result']
        self.assertIsInstance(result, dict)
        self.assertIn('binary_format', result)

    def test_thread_progress_monitoring(self):
        """Test progress monitoring during threaded analysis."""
        binary_path = self.test_binaries['pe_sample']
        progress_updates = []

        def progress_callback(stage, progress, thread_id):
            progress_updates.append({
                'stage': stage,
                'progress': progress,
                'thread_id': thread_id
            })

        thread_id = _run_ghidra_thread(
            binary_path,
            progress_callback=progress_callback
        )

        # Wait for progress updates
        time.sleep(3)

        # Validate progress monitoring
        self.assertGreater(len(progress_updates), 0)

        # Validate thread ID consistency
        for update in progress_updates:
            self.assertEqual(update['thread_id'], thread_id)
            self.assertIsInstance(update['progress'], (int, float))
            self.assertGreaterEqual(update['progress'], 0)
            self.assertLessEqual(update['progress'], 100)

    def test_thread_cancellation_capability(self):
        """Test ability to cancel long-running analysis."""
        binary_path = self.test_binaries['pe_sample']

        # Start analysis
        thread_id = _run_ghidra_thread(binary_path)

        # Immediate cancellation request
        cancel_result = _run_ghidra_thread(
            None,
            action='cancel',
            thread_id=thread_id
        )

        # Validate cancellation capability
        self.assertTrue(cancel_result)

        # Thread should stop within reasonable time
        time.sleep(2)

        # Validate thread status
        status = _run_ghidra_thread(
            None,
            action='status',
            thread_id=thread_id
        )
        self.assertIn(status, ['cancelled', 'stopped', 'terminated'])

    def test_thread_resource_management(self):
        """Test proper resource cleanup in threaded execution."""
        binary_path = self.test_binaries['pe_sample']
        initial_thread_count = threading.active_count()

        # Start multiple analyses
        thread_ids = []
        for _ in range(3):
            thread_id = _run_ghidra_thread(binary_path)
            thread_ids.append(thread_id)

        # Wait for completion
        time.sleep(10)

        # Validate resource cleanup
        final_thread_count = threading.active_count()
        self.assertLessEqual(final_thread_count, initial_thread_count + 1)

    def test_thread_error_handling(self):
        """Test error propagation in threaded execution."""
        invalid_path = "C:\\nonexistent\\file.exe"
        error_container = {'error': None}

        def error_callback(result, error=None):
            error_container['error'] = error

        thread_id = _run_ghidra_thread(
            invalid_path,
            callback=error_callback
        )

        # Wait for error handling
        time.sleep(2)

        # Validate error propagation
        self.assertIsNotNone(error_container['error'])
        self.assertIn('not found', str(error_container['error']).lower())

    def test_concurrent_thread_management(self):
        """Test management of multiple concurrent analysis threads."""
        binary_paths = [
            self.test_binaries['pe_sample'],
            self.test_binaries['elf_sample'],
            self.test_binaries['protected_sample']
        ]

        # Start concurrent analyses
        thread_ids = []
        for path in binary_paths:
            thread_id = _run_ghidra_thread(path)
            thread_ids.append(thread_id)

        # Validate unique thread IDs
        self.assertEqual(len(set(thread_ids)), len(thread_ids))

        # Monitor all threads
        for thread_id in thread_ids:
            status = _run_ghidra_thread(
                None,
                action='status',
                thread_id=thread_id
            )
            self.assertIn(status, ['running', 'completed', 'pending'])

    def test_thread_timeout_handling(self):
        """Test timeout handling for long-running analyses."""
        binary_path = self.test_binaries['pe_sample']

        # Set short timeout for testing
        thread_id = _run_ghidra_thread(
            binary_path,
            timeout=1  # 1 second timeout
        )

        # Wait beyond timeout
        time.sleep(3)

        # Check thread status
        status = _run_ghidra_thread(
            None,
            action='status',
            thread_id=thread_id
        )

        # Should handle timeout appropriately
        self.assertIn(status, ['timeout', 'terminated', 'cancelled'])


class TestGhidraAnalyzerIntegration(TestGhidraAnalyzerProductionCapabilities):
    """Integration tests validating end-to-end Ghidra analyzer functionality."""

    def test_complete_analysis_workflow(self):
        """Test complete binary analysis workflow from file to results."""
        binary_path = self.test_binaries['pe_sample']

        # Execute complete workflow
        result = run_advanced_ghidra_analysis(
            binary_path,
            options={
                'deep_analysis': True,
                'generate_report': True,
                'extract_metadata': True
            }
        )

        # Validate complete analysis results
        required_sections = [
            'binary_format', 'architecture', 'functions', 'imports',
            'strings', 'sections', 'vulnerabilities', 'protections',
            'metadata', 'analysis_summary'
        ]

        for section in required_sections:
            self.assertIn(section, result)

        # Validate analysis completeness
        self.assertGreater(len(result['functions']), 0)
        self.assertIn('total_functions', result['analysis_summary'])
        self.assertIn('analysis_coverage', result['analysis_summary'])

    def test_cross_platform_binary_support(self):
        """Test support for multiple binary formats and architectures."""
        test_cases = [
            ('pe_sample', 'PE', ['x86', 'x64']),
            ('elf_sample', 'ELF', ['x86', 'x64', 'ARM'])
        ]

        for sample_key, expected_format, expected_archs in test_cases:
            binary_path = self.test_binaries[sample_key]
            result = run_advanced_ghidra_analysis(binary_path)

            # Validate format detection
            self.assertEqual(result['binary_format'], expected_format)

            # Validate architecture detection
            self.assertIn('architecture', result)
            detected_arch = result['architecture']
            self.assertTrue(any(arch.lower() in detected_arch.lower()
                             for arch in expected_archs))

    def test_analysis_result_persistence(self):
        """Test persistence and retrieval of analysis results."""
        binary_path = self.test_binaries['pe_sample']

        # First analysis
        result1 = run_advanced_ghidra_analysis(
            binary_path,
            options={'save_results': True}
        )

        # Second analysis (should utilize cached results)
        result2 = run_advanced_ghidra_analysis(
            binary_path,
            options={'use_cache': True}
        )

        # Validate result consistency
        self.assertEqual(result1['binary_format'], result2['binary_format'])
        self.assertEqual(len(result1['functions']), len(result2['functions']))

        # Second analysis should be faster
        self.assertLessEqual(result2['analysis_time'], result1['analysis_time'])


if __name__ == '__main__':
    # Configure test discovery and execution
    unittest.main(verbosity=2, buffer=True)
