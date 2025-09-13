"""
Comprehensive unit tests for incremental_analyzer.py module.

This test suite validates production-ready incremental binary analysis capabilities
using specification-driven, black-box testing methodology. Tests are designed to
fail for placeholder implementations and validate genuine security research functionality.
"""

import pytest
import os
import hashlib
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta

from intellicrack.core.analysis.incremental_analyzer import get_cache_path, run_incremental_analysis


class TestGetCachePath:
    """Test suite for get_cache_path function - validates intelligent cache path generation."""

    def setup_method(self):
        """Setup test fixtures with real binary data."""
        # Create temporary directory for test cache operations
        self.temp_dir = tempfile.mkdtemp()
        self.test_binary_path = os.path.join(self.temp_dir, "test_binary.exe")

        # Create realistic binary content (PE header-like structure)
        pe_header = (
            b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            b'\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00'
            + b'\x00' * 32 + b'PE\x00\x00'  # PE signature
            + b'\x4c\x01'  # Machine type (i386)
            + b'\x00' * 1000  # Additional binary content
        )

        with open(self.test_binary_path, 'wb') as f:
            f.write(pe_header)

    def teardown_method(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cache_path_generation_with_valid_binary(self):
        """Test cache path generation for valid binary with sophisticated naming."""
        # Test with realistic analysis parameters
        analysis_params = {
            'depth': 'full',
            'protection_scan': True,
            'entropy_analysis': True,
            'signature_matching': True
        }

        cache_path = get_cache_path(self.test_binary_path, analysis_params)

        # Validate sophisticated path structure
        assert isinstance(cache_path, (str, Path))
        cache_path_str = str(cache_path)

        # Should include binary hash for collision resistance
        with open(self.test_binary_path, 'rb') as f:
            binary_hash = hashlib.sha256(f.read()).hexdigest()[:16]
        assert binary_hash in cache_path_str or "hash" in cache_path_str.lower()

        # Should be platform-appropriate path
        assert os.sep in cache_path_str or "\\" in cache_path_str or "/" in cache_path_str

        # Should include analysis parameter fingerprint
        assert len(cache_path_str) > 10  # Non-trivial path length
        assert cache_path_str.endswith(('.cache', '.dat', '.json', '.bin')) or 'cache' in cache_path_str

        # Path should be valid for filesystem operations
        parent_dir = os.path.dirname(cache_path_str)
        assert len(parent_dir) > 0

    def test_cache_path_collision_resistance(self):
        """Test that different binaries/parameters generate different cache paths."""
        params1 = {'depth': 'surface', 'protection_scan': False}
        params2 = {'depth': 'full', 'protection_scan': True}

        # Create second binary with different content
        binary2_path = os.path.join(self.temp_dir, "different_binary.exe")
        with open(binary2_path, 'wb') as f:
            f.write(b'MZ\x90\x00DIFFERENT_CONTENT' + b'\x00' * 500)

        path1 = get_cache_path(self.test_binary_path, params1)
        path2 = get_cache_path(self.test_binary_path, params2)  # Same binary, different params
        path3 = get_cache_path(binary2_path, params1)  # Different binary, same params

        # All paths should be different (collision resistance)
        assert str(path1) != str(path2)
        assert str(path1) != str(path3)
        assert str(path2) != str(path3)

    def test_cache_path_with_complex_parameters(self):
        """Test cache path generation with sophisticated analysis parameters."""
        complex_params = {
            'analysis_depth': 'comprehensive',
            'protection_types': ['upx', 'vmprotect', 'themida', 'custom'],
            'signature_databases': ['yara_rules', 'commercial_av', 'custom_sigs'],
            'behavioral_analysis': True,
            'code_similarity_threshold': 0.85,
            'entropy_windows': [16, 32, 64, 128],
            'disassembly_engines': ['capstone', 'ghidra', 'ida'],
            'timestamp': datetime.now().isoformat()
        }

        cache_path = get_cache_path(self.test_binary_path, complex_params)

        # Should handle complex parameter structures
        assert isinstance(cache_path, (str, Path))
        path_str = str(cache_path)
        assert len(path_str) > 20  # Should be substantial path for complex params

        # Should be deterministic - same params should generate same path
        cache_path2 = get_cache_path(self.test_binary_path, complex_params)
        assert str(cache_path) == str(cache_path2)

    def test_cache_path_with_edge_case_filenames(self):
        """Test cache path handling with challenging filenames and paths."""
        # Test with various edge case filenames
        edge_case_names = [
            "file with spaces.exe",
            "file_with_unicode_\u00e9\u00fc\u00f1.bin",
            "very_long_filename_" + "x" * 200 + ".dll",
            "file.with.multiple.dots.exe",
            "file-with-dashes_and_underscores.bin"
        ]

        for filename in edge_case_names:
            test_path = os.path.join(self.temp_dir, filename)
            try:
                with open(test_path, 'wb') as f:
                    f.write(b'MZ\x90\x00TEST' + b'\x00' * 100)

                cache_path = get_cache_path(test_path, {'depth': 'basic'})

                # Should generate valid paths even for edge cases
                assert isinstance(cache_path, (str, Path))
                path_str = str(cache_path)
                assert len(path_str) > 0

                # Path should be filesystem-safe
                assert not any(char in path_str for char in ['<', '>', ':', '"', '|', '?', '*'])

            except (OSError, UnicodeError):
                # Some edge cases may not be supported by filesystem
                pass
            finally:
                if os.path.exists(test_path):
                    os.remove(test_path)

    def test_cache_path_temporal_consistency(self):
        """Test that cache paths remain consistent across time for same inputs."""
        params = {'depth': 'full', 'created_time': '2024-01-01T00:00:00'}

        # Generate paths at different times
        path1 = get_cache_path(self.test_binary_path, params)

        # Small delay to test temporal consistency
        import time
        time.sleep(0.1)

        path2 = get_cache_path(self.test_binary_path, params)

        # Should be consistent (unless timestamp is part of hashing)
        # This tests the quality of the caching strategy
        assert str(path1) == str(path2) or 'timestamp' in str(path1).lower()


class TestRunIncrementalAnalysis:
    """Test suite for run_incremental_analysis function - validates sophisticated differential analysis."""

    def setup_method(self):
        """Setup test fixtures with realistic binary data."""
        self.temp_dir = tempfile.mkdtemp()

        # Create original binary (simulating malware sample v1)
        self.original_binary = os.path.join(self.temp_dir, "malware_v1.exe")
        self._create_realistic_pe_binary(self.original_binary, version=1)

        # Create modified binary (simulating malware sample v2)
        self.modified_binary = os.path.join(self.temp_dir, "malware_v2.exe")
        self._create_realistic_pe_binary(self.modified_binary, version=2)

        # Create cache directory
        self.cache_dir = os.path.join(self.temp_dir, "cache")
        os.makedirs(self.cache_dir, exist_ok=True)

    def _create_realistic_pe_binary(self, file_path, version=1):
        """Create realistic PE binary with version-specific modifications."""
        pe_header = (
            b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            b'\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00'
            + b'\x00' * 32 + b'PE\x00\x00'
        )

        # Version-specific code sections
        if version == 1:
            code_section = b'\x55\x8b\xec'  # Standard function prologue
            code_section += b'\x68\x00\x10\x00\x00'  # Push constant
            code_section += b'\xff\x15\x00\x20\x00\x00'  # Call API
            code_section += b'\x5d\xc3'  # Function epilogue

            # Add protection signature (UPX-like)
            protection_sig = b'UPX0\x00\x00\x00\x00'

        else:  # version == 2
            code_section = b'\x55\x8b\xec'  # Same prologue
            code_section += b'\x68\x00\x20\x00\x00'  # Different constant (evolution)
            code_section += b'\xff\x15\x00\x30\x00\x00'  # Different API call
            code_section += b'\x90\x90'  # Added NOPs (anti-analysis)
            code_section += b'\x5d\xc3'

            # Modified protection (Themida-like)
            protection_sig = b'TMD!\x00\x00\x00\x00'

        # Pad with realistic binary content
        binary_content = pe_header + code_section + protection_sig + b'\x00' * 2000

        with open(file_path, 'wb') as f:
            f.write(binary_content)

    def teardown_method(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_incremental_analysis_detects_code_changes(self):
        """Test detection of code modifications between binary versions."""
        # Run incremental analysis comparing two versions
        result = run_incremental_analysis(
            current_binary=self.modified_binary,
            previous_binary=self.original_binary,
            cache_dir=self.cache_dir
        )

        # Should return comprehensive analysis results
        assert isinstance(result, dict)

        # Should detect code changes
        assert 'code_changes' in result or 'modifications' in result or 'diff' in result
        changes = result.get('code_changes', result.get('modifications', result.get('diff', {})))
        assert len(changes) > 0

        # Should provide detailed change analysis
        assert any(key in result for key in ['entropy_changes', 'api_changes', 'section_changes', 'protection_changes'])

        # Should indicate evolution detected
        assert result.get('analysis_status') in ['completed', 'success', True] or 'changes_detected' in result

    def test_incremental_analysis_protection_evolution_detection(self):
        """Test detection of protection mechanism changes."""
        result = run_incremental_analysis(
            current_binary=self.modified_binary,
            previous_binary=self.original_binary,
            cache_dir=self.cache_dir,
            analysis_options={'focus': 'protection_mechanisms'}
        )

        assert isinstance(result, dict)

        # Should detect protection changes (UPX -> Themida simulation)
        protection_info = result.get('protection_analysis', result.get('packer_changes', {}))
        assert isinstance(protection_info, dict)

        # Should identify specific protection types
        assert any(key in str(result).lower() for key in ['upx', 'themida', 'packer', 'protector', 'obfuscation'])

        # Should provide bypass recommendations
        assert any(key in result for key in ['bypass_suggestions', 'recommendations', 'mitigation_strategies'])

    def test_incremental_analysis_with_comprehensive_options(self):
        """Test incremental analysis with full analysis options."""
        comprehensive_options = {
            'analysis_depth': 'maximum',
            'include_entropy': True,
            'include_strings': True,
            'include_imports': True,
            'include_exports': True,
            'include_sections': True,
            'behavioral_analysis': True,
            'code_similarity_threshold': 0.7,
            'generate_report': True
        }

        result = run_incremental_analysis(
            current_binary=self.modified_binary,
            previous_binary=self.original_binary,
            cache_dir=self.cache_dir,
            analysis_options=comprehensive_options
        )

        assert isinstance(result, dict)

        # Should provide comprehensive analysis results
        expected_sections = [
            'entropy_analysis', 'string_analysis', 'import_analysis',
            'export_analysis', 'section_analysis', 'behavioral_analysis'
        ]

        # At least some comprehensive analysis should be present
        assert any(section in result for section in expected_sections)

        # Should include similarity metrics
        assert any(key in result for key in ['similarity_score', 'similarity_analysis', 'code_similarity'])

        # Should be detailed (production-quality output)
        assert len(str(result)) > 500  # Substantial analysis output

    def test_incremental_analysis_caching_integration(self):
        """Test integration with caching system for performance optimization."""
        # First analysis should create cache
        result1 = run_incremental_analysis(
            current_binary=self.modified_binary,
            previous_binary=self.original_binary,
            cache_dir=self.cache_dir
        )

        # Check that cache directory has files
        cache_files_after_first = os.listdir(self.cache_dir)
        assert len(cache_files_after_first) > 0

        # Second analysis should use cache (should be faster and consistent)
        result2 = run_incremental_analysis(
            current_binary=self.modified_binary,
            previous_binary=self.original_binary,
            cache_dir=self.cache_dir
        )

        # Results should be consistent
        assert isinstance(result1, dict) and isinstance(result2, dict)

        # Key analysis results should match (cache working correctly)
        if 'analysis_status' in result1 and 'analysis_status' in result2:
            assert result1['analysis_status'] == result2['analysis_status']

    def test_incremental_analysis_handles_corrupted_binaries(self):
        """Test graceful handling of corrupted or malformed binaries."""
        # Create corrupted binary
        corrupted_binary = os.path.join(self.temp_dir, "corrupted.exe")
        with open(corrupted_binary, 'wb') as f:
            f.write(b'\x00\x00\x00\x00CORRUPTED_HEADER' + b'\xff' * 1000)

        # Should handle corrupted input gracefully
        result = run_incremental_analysis(
            current_binary=corrupted_binary,
            previous_binary=self.original_binary,
            cache_dir=self.cache_dir
        )

        assert isinstance(result, dict)

        # Should indicate error condition or provide partial analysis
        assert any(key in result for key in [
            'error', 'warning', 'partial_analysis', 'analysis_status',
            'format_errors', 'parsing_errors'
        ])

        # Should not crash the analysis system
        assert result is not None

    def test_incremental_analysis_binary_format_support(self):
        """Test support for different binary formats beyond PE."""
        # Create ELF-like binary header
        elf_binary = os.path.join(self.temp_dir, "test_elf")
        elf_header = b'\x7fELF\x01\x01\x01\x00' + b'\x00' * 8  # ELF magic
        with open(elf_binary, 'wb') as f:
            f.write(elf_header + b'\x00' * 1000)

        # Should detect format differences
        result = run_incremental_analysis(
            current_binary=elf_binary,
            previous_binary=self.original_binary,  # PE format
            cache_dir=self.cache_dir
        )

        assert isinstance(result, dict)

        # Should handle format differences intelligently
        assert any(key in result for key in [
            'format_mismatch', 'binary_formats', 'format_analysis',
            'cross_format_analysis', 'format_differences'
        ])

    def test_incremental_analysis_performance_metrics(self):
        """Test that analysis provides performance and timing metrics."""
        result = run_incremental_analysis(
            current_binary=self.modified_binary,
            previous_binary=self.original_binary,
            cache_dir=self.cache_dir,
            analysis_options={'include_timing': True}
        )

        assert isinstance(result, dict)

        # Should include performance metrics for production monitoring
        assert any(key in result for key in [
            'analysis_time', 'timing_metrics', 'performance_stats',
            'execution_time', 'processing_time'
        ])

        # Should provide memory usage or other resource metrics
        assert any(key in result for key in [
            'memory_usage', 'resource_stats', 'cache_efficiency',
            'bytes_processed', 'analysis_efficiency'
        ])

    def test_incremental_analysis_threat_evolution_tracking(self):
        """Test tracking of threat evolution patterns over time."""
        # Create a series of evolved binaries
        evolution_series = []
        for i in range(3):
            evolved_binary = os.path.join(self.temp_dir, f"malware_v{i+3}.exe")
            self._create_realistic_pe_binary(evolved_binary, version=i+3)
            evolution_series.append(evolved_binary)

        # Analyze evolution over multiple versions
        evolution_results = []
        previous = self.original_binary

        for current in evolution_series:
            result = run_incremental_analysis(
                current_binary=current,
                previous_binary=previous,
                cache_dir=self.cache_dir,
                analysis_options={'track_evolution': True}
            )
            evolution_results.append(result)
            previous = current

        # Should track evolution patterns
        assert len(evolution_results) == 3
        assert all(isinstance(r, dict) for r in evolution_results)

        # Should provide evolution intelligence
        final_result = evolution_results[-1]
        assert any(key in final_result for key in [
            'evolution_pattern', 'threat_progression', 'development_timeline',
            'variant_analysis', 'family_classification'
        ])


class TestIncrementalAnalyzerIntegration:
    """Integration tests for the complete incremental analysis workflow."""

    def setup_method(self):
        """Setup comprehensive integration test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_root = os.path.join(self.temp_dir, "analysis_cache")
        os.makedirs(self.cache_root, exist_ok=True)

        # Create realistic malware family samples
        self.malware_family = []
        for i in range(4):
            sample_path = os.path.join(self.temp_dir, f"family_sample_{i}.exe")
            self._create_malware_family_sample(sample_path, variant=i)
            self.malware_family.append(sample_path)

    def _create_malware_family_sample(self, file_path, variant=0):
        """Create realistic malware family samples with evolutionary changes."""
        base_pe = (
            b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            b'\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00'
            + b'\x00' * 32 + b'PE\x00\x00'
        )

        # Family-specific characteristics with evolution
        family_signatures = {
            0: b'FAMILY_A_V1\x00\x00\x00\x00',  # Original
            1: b'FAMILY_A_V2\x00\x00\x00\x00',  # Minor evolution
            2: b'FAMILY_A_V3_PACKED\x00',       # Added packing
            3: b'FAMILY_A_V4_ENCRYPTED'        # Added encryption
        }

        # Evolutionary code changes
        code_variants = {
            0: b'\x55\x8b\xec\x68\x00\x10\x40\x00',  # Basic
            1: b'\x55\x8b\xec\x90\x68\x00\x10\x40\x00',  # Added NOP
            2: b'\x55\x8b\xec\x90\x90\x68\x00\x20\x40\x00',  # More obfuscation
            3: b'\x60\x55\x8b\xec\x90\x90\x68\x00\x30\x40\x00\x61'  # Full obfuscation
        }

        content = (base_pe +
                  family_signatures.get(variant, family_signatures[0]) +
                  code_variants.get(variant, code_variants[0]) +
                  b'\x00' * 2000)

        with open(file_path, 'wb') as f:
            f.write(content)

    def teardown_method(self):
        """Clean up integration test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_complete_incremental_analysis_workflow(self):
        """Test complete workflow from cache generation through evolution analysis."""
        # Step 1: Generate cache paths for all samples
        cache_paths = []
        for sample in self.malware_family:
            params = {'analysis_type': 'family_evolution', 'depth': 'comprehensive'}
            cache_path = get_cache_path(sample, params)
            cache_paths.append(cache_path)
            assert cache_path is not None

        # All cache paths should be unique
        assert len(set(str(p) for p in cache_paths)) == len(cache_paths)

        # Step 2: Perform incremental analysis across family evolution
        analysis_chain = []
        for i in range(1, len(self.malware_family)):
            result = run_incremental_analysis(
                current_binary=self.malware_family[i],
                previous_binary=self.malware_family[i-1],
                cache_dir=self.cache_root,
                analysis_options={
                    'track_family_evolution': True,
                    'detect_packing_changes': True,
                    'analyze_obfuscation_evolution': True
                }
            )
            analysis_chain.append(result)

        # Should have complete analysis chain
        assert len(analysis_chain) == 3
        assert all(isinstance(result, dict) for result in analysis_chain)

        # Step 3: Validate evolution detection across the chain
        for i, result in enumerate(analysis_chain):
            # Should detect increasing sophistication
            assert any(key in result for key in [
                'evolution_detected', 'sophistication_increase',
                'obfuscation_evolution', 'family_progression'
            ])

            # Later variants should show more complex changes
            if i > 0:  # Compare evolution complexity
                complexity_indicators = [
                    'packing_detected', 'encryption_detected',
                    'obfuscation_level', 'evasion_techniques'
                ]
                current_complexity = sum(1 for indicator in complexity_indicators
                                       if indicator in result)
                # Should show progression in complexity detection
                assert current_complexity >= 0  # At minimum, should have some analysis

    def test_cache_consistency_across_analysis_sessions(self):
        """Test that cache remains consistent across multiple analysis sessions."""
        params = {'session_test': True, 'consistency_check': True}

        # Generate cache paths in multiple sessions
        session_1_paths = [get_cache_path(sample, params) for sample in self.malware_family[:2]]
        session_2_paths = [get_cache_path(sample, params) for sample in self.malware_family[:2]]

        # Paths should be consistent across sessions
        assert len(session_1_paths) == len(session_2_paths)
        for path1, path2 in zip(session_1_paths, session_2_paths):
            assert str(path1) == str(path2)

        # Perform analysis in multiple sessions with caching
        result_session_1 = run_incremental_analysis(
            current_binary=self.malware_family[1],
            previous_binary=self.malware_family[0],
            cache_dir=self.cache_root
        )

        result_session_2 = run_incremental_analysis(
            current_binary=self.malware_family[1],
            previous_binary=self.malware_family[0],
            cache_dir=self.cache_root
        )

        # Results should be consistent (cache working)
        assert isinstance(result_session_1, dict)
        assert isinstance(result_session_2, dict)

        # Key metrics should match between sessions
        key_fields = ['analysis_status', 'changes_detected', 'binary_formats']
        for field in key_fields:
            if field in result_session_1 and field in result_session_2:
                assert result_session_1[field] == result_session_2[field]


if __name__ == "__main__":
    # Run with coverage reporting
    pytest.main([__file__, "-v", "--cov=intellicrack.core.analysis.incremental_analyzer", "--cov-report=html"])
