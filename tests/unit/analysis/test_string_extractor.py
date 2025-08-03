"""
Unit tests for String Extractor with REAL binary string extraction.
Tests REAL string extraction from various binary formats and encodings.
NO MOCKS - ALL TESTS USE REAL BINARIES AND PRODUCE REAL RESULTS.
"""

import pytest
from pathlib import Path

from intellicrack.core.analysis.string_extractor import StringExtractor
from tests.base_test import IntellicrackTestBase


class TestStringExtractor(IntellicrackTestBase):
    """Test string extraction with REAL binaries."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real binaries."""
        self.extractor = StringExtractor()
        self.test_dir = Path(__file__).parent.parent.parent / 'fixtures' / 'binaries'
        
        # Test binaries
        self.simple_pe = self.test_dir / 'pe' / 'simple_hello_world.exe'
        self.simple_elf = self.test_dir / 'elf' / 'simple_x64'
        self.dotnet_binary = self.test_dir / 'protected' / 'dotnet_assembly_0.exe'
        self.packed_binary = self.test_dir / 'protected' / 'upx_packed_0.exe'
        
    def test_ascii_string_extraction(self):
        """Test ASCII string extraction from binary."""
        strings = self.extractor.extract_strings(self.simple_pe, encoding='ascii')
        
        self.assert_real_output(strings)
        assert isinstance(strings, list)
        assert len(strings) > 0
        
        for string_info in strings:
            assert 'string' in string_info
            assert 'offset' in string_info
            assert 'encoding' in string_info
            assert 'length' in string_info
            
            # Validate string properties
            s = string_info['string']
            assert len(s) >= 4  # Minimum length
            assert s.isprintable()  # ASCII printable
            assert not s.startswith('MOCK_')
            assert not s.startswith('FAKE_')
            
    def test_unicode_string_extraction(self):
        """Test Unicode string extraction from binary."""
        strings = self.extractor.extract_strings(self.simple_pe, encoding='unicode')
        
        self.assert_real_output(strings)
        assert isinstance(strings, list)
        
        # Windows binaries often have Unicode strings
        if strings:
            for string_info in strings:
                s = string_info['string']
                assert isinstance(s, str)
                assert len(s) >= 4
                assert string_info['encoding'] == 'unicode'
                
    def test_all_encodings_extraction(self):
        """Test extraction with all supported encodings."""
        strings = self.extractor.extract_all_strings(self.simple_pe)
        
        self.assert_real_output(strings)
        assert isinstance(strings, dict)
        
        # Should have multiple encoding categories
        assert 'ascii' in strings
        assert 'unicode' in strings
        assert 'utf8' in strings
        
        total_strings = sum(len(v) for v in strings.values())
        assert total_strings > 10  # Real binaries have many strings
        
    def test_minimum_length_filtering(self):
        """Test string extraction with different minimum lengths."""
        # Short strings
        short_strings = self.extractor.extract_strings(self.simple_pe, min_length=2)
        
        # Normal strings
        normal_strings = self.extractor.extract_strings(self.simple_pe, min_length=4)
        
        # Long strings
        long_strings = self.extractor.extract_strings(self.simple_pe, min_length=10)
        
        # Validate filtering
        assert len(short_strings) >= len(normal_strings)
        assert len(normal_strings) >= len(long_strings)
        
        # Check actual lengths
        for s in long_strings:
            assert len(s['string']) >= 10
            
    def test_string_context_extraction(self):
        """Test string extraction with context."""
        strings = self.extractor.extract_with_context(self.simple_pe, context_size=16)
        
        self.assert_real_output(strings)
        
        for string_info in strings:
            assert 'string' in string_info
            assert 'offset' in string_info
            assert 'context_before' in string_info
            assert 'context_after' in string_info
            
            # Context should be binary data
            assert isinstance(string_info['context_before'], bytes)
            assert isinstance(string_info['context_after'], bytes)
            assert len(string_info['context_before']) <= 16
            assert len(string_info['context_after']) <= 16
            
    def test_interesting_strings_detection(self):
        """Test detection of interesting/suspicious strings."""
        interesting = self.extractor.find_interesting_strings(self.simple_pe)
        
        self.assert_real_output(interesting)
        assert isinstance(interesting, dict)
        
        # Categories of interesting strings
        expected_categories = [
            'urls',
            'emails', 
            'file_paths',
            'registry_keys',
            'api_calls',
            'crypto_indicators',
            'debug_strings'
        ]
        
        for category in expected_categories:
            assert category in interesting
            assert isinstance(interesting[category], list)
            
        # Windows executables should have API calls
        assert len(interesting['api_calls']) > 0
        
    def test_encoded_string_detection(self):
        """Test detection of encoded/obfuscated strings."""
        encoded = self.extractor.detect_encoded_strings(self.simple_pe)
        
        assert isinstance(encoded, list)
        
        for enc_string in encoded:
            assert 'string' in enc_string
            assert 'encoding_type' in enc_string
            assert 'decoded' in enc_string or 'decode_failed' in enc_string
            assert 'confidence' in enc_string
            
    def test_string_clustering(self):
        """Test string clustering by similarity."""
        strings = self.extractor.extract_strings(self.simple_pe)
        
        if len(strings) > 10:
            clusters = self.extractor.cluster_strings(strings)
            
            self.assert_real_output(clusters)
            assert isinstance(clusters, list)
            
            for cluster in clusters:
                assert 'representative' in cluster
                assert 'members' in cluster
                assert 'similarity' in cluster
                assert len(cluster['members']) > 0
                
    def test_cross_reference_analysis(self):
        """Test string cross-reference analysis."""
        xrefs = self.extractor.analyze_string_xrefs(self.simple_pe)
        
        assert isinstance(xrefs, list)
        
        for xref in xrefs:
            assert 'string' in xref
            assert 'offset' in xref
            assert 'references' in xref
            
            # Each reference should have address
            for ref in xref['references']:
                assert 'address' in ref
                assert 'type' in ref  # data/code reference
                
    def test_dotnet_string_extraction(self):
        """Test .NET specific string extraction."""
        if not self.dotnet_binary.exists():
            pytest.skip(".NET binary not found")
            
        strings = self.extractor.extract_dotnet_strings(self.dotnet_binary)
        
        assert isinstance(strings, list)
        
        if strings:  # .NET assemblies have metadata strings
            self.assert_real_output(strings)
            
            # Check for .NET specific strings
            dotnet_indicators = ['System.', 'Microsoft.', '.dll', '.exe']
            found_dotnet = any(
                any(ind in s['string'] for ind in dotnet_indicators)
                for s in strings
            )
            assert found_dotnet
            
    def test_packed_binary_strings(self):
        """Test string extraction from packed binary."""
        if not self.packed_binary.exists():
            pytest.skip("Packed binary not found")
            
        # Packed binaries have fewer visible strings
        packed_strings = self.extractor.extract_strings(self.packed_binary)
        normal_strings = self.extractor.extract_strings(self.simple_pe)
        
        # Packed should have significantly fewer strings
        assert len(packed_strings) < len(normal_strings)
        
        # But should still find some strings
        assert len(packed_strings) > 0
        
    def test_wide_string_extraction(self):
        """Test wide character string extraction."""
        wide_strings = self.extractor.extract_wide_strings(self.simple_pe)
        
        assert isinstance(wide_strings, list)
        
        for string_info in wide_strings:
            assert string_info['encoding'] in ['utf-16le', 'utf-16be', 'unicode']
            assert len(string_info['string']) >= 2
            
    def test_string_entropy_analysis(self):
        """Test entropy analysis of extracted strings."""
        strings = self.extractor.extract_strings(self.simple_pe)[:50]  # First 50
        
        entropy_analysis = self.extractor.analyze_string_entropy(strings)
        
        self.assert_real_output(entropy_analysis)
        
        for analysis in entropy_analysis:
            assert 'string' in analysis
            assert 'entropy' in analysis
            assert 0.0 <= analysis['entropy'] <= 8.0
            
            # Normal text has moderate entropy
            if analysis['string'].isalpha():
                assert 3.0 <= analysis['entropy'] <= 5.0
                
    def test_string_deduplication(self):
        """Test string deduplication."""
        strings = self.extractor.extract_strings(self.simple_pe)
        
        # Get unique strings
        unique = self.extractor.deduplicate_strings(strings)
        
        assert len(unique) <= len(strings)
        
        # Check no duplicates
        seen = set()
        for s in unique:
            assert s['string'] not in seen
            seen.add(s['string'])
            
    def test_string_filtering(self):
        """Test string filtering by patterns."""
        strings = self.extractor.extract_strings(self.simple_pe)
        
        # Filter for specific patterns
        filters = {
            'dlls': r'.*\.dll$',
            'paths': r'^[A-Za-z]:\\',
            'urls': r'^https?://',
        }
        
        filtered = self.extractor.filter_strings(strings, filters)
        
        assert isinstance(filtered, dict)
        for category, results in filtered.items():
            assert isinstance(results, list)
            # Validate filter worked
            if category == 'dlls' and results:
                assert all(s['string'].endswith('.dll') for s in results)
                
    def test_language_detection(self):
        """Test natural language detection in strings."""
        strings = self.extractor.extract_strings(self.simple_pe, min_length=10)
        
        language_stats = self.extractor.detect_languages(strings)
        
        assert isinstance(language_stats, dict)
        
        # Most strings in Windows binaries are English
        if 'english' in language_stats:
            assert language_stats['english'] > 0
            
    def test_string_scoring(self):
        """Test string suspiciousness scoring."""
        strings = self.extractor.extract_strings(self.simple_pe)
        
        scored = self.extractor.score_string_suspiciousness(strings)
        
        self.assert_real_output(scored)
        
        for s in scored:
            assert 'score' in s
            assert 0.0 <= s['score'] <= 1.0
            assert 'reasons' in s
            
            # High score strings should have reasons
            if s['score'] > 0.7:
                assert len(s['reasons']) > 0