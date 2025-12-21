"""
Unit tests for SimilaritySearcher alias module with REAL binary similarity analysis.
Tests alias functionality and production-ready similarity algorithms with real binary samples.
NO MOCKS - ALL TESTS USE REAL BINARIES AND VALIDATE ADVANCED SIMILARITY CAPABILITIES.

Anti-placeholder validation: These tests are designed to FAIL if the implementation
contains stubs, mocks, or placeholder code. Only genuine, production-ready
binary similarity analysis capabilities will pass these tests.
"""

import pytest
import tempfile
import json
import os
import time
from pathlib import Path

from intellicrack.core.analysis.similarity_searcher import SimilaritySearcher, BinarySimilaritySearcher
from intellicrack.core.analysis.binary_similarity_search import BinarySimilaritySearch
from tests.base_test import IntellicrackTestBase


class TestSimilaritySearcher(IntellicrackTestBase):
    """Test similarity searcher alias module with real binaries and production-ready validation."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test environment with real test binaries and similarity database."""
        # Create temporary database for similarity search
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_db.close()
        self.db_path = self.temp_db.name

        # Initialize similarity searcher through alias
        self.searcher = SimilaritySearcher(self.db_path)

        # Use available real test binaries
        self.test_fixtures_dir = Path("tests/fixtures/binaries")

        # Real PE binaries for advanced similarity testing
        self.pe_binaries = [
            self.test_fixtures_dir / "pe/real_protected/upx_packer/upx-4.2.2-win64/upx.exe",
            self.test_fixtures_dir / "pe/legitimate/7zip.exe",
            self.test_fixtures_dir / "pe/simple_hello_world.exe",
            self.test_fixtures_dir / "size_categories/tiny_4kb/tiny_hello.exe",
            self.test_fixtures_dir / "pe/real_protected/ccleaner_free.exe",
            self.test_fixtures_dir / "pe/real_protected/steam_installer.exe"
        ]

        # Real ELF binaries for cross-architecture testing
        self.elf_binaries = [
            self.test_fixtures_dir / "elf/simple_x64"
        ]

        # Filter for existing binaries
        self.pe_binaries = [p for p in self.pe_binaries if p.exists()]
        self.elf_binaries = [p for p in self.elf_binaries if p.exists()]

        # Ensure we have at least one test binary
        if not self.pe_binaries and not self.elf_binaries:
            pytest.skip("No test binaries available for advanced similarity testing")

        # Sample binary for testing
        self.sample_binary = str(self.pe_binaries[0]) if self.pe_binaries else str(self.elf_binaries[0])

    def teardown_method(self):
        """Clean up temporary files and database."""
        try:
            if os.path.exists(self.db_path):
                os.unlink(self.db_path)
        except OSError:
            pass

    def test_alias_functionality_and_imports(self):
        """Test that similarity searcher aliases work correctly."""
        # Test that aliases point to the correct class
        assert SimilaritySearcher is BinarySimilaritySearch
        assert BinarySimilaritySearcher is BinarySimilaritySearch

        # Test that aliases can be instantiated
        searcher1 = SimilaritySearcher()
        searcher2 = BinarySimilaritySearcher()

        assert isinstance(searcher1, BinarySimilaritySearch)
        assert isinstance(searcher2, BinarySimilaritySearch)

        # Test that aliases have the same functionality
        assert hasattr(searcher1, 'database')
        assert hasattr(searcher2, 'database')
        assert hasattr(searcher1, 'add_binary')
        assert hasattr(searcher2, 'add_binary')

        # Anti-placeholder validation - classes should have real methods
        method_count = len([attr for attr in dir(searcher1) if not attr.startswith('_')])
        assert method_count > 5, "Too few public methods - likely placeholder implementation"

    def test_initialization_and_database_setup(self):
        """Test SimilaritySearcher initialization through aliases."""
        # Test initialization through different aliases
        searcher_alias1 = SimilaritySearcher(self.db_path)
        searcher_alias2 = BinarySimilaritySearcher(self.db_path)

        # Both should work identically
        assert searcher_alias1.database_path == self.db_path
        assert searcher_alias2.database_path == self.db_path

        # Both should have proper database structure
        assert isinstance(searcher_alias1.database, dict)
        assert isinstance(searcher_alias2.database, dict)
        assert 'binaries' in searcher_alias1.database
        assert 'binaries' in searcher_alias2.database

        # Anti-placeholder validation - should have logger
        assert hasattr(searcher_alias1, 'logger')
        assert hasattr(searcher_alias2, 'logger')
        self.assert_real_output(searcher_alias1.database)

    def test_advanced_binary_feature_extraction(self):
        """Test advanced binary feature extraction through similarity searcher alias."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for feature extraction testing")

        binary_path = self.sample_binary

        # Test feature extraction through alias
        features = self.searcher._extract_binary_features(binary_path)

        # Validate production-ready feature extraction
        self.assert_real_output(features)
        assert isinstance(features, dict)

        # Verify comprehensive feature extraction that would be expected
        # from a production-ready similarity searcher
        expected_feature_categories = [
            'file_size',        # Basic file metadata
            'entropy',          # Entropy analysis for obfuscation detection
            'sections',         # PE/ELF section analysis
            'imports',          # Import table analysis
            'exports',          # Export table analysis
            'strings',          # String extraction and analysis
            'machine',          # Architecture information
            'timestamp',        # Compilation timestamp
            'characteristics'   # PE characteristics
        ]

        for category in expected_feature_categories:
            assert category in features, f"Missing expected feature category: {category}"

        # Validate specific feature quality for production use
        assert features['file_size'] > 0, "File size should be positive for real files"
        assert isinstance(features['entropy'], float), "Entropy should be float"
        assert 0.0 <= features['entropy'] <= 8.0, "Entropy should be in valid range"

        if sections := features['sections']:
            for section in sections:
                assert 'name' in section, "Section should have name"
                assert 'entropy' in section, "Section should have entropy analysis"
                assert isinstance(section['entropy'], float), "Section entropy should be float"

        # Strings should be intelligently filtered and analyzed
        strings = features['strings']
        assert isinstance(strings, list), "Strings should be list"
        if strings:
            # Should have reasonable string filtering (not too many, not empty)
            assert len(strings) <= 100, "String count should be reasonably filtered"
            for string in strings[:3]:  # Check first few strings
                assert len(string) >= 4, "Extracted strings should meet minimum length"

    def test_multi_algorithm_similarity_analysis(self):
        """Test sophisticated similarity analysis through searcher alias."""
        if len(self.pe_binaries) < 2:
            pytest.skip("Need at least 2 binaries for similarity testing")

        binary1_path = str(self.pe_binaries[0])
        binary2_path = str(self.pe_binaries[1])

        # Extract features for both binaries
        features1 = self.searcher._extract_binary_features(binary1_path)
        features2 = self.searcher._extract_binary_features(binary2_path)

        # Test basic similarity calculation
        basic_similarity = self.searcher._calculate_basic_similarity(features1, features2)

        # Validate production-ready similarity calculation
        assert isinstance(basic_similarity, float), "Similarity should be float"
        assert 0.0 <= basic_similarity <= 1.0, "Similarity should be in [0,1] range"

        # Test advanced similarity algorithms that should exist in production system
        if hasattr(self.searcher, '_calculate_structural_similarity'):
            structural_sim = self.searcher._calculate_structural_similarity(features1, features2)
            assert isinstance(structural_sim, float)
            assert 0.0 <= structural_sim <= 1.0

        if hasattr(self.searcher, '_calculate_content_similarity'):
            content_sim = self.searcher._calculate_content_similarity(features1, features2)
            assert isinstance(content_sim, float)
            assert 0.0 <= content_sim <= 1.0

        if hasattr(self.searcher, '_calculate_statistical_similarity'):
            statistical_sim = self.searcher._calculate_statistical_similarity(features1, features2)
            assert isinstance(statistical_sim, float)
            assert 0.0 <= statistical_sim <= 1.0

        # Anti-placeholder validation - similarity should not be hardcoded values
        common_placeholder_values = [0.0, 0.5, 0.75, 1.0]
        assert basic_similarity not in common_placeholder_values or len(self.pe_binaries) == 1, \
            f"Suspiciously common similarity value: {basic_similarity} (possible placeholder)"

    def test_database_operations_and_binary_management(self):
        """Test database operations for binary similarity management."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for database testing")

        binary_path = self.sample_binary
        cracking_patterns = [
            "Advanced entropy analysis",
            "Control flow graph mapping",
            "Cross-reference analysis",
            "Dynamic instrumentation hooks"
        ]

        # Test adding binary through alias
        add_result = self.searcher.add_binary(binary_path, cracking_patterns)
        assert add_result is True, "Failed to add binary - non-functional implementation"

        # Verify binary was properly indexed
        assert len(self.searcher.database['binaries']) == 1
        added_entry = self.searcher.database['binaries'][0]

        # Validate comprehensive database entry
        required_fields = ['path', 'filename', 'features', 'cracking_patterns', 'added', 'file_size']
        for field in required_fields:
            assert field in added_entry, f"Missing required database field: {field}"

        # Validate features were extracted and stored
        stored_features = added_entry['features']
        self.assert_real_output(stored_features)
        assert stored_features['file_size'] > 0

        # Test binary search functionality
        search_results = self.searcher.search_similar_binaries(binary_path, threshold=0.1)
        assert isinstance(search_results, list)

        # Should find itself with high similarity
        if search_results:
            self.assert_real_output(search_results)
            for result in search_results:
                assert 'path' in result
                assert 'similarity' in result
                assert 'cracking_patterns' in result
                assert isinstance(result['similarity'], float)
                assert 0.1 <= result['similarity'] <= 1.0

    def test_advanced_search_and_clustering_capabilities(self):
        """Test advanced search and clustering through similarity searcher."""
        if len(self.pe_binaries) < 2:
            pytest.skip("Need multiple binaries for clustering testing")

        # Add multiple binaries with different patterns
        test_binaries = self.pe_binaries[:3] if len(self.pe_binaries) >= 3 else self.pe_binaries
        pattern_sets = [
            ["Cryptographic operations", "Key generation"],
            ["Network communication", "Protocol analysis"],
            ["File system manipulation", "Registry access"]
        ]

        for i, binary_path in enumerate(test_binaries):
            patterns = pattern_sets[i % len(pattern_sets)]
            result = self.searcher.add_binary(str(binary_path), patterns)
            assert result is True

        # Test database statistics for clustering analysis
        stats = self.searcher.get_database_stats()
        self.assert_real_output(stats)

        # Validate comprehensive statistics
        assert 'total_binaries' in stats
        assert 'total_patterns' in stats
        assert 'avg_file_size' in stats
        assert stats['total_binaries'] == len(test_binaries)
        assert stats['total_patterns'] > 0
        assert stats['avg_file_size'] > 0

        # Test similarity search across multiple binaries
        query_binary = str(test_binaries[0])
        similar_results = self.searcher.search_similar_binaries(query_binary, threshold=0.0)

        # Should find all binaries (including itself) with threshold 0.0
        assert len(similar_results) >= 1  # At least itself

        # Results should be properly sorted by similarity
        if len(similar_results) > 1:
            similarities = [r['similarity'] for r in similar_results]
            assert similarities == sorted(similarities, reverse=True), \
                "Results should be sorted by similarity (descending)"

    def test_performance_and_scalability_validation(self):
        """Test performance characteristics expected from production similarity searcher."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for performance testing")

        # Test feature extraction performance
        binary_path = self.sample_binary

        # Should complete feature extraction in reasonable time
        extraction_time = self.assert_performance_acceptable(
            lambda: self.searcher._extract_binary_features(binary_path),
            max_time=5.0  # 5 seconds for comprehensive feature extraction
        )

        # Test similarity calculation performance
        if len(self.pe_binaries) >= 2:
            features1 = self.searcher._extract_binary_features(str(self.pe_binaries[0]))
            features2 = self.searcher._extract_binary_features(str(self.pe_binaries[1]))

            # Similarity calculation should be fast
            similarity_time = self.assert_performance_acceptable(
                lambda: self.searcher._calculate_basic_similarity(features1, features2),
                max_time=1.0  # 1 second for similarity calculation
            )

        # Test database search performance with multiple entries
        for i, binary in enumerate((self.pe_binaries + self.elf_binaries)[:5]):
            patterns = [f"Performance test pattern {i}"]
            self.searcher.add_binary(str(binary), patterns)

        # Search should scale reasonably with database size
        search_time = self.assert_performance_acceptable(
            lambda: self.searcher.search_similar_binaries(self.sample_binary, threshold=0.1),
            max_time=3.0  # 3 seconds for search across 5+ binaries
        )

    def test_error_handling_and_robustness(self):
        """Test error handling and robustness of similarity searcher."""
        # Test with non-existent binary
        nonexistent_path = "/absolutely/does/not/exist.exe"

        # Feature extraction should handle missing files gracefully
        features = self.searcher._extract_binary_features(nonexistent_path)
        assert isinstance(features, dict)
        # Should return empty/default features, not crash

        # Adding non-existent binary should fail gracefully
        add_result = self.searcher.add_binary(nonexistent_path, ["test pattern"])
        assert add_result is False

        # Search with non-existent binary should return empty results
        search_results = self.searcher.search_similar_binaries(nonexistent_path)
        assert isinstance(search_results, list)
        assert len(search_results) == 0

        # Test with corrupted/invalid database
        corrupted_db = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        corrupted_db.write(b'{invalid json content}')
        corrupted_db.close()

        # Should handle corrupted database gracefully
        try:
            corrupted_searcher = SimilaritySearcher(corrupted_db.name)
            assert corrupted_searcher.database == {"binaries": []}
        finally:
            os.unlink(corrupted_db.name)

    def test_anti_placeholder_comprehensive_validation(self):
        """
        Comprehensive anti-placeholder validation tests.
        These tests MUST FAIL if the implementation contains stubs, mocks, or placeholders.
        """
        # Test 1: Method implementation validation
        searcher = SimilaritySearcher()

        # Should have real methods, not just pass statements
        public_methods = [method for method in dir(searcher) if not method.startswith('_') and callable(getattr(searcher, method))]
        assert len(public_methods) > 3, "Too few public methods - likely placeholder class"

        # Test 2: Feature extraction must produce varied, realistic data
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries for anti-placeholder testing")

        features = self.searcher._extract_binary_features(self.sample_binary)

        # Features should not be empty or hardcoded
        assert features != {}, "Empty features indicate placeholder implementation"
        assert features.get('file_size', 0) > 0, "Zero file size indicates placeholder feature extraction"

        # Entropy should be calculated, not hardcoded
        entropy = features.get('entropy', 0)
        assert entropy > 0, "Zero entropy indicates placeholder entropy calculation"
        assert entropy != 1.0, "Perfect entropy value likely hardcoded placeholder"

        # Test 3: Similarity calculation must produce realistic variance
        if len(self.pe_binaries) >= 2:
            features1 = self.searcher._extract_binary_features(str(self.pe_binaries[0]))
            features2 = self.searcher._extract_binary_features(str(self.pe_binaries[1]))

            similarity = self.searcher._calculate_basic_similarity(features1, features2)

            # Similarity should not be obvious placeholder values
            placeholder_values = [0.0, 0.25, 0.5, 0.75, 1.0]
            assert similarity not in placeholder_values, \
                    f"Similarity {similarity} appears to be placeholder value"

        # Test 4: Database operations must persist real data
        if self.pe_binaries or self.elf_binaries:
            test_binary = self.sample_binary
            unique_patterns = [f"Anti-placeholder test {time.time()}"]

            # Add should actually store data
            add_success = self.searcher.add_binary(test_binary, unique_patterns)
            assert add_success is True, "Failed to add binary - non-functional database"

            # Data should be retrievable
            assert len(self.searcher.database['binaries']) > 0, "No binaries in database after adding"

            # Stored data should match input
            stored_entry = self.searcher.database['binaries'][-1]  # Last added
            assert stored_entry['path'] == test_binary, "Stored path doesn't match input"
            assert stored_entry['cracking_patterns'] == unique_patterns, "Stored patterns don't match input"

        # Test 5: Statistics must reflect real database state
        stats = self.searcher.get_database_stats()
        assert isinstance(stats, dict), "Statistics should return dictionary"
        assert 'total_binaries' in stats, "Missing total_binaries in statistics"

        if len(self.searcher.database['binaries']) > 0:
            assert stats['total_binaries'] > 0, "Statistics don't reflect actual database contents"

            search_results = self.searcher.search_similar_binaries(
                self.sample_binary, threshold=0.0
            )

            assert isinstance(search_results, list), "Search should return list"

            if search_results:
                # Results should have required fields
                for result in search_results:
                    assert 'similarity' in result, "Search results missing similarity scores"
                    assert isinstance(result['similarity'], float), "Similarity should be float"

                # Results should be sorted by similarity
                if len(search_results) > 1:
                    similarities = [r['similarity'] for r in search_results]
                    assert similarities == sorted(similarities, reverse=True), \
                            "Search results not properly sorted - indicates placeholder search implementation"
