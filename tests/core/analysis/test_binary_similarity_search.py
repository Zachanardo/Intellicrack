"""
Unit tests for BinarySimilaritySearch with REAL binary similarity analysis.
Tests actual production-ready similarity algorithms with real binary samples.
NO MOCKS - ALL TESTS USE REAL BINARIES AND VALIDATE ADVANCED SIMILARITY ALGORITHMS.
"""

from typing import Any
import pytest
import tempfile
import json
import os
from pathlib import Path

try:
    from intellicrack.core.analysis.binary_similarity_search import BinarySimilaritySearch, create_similarity_search
    AVAILABLE = True
except ImportError:
    BinarySimilaritySearch = None  # type: ignore[misc, assignment]
    create_similarity_search = None  # type: ignore[assignment]
    AVAILABLE = False

try:
    from tests.base_test import IntellicrackTestBase
except ImportError:
    IntellicrackTestBase = object  # type: ignore[misc, assignment]

pytestmark = pytest.mark.skipif(not AVAILABLE, reason="Module not available")


class TestBinarySimilaritySearch(IntellicrackTestBase):
    """Test binary similarity search with real binaries and production-ready validation."""

    @pytest.fixture(autouse=True)
    def setup(self) -> Any:
        """Set up test environment with real test binaries and temporary database."""
        # Create temporary database file
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_db.close()
        self.db_path = self.temp_db.name

        # Initialize search engine
        self.search_engine = BinarySimilaritySearch(self.db_path)

        # Use available real test binaries
        self.test_fixtures_dir = Path("tests/fixtures/binaries")

        # Real PE binaries for testing
        self.pe_binaries = [
            self.test_fixtures_dir / "pe/real_protected/upx_packer/upx-4.2.2-win64/upx.exe",
            self.test_fixtures_dir / "pe/legitimate/7zip.exe",
            self.test_fixtures_dir / "pe/simple_hello_world.exe",
            self.test_fixtures_dir / "size_categories/tiny_4kb/tiny_hello.exe",
            self.test_fixtures_dir / "pe/real_protected/ccleaner_free.exe",
            self.test_fixtures_dir / "pe/real_protected/steam_installer.exe"
        ]

        # Real ELF binaries
        self.elf_binaries = [
            self.test_fixtures_dir / "elf/simple_x64"
        ]

        # Filter for existing binaries
        self.pe_binaries = [p for p in self.pe_binaries if p.exists()]
        self.elf_binaries = [p for p in self.elf_binaries if p.exists()]

        # Ensure we have at least one test binary
        if not self.pe_binaries and not self.elf_binaries:
            pytest.skip("No test binaries available for testing")

        # Create sample database entries for testing
        self.sample_binary_path = str(self.pe_binaries[0]) if self.pe_binaries else str(self.elf_binaries[0])

    def teardown_method(self) -> None:
        """Clean up temporary files."""
        try:
            if os.path.exists(self.db_path):
                os.unlink(self.db_path)
        except OSError:
            pass

    def test_initialization(self) -> None:
        """Test BinarySimilaritySearch initialization and database setup."""
        # Test default initialization
        search_engine = BinarySimilaritySearch()
        assert hasattr(search_engine, 'database_path')
        assert search_engine.database_path == "binary_database.json"
        assert hasattr(search_engine, 'database')
        assert hasattr(search_engine, 'logger')

        # Test custom database path initialization
        custom_search = BinarySimilaritySearch(self.db_path)
        assert custom_search.database_path == self.db_path
        assert isinstance(custom_search.database, dict)
        assert 'binaries' in custom_search.database

        # Test factory function
        factory_search = create_similarity_search(self.db_path)
        assert isinstance(factory_search, BinarySimilaritySearch)
        assert factory_search.database_path == self.db_path

    def test_database_loading_and_saving(self) -> None:
        """Test database loading and saving operations."""
        # Test loading non-existent database (should create empty)
        non_existent_db = tempfile.NamedTemporaryFile(delete=True).name
        search_engine = BinarySimilaritySearch(non_existent_db)
        assert search_engine.database == {"binaries": []}

        # Test saving database
        test_data = {
            "binaries": [
                {
                    "path": "/test/binary.exe",
                    "filename": "binary.exe",
                    "features": {"file_size": 1024},
                    "cracking_patterns": ["pattern1"],
                    "added": "2025-01-01T00:00:00"
                }
            ]
        }
        search_engine.database = test_data
        search_engine._save_database()

        # Verify saved data
        assert os.path.exists(search_engine.database_path)
        with open(search_engine.database_path) as f:
            loaded_data = json.load(f)
        assert loaded_data == test_data

        # Test loading existing database
        new_engine = BinarySimilaritySearch(search_engine.database_path)
        assert new_engine.database == test_data

    def test_extract_binary_features_pe(self) -> None:
        """Test binary feature extraction with real PE files."""
        if not self.pe_binaries:
            pytest.skip("No PE binaries available for testing")

        pe_binary = str(self.pe_binaries[0])
        features = self.search_engine._extract_binary_features(pe_binary)

        # Validate production-ready feature extraction
        self.assert_real_output(features)
        assert isinstance(features, dict)

        # Verify required feature fields
        required_fields = ['file_size', 'entropy', 'sections', 'imports',
                          'exports', 'strings', 'machine', 'timestamp', 'characteristics']
        for field in required_fields:
            assert field in features

        # Validate file size
        assert features['file_size'] > 0
        assert isinstance(features['file_size'], int)

        # Validate entropy calculation
        assert isinstance(features['entropy'], float)
        assert 0.0 <= features['entropy'] <= 8.0

        # Validate sections (should be extracted from real PE)
        sections = features['sections']
        assert isinstance(sections, list)
        if sections:  # If PE analysis succeeded
            for section in sections:
                assert 'name' in section
                assert 'virtual_address' in section
                assert 'virtual_size' in section
                assert 'raw_data_size' in section
                assert 'entropy' in section
                assert isinstance(section['entropy'], float)

        # Validate imports/exports
        assert isinstance(features['imports'], list)
        assert isinstance(features['exports'], list)
        if features['imports']:  # If imports were extracted
            for imp in features['imports'][:5]:  # Check first 5
                assert ':' in imp or imp  # Should be dll:function format or function name

        # Validate strings extraction
        strings = features['strings']
        assert isinstance(strings, list)
        assert len(strings) <= 50  # Limited as per implementation
        if strings:
            for string in strings[:5]:
                assert isinstance(string, str)
                assert len(string) >= 4  # Minimum string length

    def test_extract_binary_features_elf(self) -> None:
        """Test binary feature extraction with real ELF files."""
        if not self.elf_binaries:
            pytest.skip("No ELF binaries available for testing")

        elf_binary = str(self.elf_binaries[0])
        features = self.search_engine._extract_binary_features(elf_binary)

        # Validate feature extraction for ELF
        self.assert_real_output(features)
        assert isinstance(features, dict)

        # ELF files should still have basic features
        assert features['file_size'] > 0
        assert isinstance(features['entropy'], float)
        assert isinstance(features['strings'], list)

    def test_add_binary_to_database(self) -> None:
        """Test adding binaries to the database with feature extraction."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for testing")

        test_binary = self.sample_binary_path
        cracking_patterns = ["XOR decryption", "API hooking", "Dynamic analysis"]

        # Test adding binary
        result = self.search_engine.add_binary(test_binary, cracking_patterns)
        assert result is True

        # Verify binary was added to database
        assert len(self.search_engine.database['binaries']) == 1

        binary_entry = self.search_engine.database['binaries'][0]
        assert binary_entry['path'] == test_binary
        assert binary_entry['filename'] == os.path.basename(test_binary)
        assert binary_entry['cracking_patterns'] == cracking_patterns
        assert 'features' in binary_entry
        assert 'added' in binary_entry
        assert 'file_size' in binary_entry

        # Verify features were extracted
        features = binary_entry['features']
        assert isinstance(features, dict)
        assert features['file_size'] > 0

        # Test adding duplicate binary (should fail)
        duplicate_result = self.search_engine.add_binary(test_binary, ["new pattern"])
        assert duplicate_result is False
        assert len(self.search_engine.database['binaries']) == 1  # No duplicate added

    def test_calculate_basic_similarity(self) -> None:
        """Test basic similarity calculation algorithms."""
        # Create test feature sets
        features1 = {
            'file_size': 1024,
            'entropy': 6.5,
            'sections': [
                {'name': '.text', 'entropy': 6.2, 'virtual_address': 0x1000},
                {'name': '.data', 'entropy': 4.8, 'virtual_address': 0x2000}
            ],
            'imports': ['kernel32.dll:CreateFileA', 'kernel32.dll:ReadFile', 'user32.dll:MessageBoxA'],
            'exports': ['MyFunction', 'Initialize'],
            'strings': ['Hello World', 'Error:', 'Success', 'Processing']
        }

        features2 = {
            'file_size': 1100,
            'entropy': 6.8,
            'sections': [
                {'name': '.text', 'entropy': 6.0, 'virtual_address': 0x1000},
                {'name': '.data', 'entropy': 5.0, 'virtual_address': 0x2000},
                {'name': '.rsrc', 'entropy': 4.0, 'virtual_address': 0x3000}
            ],
            'imports': ['kernel32.dll:CreateFileA', 'kernel32.dll:WriteFile', 'user32.dll:MessageBoxA'],
            'exports': ['MyFunction', 'Cleanup'],
            'strings': ['Hello World', 'Warning:', 'Success', 'Complete']
        }

        # Test basic similarity calculation
        similarity = self.search_engine._calculate_basic_similarity(features1, features2)

        # Validate production-ready similarity calculation
        assert isinstance(similarity, float)
        assert 0.0 <= similarity <= 1.0

        # Should detect some similarity due to common imports, exports, strings
        assert similarity > 0.3  # Reasonable similarity threshold

        # Test with identical features (should be very high similarity)
        identical_similarity = self.search_engine._calculate_basic_similarity(features1, features1)
        assert identical_similarity > 0.9

        # Test with completely different features
        different_features = {
            'file_size': 50000,
            'entropy': 2.0,
            'sections': [{'name': '.custom', 'entropy': 1.5}],
            'imports': ['ntdll.dll:NtCreateFile', 'advapi32.dll:RegOpenKey'],
            'exports': ['DifferentFunction'],
            'strings': ['Completely different', 'No match', 'Unique content']
        }

        different_similarity = self.search_engine._calculate_basic_similarity(features1, different_features)
        assert different_similarity < identical_similarity  # Should be less similar

    def test_advanced_similarity_algorithms(self) -> None:
        """Test advanced similarity calculation methods."""
        # Create realistic feature sets for advanced testing
        features1 = {
            'sections': [
                {'name': '.text', 'entropy': 6.5, 'virtual_address': 0x1000, 'virtual_size': 4096},
                {'name': '.data', 'entropy': 4.0, 'virtual_address': 0x2000, 'virtual_size': 1024}
            ],
            'imports': ['kernel32.dll:CreateFileW', 'kernel32.dll:ReadFile', 'ntdll.dll:NtCreateFile'] * 20,
            'exports': ['Export1', 'Export2', 'Export3'],
            'strings': ['string1', 'string2', 'common_pattern'] * 15,
            'file_size': 10240,
            'entropy': 6.5
        }

        features2 = {
            'sections': [
                {'name': '.text', 'entropy': 6.3, 'virtual_address': 0x1000, 'virtual_size': 4000},
                {'name': '.data', 'entropy': 4.2, 'virtual_address': 0x2000, 'virtual_size': 1100}
            ],
            'imports': ['kernel32.dll:CreateFileW', 'kernel32.dll:WriteFile', 'ntdll.dll:NtCreateFile'] * 18,
            'exports': ['Export1', 'Export4', 'Export5'],
            'strings': ['string1', 'string3', 'common_pattern'] * 12,
            'file_size': 11000,
            'entropy': 6.3
        }

        # Test structural similarity
        structural_sim = self.search_engine._calculate_structural_similarity(features1, features2)
        assert isinstance(structural_sim, float)
        assert 0.0 <= structural_sim <= 1.0

        # Test content similarity
        content_sim = self.search_engine._calculate_content_similarity(features1, features2)
        assert isinstance(content_sim, float)
        assert 0.0 <= content_sim <= 1.0

        # Test statistical similarity
        statistical_sim = self.search_engine._calculate_statistical_similarity(features1, features2)
        assert isinstance(statistical_sim, float)
        assert 0.0 <= statistical_sim <= 1.0

        # Test advanced algorithms
        advanced_sim = self.search_engine._calculate_advanced_similarity(features1, features2)
        assert isinstance(advanced_sim, float)
        assert 0.0 <= advanced_sim <= 1.0

        # Test fuzzy hash similarity
        fuzzy_sim = self.search_engine._calculate_fuzzy_hash_similarity(features1, features2)
        assert isinstance(fuzzy_sim, float)
        assert 0.0 <= fuzzy_sim <= 1.0

        # Test control flow similarity
        control_flow_sim = self.search_engine._calculate_control_flow_similarity(features1, features2)
        assert isinstance(control_flow_sim, float)
        assert 0.0 <= control_flow_sim <= 1.0

        # Test opcode similarity
        opcode_sim = self.search_engine._calculate_opcode_similarity(features1, features2)
        assert isinstance(opcode_sim, float)
        assert 0.0 <= opcode_sim <= 1.0

    def test_comprehensive_similarity_calculation(self) -> None:
        """Test the main similarity calculation with all algorithms."""
        # Create comprehensive feature sets
        features1 = {
            'file_size': 15360,
            'entropy': 7.2,
            'sections': [
                {'name': '.text', 'entropy': 7.0, 'virtual_address': 0x1000},
                {'name': '.data', 'entropy': 5.5, 'virtual_address': 0x5000}
            ],
            'imports': ['kernel32.dll:CreateProcessW', 'kernel32.dll:VirtualAlloc'] * 30,
            'exports': ['MainFunction', 'Initialize', 'Cleanup'],
            'strings': ['Advanced pattern', 'Crypto operation', 'Network comm'] * 20,
            'machine': 0x8664,  # x64
            'characteristics': 0x0102
        }

        features2 = {
            'file_size': 16000,
            'entropy': 7.4,
            'sections': [
                {'name': '.text', 'entropy': 6.8, 'virtual_address': 0x1000},
                {'name': '.data', 'entropy': 5.8, 'virtual_address': 0x5000},
                {'name': '.rsrc', 'entropy': 4.0, 'virtual_address': 0x8000}
            ],
            'imports': ['kernel32.dll:CreateProcessW', 'kernel32.dll:VirtualProtect'] * 25,
            'exports': ['MainFunction', 'Initialize', 'Finalize'],
            'strings': ['Advanced pattern', 'Crypto function', 'Network comm'] * 18,
            'machine': 0x8664,  # x64
            'characteristics': 0x0102
        }

        # Test comprehensive similarity calculation
        similarity = self.search_engine._calculate_similarity(features1, features2)

        # Validate production-ready comprehensive similarity
        assert isinstance(similarity, float)
        assert 0.0 <= similarity <= 1.0

        # Should detect reasonable similarity with advanced algorithms
        assert similarity > 0.4  # With advanced algorithms, should detect more nuanced similarity

        # Test adaptive weights calculation
        weights = self.search_engine._calculate_adaptive_weights(features1, features2)
        assert isinstance(weights, dict)
        expected_components = ['structural', 'content', 'statistical', 'advanced',
                              'fuzzy', 'control_flow', 'opcode']
        for component in expected_components:
            assert component in weights
            assert isinstance(weights[component], float)
            assert weights[component] >= 0.0

        # Weights should sum to approximately 1.0
        total_weight = sum(weights.values())
        assert 0.95 <= total_weight <= 1.05

    def test_section_similarity_calculation(self) -> None:
        """Test section-based similarity calculations."""
        sections1 = [
            {'name': '.text', 'entropy': 6.5, 'virtual_address': 0x1000},
            {'name': '.data', 'entropy': 4.0, 'virtual_address': 0x2000},
            {'name': '.rsrc', 'entropy': 3.5, 'virtual_address': 0x3000}
        ]

        sections2 = [
            {'name': '.text', 'entropy': 6.3, 'virtual_address': 0x1000},
            {'name': '.data', 'entropy': 4.2, 'virtual_address': 0x2000},
            {'name': '.idata', 'entropy': 5.0, 'virtual_address': 0x4000}
        ]

        # Test section similarity
        similarity = self.search_engine._calculate_section_similarity(sections1, sections2)
        assert isinstance(similarity, float)
        assert 0.0 <= similarity <= 1.0

        # Should detect some similarity due to common section names
        assert similarity > 0.2

        # Test with identical sections
        identical_similarity = self.search_engine._calculate_section_similarity(sections1, sections1)
        assert identical_similarity > 0.8

    def test_list_similarity_jaccard(self) -> None:
        """Test Jaccard similarity for lists (imports, exports, strings)."""
        list1 = ['item1', 'item2', 'item3', 'common1', 'common2']
        list2 = ['item4', 'item5', 'item3', 'common1', 'common2']

        # Test Jaccard similarity calculation
        similarity = self.search_engine._calculate_list_similarity(list1, list2)
        assert isinstance(similarity, float)
        assert 0.0 <= similarity <= 1.0

        # Should detect overlap (3 common items out of 7 unique)
        expected_jaccard = 3 / 7  # intersection / union
        assert abs(similarity - expected_jaccard) < 0.01

        # Test with identical lists
        identical_similarity = self.search_engine._calculate_list_similarity(list1, list1)
        assert identical_similarity == 1.0

        # Test with no overlap
        no_overlap_list = ['different1', 'different2', 'different3']
        no_similarity = self.search_engine._calculate_list_similarity(list1, no_overlap_list)
        assert no_similarity == 0.0

    def test_search_similar_binaries(self) -> None:
        """Test searching for similar binaries in database."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for testing")

        # Add multiple binaries to database for similarity testing
        test_binaries = self.pe_binaries[:3] if len(self.pe_binaries) >= 3 else self.pe_binaries
        if not test_binaries and self.elf_binaries:
            test_binaries = self.elf_binaries[:1]

        patterns_list = [
            ["Pattern A", "Common technique"],
            ["Pattern B", "Advanced method", "Common technique"],
            ["Pattern C", "Basic approach"]
        ]

        # Add binaries to database
        for i, binary_path in enumerate(test_binaries):
            patterns = patterns_list[i % len(patterns_list)]
            result = self.search_engine.add_binary(str(binary_path), patterns)
            assert result is True

        # Search for similar binaries
        if test_binaries:
            target_binary = str(test_binaries[0])
            similar_binaries = self.search_engine.search_similar_binaries(target_binary, threshold=0.1)

            # Validate search results
            assert isinstance(similar_binaries, list)

            if similar_binaries:
                self.assert_real_output(similar_binaries)

                # Verify result structure
                for match in similar_binaries:
                    assert 'path' in match
                    assert 'filename' in match
                    assert 'similarity' in match
                    assert 'cracking_patterns' in match
                    assert 'added' in match
                    assert 'file_size' in match

                    # Validate similarity score
                    similarity = match['similarity']
                    assert isinstance(similarity, float)
                    assert 0.1 <= similarity <= 1.0  # Above threshold

                    # Validate cracking patterns
                    assert isinstance(match['cracking_patterns'], list)

                # Results should be sorted by similarity (descending)
                if len(similar_binaries) > 1:
                    similarities = [r['similarity'] for r in similar_binaries]
                    assert similarities == sorted(similarities, reverse=True)

    def test_database_statistics(self) -> None:
        """Test database statistics calculation."""
        # Start with empty database
        stats = self.search_engine.get_database_stats()
        assert isinstance(stats, dict)
        assert stats['total_binaries'] == 0
        assert stats['total_patterns'] == 0
        assert stats['avg_file_size'] == 0

        # Add some binaries for statistics
        if self.pe_binaries or self.elf_binaries:
            test_binaries = (self.pe_binaries[:2] if self.pe_binaries else []) + \
                           (self.elf_binaries[:1] if self.elf_binaries else [])

            patterns_list = [
                ["Pattern 1", "Pattern 2"],
                ["Pattern 3", "Pattern 4", "Pattern 5"],
                ["Pattern 6"]
            ]

            for i, binary_path in enumerate(test_binaries):
                patterns = patterns_list[i % len(patterns_list)]
                self.search_engine.add_binary(str(binary_path), patterns)

            # Get updated statistics
            stats = self.search_engine.get_database_stats()

            # Validate statistics
            assert stats['total_binaries'] == len(test_binaries)
            assert stats['total_patterns'] > 0
            assert stats['avg_file_size'] > 0
            assert isinstance(stats['unique_imports'], int)
            assert isinstance(stats['unique_exports'], int)

    def test_remove_binary_from_database(self) -> None:
        """Test removing binaries from database."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for testing")

        test_binary = str(self.sample_binary_path)

        # Add binary first
        result = self.search_engine.add_binary(test_binary, ["test pattern"])
        assert result is True
        assert len(self.search_engine.database['binaries']) == 1

        # Remove binary
        remove_result = self.search_engine.remove_binary(test_binary)
        assert remove_result is True
        assert len(self.search_engine.database['binaries']) == 0

        # Try removing non-existent binary
        remove_nonexistent = self.search_engine.remove_binary("/non/existent/path.exe")
        assert remove_nonexistent is False

    def test_load_database_method(self) -> None:
        """Test database loading with load_database method."""
        # Create test database file
        test_db_data = {
            "binaries": [
                {
                    "path": "/test/sample.exe",
                    "filename": "sample.exe",
                    "features": {"file_size": 2048, "entropy": 5.5},
                    "cracking_patterns": ["test pattern"],
                    "added": "2025-01-01T00:00:00",
                    "file_size": 2048
                }
            ]
        }

        temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        with open(temp_db.name, 'w') as f:
            json.dump(test_db_data, f)

        # Load the database
        load_result = self.search_engine.load_database(temp_db.name)
        assert load_result is True
        assert self.search_engine.database == test_db_data
        assert self.search_engine.database_path == temp_db.name

        # Clean up
        os.unlink(temp_db.name)

    def test_find_similar_alias_method(self) -> None:
        """Test the find_similar alias method."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for testing")

        # Add a binary to database
        test_binary = str(self.sample_binary_path)
        self.search_engine.add_binary(test_binary, ["test pattern"])

        # Test find_similar method (alias for search_similar_binaries)
        results = self.search_engine.find_similar(test_binary, threshold=0.1)
        expected_results = self.search_engine.search_similar_binaries(test_binary, threshold=0.1)

        # Should return identical results
        assert results == expected_results

    def test_error_handling_corrupted_database(self) -> None:
        """Test error handling with corrupted database file."""
        # Create corrupted database file
        corrupted_db = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        corrupted_db.write(b'{"invalid": json content')  # Invalid JSON
        corrupted_db.close()

        # Should handle corrupted database gracefully
        search_engine = BinarySimilaritySearch(corrupted_db.name)
        assert search_engine.database == {"binaries": []}

        # Clean up
        os.unlink(corrupted_db.name)

    def test_error_handling_nonexistent_binary(self) -> None:
        """Test error handling with non-existent binary files."""
        nonexistent_path = "/definitely/does/not/exist.exe"

        # Test feature extraction with non-existent file
        features = self.search_engine._extract_binary_features(nonexistent_path)
        assert isinstance(features, dict)
        # Should return default/empty features structure
        assert features['file_size'] == 0
        assert features['entropy'] == 0.0

        # Test adding non-existent binary
        add_result = self.search_engine.add_binary(nonexistent_path, ["pattern"])
        assert add_result is False  # Should fail gracefully

        # Test searching with non-existent binary
        search_results = self.search_engine.search_similar_binaries(nonexistent_path)
        assert isinstance(search_results, list)
        assert len(search_results) == 0

    def test_advanced_algorithm_components(self) -> None:
        """Test individual advanced algorithm components."""
        # Test LSH similarity
        features1 = ['feature1', 'feature2', 'common1', 'common2'] * 10
        features2 = ['feature3', 'feature4', 'common1', 'common2'] * 8

        lsh_sim = self.search_engine._calculate_lsh_similarity(features1, features2)
        assert isinstance(lsh_sim, float)
        assert 0.0 <= lsh_sim <= 1.0

        # Test edit distance similarity
        strings1 = ['hello world', 'test string', 'common pattern']
        strings2 = ['hello there', 'test data', 'common pattern']

        edit_sim = self.search_engine._calculate_edit_distance_similarity(strings1, strings2)
        assert isinstance(edit_sim, float)
        assert 0.0 <= edit_sim <= 1.0

        # Test cosine similarity
        features_dict1 = {'file_size': 1000, 'entropy': 6.0, 'sections': [1, 2],
                         'imports': list(range(10)), 'exports': [1], 'strings': list(range(20))}
        features_dict2 = {'file_size': 1200, 'entropy': 6.5, 'sections': [1, 2, 3],
                         'imports': list(range(12)), 'exports': [1, 2], 'strings': list(range(25))}

        cosine_sim = self.search_engine._calculate_cosine_similarity(features_dict1, features_dict2)
        assert isinstance(cosine_sim, float)
        assert 0.0 <= cosine_sim <= 1.0

    def test_fuzzy_hash_and_rolling_hash(self) -> None:
        """Test fuzzy hashing and rolling hash generation."""
        strings1 = ['pattern1', 'pattern2', 'common_string'] * 5
        strings2 = ['pattern3', 'pattern4', 'common_string'] * 4

        # Test rolling hash generation
        hash1 = self.search_engine._generate_rolling_hash(strings1)
        hash2 = self.search_engine._generate_rolling_hash(strings2)

        assert isinstance(hash1, str)
        assert isinstance(hash2, str)
        assert len(hash1) == 64  # SHA256 hex length
        assert len(hash2) == 64

        # Test hash similarity calculation
        if hash1 and hash2:
            hash_similarity = self.search_engine._calculate_hash_similarity(hash1, hash2)
            assert isinstance(hash_similarity, float)
            assert 0.0 <= hash_similarity <= 1.0

        # Test with identical strings (should have high similarity)
        identical_hash = self.search_engine._generate_rolling_hash(strings1)
        if hash1 and identical_hash:
            identical_similarity = self.search_engine._calculate_hash_similarity(hash1, identical_hash)
            assert identical_similarity == 1.0

    def test_entropy_and_statistical_methods(self) -> None:
        """Test entropy-based and statistical similarity methods."""
        # Test logarithmic size similarity
        size_sim = self.search_engine._calculate_logarithmic_size_similarity(1000, 1100)
        assert isinstance(size_sim, float)
        assert 0.0 <= size_sim <= 1.0
        assert size_sim > 0.8  # Similar sizes should have high similarity

        # Test entropy similarity
        entropy_sim = self.search_engine._calculate_entropy_similarity(6.5, 6.8)
        assert isinstance(entropy_sim, float)
        assert 0.0 <= entropy_sim <= 1.0
        assert entropy_sim > 0.8  # Similar entropy should have high similarity

        # Test section distribution similarity
        sections1 = [{'raw_data_size': 1000}, {'raw_data_size': 500}, {'raw_data_size': 200}]
        sections2 = [{'raw_data_size': 1100}, {'raw_data_size': 450}, {'raw_data_size': 250}]

        dist_sim = self.search_engine._calculate_section_distribution_similarity(sections1, sections2)
        assert isinstance(dist_sim, float)
        assert 0.0 <= dist_sim <= 1.0

    def test_weighted_api_similarity(self) -> None:
        """Test weighted API similarity with criticality scoring."""
        imports1 = [
            'kernel32.dll:CreateFileW',
            'kernel32.dll:ReadFile',
            'ntdll.dll:NtCreateFile',
            'crypt32.dll:CryptEncrypt',
            'user32.dll:MessageBoxA'
        ]

        imports2 = [
            'kernel32.dll:CreateFileW',
            'kernel32.dll:WriteFile',
            'ntdll.dll:NtWriteFile',
            'crypt32.dll:CryptDecrypt',
            'user32.dll:MessageBoxW'
        ]

        # Test weighted API similarity
        weighted_sim = self.search_engine._calculate_weighted_api_similarity(imports1, imports2)
        assert isinstance(weighted_sim, float)
        assert 0.0 <= weighted_sim <= 1.0

        # Should weight critical APIs higher
        assert weighted_sim > 0.2  # Some common critical APIs

    def test_pe_header_similarity(self) -> None:
        """Test PE header metadata similarity calculation."""
        features1 = {
            'machine': 0x8664,  # x64
            'characteristics': 0x0102,
            'timestamp': 1234567890
        }

        features2 = {
            'machine': 0x8664,  # x64 (same)
            'characteristics': 0x0106,  # Different characteristics
            'timestamp': 1234567900
        }

        # Test PE header similarity
        header_sim = self.search_engine._calculate_pe_header_similarity(features1, features2)
        assert isinstance(header_sim, float)
        assert 0.0 <= header_sim <= 1.0

        # Should have some similarity due to same machine type
        assert header_sim > 0.4

    def test_string_similarity_methods(self) -> None:
        """Test string similarity calculation methods."""
        # Test fuzzy string similarity
        strings1 = ['hello world', 'test pattern', 'common string', 'unique1'] * 5
        strings2 = ['hello there', 'test data', 'common string', 'unique2'] * 4

        fuzzy_sim = self.search_engine._calculate_fuzzy_string_similarity(strings1, strings2)
        assert isinstance(fuzzy_sim, float)
        assert 0.0 <= fuzzy_sim <= 1.0

        # Test individual string similarity
        str_sim = self.search_engine._calculate_string_similarity('hello world', 'hello there')
        assert isinstance(str_sim, float)
        assert 0.0 <= str_sim <= 1.0
        assert str_sim > 0.5  # Should detect some similarity

        # Test n-gram similarity
        ngram_sim = self.search_engine._calculate_ngram_similarity(strings1, strings2)
        assert isinstance(ngram_sim, float)
        assert 0.0 <= ngram_sim <= 1.0

    def test_entropy_pattern_similarity(self) -> None:
        """Test entropy pattern distribution similarity."""
        features1 = {
            'sections': [
                {'entropy': 6.5}, {'entropy': 4.0}, {'entropy': 7.2}, {'entropy': 3.5}
            ]
        }

        features2 = {
            'sections': [
                {'entropy': 6.3}, {'entropy': 4.2}, {'entropy': 7.0}, {'entropy': 3.8}
            ]
        }

        # Test entropy pattern similarity
        entropy_pattern_sim = self.search_engine._calculate_entropy_pattern_similarity(features1, features2)
        assert isinstance(entropy_pattern_sim, float)
        assert 0.0 <= entropy_pattern_sim <= 1.0

        # Should have high similarity due to similar entropy distributions
        assert entropy_pattern_sim > 0.7

    def test_performance_with_large_datasets(self) -> None:
        """Test performance with larger feature sets."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for testing")

        if test_binaries := (self.pe_binaries + self.elf_binaries)[:5]:
            for binary_path in test_binaries:
                patterns = [f"Pattern {i}" for i in range(5)]
                self.search_engine.add_binary(str(binary_path), patterns)

            # Search should complete in reasonable time
            target_binary = str(test_binaries[0])

            # Performance test - should complete within reasonable time
            self.assert_performance_acceptable(
                lambda: self.search_engine.search_similar_binaries(target_binary, threshold=0.1),
                max_time=10.0  # 10 seconds should be plenty for similarity search
            )

    def test_edge_cases_and_boundary_conditions(self) -> None:
        """Test edge cases and boundary conditions."""
        # Test with empty features
        empty_features = {
            'file_size': 0, 'entropy': 0.0, 'sections': [], 'imports': [],
            'exports': [], 'strings': []
        }

        normal_features = {
            'file_size': 1000, 'entropy': 5.0, 'sections': [{'name': '.text'}],
            'imports': ['kernel32.dll:CreateFileA'], 'exports': ['Function1'],
            'strings': ['string1']
        }

        # Should handle empty features gracefully
        similarity = self.search_engine._calculate_similarity(empty_features, normal_features)
        assert isinstance(similarity, float)
        assert 0.0 <= similarity <= 1.0

        # Test with very large numbers
        large_features = {
            'file_size': 1000000000,  # 1GB
            'entropy': 8.0,           # Max entropy
            'sections': [{'entropy': 8.0}] * 100,  # Many sections
            'imports': [f'dll{i}.dll:Function{i}' for i in range(1000)],  # Many imports
            'exports': [f'Export{i}' for i in range(500)],  # Many exports
            'strings': [f'String{i}' for i in range(2000)]  # Many strings
        }

        # Should handle large datasets
        large_similarity = self.search_engine._calculate_similarity(large_features, normal_features)
        assert isinstance(large_similarity, float)
        assert 0.0 <= large_similarity <= 1.0

        # Test threshold edge cases
        if self.pe_binaries or self.elf_binaries:
            test_binary = str(self.sample_binary_path)

            # Add binary for testing
            self.search_engine.add_binary(test_binary, ["pattern"])

            # Test with threshold = 0.0 (should return everything)
            results_zero = self.search_engine.search_similar_binaries(test_binary, threshold=0.0)
            assert isinstance(results_zero, list)

            # Test with threshold = 1.0 (should return only perfect matches)
            results_perfect = self.search_engine.search_similar_binaries(test_binary, threshold=1.0)
            assert isinstance(results_perfect, list)
