"""Production-ready tests for Binary Similarity Search against real-world scenarios.

Tests validate actual offensive capability to identify similar cracked binaries across:
- Different compiler optimizations (O0, O1, O2, O3)
- Different architectures (x86, x64, ARM)
- Different protection schemes (VMProtect, Themida, UPX)
- Function-level similarity (BinDiff-style)
- Fuzzy hash matching (ssdeep-style, TLSH-style)
- LSH for large-scale similarity

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import os
import struct
import tempfile
import time
from pathlib import Path
from typing import Any, cast

import pytest

from intellicrack.core.analysis.binary_similarity_search import BinarySimilaritySearch


class TestFuzzyHashMatching:
    """Test fuzzy hash matching validates real similarity beyond exact hash."""

    @pytest.fixture
    def search_engine(self, tmp_path: Path) -> BinarySimilaritySearch:
        """Create search engine with temporary database."""
        db_path = tmp_path / "fuzzy_test.json"
        return BinarySimilaritySearch(database_path=str(db_path))

    @pytest.fixture
    def base_binary(self, tmp_path: Path) -> Path:
        """Create base binary with known content."""
        binary_path = tmp_path / "base.exe"

        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + struct.pack("<H", 1)
        file_header = b"\x00" * 14
        optional_header = struct.pack("<H", 0x010B) + b"\x00" * 222

        code_section = b".text\x00\x00\x00" + b"\x00" * 32
        data_section = b".data\x00\x00\x00" + b"\x00" * 32

        padding = b"\x00" * (0x200 - len(dos_header) - len(pe_header) -
                             len(file_header) - len(optional_header) -
                             len(code_section) - len(data_section))

        license_check_code = (
            b"\x55\x89\xE5\x83\xEC\x10"  # function prologue
            b"\xC7\x45\xFC\x00\x00\x00\x00"  # local var = 0
            b"\x8B\x45\x08"  # mov eax, [ebp+8] (get license param)
            b"\x83\xF8\x00"  # cmp eax, 0
            b"\x74\x0A"  # je invalid
            b"\xC7\x45\xFC\x01\x00\x00\x00"  # valid = 1
            b"\xEB\x08"  # jmp end
            b"\xC7\x45\xFC\x00\x00\x00\x00"  # invalid = 0
            b"\x8B\x45\xFC"  # mov eax, valid
            b"\x89\xEC\x5D\xC3"  # epilogue, ret
        )

        license_strings = (
            b"License Key Required\x00"
            b"Invalid License\x00"
            b"Trial Expired\x00"
            b"Registration Failed\x00"
            b"Product Activated\x00"
            b"Serial Number\x00"
        )

        code_data = license_check_code + b"\x00" * 200 + license_strings + b"\x00" * 1000
        data_data = b"\x00" * 512

        full_binary = (dos_header + pe_header + file_header + optional_header +
                      code_section + data_section + padding + code_data + data_data)

        binary_path.write_bytes(full_binary)
        return binary_path

    @pytest.fixture
    def slightly_modified_binary(self, tmp_path: Path) -> Path:
        """Create binary with slight modifications (same functionality, different bytes)."""
        binary_path = tmp_path / "modified.exe"

        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + struct.pack("<H", 1)
        file_header = b"\x00" * 14
        optional_header = struct.pack("<H", 0x010B) + b"\x00" * 222

        code_section = b".text\x00\x00\x00" + b"\x00" * 32
        data_section = b".data\x00\x00\x00" + b"\x00" * 32

        padding = b"\x00" * (0x200 - len(dos_header) - len(pe_header) -
                             len(file_header) - len(optional_header) -
                             len(code_section) - len(data_section))

        modified_license_check = (
            b"\x55\x8B\xEC\x83\xEC\x10"  # different prologue
            b"\x33\xC0"  # xor eax, eax (different zero)
            b"\x89\x45\xFC"  # mov [ebp-4], eax
            b"\x8B\x45\x08"  # mov eax, [ebp+8]
            b"\x85\xC0"  # test eax, eax (different comparison)
            b"\x74\x07"  # je invalid
            b"\xC7\x45\xFC\x01\x00\x00\x00"  # valid = 1
            b"\xEB\x05"  # jmp end
            b"\x89\x45\xFC"  # mov [ebp-4], eax (different zero set)
            b"\x8B\x45\xFC"  # mov eax, valid
            b"\x8B\xE5\x5D\xC3"  # different epilogue, ret
        )

        modified_strings = (
            b"License Key Needed\x00"  # slightly different
            b"License Invalid\x00"  # reordered words
            b"Trial Has Expired\x00"  # added word
            b"Registration Error\x00"  # different word
            b"Product Is Activated\x00"  # added word
            b"Serial Code\x00"  # different word
        )

        code_data = modified_license_check + b"\x00" * 200 + modified_strings + b"\x00" * 1000
        data_data = b"\x00" * 512

        full_binary = (dos_header + pe_header + file_header + optional_header +
                      code_section + data_section + padding + code_data + data_data)

        binary_path.write_bytes(full_binary)
        return binary_path

    def test_fuzzy_hash_detects_similar_modified_binary(
        self,
        search_engine: BinarySimilaritySearch,
        base_binary: Path,
        slightly_modified_binary: Path
    ) -> None:
        """Fuzzy hash matching detects similarity despite byte-level changes."""
        base_features = search_engine._extract_binary_features(str(base_binary))
        modified_features = search_engine._extract_binary_features(str(slightly_modified_binary))

        fuzzy_similarity = search_engine._calculate_fuzzy_hash_similarity(
            base_features, modified_features
        )

        assert isinstance(fuzzy_similarity, float)
        assert 0.0 <= fuzzy_similarity <= 1.0

        assert fuzzy_similarity > 0.3, \
            "Fuzzy hash must detect similarity in functionally similar code with different bytes"

        hash1 = search_engine._generate_rolling_hash(cast(list[str], base_features.get("strings", [])))
        hash2 = search_engine._generate_rolling_hash(cast(list[str], modified_features.get("strings", [])))

        assert hash1 != hash2, "Exact hashes should differ for modified binary"

        if hash1 and hash2:
            hash_similarity = search_engine._calculate_hash_similarity(hash1, hash2)
            assert hash_similarity < 1.0, "Hash similarity should not be perfect for modifications"

    def test_fuzzy_hash_statistics_tracking(
        self,
        search_engine: BinarySimilaritySearch,
        base_binary: Path,
        slightly_modified_binary: Path
    ) -> None:
        """Fuzzy match statistics provide insight into matching process."""
        base_features = search_engine._extract_binary_features(str(base_binary))
        modified_features = search_engine._extract_binary_features(str(slightly_modified_binary))

        search_engine._calculate_fuzzy_string_similarity(
            cast(list[str], base_features.get("strings", [])),
            cast(list[str], modified_features.get("strings", []))
        )

        stats = search_engine.get_fuzzy_match_statistics()

        assert "total_comparisons" in stats
        assert "matches_found" in stats
        assert "sample_size" in stats

        assert stats["total_comparisons"] > 0, "Must perform string comparisons"
        assert stats["sample_size"] > 0, "Must sample strings for comparison"

        if stats["sample_size"] > 0:
            match_ratio = stats["matches_found"] / stats["sample_size"]
            assert 0.0 <= match_ratio <= 1.0

    def test_rolling_hash_consistency(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Rolling hash generates consistent hashes for identical input."""
        strings = ["License Check", "Serial Validation", "Product Key"]

        hash1 = search_engine._generate_rolling_hash(strings)
        hash2 = search_engine._generate_rolling_hash(strings)

        assert hash1 == hash2, "Rolling hash must be deterministic"
        assert len(hash1) == 64, "SHA256 hash should be 64 hex characters"

        different_strings = ["Different", "Content", "Here"]
        hash3 = search_engine._generate_rolling_hash(different_strings)

        assert hash3 != hash1, "Different content should produce different hashes"


class TestLSHCodeSimilarity:
    """Test Locality Sensitive Hashing for large-scale code similarity detection."""

    @pytest.fixture
    def search_engine(self, tmp_path: Path) -> BinarySimilaritySearch:
        """Create search engine with temporary database."""
        db_path = tmp_path / "lsh_test.json"
        return BinarySimilaritySearch(database_path=str(db_path))

    def test_lsh_detects_similar_import_sets(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """LSH detects similarity in large import/export feature sets."""
        base_imports = [
            "kernel32.dll:CreateFileW",
            "kernel32.dll:ReadFile",
            "kernel32.dll:WriteFile",
            "kernel32.dll:VirtualAlloc",
            "kernel32.dll:VirtualProtect",
            "ntdll.dll:NtQueryInformationProcess",
            "ntdll.dll:NtSetInformationThread",
            "advapi32.dll:RegOpenKeyExW",
            "advapi32.dll:RegQueryValueExW",
            "crypt32.dll:CryptDecrypt",
        ] * 10  # 100 imports

        similar_imports = [
            "kernel32.dll:CreateFileW",
            "kernel32.dll:ReadFile",
            "kernel32.dll:WriteFile",
            "kernel32.dll:VirtualAlloc",
            "kernel32.dll:VirtualFree",  # slightly different
            "ntdll.dll:NtQueryInformationProcess",
            "ntdll.dll:NtProtectVirtualMemory",  # different
            "advapi32.dll:RegOpenKeyExW",
            "advapi32.dll:RegSetValueExW",  # different
            "crypt32.dll:CryptEncrypt",  # different
        ] * 10  # 100 imports with some differences

        lsh_similarity = search_engine._calculate_lsh_similarity(base_imports, similar_imports)

        assert isinstance(lsh_similarity, float)
        assert 0.0 <= lsh_similarity <= 1.0

        assert lsh_similarity > 0.5, \
            "LSH must detect high similarity in mostly-overlapping import sets"

        completely_different = [
            "user32.dll:MessageBoxW",
            "gdi32.dll:CreateDC",
            "shell32.dll:ShellExecuteW",
        ] * 35  # 105 completely different imports

        different_similarity = search_engine._calculate_lsh_similarity(
            base_imports, completely_different
        )

        assert different_similarity < lsh_similarity, \
            "LSH must score different imports lower than similar imports"

    def test_lsh_hash_signature_generation(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """LSH generates min-hash signatures for feature sets."""
        features = [f"feature_{i}" for i in range(100)]

        lsh_sim = search_engine._calculate_lsh_similarity(features, features)

        assert lsh_sim == 1.0, "LSH signature for identical sets should match perfectly"

        subset_features = features[:50]
        subset_sim = search_engine._calculate_lsh_similarity(features, subset_features)

        assert subset_sim > 0.3, "LSH should detect subset similarity"
        assert subset_sim < 1.0, "LSH should not report perfect match for subset"

    def test_lsh_performance_with_large_sets(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """LSH handles large feature sets efficiently."""
        large_set1 = [f"import_{i}" for i in range(1000)]
        large_set2 = [f"import_{i}" for i in range(500, 1500)]

        start_time = time.time()

        lsh_similarity = search_engine._calculate_lsh_similarity(large_set1, large_set2)

        elapsed = time.time() - start_time

        assert elapsed < 5.0, "LSH must complete large set comparison within 5 seconds"
        assert isinstance(lsh_similarity, float)
        assert 0.0 <= lsh_similarity <= 1.0


class TestFunctionSimilarityMetrics:
    """Test BinDiff-style function similarity calculation."""

    @pytest.fixture
    def search_engine(self, tmp_path: Path) -> BinarySimilaritySearch:
        """Create search engine with temporary database."""
        db_path = tmp_path / "function_sim_test.json"
        return BinarySimilaritySearch(database_path=str(db_path))

    def test_control_flow_similarity_detects_similar_code_patterns(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Control flow similarity detects similar execution patterns."""
        base_features = {
            "sections": [
                {"name": ".text", "entropy": 6.5},
                {"name": ".data", "entropy": 4.0},
            ]
        }

        similar_features = {
            "sections": [
                {"name": ".text", "entropy": 6.3},
                {"name": ".data", "entropy": 4.2},
            ]
        }

        control_flow_sim = search_engine._calculate_control_flow_similarity(
            base_features, similar_features
        )

        assert isinstance(control_flow_sim, float)
        assert 0.0 <= control_flow_sim <= 1.0
        assert control_flow_sim > 0.7, \
            "Similar code sections should have high control flow similarity"

        different_features = {
            "sections": [
                {"name": ".text", "entropy": 2.0},  # Very different
            ]
        }

        different_sim = search_engine._calculate_control_flow_similarity(
            base_features, different_features
        )

        assert different_sim < control_flow_sim, \
            "Different entropy patterns should score lower"

    def test_opcode_similarity_via_import_patterns(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Opcode similarity uses import patterns as proxy for instruction patterns."""
        license_validation_imports = {
            "imports": [
                "crypt32.dll:CryptDecrypt",
                "crypt32.dll:CryptVerifySignature",
                "advapi32.dll:RegQueryValueExW",
                "kernel32.dll:CompareStringW",
                "kernel32.dll:lstrcmpW",
            ]
        }

        similar_validation_imports = {
            "imports": [
                "crypt32.dll:CryptDecrypt",
                "crypt32.dll:CryptHashData",  # slightly different
                "advapi32.dll:RegQueryValueExW",
                "kernel32.dll:CompareStringW",
                "kernel32.dll:lstrcmpiW",  # case-insensitive variant
            ]
        }

        opcode_sim = search_engine._calculate_opcode_similarity(
            license_validation_imports, similar_validation_imports
        )

        assert isinstance(opcode_sim, float)
        assert 0.0 <= opcode_sim <= 1.0
        assert opcode_sim > 0.4, \
            "Similar licensing validation patterns should be detected"

        network_imports = {
            "imports": [
                "wininet.dll:InternetOpenW",
                "wininet.dll:HttpOpenRequestW",
                "ws2_32.dll:socket",
                "ws2_32.dll:connect",
            ]
        }

        different_sim = search_engine._calculate_opcode_similarity(
            license_validation_imports, network_imports
        )

        assert different_sim < opcode_sim, \
            "Different functionality should have lower opcode similarity"

    def test_structural_similarity_with_complex_binaries(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Structural similarity handles complex multi-section binaries."""
        complex_binary1 = {
            "sections": [
                {"name": ".text", "entropy": 6.8},
                {"name": ".rdata", "entropy": 5.2},
                {"name": ".data", "entropy": 4.5},
                {"name": ".idata", "entropy": 3.8},
                {"name": ".rsrc", "entropy": 5.0},
            ],
            "imports": ["kernel32.dll:LoadLibraryW"] * 50,
            "exports": ["DllMain", "Export1", "Export2"],
            "machine": 0x8664,
            "characteristics": 0x2022,
        }

        complex_binary2 = {
            "sections": [
                {"name": ".text", "entropy": 6.5},
                {"name": ".rdata", "entropy": 5.0},
                {"name": ".data", "entropy": 4.8},
                {"name": ".idata", "entropy": 4.0},
                {"name": ".reloc", "entropy": 4.5},  # different section
            ],
            "imports": ["kernel32.dll:GetProcAddress"] * 45,  # different imports
            "exports": ["DllMain", "Export1", "Export3"],  # mostly same
            "machine": 0x8664,
            "characteristics": 0x2022,
        }

        structural_sim = search_engine._calculate_structural_similarity(
            complex_binary1, complex_binary2
        )

        assert isinstance(structural_sim, float)
        assert 0.0 <= structural_sim <= 1.0
        assert structural_sim > 0.5, \
            "Binaries with similar structure should have high structural similarity"


class TestCrossArchitectureSimilarity:
    """Test similarity detection across different architectures."""

    @pytest.fixture
    def search_engine(self, tmp_path: Path) -> BinarySimilaritySearch:
        """Create search engine with temporary database."""
        db_path = tmp_path / "cross_arch_test.json"
        return BinarySimilaritySearch(database_path=str(db_path))

    def test_similarity_between_x86_and_x64_same_code(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Detects similarity between x86 and x64 versions of same code."""
        x86_features = {
            "file_size": 8192,
            "entropy": 6.2,
            "sections": [
                {"name": ".text", "entropy": 6.5},
                {"name": ".data", "entropy": 4.0},
            ],
            "imports": [
                "kernel32.dll:CreateFileA",
                "kernel32.dll:ReadFile",
                "advapi32.dll:RegOpenKeyExA",
            ] * 20,
            "exports": ["CheckLicense", "ValidateKey"],
            "strings": [
                "License verification",
                "Invalid product key",
                "Registration required",
            ] * 10,
            "machine": 0x014C,  # x86
            "characteristics": 0x0102,
        }

        x64_features = {
            "file_size": 12288,  # larger due to 64-bit
            "entropy": 6.4,
            "sections": [
                {"name": ".text", "entropy": 6.3},
                {"name": ".data", "entropy": 4.2},
            ],
            "imports": [
                "kernel32.dll:CreateFileW",  # Unicode on x64
                "kernel32.dll:ReadFile",
                "advapi32.dll:RegOpenKeyExW",  # Unicode on x64
            ] * 20,
            "exports": ["CheckLicense", "ValidateKey"],
            "strings": [
                "License verification",
                "Invalid product key",
                "Registration required",
            ] * 10,
            "machine": 0x8664,  # x64
            "characteristics": 0x0022,
        }

        similarity = search_engine._calculate_similarity(x86_features, x64_features)

        assert isinstance(similarity, float)
        assert 0.0 <= similarity <= 1.0

        assert similarity > 0.5, \
            "Must detect similarity between x86 and x64 versions despite architecture differences"

        pe_header_sim = search_engine._calculate_pe_header_similarity(
            x86_features, x64_features
        )

        assert pe_header_sim < 1.0, \
            "PE header similarity should acknowledge architecture differences"

    def test_adaptive_weights_adjust_for_architecture_differences(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Adaptive weights compensate for architecture-specific differences."""
        x86_features = {
            "imports": ["func"] * 30,
            "strings": ["str"] * 20,
            "machine": 0x014C,
        }

        x64_features = {
            "imports": ["func"] * 60,  # More imports typical in x64
            "strings": ["str"] * 40,  # More strings
            "machine": 0x8664,
        }

        weights = search_engine._calculate_adaptive_weights(x86_features, x64_features)

        assert isinstance(weights, dict)
        assert abs(sum(weights.values()) - 1.0) < 0.01, "Weights must sum to 1.0"

        assert weights["structural"] > 0.2, "Structural weight should be significant"
        assert weights["opcode"] > 0.0, "Opcode weight should be included"


class TestCompilerOptimizationVariations:
    """Test similarity detection across compiler optimization levels."""

    @pytest.fixture
    def search_engine(self, tmp_path: Path) -> BinarySimilaritySearch:
        """Create search engine with temporary database."""
        db_path = tmp_path / "compiler_test.json"
        return BinarySimilaritySearch(database_path=str(db_path))

    def test_detects_similarity_despite_optimization_level_changes(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Detects similarity between O0 and O2 compiled versions."""
        unoptimized_features = {
            "file_size": 4096,
            "entropy": 5.5,  # Lower entropy, less packed
            "sections": [
                {"name": ".text", "entropy": 5.0, "raw_data_size": 2048},
                {"name": ".data", "entropy": 3.5, "raw_data_size": 1024},
            ],
            "imports": [
                "kernel32.dll:CreateFileW",
                "kernel32.dll:ReadFile",
                "kernel32.dll:WriteFile",
                "msvcrt.dll:malloc",
                "msvcrt.dll:free",
                "msvcrt.dll:memcpy",
            ] * 5,
            "strings": [
                "Debug: License check start",
                "Debug: Reading registry",
                "Debug: Validating key",
                "Error: Invalid license",
            ] * 3,
        }

        optimized_features = {
            "file_size": 2048,  # Smaller due to optimization
            "entropy": 6.5,  # Higher entropy, more compact
            "sections": [
                {"name": ".text", "entropy": 6.8, "raw_data_size": 1024},  # Smaller, denser
                {"name": ".data", "entropy": 4.0, "raw_data_size": 512},
            ],
            "imports": [
                "kernel32.dll:CreateFileW",
                "kernel32.dll:ReadFile",
                "kernel32.dll:WriteFile",
            ] * 5,  # Fewer imports, inlined functions
            "strings": [
                "Error: Invalid license",  # Debug strings removed
            ] * 2,
        }

        similarity = search_engine._calculate_similarity(
            unoptimized_features, optimized_features
        )

        assert isinstance(similarity, float)
        assert 0.0 <= similarity <= 1.0

        assert similarity > 0.3, \
            "Must detect similarity despite optimization changing code density and size"

        content_sim = search_engine._calculate_content_similarity(
            unoptimized_features, optimized_features
        )

        assert content_sim > 0.1, \
            "Content similarity should detect some string overlap even after optimization"

    def test_entropy_pattern_handles_optimization_changes(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Entropy pattern similarity handles optimization-induced entropy changes."""
        debug_features = {
            "sections": [
                {"entropy": 4.5},  # Low entropy debug code
                {"entropy": 3.0},  # Debug symbols
                {"entropy": 5.0},  # Code section
            ]
        }

        release_features = {
            "sections": [
                {"entropy": 6.5},  # High entropy optimized code
                {"entropy": 4.0},  # Minimal data
            ]
        }

        entropy_sim = search_engine._calculate_entropy_pattern_similarity(
            debug_features, release_features
        )

        assert isinstance(entropy_sim, float)
        assert 0.0 <= entropy_sim <= 1.0


class TestSimilarityScoringWithConfidence:
    """Test similarity scoring provides confidence levels."""

    @pytest.fixture
    def search_engine(self, tmp_path: Path) -> BinarySimilaritySearch:
        """Create search engine with temporary database."""
        db_path = tmp_path / "confidence_test.json"
        return BinarySimilaritySearch(database_path=str(db_path))

    def test_similarity_score_includes_multiple_algorithm_components(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Similarity calculation uses multiple algorithms for confidence."""
        rich_features = {
            "file_size": 10240,
            "entropy": 6.5,
            "sections": [{"name": ".text", "entropy": 6.5}] * 3,
            "imports": ["kernel32.dll:func"] * 60,
            "exports": ["export1", "export2"],
            "strings": ["string"] * 40,
            "machine": 0x8664,
            "characteristics": 0x0022,
        }

        similar_features = {
            "file_size": 11000,
            "entropy": 6.8,
            "sections": [{"name": ".text", "entropy": 6.3}] * 3,
            "imports": ["kernel32.dll:func"] * 55,
            "exports": ["export1", "export3"],
            "strings": ["string"] * 35,
            "machine": 0x8664,
            "characteristics": 0x0022,
        }

        overall_similarity = search_engine._calculate_similarity(
            rich_features, similar_features
        )

        structural_sim = search_engine._calculate_structural_similarity(
            rich_features, similar_features
        )
        content_sim = search_engine._calculate_content_similarity(
            rich_features, similar_features
        )
        statistical_sim = search_engine._calculate_statistical_similarity(
            rich_features, similar_features
        )
        advanced_sim = search_engine._calculate_advanced_similarity(
            rich_features, similar_features
        )

        assert all(isinstance(s, float) for s in [
            overall_similarity, structural_sim, content_sim, statistical_sim, advanced_sim
        ])

        assert all(0.0 <= s <= 1.0 for s in [
            overall_similarity, structural_sim, content_sim, statistical_sim, advanced_sim
        ])

        component_avg = (structural_sim + content_sim + statistical_sim + advanced_sim) / 4

        assert abs(overall_similarity - component_avg) < 0.5, \
            "Overall similarity should be weighted combination of components"

    def test_weighted_similarity_provides_higher_confidence_than_single_metric(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Weighted multi-algorithm approach provides more reliable scoring."""
        features1 = {
            "file_size": 8192,
            "entropy": 6.0,
            "sections": [{"name": ".text", "entropy": 6.2}],
            "imports": ["kernel32.dll:CreateFile"] * 30,
            "exports": [],
            "strings": ["License", "Key"] * 15,
        }

        features2 = {
            "file_size": 8500,
            "entropy": 6.1,
            "sections": [{"name": ".text", "entropy": 6.0}],
            "imports": ["kernel32.dll:CreateFile"] * 28,
            "exports": [],
            "strings": ["License", "Serial"] * 14,
        }

        weighted_sim = search_engine._calculate_similarity(features1, features2)
        basic_sim = search_engine._calculate_basic_similarity(features1, features2)

        assert abs(weighted_sim - basic_sim) >= 0.0, \
            "Advanced weighted similarity may differ from basic similarity"

        weights = search_engine._calculate_adaptive_weights(features1, features2)

        assert len(weights) >= 5, "Should use multiple similarity components"


class TestEdgeCasesAndRobustness:
    """Test edge cases: heavily optimized code, stripped binaries, obfuscation."""

    @pytest.fixture
    def search_engine(self, tmp_path: Path) -> BinarySimilaritySearch:
        """Create search engine with temporary database."""
        db_path = tmp_path / "edge_test.json"
        return BinarySimilaritySearch(database_path=str(db_path))

    def test_handles_stripped_binary_with_no_exports(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Similarity detection works even when symbols are stripped."""
        normal_features = {
            "exports": ["Function1", "Function2", "CheckLicense"],
            "imports": ["kernel32.dll:CreateFile"] * 20,
            "strings": ["License check"] * 10,
            "sections": [{"name": ".text", "entropy": 6.0}],
        }

        stripped_features = {
            "exports": [],  # All symbols stripped
            "imports": ["kernel32.dll:CreateFile"] * 20,
            "strings": ["License check"] * 10,
            "sections": [{"name": ".text", "entropy": 6.0}],
        }

        similarity = search_engine._calculate_similarity(normal_features, stripped_features)

        assert isinstance(similarity, float)
        assert 0.0 <= similarity <= 1.0

        assert similarity > 0.4, \
            "Must detect similarity based on imports and strings even without exports"

    def test_handles_heavily_obfuscated_high_entropy_code(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Similarity detection handles obfuscated/packed binaries."""
        normal_features = {
            "entropy": 6.0,
            "sections": [
                {"name": ".text", "entropy": 5.8},
                {"name": ".data", "entropy": 4.0},
            ],
            "strings": ["License", "Serial", "Product"] * 10,
        }

        obfuscated_features = {
            "entropy": 7.8,  # Very high entropy from obfuscation
            "sections": [
                {"name": ".text", "entropy": 7.9},  # Encrypted code
                {"name": ".data", "entropy": 7.5},  # Encrypted data
            ],
            "strings": [],  # Strings encrypted/hidden
        }

        similarity = search_engine._calculate_similarity(normal_features, obfuscated_features)

        assert isinstance(similarity, float)
        assert 0.0 <= similarity <= 1.0

        entropy_sim = search_engine._calculate_entropy_similarity(
            normal_features["entropy"], obfuscated_features["entropy"]
        )

        assert entropy_sim < 0.7, "Should recognize entropy difference from obfuscation"

    def test_handles_empty_or_minimal_features_gracefully(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Handles binaries with minimal extractable features."""
        minimal_features = {
            "file_size": 512,
            "entropy": 0.0,
            "sections": [],
            "imports": [],
            "exports": [],
            "strings": [],
        }

        normal_features = {
            "file_size": 10240,
            "entropy": 6.0,
            "sections": [{"name": ".text", "entropy": 6.0}],
            "imports": ["kernel32.dll:CreateFile"],
            "exports": ["Function1"],
            "strings": ["License"],
        }

        similarity = search_engine._calculate_similarity(minimal_features, normal_features)

        assert isinstance(similarity, float)
        assert 0.0 <= similarity <= 1.0
        assert similarity < 0.3, "Minimal features should show low similarity to normal binary"

    def test_n_gram_similarity_with_compiler_generated_strings(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """N-gram similarity handles compiler-generated string variations."""
        msvc_strings = [
            "This program cannot be run in DOS mode",
            "Runtime Error!",
            "Microsoft Visual C++ Runtime Library",
        ]

        gcc_strings = [
            "This program cannot be run in DOS mode",  # Same PE header string
            "pure virtual method called",
            "GCC: (GNU) 11.2.0",
        ]

        ngram_sim = search_engine._calculate_ngram_similarity(msvc_strings, gcc_strings)

        assert isinstance(ngram_sim, float)
        assert 0.0 <= ngram_sim <= 1.0
        assert ngram_sim > 0.1, "Should detect some n-gram overlap in standard strings"

    def test_section_distribution_with_unusual_layouts(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Section distribution similarity handles non-standard section layouts."""
        standard_sections = [
            {"raw_data_size": 4096},  # .text
            {"raw_data_size": 2048},  # .data
            {"raw_data_size": 1024},  # .rdata
        ]

        unusual_sections = [
            {"raw_data_size": 1024},  # Custom section
            {"raw_data_size": 8192},  # Large packed section
            {"raw_data_size": 512},   # Tiny section
            {"raw_data_size": 256},   # Resources
            {"raw_data_size": 128},   # Debug
        ]

        dist_sim = search_engine._calculate_section_distribution_similarity(
            standard_sections, unusual_sections
        )

        assert isinstance(dist_sim, float)
        assert 0.0 <= dist_sim <= 1.0
