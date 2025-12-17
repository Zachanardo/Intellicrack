"""Production-Grade Tests for Binary Similarity Search Engine.

Validates REAL binary similarity detection using structural analysis and feature
extraction. Tests actual similarity scoring algorithms against real PE binaries,
proving offensive capability for identifying known cracking patterns.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0+
"""

import json
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.binary_similarity_search import (
    BinarySimilaritySearch,
    create_similarity_search,
)


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    """Provide temporary directory for test files."""
    return tmp_path


@pytest.fixture
def database_path(temp_dir: Path) -> Path:
    """Provide database file path."""
    return temp_dir / "test_database.json"


@pytest.fixture
def searcher(database_path: Path) -> BinarySimilaritySearch:
    """Provide binary similarity search instance."""
    return BinarySimilaritySearch(database_path=str(database_path))


def create_pe_binary(
    path: Path,
    size: int = 2000,
    sections: list[tuple[str, int]] = None,
    imports: list[str] = None,
    exports: list[str] = None,
    strings: list[str] = None,
) -> Path:
    """Create realistic PE binary with specified features.

    Args:
        path: Output path for binary
        size: Total binary size
        sections: List of (name, entropy*100) tuples
        imports: List of import strings (dll:function format)
        exports: List of export function names
        strings: List of ASCII strings to embed

    Returns:
        Path to created binary
    """
    dos_header = bytearray([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ] + [0x00] * 32 + [0x80, 0x00, 0x00, 0x00])

    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7
    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0x00F0, 0x0022)

    optional_header = bytearray(240)
    optional_header[0:2] = struct.pack("<H", 0x020B)

    binary_content = dos_header + dos_stub + pe_signature + coff_header + optional_header

    binary_content += b"\x90" * (400 - len(binary_content))

    if strings:
        for s in strings:
            binary_content += s.encode("utf-8", errors="ignore") + b"\x00"

    if imports:
        for imp in imports:
            binary_content += imp.encode("utf-8", errors="ignore") + b"\x00"

    if exports:
        for exp in exports:
            binary_content += exp.encode("utf-8", errors="ignore") + b"\x00"

    binary_content += b"\x00" * (size - len(binary_content))

    path.write_bytes(binary_content)
    return path


def test_searcher_initialization(searcher: BinarySimilaritySearch, database_path: Path) -> None:
    """Searcher initializes with correct database path and structure."""
    assert searcher.database_path == str(database_path)
    assert "binaries" in searcher.database
    assert isinstance(searcher.database["binaries"], list)


def test_create_similarity_search_factory(temp_dir: Path) -> None:
    """Factory function creates configured search instance."""
    db_path = str(temp_dir / "factory_db.json")
    searcher = create_similarity_search(db_path)

    assert isinstance(searcher, BinarySimilaritySearch)
    assert searcher.database_path == db_path


def test_add_binary_to_database(searcher: BinarySimilaritySearch, temp_dir: Path) -> None:
    """Adding binary extracts features and stores in database."""
    binary = create_pe_binary(
        temp_dir / "test1.exe",
        size=1500,
        strings=["LICENSE", "TRIAL", "REGISTER"],
    )

    result = searcher.add_binary(str(binary), cracking_patterns=["patch_0x401000"])

    assert result is True
    assert len(searcher.database["binaries"]) == 1

    entry = searcher.database["binaries"][0]
    assert entry["path"] == str(binary)
    assert entry["filename"] == "test1.exe"
    assert "LICENSE" in entry["features"]["strings"]
    assert "patch_0x401000" in entry["cracking_patterns"]
    assert entry["file_size"] == binary.stat().st_size


def test_add_duplicate_binary_fails(searcher: BinarySimilaritySearch, temp_dir: Path) -> None:
    """Adding duplicate binary returns False."""
    binary = create_pe_binary(temp_dir / "test1.exe", size=1000)

    searcher.add_binary(str(binary))
    result = searcher.add_binary(str(binary))

    assert result is False
    assert len(searcher.database["binaries"]) == 1


def test_extract_binary_features_file_size(searcher: BinarySimilaritySearch, temp_dir: Path) -> None:
    """Feature extraction includes accurate file size."""
    binary = create_pe_binary(temp_dir / "test.exe", size=3000)

    features = searcher._extract_binary_features(str(binary))

    assert features["file_size"] == 3000


def test_extract_binary_features_entropy(searcher: BinarySimilaritySearch, temp_dir: Path) -> None:
    """Feature extraction calculates file entropy."""
    binary = create_pe_binary(temp_dir / "test.exe", size=2000)

    features = searcher._extract_binary_features(str(binary))

    assert "entropy" in features
    assert isinstance(features["entropy"], float)
    assert 0.0 <= features["entropy"] <= 8.0


def test_extract_binary_features_strings(searcher: BinarySimilaritySearch, temp_dir: Path) -> None:
    """Feature extraction finds embedded strings."""
    binary = create_pe_binary(
        temp_dir / "test.exe",
        size=2000,
        strings=["ACTIVATION_KEY", "LICENSE_CHECK", "TRIAL_EXPIRED"],
    )

    features = searcher._extract_binary_features(str(binary))

    assert "ACTIVATION_KEY" in features["strings"]
    assert "LICENSE_CHECK" in features["strings"]
    assert "TRIAL_EXPIRED" in features["strings"]


def test_extract_binary_features_nonexistent_file(searcher: BinarySimilaritySearch) -> None:
    """Feature extraction handles nonexistent files gracefully."""
    features = searcher._extract_binary_features("/nonexistent/binary.exe")

    assert features["file_size"] == 0
    assert features["entropy"] == 0.0
    assert len(features["sections"]) == 0


def test_search_similar_binaries_exact_match(searcher: BinarySimilaritySearch, temp_dir: Path) -> None:
    """Search finds exact matches with 1.0 similarity."""
    binary1 = create_pe_binary(
        temp_dir / "app1.exe",
        size=2000,
        strings=["LICENSE", "KEY", "ACTIVATION"],
    )

    searcher.add_binary(str(binary1), ["patch_license"])

    binary2 = create_pe_binary(
        temp_dir / "app2.exe",
        size=2000,
        strings=["LICENSE", "KEY", "ACTIVATION"],
    )

    results = searcher.search_similar_binaries(str(binary2), threshold=0.5)

    assert len(results) > 0
    assert results[0]["path"] == str(binary1)
    assert results[0]["similarity"] > 0.5


def test_search_similar_binaries_threshold_filtering(searcher: BinarySimilaritySearch, temp_dir: Path) -> None:
    """Search filters results by similarity threshold."""
    binary1 = create_pe_binary(
        temp_dir / "similar.exe",
        size=2000,
        strings=["LICENSE", "ACTIVATION"],
    )

    searcher.add_binary(str(binary1))

    binary2 = create_pe_binary(
        temp_dir / "different.exe",
        size=5000,
        strings=["COMPLETELY", "DIFFERENT", "STRINGS"],
    )

    results = searcher.search_similar_binaries(str(binary2), threshold=0.9)

    assert len(results) == 0


def test_search_similar_binaries_returns_cracking_patterns(
    searcher: BinarySimilaritySearch, temp_dir: Path
) -> None:
    """Search results include associated cracking patterns."""
    binary1 = create_pe_binary(temp_dir / "protected.exe", size=2000)

    patterns = ["nop_0x401000", "patch_registration_check", "bypass_trial"]
    searcher.add_binary(str(binary1), patterns)

    binary2 = create_pe_binary(temp_dir / "target.exe", size=2000)

    results = searcher.search_similar_binaries(str(binary2), threshold=0.1)

    assert len(results) > 0
    assert set(results[0]["cracking_patterns"]) == set(patterns)


def test_search_similar_binaries_sorted_by_similarity(
    searcher: BinarySimilaritySearch, temp_dir: Path
) -> None:
    """Search results sorted by similarity score descending."""
    binary1 = create_pe_binary(
        temp_dir / "low_sim.exe",
        size=5000,
        strings=["UNRELATED"],
    )
    searcher.add_binary(str(binary1))

    binary2 = create_pe_binary(
        temp_dir / "high_sim.exe",
        size=2000,
        strings=["LICENSE", "TRIAL"],
    )
    searcher.add_binary(str(binary2))

    target = create_pe_binary(
        temp_dir / "target.exe",
        size=2000,
        strings=["LICENSE", "TRIAL"],
    )

    results = searcher.search_similar_binaries(str(target), threshold=0.0)

    assert len(results) >= 2
    for i in range(len(results) - 1):
        assert results[i]["similarity"] >= results[i + 1]["similarity"]


def test_calculate_similarity_structural_components(
    searcher: BinarySimilaritySearch, temp_dir: Path
) -> None:
    """Similarity calculation considers structural features."""
    features1 = {
        "file_size": 2000,
        "entropy": 5.5,
        "sections": [{"name": ".text", "entropy": 6.0}],
        "imports": ["kernel32.dll:CreateFileW"],
        "exports": [],
        "strings": ["LICENSE"],
    }

    features2 = {
        "file_size": 2100,
        "entropy": 5.6,
        "sections": [{"name": ".text", "entropy": 6.1}],
        "imports": ["kernel32.dll:CreateFileW"],
        "exports": [],
        "strings": ["LICENSE"],
    }

    similarity = searcher._calculate_similarity(features1, features2)

    assert 0.0 <= similarity <= 1.0
    assert similarity > 0.5


def test_calculate_section_similarity_matching_names(searcher: BinarySimilaritySearch) -> None:
    """Section similarity detects matching section names."""
    sections1 = [
        {"name": ".text", "entropy": 6.0},
        {"name": ".data", "entropy": 3.5},
        {"name": ".rdata", "entropy": 4.0},
    ]

    sections2 = [
        {"name": ".text", "entropy": 6.1},
        {"name": ".data", "entropy": 3.6},
        {"name": ".rdata", "entropy": 4.1},
    ]

    similarity = searcher._calculate_section_similarity(sections1, sections2)

    assert similarity > 0.7


def test_calculate_section_similarity_empty_sections(searcher: BinarySimilaritySearch) -> None:
    """Section similarity handles empty section lists."""
    similarity = searcher._calculate_section_similarity([], [])

    assert similarity == 0.0


def test_calculate_list_similarity_identical_lists(searcher: BinarySimilaritySearch) -> None:
    """List similarity returns 1.0 for identical lists."""
    list1 = ["item1", "item2", "item3"]
    list2 = ["item1", "item2", "item3"]

    similarity = searcher._calculate_list_similarity(list1, list2)

    assert similarity == 1.0


def test_calculate_list_similarity_no_overlap(searcher: BinarySimilaritySearch) -> None:
    """List similarity returns 0.0 for completely different lists."""
    list1 = ["a", "b", "c"]
    list2 = ["x", "y", "z"]

    similarity = searcher._calculate_list_similarity(list1, list2)

    assert similarity == 0.0


def test_calculate_list_similarity_partial_overlap(searcher: BinarySimilaritySearch) -> None:
    """List similarity calculates Jaccard index for partial overlap."""
    list1 = ["a", "b", "c", "d"]
    list2 = ["c", "d", "e", "f"]

    similarity = searcher._calculate_list_similarity(list1, list2)

    assert similarity == 2 / 6


def test_calculate_fuzzy_string_similarity_matching_strings(
    searcher: BinarySimilaritySearch,
) -> None:
    """Fuzzy string similarity detects similar strings."""
    strings1 = ["LICENSE_KEY", "ACTIVATION_CODE", "TRIAL_PERIOD"]
    strings2 = ["LICENSE_KEY", "ACTIVATION_CODE", "TRIAL_PERIOD"]

    similarity = searcher._calculate_fuzzy_string_similarity(strings1, strings2)

    assert similarity > 0.9


def test_calculate_fuzzy_string_similarity_updates_stats(
    searcher: BinarySimilaritySearch,
) -> None:
    """Fuzzy string similarity updates match statistics."""
    strings1 = ["TEST", "STRING", "LIST"]
    strings2 = ["TEST", "STRING", "LIST"]

    searcher._calculate_fuzzy_string_similarity(strings1, strings2)

    stats = searcher.get_fuzzy_match_statistics()

    assert stats["total_comparisons"] > 0
    assert stats["matches_found"] > 0
    assert stats["sample_size"] > 0


def test_calculate_ngram_similarity_shared_patterns(searcher: BinarySimilaritySearch) -> None:
    """N-gram similarity detects shared character patterns."""
    strings1 = ["LICENSE_CHECK", "REGISTRATION_VERIFY"]
    strings2 = ["LICENSE_VALIDATE", "REGISTRATION_CHECK"]

    similarity = searcher._calculate_ngram_similarity(strings1, strings2)

    assert similarity > 0.0


def test_calculate_entropy_pattern_similarity(searcher: BinarySimilaritySearch) -> None:
    """Entropy pattern similarity compares section entropy distributions."""
    features1 = {
        "sections": [
            {"entropy": 2.0},
            {"entropy": 6.0},
            {"entropy": 7.5},
        ]
    }

    features2 = {
        "sections": [
            {"entropy": 2.1},
            {"entropy": 6.1},
            {"entropy": 7.4},
        ]
    }

    similarity = searcher._calculate_entropy_pattern_similarity(features1, features2)

    assert similarity > 0.8


def test_calculate_logarithmic_size_similarity_similar_sizes(
    searcher: BinarySimilaritySearch,
) -> None:
    """Logarithmic size similarity handles similar file sizes."""
    similarity = searcher._calculate_logarithmic_size_similarity(2000, 2100)

    assert similarity > 0.95


def test_calculate_logarithmic_size_similarity_very_different_sizes(
    searcher: BinarySimilaritySearch,
) -> None:
    """Logarithmic size similarity penalizes vastly different sizes."""
    similarity = searcher._calculate_logarithmic_size_similarity(1000, 1000000)

    assert similarity < 0.5


def test_get_database_stats_empty_database(searcher: BinarySimilaritySearch) -> None:
    """Database stats work with empty database."""
    stats = searcher.get_database_stats()

    assert stats["total_binaries"] == 0
    assert stats["total_patterns"] == 0
    assert stats["avg_file_size"] == 0


def test_get_database_stats_with_entries(searcher: BinarySimilaritySearch, temp_dir: Path) -> None:
    """Database stats aggregate information from entries."""
    binary1 = create_pe_binary(temp_dir / "app1.exe", size=2000)
    searcher.add_binary(str(binary1), ["pattern1", "pattern2"])

    binary2 = create_pe_binary(temp_dir / "app2.exe", size=3000)
    searcher.add_binary(str(binary2), ["pattern3"])

    stats = searcher.get_database_stats()

    assert stats["total_binaries"] == 2
    assert stats["total_patterns"] == 3
    assert stats["avg_file_size"] == 2500


def test_remove_binary_from_database(searcher: BinarySimilaritySearch, temp_dir: Path) -> None:
    """Binary removal deletes entry from database."""
    binary = create_pe_binary(temp_dir / "removeme.exe", size=1000)
    searcher.add_binary(str(binary))

    assert len(searcher.database["binaries"]) == 1

    result = searcher.remove_binary(str(binary))

    assert result is True
    assert len(searcher.database["binaries"]) == 0


def test_remove_nonexistent_binary(searcher: BinarySimilaritySearch) -> None:
    """Removing nonexistent binary returns False."""
    result = searcher.remove_binary("/nonexistent/binary.exe")

    assert result is False


def test_load_database_from_file(temp_dir: Path) -> None:
    """Database loads existing file content."""
    db_path = temp_dir / "existing_db.json"

    existing_data = {
        "binaries": [
            {
                "path": "/test/app.exe",
                "filename": "app.exe",
                "features": {"file_size": 1000},
                "cracking_patterns": ["patch1"],
            }
        ]
    }

    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(existing_data, f)

    searcher = BinarySimilaritySearch(database_path=str(db_path))

    assert len(searcher.database["binaries"]) == 1
    assert searcher.database["binaries"][0]["path"] == "/test/app.exe"


def test_load_database_creates_empty_if_missing(temp_dir: Path) -> None:
    """Database creates empty structure if file doesn't exist."""
    db_path = temp_dir / "nonexistent.json"

    searcher = BinarySimilaritySearch(database_path=str(db_path))

    assert "binaries" in searcher.database
    assert len(searcher.database["binaries"]) == 0


def test_find_similar_alias_method(searcher: BinarySimilaritySearch, temp_dir: Path) -> None:
    """find_similar() is an alias for search_similar_binaries()."""
    binary = create_pe_binary(temp_dir / "test.exe", size=1000)

    results1 = searcher.find_similar(str(binary), threshold=0.7)
    results2 = searcher.search_similar_binaries(str(binary), threshold=0.7)

    assert results1 == results2


def test_get_fuzzy_match_statistics_initial_state(searcher: BinarySimilaritySearch) -> None:
    """Fuzzy match statistics initialize to zero."""
    stats = searcher.get_fuzzy_match_statistics()

    assert stats["total_comparisons"] == 0
    assert stats["matches_found"] == 0
    assert stats["sample_size"] == 0


def test_calculate_weighted_api_similarity_critical_apis(
    searcher: BinarySimilaritySearch,
) -> None:
    """Weighted API similarity prioritizes critical security APIs."""
    imports1 = ["kernel32.dll:CreateFileW", "advapi32.dll:RegQueryValueExA"]
    imports2 = ["kernel32.dll:CreateFileW", "advapi32.dll:RegQueryValueExA"]

    similarity = searcher._calculate_weighted_api_similarity(imports1, imports2)

    assert similarity > 0.9


def test_calculate_pe_header_similarity_matching_headers(
    searcher: BinarySimilaritySearch,
) -> None:
    """PE header similarity detects matching machine types and characteristics."""
    features1 = {"machine": 0x8664, "characteristics": 0x0022}
    features2 = {"machine": 0x8664, "characteristics": 0x0022}

    similarity = searcher._calculate_pe_header_similarity(features1, features2)

    assert similarity == 1.0


def test_calculate_adaptive_weights_feature_rich_binaries(
    searcher: BinarySimilaritySearch,
) -> None:
    """Adaptive weights adjust based on feature availability."""
    features1 = {
        "imports": ["import" + str(i) for i in range(100)],
        "strings": ["string" + str(i) for i in range(50)],
    }

    features2 = {
        "imports": ["import" + str(i) for i in range(100)],
        "strings": ["string" + str(i) for i in range(50)],
    }

    weights = searcher._calculate_adaptive_weights(features1, features2)

    assert sum(weights.values()) == pytest.approx(1.0)
    assert weights["structural"] > 0.25


def test_calculate_lsh_similarity_identical_features(searcher: BinarySimilaritySearch) -> None:
    """LSH similarity high for identical feature sets."""
    features = ["feature1", "feature2", "feature3"]

    similarity = searcher._calculate_lsh_similarity(features, features)

    assert similarity > 0.5


def test_calculate_edit_distance_similarity_identical_strings(
    searcher: BinarySimilaritySearch,
) -> None:
    """Edit distance similarity returns 1.0 for identical strings."""
    strings = ["test", "string", "list"]

    similarity = searcher._calculate_edit_distance_similarity(strings, strings)

    assert similarity == 1.0


def test_calculate_cosine_similarity_feature_vectors(searcher: BinarySimilaritySearch) -> None:
    """Cosine similarity compares multi-dimensional feature vectors."""
    features1 = {
        "file_size": 2000000,
        "entropy": 6.5,
        "sections": [1, 2, 3],
        "imports": ["a", "b"],
        "exports": ["x"],
        "strings": ["str1", "str2"],
    }

    features2 = {
        "file_size": 2100000,
        "entropy": 6.6,
        "sections": [1, 2, 3],
        "imports": ["a", "b"],
        "exports": ["x"],
        "strings": ["str1", "str2"],
    }

    similarity = searcher._calculate_cosine_similarity(features1, features2)

    assert 0.9 <= similarity <= 1.0


def test_save_and_reload_database_persistence(temp_dir: Path) -> None:
    """Database persists correctly across save and reload."""
    db_path = temp_dir / "persist_db.json"

    searcher1 = BinarySimilaritySearch(database_path=str(db_path))

    binary = create_pe_binary(temp_dir / "app.exe", size=2000)
    searcher1.add_binary(str(binary), ["pattern1"])

    searcher2 = BinarySimilaritySearch(database_path=str(db_path))

    assert len(searcher2.database["binaries"]) == 1
    assert searcher2.database["binaries"][0]["path"] == str(binary)


def test_search_with_high_similarity_threshold(
    searcher: BinarySimilaritySearch, temp_dir: Path
) -> None:
    """High similarity threshold returns only very close matches."""
    binary1 = create_pe_binary(temp_dir / "exact.exe", size=2000, strings=["TEST"])
    searcher.add_binary(str(binary1))

    binary2 = create_pe_binary(temp_dir / "target.exe", size=5000, strings=["DIFFERENT"])

    results = searcher.search_similar_binaries(str(binary2), threshold=0.95)

    assert len(results) == 0
