"""Production-ready tests for Binary Similarity Search Engine.

Tests validate real similarity algorithms including:
- Fuzzy hash matching (ssdeep-like, TLSH-like)
- LSH (Locality Sensitive Hashing) for code similarity
- Function similarity metrics (BinDiff-style)
- Cross-architecture similarity detection
- Similarity scoring with confidence levels

Copyright (C) 2025 Zachary Flint
Licensed under GPL-3.0
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.analysis.binary_similarity_search import BinarySimilaritySearch


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def temp_db_dir() -> Iterator[Path]:
    """Create temporary directory for test databases."""
    with tempfile.TemporaryDirectory(prefix="similarity_test_") as tmp:
        yield Path(tmp)


@pytest.fixture
def similarity_engine(temp_db_dir: Path) -> BinarySimilaritySearch:
    """Create similarity search engine with temporary database."""
    db_path = temp_db_dir / "test_binary_db.json"
    return BinarySimilaritySearch(str(db_path))


@pytest.fixture
def sample_pe_binary(temp_db_dir: Path) -> Path:
    """Create realistic PE binary with proper structure."""
    binary_path = temp_db_dir / "sample.exe"

    pe_header = bytearray(b"MZ" + b"\x90" * 58)
    pe_header += b"\x3C\x00\x00\x00"

    dos_stub = b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21"
    dos_stub += b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack("<HHIIIHH",
        0x014C,
        3,
        0x5F5E100,
        0,
        0,
        0xE0,
        0x010B
    )

    optional_header = bytearray(224)
    optional_header[0:2] = struct.pack("<H", 0x010B)
    optional_header[2] = 0x0E
    optional_header[3] = 0x00

    section_header_text = struct.pack("<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x1000,
        0x1000,
        0x800,
        0x400,
        0,
        0,
        0,
        0,
        0x60000020
    )

    section_header_data = struct.pack("<8sIIIIIIHHI",
        b".data\x00\x00\x00",
        0x800,
        0x2000,
        0x400,
        0xC00,
        0,
        0,
        0,
        0,
        0xC0000040
    )

    section_header_rdata = struct.pack("<8sIIIIIIHHI",
        b".rdata\x00\x00",
        0x400,
        0x3000,
        0x200,
        0x1000,
        0,
        0,
        0,
        0,
        0x40000040
    )

    text_section = bytearray(0x800)
    code_pattern = b"\x55\x8B\xEC\x83\xEC\x40\x53\x56\x57"
    for i in range(0, len(text_section) - len(code_pattern), 64):
        text_section[i:i + len(code_pattern)] = code_pattern

    data_section = bytearray(0x400)
    for i in range(0, len(data_section), 8):
        data_section[i:i+8] = struct.pack("<Q", 0x4141414141414141)

    rdata_section = bytearray(0x200)
    strings = [b"kernel32.dll\x00", b"user32.dll\x00", b"GetProcAddress\x00", b"LoadLibraryA\x00"]
    offset = 0
    for s in strings:
        rdata_section[offset:offset+len(s)] = s
        offset += len(s)

    pe_data = (
        pe_header +
        dos_stub +
        pe_signature +
        coff_header +
        optional_header +
        section_header_text +
        section_header_data +
        section_header_rdata +
        bytes(0x400 - len(pe_header) - len(dos_stub) - len(pe_signature) -
              len(coff_header) - len(optional_header) - len(section_header_text) -
              len(section_header_data) - len(section_header_rdata)) +
        text_section +
        data_section +
        rdata_section
    )

    binary_path.write_bytes(pe_data)
    return binary_path


@pytest.fixture
def variant_pe_binary(temp_db_dir: Path) -> Path:
    """Create variant PE binary with similar but different code."""
    binary_path = temp_db_dir / "variant.exe"

    pe_header = bytearray(b"MZ" + b"\x90" * 58)
    pe_header += b"\x3C\x00\x00\x00"

    dos_stub = b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21"
    dos_stub += b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack("<HHIIIHH",
        0x014C,
        3,
        0x5F5E110,
        0,
        0,
        0xE0,
        0x010B
    )

    optional_header = bytearray(224)
    optional_header[0:2] = struct.pack("<H", 0x010B)
    optional_header[2] = 0x0E
    optional_header[3] = 0x00

    section_header_text = struct.pack("<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x1000,
        0x1000,
        0x800,
        0x400,
        0,
        0,
        0,
        0,
        0x60000020
    )

    section_header_data = struct.pack("<8sIIIIIIHHI",
        b".data\x00\x00\x00",
        0x800,
        0x2000,
        0x400,
        0xC00,
        0,
        0,
        0,
        0,
        0xC0000040
    )

    section_header_rdata = struct.pack("<8sIIIIIIHHI",
        b".rdata\x00\x00",
        0x400,
        0x3000,
        0x200,
        0x1000,
        0,
        0,
        0,
        0,
        0x40000040
    )

    text_section = bytearray(0x800)
    variant_code = b"\x55\x8B\xEC\x83\xEC\x40\x53\x56\x57\x90\x90"
    for i in range(0, len(text_section) - len(variant_code), 64):
        text_section[i:i + len(variant_code)] = variant_code

    data_section = bytearray(0x400)
    for i in range(0, len(data_section), 8):
        data_section[i:i+8] = struct.pack("<Q", 0x4242424242424242)

    rdata_section = bytearray(0x200)
    strings = [b"kernel32.dll\x00", b"user32.dll\x00", b"GetModuleHandleA\x00", b"LoadLibraryA\x00"]
    offset = 0
    for s in strings:
        rdata_section[offset:offset+len(s)] = s
        offset += len(s)

    pe_data = (
        pe_header +
        dos_stub +
        pe_signature +
        coff_header +
        optional_header +
        section_header_text +
        section_header_data +
        section_header_rdata +
        bytes(0x400 - len(pe_header) - len(dos_stub) - len(pe_signature) -
              len(coff_header) - len(optional_header) - len(section_header_text) -
              len(section_header_data) - len(section_header_rdata)) +
        text_section +
        data_section +
        rdata_section
    )

    binary_path.write_bytes(pe_data)
    return binary_path


@pytest.fixture
def different_binary(temp_db_dir: Path) -> Path:
    """Create completely different binary."""
    binary_path = temp_db_dir / "different.exe"

    pe_header = bytearray(b"MZ" + b"\x00" * 58)
    pe_header += b"\x3C\x00\x00\x00"

    dos_stub = b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21"
    dos_stub += b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack("<HHIIIHH",
        0x8664,
        2,
        0x6F5E100,
        0,
        0,
        0xF0,
        0x020B
    )

    optional_header = bytearray(240)
    optional_header[0:2] = struct.pack("<H", 0x020B)

    section_header_code = struct.pack("<8sIIIIIIHHI",
        b".code\x00\x00\x00",
        0x2000,
        0x1000,
        0x1000,
        0x400,
        0,
        0,
        0,
        0,
        0x60000020
    )

    section_header_rodata = struct.pack("<8sIIIIIIHHI",
        b".rodata\x00",
        0x1000,
        0x3000,
        0x800,
        0x1400,
        0,
        0,
        0,
        0,
        0x40000040
    )

    code_section = bytearray(0x1000)
    for i in range(0, len(code_section), 32):
        code_section[i:i+16] = hashlib.sha256(str(i).encode()).digest()[:16]

    rodata_section = bytearray(0x800)
    strings = [b"ntdll.dll\x00", b"advapi32.dll\x00", b"NtQuerySystemInformation\x00"]
    offset = 0
    for s in strings:
        rodata_section[offset:offset+len(s)] = s
        offset += len(s)

    pe_data = (
        pe_header +
        dos_stub +
        pe_signature +
        coff_header +
        optional_header +
        section_header_code +
        section_header_rodata +
        bytes(0x400 - len(pe_header) - len(dos_stub) - len(pe_signature) -
              len(coff_header) - len(optional_header) - len(section_header_code) -
              len(section_header_rodata)) +
        code_section +
        rodata_section
    )

    binary_path.write_bytes(pe_data)
    return binary_path


@pytest.fixture
def cross_arch_binary(temp_db_dir: Path) -> Path:
    """Create x64 binary with similar functionality to x86 sample."""
    binary_path = temp_db_dir / "cross_arch.exe"

    pe_header = bytearray(b"MZ" + b"\x90" * 58)
    pe_header += b"\x3C\x00\x00\x00"

    dos_stub = b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21"
    dos_stub += b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack("<HHIIIHH",
        0x8664,
        3,
        0x5F5E100,
        0,
        0,
        0xF0,
        0x020B
    )

    optional_header = bytearray(240)
    optional_header[0:2] = struct.pack("<H", 0x020B)

    section_header_text = struct.pack("<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x1000,
        0x1000,
        0x800,
        0x400,
        0,
        0,
        0,
        0,
        0x60000020
    )

    section_header_data = struct.pack("<8sIIIIIIHHI",
        b".data\x00\x00\x00",
        0x800,
        0x2000,
        0x400,
        0xC00,
        0,
        0,
        0,
        0,
        0xC0000040
    )

    section_header_rdata = struct.pack("<8sIIIIIIHHI",
        b".rdata\x00\x00",
        0x400,
        0x3000,
        0x200,
        0x1000,
        0,
        0,
        0,
        0,
        0x40000040
    )

    text_section = bytearray(0x800)
    x64_code = b"\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00"
    for i in range(0, len(text_section) - len(x64_code), 64):
        text_section[i:i + len(x64_code)] = x64_code

    data_section = bytearray(0x400)
    for i in range(0, len(data_section), 8):
        data_section[i:i+8] = struct.pack("<Q", 0x4141414141414141)

    rdata_section = bytearray(0x200)
    strings = [b"kernel32.dll\x00", b"user32.dll\x00", b"GetProcAddress\x00", b"LoadLibraryA\x00"]
    offset = 0
    for s in strings:
        rdata_section[offset:offset+len(s)] = s
        offset += len(s)

    pe_data = (
        pe_header +
        dos_stub +
        pe_signature +
        coff_header +
        optional_header +
        section_header_text +
        section_header_data +
        section_header_rdata +
        bytes(0x400 - len(pe_header) - len(dos_stub) - len(pe_signature) -
              len(coff_header) - len(optional_header) - len(section_header_text) -
              len(section_header_data) - len(section_header_rdata)) +
        text_section +
        data_section +
        rdata_section
    )

    binary_path.write_bytes(pe_data)
    return binary_path


@pytest.mark.real_data
def test_fuzzy_hash_similarity_real_binaries(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
) -> None:
    """Fuzzy hash matching detects similar binaries with code variations."""
    similarity_engine.add_binary(str(sample_pe_binary), ["pattern_a"])

    results = similarity_engine.search_similar_binaries(str(variant_pe_binary), threshold=0.5)

    assert len(results) > 0, "Fuzzy hash must detect similar binary variant"
    assert results[0]["similarity"] > 0.5, "Similar binaries must have >50% similarity"
    assert results[0]["similarity"] < 1.0, "Variant binaries must not be identical"

    stats = similarity_engine.get_fuzzy_match_statistics()
    assert stats["total_comparisons"] > 0, "Fuzzy matching must perform comparisons"
    assert stats["sample_size"] > 0, "Fuzzy matching must analyze sample data"


@pytest.mark.real_data
def test_fuzzy_hash_rejects_different_binaries(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    different_binary: Path,
) -> None:
    """Fuzzy hash correctly identifies completely different binaries."""
    similarity_engine.add_binary(str(sample_pe_binary), ["pattern_a"])

    results = similarity_engine.search_similar_binaries(str(different_binary), threshold=0.7)

    assert len(results) == 0, "Different binaries must not match at high threshold"


@pytest.mark.real_data
def test_lsh_similarity_code_patterns(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
) -> None:
    """LSH algorithm detects code similarity through locality-sensitive hashing."""
    features1 = similarity_engine._extract_binary_features(str(sample_pe_binary))
    features2 = similarity_engine._extract_binary_features(str(variant_pe_binary))

    lsh_score = similarity_engine._calculate_lsh_similarity(
        features1.get("imports", []) + features1.get("exports", []),
        features2.get("imports", []) + features2.get("exports", [])
    )

    assert lsh_score > 0.0, "LSH must detect similarity in API patterns"
    assert lsh_score <= 1.0, "LSH score must be normalized"
    assert isinstance(lsh_score, float), "LSH must return float similarity score"


@pytest.mark.real_data
def test_lsh_produces_different_signatures_for_different_code(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    different_binary: Path,
) -> None:
    """LSH produces distinct signatures for fundamentally different code."""
    features1 = similarity_engine._extract_binary_features(str(sample_pe_binary))
    features2 = similarity_engine._extract_binary_features(str(different_binary))

    lsh_score = similarity_engine._calculate_lsh_similarity(
        features1.get("imports", []) + features1.get("exports", []),
        features2.get("imports", []) + features2.get("exports", [])
    )

    assert lsh_score < 0.5, "LSH must detect low similarity for different binaries"


@pytest.mark.real_data
def test_function_similarity_metrics(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
) -> None:
    """BinDiff-style function similarity using structural analysis."""
    features1 = similarity_engine._extract_binary_features(str(sample_pe_binary))
    features2 = similarity_engine._extract_binary_features(str(variant_pe_binary))

    structural_similarity = similarity_engine._calculate_structural_similarity(features1, features2)

    assert structural_similarity > 0.0, "Structural similarity must detect similar functions"
    assert structural_similarity <= 1.0, "Similarity score must be normalized"

    section_similarity = similarity_engine._calculate_section_similarity(
        features1.get("sections", []),
        features2.get("sections", [])
    )

    assert section_similarity > 0.5, "Similar binaries must have similar section layout"


@pytest.mark.real_data
def test_cross_architecture_similarity_detection(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    cross_arch_binary: Path,
) -> None:
    """Similarity detection works across x86 and x64 architectures."""
    features_x86 = similarity_engine._extract_binary_features(str(sample_pe_binary))
    features_x64 = similarity_engine._extract_binary_features(str(cross_arch_binary))

    assert features_x86.get("machine") != features_x64.get("machine"), "Architectures must differ"

    import_similarity = similarity_engine._calculate_weighted_api_similarity(
        features_x86.get("imports", []),
        features_x64.get("imports", [])
    )

    assert import_similarity > 0.5, "Cross-arch binaries with same APIs must show similarity"

    overall_similarity = similarity_engine._calculate_similarity(features_x86, features_x64)

    assert overall_similarity > 0.0, "Cross-arch similarity must be detected"
    assert overall_similarity < 1.0, "Different architectures cannot be identical"


@pytest.mark.real_data
def test_similarity_scoring_with_confidence_levels(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
    different_binary: Path,
) -> None:
    """Similarity scores provide meaningful confidence levels."""
    similarity_engine.add_binary(str(sample_pe_binary), ["original"])

    variant_results = similarity_engine.search_similar_binaries(str(variant_pe_binary), threshold=0.0)
    different_results = similarity_engine.search_similar_binaries(str(different_binary), threshold=0.0)

    assert len(variant_results) > 0, "Must detect similar variant"
    assert len(different_results) > 0, "Must detect different binary at 0.0 threshold"

    variant_score = variant_results[0]["similarity"]
    different_score = different_results[0]["similarity"]

    assert variant_score > different_score, "Variant must score higher than different binary"
    assert variant_score > 0.5, "Similar variant must have >50% confidence"
    assert different_score < 0.5, "Different binary must have <50% confidence"

    assert 0.0 <= variant_score <= 1.0, "Scores must be normalized"
    assert 0.0 <= different_score <= 1.0, "Scores must be normalized"


@pytest.mark.real_data
def test_adaptive_weights_based_on_feature_richness(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
) -> None:
    """Adaptive weighting adjusts based on available features."""
    features = similarity_engine._extract_binary_features(str(sample_pe_binary))

    weights = similarity_engine._calculate_adaptive_weights(features, features)

    assert isinstance(weights, dict), "Weights must be dictionary"
    assert all(isinstance(v, float) for v in weights.values()), "All weights must be floats"

    total_weight = sum(weights.values())
    assert abs(total_weight - 1.0) < 0.01, "Weights must sum to 1.0"

    assert "structural" in weights, "Must include structural weight"
    assert "content" in weights, "Must include content weight"
    assert "advanced" in weights, "Must include advanced weight"
    assert "fuzzy" in weights, "Must include fuzzy weight"


@pytest.mark.real_data
def test_heavily_optimized_code_edge_case(
    similarity_engine: BinarySimilaritySearch,
    temp_db_dir: Path,
) -> None:
    """Similarity detection handles heavily optimized code patterns."""
    optimized_binary = temp_db_dir / "optimized.exe"

    pe_header = b"MZ" + b"\x90" * 60 + b"\x3C\x00\x00\x00"
    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0x5F5E100, 0, 0, 0xE0, 0x010B)
    optional_header = bytearray(224)
    optional_header[0:2] = struct.pack("<H", 0x010B)

    section_header = struct.pack("<8sIIIIIIHHI",
        b".text\x00\x00\x00", 0x1000, 0x1000, 0x800, 0x200, 0, 0, 0, 0, 0x60000020
    )

    optimized_code = bytearray(0x800)
    patterns = [
        b"\x31\xC0\x31\xDB\x31\xC9\x31\xD2",
        b"\x48\x31\xC0\x48\x31\xDB",
        b"\x33\xC0\x33\xDB\x33\xC9",
    ]
    for i in range(0, len(optimized_code) - 16, 32):
        pattern = patterns[i % len(patterns)]
        optimized_code[i:i+len(pattern)] = pattern

    pe_data = (
        pe_header +
        b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7 +
        pe_signature + coff_header + optional_header + section_header +
        bytes(0x200 - len(pe_header) - 64 - len(pe_signature) - len(coff_header) -
              len(optional_header) - len(section_header)) +
        optimized_code
    )

    optimized_binary.write_bytes(pe_data)

    features = similarity_engine._extract_binary_features(str(optimized_binary))

    assert features["file_size"] > 0, "Must extract file size from optimized binary"
    assert features["entropy"] > 0.0, "Must calculate entropy for optimized code"
    assert len(features["sections"]) > 0, "Must detect sections in optimized binary"


@pytest.mark.real_data
def test_compiler_variation_detection(
    similarity_engine: BinarySimilaritySearch,
    temp_db_dir: Path,
) -> None:
    """Similarity detection handles compiler optimization variations."""
    gcc_style = temp_db_dir / "gcc_compiled.exe"
    msvc_style = temp_db_dir / "msvc_compiled.exe"

    def create_compiler_variant(path: Path, prologue: bytes, epilogue: bytes) -> None:
        pe_header = b"MZ" + b"\x90" * 60 + b"\x3C\x00\x00\x00"
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0x5F5E100, 0, 0, 0xE0, 0x010B)
        optional_header = bytearray(224)
        optional_header[0:2] = struct.pack("<H", 0x010B)

        section_text = struct.pack("<8sIIIIIIHHI",
            b".text\x00\x00\x00", 0x1000, 0x1000, 0x600, 0x200, 0, 0, 0, 0, 0x60000020
        )
        section_rdata = struct.pack("<8sIIIIIIHHI",
            b".rdata\x00\x00", 0x400, 0x2000, 0x200, 0x800, 0, 0, 0, 0, 0x40000040
        )

        text_section = bytearray(0x600)
        for i in range(0, len(text_section) - len(prologue) - len(epilogue), 64):
            text_section[i:i+len(prologue)] = prologue
            text_section[i+32:i+32+len(epilogue)] = epilogue

        rdata_section = bytearray(0x200)
        rdata_section[0:13] = b"kernel32.dll\x00"
        rdata_section[13:26] = b"user32.dll\x00\x00\x00"

        pe_data = (
            pe_header +
            b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7 +
            pe_signature + coff_header + optional_header + section_text + section_rdata +
            bytes(0x200 - len(pe_header) - 64 - len(pe_signature) - len(coff_header) -
                  len(optional_header) - len(section_text) - len(section_rdata)) +
            text_section + rdata_section
        )

        path.write_bytes(pe_data)

    create_compiler_variant(gcc_style, b"\x55\x89\xE5\x83\xEC\x10", b"\x89\xEC\x5D\xC3")
    create_compiler_variant(msvc_style, b"\x55\x8B\xEC\x83\xEC\x10", b"\x8B\xE5\x5D\xC3")

    features_gcc = similarity_engine._extract_binary_features(str(gcc_style))
    features_msvc = similarity_engine._extract_binary_features(str(msvc_style))

    similarity = similarity_engine._calculate_similarity(features_gcc, features_msvc)

    assert similarity > 0.6, "Compiler variations must show high similarity"
    assert len(features_gcc["sections"]) == len(features_msvc["sections"]), "Section count must match"


@pytest.mark.real_data
def test_n_gram_similarity_for_code_patterns(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
) -> None:
    """N-gram analysis detects similar code patterns."""
    features1 = similarity_engine._extract_binary_features(str(sample_pe_binary))
    features2 = similarity_engine._extract_binary_features(str(variant_pe_binary))

    ngram_score = similarity_engine._calculate_ngram_similarity(
        features1.get("strings", []),
        features2.get("strings", [])
    )

    assert isinstance(ngram_score, float), "N-gram must return float score"
    assert 0.0 <= ngram_score <= 1.0, "N-gram score must be normalized"
    assert ngram_score > 0.0, "Similar binaries must have n-gram overlap"


@pytest.mark.real_data
def test_edit_distance_similarity_calculation(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
) -> None:
    """Edit distance calculates string sequence similarity."""
    features1 = similarity_engine._extract_binary_features(str(sample_pe_binary))
    features2 = similarity_engine._extract_binary_features(str(variant_pe_binary))

    edit_score = similarity_engine._calculate_edit_distance_similarity(
        features1.get("strings", []),
        features2.get("strings", [])
    )

    assert isinstance(edit_score, float), "Edit distance must return float"
    assert 0.0 <= edit_score <= 1.0, "Edit distance must be normalized"


@pytest.mark.real_data
def test_cosine_similarity_for_feature_vectors(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
) -> None:
    """Cosine similarity calculates vector-based similarity."""
    features1 = similarity_engine._extract_binary_features(str(sample_pe_binary))
    features2 = similarity_engine._extract_binary_features(str(variant_pe_binary))

    cosine_score = similarity_engine._calculate_cosine_similarity(features1, features2)

    assert isinstance(cosine_score, float), "Cosine similarity must return float"
    assert 0.0 <= cosine_score <= 1.0, "Cosine similarity must be normalized"
    assert cosine_score > 0.5, "Similar binaries must have high cosine similarity"


@pytest.mark.real_data
def test_entropy_pattern_similarity(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
) -> None:
    """Entropy distribution patterns detect similar code characteristics."""
    features1 = similarity_engine._extract_binary_features(str(sample_pe_binary))
    features2 = similarity_engine._extract_binary_features(str(variant_pe_binary))

    entropy_similarity = similarity_engine._calculate_entropy_pattern_similarity(features1, features2)

    assert isinstance(entropy_similarity, float), "Entropy similarity must return float"
    assert 0.0 <= entropy_similarity <= 1.0, "Entropy similarity must be normalized"


@pytest.mark.real_data
def test_control_flow_similarity_detection(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
) -> None:
    """Control flow patterns indicate similar execution structure."""
    features1 = similarity_engine._extract_binary_features(str(sample_pe_binary))
    features2 = similarity_engine._extract_binary_features(str(variant_pe_binary))

    cf_similarity = similarity_engine._calculate_control_flow_similarity(features1, features2)

    assert isinstance(cf_similarity, float), "Control flow similarity must return float"
    assert 0.0 <= cf_similarity <= 1.0, "Control flow similarity must be normalized"


@pytest.mark.real_data
def test_opcode_sequence_similarity(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
) -> None:
    """Opcode patterns detect similar instruction sequences."""
    features1 = similarity_engine._extract_binary_features(str(sample_pe_binary))
    features2 = similarity_engine._extract_binary_features(str(variant_pe_binary))

    opcode_similarity = similarity_engine._calculate_opcode_similarity(features1, features2)

    assert isinstance(opcode_similarity, float), "Opcode similarity must return float"
    assert 0.0 <= opcode_similarity <= 1.0, "Opcode similarity must be normalized"


@pytest.mark.real_data
def test_weighted_api_similarity_prioritizes_critical_apis(
    similarity_engine: BinarySimilaritySearch,
) -> None:
    """Weighted API similarity prioritizes security-critical APIs."""
    imports1 = ["kernel32.dll:LoadLibraryA", "kernel32.dll:GetProcAddress", "user32.dll:MessageBoxA"]
    imports2 = ["kernel32.dll:LoadLibraryA", "kernel32.dll:GetProcAddress", "user32.dll:CreateWindowExA"]

    similarity = similarity_engine._calculate_weighted_api_similarity(imports1, imports2)

    assert similarity > 0.5, "Shared critical APIs must produce high similarity"
    assert isinstance(similarity, float), "Must return float similarity score"


@pytest.mark.real_data
def test_pe_header_similarity_matching(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    cross_arch_binary: Path,
) -> None:
    """PE header metadata similarity detects structural matches."""
    features_x86 = similarity_engine._extract_binary_features(str(sample_pe_binary))
    features_x64 = similarity_engine._extract_binary_features(str(cross_arch_binary))

    header_similarity = similarity_engine._calculate_pe_header_similarity(features_x86, features_x64)

    assert isinstance(header_similarity, float), "Header similarity must return float"
    assert 0.0 <= header_similarity <= 1.0, "Header similarity must be normalized"
    assert header_similarity < 1.0, "Different architectures must have different headers"


@pytest.mark.real_data
def test_section_distribution_similarity(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
) -> None:
    """Section size distribution indicates similar binary structure."""
    features1 = similarity_engine._extract_binary_features(str(sample_pe_binary))
    features2 = similarity_engine._extract_binary_features(str(variant_pe_binary))

    dist_similarity = similarity_engine._calculate_section_distribution_similarity(
        features1.get("sections", []),
        features2.get("sections", [])
    )

    assert isinstance(dist_similarity, float), "Distribution similarity must return float"
    assert 0.0 <= dist_similarity <= 1.0, "Distribution similarity must be normalized"


@pytest.mark.real_data
def test_logarithmic_size_similarity_handles_large_differences(
    similarity_engine: BinarySimilaritySearch,
) -> None:
    """Logarithmic scaling reduces impact of large size differences."""
    small_size = 10240
    large_size = 10485760

    similarity = similarity_engine._calculate_logarithmic_size_similarity(small_size, large_size)

    assert isinstance(similarity, float), "Size similarity must return float"
    assert 0.0 <= similarity <= 1.0, "Size similarity must be normalized"
    assert similarity > 0.0, "Even large differences must show some similarity"


@pytest.mark.real_data
def test_rolling_hash_generation(
    similarity_engine: BinarySimilaritySearch,
) -> None:
    """Rolling hash produces consistent hashes for content."""
    strings1 = ["kernel32.dll", "LoadLibrary", "GetProcAddress"]
    strings2 = ["kernel32.dll", "LoadLibrary", "GetProcAddress"]
    strings3 = ["ntdll.dll", "NtQuerySystemInformation"]

    hash1 = similarity_engine._generate_rolling_hash(strings1)
    hash2 = similarity_engine._generate_rolling_hash(strings2)
    hash3 = similarity_engine._generate_rolling_hash(strings3)

    assert hash1 == hash2, "Identical strings must produce identical hashes"
    assert hash1 != hash3, "Different strings must produce different hashes"
    assert len(hash1) == 64, "SHA-256 hex must be 64 characters"


@pytest.mark.real_data
def test_hash_similarity_hamming_distance(
    similarity_engine: BinarySimilaritySearch,
) -> None:
    """Hash similarity uses Hamming distance for comparison."""
    hash1 = "a" * 64
    hash2 = "a" * 63 + "b"
    hash3 = "b" * 64

    similarity_identical = similarity_engine._calculate_hash_similarity(hash1, hash1)
    similarity_close = similarity_engine._calculate_hash_similarity(hash1, hash2)
    similarity_different = similarity_engine._calculate_hash_similarity(hash1, hash3)

    assert similarity_identical == 1.0, "Identical hashes must have 1.0 similarity"
    assert similarity_close > 0.9, "Nearly identical hashes must be very similar"
    assert similarity_different < 0.5, "Different hashes must have low similarity"


@pytest.mark.real_data
def test_database_persistence(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    temp_db_dir: Path,
) -> None:
    """Binary database persists and loads correctly."""
    similarity_engine.add_binary(str(sample_pe_binary), ["test_pattern"])

    db_path = temp_db_dir / "test_binary_db.json"
    assert db_path.exists(), "Database file must be created"

    with open(db_path, encoding="utf-8") as f:
        db_data = json.load(f)

    assert "binaries" in db_data, "Database must contain binaries key"
    assert len(db_data["binaries"]) == 1, "Database must contain added binary"
    assert db_data["binaries"][0]["path"] == str(sample_pe_binary), "Path must match"

    new_engine = BinarySimilaritySearch(str(db_path))
    assert len(new_engine.database["binaries"]) == 1, "Loaded database must contain binary"


@pytest.mark.real_data
def test_database_statistics(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
) -> None:
    """Database statistics provide meaningful metrics."""
    similarity_engine.add_binary(str(sample_pe_binary), ["pattern1", "pattern2"])
    similarity_engine.add_binary(str(variant_pe_binary), ["pattern3"])

    stats = similarity_engine.get_database_stats()

    assert stats["total_binaries"] == 2, "Must count all binaries"
    assert stats["total_patterns"] == 3, "Must count all patterns"
    assert stats["avg_file_size"] > 0, "Must calculate average size"
    assert isinstance(stats["unique_imports"], int), "Must count unique imports"
    assert isinstance(stats["unique_exports"], int), "Must count unique exports"


@pytest.mark.real_data
def test_binary_removal_from_database(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
) -> None:
    """Binary removal correctly updates database."""
    similarity_engine.add_binary(str(sample_pe_binary), ["pattern"])

    assert len(similarity_engine.database["binaries"]) == 1, "Binary must be added"

    result = similarity_engine.remove_binary(str(sample_pe_binary))

    assert result is True, "Removal must succeed"
    assert len(similarity_engine.database["binaries"]) == 0, "Binary must be removed"


@pytest.mark.real_data
def test_duplicate_binary_rejection(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
) -> None:
    """Duplicate binaries are rejected."""
    result1 = similarity_engine.add_binary(str(sample_pe_binary), ["pattern"])
    result2 = similarity_engine.add_binary(str(sample_pe_binary), ["pattern"])

    assert result1 is True, "First addition must succeed"
    assert result2 is False, "Duplicate addition must fail"
    assert len(similarity_engine.database["binaries"]) == 1, "Only one entry must exist"


@pytest.mark.real_data
def test_similarity_threshold_filtering(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
    different_binary: Path,
) -> None:
    """Similarity threshold correctly filters results."""
    similarity_engine.add_binary(str(sample_pe_binary), ["original"])
    similarity_engine.add_binary(str(different_binary), ["different"])

    low_threshold_results = similarity_engine.search_similar_binaries(str(variant_pe_binary), threshold=0.3)
    high_threshold_results = similarity_engine.search_similar_binaries(str(variant_pe_binary), threshold=0.8)

    assert len(low_threshold_results) >= len(high_threshold_results), "Lower threshold must return more results"

    for result in high_threshold_results:
        assert result["similarity"] >= 0.8, "High threshold results must meet threshold"


@pytest.mark.real_data
def test_feature_extraction_completeness(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
) -> None:
    """Feature extraction captures all required binary characteristics."""
    features = similarity_engine._extract_binary_features(str(sample_pe_binary))

    assert "file_size" in features and features["file_size"] > 0, "Must extract file size"
    assert "entropy" in features and features["entropy"] > 0.0, "Must calculate entropy"
    assert "sections" in features and len(features["sections"]) > 0, "Must extract sections"
    assert "imports" in features, "Must extract imports"
    assert "exports" in features, "Must extract exports"
    assert "strings" in features, "Must extract strings"
    assert "machine" in features, "Must extract machine type"
    assert "timestamp" in features, "Must extract timestamp"
    assert "characteristics" in features, "Must extract characteristics"


@pytest.mark.real_data
def test_empty_database_handling(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
) -> None:
    """Empty database returns no results gracefully."""
    results = similarity_engine.search_similar_binaries(str(sample_pe_binary), threshold=0.5)

    assert results == [], "Empty database must return empty results"
    assert isinstance(results, list), "Must return list type"


@pytest.mark.real_data
def test_nonexistent_binary_handling(
    similarity_engine: BinarySimilaritySearch,
    temp_db_dir: Path,
) -> None:
    """Nonexistent binary path handled gracefully."""
    fake_path = temp_db_dir / "nonexistent.exe"

    features = similarity_engine._extract_binary_features(str(fake_path))

    assert features["file_size"] == 0, "Nonexistent binary must have zero size"
    assert features["entropy"] == 0.0, "Nonexistent binary must have zero entropy"


@pytest.mark.real_data
def test_find_similar_alias_method(
    similarity_engine: BinarySimilaritySearch,
    sample_pe_binary: Path,
    variant_pe_binary: Path,
) -> None:
    """find_similar() method works as alias for search_similar_binaries()."""
    similarity_engine.add_binary(str(sample_pe_binary), ["pattern"])

    results = similarity_engine.find_similar(str(variant_pe_binary), threshold=0.5)

    assert isinstance(results, list), "Must return list of results"
    assert len(results) > 0, "Must find similar binaries"


@pytest.mark.real_data
def test_real_windows_executables_if_available() -> None:
    """Test with real Windows system binaries if available."""
    system32 = Path(r"C:\Windows\System32")

    if not system32.exists():
        pytest.skip("Windows System32 not available")

    notepad = system32 / "notepad.exe"
    calc = system32 / "calc.exe"

    if not notepad.exists() or not calc.exists():
        pytest.skip("Required system binaries not found")

    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "system_db.json"
        engine = BinarySimilaritySearch(str(db_path))

        engine.add_binary(str(notepad), ["system_tool"])

        results = engine.search_similar_binaries(str(calc), threshold=0.3)

        assert isinstance(results, list), "Must process real Windows binaries"

        features_notepad = engine._extract_binary_features(str(notepad))
        features_calc = engine._extract_binary_features(str(calc))

        assert features_notepad["file_size"] > 0, "Must extract notepad size"
        assert features_calc["file_size"] > 0, "Must extract calc size"
        assert len(features_notepad["imports"]) > 0, "Must extract notepad imports"
        assert len(features_calc["imports"]) > 0, "Must extract calc imports"


@pytest.mark.real_data
def test_fixture_binaries_similarity_analysis(temp_db_dir: Path) -> None:
    """Test with actual fixture binaries from test suite."""
    fixtures_dir = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe" / "legitimate"

    if not fixtures_dir.exists():
        pytest.skip("Fixture binaries not available")

    available_binaries = list(fixtures_dir.glob("*.exe"))

    if len(available_binaries) < 2:
        pytest.skip("Not enough fixture binaries for comparison")

    db_path = temp_db_dir / "fixture_db.json"
    engine = BinarySimilaritySearch(str(db_path))

    first_binary = available_binaries[0]
    engine.add_binary(str(first_binary), ["fixture_binary"])

    for test_binary in available_binaries[1:3]:
        results = engine.search_similar_binaries(str(test_binary), threshold=0.0)

        assert isinstance(results, list), f"Must process {test_binary.name}"

        features = engine._extract_binary_features(str(test_binary))
        assert features["file_size"] > 0, f"Must extract size from {test_binary.name}"
