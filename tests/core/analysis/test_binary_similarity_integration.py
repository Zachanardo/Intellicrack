"""Integration tests for Binary Similarity Search with real cracking scenarios.

Tests validate offensive capability across realistic cracking workflows:
- Building databases of cracked binaries with associated patterns
- Finding similar protected targets to apply known cracks
- Cross-protection similarity (UPX vs VMProtect vs Themida)
- Confidence scoring for crack applicability
- Database persistence and search performance

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
import struct
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, cast

import pytest

from intellicrack.core.analysis.binary_similarity_search import (
    BinarySimilaritySearch,
    create_similarity_search,
)


class TestCrackingPatternDatabase:
    """Test building and using database of cracked binaries."""

    @pytest.fixture
    def search_engine(self, tmp_path: Path) -> BinarySimilaritySearch:
        """Create search engine with temporary database."""
        db_path = tmp_path / "crack_patterns.json"
        return BinarySimilaritySearch(database_path=str(db_path))

    @pytest.fixture
    def create_protected_binary(self, tmp_path: Path) -> Callable[[str, str, bytes], Path]:
        """Factory to create realistic protected binaries."""
        def _create(name: str, protection_type: str, license_check_pattern: bytes) -> Path:
            binary_path = tmp_path / f"{name}_{protection_type}.exe"

            dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
            pe_header = b"PE\x00\x00" + struct.pack("<H", 0x8664) + struct.pack("<H", 2)
            file_header = b"\x00" * 14
            optional_header = struct.pack("<H", 0x020B) + b"\x00" * 222

            text_section = b".text\x00\x00\x00" + struct.pack("<I", 0x1000) + b"\x00" * 28
            data_section = b".data\x00\x00\x00" + struct.pack("<I", 0x3000) + b"\x00" * 28

            padding = b"\x00" * (0x200 - len(dos_header) - len(pe_header) -
                                 len(file_header) - len(optional_header) -
                                 len(text_section) - len(data_section))

            protection_markers = {
                "UPX": b"UPX0" + b"\x00" * 4 + b"UPX1" + b"\x00" * 4,
                "VMProtect": b".vmp0\x00\x00\x00" + b"\x00" * 8,
                "Themida": b".themida" + b"\x00" * 6,
            }

            marker = protection_markers.get(protection_type, b"\x00" * 16)

            code_data = marker + license_check_pattern + b"\x00" * 2000

            imports = (
                b"kernel32.dll\x00CreateFileW\x00ReadFile\x00"
                b"advapi32.dll\x00RegOpenKeyExW\x00RegQueryValueExW\x00"
                b"crypt32.dll\x00CryptDecrypt\x00CryptVerifySignature\x00"
            )

            full_binary = (dos_header + pe_header + file_header + optional_header +
                          text_section + data_section + padding + code_data + imports)

            binary_path.write_bytes(full_binary)
            return binary_path

        return _create

    def test_build_database_of_cracked_binaries(
        self,
        search_engine: BinarySimilaritySearch,
        create_protected_binary: Any
    ) -> None:
        """Build database with cracked binaries and their successful crack patterns."""
        license_check_v1 = (
            b"\x55\x89\xE5"  # function prologue
            b"\x83\xEC\x10"  # allocate locals
            b"\x8B\x45\x08"  # get license param
            b"\x83\xF8\x00"  # compare to 0
            b"\x74\x05"      # jump if equal (invalid)
            b"\xB8\x01\x00\x00\x00"  # return 1 (valid)
            b"\xEB\x03"      # jump to exit
            b"\x31\xC0"      # return 0 (invalid)
            b"\x89\xEC\x5D\xC3"  # epilogue
        )

        crack_patterns_v1 = [
            "NOP sled at offset +0x15 (4 bytes)",
            "Patch JE to JMP at offset +0x10",
            "Change CMP to XOR EAX,EAX; INC EAX at offset +0x0C",
        ]

        binary1 = create_protected_binary("product_v1.0", "UPX", license_check_v1)
        success = search_engine.add_binary(str(binary1), crack_patterns_v1)

        assert success is True
        assert len(search_engine.database["binaries"]) == 1

        entry = search_engine.database["binaries"][0]
        assert entry["path"] == str(binary1)
        assert entry["cracking_patterns"] == crack_patterns_v1
        assert "features" in entry

        license_check_v2 = (
            b"\x55\x8B\xEC"  # slightly different prologue
            b"\x83\xEC\x14"  # more locals
            b"\x8B\x45\x08"  # get license param
            b"\x85\xC0"      # test eax, eax (different comparison)
            b"\x74\x07"      # jump if zero
            b"\xC7\x45\xFC\x01\x00\x00\x00"  # set local = 1
            b"\xEB\x05"      # jump
            b"\x33\xC0"      # xor eax, eax
            b"\x8B\x45\xFC"  # return local
            b"\x8B\xE5\x5D\xC3"  # epilogue
        )

        crack_patterns_v2 = [
            "NOP sled at offset +0x16 (6 bytes)",
            "Patch JE to JNE at offset +0x0A",
        ]

        binary2 = create_protected_binary("product_v1.1", "UPX", license_check_v2)
        search_engine.add_binary(str(binary2), crack_patterns_v2)

        assert len(search_engine.database["binaries"]) == 2

        stats = search_engine.get_database_stats()
        assert stats["total_binaries"] == 2
        assert stats["total_patterns"] == len(crack_patterns_v1) + len(crack_patterns_v2)

    def test_find_similar_target_to_apply_known_crack(
        self,
        search_engine: BinarySimilaritySearch,
        create_protected_binary: Any
    ) -> None:
        """Find similar protected binary to apply known working crack."""
        known_cracked = create_protected_binary(
            "known_cracked",
            "VMProtect",
            b"\x55\x89\xE5\x83\xEC\x20" + b"LICENSE_CHECK_CODE" + b"\x00" * 100
        )

        successful_crack = [
            "VMProtect: Locate VM entry at offset +0x1234",
            "Find license validation in devirtualized code",
            "Patch validation return value to always return 1",
            "Rebuild import table",
        ]

        search_engine.add_binary(str(known_cracked), successful_crack)

        new_target = create_protected_binary(
            "new_target",
            "VMProtect",
            b"\x55\x8B\xEC\x83\xEC\x24" + b"LICENSE_CHECK_CODE" + b"\x00" * 100
        )

        similar_binaries = search_engine.search_similar_binaries(
            str(new_target),
            threshold=0.3
        )

        assert isinstance(similar_binaries, list)

        if similar_binaries:
            most_similar = similar_binaries[0]
            assert "cracking_patterns" in most_similar
            assert "similarity" in most_similar

            assert most_similar["similarity"] >= 0.3, \
                "Should find VMProtect-protected binary as similar"

            assert len(most_similar["cracking_patterns"]) > 0, \
                "Should return known crack patterns for similar binary"

    def test_database_persistence_across_sessions(
        self,
        tmp_path: Path,
        create_protected_binary: Any
    ) -> None:
        """Database persists crack patterns across tool sessions."""
        db_path = tmp_path / "persistent_db.json"

        session1 = BinarySimilaritySearch(database_path=str(db_path))

        binary1 = create_protected_binary("app1", "UPX", b"CODE1" + b"\x00" * 100)
        patterns1 = ["Crack pattern 1", "Crack pattern 2"]

        session1.add_binary(str(binary1), patterns1)
        del session1

        session2 = BinarySimilaritySearch(database_path=str(db_path))

        assert len(session2.database["binaries"]) == 1, \
            "Database must persist after session ends"

        loaded_entry = session2.database["binaries"][0]
        assert loaded_entry["cracking_patterns"] == patterns1

        binary2 = create_protected_binary("app2", "UPX", b"CODE2" + b"\x00" * 100)
        patterns2 = ["Crack pattern 3"]

        session2.add_binary(str(binary2), patterns2)
        del session2

        session3 = BinarySimilaritySearch(database_path=str(db_path))

        assert len(session3.database["binaries"]) == 2, \
            "All entries must persist across sessions"

        stats = session3.get_database_stats()
        assert stats["total_binaries"] == 2
        assert stats["total_patterns"] == 3

    def test_remove_outdated_crack_patterns(
        self,
        search_engine: BinarySimilaritySearch,
        create_protected_binary: Any
    ) -> None:
        """Remove outdated crack patterns from database."""
        binary = create_protected_binary("old_app", "Themida", b"OLD_CODE" + b"\x00" * 100)
        old_patterns = ["Outdated crack 1", "Outdated crack 2"]

        search_engine.add_binary(str(binary), old_patterns)
        assert len(search_engine.database["binaries"]) == 1

        removed = search_engine.remove_binary(str(binary))

        assert removed is True
        assert len(search_engine.database["binaries"]) == 0, \
            "Outdated entry must be removed from database"

        remove_again = search_engine.remove_binary(str(binary))
        assert remove_again is False, "Removing non-existent entry should fail"


class TestCrossProtectionSimilarity:
    """Test similarity detection across different protection schemes."""

    @pytest.fixture
    def search_engine(self, tmp_path: Path) -> BinarySimilaritySearch:
        """Create search engine with temporary database."""
        db_path = tmp_path / "cross_protection.json"
        return BinarySimilaritySearch(database_path=str(db_path))

    def test_detect_similar_licensing_across_different_protections(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Detects similar licensing logic despite different protections."""
        upx_protected: dict[str, Any] = {
            "sections": [
                {"name": "UPX0", "entropy": 7.9},
                {"name": "UPX1", "entropy": 0.5},
                {"name": ".rsrc", "entropy": 5.0},
            ],
            "imports": [
                "kernel32.dll:CreateFileW",
                "advapi32.dll:RegOpenKeyExW",
                "advapi32.dll:RegQueryValueExW",
                "crypt32.dll:CryptDecrypt",
            ] * 10,
            "strings": [
                "License Key",
                "Product Activation",
                "Serial Number",
                "Registration Required",
            ] * 5,
            "entropy": 6.5,
            "file_size": 51200,
        }

        vmprotect_protected: dict[str, Any] = {
            "sections": [
                {"name": ".vmp0", "entropy": 7.8},
                {"name": ".vmp1", "entropy": 7.5},
                {"name": ".text", "entropy": 6.0},
            ],
            "imports": [
                "kernel32.dll:CreateFileW",
                "advapi32.dll:RegOpenKeyExW",
                "advapi32.dll:RegQueryValueExW",
                "crypt32.dll:CryptHashData",
            ] * 10,
            "strings": [
                "License Key",
                "Product Activation",
                "Serial Code",
                "Registration Needed",
            ] * 5,
            "entropy": 7.2,
            "file_size": 73728,
        }

        similarity = search_engine._calculate_similarity(upx_protected, vmprotect_protected)

        assert isinstance(similarity, float)
        assert 0.0 <= similarity <= 1.0

        assert similarity > 0.4, \
            "Must detect similar licensing logic across UPX and VMProtect protection"

        content_sim = search_engine._calculate_content_similarity(
            upx_protected, vmprotect_protected
        )

        assert content_sim > 0.3, \
            "String-based licensing indicators should be detected despite protection"

    def test_statistical_similarity_normalizes_for_protection_overhead(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Statistical similarity accounts for protection scheme overhead."""
        unprotected: dict[str, Any] = {
            "file_size": 20480,
            "entropy": 5.5,
            "sections": [
                {"name": ".text", "entropy": 5.8, "raw_data_size": 10240},
                {"name": ".data", "entropy": 4.0, "raw_data_size": 5120},
            ],
        }

        themida_protected: dict[str, Any] = {
            "file_size": 122880,
            "entropy": 7.8,
            "sections": [
                {"name": ".themida", "entropy": 7.9, "raw_data_size": 81920},
                {"name": ".text", "entropy": 7.5, "raw_data_size": 20480},
                {"name": ".data", "entropy": 7.0, "raw_data_size": 10240},
            ],
        }

        statistical_sim = search_engine._calculate_statistical_similarity(
            unprotected, themida_protected
        )

        assert isinstance(statistical_sim, float)
        assert 0.0 <= statistical_sim <= 1.0

        size_sim = search_engine._calculate_logarithmic_size_similarity(
            unprotected["file_size"],
            themida_protected["file_size"]
        )

        assert size_sim > 0.1, \
            "Logarithmic scaling should prevent size difference from dominating"


class TestSimilarityScoring:
    """Test confidence-based similarity scoring for crack applicability."""

    @pytest.fixture
    def search_engine(self, tmp_path: Path) -> BinarySimilaritySearch:
        """Create search engine with temporary database."""
        db_path = tmp_path / "scoring_test.json"
        return BinarySimilaritySearch(database_path=str(db_path))

    def test_high_confidence_score_for_near_identical_binaries(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """High similarity score indicates high confidence for crack applicability."""
        base_features: dict[str, Any] = {
            "file_size": 32768,
            "entropy": 6.2,
            "sections": [
                {"name": ".text", "entropy": 6.5},
                {"name": ".data", "entropy": 4.5},
                {"name": ".rsrc", "entropy": 5.0},
            ],
            "imports": ["kernel32.dll:CreateFileW", "advapi32.dll:RegOpenKeyW"] * 25,
            "exports": ["CheckLicense", "ValidateKey", "ActivateProduct"],
            "strings": ["License validation", "Product key required"] * 20,
            "machine": 0x8664,
            "characteristics": 0x0022,
        }

        nearly_identical: dict[str, Any] = {
            "file_size": 33792,
            "entropy": 6.3,
            "sections": [
                {"name": ".text", "entropy": 6.4},
                {"name": ".data", "entropy": 4.6},
                {"name": ".rsrc", "entropy": 5.1},
            ],
            "imports": ["kernel32.dll:CreateFileW", "advapi32.dll:RegOpenKeyW"] * 24,
            "exports": ["CheckLicense", "ValidateKey", "ActivateProduct"],
            "strings": ["License validation", "Product key required"] * 19,
            "machine": 0x8664,
            "characteristics": 0x0022,
        }

        similarity = search_engine._calculate_similarity(base_features, nearly_identical)

        assert similarity > 0.8, \
            "Near-identical binaries should have >0.8 similarity (high confidence)"

    def test_medium_confidence_score_for_similar_but_different_versions(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Medium similarity score indicates crack may need adjustment."""
        v1_features: dict[str, Any] = {
            "file_size": 40960,
            "entropy": 6.0,
            "imports": ["kernel32.dll:CreateFileA"] * 30,
            "strings": ["Version 1.0", "License check"] * 15,
        }

        v2_features: dict[str, Any] = {
            "file_size": 49152,
            "entropy": 6.5,
            "imports": ["kernel32.dll:CreateFileW"] * 35,
            "strings": ["Version 2.0", "License validation"] * 18,
        }

        similarity = search_engine._calculate_similarity(v1_features, v2_features)

        assert 0.3 < similarity < 0.7, \
            "Different versions should have medium similarity (0.3-0.7)"

    def test_low_confidence_score_for_unrelated_binaries(
        self,
        search_engine: BinarySimilaritySearch
    ) -> None:
        """Low similarity score indicates crack unlikely to be applicable."""
        license_tool_features: dict[str, Any] = {
            "imports": [
                "crypt32.dll:CryptDecrypt",
                "crypt32.dll:CryptVerifySignature",
                "advapi32.dll:RegSetValueExW",
            ] * 20,
            "strings": ["License", "Activation", "Product Key"] * 10,
            "entropy": 6.0,
        }

        game_features: dict[str, Any] = {
            "imports": [
                "d3d11.dll:D3D11CreateDevice",
                "xinput1_3.dll:XInputGetState",
                "user32.dll:CreateWindowExW",
            ] * 20,
            "strings": ["Level", "Score", "Player"] * 10,
            "entropy": 6.2,
        }

        similarity = search_engine._calculate_similarity(
            license_tool_features, game_features
        )

        assert similarity < 0.3, \
            "Unrelated binaries should have <0.3 similarity (low confidence)"


class TestPerformanceAndScalability:
    """Test search performance with large binary databases."""

    @pytest.fixture
    def search_engine(self, tmp_path: Path) -> BinarySimilaritySearch:
        """Create search engine with temporary database."""
        db_path = tmp_path / "performance_test.json"
        return BinarySimilaritySearch(database_path=str(db_path))

    def test_search_performance_with_100_database_entries(
        self,
        search_engine: BinarySimilaritySearch,
        tmp_path: Path
    ) -> None:
        """Search completes in reasonable time with 100 database entries."""
        for i in range(100):
            binary_path = tmp_path / f"binary_{i}.exe"
            binary_path.write_bytes(b"MZ" + os.urandom(1024 + i * 10))

            features = {
                "file_size": 1024 + i * 10,
                "entropy": 5.0 + (i % 30) / 10.0,
                "imports": [f"dll{j}.dll:Function{j}" for j in range(10 + i % 20)],
                "strings": [f"String{j}" for j in range(15 + i % 25)],
            }

            search_engine.database["binaries"].append({
                "path": str(binary_path),
                "filename": binary_path.name,
                "features": features,
                "cracking_patterns": [f"Pattern_{i}"],
                "added": "2025-01-01T00:00:00",
                "file_size": features["file_size"],
            })

        search_engine._save_database()

        target_binary = tmp_path / "target.exe"
        target_binary.write_bytes(b"MZ" + os.urandom(2048))

        start_time = time.time()
        results = search_engine.search_similar_binaries(str(target_binary), threshold=0.1)
        elapsed = time.time() - start_time

        assert elapsed < 30.0, \
            "Search of 100 entries must complete within 30 seconds"

        assert isinstance(results, list)

    def test_feature_extraction_performance(
        self,
        search_engine: BinarySimilaritySearch,
        tmp_path: Path
    ) -> None:
        """Feature extraction completes quickly for typical binary."""
        binary_path = tmp_path / "test_binary.exe"

        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x8664) + struct.pack("<H", 3)
        sections = b".text\x00\x00\x00" + b"\x00" * 32
        sections += b".data\x00\x00\x00" + b"\x00" * 32
        sections += b".rsrc\x00\x00\x00" + b"\x00" * 32

        code_and_data = os.urandom(8192)

        binary_path.write_bytes(dos_header + pe_header + sections + code_and_data)

        start_time = time.time()
        features = search_engine._extract_binary_features(str(binary_path))
        elapsed = time.time() - start_time

        assert elapsed < 2.0, "Feature extraction must complete within 2 seconds"
        assert features["file_size"] > 0
        assert isinstance(features["entropy"], float)

    def test_database_loading_performance(
        self,
        tmp_path: Path
    ) -> None:
        """Database with many entries loads quickly."""
        db_path = tmp_path / "large_db.json"

        large_database = {"binaries": []}
        for i in range(500):
            large_database["binaries"].append({
                "path": f"/path/to/binary_{i}.exe",
                "filename": f"binary_{i}.exe",
                "features": {
                    "file_size": 1024 * i,
                    "entropy": 5.0 + i / 100.0,
                    "imports": [f"import_{j}" for j in range(10)],
                },
                "cracking_patterns": [f"pattern_{i}"],
                "added": "2025-01-01T00:00:00",
                "file_size": 1024 * i,
            })

        with open(db_path, 'w') as f:
            json.dump(large_database, f)

        start_time = time.time()
        engine = BinarySimilaritySearch(database_path=str(db_path))
        elapsed = time.time() - start_time

        assert elapsed < 5.0, "Loading 500-entry database must complete within 5 seconds"
        assert len(engine.database["binaries"]) == 500


class TestRealWorldCrackingWorkflow:
    """Integration test of complete cracking workflow using similarity search."""

    @pytest.fixture
    def search_engine(self, tmp_path: Path) -> BinarySimilaritySearch:
        """Create search engine with temporary database."""
        db_path = tmp_path / "workflow_test.json"
        return BinarySimilaritySearch(database_path=str(db_path))

    def test_complete_workflow_find_and_apply_crack(
        self,
        search_engine: BinarySimilaritySearch,
        tmp_path: Path
    ) -> None:
        """Complete workflow: analyze target, find similar, get crack patterns."""
        cracked_binary_1 = tmp_path / "shareware_app_v1.exe"
        cracked_binary_1.write_bytes(
            b"MZ" + struct.pack("<H", 0x8664) +
            b"LICENSE_CHECK_V1" + b"\x00" * 500 +
            b"Trial Expired\x00Product Key\x00"
        )

        crack_patterns_1 = [
            "Step 1: Locate trial check at offset 0x1A40",
            "Step 2: NOP out JE instruction at 0x1A48",
            "Step 3: Change trial days from 30 to 36500",
            "Step 4: Patch 'Trial Expired' message check",
        ]

        search_engine.add_binary(str(cracked_binary_1), crack_patterns_1)

        cracked_binary_2 = tmp_path / "shareware_app_v2.exe"
        cracked_binary_2.write_bytes(
            b"MZ" + struct.pack("<H", 0x8664) +
            b"LICENSE_CHECK_V2_MODIFIED" + b"\x00" * 450 +
            b"Trial Ended\x00Serial Number\x00"
        )

        crack_patterns_2 = [
            "Step 1: Locate trial check at offset 0x1B20",
            "Step 2: Patch JNE to JMP at 0x1B30",
            "Step 3: Modify trial counter reset logic",
        ]

        search_engine.add_binary(str(cracked_binary_2), crack_patterns_2)

        new_target = tmp_path / "shareware_app_v1.1.exe"
        new_target.write_bytes(
            b"MZ" + struct.pack("<H", 0x8664) +
            b"LICENSE_CHECK_V1_UPDATED" + b"\x00" * 475 +
            b"Trial Expired\x00License Key\x00"
        )

        similar_binaries = search_engine.search_similar_binaries(
            str(new_target),
            threshold=0.3
        )

        assert len(similar_binaries) > 0, "Must find similar cracked binaries"

        similar_binaries_sorted = sorted(
            similar_binaries,
            key=lambda x: cast(float, x["similarity"]),
            reverse=True
        )

        best_match = similar_binaries_sorted[0]

        assert "cracking_patterns" in best_match
        assert len(best_match["cracking_patterns"]) > 0

        applicable_patterns = best_match["cracking_patterns"]

        assert any("trial" in pattern.lower() for pattern in applicable_patterns), \
            "Crack patterns should reference trial manipulation"

        assert best_match["similarity"] >= 0.3, \
            "Best match should meet similarity threshold"

    def test_workflow_with_cross_version_similarity(
        self,
        search_engine: BinarySimilaritySearch,
        tmp_path: Path
    ) -> None:
        """Find applicable cracks across software versions."""
        v1_binary = tmp_path / "product_v1.0.exe"
        v1_binary.write_bytes(
            b"MZ" + b"PE\x00\x00" +
            b"kernel32.dll\x00CreateFileA\x00RegOpenKeyExA\x00" +
            b"Version 1.0\x00License Check\x00" + b"\x00" * 800
        )

        v1_crack = [
            "Patch license validation at 0x2340",
            "Modify registry check routine",
            "Skip hardware ID verification",
        ]

        search_engine.add_binary(str(v1_binary), v1_crack)

        v1_5_binary = tmp_path / "product_v1.5.exe"
        v1_5_binary.write_bytes(
            b"MZ" + b"PE\x00\x00" +
            b"kernel32.dll\x00CreateFileW\x00RegOpenKeyExW\x00" +  # Unicode
            b"Version 1.5\x00License Validation\x00" + b"\x00" * 750
        )

        results = search_engine.search_similar_binaries(str(v1_5_binary), threshold=0.2)

        assert len(results) > 0

        if results:
            result = results[0]
            assert "License" in " ".join(result["cracking_patterns"]), \
                "Should find license-related crack patterns"

    def test_database_statistics_provide_insights(
        self,
        search_engine: BinarySimilaritySearch,
        tmp_path: Path
    ) -> None:
        """Database statistics help understand crack pattern coverage."""
        for i in range(10):
            binary = tmp_path / f"app_{i}.exe"
            binary.write_bytes(b"MZ" + os.urandom(512) + f"App{i}\x00".encode())

            patterns = [f"Crack technique {j}" for j in range(i % 5 + 1)]
            search_engine.add_binary(str(binary), patterns)

        stats = search_engine.get_database_stats()

        assert stats["total_binaries"] == 10
        assert stats["total_patterns"] > 0
        assert stats["avg_file_size"] > 0

        assert isinstance(stats["unique_imports"], int)
        assert isinstance(stats["unique_exports"], int)

        assert stats["total_binaries"] > 0, \
            "Statistics should show database is populated"
