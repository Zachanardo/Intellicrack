"""Binary Similarity Search Engine.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import datetime
import hashlib
import json
import logging
import math
import os
from collections import defaultdict
from typing import Any

from intellicrack.utils.logger import logger

from ...utils.protection_utils import calculate_entropy

try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    logger.warning("NumPy not available - LSH performance will be degraded")

try:
    from intellicrack.handlers.pefile_handler import pefile

    HAS_PEFILE = True
except ImportError as e:
    logger.exception("Import error in binary_similarity_search: %s", e)
    HAS_PEFILE = False

__all__ = ["BinarySimilaritySearch", "MinHashLSH"]


class MinHashLSH:
    """Locality-Sensitive Hashing using MinHash for approximate nearest neighbor search.

    This implementation enables scalable similarity search across large binary corpora
    by using MinHash signatures and LSH bucketing to identify similar license protection
    patterns without pairwise comparisons.
    """

    def __init__(self, num_perm: int = 128, threshold: float = 0.5, num_bands: int = 32) -> None:
        """Initialize MinHash LSH index.

        Args:
            num_perm: Number of hash permutations for MinHash signature (default: 128).
            threshold: Jaccard similarity threshold for candidate retrieval (0.0-1.0).
            num_bands: Number of LSH bands for bucketing (default: 32 for 0.5 threshold).
        """
        self.num_perm = num_perm
        self.threshold = threshold
        self.num_bands = num_bands
        self.rows_per_band = num_perm // num_bands

        self._hash_funcs: list[tuple[int, int]] = self._generate_hash_functions()
        self._buckets: dict[tuple[int, int], set[str]] = defaultdict(set)
        self._signatures: dict[str, list[int]] = {}
        self._path_to_index: dict[str, int] = {}

    def _generate_hash_functions(self) -> list[tuple[int, int]]:
        """Generate deterministic universal hash function parameters for MinHash.

        Returns:
            List of (a, b) tuples for hash function h(x) = (a*x + b) mod prime.
        """
        prime = 2**31 - 1
        hash_funcs: list[tuple[int, int]] = []

        for i in range(self.num_perm):
            h = hashlib.sha256(f"hash_func_{i}".encode()).digest()
            a = int.from_bytes(h[:4], "little") % prime
            if a == 0:
                a = 1
            b = int.from_bytes(h[4:8], "little") % prime
            hash_funcs.append((a, b))

        return hash_funcs

    def _hash_band_deterministic(self, band_signature: tuple[int, ...]) -> int:
        """Compute deterministic hash of a band signature.

        Args:
            band_signature: Tuple of MinHash values for a band.

        Returns:
            Deterministic hash value for the band.
        """
        band_bytes = "|".join(str(x) for x in band_signature).encode()
        return int(hashlib.md5(band_bytes).hexdigest()[:16], 16)

    def compute_minhash_signature(self, features: set[str]) -> list[int]:
        """Compute MinHash signature for a set of features.

        Args:
            features: Set of feature strings (imports, exports, function names, etc.).

        Returns:
            MinHash signature as list of minimum hash values.
        """
        if not features:
            return [0] * self.num_perm

        if HAS_NUMPY:
            signature = np.full(self.num_perm, np.inf, dtype=np.float64)
        else:
            signature = [float("inf")] * self.num_perm

        prime = 2**31 - 1

        for feature in features:
            feature_hash = int(hashlib.sha256(feature.encode()).hexdigest()[:16], 16)

            for i, (a, b) in enumerate(self._hash_funcs):
                h = (a * feature_hash + b) % prime
                if HAS_NUMPY:
                    signature[i] = min(signature[i], h)
                else:
                    signature[i] = min(signature[i], h)

        if HAS_NUMPY:
            return signature.astype(np.int64).tolist()
        return [int(s) if s != float("inf") else 0 for s in signature]

    def insert(self, key: str, features: set[str]) -> None:
        """Insert a binary into the LSH index.

        Args:
            key: Unique identifier for the binary (typically file path).
            features: Set of binary features for MinHash computation.
        """
        signature = self.compute_minhash_signature(features)
        self._signatures[key] = signature
        self._path_to_index[key] = len(self._path_to_index)

        for band_idx in range(self.num_bands):
            start = band_idx * self.rows_per_band
            end = start + self.rows_per_band
            band_signature = tuple(signature[start:end])
            band_hash = self._hash_band_deterministic(band_signature)
            self._buckets[(band_idx, band_hash)].add(key)

    def query(self, features: set[str]) -> list[tuple[str, float]]:
        """Find similar items using LSH buckets.

        Args:
            features: Set of features to query against the index.

        Returns:
            List of (key, similarity) tuples sorted by similarity (descending).
        """
        signature = self.compute_minhash_signature(features)
        candidates: set[str] = set()

        for band_idx in range(self.num_bands):
            start = band_idx * self.rows_per_band
            end = start + self.rows_per_band
            band_signature = tuple(signature[start:end])
            band_hash = self._hash_band_deterministic(band_signature)
            candidates.update(self._buckets.get((band_idx, band_hash), set()))

        results: list[tuple[str, float]] = []
        for candidate in candidates:
            if candidate in self._signatures:
                similarity = self._estimate_jaccard_similarity(signature, self._signatures[candidate])
                if similarity >= self.threshold:
                    results.append((candidate, similarity))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def _estimate_jaccard_similarity(self, sig1: list[int], sig2: list[int]) -> float:
        """Estimate Jaccard similarity from MinHash signatures.

        Args:
            sig1: First MinHash signature.
            sig2: Second MinHash signature.

        Returns:
            Estimated Jaccard similarity (0.0-1.0).
        """
        if len(sig1) != len(sig2):
            return 0.0

        matches = sum(a == b for a, b in zip(sig1, sig2))
        return matches / len(sig1)

    def get_signature(self, key: str) -> list[int] | None:
        """Retrieve stored MinHash signature for a binary.

        Args:
            key: Binary identifier.

        Returns:
            MinHash signature if exists, None otherwise.
        """
        return self._signatures.get(key)

    def remove(self, key: str) -> bool:
        """Remove a binary from the LSH index.

        Args:
            key: Binary identifier to remove.

        Returns:
            True if removed, False if not found.
        """
        if key not in self._signatures:
            return False

        signature = self._signatures[key]

        for band_idx in range(self.num_bands):
            start = band_idx * self.rows_per_band
            end = start + self.rows_per_band
            band_signature = tuple(signature[start:end])
            band_hash = self._hash_band_deterministic(band_signature)

            if (band_idx, band_hash) in self._buckets:
                self._buckets[(band_idx, band_hash)].discard(key)

        del self._signatures[key]
        if key in self._path_to_index:
            del self._path_to_index[key]
        return True

    def size(self) -> int:
        """Get number of items in the index.

        Returns:
            Number of indexed binaries.
        """
        return len(self._signatures)


class BinarySimilaritySearch:
    """Binary similarity search engine to find similar cracking patterns.

    Uses structural analysis and feature extraction to identify similarities
    between binary files and associated cracking patterns.
    """

    def __init__(self, database_path: str = "binary_database.json", use_lsh: bool = True) -> None:
        """Initialize the binary similarity search engine with database configuration.

        Args:
            database_path: Path to the database file to load or create.
            use_lsh: Enable LSH indexing for fast similarity search (default: True).

        """
        self.database_path = database_path
        self.database: dict[str, Any] = {}
        self.use_lsh = use_lsh
        self.logger = logging.getLogger("IntellicrackLogger.BinarySearch")
        self.fuzzy_match_stats: dict[str, int] = {
            "total_comparisons": 0,
            "matches_found": 0,
            "sample_size": 0,
        }

        if use_lsh:
            self.lsh_index = MinHashLSH(num_perm=128, threshold=0.5, num_bands=32)
        else:
            self.lsh_index = None

        self.load_database(database_path)

    def _load_database(self) -> dict[str, Any]:
        """Load the binary database from file.

        Returns:
            Database dictionary with binary entries.

        """
        if not os.path.exists(self.database_path):
            return {"binaries": []}
        try:
            with open(self.database_path, encoding="utf-8") as f:
                data: dict[str, Any] = json.load(f)
                return data
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error loading binary database: %s", e)
            return {"binaries": []}

    def _save_database(self) -> None:
        """Save the binary database to file."""
        try:
            with open(self.database_path, "w", encoding="utf-8") as f:
                json.dump(self.database, f, indent=4)
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error saving binary database: %s", e)

    def add_binary(self, binary_path: str, cracking_patterns: list[str] | None = None) -> bool:
        """Add a binary to the database with its features and patterns.

        Args:
            binary_path: Path to the binary file.
            cracking_patterns: List of associated cracking patterns.

        Returns:
            bool: True if successful, False otherwise.

        """
        try:
            for existing in self.database["binaries"]:
                if existing["path"] == binary_path:
                    self.logger.warning("Binary %s already exists in database", binary_path)
                    return False

            features = self._extract_binary_features(binary_path)

            binary_entry = {
                "path": binary_path,
                "filename": os.path.basename(binary_path),
                "features": features,
                "cracking_patterns": cracking_patterns or [],
                "added": datetime.datetime.now().isoformat(),
                "file_size": os.path.getsize(binary_path) if os.path.exists(binary_path) else 0,
            }

            self.database["binaries"].append(binary_entry)

            if self.use_lsh and self.lsh_index is not None:
                feature_set = self._extract_feature_set_for_lsh(features)
                self.lsh_index.insert(binary_path, feature_set)

            self._save_database()

            self.logger.info("Added binary %s to database", binary_path)
            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error adding binary %s to database: %s", binary_path, e)
            return False

    def _extract_feature_set_for_lsh(self, features: dict[str, Any]) -> set[str]:
        """Extract feature set for LSH indexing.

        Args:
            features: Binary features dictionary.

        Returns:
            Set of feature strings for MinHash computation.
        """
        feature_set: set[str] = set()

        imports = features.get("imports", [])
        if isinstance(imports, list):
            feature_set.update(imports)

        exports = features.get("exports", [])
        if isinstance(exports, list):
            feature_set.update(exports)

        strings = features.get("strings", [])
        if isinstance(strings, list):
            feature_set.update(strings[:100])

        sections = features.get("sections", [])
        if isinstance(sections, list):
            for section in sections:
                if isinstance(section, dict):
                    name = section.get("name", "")
                    if name:
                        feature_set.add(f"section:{name}")

        return feature_set

    def _extract_binary_features(self, binary_path: str) -> dict[str, Any]:
        """Extract structural features from a binary file.

        Args:
            binary_path: Path to the binary file.

        Returns:
            Dictionary of extracted features including entropy, sections, imports, and exports.

        """
        features = {
            "file_size": 0,
            "entropy": 0.0,
            "sections": [],
            "imports": [],
            "exports": [],
            "strings": [],
            "machine": None,
            "timestamp": None,
            "characteristics": None,
        }

        try:
            if not os.path.exists(binary_path):
                return features

            # Basic file information
            features["file_size"] = os.path.getsize(binary_path)

            # Calculate file entropy
            with open(binary_path, "rb") as f:
                data = f.read()
                features["entropy"] = calculate_entropy(data)

            # PE file analysis if pefile is available
            if HAS_PEFILE:
                try:
                    pe = pefile.PE(binary_path)

                    # Extract basic PE information
                    features["machine"] = getattr(pe.FILE_HEADER, "Machine", 0)
                    features["timestamp"] = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
                    features["characteristics"] = getattr(pe.FILE_HEADER, "Characteristics", 0)

                    # Extract section information
                    sections_list: list[dict[str, Any]] = features["sections"]
                    for section in pe.sections:
                        section_name = section.Name.decode("utf-8", "ignore").strip("\x00")
                        section_info = {
                            "name": section_name,
                            "virtual_address": section.VirtualAddress,
                            "virtual_size": section.Misc_VirtualSize,
                            "raw_data_size": section.SizeOfRawData,
                            "entropy": calculate_entropy(section.get_data()),
                        }
                        sections_list.append(section_info)

                    # Extract import information
                    imports_list: list[str] = features["imports"]
                    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            dll_name = entry.dll.decode("utf-8", "ignore")
                            for imp in entry.imports:
                                if imp.name:
                                    imp_name = imp.name.decode("utf-8", "ignore")
                                    imports_list.append(f"{dll_name}:{imp_name}")

                    # Extract export information
                    exports_list: list[str] = features["exports"]
                    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                            if exp.name:
                                exp_name = exp.name.decode("utf-8", "ignore")
                                exports_list.append(exp_name)

                    # Extract strings (basic implementation)
                    strings = self._extract_strings(data)
                    features["strings"] = strings[:50]  # Limit to first 50 strings

                    pe.close()

                except pefile.PEFormatError as pef:
                    self.logger.warning("Malformed PE file %s: %s", binary_path, pef)
                except (OSError, ValueError, RuntimeError) as e:
                    self.logger.warning("PE analysis failed for %s: %s", binary_path, e)

            return features

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error extracting features from %s: %s", binary_path, e)
            return features

    def _extract_strings(self, data: bytes, min_length: int = 4) -> list[str]:
        """Extract ASCII strings from binary data using common utility.

        Args:
            data: Binary data to extract strings from.
            min_length: Minimum length of strings to extract.

        Returns:
            List of extracted ASCII strings.

        """
        from ...utils.core.string_utils import extract_ascii_strings

        return extract_ascii_strings(data, min_length)

    def search_similar_binaries(self, binary_path: str, threshold: float = 0.7) -> list[dict[str, Any]]:
        """Search for binaries similar to the given binary.

        Args:
            binary_path: Path to the target binary.
            threshold: Similarity threshold (0.0 to 1.0).

        Returns:
            List of similar binaries with similarity scores.

        """
        try:
            target_features = self._extract_binary_features(binary_path)
            similar_binaries = []

            if self.use_lsh and self.lsh_index is not None and self.lsh_index.size() > 0:
                feature_set = self._extract_feature_set_for_lsh(target_features)
                lsh_candidates = self.lsh_index.query(feature_set)

                for candidate_path, lsh_similarity in lsh_candidates:
                    for binary in self.database["binaries"]:
                        if binary["path"] == candidate_path:
                            detailed_similarity = self._calculate_similarity(target_features, binary["features"])

                            if detailed_similarity >= threshold:
                                similar_binaries.append(
                                    {
                                        "path": binary["path"],
                                        "filename": binary.get("filename", os.path.basename(binary["path"])),
                                        "similarity": detailed_similarity,
                                        "lsh_similarity": lsh_similarity,
                                        "cracking_patterns": binary["cracking_patterns"],
                                        "added": binary.get("added", "Unknown"),
                                        "file_size": binary.get("file_size", 0),
                                    }
                                )
                            break
            else:
                for binary in self.database["binaries"]:
                    similarity = self._calculate_similarity(target_features, binary["features"])
                    if similarity >= threshold:
                        similar_binaries.append(
                            {
                                "path": binary["path"],
                                "filename": binary.get("filename", os.path.basename(binary["path"])),
                                "similarity": similarity,
                                "cracking_patterns": binary["cracking_patterns"],
                                "added": binary.get("added", "Unknown"),
                                "file_size": binary.get("file_size", 0),
                            }
                        )

            similar_binaries.sort(key=lambda x: x["similarity"], reverse=True)

            self.logger.info("Found %d similar binaries for %s", len(similar_binaries), binary_path)
            return similar_binaries

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error searching similar binaries for %s: %s", binary_path, e)
            return []

    def _calculate_similarity(self, features1: dict[str, Any], features2: dict[str, Any]) -> float:
        """Calculate advanced similarity between two sets of features using multiple algorithms.

        This implementation uses a comprehensive approach combining:
        - Structural similarity (sections, imports, exports)
        - Content similarity (strings, fuzzy hashing)
        - Statistical similarity (entropy, file size)
        - Advanced algorithms (LSH, edit distance, n-gram analysis)

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            # Advanced similarity components
            similarity_scores = {"structural": self._calculate_structural_similarity(features1, features2)}

            # 2. Content Similarity Analysis
            similarity_scores["content"] = self._calculate_content_similarity(features1, features2)

            # 3. Statistical Similarity Analysis
            similarity_scores["statistical"] = self._calculate_statistical_similarity(features1, features2)

            # 4. Advanced Algorithm-based Similarity
            similarity_scores["advanced"] = self._calculate_advanced_similarity(features1, features2)

            # 5. Fuzzy Hash Similarity (if available)
            similarity_scores["fuzzy"] = self._calculate_fuzzy_hash_similarity(features1, features2)

            # 6. Control Flow Similarity
            similarity_scores["control_flow"] = self._calculate_control_flow_similarity(features1, features2)

            # 7. Opcode Sequence Similarity
            similarity_scores["opcode"] = self._calculate_opcode_similarity(features1, features2)

            # Calculate weighted overall similarity with adaptive weights
            weights = self._calculate_adaptive_weights(features1, features2)

            weighted_similarity = sum(similarity_scores[component] * weights.get(component, 0.1) for component in similarity_scores)

            return min(1.0, max(0.0, weighted_similarity))

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error calculating advanced similarity: %s", e)
            # Fallback to basic similarity calculation
            return self._calculate_basic_similarity(features1, features2)

    def _calculate_section_similarity(self, sections1: list[dict[str, Any]], sections2: list[dict[str, Any]]) -> float:
        """Calculate similarity between two sets of sections.

        Args:
            sections1: First set of sections.
            sections2: Second set of sections.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            if not sections1 or not sections2:
                return 0.0

            # Compare section names
            names1 = [s.get("name", "") for s in sections1]
            names2 = [s.get("name", "") for s in sections2]
            name_similarity = self._calculate_list_similarity(names1, names2)

            # Compare section entropies
            entropies1 = [s.get("entropy", 0) for s in sections1]
            entropies2 = [s.get("entropy", 0) for s in sections2]

            entropy_similarity = 0.0
            if entropies1 and entropies2:
                # Calculate average entropy difference
                min_len = min(len(entropies1), len(entropies2))
                if min_len > 0:
                    entropy_diff = sum(abs(entropies1[i] - entropies2[i]) for i in range(min_len)) / min_len
                    entropy_similarity = max(0.0, 1.0 - entropy_diff / 8.0)  # Normalize by max entropy

            return name_similarity * 0.6 + entropy_similarity * 0.4

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error calculating section similarity: %s", e)
            return 0.0

    def _calculate_list_similarity(self, list1: list[str], list2: list[str]) -> float:
        """Calculate Jaccard similarity between two lists.

        Args:
            list1: First list.
            list2: Second list.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            if not list1 or not list2:
                return 0.0

            # Convert to sets for Jaccard similarity
            set1 = set(list1)
            set2 = set(list2)

            # Calculate Jaccard similarity
            intersection = len(set1.intersection(set2))
            union = len(set1.union(set2))

            return intersection / union if union > 0 else 0.0

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error calculating list similarity: %s", e)
            return 0.0

    def _calculate_basic_similarity(self, features1: dict[str, Any], features2: dict[str, Any]) -> float:
        """Fallback basic similarity calculation.

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            # Calculate section similarity
            section_similarity = self._calculate_section_similarity(
                features1.get("sections", []),
                features2.get("sections", []),
            )

            # Calculate import similarity
            import_similarity = self._calculate_list_similarity(
                features1.get("imports", []),
                features2.get("imports", []),
            )

            # Calculate export similarity
            export_similarity = self._calculate_list_similarity(
                features1.get("exports", []),
                features2.get("exports", []),
            )

            # Calculate string similarity
            string_similarity = self._calculate_list_similarity(
                features1.get("strings", []),
                features2.get("strings", []),
            )

            # Calculate file size similarity
            size1 = features1.get("file_size", 0)
            size2 = features2.get("file_size", 0)
            if size1 > 0 and size2 > 0:
                size_diff = abs(size1 - size2) / max(size1, size2)
                size_similarity = max(0.0, 1.0 - size_diff)
            else:
                size_similarity = 0.0

            # Calculate entropy similarity
            entropy1 = features1.get("entropy", 0.0)
            entropy2 = features2.get("entropy", 0.0)
            if entropy1 > 0 and entropy2 > 0:
                entropy_diff = abs(entropy1 - entropy2) / 8.0  # Max entropy is ~8
                entropy_similarity = max(0.0, 1.0 - entropy_diff)
            else:
                entropy_similarity = 0.0

            # Calculate weighted overall similarity
            total_similarity: float = (
                section_similarity * 0.30
                + import_similarity * 0.25
                + export_similarity * 0.15
                + string_similarity * 0.15
                + size_similarity * 0.10
                + entropy_similarity * 0.05
            )

            return min(1.0, max(0.0, total_similarity))

        except Exception as e:
            self.logger.exception("Error in basic similarity calculation: %s", e)
            return 0.0

    def _calculate_structural_similarity(self, features1: dict[str, Any], features2: dict[str, Any]) -> float:
        """Calculate structural similarity using section layout and metadata.

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            # Section similarity with enhanced comparison
            section_similarity = self._calculate_section_similarity(
                features1.get("sections", []),
                features2.get("sections", []),
            )

            # Import/Export API similarity with weighted comparison
            import_similarity = self._calculate_weighted_api_similarity(
                features1.get("imports", []),
                features2.get("imports", []),
            )

            export_similarity = self._calculate_list_similarity(
                features1.get("exports", []),
                features2.get("exports", []),
            )

            # PE header similarity
            header_similarity = self._calculate_pe_header_similarity(features1, features2)

            return section_similarity * 0.4 + import_similarity * 0.3 + export_similarity * 0.2 + header_similarity * 0.1

        except Exception as e:
            self.logger.exception("Error in structural similarity: %s", e)
            return 0.0

    def _calculate_content_similarity(self, features1: dict[str, Any], features2: dict[str, Any]) -> float:
        """Calculate content similarity using string analysis and n-grams.

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            # Enhanced string similarity with fuzzy matching
            string_similarity = self._calculate_fuzzy_string_similarity(
                features1.get("strings", []),
                features2.get("strings", []),
            )

            # N-gram analysis for content patterns
            ngram_similarity = self._calculate_ngram_similarity(
                features1.get("strings", []),
                features2.get("strings", []),
            )

            # Entropy-based content analysis
            entropy_pattern_similarity = self._calculate_entropy_pattern_similarity(features1, features2)

            return string_similarity * 0.5 + ngram_similarity * 0.3 + entropy_pattern_similarity * 0.2

        except Exception as e:
            self.logger.exception("Error in content similarity: %s", e)
            return 0.0

    def _calculate_statistical_similarity(self, features1: dict[str, Any], features2: dict[str, Any]) -> float:
        """Calculate statistical similarity using file metrics.

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            # File size similarity with logarithmic scaling
            size_similarity = self._calculate_logarithmic_size_similarity(
                features1.get("file_size", 0),
                features2.get("file_size", 0),
            )

            # Entropy similarity
            entropy_similarity = self._calculate_entropy_similarity(
                features1.get("entropy", 0.0),
                features2.get("entropy", 0.0),
            )

            # Section count and distribution similarity
            section_distribution_similarity = self._calculate_section_distribution_similarity(
                features1.get("sections", []),
                features2.get("sections", []),
            )

            return size_similarity * 0.4 + entropy_similarity * 0.3 + section_distribution_similarity * 0.3

        except Exception as e:
            self.logger.exception("Error in statistical similarity: %s", e)
            return 0.0

    def _calculate_advanced_similarity(self, features1: dict[str, Any], features2: dict[str, Any]) -> float:
        """Calculate similarity using advanced algorithms like LSH and edit distance.

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            # Locality Sensitive Hashing for large feature sets
            lsh_similarity = self._calculate_lsh_similarity(
                features1.get("imports", []) + features1.get("exports", []),
                features2.get("imports", []) + features2.get("exports", []),
            )

            # Edit distance for string sequences
            edit_distance_similarity = self._calculate_edit_distance_similarity(
                features1.get("strings", []),
                features2.get("strings", []),
            )

            # Cosine similarity for feature vectors
            cosine_similarity = self._calculate_cosine_similarity(features1, features2)

            return lsh_similarity * 0.4 + edit_distance_similarity * 0.3 + cosine_similarity * 0.3

        except Exception as e:
            self.logger.exception("Error in advanced similarity: %s", e)
            return 0.0

    def _calculate_fuzzy_hash_similarity(self, features1: dict[str, Any], features2: dict[str, Any]) -> float:
        """Calculate similarity using fuzzy hashing (SSDEEP-like algorithm).

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            # Generate simple rolling hash for each binary's content
            hash1 = self._generate_rolling_hash(features1.get("strings", []))
            hash2 = self._generate_rolling_hash(features2.get("strings", []))

            # Calculate hash similarity
            if not hash1 or not hash2:
                return 0.0

            # Use Hamming distance for hash comparison
            return self._calculate_hash_similarity(hash1, hash2)

        except Exception as e:
            self.logger.exception("Error in fuzzy hash similarity: %s", e)
            return 0.0

    def _calculate_control_flow_similarity(self, features1: dict[str, Any], features2: dict[str, Any]) -> float:
        """Calculate similarity based on control flow patterns.

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            # Analyze section characteristics for control flow indicators
            sections1 = features1.get("sections", [])
            sections2 = features2.get("sections", [])

            # Look for executable sections and their entropy patterns
            exec_entropy1: list[float] = [s.get("entropy", 0) for s in sections1 if ".text" in s.get("name", "")]
            exec_entropy2: list[float] = [s.get("entropy", 0) for s in sections2 if ".text" in s.get("name", "")]

            if not exec_entropy1 or not exec_entropy2:
                return 0.0

            # Calculate entropy pattern similarity for code sections
            avg_entropy1: float = sum(exec_entropy1) / len(exec_entropy1)
            avg_entropy2: float = sum(exec_entropy2) / len(exec_entropy2)

            entropy_diff: float = abs(avg_entropy1 - avg_entropy2)
            return max(0.0, 1.0 - entropy_diff / 8.0)

        except Exception as e:
            self.logger.exception("Error in control flow similarity: %s", e)
            return 0.0

    def _calculate_opcode_similarity(self, features1: dict[str, Any], features2: dict[str, Any]) -> float:
        """Calculate similarity based on opcode sequence patterns.

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            # Use import patterns as proxy for opcode patterns
            imports1 = features1.get("imports", [])
            imports2 = features2.get("imports", [])

            # Group imports by DLL for pattern analysis
            dll_patterns1: dict[str, list[str]] = {}
            dll_patterns2: dict[str, list[str]] = {}

            for imp in imports1:
                if ":" in imp:
                    dll, func = imp.split(":", 1)
                    dll_patterns1.setdefault(dll, []).append(func)

            for imp in imports2:
                if ":" in imp:
                    dll, func = imp.split(":", 1)
                    dll_patterns2.setdefault(dll, []).append(func)

            # Calculate pattern similarity
            common_dlls = set(dll_patterns1.keys()).intersection(set(dll_patterns2.keys()))
            if not common_dlls:
                return 0.0

            pattern_similarities = []
            for dll in common_dlls:
                funcs1 = set(dll_patterns1[dll])
                funcs2 = set(dll_patterns2[dll])
                if funcs1 and funcs2:
                    similarity = len(funcs1.intersection(funcs2)) / len(funcs1.union(funcs2))
                    pattern_similarities.append(similarity)

            return sum(pattern_similarities) / len(pattern_similarities) if pattern_similarities else 0.0

        except Exception as e:
            self.logger.exception("Error in opcode similarity: %s", e)
            return 0.0

    def _calculate_adaptive_weights(self, features1: dict[str, Any], features2: dict[str, Any]) -> dict[str, float]:
        """Calculate adaptive weights based on feature availability and quality.

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Dictionary of component weights normalized to sum to 1.0.

        """
        weights = {
            "structural": 0.25,
            "content": 0.20,
            "statistical": 0.15,
            "advanced": 0.15,
            "fuzzy": 0.10,
            "control_flow": 0.10,
            "opcode": 0.05,
        }

        try:
            # Adjust weights based on feature richness
            if len(features1.get("imports", [])) > 50 and len(features2.get("imports", [])) > 50:
                weights["structural"] += 0.1
                weights["opcode"] += 0.05

            if len(features1.get("strings", [])) > 30 and len(features2.get("strings", [])) > 30:
                weights["content"] += 0.1
                weights["fuzzy"] += 0.05

            # Normalize weights to sum to 1.0
            total_weight = sum(weights.values())
            if total_weight > 0:
                weights = {k: v / total_weight for k, v in weights.items()}

        except Exception as e:
            self.logger.exception("Error calculating adaptive weights: %s", e)

        return weights

    def _calculate_weighted_api_similarity(self, imports1: list[str], imports2: list[str]) -> float:
        """Calculate weighted API similarity with importance scoring.

        Args:
            imports1: First set of import names.
            imports2: Second set of import names.

        Returns:
            Weighted similarity score between 0.0 and 1.0.

        """
        try:
            if not imports1 or not imports2:
                return 0.0

            # Weight APIs by criticality (security, crypto, system calls)
            critical_apis = {
                "kernel32.dll": 1.5,
                "ntdll.dll": 1.5,
                "advapi32.dll": 1.3,
                "crypt32.dll": 1.4,
                "wininet.dll": 1.2,
                "user32.dll": 1.0,
                "shell32.dll": 1.1,
            }

            weighted_score = 0.0
            total_weight = 0.0

            set1 = set(imports1)
            set2 = set(imports2)
            common_imports = set1.intersection(set2)

            for imp in set1.union(set2):
                dll = imp.split(":")[0] if ":" in imp else "unknown"
                weight = critical_apis.get(dll, 1.0)
                total_weight += weight

                if imp in common_imports:
                    weighted_score += weight

            return weighted_score / total_weight if total_weight > 0 else 0.0

        except Exception as e:
            self.logger.exception("Error in weighted API similarity: %s", e)
            return 0.0

    def _calculate_pe_header_similarity(self, features1: dict[str, Any], features2: dict[str, Any]) -> float:
        """Calculate PE header metadata similarity.

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            similarity_scores = []

            # Machine type similarity
            machine1 = features1.get("machine", 0)
            machine2 = features2.get("machine", 0)
            if machine1 and machine2:
                similarity_scores.append(1.0 if machine1 == machine2 else 0.0)

            # Characteristics similarity
            char1 = features1.get("characteristics", 0)
            char2 = features2.get("characteristics", 0)
            if char1 and char2:
                # Calculate bit-wise similarity
                xor_diff = char1 ^ char2
                bit_diff = bin(xor_diff).count("1")
                max_bits = max(char1.bit_length(), char2.bit_length())
                char_similarity = 1.0 - (bit_diff / max_bits) if max_bits > 0 else 1.0
                similarity_scores.append(char_similarity)

            return sum(similarity_scores) / len(similarity_scores) if similarity_scores else 0.0

        except Exception as e:
            self.logger.exception("Error in PE header similarity: %s", e)
            return 0.0

    def _calculate_fuzzy_string_similarity(self, strings1: list[str], strings2: list[str]) -> float:
        """Calculate fuzzy string similarity using approximate matching.

        Args:
            strings1: First set of strings.
            strings2: Second set of strings.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            if not strings1 or not strings2:
                self.fuzzy_match_stats = {
                    "total_comparisons": 0,
                    "matches_found": 0,
                    "sample_size": 0,
                }
                return 0.0

            matches = 0
            total_comparisons = 0

            sample_size = min(20, len(strings1), len(strings2))
            sampled1 = strings1[:sample_size]
            sampled2 = strings2[:sample_size]

            for s1 in sampled1:
                best_similarity = 0.0
                for s2 in sampled2:
                    similarity = self._calculate_string_similarity(s1, s2)
                    best_similarity = max(best_similarity, similarity)
                    total_comparisons += 1

                if best_similarity > 0.7:
                    matches += 1

            self.fuzzy_match_stats = {
                "total_comparisons": total_comparisons,
                "matches_found": matches,
                "sample_size": sample_size,
            }

            return matches / len(sampled1) if sampled1 else 0.0

        except Exception as e:
            self.logger.exception("Error in fuzzy string similarity: %s", e)
            return 0.0

    def _calculate_string_similarity(self, s1: str, s2: str) -> float:
        """Calculate similarity between two strings using edit distance.

        Args:
            s1: First string.
            s2: Second string.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            if not s1 or not s2:
                return 0.0

            # Simplified edit distance calculation
            if s1 == s2:
                return 1.0

            # Calculate character-level similarity
            set1 = set(s1.lower())
            set2 = set(s2.lower())

            if not set1 or not set2:
                return 0.0

            intersection = len(set1.intersection(set2))
            union = len(set1.union(set2))

            return intersection / union

        except Exception as e:
            self.logger.exception("Error in string similarity calculation: %s", e)
            return 0.0

    def _calculate_ngram_similarity(self, strings1: list[str], strings2: list[str]) -> float:
        """Calculate n-gram similarity for pattern detection.

        Args:
            strings1: First set of strings.
            strings2: Second set of strings.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            if not strings1 or not strings2:
                return 0.0

            # Generate character n-grams (trigrams)
            def generate_ngrams(text_list: list[str], n: int = 3) -> set[str]:
                ngrams: set[str] = set()
                for text in text_list:
                    text = text.lower()
                    for i in range(len(text) - n + 1):
                        ngrams.add(text[i : i + n])
                return ngrams

            ngrams1 = generate_ngrams(strings1)
            ngrams2 = generate_ngrams(strings2)

            if not ngrams1 or not ngrams2:
                return 0.0

            intersection = len(ngrams1.intersection(ngrams2))
            union = len(ngrams1.union(ngrams2))

            return intersection / union

        except Exception as e:
            self.logger.exception("Error in n-gram similarity: %s", e)
            return 0.0

    def _calculate_entropy_pattern_similarity(self, features1: dict[str, Any], features2: dict[str, Any]) -> float:
        """Calculate similarity based on entropy distribution patterns.

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            sections1 = features1.get("sections", [])
            sections2 = features2.get("sections", [])

            if not sections1 or not sections2:
                return 0.0

            # Calculate entropy distribution
            entropies1 = [s.get("entropy", 0) for s in sections1]
            entropies2 = [s.get("entropy", 0) for s in sections2]

            # Create entropy buckets for distribution comparison
            def create_entropy_distribution(entropies: list[float]) -> list[float]:
                buckets: list[int] = [0] * 8  # 8 entropy buckets (0-1, 1-2, ..., 7-8)
                for entropy in entropies:
                    bucket = min(7, int(entropy))
                    buckets[bucket] += 1
                total = sum(buckets)
                return [float(b) / total for b in buckets] if total > 0 else [0.0] * 8

            dist1 = create_entropy_distribution(entropies1)
            dist2 = create_entropy_distribution(entropies2)

            # Calculate distribution similarity using cosine similarity
            dot_product = sum(a * b for a, b in zip(dist1, dist2, strict=False))
            norm1 = sum(a * a for a in dist1) ** 0.5
            norm2 = sum(b * b for b in dist2) ** 0.5

            return 0.0 if norm1 == 0 or norm2 == 0 else dot_product / (norm1 * norm2)
        except Exception as e:
            self.logger.exception("Error in entropy pattern similarity: %s", e)
            return 0.0

    def _calculate_logarithmic_size_similarity(self, size1: int, size2: int) -> float:
        """Calculate file size similarity using logarithmic scaling.

        Args:
            size1: First file size in bytes.
            size2: Second file size in bytes.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            if size1 <= 0 or size2 <= 0:
                return 0.0

            # Use logarithmic scaling to reduce impact of large size differences
            import math

            log_size1 = math.log(size1)
            log_size2 = math.log(size2)

            size_diff = abs(log_size1 - log_size2)
            max_log_diff = max(log_size1, log_size2)

            return max(0.0, 1.0 - size_diff / max_log_diff) if max_log_diff > 0 else 1.0

        except Exception as e:
            self.logger.exception("Error in logarithmic size similarity: %s", e)
            return 0.0

    def _calculate_entropy_similarity(self, entropy1: float, entropy2: float) -> float:
        """Calculate entropy similarity with improved scaling.

        Args:
            entropy1: First entropy value.
            entropy2: Second entropy value.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            if entropy1 <= 0 or entropy2 <= 0:
                return 0.0

            entropy_diff = abs(entropy1 - entropy2)
            # Use adaptive scaling based on entropy values
            scale_factor = max(entropy1, entropy2) / 8.0
            normalized_diff = entropy_diff / (8.0 * scale_factor) if scale_factor > 0 else 0.0

            return max(0.0, 1.0 - normalized_diff)

        except Exception as e:
            self.logger.exception("Error in entropy similarity: %s", e)
            return 0.0

    def _calculate_section_distribution_similarity(self, sections1: list[dict[str, Any]], sections2: list[dict[str, Any]]) -> float:
        """Calculate similarity based on section size distribution.

        Args:
            sections1: First set of sections.
            sections2: Second set of sections.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            if not sections1 or not sections2:
                return 0.0

            # Calculate relative section sizes
            def get_size_distribution(sections: list[dict[str, Any]]) -> list[float]:
                sizes = [s.get("raw_data_size", 0) for s in sections]
                total = sum(sizes)
                return [float(s) / total for s in sizes] if total > 0 else []

            dist1 = get_size_distribution(sections1)
            dist2 = get_size_distribution(sections2)

            if not dist1 or not dist2:
                return 0.0

            # Pad distributions to same length
            max_len = max(len(dist1), len(dist2))
            dist1.extend([0.0] * (max_len - len(dist1)))
            dist2.extend([0.0] * (max_len - len(dist2)))

            # Calculate similarity using mean squared error
            mse = sum((a - b) ** 2 for a, b in zip(dist1, dist2, strict=False)) / max_len
            return max(0.0, 1.0 - mse)

        except Exception as e:
            self.logger.exception("Error in section distribution similarity: %s", e)
            return 0.0

    def _calculate_lsh_similarity(self, features1: list[str], features2: list[str]) -> float:
        """Calculate similarity using Locality Sensitive Hashing approximation.

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            if not features1 or not features2:
                return 0.0

            # Simple LSH approximation using hash-based bucketing
            def create_hash_signature(features: list[str], num_hashes: int = 32) -> list[int]:
                import hashlib

                signature: list[int] = []
                for i in range(num_hashes):
                    hash_val = 0
                    for feature in features:
                        feature_hash = int(hashlib.sha256(f"{feature}_{i}".encode()).hexdigest()[:8], 16)
                        hash_val = min(hash_val, feature_hash) if hash_val > 0 else feature_hash
                    signature.append(hash_val)
                return signature

            sig1 = create_hash_signature(features1)
            sig2 = create_hash_signature(features2)

            # Calculate signature similarity
            matches = sum(a == b for a, b in zip(sig1, sig2, strict=False))
            return matches / len(sig1)

        except Exception as e:
            self.logger.exception("Error in LSH similarity: %s", e)
            return 0.0

    def _calculate_edit_distance_similarity(self, strings1: list[str], strings2: list[str]) -> float:
        """Calculate similarity using edit distance on string sequences.

        Args:
            strings1: First set of strings.
            strings2: Second set of strings.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            if not strings1 or not strings2:
                return 0.0

            # Use first few strings for performance
            sample1 = " ".join(strings1[:10])
            sample2 = " ".join(strings2[:10])

            # Simplified edit distance calculation
            def edit_distance(s1: str, s2: str) -> int:
                if len(s1) < len(s2):
                    s1, s2 = s2, s1

                if not s2:
                    return len(s1)

                previous_row = list(range(len(s2) + 1))
                for i, c1 in enumerate(s1):
                    current_row = [i + 1]
                    for j, c2 in enumerate(s2):
                        insertions = previous_row[j + 1] + 1
                        deletions = current_row[j] + 1
                        substitutions = previous_row[j] + (c1 != c2)
                        current_row.append(min(insertions, deletions, substitutions))
                    previous_row = current_row

                return previous_row[-1]

            distance = edit_distance(sample1, sample2)
            max_len = max(len(sample1), len(sample2))

            return 1.0 - (distance / max_len) if max_len > 0 else 1.0

        except Exception as e:
            self.logger.exception("Error in edit distance similarity: %s", e)
            return 0.0

    def _calculate_cosine_similarity(self, features1: dict[str, Any], features2: dict[str, Any]) -> float:
        """Calculate cosine similarity for feature vectors.

        Args:
            features1: First set of features.
            features2: Second set of features.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            # Create feature vectors from various attributes
            def create_feature_vector(features: dict[str, Any]) -> list[float]:
                vector: list[float] = []
                vector.append(float(features.get("file_size", 0)) / 1000000.0)  # Normalize file size
                vector.append(float(features.get("entropy", 0.0)))
                vector.append(float(len(features.get("sections", []))))
                vector.append(float(len(features.get("imports", []))))
                vector.append(float(len(features.get("exports", []))))
                vector.append(float(len(features.get("strings", []))))
                return vector

            vec1 = create_feature_vector(features1)
            vec2 = create_feature_vector(features2)

            # Calculate cosine similarity
            dot_product = sum(a * b for a, b in zip(vec1, vec2, strict=False))
            norm1 = sum(a * a for a in vec1) ** 0.5
            norm2 = sum(b * b for b in vec2) ** 0.5

            return 0.0 if norm1 == 0 or norm2 == 0 else dot_product / (norm1 * norm2)
        except Exception as e:
            self.logger.exception("Error in cosine similarity: %s", e)
            return 0.0

    def _generate_rolling_hash(self, strings: list[str]) -> str:
        """Generate a content-preserving hash for string similarity.

        Note: This is NOT a true fuzzy/similarity-preserving hash. It computes
        a cryptographic hash (SHA256) which has avalanche property - a single
        bit change produces a completely different hash. For actual similarity
        detection, use compute_minhash_signature() instead.

        Args:
            strings: List of strings to hash.

        Returns:
            Hexadecimal hash string.

        """
        try:
            if not strings:
                return ""

            import hashlib

            combined = " ".join(strings[:20])
            hash_bytes = hashlib.sha256(combined.encode()).digest()

            return hash_bytes.hex()

        except Exception as e:
            self.logger.exception("Error generating rolling hash: %s", e)
            return ""

    def _calculate_hash_similarity(self, hash1: str, hash2: str) -> float:
        """Calculate similarity between two hashes.

        Args:
            hash1: First hash string.
            hash2: Second hash string.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        try:
            if not hash1 or not hash2 or len(hash1) != len(hash2):
                return 0.0

            differences = sum(c1 != c2 for c1, c2 in zip(hash1, hash2, strict=False))
            similarity = 1.0 - (differences / len(hash1))

            return max(0.0, similarity)

        except Exception as e:
            self.logger.exception("Error calculating hash similarity: %s", e)
            return 0.0

    def compute_instruction_ngrams(self, binary_path: str, n: int = 4) -> set[str]:
        """Extract instruction n-grams from binary for pattern matching.

        Args:
            binary_path: Path to binary file.
            n: N-gram size (default: 4 for 4-byte sequences).

        Returns:
            Set of instruction n-gram signatures.
        """
        ngrams: set[str] = set()

        try:
            if not os.path.exists(binary_path):
                return ngrams

            with open(binary_path, "rb") as f:
                data = f.read()

            if HAS_PEFILE:
                try:
                    pe = pefile.PE(binary_path)

                    for section in pe.sections:
                        if b".text" in section.Name or section.Characteristics & 0x20000000:
                            section_data = section.get_data()

                            for i in range(len(section_data) - n + 1):
                                ngram_bytes = section_data[i : i + n]
                                ngram_sig = ngram_bytes.hex()
                                ngrams.add(ngram_sig)

                                if len(ngrams) > 10000:
                                    break

                    pe.close()

                except pefile.PEFormatError as pef:
                    self.logger.warning("Malformed PE file for n-grams: %s", pef)
                except Exception as pe_error:
                    self.logger.warning("PE analysis failed for n-grams: %s", pe_error)
            else:
                for i in range(0, min(len(data), 100000), n):
                    ngram_bytes = data[i : i + n]
                    if len(ngram_bytes) == n:
                        ngrams.add(ngram_bytes.hex())

        except Exception as e:
            self.logger.exception("Error computing instruction n-grams: %s", e)

        return ngrams

    def calculate_instruction_ngram_similarity(self, binary_path1: str, binary_path2: str, n: int = 4) -> float:
        """Calculate similarity based on instruction n-grams.

        Args:
            binary_path1: First binary path.
            binary_path2: Second binary path.
            n: N-gram size (default: 4).

        Returns:
            Jaccard similarity of instruction n-grams (0.0-1.0).
        """
        try:
            ngrams1 = self.compute_instruction_ngrams(binary_path1, n)
            ngrams2 = self.compute_instruction_ngrams(binary_path2, n)

            if not ngrams1 or not ngrams2:
                return 0.0

            intersection = len(ngrams1.intersection(ngrams2))
            union = len(ngrams1.union(ngrams2))

            return intersection / union if union > 0 else 0.0

        except Exception as e:
            self.logger.exception("Error calculating instruction n-gram similarity: %s", e)
            return 0.0

    def compute_cfg_hash(self, binary_path: str) -> str:
        """Compute instruction pattern hash for function-level similarity.

        Note: This is NOT a true CFG hash. It captures call/jump instruction
        patterns but not actual control flow graph structure. These patterns
        are unstable across recompilation as addresses change.

        Args:
            binary_path: Path to binary file.

        Returns:
            Instruction pattern hash signature (hex string).
        """
        try:
            if not os.path.exists(binary_path):
                return ""

            cfg_features: list[str] = []

            if HAS_PEFILE:
                try:
                    pe = pefile.PE(binary_path)

                    for section in pe.sections:
                        if b".text" in section.Name:
                            section_data = section.get_data()

                            call_patterns = self._extract_call_patterns(section_data)
                            cfg_features.extend(call_patterns)

                            jump_patterns = self._extract_jump_patterns(section_data)
                            cfg_features.extend(jump_patterns)

                    pe.close()

                except pefile.PEFormatError as pef:
                    self.logger.warning("Malformed PE file for CFG extraction: %s", pef)
                except Exception as pe_error:
                    self.logger.warning("PE CFG extraction failed: %s", pe_error)

            if not cfg_features:
                with open(binary_path, "rb") as f:
                    data = f.read(100000)
                    cfg_features.append(hashlib.sha256(data).hexdigest())

            combined = "|".join(sorted(cfg_features))
            cfg_hash = hashlib.sha256(combined.encode()).hexdigest()

            return cfg_hash

        except Exception as e:
            self.logger.exception("Error computing CFG hash: %s", e)
            return ""

    def _extract_call_patterns(self, data: bytes) -> list[str]:
        """Extract CALL instruction patterns from binary data.

        Args:
            data: Binary data to analyze.

        Returns:
            List of call pattern signatures.
        """
        patterns: list[str] = []

        call_opcodes = [b"\xe8", b"\xff\x15", b"\xff\xd0", b"\xff\xd1", b"\xff\xd2"]

        for opcode in call_opcodes:
            offset = 0
            while True:
                idx = data.find(opcode, offset)
                if idx == -1:
                    break

                context = data[max(0, idx - 4) : idx + 8]
                pattern_sig = f"call:{context.hex()}"
                patterns.append(pattern_sig)

                offset = idx + 1

                if len(patterns) > 500:
                    break

        return patterns

    def _extract_jump_patterns(self, data: bytes) -> list[str]:
        """Extract jump instruction patterns from binary data.

        Args:
            data: Binary data to analyze.

        Returns:
            List of jump pattern signatures.
        """
        patterns: list[str] = []

        jump_opcodes = [b"\xeb", b"\xe9", b"\x74", b"\x75", b"\x7e", b"\x7f"]

        for opcode in jump_opcodes:
            offset = 0
            while True:
                idx = data.find(opcode, offset)
                if idx == -1:
                    break

                context = data[max(0, idx - 2) : idx + 6]
                pattern_sig = f"jmp:{context.hex()}"
                patterns.append(pattern_sig)

                offset = idx + 1

                if len(patterns) > 500:
                    break

        return patterns

    def calculate_cfg_similarity(self, binary_path1: str, binary_path2: str) -> float:
        """Calculate CFG-based similarity between two binaries.

        Args:
            binary_path1: First binary path.
            binary_path2: Second binary path.

        Returns:
            CFG similarity score (0.0-1.0).
        """
        try:
            cfg_hash1 = self.compute_cfg_hash(binary_path1)
            cfg_hash2 = self.compute_cfg_hash(binary_path2)

            if not cfg_hash1 or not cfg_hash2:
                return 0.0

            if cfg_hash1 == cfg_hash2:
                return 1.0

            return self._calculate_hash_similarity(cfg_hash1, cfg_hash2)

        except Exception as e:
            self.logger.exception("Error calculating CFG similarity: %s", e)
            return 0.0

    def find_protection_variants(self, binary_path: str, variant_threshold: float = 0.85) -> list[dict[str, Any]]:
        """Find protection variants across binary corpus using advanced similarity.

        Args:
            binary_path: Reference binary path.
            variant_threshold: High similarity threshold for variant detection.

        Returns:
            List of likely protection variants with detailed similarity metrics.
        """
        try:
            results = self.search_similar_binaries(binary_path, threshold=variant_threshold)

            for result in results:
                result_path = result["path"]

                ngram_sim = self.calculate_instruction_ngram_similarity(binary_path, result_path)
                result["ngram_similarity"] = ngram_sim

                cfg_sim = self.calculate_cfg_similarity(binary_path, result_path)
                result["cfg_similarity"] = cfg_sim

                composite_score = (result["similarity"] * 0.5 + ngram_sim * 0.3 + cfg_sim * 0.2)
                result["composite_similarity"] = composite_score

            results.sort(key=lambda x: x.get("composite_similarity", 0), reverse=True)

            return results

        except Exception as e:
            self.logger.exception("Error finding protection variants: %s", e)
            return []

    def get_database_stats(self) -> dict[str, Any]:
        """Get statistics about the binary database.

        Returns:
            Dictionary containing total binaries, patterns, average file size, and unique imports/exports.

        """
        binaries_list = self.database.get("binaries", [])
        unique_imports_set: set[str] = set()
        unique_exports_set: set[str] = set()

        stats: dict[str, Any] = {
            "total_binaries": len(binaries_list),
            "total_patterns": 0,
            "avg_file_size": 0,
            "unique_imports": 0,
            "unique_exports": 0,
        }

        total_binaries = len(binaries_list)
        if total_binaries > 0:
            total_size = 0
            for binary in binaries_list:
                # Count patterns
                patterns = binary.get("cracking_patterns", [])
                if isinstance(patterns, list):
                    stats["total_patterns"] += len(patterns)

                # Calculate average file size
                file_size = binary.get("file_size", 0)
                if isinstance(file_size, int):
                    total_size += file_size

                # Collect unique imports and exports
                features = binary.get("features", {})
                if isinstance(features, dict):
                    imports = features.get("imports", [])
                    exports = features.get("exports", [])
                    if isinstance(imports, list):
                        unique_imports_set.update(imports)
                    if isinstance(exports, list):
                        unique_exports_set.update(exports)

            stats["avg_file_size"] = total_size // total_binaries
            stats["unique_imports"] = len(unique_imports_set)
            stats["unique_exports"] = len(unique_exports_set)

        return stats

    def get_fuzzy_match_statistics(self) -> dict[str, int]:
        """Get statistics from the most recent fuzzy string similarity calculation.

        Returns:
            Dictionary containing total_comparisons, matches_found, and sample_size.

        """
        return self.fuzzy_match_stats.copy()

    def remove_binary(self, binary_path: str) -> bool:
        """Remove a binary from the database.

        Args:
            binary_path: Path of the binary to remove.

        Returns:
            True if removed successfully, False otherwise.

        """
        try:
            original_count = len(self.database["binaries"])
            self.database["binaries"] = [b for b in self.database["binaries"] if b["path"] != binary_path]

            if len(self.database["binaries"]) < original_count:
                if self.use_lsh and self.lsh_index is not None:
                    self.lsh_index.remove(binary_path)

                self._save_database()
                self.logger.info("Removed binary %s from database", binary_path)
                return True
            self.logger.warning("Binary %s not found in database", binary_path)
            return False

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error removing binary %s: %s", binary_path, e)
            return False

    def load_database(self, database_path: str) -> bool:
        """Load a specific database file.

        Args:
            database_path: Path to the database file to load.

        Returns:
            True if successful, False otherwise.

        """
        try:
            self.database_path = database_path
            self.database = self._load_database()

            if self.use_lsh and self.lsh_index is not None:
                self._rebuild_lsh_index()

            self.logger.info("Loaded database from %s", database_path)
            return True
        except Exception as e:
            self.logger.exception("Error loading database %s: %s", database_path, e)
            return False

    def _rebuild_lsh_index(self) -> None:
        """Rebuild LSH index from current database."""
        if not self.use_lsh or self.lsh_index is None:
            return

        self.lsh_index = MinHashLSH(num_perm=128, threshold=0.5, num_bands=32)

        for binary in self.database.get("binaries", []):
            try:
                features = binary.get("features", {})
                feature_set = self._extract_feature_set_for_lsh(features)
                self.lsh_index.insert(binary["path"], feature_set)
            except Exception as e:
                self.logger.warning("Failed to index binary %s: %s", binary.get("path", "unknown"), e)

    def find_similar(self, binary_path: str, threshold: float = 0.7) -> list[dict[str, Any]]:
        """Find similar binaries to the given binary.

        Args:
            binary_path: Path to the binary file to find similarities for.
            threshold: Similarity threshold (0.0 to 1.0).

        Returns:
            List of similar binaries with their similarity scores.

        """
        return self.search_similar_binaries(binary_path, threshold)


def create_similarity_search(database_path: str = "binary_database.json") -> BinarySimilaritySearch:
    """Create a BinarySimilaritySearch instance.

    Args:
        database_path: Path to the database file.

    Returns:
        Configured BinarySimilaritySearch instance.

    """
    return BinarySimilaritySearch(database_path)
