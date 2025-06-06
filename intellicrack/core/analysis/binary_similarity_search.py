"""
Binary Similarity Search Engine

This module provides functionality to search for similar binaries based on
structural features, enabling identification of patterns and commonalities
in cracking targets.
"""

import datetime
import json
import logging
import math
import os
from typing import Any, Dict, List, Optional

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

__all__ = ['BinarySimilaritySearch']


# Import shared entropy calculation
from ...utils.protection_utils import calculate_entropy


class BinarySimilaritySearch:
    """
    Binary similarity search engine to find similar cracking patterns.

    Uses structural analysis and feature extraction to identify similarities
    between binary files and associated cracking patterns.
    """

    def __init__(self, database_path: str = "binary_database.json"):
        """
        Initialize the binary similarity search engine.

        Args:
            database_path: Path to the binary database file
        """
        self.database_path = database_path
        self.logger = logging.getLogger(__name__)
        self.database = self._load_database()

    def _load_database(self) -> Dict[str, Any]:
        """
        Load the binary database from file.

        Returns:
            Database dictionary with binary entries
        """
        if os.path.exists(self.database_path):
            try:
                with open(self.database_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error("Error loading binary database: %s", e)
                return {"binaries": []}
        else:
            return {"binaries": []}

    def _save_database(self) -> None:
        """Save the binary database to file."""
        try:
            with open(self.database_path, "w", encoding="utf-8") as f:
                json.dump(self.database, f, indent=4)
        except Exception as e:
            self.logger.error("Error saving binary database: %s", e)

    def add_binary(self, binary_path: str, cracking_patterns: Optional[List[str]] = None) -> bool:
        """
        Add a binary to the database with its features and patterns.

        Args:
            binary_path: Path to the binary file
            cracking_patterns: List of associated cracking patterns

        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if binary already exists in database
            for existing in self.database["binaries"]:
                if existing["path"] == binary_path:
                    self.logger.warning("Binary %s already exists in database", binary_path)
                    return False

            # Extract binary features
            features = self._extract_binary_features(binary_path)

            # Add to database
            binary_entry = {
                "path": binary_path,
                "filename": os.path.basename(binary_path),
                "features": features,
                "cracking_patterns": cracking_patterns or [],
                "added": datetime.datetime.now().isoformat(),
                "file_size": os.path.getsize(binary_path) if os.path.exists(binary_path) else 0
            }

            self.database["binaries"].append(binary_entry)
            self._save_database()

            self.logger.info("Added binary %s to database", binary_path)
            return True

        except Exception as e:
            self.logger.error("Error adding binary %s to database: %s", binary_path, e)
            return False

    def _extract_binary_features(self, binary_path: str) -> Dict[str, Any]:
        """
        Extract structural features from a binary file.

        Args:
            binary_path: Path to the binary file

        Returns:
            Dictionary of extracted features
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
            "characteristics": None
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
                    features["machine"] = getattr(pe.FILE_HEADER, 'Machine', 0)
                    features["timestamp"] = getattr(pe.FILE_HEADER, 'TimeDateStamp', 0)
                    features["characteristics"] = getattr(pe.FILE_HEADER, 'Characteristics', 0)

                    # Extract section information
                    for section in pe.sections:
                        section_name = section.Name.decode('utf-8', 'ignore').strip("\x00")
                        section_info = {
                            "name": section_name,
                            "virtual_address": section.VirtualAddress,
                            "virtual_size": section.Misc_VirtualSize,
                            "raw_data_size": section.SizeOfRawData,
                            "entropy": calculate_entropy(section.get_data())
                        }
                        features["sections"].append(section_info)

                    # Extract import information
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            dll_name = entry.dll.decode('utf-8', 'ignore')
                            for imp in entry.imports:
                                if imp.name:
                                    imp_name = imp.name.decode('utf-8', 'ignore')
                                    features["imports"].append(f"{dll_name}:{imp_name}")

                    # Extract export information
                    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                            if exp.name:
                                exp_name = exp.name.decode('utf-8', 'ignore')
                                features["exports"].append(exp_name)

                    # Extract strings (basic implementation)
                    strings = self._extract_strings(data)
                    features["strings"] = strings[:50]  # Limit to first 50 strings

                except Exception as e:
                    self.logger.warning("PE analysis failed for %s: %s", binary_path, e)

            return features

        except Exception as e:
            self.logger.error("Error extracting features from %s: %s", binary_path, e)
            return features

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract ASCII strings from binary data using common utility."""
        from ...utils.string_utils import extract_ascii_strings
        return extract_ascii_strings(data, min_length)

    def search_similar_binaries(self, binary_path: str, threshold: float = 0.7) -> List[Dict[str, Any]]:
        """
        Search for binaries similar to the given binary.

        Args:
            binary_path: Path to the target binary
            threshold: Similarity threshold (0.0 to 1.0)

        Returns:
            List of similar binaries with similarity scores
        """
        try:
            # Extract binary features
            target_features = self._extract_binary_features(binary_path)

            # Calculate similarity with each binary in the database
            similar_binaries = []
            for binary in self.database["binaries"]:
                similarity = self._calculate_similarity(target_features, binary["features"])
                if similarity >= threshold:
                    similar_binaries.append({
                        "path": binary["path"],
                        "filename": binary.get("filename", os.path.basename(binary["path"])),
                        "similarity": similarity,
                        "cracking_patterns": binary["cracking_patterns"],
                        "added": binary.get("added", "Unknown"),
                        "file_size": binary.get("file_size", 0)
                    })

            # Sort by similarity (descending)
            similar_binaries.sort(key=lambda x: x["similarity"], reverse=True)

            self.logger.info(f"Found {len(similar_binaries)} similar binaries for {binary_path}")
            return similar_binaries

        except Exception as e:
            self.logger.error("Error searching similar binaries for %s: %s", binary_path, e)
            return []

    def _calculate_similarity(self, features1: Dict[str, Any], features2: Dict[str, Any]) -> float:
        """
        Calculate similarity between two sets of features.

        Args:
            features1: First set of features
            features2: Second set of features

        Returns:
            Similarity score (0.0 to 1.0)
        """
        try:
            # Calculate section similarity
            section_similarity = self._calculate_section_similarity(
                features1.get("sections", []),
                features2.get("sections", [])
            )

            # Calculate import similarity
            import_similarity = self._calculate_list_similarity(
                features1.get("imports", []),
                features2.get("imports", [])
            )

            # Calculate export similarity
            export_similarity = self._calculate_list_similarity(
                features1.get("exports", []),
                features2.get("exports", [])
            )

            # Calculate string similarity
            string_similarity = self._calculate_list_similarity(
                features1.get("strings", []),
                features2.get("strings", [])
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
            similarity = (
                section_similarity * 0.30 +
                import_similarity * 0.25 +
                export_similarity * 0.15 +
                string_similarity * 0.15 +
                size_similarity * 0.10 +
                entropy_similarity * 0.05
            )

            return min(1.0, max(0.0, similarity))

        except Exception as e:
            self.logger.error("Error calculating similarity: %s", e)
            return 0.0

    def _calculate_section_similarity(self, sections1: List[Dict[str, Any]], sections2: List[Dict[str, Any]]) -> float:
        """
        Calculate similarity between two sets of sections.

        Args:
            sections1: First set of sections
            sections2: Second set of sections

        Returns:
            Similarity score (0.0 to 1.0)
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

        except Exception as e:
            self.logger.error("Error calculating section similarity: %s", e)
            return 0.0

    def _calculate_list_similarity(self, list1: List[str], list2: List[str]) -> float:
        """
        Calculate Jaccard similarity between two lists.

        Args:
            list1: First list
            list2: Second list

        Returns:
            Similarity score (0.0 to 1.0)
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

        except Exception as e:
            self.logger.error("Error calculating list similarity: %s", e)
            return 0.0

    def get_database_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the binary database.

        Returns:
            Dictionary with database statistics
        """
        stats = {
            "total_binaries": len(self.database.get("binaries", [])),
            "total_patterns": 0,
            "avg_file_size": 0,
            "unique_imports": set(),
            "unique_exports": set()
        }

        if stats["total_binaries"] > 0:
            total_size = 0
            for binary in self.database["binaries"]:
                # Count patterns
                stats["total_patterns"] += len(binary.get("cracking_patterns", []))

                # Calculate average file size
                file_size = binary.get("file_size", 0)
                total_size += file_size

                # Collect unique imports and exports
                features = binary.get("features", {})
                stats["unique_imports"].update(features.get("imports", []))
                stats["unique_exports"].update(features.get("exports", []))

            stats["avg_file_size"] = total_size // stats["total_binaries"]
            stats["unique_imports"] = len(stats["unique_imports"])
            stats["unique_exports"] = len(stats["unique_exports"])

        return stats

    def remove_binary(self, binary_path: str) -> bool:
        """
        Remove a binary from the database.

        Args:
            binary_path: Path of the binary to remove

        Returns:
            True if removed successfully, False otherwise
        """
        try:
            original_count = len(self.database["binaries"])
            self.database["binaries"] = [
                b for b in self.database["binaries"] if b["path"] != binary_path
            ]

            if len(self.database["binaries"]) < original_count:
                self._save_database()
                self.logger.info("Removed binary %s from database", binary_path)
                return True
            else:
                self.logger.warning("Binary %s not found in database", binary_path)
                return False

        except Exception as e:
            self.logger.error("Error removing binary %s: %s", binary_path, e)
            return False


def create_similarity_search(database_path: str = "binary_database.json") -> BinarySimilaritySearch:
    """
    Factory function to create a BinarySimilaritySearch instance.

    Args:
        database_path: Path to the database file

    Returns:
        Configured BinarySimilaritySearch instance
    """
    return BinarySimilaritySearch(database_path)
