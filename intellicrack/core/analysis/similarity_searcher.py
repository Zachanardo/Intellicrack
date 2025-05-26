"""
Binary Similarity Searcher

This module provides binary similarity analysis capabilities to find similar cracking patterns
and binaries. It can extract features from binaries, build a database of known binaries,
and search for similar binaries based on various similarity metrics.

The searcher supports:
- PE file feature extraction (sections, imports, exports, entropy)
- Binary database management with JSON storage
- Similarity calculation using Jaccard similarity and entropy analysis
- Cracking pattern storage and retrieval
- Threshold-based similarity matching

Author: Intellicrack Development Team
"""

import os
import json
import logging
import datetime
from typing import Dict, List, Optional, Any, Union

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    

def calculate_entropy(data: bytes) -> float:
    """
    Calculate the Shannon entropy of binary data.
    
    Args:
        data: Binary data to analyze
        
    Returns:
        float: Entropy value (0.0 to 8.0)
    """
    if not data:
        return 0.0
        
    # Calculate frequency of each byte value
    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1
    
    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    
    for freq in frequency:
        if freq > 0:
            probability = freq / data_len
            entropy -= probability * (probability.bit_length() - 1)
    
    return entropy


class BinarySimilaritySearcher:
    """
    Binary similarity search to find similar cracking patterns and binaries.
    
    This class provides comprehensive binary analysis capabilities including feature extraction,
    similarity calculation, and pattern matching for discovering similar binaries that may
    share common cracking approaches or protection mechanisms.
    """

    def __init__(self, database_path: str = "binary_database.json") -> None:
        """
        Initialize the binary similarity searcher.

        Args:
            database_path: Path to the binary database file
        """
        self.database_path = database_path
        self.database = self._load_database()
        self.logger = logging.getLogger("IntellicrackLogger.SimilaritySearcher")

    def _load_database(self) -> Dict[str, Any]:
        """
        Load the binary database from disk.

        Returns:
            dict: Binary database structure
        """
        if os.path.exists(self.database_path):
            try:
                with open(self.database_path, "r", encoding='utf-8') as f:
                    database = json.load(f)
                    # Ensure proper structure
                    if "binaries" not in database:
                        database["binaries"] = []
                    return database
            except Exception as e:
                self.logger.error(f"Error loading binary database: {e}")
                return {"binaries": [], "metadata": {"version": "1.0", "created": datetime.datetime.now().isoformat()}}
        else:
            return {"binaries": [], "metadata": {"version": "1.0", "created": datetime.datetime.now().isoformat()}}

    def _save_database(self) -> bool:
        """
        Save the binary database to disk.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Update metadata
            if "metadata" not in self.database:
                self.database["metadata"] = {}
            self.database["metadata"]["last_updated"] = datetime.datetime.now().isoformat()
            self.database["metadata"]["binary_count"] = len(self.database.get("binaries", []))
            
            with open(self.database_path, "w", encoding='utf-8') as f:
                json.dump(self.database, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            self.logger.error(f"Error saving binary database: {e}")
            return False

    def add_binary(self, binary_path: str, cracking_patterns: Optional[List[str]] = None) -> bool:
        """
        Add a binary to the database with extracted features.

        Args:
            binary_path: Path to the binary file
            cracking_patterns: List of cracking patterns associated with this binary

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not os.path.exists(binary_path):
                self.logger.error(f"Binary file not found: {binary_path}")
                return False
                
            # Extract binary features
            features = self._extract_binary_features(binary_path)
            if not features:
                self.logger.error(f"Failed to extract features from {binary_path}")
                return False

            # Check if binary already exists in database
            for binary in self.database["binaries"]:
                if binary["path"] == binary_path:
                    self.logger.warning(f"Binary {binary_path} already exists in database, updating...")
                    binary["features"] = features
                    binary["cracking_patterns"] = cracking_patterns or []
                    binary["updated"] = datetime.datetime.now().isoformat()
                    self._save_database()
                    return True

            # Add new binary to database
            binary_entry = {
                "path": binary_path,
                "name": os.path.basename(binary_path),
                "features": features,
                "cracking_patterns": cracking_patterns or [],
                "added": datetime.datetime.now().isoformat(),
                "file_size": os.path.getsize(binary_path)
            }

            self.database["binaries"].append(binary_entry)
            self._save_database()

            self.logger.info(f"Added binary {binary_path} to database")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding binary {binary_path} to database: {e}")
            return False

    def _extract_binary_features(self, binary_path: str) -> Dict[str, Any]:
        """
        Extract comprehensive features from a binary file.

        Args:
            binary_path: Path to the binary file

        Returns:
            dict: Extracted features dictionary
        """
        try:
            if not PEFILE_AVAILABLE:
                self.logger.warning("pefile not available, using basic features only")
                return self._extract_basic_features(binary_path)
                
            pe = pefile.PE(binary_path)

            # Extract basic PE information
            features = {
                "machine": pe.FILE_HEADER.Machine,
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "characteristics": pe.FILE_HEADER.Characteristics,
                "subsystem": pe.OPTIONAL_HEADER.Subsystem if hasattr(pe, 'OPTIONAL_HEADER') else 0,
                "sections": [],
                "imports": [],
                "exports": [],
                "file_entropy": 0.0
            }

            # Extract section information
            for section in pe.sections:
                try:
                    section_name = section.Name.decode('utf-8', 'ignore').strip("\x00")
                    section_data = section.get_data()
                    section_info = {
                        "name": section_name,
                        "virtual_address": section.VirtualAddress,
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_data_size": section.SizeOfRawData,
                        "characteristics": section.Characteristics,
                        "entropy": calculate_entropy(section_data)
                    }
                    features["sections"].append(section_info)
                except Exception as e:
                    self.logger.warning(f"Error processing section: {e}")

            # Extract import information
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    try:
                        dll_name = entry.dll.decode('utf-8', 'ignore')
                        for imp in entry.imports:
                            if imp.name:
                                imp_name = imp.name.decode('utf-8', 'ignore')
                                features["imports"].append(f"{dll_name}:{imp_name}")
                    except Exception as e:
                        self.logger.warning(f"Error processing import: {e}")

            # Extract export information
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    try:
                        if exp.name:
                            exp_name = exp.name.decode('utf-8', 'ignore')
                            features["exports"].append(exp_name)
                    except Exception as e:
                        self.logger.warning(f"Error processing export: {e}")

            # Calculate overall file entropy
            with open(binary_path, 'rb') as f:
                # Read first 64KB for entropy calculation
                file_data = f.read(65536)
                features["file_entropy"] = calculate_entropy(file_data)

            pe.close()
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting features from {binary_path}: {e}")
            return self._extract_basic_features(binary_path)
            
    def _extract_basic_features(self, binary_path: str) -> Dict[str, Any]:
        """
        Extract basic features when pefile is not available.
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            dict: Basic features dictionary
        """
        try:
            features = {
                "file_size": os.path.getsize(binary_path),
                "file_entropy": 0.0,
                "basic_features": True
            }
            
            # Calculate file entropy from first 64KB
            with open(binary_path, 'rb') as f:
                file_data = f.read(65536)
                features["file_entropy"] = calculate_entropy(file_data)
                
            return features
        except Exception as e:
            self.logger.error(f"Error extracting basic features from {binary_path}: {e}")
            return {}

    def search_similar_binaries(self, binary_path: str, threshold: float = 0.7) -> List[Dict[str, Any]]:
        """
        Search for similar binaries in the database.

        Args:
            binary_path: Path to the target binary
            threshold: Similarity threshold (0.0 to 1.0)

        Returns:
            list: List of similar binaries with similarity scores
        """
        try:
            # Extract features from target binary
            target_features = self._extract_binary_features(binary_path)
            if not target_features:
                self.logger.error(f"Failed to extract features from target binary: {binary_path}")
                return []

            # Calculate similarity with each binary in the database
            similar_binaries = []
            for binary in self.database["binaries"]:
                similarity = self._calculate_similarity(target_features, binary["features"])
                if similarity >= threshold:
                    similar_binaries.append({
                        "path": binary["path"],
                        "name": binary["name"],
                        "similarity": similarity,
                        "cracking_patterns": binary["cracking_patterns"],
                        "added": binary.get("added", "unknown"),
                        "file_size": binary.get("file_size", 0)
                    })

            # Sort by similarity (descending)
            similar_binaries.sort(key=lambda x: x["similarity"], reverse=True)

            self.logger.info(f"Found {len(similar_binaries)} similar binaries for {binary_path}")
            return similar_binaries
            
        except Exception as e:
            self.logger.error(f"Error searching similar binaries for {binary_path}: {e}")
            return []

    def _calculate_similarity(self, features1: Dict[str, Any], features2: Dict[str, Any]) -> float:
        """
        Calculate similarity between two sets of binary features.

        Args:
            features1: First set of features
            features2: Second set of features

        Returns:
            float: Similarity score (0.0 to 1.0)
        """
        try:
            # Handle basic features mode
            if features1.get("basic_features") or features2.get("basic_features"):
                return self._calculate_basic_similarity(features1, features2)
                
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
            
            # Calculate entropy similarity
            entropy_similarity = self._calculate_entropy_similarity(
                features1.get("file_entropy", 0),
                features2.get("file_entropy", 0)
            )

            # Weighted overall similarity
            similarity = (
                section_similarity * 0.4 + 
                import_similarity * 0.3 + 
                export_similarity * 0.2 + 
                entropy_similarity * 0.1
            )

            return min(1.0, max(0.0, similarity))
            
        except Exception as e:
            self.logger.error(f"Error calculating similarity: {e}")
            return 0.0
            
    def _calculate_basic_similarity(self, features1: Dict[str, Any], features2: Dict[str, Any]) -> float:
        """
        Calculate basic similarity when full PE analysis is not available.
        
        Args:
            features1: First set of features
            features2: Second set of features
            
        Returns:
            float: Basic similarity score (0.0 to 1.0)
        """
        try:
            # File size similarity
            size1 = features1.get("file_size", 0)
            size2 = features2.get("file_size", 0)
            
            if size1 == 0 or size2 == 0:
                size_similarity = 0.0
            else:
                size_ratio = min(size1, size2) / max(size1, size2)
                size_similarity = size_ratio
            
            # Entropy similarity
            entropy_similarity = self._calculate_entropy_similarity(
                features1.get("file_entropy", 0),
                features2.get("file_entropy", 0)
            )
            
            return size_similarity * 0.5 + entropy_similarity * 0.5
            
        except Exception as e:
            self.logger.error(f"Error calculating basic similarity: {e}")
            return 0.0

    def _calculate_section_similarity(self, sections1: List[Dict[str, Any]], sections2: List[Dict[str, Any]]) -> float:
        """
        Calculate similarity between two sets of PE sections.

        Args:
            sections1: First set of sections
            sections2: Second set of sections

        Returns:
            float: Section similarity score (0.0 to 1.0)
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
            entropy_similarity = self._calculate_entropy_list_similarity(entropies1, entropies2)

            # Compare section characteristics
            characteristics1 = [s.get("characteristics", 0) for s in sections1]
            characteristics2 = [s.get("characteristics", 0) for s in sections2]
            char_similarity = self._calculate_numeric_similarity(characteristics1, characteristics2)

            return name_similarity * 0.5 + entropy_similarity * 0.3 + char_similarity * 0.2
            
        except Exception as e:
            self.logger.error(f"Error calculating section similarity: {e}")
            return 0.0

    def _calculate_list_similarity(self, list1: List[str], list2: List[str]) -> float:
        """
        Calculate Jaccard similarity between two lists.

        Args:
            list1: First list
            list2: Second list

        Returns:
            float: Jaccard similarity score (0.0 to 1.0)
        """
        try:
            if not list1 or not list2:
                return 0.0

            # Convert to sets for Jaccard similarity
            set1 = set(list1)
            set2 = set(list2)

            # Calculate Jaccard similarity coefficient
            intersection = len(set1.intersection(set2))
            union = len(set1.union(set2))

            return intersection / union if union > 0 else 0.0
            
        except Exception as e:
            self.logger.error(f"Error calculating list similarity: {e}")
            return 0.0
            
    def _calculate_entropy_similarity(self, entropy1: float, entropy2: float) -> float:
        """
        Calculate similarity between two entropy values.
        
        Args:
            entropy1: First entropy value
            entropy2: Second entropy value
            
        Returns:
            float: Entropy similarity score (0.0 to 1.0)
        """
        try:
            if entropy1 == 0 and entropy2 == 0:
                return 1.0
            
            # Calculate normalized difference
            max_entropy = 8.0  # Maximum possible entropy for byte data
            entropy_diff = abs(entropy1 - entropy2)
            
            # Convert difference to similarity
            return max(0.0, 1.0 - (entropy_diff / max_entropy))
            
        except Exception as e:
            self.logger.error(f"Error calculating entropy similarity: {e}")
            return 0.0
            
    def _calculate_entropy_list_similarity(self, entropies1: List[float], entropies2: List[float]) -> float:
        """
        Calculate similarity between two lists of entropy values.
        
        Args:
            entropies1: First list of entropy values
            entropies2: Second list of entropy values
            
        Returns:
            float: Entropy list similarity score (0.0 to 1.0)
        """
        try:
            if not entropies1 or not entropies2:
                return 0.0
                
            # Pad shorter list with zeros
            min_len = min(len(entropies1), len(entropies2))
            max_len = max(len(entropies1), len(entropies2))
            
            if min_len == 0:
                return 0.0
                
            # Calculate average entropy similarity for overlapping elements
            total_similarity = 0.0
            for i in range(min_len):
                total_similarity += self._calculate_entropy_similarity(entropies1[i], entropies2[i])
            
            # Penalty for length difference
            length_penalty = min_len / max_len
            
            return (total_similarity / min_len) * length_penalty
            
        except Exception as e:
            self.logger.error(f"Error calculating entropy list similarity: {e}")
            return 0.0
            
    def _calculate_numeric_similarity(self, list1: List[Union[int, float]], list2: List[Union[int, float]]) -> float:
        """
        Calculate similarity between two lists of numeric values.
        
        Args:
            list1: First list of numeric values
            list2: Second list of numeric values
            
        Returns:
            float: Numeric similarity score (0.0 to 1.0)
        """
        try:
            if not list1 or not list2:
                return 0.0
                
            # Convert to sets and calculate Jaccard similarity
            set1 = set(list1)
            set2 = set(list2)
            
            intersection = len(set1.intersection(set2))
            union = len(set1.union(set2))
            
            return intersection / union if union > 0 else 0.0
            
        except Exception as e:
            self.logger.error(f"Error calculating numeric similarity: {e}")
            return 0.0

    def get_database_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the binary database.
        
        Returns:
            dict: Database statistics
        """
        try:
            stats = {
                "total_binaries": len(self.database.get("binaries", [])),
                "database_size_bytes": os.path.getsize(self.database_path) if os.path.exists(self.database_path) else 0,
                "creation_date": self.database.get("metadata", {}).get("created", "unknown"),
                "last_updated": self.database.get("metadata", {}).get("last_updated", "unknown"),
                "binaries_with_patterns": 0,
                "total_patterns": 0
            }
            
            # Count patterns
            for binary in self.database.get("binaries", []):
                patterns = binary.get("cracking_patterns", [])
                if patterns:
                    stats["binaries_with_patterns"] += 1
                    stats["total_patterns"] += len(patterns)
                    
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting database stats: {e}")
            return {}

    def remove_binary(self, binary_path: str) -> bool:
        """
        Remove a binary from the database.
        
        Args:
            binary_path: Path to the binary to remove
            
        Returns:
            bool: True if removed successfully, False otherwise
        """
        try:
            initial_count = len(self.database["binaries"])
            self.database["binaries"] = [
                binary for binary in self.database["binaries"] 
                if binary["path"] != binary_path
            ]
            
            if len(self.database["binaries"]) < initial_count:
                self._save_database()
                self.logger.info(f"Removed binary {binary_path} from database")
                return True
            else:
                self.logger.warning(f"Binary {binary_path} not found in database")
                return False
                
        except Exception as e:
            self.logger.error(f"Error removing binary {binary_path}: {e}")
            return False


__all__ = ['BinarySimilaritySearcher', 'calculate_entropy']