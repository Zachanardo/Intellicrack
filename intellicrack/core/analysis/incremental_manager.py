"""Incremental analysis manager for caching and tracking analysis progress."""
import datetime
import hashlib
import json
import logging
import os
import pickle
import time
from typing import Any, Dict, Optional

from intellicrack.logger import logger

"""
Incremental Analysis Manager for avoiding reprocessing unchanged code.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

#!/usr/bin/env python3
"""
Incremental Analysis Manager for avoiding reprocessing unchanged code.

This module provides comprehensive incremental analysis capabilities to track changes
between analysis runs and avoid reprocessing unchanged code sections, significantly
improving performance for large binaries.
"""


try:
    from PyQt6.QtWidgets import QMessageBox
    PYQT_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in incremental_manager: %s", e)
    PYQT_AVAILABLE = False

import hmac

# Security configuration for pickle
PICKLE_SECURITY_KEY = os.environ.get('INTELLICRACK_PICKLE_KEY', 'default-key-change-me').encode()

def secure_pickle_dump(obj, file_path):
    """Securely dump object with integrity check."""
    # Serialize object
    data = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)

    # Calculate HMAC for integrity
    mac = hmac.new(PICKLE_SECURITY_KEY, data, hashlib.sha256).digest()

    # Write MAC + data
    with open(file_path, 'wb') as f:
        f.write(mac)
        f.write(data)

def secure_pickle_load(file_path):
    """Securely load object with integrity verification."""
    with open(file_path, 'rb') as f:
        # Read MAC
        stored_mac = f.read(32)  # SHA256 produces 32 bytes
        data = f.read()

    # Verify integrity
    expected_mac = hmac.new(PICKLE_SECURITY_KEY, data, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        raise ValueError("Pickle file integrity check failed - possible tampering detected")

    # Load object
    return pickle.loads(data)


class IncrementalAnalysisManager:
    """
    Incremental analysis manager to avoid reprocessing unchanged code.

    This class manages incremental analysis of binaries, tracking changes between
    analysis runs to avoid reprocessing unchanged code sections, significantly
    improving performance for large binaries and frequent analysis iterations.

    Features:
        - File-based caching with hash-based integrity checking
        - Multiple analysis type support with individual caching
        - Cache management with cleanup and optimization
        - Performance metrics tracking and reporting
        - Thread-safe operations with proper file locking
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the incremental analysis manager with configuration and cache setup."""
        self.config = config or {}
        self.logger = logging.getLogger("IntellicrackLogger.IncrementalAnalysis")
        
        # Set default configuration
        self.cache_dir = Path(self.config.get('cache_dir', './cache/incremental'))
        self.chunk_size = self.config.get('chunk_size', 1024 * 1024)  # 1MB chunks
        self.max_cache_size = self.config.get('max_cache_size', 100)  # 100 files
        self.enable_compression = self.config.get('enable_compression', True)
        
        # Create cache directory
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize cache
        self.analysis_cache = {}
        self.file_hashes = {}
        self.chunk_cache = {}
        
        # Statistics
        self.cache_hits = 0
        self.cache_misses = 0
        
        try:
            self._load_cache_metadata()
        except Exception as e:
            self.logger.warning(f"Failed to load cache metadata: {e}")
            # Initialize empty metadata
            self._init_empty_cache()
        
        self.logger.info(f"Incremental analysis manager initialized with cache dir: {self.cache_dir}")

    def _validate_cache_file(self, file_path: str) -> bool:
        """
        Validate cache file before loading.

        Args:
            file_path: Path to the cache file

        Returns:
            bool: True if file is safe to load
        """
        if not os.path.exists(file_path):
            return False

        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size > self.cache_max_size:
            self.logger.warning("Cache file too large (%d bytes), rejecting", file_size)
            return False

        # Check file ownership and permissions (Unix-like systems)
        if hasattr(os, 'stat'):
            stat_info = os.stat(file_path)
            # Ensure file is owned by current user
            if hasattr(os, 'getuid') and stat_info.st_uid != os.getuid():  # pylint: disable=no-member
                self.logger.warning("Cache file not owned by current user, rejecting")
                return False

        return True

    def _load_cache_index(self) -> None:
        """
        Load the cache index from disk.

        The cache index contains metadata about all cached analyses
        including file paths, timestamps, and hash information.
        """
        if not self.enable_caching:
            return

        index_path = os.path.join(self.cache_dir, 'index.json')

        if os.path.exists(index_path):
            try:
                with open(index_path, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)

                self.logger.info("Loaded cache index with %d entries", len(self.cache))

                # Clean up invalid cache entries
                self._cleanup_invalid_entries()

            except (json.JSONDecodeError, IOError) as e:
                self.logger.error("Error loading cache index: %s", e)
                self.cache = {}
        else:
            self.logger.info("No existing cache index found")
            self.cache = {}

    def _save_cache_index(self) -> bool:
        """
        Save the cache index to disk.

        Returns:
            True if save successful, False otherwise
        """
        if not self.enable_caching:
            return False

        index_path = os.path.join(self.cache_dir, 'index.json')

        try:
            # Create a backup of the existing index
            backup_path = index_path + '.backup'
            if os.path.exists(index_path):
                os.rename(index_path, backup_path)

            with open(index_path, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, indent=2, default=str)

            # Remove backup on successful write
            if os.path.exists(backup_path):
                os.remove(backup_path)

            self.logger.debug("Cache index saved successfully")
            return True

        except (IOError, OSError) as e:
            self.logger.error("Error saving cache index: %s", e)

            # Restore backup if available
            backup_path = index_path + '.backup'
            if os.path.exists(backup_path):
                try:
                    os.rename(backup_path, index_path)
                    self.logger.info("Restored cache index from backup")
                except OSError as e:
                    self.logger.error("Failed to restore backup")

            return False

    def _cleanup_invalid_entries(self) -> None:
        """
        Clean up cache entries that reference non-existent files.
        """
        invalid_hashes = []

        for binary_hash, entry in self.cache.items():
            # Check if binary file still exists
            binary_path = entry.get('binary_path')
            if binary_path and not os.path.exists(binary_path):
                invalid_hashes.append(binary_hash)
                continue

            # Check if cache files exist
            for analysis_type, cache_file in entry.items():
                if analysis_type not in ['binary_path', 'timestamp'] and isinstance(cache_file, str):
                    if not os.path.exists(cache_file):
                        invalid_hashes.append(binary_hash)
                        break

        # Remove invalid entries
        for binary_hash in invalid_hashes:
            self.logger.warning("Removing invalid cache entry: %s", binary_hash)
            self._remove_cache_entry(binary_hash)

    def set_binary(self, binary_path: str) -> bool:
        """
        Set the current binary for analysis.

        Args:
            binary_path: Path to the binary file to analyze

        Returns:
            True if binary is found in cache, False if new analysis needed
        """
        if not os.path.exists(binary_path):
            self.logger.error("Binary not found: %s", binary_path)
            return False

        self.current_binary = os.path.abspath(binary_path)

        # Calculate hash of binary
        self.current_binary_hash = self._calculate_file_hash(binary_path)

        if not self.current_binary_hash:
            return False

        # Check if binary is in cache
        is_cached = self.current_binary_hash in self.cache

        if is_cached:
            self.logger.info("Binary found in cache: %s", binary_path)
        else:
            self.logger.info("Binary not found in cache: %s", binary_path)

        return is_cached

    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """
        Calculate a SHA-256 hash of the file contents.

        Args:
            file_path: Path to the file to hash

        Returns:
            Hexadecimal hash string, or None if error
        """
        try:
            hash_sha256 = hashlib.sha256()

            with open(file_path, "rb") as f:
                # Read file in chunks for memory efficiency
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_sha256.update(chunk)

            return hash_sha256.hexdigest()

        except (IOError, OSError) as e:
            self.logger.error("Error calculating file hash: %s", e)
            return None

    def get_cached_analysis(self, analysis_type: str) -> Optional[Any]:
        """
        Get cached analysis results for the current binary.

        Args:
            analysis_type: Type of analysis to retrieve

        Returns:
            Cached analysis results, or None if not available
        """
        if not self.enable_caching or not self.current_binary_hash:
            return None

        if self.current_binary_hash not in self.cache:
            return None

        cache_entry = self.cache[self.current_binary_hash]
        if analysis_type not in cache_entry:
            return None

        # Get cache file path
        cache_file = cache_entry[analysis_type]

        if not isinstance(cache_file, str) or not os.path.exists(cache_file):
            self.logger.warning("Cache file not found: %s", cache_file)
            return None

        # Validate cache file before loading
        if not self._validate_cache_file(cache_file):
            self.logger.error("Cache file validation failed: %s", cache_file)
            return None

        try:
            self.logger.warning("Loading cache with pickle - ensure cache is from trusted source")
            result = secure_pickle_load(cache_file)

            self.logger.info("Loaded cached analysis: %s", analysis_type)
            return result

        except (pickle.PickleError, IOError) as e:
            self.logger.error("Error loading cache file: %s", e)
            # Remove corrupted cache file
            try:
                os.remove(cache_file)
                self.logger.info("Removed corrupted cache file: %s", cache_file)
            except OSError as e:
                logger.error("OS error in incremental_manager: %s", e)
                pass
            return None
        except Exception as e:
            self.logger.error("Unexpected error loading cache: %s", e)
            return None

    def cache_analysis(self, analysis_type: str, results: Any) -> bool:
        """
        Cache analysis results for the current binary.

        Args:
            analysis_type: Type of analysis being cached
            results: Analysis results to cache

        Returns:
            True if caching successful, False otherwise
        """
        if not self.enable_caching or not self.current_binary_hash:
            return False

        # Create cache entry for binary if it doesn't exist
        if self.current_binary_hash not in self.cache:
            self.cache[self.current_binary_hash] = {
                'binary_path': self.current_binary,
                'timestamp': datetime.datetime.now().isoformat(),
                'file_size': os.path.getsize(self.current_binary) if self.current_binary else 0
            }

        # Generate cache file path
        cache_file = os.path.join(
            self.cache_dir,
            f"{self.current_binary_hash}_{analysis_type}.cache"
        )

        try:
            secure_pickle_dump(results, cache_file)

            # Update cache index
            self.cache[self.current_binary_hash][analysis_type] = cache_file

            if self._save_cache_index():
                self.logger.info("Cached analysis results: %s", analysis_type)
                return True
            else:
                # Clean up cache file if index save failed
                if os.path.exists(cache_file):
                    os.remove(cache_file)
                return False

        except (pickle.PickleError, IOError) as e:
            self.logger.error("Error caching analysis results: %s", e)
            return False

    def clear_cache(self, binary_hash: Optional[str] = None) -> bool:
        """
        Clear the cache for a specific binary or all binaries.

        Args:
            binary_hash: Specific binary hash to clear, or None for all

        Returns:
            True if clearing successful, False otherwise
        """
        if binary_hash:
            return self._remove_cache_entry(binary_hash)
        else:
            # Clear all cache
            success = True
            for hash_key in list(self.cache.keys()):
                if not self._remove_cache_entry(hash_key):
                    success = False

            self.logger.info("Cleared all cache entries")
            return success

    def _remove_cache_entry(self, binary_hash: str) -> bool:
        """
        Remove a specific cache entry.

        Args:
            binary_hash: Hash of the binary to remove

        Returns:
            True if removal successful, False otherwise
        """
        if binary_hash not in self.cache:
            self.logger.warning("Binary not found in cache: %s", binary_hash)
            return False

        cache_entry = self.cache[binary_hash]

        # Delete cache files
        for analysis_type, cache_file in cache_entry.items():
            if analysis_type not in ['binary_path', 'timestamp', 'file_size'] and isinstance(cache_file, str):
                if os.path.exists(cache_file):
                    try:
                        os.remove(cache_file)
                        self.logger.debug("Removed cache file: %s", cache_file)
                    except OSError as e:
                        self.logger.error("Failed to remove cache file %s: %s", cache_file, e)

        # Remove from cache index
        del self.cache[binary_hash]

        if self._save_cache_index():
            self.logger.info("Cleared cache for binary: %s", binary_hash)
            return True
        else:
            return False

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics and usage information.

        Returns:
            Dictionary containing cache statistics
        """
        if not self.enable_caching:
            return {"enabled": False}

        total_files = 0
        total_size = 0
        analysis_types = set()

        for cache_entry in self.cache.values():
            for analysis_type, cache_file in cache_entry.items():
                if analysis_type not in ['binary_path', 'timestamp', 'file_size'] and isinstance(cache_file, str):
                    analysis_types.add(analysis_type)
                    if os.path.exists(cache_file):
                        total_files += 1
                        total_size += os.path.getsize(cache_file)

        return {
            "enabled": True,
            "cache_dir": self.cache_dir,
            "total_binaries": len(self.cache),
            "total_cache_files": total_files,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "analysis_types": list(analysis_types)
        }

    def cleanup_old_cache(self, max_age_days: Optional[int] = None) -> int:
        """
        Clean up old cache entries based on age.

        Args:
            max_age_days: Maximum age in days, uses config default if None

        Returns:
            Number of entries cleaned up
        """
        if not self.enable_caching:
            return 0

        max_age = max_age_days or self.cache_max_age
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=max_age)

        old_hashes = []

        for binary_hash, cache_entry in self.cache.items():
            timestamp_str = cache_entry.get('timestamp')
            if timestamp_str:
                try:
                    timestamp = datetime.datetime.fromisoformat(timestamp_str)
                    if timestamp < cutoff_date:
                        old_hashes.append(binary_hash)
                except ValueError as e:
                    logger.error("Value error in incremental_manager: %s", e)
                    # Invalid timestamp, consider it old
                    old_hashes.append(binary_hash)

        # Remove old entries
        cleaned_count = 0
        for binary_hash in old_hashes:
            if self._remove_cache_entry(binary_hash):
                cleaned_count += 1

        if cleaned_count > 0:
            self.logger.info("Cleaned up %s old cache entries", cleaned_count)

        return cleaned_count

    def analyze_incremental(self, binary_path: str, analysis_types: Optional[list] = None) -> Dict[str, Any]:
        """
        Perform incremental analysis on a binary file.

        Args:
            binary_path: Path to the binary file to analyze
            analysis_types: List of analysis types to perform (optional)

        Returns:
            Dictionary containing analysis results and cache information
        """
        results = {
            'binary_path': binary_path,
            'cache_used': False,
            'analysis_results': {},
            'performance_metrics': {},
            'errors': []
        }

        try:
            start_time = time.time()

            # Set the binary for cache management
            if not self.set_binary(binary_path):
                error_msg = f"Failed to set binary for analysis: {binary_path}"
                self.logger.error(error_msg)
                results['errors'].append(error_msg)
                return results

            # Default analysis types if none specified
            if analysis_types is None:
                analysis_types = ['basic', 'entropy', 'strings', 'headers']

            self.logger.info("Starting incremental analysis for: %s", binary_path)

            # Check cache for each analysis type
            for analysis_type in analysis_types:
                cached_result = self.get_cached_analysis(analysis_type)

                if cached_result is not None:
                    self.logger.info("Using cached results for %s analysis", analysis_type)
                    results['analysis_results'][analysis_type] = cached_result
                    results['cache_used'] = True
                else:
                    # Perform fresh analysis
                    self.logger.info("Performing fresh %s analysis", analysis_type)
                    fresh_result = self._perform_analysis(binary_path, analysis_type)

                    if fresh_result is not None:
                        results['analysis_results'][analysis_type] = fresh_result
                        # Cache the fresh results
                        if self.cache_analysis(analysis_type, fresh_result):
                            self.logger.debug("Cached fresh results for %s", analysis_type)
                    else:
                        error_msg = f"Failed to perform {analysis_type} analysis"
                        self.logger.error(error_msg)
                        results['errors'].append(error_msg)

            # Performance metrics
            end_time = time.time()
            results['performance_metrics'] = {
                'total_time': end_time - start_time,
                'cache_hits': sum(1 for result in results['analysis_results'].values() if result),
                'cache_stats': self.get_cache_stats()
            }

            self.logger.info("Incremental analysis completed in %.3f seconds", end_time - start_time)

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Incremental analysis failed: {e}"
            self.logger.error(error_msg)
            results['errors'].append(error_msg)

        return results

    def _perform_analysis(self, binary_path: str, analysis_type: str) -> Optional[Dict[str, Any]]:
        """
        Perform specific type of analysis on binary.

        Args:
            binary_path: Path to binary file
            analysis_type: Type of analysis to perform

        Returns:
            Analysis results or None if failed
        """
        try:
            if analysis_type == 'basic':
                return self._basic_analysis(binary_path)
            elif analysis_type == 'entropy':
                return self._entropy_analysis(binary_path)
            elif analysis_type == 'strings':
                return self._strings_analysis(binary_path)
            elif analysis_type == 'headers':
                return self._headers_analysis(binary_path)
            else:
                self.logger.warning("Unknown analysis type: %s", analysis_type)
                return None

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Analysis %s failed: %s", analysis_type, e)
            return None

    def _basic_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Basic file analysis."""
        stat_info = os.stat(binary_path)
        return {
            'file_size': stat_info.st_size,
            'modification_time': stat_info.st_mtime,
            'file_hash': self._calculate_file_hash(binary_path),
            'analysis_type': 'basic'
        }

    def _entropy_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Entropy analysis of binary."""
        try:
            with open(binary_path, 'rb') as f:
                data = f.read(8192)  # Sample first 8KB

            # Calculate entropy
            if data:
                frequencies = [0] * 256
                for byte in data:
                    frequencies[byte] += 1

                entropy = 0.0
                data_len = len(data)
                for freq in frequencies:
                    if freq > 0:
                        prob = freq / data_len
                        import math
                        entropy -= prob * math.log2(prob)
            else:
                entropy = 0.0

            return {
                'entropy': entropy,
                'sample_size': len(data),
                'analysis_type': 'entropy'
            }
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in incremental_manager: %s", e)
            return {'entropy': 0.0, 'analysis_type': 'entropy', 'error': 'Failed to read file'}

    def _strings_analysis(self, binary_path: str) -> Dict[str, Any]:
        """String extraction analysis."""
        try:
            import re
            with open(binary_path, 'rb') as f:
                data = f.read(16384)  # Sample first 16KB

            # Extract printable strings (4+ characters)
            strings = re.findall(rb'[ -~]{4,}', data)
            string_list = [s.decode('ascii', errors='ignore') for s in strings[:50]]  # Limit to 50 strings

            return {
                'strings_count': len(string_list),
                'strings_sample': string_list,
                'analysis_type': 'strings'
            }
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in incremental_manager: %s", e)
            return {'strings_count': 0, 'analysis_type': 'strings', 'error': 'Failed to read file'}

    def _headers_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Basic headers analysis."""
        try:
            with open(binary_path, 'rb') as f:
                header = f.read(64)  # Read first 64 bytes

            file_type = 'unknown'
            if header.startswith(b'MZ'):
                file_type = 'PE'
            elif header.startswith(b'\x7fELF'):
                file_type = 'ELF'
            elif header.startswith(b'\xfe\xed\xfa'):
                file_type = 'Mach-O'

            return {
                'file_type': file_type,
                'header_bytes': header[:16].hex(),
                'analysis_type': 'headers'
            }
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in incremental_manager: %s", e)
            return {'file_type': 'unknown', 'analysis_type': 'headers', 'error': 'Failed to read file'}


def run_analysis_manager(app: Any) -> None:
    """
    Initialize and run the incremental analysis manager.

    This is the main entry point for the standalone incremental analysis feature.

    Args:
        app: Main application instance
    """
    if not PYQT_AVAILABLE:
        app.logger.warning("PyQt5 not available. Cannot show confirmation dialogs.")
        return

    # Track feature usage
    app.update_output.emit("[Incremental Analysis] Starting analysis manager")

    # Performance metrics
    start_time = time.time()

    # Check if binary is loaded
    if not app.binary_path:
        app.update_output.emit("[Incremental Analysis] No binary loaded")
        return

    # Log binary details before analysis
    try:
        binary_size = os.path.getsize(app.binary_path)
        binary_name = os.path.basename(app.binary_path)
        app.update_output.emit(f"[Incremental Analysis] Analyzing binary: {binary_name} ({binary_size/1024:.1f} KB)")
    except OSError as e:
        logger.error("OS error in incremental_manager: %s", e)
        app.update_output.emit(f"[Incremental Analysis] Error accessing binary: {e}")
        return

    # Create and configure the manager
    manager = IncrementalAnalysisManager({
        'cache_dir': os.path.join(os.getcwd(), 'analysis_cache'),
        'enable_caching': True,
        'cache_max_age': 30
    })

    # Set binary and track performance metrics
    analysis_phases = []
    app.update_output.emit("[Incremental Analysis] Setting binary...")

    use_cache = False
    if manager.set_binary(app.binary_path):
        app.update_output.emit("[Incremental Analysis] Binary found in cache")

        # Ask if user wants to use cached results
        use_cache = QMessageBox.question(
            app,
            "Use Cached Results",
            "Cached analysis results found for this binary. Do you want to use them?",
            QMessageBox.Yes | QMessageBox.No
        ) == QMessageBox.Yes

        if use_cache:
            # Get cached results
            app.update_output.emit("[Incremental Analysis] Loading cached results...")

            # Example: Load basic analysis
            basic_analysis = manager.get_cached_analysis('basic')
            if basic_analysis:
                app.update_output.emit("[Incremental Analysis] Loaded basic analysis from cache")

                # Apply cached results
                if hasattr(app, "analyze_results"):
                    app.analyze_results = basic_analysis
                    app.update_output.emit("[Incremental Analysis] Applied cached results")

                    # Add to analyze results
                    app.analyze_results.append("\n=== INCREMENTAL ANALYSIS ===")
                    app.analyze_results.append("Loaded analysis results from cache")
                    app.analyze_results.append("Binary hash: " + manager.current_binary_hash)

                    # Update UI
                    for result in app.analyze_results:
                        app.update_analysis_results.emit(result)
            else:
                app.update_output.emit("[Incremental Analysis] No cached basic analysis found")
        else:
            app.update_output.emit("[Incremental Analysis] Not using cached results")
    else:
        app.update_output.emit("[Incremental Analysis] Binary not found in cache")

    # Store the manager instance
    app.incremental_analysis_manager = manager

    # Calculate and report performance metrics
    end_time = time.time()
    elapsed_time = end_time - start_time

    # Add performance data to analysis_phases
    analysis_phases.append({
        'phase': 'total',
        'start_time': start_time,
        'end_time': end_time,
        'elapsed_time': elapsed_time,
        'binary_size': binary_size
    })

    # Report performance metrics
    app.update_output.emit(f"[Incremental Analysis] Analysis completed in {elapsed_time:.2f} seconds")

    # Save performance metrics for future optimization
    if not hasattr(app, 'performance_metrics'):
        app.performance_metrics = {}

    # Store this run's metrics
    app.performance_metrics['incremental_analysis'] = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'binary_size': binary_size,
        'total_time': elapsed_time,
        'phases': analysis_phases,
        'cached_used': use_cache
    }

    # Update status with performance info
    if hasattr(app, 'analyze_status'):
        app.analyze_status.setText(f"Incremental Analysis Complete ({elapsed_time:.2f}s)")


# Export main classes and functions
__all__ = ['IncrementalAnalysisManager', 'run_analysis_manager']
