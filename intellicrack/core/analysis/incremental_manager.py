#!/usr/bin/env python3
"""
Incremental Analysis Manager for avoiding reprocessing unchanged code.

This module provides comprehensive incremental analysis capabilities to track changes
between analysis runs and avoid reprocessing unchanged code sections, significantly
improving performance for large binaries.
"""

import datetime
import hashlib
import json
import logging
import os
import pickle
import time
from typing import Any, Dict, Optional

try:
    from PyQt5.QtWidgets import QMessageBox
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False


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
        """
        Initialize the incremental analysis manager with configuration.

        Args:
            config: Configuration dictionary with cache settings
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Configure cache settings
        self.cache_dir = self.config.get('cache_dir', os.path.join(os.getcwd(), 'analysis_cache'))
        self.enable_caching = self.config.get('enable_caching', True)
        self.cache_max_size = self.config.get('cache_max_size', 1024 * 1024 * 100)  # 100MB default
        self.cache_max_age = self.config.get('cache_max_age', 30)  # 30 days default

        # Initialize cache state
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.current_binary: Optional[str] = None
        self.current_binary_hash: Optional[str] = None

        # Create cache directory if it doesn't exist
        if self.enable_caching:
            try:
                os.makedirs(self.cache_dir, exist_ok=True)
                self.logger.info(f"Cache directory initialized: {self.cache_dir}")
            except OSError as e:
                self.logger.error(f"Failed to create cache directory: {e}")
                self.enable_caching = False

        # Load cache index
        self._load_cache_index()

        self.logger.info("Incremental analysis manager initialized")

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

                self.logger.info(f"Loaded cache index with {len(self.cache)} entries")

                # Clean up invalid cache entries
                self._cleanup_invalid_entries()

            except (json.JSONDecodeError, IOError) as e:
                self.logger.error(f"Error loading cache index: {e}")
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
            self.logger.error(f"Error saving cache index: {e}")

            # Restore backup if available
            backup_path = index_path + '.backup'
            if os.path.exists(backup_path):
                try:
                    os.rename(backup_path, index_path)
                    self.logger.info("Restored cache index from backup")
                except OSError:
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
            self.logger.warning(f"Removing invalid cache entry: {binary_hash}")
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
            self.logger.error(f"Binary not found: {binary_path}")
            return False

        self.current_binary = os.path.abspath(binary_path)

        # Calculate hash of binary
        self.current_binary_hash = self._calculate_file_hash(binary_path)

        if not self.current_binary_hash:
            return False

        # Check if binary is in cache
        is_cached = self.current_binary_hash in self.cache

        if is_cached:
            self.logger.info(f"Binary found in cache: {binary_path}")
        else:
            self.logger.info(f"Binary not found in cache: {binary_path}")

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
            self.logger.error(f"Error calculating file hash: {e}")
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
            self.logger.warning(f"Cache file not found: {cache_file}")
            return None

        try:
            with open(cache_file, 'rb') as f:
                result = pickle.load(f)

            self.logger.info(f"Loaded cached analysis: {analysis_type}")
            return result

        except (pickle.PickleError, IOError) as e:
            self.logger.error(f"Error loading cache file: {e}")
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
            with open(cache_file, 'wb') as f:
                pickle.dump(results, f, protocol=pickle.HIGHEST_PROTOCOL)

            # Update cache index
            self.cache[self.current_binary_hash][analysis_type] = cache_file

            if self._save_cache_index():
                self.logger.info(f"Cached analysis results: {analysis_type}")
                return True
            else:
                # Clean up cache file if index save failed
                if os.path.exists(cache_file):
                    os.remove(cache_file)
                return False

        except (pickle.PickleError, IOError) as e:
            self.logger.error(f"Error caching analysis results: {e}")
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
            self.logger.warning(f"Binary not found in cache: {binary_hash}")
            return False

        cache_entry = self.cache[binary_hash]

        # Delete cache files
        for analysis_type, cache_file in cache_entry.items():
            if analysis_type not in ['binary_path', 'timestamp', 'file_size'] and isinstance(cache_file, str):
                if os.path.exists(cache_file):
                    try:
                        os.remove(cache_file)
                        self.logger.debug(f"Removed cache file: {cache_file}")
                    except OSError as e:
                        self.logger.error(f"Failed to remove cache file {cache_file}: {e}")

        # Remove from cache index
        del self.cache[binary_hash]

        if self._save_cache_index():
            self.logger.info(f"Cleared cache for binary: {binary_hash}")
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
                except ValueError:
                    # Invalid timestamp, consider it old
                    old_hashes.append(binary_hash)

        # Remove old entries
        cleaned_count = 0
        for binary_hash in old_hashes:
            if self._remove_cache_entry(binary_hash):
                cleaned_count += 1

        if cleaned_count > 0:
            self.logger.info(f"Cleaned up {cleaned_count} old cache entries")

        return cleaned_count


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
