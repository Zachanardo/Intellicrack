"""Protection database manager with caching and performance optimization.

This module provides centralized management of the protection database with
caching, performance optimization, and coordination between components.

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

import asyncio
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .pattern_matcher import AdvancedPatternMatcher, ScanResult
from .signature_database import (
    ArchitectureType, ProtectionSignature, ProtectionSignatureDatabase,
    ProtectionType
)
import logging

logger = logging.getLogger(__name__)


class DatabaseCache:
    """High-performance cache for database operations."""
    
    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        """Initialize the cache.
        
        Args:
            max_size: Maximum number of items to cache
            ttl: Time to live in seconds
        """
        self.max_size = max_size
        self.ttl = ttl
        self.cache = {}
        self.timestamps = {}
        self.lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached item or None if not found/expired
        """
        with self.lock:
            if key not in self.cache:
                return None
            
            # Check if expired
            if time.time() - self.timestamps[key] > self.ttl:
                del self.cache[key]
                del self.timestamps[key]
                return None
            
            return self.cache[key]
    
    def set(self, key: str, value: Any):
        """Set item in cache.
        
        Args:
            key: Cache key
            value: Value to cache
        """
        with self.lock:
            # Evict old items if cache is full
            if len(self.cache) >= self.max_size:
                self._evict_oldest()
            
            self.cache[key] = value
            self.timestamps[key] = time.time()
    
    def _evict_oldest(self):
        """Evict the oldest item from cache."""
        if not self.timestamps:
            return
        
        oldest_key = min(self.timestamps, key=self.timestamps.get)
        del self.cache[oldest_key]
        del self.timestamps[oldest_key]
    
    def clear(self):
        """Clear all cached items."""
        with self.lock:
            self.cache.clear()
            self.timestamps.clear()
    
    def size(self) -> int:
        """Get current cache size."""
        with self.lock:
            return len(self.cache)


class ProtectionDatabaseManager:
    """Central manager for protection database operations."""
    
    def __init__(self, database_path: Optional[Path] = None, cache_size: int = 1000):
        """Initialize the database manager.
        
        Args:
            database_path: Optional path to database directory
            cache_size: Maximum cache size
        """
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.database = ProtectionSignatureDatabase(database_path)
        self.pattern_matcher = AdvancedPatternMatcher(self.database)
        
        # Caching system
        self.cache = DatabaseCache(max_size=cache_size)
        self.scan_cache = DatabaseCache(max_size=cache_size // 2)
        
        # Performance tracking
        self.stats = {
            'scans_performed': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'total_scan_time': 0.0,
            'average_scan_time': 0.0
        }
        
        # Thread pool for async operations
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Configuration
        self.config = {
            'enable_caching': True,
            'enable_parallel_scanning': True,
            'max_file_size': 100 * 1024 * 1024,  # 100MB
            'scan_timeout': 30,  # seconds
            'auto_update': True,
            'update_interval': 3600  # 1 hour
        }
        
        # Background update thread
        self._update_thread = None
        self._shutdown_event = threading.Event()
        
        # Load database
        self.reload_database()
    
    def reload_database(self) -> bool:
        """Reload the database and clear caches.
        
        Returns:
            True if database reloaded successfully
        """
        try:
            success = self.database.load_database()
            if success:
                self.cache.clear()
                self.scan_cache.clear()
                self.logger.info("Protection database reloaded successfully")
                
                # Start background update thread if enabled
                if self.config['auto_update'] and self._update_thread is None:
                    self._start_update_thread()
                
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to reload database: {e}")
            return False
    
    def scan_file(self, file_path: str, use_cache: bool = True, 
                  architecture: Optional[ArchitectureType] = None) -> ScanResult:
        """Scan a file for protection patterns.
        
        Args:
            file_path: Path to file to scan
            use_cache: Whether to use cached results
            architecture: Optional architecture hint
            
        Returns:
            Scan results
        """
        start_time = time.time()
        
        try:
            # Check file size
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                return ScanResult(
                    file_path=file_path,
                    file_size=0,
                    file_hash="",
                    architecture=architecture,
                    error="File not found"
                )
            
            file_size = file_path_obj.stat().st_size
            if file_size > self.config['max_file_size']:
                return ScanResult(
                    file_path=file_path,
                    file_size=file_size,
                    file_hash="",
                    architecture=architecture,
                    error=f"File too large ({file_size} bytes)"
                )
            
            # Generate cache key
            cache_key = f"{file_path}:{file_path_obj.stat().st_mtime}:{architecture}"
            
            # Check cache
            if use_cache and self.config['enable_caching']:
                cached_result = self.scan_cache.get(cache_key)
                if cached_result:
                    self.stats['cache_hits'] += 1
                    return cached_result
            
            self.stats['cache_misses'] += 1
            
            # Perform scan
            result = self.pattern_matcher.scan_file(file_path, architecture)
            
            # Cache result
            if use_cache and self.config['enable_caching'] and not result.error:
                self.scan_cache.set(cache_key, result)
            
            # Update statistics
            scan_time = time.time() - start_time
            self.stats['scans_performed'] += 1
            self.stats['total_scan_time'] += scan_time
            self.stats['average_scan_time'] = self.stats['total_scan_time'] / self.stats['scans_performed']
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
            return ScanResult(
                file_path=file_path,
                file_size=0,
                file_hash="",
                architecture=architecture,
                error=str(e),
                scan_time=time.time() - start_time
            )
    
    def scan_multiple_files(self, file_paths: List[str], 
                           architecture: Optional[ArchitectureType] = None) -> List[ScanResult]:
        """Scan multiple files in parallel.
        
        Args:
            file_paths: List of file paths to scan
            architecture: Optional architecture hint
            
        Returns:
            List of scan results
        """
        if not self.config['enable_parallel_scanning']:
            # Sequential scanning
            return [self.scan_file(file_path, architecture=architecture) for file_path in file_paths]
        
        # Parallel scanning
        futures = []
        for file_path in file_paths:
            future = self.executor.submit(self.scan_file, file_path, True, architecture)
            futures.append(future)
        
        results = []
        for future in futures:
            try:
                result = future.result(timeout=self.config['scan_timeout'])
                results.append(result)
            except Exception as e:
                self.logger.error(f"Error in parallel scan: {e}")
                results.append(ScanResult(
                    file_path="unknown",
                    file_size=0,
                    file_hash="",
                    architecture=architecture,
                    error=str(e)
                ))
        
        return results
    
    def get_protection_signatures(self, protection_type: Optional[ProtectionType] = None) -> List[ProtectionSignature]:
        """Get protection signatures by type.
        
        Args:
            protection_type: Optional filter by protection type
            
        Returns:
            List of protection signatures
        """
        cache_key = f"signatures:{protection_type}"
        
        if self.config['enable_caching']:
            cached_result = self.cache.get(cache_key)
            if cached_result:
                return cached_result
        
        if protection_type:
            signatures = self.database.get_signatures_by_type(protection_type)
        else:
            signatures = list(self.database.signatures.values())
        
        if self.config['enable_caching']:
            self.cache.set(cache_key, signatures)
        
        return signatures
    
    def search_protections(self, query: str, protection_type: Optional[ProtectionType] = None) -> List[ProtectionSignature]:
        """Search for protection signatures.
        
        Args:
            query: Search query
            protection_type: Optional filter by protection type
            
        Returns:
            List of matching signatures
        """
        cache_key = f"search:{query}:{protection_type}"
        
        if self.config['enable_caching']:
            cached_result = self.cache.get(cache_key)
            if cached_result:
                return cached_result
        
        results = self.pattern_matcher.search_patterns(query, protection_type)
        
        if self.config['enable_caching']:
            self.cache.set(cache_key, results)
        
        return results
    
    def get_protection_info(self, protection_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed protection information.
        
        Args:
            protection_id: Protection signature ID
            
        Returns:
            Protection information dictionary
        """
        cache_key = f"info:{protection_id}"
        
        if self.config['enable_caching']:
            cached_result = self.cache.get(cache_key)
            if cached_result:
                return cached_result
        
        signature = self.database.get_signature_by_id(protection_id)
        if not signature:
            return None
        
        info = {
            'id': signature.id,
            'name': signature.name,
            'version': signature.version,
            'type': signature.protection_type.value,
            'architecture': signature.architecture.value,
            'confidence': signature.confidence,
            'description': signature.description,
            'references': signature.references,
            'metadata': signature.metadata,
            'created_date': signature.created_date.isoformat() if signature.created_date else None,
            'updated_date': signature.updated_date.isoformat() if signature.updated_date else None,
            'signatures': {
                'binary': len(signature.binary_signatures),
                'string': len(signature.string_signatures),
                'import': len(signature.import_signatures),
                'section': len(signature.section_signatures)
            }
        }
        
        if self.config['enable_caching']:
            self.cache.set(cache_key, info)
        
        return info
    
    def add_custom_signature(self, signature: ProtectionSignature) -> bool:
        """Add a custom protection signature.
        
        Args:
            signature: Signature to add
            
        Returns:
            True if signature added successfully
        """
        try:
            success = self.database.add_signature(signature)
            if success:
                # Clear relevant caches
                self.cache.clear()
                self.scan_cache.clear()
                self.logger.info(f"Added custom signature: {signature.name}")
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to add custom signature: {e}")
            return False
    
    def validate_signature(self, signature_id: str, test_files: List[str]) -> Dict[str, Any]:
        """Validate a signature against test files.
        
        Args:
            signature_id: ID of signature to validate
            test_files: List of test file paths
            
        Returns:
            Validation results
        """
        signature = self.database.get_signature_by_id(signature_id)
        if not signature:
            return {'error': 'Signature not found'}
        
        return self.pattern_matcher.validate_signature(signature, test_files)
    
    def get_database_statistics(self) -> Dict[str, Any]:
        """Get comprehensive database statistics.
        
        Returns:
            Database statistics
        """
        db_stats = self.database.get_statistics()
        
        stats = {
            'database': db_stats,
            'cache': {
                'scan_cache_size': self.scan_cache.size(),
                'pattern_cache_size': self.cache.size(),
                'cache_hits': self.stats['cache_hits'],
                'cache_misses': self.stats['cache_misses'],
                'hit_ratio': self.stats['cache_hits'] / max(1, self.stats['cache_hits'] + self.stats['cache_misses'])
            },
            'performance': {
                'scans_performed': self.stats['scans_performed'],
                'total_scan_time': self.stats['total_scan_time'],
                'average_scan_time': self.stats['average_scan_time']
            },
            'configuration': self.config.copy()
        }
        
        return stats
    
    def update_configuration(self, config: Dict[str, Any]) -> bool:
        """Update manager configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            True if configuration updated successfully
        """
        try:
            self.config.update(config)
            
            # Apply configuration changes
            if 'enable_caching' in config and not config['enable_caching']:
                self.cache.clear()
                self.scan_cache.clear()
            
            if 'auto_update' in config:
                if config['auto_update'] and self._update_thread is None:
                    self._start_update_thread()
                elif not config['auto_update'] and self._update_thread:
                    self._stop_update_thread()
            
            self.logger.info("Configuration updated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update configuration: {e}")
            return False
    
    def export_results(self, results: List[ScanResult], output_path: str, format: str = 'json') -> bool:
        """Export scan results to file.
        
        Args:
            results: List of scan results to export
            output_path: Output file path
            format: Export format ('json', 'csv', 'xml')
            
        Returns:
            True if export successful
        """
        try:
            output_path_obj = Path(output_path)
            output_path_obj.parent.mkdir(parents=True, exist_ok=True)
            
            if format.lower() == 'json':
                self._export_json(results, output_path_obj)
            elif format.lower() == 'csv':
                self._export_csv(results, output_path_obj)
            elif format.lower() == 'xml':
                self._export_xml(results, output_path_obj)
            else:
                raise ValueError(f"Unsupported export format: {format}")
            
            self.logger.info(f"Exported {len(results)} results to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export results: {e}")
            return False
    
    def _export_json(self, results: List[ScanResult], output_path: Path):
        """Export results to JSON format."""
        export_data = {
            'export_timestamp': time.time(),
            'total_results': len(results),
            'results': []
        }
        
        for result in results:
            result_data = {
                'file_path': result.file_path,
                'file_size': result.file_size,
                'file_hash': result.file_hash,
                'architecture': result.architecture.value if result.architecture else None,
                'scan_time': result.scan_time,
                'error': result.error,
                'detected_protections': list(result.detected_protections),
                'protection_types': [pt.value for pt in result.protection_types],
                'matches': []
            }
            
            for match in result.matches:
                match_data = {
                    'signature_id': match.signature_id,
                    'signature_name': match.signature_name,
                    'protection_type': match.protection_type.value,
                    'confidence': match.confidence,
                    'adjusted_confidence': match.adjusted_confidence,
                    'match_count': match.match_count,
                    'false_positive_score': match.false_positive_score,
                    'metadata': match.metadata
                }
                result_data['matches'].append(match_data)
            
            export_data['results'].append(result_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    def _export_csv(self, results: List[ScanResult], output_path: Path):
        """Export results to CSV format."""
        import csv
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'file_path', 'file_size', 'file_hash', 'architecture',
                'scan_time', 'error', 'detected_protections', 'match_count'
            ])
            
            # Write data
            for result in results:
                writer.writerow([
                    result.file_path,
                    result.file_size,
                    result.file_hash,
                    result.architecture.value if result.architecture else '',
                    result.scan_time,
                    result.error or '',
                    ';'.join(result.detected_protections),
                    len(result.matches)
                ])
    
    def _export_xml(self, results: List[ScanResult], output_path: Path):
        """Export results to XML format."""
        import xml.etree.ElementTree as ET
        
        root = ET.Element('scan_results')
        root.set('export_timestamp', str(time.time()))
        root.set('total_results', str(len(results)))
        
        for result in results:
            result_elem = ET.SubElement(root, 'result')
            result_elem.set('file_path', result.file_path)
            result_elem.set('file_size', str(result.file_size))
            result_elem.set('file_hash', result.file_hash)
            result_elem.set('architecture', result.architecture.value if result.architecture else '')
            result_elem.set('scan_time', str(result.scan_time))
            
            if result.error:
                error_elem = ET.SubElement(result_elem, 'error')
                error_elem.text = result.error
            
            if result.detected_protections:
                protections_elem = ET.SubElement(result_elem, 'detected_protections')
                for protection in result.detected_protections:
                    prot_elem = ET.SubElement(protections_elem, 'protection')
                    prot_elem.text = protection
            
            if result.matches:
                matches_elem = ET.SubElement(result_elem, 'matches')
                for match in result.matches:
                    match_elem = ET.SubElement(matches_elem, 'match')
                    match_elem.set('signature_id', match.signature_id)
                    match_elem.set('signature_name', match.signature_name)
                    match_elem.set('protection_type', match.protection_type.value)
                    match_elem.set('confidence', str(match.confidence))
                    match_elem.set('adjusted_confidence', str(match.adjusted_confidence))
        
        tree = ET.ElementTree(root)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)
    
    def _start_update_thread(self):
        """Start background update thread."""
        if self._update_thread is None:
            self._update_thread = threading.Thread(target=self._update_worker, daemon=True)
            self._update_thread.start()
    
    def _stop_update_thread(self):
        """Stop background update thread."""
        if self._update_thread:
            self._shutdown_event.set()
            self._update_thread = None
    
    def _update_worker(self):
        """Background worker for database updates."""
        while not self._shutdown_event.is_set():
            try:
                # Wait for update interval or shutdown
                if self._shutdown_event.wait(self.config['update_interval']):
                    break
                
                # Perform update check
                self.logger.debug("Checking for database updates...")
                # Implementation would check for database updates
                
            except Exception as e:
                self.logger.error(f"Error in update worker: {e}")
    
    def shutdown(self):
        """Shutdown the database manager."""
        try:
            self._stop_update_thread()
            self.executor.shutdown(wait=True)
            self.cache.clear()
            self.scan_cache.clear()
            self.logger.info("Database manager shut down successfully")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()