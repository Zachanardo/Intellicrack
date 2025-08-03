"""
Unit Tests for QEMU Snapshot Diffing System.

Comprehensive test suite for the QEMU snapshot diffing mechanism,
including memory change detection, behavior analysis, and license detection.

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
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from intellicrack.core.processing.qemu_snapshot_differ import (
    ChangeType,
    CompressionType,
    MemoryChange,
    MemoryDiffEngine,
    MemoryRegion,
    QEMUSnapshotDiffer,
    SnapshotMetadata,
    create_snapshot_differ,
    quick_behavior_analysis,
)


class TestMemoryRegion(unittest.TestCase):
    """Test cases for MemoryRegion class."""
    
    def test_memory_region_creation(self):
        """Test memory region creation and properties."""
        region = MemoryRegion(
            start_addr=0x10000000,
            end_addr=0x10001000,
            size=0x1000,
            permissions="rwx",
            mapping_type="heap"
        )
        
        self.assertEqual(region.start_addr, 0x10000000)
        self.assertEqual(region.end_addr, 0x10001000)
        self.assertEqual(region.size, 0x1000)
        self.assertEqual(region.permissions, "rwx")
        self.assertEqual(region.mapping_type, "heap")
        self.assertEqual(region.page_count, 1)
    
    def test_contains_address(self):
        """Test address containment checking."""
        region = MemoryRegion(
            start_addr=0x10000000,
            end_addr=0x10001000,
            size=0x1000,
            permissions="rwx",
            mapping_type="heap"
        )
        
        self.assertTrue(region.contains_address(0x10000000))
        self.assertTrue(region.contains_address(0x10000500))
        self.assertFalse(region.contains_address(0x10001000))  # End address is exclusive
        self.assertFalse(region.contains_address(0x0FFFFFFF))
        self.assertFalse(region.contains_address(0x10002000))


class TestMemoryChange(unittest.TestCase):
    """Test cases for MemoryChange class."""
    
    def test_memory_change_creation(self):
        """Test memory change creation and properties."""
        region = MemoryRegion(
            start_addr=0x10000000,
            end_addr=0x10001000,
            size=0x1000,
            permissions="rwx",
            mapping_type="code"
        )
        
        change = MemoryChange(
            change_type=ChangeType.CODE_MODIFICATION,
            address=0x10000500,
            size=256,
            region_info=region,
            description="Code modification detected"
        )
        
        self.assertEqual(change.change_type, ChangeType.CODE_MODIFICATION)
        self.assertEqual(change.address, 0x10000500)
        self.assertEqual(change.size, 256)
        self.assertEqual(change.region_info, region)
        self.assertTrue(change.is_code_change)
        self.assertFalse(change.is_data_change)
    
    def test_change_type_properties(self):
        """Test change type property methods."""
        code_change = MemoryChange(
            change_type=ChangeType.CODE_MODIFICATION,
            address=0x10000000,
            size=100
        )
        
        data_change = MemoryChange(
            change_type=ChangeType.DATA_CHANGE,
            address=0x20000000,
            size=50
        )
        
        self.assertTrue(code_change.is_code_change)
        self.assertFalse(code_change.is_data_change)
        
        self.assertFalse(data_change.is_code_change)
        self.assertTrue(data_change.is_data_change)


class TestSnapshotMetadata(unittest.TestCase):
    """Test cases for SnapshotMetadata class."""
    
    def test_snapshot_metadata_creation(self):
        """Test snapshot metadata creation."""
        metadata = SnapshotMetadata(
            name="test_snapshot",
            timestamp=time.time(),
            qemu_version="6.2.0",
            architecture="x86_64",
            memory_size=1024*1024*1024,
            snapshot_path=Path("/tmp/test.qcow2"),
            compression=CompressionType.GZIP
        )
        
        self.assertEqual(metadata.name, "test_snapshot")
        self.assertEqual(metadata.qemu_version, "6.2.0")
        self.assertEqual(metadata.architecture, "x86_64")
        self.assertEqual(metadata.compression, CompressionType.GZIP)
    
    def test_to_dict_serialization(self):
        """Test metadata serialization to dictionary."""
        region = MemoryRegion(
            start_addr=0x10000000,
            end_addr=0x10001000,
            size=0x1000,
            permissions="rwx",
            mapping_type="heap"
        )
        
        metadata = SnapshotMetadata(
            name="test_snapshot",
            timestamp=1234567890.0,
            qemu_version="6.2.0",
            architecture="x86_64",
            memory_size=1024*1024*1024,
            snapshot_path=Path("/tmp/test.qcow2"),
            compression=CompressionType.GZIP,
            memory_regions=[region]
        )
        
        data_dict = metadata.to_dict()
        
        self.assertEqual(data_dict['name'], "test_snapshot")
        self.assertEqual(data_dict['timestamp'], 1234567890.0)
        self.assertEqual(data_dict['compression'], 'gzip')
        self.assertEqual(len(data_dict['memory_regions']), 1)
        self.assertEqual(data_dict['memory_regions'][0]['start_addr'], '0x10000000')


class TestMemoryDiffEngine(unittest.TestCase):
    """Test cases for MemoryDiffEngine class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.diff_engine = MemoryDiffEngine(max_workers=2, chunk_size=4096)
    
    def tearDown(self):
        """Clean up test fixtures."""
        self.diff_engine.shutdown()
    
    def test_diff_engine_initialization(self):
        """Test diff engine initialization."""
        self.assertEqual(self.diff_engine.max_workers, 2)
        self.assertEqual(self.diff_engine.chunk_size, 4096)
        self.assertIsNotNone(self.diff_engine.executor)
    
    def test_new_region_detection(self):
        """Test detection of new memory regions."""
        region1 = MemoryRegion(
            start_addr=0x10000000,
            end_addr=0x10001000,
            size=0x1000,
            permissions="rwx",
            mapping_type="heap"
        )
        
        region2 = MemoryRegion(
            start_addr=0x20000000,
            end_addr=0x20001000,
            size=0x1000,
            permissions="rwx",
            mapping_type="stack"
        )
        
        regions1 = [region1]
        regions2 = [region1, region2]
        
        changes = self.diff_engine.diff_memory_regions(regions1, regions2)
        
        new_region_changes = [c for c in changes if c.change_type == ChangeType.NEW_REGION]
        self.assertEqual(len(new_region_changes), 1)
        self.assertEqual(new_region_changes[0].address, 0x20000000)
    
    def test_removed_region_detection(self):
        """Test detection of removed memory regions."""
        region1 = MemoryRegion(
            start_addr=0x10000000,
            end_addr=0x10001000,
            size=0x1000,
            permissions="rwx",
            mapping_type="heap"
        )
        
        region2 = MemoryRegion(
            start_addr=0x20000000,
            end_addr=0x20001000,
            size=0x1000,
            permissions="rwx",
            mapping_type="stack"
        )
        
        regions1 = [region1, region2]
        regions2 = [region1]
        
        changes = self.diff_engine.diff_memory_regions(regions1, regions2)
        
        removed_region_changes = [c for c in changes if c.change_type == ChangeType.REMOVED_REGION]
        self.assertEqual(len(removed_region_changes), 1)
        self.assertEqual(removed_region_changes[0].address, 0x20000000)
    
    def test_modified_region_detection(self):
        """Test detection of modified memory regions."""
        region1 = MemoryRegion(
            start_addr=0x10000000,
            end_addr=0x10001000,
            size=0x1000,
            permissions="rwx",
            mapping_type="heap",
            data_hash="hash1",
            data_chunk_hashes=["chunk1", "chunk2"]
        )
        
        region2 = MemoryRegion(
            start_addr=0x10000000,
            end_addr=0x10001000,
            size=0x1000,
            permissions="rwx",
            mapping_type="heap",
            data_hash="hash2",
            data_chunk_hashes=["chunk1", "chunk3"]  # Second chunk modified
        )
        
        regions1 = [region1]
        regions2 = [region2]
        
        changes = self.diff_engine.diff_memory_regions(regions1, regions2)
        
        # Should detect chunk-level changes
        self.assertTrue(len(changes) > 0)


if __name__ == '__main__':
    unittest.main()