"""
QEMU Snapshot Diffing System for Runtime Behavior Analysis.

This module provides comprehensive snapshot management and diffing capabilities
for tracking runtime behavior changes during dynamic analysis in QEMU environments.

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
import gzip
import hashlib
import json
import mmap
import os
import struct
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from intellicrack.logger import logger


class ChangeType(Enum):
    """Types of memory changes detected in snapshots."""
    CODE_MODIFICATION = "code_modification"
    DATA_CHANGE = "data_change"
    HEAP_ALLOCATION = "heap_allocation"
    HEAP_DEALLOCATION = "heap_deallocation"
    STACK_CHANGE = "stack_change"
    PROTECTION_CHANGE = "protection_change"
    NEW_REGION = "new_region"
    REMOVED_REGION = "removed_region"


class CompressionType(Enum):
    """Compression types for snapshot storage."""
    NONE = "none"
    GZIP = "gzip"
    ZLIB = "zlib"
    LZ4 = "lz4"


@dataclass
class MemoryRegion:
    """Represents a memory region in a snapshot."""
    start_addr: int
    end_addr: int
    size: int
    permissions: str
    mapping_type: str
    file_path: Optional[str] = None
    data_hash: Optional[str] = None
    data_chunk_hashes: List[str] = field(default_factory=list)
    
    @property
    def page_count(self) -> int:
        """Number of memory pages in this region."""
        return (self.size + 4095) // 4096
    
    def contains_address(self, addr: int) -> bool:
        """Check if an address falls within this region."""
        return self.start_addr <= addr < self.end_addr


@dataclass
class MemoryChange:
    """Represents a change detected between snapshots."""
    change_type: ChangeType
    address: int
    size: int
    old_data: Optional[bytes] = None
    new_data: Optional[bytes] = None
    region_info: Optional[MemoryRegion] = None
    timestamp: float = field(default_factory=time.time)
    confidence: float = 1.0
    description: str = ""
    
    @property
    def is_code_change(self) -> bool:
        """Check if this is a code modification."""
        return self.change_type == ChangeType.CODE_MODIFICATION
    
    @property
    def is_data_change(self) -> bool:
        """Check if this is a data modification."""
        return self.change_type == ChangeType.DATA_CHANGE


@dataclass
class SnapshotMetadata:
    """Metadata for a QEMU snapshot."""
    name: str
    timestamp: float
    qemu_version: str
    architecture: str
    memory_size: int
    snapshot_path: Path
    compression: CompressionType
    annotations: Dict[str, Any] = field(default_factory=dict)
    memory_regions: List[MemoryRegion] = field(default_factory=list)
    process_list: List[Dict[str, Any]] = field(default_factory=list)
    file_handles: List[Dict[str, Any]] = field(default_factory=list)
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    checksum: Optional[str] = None
    size_bytes: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary for serialization."""
        return {
            'name': self.name,
            'timestamp': self.timestamp,
            'qemu_version': self.qemu_version,
            'architecture': self.architecture,
            'memory_size': self.memory_size,
            'snapshot_path': str(self.snapshot_path),
            'compression': self.compression.value,
            'annotations': self.annotations,
            'memory_regions': [
                {
                    'start_addr': hex(r.start_addr),
                    'end_addr': hex(r.end_addr),
                    'size': r.size,
                    'permissions': r.permissions,
                    'mapping_type': r.mapping_type,
                    'file_path': r.file_path,
                    'data_hash': r.data_hash,
                    'data_chunk_hashes': r.data_chunk_hashes
                }
                for r in self.memory_regions
            ],
            'process_list': self.process_list,
            'file_handles': self.file_handles,
            'network_connections': self.network_connections,
            'checksum': self.checksum,
            'size_bytes': self.size_bytes
        }


class QMPClient:
    """Simplified QMP (QEMU Machine Protocol) client for snapshot operations."""
    
    def __init__(self, socket_path: str):
        """Initialize QMP client with socket path."""
        self.socket_path = socket_path
        self.socket = None
        self.reader = None
        self.writer = None
        self.capabilities_negotiated = False
        
    async def connect(self) -> bool:
        """Connect to QMP socket and negotiate capabilities."""
        try:
            self.reader, self.writer = await asyncio.open_unix_connection(self.socket_path)
            
            greeting = await self.reader.readline()
            greeting_data = json.loads(greeting.decode())
            
            if 'QMP' not in greeting_data:
                logger.error("Invalid QMP greeting received")
                return False
            
            capabilities_cmd = json.dumps({"execute": "qmp_capabilities"}) + "\n"
            self.writer.write(capabilities_cmd.encode())
            await self.writer.drain()
            
            response = await self.reader.readline()
            response_data = json.loads(response.decode())
            
            if response_data.get('return') == {}:
                self.capabilities_negotiated = True
                logger.info("QMP capabilities negotiated successfully")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to connect to QMP: {e}")
            return False
    
    async def execute_command(self, command: str, arguments: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Execute a QMP command and return the response."""
        if not self.capabilities_negotiated:
            logger.error("QMP capabilities not negotiated")
            return None
        
        try:
            cmd_data = {"execute": command}
            if arguments:
                cmd_data["arguments"] = arguments
            
            cmd_json = json.dumps(cmd_data) + "\n"
            self.writer.write(cmd_json.encode())
            await self.writer.drain()
            
            response = await self.reader.readline()
            return json.loads(response.decode())
            
        except Exception as e:
            logger.error(f"QMP command execution failed: {e}")
            return None
    
    async def disconnect(self):
        """Disconnect from QMP socket."""
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
        self.capabilities_negotiated = False


class MemoryDiffEngine:
    """High-performance memory diffing engine with multi-threading support."""
    
    def __init__(self, max_workers: int = 4, chunk_size: int = 4096):
        """Initialize memory diff engine."""
        self.max_workers = max_workers
        self.chunk_size = chunk_size
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
    def diff_memory_regions(self, regions1: List[MemoryRegion], regions2: List[MemoryRegion]) -> List[MemoryChange]:
        """Compare memory regions between two snapshots."""
        changes = []
        
        # Create address mappings for efficient lookup
        addr_map1 = {r.start_addr: r for r in regions1}
        addr_map2 = {r.start_addr: r for r in regions2}
        
        # Find new regions
        for addr, region in addr_map2.items():
            if addr not in addr_map1:
                changes.append(MemoryChange(
                    change_type=ChangeType.NEW_REGION,
                    address=region.start_addr,
                    size=region.size,
                    region_info=region,
                    description=f"New memory region: {region.mapping_type}"
                ))
        
        # Find removed regions
        for addr, region in addr_map1.items():
            if addr not in addr_map2:
                changes.append(MemoryChange(
                    change_type=ChangeType.REMOVED_REGION,
                    address=region.start_addr,
                    size=region.size,
                    region_info=region,
                    description=f"Removed memory region: {region.mapping_type}"
                ))
        
        # Find modified regions
        common_addrs = set(addr_map1.keys()) & set(addr_map2.keys())
        futures = []
        
        for addr in common_addrs:
            region1 = addr_map1[addr]
            region2 = addr_map2[addr]
            
            if region1.data_hash != region2.data_hash:
                future = self.executor.submit(
                    self._diff_region_content,
                    region1, region2
                )
                futures.append(future)
        
        # Collect results from futures
        for future in as_completed(futures):
            try:
                region_changes = future.result()
                changes.extend(region_changes)
            except Exception as e:
                logger.error(f"Error in region diff: {e}")
        
        return changes
    
    def _diff_region_content(self, region1: MemoryRegion, region2: MemoryRegion) -> List[MemoryChange]:
        """Compare content of two memory regions using chunk-level diffing."""
        changes = []
        
        # Use chunk hashes for efficient comparison
        if len(region1.data_chunk_hashes) != len(region2.data_chunk_hashes):
            changes.append(MemoryChange(
                change_type=ChangeType.DATA_CHANGE,
                address=region1.start_addr,
                size=region1.size,
                region_info=region1,
                description="Region size changed"
            ))
            return changes
        
        # Compare chunk hashes
        for i, (hash1, hash2) in enumerate(zip(region1.data_chunk_hashes, region2.data_chunk_hashes)):
            if hash1 != hash2:
                chunk_addr = region1.start_addr + (i * self.chunk_size)
                
                # Determine change type based on region type
                if 'x' in region1.permissions:  # Executable
                    change_type = ChangeType.CODE_MODIFICATION
                elif 'heap' in region1.mapping_type.lower():
                    change_type = ChangeType.HEAP_ALLOCATION
                elif 'stack' in region1.mapping_type.lower():
                    change_type = ChangeType.STACK_CHANGE
                else:
                    change_type = ChangeType.DATA_CHANGE
                
                changes.append(MemoryChange(
                    change_type=change_type,
                    address=chunk_addr,
                    size=min(self.chunk_size, region1.end_addr - chunk_addr),
                    region_info=region1,
                    description=f"Chunk {i} modified in {region1.mapping_type}"
                ))
        
        return changes
    
    def shutdown(self):
        """Shutdown the thread pool executor."""
        self.executor.shutdown(wait=True)


class QEMUSnapshotDiffer:
    """
    Comprehensive QEMU snapshot diffing system for runtime behavior analysis.
    
    Provides advanced snapshot management, memory diffing, and behavior analysis
    capabilities for security research and vulnerability assessment.
    """
    
    def __init__(self, qemu_emulator, storage_path: str = None, max_snapshots: int = 50):
        """
        Initialize the QEMU snapshot differ.
        
        Args:
            qemu_emulator: QEMUSystemEmulator instance
            storage_path: Path to store snapshots and metadata
            max_snapshots: Maximum number of snapshots to retain
        """
        self.qemu_emulator = qemu_emulator
        self.storage_path = Path(storage_path or "snapshots")
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.max_snapshots = max_snapshots
        
        # Initialize components
        self.diff_engine = MemoryDiffEngine()
        self.qmp_client = None
        
        # Snapshot tracking
        self.snapshots: Dict[str, SnapshotMetadata] = {}
        self.snapshot_index = 0
        
        # Analysis state
        self.baseline_snapshot: Optional[str] = None
        self.behavior_patterns: Dict[str, List[MemoryChange]] = {}
        
        # Performance optimization
        self.memory_map_cache: Dict[str, List[MemoryRegion]] = {}
        self.chunk_cache: Dict[str, Dict[str, str]] = {}
        
        # Load existing snapshots
        self._load_existing_snapshots()
        
        logger.info(f"QEMUSnapshotDiffer initialized with storage at {self.storage_path}")
    
    async def initialize_qmp(self) -> bool:
        """Initialize QMP connection for advanced snapshot operations."""
        if not hasattr(self.qemu_emulator, 'monitor_socket') or not self.qemu_emulator.monitor_socket:
            logger.warning("QMP socket not available, using fallback methods")
            return False
        
        qmp_socket = self.qemu_emulator.monitor_socket.replace('monitor', 'qmp')
        if not os.path.exists(qmp_socket):
            qmp_socket = self.qemu_emulator.monitor_socket
        
        self.qmp_client = QMPClient(qmp_socket)
        connected = await self.qmp_client.connect()
        
        if connected:
            logger.info("QMP connection established successfully")
        else:
            logger.warning("Failed to establish QMP connection")
        
        return connected
    
    async def create_snapshot(self, name: str, annotations: Optional[Dict[str, Any]] = None) -> bool:
        """
        Create a comprehensive snapshot with memory state and metadata.
        
        Args:
            name: Unique snapshot name
            annotations: Additional metadata annotations
            
        Returns:
            True if snapshot created successfully
        """
        if name in self.snapshots:
            logger.error(f"Snapshot {name} already exists")
            return False
        
        try:
            logger.info(f"Creating snapshot: {name}")
            start_time = time.time()
            
            # Create QEMU snapshot via QMP if available
            if self.qmp_client:
                qmp_result = await self.qmp_client.execute_command(
                    "savevm", {"tag": name}
                )
                if not qmp_result or 'error' in qmp_result:
                    logger.error(f"QMP snapshot creation failed: {qmp_result}")
                    return False
            else:
                # Fallback to monitor command
                result = self.qemu_emulator._send_monitor_command(f'savevm {name}')
                if not result or 'Error' in result:
                    logger.error(f"Monitor snapshot creation failed: {result}")
                    return False
            
            # Capture memory state and metadata
            metadata = await self._capture_snapshot_metadata(name, annotations)
            
            # Store metadata
            metadata_path = self.storage_path / f"{name}.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata.to_dict(), f, indent=2)
            
            self.snapshots[name] = metadata
            
            # Cleanup old snapshots if needed
            await self._cleanup_old_snapshots()
            
            duration = time.time() - start_time
            logger.info(f"Snapshot {name} created successfully in {duration:.2f}s")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to create snapshot {name}: {e}")
            return False
    
    async def restore_snapshot(self, name: str) -> bool:
        """
        Restore a snapshot to return system to previous state.
        
        Args:
            name: Snapshot name to restore
            
        Returns:
            True if snapshot restored successfully
        """
        if name not in self.snapshots:
            logger.error(f"Snapshot {name} not found")
            return False
        
        try:
            logger.info(f"Restoring snapshot: {name}")
            
            # Restore QEMU snapshot via QMP if available
            if self.qmp_client:
                qmp_result = await self.qmp_client.execute_command(
                    "loadvm", {"tag": name}
                )
                if not qmp_result or 'error' in qmp_result:
                    logger.error(f"QMP snapshot restore failed: {qmp_result}")
                    return False
            else:
                # Fallback to monitor command
                result = self.qemu_emulator._send_monitor_command(f'loadvm {name}')
                if not result or 'Error' in result:
                    logger.error(f"Monitor snapshot restore failed: {result}")
                    return False
            
            logger.info(f"Snapshot {name} restored successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore snapshot {name}: {e}")
            return False
    
    async def delete_snapshot(self, name: str) -> bool:
        """
        Delete a snapshot and its associated data.
        
        Args:
            name: Snapshot name to delete
            
        Returns:
            True if snapshot deleted successfully
        """
        if name not in self.snapshots:
            logger.error(f"Snapshot {name} not found")
            return False
        
        try:
            logger.info(f"Deleting snapshot: {name}")
            
            # Delete QEMU snapshot via QMP if available
            if self.qmp_client:
                qmp_result = await self.qmp_client.execute_command(
                    "delvm", {"tag": name}
                )
                if qmp_result and 'error' in qmp_result:
                    logger.warning(f"QMP snapshot deletion warning: {qmp_result}")
            else:
                # Fallback to monitor command
                result = self.qemu_emulator._send_monitor_command(f'delvm {name}')
                if result and 'Error' in result:
                    logger.warning(f"Monitor snapshot deletion warning: {result}")
            
            # Remove metadata file
            metadata_path = self.storage_path / f"{name}.json"
            if metadata_path.exists():
                metadata_path.unlink()
            
            # Remove from tracking
            del self.snapshots[name]
            
            # Clear caches
            if name in self.memory_map_cache:
                del self.memory_map_cache[name]
            if name in self.chunk_cache:
                del self.chunk_cache[name]
            
            logger.info(f"Snapshot {name} deleted successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete snapshot {name}: {e}")
            return False
    
    async def diff_snapshots(self, snapshot1: str, snapshot2: str) -> Dict[str, Any]:
        """
        Perform comprehensive diff between two snapshots.
        
        Args:
            snapshot1: First snapshot name (baseline)
            snapshot2: Second snapshot name (comparison)
            
        Returns:
            Dictionary containing detailed diff results
        """
        if snapshot1 not in self.snapshots or snapshot2 not in self.snapshots:
            return {"error": "One or both snapshots not found"}
        
        try:
            logger.info(f"Diffing snapshots: {snapshot1} -> {snapshot2}")
            start_time = time.time()
            
            meta1 = self.snapshots[snapshot1]
            meta2 = self.snapshots[snapshot2]
            
            # Memory region analysis
            memory_changes = self.diff_engine.diff_memory_regions(
                meta1.memory_regions, meta2.memory_regions
            )
            
            # Process analysis
            process_changes = self._analyze_process_changes(
                meta1.process_list, meta2.process_list
            )
            
            # Network analysis
            network_changes = self._analyze_network_changes(
                meta1.network_connections, meta2.network_connections
            )
            
            # File handle analysis
            file_changes = self._analyze_file_handle_changes(
                meta1.file_handles, meta2.file_handles
            )
            
            # Behavior pattern detection
            patterns = self._detect_behavior_patterns(memory_changes)
            
            # License detection analysis
            license_analysis = self._analyze_license_indicators(
                memory_changes, process_changes, network_changes, file_changes
            )
            
            diff_result = {
                "snapshot1": snapshot1,
                "snapshot2": snapshot2,
                "timestamp1": meta1.timestamp,
                "timestamp2": meta2.timestamp,
                "duration": meta2.timestamp - meta1.timestamp,
                "memory_changes": {
                    "total_changes": len(memory_changes),
                    "by_type": self._categorize_changes(memory_changes),
                    "changes": [self._serialize_change(c) for c in memory_changes[:100]]  # Limit output
                },
                "process_changes": process_changes,
                "network_changes": network_changes,
                "file_changes": file_changes,
                "behavior_patterns": patterns,
                "license_analysis": license_analysis,
                "statistics": {
                    "regions_added": len([c for c in memory_changes if c.change_type == ChangeType.NEW_REGION]),
                    "regions_removed": len([c for c in memory_changes if c.change_type == ChangeType.REMOVED_REGION]),
                    "code_modifications": len([c for c in memory_changes if c.change_type == ChangeType.CODE_MODIFICATION]),
                    "heap_changes": len([c for c in memory_changes if c.change_type in [ChangeType.HEAP_ALLOCATION, ChangeType.HEAP_DEALLOCATION]]),
                    "diff_duration": time.time() - start_time
                }
            }
            
            logger.info(f"Snapshot diff completed in {diff_result['statistics']['diff_duration']:.2f}s")
            return diff_result
            
        except Exception as e:
            logger.error(f"Failed to diff snapshots {snapshot1} -> {snapshot2}: {e}")
            return {"error": str(e)}
    
    async def _capture_snapshot_metadata(self, name: str, annotations: Optional[Dict[str, Any]]) -> SnapshotMetadata:
        """Capture comprehensive metadata for a snapshot."""
        metadata = SnapshotMetadata(
            name=name,
            timestamp=time.time(),
            qemu_version="unknown",
            architecture=self.qemu_emulator.architecture,
            memory_size=self.qemu_emulator.config.get('memory_mb', 1024) * 1024 * 1024,
            snapshot_path=self.storage_path / f"{name}.qcow2",
            compression=CompressionType.GZIP,
            annotations=annotations or {}
        )
        
        # Capture memory regions
        metadata.memory_regions = await self._capture_memory_regions()
        
        # Capture process list
        metadata.process_list = await self._capture_process_list()
        
        # Capture file handles
        metadata.file_handles = await self._capture_file_handles()
        
        # Capture network connections
        metadata.network_connections = await self._capture_network_connections()
        
        return metadata
    
    async def _capture_memory_regions(self) -> List[MemoryRegion]:
        """Capture current memory regions using QMP info commands."""
        regions = []
        
        try:
            if self.qmp_client:
                # Get memory info via QMP
                mem_info = await self.qmp_client.execute_command("info", {"item": "mtree"})
                if mem_info and 'return' in mem_info:
                    regions = self._parse_memory_tree(mem_info['return'])
            else:
                # Fallback to monitor command
                mem_info = self.qemu_emulator._send_monitor_command('info mtree')
                if mem_info:
                    regions = self._parse_memory_tree_text(mem_info)
            
            # Generate hashes for regions
            for region in regions:
                await self._generate_region_hashes(region)
            
        except Exception as e:
            logger.error(f"Failed to capture memory regions: {e}")
        
        return regions
    
    def _parse_memory_tree_text(self, mem_tree_output: str) -> List[MemoryRegion]:
        """Parse memory tree output from text format."""
        regions = []
        
        for line in mem_tree_output.split('\n'):
            line = line.strip()
            if not line or not ('-' in line and '0x' in line):
                continue
            
            try:
                # Parse format: "0x00000000-0x7fffffff (size 0x80000000): system"
                addr_part, desc_part = line.split(': ', 1)
                addr_range, size_part = addr_part.split(' (size ', 1)
                
                start_str, end_str = addr_range.split('-')
                start_addr = int(start_str, 16)
                end_addr = int(end_str, 16)
                
                size_str = size_part.rstrip(')')
                size = int(size_str, 16)
                
                region = MemoryRegion(
                    start_addr=start_addr,
                    end_addr=end_addr,
                    size=size,
                    permissions="rwx",  # Default, would need more detailed parsing
                    mapping_type=desc_part.strip(),
                    file_path=None
                )
                
                regions.append(region)
                
            except (ValueError, IndexError) as e:
                logger.debug(f"Failed to parse memory tree line '{line}': {e}")
                continue
        
        return regions
    
    def _parse_memory_tree(self, mem_tree_data: Any) -> List[MemoryRegion]:
        """Parse memory tree data from QMP response."""
        regions = []
        
        if isinstance(mem_tree_data, dict):
            # Handle different QMP response formats
            if 'memory' in mem_tree_data:
                memory_data = mem_tree_data['memory']
            else:
                memory_data = mem_tree_data
            
            # Parse memory regions from structured data
            for region_data in memory_data.get('regions', []):
                try:
                    region = MemoryRegion(
                        start_addr=region_data.get('start', 0),
                        end_addr=region_data.get('end', 0),
                        size=region_data.get('size', 0),
                        permissions=region_data.get('permissions', 'rwx'),
                        mapping_type=region_data.get('type', 'unknown'),
                        file_path=region_data.get('file')
                    )
                    regions.append(region)
                except Exception as e:
                    logger.debug(f"Failed to parse memory region data: {e}")
        
        return regions
    
    async def _generate_region_hashes(self, region: MemoryRegion):
        """Generate content hashes for memory region."""
        try:
            # For now, generate placeholder hashes based on region properties
            # In a full implementation, this would read actual memory content
            region_str = f"{region.start_addr:x}-{region.end_addr:x}-{region.mapping_type}"
            region.data_hash = hashlib.sha256(region_str.encode()).hexdigest()
            
            # Generate chunk hashes
            chunk_count = region.page_count
            for i in range(chunk_count):
                chunk_str = f"{region_str}-chunk-{i}"
                chunk_hash = hashlib.sha256(chunk_str.encode()).hexdigest()
                region.data_chunk_hashes.append(chunk_hash)
                
        except Exception as e:
            logger.error(f"Failed to generate region hashes: {e}")
    
    async def _capture_process_list(self) -> List[Dict[str, Any]]:
        """Capture current process list from guest system."""
        processes = []
        
        try:
            if hasattr(self.qemu_emulator, '_get_guest_processes'):
                processes = self.qemu_emulator._get_guest_processes()
            
        except Exception as e:
            logger.error(f"Failed to capture process list: {e}")
        
        return processes
    
    async def _capture_file_handles(self) -> List[Dict[str, Any]]:
        """Capture open file handles from guest system."""
        file_handles = []
        
        try:
            # Implementation would use guest agent or SSH to get file handle info
            # For now, return empty list as placeholder
            pass
            
        except Exception as e:
            logger.error(f"Failed to capture file handles: {e}")
        
        return file_handles
    
    async def _capture_network_connections(self) -> List[Dict[str, Any]]:
        """Capture network connections from guest system."""
        connections = []
        
        try:
            if hasattr(self.qemu_emulator, '_get_guest_network_connections'):
                connections = self.qemu_emulator._get_guest_network_connections()
            
        except Exception as e:
            logger.error(f"Failed to capture network connections: {e}")
        
        return connections
    
    def _analyze_process_changes(self, processes1: List[Dict[str, Any]], processes2: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze changes in process list between snapshots."""
        pid_map1 = {p.get('pid'): p for p in processes1}
        pid_map2 = {p.get('pid'): p for p in processes2}
        
        new_processes = []
        terminated_processes = []
        
        # Find new processes
        for pid, proc in pid_map2.items():
            if pid not in pid_map1:
                new_processes.append(proc)
        
        # Find terminated processes
        for pid, proc in pid_map1.items():
            if pid not in pid_map2:
                terminated_processes.append(proc)
        
        return {
            "new_processes": new_processes,
            "terminated_processes": terminated_processes,
            "total_processes_before": len(processes1),
            "total_processes_after": len(processes2)
        }
    
    def _analyze_network_changes(self, connections1: List[Dict[str, Any]], connections2: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze changes in network connections between snapshots."""
        conn_ids1 = {self._connection_id(c) for c in connections1}
        conn_ids2 = {self._connection_id(c) for c in connections2}
        
        new_connections = [c for c in connections2 if self._connection_id(c) not in conn_ids1]
        closed_connections = [c for c in connections1 if self._connection_id(c) not in conn_ids2]
        
        return {
            "new_connections": new_connections,
            "closed_connections": closed_connections,
            "total_connections_before": len(connections1),
            "total_connections_after": len(connections2)
        }
    
    def _analyze_file_handle_changes(self, handles1: List[Dict[str, Any]], handles2: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze changes in file handles between snapshots."""
        # Simple comparison for now
        return {
            "handles_opened": len(handles2) - len(handles1),
            "total_handles_before": len(handles1),
            "total_handles_after": len(handles2)
        }
    
    def _connection_id(self, conn: Dict[str, Any]) -> str:
        """Generate unique identifier for network connection."""
        return f"{conn.get('src_ip', '')}:{conn.get('src_port', 0)}-{conn.get('dst_ip', '')}:{conn.get('dst_port', 0)}"
    
    def _detect_behavior_patterns(self, changes: List[MemoryChange]) -> Dict[str, Any]:
        """Detect behavioral patterns from memory changes."""
        patterns = {
            "self_modifying_code": False,
            "heap_spray": False,
            "stack_overflow": False,
            "code_injection": False,
            "unpacking_activity": False
        }
        
        # Detect self-modifying code
        code_mods = [c for c in changes if c.change_type == ChangeType.CODE_MODIFICATION]
        if len(code_mods) > 5:
            patterns["self_modifying_code"] = True
        
        # Detect heap spray
        heap_allocs = [c for c in changes if c.change_type == ChangeType.HEAP_ALLOCATION]
        if len(heap_allocs) > 50:
            patterns["heap_spray"] = True
        
        # Detect potential unpacking
        if code_mods and heap_allocs:
            patterns["unpacking_activity"] = True
        
        return patterns
    
    def _analyze_license_indicators(self, memory_changes: List[MemoryChange], 
                                   process_changes: Dict[str, Any],
                                   network_changes: Dict[str, Any],
                                   file_changes: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze changes for license-related activity indicators."""
        indicators = {
            "license_check_detected": False,
            "network_validation": False,
            "protection_circumvention": False,
            "confidence_score": 0.0,
            "evidence": []
        }
        
        # Check for license-related processes
        for proc in process_changes.get("new_processes", []):
            proc_name = proc.get('name', '').lower()
            if any(term in proc_name for term in ['license', 'activation', 'validation']):
                indicators["license_check_detected"] = True
                indicators["evidence"].append(f"License process started: {proc_name}")
        
        # Check for network validation attempts
        for conn in network_changes.get("new_connections", []):
            if conn.get('dst_port') in [80, 443, 27000, 1947]:
                indicators["network_validation"] = True
                indicators["evidence"].append(f"Network validation attempt: {conn.get('dst_ip')}:{conn.get('dst_port')}")
        
        # Check for code modifications (potential protection bypass)
        code_changes = [c for c in memory_changes if c.change_type == ChangeType.CODE_MODIFICATION]
        if len(code_changes) > 3:
            indicators["protection_circumvention"] = True
            indicators["evidence"].append(f"Multiple code modifications: {len(code_changes)} changes")
        
        # Calculate confidence score
        score = 0.0
        if indicators["license_check_detected"]:
            score += 0.4
        if indicators["network_validation"]:
            score += 0.3
        if indicators["protection_circumvention"]:
            score += 0.3
        
        indicators["confidence_score"] = min(score, 1.0)
        
        return indicators
    
    def _categorize_changes(self, changes: List[MemoryChange]) -> Dict[str, int]:
        """Categorize memory changes by type."""
        categories = {}
        for change in changes:
            change_type = change.change_type.value
            categories[change_type] = categories.get(change_type, 0) + 1
        return categories
    
    def _serialize_change(self, change: MemoryChange) -> Dict[str, Any]:
        """Serialize memory change for JSON output."""
        return {
            "type": change.change_type.value,
            "address": hex(change.address),
            "size": change.size,
            "timestamp": change.timestamp,
            "confidence": change.confidence,
            "description": change.description,
            "region_type": change.region_info.mapping_type if change.region_info else None
        }
    
    def _load_existing_snapshots(self):
        """Load existing snapshot metadata from storage."""
        try:
            for metadata_file in self.storage_path.glob("*.json"):
                with open(metadata_file, 'r') as f:
                    data = json.load(f)
                
                # Convert back to SnapshotMetadata object
                metadata = SnapshotMetadata(
                    name=data['name'],
                    timestamp=data['timestamp'],
                    qemu_version=data['qemu_version'],
                    architecture=data['architecture'],
                    memory_size=data['memory_size'],
                    snapshot_path=Path(data['snapshot_path']),
                    compression=CompressionType(data['compression']),
                    annotations=data.get('annotations', {}),
                    checksum=data.get('checksum'),
                    size_bytes=data.get('size_bytes', 0)
                )
                
                # Convert memory regions
                for region_data in data.get('memory_regions', []):
                    region = MemoryRegion(
                        start_addr=int(region_data['start_addr'], 16),
                        end_addr=int(region_data['end_addr'], 16),
                        size=region_data['size'],
                        permissions=region_data['permissions'],
                        mapping_type=region_data['mapping_type'],
                        file_path=region_data.get('file_path'),
                        data_hash=region_data.get('data_hash'),
                        data_chunk_hashes=region_data.get('data_chunk_hashes', [])
                    )
                    metadata.memory_regions.append(region)
                
                # Set other attributes
                metadata.process_list = data.get('process_list', [])
                metadata.file_handles = data.get('file_handles', [])
                metadata.network_connections = data.get('network_connections', [])
                
                self.snapshots[metadata.name] = metadata
                
            logger.info(f"Loaded {len(self.snapshots)} existing snapshots")
            
        except Exception as e:
            logger.error(f"Failed to load existing snapshots: {e}")
    
    async def _cleanup_old_snapshots(self):
        """Remove old snapshots if limit exceeded."""
        if len(self.snapshots) <= self.max_snapshots:
            return
        
        # Sort by timestamp and remove oldest
        sorted_snapshots = sorted(self.snapshots.items(), key=lambda x: x[1].timestamp)
        to_remove = sorted_snapshots[:-self.max_snapshots]
        
        for name, _ in to_remove:
            await self.delete_snapshot(name)
            logger.info(f"Removed old snapshot: {name}")
    
    def list_snapshots(self) -> List[Dict[str, Any]]:
        """Get list of available snapshots with metadata."""
        snapshots_list = []
        for name, metadata in self.snapshots.items():
            snapshots_list.append({
                "name": name,
                "timestamp": metadata.timestamp,
                "architecture": metadata.architecture,
                "memory_size": metadata.memory_size,
                "size_bytes": metadata.size_bytes,
                "annotations": metadata.annotations
            })
        
        return sorted(snapshots_list, key=lambda x: x['timestamp'], reverse=True)
    
    def get_snapshot_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific snapshot."""
        if name not in self.snapshots:
            return None
        
        metadata = self.snapshots[name]
        return metadata.to_dict()
    
    async def set_baseline(self, snapshot_name: str) -> bool:
        """Set a snapshot as the baseline for future comparisons."""
        if snapshot_name not in self.snapshots:
            logger.error(f"Snapshot {snapshot_name} not found")
            return False
        
        self.baseline_snapshot = snapshot_name
        logger.info(f"Set baseline snapshot: {snapshot_name}")
        return True
    
    async def analyze_since_baseline(self, current_snapshot: str) -> Optional[Dict[str, Any]]:
        """Analyze changes since the baseline snapshot."""
        if not self.baseline_snapshot:
            logger.error("No baseline snapshot set")
            return None
        
        return await self.diff_snapshots(self.baseline_snapshot, current_snapshot)
    
    async def monitor_realtime_changes(self, interval: float = 1.0, duration: float = 60.0) -> List[Dict[str, Any]]:
        """
        Monitor real-time changes by taking periodic snapshots.
        
        Args:
            interval: Time between snapshots in seconds
            duration: Total monitoring duration in seconds
            
        Returns:
            List of change analyses between consecutive snapshots
        """
        changes_timeline = []
        snapshot_count = int(duration / interval)
        
        logger.info(f"Starting real-time monitoring for {duration}s with {interval}s intervals")
        
        # Create initial snapshot
        initial_name = f"monitor_start_{int(time.time())}"
        if not await self.create_snapshot(initial_name):
            logger.error("Failed to create initial monitoring snapshot")
            return changes_timeline
        
        previous_snapshot = initial_name
        
        for i in range(snapshot_count):
            await asyncio.sleep(interval)
            
            current_name = f"monitor_{int(time.time())}_{i}"
            if await self.create_snapshot(current_name):
                # Analyze changes since previous snapshot
                diff_result = await self.diff_snapshots(previous_snapshot, current_name)
                if diff_result and 'error' not in diff_result:
                    changes_timeline.append({
                        "interval": i,
                        "timestamp": time.time(),
                        "snapshot_name": current_name,
                        "changes": diff_result
                    })
                
                # Cleanup previous snapshot to save space
                if i > 0:  # Keep the first snapshot
                    await self.delete_snapshot(previous_snapshot)
                
                previous_snapshot = current_name
            else:
                logger.warning(f"Failed to create monitoring snapshot {current_name}")
        
        # Cleanup final snapshot
        await self.delete_snapshot(previous_snapshot)
        
        logger.info(f"Real-time monitoring completed with {len(changes_timeline)} intervals")
        return changes_timeline
    
    async def export_analysis_report(self, snapshot1: str, snapshot2: str, output_path: str) -> bool:
        """
        Export comprehensive analysis report to file.
        
        Args:
            snapshot1: First snapshot name
            snapshot2: Second snapshot name
            output_path: Path for output report file
            
        Returns:
            True if report exported successfully
        """
        try:
            diff_result = await self.diff_snapshots(snapshot1, snapshot2)
            if 'error' in diff_result:
                logger.error(f"Cannot export report due to diff error: {diff_result['error']}")
                return False
            
            # Add additional analysis context
            report = {
                "report_metadata": {
                    "generated_at": time.time(),
                    "generator": "QEMUSnapshotDiffer",
                    "version": "1.0",
                    "architecture": self.qemu_emulator.architecture
                },
                "snapshot_analysis": diff_result,
                "recommendations": self._generate_recommendations(diff_result)
            }
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Analysis report exported to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export analysis report: {e}")
            return False
    
    def _generate_recommendations(self, diff_result: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis results."""
        recommendations = []
        
        license_analysis = diff_result.get('license_analysis', {})
        if license_analysis.get('confidence_score', 0) > 0.7:
            recommendations.append("High confidence license activity detected - review protection mechanisms")
        
        memory_stats = diff_result.get('statistics', {})
        if memory_stats.get('code_modifications', 0) > 10:
            recommendations.append("Extensive code modifications detected - investigate for potential exploitation")
        
        patterns = diff_result.get('behavior_patterns', {})
        if patterns.get('self_modifying_code'):
            recommendations.append("Self-modifying code detected - analyze for unpacking or obfuscation")
        
        if patterns.get('heap_spray'):
            recommendations.append("Potential heap spray detected - investigate for exploitation attempts")
        
        return recommendations
    
    async def cleanup(self):
        """Cleanup resources and connections."""
        try:
            # Shutdown diff engine
            self.diff_engine.shutdown()
            
            # Disconnect QMP client
            if self.qmp_client:
                await self.qmp_client.disconnect()
            
            logger.info("QEMUSnapshotDiffer cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


# Convenience functions for integration
async def create_snapshot_differ(qemu_emulator, storage_path: str = None) -> QEMUSnapshotDiffer:
    """
    Create and initialize a QEMUSnapshotDiffer instance.
    
    Args:
        qemu_emulator: QEMUSystemEmulator instance
        storage_path: Path to store snapshots
        
    Returns:
        Initialized QEMUSnapshotDiffer instance
    """
    differ = QEMUSnapshotDiffer(qemu_emulator, storage_path)
    await differ.initialize_qmp()
    return differ


async def quick_behavior_analysis(qemu_emulator, before_action_name: str = "before", 
                                 after_action_name: str = "after") -> Dict[str, Any]:
    """
    Perform quick before/after behavior analysis.
    
    Args:
        qemu_emulator: QEMUSystemEmulator instance
        before_action_name: Name for before snapshot
        after_action_name: Name for after snapshot
        
    Returns:
        Analysis results
    """
    differ = await create_snapshot_differ(qemu_emulator)
    
    # Create before snapshot
    if not await differ.create_snapshot(before_action_name):
        return {"error": "Failed to create before snapshot"}
    
    # User performs action here (externally)
    logger.info("Take action now, then call this function again to create after snapshot")
    
    # This would be called separately after the action
    if not await differ.create_snapshot(after_action_name):
        return {"error": "Failed to create after snapshot"}
    
    # Analyze differences
    result = await differ.diff_snapshots(before_action_name, after_action_name)
    
    # Cleanup
    await differ.cleanup()
    
    return result


__all__ = [
    'QEMUSnapshotDiffer',
    'MemoryChange',
    'MemoryRegion', 
    'SnapshotMetadata',
    'ChangeType',
    'CompressionType',
    'create_snapshot_differ',
    'quick_behavior_analysis'
]