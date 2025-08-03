"""
Common Snapshot Utilities.

Shared functionality for snapshot operations across different platforms.
This module eliminates duplicate code and provides consistent error handling.

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

import time
from typing import Any, Dict, Tuple


def start_snapshot_comparison(snapshots: Dict[str, Dict[str, Any]], 
                            snapshot1: str, snapshot2: str, 
                            logger) -> Tuple[bool, Dict[str, Any], str]:
    """
    Initialize snapshot comparison with validation and error handling.
    
    Args:
        snapshots: Dictionary of available snapshots
        snapshot1: First snapshot name
        snapshot2: Second snapshot name
        logger: Logger instance for error reporting
        
    Returns:
        Tuple of (success, snapshot_data, error_message)
    """
    try:
        # Validate snapshot existence
        if snapshot1 not in snapshots:
            error_msg = f"Snapshot '{snapshot1}' not found"
            logger.error(error_msg)
            return False, {}, error_msg
        
        if snapshot2 not in snapshots:
            error_msg = f"Snapshot '{snapshot2}' not found"
            logger.error(error_msg)
            return False, {}, error_msg
        
        # Get snapshot data
        s1 = snapshots[snapshot1]
        s2 = snapshots[snapshot2]
        
        # Validate snapshot data structure
        if not isinstance(s1, dict) or not isinstance(s2, dict):
            error_msg = "Invalid snapshot data structure"
            logger.error(error_msg)
            return False, {}, error_msg
        
        # Prepare snapshot data for comparison
        snapshot_data = {
            "s1": s1,
            "s2": s2,
            "comparison_start_time": time.time()
        }
        
        logger.info(f"Starting snapshot comparison: {snapshot1} -> {snapshot2}")
        return True, snapshot_data, ""
        
    except Exception as e:
        error_msg = f"Failed to initialize snapshot comparison: {str(e)}"
        logger.error(error_msg)
        return False, {}, error_msg


def validate_snapshot_metadata(snapshot_data: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate snapshot metadata structure.
    
    Args:
        snapshot_data: Snapshot metadata dictionary
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    required_fields = ['timestamp', 'name']
    
    for field in required_fields:
        if field not in snapshot_data:
            return False, f"Missing required field: {field}"
    
    # Validate field types
    if not isinstance(snapshot_data['timestamp'], (int, float)):
        return False, "Invalid timestamp format"
    
    if not isinstance(snapshot_data['name'], str):
        return False, "Invalid name format"
    
    return True, ""


def calculate_change_statistics(changes: list) -> Dict[str, Any]:
    """
    Calculate statistics for a list of changes.
    
    Args:
        changes: List of change objects
        
    Returns:
        Dictionary containing change statistics
    """
    stats = {
        "total_changes": len(changes),
        "change_types": {},
        "affected_regions": set(),
        "total_bytes_changed": 0
    }
    
    for change in changes:
        # Count change types
        change_type = getattr(change, 'change_type', 'unknown')
        if hasattr(change_type, 'value'):
            change_type = change_type.value
        
        stats["change_types"][change_type] = stats["change_types"].get(change_type, 0) + 1
        
        # Track affected regions
        if hasattr(change, 'region_info') and change.region_info:
            region_id = f"{change.region_info.start_addr:x}-{change.region_info.end_addr:x}"
            stats["affected_regions"].add(region_id)
        
        # Sum bytes changed
        if hasattr(change, 'size') and change.size:
            stats["total_bytes_changed"] += change.size
    
    # Convert set to count
    stats["affected_regions"] = len(stats["affected_regions"])
    
    return stats


def format_memory_address(address: int) -> str:
    """
    Format memory address for display.
    
    Args:
        address: Memory address as integer
        
    Returns:
        Formatted address string
    """
    return f"0x{address:08x}"


def format_memory_size(size_bytes: int) -> str:
    """
    Format memory size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def generate_change_summary(changes: list) -> str:
    """
    Generate human-readable summary of changes.
    
    Args:
        changes: List of change objects
        
    Returns:
        Summary string
    """
    if not changes:
        return "No changes detected"
    
    stats = calculate_change_statistics(changes)
    
    summary_parts = [
        f"Total changes: {stats['total_changes']}",
        f"Affected regions: {stats['affected_regions']}",
        f"Total bytes changed: {format_memory_size(stats['total_bytes_changed'])}"
    ]
    
    # Add change type breakdown
    if stats['change_types']:
        type_breakdown = []
        for change_type, count in stats['change_types'].items():
            type_breakdown.append(f"{change_type}: {count}")
        
        summary_parts.append("Changes by type: " + ", ".join(type_breakdown))
    
    return " | ".join(summary_parts)


def extract_license_indicators(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract license-related indicators from analysis results.
    
    Args:
        analysis_result: Analysis result dictionary
        
    Returns:
        Dictionary of license indicators
    """
    indicators = {
        "license_files_accessed": [],
        "license_processes": [],
        "license_network_activity": [],
        "license_registry_changes": [],
        "confidence_score": 0.0
    }
    
    # Extract from different analysis sections
    if 'filesystem_changes' in analysis_result:
        fs_changes = analysis_result['filesystem_changes']
        for file_path in fs_changes.get('files_created', []) + fs_changes.get('files_modified', []):
            if isinstance(file_path, dict):
                file_path = file_path.get('path', '')
            
            if any(keyword in file_path.lower() for keyword in ['license', 'activation', 'serial', 'key']):
                indicators["license_files_accessed"].append(file_path)
    
    if 'process_changes' in analysis_result:
        process_changes = analysis_result['process_changes']
        for process in process_changes.get('processes_started', []):
            process_name = process.get('name', '').lower()
            if any(keyword in process_name for keyword in ['license', 'activation', 'validation']):
                indicators["license_processes"].append(process)
    
    if 'network_changes' in analysis_result:
        network_changes = analysis_result['network_changes']
        for connection in network_changes.get('new_connections', []):
            # Check for license server ports
            dst_port = connection.get('dst_port', 0)
            if dst_port in [27000, 27001, 1947, 7777]:  # Common license server ports
                indicators["license_network_activity"].append(connection)
    
    # Calculate confidence score
    score = 0.0
    if indicators["license_files_accessed"]:
        score += min(len(indicators["license_files_accessed"]) * 0.2, 0.4)
    if indicators["license_processes"]:
        score += min(len(indicators["license_processes"]) * 0.3, 0.5)
    if indicators["license_network_activity"]:
        score += min(len(indicators["license_network_activity"]) * 0.2, 0.3)
    
    indicators["confidence_score"] = min(score, 1.0)
    
    return indicators


def merge_analysis_results(results_list: list) -> Dict[str, Any]:
    """
    Merge multiple analysis results into a combined result.
    
    Args:
        results_list: List of analysis result dictionaries
        
    Returns:
        Merged analysis result
    """
    if not results_list:
        return {}
    
    if len(results_list) == 1:
        return results_list[0]
    
    merged = {
        "merged_analysis": True,
        "source_count": len(results_list),
        "merge_timestamp": time.time(),
        "combined_changes": [],
        "combined_statistics": {},
        "highest_confidence_score": 0.0
    }
    
    # Combine changes from all results
    total_changes = 0
    all_change_types = {}
    
    for result in results_list:
        if 'memory_changes' in result:
            memory_changes = result['memory_changes']
            if isinstance(memory_changes, dict) and 'changes' in memory_changes:
                merged["combined_changes"].extend(memory_changes['changes'])
                total_changes += memory_changes.get('total_changes', 0)
                
                # Merge change type counts
                by_type = memory_changes.get('by_type', {})
                for change_type, count in by_type.items():
                    all_change_types[change_type] = all_change_types.get(change_type, 0) + count
        
        # Track highest confidence score
        license_analysis = result.get('license_analysis', {})
        confidence = license_analysis.get('confidence_score', 0.0)
        merged["highest_confidence_score"] = max(merged["highest_confidence_score"], confidence)
    
    merged["combined_statistics"] = {
        "total_changes": total_changes,
        "change_types": all_change_types,
        "results_merged": len(results_list)
    }
    
    return merged


__all__ = [
    'start_snapshot_comparison',
    'validate_snapshot_metadata',
    'calculate_change_statistics',
    'format_memory_address',
    'format_memory_size',
    'generate_change_summary',
    'extract_license_indicators',
    'merge_analysis_results'
]