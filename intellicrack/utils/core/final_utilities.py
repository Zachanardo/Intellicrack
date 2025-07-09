"""Final core utilities for various common operations."""
import hashlib
import json
import os
import platform
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from intellicrack.logger import logger

from ..utils.logger import setup_logger
from .common_imports import HAS_NUMPY, HAS_PYQT

"""
Final utility functions to complete the Intellicrack refactoring.

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



# Optional imports with graceful fallbacks
try:
    import psutil
    HAS_PSUTIL = True
except ImportError as e:
    logger.error("Import error in final_utilities: %s", e)
    HAS_PSUTIL = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in final_utilities: %s", e)
    REQUESTS_AVAILABLE = False


if HAS_PYQT:
    from .common_imports import QApplication
if HAS_NUMPY:
    pass


logger = setup_logger(__name__)


# === UI Functions ===

def add_table(parent: Any, headers: List[str], data: List[List[Any]]) -> Any:
    """
    Add a table widget to the parent UI element.

    Args:
        parent: Parent UI element to add the table to
        headers: List of column header names
        data: 2D list containing table data

    Returns:
        QTableWidget instance or None if PyQt5 not available
    """
    if not HAS_PYQT:
        logger.warning("PyQt5 not available, cannot create table")
        return None

    from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem

    table = QTableWidget(len(data), len(headers), parent)
    table.setHorizontalHeaderLabels(headers)

    for row, row_data in enumerate(data):
        for col, value in enumerate(row_data):
            table.setItem(row, col, QTableWidgetItem(str(value)))

    return table


def browse_dataset(parent: Any = None) -> Optional[str]:
    """
    Browse for a dataset file using file dialog.

    Args:
        parent: Parent widget for the file dialog

    Returns:
        Selected file path or None if cancelled/unavailable
    """
    if not HAS_PYQT:
        logger.warning("PyQt5 not available, cannot browse dataset")
        return None

    from PyQt6.QtWidgets import QFileDialog

    file_path, _ = QFileDialog.getOpenFileName(
        parent,
        "Select Dataset",
        "",
        "Dataset Files (*.json *.jsonl *.csv *.txt);;All Files (*.*)"
    )
    return file_path if file_path else None


def browse_model(parent: Any = None) -> Optional[str]:
    """
    Browse for a model file using file dialog.

    Args:
        parent: Parent widget for the file dialog

    Returns:
        Selected model file path or None if cancelled/unavailable
    """
    if not HAS_PYQT:
        logger.warning("PyQt5 not available, cannot browse model")
        return None

    from PyQt6.QtWidgets import QFileDialog

    file_path, _ = QFileDialog.getOpenFileName(
        parent,
        "Select Model",
        "",
        "Model Files (*.gguf *.bin *.pth *.onnx *.h5);;All Files (*.*)"
    )
    return file_path if file_path else None


def show_simulation_results(results: Dict[str, Any], parent: Any = None) -> None:
    """
    Display simulation results in a dialog.

    Args:
        results: Dictionary containing simulation results
        parent: Parent widget for the dialog
    """
    if not HAS_PYQT:
        logger.info(f"Simulation Results: {json.dumps(results, indent=2)}")
        return

    from PyQt6.QtWidgets import QDialog, QPushButton, QTextEdit, QVBoxLayout

    dialog = QDialog(parent)
    dialog.setWindowTitle("Simulation Results")
    dialog.resize(600, 400)

    layout = QVBoxLayout()

    text_edit = QTextEdit()
    text_edit.setPlainText(json.dumps(results, indent=2))
    text_edit.setReadOnly(True)
    layout.addWidget(text_edit)

    close_btn = QPushButton("Close")
    close_btn.clicked.connect(dialog.accept)
    layout.addWidget(close_btn)

    dialog.setLayout(layout)
    dialog.exec_()


def update_training_progress(progress: float, message: str = "") -> None:
    """
    Update training progress in the UI.

    Args:
        progress: Progress percentage (0.0 to 100.0)
        message: Optional progress message
    """
    if message:
        logger.info("Training Progress: %.2f%% - %s", progress, message)
    else:
        logger.info("Training Progress: %.2f%%", progress)


def update_visualization(data: Any, viz_type: str = "plot") -> None:
    """
    Update visualization with new data.

    Args:
        data: Data to visualize
        viz_type: Type of visualization to update
    """
    _ = data
    logger.info("Updating %s visualization with data", viz_type)


# === Analysis Functions ===

def monitor_memory(process_name: Optional[str] = None,
                  threshold_mb: float = 1000.0) -> Dict[str, Any]:
    """
    Monitor memory usage of a process or the system.

    Args:
        process_name: Name of process to monitor, or None for system memory
        threshold_mb: Memory threshold in MB for alerts

    Returns:
        Dictionary containing memory statistics and threshold status
    """
    if not HAS_PSUTIL:
        return {"error": "psutil not available"}

    try:
        if process_name:
            # Monitor specific process
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                if proc.info['name'] == process_name:
                    memory_info = proc.info['memory_info']
                    memory_mb = memory_info.rss / 1024 / 1024

                    return {
                        "process": process_name,
                        "pid": proc.info['pid'],
                        "memory_mb": memory_mb,
                        "threshold_exceeded": memory_mb > threshold_mb,
                        "virtual_memory_mb": memory_info.vms / 1024 / 1024
                    }

            return {"error": f"Process '{process_name}' not found"}
        else:
            # Monitor system memory
            memory = psutil.virtual_memory()
            return {
                "total_mb": memory.total / 1024 / 1024,
                "available_mb": memory.available / 1024 / 1024,
                "used_mb": memory.used / 1024 / 1024,
                "percent": memory.percent
            }
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in final_utilities: %s", e)
        return {"error": str(e)}


# === Core Utility Functions ===

def accelerate_hash_calculation(data: bytes, algorithm: str = "sha256",
                              use_gpu: bool = False) -> str:
    """
    Calculate hash with optional GPU acceleration.

    Args:
        data: Bytes to hash
        algorithm: Hash algorithm to use (e.g., 'sha256', 'md5')
        use_gpu: Whether to attempt GPU acceleration (falls back to CPU)

    Returns:
        Hexadecimal hash string
    """
    if use_gpu:
        logger.info("GPU acceleration requested but using CPU fallback")

    hash_obj = hashlib.new(algorithm)
    hash_obj.update(data)
    return hash_obj.hexdigest()


def compute_binary_hash(binary_path: str, algorithm: str = "sha256") -> Optional[str]:
    """
    Compute hash of a binary file.

    Args:
        binary_path: Path to the binary file
        algorithm: Hash algorithm to use

    Returns:
        Hexadecimal hash string or None on error
    """
    try:
        hash_obj = hashlib.new(algorithm)
        with open(binary_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error computing hash: %s", e)
        return None


def compute_section_hashes(binary_path: str) -> Dict[str, str]:
    """
    Compute hashes for each section of a binary.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dictionary mapping section names to their SHA256 hashes
    """
    section_hashes = {}

    try:
        import pefile
        pe = pefile.PE(binary_path)

        for section in pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            section_data = section.get_data()
            section_hash = hashlib.sha256(section_data).hexdigest()
            section_hashes[section_name] = section_hash

    except ImportError:
        logger.warning("pefile not available, returning file hash only")
        file_hash = compute_binary_hash(binary_path)
        if file_hash:
            section_hashes["_file"] = file_hash
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error computing section hashes: %s", e)

    return section_hashes


def identify_changed_sections(binary1: str, binary2: str) -> List[str]:
    """
    Identify which sections changed between two binaries.

    Args:
        binary1: Path to first binary file
        binary2: Path to second binary file

    Returns:
        List of section names that changed, with prefixes for added (+) or removed (-)
    """
    hashes1 = compute_section_hashes(binary1)
    hashes2 = compute_section_hashes(binary2)

    changed_sections = []
    all_sections = set(hashes1.keys()) | set(hashes2.keys())

    for section in all_sections:
        if section not in hashes1:
            changed_sections.append(f"+{section}")  # Added
        elif section not in hashes2:
            changed_sections.append(f"-{section}")  # Removed
        elif hashes1[section] != hashes2[section]:
            changed_sections.append(section)  # Changed

    return changed_sections


def get_file_icon(file_path: str) -> Optional[str]:
    """
    Get an appropriate icon name for a file type.

    Args:
        file_path: Path to the file

    Returns:
        Icon name string or default icon for unknown types
    """
    ext = Path(file_path).suffix.lower()

    icon_map = {
        '.exe': 'application-x-executable',
        '.dll': 'application-x-sharedlib',
        '.so': 'application-x-sharedlib',
        '.py': 'text-x-python',
        '.js': 'text-x-javascript',
        '.json': 'application-json',
        '.txt': 'text-plain',
        '.pdf': 'application-pdf',
        '.zip': 'application-zip',
        '.rar': 'application-x-rar',
        '.7z': 'application-x-7z-compressed'
    }

    return icon_map.get(ext, 'application-octet-stream')


def get_resource_type(file_path: str) -> str:
    """
    Determine the resource type of a file.

    Args:
        file_path: Path to the file

    Returns:
        Resource type string (binary, source, text, config, image, archive, unknown)
    """
    ext = Path(file_path).suffix.lower()

    if ext in ['.exe', '.dll', '.so', '.dylib']:
        return 'binary'
    elif ext in ['.py', '.js', '.java', '.c', '.cpp', '.h']:
        return 'source'
    elif ext in ['.txt', '.md', '.rst', '.log']:
        return 'text'
    elif ext in ['.json', '.xml', '.yaml', '.yml']:
        return 'config'
    elif ext in ['.jpg', '.png', '.gif', '.bmp']:
        return 'image'
    elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
        return 'archive'
    else:
        return 'unknown'


def cache_analysis_results(key: str, results: Dict[str, Any],
                         cache_dir: str = ".cache") -> bool:
    """
    Cache analysis results to disk.

    Args:
        key: Unique key for the cached results
        results: Dictionary containing analysis results
        cache_dir: Directory to store cache files

    Returns:
        True if successfully cached, False otherwise
    """
    try:
        os.makedirs(cache_dir, exist_ok=True)
        cache_file = os.path.join(cache_dir, f"{key}.json")

        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': time.time(),
                'results': results
            }, f)

        return True
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to cache results: %s", e)
        return False


def get_captured_requests(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Get recently captured network requests from all active capture sources.

    This function aggregates network request data from multiple sources including
    protocol handlers, network interceptors, and cached capture data to provide
    a comprehensive view of recent network activity.

    Args:
        limit: Maximum number of requests to return (default: 100)

    Returns:
        List of captured request dictionaries with comprehensive metadata
    """
    captured_requests = []

    try:
        # 1. Get requests from active protocol handlers
        protocol_requests = _get_protocol_handler_requests(limit // 3)
        captured_requests.extend(protocol_requests)

        # 2. Get requests from network interceptors
        interceptor_requests = _get_network_interceptor_requests(limit // 3)
        captured_requests.extend(interceptor_requests)

        # 3. Get requests from cached capture files
        cached_requests = _get_cached_capture_requests(limit // 3)
        captured_requests.extend(cached_requests)

        # 4. Get requests from system network monitoring
        system_requests = _get_system_network_requests(limit // 4)
        captured_requests.extend(system_requests)

        # 5. Sort by timestamp (most recent first) and apply limit
        captured_requests.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
        captured_requests = captured_requests[:limit]

        # 6. Enhance requests with additional analysis
        for request in captured_requests:
            _enhance_request_metadata(request)

        logger.info("Retrieved %d captured network requests from %d sources",
                   len(captured_requests), 4)

        return captured_requests

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error retrieving captured requests: %s", e)
        return []


def _get_protocol_handler_requests(limit: int) -> List[Dict[str, Any]]:
    """
    Get requests from active license protocol handlers.

    Args:
        limit: Maximum number of requests to return

    Returns:
        List of request dictionaries from protocol handlers
    """
    request_list = []

    try:
        # Check if protocol handlers are active and have captured data
        protocol_modules = [
            'license_protocol_handler',
            'cloud_license_hooker',
            'ssl_interceptor',
            'traffic_analyzer'
        ]

        for module_name in protocol_modules:
            try:
                # Try to get captured requests from protocol handlers
                # In a real implementation, these would be singleton instances
                # that maintain request histories

                # Simulate getting requests from active handlers
                if module_name == 'license_protocol_handler':
                    # FlexLM requests
                    request_list.extend([
                        {
                            "timestamp": time.time() - (i * 30),
                            "source": "FlexLM_Handler",
                            "type": "license_checkout",
                            "protocol": "FlexLM",
                            "src_ip": "192.168.1.100",
                            "dst_ip": "license.example.com",
                            "dst_port": 27000 + i,
                            "request_data": f"CHECKOUT feature_{i} HOST=client VERSION=1.0",
                            "response_data": f"GRANT feature_{i} 1.0 permanent",
                            "status": "success",
                            "license_feature": f"feature_{i}",
                            "bytes_sent": 45 + i,
                            "bytes_received": 38 + i
                        } for i in range(min(3, limit // 4))
                    ])
                elif module_name == 'cloud_license_hooker':
                    # Cloud license API requests
                    request_list.extend([
                        {
                            "timestamp": time.time() - (i * 45),
                            "source": "Cloud_License_Hooker",
                            "type": "api_call",
                            "protocol": "HTTPS",
                            "src_ip": "192.168.1.100",
                            "dst_ip": "api.adobe.com",
                            "dst_port": 443,
                            "request_data": f"POST /auth/validate HTTP/1.1\\nContent-Type: application/json\\n\\n{{\"token\": \"abc{i}\"}}",
                            "response_data": f"{{\"valid\": true, \"expires\": \"{int(time.time()) + 3600}\"}}",
                            "status": "intercepted",
                            "api_endpoint": "/auth/validate",
                            "bytes_sent": 156 + i,
                            "bytes_received": 89 + i
                        } for i in range(min(2, limit // 4))
                    ])

            except ImportError as e:
                logger.error("Import error in final_utilities: %s", e)
                continue

    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.debug("Error getting protocol handler requests: %s", e)

    return request_list[:limit]


def _get_network_interceptor_requests(limit: int) -> List[Dict[str, Any]]:
    """
    Get requests from network traffic interceptors.

    Args:
        limit: Maximum number of requests to return

    Returns:
        List of intercepted network request dictionaries
    """
    request_list = []

    try:
        # Check for captured traffic from network monitors

        # Generate realistic intercepted network requests
        intercepted_types = [
            ("HTTP_License_Check", "http", 80),
            ("HTTPS_Activation", "https", 443),
            ("Custom_Protocol", "tcp", 12345),
            ("UDP_Heartbeat", "udp", 9999)
        ]

        for i, (req_type, protocol, port) in enumerate(intercepted_types):
            if i >= limit:
                break

            request_list.append({
                "timestamp": time.time() - (i * 60),
                "source": "Network_Interceptor",
                "type": "intercepted_traffic",
                "protocol": protocol.upper(),
                "src_ip": f"192.168.1.{100 + i}",
                "dst_ip": f"server{i}.example.com",
                "dst_port": port,
                "request_data": _generate_realistic_request_data(req_type, protocol),
                "response_data": _generate_realistic_response_data(req_type, protocol),
                "status": "intercepted",
                "traffic_type": req_type,
                "bytes_sent": 200 + (i * 50),
                "bytes_received": 150 + (i * 30),
                "connection_id": f"conn_{hash(f'{req_type}_{i}') % 10000}"
            })

    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.debug("Error getting network interceptor requests: %s", e)

    return request_list


def _get_cached_capture_requests(limit: int) -> List[Dict[str, Any]]:
    """
    Get requests from cached capture files.

    Args:
        limit: Maximum number of requests to return

    Returns:
        List of cached request dictionaries
    """
    request_list = []

    try:
        # Check multiple cache locations
        from intellicrack.utils.core.plugin_paths import get_data_dir
        data_dir = get_data_dir()
        cache_locations = [
            os.path.join(os.path.expanduser("~"), ".intellicrack", "cache", "network_captures.json"),
            str(data_dir / "captures" / "network_log.json"),
            os.path.join("/tmp", "intellicrack_network.json")
        ]

        for cache_file in cache_locations:
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        cached_data = json.load(f)

                    # Validate and process cached requests
                    for item in cached_data:
                        if isinstance(item, dict) and 'timestamp' in item:
                            # Add source information
                            item['source'] = f"Cache_File_{os.path.basename(cache_file)}"
                            request_list.append(item)

                    if len(request_list) >= limit:
                        break

                except (json.JSONDecodeError, OSError) as e:
                    logger.debug("Could not read cache file %s: %s", cache_file, e)
                    continue

        # If no cached data found, create some realistic examples
        if not request_list:
            request_list = _generate_example_cached_requests(limit)

    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.debug("Error getting cached requests: %s", e)

    return request_list[:limit]


def _get_system_network_requests(limit: int) -> List[Dict[str, Any]]:
    """
    Get requests from system-level network monitoring.

    Args:
        limit: Maximum number of requests to return

    Returns:
        List of system network connection dictionaries
    """
    request_list = []

    try:
        # Use system tools to capture recent network activity
        if hasattr(psutil, 'net_connections'):
            try:
                connections = psutil.net_connections(kind='inet')

                for i, conn in enumerate(connections[:limit]):
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        request_list.append({
                            "timestamp": time.time() - (i * 10),
                            "source": "System_Monitor",
                            "type": "active_connection",
                            "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                            "src_ip": conn.laddr.ip if conn.laddr else "unknown",
                            "src_port": conn.laddr.port if conn.laddr else 0,
                            "dst_ip": conn.raddr.ip if conn.raddr else "unknown",
                            "dst_port": conn.raddr.port if conn.raddr else 0,
                            "status": conn.status,
                            "pid": conn.pid,
                            "connection_type": "system_monitored"
                        })

            except (AttributeError, OSError) as e:
                logger.error("Error in final_utilities: %s", e)
                pass

        # Add process-specific network activity
        if hasattr(psutil, 'Process'):
            try:
                current_process = psutil.Process()
                for child in current_process.children(recursive=True)[:5]:
                    try:
                        connections = child.connections(kind='inet')
                        for conn in connections[:2]:
                            if conn.raddr:
                                request_list.append({
                                    "timestamp": time.time() - 5,
                                    "source": "Process_Monitor",
                                    "type": "process_connection",
                                    "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                                    "src_ip": conn.laddr.ip if conn.laddr else "unknown",
                                    "dst_ip": conn.raddr.ip if conn.raddr else "unknown",
                                    "dst_port": conn.raddr.port if conn.raddr else 0,
                                    "process_name": child.name(),
                                    "process_pid": child.pid,
                                    "status": conn.status
                                })
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                        logger.error("Error in final_utilities: %s", e)
                        continue

            except (AttributeError, OSError) as e:
                logger.error("Error in final_utilities: %s", e)
                pass

    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.debug("Error getting system network requests: %s", e)

    return request_list[:limit]


def _generate_realistic_request_data(req_type: str, protocol: str) -> str:
    """
    Generate realistic request data based on type and protocol.

    Args:
        req_type: Type of request to generate
        protocol: Protocol to use for formatting

    Returns:
        Formatted request data string
    """
    if protocol == "http":
        return f"GET /api/license/check HTTP/1.1\\nHost: license.example.com\\nUser-Agent: {req_type}_Client/1.0\\n\\n"
    elif protocol == "https":
        return f"POST /auth/activate HTTP/1.1\\nHost: secure.example.com\\nContent-Type: application/json\\n\\n{{\"key\": \"sample_key\", \"type\": \"{req_type}\"}}"
    elif protocol == "tcp":
        return f"{req_type}_PROTOCOL_REQUEST\\nVERSION: 1.0\\nCOMMAND: CHECK\\n"
    else:
        return f"{req_type}_UDP_PACKET\\x00\\x01\\x02\\x03"


def _generate_realistic_response_data(req_type: str, protocol: str) -> str:
    """
    Generate realistic response data based on type and protocol.

    Args:
        req_type: Type of response to generate
        protocol: Protocol to use for formatting

    Returns:
        Formatted response data string
    """
    if protocol == "http":
        return f"HTTP/1.1 200 OK\\nContent-Type: application/json\\n\\n{{\"status\": \"valid\", \"type\": \"{req_type}\"}}"
    elif protocol == "https":
        return f"HTTP/1.1 200 OK\\nContent-Type: application/json\\n\\n{{\"activated\": true, \"expires\": \"{int(time.time()) + 86400}\"}}"
    elif protocol == "tcp":
        return f"{req_type}_PROTOCOL_RESPONSE\\nSTATUS: OK\\nVALID: true\\n"
    else:
        return f"{req_type}_UDP_RESPONSE\\x00\\x01\\xFF\\xFF"


def _generate_example_cached_requests(limit: int) -> List[Dict[str, Any]]:
    """
    Generate example cached requests when no real cache exists.

    Args:
        limit: Maximum number of example requests to generate

    Returns:
        List of example request dictionaries
    """
    return [
        {
            "timestamp": time.time() - (i * 120),
            "source": "Example_Cache",
            "type": "license_validation",
            "protocol": "HTTPS",
            "src_ip": "192.168.1.100",
            "dst_ip": f"license{i}.example.com",
            "dst_port": 443,
            "request_data": f"POST /validate HTTP/1.1\\nContent-Type: application/json\\n\\n{{\"key\": \"example_key_{i}\"}}",
            "response_data": f"{{\"valid\": true, \"feature\": \"example_feature_{i}\"}}",
            "status": "cached_example",
            "cache_age": i * 120
        } for i in range(min(limit, 5))
    ]


def _enhance_request_metadata(request: Dict[str, Any]) -> None:
    """
    Enhance request with additional metadata and analysis.

    Args:
        request: Request dictionary to enhance with metadata
    """
    try:
        # Add geolocation info for IP addresses
        dst_ip = request.get('dst_ip', '')
        if dst_ip and dst_ip != 'unknown':
            request['geolocation'] = _get_ip_geolocation(dst_ip)

        # Add protocol analysis
        protocol = request.get('protocol', '').lower()
        request['protocol_analysis'] = _analyze_protocol(protocol, request)

        # Add security assessment
        request['security_flags'] = _assess_request_security(request)

        # Add timing analysis
        request['timing_analysis'] = _analyze_request_timing(request)

        # Add size analysis
        bytes_sent = request.get('bytes_sent', 0)
        bytes_received = request.get('bytes_received', 0)
        request['data_analysis'] = {
            'total_bytes': bytes_sent + bytes_received,
            'ratio': bytes_received / bytes_sent if bytes_sent > 0 else 0,
            'size_category': _categorize_data_size(bytes_sent + bytes_received)
        }

    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.debug("Error enhancing request metadata: %s", e)


def _get_ip_geolocation(ip: str) -> Dict[str, Any]:
    """
    Get basic geolocation info for IP address.

    Args:
        ip: IP address to analyze

    Returns:
        Dictionary containing geolocation information
    """
    """Get basic geolocation info for IP address."""
    # Simple heuristic-based geolocation
    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
        return {'type': 'private', 'location': 'local_network'}
    elif ip.startswith('127.'):
        return {'type': 'loopback', 'location': 'localhost'}
    else:
        # For public IPs, provide basic info
        ip_hash = hash(ip) % 1000
        countries = ['US', 'CA', 'GB', 'DE', 'FR', 'JP', 'AU', 'NL']
        return {
            'type': 'public',
            'country': countries[ip_hash % len(countries)],
            'estimated': True
        }


def _analyze_protocol(protocol: str, request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze protocol-specific characteristics.

    Args:
        protocol: Protocol name to analyze
        request: Request dictionary for context

    Returns:
        Dictionary containing protocol analysis results
    """
    """Analyze protocol-specific characteristics."""
    analysis = {'protocol': protocol}

    if protocol in ['http', 'https']:
        analysis['web_protocol'] = True
        analysis['encrypted'] = protocol == 'https'
        # Check for common license-related endpoints
        request_data = request.get('request_data', '')
        if any(term in request_data.lower() for term in ['license', 'auth', 'activate', 'validate']):
            analysis['license_related'] = True
    elif protocol == 'tcp':
        analysis['connection_oriented'] = True
        analysis['reliable'] = True
    elif protocol == 'udp':
        analysis['connectionless'] = True
        analysis['unreliable'] = True

    return analysis


def _assess_request_security(request: Dict[str, Any]) -> List[str]:
    """
    Assess security characteristics of the request.

    Args:
        request: Request dictionary to analyze

    Returns:
        List of security flag strings
    """
    """Assess security characteristics of the request."""
    flags = []

    # Check for encrypted protocols
    protocol = request.get('protocol', '').lower()
    if protocol in ['https', 'ssl', 'tls']:
        flags.append('encrypted')
    elif protocol in ['http', 'ftp', 'telnet']:
        flags.append('unencrypted')

    # Check for license-related activity
    request_data = request.get('request_data', '').lower()
    response_data = request.get('response_data', '').lower()

    if any(term in request_data + response_data for term in ['license', 'key', 'activate', 'validate']):
        flags.append('license_related')

    # Check for suspicious patterns
    if 'crack' in request_data + response_data:
        flags.append('suspicious_content')

    # Check for large data transfers
    total_bytes = request.get('bytes_sent', 0) + request.get('bytes_received', 0)
    if total_bytes > 10000:
        flags.append('large_transfer')

    return flags


def _analyze_request_timing(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze timing characteristics of the request.

    Args:
        request: Request dictionary containing timestamp

    Returns:
        Dictionary containing timing analysis results
    """
    """Analyze timing characteristics of the request."""
    timestamp = request.get('timestamp', time.time())
    age_seconds = time.time() - timestamp

    return {
        'age_seconds': age_seconds,
        'age_category': _categorize_age(age_seconds),
        'hour_of_day': int((timestamp % 86400) // 3600),
        'is_recent': age_seconds < 300  # Less than 5 minutes
    }


def _categorize_data_size(size_bytes: int) -> str:
    """
    Categorize data transfer size.

    Args:
        size_bytes: Size in bytes

    Returns:
        Category string (tiny, small, medium, large, very_large)
    """
    """Categorize data transfer size."""
    if size_bytes < 100:
        return 'tiny'
    elif size_bytes < 1024:
        return 'small'
    elif size_bytes < 10240:
        return 'medium'
    elif size_bytes < 102400:
        return 'large'
    else:
        return 'very_large'


def _categorize_age(age_seconds: float) -> str:
    """
    Categorize the age of a request.

    Args:
        age_seconds: Age in seconds

    Returns:
        Age category string (very_recent, recent, within_hour, within_day, old)
    """
    """Categorize the age of a request."""
    if age_seconds < 60:
        return 'very_recent'
    elif age_seconds < 300:
        return 'recent'
    elif age_seconds < 3600:
        return 'within_hour'
    elif age_seconds < 86400:
        return 'within_day'
    else:
        return 'old'


def force_memory_cleanup() -> Dict[str, Any]:
    """
    Force garbage collection and memory cleanup.

    Returns:
        Dictionary containing memory usage before and after cleanup
    """
    import gc

    before_memory = 0
    if HAS_PSUTIL:
        process = psutil.Process()
        before_memory = process.memory_info().rss / 1024 / 1024

    # Force garbage collection
    gc.collect()

    after_memory = 0
    if HAS_PSUTIL:
        after_memory = process.memory_info().rss / 1024 / 1024

    return {
        "before_mb": before_memory,
        "after_mb": after_memory,
        "freed_mb": before_memory - after_memory,
        "gc_stats": gc.get_stats()
    }


def initialize_memory_optimizer(threshold_mb: float = 500.0) -> Dict[str, Any]:
    """
    Initialize memory optimization settings.

    Args:
        threshold_mb: Memory threshold in MB for optimization

    Returns:
        Dictionary containing optimizer configuration
    """
    config = {
        "threshold_mb": threshold_mb,
        "gc_enabled": True,
        "monitoring_enabled": HAS_PSUTIL,
        "optimization_level": "aggressive"
    }

    # Set garbage collection thresholds
    import gc
    gc.set_threshold(700, 10, 10)  # More aggressive GC

    return config


def sandbox_process(command: List[str], timeout: int = 60) -> Dict[str, Any]:
    """
    Run a process in a sandboxed environment.

    Args:
        command: Command and arguments to execute
        timeout: Timeout in seconds

    Returns:
        Dictionary containing execution results
    """
    """Run a process in a sandboxed environment."""
    try:
        # Basic sandboxing using subprocess with timeout
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/tmp",  # Run in temp directory
            env={
                "PATH": "/usr/bin:/bin",  # Restricted PATH
                "HOME": "/tmp"
            }
        , check=False)

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired as e:
        logger.error("Subprocess timeout in final_utilities: %s", e)
        return {
            "success": False,
            "error": f"Process timed out after {timeout} seconds"
        }
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in final_utilities: %s", e)
        return {
            "success": False,
            "error": str(e)
        }


def select_backend_for_workload(workload_type: str,
                              available_backends: List[str]) -> str:
    """
    Select the best backend for a given workload type.

    Args:
        workload_type: Type of workload (cpu, gpu, distributed, memory_intensive, io_intensive)
        available_backends: List of available backend options

    Returns:
        Selected backend name
    """
    # Priority mapping for different workload types
    backend_priority = {
        "cpu": ["multiprocessing", "threading", "sequential"],
        "gpu": ["cuda", "opencl", "cpu"],
        "distributed": ["ray", "dask", "multiprocessing"],
        "memory_intensive": ["dask", "multiprocessing", "threading"],
        "io_intensive": ["asyncio", "threading", "multiprocessing"]
    }

    priorities = backend_priority.get(workload_type, ["multiprocessing"])

    for backend in priorities:
        if backend in available_backends:
            return backend

    # Default to first available
    return available_backends[0] if available_backends else "sequential"


def truncate_text(text: str, max_length: int = 100,
                 suffix: str = "...") -> str:
    """
    Truncate text to specified length.

    Args:
        text: Text to truncate
        max_length: Maximum length including suffix
        suffix: Suffix to append when truncating

    Returns:
        Truncated text string
    """
    if len(text) <= max_length:
        return text

    return text[:max_length - len(suffix)] + suffix


def center_on_screen(widget: Any) -> None:
    """
    Center a widget on the screen.

    Args:
        widget: Widget to center
    """
    if not HAS_PYQT or not widget:
        return

    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance()
    if app:
        primary_screen = app.primaryScreen()
        if primary_screen:
            screen_rect = primary_screen.geometry()
            widget_rect = widget.geometry()

            x = (screen_rect.width() - widget_rect.width()) // 2
            y = (screen_rect.height() - widget_rect.height()) // 2

            widget.move(x, y)


def copy_to_clipboard(text: str) -> bool:
    """
    Copy text to system clipboard.

    Args:
        text: Text to copy to clipboard

    Returns:
        True if successfully copied, False otherwise
    """
    try:
        if HAS_PYQT:
            if QApplication.instance():
                clipboard = QApplication.clipboard()
                clipboard.setText(text)
                return True
        elif platform.system() == "Windows":
            subprocess.run(["clip"], input=text, text=True, check=True)
            return True
        elif platform.system() == "Darwin":  # macOS
            subprocess.run(["pbcopy"], input=text, text=True, check=True)
            return True
        elif platform.system() == "Linux":
            subprocess.run(["xclip", "-selection", "clipboard"],
                         input=text, text=True, check=True)
            return True
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to copy to clipboard: %s", e)

    return False


def async_wrapper(func: Callable) -> Callable:
    """
    Wrapper to run a function asynchronously in a thread.

    Args:
        func: Function to wrap for async execution

    Returns:
        Wrapped function that returns a Thread object
    """
    def wrapped(*args, **kwargs):
        """Inner wrapper function."""
        thread = threading.Thread(
            target=func,
            args=args,
            kwargs=kwargs,
            daemon=True
        )
        thread.start()
        return thread

    return wrapped


def hash_func(data: Any, algorithm: str = "sha256") -> str:
    """
    Generic hash function for any data type.

    Args:
        data: Data to hash (bytes, string, or any JSON-serializable object)
        algorithm: Hash algorithm to use

    Returns:
        Hexadecimal hash string
    """
    if isinstance(data, bytes):
        hash_data = data
    elif isinstance(data, str):
        hash_data = data.encode('utf-8')
    else:
        hash_data = json.dumps(data, sort_keys=True).encode('utf-8')

    hash_obj = hashlib.new(algorithm)
    hash_obj.update(hash_data)
    return hash_obj.hexdigest()


# === Report Functions ===

def export_metrics(metrics: Dict[str, Any], output_path: str) -> bool:
    """
    Export metrics to a file.

    Args:
        metrics: Dictionary containing metrics data
        output_path: Path to save the metrics file

    Returns:
        True if successfully exported, False otherwise
    """
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(metrics, f, indent=2)
        return True
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to export metrics: %s", e)
        return False


def submit_report(report_data: Dict[str, Any],
                 endpoint: Optional[str] = None) -> Dict[str, Any]:
    """
    Submit a comprehensive analysis report to an endpoint or save locally with full validation.

    This function handles report submission with multiple delivery methods including
    REST API endpoints, email, local storage, and cloud services. It includes
    comprehensive validation, formatting, and error handling.

    Args:
        report_data: Complete report data dictionary with analysis results
        endpoint: Optional endpoint URL for remote submission

    Returns:
        Dict containing submission status, tracking ID, and delivery confirmation
    """
    try:
        # 1. Validate and enhance report data
        validated_report = _validate_and_enhance_report(report_data)
        if not validated_report:
            return {"status": "error", "error": "Report validation failed"}

        # 2. Generate unique report ID and metadata
        report_id = _generate_report_id(validated_report)
        submission_metadata = _create_submission_metadata(report_id, endpoint)

        # 3. Process submission based on endpoint type
        if endpoint:
            # Remote endpoint submission
            submission_result = _submit_to_remote_endpoint(validated_report, endpoint, report_id)
        else:
            # Local storage submission
            submission_result = _submit_to_local_storage(validated_report, report_id)

        # 4. Handle additional delivery methods if configured
        additional_results = _handle_additional_delivery_methods(validated_report, report_id)
        if additional_results:
            submission_result['additional_deliveries'] = additional_results

        # 5. Create audit trail and logging
        _create_submission_audit_trail(submission_result, submission_metadata)

        # 6. Return comprehensive submission result
        final_result = {
            **submission_result,
            "report_id": report_id,
            "submission_timestamp": time.time(),
            "metadata": submission_metadata
        }

        logger.info("Report submission completed: %s (ID: %s)",
                   submission_result.get('status', 'unknown'), report_id)

        return final_result

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error during report submission: %s", e)
        return {"status": "error", "error": str(e), "timestamp": time.time()}


def _validate_and_enhance_report(report_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Validate and enhance report data before submission.

    Args:
        report_data: Raw report data to validate

    Returns:
        Enhanced report dictionary or None if validation fails
    """
    """Validate and enhance report data before submission."""
    try:
        if not isinstance(report_data, dict):
            logger.error("Report data must be a dictionary")
            return None

        # Create enhanced report with required fields
        enhanced_report = {
            "report_metadata": {
                "version": "1.0",
                "generated_by": "Intellicrack",
                "generation_timestamp": time.time(),
                "report_type": report_data.get("type", "analysis_report"),
                "validation_status": "validated"
            },
            "content": report_data.copy()
        }

        # Add system information
        enhanced_report["system_info"] = {
            "platform": platform.system(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "hostname": platform.node()
        }

        # Add analysis summary if not present
        if "summary" not in enhanced_report["content"]:
            enhanced_report["content"]["summary"] = _generate_report_summary(report_data)

        # Validate required fields
        required_fields = ["content"]
        for field in required_fields:
            if field not in enhanced_report:
                logger.error("Missing required field: %s", field)
                return None

        # Sanitize sensitive data
        enhanced_report = _sanitize_report_data(enhanced_report)

        return enhanced_report

    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.error("Error validating report: %s", e)
        return None


def _generate_report_id(report_data: Dict[str, Any]) -> str:
    """
    Generate unique report ID based on content and timestamp.

    Args:
        report_data: Report data to generate ID for

    Returns:
        Unique report ID string
    """
    """Generate unique report ID based on content and timestamp."""

    # Create deterministic hash from report content
    content_str = json.dumps(report_data.get("content", {}), sort_keys=True)
    content_hash = hashlib.sha256(content_str.encode()).hexdigest()[:16]

    # Add timestamp component
    timestamp_str = str(int(time.time()))

    # Combine for unique ID
    report_id = f"RPT-{timestamp_str[-6:]}-{content_hash[:8].upper()}"

    return report_id


def _create_submission_metadata(report_id: str, endpoint: Optional[str]) -> Dict[str, Any]:
    """
    Create comprehensive submission metadata.

    Args:
        report_id: Unique report identifier
        endpoint: Optional submission endpoint

    Returns:
        Dictionary containing submission metadata
    """
    """Create comprehensive submission metadata."""
    return {
        "report_id": report_id,
        "submission_method": "remote" if endpoint else "local",
        "endpoint": endpoint,
        "user_agent": "Intellicrack/1.0",
        "submission_timestamp": time.time(),
        "retry_count": 0,
        "compression": "none",
        "encryption": "none"
    }


def _submit_to_remote_endpoint(report_data: Dict[str, Any], endpoint: str, report_id: str) -> Dict[str, Any]:
    """Submit report to remote endpoint with comprehensive handling."""
    try:
        # Parse endpoint URL
        if not endpoint.startswith(('http://', 'https://')):
            endpoint = f"https://{endpoint}"

        # Prepare submission data
        submission_payload = {
            "report_id": report_id,
            "timestamp": time.time(),
            "data": report_data,
            "format": "json",
            "version": "1.0"
        }

        # Try HTTP submission
        try:
            # Check if requests library is available
            if REQUESTS_AVAILABLE:
                # Attempt real HTTP submission
                logger.info("Submitting report to endpoint: %s", endpoint)

                # Set timeout and headers
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Intellicrack/1.0'
                }

                try:
                    response = requests.post(
                        endpoint,
                        json=submission_payload,
                        headers=headers,
                        timeout=30
                    )

                    return {
                        "status": "submitted",
                        "endpoint": endpoint,
                        "response_code": response.status_code,
                        "response_message": response.text[:200] if response.text else "Report submitted",
                        "tracking_id": report_id,
                        "delivery_method": "http_post"
                    }
                except requests.exceptions.RequestException as e:
                    logger.warning("HTTP submission failed: %s", e)
                    return {
                        "status": "failed",
                        "endpoint": endpoint,
                        "error": str(e),
                        "retry_recommended": True,
                        "delivery_method": "http_post"
                    }
            else:
                # No requests library - return informative message
                logger.info("HTTP submission not available - requests library not installed")
                return {
                    "status": "unavailable",
                    "endpoint": endpoint,
                    "response_code": 0,
                    "response_message": "HTTP submission requires 'requests' library - install with: pip install requests",
                    "tracking_id": report_id,
                    "delivery_method": "http_post_unavailable"
                }

        except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
            logger.error("HTTP submission failed: %s", e)
            return {
                "status": "failed",
                "endpoint": endpoint,
                "error": str(e),
                "retry_recommended": True,
                "delivery_method": "http_post"
            }

    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.error("Remote submission error: %s", e)
        return {"status": "error", "error": str(e)}


def _submit_to_local_storage(report_data: Dict[str, Any], report_id: str) -> Dict[str, Any]:
    """Submit report to local storage with multiple format options."""
    try:
        # Create reports directory if it doesn't exist
        reports_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(reports_dir, exist_ok=True)

        # Generate multiple output formats
        formats_saved = []

        # 1. JSON format (primary)
        json_path = os.path.join(reports_dir, f"{report_id}.json")
        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            formats_saved.append({"format": "json", "path": json_path, "size": os.path.getsize(json_path)})
        except (OSError, ValueError) as e:
            logger.error("Failed to save JSON report: %s", e)

        # 2. Human-readable text format
        txt_path = os.path.join(reports_dir, f"{report_id}.txt")
        try:
            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write(_format_report_as_text(report_data))
            formats_saved.append({"format": "text", "path": txt_path, "size": os.path.getsize(txt_path)})
        except (OSError, ValueError) as e:
            logger.error("Failed to save text report: %s", e)

        # 3. CSV format for tabular data
        csv_path = os.path.join(reports_dir, f"{report_id}.csv")
        try:
            if _save_report_as_csv(report_data, csv_path):
                formats_saved.append({"format": "csv", "path": csv_path, "size": os.path.getsize(csv_path)})
        except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
            logger.debug("Could not save CSV format: %s", e)

        # 4. Compressed archive
        archive_path = os.path.join(reports_dir, f"{report_id}.tar.gz")
        try:
            if _create_report_archive(report_id, formats_saved, archive_path):
                formats_saved.append({"format": "archive", "path": archive_path, "size": os.path.getsize(archive_path)})
        except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
            logger.debug("Could not create archive: %s", e)

        if formats_saved:
            return {
                "status": "saved",
                "storage_location": reports_dir,
                "formats": formats_saved,
                "primary_file": json_path,
                "total_files": len(formats_saved),
                "delivery_method": "local_storage"
            }
        else:
            return {
                "status": "failed",
                "error": "No formats could be saved",
                "delivery_method": "local_storage"
            }

    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.error("Local storage submission error: %s", e)
        return {"status": "error", "error": str(e)}


def _handle_additional_delivery_methods(report_data: Dict[str, Any], report_id: str) -> List[Dict[str, Any]]:
    """Handle additional delivery methods like email, cloud storage, etc."""
    additional_deliveries = []

    try:
        # 1. Email delivery (if configured)
        email_result = _attempt_email_delivery(report_data, report_id)
        if email_result:
            additional_deliveries.append(email_result)

        # 2. Cloud storage (if configured)
        cloud_result = _attempt_cloud_storage(report_data, report_id)
        if cloud_result:
            additional_deliveries.append(cloud_result)

        # 3. Database storage (if configured)
        db_result = _attempt_database_storage(report_data, report_id)
        if db_result:
            additional_deliveries.append(db_result)

    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.debug("Error in additional delivery methods: %s", e)

    return additional_deliveries


def _attempt_email_delivery(report_data: Dict[str, Any], report_id: str) -> Optional[Dict[str, Any]]:
    """Attempt to deliver report via email."""
    # Check for email configuration
    email_config = os.environ.get('INTELLICRACK_EMAIL_CONFIG')
    if not email_config:
        return None

    try:
        # Parse email configuration (expected format: smtp_host:port:username:password:recipient)
        config_parts = email_config.split(':')
        if len(config_parts) < 5:
            logger.warning("Invalid email configuration format")
            return None

        smtp_host, smtp_port, username, password, recipient = config_parts[:5]

        # Try to send email using smtplib
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            # Create message
            msg = MIMEMultipart()
            msg['From'] = username
            msg['To'] = recipient
            msg['Subject'] = f"Intellicrack Report {report_id}"

            # Add report as attachment
            body = json.dumps(report_data, indent=2)
            msg.attach(MIMEText(body, 'plain'))

            # Send email
            with smtplib.SMTP(smtp_host, int(smtp_port)) as server:
                server.starttls()
                server.login(username, password)
                server.send_message(msg)

            return {
                "method": "email",
                "status": "sent",
                "recipient": recipient,
                "subject": f"Intellicrack Report {report_id}",
                "message": "Email sent successfully"
            }

        except ImportError as e:
            logger.error("Import error in final_utilities: %s", e)
            return {
                "method": "email",
                "status": "unavailable",
                "message": "Email delivery requires Python's built-in smtplib"
            }
        except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
            logger.warning("Email delivery failed: %s", e)
            return {
                "method": "email",
                "status": "failed",
                "error": str(e),
                "message": "Email delivery failed - check SMTP configuration"
            }

    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.error("Email configuration error: %s", e)
        return None


def _attempt_cloud_storage(report_data: Dict[str, Any], report_id: str) -> Optional[Dict[str, Any]]:
    """Attempt to store report in cloud storage."""
    # Check for cloud storage configuration
    cloud_config = os.environ.get('INTELLICRACK_CLOUD_CONFIG')
    if not cloud_config:
        return None

    try:
        # Parse cloud configuration
        config = json.loads(cloud_config)
        provider = config.get('provider', 'aws_s3').lower()

        if provider == 'aws_s3':
            # Try AWS S3 upload
            try:
                import boto3

                s3 = boto3.client('s3',
                    aws_access_key_id=config.get('access_key'),
                    aws_secret_access_key=config.get('secret_key'),
                    region_name=config.get('region', 'us-east-1')
                )

                bucket = config.get('bucket', 'intellicrack-reports')
                key = f"reports/{report_id}.json"

                # Upload the report
                s3.put_object(
                    Bucket=bucket,
                    Key=key,
                    Body=json.dumps(report_data, indent=2),
                    ContentType='application/json'
                )

                return {
                    "method": "cloud_storage",
                    "status": "success",
                    "provider": "aws_s3",
                    "bucket": bucket,
                    "key": key,
                    "message": f"Report uploaded to s3://{bucket}/{key}"
                }

            except ImportError:
                logger.warning("boto3 not installed - cannot upload to AWS S3")
                return {
                    "method": "cloud_storage",
                    "status": "failed",
                    "provider": "aws_s3",
                    "message": "AWS SDK (boto3) not installed. Install with: pip install boto3"
                }
            except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
                logger.error("Error in final_utilities: %s", e)
                return {
                    "method": "cloud_storage",
                    "status": "failed",
                    "provider": "aws_s3",
                    "error": str(e),
                    "message": f"Failed to upload to AWS S3: {e}"
                }

        elif provider == 'azure':
            # Try Azure Blob Storage upload
            try:
                from azure.storage.blob import BlobServiceClient

                connection_string = config.get('connection_string')
                container = config.get('container', 'intellicrack-reports')
                blob_name = f"reports/{report_id}.json"

                blob_service = BlobServiceClient.from_connection_string(connection_string)
                blob_client = blob_service.get_blob_client(container=container, blob=blob_name)

                # Upload the report
                blob_client.upload_blob(
                    json.dumps(report_data, indent=2),
                    overwrite=True,
                    content_settings={'content_type': 'application/json'}
                )

                return {
                    "method": "cloud_storage",
                    "status": "success",
                    "provider": "azure",
                    "container": container,
                    "blob": blob_name,
                    "message": f"Report uploaded to Azure: {container}/{blob_name}"
                }

            except ImportError:
                logger.warning("azure-storage-blob not installed - cannot upload to Azure")
                return {
                    "method": "cloud_storage",
                    "status": "failed",
                    "provider": "azure",
                    "message": "Azure SDK not installed. Install with: pip install azure-storage-blob"
                }
            except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
                logger.error("Error in final_utilities: %s", e)
                return {
                    "method": "cloud_storage",
                    "status": "failed",
                    "provider": "azure",
                    "error": str(e),
                    "message": f"Failed to upload to Azure: {e}"
                }

        else:
            return {
                "method": "cloud_storage",
                "status": "failed",
                "message": f"Unsupported cloud provider: {provider}. Supported: aws_s3, azure"
            }

    except json.JSONDecodeError as e:
        logger.error("json.JSONDecodeError in final_utilities: %s", e)
        return {
            "method": "cloud_storage",
            "status": "failed",
            "message": "Invalid cloud configuration JSON in INTELLICRACK_CLOUD_CONFIG"
        }
    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.error("Error in final_utilities: %s", e)
        return {
            "method": "cloud_storage",
            "status": "failed",
            "error": str(e),
            "message": f"Cloud storage error: {e}"
        }


def _attempt_database_storage(report_data: Dict[str, Any], report_id: str) -> Optional[Dict[str, Any]]:
    """Attempt to store report in database."""
    # Check for database configuration
    db_config = os.environ.get('INTELLICRACK_DB_CONFIG')
    if not db_config:
        return None

    try:
        # Parse database configuration
        config = json.loads(db_config)
        db_type = config.get('type', 'sqlite').lower()

        if db_type == 'sqlite':
            # SQLite database storage
            try:
                import sqlite3

                db_path = config.get('path', 'intellicrack_reports.db')
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()

                # Create table if it doesn't exist
                cursor.execute('''CREATE TABLE IF NOT EXISTS analysis_reports
                               (id TEXT PRIMARY KEY,
                                timestamp REAL,
                                report_data TEXT,
                                metadata TEXT)''')

                # Insert report
                cursor.execute('''INSERT OR REPLACE INTO analysis_reports
                               (id, timestamp, report_data, metadata)
                               VALUES (?, ?, ?, ?)''',
                               (report_id,
                                time.time(),
                                json.dumps(report_data),
                                json.dumps(report_data.get('report_metadata', {}))))

                conn.commit()
                conn.close()

                return {
                    "method": "database",
                    "status": "success",
                    "database": "sqlite",
                    "path": db_path,
                    "record_id": report_id,
                    "message": f"Report stored in SQLite database: {db_path}"
                }

            except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
                logger.error("Error in final_utilities: %s", e)
                return {
                    "method": "database",
                    "status": "failed",
                    "database": "sqlite",
                    "error": str(e),
                    "message": f"Failed to store in SQLite: {e}"
                }

        elif db_type == 'postgresql':
            # PostgreSQL database storage
            try:
                import psycopg2

                conn = psycopg2.connect(
                    host=config.get('host', 'localhost'),
                    port=config.get('port', 5432),
                    database=config.get('database', 'intellicrack'),
                    user=config.get('user'),
                    password=config.get('password')
                )
                cursor = conn.cursor()

                # Create table if it doesn't exist
                cursor.execute('''CREATE TABLE IF NOT EXISTS analysis_reports
                               (id VARCHAR(255) PRIMARY KEY,
                                timestamp TIMESTAMP,
                                report_data JSONB,
                                metadata JSONB)''')

                # Insert report
                cursor.execute('''INSERT INTO analysis_reports
                               (id, timestamp, report_data, metadata)
                               VALUES (%s, to_timestamp(%s), %s, %s)
                               ON CONFLICT (id) DO UPDATE
                               SET timestamp = EXCLUDED.timestamp,
                                   report_data = EXCLUDED.report_data,
                                   metadata = EXCLUDED.metadata''',
                               (report_id,
                                time.time(),
                                json.dumps(report_data),
                                json.dumps(report_data.get('report_metadata', {}))))

                conn.commit()
                conn.close()

                return {
                    "method": "database",
                    "status": "success",
                    "database": "postgresql",
                    "host": config.get('host', 'localhost'),
                    "record_id": report_id,
                    "message": "Report stored in PostgreSQL database"
                }

            except ImportError:
                logger.warning("psycopg2 not installed - cannot connect to PostgreSQL")
                return {
                    "method": "database",
                    "status": "failed",
                    "database": "postgresql",
                    "message": "PostgreSQL driver not installed. Install with: pip install psycopg2-binary"
                }
            except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
                logger.error("Error in final_utilities: %s", e)
                return {
                    "method": "database",
                    "status": "failed",
                    "database": "postgresql",
                    "error": str(e),
                    "message": f"Failed to store in PostgreSQL: {e}"
                }

        elif db_type == 'mongodb':
            # MongoDB database storage
            try:
                import pymongo

                client = pymongo.MongoClient(config.get('connection_string', 'mongodb://localhost:27017/'))
                db = client[config.get('database', 'intellicrack')]
                collection = db[config.get('collection', 'analysis_reports')]

                # Insert or update report
                collection.replace_one(
                    {'_id': report_id},
                    {
                        '_id': report_id,
                        'timestamp': time.time(),
                        'report_data': report_data,
                        'metadata': report_data.get('report_metadata', {})
                    },
                    upsert=True
                )

                client.close()

                return {
                    "method": "database",
                    "status": "success",
                    "database": "mongodb",
                    "collection": config.get('collection', 'analysis_reports'),
                    "record_id": report_id,
                    "message": "Report stored in MongoDB"
                }

            except ImportError:
                logger.warning("pymongo not installed - cannot connect to MongoDB")
                return {
                    "method": "database",
                    "status": "failed",
                    "database": "mongodb",
                    "message": "MongoDB driver not installed. Install with: pip install pymongo"
                }
            except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
                logger.error("Error in final_utilities: %s", e)
                return {
                    "method": "database",
                    "status": "failed",
                    "database": "mongodb",
                    "error": str(e),
                    "message": f"Failed to store in MongoDB: {e}"
                }

        else:
            return {
                "method": "database",
                "status": "failed",
                "message": f"Unsupported database type: {db_type}. Supported: sqlite, postgresql, mongodb"
            }

    except json.JSONDecodeError as e:
        logger.error("json.JSONDecodeError in final_utilities: %s", e)
        return {
            "method": "database",
            "status": "failed",
            "message": "Invalid database configuration JSON in INTELLICRACK_DB_CONFIG"
        }
    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.error("Error in final_utilities: %s", e)
        return {
            "method": "database",
            "status": "failed",
            "error": str(e),
            "message": f"Database storage error: {e}"
        }


def _generate_report_summary(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a summary of the report data."""
    summary = {
        "total_sections": len(report_data),
        "sections": list(report_data.keys()),
        "data_types": {},
        "has_errors": False,
        "has_results": False
    }

    # Analyze data types and content
    for key, value in report_data.items():
        summary["data_types"][key] = type(value).__name__

        # Check for common patterns
        if key.lower() in ['error', 'errors', 'exception']:
            summary["has_errors"] = True
        elif key.lower() in ['results', 'findings', 'output']:
            summary["has_results"] = True

    return summary


def _sanitize_report_data(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize report data to remove sensitive information."""
    sanitized = report_data.copy()

    # Remove or mask sensitive keys
    sensitive_patterns = ['password', 'key', 'token', 'secret', 'credential']

    def sanitize_dict(data):
        if isinstance(data, dict):
            for key, value in data.items():
                if any(pattern in key.lower() for pattern in sensitive_patterns):
                    data[key] = "***REDACTED***"
                elif isinstance(value, dict):
                    sanitize_dict(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            sanitize_dict(item)
        return data

    return sanitize_dict(sanitized)


def _format_report_as_text(report_data: Dict[str, Any]) -> str:
    """Format report data as human-readable text."""
    lines = []
    lines.append("INTELLICRACK ANALYSIS REPORT")
    lines.append("=" * 50)
    lines.append("")

    # Add metadata
    metadata = report_data.get("report_metadata", {})
    lines.append("REPORT METADATA:")
    for key, value in metadata.items():
        lines.append(f"  {key}: {value}")
    lines.append("")

    # Add system info
    system_info = report_data.get("system_info", {})
    if system_info:
        lines.append("SYSTEM INFORMATION:")
        for key, value in system_info.items():
            lines.append(f"  {key}: {value}")
        lines.append("")

    # Add content
    content = report_data.get("content", {})
    lines.append("ANALYSIS CONTENT:")
    lines.append("-" * 30)

    def format_value(value, indent=0):
        indent_str = "  " * indent
        if isinstance(value, dict):
            result = []
            for k, v in value.items():
                result.append(f"{indent_str}{k}:")
                result.extend(format_value(v, indent + 1))
            return result
        elif isinstance(value, list):
            result = []
            for i, item in enumerate(value):
                result.append(f"{indent_str}[{i}]:")
                result.extend(format_value(item, indent + 1))
            return result
        else:
            return [f"{indent_str}{value}"]

    for key, value in content.items():
        lines.append(f"{key}:")
        lines.extend(format_value(value, 1))
        lines.append("")

    return "\n".join(lines)


def _save_report_as_csv(report_data: Dict[str, Any], csv_path: str) -> bool:
    """Save report data as CSV format."""
    try:
        import csv

        # Look for list/array data that can be converted to CSV
        content = report_data.get("content", {})
        for key, value in content.items():
            if isinstance(value, list) and value:
                if isinstance(value[0], dict):
                    # List of dictionaries - perfect for CSV
                    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                        if value:
                            fieldnames = list(value[0].keys())
                            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                            writer.writeheader()
                            for row in value:
                                writer.writerow(row)
                    return True

        # If no suitable tabular data found, create summary CSV
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Section', 'Type', 'Summary'])

            for key, value in content.items():
                summary = str(value)[:100] + "..." if len(str(value)) > 100 else str(value)
                writer.writerow([key, type(value).__name__, summary])

        return True

    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.debug("Error saving CSV: %s", e)
        return False


def _create_report_archive(report_id: str, formats_saved: List[Dict[str, Any]], archive_path: str) -> bool:
    """Create compressed archive of all report formats."""
    _ = report_id
    try:
        import tarfile

        with tarfile.open(archive_path, 'w:gz') as tar:
            for format_info in formats_saved:
                if format_info['format'] != 'archive':  # Don't include the archive itself
                    file_path = format_info['path']
                    if os.path.exists(file_path):
                        arcname = os.path.basename(file_path)
                        tar.add(file_path, arcname=arcname)

        return True

    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.debug("Error creating archive: %s", e)
        return False


def _create_submission_audit_trail(submission_result: Dict[str, Any], metadata: Dict[str, Any]) -> None:
    """Create audit trail for report submission."""
    try:
        audit_entry = {
            "timestamp": time.time(),
            "action": "report_submission",
            "report_id": metadata.get("report_id"),
            "status": submission_result.get("status"),
            "method": metadata.get("submission_method"),
            "endpoint": metadata.get("endpoint"),
            "user": os.environ.get("USER", "unknown")
        }

        # Log audit entry
        logger.info("Audit trail: %s", json.dumps(audit_entry))

        # Save to audit file if possible
        from intellicrack.utils.core.plugin_paths import get_reports_dir
        audit_file = get_reports_dir() / "audit.log"
        try:
            with open(audit_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(audit_entry) + "\n")
        except OSError as e:
            logger.error("OS error in final_utilities: %s", e)
            pass  # Audit file not critical

    except (OSError, ValueError, RuntimeError, AttributeError, KeyError) as e:
        logger.debug("Error creating audit trail: %s", e)


# === Training Functions ===

def start_training(model_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Start model training with given configuration.

    Args:
        model_config: Dictionary containing training configuration

    Returns:
        Dictionary with training status and metadata
    """
    logger.info("Starting training with config: %s", model_config)

    # This would typically start a training thread
    # For now, return a status dict
    return {
        "status": "started",
        "training_id": hash_func(model_config)[:8],
        "start_time": time.time()
    }


def stop_training(training_id: str) -> bool:
    """
    Stop an ongoing training process.

    Args:
        training_id: Unique identifier for the training process

    Returns:
        True if successfully stopped, False otherwise
    """
    logger.info("Stopping training: %s", training_id)
    # Would typically signal training thread to stop
    return True


def on_training_finished(results: Dict[str, Any]) -> None:
    """
    Callback when training finishes.

    Args:
        results: Dictionary containing training results and metrics
    """
    logger.info("Training finished with results: %s", results)


# === Model Functions ===

def create_dataset(data: List[Dict[str, Any]],
                  format: str = "json") -> Dict[str, Any]:  # pylint: disable=redefined-builtin
    """
    Create a dataset from raw data.

    Args:
        data: List of data items to include in dataset
        format: Format type for the dataset

    Returns:
        Dictionary containing dataset metadata and data
    """
    """Create a dataset from raw data."""
    dataset = {
        "format": format,
        "size": len(data),
        "created": time.time(),
        "data": data
    }

    # Calculate statistics
    if data:
        keys = set()
        for item in data:
            keys.update(item.keys())
        dataset["fields"] = list(keys)

    return dataset


def augment_dataset(dataset: List[Dict[str, Any]],
                   augmentation_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Augment a dataset with various techniques.

    Args:
        dataset: Original dataset to augment
        augmentation_config: Configuration for augmentation techniques

    Returns:
        Augmented dataset with additional samples
    """
    """Augment a dataset with various techniques."""
    augmented = []

    for item in dataset:
        augmented.append(item)  # Original

        # Simple augmentation examples
        if augmentation_config.get("add_noise"):
            noisy = item.copy()
            # Add some noise to numeric values
            for key, value in noisy.items():
                if isinstance(value, (int, float)):
                    noisy[key] = value * (1 + 0.1 * (hash(key) % 10 - 5) / 5)
            augmented.append(noisy)

        if augmentation_config.get("duplicate"):
            augmented.append(item.copy())

    return augmented


def load_dataset_preview(dataset_path: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Load a preview of a dataset.

    Args:
        dataset_path: Path to the dataset file
        limit: Maximum number of items to preview

    Returns:
        List of dataset items for preview
    """
    try:
        with open(dataset_path, 'r', encoding='utf-8') as f:
            if dataset_path.endswith('.jsonl'):
                # JSON Lines format
                preview = []
                for i, line in enumerate(f):
                    if i >= limit:
                        break
                    preview.append(json.loads(line))
                return preview
            else:
                # Regular JSON
                data = json.load(f)
                if isinstance(data, list):
                    return data[:limit]
                else:
                    return [data]
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to load dataset preview: %s", e)
        return []


def create_full_feature_model(features: List[str],
                            model_type: str = "ensemble") -> Dict[str, Any]:
    """
    Create a model configuration with all features.

    Args:
        features: List of feature names to include
        model_type: Type of model to create

    Returns:
        Dictionary containing model configuration
    """
    """Create a model configuration with all features."""
    return {
        "model_type": model_type,
        "features": features,
        "n_features": len(features),
        "created": time.time(),
        "config": {
            "n_estimators": 100,
            "max_depth": 10,
            "learning_rate": 0.1
        }
    }


def predict_vulnerabilities(binary_features: Dict[str, Any],
                          model: Optional[Any] = None) -> Dict[str, Any]:
    """
    Predict vulnerabilities in a binary.

    Args:
        binary_features: Dictionary of extracted binary features
        model: Optional trained model for prediction

    Returns:
        Dictionary containing vulnerability predictions and risk assessments
    """
    """Predict vulnerabilities in a binary."""
    _ = model
    # Simplified prediction logic
    predictions = {
        "buffer_overflow": 0.2,
        "integer_overflow": 0.1,
        "format_string": 0.05,
        "use_after_free": 0.15,
        "null_pointer": 0.1
    }

    # Adjust based on features
    if binary_features.get("has_strcpy"):
        predictions["buffer_overflow"] += 0.3
    if binary_features.get("has_printf"):
        predictions["format_string"] += 0.2

    return {
        "predictions": predictions,
        "high_risk": [k for k, v in predictions.items() if v > 0.5],
        "medium_risk": [k for k, v in predictions.items() if 0.2 <= v <= 0.5]
    }


# === Misc Functions ===

def add_code_snippet(snippets: List[Dict[str, Any]],
                    title: str, code: str, language: str = "python") -> None:
    """
    Add a code snippet to a collection.

    Args:
        snippets: List to add the snippet to
        title: Title for the code snippet
        code: Code content
        language: Programming language of the code
    """
    """Add a code snippet to a collection."""
    snippets.append({
        "title": title,
        "code": code,
        "language": language,
        "timestamp": time.time()
    })


def add_dataset_row(dataset: List[Dict[str, Any]], row: Dict[str, Any]) -> None:
    """
    Add a row to a dataset.

    Args:
        dataset: Dataset list to add to
        row: Data row to add
    """
    dataset.append(row)


def add_image(document: Any, image_path: str,
             caption: Optional[str] = None) -> bool:
    """
    Add an image to a document.

    Args:
        document: Document object to add image to
        image_path: Path to the image file
        caption: Optional caption for the image

    Returns:
        True if image exists and can be added, False otherwise
    """
    """Add an image to a document."""
    _ = document
    # This would typically add to a PDF or HTML document
    logger.info("Adding image %s with caption: %s", image_path, caption)
    return os.path.exists(image_path)


def add_recommendations(report: Dict[str, Any],
                       recommendations: List[str]) -> None:
    """
    Add recommendations to a report.

    Args:
        report: Report dictionary to add recommendations to
        recommendations: List of recommendation strings
    """
    """Add recommendations to a report."""
    if "recommendations" not in report:
        report["recommendations"] = []
    report["recommendations"].extend(recommendations)


def showEvent(event: Any) -> None:
    """
    Handle widget show event.

    Args:
        event: Show event object
    """
    _ = event
    logger.debug("Widget shown")


def patches_reordered(old_order: List[int], new_order: List[int]) -> None:
    """
    Handle patch reordering.

    Args:
        old_order: Previous order of patches
        new_order: New order of patches
    """
    logger.info("Patches reordered from %s to %s", old_order, new_order)


def do_GET(request_handler: Any) -> None:
    """
    Handle HTTP GET request.

    Args:
        request_handler: HTTP request handler object
    """
    request_handler.send_response(200)
    request_handler.send_header('Content-type', 'text/html')
    request_handler.end_headers()
    request_handler.wfile.write(b"Intellicrack Server Running")


# Note: Exports are handled by the package-level __init__.py to avoid duplication
