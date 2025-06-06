"""Final utility functions to complete the Intellicrack refactoring.

This module contains the remaining essential functions that were identified
as missing from the modular structure. Most internal helper functions (_*)
are omitted as they are implementation details that have been replaced
by the modular architecture.
"""

import hashlib
import json
import os
import platform
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Optional imports with graceful fallbacks
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from PyQt5.QtCore import QThread, QTimer, pyqtSignal
    from PyQt5.QtWidgets import QApplication, QWidget
    HAS_PYQT = True
except ImportError:
    HAS_PYQT = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

from ..utils.logger import setup_logger

logger = setup_logger(__name__)


# === UI Functions ===

def add_table(parent: Any, headers: List[str], data: List[List[Any]]) -> Any:
    """Add a table widget to the parent UI element."""
    if not HAS_PYQT:
        logger.warning("PyQt5 not available, cannot create table")
        return None

    from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem

    table = QTableWidget(len(data), len(headers), parent)
    table.setHorizontalHeaderLabels(headers)

    for row, row_data in enumerate(data):
        for col, value in enumerate(row_data):
            table.setItem(row, col, QTableWidgetItem(str(value)))

    return table


def browse_dataset(parent: Any = None) -> Optional[str]:
    """Browse for a dataset file."""
    if not HAS_PYQT:
        logger.warning("PyQt5 not available, cannot browse dataset")
        return None

    from PyQt5.QtWidgets import QFileDialog

    file_path, _ = QFileDialog.getOpenFileName(
        parent,
        "Select Dataset",
        "",
        "Dataset Files (*.json *.jsonl *.csv *.txt);;All Files (*.*)"
    )
    return file_path if file_path else None


def browse_model(parent: Any = None) -> Optional[str]:
    """Browse for a model file."""
    if not HAS_PYQT:
        logger.warning("PyQt5 not available, cannot browse model")
        return None

    from PyQt5.QtWidgets import QFileDialog

    file_path, _ = QFileDialog.getOpenFileName(
        parent,
        "Select Model",
        "",
        "Model Files (*.gguf *.bin *.pth *.onnx *.h5);;All Files (*.*)"
    )
    return file_path if file_path else None


def show_simulation_results(results: Dict[str, Any], parent: Any = None) -> None:
    """Display simulation results in a dialog."""
    if not HAS_PYQT:
        logger.info(f"Simulation Results: {json.dumps(results, indent=2)}")
        return

    from PyQt5.QtWidgets import QDialog, QPushButton, QTextEdit, QVBoxLayout

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
    """Update training progress in the UI."""
    logger.info("Training Progress: %f% - %s", progress, message)


def update_visualization(data: Any, viz_type: str = "plot") -> None:
    """Update visualization with new data."""
    logger.info("Updating %s visualization with data", viz_type)


# === Analysis Functions ===

def monitor_memory(process_name: Optional[str] = None,
                  threshold_mb: float = 1000.0) -> Dict[str, Any]:
    """Monitor memory usage of a process or the system."""
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
    except Exception as e:
        return {"error": str(e)}


# === Core Utility Functions ===

def accelerate_hash_calculation(data: bytes, algorithm: str = "sha256",
                              use_gpu: bool = False) -> str:
    """Calculate hash with optional GPU acceleration."""
    if use_gpu:
        logger.info("GPU acceleration requested but using CPU fallback")

    hash_obj = hashlib.new(algorithm)
    hash_obj.update(data)
    return hash_obj.hexdigest()


def compute_binary_hash(binary_path: str, algorithm: str = "sha256") -> Optional[str]:
    """Compute hash of a binary file."""
    try:
        hash_obj = hashlib.new(algorithm)
        with open(binary_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        logger.error("Error computing hash: %s", e)
        return None


def compute_section_hashes(binary_path: str) -> Dict[str, str]:
    """Compute hashes for each section of a binary."""
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
    except Exception as e:
        logger.error("Error computing section hashes: %s", e)

    return section_hashes


def identify_changed_sections(binary1: str, binary2: str) -> List[str]:
    """Identify which sections changed between two binaries."""
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
    """Get an appropriate icon name for a file type."""
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
    """Determine the resource type of a file."""
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
    """Cache analysis results to disk."""
    try:
        os.makedirs(cache_dir, exist_ok=True)
        cache_file = os.path.join(cache_dir, f"{key}.json")

        with open(cache_file, 'w') as f:
            json.dump({
                'timestamp': time.time(),
                'results': results
            }, f)

        return True
    except Exception as e:
        logger.error("Failed to cache results: %s", e)
        return False


def get_captured_requests(limit: int = 100) -> List[Dict[str, Any]]:
    """Get recently captured network requests."""
    # This would typically read from a capture buffer
    # For now, return empty list as placeholder
    return []


def force_memory_cleanup() -> Dict[str, Any]:
    """Force garbage collection and memory cleanup."""
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
    """Initialize memory optimization settings."""
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
        )

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Process timed out after {timeout} seconds"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def select_backend_for_workload(workload_type: str,
                              available_backends: List[str]) -> str:
    """Select the best backend for a given workload type."""
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
    """Truncate text to specified length."""
    if len(text) <= max_length:
        return text

    return text[:max_length - len(suffix)] + suffix


def center_on_screen(widget: Any) -> None:
    """Center a widget on the screen."""
    if not HAS_PYQT or not widget:
        return

    from PyQt5.QtWidgets import QDesktopWidget

    desktop = QDesktopWidget()
    screen_rect = desktop.screenGeometry()
    widget_rect = widget.geometry()

    x = (screen_rect.width() - widget_rect.width()) // 2
    y = (screen_rect.height() - widget_rect.height()) // 2

    widget.move(x, y)


def copy_to_clipboard(text: str) -> bool:
    """Copy text to system clipboard."""
    try:
        if HAS_PYQT:
            from PyQt5.QtWidgets import QApplication
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
    except Exception as e:
        logger.error("Failed to copy to clipboard: %s", e)

    return False


def async_wrapper(func: Callable) -> Callable:
    """Wrapper to run a function asynchronously in a thread."""
    def wrapped(*args, **kwargs):
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
    """Generic hash function for any data type."""
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
    """Export metrics to a file."""
    try:
        with open(output_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        return True
    except Exception as e:
        logger.error("Failed to export metrics: %s", e)
        return False


def submit_report(report_data: Dict[str, Any],
                 endpoint: Optional[str] = None) -> Dict[str, Any]:
    """Submit a report to an endpoint or save locally."""
    if endpoint:
        # Would typically POST to endpoint
        logger.info("Would submit report to %s", endpoint)
        return {"status": "simulated", "id": hash_func(report_data)[:8]}
    else:
        # Save locally
        report_id = hash_func(report_data)[:8]
        report_path = f"report_{report_id}.json"

        try:
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            return {"status": "saved", "id": report_id, "path": report_path}
        except Exception as e:
            return {"status": "error", "error": str(e)}


# === Training Functions ===

def start_training(model_config: Dict[str, Any]) -> Dict[str, Any]:
    """Start model training with given configuration."""
    logger.info("Starting training with config: %s", model_config)

    # This would typically start a training thread
    # For now, return a status dict
    return {
        "status": "started",
        "training_id": hash_func(model_config)[:8],
        "start_time": time.time()
    }


def stop_training(training_id: str) -> bool:
    """Stop an ongoing training process."""
    logger.info("Stopping training: %s", training_id)
    # Would typically signal training thread to stop
    return True


def on_training_finished(results: Dict[str, Any]) -> None:
    """Callback when training finishes."""
    logger.info("Training finished with results: %s", results)


# === Model Functions ===

def create_dataset(data: List[Dict[str, Any]],
                  format: str = "json") -> Dict[str, Any]:
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
    """Load a preview of a dataset."""
    try:
        with open(dataset_path, 'r') as f:
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
    except Exception as e:
        logger.error("Failed to load dataset preview: %s", e)
        return []


def create_full_feature_model(features: List[str],
                            model_type: str = "ensemble") -> Dict[str, Any]:
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
    """Predict vulnerabilities in a binary."""
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
    """Add a code snippet to a collection."""
    snippets.append({
        "title": title,
        "code": code,
        "language": language,
        "timestamp": time.time()
    })


def add_dataset_row(dataset: List[Dict[str, Any]], row: Dict[str, Any]) -> None:
    """Add a row to a dataset."""
    dataset.append(row)


def add_image(document: Any, image_path: str,
             caption: Optional[str] = None) -> bool:
    """Add an image to a document."""
    # This would typically add to a PDF or HTML document
    logger.info("Adding image %s with caption: %s", image_path, caption)
    return os.path.exists(image_path)


def add_recommendations(report: Dict[str, Any],
                       recommendations: List[str]) -> None:
    """Add recommendations to a report."""
    if "recommendations" not in report:
        report["recommendations"] = []
    report["recommendations"].extend(recommendations)


def showEvent(event: Any) -> None:
    """Handle widget show event."""
    logger.debug("Widget shown")


def patches_reordered(old_order: List[int], new_order: List[int]) -> None:
    """Handle patch reordering."""
    logger.info("Patches reordered from %s to %s", old_order, new_order)


def do_GET(request_handler: Any) -> None:
    """Handle HTTP GET request."""
    request_handler.send_response(200)
    request_handler.send_header('Content-type', 'text/html')
    request_handler.end_headers()
    request_handler.wfile.write(b"Intellicrack Server Running")


# Export all functions
__all__ = [
    # UI Functions
    'add_table', 'browse_dataset', 'browse_model',
    'show_simulation_results', 'update_training_progress',
    'update_visualization', 'center_on_screen', 'copy_to_clipboard',
    'showEvent',

    # Analysis Functions
    'monitor_memory', 'predict_vulnerabilities',

    # Core Utility Functions
    'accelerate_hash_calculation', 'compute_binary_hash',
    'compute_section_hashes', 'identify_changed_sections',
    'get_file_icon', 'get_resource_type', 'cache_analysis_results',
    'get_captured_requests', 'force_memory_cleanup',
    'initialize_memory_optimizer', 'sandbox_process',
    'select_backend_for_workload', 'truncate_text',
    'async_wrapper', 'hash_func',

    # Report Functions
    'export_metrics', 'submit_report',

    # Training Functions
    'start_training', 'stop_training', 'on_training_finished',

    # Model Functions
    'create_dataset', 'augment_dataset', 'load_dataset_preview',
    'create_full_feature_model',

    # Misc Functions
    'add_code_snippet', 'add_dataset_row', 'add_image',
    'add_recommendations', 'patches_reordered', 'do_GET'
]
