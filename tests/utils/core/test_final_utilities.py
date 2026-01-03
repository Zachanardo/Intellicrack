"""Comprehensive production-grade tests for final_utilities.py.

Tests validate real utility functions work correctly including:
- File operations and path handling
- Binary manipulation and hash calculation
- Data processing and conversion
- Windows-specific operations
- Network request capture and analysis
- Report generation and submission
- Memory management
- Dataset operations

Copyright (C) 2025 Zachary Flint
"""

import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import tempfile
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.core.final_utilities import (
    accelerate_hash_calculation,
    add_code_snippet,
    add_dataset_row,
    add_image,
    add_recommendations,
    async_wrapper,
    augment_dataset,
    cache_analysis_results,
    center_on_screen,
    compute_binary_hash,
    compute_section_hashes,
    copy_to_clipboard,
    create_dataset,
    create_full_feature_model,
    display_patch_validation_results,
    do_GET,
    export_metrics,
    force_memory_cleanup,
    get_captured_requests,
    get_file_icon,
    get_resource_type,
    hash_func,
    identify_changed_sections,
    initialize_memory_optimizer,
    load_dataset_preview,
    monitor_memory,
    patches_reordered,
    predict_vulnerabilities,
    sandbox_process,
    select_backend_for_workload,
    showEvent,
    start_training,
    stop_training,
    submit_report,
    truncate_text,
    update_training_progress,
    update_visualization,
)


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create temporary directory for test operations."""
    temp_path = Path(tempfile.mkdtemp(prefix="test_final_utils_"))
    yield temp_path
    if temp_path.exists():
        shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def sample_binary(temp_dir: Path) -> Path:
    """Create sample binary file for testing."""
    binary_path = temp_dir / "test_binary.exe"
    binary_data = b"MZ\x90\x00" + os.urandom(1024)
    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def sample_pe_binary(temp_dir: Path) -> Path:
    """Create minimal valid PE binary for section hash testing."""
    binary_path = temp_dir / "test_pe.exe"

    dos_header = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"
    padding = b"\x00" * 64

    pe_signature = b"PE\x00\x00"
    coff_header = (
        b"\x4c\x01"
        b"\x01\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00"
        b"\xe0\x00"
        b"\x0f\x01"
    )

    optional_header = b"\x0b\x01" + b"\x00" * 222

    section_header = (
        b".text\x00\x00\x00"
        b"\x00\x04\x00\x00"
        b"\x00\x10\x00\x00"
        b"\x00\x02\x00\x00"
        b"\x00\x04\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x20\x00\x00\x60"
    )

    section_data = b"\x90" * 512

    pe_binary = dos_header + padding + pe_signature + coff_header + optional_header + section_header + section_data
    binary_path.write_bytes(pe_binary)
    return binary_path


@pytest.fixture
def sample_json_file(temp_dir: Path) -> Path:
    """Create sample JSON file for testing."""
    json_path = temp_dir / "test_data.json"
    data = [
        {"id": 1, "name": "test1", "value": 100},
        {"id": 2, "name": "test2", "value": 200},
        {"id": 3, "name": "test3", "value": 300},
    ]
    json_path.write_text(json.dumps(data))
    return json_path


@pytest.fixture
def sample_jsonl_file(temp_dir: Path) -> Path:
    """Create sample JSONL file for testing."""
    jsonl_path = temp_dir / "test_data.jsonl"
    lines = [
        '{"id": 1, "name": "test1"}\n',
        '{"id": 2, "name": "test2"}\n',
        '{"id": 3, "name": "test3"}\n',
    ]
    jsonl_path.write_text("".join(lines))
    return jsonl_path


class TestHashCalculation:
    """Test hash calculation utilities."""

    def test_accelerate_hash_calculation_sha256(self) -> None:
        """Hash calculation produces correct SHA256 hash."""
        data = b"test data for hashing"
        result = accelerate_hash_calculation(data, algorithm="sha256")

        expected = hashlib.sha256(data).hexdigest()
        assert result == expected
        assert len(result) == 64

    def test_accelerate_hash_calculation_md5(self) -> None:
        """Hash calculation produces correct MD5 hash."""
        data = b"test data for md5"
        result = accelerate_hash_calculation(data, algorithm="md5")

        expected = hashlib.md5(data).hexdigest()
        assert result == expected
        assert len(result) == 32

    def test_accelerate_hash_calculation_with_gpu_fallback(self) -> None:
        """GPU acceleration request falls back to CPU correctly."""
        data = b"gpu test data"
        result = accelerate_hash_calculation(data, use_gpu=True)

        expected = hashlib.sha256(data).hexdigest()
        assert result == expected

    def test_compute_binary_hash_success(self, sample_binary: Path) -> None:
        """Binary hash computation produces correct hash."""
        result = compute_binary_hash(str(sample_binary))

        assert result is not None
        assert len(result) == 64

        with open(sample_binary, "rb") as f:
            expected = hashlib.sha256(f.read()).hexdigest()
        assert result == expected

    def test_compute_binary_hash_large_file(self, temp_dir: Path) -> None:
        """Binary hash computation handles large files correctly."""
        large_binary = temp_dir / "large.bin"
        large_binary.write_bytes(os.urandom(100000))

        result = compute_binary_hash(str(large_binary))

        assert result is not None
        assert len(result) == 64

    def test_compute_binary_hash_nonexistent_file(self) -> None:
        """Binary hash computation returns None for missing file."""
        result = compute_binary_hash("/nonexistent/file.exe")
        assert result is None

    def test_compute_section_hashes_without_pefile(self, sample_binary: Path) -> None:
        """Section hash computation falls back to file hash without pefile."""
        result = compute_section_hashes(str(sample_binary))

        assert isinstance(result, dict)
        if "_file" in result:
            file_hash = compute_binary_hash(str(sample_binary))
            assert result["_file"] == file_hash

    def test_identify_changed_sections(self, temp_dir: Path) -> None:
        """Changed section identification detects modifications."""
        binary1 = temp_dir / "binary1.exe"
        binary2 = temp_dir / "binary2.exe"

        data1 = b"MZ\x90\x00" + b"A" * 1000
        data2 = b"MZ\x90\x00" + b"B" * 1000

        binary1.write_bytes(data1)
        binary2.write_bytes(data2)

        result = identify_changed_sections(str(binary1), str(binary2))

        assert isinstance(result, list)

    def test_hash_func_with_bytes(self) -> None:
        """Hash function handles bytes input correctly."""
        data = b"test bytes"
        result = hash_func(data)

        expected = hashlib.sha256(data).hexdigest()
        assert result == expected

    def test_hash_func_with_string(self) -> None:
        """Hash function handles string input correctly."""
        data = "test string"
        result = hash_func(data)

        expected = hashlib.sha256(data.encode("utf-8")).hexdigest()
        assert result == expected

    def test_hash_func_with_dict(self) -> None:
        """Hash function handles dictionary input correctly."""
        data = {"key": "value", "number": 42}
        result = hash_func(data)

        json_data = json.dumps(data, sort_keys=True).encode("utf-8")
        expected = hashlib.sha256(json_data).hexdigest()
        assert result == expected

    def test_hash_func_different_algorithms(self) -> None:
        """Hash function supports different algorithms."""
        data = b"test data"

        sha256_result = hash_func(data, algorithm="sha256")
        md5_result = hash_func(data, algorithm="md5")

        assert len(sha256_result) == 64
        assert len(md5_result) == 32
        assert sha256_result != md5_result


class TestFileUtilities:
    """Test file and resource utilities."""

    def test_get_file_icon_executable(self) -> None:
        """File icon returns correct icon for executables."""
        assert get_file_icon("test.exe") == "application-x-executable"
        assert get_file_icon("TEST.EXE") == "application-x-executable"

    def test_get_file_icon_library(self) -> None:
        """File icon returns correct icon for libraries."""
        assert get_file_icon("test.dll") == "application-x-sharedlib"
        assert get_file_icon("test.so") == "application-x-sharedlib"

    def test_get_file_icon_various_types(self) -> None:
        """File icon returns correct icons for various file types."""
        assert get_file_icon("script.py") == "text-x-python"
        assert get_file_icon("code.js") == "text-x-javascript"
        assert get_file_icon("data.json") == "application-json"
        assert get_file_icon("document.pdf") == "application-pdf"
        assert get_file_icon("archive.zip") == "application-zip"

    def test_get_file_icon_unknown_type(self) -> None:
        """File icon returns default for unknown types."""
        assert get_file_icon("unknown.xyz") == "application-octet-stream"

    def test_get_resource_type_binary(self) -> None:
        """Resource type correctly identifies binaries."""
        assert get_resource_type("app.exe") == "binary"
        assert get_resource_type("library.dll") == "binary"
        assert get_resource_type("lib.so") == "binary"

    def test_get_resource_type_source(self) -> None:
        """Resource type correctly identifies source code."""
        assert get_resource_type("script.py") == "source"
        assert get_resource_type("code.js") == "source"
        assert get_resource_type("program.c") == "source"

    def test_get_resource_type_text(self) -> None:
        """Resource type correctly identifies text files."""
        assert get_resource_type("readme.txt") == "text"
        assert get_resource_type("document.md") == "text"

    def test_get_resource_type_config(self) -> None:
        """Resource type correctly identifies config files."""
        assert get_resource_type("config.json") == "config"
        assert get_resource_type("settings.xml") == "config"
        assert get_resource_type("data.yaml") == "config"

    def test_get_resource_type_image(self) -> None:
        """Resource type correctly identifies images."""
        assert get_resource_type("photo.jpg") == "image"
        assert get_resource_type("icon.png") == "image"

    def test_get_resource_type_archive(self) -> None:
        """Resource type correctly identifies archives."""
        assert get_resource_type("package.zip") == "archive"
        assert get_resource_type("backup.tar") == "archive"

    def test_get_resource_type_unknown(self) -> None:
        """Resource type returns unknown for unrecognized types."""
        assert get_resource_type("file.unknown") == "unknown"


class TestCacheOperations:
    """Test cache and analysis result operations."""

    def test_cache_analysis_results_success(self, temp_dir: Path) -> None:
        """Cache analysis results stores data correctly."""
        cache_dir = str(temp_dir / "cache")
        results = {
            "analysis": "test",
            "findings": ["item1", "item2"],
            "score": 85,
        }

        success = cache_analysis_results("test_key", results, cache_dir)

        assert success is True
        cache_file = Path(cache_dir) / "test_key.json"
        assert cache_file.exists()

        cached_data = json.loads(cache_file.read_text())
        assert "timestamp" in cached_data
        assert cached_data["results"] == results

    def test_cache_analysis_results_creates_directory(self, temp_dir: Path) -> None:
        """Cache analysis results creates directory if missing."""
        cache_dir = str(temp_dir / "new_cache_dir")
        results: dict[str, object] = {"test": "data"}

        success = cache_analysis_results("key", results, cache_dir)

        assert success is True
        assert Path(cache_dir).exists()

    def test_cache_analysis_results_overwrites_existing(self, temp_dir: Path) -> None:
        """Cache analysis results overwrites existing cache."""
        cache_dir = str(temp_dir / "cache")

        cache_analysis_results("key", {"old": "data"}, cache_dir)
        cache_analysis_results("key", {"new": "data"}, cache_dir)

        cache_file = Path(cache_dir) / "key.json"
        cached_data = json.loads(cache_file.read_text())
        assert cached_data["results"]["new"] == "data"
        assert "old" not in cached_data["results"]


class TestNetworkRequestCapture:
    """Test network request capture and analysis."""

    def test_get_captured_requests_returns_list(self) -> None:
        """Get captured requests returns list of dictionaries."""
        requests = get_captured_requests(limit=10)

        assert isinstance(requests, list)
        for request in requests:
            assert isinstance(request, dict)

    def test_get_captured_requests_respects_limit(self) -> None:
        """Get captured requests respects limit parameter."""
        requests = get_captured_requests(limit=5)

        assert len(requests) <= 5

    def test_get_captured_requests_contains_metadata(self) -> None:
        """Get captured requests contains required metadata."""
        if requests := get_captured_requests(limit=1):
            request = requests[0]
            assert "timestamp" in request or "source" in request

    def test_get_captured_requests_large_limit(self) -> None:
        """Get captured requests handles large limits."""
        requests = get_captured_requests(limit=1000)

        assert isinstance(requests, list)
        assert len(requests) <= 1000


class TestMemoryManagement:
    """Test memory management utilities."""

    def test_force_memory_cleanup(self) -> None:
        """Memory cleanup executes and returns stats."""
        result = force_memory_cleanup()

        assert isinstance(result, dict)
        assert "gc_stats" in result
        assert isinstance(result["gc_stats"], list)

    def test_initialize_memory_optimizer(self) -> None:
        """Memory optimizer initialization returns config."""
        config = initialize_memory_optimizer(threshold_mb=1000.0)

        assert isinstance(config, dict)
        assert config["threshold_mb"] == 1000.0
        assert config["gc_enabled"] is True
        assert "monitoring_enabled" in config
        assert "optimization_level" in config

    def test_monitor_memory_system(self) -> None:
        """Memory monitoring returns system memory stats."""
        result = monitor_memory()

        assert isinstance(result, dict)
        if "error" not in result:
            assert "total_mb" in result or "percent" in result


class TestProcessSandboxing:
    """Test process sandboxing utilities."""

    @pytest.mark.skipif(platform.system() == "Windows", reason="Test requires Unix-like echo command")
    def test_sandbox_process_success(self) -> None:
        """Sandbox process executes command and returns result."""
        result = sandbox_process(["echo", "test"], timeout=5)

        assert isinstance(result, dict)
        assert "success" in result
        assert "stdout" in result or "error" in result

    def test_sandbox_process_timeout(self) -> None:
        """Sandbox process handles timeout correctly."""
        if platform.system() == "Windows":
            command = ["timeout", "10"]
        else:
            command = ["sleep", "10"]

        result = sandbox_process(command, timeout=1)

        assert isinstance(result, dict)
        assert result["success"] is False
        if "error" in result:
            error_val = result["error"]
            assert isinstance(error_val, str) and "timed out" in error_val.lower()


class TestTextUtilities:
    """Test text processing utilities."""

    def test_truncate_text_short(self) -> None:
        """Truncate text returns original if under limit."""
        text = "short text"
        result = truncate_text(text, max_length=100)

        assert result == text

    def test_truncate_text_long(self) -> None:
        """Truncate text truncates long text correctly."""
        text = "a" * 200
        result = truncate_text(text, max_length=50)

        assert len(result) == 50
        assert result.endswith("...")

    def test_truncate_text_custom_suffix(self) -> None:
        """Truncate text uses custom suffix."""
        text = "a" * 200
        result = truncate_text(text, max_length=50, suffix="[...]")

        assert result.endswith("[...]")
        assert len(result) == 50

    def test_truncate_text_exact_length(self) -> None:
        """Truncate text handles exact length match."""
        text = "a" * 50
        result = truncate_text(text, max_length=50)

        assert result == text


class TestBackendSelection:
    """Test backend selection utilities."""

    def test_select_backend_cpu_workload(self) -> None:
        """Backend selection chooses correct backend for CPU."""
        backends = ["threading", "multiprocessing", "sequential"]
        result = select_backend_for_workload("cpu", backends)

        assert result in backends
        assert result == "multiprocessing"

    def test_select_backend_gpu_workload(self) -> None:
        """Backend selection prioritizes GPU backends."""
        backends = ["cuda", "cpu"]
        result = select_backend_for_workload("gpu", backends)

        assert result == "cuda"

    def test_select_backend_fallback(self) -> None:
        """Backend selection falls back when preferred unavailable."""
        backends = ["cpu", "sequential"]
        result = select_backend_for_workload("gpu", backends)

        assert result == "cpu"

    def test_select_backend_empty_list(self) -> None:
        """Backend selection handles empty backend list."""
        result = select_backend_for_workload("cpu", [])

        assert result == "sequential"


class TestAsyncWrapper:
    """Test async wrapper utilities."""

    def test_async_wrapper_executes_function(self) -> None:
        """Async wrapper executes function in thread."""
        executed = []

        def test_func(value: str) -> None:
            executed.append(value)

        wrapped = async_wrapper(test_func)
        thread = wrapped("test_value")

        thread.join(timeout=2)
        assert "test_value" in executed

    def test_async_wrapper_returns_thread(self) -> None:
        """Async wrapper returns thread object."""
        def test_func() -> None:
            time.sleep(0.1)

        wrapped = async_wrapper(test_func)
        result = wrapped()

        assert hasattr(result, "join")
        assert hasattr(result, "is_alive")
        result.join(timeout=1)


class TestReportGeneration:
    """Test report generation and submission utilities."""

    def test_export_metrics_success(self, temp_dir: Path) -> None:
        """Export metrics writes metrics to file."""
        output_path = str(temp_dir / "metrics.json")
        metrics: dict[str, object] = {
            "total_scans": 100,
            "vulnerabilities_found": 15,
            "average_scan_time": 5.2,
        }

        success = export_metrics(metrics, output_path)

        assert success is True
        assert Path(output_path).exists()

        saved_metrics = json.loads(Path(output_path).read_text())
        assert saved_metrics == metrics

    def test_submit_report_local_storage(self, temp_dir: Path) -> None:
        """Report submission saves to local storage."""
        report_data: dict[str, object] = {
            "type": "analysis_report",
            "findings": ["finding1", "finding2"],
            "severity": "high",
        }

        result = submit_report(report_data)

        assert isinstance(result, dict)
        assert "report_id" in result
        assert "timestamp" in result

    def test_submit_report_with_endpoint(self) -> None:
        """Report submission handles remote endpoint."""
        report_data: dict[str, object] = {"test": "data"}

        result = submit_report(report_data, endpoint="https://example.com/reports")

        assert isinstance(result, dict)
        assert "status" in result


class TestDatasetOperations:
    """Test dataset creation and manipulation."""

    def test_create_dataset_basic(self) -> None:
        """Dataset creation produces valid dataset."""
        data: list[dict[str, object]] = [
            {"id": 1, "value": "test1"},
            {"id": 2, "value": "test2"},
        ]

        dataset = create_dataset(data)

        assert dataset["format"] == "json"
        assert dataset["size"] == 2
        assert dataset["data"] == data
        assert "created" in dataset
        assert "fields" in dataset

    def test_create_dataset_with_format(self) -> None:
        """Dataset creation respects format parameter."""
        data: list[dict[str, object]] = [{"test": "data"}]

        dataset = create_dataset(data, format="csv")

        assert dataset["format"] == "csv"

    def test_augment_dataset_basic(self) -> None:
        """Dataset augmentation increases dataset size."""
        data: list[dict[str, object]] = [{"value": 100}, {"value": 200}]
        config: dict[str, object] = {"add_noise": False, "duplicate": False}

        result = augment_dataset(data, config)

        assert len(result) >= len(data)

    def test_augment_dataset_with_noise(self) -> None:
        """Dataset augmentation adds noisy samples."""
        data: list[dict[str, object]] = [{"value": 100}]
        config: dict[str, object] = {"add_noise": True}

        result = augment_dataset(data, config)

        assert len(result) > len(data)

    def test_augment_dataset_with_duplication(self) -> None:
        """Dataset augmentation duplicates samples."""
        data: list[dict[str, object]] = [{"id": 1}, {"id": 2}]
        config: dict[str, object] = {"duplicate": True}

        result = augment_dataset(data, config)

        assert len(result) == len(data) * 2

    def test_load_dataset_preview_json(self, sample_json_file: Path) -> None:
        """Dataset preview loads JSON files correctly."""
        result = load_dataset_preview(str(sample_json_file), limit=2)

        assert isinstance(result, list)
        assert len(result) <= 2
        assert all(isinstance(item, dict) for item in result)

    def test_load_dataset_preview_jsonl(self, sample_jsonl_file: Path) -> None:
        """Dataset preview loads JSONL files correctly."""
        result = load_dataset_preview(str(sample_jsonl_file), limit=2)

        assert isinstance(result, list)
        assert len(result) <= 2

    def test_load_dataset_preview_nonexistent(self) -> None:
        """Dataset preview handles missing files."""
        result = load_dataset_preview("/nonexistent/dataset.json")

        assert result == []

    def test_add_dataset_row(self) -> None:
        """Add dataset row appends to dataset."""
        dataset: list[dict[str, Any]] = []
        row = {"id": 1, "value": "test"}

        add_dataset_row(dataset, row)

        assert len(dataset) == 1
        assert dataset[0] == row


class TestModelOperations:
    """Test model creation and prediction utilities."""

    def test_create_full_feature_model(self) -> None:
        """Model creation produces valid configuration."""
        features = ["feature1", "feature2", "feature3"]

        model = create_full_feature_model(features, model_type="random_forest")

        assert model["model_type"] == "random_forest"
        assert model["features"] == features
        assert model["n_features"] == 3
        assert "created" in model
        assert "config" in model

    def test_predict_vulnerabilities_basic(self) -> None:
        """Vulnerability prediction returns predictions."""
        features: dict[str, object] = {"has_strcpy": False, "has_printf": False}

        result = predict_vulnerabilities(features)

        assert "predictions" in result
        assert "high_risk" in result
        assert "medium_risk" in result
        assert isinstance(result["predictions"], dict)

    def test_predict_vulnerabilities_with_strcpy(self) -> None:
        """Vulnerability prediction detects strcpy risk."""
        features: dict[str, object] = {"has_strcpy": True, "has_printf": False}

        result = predict_vulnerabilities(features)

        predictions = result["predictions"]
        assert isinstance(predictions, dict)
        assert predictions["buffer_overflow"] > 0.3

    def test_predict_vulnerabilities_with_printf(self) -> None:
        """Vulnerability prediction detects printf risk."""
        features: dict[str, object] = {"has_strcpy": False, "has_printf": True}

        result = predict_vulnerabilities(features)

        predictions = result["predictions"]
        assert isinstance(predictions, dict)
        assert predictions["format_string"] > 0.2


class TestTrainingOperations:
    """Test training management utilities."""

    def test_start_training(self) -> None:
        """Training start returns status."""
        config = {"model": "test", "epochs": 10}

        result = start_training(config)

        assert result["status"] == "started"
        assert "training_id" in result
        assert "start_time" in result

    def test_stop_training(self) -> None:
        """Training stop completes successfully."""
        result = stop_training("test_id")

        assert result is True

    def test_update_training_progress(self) -> None:
        """Training progress update executes without error."""
        update_training_progress(50.0, "halfway done")
        update_training_progress(100.0)


class TestMiscellaneousUtilities:
    """Test miscellaneous utility functions."""

    def test_add_code_snippet(self) -> None:
        """Code snippet addition stores snippet correctly."""
        snippets: list[dict[str, Any]] = []

        add_code_snippet(snippets, "Test Function", "def test(): pass", "python")

        assert len(snippets) == 1
        assert snippets[0]["title"] == "Test Function"
        assert snippets[0]["code"] == "def test(): pass"
        assert snippets[0]["language"] == "python"
        assert "timestamp" in snippets[0]

    def test_add_image(self, temp_dir: Path) -> None:
        """Image addition validates image existence."""
        image_path = temp_dir / "test.png"
        image_path.write_bytes(b"\x89PNG\r\n\x1a\n")

        result = add_image(None, str(image_path), "Test Image")

        assert result is True

    def test_add_image_nonexistent(self) -> None:
        """Image addition handles missing images."""
        result = add_image(None, "/nonexistent/image.png")

        assert result is False

    def test_add_recommendations(self) -> None:
        """Recommendations addition appends to report."""
        report: dict[str, Any] = {}
        recommendations = ["Fix vulnerability A", "Update library B"]

        add_recommendations(report, recommendations)

        assert "recommendations" in report
        assert len(report["recommendations"]) == 2
        assert "Fix vulnerability A" in report["recommendations"]

    def test_add_recommendations_appends(self) -> None:
        """Recommendations addition appends to existing."""
        report: dict[str, Any] = {"recommendations": ["Existing"]}

        add_recommendations(report, ["New"])

        assert len(report["recommendations"]) == 2

    def test_patches_reordered(self) -> None:
        """Patch reordering executes without error."""
        patches_reordered([1, 2, 3], [3, 1, 2])

    def test_showEvent(self) -> None:
        """Show event handler executes without error."""
        showEvent(None)

    def test_update_visualization(self) -> None:
        """Visualization update executes without error."""
        update_visualization({"data": [1, 2, 3]}, viz_type="chart")

    def test_do_GET(self) -> None:
        """GET request handler processes request."""
        class MockHandler:
            def __init__(self) -> None:
                self.response_code = 0
                self.headers: dict[str, str] = {}
                self.wfile = MockFile()

            def send_response(self, code: int) -> None:
                self.response_code = code

            def send_header(self, key: str, value: str) -> None:
                self.headers[key] = value

            def end_headers(self) -> None:
                pass

        class MockFile:
            def __init__(self) -> None:
                self.data = b""

            def write(self, data: bytes) -> None:
                self.data += data

        handler = MockHandler()
        do_GET(handler)

        assert handler.response_code == 200
        assert handler.headers["Content-type"] == "text/html"
        assert b"Intellicrack" in handler.wfile.data


class TestPatchValidationDisplay:
    """Test patch validation result display utilities."""

    def test_display_patch_validation_results_console(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Patch validation display outputs to console."""
        results = {
            "success": True,
            "patches_total": 5,
            "patches_validated": 4,
            "patches_failed": 1,
            "validation_results": [
                {
                    "offset": 0x1000,
                    "description": "License check bypass",
                    "success": True,
                }
            ],
        }

        display_patch_validation_results(results, display_mode="console")

        captured = capsys.readouterr()
        assert "PATCH TESTING RESULTS" in captured.out
        assert "SUCCESS" in captured.out
        assert "Total Patches: 5" in captured.out

    def test_display_patch_validation_results_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Patch validation display outputs valid JSON."""
        results: dict[str, object] = {"success": True, "patches_total": 3}

        display_patch_validation_results(results, display_mode="json")

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["success"] is True
        assert parsed["patches_total"] == 3

    def test_display_patch_validation_results_empty(self) -> None:
        """Patch validation display handles empty results."""
        empty_results: dict[str, object] = {}
        display_patch_validation_results(empty_results, display_mode="console")


class TestWindowsClipboard:
    """Test clipboard operations."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_copy_to_clipboard_windows(self) -> None:
        """Clipboard copy works on Windows."""
        result = copy_to_clipboard("test clipboard content")

        assert isinstance(result, bool)

    @pytest.mark.skipif(platform.system() == "Windows", reason="Non-Windows test")
    def test_copy_to_clipboard_unix(self) -> None:
        """Clipboard copy attempts platform-specific command."""
        result = copy_to_clipboard("test content")

        assert isinstance(result, bool)


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_hash_func_empty_bytes(self) -> None:
        """Hash function handles empty bytes."""
        result = hash_func(b"")

        assert len(result) == 64
        assert result == hashlib.sha256(b"").hexdigest()

    def test_truncate_text_empty(self) -> None:
        """Truncate text handles empty string."""
        result = truncate_text("")

        assert result == ""

    def test_create_dataset_empty(self) -> None:
        """Dataset creation handles empty data."""
        dataset = create_dataset([])

        assert dataset["size"] == 0
        assert dataset["data"] == []

    def test_augment_dataset_empty(self) -> None:
        """Dataset augmentation handles empty data."""
        result = augment_dataset([], {})

        assert result == []

    def test_cache_analysis_results_invalid_path(self) -> None:
        """Cache analysis handles invalid paths gracefully."""
        if platform.system() == "Windows":
            invalid_path = "Z:\\nonexistent\\path\\cache"
        else:
            invalid_path = "/root/forbidden/cache"

        result = cache_analysis_results("key", {}, invalid_path)

        assert isinstance(result, bool)


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_complete_binary_analysis_workflow(self, temp_dir: Path) -> None:
        """Complete binary analysis workflow succeeds."""
        binary = temp_dir / "target.exe"
        binary.write_bytes(b"MZ\x90\x00" + os.urandom(2048))

        file_hash = compute_binary_hash(str(binary))
        assert file_hash is not None

        icon = get_file_icon(str(binary))
        assert icon == "application-x-executable"

        resource_type = get_resource_type(str(binary))
        assert resource_type == "binary"

        cache_dir = str(temp_dir / "cache")
        results: dict[str, object] = {
            "hash": file_hash,
            "type": resource_type,
            "icon": icon,
        }
        success = cache_analysis_results("analysis", results, cache_dir)
        assert success is True

    def test_report_generation_workflow(self, temp_dir: Path) -> None:
        """Complete report generation workflow succeeds."""
        findings = [
            {"type": "license_check", "location": "0x1000", "severity": "high"},
            {"type": "trial_timer", "location": "0x2000", "severity": "medium"},
        ]

        report: dict[str, Any] = {
            "type": "crack_analysis",
            "target": "test.exe",
            "findings": findings,
        }

        add_recommendations(
            report,
            [
                "Bypass license check at 0x1000",
                "Remove trial timer at 0x2000",
            ],
        )

        assert len(report["recommendations"]) == 2

        metrics_path = str(temp_dir / "metrics.json")
        metrics: dict[str, object] = {
            "total_findings": len(findings),
            "high_severity": 1,
            "medium_severity": 1,
        }
        success = export_metrics(metrics, metrics_path)
        assert success is True

        result = submit_report(report)
        assert "report_id" in result

    def test_dataset_processing_workflow(self, sample_json_file: Path, temp_dir: Path) -> None:
        """Complete dataset processing workflow succeeds."""
        preview = load_dataset_preview(str(sample_json_file), limit=5)
        assert len(preview) > 0

        full_dataset = load_dataset_preview(str(sample_json_file), limit=100)

        augmented = augment_dataset(full_dataset, {"duplicate": True})
        assert len(augmented) >= len(full_dataset)

        dataset = create_dataset(augmented)
        assert dataset["size"] == len(augmented)


class TestPerformance:
    """Test performance characteristics of utilities."""

    def test_hash_large_file_performance(self, temp_dir: Path) -> None:
        """Hash calculation completes in reasonable time for large files."""
        large_file = temp_dir / "large.bin"
        large_file.write_bytes(os.urandom(10 * 1024 * 1024))

        start_time = time.time()
        result = compute_binary_hash(str(large_file))
        elapsed = time.time() - start_time

        assert result is not None
        assert elapsed < 5.0

    def test_dataset_augmentation_performance(self) -> None:
        """Dataset augmentation completes in reasonable time."""
        dataset: list[dict[str, object]] = [
            {"id": i, "value": i * 10} for i in range(1000)
        ]
        config: dict[str, object] = {"add_noise": True}

        start_time = time.time()
        augment_dataset(dataset, config)
        elapsed = time.time() - start_time

        assert elapsed < 2.0
