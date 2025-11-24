"""Simple test runner for final_utilities tests.

Runs tests directly without pytest to verify functionality.
"""

import hashlib
import json
import os
import shutil
import tempfile
import time
from pathlib import Path


def test_hash_calculation() -> None:
    """Test hash calculation functions."""
    print("Testing hash calculation...")

    from intellicrack.utils.core.final_utilities import (
        accelerate_hash_calculation,
        compute_binary_hash,
        hash_func,
    )

    data = b"test data for hashing"
    result = accelerate_hash_calculation(data, algorithm="sha256")
    expected = hashlib.sha256(data).hexdigest()
    assert result == expected, f"Hash mismatch: {result} != {expected}"
    print("  ✓ accelerate_hash_calculation with SHA256")

    result_md5 = accelerate_hash_calculation(data, algorithm="md5")
    expected_md5 = hashlib.md5(data).hexdigest()
    assert result_md5 == expected_md5
    print("  ✓ accelerate_hash_calculation with MD5")

    temp_dir = Path(tempfile.mkdtemp(prefix="test_hash_"))
    try:
        binary_path = temp_dir / "test.bin"
        binary_data = b"MZ\x90\x00" + os.urandom(1024)
        binary_path.write_bytes(binary_data)

        file_hash = compute_binary_hash(str(binary_path))
        assert file_hash is not None
        assert len(file_hash) == 64
        print("  ✓ compute_binary_hash")

        bytes_hash = hash_func(b"test bytes")
        assert len(bytes_hash) == 64
        print("  ✓ hash_func with bytes")

        str_hash = hash_func("test string")
        assert len(str_hash) == 64
        print("  ✓ hash_func with string")

        dict_hash = hash_func({"key": "value"})
        assert len(dict_hash) == 64
        print("  ✓ hash_func with dict")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_file_utilities() -> None:
    """Test file and resource utilities."""
    print("\nTesting file utilities...")

    from intellicrack.utils.core.final_utilities import (
        get_file_icon,
        get_resource_type,
    )

    assert get_file_icon("test.exe") == "application-x-executable"
    print("  ✓ get_file_icon for executable")

    assert get_file_icon("test.dll") == "application-x-sharedlib"
    print("  ✓ get_file_icon for library")

    assert get_resource_type("app.exe") == "binary"
    print("  ✓ get_resource_type for binary")

    assert get_resource_type("script.py") == "source"
    print("  ✓ get_resource_type for source")

    assert get_resource_type("config.json") == "config"
    print("  ✓ get_resource_type for config")


def test_cache_operations() -> None:
    """Test cache operations."""
    print("\nTesting cache operations...")

    from intellicrack.utils.core.final_utilities import cache_analysis_results

    temp_dir = Path(tempfile.mkdtemp(prefix="test_cache_"))
    try:
        cache_dir = str(temp_dir / "cache")
        results = {"analysis": "test", "findings": ["item1", "item2"]}

        success = cache_analysis_results("test_key", results, cache_dir)
        assert success is True
        print("  ✓ cache_analysis_results stores data")

        cache_file = Path(cache_dir) / "test_key.json"
        assert cache_file.exists()
        print("  ✓ cache file created")

        cached_data = json.loads(cache_file.read_text())
        assert cached_data["results"] == results
        print("  ✓ cached data matches")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_text_utilities() -> None:
    """Test text processing utilities."""
    print("\nTesting text utilities...")

    from intellicrack.utils.core.final_utilities import truncate_text

    text = "short text"
    result = truncate_text(text, max_length=100)
    assert result == text
    print("  ✓ truncate_text preserves short text")

    long_text = "a" * 200
    result = truncate_text(long_text, max_length=50)
    assert len(result) == 50
    assert result.endswith("...")
    print("  ✓ truncate_text truncates long text")


def test_backend_selection() -> None:
    """Test backend selection."""
    print("\nTesting backend selection...")

    from intellicrack.utils.core.final_utilities import select_backend_for_workload

    backends = ["threading", "multiprocessing", "sequential"]
    result = select_backend_for_workload("cpu", backends)
    assert result == "multiprocessing"
    print("  ✓ select_backend_for_workload CPU")

    backends = ["cuda", "cpu"]
    result = select_backend_for_workload("gpu", backends)
    assert result == "cuda"
    print("  ✓ select_backend_for_workload GPU")


def test_dataset_operations() -> None:
    """Test dataset operations."""
    print("\nTesting dataset operations...")

    from intellicrack.utils.core.final_utilities import (
        add_dataset_row,
        augment_dataset,
        create_dataset,
    )

    data = [{"id": 1, "value": "test1"}, {"id": 2, "value": "test2"}]
    dataset = create_dataset(data)
    assert dataset["format"] == "json"
    assert dataset["size"] == 2
    print("  ✓ create_dataset")

    augmented = augment_dataset(data, {"duplicate": True})
    assert len(augmented) >= len(data)
    print("  ✓ augment_dataset")

    dataset_list = []
    add_dataset_row(dataset_list, {"id": 1, "value": "test"})
    assert len(dataset_list) == 1
    print("  ✓ add_dataset_row")


def test_report_generation() -> None:
    """Test report generation."""
    print("\nTesting report generation...")

    from intellicrack.utils.core.final_utilities import export_metrics, submit_report

    temp_dir = Path(tempfile.mkdtemp(prefix="test_report_"))
    try:
        metrics_path = str(temp_dir / "metrics.json")
        metrics = {"total_scans": 100, "vulnerabilities": 15}

        success = export_metrics(metrics, metrics_path)
        assert success is True
        print("  ✓ export_metrics")

        saved_metrics = json.loads(Path(metrics_path).read_text())
        assert saved_metrics == metrics
        print("  ✓ metrics saved correctly")

        report_data = {"type": "analysis", "findings": ["test"]}
        result = submit_report(report_data)
        assert "report_id" in result
        print("  ✓ submit_report")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_model_operations() -> None:
    """Test model operations."""
    print("\nTesting model operations...")

    from intellicrack.utils.core.final_utilities import (
        create_full_feature_model,
        predict_vulnerabilities,
    )

    features = ["feature1", "feature2", "feature3"]
    model = create_full_feature_model(features, model_type="random_forest")
    assert model["model_type"] == "random_forest"
    assert model["n_features"] == 3
    print("  ✓ create_full_feature_model")

    binary_features = {"has_strcpy": True, "has_printf": False}
    result = predict_vulnerabilities(binary_features)
    assert "predictions" in result
    assert result["predictions"]["buffer_overflow"] > 0.3
    print("  ✓ predict_vulnerabilities")


def test_async_wrapper() -> None:
    """Test async wrapper."""
    print("\nTesting async wrapper...")

    from intellicrack.utils.core.final_utilities import async_wrapper

    executed = []

    def test_func(value: str) -> None:
        executed.append(value)

    wrapped = async_wrapper(test_func)
    thread = wrapped("test_value")
    thread.join(timeout=2)

    assert "test_value" in executed
    print("  ✓ async_wrapper executes function")


def test_memory_management() -> None:
    """Test memory management."""
    print("\nTesting memory management...")

    from intellicrack.utils.core.final_utilities import (
        force_memory_cleanup,
        initialize_memory_optimizer,
    )

    result = force_memory_cleanup()
    assert isinstance(result, dict)
    assert "gc_stats" in result
    print("  ✓ force_memory_cleanup")

    config = initialize_memory_optimizer(threshold_mb=1000.0)
    assert config["threshold_mb"] == 1000.0
    print("  ✓ initialize_memory_optimizer")


def main() -> None:
    """Run all tests."""
    print("=" * 60)
    print("Running final_utilities.py tests")
    print("=" * 60)

    start_time = time.time()
    tests_passed = 0
    tests_failed = 0

    tests = [
        test_hash_calculation,
        test_file_utilities,
        test_cache_operations,
        test_text_utilities,
        test_backend_selection,
        test_dataset_operations,
        test_report_generation,
        test_model_operations,
        test_async_wrapper,
        test_memory_management,
    ]

    for test in tests:
        try:
            test()
            tests_passed += 1
        except Exception as e:
            print(f"\n✗ {test.__name__} FAILED: {e}")
            tests_failed += 1

    elapsed = time.time() - start_time

    print("\n" + "=" * 60)
    print(f"Tests completed in {elapsed:.2f}s")
    print(f"Passed: {tests_passed}/{len(tests)}")
    print(f"Failed: {tests_failed}/{len(tests)}")
    print("=" * 60)

    if tests_failed > 0:
        exit(1)
    else:
        print("\nAll tests PASSED!")
        exit(0)


if __name__ == "__main__":
    main()
