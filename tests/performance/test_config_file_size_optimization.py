"""
Test Suite: Config File Size and Load Time Optimization (Task 18.2.4)

This module validates configuration file size optimization and load time performance.
Tests compression strategies, file size growth over time, and load performance.

Author: Intellicrack Development Team
Date: 2024
"""

import json
import time
import gzip
import zlib
import bz2
import unittest
from pathlib import Path
import tempfile
import shutil
import sys
import os
import random
import string
from typing import Dict, Any, Tuple
import msgpack  # For binary serialization testing
import pickle
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from intellicrack.core.config_manager import IntellicrackConfig


class TestConfigFileSizeOptimization(unittest.TestCase):
    """Test configuration file size optimization and load times."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp(prefix="test_config_size_")
        self.config_path = Path(self.test_dir) / "config.json"
        self.compressed_path = Path(self.test_dir) / "config.json.gz"

        # Size thresholds for production
        self.MAX_CONFIG_SIZE_MB = 10  # Maximum acceptable config size
        self.TARGET_CONFIG_SIZE_MB = 2  # Target size for typical config
        self.MAX_LOAD_TIME_SECONDS = 1.0  # Maximum acceptable load time
        self.TARGET_LOAD_TIME_SECONDS = 0.1  # Target load time

    def tearDown(self):
        """Clean up test environment."""
        if Path(self.test_dir).exists():
            shutil.rmtree(self.test_dir)

    def _generate_large_config(self, num_entries: int = 1000) -> dict[str, Any]:
        """Generate a large configuration for testing."""
        config = {
            "version": "3.0",
            "application": {"name": "Intellicrack", "version": "1.0.0"},
            "llm_configuration": {"models": {}, "profiles": {}, "metrics": {}},
            "ui_preferences": {"window_states": {}, "splitter_states": {}},
            "analysis_history": [],
            "tool_cache": {},
        }

        # Add many model configurations
        for i in range(num_entries):
            model_id = f"model_{i}"
            config["llm_configuration"]["models"][model_id] = {
                "provider": random.choice(["openai", "anthropic", "google"]),
                "model_name": f"model-{i}",
                "api_key": "sk-"
                + "".join(
                    random.choices(string.ascii_letters + string.digits, k=48)
                ),
                "api_base": f"https://api-{i}.example.com",
                "context_length": random.randint(1000, 100000),
                "temperature": random.uniform(0.1, 2.0),
                "max_tokens": random.randint(100, 4000),
                "custom_params": {
                    f"param_{j}": "".join(
                        random.choices(string.ascii_letters, k=50)
                    )
                    for j in range(10)
                },
                "metadata": {
                    "description": "".join(
                        random.choices(f"{string.ascii_letters} ", k=200)
                    ),
                    "tags": [f"tag_{j}" for j in range(20)],
                },
            }

        # Add analysis history entries
        for i in range(num_entries // 10):
            config["analysis_history"].append({
                "timestamp": time.time() - i * 3600,
                "file_path": f"/path/to/binary_{i}.exe",
                "results": {
                    "protections": [f"protection_{j}" for j in range(10)],
                    "vulnerabilities": [f"vuln_{j}" for j in range(5)],
                    "metadata": {f"key_{j}": "".join(random.choices(string.ascii_letters, k=100)) for j in range(20)},
                },
            })

        # Add tool cache entries
        for i in range(num_entries // 5):
            tool_name = f"tool_{i}"
            config["tool_cache"][tool_name] = {
                "path": f"/path/to/tool_{i}",
                "version": f"v{random.randint(1, 10)}.{random.randint(0, 99)}.{random.randint(0, 999)}",
                "capabilities": [f"cap_{j}" for j in range(15)],
                "configuration": {f"setting_{j}": random.choice([True, False, random.randint(0, 100)]) for j in range(30)},
            }

        return config

    def test_18_2_4_config_file_size_baseline(self):
        """Test baseline config file size."""
        # Create default config
        config = IntellicrackConfig(config_path=str(self.config_path))
        config.save()

        # Check file size
        file_size = self.config_path.stat().st_size
        file_size_mb = file_size / (1024 * 1024)

        print(f"\nBaseline config size: {file_size:,} bytes ({file_size_mb:.2f} MB)")

        # Baseline should be under 1MB
        self.assertLess(file_size_mb, 1.0, "Baseline config exceeds 1MB")

        # Measure load time
        start_time = time.time()
        loaded_config = IntellicrackConfig(config_path=str(self.config_path))
        load_time = time.time() - start_time

        print(f"Baseline load time: {load_time:.3f} seconds")

        # Baseline should load quickly
        self.assertLess(load_time, 0.1, "Baseline config load time exceeds 0.1 seconds")

    def test_18_2_4_large_config_optimization(self):
        """Test optimization of large configuration files."""
        # Generate large config
        large_config = self._generate_large_config(num_entries=1000)

        # Write unoptimized
        with open(self.config_path, "w") as f:
            json.dump(large_config, f, indent=2)

        unoptimized_size = self.config_path.stat().st_size
        unoptimized_mb = unoptimized_size / (1024 * 1024)

        print(f"\nUnoptimized large config: {unoptimized_size:,} bytes ({unoptimized_mb:.2f} MB)")

        # Write optimized (no indentation, compact)
        optimized_path = Path(self.test_dir) / "config_optimized.json"
        with open(optimized_path, "w") as f:
            json.dump(large_config, f, separators=(",", ":"))

        optimized_size = optimized_path.stat().st_size
        optimized_mb = optimized_size / (1024 * 1024)
        size_reduction = (1 - optimized_size / unoptimized_size) * 100

        print(f"Optimized large config: {optimized_size:,} bytes ({optimized_mb:.2f} MB)")
        print(f"Size reduction: {size_reduction:.1f}%")

        # Optimized should be significantly smaller
        self.assertLess(optimized_size, unoptimized_size * 0.8, "Optimization insufficient")

    def test_18_2_4_compression_strategies(self):
        """Test different compression strategies for config files."""
        # Generate large config
        config_data = self._generate_large_config(num_entries=500)
        json_data = json.dumps(config_data, separators=(",", ":")).encode("utf-8")
        original_size = len(json_data)

        compression_results = {}

        # Test gzip compression
        start_time = time.time()
        gzip_data = gzip.compress(json_data, compresslevel=9)
        gzip_time = time.time() - start_time
        gzip_size = len(gzip_data)
        compression_results["gzip"] = {"size": gzip_size, "ratio": gzip_size / original_size, "compress_time": gzip_time}

        # Test zlib compression
        start_time = time.time()
        zlib_data = zlib.compress(json_data, level=9)
        zlib_time = time.time() - start_time
        zlib_size = len(zlib_data)
        compression_results["zlib"] = {"size": zlib_size, "ratio": zlib_size / original_size, "compress_time": zlib_time}

        # Test bz2 compression
        start_time = time.time()
        bz2_data = bz2.compress(json_data, compresslevel=9)
        bz2_time = time.time() - start_time
        bz2_size = len(bz2_data)
        compression_results["bz2"] = {"size": bz2_size, "ratio": bz2_size / original_size, "compress_time": bz2_time}

        print(f"\nOriginal size: {original_size:,} bytes")
        print("\nCompression results:")
        for method, results in compression_results.items():
            print(f"  {method}:")
            print(f"    Size: {results['size']:,} bytes")
            print(f"    Ratio: {results['ratio']:.2%}")
            print(f"    Time: {results['compress_time']:.3f}s")

        # Test decompression times
        start_time = time.time()
        gzip.decompress(gzip_data)
        gzip_decompress_time = time.time() - start_time

        start_time = time.time()
        zlib.decompress(zlib_data)
        zlib_decompress_time = time.time() - start_time

        start_time = time.time()
        bz2.decompress(bz2_data)
        bz2_decompress_time = time.time() - start_time

        print("\nDecompression times:")
        print(f"  gzip: {gzip_decompress_time:.3f}s")
        print(f"  zlib: {zlib_decompress_time:.3f}s")
        print(f"  bz2: {bz2_decompress_time:.3f}s")

        # All methods should achieve significant compression
        for method, results in compression_results.items():
            self.assertLess(results["ratio"], 0.3, f"{method} compression ratio too high")

    def test_18_2_4_incremental_config_growth(self):
        """Test config file growth over simulated time."""
        config = IntellicrackConfig(config_path=str(self.config_path))

        growth_data = []

        # Simulate config growth over time
        for day in range(30):  # 30 days of usage
            # Add some models
            for i in range(random.randint(1, 5)):
                model_id = f"model_day{day}_{i}"
                config.set(
                    f"llm_configuration.models.{model_id}",
                    {
                        "provider": "openai",
                        "model_name": f"gpt-{day}-{i}",
                        "api_key": "sk-" + "".join(random.choices(string.ascii_letters, k=48)),
                    },
                )

            # Add analysis history
            for i in range(random.randint(5, 20)):
                history = config.get("analysis_history", [])
                history.append({"timestamp": time.time(), "file": f"binary_day{day}_{i}.exe", "results": {"status": "complete"}})
                config.set("analysis_history", history)

            # Save and measure
            config.save()
            file_size = self.config_path.stat().st_size
            growth_data.append({"day": day, "size": file_size, "size_mb": file_size / (1024 * 1024)})

        # Analyze growth rate
        initial_size = growth_data[0]["size"]
        final_size = growth_data[-1]["size"]
        growth_rate = (final_size - initial_size) / initial_size

        print(f"\nConfig growth over 30 days:")
        print(f"  Initial: {initial_size:,} bytes")
        print(f"  Final: {final_size:,} bytes")
        print(f"  Growth: {growth_rate:.1%}")

        # Check if growth is reasonable
        self.assertLess(growth_data[-1]["size_mb"], self.MAX_CONFIG_SIZE_MB, f"Config exceeds {self.MAX_CONFIG_SIZE_MB}MB after 30 days")

    def test_18_2_4_load_time_scaling(self):
        """Test config load time scaling with size."""
        load_times = []

        for num_entries in [10, 50, 100, 500, 1000, 2000]:
            # Generate config of specific size
            config_data = self._generate_large_config(num_entries=num_entries)

            # Write to file
            config_path = Path(self.test_dir) / f"config_{num_entries}.json"
            with open(config_path, "w") as f:
                json.dump(config_data, f)

            file_size = config_path.stat().st_size

            # Measure load time (average of 3 runs)
            times = []
            for _ in range(3):
                start_time = time.time()
                with open(config_path) as f:
                    loaded = json.load(f)
                load_time = time.time() - start_time
                times.append(load_time)

            avg_load_time = sum(times) / len(times)
            load_times.append({"entries": num_entries, "size": file_size, "size_mb": file_size / (1024 * 1024), "load_time": avg_load_time})

        print("\nLoad time scaling:")
        for data in load_times:
            print(f"  {data['entries']:4} entries: {data['size_mb']:6.2f}MB -> {data['load_time']:.3f}s")

        # Check that large configs still load within acceptable time
        for data in load_times:
            if data["size_mb"] <= self.TARGET_CONFIG_SIZE_MB:
                self.assertLess(
                    data["load_time"], self.TARGET_LOAD_TIME_SECONDS, f"Load time exceeds target for {data['size_mb']:.2f}MB config"
                )
            else:
                self.assertLess(
                    data["load_time"], self.MAX_LOAD_TIME_SECONDS, f"Load time exceeds maximum for {data['size_mb']:.2f}MB config"
                )

    def test_18_2_4_binary_serialization_comparison(self):
        """Compare JSON vs binary serialization formats."""
        config_data = self._generate_large_config(num_entries=500)

        # JSON serialization
        json_data = json.dumps(config_data).encode("utf-8")
        json_size = len(json_data)

        start_time = time.time()
        json.loads(json_data.decode("utf-8"))
        json_load_time = time.time() - start_time

        # Pickle serialization
        pickle_data = pickle.dumps(config_data, protocol=pickle.HIGHEST_PROTOCOL)
        pickle_size = len(pickle_data)

        start_time = time.time()
        pickle.loads(pickle_data)
        pickle_load_time = time.time() - start_time

        # MessagePack serialization (if available)
        try:
            msgpack_data = msgpack.packb(config_data)
            msgpack_size = len(msgpack_data)

            start_time = time.time()
            msgpack.unpackb(msgpack_data)
            msgpack_load_time = time.time() - start_time
        except Exception:
            msgpack_size = 0
            msgpack_load_time = 0

        print("\nSerialization format comparison:")
        print(f"  JSON:    {json_size:,} bytes, {json_load_time:.3f}s load")
        print(f"  Pickle:  {pickle_size:,} bytes, {pickle_load_time:.3f}s load")
        if msgpack_size > 0:
            print(f"  MsgPack: {msgpack_size:,} bytes, {msgpack_load_time:.3f}s load")

        # JSON should remain the format for human readability
        # But verify it's not significantly worse than alternatives
        if pickle_size > 0:
            self.assertLess(json_size / pickle_size, 2.0, "JSON size is more than 2x pickle size")

    def test_18_2_4_config_cleanup_optimization(self):
        """Test cleanup of old/unused config entries."""
        config = IntellicrackConfig(config_path=str(self.config_path))

        # Add many temporary entries
        for i in range(100):
            config.set(f"temp.entry_{i}", {"data": "x" * 1000})

        # Add old metrics
        for i in range(100):
            config.set(
                f"llm_configuration.metrics.old_model_{i}",
                {
                    "history": [{"timestamp": time.time() - 86400 * 90}] * 100  # 90 days old
                },
            )

        config.save()
        initial_size = self.config_path.stat().st_size

        # Simulate cleanup of old entries
        cleaned_config = IntellicrackConfig(config_path=str(self.config_path))

        # Remove temp entries
        if "temp" in cleaned_config.config:
            del cleaned_config.config["temp"]

        # Remove old metrics (>60 days)
        current_time = time.time()
        metrics = cleaned_config.get("llm_configuration.metrics", {})
        for model_id in list(metrics):
            if model_id.startswith("old_model_"):
                history = metrics[model_id].get("history", [])
                if history and history[0].get("timestamp", current_time) < current_time - 86400 * 60:
                    del metrics[model_id]

        cleaned_config.set("llm_configuration.metrics", metrics)
        cleaned_config.save()

        cleaned_size = self.config_path.stat().st_size
        reduction = (1 - cleaned_size / initial_size) * 100

        print(f"\nConfig cleanup optimization:")
        print(f"  Before: {initial_size:,} bytes")
        print(f"  After:  {cleaned_size:,} bytes")
        print(f"  Reduction: {reduction:.1f}%")

        self.assertLess(cleaned_size, initial_size, "Cleanup should reduce file size")

    def test_18_2_4_lazy_loading_simulation(self):
        """Test simulated lazy loading of config sections."""
        # Create config with multiple large sections
        config_data = {
            "version": "3.0",
            "core": {"setting": "value"},  # Small, always loaded
            "llm_configuration": self._generate_large_config(100)["llm_configuration"],
            "analysis_history": [{"data": "x" * 1000} for _ in range(500)],
            "tool_cache": {f"tool_{i}": {"data": "y" * 500} for i in range(200)},
        }

        with open(self.config_path, "w") as f:
            json.dump(config_data, f)

        # Simulate loading only core section
        start_time = time.time()
        with open(self.config_path) as f:
            # In production, would use streaming JSON parser
            full_data = json.load(f)
            core_data = full_data.get("core", {})
        core_load_time = time.time() - start_time

        # Load everything
        start_time = time.time()
        with open(self.config_path) as f:
            full_data = json.load(f)
        full_load_time = time.time() - start_time

        print(f"\nLazy loading simulation:")
        print(f"  Core only: {core_load_time:.3f}s")
        print(f"  Full load: {full_load_time:.3f}s")
        print(f"  Time saved: {(full_load_time - core_load_time):.3f}s")

        # Core loading should be faster (though this is simulated)
        self.assertLess(core_load_time, full_load_time)

    def test_18_2_4_config_validation_overhead(self):
        """Test overhead of config validation on load."""
        config_data = self._generate_large_config(num_entries=500)

        with open(self.config_path, "w") as f:
            json.dump(config_data, f)

        # Load without validation
        start_time = time.time()
        with open(self.config_path) as f:
            data = json.load(f)
        no_validation_time = time.time() - start_time

        # Load with validation (simulated)
        start_time = time.time()
        with open(self.config_path) as f:
            data = json.load(f)
            # Simulate validation
            self._validate_config_structure(data)
        with_validation_time = time.time() - start_time

        validation_overhead = with_validation_time - no_validation_time
        overhead_percent = (validation_overhead / no_validation_time) * 100

        print(f"\nValidation overhead:")
        print(f"  Without validation: {no_validation_time:.3f}s")
        print(f"  With validation: {with_validation_time:.3f}s")
        print(f"  Overhead: {validation_overhead:.3f}s ({overhead_percent:.1f}%)")

        # Validation overhead should be reasonable
        self.assertLess(overhead_percent, 50, "Validation overhead exceeds 50%")

    def _validate_config_structure(self, config: dict[str, Any]) -> bool:
        """Simulate config structure validation."""
        required_fields = ["version", "application"]
        for field in required_fields:
            if field not in config:
                return False

        # Simulate deep validation
        if "llm_configuration" in config:
            for model_id, model_config in config["llm_configuration"].get("models", {}).items():
                if "provider" not in model_config:
                    return False

        return True


if __name__ == "__main__":
    unittest.main(verbosity=2)
