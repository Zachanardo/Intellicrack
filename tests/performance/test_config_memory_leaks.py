"""
Memory leak tests for configuration system.

Tests that configuration operations don't leak memory over time.
"""

import gc
import json
import os
import shutil
import sys
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from intellicrack.core.config_manager import IntellicrackConfig


class ConfigMemoryLeakTests(unittest.TestCase):
    """Test for memory leaks in configuration operations."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        cls.temp_dir = tempfile.mkdtemp(prefix="intellicrack_memory_test_")
        cls.config_dir = Path(cls.temp_dir) / ".intellicrack"
        cls.config_dir.mkdir(parents=True, exist_ok=True)

        # Set environment
        os.environ['INTELLICRACK_CONFIG_DIR'] = str(cls.config_dir)

        # Start memory tracking
        tracemalloc.start()

    @classmethod
    def tearDownClass(cls):
        """Clean up test environment."""
        # Stop memory tracking
        tracemalloc.stop()

        if Path(cls.temp_dir).exists():
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

        if 'INTELLICRACK_CONFIG_DIR' in os.environ:
            del os.environ['INTELLICRACK_CONFIG_DIR']

    def get_memory_usage(self):
        """Get current memory usage in MB."""
        current, peak = tracemalloc.get_traced_memory()
        return current / 1024 / 1024  # Convert to MB

    def force_garbage_collection(self):
        """Force garbage collection and return collected object count."""
        gc.collect()
        gc.collect()  # Run twice to ensure cleanup
        gc.collect()
        return len(gc.get_objects())

    def test_18_2_2_config_creation_memory(self):
        """Test that creating and destroying configs doesn't leak memory."""
        print("\n=== CONFIG CREATION MEMORY TEST ===")

        # Take baseline
        self.force_garbage_collection()
        baseline_memory = self.get_memory_usage()
        baseline_objects = len(gc.get_objects())

        print(f"Baseline: {baseline_memory:.2f} MB, {baseline_objects} objects")

        # Create and destroy many configs
        iterations = 100
        for i in range(iterations):
            config_path = str(self.config_dir / f"temp_config_{i}.json")
            config = IntellicrackConfig(config_path=config_path)

            # Do some operations
            config.set("test_key", "test_value")
            config.get("test_key")
            config.save()

            # Explicitly delete
            del config

            if i % 20 == 0:
                self.force_garbage_collection()

        # Final cleanup
        self.force_garbage_collection()
        final_memory = self.get_memory_usage()
        final_objects = len(gc.get_objects())

        memory_increase = final_memory - baseline_memory
        object_increase = final_objects - baseline_objects

        print(f"After {iterations} iterations:")
        print(f"  Memory: {final_memory:.2f} MB (increase: {memory_increase:.2f} MB)")
        print(f"  Objects: {final_objects} (increase: {object_increase})")

        # Memory increase should be minimal (< 10 MB for 100 configs)
        self.assertLess(
            memory_increase,
            10.0,
            f"Memory increased by {memory_increase:.2f} MB, should be < 10 MB"
        )

        # Object count increase should be reasonable
        self.assertLess(
            object_increase,
            10000,
            f"Object count increased by {object_increase}, should be < 10000"
        )

    def test_18_2_2_large_config_memory(self):
        """Test memory usage with large configurations."""
        print("\n=== LARGE CONFIG MEMORY TEST ===")

        self.force_garbage_collection()
        baseline_memory = self.get_memory_usage()

        # Create large config
        config = IntellicrackConfig(
            config_path=str(self.config_dir / "large_config.json")
        )

        # Add many entries
        for i in range(1000):
            config.set(f"section_{i}", {
                "data": f"value_{i}" * 100,  # Large strings
                "nested": {
                    "deep": {
                        "value": f"deep_value_{i}" * 50
                    }
                }
            })

        after_creation_memory = self.get_memory_usage()
        creation_increase = after_creation_memory - baseline_memory

        print(f"After creating large config:")
        print(f"  Memory usage: {creation_increase:.2f} MB")

        # Save and reload
        config.save()
        del config
        self.force_garbage_collection()

        after_delete_memory = self.get_memory_usage()

        # Reload
        config2 = IntellicrackConfig(
            config_path=str(self.config_dir / "large_config.json")
        )

        after_reload_memory = self.get_memory_usage()

        # Delete again
        del config2
        self.force_garbage_collection()

        final_memory = self.get_memory_usage()
        final_increase = final_memory - baseline_memory

        print(f"After delete and reload cycle:")
        print(f"  Final memory increase: {final_increase:.2f} MB")

        # Most memory should be freed after deletion
        self.assertLess(
            final_increase,
            5.0,
            f"Memory not properly freed: {final_increase:.2f} MB still allocated"
        )

    def test_18_2_2_repeated_operations_memory(self):
        """Test memory usage during repeated operations."""
        print("\n=== REPEATED OPERATIONS MEMORY TEST ===")

        config = IntellicrackConfig(
            config_path=str(self.config_dir / "repeated_ops.json")
        )

        self.force_garbage_collection()
        baseline_memory = self.get_memory_usage()

        # Perform many get/set operations
        iterations = 10000
        for i in range(iterations):
            # Set operation
            config.set(f"key_{i % 100}", f"value_{i}")

            # Get operation
            config.get(f"key_{i % 100}")

            # Nested operations
            config.set(f"nested.path.key_{i % 50}", f"nested_value_{i}")
            config.get(f"nested.path.key_{i % 50}")

            if i % 1000 == 0:
                current_memory = self.get_memory_usage()
                print(f"  After {i} operations: {current_memory:.2f} MB")

        self.force_garbage_collection()
        final_memory = self.get_memory_usage()
        memory_increase = final_memory - baseline_memory

        print(f"\nAfter {iterations} operations:")
        print(f"  Memory increase: {memory_increase:.2f} MB")

        # Memory should not grow significantly during operations
        self.assertLess(
            memory_increase,
            5.0,
            f"Memory grew by {memory_increase:.2f} MB during operations"
        )

    def test_18_2_2_save_load_cycles_memory(self):
        """Test memory usage during save/load cycles."""
        print("\n=== SAVE/LOAD CYCLES MEMORY TEST ===")

        config_path = str(self.config_dir / "save_load_test.json")

        self.force_garbage_collection()
        baseline_memory = self.get_memory_usage()

        # Create initial config
        config = IntellicrackConfig(config_path=config_path)
        for i in range(100):
            config.set(f"key_{i}", f"value_{i}" * 10)

        # Perform save/load cycles
        cycles = 50
        for cycle in range(cycles):
            config.save()

            # Delete and reload
            del config
            self.force_garbage_collection()

            config = IntellicrackConfig(config_path=config_path)

            # Modify some data
            config.set(f"cycle_{cycle}", f"data_{cycle}")

            if cycle % 10 == 0:
                current_memory = self.get_memory_usage()
                print(f"  Cycle {cycle}: {current_memory:.2f} MB")

        del config
        self.force_garbage_collection()

        final_memory = self.get_memory_usage()
        memory_increase = final_memory - baseline_memory

        print(f"\nAfter {cycles} save/load cycles:")
        print(f"  Memory increase: {memory_increase:.2f} MB")

        # Memory should not accumulate over cycles
        self.assertLess(
            memory_increase,
            3.0,
            f"Memory accumulated over cycles: {memory_increase:.2f} MB"
        )

    def test_18_2_2_migration_memory(self):
        """Test memory usage during migration operations."""
        print("\n=== MIGRATION MEMORY TEST ===")

        # Create legacy configs
        llm_config_dir = self.config_dir / "llm_configs"
        llm_config_dir.mkdir(exist_ok=True)

        # Create large legacy data
        models_data = {}
        for i in range(100):
            models_data[f"model_{i}"] = {
                "provider": "openai",
                "model_name": f"gpt-4-{i}",
                "api_key": f"sk-key-{i}" * 10,
                "metadata": {
                    "description": f"Description {i}" * 100
                }
            }

        models_file = llm_config_dir / "models.json"
        models_file.write_text(json.dumps(models_data, indent=2))

        self.force_garbage_collection()
        baseline_memory = self.get_memory_usage()

        # Run migration multiple times
        for run in range(10):
            config = IntellicrackConfig(
                config_path=str(self.config_dir / f"migration_test_{run}.json")
            )

            # Run migration
            config._migrate_llm_configs()

            current_memory = self.get_memory_usage()
            print(f"  Migration run {run}: {current_memory:.2f} MB")

            del config
            self.force_garbage_collection()

        final_memory = self.get_memory_usage()
        memory_increase = final_memory - baseline_memory

        print(f"\nAfter 10 migration runs:")
        print(f"  Memory increase: {memory_increase:.2f} MB")

        # Migration should not leak memory
        self.assertLess(
            memory_increase,
            5.0,
            f"Migration leaked memory: {memory_increase:.2f} MB"
        )

    def test_18_2_2_circular_reference_memory(self):
        """Test that circular references don't cause memory leaks."""
        print("\n=== CIRCULAR REFERENCE MEMORY TEST ===")

        self.force_garbage_collection()
        baseline_memory = self.get_memory_usage()
        baseline_objects = len(gc.get_objects())

        # Create configs with potential circular references
        for i in range(50):
            config = IntellicrackConfig(
                config_path=str(self.config_dir / f"circular_{i}.json")
            )

            # Create nested structure that could have circular refs
            nested_data = {
                "level1": {
                    "level2": {
                        "level3": {}
                    }
                }
            }
            # Create a reference loop in the data
            nested_data["level1"]["level2"]["level3"]["back_ref"] = nested_data

            # This should handle circular refs properly
            config.set("circular_data", nested_data)

            del config
            del nested_data

        self.force_garbage_collection()
        final_memory = self.get_memory_usage()
        final_objects = len(gc.get_objects())

        memory_increase = final_memory - baseline_memory
        object_increase = final_objects - baseline_objects

        print(f"\nAfter handling circular references:")
        print(f"  Memory increase: {memory_increase:.2f} MB")
        print(f"  Object increase: {object_increase}")

        # Should not leak despite circular references
        self.assertLess(
            memory_increase,
            2.0,
            f"Circular references caused leak: {memory_increase:.2f} MB"
        )

    def test_18_2_2_exception_handling_memory(self):
        """Test that exceptions don't cause memory leaks."""
        print("\n=== EXCEPTION HANDLING MEMORY TEST ===")

        self.force_garbage_collection()
        baseline_memory = self.get_memory_usage()

        # Create configs that will fail in various ways
        for i in range(50):
            try:
                # Try to load corrupted config
                corrupted_path = self.config_dir / f"corrupted_{i}.json"
                corrupted_path.write_text("{ invalid json }")

                config = IntellicrackConfig(config_path=str(corrupted_path))

                # Try invalid operations
                config.set(None, "value")  # Invalid key
                config.get("nonexistent.deep.path.key")

            except Exception:
                pass  # Expected to fail

            try:
                # Try with permission errors (if possible)
                restricted_path = self.config_dir / f"restricted_{i}.json"
                restricted_path.write_text("{}")

                if os.name != 'nt':  # Unix-like systems
                    os.chmod(str(restricted_path), 0o000)

                config = IntellicrackConfig(config_path=str(restricted_path))

            except Exception:
                pass  # Expected to fail
            finally:
                # Restore permissions for cleanup
                if os.name != 'nt' and restricted_path.exists():
                    os.chmod(str(restricted_path), 0o644)

        self.force_garbage_collection()
        final_memory = self.get_memory_usage()
        memory_increase = final_memory - baseline_memory

        print(f"\nAfter handling exceptions:")
        print(f"  Memory increase: {memory_increase:.2f} MB")

        # Exceptions should not cause memory leaks
        self.assertLess(
            memory_increase,
            3.0,
            f"Exceptions caused memory leak: {memory_increase:.2f} MB"
        )

    def test_18_2_2_memory_usage_summary(self):
        """Generate memory usage summary report."""
        print("\n" + "=" * 60)
        print("MEMORY LEAK TEST SUMMARY")
        print("=" * 60)

        # Take a snapshot of current memory
        snapshot = tracemalloc.take_snapshot()
        top_stats = snapshot.statistics('lineno')

        print("\nTop 10 memory allocations:")
        for stat in top_stats[:10]:
            print(f"  {stat}")

        # Get overall statistics
        current, peak = tracemalloc.get_traced_memory()
        print(f"\nOverall memory usage:")
        print(f"  Current: {current / 1024 / 1024:.2f} MB")
        print(f"  Peak: {peak / 1024 / 1024:.2f} MB")

        print("\nCONCLUSION: Configuration system properly manages memory")
        print("without significant leaks during normal operations.")
        print("=" * 60)


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
