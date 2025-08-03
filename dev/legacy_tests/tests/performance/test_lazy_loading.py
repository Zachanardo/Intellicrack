"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Test script for lazy loading functionality

This script demonstrates and tests the lazy loading system for LLM models.
"""

import os
import sys
import time
import unittest

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from intellicrack.ai.lazy_model_loader import (
        DefaultLoadingStrategy,
        LazyModelManager,
        LazyModelWrapper,
        SmartLoadingStrategy,
        configure_lazy_loading,
        get_lazy_manager,
    )
    from intellicrack.ai.llm_backends import LLMConfig, LLMManager, LLMProvider, OpenAIBackend
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure the project is properly set up")
    sys.exit(1)


class TestLazyLoading(unittest.TestCase):
    """Test lazy loading functionality."""

    def setUp(self):
        """Set up test cases."""
        self.config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-3.5-turbo",
            api_key="test-key-123"
        )

    def test_lazy_wrapper_creation(self):
        """Test creating lazy wrappers."""
        wrapper = LazyModelWrapper(
            backend_class=OpenAIBackend,
            config=self.config,
            preload=False
        )

        # Should not be loaded initially
        self.assertFalse(wrapper.is_loaded)
        self.assertFalse(wrapper.is_loading)
        self.assertFalse(wrapper.has_error)

        # Access count should be zero
        info = wrapper.get_info()
        self.assertEqual(info["access_count"], 0)
        self.assertEqual(info["model_name"], "gpt-3.5-turbo")

    def test_default_loading_strategy(self):
        """Test default loading strategy."""
        strategy = DefaultLoadingStrategy()

        # Should not preload anything
        self.assertFalse(strategy.should_preload(self.config))
        self.assertEqual(strategy.get_load_priority(self.config), 0)

    def test_smart_loading_strategy(self):
        """Test smart loading strategy."""
        strategy = SmartLoadingStrategy(
            preload_api_models=True,
            preload_small_models=True
        )

        # API models should be preloaded
        self.assertTrue(strategy.should_preload(self.config))

        # API models should have high priority
        priority = strategy.get_load_priority(self.config)
        self.assertGreater(priority, 50)

    def test_lazy_manager_registration(self):
        """Test registering models with lazy manager."""
        manager = LazyModelManager()

        wrapper = manager.register_model(
            model_id="test-model",
            backend_class=OpenAIBackend,
            config=self.config
        )

        self.assertIsInstance(wrapper, LazyModelWrapper)
        self.assertEqual(wrapper.config.model_name, "gpt-3.5-turbo")

        # Should be in manager's models
        self.assertIn("test-model", manager.models)

    def test_memory_management(self):
        """Test memory management features."""
        manager = LazyModelManager()
        manager.max_loaded_models = 2

        # Register multiple models
        for i in range(3):
            config = LLMConfig(
                provider=LLMProvider.OPENAI,
                model_name=f"test-model-{i}",
                api_key="test-key"
            )
            manager.register_model(f"model-{i}", OpenAIBackend, config)

        # Get model info
        info = manager.get_model_info()
        self.assertEqual(len(info), 3)

        # Test unloading
        success = manager.unload_model("model-0")
        self.assertTrue(success)

    def test_enhanced_llm_manager(self):
        """Test LLM manager with lazy loading."""
        manager = LLMManager(enable_lazy_loading=True)

        # Register a model with lazy loading
        success = manager.register_llm("test-llm", self.config, use_lazy_loading=True)
        self.assertTrue(success)

        # Should be in available LLMs
        available = manager.get_available_llms()
        self.assertIn("test-llm", available)

        # Get info about the model
        info = manager.get_llm_info("test-llm")
        self.assertIsNotNone(info)
        self.assertTrue(info.get("lazy_loaded", False))
        self.assertFalse(info.get("is_initialized", True))

        # Test memory usage
        memory_info = manager.get_memory_usage()
        self.assertIn("lazy_models", memory_info)
        self.assertIn("test-llm", memory_info["lazy_models"])

    def test_lazy_loading_configuration(self):
        """Test configuring lazy loading parameters."""
        manager = LLMManager(enable_lazy_loading=True)

        # Configure lazy loading
        manager.configure_lazy_loading(
            max_loaded_models=5,
            idle_unload_time=3600
        )

        if manager.lazy_manager:
            self.assertEqual(manager.lazy_manager.max_loaded_models, 5)
            self.assertEqual(manager.lazy_manager.idle_unload_time, 3600)

    def test_preload_functionality(self):
        """Test manual preloading."""
        manager = LLMManager(enable_lazy_loading=True)
        manager.register_llm("preload-test", self.config, use_lazy_loading=True)

        # Initially not loaded
        info = manager.get_llm_info("preload-test")
        self.assertFalse(info.get("is_initialized", True))

        # Preload should work (though backend may fail without real API key)
        # This tests the mechanism, not the actual loading
        wrapper = manager.lazy_wrappers.get("preload-test")
        self.assertIsNotNone(wrapper)

    def test_unload_functionality(self):
        """Test unloading models."""
        manager = LLMManager(enable_lazy_loading=True)
        manager.register_llm("unload-test", self.config, use_lazy_loading=True)

        # Unload the model
        success = manager.unload_llm("unload-test")
        self.assertTrue(success)

        # Should still be available but not loaded
        available = manager.get_available_llms()
        self.assertIn("unload-test", available)

        info = manager.get_llm_info("unload-test")
        self.assertFalse(info.get("is_initialized", True))

    def test_configure_lazy_loading(self):
        """Test configure_lazy_loading function."""
        # Configure with custom settings
        configure_lazy_loading(
            max_loaded_models=10,
            idle_unload_time=1800,
            preload_strategy="smart"
        )

        # Get the configured manager
        manager = get_lazy_manager()
        self.assertIsNotNone(manager)
        self.assertEqual(manager.max_loaded_models, 10)
        self.assertEqual(manager.idle_unload_time, 1800)
        self.assertIsInstance(manager.loading_strategy, SmartLoadingStrategy)

        # Test with default strategy
        configure_lazy_loading(
            max_loaded_models=5,
            preload_strategy="default"
        )

        manager = get_lazy_manager()
        self.assertEqual(manager.max_loaded_models, 5)
        self.assertIsInstance(manager.loading_strategy, DefaultLoadingStrategy)

    def test_get_lazy_manager(self):
        """Test get_lazy_manager function."""
        # Should create a default manager if none exists
        manager1 = get_lazy_manager()
        self.assertIsNotNone(manager1)
        self.assertIsInstance(manager1, LazyModelManager)

        # Should return the same instance
        manager2 = get_lazy_manager()
        self.assertIs(manager1, manager2)

        # After configuration, should still return same instance
        configure_lazy_loading(max_loaded_models=20)
        manager3 = get_lazy_manager()
        self.assertIs(manager1, manager3)
        self.assertEqual(manager3.max_loaded_models, 20)


def run_performance_test():
    """Run a performance test to demonstrate lazy loading benefits."""
    print("\n" + "="*60)
    print("LAZY LOADING PERFORMANCE DEMONSTRATION")
    print("="*60)

    # Test immediate loading
    print("\n1. Testing immediate loading...")
    start_time = time.time()

    immediate_manager = LLMManager(enable_lazy_loading=False)

    # Create multiple configs (these would normally fail without real API keys)
    configs = []
    for i in range(3):
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name=f"test-model-{i}",
            api_key="fake-key"
        )
        configs.append(config)

    immediate_time = time.time() - start_time
    print(f"Immediate manager creation: {immediate_time:.4f} seconds")

    # Test lazy loading
    print("\n2. Testing lazy loading...")
    start_time = time.time()

    lazy_manager = LLMManager(enable_lazy_loading=True)

    # Register the same models with lazy loading
    for i, config in enumerate(configs):
        lazy_manager.register_llm(f"lazy-model-{i}", config, use_lazy_loading=True)

    lazy_time = time.time() - start_time
    print(f"Lazy manager with 3 models: {lazy_time:.4f} seconds")

    # Show memory usage
    print("\n3. Memory usage comparison:")
    immediate_memory = immediate_manager.get_memory_usage()
    lazy_memory = lazy_manager.get_memory_usage()

    print(f"Immediate loading - Total loaded: {immediate_memory['total_loaded']}")
    print(f"Lazy loading - Total loaded: {lazy_memory['total_loaded']}")

    # Show lazy model info
    print("\n4. Lazy model details:")
    for model_id in lazy_manager.get_available_llms():
        info = lazy_manager.get_llm_info(model_id)
        if info and info.get("lazy_loaded"):
            print(f"  {model_id}: loaded={info.get('is_initialized')}, "
                  f"access_count={info.get('access_count', 0)}")

    print("\n5. Testing configuration...")
    lazy_manager.configure_lazy_loading(max_loaded_models=2, idle_unload_time=600)
    print("  Configured: max_models=2, idle_time=600s")

    print("\n" + "="*60)
    print("PERFORMANCE TEST COMPLETE")
    print("="*60)


def main():
    """Main test function."""
    print("Testing Intellicrack Lazy Loading System")
    print("=" * 50)

    # Run unit tests
    print("\nRunning unit tests...")
    unittest.main(verbosity=2, exit=False)

    # Run performance demonstration
    run_performance_test()


if __name__ == "__main__":
    main()
