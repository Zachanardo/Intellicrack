"""Tests for startup optimizations.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class TestLazyTensorFlowLoading:
    """Test lazy loading of TensorFlow in tensorflow_handler."""

    def test_tensorflow_not_loaded_on_import(self):
        """Test that TensorFlow is not loaded when module is imported."""
        # Clear any previous imports
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        with patch.dict(os.environ, {"INTELLICRACK_TESTING": "1"}):
            # Mock TensorFlow to track if it's imported
            with patch.dict(sys.modules, {"tensorflow": MagicMock()}):
                from intellicrack.handlers import tensorflow_handler

                # Verify module-level flag is False initially
                assert tensorflow_handler._tf_initialized is False
                assert tensorflow_handler.HAS_TENSORFLOW is False

    def test_ensure_tensorflow_loaded_called_once(self):
        """Test that ensure_tensorflow_loaded only loads TensorFlow once."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        with patch.dict(os.environ, {"INTELLICRACK_TESTING": "1"}):
            from intellicrack.handlers import tensorflow_handler

            # Reset initialization flag
            tensorflow_handler._tf_initialized = False

            # Mock the import function to track calls
            import_mock = MagicMock(return_value=(False, None, ImportError("Test")))
            tensorflow_handler._safe_tensorflow_import = import_mock

            # Call ensure_tensorflow_loaded multiple times
            tensorflow_handler.ensure_tensorflow_loaded()
            tensorflow_handler.ensure_tensorflow_loaded()
            tensorflow_handler.ensure_tensorflow_loaded()

            # Should only be called once
            assert import_mock.call_count == 1
            assert tensorflow_handler._tf_initialized

    def test_fallback_objects_available_when_tensorflow_unavailable(self):
        """Test that fallback objects are available when TensorFlow is unavailable."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        with patch.dict(os.environ, {"INTELLICRACK_TESTING": "1"}):
            # Mock TensorFlow import failure
            with patch("importlib.import_module", side_effect=ImportError("TensorFlow not available")):
                from intellicrack.handlers import tensorflow_handler

                tensorflow_handler._tf_initialized = False
                tensorflow_handler.ensure_tensorflow_loaded()

                # Verify fallback objects are assigned
                assert tensorflow_handler.tf is not None
                assert tensorflow_handler.tensorflow is not None
                assert tensorflow_handler.keras is not None
                assert tensorflow_handler.layers is not None
                assert tensorflow_handler.models is not None
                assert tensorflow_handler.optimizers is not None

                # Verify they are fallback types
                assert hasattr(tensorflow_handler.tf, "__version__")
                assert tensorflow_handler.tf.__version__ == "0.0.0-fallback"

    def test_fallback_tensor_operations_work(self):
        """Test that fallback tensor operations are functional."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        with patch.dict(os.environ, {"INTELLICRACK_TESTING": "1"}):
            from intellicrack.handlers import tensorflow_handler

            # Create fallback tensor
            tensor = tensorflow_handler.tf.constant([[1.0, 2.0], [3.0, 4.0]])

            # Test reduce_sum operation
            result = tensorflow_handler.tf.reduce_sum(tensor)

            # Verify result
            assert hasattr(result, "numpy")
            result_value = result.numpy()
            assert abs(float(result_value) - 10.0) < 1e-6

    def test_tensorflow_variable_updated_on_successful_load(self):
        """Test that tensorflow variable is updated when TensorFlow loads successfully."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        with patch.dict(os.environ, {"INTELLICRACK_TESTING": "1"}):
            from intellicrack.handlers import tensorflow_handler

            # Create mock TensorFlow module
            mock_tf = MagicMock()
            mock_tf.__version__ = "2.15.0"
            mock_tf.keras.layers = MagicMock()
            mock_tf.keras.models = MagicMock()
            mock_tf.keras.optimizers = MagicMock()
            mock_tf.config.experimental.list_physical_devices.return_value = []

            # Mock successful import
            import_mock = MagicMock(
                return_value=(
                    True,
                    {
                        "tf": mock_tf,
                        "keras": mock_tf.keras,
                        "layers": mock_tf.keras.layers,
                        "models": mock_tf.keras.models,
                        "optimizers": mock_tf.keras.optimizers,
                    },
                    None,
                )
            )

            tensorflow_handler._tf_initialized = False
            tensorflow_handler._safe_tensorflow_import = import_mock

            # Load TensorFlow
            tensorflow_handler.ensure_tensorflow_loaded()

            # Verify tensorflow variable is updated
            assert tensorflow_handler.tensorflow == mock_tf
            assert tensorflow_handler.HAS_TENSORFLOW is True
            assert tensorflow_handler.TENSORFLOW_VERSION == "2.15.0"


class TestDuplicateValidationRemoval:
    """Test that duplicate validation has been removed."""

    def test_flask_validation_runs_once(self):
        """Test that Flask validation only runs once in check_dependencies."""
        from intellicrack.core import startup_checks

        # Verify validate_flask_server function doesn't exist
        assert not hasattr(startup_checks, "validate_flask_server")

    def test_llama_cpp_validation_runs_once(self):
        """Test that llama-cpp validation only runs once in check_dependencies."""
        from intellicrack.core import startup_checks

        # Verify validate_llama_cpp function doesn't exist
        assert not hasattr(startup_checks, "validate_llama_cpp")

    def test_perform_startup_checks_structure(self):
        """Test that perform_startup_checks has correct structure after optimization."""
        from intellicrack.core import startup_checks

        # Get source code of perform_startup_checks
        import inspect

        source = inspect.getsource(startup_checks.perform_startup_checks)

        # Verify flask_validation is not in the results dict
        assert "flask_validation" not in source or source.count("flask_validation") <= 1

        # Verify llama_validation is not in the results dict
        assert "llama_validation" not in source or source.count("llama_validation") <= 1


class TestFallbackFunctionality:
    """Test that fallback implementations provide real functionality."""

    def test_fallback_dense_layer_forward_pass(self):
        """Test that fallback dense layer can perform forward pass."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        with patch.dict(os.environ, {"INTELLICRACK_TESTING": "1"}):
            from intellicrack.handlers import tensorflow_handler

            # Create dense layer
            layer = tensorflow_handler.layers.Dense(units=10, activation="relu")

            # Create input tensor
            input_tensor = tensorflow_handler.tf.constant([[1.0, 2.0, 3.0, 4.0, 5.0]])

            # Build and call layer
            layer.build((5,))
            output = layer.call(input_tensor)

            # Verify output shape
            assert hasattr(output, "shape")
            assert output.shape == (10,)
            assert hasattr(output, "data")
            assert len(output.data) == 10

    def test_fallback_model_can_compile_and_predict(self):
        """Test that fallback model can compile and make predictions."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        with patch.dict(os.environ, {"INTELLICRACK_TESTING": "1"}):
            from intellicrack.handlers import tensorflow_handler

            # Create model
            model = tensorflow_handler.models.Sequential(
                [
                    tensorflow_handler.layers.Dense(64, activation="relu"),
                    tensorflow_handler.layers.Dense(10, activation="sigmoid"),
                ]
            )

            # Compile model
            model.compile(optimizer="adam", loss="categorical_crossentropy", metrics=["accuracy"])

            # Create test input
            test_input = tensorflow_handler.tf.constant([[1.0] * 10])

            # Make prediction
            output = model.predict(test_input, verbose=0)

            # Verify output
            assert hasattr(output, "shape")
            assert hasattr(output, "data")

    def test_fallback_tensor_mathematical_operations(self):
        """Test that fallback tensor supports mathematical operations."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        with patch.dict(os.environ, {"INTELLICRACK_TESTING": "1"}):
            from intellicrack.handlers import tensorflow_handler

            # Create tensors
            tensor1 = tensorflow_handler.tf.constant([1.0, 2.0, 3.0])
            tensor2 = tensorflow_handler.tf.constant([4.0, 5.0, 6.0])

            # Test addition
            result_add = tensor1 + tensor2
            expected_add = [5.0, 7.0, 9.0]
            assert all(abs(a - b) < 1e-6 for a, b in zip(result_add.data, expected_add))

            # Test scalar multiplication
            result_mul = tensor1 * 2
            expected_mul = [2.0, 4.0, 6.0]
            assert all(abs(a - b) < 1e-6 for a, b in zip(result_mul.data, expected_mul))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
