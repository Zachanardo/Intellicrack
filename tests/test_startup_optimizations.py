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
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest


class FakeTensorFlowModule:
    """Real test double for TensorFlow module."""

    def __init__(self, version: str = "2.15.0") -> None:
        self.__version__ = version
        self.keras = FakeKerasModule()
        self.config = FakeConfigModule()
        self.call_log: List[str] = []

    def constant(self, data: Any) -> "FakeTensor":
        self.call_log.append("constant")
        return FakeTensor(data)

    def reduce_sum(self, tensor: "FakeTensor") -> "FakeTensor":
        self.call_log.append("reduce_sum")
        return FakeTensor(sum(self._flatten(tensor.data)))

    def _flatten(self, data: Any) -> List[float]:
        if isinstance(data, (int, float)):
            return [float(data)]
        result: List[float] = []
        for item in data:
            result.extend(self._flatten(item))
        return result


class FakeKerasModule:
    """Real test double for Keras module."""

    def __init__(self) -> None:
        self.layers = FakeLayersModule()
        self.models = FakeModelsModule()
        self.optimizers = FakeOptimizersModule()


class FakeLayersModule:
    """Real test double for Keras layers module."""

    def Dense(
        self, units: int, activation: Optional[str] = None
    ) -> "FakeDenseLayer":
        return FakeDenseLayer(units, activation)


class FakeModelsModule:
    """Real test double for Keras models module."""

    def Sequential(self, layers: List[Any]) -> "FakeSequentialModel":
        return FakeSequentialModel(layers)


class FakeOptimizersModule:
    """Real test double for Keras optimizers module."""

    pass


class FakeConfigModule:
    """Real test double for TensorFlow config module."""

    def __init__(self) -> None:
        self.experimental = FakeExperimentalConfig()


class FakeExperimentalConfig:
    """Real test double for TensorFlow experimental config."""

    def list_physical_devices(self, device_type: Optional[str] = None) -> List[Any]:
        return []


class FakeTensor:
    """Real test double for TensorFlow tensor."""

    def __init__(self, data: Any) -> None:
        self.data = data
        if isinstance(data, list):
            if data and isinstance(data[0], list):
                self.shape: tuple[int, ...] = (len(data), len(data[0]))
            else:
                self.shape = (len(data),)
        else:
            self.shape = ()

    def numpy(self) -> Any:
        return self.data

    def __add__(self, other: "FakeTensor") -> "FakeTensor":
        if isinstance(self.data, list) and isinstance(other.data, list):
            result = [a + b for a, b in zip(self.data, other.data)]
            return FakeTensor(result)
        return FakeTensor(self.data + other.data)

    def __mul__(self, scalar: float) -> "FakeTensor":
        if isinstance(self.data, list):
            result = [x * scalar for x in self.data]
            return FakeTensor(result)
        return FakeTensor(self.data * scalar)


class FakeDenseLayer:
    """Real test double for Keras Dense layer."""

    def __init__(self, units: int, activation: Optional[str] = None) -> None:
        self.units = units
        self.activation = activation
        self.weights: Optional[List[float]] = None
        self.bias: Optional[List[float]] = None

    def build(self, input_shape: Tuple[int, ...]) -> None:
        input_dim = input_shape[0] if isinstance(input_shape, tuple) else input_shape
        self.weights = [0.1] * (input_dim * self.units)
        self.bias = [0.0] * self.units

    def call(self, inputs: FakeTensor) -> FakeTensor:
        import math

        if self.weights is None or self.bias is None:
            raise ValueError("Layer must be built before calling")

        if isinstance(inputs.data, list) and isinstance(inputs.data[0], list):
            input_data = inputs.data[0]
        else:
            input_data = inputs.data if isinstance(inputs.data, list) else [inputs.data]

        output_data = []
        for i in range(self.units):
            value = self.bias[i]
            for j, inp in enumerate(input_data):
                if j * self.units + i < len(self.weights):
                    value += inp * self.weights[j * self.units + i]

            if self.activation == "relu":
                value = max(0.0, value)
            elif self.activation == "sigmoid":
                value = 1.0 / (1.0 + math.exp(-value))

            output_data.append(value)

        return FakeTensor(output_data)


class FakeSequentialModel:
    """Real test double for Keras Sequential model."""

    def __init__(self, layers: List[FakeDenseLayer]) -> None:
        self.layers = layers
        self.optimizer: Optional[str] = None
        self.loss: Optional[str] = None
        self.metrics: Optional[List[str]] = None

    def compile(
        self,
        optimizer: str,
        loss: str,
        metrics: Optional[List[str]] = None,
    ) -> None:
        self.optimizer = optimizer
        self.loss = loss
        self.metrics = metrics or []

    def predict(self, inputs: FakeTensor, verbose: int = 0) -> FakeTensor:
        current_output = inputs
        for layer in self.layers:
            if not hasattr(layer, "weights") or layer.weights is None:
                layer.build((len(current_output.data),))
            current_output = layer.call(current_output)
        return current_output


class FakeSafeTensorFlowImport:
    """Real test double for _safe_tensorflow_import function."""

    def __init__(
        self,
        should_succeed: bool = True,
        tf_version: str = "2.15.0",
    ) -> None:
        self.should_succeed = should_succeed
        self.tf_version = tf_version
        self.call_count = 0

    def __call__(self) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Exception]]:
        self.call_count += 1

        if not self.should_succeed:
            return (False, None, ImportError("Test import failure"))

        mock_tf = FakeTensorFlowModule(self.tf_version)
        return (
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


class FakeImportlib:
    """Real test double for importlib module."""

    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail

    def import_module(self, name: str) -> Any:
        if self.should_fail:
            raise ImportError("TensorFlow not available")
        return FakeTensorFlowModule()


class TestLazyTensorFlowLoading:
    """Test lazy loading of TensorFlow in tensorflow_handler."""

    def test_tensorflow_not_loaded_on_import(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that TensorFlow is not loaded when module is imported."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        env_vars = os.environ.copy()
        env_vars["INTELLICRACK_TESTING"] = "1"
        monkeypatch.setattr(os, "environ", env_vars)

        sys_modules = sys.modules.copy()
        sys_modules["tensorflow"] = FakeTensorFlowModule()  # type: ignore[assignment]
        monkeypatch.setattr(sys, "modules", sys_modules)

        from intellicrack.handlers import tensorflow_handler

        assert tensorflow_handler._tf_initialized is False
        assert tensorflow_handler.HAS_TENSORFLOW is False

    def test_ensure_tensorflow_loaded_called_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that ensure_tensorflow_loaded only loads TensorFlow once."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        env_vars = os.environ.copy()
        env_vars["INTELLICRACK_TESTING"] = "1"
        monkeypatch.setattr(os, "environ", env_vars)

        from intellicrack.handlers import tensorflow_handler

        tensorflow_handler._tf_initialized = False

        fake_import = FakeSafeTensorFlowImport(should_succeed=False)
        monkeypatch.setattr(tensorflow_handler, "_safe_tensorflow_import", fake_import)

        tensorflow_handler.ensure_tensorflow_loaded()
        tensorflow_handler.ensure_tensorflow_loaded()
        tensorflow_handler.ensure_tensorflow_loaded()

        assert fake_import.call_count == 1
        assert tensorflow_handler._tf_initialized

    def test_fallback_objects_available_when_tensorflow_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that fallback objects are available when TensorFlow is unavailable."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        env_vars = os.environ.copy()
        env_vars["INTELLICRACK_TESTING"] = "1"
        monkeypatch.setattr(os, "environ", env_vars)

        import importlib
        fake_importlib = FakeImportlib(should_fail=True)
        monkeypatch.setattr(importlib, "import_module", fake_importlib.import_module)

        from intellicrack.handlers import tensorflow_handler

        tensorflow_handler._tf_initialized = False
        tensorflow_handler.ensure_tensorflow_loaded()

        assert tensorflow_handler.tf is not None
        assert tensorflow_handler.tensorflow is not None  # type: ignore[attr-defined]
        assert tensorflow_handler.keras is not None  # type: ignore[attr-defined]
        assert tensorflow_handler.layers is not None  # type: ignore[attr-defined]
        assert tensorflow_handler.models is not None  # type: ignore[attr-defined]
        assert tensorflow_handler.optimizers is not None  # type: ignore[attr-defined]

        assert hasattr(tensorflow_handler.tf, "__version__")
        assert tensorflow_handler.tf.__version__ == "0.0.0-fallback"

    def test_fallback_tensor_operations_work(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that fallback tensor operations are functional."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        env_vars = os.environ.copy()
        env_vars["INTELLICRACK_TESTING"] = "1"
        monkeypatch.setattr(os, "environ", env_vars)

        from intellicrack.handlers import tensorflow_handler

        tensor = tensorflow_handler.tf.constant([[1.0, 2.0], [3.0, 4.0]])  # type: ignore[attr-defined]

        result = tensorflow_handler.tf.reduce_sum(tensor)  # type: ignore[attr-defined]

        assert hasattr(result, "numpy")
        result_value = result.numpy()
        assert abs(float(result_value) - 10.0) < 1e-6

    def test_tensorflow_variable_updated_on_successful_load(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that tensorflow variable is updated when TensorFlow loads successfully."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        env_vars = os.environ.copy()
        env_vars["INTELLICRACK_TESTING"] = "1"
        monkeypatch.setattr(os, "environ", env_vars)

        from intellicrack.handlers import tensorflow_handler

        fake_import = FakeSafeTensorFlowImport(should_succeed=True, tf_version="2.15.0")

        tensorflow_handler._tf_initialized = False
        monkeypatch.setattr(tensorflow_handler, "_safe_tensorflow_import", fake_import)

        tensorflow_handler.ensure_tensorflow_loaded()

        assert tensorflow_handler.tensorflow is not None  # type: ignore[attr-defined]
        assert tensorflow_handler.HAS_TENSORFLOW is True
        assert tensorflow_handler.TENSORFLOW_VERSION == "2.15.0"


class TestDuplicateValidationRemoval:
    """Test that duplicate validation has been removed."""

    def test_flask_validation_runs_once(self) -> None:
        """Test that Flask validation only runs once in check_dependencies."""
        from intellicrack.core import startup_checks

        assert not hasattr(startup_checks, "validate_flask_server")

    def test_llama_cpp_validation_runs_once(self) -> None:
        """Test that llama-cpp validation only runs once in check_dependencies."""
        from intellicrack.core import startup_checks

        assert not hasattr(startup_checks, "validate_llama_cpp")

    def test_perform_startup_checks_structure(self) -> None:
        """Test that perform_startup_checks has correct structure after optimization."""
        from intellicrack.core import startup_checks

        import inspect

        source = inspect.getsource(startup_checks.perform_startup_checks)

        assert "flask_validation" not in source or source.count("flask_validation") <= 1

        assert "llama_validation" not in source or source.count("llama_validation") <= 1


class TestFallbackFunctionality:
    """Test that fallback implementations provide real functionality."""

    def test_fallback_dense_layer_forward_pass(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that fallback dense layer can perform forward pass."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        env_vars = os.environ.copy()
        env_vars["INTELLICRACK_TESTING"] = "1"
        monkeypatch.setattr(os, "environ", env_vars)

        from intellicrack.handlers import tensorflow_handler

        layer = tensorflow_handler.layers.Dense(units=10, activation="relu")  # type: ignore[attr-defined]

        input_tensor = tensorflow_handler.tf.constant([[1.0, 2.0, 3.0, 4.0, 5.0]])  # type: ignore[attr-defined]

        layer.build((5,))
        output = layer.call(input_tensor)

        assert hasattr(output, "shape")
        assert output.shape == (10,)
        assert hasattr(output, "data")
        assert len(output.data) == 10

    def test_fallback_model_can_compile_and_predict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that fallback model can compile and make predictions."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        env_vars = os.environ.copy()
        env_vars["INTELLICRACK_TESTING"] = "1"
        monkeypatch.setattr(os, "environ", env_vars)

        from intellicrack.handlers import tensorflow_handler

        model = tensorflow_handler.models.Sequential(  # type: ignore[attr-defined]
            [
                tensorflow_handler.layers.Dense(64, activation="relu"),  # type: ignore[attr-defined]
                tensorflow_handler.layers.Dense(10, activation="sigmoid"),  # type: ignore[attr-defined]
            ]
        )

        model.compile(optimizer="adam", loss="categorical_crossentropy", metrics=["accuracy"])

        test_input = tensorflow_handler.tf.constant([[1.0] * 10])  # type: ignore[attr-defined]

        output = model.predict(test_input, verbose=0)

        assert hasattr(output, "shape")
        assert hasattr(output, "data")

    def test_fallback_tensor_mathematical_operations(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that fallback tensor supports mathematical operations."""
        if "intellicrack.handlers.tensorflow_handler" in sys.modules:
            del sys.modules["intellicrack.handlers.tensorflow_handler"]

        env_vars = os.environ.copy()
        env_vars["INTELLICRACK_TESTING"] = "1"
        monkeypatch.setattr(os, "environ", env_vars)

        from intellicrack.handlers import tensorflow_handler

        tensor1 = tensorflow_handler.tf.constant([1.0, 2.0, 3.0])  # type: ignore[attr-defined]
        tensor2 = tensorflow_handler.tf.constant([4.0, 5.0, 6.0])  # type: ignore[attr-defined]

        result_add = tensor1 + tensor2
        expected_add = [5.0, 7.0, 9.0]
        assert all(abs(a - b) < 1e-6 for a, b in zip(result_add.data, expected_add))

        result_mul = tensor1 * 2
        expected_mul = [2.0, 4.0, 6.0]
        assert all(abs(a - b) < 1e-6 for a, b in zip(result_mul.data, expected_mul))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
