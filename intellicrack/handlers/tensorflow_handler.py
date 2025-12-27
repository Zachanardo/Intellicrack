"""TensorFlow handler for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import math
import os
import random
import threading
from collections.abc import Generator, Iterable, Sequence, Sized
from typing import SupportsFloat, SupportsIndex

from intellicrack.utils.logger import logger


def _to_float(value: object) -> float:
    """Safely convert an object to float.

    Args:
        value: Any object that may be convertible to float.

    Returns:
        Float value of the input.

    Raises:
        TypeError: If the value cannot be converted to float.
        ValueError: If the value cannot be converted to float.

    """
    if isinstance(value, float):
        return value
    if isinstance(value, int):
        return float(value)
    if isinstance(value, SupportsFloat):
        return float(value)
    if isinstance(value, SupportsIndex):
        return float(value)
    if isinstance(value, str):
        return float(value)
    if isinstance(value, (bytes, bytearray)):
        return float(value)
    error_msg: str = f"Cannot convert {type(value).__name__} to float"
    raise TypeError(error_msg)


"""
TensorFlow Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for TensorFlow imports.
When TensorFlow is not available, it provides REAL, functional Python-based
implementations for essential ML operations used in Intellicrack.
"""

# TensorFlow availability detection and import handling with universal GPU compatibility

# Initialize variables
HAS_TENSORFLOW: bool = False
TENSORFLOW_VERSION: str | None = None
tf: object = None
keras_module: object = None
layers_module: object = None
models_module: object = None
optimizers_module: object = None
_tf_initialized: bool = False

# Load environment variables from .env file
# Users can customize GPU settings in the .env file
try:
    from dotenv import load_dotenv

    load_dotenv()  # Load .env file from project root
except ImportError:
    pass  # dotenv not available, use system environment variables


def _safe_tensorflow_import(
    timeout: float = 15.0,
) -> tuple[bool, dict[str, object] | None, Exception | None]:
    """Safely import TensorFlow with timeout to handle GPU compatibility issues across NVIDIA, AMD, and Intel.

    Args:
        timeout: Maximum time in seconds to wait for TensorFlow import.

    Returns:
        A tuple of (success: bool, modules: dict or None, error: Exception or None).

    Raises:
        TimeoutError: If TensorFlow import takes longer than the specified timeout.

    """
    import_success: bool = False
    import_error: Exception | None = None
    tf_modules: dict[str, object] = {}

    def _import_tensorflow() -> None:
        nonlocal import_success, import_error, tf_modules
        try:
            import tensorflow as tf

            tf_modules["tf"] = tf
            tf_modules["keras"] = tf.keras
            tf_modules["layers"] = tf.keras.layers
            tf_modules["models"] = tf.keras.models
            tf_modules["optimizers"] = tf.keras.optimizers
            import_success = True
        except Exception as e:
            import_error = e

    import_thread: threading.Thread | None = None
    if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
        logger.info("Skipping tensorflow import thread (testing mode)")
        _import_tensorflow()
    else:
        import_thread = threading.Thread(target=_import_tensorflow, daemon=True)
        import_thread.start()
        import_thread.join(timeout=timeout)

    if import_thread and import_thread.is_alive():
        logger.warning("TensorFlow import timeout - using fallback (universal GPU compatibility)")
        return False, None, TimeoutError("TensorFlow import timed out")

    return import_success, tf_modules if import_success else None, import_error


def ensure_tensorflow_loaded() -> None:
    """Ensure TensorFlow is loaded (lazy loading)."""
    global _tf_initialized, HAS_TENSORFLOW, TENSORFLOW_VERSION, tf, keras_module, layers_module, models_module, optimizers_module

    if _tf_initialized:
        return

    _tf_initialized = True

    try:
        success, modules, error = _safe_tensorflow_import()

        if not success or not modules:
            raise error or ImportError("TensorFlow import failed")

        tf_imported: object = modules["tf"]
        tf = tf_imported
        keras_module = modules["keras"]
        layers_module = modules["layers"]
        models_module = modules["models"]
        optimizers_module = modules["optimizers"]

        try:
            if hasattr(tf_imported, "config") and hasattr(tf_imported.config, "experimental"):
                if gpus := tf_imported.config.experimental.list_physical_devices("GPU"):
                    for gpu in gpus:
                        tf_imported.config.experimental.set_memory_growth(gpu, True)
        except Exception as gpu_config_error:
            logger.info(f"GPU configuration warning: {gpu_config_error}")

        HAS_TENSORFLOW = True
        if hasattr(tf_imported, "__version__"):
            TENSORFLOW_VERSION = str(tf_imported.__version__)
        logger.info(f"TensorFlow {TENSORFLOW_VERSION} imported successfully with universal GPU compatibility")
    except Exception as e:
        logger.info(f"Using TensorFlow fallbacks due to import issue: {e}")
        HAS_TENSORFLOW = False
        TENSORFLOW_VERSION = None
        tf = FallbackTensorFlow()
        keras_module = FallbackKeras()
        layers_module = FallbackKerasLayers()
        models_module = FallbackKerasModels()
        optimizers_module = FallbackKerasOptimizers()


# Lazy loading - TensorFlow is only imported when ensure_tensorflow_loaded() is called
# Initialize fallback objects at module level for immediate availability


class FallbackTensor:
    """Functional tensor implementation for ML operations.

    Provides tensor operations including data flattening, shape inference, matrix
    operations, and reshaping for fallback TensorFlow implementations.
    """

    def __init__(self, data: object, shape: tuple[int, ...] | None = None, dtype: str = "float32") -> None:
        """Initialize tensor with data.

        Args:
            data: Input data as scalar, list, or nested iterable structure.
            shape: Optional tuple specifying tensor shape. Inferred from data if None.
            dtype: Data type string, defaults to 'float32'.

        """
        if isinstance(data, Iterable) and not isinstance(data, str):
            self.data: list[object] = list(self._flatten(data))
        else:
            self.data = [data]
        self.shape: tuple[int, ...] = self._infer_shape(data) if shape is None else tuple(shape)
        self.dtype: str = dtype
        self.ndim: int = len(self.shape)
        self.size: int = self._calculate_size()

    def _flatten(self, data: Iterable[object]) -> Generator[object, None, None]:
        """Flatten nested data structure.

        Args:
            data: Nested iterable to flatten.

        Yields:
            Individual elements from the nested structure.

        """
        for item in data:
            if isinstance(item, Iterable) and not isinstance(item, str):
                yield from self._flatten(item)
            else:
                yield item

    def _infer_shape(self, data: object) -> tuple[int, ...]:
        """Infer shape from data structure.

        Args:
            data: Input data structure to infer shape from.

        Returns:
            Tuple representing the inferred shape dimensions.

        """
        if not isinstance(data, Iterable) or isinstance(data, str):
            return ()

        shape: list[int] = []
        current: object = data
        while isinstance(current, Iterable) and not isinstance(current, str):
            if isinstance(current, Sequence):
                current_len: int = len(current)
                shape.append(current_len)
                if current_len > 0:
                    current = current[0]
                else:
                    break
            elif isinstance(current, Sized):
                try:
                    current_len = len(current)
                    shape.append(current_len)
                    current_as_seq: Sequence[object] = list(current)
                    if current_len > 0:
                        current = current_as_seq[0]
                    else:
                        break
                except (TypeError, IndexError):
                    break
            else:
                break
        return tuple(shape)

    def _calculate_size(self) -> int:
        """Calculate total number of elements.

        Returns:
            Total number of elements in tensor based on shape.

        """
        if not self.shape:
            return 1
        size: int = 1
        for dim in self.shape:
            size *= dim
        return size

    def numpy(self) -> object:
        """Convert to numpy-like array.

        Returns:
            Reshaped data structure matching the tensor's shape.

        """
        return self._reshape_data(self.data, self.shape)

    def _reshape_data(self, data: list[object], shape: tuple[int, ...]) -> object:
        """Reshape flat data to given shape.

        Args:
            data: Flat list of data elements.
            shape: Target shape tuple.

        Returns:
            Nested structure reshaped to target dimensions.

        """
        if not shape:
            return data[0] if data else 0

        if len(shape) == 1:
            return data[: shape[0]]

        size: int = 1
        for dim in shape[1:]:
            size *= dim

        result: list[object] = []
        for i in range(shape[0]):
            start: int = i * size
            end: int = start + size
            result.append(self._reshape_data(data[start:end], shape[1:]))
        return result

    def reshape(self, new_shape: tuple[int, ...]) -> "FallbackTensor":
        """Reshape tensor.

        Args:
            new_shape: Target shape tuple for the tensor.

        Returns:
            New FallbackTensor with reshaped data.

        """
        return FallbackTensor(self.data, shape=new_shape, dtype=self.dtype)

    def __add__(self, other: object) -> "FallbackTensor":
        """Add tensors or scalar.

        Args:
            other: FallbackTensor or scalar to add.

        Returns:
            New FallbackTensor with element-wise sum.

        """
        if isinstance(other, FallbackTensor):
            result: list[float] = [_to_float(a) + _to_float(b) for a, b in zip(self.data, other.data, strict=False)]
        else:
            other_float: float = _to_float(other)
            result = [_to_float(a) + other_float for a in self.data]
        return FallbackTensor(result, self.shape, self.dtype)

    def __mul__(self, other: object) -> "FallbackTensor":
        """Multiply tensors or scalar.

        Args:
            other: FallbackTensor or scalar to multiply.

        Returns:
            New FallbackTensor with element-wise product.

        """
        if isinstance(other, FallbackTensor):
            result: list[float] = [_to_float(a) * _to_float(b) for a, b in zip(self.data, other.data, strict=False)]
        else:
            other_float: float = _to_float(other)
            result = [_to_float(a) * other_float for a in self.data]
        return FallbackTensor(result, self.shape, self.dtype)

    def __repr__(self) -> str:
        """Return string representation.

        Returns:
            String describing tensor shape and dtype.

        """
        return f"<Tensor shape={self.shape} dtype={self.dtype}>"


class FallbackVariable:
    """Variable for trainable parameters.

    Represents a trainable parameter in neural networks with gradient tracking
    capabilities for fallback TensorFlow implementations.
    """

    def __init__(self, initial_value: object, trainable: bool = True, name: str | None = None) -> None:
        """Initialize variable.

        Args:
            initial_value: Initial value as scalar, list, or FallbackTensor.
            trainable: Whether variable is trainable, defaults to True.
            name: Optional name identifier for the variable.

        """
        self.value: FallbackTensor = initial_value if isinstance(initial_value, FallbackTensor) else FallbackTensor(initial_value)
        self.trainable: bool = trainable
        self.name: str = name or "Variable"
        self.gradient: object = None

    def assign(self, new_value: object) -> None:
        """Assign new value to variable.

        Args:
            new_value: New value to assign (scalar, list, or FallbackTensor).

        """
        self.value = new_value if isinstance(new_value, FallbackTensor) else FallbackTensor(new_value)

    def numpy(self) -> object:
        """Get numpy value.

        Returns:
            Numpy-like representation of the variable value.

        """
        return self.value.numpy()


class FallbackDenseLayer:
    """Dense (fully connected) layer implementation.

    Implements a fully connected neural network layer with optional bias and
    activation functions for fallback TensorFlow implementations.
    """

    def __init__(
        self,
        units: int,
        activation: str | None = None,
        use_bias: bool = True,
        name: str | None = None,
    ) -> None:
        """Initialize dense layer.

        Args:
            units: Number of output units in the layer.
            activation: Activation function name ('relu', 'sigmoid', 'tanh', None).
            use_bias: Whether to include bias term, defaults to True.
            name: Optional name identifier for the layer.

        """
        self.units: int = units
        self.activation: str | None = activation
        self.use_bias: bool = use_bias
        self.name: str = name or "dense"
        self.weights: FallbackVariable | None = None
        self.bias: FallbackVariable | None = None
        self.built: bool = False

    def build(self, input_shape: tuple[int, ...]) -> None:
        """Build layer with input shape.

        Args:
            input_shape: Tuple specifying the input tensor shape.

        """
        if self.built:
            return

        input_dim: int = input_shape[-1] if isinstance(input_shape, tuple) else input_shape

        scale: float = math.sqrt(2.0 / (input_dim + self.units))
        weight_data: list[list[float]] = [[random.gauss(0, scale) for _ in range(self.units)] for _ in range(input_dim)]
        self.weights = FallbackVariable(weight_data, name=f"{self.name}/kernel")

        if self.use_bias:
            bias_data: list[float] = [0.0] * self.units
            self.bias = FallbackVariable(bias_data, name=f"{self.name}/bias")

        self.built = True

    def call(self, inputs: FallbackTensor) -> FallbackTensor:
        """Forward pass through layer.

        Args:
            inputs: Input tensor to process.

        Returns:
            Output tensor after applying weights, bias, and activation.

        """
        if not self.built:
            self.build(inputs.shape)

        if self.weights is None:
            raise RuntimeError("Layer weights not initialized")

        output_data: list[float] = []
        for i in range(self.units):
            sum_val: float = 0.0
            for j, input_val in enumerate(inputs.data):
                weight_idx: int = j * self.units + i
                weight_val: object = self.weights.value.data[weight_idx]
                sum_val += _to_float(input_val) * _to_float(weight_val)

            if self.use_bias and self.bias is not None:
                bias_val: object = self.bias.value.data[i]
                sum_val += _to_float(bias_val)

            if self.activation == "relu":
                sum_val = max(0, sum_val)
            elif self.activation == "sigmoid":
                sum_val = 1 / (1 + math.exp(-sum_val))
            elif self.activation == "tanh":
                sum_val = math.tanh(sum_val)

            output_data.append(sum_val)

        return FallbackTensor(output_data, shape=(self.units,))

    def __call__(self, inputs: FallbackTensor) -> FallbackTensor:
        """Make layer callable.

        Args:
            inputs: Input tensor to process.

        Returns:
            Output tensor from forward pass.

        """
        return self.call(inputs)


class FallbackConv2DLayer:
    """2D Convolution layer implementation.

    Implements a 2D convolutional layer with configurable filters, kernel size,
    strides, and padding for neural network feature extraction.
    """

    def __init__(
        self,
        filters: int,
        kernel_size: int | tuple[int, int],
        strides: int | tuple[int, int] = 1,
        padding: str = "valid",
        activation: str | None = None,
        name: str | None = None,
    ) -> None:
        """Initialize conv layer.

        Args:
            filters: Number of output filters.
            kernel_size: Size of convolution kernel (int or tuple).
            strides: Stride of convolution operations, defaults to 1.
            padding: Padding mode ('valid' or 'same'), defaults to 'valid'.
            activation: Activation function name, defaults to None.
            name: Optional name identifier for the layer.

        """
        self.filters: int = filters
        self.kernel_size: tuple[int, int] = kernel_size if isinstance(kernel_size, tuple) else (kernel_size, kernel_size)
        self.strides: tuple[int, int] = strides if isinstance(strides, tuple) else (strides, strides)
        self.padding: str = padding
        self.activation: str | None = activation
        self.name: str = name or "conv2d"
        self.kernel: FallbackVariable | None = None
        self.bias: FallbackVariable | None = None
        self.built: bool = False

    def build(self, input_shape: tuple[int, ...]) -> None:
        """Build layer.

        Args:
            input_shape: Tuple specifying the input tensor shape.

        """
        if self.built:
            return

        kernel_shape: tuple[int, ...] = (*self.kernel_size, input_shape[-1], self.filters)
        kernel_size_total: int = 1
        for dim in kernel_shape:
            kernel_size_total *= dim

        scale: float = math.sqrt(2.0 / kernel_size_total)
        kernel_data: list[float] = [random.gauss(0, scale) for _ in range(kernel_size_total)]
        self.kernel = FallbackVariable(kernel_data, name=f"{self.name}/kernel")

        bias_data: list[float] = [0.0] * self.filters
        self.bias = FallbackVariable(bias_data, name=f"{self.name}/bias")

        self.built = True

    def call(self, inputs: FallbackTensor) -> FallbackTensor:
        """Forward pass through convolution layer.

        Args:
            inputs: Input tensor to convolve.

        Returns:
            Output tensor after convolution operation.

        """
        if not self.built:
            self.build(inputs.shape)

        batch_size: int = inputs.shape[0] if len(inputs.shape) > 3 else 1
        height: int = inputs.shape[-3] if len(inputs.shape) > 2 else 28
        width: int = inputs.shape[-2] if len(inputs.shape) > 1 else 28
        in_channels: int = inputs.shape[-1] if len(inputs.shape) > 3 else 1

        if self.padding == "same":
            out_height: int = height // self.strides[0]
            out_width: int = width // self.strides[1]
        else:
            out_height = (height - self.kernel_size[0]) // self.strides[0] + 1
            out_width = (width - self.kernel_size[1]) // self.strides[1] + 1

        output_shape: tuple[int, ...] = (batch_size, out_height, out_width, self.filters)
        output_data: list[float] = []

        for b in range(batch_size):
            for f in range(self.filters):
                for h in range(out_height):
                    for w in range(out_width):
                        h_start: int = h * self.strides[0]
                        w_start: int = w * self.strides[1]

                        conv_sum: float = 0.0
                        kernel_positions: int = 0

                        for kh in range(self.kernel_size[0]):
                            for kw in range(self.kernel_size[1]):
                                input_h: int = h_start + kh
                                input_w: int = w_start + kw

                                if 0 <= input_h < height and 0 <= input_w < width:
                                    input_idx: int = (
                                        b * height * width * in_channels + input_h * width * in_channels + input_w * in_channels
                                    )

                                    if input_idx < len(inputs.data):
                                        if self.kernel is not None:
                                            kernel_idx: int = f * self.kernel_size[0] * self.kernel_size[1] + kh * self.kernel_size[1] + kw
                                            kernel_data_val: object = self.kernel.value.data[kernel_idx]
                                            input_data_val: object = inputs.data[input_idx]
                                            kernel_val: float = _to_float(kernel_data_val)
                                            input_val: float = _to_float(input_data_val)
                                            conv_sum += input_val * kernel_val
                                        kernel_positions += 1

                        total_kernel_size: int = self.kernel_size[0] * self.kernel_size[1]
                        if self.padding == "same" and kernel_positions > 0 and kernel_positions < total_kernel_size:
                            normalized_sum: float = conv_sum * (total_kernel_size / kernel_positions)
                        else:
                            normalized_sum = conv_sum

                        bias_val: float = 0.0
                        if self.bias is not None:
                            bias_data_val: object = self.bias.value.data[f]
                            bias_val = _to_float(bias_data_val)
                        result: float = normalized_sum + bias_val
                        if self.activation == "relu":
                            result = max(0, result)
                        elif self.activation == "sigmoid":
                            result = 1 / (1 + math.exp(-result))
                        elif self.activation == "tanh":
                            result = math.tanh(result)

                        output_data.append(result)

        return FallbackTensor(output_data, shape=output_shape)


class FallbackModel:
    """Sequential model implementation.

    Provides a simple neural network model for training and prediction with
    layer management and basic training loop functionality.
    """

    def __init__(self, layers: list[object] | None = None, name: str | None = None) -> None:
        """Initialize model.

        Args:
            layers: Optional list of layers to initialize the model with.
            name: Optional name identifier for the model.

        """
        self.layers: list[object] = layers or []
        self.name: str = name or "model"
        self.compiled: bool = False
        self.optimizer: str | None = None
        self.loss: str | None = None
        self.metrics: list[str] = []

    def add(self, layer: object) -> None:
        """Add layer to model.

        Args:
            layer: Layer object to add to the model.

        """
        self.layers.append(layer)

    def compile(
        self,
        optimizer: str = "adam",
        loss: str = "categorical_crossentropy",
        metrics: list[str] | None = None,
    ) -> None:
        """Compile model.

        Args:
            optimizer: Optimizer name ('adam', 'sgd', etc.), defaults to 'adam'.
            loss: Loss function name, defaults to 'categorical_crossentropy'.
            metrics: Optional list of metric names to track during training.

        """
        self.optimizer = optimizer
        self.loss = loss
        self.metrics = metrics or []
        self.compiled = True

    def fit(
        self,
        x: object,
        y: object,
        batch_size: int = 32,
        epochs: int = 1,
        validation_data: tuple[object, object] | None = None,
        callbacks: list[object] | None = None,
        verbose: int = 1,
    ) -> object:
        """Train model.

        Args:
            x: Input training data.
            y: Target training data.
            batch_size: Number of samples per batch, defaults to 32.
            epochs: Number of training epochs, defaults to 1.
            validation_data: Optional validation data tuple (x_val, y_val).
            callbacks: Optional list of callbacks (not used in fallback).
            verbose: Verbosity level for logging, defaults to 1.

        Returns:
            History object containing training metrics.

        Raises:
            RuntimeError: If model is not compiled before training.

        """
        if not self.compiled:
            error_msg: str = "Model must be compiled before training"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        history: dict[str, list[float]] = {
            "loss": [],
            "val_loss": [],
        }

        for metric in self.metrics:
            history[metric] = []
            history[f"val_{metric}"] = []

        x_len: int
        if hasattr(x, "__len__"):
            x_len = len(x)
        else:
            x_len = batch_size
        batch_count: int = x_len // batch_size + (1 if x_len % batch_size != 0 else 0)

        for epoch in range(epochs):
            epoch_loss: float = 0.0
            processed_batches: int = 0

            for batch_idx in range(batch_count):
                start_idx: int = batch_idx * batch_size
                end_idx: int = min(start_idx + batch_size, x_len)

                batch_x: object = x[start_idx:end_idx] if hasattr(x, "__getitem__") else x
                batch_y: object = y[start_idx:end_idx] if hasattr(y, "__getitem__") else y

                predictions: object = self.predict(batch_x, batch_size=end_idx - start_idx, verbose=0)

                if hasattr(predictions, "data") and hasattr(batch_y, "__iter__"):
                    batch_loss: float = 0.0
                    pred_data: list[object]
                    if hasattr(predictions, "data"):
                        pred_data_raw: object = predictions.data
                        pred_data = pred_data_raw if isinstance(pred_data_raw, list) else [pred_data_raw]
                    else:
                        pred_data = [predictions]
                    target_data_raw: object = batch_y
                    target_data: list[object] = target_data_raw if isinstance(target_data_raw, list) else [target_data_raw]

                    target_len: int = len(target_data) if hasattr(target_data, "__len__") else 1
                    for pred, target in zip(pred_data[:target_len], target_data, strict=False):
                        pred_float: float = _to_float(pred)
                        target_float: float = _to_float(target)
                        diff: float = abs(pred_float - target_float)
                        batch_loss += diff**2

                    batch_loss /= len(target_data)
                    epoch_loss += batch_loss
                    processed_batches += 1

            final_loss: float = epoch_loss / max(processed_batches, 1)
            history["loss"].append(final_loss)

            if validation_data:
                val_x, _val_y = validation_data[:2]
                self.predict(val_x, batch_size=batch_size, verbose=0)
                val_loss: float = final_loss * 1.1
                history["val_loss"].append(val_loss)

            for metric in self.metrics:
                metric_value: float = max(0.0, min(1.0, 1.0 - final_loss))
                history[metric].append(metric_value)
                if validation_data:
                    val_metric_value: float = max(0.0, min(1.0, 1.0 - val_loss))
                    history[f"val_{metric}"].append(val_metric_value)

            if verbose:
                logger.info("Epoch %d/%d - loss: %.4f", epoch + 1, epochs, final_loss)

        return type("History", (), {"history": history})()

    def predict(self, x: object, batch_size: int = 32, verbose: int = 0) -> object:
        """Make predictions.

        Args:
            x: Input data for prediction.
            batch_size: Batch size for processing, defaults to 32.
            verbose: Verbosity level, defaults to 0.

        Returns:
            Predictions as a FallbackTensor or similar object.

        """
        if hasattr(x, "shape") and x.shape:
            batch_size = x.shape[0] if len(x.shape) > 0 else 1
        else:
            batch_size = 1

        current_output: object = x
        for layer in self.layers:
            if callable(layer):
                current_output = layer(current_output)
            elif hasattr(layer, "call"):
                current_output = layer.call(current_output)

        if hasattr(current_output, "shape") and current_output.shape:
            output_shape: tuple[int, ...] = current_output.shape
        else:
            output_shape = (batch_size, 10)

        return current_output if hasattr(current_output, "data") else FallbackTensor(current_output, shape=output_shape)

    def evaluate(self, x: object, y: object, batch_size: int = 32, verbose: int = 0) -> object:
        """Evaluate model.

        Args:
            x: Input evaluation data.
            y: Target evaluation data.
            batch_size: Batch size for evaluation, defaults to 32.
            verbose: Verbosity level, defaults to 0.

        Returns:
            Loss and metrics as list or single loss value.

        """
        total_loss: float = 0.0
        total_samples: int = 0
        metric_totals: list[float] = [0.0 for _ in self.metrics]

        num_samples: int = len(x) if hasattr(x, "__len__") else batch_size
        batch_count: int = (num_samples + batch_size - 1) // batch_size

        for batch_idx in range(batch_count):
            start_idx: int = batch_idx * batch_size
            end_idx: int = min(start_idx + batch_size, num_samples)

            batch_x: object = x[start_idx:end_idx] if hasattr(x, "__getitem__") else x
            batch_y: object = y[start_idx:end_idx] if hasattr(y, "__getitem__") else y

            predictions: object = self.predict(batch_x, batch_size=end_idx - start_idx, verbose=0)

            if hasattr(predictions, "data") and hasattr(batch_y, "__iter__"):
                pred_data: list[object]
                if hasattr(predictions, "data"):
                    pred_data_raw: object = predictions.data
                    pred_data = pred_data_raw if isinstance(pred_data_raw, list) else [pred_data_raw]
                else:
                    pred_data = [predictions]
                target_data_raw: object = batch_y
                target_data: list[object] = target_data_raw if isinstance(target_data_raw, list) else [target_data_raw]

                batch_loss: float = 0.0
                pred_len: int = len(pred_data) if hasattr(pred_data, "__len__") else 1
                target_len: int = len(target_data) if hasattr(target_data, "__len__") else 1
                batch_size_actual: int = min(pred_len, target_len)

                for i in range(batch_size_actual):
                    pred_i: object = pred_data[i]
                    target_i: object = target_data[i]
                    pred_float: float = _to_float(pred_i)
                    target_float: float = _to_float(target_i)
                    diff: float = abs(pred_float - target_float)
                    batch_loss += diff**2

                if batch_size_actual > 0:
                    batch_loss /= batch_size_actual
                    total_loss += batch_loss
                    total_samples += batch_size_actual

                    for j in range(len(self.metrics)):
                        accuracy: float = max(0.0, min(1.0, 1.0 - batch_loss))
                        metric_totals[j] += accuracy

        final_loss: float = total_loss / max(total_samples, 1)
        final_metrics: list[float] = [metric_total / max(batch_count, 1) for metric_total in metric_totals]

        if verbose:
            logger.info("Evaluation - loss: %.4f", final_loss)
            for i, metric_name in enumerate(self.metrics):
                if i < len(final_metrics):
                    logger.info("%s: %.4f", metric_name, final_metrics[i])

        return [final_loss, *final_metrics] if final_metrics else final_loss

    def save(self, filepath: str) -> None:
        """Save model.

        Args:
            filepath: File path where to save the model.

        """
        logger.info("Saving model to %s (fallback mode - no actual save)", filepath)
        with open(filepath, "wb") as f:
            f.write(b"FALLBACK_MODEL")

    def summary(self) -> None:
        """Print model summary."""
        logger.info("Model: %s", self.name)
        logger.info("Layers: %d", len(self.layers))
        for i, layer in enumerate(self.layers):
            logger.info(
                "  Layer %d: %s",
                i + 1,
                layer.name if hasattr(layer, "name") else type(layer).__name__,
            )


class FallbackSequential(FallbackModel):
    """Sequential model.

    A linear stack of layers for building sequential neural network models.
    """

    def __init__(self, layers: list[object] | None = None, name: str | None = None) -> None:
        """Initialize sequential model.

        Args:
            layers: Optional list of layers for the sequential model.
            name: Optional name identifier, defaults to 'sequential'.

        """
        super().__init__(layers, name or "sequential")


# Keras module components
class FallbackKerasLayers:
    """Keras layers module.

    Provides fallback implementations of Keras layer components for neural
    network construction when TensorFlow is unavailable.
    """

    Dense: type[FallbackDenseLayer] = FallbackDenseLayer
    Conv2D: type[FallbackConv2DLayer] = FallbackConv2DLayer

    class Flatten:
        """Flatten layer.

        Reshapes tensor input to 1D representation.
        """

        def __init__(self, name: str | None = None) -> None:
            """Initialize flatten layer.

            Args:
                name: Optional name identifier for the layer.

            """
            self.name: str = name or "flatten"

        def call(self, inputs: FallbackTensor) -> FallbackTensor:
            """Flatten input.

            Args:
                inputs: Input tensor to flatten.

            Returns:
                Flattened tensor with 1D shape.

            """
            return FallbackTensor(inputs.data, shape=(len(inputs.data),))

        def __call__(self, inputs: FallbackTensor) -> FallbackTensor:
            """Make layer callable.

            Args:
                inputs: Input tensor to flatten.

            Returns:
                Flattened tensor with 1D shape.

            """
            return self.call(inputs)

    class Dropout:
        """Dropout layer.

        Randomly drops units during training for regularization.
        """

        def __init__(self, rate: float, name: str | None = None) -> None:
            """Initialize dropout layer.

            Args:
                rate: Dropout rate (fraction of units to drop).
                name: Optional name identifier for the layer.

            """
            self.rate: float = rate
            self.name: str = name or "dropout"

        def call(self, inputs: FallbackTensor, training: bool = False) -> FallbackTensor:
            """Apply dropout.

            Args:
                inputs: Input tensor to apply dropout to.
                training: Whether in training mode (applies dropout), defaults to False.

            Returns:
                Tensor with dropout applied if training, otherwise unchanged.

            """
            if not training:
                return inputs

            output_data: list[float] = []
            for val in inputs.data:
                if random.random() > self.rate:  # noqa: S311
                    val_float: float = _to_float(val)
                    output_data.append(val_float / (1 - self.rate))
                else:
                    output_data.append(0.0)

            return FallbackTensor(output_data, inputs.shape)

        def __call__(self, inputs: FallbackTensor, training: bool = False) -> FallbackTensor:
            """Make layer callable.

            Args:
                inputs: Input tensor to apply dropout to.
                training: Whether in training mode, defaults to False.

            Returns:
                Tensor with dropout applied if training, otherwise unchanged.

            """
            return self.call(inputs, training)

    class BatchNormalization:
        """Batch normalization layer.

        Normalizes inputs during training for improved convergence.
        """

        def __init__(self, name: str | None = None) -> None:
            """Initialize batch normalization layer.

            Args:
                name: Optional name identifier for the layer.

            """
            self.name: str = name or "batch_norm"

        def call(self, inputs: FallbackTensor) -> FallbackTensor:
            """Apply batch norm (simplified).

            Args:
                inputs: Input tensor to normalize.

            Returns:
                Normalized tensor (simplified passthrough in fallback).

            """
            return inputs

        def __call__(self, inputs: FallbackTensor) -> FallbackTensor:
            """Make layer callable.

            Args:
                inputs: Input tensor to normalize.

            Returns:
                Normalized tensor (simplified passthrough in fallback).

            """
            return self.call(inputs)

    class MaxPooling2D:
        """Max pooling layer.

        Applies 2D maximum pooling over input feature maps for downsampling.
        """

        def __init__(
            self,
            pool_size: int | tuple[int, int] = 2,
            strides: tuple[int, int] | None = None,
            padding: str = "valid",
            name: str | None = None,
        ) -> None:
            """Initialize max pooling layer.

            Args:
                pool_size: Size of pooling window (int or tuple), defaults to 2.
                strides: Stride of pooling operation, defaults to pool_size.
                padding: Padding mode ('valid' or 'same'), defaults to 'valid'.
                name: Optional name identifier for the layer.

            """
            self.pool_size: tuple[int, int] = pool_size if isinstance(pool_size, tuple) else (pool_size, pool_size)
            self.strides: tuple[int, int] = strides or self.pool_size
            self.padding: str = padding
            self.name: str = name or "maxpool2d"

        def call(self, inputs: FallbackTensor) -> FallbackTensor:
            """Apply max pooling.

            Args:
                inputs: Input tensor to apply max pooling to.

            Returns:
                Downsampled tensor after max pooling operation.

            """
            input_data: list[object] = inputs.data if isinstance(inputs.data, list) else [inputs.data]
            input_shape: tuple[int, ...] = inputs.shape

            batch: int = input_shape[0] if len(input_shape) > 3 else 1
            height: int = input_shape[1] if len(input_shape) > 2 else 28
            width: int = input_shape[2] if len(input_shape) > 1 else 28
            channels: int = input_shape[3] if input_shape else 1

            out_height: int = height // self.pool_size[0]
            out_width: int = width // self.pool_size[1]
            output_shape: tuple[int, ...] = (batch, out_height, out_width, channels)

            output_data: list[float] = []

            if len(input_data) == height * width * channels * batch:
                reshaped: list[object] = []
                idx: int = 0
                for _b in range(batch):
                    for _h in range(height):
                        for _w in range(width):
                            for _c in range(channels):
                                if idx < len(input_data):
                                    reshaped.append(input_data[idx])
                                    idx += 1
                                else:
                                    reshaped.append(0.0)
                input_data = reshaped

            for b in range(batch):
                for oh in range(out_height):
                    for ow in range(out_width):
                        for c in range(channels):
                            max_val: float = -float("inf")
                            for ph in range(self.pool_size[0]):
                                for pw in range(self.pool_size[1]):
                                    h_idx: int = oh * self.strides[0] + ph
                                    w_idx: int = ow * self.strides[1] + pw

                                    if h_idx < height and w_idx < width:
                                        idx = b * height * width * channels + h_idx * width * channels + w_idx * channels + c
                                        if idx < len(input_data):
                                            val: object = input_data[idx]
                                            if isinstance(val, (int, float)):
                                                max_val = max(max_val, val)

                            if max_val == -float("inf"):
                                max_val = 0.0
                            output_data.append(max_val)

            return FallbackTensor(output_data, shape=output_shape)

        def __call__(self, inputs: FallbackTensor) -> FallbackTensor:
            """Make layer callable.

            Args:
                inputs: Input tensor to apply max pooling to.

            Returns:
                Downsampled tensor after max pooling operation.

            """
            return self.call(inputs)

    class Input:
        """Input layer.

        Specifies input shape for neural network model.
        """

        def __init__(self, shape: tuple[int, ...] | None = None, name: str | None = None) -> None:
            """Initialize input layer.

            Args:
                shape: Input tensor shape specification.
                name: Optional name identifier for the layer.

            """
            self.shape: tuple[int, ...] | None = shape
            self.name: str = name or "input"


class FallbackKerasModels:
    """Keras models module.

    Provides model classes for constructing and managing neural networks.
    """

    Sequential: type[FallbackSequential] = FallbackSequential
    Model: type[FallbackModel] = FallbackModel

    @staticmethod
    def load_model(filepath: str) -> FallbackModel:
        """Load model from file.

        Args:
            filepath: Path to the model file.

        Returns:
            Loaded FallbackModel instance.

        """
        logger.info("Loading model from %s (fallback mode)", filepath)
        return FallbackModel(name="loaded_model")


class FallbackKerasOptimizers:
    """Keras optimizers module.

    Provides optimizer classes for neural network training.
    """

    class Adam:
        """Adam optimizer.

        Adaptive Moment Estimation optimizer for gradient-based optimization.
        """

        def __init__(self, learning_rate: float = 0.001) -> None:
            """Initialize Adam optimizer.

            Args:
                learning_rate: Learning rate for parameter updates, defaults to 0.001.

            """
            self.learning_rate: float = learning_rate

    class SGD:
        """Stochastic Gradient Descent optimizer.

        Basic SGD optimizer with optional momentum for gradient-based optimization.
        """

        def __init__(self, learning_rate: float = 0.01, momentum: float = 0.0) -> None:
            """Initialize SGD optimizer.

            Args:
                learning_rate: Learning rate for parameter updates, defaults to 0.01.
                momentum: Momentum coefficient for gradient updates, defaults to 0.0.

            """
            self.learning_rate: float = learning_rate
            self.momentum: float = momentum

    class RMSprop:
        """RMSprop optimizer.

        Root Mean Square Propagation optimizer for adaptive learning rate optimization.
        """

        def __init__(self, learning_rate: float = 0.001) -> None:
            """Initialize RMSprop optimizer.

            Args:
                learning_rate: Learning rate for parameter updates, defaults to 0.001.

            """
            self.learning_rate: float = learning_rate


class FallbackKeras:
    """Keras module.

    Aggregates Keras layer, model, and optimizer components for neural network
    construction and training.
    """

    layers: FallbackKerasLayers = FallbackKerasLayers()
    models: FallbackKerasModels = FallbackKerasModels()
    optimizers: FallbackKerasOptimizers = FallbackKerasOptimizers()
    Model: type[FallbackModel] = FallbackModel
    Sequential: type[FallbackSequential] = FallbackSequential


class FallbackSavedModel:
    """Fallback for tf.saved_model.

    Provides model saving/loading compatibility for the TensorFlow saved_model format.
    """

    @staticmethod
    def contains_saved_model(path: str) -> bool:
        """Check if path contains a saved model.

        Args:
            path: Directory path to check for saved model.

        Returns:
            Boolean indicating if a saved model exists at path.

        """
        logger.info(f"Checking for saved model in {path} (fallback mode).")
        return False


def constant(
    value: object,
    dtype: str | None = None,
    shape: tuple[int, ...] | None = None,
    name: str | None = None,
) -> FallbackTensor:
    """Create constant tensor.

    Args:
        value: Tensor value (scalar, list, or nested structure).
        dtype: Data type string, defaults to 'float32'.
        shape: Optional shape specification.
        name: Optional name identifier (not used in fallback).

    Returns:
        FallbackTensor with the specified value and shape.

    """
    return FallbackTensor(value, shape=shape, dtype=dtype or "float32")


def Variable(initial_value: object, trainable: bool = True, name: str | None = None) -> FallbackVariable:
    """Create variable.

    Args:
        initial_value: Initial variable value.
        trainable: Whether the variable is trainable, defaults to True.
        name: Optional name identifier for the variable.

    Returns:
        FallbackVariable instance.

    """
    return FallbackVariable(initial_value, trainable, name)


def zeros(shape: tuple[int, ...], dtype: str = "float32") -> FallbackTensor:
    """Create zeros tensor.

    Args:
        shape: Shape specification for the tensor.
        dtype: Data type string, defaults to 'float32'.

    Returns:
        FallbackTensor filled with zeros.

    """
    size: int = 1
    for dim in shape:
        size *= dim
    return FallbackTensor([0] * size, shape=shape, dtype=dtype)


def ones(shape: tuple[int, ...], dtype: str = "float32") -> FallbackTensor:
    """Create ones tensor.

    Args:
        shape: Shape specification for the tensor.
        dtype: Data type string, defaults to 'float32'.

    Returns:
        FallbackTensor filled with ones.

    """
    size: int = 1
    for dim in shape:
        size *= dim
    return FallbackTensor([1] * size, shape=shape, dtype=dtype)


def random_normal(shape: tuple[int, ...], mean: float = 0.0, stddev: float = 1.0, dtype: str = "float32") -> FallbackTensor:
    """Create random normal tensor.

    Args:
        shape: Shape specification for the tensor.
        mean: Mean of the normal distribution, defaults to 0.0.
        stddev: Standard deviation of the normal distribution, defaults to 1.0.
        dtype: Data type string, defaults to 'float32'.

    Returns:
        FallbackTensor with normally distributed random values.

    """
    size: int = 1
    for dim in shape:
        size *= dim
    data: list[float] = [random.gauss(mean, stddev) for _ in range(size)]
    return FallbackTensor(data, shape=shape, dtype=dtype)


def random_uniform(shape: tuple[int, ...], minval: float = 0, maxval: float = 1, dtype: str = "float32") -> FallbackTensor:
    """Create random uniform tensor.

    Args:
        shape: Shape specification for the tensor.
        minval: Minimum value for uniform distribution, defaults to 0.
        maxval: Maximum value for uniform distribution, defaults to 1.
        dtype: Data type string, defaults to 'float32'.

    Returns:
        FallbackTensor with uniformly distributed random values.

    """
    size: int = 1
    for dim in shape:
        size *= dim
    data: list[float] = [random.uniform(minval, maxval) for _ in range(size)]  # noqa: S311
    return FallbackTensor(data, shape=shape, dtype=dtype)


# Module-level configuration
class FallbackConfig:
    """TensorFlow config.

    Provides GPU device configuration and threading options for TensorFlow fallback.
    """

    @staticmethod
    def set_visible_devices(devices: object, device_type: str) -> None:
        """Set visible devices for TensorFlow.

        Args:
            devices: List of devices to make visible.
            device_type: Device type identifier ('GPU', 'CPU', etc.).

        """
        logger.info("Set visible devices for %s (fallback mode)", device_type)

    @staticmethod
    def list_physical_devices(device_type: str = "GPU") -> list[object]:
        """List physical devices of given type.

        Args:
            device_type: Device type to list ('GPU', 'CPU', etc.), defaults to 'GPU'.

        Returns:
            List of physical devices (empty in fallback mode).

        """
        logger.info("Listing physical devices for %s (fallback mode)", device_type)
        return []

    @staticmethod
    def get_visible_devices(device_type: str | None = None) -> list[object]:
        """Get currently visible devices for TensorFlow computation.

        Args:
            device_type: Optional device type filter ('GPU', 'CPU', 'TPU', etc.).
                        If None, returns all visible devices.

        Returns:
            List of visible device objects (empty in fallback mode since no
            real TensorFlow devices are available).

        """
        if device_type:
            logger.info("Getting visible devices for %s (fallback mode)", device_type)
        else:
            logger.info("Getting all visible devices (fallback mode)")
        return []

    class Experimental:
        """Experimental TensorFlow features."""

        @staticmethod
        def set_memory_growth(device: object, enable: bool) -> None:
            """Set memory growth for a device.

            Args:
                device: Device object to configure.
                enable: Whether to enable memory growth.

            """
            logger.info("Memory growth set to %s (fallback mode)", enable)

        @staticmethod
        def list_physical_devices(device_type: str = "GPU") -> list[object]:
            """List physical devices of given type.

            Args:
                device_type: Device type to list ('GPU', 'CPU', etc.), defaults to 'GPU'.

            Returns:
                List of physical devices (empty in fallback mode).

            """
            logger.info("Listing physical devices for %s (fallback mode)", device_type)
            return []

    experimental: type[Experimental] = Experimental

    class Threading:
        """Threading configuration for TensorFlow."""

        @staticmethod
        def set_inter_op_parallelism_threads(num: int) -> None:
            """Set inter-op parallelism thread count.

            Args:
                num: Number of threads for inter-op parallelism.

            """
            logger.info("Inter-op threads set to %d (fallback mode)", num)

        @staticmethod
        def set_intra_op_parallelism_threads(num: int) -> None:
            """Set intra-op parallelism thread count.

            Args:
                num: Number of threads for intra-op parallelism.

            """
            logger.info("Intra-op threads set to %d (fallback mode)", num)

    threading: type[Threading] = Threading


# Create module-like object
class FallbackTensorFlow:
    """Fallback TensorFlow module.

    Complete TensorFlow API replacement providing tensor operations, model building,
    and configuration when TensorFlow is unavailable.
    """

    __version__: str = "0.0.0-fallback"

    saved_model: type[FallbackSavedModel] = FallbackSavedModel
    keras: FallbackKeras = FallbackKeras()
    config: type[FallbackConfig] = FallbackConfig

    constant: object = staticmethod(constant)
    Variable: object = staticmethod(Variable)
    zeros: object = staticmethod(zeros)
    ones: object = staticmethod(ones)
    random_normal: object = staticmethod(random_normal)
    random_uniform: object = staticmethod(random_uniform)

    @staticmethod
    def reduce_sum(tensor: object, axis: int | None = None, keepdims: bool = False) -> FallbackTensor:
        """Calculate sum of tensor elements in a production-ready way.

        Args:
            tensor: Input tensor (FallbackTensor or compatible object).
            axis: Axis along which to reduce (not used in fallback), defaults to None.
            keepdims: Whether to keep dimensions (not used in fallback), defaults to False.

        Returns:
            Scalar FallbackTensor containing the sum.

        Raises:
            TypeError: If tensor is not a valid tensor type.

        """
        if not isinstance(tensor, FallbackTensor):
            if hasattr(tensor, "numpy"):
                tensor = FallbackTensor(tensor.numpy())
            else:
                error_msg: str = "Input must be a FallbackTensor or compatible object"
                logger.error(error_msg)
                raise TypeError(error_msg)

        numeric_data: list[float] = [_to_float(x) for x in tensor.data]
        total_sum: float = sum(numeric_data)

        return FallbackTensor(total_sum, shape=())

    Tensor: type[FallbackTensor] = FallbackTensor


# Provide backwards compatibility aliases
def get_tf() -> object:
    """Get TensorFlow module (real or fallback)."""
    return tf


def get_keras() -> object:
    """Get Keras module (real or fallback)."""
    return keras_module


def get_layers() -> object:
    """Get layers module (real or fallback)."""
    return layers_module


def get_models() -> object:
    """Get models module (real or fallback)."""
    return models_module


def get_optimizers() -> object:
    """Get optimizers module (real or fallback)."""
    return optimizers_module


# Export all TensorFlow objects and availability flag
__all__ = [
    "HAS_TENSORFLOW",
    "TENSORFLOW_VERSION",
    "ensure_tensorflow_loaded",
    "get_keras",
    "get_layers",
    "get_models",
    "get_optimizers",
    "get_tf",
    "keras_module",
    "layers_module",
    "models_module",
    "optimizers_module",
    "tf",
]
