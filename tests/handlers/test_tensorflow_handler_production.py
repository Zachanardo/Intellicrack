"""Production-grade tests for TensorFlow handler.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.
"""

from __future__ import annotations

import pytest


class TestTensorFlowHandlerFallbackMode:
    """Test TensorFlow handler fallback tensor operations."""

    def test_fallback_tensor_creation_and_shape(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        tensor = handler.FallbackTensor([1, 2, 3, 4], shape=(2, 2))

        assert tensor.shape == (2, 2)
        assert tensor.size == 4
        assert tensor.ndim == 2

    def test_fallback_tensor_arithmetic_operations(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        t1 = handler.FallbackTensor([1, 2, 3])
        t2 = handler.FallbackTensor([4, 5, 6])

        t_add = t1 + t2
        assert t_add.data == [5, 7, 9]

        t_mul = t1 * 2
        assert t_mul.data == [2, 4, 6]

    def test_fallback_tensor_reshape(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        tensor = handler.FallbackTensor([1, 2, 3, 4, 5, 6], shape=(2, 3))
        reshaped = tensor.reshape((3, 2))

        assert reshaped.shape == (3, 2)
        assert len(reshaped.data) == 6

    def test_fallback_variable_initialization(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        var = handler.FallbackVariable([1.0, 2.0, 3.0], trainable=True, name="test_var")

        assert var.trainable
        assert var.name == "test_var"
        assert len(var.value.data) == 3

    def test_fallback_variable_assignment(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        var = handler.FallbackVariable([1.0, 2.0])
        var.assign([5.0, 6.0])

        assert var.value.data == [5.0, 6.0]

    def test_fallback_dense_layer_initialization(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        layer = handler.FallbackDenseLayer(units=10, activation="relu", name="dense1")

        assert layer.units == 10
        assert layer.activation == "relu"
        assert not layer.built

    def test_fallback_dense_layer_forward_pass(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        layer = handler.FallbackDenseLayer(units=5, activation="relu")
        input_tensor = handler.FallbackTensor([1.0, 2.0, 3.0], shape=(3,))

        output = layer(input_tensor)

        assert output.shape == (5,)
        assert layer.built

    def test_fallback_model_creation_and_compilation(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        model = handler.FallbackModel(name="test_model")
        model.add(handler.FallbackDenseLayer(10, activation="relu"))
        model.add(handler.FallbackDenseLayer(5, activation="softmax"))

        model.compile(optimizer="adam", loss="categorical_crossentropy", metrics=["accuracy"])

        assert model.compiled
        assert model.optimizer == "adam"
        assert len(model.layers) == 2

    def test_fallback_model_training(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        model = handler.FallbackModel()
        model.add(handler.FallbackDenseLayer(10))
        model.compile(optimizer="adam", loss="mse")

        x_train = [[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]]
        y_train = [[0.5], [1.5], [2.5]]

        history = model.fit(x_train, y_train, epochs=2, batch_size=2, verbose=0)

        assert "loss" in history.history
        assert len(history.history["loss"]) == 2

    def test_fallback_model_prediction(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        model = handler.FallbackModel()
        model.add(handler.FallbackDenseLayer(5))
        model.compile(optimizer="adam", loss="mse")

        x_test = [[1.0, 2.0, 3.0]]
        predictions = model.predict(x_test, verbose=0)

        assert predictions is not None

    def test_fallback_conv2d_layer_initialization(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        layer = handler.FallbackConv2DLayer(filters=32, kernel_size=3, strides=1, padding="valid")

        assert layer.filters == 32
        assert layer.kernel_size == (3, 3)
        assert layer.padding == "valid"

    def test_fallback_flatten_layer(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        layers_module = handler.FallbackKerasLayers()
        flatten = layers_module.Flatten()

        input_tensor = handler.FallbackTensor([1, 2, 3, 4], shape=(2, 2))
        output = flatten(input_tensor)

        assert output.shape == (4,)

    def test_fallback_dropout_layer_training_mode(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        layers_module = handler.FallbackKerasLayers()
        dropout = layers_module.Dropout(rate=0.5)

        input_tensor = handler.FallbackTensor([1.0, 2.0, 3.0, 4.0], shape=(4,))
        output = dropout(input_tensor, training=True)

        assert len(output.data) == 4

    def test_fallback_tensor_creation_functions(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        zeros = handler.zeros((2, 3))
        assert zeros.data == [0, 0, 0, 0, 0, 0]

        ones = handler.ones((2, 2))
        assert ones.data == [1, 1, 1, 1]

        constant = handler.constant([5, 5, 5], shape=(3,))
        assert constant.data == [5, 5, 5]

    def test_fallback_random_tensor_generation(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        random_normal = handler.random_normal((3, 3))
        assert len(random_normal.data) == 9

        random_uniform = handler.random_uniform((2, 2), minval=0, maxval=1)
        assert len(random_uniform.data) == 4


class TestTensorFlowHandlerRealMode:
    """Test TensorFlow handler with real TensorFlow (if available)."""

    def test_real_tensorflow_detection(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        assert handler.tf is not None
        assert handler.keras is not None

    def test_tensorflow_version_info(self) -> None:
        import intellicrack.handlers.tensorflow_handler as handler

        handler.ensure_tensorflow_loaded()

        if handler.HAS_TENSORFLOW:
            assert handler.TENSORFLOW_VERSION is not None
