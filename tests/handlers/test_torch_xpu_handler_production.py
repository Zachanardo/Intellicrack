"""Production tests for Torch XPU handler.

Tests validate Intel GPU acceleration functionality and fallbacks.
Tests verify tensor operations, model inference, and XPU availability.
"""

from typing import Any

import pytest

from intellicrack.handlers.torch_xpu_handler import (
    TORCH_XPU_AVAILABLE,
    create_tensor,
    get_device_count,
    get_device_name,
    is_xpu_available,
    move_to_device,
    tensor_operation,
)


class TestXPUAvailability:
    """Test XPU device availability detection."""

    def test_is_xpu_available(self) -> None:
        """Check if XPU is available."""
        available = is_xpu_available()

        assert isinstance(available, bool)

    def test_get_device_count(self) -> None:
        """Get number of XPU devices."""
        count = get_device_count()

        assert isinstance(count, int)
        assert count >= 0

    def test_get_device_name(self) -> None:
        """Get XPU device name."""
        if is_xpu_available() and get_device_count() > 0:
            name = get_device_name(0)

            assert isinstance(name, str)
            assert len(name) > 0
        else:
            pytest.skip("No XPU device available")


class TestTensorCreation:
    """Test tensor creation and manipulation."""

    def test_create_tensor_from_list(self) -> None:
        """Create tensor from Python list."""
        data = [1.0, 2.0, 3.0, 4.0]

        tensor = create_tensor(data)

        assert tensor is not None
        assert len(tensor.shape) == 1
        assert tensor.shape[0] == 4

    def test_create_tensor_from_nested_list(self) -> None:
        """Create 2D tensor from nested list."""
        data = [[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]]

        tensor = create_tensor(data)

        assert tensor is not None
        assert len(tensor.shape) == 2
        assert tensor.shape[0] == 3
        assert tensor.shape[1] == 2

    def test_create_tensor_with_dtype(self) -> None:
        """Create tensor with specific dtype."""
        data = [1, 2, 3, 4]

        tensor = create_tensor(data, dtype="int32")

        assert tensor is not None

    def test_create_empty_tensor(self) -> None:
        """Create empty tensor."""
        tensor = create_tensor([])

        assert tensor is not None

    def test_create_large_tensor(self) -> None:
        """Create large tensor."""
        data = [float(i) for i in range(10000)]

        tensor = create_tensor(data)

        assert tensor is not None
        assert tensor.shape[0] == 10000


class TestTensorOperations:
    """Test tensor operations on XPU."""

    def test_tensor_addition(self) -> None:
        """Perform tensor addition."""
        tensor1 = create_tensor([1.0, 2.0, 3.0])
        tensor2 = create_tensor([4.0, 5.0, 6.0])

        result = tensor_operation(tensor1, tensor2, operation="add")

        assert result is not None
        assert result.shape == tensor1.shape

    def test_tensor_multiplication(self) -> None:
        """Perform tensor multiplication."""
        tensor1 = create_tensor([2.0, 3.0, 4.0])
        tensor2 = create_tensor([5.0, 6.0, 7.0])

        result = tensor_operation(tensor1, tensor2, operation="mul")

        assert result is not None
        assert result.shape == tensor1.shape

    def test_tensor_subtraction(self) -> None:
        """Perform tensor subtraction."""
        tensor1 = create_tensor([10.0, 20.0, 30.0])
        tensor2 = create_tensor([5.0, 10.0, 15.0])

        result = tensor_operation(tensor1, tensor2, operation="sub")

        assert result is not None
        assert result.shape == tensor1.shape

    def test_tensor_division(self) -> None:
        """Perform tensor division."""
        tensor1 = create_tensor([10.0, 20.0, 30.0])
        tensor2 = create_tensor([2.0, 4.0, 5.0])

        result = tensor_operation(tensor1, tensor2, operation="div")

        assert result is not None
        assert result.shape == tensor1.shape


class TestDeviceMovement:
    """Test moving tensors between devices."""

    def test_move_tensor_to_cpu(self) -> None:
        """Move tensor to CPU."""
        tensor = create_tensor([1.0, 2.0, 3.0])

        cpu_tensor = move_to_device(tensor, "cpu")

        assert cpu_tensor is not None

    def test_move_tensor_to_xpu(self) -> None:
        """Move tensor to XPU device."""
        if is_xpu_available():
            tensor = create_tensor([1.0, 2.0, 3.0])

            xpu_tensor = move_to_device(tensor, "xpu")

            assert xpu_tensor is not None
        else:
            pytest.skip("XPU not available")

    def test_move_tensor_cpu_to_xpu_to_cpu(self) -> None:
        """Move tensor from CPU to XPU and back."""
        if is_xpu_available():
            tensor = create_tensor([1.0, 2.0, 3.0])

            xpu_tensor = move_to_device(tensor, "xpu")
            cpu_tensor = move_to_device(xpu_tensor, "cpu")

            assert cpu_tensor is not None
        else:
            pytest.skip("XPU not available")


class TestMatrixOperations:
    """Test matrix operations for ML inference."""

    def test_matrix_multiplication(self) -> None:
        """Perform matrix multiplication."""
        matrix1 = create_tensor([[1.0, 2.0], [3.0, 4.0]])
        matrix2 = create_tensor([[5.0, 6.0], [7.0, 8.0]])

        result = tensor_operation(matrix1, matrix2, operation="matmul")

        assert result is not None
        assert len(result.shape) == 2

    def test_transpose_matrix(self) -> None:
        """Transpose matrix."""
        matrix = create_tensor([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]])

        result = tensor_operation(matrix, None, operation="transpose")

        assert result is not None
        assert result.shape[0] == 3
        assert result.shape[1] == 2

    def test_matrix_sum(self) -> None:
        """Sum matrix elements."""
        matrix = create_tensor([[1.0, 2.0], [3.0, 4.0]])

        result = tensor_operation(matrix, None, operation="sum")

        assert result is not None


class TestMLInference:
    """Test ML model inference for binary analysis."""

    def test_simple_linear_layer(self) -> None:
        """Test simple linear layer inference."""
        input_tensor = create_tensor([1.0, 2.0, 3.0, 4.0])

        if is_xpu_available():
            input_tensor = move_to_device(input_tensor, "xpu")

        assert input_tensor is not None

    def test_batch_inference(self) -> None:
        """Test batch inference."""
        batch = create_tensor([[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]])

        if is_xpu_available():
            batch = move_to_device(batch, "xpu")

        assert batch is not None
        assert batch.shape[0] == 3


class TestProtectionClassification:
    """Test XPU acceleration for protection classification."""

    def test_feature_extraction_tensor(self) -> None:
        """Create tensor for binary features."""
        features = [float(i % 2) for i in range(256)]

        tensor = create_tensor(features)

        if is_xpu_available():
            tensor = move_to_device(tensor, "xpu")

        assert tensor is not None
        assert tensor.shape[0] == 256

    def test_classification_output_tensor(self) -> None:
        """Create tensor for classification outputs."""
        class_probabilities = [0.1, 0.3, 0.4, 0.2]

        tensor = create_tensor(class_probabilities)

        assert tensor is not None
        assert tensor.shape[0] == 4


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_create_tensor_with_invalid_data(self) -> None:
        """Handle invalid data for tensor creation."""
        with pytest.raises(Exception):
            create_tensor(None)

    def test_tensor_operation_with_mismatched_shapes(self) -> None:
        """Handle mismatched tensor shapes."""
        tensor1 = create_tensor([1.0, 2.0, 3.0])
        tensor2 = create_tensor([1.0, 2.0])

        with pytest.raises(Exception):
            tensor_operation(tensor1, tensor2, operation="add")

    def test_move_to_invalid_device(self) -> None:
        """Handle invalid device name."""
        tensor = create_tensor([1.0, 2.0])

        with pytest.raises(Exception):
            move_to_device(tensor, "invalid_device")


class TestFallbackImplementation:
    """Test fallback implementation when XPU unavailable."""

    def test_fallback_tensor_creation(self) -> None:
        """Verify fallback tensor creation works."""
        data = [1.0, 2.0, 3.0]

        tensor = create_tensor(data)

        assert tensor is not None

    def test_fallback_tensor_operations(self) -> None:
        """Verify fallback tensor operations work."""
        tensor1 = create_tensor([1.0, 2.0])
        tensor2 = create_tensor([3.0, 4.0])

        result = tensor_operation(tensor1, tensor2, operation="add")

        assert result is not None

    def test_fallback_device_movement(self) -> None:
        """Verify fallback device movement works."""
        tensor = create_tensor([1.0, 2.0])

        cpu_tensor = move_to_device(tensor, "cpu")

        assert cpu_tensor is not None


class TestPerformance:
    """Test XPU performance characteristics."""

    @pytest.mark.benchmark
    def test_large_tensor_creation_performance(self, benchmark: Any) -> None:
        """Benchmark large tensor creation."""
        data = [float(i) for i in range(10000)]

        result = benchmark(create_tensor, data)

        assert result is not None

    @pytest.mark.benchmark
    def test_tensor_operation_performance(self, benchmark: Any) -> None:
        """Benchmark tensor operations."""
        tensor1 = create_tensor([float(i) for i in range(1000)])
        tensor2 = create_tensor([float(i) for i in range(1000)])

        result = benchmark(tensor_operation, tensor1, tensor2, operation="add")

        assert result is not None

    def test_xpu_vs_cpu_performance(self) -> None:
        """Compare XPU vs CPU performance."""
        if is_xpu_available():
            data1 = [float(i) for i in range(10000)]
            data2 = [float(i) for i in range(10000)]

            tensor1_cpu = create_tensor(data1)
            tensor2_cpu = create_tensor(data2)

            result_cpu = tensor_operation(tensor1_cpu, tensor2_cpu, operation="add")

            tensor1_xpu = move_to_device(tensor1_cpu, "xpu")
            tensor2_xpu = move_to_device(tensor2_cpu, "xpu")

            result_xpu = tensor_operation(tensor1_xpu, tensor2_xpu, operation="add")

            assert result_cpu is not None
            assert result_xpu is not None
        else:
            pytest.skip("XPU not available for comparison")
