"""Production tests for numpy_handler.

Tests validate array operations, mathematical functions, linear algebra, FFT,
random number generation, and fallback implementation compatibility.
"""

import math

import pytest

from intellicrack.handlers import numpy_handler


def test_array_creation_from_list() -> None:
    """array() creates array from Python list."""
    data = [1, 2, 3, 4, 5]

    arr = numpy_handler.array(data)

    assert arr.shape == (5,)
    assert arr.size == 5
    assert list(arr.tolist()) == data


def test_array_creation_from_nested_list() -> None:
    """array() flattens nested lists correctly."""
    data = [[1, 2], [3, 4]]

    arr = numpy_handler.array(data)

    assert arr.size == 4
    assert arr.data[0] == 1
    assert arr.data[3] == 4


def test_zeros_creates_array_of_zeros() -> None:
    """zeros() creates array filled with zeros."""
    arr = numpy_handler.zeros(10)

    assert arr.shape == (10,)
    assert all(x == 0 for x in arr.data)


def test_ones_creates_array_of_ones() -> None:
    """ones() creates array filled with ones."""
    arr = numpy_handler.ones(8)

    assert arr.shape == (8,)
    assert all(x == 1 for x in arr.data)


def test_arange_creates_range_array() -> None:
    """arange() creates array with sequential values."""
    arr = numpy_handler.arange(0, 10, 1)

    assert arr.size == 10
    assert arr.data[0] == 0
    assert arr.data[9] == 9


def test_linspace_creates_linearly_spaced_array() -> None:
    """linspace() creates evenly spaced values."""
    arr = numpy_handler.linspace(0, 10, 11)

    assert arr.size == 11
    assert arr.data[0] == 0
    assert arr.data[10] == 10


def test_array_reshape() -> None:
    """reshape() changes array dimensions correctly."""
    arr = numpy_handler.array([1, 2, 3, 4, 5, 6])

    reshaped = arr.reshape(2, 3)

    assert reshaped.shape == (2, 3)
    assert reshaped.size == 6


def test_array_reshape_invalid_size_raises_error() -> None:
    """reshape() raises ValueError for incompatible dimensions."""
    arr = numpy_handler.array([1, 2, 3, 4, 5])

    with pytest.raises(ValueError):
        arr.reshape(2, 3)


def test_array_flatten() -> None:
    """flatten() converts multi-dimensional array to 1D."""
    arr = numpy_handler.array([1, 2, 3, 4]).reshape(2, 2)

    flat = arr.flatten()

    assert flat.shape == (4,)
    assert flat.ndim == 1


def test_array_addition() -> None:
    """Array addition performs element-wise sum."""
    arr1 = numpy_handler.array([1, 2, 3])
    arr2 = numpy_handler.array([4, 5, 6])

    result = arr1 + arr2

    assert result.data == [5, 7, 9]


def test_array_subtraction() -> None:
    """Array subtraction performs element-wise difference."""
    arr1 = numpy_handler.array([10, 20, 30])
    arr2 = numpy_handler.array([1, 2, 3])

    result = arr1 - arr2

    assert result.data == [9, 18, 27]


def test_array_multiplication() -> None:
    """Array multiplication performs element-wise product."""
    arr1 = numpy_handler.array([2, 3, 4])
    arr2 = numpy_handler.array([5, 6, 7])

    result = arr1 * arr2

    assert result.data == [10, 18, 28]


def test_array_division() -> None:
    """Array division performs element-wise quotient."""
    arr1 = numpy_handler.array([10, 20, 30])
    arr2 = numpy_handler.array([2, 4, 5])

    result = arr1 / arr2

    assert result.data == [5.0, 5.0, 6.0]


def test_array_scalar_addition() -> None:
    """Array + scalar adds scalar to all elements."""
    arr = numpy_handler.array([1, 2, 3])

    result = arr + 10

    assert result.data == [11, 12, 13]


def test_array_scalar_multiplication() -> None:
    """Array * scalar multiplies all elements by scalar."""
    arr = numpy_handler.array([2, 4, 6])

    result = arr * 3

    assert result.data == [6, 12, 18]


def test_array_sum() -> None:
    """sum() calculates total of all elements."""
    arr = numpy_handler.array([1, 2, 3, 4, 5])

    total = arr.sum()

    assert total == 15.0


def test_array_mean() -> None:
    """mean() calculates arithmetic mean of elements."""
    arr = numpy_handler.array([10, 20, 30, 40])

    mean = arr.mean()

    assert mean == 25.0


def test_array_std() -> None:
    """std() calculates standard deviation."""
    arr = numpy_handler.array([2, 4, 6, 8])

    std = arr.std()

    assert std > 0


def test_array_min() -> None:
    """min() returns minimum element."""
    arr = numpy_handler.array([5, 2, 8, 1, 9])

    minimum = arr.min()

    assert minimum == 1.0


def test_array_max() -> None:
    """max() returns maximum element."""
    arr = numpy_handler.array([5, 2, 8, 1, 9])

    maximum = arr.max()

    assert maximum == 9.0


def test_array_argmin() -> None:
    """argmin() returns index of minimum element."""
    arr = numpy_handler.array([5, 2, 8, 1, 9])

    idx = arr.argmin()

    assert idx == 3


def test_array_argmax() -> None:
    """argmax() returns index of maximum element."""
    arr = numpy_handler.array([5, 2, 8, 1, 9])

    idx = arr.argmax()

    assert idx == 4


def test_sqrt_function() -> None:
    """sqrt() calculates square root of array elements."""
    arr = numpy_handler.array([4, 9, 16, 25])

    result = numpy_handler.sqrt(arr)

    assert result.data == [2.0, 3.0, 4.0, 5.0]


def test_dot_product() -> None:
    """dot() calculates dot product of two arrays."""
    arr1 = numpy_handler.array([1, 2, 3])
    arr2 = numpy_handler.array([4, 5, 6])

    result = numpy_handler.dot(arr1, arr2)

    assert result == 32.0


def test_cross_product() -> None:
    """cross() calculates cross product of 3D vectors."""
    arr1 = numpy_handler.array([1, 0, 0])
    arr2 = numpy_handler.array([0, 1, 0])

    result = numpy_handler.cross(arr1, arr2)

    assert result.data == [0.0, 0.0, 1.0]


def test_concatenate_arrays() -> None:
    """concatenate() joins multiple arrays."""
    arr1 = numpy_handler.array([1, 2, 3])
    arr2 = numpy_handler.array([4, 5, 6])

    result = numpy_handler.concatenate([arr1, arr2])

    assert result.data == [1, 2, 3, 4, 5, 6]


def test_unique_finds_unique_elements() -> None:
    """unique() returns array with unique elements only."""
    arr = numpy_handler.array([1, 2, 2, 3, 3, 3, 4])

    result = numpy_handler.unique(arr)

    assert set(result.data) == {1, 2, 3, 4}


def test_sort_array() -> None:
    """sort() returns sorted array."""
    arr = numpy_handler.array([5, 2, 8, 1, 9])

    result = numpy_handler.sort(arr)

    assert result.data == [1, 2, 5, 8, 9]


def test_argsort_returns_sorted_indices() -> None:
    """argsort() returns indices that would sort array."""
    arr = numpy_handler.array([5, 2, 8, 1, 9])

    indices = numpy_handler.argsort(arr)

    assert arr.data[indices.data[0]] == 1
    assert arr.data[indices.data[4]] == 9


def test_where_with_condition_only() -> None:
    """where() with condition only returns indices of True values."""
    condition = numpy_handler.array([True, False, True, False, True])

    result = numpy_handler.where(condition)

    assert isinstance(result, tuple)
    assert len(result) == 1
    assert 0 in result[0].data
    assert 2 in result[0].data
    assert 4 in result[0].data


def test_where_selects_values() -> None:
    """where() selects from x or y based on condition."""
    condition = numpy_handler.array([True, False, True])
    x = numpy_handler.array([10, 20, 30])
    y = numpy_handler.array([1, 2, 3])

    result = numpy_handler.where(condition, x, y)

    assert result.data == [10, 2, 30]


def test_allclose_returns_true_for_close_arrays() -> None:
    """allclose() returns True when arrays are element-wise close."""
    arr1 = numpy_handler.array([1.0, 2.0, 3.0])
    arr2 = numpy_handler.array([1.00001, 2.00001, 3.00001])

    result = numpy_handler.allclose(arr1, arr2)

    assert result is True


def test_allclose_returns_false_for_different_arrays() -> None:
    """allclose() returns False when arrays differ significantly."""
    arr1 = numpy_handler.array([1.0, 2.0, 3.0])
    arr2 = numpy_handler.array([1.5, 2.5, 3.5])

    result = numpy_handler.allclose(arr1, arr2)

    assert result is False


def test_array_equal_returns_true_for_identical() -> None:
    """array_equal() returns True for identical arrays."""
    arr1 = numpy_handler.array([1, 2, 3])
    arr2 = numpy_handler.array([1, 2, 3])

    result = numpy_handler.array_equal(arr1, arr2)

    assert result is True


def test_gradient_calculates_differences() -> None:
    """gradient() computes gradient using finite differences."""
    arr = numpy_handler.array([1, 3, 7, 13])

    result = numpy_handler.gradient(arr)

    assert result.size == arr.size


def test_diff_calculates_discrete_difference() -> None:
    """diff() calculates discrete difference between elements."""
    arr = numpy_handler.array([1, 3, 6, 10])

    result = numpy_handler.diff(arr)

    assert result.data == [2, 3, 4]


def test_cumsum_calculates_cumulative_sum() -> None:
    """cumsum() calculates cumulative sum of elements."""
    arr = numpy_handler.array([1, 2, 3, 4])

    result = numpy_handler.cumsum(arr)

    assert result.data == [1.0, 3.0, 6.0, 10.0]


def test_histogram_computes_distribution() -> None:
    """histogram() computes distribution of values."""
    arr = numpy_handler.array([1, 2, 2, 3, 3, 3, 4, 4, 4, 4])

    counts, edges = numpy_handler.histogram(arr, bins=4)

    assert counts.size == 4
    assert edges.size == 5


def test_percentile_calculates_percentile() -> None:
    """percentile() calculates specified percentile value."""
    arr = numpy_handler.array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

    p50 = numpy_handler.percentile(arr, 50)

    assert 5.0 <= p50 <= 6.0


def test_median_calculates_median() -> None:
    """median() calculates median value."""
    arr = numpy_handler.array([1, 3, 5, 7, 9])

    median = numpy_handler.median(arr)

    assert median == 5.0


def test_linalg_norm() -> None:
    """linalg.norm() calculates vector norm."""
    arr = numpy_handler.array([3, 4])

    norm = numpy_handler.linalg.norm(arr)

    assert norm == 5.0


def test_linalg_inv_2x2_matrix() -> None:
    """linalg.inv() calculates matrix inverse for 2x2."""
    matrix = numpy_handler.array([4, 7, 2, 6]).reshape(2, 2)

    inverse = numpy_handler.linalg.inv(matrix)

    assert inverse.shape == (2, 2)


def test_random_rand_generates_values() -> None:
    """random.rand() generates random values in [0, 1)."""
    arr = numpy_handler.random.rand(10)

    assert arr.size == 10
    assert all(0 <= x < 1 for x in arr.data)


def test_random_randn_generates_normal_distribution() -> None:
    """random.randn() generates normally distributed values."""
    arr = numpy_handler.random.randn(100)

    assert arr.size == 100


def test_random_randint_generates_integers() -> None:
    """random.randint() generates random integers in range."""
    arr = numpy_handler.random.randint(0, 10, size=20)

    assert arr.size == 20
    assert all(0 <= x < 10 for x in arr.data)


def test_random_choice_selects_elements() -> None:
    """random.choice() randomly selects elements."""
    arr = numpy_handler.array([1, 2, 3, 4, 5])

    result = numpy_handler.random.choice(arr, size=3)

    assert result.size == 3


def test_random_seed_sets_reproducibility() -> None:
    """random.seed() sets seed for reproducible results."""
    numpy_handler.random.seed(42)
    arr1 = numpy_handler.random.rand(5)

    numpy_handler.random.seed(42)
    arr2 = numpy_handler.random.rand(5)

    assert arr1.data == arr2.data


def test_fft_computes_fourier_transform() -> None:
    """fft.fft() computes discrete Fourier transform."""
    arr = numpy_handler.array([1, 2, 3, 4])

    result = numpy_handler.fft.fft(arr)

    assert result.size == 4


def test_fft_ifft_computes_inverse() -> None:
    """fft.ifft() computes inverse Fourier transform."""
    arr = numpy_handler.array([1, 2, 3, 4])

    fft_result = numpy_handler.fft.fft(arr)
    ifft_result = numpy_handler.fft.ifft(fft_result)

    assert ifft_result.size == 4


def test_eye_creates_identity_matrix() -> None:
    """eye() creates identity matrix."""
    identity = numpy_handler.eye(3)

    assert identity.shape == (3, 3)
    assert identity.data[0] == 1
    assert identity.data[4] == 1
    assert identity.data[8] == 1


def test_full_creates_filled_array() -> None:
    """full() creates array filled with specified value."""
    arr = numpy_handler.full(5, 7)

    assert arr.size == 5
    assert all(x == 7 for x in arr.data)


def test_transpose_2d_array() -> None:
    """transpose() transposes 2D array."""
    arr = numpy_handler.array([1, 2, 3, 4, 5, 6]).reshape(2, 3)

    transposed = numpy_handler.transpose(arr)

    assert transposed.shape == (3, 2)


def test_has_numpy_flag_is_boolean() -> None:
    """HAS_NUMPY is a boolean flag."""
    assert isinstance(numpy_handler.HAS_NUMPY, bool)


def test_numpy_version_is_string_or_none() -> None:
    """NUMPY_VERSION is None or valid version string."""
    version = numpy_handler.NUMPY_VERSION

    if version is not None:
        assert isinstance(version, str)


def test_module_exports_required_functions() -> None:
    """numpy_handler exports all required functions."""
    assert hasattr(numpy_handler, "array")
    assert hasattr(numpy_handler, "zeros")
    assert hasattr(numpy_handler, "ones")
    assert hasattr(numpy_handler, "arange")
    assert hasattr(numpy_handler, "linspace")
    assert hasattr(numpy_handler, "sqrt")
    assert hasattr(numpy_handler, "dot")
    assert hasattr(numpy_handler, "mean")
    assert hasattr(numpy_handler, "std")


def test_module_exports_required_submodules() -> None:
    """numpy_handler exports linalg, fft, and random submodules."""
    assert hasattr(numpy_handler, "linalg")
    assert hasattr(numpy_handler, "fft")
    assert hasattr(numpy_handler, "random")


def test_array_indexing() -> None:
    """Array supports integer indexing."""
    arr = numpy_handler.array([10, 20, 30, 40, 50])

    assert arr[0] == 10
    assert arr[4] == 50


def test_array_slicing() -> None:
    """Array supports slice indexing."""
    arr = numpy_handler.array([1, 2, 3, 4, 5])

    sliced = arr[1:4]

    assert sliced.size == 3
    assert sliced.data == [2, 3, 4]


def test_array_copy() -> None:
    """copy() creates independent copy of array."""
    arr1 = numpy_handler.array([1, 2, 3])

    arr2 = arr1.copy()

    arr2.data[0] = 999

    assert arr1.data[0] == 1


def test_array_astype_converts_dtype() -> None:
    """astype() converts array to different data type."""
    arr = numpy_handler.array([1.5, 2.7, 3.9])

    int_arr = arr.astype(int)

    assert int_arr.dtype == int
    assert int_arr.data == [1, 2, 3]


def test_floor_rounds_down() -> None:
    """floor() rounds down to nearest integer."""
    arr = numpy_handler.array([1.9, 2.5, 3.1])

    result = numpy_handler.floor(arr)

    assert result.data == [1, 2, 3]


def test_ceil_rounds_up() -> None:
    """ceil() rounds up to nearest integer."""
    arr = numpy_handler.array([1.1, 2.5, 3.9])

    result = numpy_handler.ceil(arr)

    assert result.data == [2, 3, 4]


def test_abs_calculates_absolute_value() -> None:
    """abs() calculates absolute value of elements."""
    arr = numpy_handler.array([-1, -2, 3, -4])

    result = numpy_handler.np_abs(arr)

    assert result.data == [1.0, 2.0, 3.0, 4.0]


def test_round_rounds_to_decimals() -> None:
    """round() rounds to specified decimal places."""
    arr = numpy_handler.array([1.234, 2.567, 3.891])

    result = numpy_handler.np_round(arr, decimals=1)

    assert all(abs(a - b) < 0.01 for a, b in zip(result.data, [1.2, 2.6, 3.9], strict=False))


def test_meshgrid_creates_coordinate_matrices() -> None:
    """meshgrid() creates coordinate arrays for 2D grids."""
    x = numpy_handler.array([1, 2, 3])
    y = numpy_handler.array([4, 5])

    xx, yy = numpy_handler.meshgrid(x, y)

    assert xx.size == 6
    assert yy.size == 6


def test_var_calculates_variance() -> None:
    """var() calculates variance of elements."""
    arr = numpy_handler.array([2, 4, 6, 8])

    variance = numpy_handler.var(arr)

    assert variance > 0


def test_stack_stacks_arrays() -> None:
    """stack() stacks arrays along axis."""
    arr1 = numpy_handler.array([1, 2, 3])
    arr2 = numpy_handler.array([4, 5, 6])

    result = numpy_handler.stack([arr1, arr2])

    assert result.size == 6


def test_empty_creates_uninitialized_array() -> None:
    """empty() creates array with specified shape."""
    arr = numpy_handler.empty(5)

    assert arr.shape == (5,)
    assert arr.size == 5


def test_asarray_converts_list() -> None:
    """asarray() converts list to array."""
    data = [1, 2, 3, 4]

    arr = numpy_handler.asarray(data)

    assert arr.size == 4
    assert arr.data == data


class TestFallbackArrayBasicOperations:
    """Tests for FallbackArray basic operations (no axis support)."""

    def test_sum_returns_scalar(self) -> None:
        """sum() returns sum of all elements as float."""
        from intellicrack.handlers.numpy_handler import FallbackArray

        arr = FallbackArray([1, 2, 3, 4, 5, 6], float, (2, 3))

        result = arr.sum()

        assert result == 21.0
        assert isinstance(result, float)

    def test_mean_returns_scalar(self) -> None:
        """mean() returns mean of all elements."""
        from intellicrack.handlers.numpy_handler import FallbackArray

        arr = FallbackArray([2, 4, 6, 8], float, (2, 2))

        result = arr.mean()

        assert result == 5.0
        assert isinstance(result, float)

    def test_std_returns_scalar(self) -> None:
        """std() returns std of all elements."""
        from intellicrack.handlers.numpy_handler import FallbackArray

        arr = FallbackArray([2, 4, 4, 4, 5, 5, 7, 9], float, (2, 4))

        result = arr.std()

        assert isinstance(result, float)
        assert result > 0

    def test_min_returns_scalar(self) -> None:
        """min() returns minimum of all elements."""
        from intellicrack.handlers.numpy_handler import FallbackArray

        arr = FallbackArray([5, 2, 8, 1, 9, 3], float, (2, 3))

        result = arr.min()

        assert result == 1.0
        assert isinstance(result, float)

    def test_max_returns_scalar(self) -> None:
        """max() returns maximum of all elements."""
        from intellicrack.handlers.numpy_handler import FallbackArray

        arr = FallbackArray([5, 2, 8, 1, 9, 3], float, (2, 3))

        result = arr.max()

        assert result == 9.0
        assert isinstance(result, float)

    def test_argmin_returns_int(self) -> None:
        """argmin() returns index in flat array."""
        from intellicrack.handlers.numpy_handler import FallbackArray

        arr = FallbackArray([5, 2, 8, 1, 9, 3], float, (2, 3))

        result = arr.argmin()

        assert result == 3
        assert isinstance(result, int)

    def test_argmax_returns_int(self) -> None:
        """argmax() returns index in flat array."""
        from intellicrack.handlers.numpy_handler import FallbackArray

        arr = FallbackArray([5, 2, 8, 1, 9, 3], float, (2, 3))

        result = arr.argmax()

        assert result == 4
        assert isinstance(result, int)


class TestConcatenateFuncBasic:
    """Tests for concatenate_func basic operations."""

    def test_concatenate_1d_arrays(self) -> None:
        """concatenate() joins 1D arrays."""
        from intellicrack.handlers.numpy_handler import FallbackArray, _FallbackFunctions

        arr1 = FallbackArray([1, 2, 3])
        arr2 = FallbackArray([4, 5, 6])

        result = _FallbackFunctions.concatenate_func([arr1, arr2])

        assert result.data == [1, 2, 3, 4, 5, 6]

    def test_concatenate_empty_list_returns_empty(self) -> None:
        """concatenate() with empty list returns empty array."""
        from intellicrack.handlers.numpy_handler import FallbackArray, _FallbackFunctions

        result = _FallbackFunctions.concatenate_func([])

        assert isinstance(result, FallbackArray)
        assert result.data == []

    def test_concatenate_multiple_arrays(self) -> None:
        """concatenate() handles more than 2 arrays."""
        from intellicrack.handlers.numpy_handler import FallbackArray, _FallbackFunctions

        arr1 = FallbackArray([1, 2])
        arr2 = FallbackArray([3, 4])
        arr3 = FallbackArray([5, 6])

        result = _FallbackFunctions.concatenate_func([arr1, arr2, arr3])

        assert result.data == [1, 2, 3, 4, 5, 6]


class TestGradientFuncBasic:
    """Tests for gradient_func basic operations."""

    def test_gradient_default_spacing(self) -> None:
        """gradient() with default computes finite differences."""
        from intellicrack.handlers.numpy_handler import FallbackArray, _FallbackFunctions

        arr = FallbackArray([1, 2, 4, 7, 11])

        result = _FallbackFunctions.gradient_func(arr)

        assert isinstance(result, FallbackArray)
        assert result.data[0] == 1.0
        assert result.data[1] == 1.5
        assert result.data[2] == 2.5
        assert result.data[3] == 3.5
        assert result.data[4] == 4.0

    def test_gradient_uniform_spacing(self) -> None:
        """gradient() with uniform spacing scales properly."""
        from intellicrack.handlers.numpy_handler import FallbackArray, _FallbackFunctions

        arr = FallbackArray([0, 2, 4, 6, 8])

        result = _FallbackFunctions.gradient_func(arr, 2.0)

        assert result.data[0] == 1.0

    def test_gradient_single_element(self) -> None:
        """gradient() with single element returns 0."""
        from intellicrack.handlers.numpy_handler import FallbackArray, _FallbackFunctions

        arr = FallbackArray([5])

        result = _FallbackFunctions.gradient_func(arr)

        assert result.data[0] == 0.0

    def test_gradient_two_elements(self) -> None:
        """gradient() with two elements uses forward/backward difference."""
        from intellicrack.handlers.numpy_handler import FallbackArray, _FallbackFunctions

        arr = FallbackArray([2, 5])

        result = _FallbackFunctions.gradient_func(arr)

        assert result.data[0] == 3.0
        assert result.data[1] == 3.0


class TestFallbackArrayEdgeCases:
    """Tests for edge cases in FallbackArray operations."""

    def test_empty_array_sum_returns_zero(self) -> None:
        """sum() on empty array returns 0."""
        from intellicrack.handlers.numpy_handler import FallbackArray

        arr = FallbackArray([])

        result = arr.sum()

        assert result == 0.0

    def test_empty_array_mean_returns_zero(self) -> None:
        """mean() on empty array returns 0."""
        from intellicrack.handlers.numpy_handler import FallbackArray

        arr = FallbackArray([])

        result = arr.mean()

        assert result == 0.0

    def test_empty_array_min_returns_float(self) -> None:
        """min() on empty array returns default float min."""
        from intellicrack.handlers.numpy_handler import FallbackArray

        arr = FallbackArray([])

        result = arr.min()

        assert isinstance(result, float)

    def test_empty_array_max_returns_float(self) -> None:
        """max() on empty array returns default float max."""
        from intellicrack.handlers.numpy_handler import FallbackArray

        arr = FallbackArray([])

        result = arr.max()

        assert isinstance(result, float)

    def test_single_element_std_returns_zero(self) -> None:
        """std() of single element is 0."""
        from intellicrack.handlers.numpy_handler import FallbackArray

        arr = FallbackArray([42])

        result = arr.std()

        assert result == 0.0


class TestStaticFunctionBasic:
    """Tests for _FallbackFunctions static methods basic operations."""

    def test_sum_func_returns_float(self) -> None:
        """sum_func returns float."""
        from intellicrack.handlers.numpy_handler import FallbackArray, _FallbackFunctions

        arr = FallbackArray([1, 2, 3, 4], float, (2, 2))

        result = _FallbackFunctions.sum_func(arr)

        assert isinstance(result, float)
        assert result == 10.0

    def test_mean_func_returns_float(self) -> None:
        """mean_func returns float."""
        from intellicrack.handlers.numpy_handler import FallbackArray, _FallbackFunctions

        arr = FallbackArray([1, 2, 3, 4], float, (2, 2))

        result = _FallbackFunctions.mean_func(arr)

        assert isinstance(result, float)
        assert result == 2.5

    def test_min_func_with_list(self) -> None:
        """min_func works with list."""
        from intellicrack.handlers.numpy_handler import _FallbackFunctions

        result = _FallbackFunctions.min_func([5, 2, 8, 1])

        assert result == 1.0
