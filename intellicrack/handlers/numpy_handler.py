"""Numpy handler for Intellicrack.

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
import random as _random

from intellicrack.utils.logger import logger

"""
NumPy Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for NumPy imports.
When NumPy is not available, it provides REAL, functional Python-based
implementations for essential operations used in Intellicrack.
"""

# NumPy availability detection and import handling
try:
    import numpy as np

    # NumPy submodules
    from numpy import (
        abs as np_abs,
    )
    from numpy import (
        allclose,
        arange,
        argmax,
        argmin,
        argsort,
        array,
        array_equal,
        asarray,
        ceil,
        concatenate,
        cross,
        cumsum,
        diff,
        dot,
        dtype,
        empty,
        eye,
        fft,
        float32,
        float64,
        floor,
        full,
        gradient,
        histogram,
        int32,
        int64,
        linalg,
        linspace,
        mean,
        median,
        meshgrid,
        ndarray,
        ones,
        percentile,
        random,
        reshape,
        sort,
        sqrt,
        stack,
        std,
        transpose,
        uint8,
        uint16,
        uint32,
        unique,
        var,
        where,
        zeros,
    )
    from numpy import (
        max as np_max,
    )
    from numpy import (
        min as np_min,
    )
    from numpy import (
        round as np_round,
    )
    from numpy import (
        sum as np_sum,
    )

    HAS_NUMPY = True
    NUMPY_VERSION = np.__version__

except ImportError as e:
    logger.error("NumPy not available, using fallback implementations: %s", e)
    HAS_NUMPY = False
    NUMPY_VERSION = None

    # Production-ready fallback implementations for Intellicrack's binary analysis needs

    class FallbackArray:
        """Functional array implementation for binary analysis operations.

        This class provides NumPy-like array functionality when NumPy is unavailable.
        It supports basic array operations including indexing, slicing, reshaping,
        and mathematical operations used in binary analysis and signal processing.
        """

        def __init__(self, data: list | tuple | "FallbackArray" | float, dtype: type | None = None, shape: tuple[int, ...] | None = None) -> None:
            """Initialize array with data, dtype, and shape.

            Args:
                data: Array data as list, tuple, FallbackArray, or scalar value
                dtype: Data type for array elements; defaults to type of first element
                shape: Target shape for the array as tuple of dimensions

            """
            if isinstance(data, (list, tuple)):
                self.data = list(data)
            elif isinstance(data, FallbackArray):
                self.data = data.data.copy()
            else:
                self.data = [data]

            self.dtype = dtype or type(self.data[0]) if self.data else float
            self._shape = shape or (len(self.data),)

            if isinstance(self.data[0], (list, tuple)):
                self.data = self._flatten(self.data)

        def _flatten(self, lst: list | tuple) -> list:
            """Flatten nested lists.

            Args:
                lst: Nested list or tuple to flatten

            Returns:
                Single-level list with all elements from nested structure

            """
            result = []
            for item in lst:
                if isinstance(item, (list, tuple)):
                    result.extend(self._flatten(item))
                else:
                    result.append(item)
            return result

        @property
        def shape(self) -> tuple[int, ...]:
            """Get array shape.

            Returns:
                Tuple representing dimensions of the array

            """
            return self._shape

        @property
        def size(self) -> int:
            """Get total number of elements.

            Returns:
                Total number of elements in the array

            """
            return len(self.data)

        @property
        def ndim(self) -> int:
            """Get number of dimensions.

            Returns:
                Number of dimensions in the array

            """
            return len(self._shape)

        def reshape(self, *new_shape: int) -> "FallbackArray":
            """Reshape array to new dimensions.

            Args:
                *new_shape: New shape as variable arguments or single tuple

            Returns:
                New FallbackArray with reshaped data

            Raises:
                ValueError: If total elements don't match new shape

            """
            if len(new_shape) == 1 and isinstance(new_shape[0], (list, tuple)):
                new_shape = new_shape[0]

            total = 1
            for dim in new_shape:
                total *= dim

            if total != self.size:
                raise ValueError(f"Cannot reshape array of size {self.size} into shape {new_shape}")

            result = FallbackArray(self.data.copy(), self.dtype, new_shape)
            return result

        def flatten(self) -> "FallbackArray":
            """Flatten array to 1D.

            Returns:
                Flattened 1D FallbackArray

            """
            return FallbackArray(self.data.copy(), self.dtype, (self.size,))

        def tolist(self) -> list:
            """Convert to Python list.

            Returns:
                List representation of array data

            """
            if self.ndim == 1:
                return self.data.copy()

            result = self.data.copy()
            for dim in reversed(self._shape[1:]):
                temp = []
                for i in range(0, len(result), dim):
                    temp.append(result[i : i + dim])
                result = temp
            return result[0] if len(result) == 1 else result

        def copy(self) -> "FallbackArray":
            """Create a copy of the array.

            Returns:
                Deep copy of this FallbackArray

            """
            return FallbackArray(self.data.copy(), self.dtype, self._shape)

        def astype(self, dtype: type) -> "FallbackArray":
            """Convert array to new data type.

            Args:
                dtype: Target data type for conversion

            Returns:
                New FallbackArray with converted data type

            """
            converter = dtype if callable(dtype) else lambda x: dtype(x)
            new_data = [converter(x) for x in self.data]
            return FallbackArray(new_data, dtype, self._shape)

        def __getitem__(self, key: int | slice | list | tuple) -> "FallbackArray" | int | float:
            """Get item or slice.

            Args:
                key: Integer index, slice, or list of indices

            Returns:
                Single element or FallbackArray with selected elements

            """
            if isinstance(key, int):
                return self.data[key]
            if isinstance(key, slice):
                return FallbackArray(self.data[key], self.dtype)
            if isinstance(key, (list, tuple)):
                return FallbackArray([self.data[i] for i in key], self.dtype)
            return self.data[key]

        def __setitem__(self, key: int | slice, value: float | "FallbackArray" | list) -> None:
            """Set item or slice.

            Args:
                key: Integer index or slice to assign to
                value: Value or array to assign

            """
            if isinstance(key, int):
                self.data[key] = value
            elif isinstance(key, slice):
                if isinstance(value, FallbackArray):
                    self.data[key] = value.data
                else:
                    self.data[key] = value

        def __len__(self) -> int:
            """Get length of first dimension.

            Returns:
                Size of first dimension

            """
            return self._shape[0] if self._shape else 0

        def __repr__(self) -> str:
            """Represent as string.

            Returns:
                String representation of the array

            """
            return f"FallbackArray({self.tolist()})"

        def __add__(self, other: "FallbackArray" | float) -> "FallbackArray":
            """Element-wise addition.

            Args:
                other: FallbackArray or scalar to add

            Returns:
                New FallbackArray with element-wise sum

            """
            if isinstance(other, FallbackArray):
                result = [a + b for a, b in zip(self.data, other.data, strict=False)]
            else:
                result = [a + other for a in self.data]
            return FallbackArray(result, self.dtype, self._shape)

        def __sub__(self, other: "FallbackArray" | float) -> "FallbackArray":
            """Element-wise subtraction.

            Args:
                other: FallbackArray or scalar to subtract

            Returns:
                New FallbackArray with element-wise difference

            """
            if isinstance(other, FallbackArray):
                result = [a - b for a, b in zip(self.data, other.data, strict=False)]
            else:
                result = [a - other for a in self.data]
            return FallbackArray(result, self.dtype, self._shape)

        def __mul__(self, other: "FallbackArray" | float) -> "FallbackArray":
            """Element-wise multiplication.

            Args:
                other: FallbackArray or scalar to multiply

            Returns:
                New FallbackArray with element-wise product

            """
            if isinstance(other, FallbackArray):
                result = [a * b for a, b in zip(self.data, other.data, strict=False)]
            else:
                result = [a * other for a in self.data]
            return FallbackArray(result, self.dtype, self._shape)

        def __truediv__(self, other: "FallbackArray" | float) -> "FallbackArray":
            """Element-wise division.

            Args:
                other: FallbackArray or scalar to divide by

            Returns:
                New FallbackArray with element-wise quotient

            """
            if isinstance(other, FallbackArray):
                result = [a / b for a, b in zip(self.data, other.data, strict=False)]
            else:
                result = [a / other for a in self.data]
            return FallbackArray(result, self.dtype, self._shape)

        def sum(self, axis: int | None = None) -> int | float:
            """Sum of array elements.

            Args:
                axis: Axis along which to sum; currently unused for fallback

            Returns:
                Sum of all elements

            """
            if axis is None:
                return sum(self.data)
            return sum(self.data)

        def mean(self) -> float:
            """Mean of array elements.

            Returns:
                Arithmetic mean of array elements

            """
            return sum(self.data) / len(self.data) if self.data else 0

        def std(self) -> float:
            """Calculate standard deviation of array elements.

            Returns:
                Standard deviation of array elements

            """
            m = self.mean()
            variance = sum((x - m) ** 2 for x in self.data) / len(self.data)
            return math.sqrt(variance)

        def min(self) -> int | float | None:
            """Minimum value.

            Returns:
                Minimum element in array or None if empty

            """
            return min(self.data) if self.data else None

        def max(self) -> int | float | None:
            """Maximum value.

            Returns:
                Maximum element in array or None if empty

            """
            return max(self.data) if self.data else None

        def argmin(self) -> int | None:
            """Index of minimum value.

            Returns:
                Index of minimum element or None if empty

            """
            if not self.data:
                return None
            min_val = min(self.data)
            return self.data.index(min_val)

        def argmax(self) -> int | None:
            """Index of maximum value.

            Returns:
                Index of maximum element or None if empty

            """
            if not self.data:
                return None
            max_val = max(self.data)
            return self.data.index(max_val)

    # Fallback array creation functions
    def array(data: list | tuple | "FallbackArray" | float, dtype: type | None = None) -> "FallbackArray":
        """Create array from data.

        Args:
            data: Input data for array creation
            dtype: Optional data type for array elements

        Returns:
            FallbackArray created from input data

        """
        return FallbackArray(data, dtype)

    def zeros(shape: int | tuple[int, ...], dtype: type = float) -> "FallbackArray":
        """Create array of zeros.

        Args:
            shape: Shape of array as integer or tuple of integers
            dtype: Data type for array elements; defaults to float

        Returns:
            FallbackArray filled with zeros

        """
        if isinstance(shape, int):
            shape = (shape,)
        total = 1
        for dim in shape:
            total *= dim
        return FallbackArray([0] * total, dtype, shape)

    def ones(shape: int | tuple[int, ...], dtype: type = float) -> "FallbackArray":
        """Create array of ones.

        Args:
            shape: Shape of array as integer or tuple of integers
            dtype: Data type for array elements; defaults to float

        Returns:
            FallbackArray filled with ones

        """
        if isinstance(shape, int):
            shape = (shape,)
        total = 1
        for dim in shape:
            total *= dim
        return FallbackArray([1] * total, dtype, shape)

    def empty(shape: int | tuple[int, ...], dtype: type = float) -> "FallbackArray":
        """Create uninitialized array (returns zeros for safety).

        Args:
            shape: Shape of array as integer or tuple of integers
            dtype: Data type for array elements; defaults to float

        Returns:
            FallbackArray with shape initialized to zeros

        """
        return zeros(shape, dtype)

    def full(shape: int | tuple[int, ...], fill_value: float, dtype: type | None = None) -> "FallbackArray":
        """Create array filled with value.

        Args:
            shape: Shape of array as integer or tuple of integers
            fill_value: Value to fill array with
            dtype: Optional data type; defaults to type of fill_value

        Returns:
            FallbackArray filled with the specified value

        """
        if isinstance(shape, int):
            shape = (shape,)
        total = 1
        for dim in shape:
            total *= dim
        dtype = dtype or type(fill_value)
        return FallbackArray([fill_value] * total, dtype, shape)

    def eye(N: int, M: int | None = None, k: int = 0, dtype: type = float) -> "FallbackArray":
        """Create identity matrix.

        Args:
            N: Number of rows
            M: Number of columns; defaults to N if None
            k: Diagonal offset from main diagonal
            dtype: Data type for array elements; defaults to float

        Returns:
            Identity-like FallbackArray with ones on offset diagonal

        """
        M = M or N
        result = []
        for i in range(N):
            row = []
            for j in range(M):
                row.append(1 if i - j == -k else 0)
            result.append(row)
        return FallbackArray(result, dtype, (N, M))

    def arange(start: float, stop: float | None = None, step: float = 1, dtype: type | None = None) -> "FallbackArray":
        """Create array with range of values.

        Args:
            start: Start value or stop if stop is None
            stop: End value (exclusive); if None, start becomes stop and start becomes 0
            step: Increment between values; defaults to 1
            dtype: Optional data type; defaults to type of start

        Returns:
            FallbackArray with values from start to stop with given step

        """
        if stop is None:
            stop = start
            start = 0

        result = []
        current = start
        while (step > 0 and current < stop) or (step < 0 and current > stop):
            result.append(current)
            current += step

        return FallbackArray(result, dtype or type(start))

    def linspace(start: float, stop: float, num: int = 50) -> "FallbackArray":
        """Create linearly spaced array.

        Args:
            start: Start value
            stop: End value
            num: Number of samples to generate; defaults to 50

        Returns:
            FallbackArray with linearly spaced values

        """
        if num <= 0:
            return FallbackArray([])
        if num == 1:
            return FallbackArray([start])

        step = (stop - start) / (num - 1)
        result = [start + i * step for i in range(num)]
        return FallbackArray(result)

    def meshgrid(*xi: list | tuple | "FallbackArray") -> list["FallbackArray"]:
        """Create coordinate matrices from coordinate vectors.

        Args:
            *xi: Variable number of coordinate arrays

        Returns:
            List of FallbackArrays representing coordinate matrices

        """
        if len(xi) == 0:
            return []
        if len(xi) == 1:
            return [FallbackArray(xi[0])]

        x = xi[0] if isinstance(xi[0], FallbackArray) else FallbackArray(xi[0])
        y = xi[1] if isinstance(xi[1], FallbackArray) else FallbackArray(xi[1])

        xx = []
        yy = []
        for j in y.data:
            for i in x.data:
                xx.append(i)
                yy.append(j)

        return [FallbackArray(xx, shape=(len(y.data), len(x.data))), FallbackArray(yy, shape=(len(y.data), len(x.data)))]

    # Math operations
    def sqrt(x: "FallbackArray" | float) -> "FallbackArray" | float:
        """Square root.

        Args:
            x: FallbackArray or numeric value

        Returns:
            FallbackArray with square root of elements, or float for scalar input

        """
        if isinstance(x, FallbackArray):
            return FallbackArray([math.sqrt(val) for val in x.data], x.dtype, x.shape)
        return math.sqrt(x)

    def abs(x: "FallbackArray" | float) -> "FallbackArray" | int | float:
        """Absolute value.

        Args:
            x: FallbackArray or numeric value

        Returns:
            FallbackArray with absolute values, or numeric type for scalar input

        """
        if isinstance(x, FallbackArray):
            return FallbackArray([abs(val) for val in x.data], x.dtype, x.shape)
        return abs(x)

    def round(x: "FallbackArray" | float, decimals: int = 0) -> "FallbackArray" | int | float:
        """Round to decimals.

        Args:
            x: FallbackArray or numeric value
            decimals: Number of decimal places; defaults to 0

        Returns:
            FallbackArray with rounded values, or numeric type for scalar input

        """
        if isinstance(x, FallbackArray):
            factor = 10**decimals
            return FallbackArray([round(val * factor) / factor for val in x.data], x.dtype, x.shape)
        return round(x, decimals)

    def floor(x: "FallbackArray" | float) -> "FallbackArray" | int:
        """Floor operation.

        Args:
            x: FallbackArray or numeric value

        Returns:
            FallbackArray with floor of elements, or int for scalar input

        """
        if isinstance(x, FallbackArray):
            return FallbackArray([math.floor(val) for val in x.data], x.dtype, x.shape)
        return math.floor(x)

    def ceil(x: "FallbackArray" | float) -> "FallbackArray" | int:
        """Ceiling operation.

        Args:
            x: FallbackArray or numeric value

        Returns:
            FallbackArray with ceiling of elements, or int for scalar input

        """
        if isinstance(x, FallbackArray):
            return FallbackArray([math.ceil(val) for val in x.data], x.dtype, x.shape)
        return math.ceil(x)

    # Array operations
    def concatenate(arrays: list["FallbackArray"] | list[list], axis: int = 0) -> "FallbackArray":
        """Concatenate arrays.

        Args:
            arrays: List of FallbackArrays or lists to concatenate
            axis: Axis along which to concatenate; currently unused for fallback

        Returns:
            Concatenated FallbackArray

        """
        if not arrays:
            return FallbackArray([])

        result = []
        for arr in arrays:
            if isinstance(arr, FallbackArray):
                result.extend(arr.data)
            else:
                result.extend(arr)

        return FallbackArray(result)

    def stack(arrays: list["FallbackArray"] | list[list], axis: int = 0) -> "FallbackArray":
        """Stack arrays.

        Args:
            arrays: List of FallbackArrays or lists to stack
            axis: Axis along which to stack; currently unused for fallback

        Returns:
            Stacked FallbackArray

        """
        return concatenate(arrays, axis)

    def unique(ar: "FallbackArray" | list) -> "FallbackArray":
        """Find unique elements.

        Args:
            ar: FallbackArray or list to find unique elements in

        Returns:
            FallbackArray with unique elements

        """
        if isinstance(ar, FallbackArray):
            data = ar.data
        else:
            data = ar

        seen = set()
        result = []
        for x in data:
            if x not in seen:
                seen.add(x)
                result.append(x)

        return FallbackArray(result)

    def sort(a: "FallbackArray" | list) -> "FallbackArray" | list:
        """Sort array.

        Args:
            a: FallbackArray or list to sort

        Returns:
            FallbackArray with sorted elements, or sorted list for list input

        """
        if isinstance(a, FallbackArray):
            return FallbackArray(sorted(a.data), a.dtype, a.shape)
        return sorted(a)

    def argsort(a: "FallbackArray" | list) -> "FallbackArray":
        """Get indices that would sort array.

        Args:
            a: FallbackArray or list to sort

        Returns:
            FallbackArray with indices that would sort the input

        """
        if isinstance(a, FallbackArray):
            data = a.data
        else:
            data = a

        indices = list(range(len(data)))
        indices.sort(key=lambda i: data[i])
        return FallbackArray(indices)

    def where(condition: "FallbackArray" | list, x: "FallbackArray" | float | None = None, y: "FallbackArray" | float | None = None) -> "FallbackArray" | tuple:
        """Return elements chosen from x or y depending on condition.

        Args:
            condition: FallbackArray or list of boolean values
            x: Values to select where condition is True
            y: Values to select where condition is False

        Returns:
            FallbackArray with selected elements, or tuple of indices if x and y are None

        """
        if x is None and y is None:
            if isinstance(condition, FallbackArray):
                indices = [i for i, val in enumerate(condition.data) if val]
            else:
                indices = [i for i, val in enumerate(condition) if val]
            return (FallbackArray(indices),)

        result = []
        cond_data = condition.data if isinstance(condition, FallbackArray) else condition
        x_data = x.data if isinstance(x, FallbackArray) else [x] * len(cond_data)
        y_data = y.data if isinstance(y, FallbackArray) else [y] * len(cond_data)

        for c, xv, yv in zip(cond_data, x_data, y_data, strict=False):
            result.append(xv if c else yv)

        return FallbackArray(result)

    def allclose(a: "FallbackArray" | list, b: "FallbackArray" | list, rtol: float = 1e-05, atol: float = 1e-08) -> bool:
        """Check if arrays are element-wise equal within tolerance.

        Args:
            a: First FallbackArray or list
            b: Second FallbackArray or list
            rtol: Relative tolerance; defaults to 1e-05
            atol: Absolute tolerance; defaults to 1e-08

        Returns:
            True if arrays are close within tolerance, False otherwise

        """
        a_data = a.data if isinstance(a, FallbackArray) else a
        b_data = b.data if isinstance(b, FallbackArray) else b

        if len(a_data) != len(b_data):
            return False

        for av, bv in zip(a_data, b_data, strict=False):
            if np_abs(av - bv) > atol + rtol * np_abs(bv):
                return False
        return True

    def array_equal(a: "FallbackArray" | list, b: "FallbackArray" | list) -> bool:
        """Check if arrays are exactly equal.

        Args:
            a: First FallbackArray or list
            b: Second FallbackArray or list

        Returns:
            True if arrays are exactly equal, False otherwise

        """
        a_data = a.data if isinstance(a, FallbackArray) else a
        b_data = b.data if isinstance(b, FallbackArray) else b
        return a_data == b_data

    def asarray(a: "FallbackArray" | list, dtype: type | None = None) -> "FallbackArray":
        """Convert to array.

        Args:
            a: Input data to convert to array
            dtype: Optional data type for conversion

        Returns:
            FallbackArray with input data

        """
        if isinstance(a, FallbackArray):
            return a if dtype is None else a.astype(dtype)
        return FallbackArray(a, dtype)

    def gradient(f: "FallbackArray" | list, *varargs: float) -> "FallbackArray":
        """Calculate gradient using finite differences.

        Args:
            f: FallbackArray or list to compute gradient for
            *varargs: Additional parameters (currently unused for fallback)

        Returns:
            FallbackArray with gradient values using forward, backward, or central differences

        """
        if isinstance(f, FallbackArray):
            data = f.data
        else:
            data = f

        result = []
        for i in range(len(data)):
            if i == 0:
                grad = data[1] - data[0] if len(data) > 1 else 0
            elif i == len(data) - 1:
                grad = data[-1] - data[-2]
            else:
                grad = (data[i + 1] - data[i - 1]) / 2
            result.append(grad)

        return FallbackArray(result)

    def diff(a: "FallbackArray" | list, n: int = 1) -> "FallbackArray":
        """Calculate n-th discrete difference.

        Args:
            a: FallbackArray or list to compute differences for
            n: Order of difference; defaults to 1

        Returns:
            FallbackArray with differences

        """
        if isinstance(a, FallbackArray):
            data = a.data
        else:
            data = a

        for _ in range(n):
            result = []
            for i in range(1, len(data)):
                result.append(data[i] - data[i - 1])
            data = result

        return FallbackArray(data)

    def cumsum(a: "FallbackArray" | list) -> "FallbackArray":
        """Cumulative sum.

        Args:
            a: FallbackArray or list to compute cumulative sum for

        Returns:
            FallbackArray with cumulative sum

        """
        if isinstance(a, FallbackArray):
            data = a.data
        else:
            data = a

        result = []
        total = 0
        for val in data:
            total += val
            result.append(total)

        return FallbackArray(result)

    def histogram(a: "FallbackArray" | list, bins: int = 10) -> tuple["FallbackArray", "FallbackArray"]:
        """Compute histogram.

        Args:
            a: FallbackArray or list to compute histogram for
            bins: Number of bins; defaults to 10

        Returns:
            Tuple of (counts, bin_edges) as FallbackArrays

        """
        if isinstance(a, FallbackArray):
            data = a.data
        else:
            data = a

        if not data:
            return FallbackArray([0] * bins), FallbackArray([0] * (bins + 1))

        min_val = min(data)
        max_val = max(data)

        if min_val == max_val:
            return FallbackArray([len(data)]), FallbackArray([min_val, max_val])

        bin_width = (max_val - min_val) / bins
        edges = [min_val + i * bin_width for i in range(bins + 1)]

        counts = [0] * bins
        for val in data:
            bin_idx = min(int((val - min_val) / bin_width), bins - 1)
            counts[bin_idx] += 1

        return FallbackArray(counts), FallbackArray(edges)

    def percentile(a: "FallbackArray" | list, q: float) -> int | float | None:
        """Calculate percentile.

        Args:
            a: FallbackArray or list to compute percentile for
            q: Percentile value (0-100)

        Returns:
            Percentile value, or None if input is empty

        """
        if isinstance(a, FallbackArray):
            data = sorted(a.data)
        else:
            data = sorted(a)

        if not data:
            return None

        k = (len(data) - 1) * (q / 100.0)
        f = math.floor(k)
        c = math.ceil(k)

        if f == c:
            return data[int(k)]

        d0 = data[int(f)] * (c - k)
        d1 = data[int(c)] * (k - f)
        return d0 + d1

    def median(a: "FallbackArray" | list) -> int | float | None:
        """Calculate median.

        Args:
            a: FallbackArray or list to compute median for

        Returns:
            Median value, or None if input is empty

        """
        return percentile(a, 50)

    def dot(a: "FallbackArray" | list, b: "FallbackArray" | list) -> int | float:
        """Dot product of two arrays.

        Args:
            a: First FallbackArray or list
            b: Second FallbackArray or list

        Returns:
            Dot product result

        Raises:
            ValueError: If arrays have different lengths

        """
        a_data = a.data if isinstance(a, FallbackArray) else a
        b_data = b.data if isinstance(b, FallbackArray) else b

        if len(a_data) != len(b_data):
            raise ValueError("Arrays must have same length for dot product")

        return sum(av * bv for av, bv in zip(a_data, b_data, strict=False))

    def cross(a: "FallbackArray" | list, b: "FallbackArray" | list) -> "FallbackArray":
        """Cross product of two 3D vectors.

        Args:
            a: First FallbackArray or list (3D vector)
            b: Second FallbackArray or list (3D vector)

        Returns:
            FallbackArray with cross product result

        Raises:
            ValueError: If vectors are not 3D

        """
        a_data = a.data if isinstance(a, FallbackArray) else a
        b_data = b.data if isinstance(b, FallbackArray) else b

        if len(a_data) != 3 or len(b_data) != 3:
            raise ValueError("Cross product requires 3D vectors")

        result = [
            a_data[1] * b_data[2] - a_data[2] * b_data[1],
            a_data[2] * b_data[0] - a_data[0] * b_data[2],
            a_data[0] * b_data[1] - a_data[1] * b_data[0],
        ]
        return FallbackArray(result)

    # Fallback implementations for numpy-specific operations
    def reshape(a: "FallbackArray" | list, newshape: int | tuple[int, ...]) -> "FallbackArray":
        """Reshape array.

        Args:
            a: FallbackArray or list to reshape
            newshape: New shape as integer or tuple of integers

        Returns:
            Reshaped FallbackArray

        """
        if isinstance(a, FallbackArray):
            return a.reshape(newshape)
        return FallbackArray(a).reshape(newshape)

    def transpose(a: "FallbackArray" | list) -> "FallbackArray":
        """Transpose array (basic 2D implementation).

        Args:
            a: FallbackArray or list to transpose

        Returns:
            Transposed FallbackArray

        """
        if isinstance(a, FallbackArray):
            if a.ndim != 2:
                return a

            rows, cols = a.shape
            result = []
            for j in range(cols):
                for i in range(rows):
                    result.append(a.data[i * cols + j])

            return FallbackArray(result, a.dtype, (cols, rows))
        return FallbackArray(a)

    # Statistical functions that operate on arrays
    def sum(a: "FallbackArray" | list, axis: int | None = None) -> int | float:
        """Sum of array elements.

        Args:
            a: FallbackArray or list to sum
            axis: Axis along which to sum; currently unused for fallback

        Returns:
            Sum of all elements

        """
        if isinstance(a, FallbackArray):
            return a.sum(axis)
        return sum(a)

    def mean(a: "FallbackArray" | list, axis: int | None = None) -> int | float:
        """Mean of array elements.

        Args:
            a: FallbackArray or list to compute mean of
            axis: Axis along which to compute mean; currently unused for fallback

        Returns:
            Mean value

        """
        if isinstance(a, FallbackArray):
            return a.mean()
        return sum(a) / len(a) if a else 0

    def std(a: "FallbackArray" | list, axis: int | None = None) -> float:
        """Calculate standard deviation.

        Args:
            a: FallbackArray or list to compute standard deviation of
            axis: Axis along which to compute std; currently unused for fallback

        Returns:
            Standard deviation value

        """
        if isinstance(a, FallbackArray):
            return a.std()
        m = mean(a)
        variance = sum((x - m) ** 2 for x in a) / len(a)
        return math.sqrt(variance)

    def var(a: "FallbackArray" | list, axis: int | None = None) -> float:
        """Variance.

        Args:
            a: FallbackArray or list to compute variance of
            axis: Axis along which to compute variance; currently unused for fallback

        Returns:
            Variance value

        """
        if isinstance(a, FallbackArray):
            m = a.mean()
            return sum((x - m) ** 2 for x in a.data) / len(a.data)
        m = mean(a)
        return sum((x - m) ** 2 for x in a) / len(a)

    def min(a: "FallbackArray" | list, axis: int | None = None) -> int | float | None:
        """Minimum value.

        Args:
            a: FallbackArray or list to find minimum of
            axis: Axis along which to find min; currently unused for fallback

        Returns:
            Minimum value, or None if empty

        """
        if isinstance(a, FallbackArray):
            return a.min()
        return min(a) if a else None

    def max(a: "FallbackArray" | list, axis: int | None = None) -> int | float | None:
        """Maximum value.

        Args:
            a: FallbackArray or list to find maximum of
            axis: Axis along which to find max; currently unused for fallback

        Returns:
            Maximum value, or None if empty

        """
        if isinstance(a, FallbackArray):
            return a.max()
        return max(a) if a else None

    def argmin(a: "FallbackArray" | list, axis: int | None = None) -> int | None:
        """Index of minimum.

        Args:
            a: FallbackArray or list to find minimum index of
            axis: Axis along which to find argmin; currently unused for fallback

        Returns:
            Index of minimum element, or None if empty

        """
        if isinstance(a, FallbackArray):
            return a.argmin()
        min_val = min(a)
        return a.index(min_val)

    def argmax(a: "FallbackArray" | list, axis: int | None = None) -> int | None:
        """Index of maximum.

        Args:
            a: FallbackArray or list to find maximum index of
            axis: Axis along which to find argmax; currently unused for fallback

        Returns:
            Index of maximum element, or None if empty

        """
        if isinstance(a, FallbackArray):
            return a.argmax()
        max_val = max(a)
        return a.index(max_val)

    # Type definitions
    ndarray = FallbackArray
    dtype = type
    float32 = float
    float64 = float
    int32 = int
    int64 = int
    uint8 = int
    uint16 = int
    uint32 = int

    # Fallback numpy-like module with submodules
    class FallbackNumPy:
        """Fallback numpy module with submodules."""

        # Array creation
        array = array
        zeros = zeros
        ones = ones
        empty = empty
        full = full
        eye = eye
        arange = arange
        linspace = linspace
        meshgrid = meshgrid

        # Math operations
        sqrt = sqrt
        abs = abs
        round = round
        floor = floor
        ceil = ceil

        # Array operations
        concatenate = concatenate
        stack = stack
        reshape = reshape
        transpose = transpose
        unique = unique
        sort = sort
        argsort = argsort
        where = where
        allclose = allclose
        array_equal = array_equal
        asarray = asarray

        # Statistical
        sum = sum
        mean = mean
        std = std
        var = var
        min = min
        max = max
        argmin = argmin
        argmax = argmax

        # Calculus
        gradient = gradient
        diff = diff
        cumsum = cumsum

        # Histogram
        histogram = histogram
        percentile = percentile
        median = median

        # Linear algebra
        dot = dot
        cross = cross

        # Types
        ndarray = ndarray
        dtype = dtype
        float32 = float32
        float64 = float64
        int32 = int32
        int64 = int64
        uint8 = uint8
        uint16 = uint16
        uint32 = uint32

        class Linalg:
            """Linear algebra fallback submodule.

            Provides basic linear algebra operations for fallback NumPy implementation.
            """

            @staticmethod
            def norm(x: "FallbackArray" | list, ord: float | str | None = None) -> float:
                """Vector norm.

                Args:
                    x: FallbackArray or list to compute norm of
                    ord: Order of norm; 1, 2, inf, or None for L2 norm

                Returns:
                    Computed norm value

                """
                if isinstance(x, FallbackArray):
                    data = x.data
                else:
                    data = x

                if ord is None or ord == 2:
                    return math.sqrt(sum(val**2 for val in data))
                if ord == 1:
                    return sum(abs(val) for val in data)
                if ord == float("inf"):
                    return max(abs(val) for val in data)
                return sum(abs(val) ** ord for val in data) ** (1 / ord)

            @staticmethod
            def inv(a: "FallbackArray") -> "FallbackArray":
                """Matrix inverse (2x2 only for fallback).

                Args:
                    a: FallbackArray representing a 2x2 matrix

                Returns:
                    Inverted 2x2 matrix as FallbackArray

                Raises:
                    ValueError: If not 2x2 matrix or matrix is singular

                """
                if isinstance(a, FallbackArray):
                    if a.shape != (2, 2):
                        raise ValueError("Fallback only supports 2x2 matrix inverse")

                    det = a.data[0] * a.data[3] - a.data[1] * a.data[2]
                    if abs(det) < 1e-10:
                        raise ValueError("Matrix is singular")

                    inv_data = [a.data[3] / det, -a.data[1] / det, -a.data[2] / det, a.data[0] / det]
                    return FallbackArray(inv_data, a.dtype, (2, 2))

                raise ValueError("Input must be a 2x2 FallbackArray")

        class Fft:
            """FFT fallback submodule (basic DFT implementation).

            Provides Fast Fourier Transform and inverse FFT for fallback NumPy.
            """

            @staticmethod
            def fft(a: "FallbackArray" | list) -> "FallbackArray":
                """Implement basic DFT.

                Args:
                    a: FallbackArray or list to compute FFT of

                Returns:
                    FallbackArray with FFT result as complex numbers

                """
                if isinstance(a, FallbackArray):
                    data = a.data
                else:
                    data = a

                N = len(data)
                result = []

                for k in range(N):
                    sum_real = 0
                    sum_imag = 0
                    for n in range(N):
                        angle = -2 * math.pi * k * n / N
                        sum_real += data[n] * math.cos(angle)
                        sum_imag += data[n] * math.sin(angle)
                    result.append(complex(sum_real, sum_imag))

                return FallbackArray(result)

            @staticmethod
            def ifft(a: "FallbackArray" | list) -> "FallbackArray":
                """Implement basic inverse DFT.

                Args:
                    a: FallbackArray or list of complex numbers to compute inverse FFT of

                Returns:
                    FallbackArray with inverse FFT result

                """
                if isinstance(a, FallbackArray):
                    data = a.data
                else:
                    data = a

                N = len(data)
                result = []

                for n in range(N):
                    sum_real = 0
                    sum_imag = 0
                    for k in range(N):
                        angle = 2 * math.pi * k * n / N
                        if isinstance(data[k], complex):
                            sum_real += data[k].real * math.cos(angle) - data[k].imag * math.sin(angle)
                            sum_imag += data[k].real * math.sin(angle) + data[k].imag * math.cos(angle)
                        else:
                            sum_real += data[k] * math.cos(angle)
                            sum_imag += data[k] * math.sin(angle)
                    result.append(complex(sum_real / N, sum_imag / N))

                return FallbackArray(result)

        class Random:
            """Random number generation fallback submodule.

            Provides random number generation utilities for fallback NumPy.
            """

            @staticmethod
            def rand(*shape: int) -> "FallbackArray" | float:
                """Random values in [0, 1).

                Args:
                    *shape: Dimensions of output array; if none, returns scalar

                Returns:
                    FallbackArray of random values or float scalar

                """
                if not shape:
                    return _random.random()  # noqa: S311

                total = 1
                for dim in shape:
                    total *= dim

                data = [_random.random() for _ in range(total)]  # noqa: S311
                return FallbackArray(data, float, shape)

            @staticmethod
            def randn(*shape: int) -> "FallbackArray" | float:
                """Random normal distribution.

                Args:
                    *shape: Dimensions of output array; if none, returns scalar

                Returns:
                    FallbackArray of normally distributed values or float scalar

                """
                if not shape:
                    return _random.gauss(0, 1)

                total = 1
                for dim in shape:
                    total *= dim

                data = [_random.gauss(0, 1) for _ in range(total)]
                return FallbackArray(data, float, shape)

            @staticmethod
            def randint(low: int, high: int | None = None, size: int | tuple[int, ...] | None = None) -> "FallbackArray" | int:
                """Random integers.

                Args:
                    low: Lowest value or highest if high is None
                    high: Highest value (exclusive); if None, low becomes high and low becomes 0
                    size: Shape of output array; if None, returns scalar

                Returns:
                    FallbackArray of random integers or int scalar

                """
                if high is None:
                    high = low
                    low = 0

                if size is None:
                    return _random.randint(low, high - 1)  # noqa: S311

                if isinstance(size, int):
                    size = (size,)

                total = 1
                for dim in size:
                    total *= dim

                data = [_random.randint(low, high - 1) for _ in range(total)]  # noqa: S311
                return FallbackArray(data, int, size)

            @staticmethod
            def choice(a: "FallbackArray" | int | list, size: int | tuple[int, ...] | None = None, replace: bool = True) -> "FallbackArray" | int | float:
                """Random choice from array.

                Args:
                    a: FallbackArray, integer range, or list to choose from
                    size: Shape of output array; if None, returns scalar
                    replace: Whether to allow repeated selections; defaults to True

                Returns:
                    FallbackArray with random selections or scalar value

                Raises:
                    ValueError: If sampling without replacement and size exceeds population

                """
                if isinstance(a, FallbackArray):
                    data = a.data
                elif isinstance(a, int):
                    data = list(range(a))
                else:
                    data = list(a)

                if size is None:
                    return _random.choice(data)  # noqa: S311

                if isinstance(size, int):
                    total = size
                    shape = (size,)
                else:
                    total = 1
                    for dim in size:
                        total *= dim
                    shape = size

                if replace:
                    result = [_random.choice(data) for _ in range(total)]  # noqa: S311
                else:
                    if total > len(data):
                        raise ValueError("Cannot sample more items than available without replacement")
                    result = _random.sample(data, total)

                return FallbackArray(result, None, shape)

            @staticmethod
            def seed(s: int) -> None:
                """Set random seed.

                Args:
                    s: Seed value for reproducible random generation

                """
                _random.seed(s)

        # Compatibility aliases
        linalg = Linalg
        fft = Fft
        random = Random

    # Create module instances
    np = FallbackNumPy()
    numpy = FallbackNumPy()

    # Also assign submodules
    linalg = FallbackNumPy.Linalg
    fft = FallbackNumPy.Fft
    random = FallbackNumPy.Random


# Export all NumPy objects and availability flag
__all__ = [
    # Availability flags
    "HAS_NUMPY",
    "NUMPY_VERSION",
    # Main numpy references
    "np",
    "numpy",
    # Array creation
    "array",
    "zeros",
    "ones",
    "empty",
    "full",
    "eye",
    "arange",
    "linspace",
    "meshgrid",
    # Data types
    "ndarray",
    "dtype",
    "float32",
    "float64",
    "int32",
    "int64",
    "uint8",
    "uint16",
    "uint32",
    # Array manipulation
    "reshape",
    "transpose",
    "concatenate",
    "stack",
    # Mathematical operations
    "sum",
    "mean",
    "std",
    "var",
    "min",
    "max",
    "argmin",
    "argmax",
    "dot",
    "cross",
    # Submodules
    "linalg",
    "fft",
    "random",
    # Mathematical functions
    "sqrt",
    "abs",
    "round",
    "floor",
    "ceil",
    # Logical operations
    "where",
    "unique",
    "sort",
    "argsort",
    # Comparison
    "allclose",
    "array_equal",
    # Array conversion
    "asarray",
    # Calculus
    "gradient",
    "diff",
    "cumsum",
    # Statistics
    "histogram",
    "percentile",
    "median",
]
