"""This file is part of Intellicrack.
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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import math
import random as _random

from intellicrack.logger import logger

"""
NumPy Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for NumPy imports.
When NumPy is not available, it provides REAL, functional Python-based
implementations for essential operations used in Intellicrack.
"""

# NumPy availability detection and import handling
try:
    import numpy
    import numpy as np

    # NumPy submodules
    from numpy import (
        abs,
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
        max,
        mean,
        median,
        meshgrid,
        min,
        ndarray,
        ones,
        percentile,
        random,
        reshape,
        round,
        sort,
        sqrt,
        stack,
        std,
        sum,
        transpose,
        uint8,
        uint16,
        uint32,
        unique,
        var,
        where,
        zeros,
    )

    HAS_NUMPY = True
    NUMPY_VERSION = numpy.__version__

except ImportError as e:
    logger.error("NumPy not available, using fallback implementations: %s", e)
    HAS_NUMPY = False
    NUMPY_VERSION = None

    # Production-ready fallback implementations for Intellicrack's binary analysis needs

    class FallbackArray:
        """Functional array implementation for binary analysis operations."""

        def __init__(self, data, dtype=None, shape=None):
            """Initialize array with data, dtype, and shape."""
            if isinstance(data, (list, tuple)):
                self.data = list(data)
            elif isinstance(data, FallbackArray):
                self.data = data.data.copy()
            else:
                self.data = [data]

            self.dtype = dtype or type(self.data[0]) if self.data else float
            self._shape = shape or (len(self.data),)

            # Flatten multi-dimensional data
            if isinstance(self.data[0], (list, tuple)):
                self.data = self._flatten(self.data)

        def _flatten(self, lst):
            """Flatten nested lists."""
            result = []
            for item in lst:
                if isinstance(item, (list, tuple)):
                    result.extend(self._flatten(item))
                else:
                    result.append(item)
            return result

        @property
        def shape(self):
            """Get array shape."""
            return self._shape

        @property
        def size(self):
            """Get total number of elements."""
            return len(self.data)

        @property
        def ndim(self):
            """Get number of dimensions."""
            return len(self._shape)

        def reshape(self, *new_shape):
            """Reshape array to new dimensions."""
            if len(new_shape) == 1 and isinstance(new_shape[0], (list, tuple)):
                new_shape = new_shape[0]

            total = 1
            for dim in new_shape:
                total *= dim

            if total != self.size:
                raise ValueError(f"Cannot reshape array of size {self.size} into shape {new_shape}")

            result = FallbackArray(self.data.copy(), self.dtype, new_shape)
            return result

        def flatten(self):
            """Flatten array to 1D."""
            return FallbackArray(self.data.copy(), self.dtype, (self.size,))

        def tolist(self):
            """Convert to Python list."""
            if self.ndim == 1:
                return self.data.copy()

            # Reconstruct multi-dimensional list
            result = self.data.copy()
            for dim in reversed(self._shape[1:]):
                temp = []
                for i in range(0, len(result), dim):
                    temp.append(result[i:i+dim])
                result = temp
            return result[0] if len(result) == 1 else result

        def copy(self):
            """Create a copy of the array."""
            return FallbackArray(self.data.copy(), self.dtype, self._shape)

        def astype(self, dtype):
            """Convert array to new data type."""
            converter = dtype if callable(dtype) else lambda x: dtype(x)
            new_data = [converter(x) for x in self.data]
            return FallbackArray(new_data, dtype, self._shape)

        def __getitem__(self, key):
            """Get item or slice."""
            if isinstance(key, int):
                return self.data[key]
            elif isinstance(key, slice):
                return FallbackArray(self.data[key], self.dtype)
            elif isinstance(key, (list, tuple)):
                return FallbackArray([self.data[i] for i in key], self.dtype)
            return self.data[key]

        def __setitem__(self, key, value):
            """Set item or slice."""
            if isinstance(key, int):
                self.data[key] = value
            elif isinstance(key, slice):
                if isinstance(value, FallbackArray):
                    self.data[key] = value.data
                else:
                    self.data[key] = value

        def __len__(self):
            """Get length of first dimension."""
            return self._shape[0] if self._shape else 0

        def __repr__(self):
            """String representation."""
            return f"FallbackArray({self.tolist()})"

        def __add__(self, other):
            """Element-wise addition."""
            if isinstance(other, FallbackArray):
                result = [a + b for a, b in zip(self.data, other.data, strict=False)]
            else:
                result = [a + other for a in self.data]
            return FallbackArray(result, self.dtype, self._shape)

        def __sub__(self, other):
            """Element-wise subtraction."""
            if isinstance(other, FallbackArray):
                result = [a - b for a, b in zip(self.data, other.data, strict=False)]
            else:
                result = [a - other for a in self.data]
            return FallbackArray(result, self.dtype, self._shape)

        def __mul__(self, other):
            """Element-wise multiplication."""
            if isinstance(other, FallbackArray):
                result = [a * b for a, b in zip(self.data, other.data, strict=False)]
            else:
                result = [a * other for a in self.data]
            return FallbackArray(result, self.dtype, self._shape)

        def __truediv__(self, other):
            """Element-wise division."""
            if isinstance(other, FallbackArray):
                result = [a / b for a, b in zip(self.data, other.data, strict=False)]
            else:
                result = [a / other for a in self.data]
            return FallbackArray(result, self.dtype, self._shape)

        def sum(self, axis=None):
            """Sum of array elements."""
            if axis is None:
                return sum(self.data)
            # For multi-dimensional operations
            return sum(self.data)

        def mean(self):
            """Mean of array elements."""
            return sum(self.data) / len(self.data) if self.data else 0

        def std(self):
            """Standard deviation of array elements."""
            m = self.mean()
            variance = sum((x - m) ** 2 for x in self.data) / len(self.data)
            return math.sqrt(variance)

        def min(self):
            """Minimum value."""
            return min(self.data) if self.data else None

        def max(self):
            """Maximum value."""
            return max(self.data) if self.data else None

        def argmin(self):
            """Index of minimum value."""
            if not self.data:
                return None
            min_val = min(self.data)
            return self.data.index(min_val)

        def argmax(self):
            """Index of maximum value."""
            if not self.data:
                return None
            max_val = max(self.data)
            return self.data.index(max_val)

    # Fallback array creation functions
    def array(data, dtype=None):
        """Create array from data."""
        return FallbackArray(data, dtype)

    def zeros(shape, dtype=float):
        """Create array of zeros."""
        if isinstance(shape, int):
            shape = (shape,)
        total = 1
        for dim in shape:
            total *= dim
        return FallbackArray([0] * total, dtype, shape)

    def ones(shape, dtype=float):
        """Create array of ones."""
        if isinstance(shape, int):
            shape = (shape,)
        total = 1
        for dim in shape:
            total *= dim
        return FallbackArray([1] * total, dtype, shape)

    def empty(shape, dtype=float):
        """Create uninitialized array (returns zeros for safety)."""
        return zeros(shape, dtype)

    def full(shape, fill_value, dtype=None):
        """Create array filled with value."""
        if isinstance(shape, int):
            shape = (shape,)
        total = 1
        for dim in shape:
            total *= dim
        dtype = dtype or type(fill_value)
        return FallbackArray([fill_value] * total, dtype, shape)

    def eye(N, M=None, k=0, dtype=float):
        """Create identity matrix."""
        M = M or N
        result = []
        for i in range(N):
            row = []
            for j in range(M):
                row.append(1 if i - j == -k else 0)
            result.append(row)
        return FallbackArray(result, dtype, (N, M))

    def arange(start, stop=None, step=1, dtype=None):
        """Create array with range of values."""
        if stop is None:
            stop = start
            start = 0

        result = []
        current = start
        while (step > 0 and current < stop) or (step < 0 and current > stop):
            result.append(current)
            current += step

        return FallbackArray(result, dtype or type(start))

    def linspace(start, stop, num=50):
        """Create linearly spaced array."""
        if num <= 0:
            return FallbackArray([])
        if num == 1:
            return FallbackArray([start])

        step = (stop - start) / (num - 1)
        result = [start + i * step for i in range(num)]
        return FallbackArray(result)

    def meshgrid(*xi):
        """Create coordinate matrices from coordinate vectors."""
        if len(xi) == 0:
            return []
        if len(xi) == 1:
            return [FallbackArray(xi[0])]

        # Simple 2D meshgrid implementation
        x = xi[0] if isinstance(xi[0], FallbackArray) else FallbackArray(xi[0])
        y = xi[1] if isinstance(xi[1], FallbackArray) else FallbackArray(xi[1])

        xx = []
        yy = []
        for j in y.data:
            for i in x.data:
                xx.append(i)
                yy.append(j)

        return [FallbackArray(xx, shape=(len(y.data), len(x.data))),
                FallbackArray(yy, shape=(len(y.data), len(x.data)))]

    # Math operations
    def sqrt(x):
        """Square root."""
        if isinstance(x, FallbackArray):
            return FallbackArray([math.sqrt(val) for val in x.data], x.dtype, x.shape)
        return math.sqrt(x)

    def abs(x):
        """Absolute value."""
        if isinstance(x, FallbackArray):
            return FallbackArray([abs(val) for val in x.data], x.dtype, x.shape)
        return abs(x)

    def round(x, decimals=0):
        """Round to decimals."""
        if isinstance(x, FallbackArray):
            factor = 10 ** decimals
            return FallbackArray([round(val * factor) / factor for val in x.data], x.dtype, x.shape)
        return round(x, decimals)

    def floor(x):
        """Floor operation."""
        if isinstance(x, FallbackArray):
            return FallbackArray([math.floor(val) for val in x.data], x.dtype, x.shape)
        return math.floor(x)

    def ceil(x):
        """Ceiling operation."""
        if isinstance(x, FallbackArray):
            return FallbackArray([math.ceil(val) for val in x.data], x.dtype, x.shape)
        return math.ceil(x)

    # Array operations
    def concatenate(arrays, axis=0):
        """Concatenate arrays."""
        if not arrays:
            return FallbackArray([])

        result = []
        for arr in arrays:
            if isinstance(arr, FallbackArray):
                result.extend(arr.data)
            else:
                result.extend(arr)

        return FallbackArray(result)

    def stack(arrays, axis=0):
        """Stack arrays."""
        return concatenate(arrays, axis)

    def unique(ar):
        """Find unique elements."""
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

    def sort(a):
        """Sort array."""
        if isinstance(a, FallbackArray):
            return FallbackArray(sorted(a.data), a.dtype, a.shape)
        return sorted(a)

    def argsort(a):
        """Get indices that would sort array."""
        if isinstance(a, FallbackArray):
            data = a.data
        else:
            data = a

        indices = list(range(len(data)))
        indices.sort(key=lambda i: data[i])
        return FallbackArray(indices)

    def where(condition, x=None, y=None):
        """Return elements chosen from x or y depending on condition."""
        if x is None and y is None:
            # Return indices where condition is True
            if isinstance(condition, FallbackArray):
                indices = [i for i, val in enumerate(condition.data) if val]
            else:
                indices = [i for i, val in enumerate(condition) if val]
            return (FallbackArray(indices),)

        # Return elements from x where condition is True, else from y
        result = []
        cond_data = condition.data if isinstance(condition, FallbackArray) else condition
        x_data = x.data if isinstance(x, FallbackArray) else [x] * len(cond_data)
        y_data = y.data if isinstance(y, FallbackArray) else [y] * len(cond_data)

        for c, xv, yv in zip(cond_data, x_data, y_data, strict=False):
            result.append(xv if c else yv)

        return FallbackArray(result)

    def allclose(a, b, rtol=1e-05, atol=1e-08):
        """Check if arrays are element-wise equal within tolerance."""
        a_data = a.data if isinstance(a, FallbackArray) else a
        b_data = b.data if isinstance(b, FallbackArray) else b

        if len(a_data) != len(b_data):
            return False

        for av, bv in zip(a_data, b_data, strict=False):
            if abs(av - bv) > atol + rtol * abs(bv):
                return False
        return True

    def array_equal(a, b):
        """Check if arrays are exactly equal."""
        a_data = a.data if isinstance(a, FallbackArray) else a
        b_data = b.data if isinstance(b, FallbackArray) else b
        return a_data == b_data

    def asarray(a, dtype=None):
        """Convert to array."""
        if isinstance(a, FallbackArray):
            return a if dtype is None else a.astype(dtype)
        return FallbackArray(a, dtype)

    def gradient(f, *varargs):
        """Calculate gradient using finite differences."""
        if isinstance(f, FallbackArray):
            data = f.data
        else:
            data = f

        result = []
        for i in range(len(data)):
            if i == 0:
                # Forward difference
                grad = data[1] - data[0] if len(data) > 1 else 0
            elif i == len(data) - 1:
                # Backward difference
                grad = data[-1] - data[-2]
            else:
                # Central difference
                grad = (data[i+1] - data[i-1]) / 2
            result.append(grad)

        return FallbackArray(result)

    def diff(a, n=1):
        """Calculate n-th discrete difference."""
        if isinstance(a, FallbackArray):
            data = a.data
        else:
            data = a

        for _ in range(n):
            result = []
            for i in range(1, len(data)):
                result.append(data[i] - data[i-1])
            data = result

        return FallbackArray(data)

    def cumsum(a):
        """Cumulative sum."""
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

    def histogram(a, bins=10):
        """Compute histogram."""
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

        # Create bin edges
        bin_width = (max_val - min_val) / bins
        edges = [min_val + i * bin_width for i in range(bins + 1)]

        # Count values in each bin
        counts = [0] * bins
        for val in data:
            bin_idx = min(int((val - min_val) / bin_width), bins - 1)
            counts[bin_idx] += 1

        return FallbackArray(counts), FallbackArray(edges)

    def percentile(a, q):
        """Calculate percentile."""
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

    def median(a):
        """Calculate median."""
        return percentile(a, 50)

    def dot(a, b):
        """Dot product of two arrays."""
        a_data = a.data if isinstance(a, FallbackArray) else a
        b_data = b.data if isinstance(b, FallbackArray) else b

        if len(a_data) != len(b_data):
            raise ValueError("Arrays must have same length for dot product")

        return sum(av * bv for av, bv in zip(a_data, b_data, strict=False))

    def cross(a, b):
        """Cross product of two 3D vectors."""
        a_data = a.data if isinstance(a, FallbackArray) else a
        b_data = b.data if isinstance(b, FallbackArray) else b

        if len(a_data) != 3 or len(b_data) != 3:
            raise ValueError("Cross product requires 3D vectors")

        result = [
            a_data[1] * b_data[2] - a_data[2] * b_data[1],
            a_data[2] * b_data[0] - a_data[0] * b_data[2],
            a_data[0] * b_data[1] - a_data[1] * b_data[0]
        ]
        return FallbackArray(result)

    # Fallback implementations for numpy-specific operations
    def reshape(a, newshape):
        """Reshape array."""
        if isinstance(a, FallbackArray):
            return a.reshape(newshape)
        return FallbackArray(a).reshape(newshape)

    def transpose(a):
        """Transpose array (basic 2D implementation)."""
        if isinstance(a, FallbackArray):
            if a.ndim != 2:
                return a  # Only handle 2D for now

            rows, cols = a.shape
            result = []
            for j in range(cols):
                for i in range(rows):
                    result.append(a.data[i * cols + j])

            return FallbackArray(result, a.dtype, (cols, rows))
        return FallbackArray(a)

    # Statistical functions that operate on arrays
    def sum(a, axis=None):
        """Sum of array elements."""
        if isinstance(a, FallbackArray):
            return a.sum(axis)
        return sum(a)

    def mean(a, axis=None):
        """Mean of array elements."""
        if isinstance(a, FallbackArray):
            return a.mean()
        return sum(a) / len(a) if a else 0

    def std(a, axis=None):
        """Standard deviation."""
        if isinstance(a, FallbackArray):
            return a.std()
        m = mean(a)
        variance = sum((x - m) ** 2 for x in a) / len(a)
        return math.sqrt(variance)

    def var(a, axis=None):
        """Variance."""
        if isinstance(a, FallbackArray):
            m = a.mean()
            return sum((x - m) ** 2 for x in a.data) / len(a.data)
        m = mean(a)
        return sum((x - m) ** 2 for x in a) / len(a)

    def min(a, axis=None):
        """Minimum value."""
        if isinstance(a, FallbackArray):
            return a.min()
        return min(a) if a else None

    def max(a, axis=None):
        """Maximum value."""
        if isinstance(a, FallbackArray):
            return a.max()
        return max(a) if a else None

    def argmin(a, axis=None):
        """Index of minimum."""
        if isinstance(a, FallbackArray):
            return a.argmin()
        min_val = min(a)
        return a.index(min_val)

    def argmax(a, axis=None):
        """Index of maximum."""
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
            """Linear algebra fallback."""

            @staticmethod
            def norm(x, ord=None):
                """Vector norm."""
                if isinstance(x, FallbackArray):
                    data = x.data
                else:
                    data = x

                if ord is None or ord == 2:
                    return math.sqrt(sum(val ** 2 for val in data))
                elif ord == 1:
                    return sum(abs(val) for val in data)
                elif ord == float('inf'):
                    return max(abs(val) for val in data)
                else:
                    return sum(abs(val) ** ord for val in data) ** (1/ord)

            @staticmethod
            def inv(a):
                """Matrix inverse (2x2 only for fallback)."""
                if isinstance(a, FallbackArray):
                    if a.shape != (2, 2):
                        raise ValueError("Fallback only supports 2x2 matrix inverse")

                    # 2x2 matrix inverse
                    det = a.data[0] * a.data[3] - a.data[1] * a.data[2]
                    if abs(det) < 1e-10:
                        raise ValueError("Matrix is singular")

                    inv_data = [
                        a.data[3] / det, -a.data[1] / det,
                        -a.data[2] / det, a.data[0] / det
                    ]
                    return FallbackArray(inv_data, a.dtype, (2, 2))

                raise ValueError("Input must be a 2x2 FallbackArray")

        class Fft:
            """FFT fallback (basic DFT implementation)."""

            @staticmethod
            def fft(a):
                """Basic DFT implementation."""
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
            def ifft(a):
                """Basic inverse DFT."""
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
            """Random number generation fallback."""

            @staticmethod
            def rand(*shape):
                """Random values in [0, 1)."""
                if not shape:
                    return _random.random()

                total = 1
                for dim in shape:
                    total *= dim

                data = [_random.random() for _ in range(total)]
                return FallbackArray(data, float, shape)

            @staticmethod
            def randn(*shape):
                """Random normal distribution."""
                if not shape:
                    return _random.gauss(0, 1)

                total = 1
                for dim in shape:
                    total *= dim

                data = [_random.gauss(0, 1) for _ in range(total)]
                return FallbackArray(data, float, shape)

            @staticmethod
            def randint(low, high=None, size=None):
                """Random integers."""
                if high is None:
                    high = low
                    low = 0

                if size is None:
                    return _random.randint(low, high-1)

                if isinstance(size, int):
                    size = (size,)

                total = 1
                for dim in size:
                    total *= dim

                data = [_random.randint(low, high-1) for _ in range(total)]
                return FallbackArray(data, int, size)

            @staticmethod
            def choice(a, size=None, replace=True):
                """Random choice from array."""
                if isinstance(a, FallbackArray):
                    data = a.data
                elif isinstance(a, int):
                    data = list(range(a))
                else:
                    data = list(a)

                if size is None:
                    return _random.choice(data)

                if isinstance(size, int):
                    total = size
                    shape = (size,)
                else:
                    total = 1
                    for dim in size:
                        total *= dim
                    shape = size

                if replace:
                    result = [_random.choice(data) for _ in range(total)]
                else:
                    if total > len(data):
                        raise ValueError("Cannot sample more items than available without replacement")
                    result = _random.sample(data, total)

                return FallbackArray(result, None, shape)

            @staticmethod
            def seed(s):
                """Set random seed."""
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
    "HAS_NUMPY", "NUMPY_VERSION",
    # Main numpy references
    "np", "numpy",
    # Array creation
    "array", "zeros", "ones", "empty", "full", "eye",
    "arange", "linspace", "meshgrid",
    # Data types
    "ndarray", "dtype", "float32", "float64", "int32", "int64",
    "uint8", "uint16", "uint32",
    # Array manipulation
    "reshape", "transpose", "concatenate", "stack",
    # Mathematical operations
    "sum", "mean", "std", "var", "min", "max", "argmin", "argmax",
    "dot", "cross",
    # Submodules
    "linalg", "fft", "random",
    # Mathematical functions
    "sqrt", "abs", "round", "floor", "ceil",
    # Logical operations
    "where", "unique", "sort", "argsort",
    # Comparison
    "allclose", "array_equal",
    # Array conversion
    "asarray",
    # Calculus
    "gradient", "diff", "cumsum",
    # Statistics
    "histogram", "percentile", "median",
]
