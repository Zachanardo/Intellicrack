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

from __future__ import annotations

import math
import random as _random
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, TypeVar, Union, overload

from intellicrack.utils.logger import logger


"""
NumPy Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for NumPy imports.
When NumPy is not available, it provides REAL, functional Python-based
implementations for essential operations used in Intellicrack.
"""

_T = TypeVar("_T")

ArrayLike = Union["FallbackArray", list[Any], tuple[Any, ...]]
Numeric = Union[int, float]
Shape = Union[int, tuple[int, ...]]


class FallbackArray:
    """Functional array implementation for binary analysis operations.

    This class provides NumPy-like array functionality when NumPy is unavailable.
    It supports basic array operations including indexing, slicing, reshaping,
    and mathematical operations used in binary analysis and signal processing.
    """

    def __init__(
        self,
        data: list[Any] | tuple[Any, ...] | FallbackArray | float | int,
        dtype_arg: type[Any] | None = None,
        shape: tuple[int, ...] | None = None,
    ) -> None:
        """Initialize array with data, dtype, and shape.

        Args:
            data: Array data as list, tuple, FallbackArray, or scalar value
            dtype_arg: Data type for array elements; defaults to type of first element
            shape: Target shape for the array as tuple of dimensions

        """
        if isinstance(data, (list, tuple)):
            self.data: list[Any] = list(data)
        elif isinstance(data, FallbackArray):
            self.data = data.data.copy()
        else:
            self.data = [data]

        self.dtype: type[Any] = dtype_arg or (type(self.data[0]) if self.data else float)
        self._shape: tuple[int, ...] = shape or (len(self.data),)

        if self.data and isinstance(self.data[0], (list, tuple)):
            self.data = self._flatten(self.data)

    def _flatten(self, lst: list[Any] | tuple[Any, ...]) -> list[Any]:
        """Flatten nested lists.

        Args:
            lst: Nested list or tuple to flatten

        Returns:
            Single-level list with all elements from nested structure

        """
        result: list[Any] = []
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

    def reshape(self, *new_shape: int | tuple[int, ...]) -> FallbackArray:
        """Reshape array to new dimensions.

        Args:
            *new_shape: New shape as variable arguments or single tuple

        Returns:
            New FallbackArray with reshaped data

        Raises:
            ValueError: If total elements don't match new shape

        """
        final_shape: tuple[int, ...]
        if len(new_shape) == 1 and isinstance(new_shape[0], tuple):
            final_shape = new_shape[0]
        else:
            final_shape = tuple(int(d) for d in new_shape if isinstance(d, int))

        total = 1
        for dim in final_shape:
            total *= dim

        if total != self.size:
            raise ValueError(f"Cannot reshape array of size {self.size} into shape {final_shape}")

        return FallbackArray(self.data.copy(), self.dtype, final_shape)

    def flatten(self) -> FallbackArray:
        """Flatten array to 1D.

        Returns:
            Flattened 1D FallbackArray

        """
        return FallbackArray(self.data.copy(), self.dtype, (self.size,))

    def tolist(self) -> list[Any]:
        """Convert to Python list.

        Returns:
            List representation of array data

        """
        if self.ndim == 1:
            return self.data.copy()

        result: list[Any] = self.data.copy()
        for dim in reversed(self._shape[1:]):
            temp = [result[i : i + dim] for i in range(0, len(result), dim)]
            result = temp
        return result[0] if len(result) == 1 else result

    def copy(self) -> FallbackArray:
        """Create a copy of the array.

        Returns:
            Deep copy of this FallbackArray

        """
        return FallbackArray(self.data.copy(), self.dtype, self._shape)

    def astype(self, dtype_arg: type[Any]) -> FallbackArray:
        """Convert array to new data type.

        Args:
            dtype_arg: Target data type for conversion

        Returns:
            New FallbackArray with converted data type

        """
        new_data = [dtype_arg(x) for x in self.data]
        return FallbackArray(new_data, dtype_arg, self._shape)

    @overload
    def __getitem__(self, key: int) -> Any: ...
    @overload
    def __getitem__(self, key: slice) -> FallbackArray: ...
    @overload
    def __getitem__(self, key: list[int] | tuple[int, ...]) -> FallbackArray: ...

    def __getitem__(self, key: int | slice | list[int] | tuple[int, ...]) -> FallbackArray | Any:
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
        return FallbackArray([self.data[i] for i in key], self.dtype)

    def __setitem__(self, key: int | slice, value: float | int | FallbackArray | list[Any]) -> None:
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
            elif isinstance(value, list):
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

    def __add__(self, other: FallbackArray | float | int) -> FallbackArray:
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

    def __sub__(self, other: FallbackArray | float | int) -> FallbackArray:
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

    def __mul__(self, other: FallbackArray | float | int) -> FallbackArray:
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

    def __truediv__(self, other: FallbackArray | float | int) -> FallbackArray:
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

    def sum(self, axis: int | None = None) -> float:
        """Sum of array elements.

        Args:
            axis: Axis along which to sum; currently unused for fallback

        Returns:
            Sum of all elements

        """
        return float(sum(self.data))

    def mean(self) -> float:
        """Mean of array elements.

        Returns:
            Arithmetic mean of array elements

        """
        return float(sum(self.data)) / len(self.data) if self.data else 0.0

    def std(self) -> float:
        """Calculate standard deviation of array elements.

        Returns:
            Standard deviation of array elements

        """
        m = self.mean()
        variance = sum((float(x) - m) ** 2 for x in self.data) / len(self.data)
        return math.sqrt(variance)

    def min(self) -> float | None:
        """Minimum value.

        Returns:
            Minimum element in array or None if empty

        """
        return float(min(self.data)) if self.data else None

    def max(self) -> float | None:
        """Maximum value.

        Returns:
            Maximum element in array or None if empty

        """
        return float(max(self.data)) if self.data else None

    def argmin(self) -> int | None:
        """Index of minimum value.

        Returns:
            Index of minimum element or None if empty

        """
        if not self.data:
            return None
        min_val = min(self.data)
        return int(self.data.index(min_val))

    def argmax(self) -> int | None:
        """Index of maximum value.

        Returns:
            Index of maximum element or None if empty

        """
        if not self.data:
            return None
        max_val = max(self.data)
        return int(self.data.index(max_val))


class _FallbackLinalg:
    """Linear algebra fallback submodule.

    Provides basic linear algebra operations for fallback NumPy implementation.
    """

    @staticmethod
    def norm(x: FallbackArray | list[Any], ord: float | int | None = None) -> float:
        """Vector norm.

        Args:
            x: FallbackArray or list to compute norm of
            ord: Order of norm; 1, 2, inf, or None for L2 norm

        Returns:
            Computed norm value

        """
        data: list[Any] = x.data if isinstance(x, FallbackArray) else list(x)
        if ord is None or ord == 2:
            return math.sqrt(sum(float(val) ** 2 for val in data))
        if ord == 1:
            return sum(abs(float(val)) for val in data)
        if ord == float("inf"):
            return float(max(abs(float(val)) for val in data))
        return float(sum(abs(float(val)) ** float(ord) for val in data) ** (1 / float(ord)))

    @staticmethod
    def inv(a: FallbackArray) -> FallbackArray:
        """Matrix inverse (2x2 only for fallback).

        Args:
            a: FallbackArray representing a 2x2 matrix

        Returns:
            Inverted 2x2 matrix as FallbackArray

        Raises:
            ValueError: If not 2x2 matrix or matrix is singular

        """
        if a.shape != (2, 2):
            raise ValueError("Fallback only supports 2x2 matrix inverse")

        det = float(a.data[0]) * float(a.data[3]) - float(a.data[1]) * float(a.data[2])
        if abs(det) < 1e-10:
            raise ValueError("Matrix is singular")

        inv_data: list[float] = [
            float(a.data[3]) / det,
            -float(a.data[1]) / det,
            -float(a.data[2]) / det,
            float(a.data[0]) / det,
        ]
        return FallbackArray(inv_data, a.dtype, (2, 2))


class _FallbackFft:
    """FFT fallback submodule (basic DFT implementation).

    Provides Fast Fourier Transform and inverse FFT for fallback NumPy.
    """

    @staticmethod
    def fft(a: FallbackArray | list[Any]) -> FallbackArray:
        """Implement basic DFT.

        Args:
            a: FallbackArray or list to compute FFT of

        Returns:
            FallbackArray with FFT result as complex numbers

        """
        data: list[Any] = a.data if isinstance(a, FallbackArray) else list(a)
        N = len(data)
        result: list[complex] = []

        for k in range(N):
            sum_real = 0.0
            sum_imag = 0.0
            for n in range(N):
                angle = -2 * math.pi * k * n / N
                sum_real += float(data[n]) * math.cos(angle)
                sum_imag += float(data[n]) * math.sin(angle)
            result.append(complex(sum_real, sum_imag))

        return FallbackArray(result)

    @staticmethod
    def ifft(a: FallbackArray | list[Any]) -> FallbackArray:
        """Implement basic inverse DFT.

        Args:
            a: FallbackArray or list of complex numbers to compute inverse FFT of

        Returns:
            FallbackArray with inverse FFT result

        """
        data: list[Any] = a.data if isinstance(a, FallbackArray) else list(a)
        N = len(data)
        result: list[complex] = []

        for n in range(N):
            sum_real = 0.0
            sum_imag = 0.0
            for k in range(N):
                angle = 2 * math.pi * k * n / N
                if isinstance(data[k], complex):
                    sum_real += data[k].real * math.cos(angle) - data[k].imag * math.sin(angle)
                    sum_imag += data[k].real * math.sin(angle) + data[k].imag * math.cos(angle)
                else:
                    sum_real += float(data[k]) * math.cos(angle)
                    sum_imag += float(data[k]) * math.sin(angle)
            result.append(complex(sum_real / N, sum_imag / N))

        return FallbackArray(result)


class _FallbackRandom:
    """Random number generation fallback submodule.

    Provides random number generation utilities for fallback NumPy.
    """

    @staticmethod
    def rand(*shape: int) -> FallbackArray | float:
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
    def randn(*shape: int) -> FallbackArray | float:
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
    def randint(low: int, high: int | None = None, size: int | tuple[int, ...] | None = None) -> FallbackArray | int:
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

        shape: tuple[int, ...]
        shape = (size, ) if isinstance(size, int) else size
        total = 1
        for dim in shape:
            total *= dim

        data = [_random.randint(low, high - 1) for _ in range(total)]  # noqa: S311
        return FallbackArray(data, int, shape)

    @staticmethod
    def choice(
        a: FallbackArray | int | list[Any],
        size: int | tuple[int, ...] | None = None,
        replace: bool = True,
    ) -> FallbackArray | Any:
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
        data: list[Any]
        if isinstance(a, FallbackArray):
            data = a.data
        elif isinstance(a, int):
            data = list(range(a))
        else:
            data = list(a)

        if size is None:
            return _random.choice(data)  # noqa: S311

        shape: tuple[int, ...]
        if isinstance(size, int):
            total = size
            shape = (size,)
        else:
            total = 1
            for dim in size:
                total *= dim
            shape = size

        result: list[Any]
        if replace:
            result = [_random.choice(data) for _ in range(total)]  # noqa: S311
        elif total > len(data):
            raise ValueError("Cannot sample more items than available without replacement")
        else:
            result = _random.sample(data, total)

        return FallbackArray(result, None, shape)

    @staticmethod
    def seed(s: int) -> None:
        """Set random seed.

        Args:
            s: Seed value for reproducible random generation

        """
        _random.seed(s)


class _FallbackFunctions:
    """Collection of fallback functions that mimic numpy operations."""

    @staticmethod
    def array_func(data: list[Any] | tuple[Any, ...] | FallbackArray | float | int, dtype_arg: type[Any] | None = None) -> FallbackArray:
        """Create array from data.

        Args:
            data: Input data for array creation
            dtype_arg: Optional data type for array elements

        Returns:
            FallbackArray created from input data

        """
        return FallbackArray(data, dtype_arg)

    @staticmethod
    def zeros_func(shape: int | tuple[int, ...], dtype_arg: type[Any] = float) -> FallbackArray:
        """Create array of zeros.

        Args:
            shape: Shape of array as integer or tuple of integers
            dtype_arg: Data type for array elements; defaults to float

        Returns:
            FallbackArray filled with zeros

        """
        final_shape: tuple[int, ...]
        final_shape = (shape, ) if isinstance(shape, int) else shape
        total = 1
        for dim in final_shape:
            total *= dim
        return FallbackArray([0] * total, dtype_arg, final_shape)

    @staticmethod
    def ones_func(shape: int | tuple[int, ...], dtype_arg: type[Any] = float) -> FallbackArray:
        """Create array of ones.

        Args:
            shape: Shape of array as integer or tuple of integers
            dtype_arg: Data type for array elements; defaults to float

        Returns:
            FallbackArray filled with ones

        """
        final_shape: tuple[int, ...]
        final_shape = (shape, ) if isinstance(shape, int) else shape
        total = 1
        for dim in final_shape:
            total *= dim
        return FallbackArray([1] * total, dtype_arg, final_shape)

    @staticmethod
    def empty_func(shape: int | tuple[int, ...], dtype_arg: type[Any] = float) -> FallbackArray:
        """Create uninitialized array (returns zeros for safety).

        Args:
            shape: Shape of array as integer or tuple of integers
            dtype_arg: Data type for array elements; defaults to float

        Returns:
            FallbackArray with shape initialized to zeros

        """
        return _FallbackFunctions.zeros_func(shape, dtype_arg)

    @staticmethod
    def full_func(shape: int | tuple[int, ...], fill_value: float | int, dtype_arg: type[Any] | None = None) -> FallbackArray:
        """Create array filled with value.

        Args:
            shape: Shape of array as integer or tuple of integers
            fill_value: Value to fill array with
            dtype_arg: Optional data type; defaults to type of fill_value

        Returns:
            FallbackArray filled with the specified value

        """
        final_shape: tuple[int, ...]
        final_shape = (shape, ) if isinstance(shape, int) else shape
        total = 1
        for dim in final_shape:
            total *= dim
        effective_dtype = dtype_arg or type(fill_value)
        return FallbackArray([fill_value] * total, effective_dtype, final_shape)

    @staticmethod
    def eye_func(N: int, M: int | None = None, k: int = 0, dtype_arg: type[Any] = float) -> FallbackArray:
        """Create identity matrix.

        Args:
            N: Number of rows
            M: Number of columns; defaults to N if None
            k: Diagonal offset from main diagonal
            dtype_arg: Data type for array elements; defaults to float

        Returns:
            Identity-like FallbackArray with ones on offset diagonal

        """
        actual_M = M or N
        result: list[int] = []
        for i in range(N):
            row = [1 if i - j == -k else 0 for j in range(actual_M)]
            result.extend(row)
        return FallbackArray(result, dtype_arg, (N, actual_M))

    @staticmethod
    def arange_func(
        start: float | int, stop: float | int | None = None, step: float | int = 1, dtype_arg: type[Any] | None = None
    ) -> FallbackArray:
        """Create array with range of values.

        Args:
            start: Start value or stop if stop is None
            stop: End value (exclusive); if None, start becomes stop and start becomes 0
            step: Increment between values; defaults to 1
            dtype_arg: Optional data type; defaults to type of start

        Returns:
            FallbackArray with values from start to stop with given step

        """
        if stop is None:
            stop = start
            start = 0

        result: list[float | int] = []
        current: float | int = start
        while (step > 0 and current < stop) or (step < 0 and current > stop):
            result.append(current)
            current += step

        return FallbackArray(result, dtype_arg or type(start))

    @staticmethod
    def linspace_func(start: float | int, stop: float | int, num: int = 50) -> FallbackArray:
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
            return FallbackArray([float(start)])

        step = (float(stop) - float(start)) / (num - 1)
        result = [float(start) + i * step for i in range(num)]
        return FallbackArray(result)

    @staticmethod
    def meshgrid_func(*xi: list[Any] | tuple[Any, ...] | FallbackArray) -> list[FallbackArray]:
        """Create coordinate matrices from coordinate vectors.

        Args:
            *xi: Variable number of coordinate arrays

        Returns:
            List of FallbackArrays representing coordinate matrices

        """
        if not xi:
            return []
        if len(xi) == 1:
            arr = xi[0] if isinstance(xi[0], FallbackArray) else FallbackArray(xi[0])
            return [arr]

        x = xi[0] if isinstance(xi[0], FallbackArray) else FallbackArray(xi[0])
        y = xi[1] if isinstance(xi[1], FallbackArray) else FallbackArray(xi[1])

        xx: list[Any] = []
        yy: list[Any] = []
        for j in y.data:
            for i in x.data:
                xx.append(i)
                yy.append(j)

        return [
            FallbackArray(xx, shape=(len(y.data), len(x.data))),
            FallbackArray(yy, shape=(len(y.data), len(x.data))),
        ]

    @staticmethod
    def sqrt_func(x: FallbackArray | float | int) -> FallbackArray | float:
        """Square root.

        Args:
            x: FallbackArray or numeric value

        Returns:
            FallbackArray with square root of elements, or float for scalar input

        """
        if isinstance(x, FallbackArray):
            return FallbackArray([math.sqrt(float(val)) for val in x.data], x.dtype, x.shape)
        return math.sqrt(float(x))

    @staticmethod
    def abs_func(x: FallbackArray | float | int) -> FallbackArray | float:
        """Absolute value.

        Args:
            x: FallbackArray or numeric value

        Returns:
            FallbackArray with absolute values, or numeric type for scalar input

        """
        if isinstance(x, FallbackArray):
            return FallbackArray([abs(val) for val in x.data], x.dtype, x.shape)
        return float(abs(x))

    @staticmethod
    def round_func(x: FallbackArray | float | int, decimals: int = 0) -> FallbackArray | float:
        """Round to decimals.

        Args:
            x: FallbackArray or numeric value
            decimals: Number of decimal places; defaults to 0

        Returns:
            FallbackArray with rounded values, or numeric type for scalar input

        """
        if isinstance(x, FallbackArray):
            factor = 10**decimals
            return FallbackArray([round(float(val) * factor) / factor for val in x.data], x.dtype, x.shape)
        return float(round(float(x), decimals))

    @staticmethod
    def floor_func(x: FallbackArray | float | int) -> FallbackArray | int:
        """Floor operation.

        Args:
            x: FallbackArray or numeric value

        Returns:
            FallbackArray with floor of elements, or int for scalar input

        """
        if isinstance(x, FallbackArray):
            return FallbackArray([math.floor(float(val)) for val in x.data], x.dtype, x.shape)
        return math.floor(float(x))

    @staticmethod
    def ceil_func(x: FallbackArray | float | int) -> FallbackArray | int:
        """Ceiling operation.

        Args:
            x: FallbackArray or numeric value

        Returns:
            FallbackArray with ceiling of elements, or int for scalar input

        """
        if isinstance(x, FallbackArray):
            return FallbackArray([math.ceil(float(val)) for val in x.data], x.dtype, x.shape)
        return math.ceil(float(x))

    @staticmethod
    def concatenate_func(arrays: list[FallbackArray] | list[list[Any]], axis: int = 0) -> FallbackArray:
        """Concatenate arrays.

        Args:
            arrays: List of FallbackArrays or lists to concatenate
            axis: Axis along which to concatenate; currently unused for fallback

        Returns:
            Concatenated FallbackArray

        """
        if not arrays:
            return FallbackArray([])

        result: list[Any] = []
        for arr in arrays:
            if isinstance(arr, FallbackArray):
                result.extend(arr.data)
            else:
                result.extend(arr)

        return FallbackArray(result)

    @staticmethod
    def stack_func(arrays: list[FallbackArray] | list[list[Any]], axis: int = 0) -> FallbackArray:
        """Stack arrays.

        Args:
            arrays: List of FallbackArrays or lists to stack
            axis: Axis along which to stack; currently unused for fallback

        Returns:
            Stacked FallbackArray

        """
        return _FallbackFunctions.concatenate_func(arrays, axis)

    @staticmethod
    def unique_func(ar: FallbackArray | list[Any]) -> FallbackArray:
        """Find unique elements.

        Args:
            ar: FallbackArray or list to find unique elements in

        Returns:
            FallbackArray with unique elements

        """
        data: list[Any] = ar.data if isinstance(ar, FallbackArray) else list(ar)
        seen: set[Any] = set()
        result: list[Any] = []
        for x in data:
            if x not in seen:
                seen.add(x)
                result.append(x)

        return FallbackArray(result)

    @staticmethod
    def sort_func(a: FallbackArray | list[Any]) -> FallbackArray | list[Any]:
        """Sort array.

        Args:
            a: FallbackArray or list to sort

        Returns:
            FallbackArray with sorted elements, or sorted list for list input

        """
        if isinstance(a, FallbackArray):
            return FallbackArray(sorted(a.data), a.dtype, a.shape)
        return sorted(a)

    @staticmethod
    def argsort_func(a: FallbackArray | list[Any]) -> FallbackArray:
        """Get indices that would sort array.

        Args:
            a: FallbackArray or list to sort

        Returns:
            FallbackArray with indices that would sort the input

        """
        data: list[Any] = a.data if isinstance(a, FallbackArray) else list(a)
        indices = list(range(len(data)))
        indices.sort(key=lambda i: data[i])
        return FallbackArray(indices)

    @staticmethod
    def where_func(
        condition: FallbackArray | list[Any],
        x: FallbackArray | float | int | None = None,
        y: FallbackArray | float | int | None = None,
    ) -> FallbackArray | tuple[FallbackArray, ...]:
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

        cond_data: list[Any] = condition.data if isinstance(condition, FallbackArray) else list(condition)
        x_data: list[Any] = x.data if isinstance(x, FallbackArray) else [x] * len(cond_data)
        y_data: list[Any] = y.data if isinstance(y, FallbackArray) else [y] * len(cond_data)

        result = [xv if c else yv for c, xv, yv in zip(cond_data, x_data, y_data, strict=False)]
        return FallbackArray(result)

    @staticmethod
    def allclose_func(
        a: FallbackArray | list[Any],
        b: FallbackArray | list[Any],
        rtol: float = 1e-05,
        atol: float = 1e-08,
    ) -> bool:
        """Check if arrays are element-wise equal within tolerance.

        Args:
            a: First FallbackArray or list
            b: Second FallbackArray or list
            rtol: Relative tolerance; defaults to 1e-05
            atol: Absolute tolerance; defaults to 1e-08

        Returns:
            True if arrays are close within tolerance, False otherwise

        """
        a_data: list[Any] = a.data if isinstance(a, FallbackArray) else list(a)
        b_data: list[Any] = b.data if isinstance(b, FallbackArray) else list(b)

        if len(a_data) != len(b_data):
            return False

        return all(abs(float(av) - float(bv)) <= atol + rtol * abs(float(bv)) for av, bv in zip(a_data, b_data, strict=False))

    @staticmethod
    def array_equal_func(a: FallbackArray | list[Any], b: FallbackArray | list[Any]) -> bool:
        """Check if arrays are exactly equal.

        Args:
            a: First FallbackArray or list
            b: Second FallbackArray or list

        Returns:
            True if arrays are exactly equal, False otherwise

        """
        a_data: list[Any] = a.data if isinstance(a, FallbackArray) else list(a)
        b_data: list[Any] = b.data if isinstance(b, FallbackArray) else list(b)
        return a_data == b_data

    @staticmethod
    def asarray_func(a: FallbackArray | list[Any], dtype_arg: type[Any] | None = None) -> FallbackArray:
        """Convert to array.

        Args:
            a: Input data to convert to array
            dtype_arg: Optional data type for conversion

        Returns:
            FallbackArray with input data

        """
        if isinstance(a, FallbackArray):
            return a if dtype_arg is None else a.astype(dtype_arg)
        return FallbackArray(a, dtype_arg)

    @staticmethod
    def gradient_func(f: FallbackArray | list[Any], *varargs: float) -> FallbackArray:
        """Calculate gradient using finite differences.

        Args:
            f: FallbackArray or list to compute gradient for
            *varargs: Additional parameters (currently unused for fallback)

        Returns:
            FallbackArray with gradient values using forward, backward, or central differences

        """
        data: list[Any] = f.data if isinstance(f, FallbackArray) else list(f)
        result: list[float] = []
        for i in range(len(data)):
            if i == 0:
                grad = float(data[1]) - float(data[0]) if len(data) > 1 else 0.0
            elif i == len(data) - 1:
                grad = float(data[-1]) - float(data[-2])
            else:
                grad = (float(data[i + 1]) - float(data[i - 1])) / 2
            result.append(grad)

        return FallbackArray(result)

    @staticmethod
    def diff_func(a: FallbackArray | list[Any], n: int = 1) -> FallbackArray:
        """Calculate n-th discrete difference.

        Args:
            a: FallbackArray or list to compute differences for
            n: Order of difference; defaults to 1

        Returns:
            FallbackArray with differences

        """
        data: list[Any] = a.data if isinstance(a, FallbackArray) else list(a)
        for _ in range(n):
            result = [data[i] - data[i - 1] for i in range(1, len(data))]
            data = result

        return FallbackArray(data)

    @staticmethod
    def cumsum_func(a: FallbackArray | list[Any]) -> FallbackArray:
        """Cumulative sum.

        Args:
            a: FallbackArray or list to compute cumulative sum for

        Returns:
            FallbackArray with cumulative sum

        """
        data: list[Any] = a.data if isinstance(a, FallbackArray) else list(a)
        result: list[float] = []
        total = 0.0
        for val in data:
            total += float(val)
            result.append(total)

        return FallbackArray(result)

    @staticmethod
    def histogram_func(a: FallbackArray | list[Any], bins: int = 10) -> tuple[FallbackArray, FallbackArray]:
        """Compute histogram.

        Args:
            a: FallbackArray or list to compute histogram for
            bins: Number of bins; defaults to 10

        Returns:
            Tuple of (counts, bin_edges) as FallbackArrays

        """
        data: list[Any] = a.data if isinstance(a, FallbackArray) else list(a)
        if not data:
            return FallbackArray([0] * bins), FallbackArray([0.0] * (bins + 1))

        min_val = float(min(data))
        max_val = float(max(data))

        if min_val == max_val:
            return FallbackArray([len(data)]), FallbackArray([min_val, max_val])

        bin_width = (max_val - min_val) / bins
        edges = [min_val + i * bin_width for i in range(bins + 1)]

        counts = [0] * bins
        for val in data:
            bin_idx = min(int((float(val) - min_val) / bin_width), bins - 1)
            counts[bin_idx] += 1

        return FallbackArray(counts), FallbackArray(edges)

    @staticmethod
    def percentile_func(a: FallbackArray | list[Any], q: float) -> float | None:
        """Calculate percentile.

        Args:
            a: FallbackArray or list to compute percentile for
            q: Percentile value (0-100)

        Returns:
            Percentile value, or None if input is empty

        """
        data = sorted(a.data) if isinstance(a, FallbackArray) else sorted(a)
        if not data:
            return None

        k = (len(data) - 1) * (q / 100.0)
        f = math.floor(k)
        c = math.ceil(k)

        if f == c:
            return float(data[int(k)])

        d0 = float(data[int(f)]) * (c - k)
        d1 = float(data[int(c)]) * (k - f)
        return d0 + d1

    @staticmethod
    def median_func(a: FallbackArray | list[Any]) -> float | None:
        """Calculate median.

        Args:
            a: FallbackArray or list to compute median for

        Returns:
            Median value, or None if input is empty

        """
        return _FallbackFunctions.percentile_func(a, 50)

    @staticmethod
    def dot_func(a: FallbackArray | list[Any], b: FallbackArray | list[Any]) -> float:
        """Dot product of two arrays.

        Args:
            a: First FallbackArray or list
            b: Second FallbackArray or list

        Returns:
            Dot product result

        Raises:
            ValueError: If arrays have different lengths

        """
        a_data: list[Any] = a.data if isinstance(a, FallbackArray) else list(a)
        b_data: list[Any] = b.data if isinstance(b, FallbackArray) else list(b)

        if len(a_data) != len(b_data):
            raise ValueError("Arrays must have same length for dot product")

        return sum(float(av) * float(bv) for av, bv in zip(a_data, b_data, strict=False))

    @staticmethod
    def cross_func(a: FallbackArray | list[Any], b: FallbackArray | list[Any]) -> FallbackArray:
        """Cross product of two 3D vectors.

        Args:
            a: First FallbackArray or list (3D vector)
            b: Second FallbackArray or list (3D vector)

        Returns:
            FallbackArray with cross product result

        Raises:
            ValueError: If vectors are not 3D

        """
        a_data: list[Any] = a.data if isinstance(a, FallbackArray) else list(a)
        b_data: list[Any] = b.data if isinstance(b, FallbackArray) else list(b)

        if len(a_data) != 3 or len(b_data) != 3:
            raise ValueError("Cross product requires 3D vectors")

        result = [
            float(a_data[1]) * float(b_data[2]) - float(a_data[2]) * float(b_data[1]),
            float(a_data[2]) * float(b_data[0]) - float(a_data[0]) * float(b_data[2]),
            float(a_data[0]) * float(b_data[1]) - float(a_data[1]) * float(b_data[0]),
        ]
        return FallbackArray(result)

    @staticmethod
    def reshape_func(a: FallbackArray | list[Any], newshape: int | tuple[int, ...]) -> FallbackArray:
        """Reshape array.

        Args:
            a: FallbackArray or list to reshape
            newshape: New shape as integer or tuple of integers

        Returns:
            Reshaped FallbackArray

        """
        if isinstance(a, FallbackArray):
            if isinstance(newshape, int):
                return a.reshape(newshape)
            return a.reshape(*newshape)
        arr = FallbackArray(a)
        if isinstance(newshape, int):
            return arr.reshape(newshape)
        return arr.reshape(*newshape)

    @staticmethod
    def transpose_func(a: FallbackArray | list[Any]) -> FallbackArray:
        """Transpose array (basic 2D implementation).

        Args:
            a: FallbackArray or list to transpose

        Returns:
            Transposed FallbackArray

        """
        if not isinstance(a, FallbackArray):
            return FallbackArray(a)
        if a.ndim != 2:
            return a

        rows, cols = a.shape
        result: list[Any] = []
        for j in range(cols):
            result.extend(a.data[i * cols + j] for i in range(rows))
        return FallbackArray(result, a.dtype, (cols, rows))

    @staticmethod
    def sum_func(a: FallbackArray | list[Any], axis: int | None = None) -> float:
        """Sum of array elements.

        Args:
            a: FallbackArray or list to sum
            axis: Axis along which to sum; currently unused for fallback

        Returns:
            Sum of all elements

        """
        return a.sum(axis) if isinstance(a, FallbackArray) else float(sum(a))

    @staticmethod
    def mean_func(a: FallbackArray | list[Any], axis: int | None = None) -> float:
        """Mean of array elements.

        Args:
            a: FallbackArray or list to compute mean of
            axis: Axis along which to compute mean; currently unused for fallback

        Returns:
            Mean value

        """
        if isinstance(a, FallbackArray):
            return a.mean()
        return float(sum(a)) / len(a) if a else 0.0

    @staticmethod
    def std_func(a: FallbackArray | list[Any], axis: int | None = None) -> float:
        """Calculate standard deviation.

        Args:
            a: FallbackArray or list to compute standard deviation of
            axis: Axis along which to compute std; currently unused for fallback

        Returns:
            Standard deviation value

        """
        if isinstance(a, FallbackArray):
            return a.std()
        m = _FallbackFunctions.mean_func(a)
        variance = sum((float(x) - m) ** 2 for x in a) / len(a)
        return math.sqrt(variance)

    @staticmethod
    def var_func(a: FallbackArray | list[Any], axis: int | None = None) -> float:
        """Variance.

        Args:
            a: FallbackArray or list to compute variance of
            axis: Axis along which to compute variance; currently unused for fallback

        Returns:
            Variance value

        """
        if isinstance(a, FallbackArray):
            m = a.mean()
            return sum((float(x) - m) ** 2 for x in a.data) / len(a.data)
        m = _FallbackFunctions.mean_func(a)
        return sum((float(x) - m) ** 2 for x in a) / len(a)

    @staticmethod
    def min_func(a: FallbackArray | list[Any], axis: int | None = None) -> float | None:
        """Minimum value.

        Args:
            a: FallbackArray or list to find minimum of
            axis: Axis along which to find min; currently unused for fallback

        Returns:
            Minimum value, or None if empty

        """
        if isinstance(a, FallbackArray):
            return a.min()
        return float(min(a)) if a else None

    @staticmethod
    def max_func(a: FallbackArray | list[Any], axis: int | None = None) -> float | None:
        """Maximum value.

        Args:
            a: FallbackArray or list to find maximum of
            axis: Axis along which to find max; currently unused for fallback

        Returns:
            Maximum value, or None if empty

        """
        if isinstance(a, FallbackArray):
            return a.max()
        return float(max(a)) if a else None

    @staticmethod
    def argmin_func(a: FallbackArray | list[Any], axis: int | None = None) -> int | None:
        """Index of minimum.

        Args:
            a: FallbackArray or list to find minimum index of
            axis: Axis along which to find argmin; currently unused for fallback

        Returns:
            Index of minimum element, or None if empty

        """
        if isinstance(a, FallbackArray):
            return a.argmin()
        if not a:
            return None
        min_val = min(a)
        return list(a).index(min_val)

    @staticmethod
    def argmax_func(a: FallbackArray | list[Any], axis: int | None = None) -> int | None:
        """Index of maximum.

        Args:
            a: FallbackArray or list to find maximum index of
            axis: Axis along which to find argmax; currently unused for fallback

        Returns:
            Index of maximum element, or None if empty

        """
        if isinstance(a, FallbackArray):
            return a.argmax()
        if not a:
            return None
        max_val = max(a)
        return list(a).index(max_val)


class FallbackNumPy:
    """Fallback numpy module with submodules."""

    array = staticmethod(_FallbackFunctions.array_func)
    zeros = staticmethod(_FallbackFunctions.zeros_func)
    ones = staticmethod(_FallbackFunctions.ones_func)
    empty = staticmethod(_FallbackFunctions.empty_func)
    full = staticmethod(_FallbackFunctions.full_func)
    eye = staticmethod(_FallbackFunctions.eye_func)
    arange = staticmethod(_FallbackFunctions.arange_func)
    linspace = staticmethod(_FallbackFunctions.linspace_func)
    meshgrid = staticmethod(_FallbackFunctions.meshgrid_func)
    sqrt = staticmethod(_FallbackFunctions.sqrt_func)
    abs = staticmethod(_FallbackFunctions.abs_func)
    round = staticmethod(_FallbackFunctions.round_func)
    floor = staticmethod(_FallbackFunctions.floor_func)
    ceil = staticmethod(_FallbackFunctions.ceil_func)
    concatenate = staticmethod(_FallbackFunctions.concatenate_func)
    stack = staticmethod(_FallbackFunctions.stack_func)
    reshape = staticmethod(_FallbackFunctions.reshape_func)
    transpose = staticmethod(_FallbackFunctions.transpose_func)
    unique = staticmethod(_FallbackFunctions.unique_func)
    sort = staticmethod(_FallbackFunctions.sort_func)
    argsort = staticmethod(_FallbackFunctions.argsort_func)
    where = staticmethod(_FallbackFunctions.where_func)
    allclose = staticmethod(_FallbackFunctions.allclose_func)
    array_equal = staticmethod(_FallbackFunctions.array_equal_func)
    asarray = staticmethod(_FallbackFunctions.asarray_func)
    sum = staticmethod(_FallbackFunctions.sum_func)
    mean = staticmethod(_FallbackFunctions.mean_func)
    std = staticmethod(_FallbackFunctions.std_func)
    var = staticmethod(_FallbackFunctions.var_func)
    min = staticmethod(_FallbackFunctions.min_func)
    max = staticmethod(_FallbackFunctions.max_func)
    argmin = staticmethod(_FallbackFunctions.argmin_func)
    argmax = staticmethod(_FallbackFunctions.argmax_func)
    gradient = staticmethod(_FallbackFunctions.gradient_func)
    diff = staticmethod(_FallbackFunctions.diff_func)
    cumsum = staticmethod(_FallbackFunctions.cumsum_func)
    histogram = staticmethod(_FallbackFunctions.histogram_func)
    percentile = staticmethod(_FallbackFunctions.percentile_func)
    median = staticmethod(_FallbackFunctions.median_func)
    dot = staticmethod(_FallbackFunctions.dot_func)
    cross = staticmethod(_FallbackFunctions.cross_func)
    ndarray = FallbackArray
    dtype = type
    float32 = float
    float64 = float
    int32 = int
    int64 = int
    uint8 = int
    uint16 = int
    uint32 = int
    linalg = _FallbackLinalg
    fft = _FallbackFft
    random = _FallbackRandom


if TYPE_CHECKING:
    import numpy as np

    NpOrFallback = np.ndarray[Any, Any] | FallbackArray


HAS_NUMPY: bool
NUMPY_VERSION: str | None
np: Any
numpy: Any
ndarray: type[Any]
dtype: type[Any]
float32: type[Any]
float64: type[Any]
int32: type[Any]
int64: type[Any]
uint8: type[Any]
uint16: type[Any]
uint32: type[Any]
linalg: Any
fft: Any
random: Any
array: Any
zeros: Any
ones: Any
empty: Any
full: Any
eye: Any
arange: Any
linspace: Any
meshgrid: Any
sqrt: Any
np_abs: Any
np_round: Any
floor: Any
ceil: Any
concatenate: Any
stack: Any
reshape: Any
transpose: Any
unique: Any
sort: Any
argsort: Any
where: Any
allclose: Any
array_equal: Any
asarray: Any
np_sum: Any
mean: Any
std: Any
var: Any
np_min: Any
np_max: Any
argmin: Any
argmax: Any
gradient: Any
diff: Any
cumsum: Any
histogram: Any
percentile: Any
median: Any
dot: Any
cross: Any


try:
    import numpy as np

    HAS_NUMPY = True
    NUMPY_VERSION = str(np.__version__)
    numpy = np

    ndarray = np.ndarray
    dtype = np.dtype
    float32 = np.float32
    float64 = np.float64
    int32 = np.int32
    int64 = np.int64
    uint8 = np.uint8
    uint16 = np.uint16
    uint32 = np.uint32

    linalg = np.linalg
    fft = np.fft
    random = np.random

    array = np.array
    zeros = np.zeros
    ones = np.ones
    empty = np.empty
    full = np.full
    eye = np.eye
    arange = np.arange
    linspace = np.linspace
    meshgrid = np.meshgrid
    sqrt = np.sqrt
    np_abs = np.abs
    np_round = np.round
    floor = np.floor
    ceil = np.ceil
    concatenate = np.concatenate
    stack = np.stack
    reshape = np.reshape
    transpose = np.transpose
    unique = np.unique
    sort = np.sort
    argsort = np.argsort
    where = np.where
    allclose = np.allclose
    array_equal = np.array_equal
    asarray = np.asarray
    np_sum = np.sum
    mean = np.mean
    std = np.std
    var = np.var
    np_min = np.min
    np_max = np.max
    argmin = np.argmin
    argmax = np.argmax
    gradient = np.gradient
    diff = np.diff
    cumsum = np.cumsum
    histogram = np.histogram
    percentile = np.percentile
    median = np.median
    dot = np.dot
    cross = np.cross

except ImportError as e:
    logger.error("NumPy not available, using fallback implementations: %s", e)
    HAS_NUMPY = False
    NUMPY_VERSION = None

    _fallback_instance = FallbackNumPy()
    np = _fallback_instance
    numpy = _fallback_instance

    ndarray = FallbackArray
    dtype = type
    float32 = float
    float64 = float
    int32 = int
    int64 = int
    uint8 = int
    uint16 = int
    uint32 = int

    linalg = _FallbackLinalg
    fft = _FallbackFft
    random = _FallbackRandom

    array = _FallbackFunctions.array_func
    zeros = _FallbackFunctions.zeros_func
    ones = _FallbackFunctions.ones_func
    empty = _FallbackFunctions.empty_func
    full = _FallbackFunctions.full_func
    eye = _FallbackFunctions.eye_func
    arange = _FallbackFunctions.arange_func
    linspace = _FallbackFunctions.linspace_func
    meshgrid = _FallbackFunctions.meshgrid_func
    sqrt = _FallbackFunctions.sqrt_func
    np_abs = _FallbackFunctions.abs_func
    np_round = _FallbackFunctions.round_func
    floor = _FallbackFunctions.floor_func
    ceil = _FallbackFunctions.ceil_func
    concatenate = _FallbackFunctions.concatenate_func
    stack = _FallbackFunctions.stack_func
    reshape = _FallbackFunctions.reshape_func
    transpose = _FallbackFunctions.transpose_func
    unique = _FallbackFunctions.unique_func
    sort = _FallbackFunctions.sort_func
    argsort = _FallbackFunctions.argsort_func
    where = _FallbackFunctions.where_func
    allclose = _FallbackFunctions.allclose_func
    array_equal = _FallbackFunctions.array_equal_func
    asarray = _FallbackFunctions.asarray_func
    np_sum = _FallbackFunctions.sum_func
    mean = _FallbackFunctions.mean_func
    std = _FallbackFunctions.std_func
    var = _FallbackFunctions.var_func
    np_min = _FallbackFunctions.min_func
    np_max = _FallbackFunctions.max_func
    argmin = _FallbackFunctions.argmin_func
    argmax = _FallbackFunctions.argmax_func
    gradient = _FallbackFunctions.gradient_func
    diff = _FallbackFunctions.diff_func
    cumsum = _FallbackFunctions.cumsum_func
    histogram = _FallbackFunctions.histogram_func
    percentile = _FallbackFunctions.percentile_func
    median = _FallbackFunctions.median_func
    dot = _FallbackFunctions.dot_func
    cross = _FallbackFunctions.cross_func


__all__ = [
    "FallbackArray",
    "FallbackNumPy",
    "HAS_NUMPY",
    "NUMPY_VERSION",
    "allclose",
    "arange",
    "argmax",
    "argmin",
    "argsort",
    "array",
    "array_equal",
    "asarray",
    "ceil",
    "concatenate",
    "cross",
    "cumsum",
    "diff",
    "dot",
    "dtype",
    "empty",
    "eye",
    "fft",
    "float32",
    "float64",
    "floor",
    "full",
    "gradient",
    "histogram",
    "int32",
    "int64",
    "linalg",
    "linspace",
    "mean",
    "median",
    "meshgrid",
    "ndarray",
    "np",
    "np_abs",
    "np_max",
    "np_min",
    "np_round",
    "np_sum",
    "numpy",
    "ones",
    "percentile",
    "random",
    "reshape",
    "sort",
    "sqrt",
    "stack",
    "std",
    "transpose",
    "uint16",
    "uint32",
    "uint8",
    "unique",
    "var",
    "where",
    "zeros",
]
