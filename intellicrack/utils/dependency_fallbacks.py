"""Dependency fallbacks for Intellicrack.

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

Dependency fallbacks for Intellicrack
Provides safe imports and fallback implementations when dependencies are missing or incompatible
"""

import logging
import sys
from collections.abc import Callable, Sequence
from typing import Any


logger = logging.getLogger(__name__)

# Global flags for dependency availability
NUMPY_AVAILABLE: bool = False
PANDAS_AVAILABLE: bool = False
SKLEARN_AVAILABLE: bool = False
LIEF_AVAILABLE: bool = False
PYELFTOOLS_AVAILABLE: bool = False


# Safe import functions
def safe_import_numpy() -> Any:
    """Safely import numpy with fallback.

    Returns:
        Either the real numpy module or a NumpyFallback instance.

    """
    global NUMPY_AVAILABLE
    try:
        from intellicrack.handlers.numpy_handler import (
            HAS_NUMPY,
            numpy as np,
        )

        NUMPY_AVAILABLE = HAS_NUMPY
        return np
    except ImportError:
        logger.warning("numpy not available - using fallback", exc_info=True)
        NUMPY_AVAILABLE = False
        return create_numpy_fallback()
    except Exception as e:
        if "numpy.dtype size changed" in str(e):
            logger.warning("numpy compatibility issue - using fallback", exc_info=True)
        else:
            logger.warning("numpy import error: %s - using fallback", e, exc_info=True)
        NUMPY_AVAILABLE = False
        return create_numpy_fallback()


def safe_import_pandas() -> Any:
    """Safely import pandas with fallback.

    Returns:
        Either the real pandas module or a PandasFallback instance.

    """
    global PANDAS_AVAILABLE
    try:
        import pandas as pd

        PANDAS_AVAILABLE = True
        return pd
    except ImportError:
        logger.warning("pandas not available - using fallback", exc_info=True)
        PANDAS_AVAILABLE = False
        return create_pandas_fallback()
    except Exception as e:
        if "numpy.dtype size changed" in str(e):
            logger.warning("pandas compatibility issue - using fallback", exc_info=True)
        else:
            logger.warning("pandas import error: %s - using fallback", e, exc_info=True)
        PANDAS_AVAILABLE = False
        return create_pandas_fallback()


def safe_import_sklearn() -> Any:
    """Safely import sklearn with fallback.

    Returns:
        Either the real sklearn module or a SklearnFallback instance.

    """
    global SKLEARN_AVAILABLE
    try:
        import sklearn

        SKLEARN_AVAILABLE = True
        return sklearn
    except ImportError:
        logger.warning("sklearn not available - using fallback", exc_info=True)
        SKLEARN_AVAILABLE = False
        return create_sklearn_fallback()
    except Exception as e:
        if "numpy.dtype size changed" in str(e):
            logger.warning("sklearn compatibility issue - using fallback", exc_info=True)
        else:
            logger.warning("sklearn import error: %s - using fallback", e, exc_info=True)
        SKLEARN_AVAILABLE = False
        return create_sklearn_fallback()


def safe_import_lief() -> Any:
    """Safely import lief with fallback.

    Returns:
        Either the real lief module or a LiefFallback instance.

    Raises:
        ImportError: May raise and catch internally when lief handler
            is unavailable.

    """
    global LIEF_AVAILABLE
    try:
        from intellicrack.handlers.lief_handler import HAS_LIEF, lief

        LIEF_AVAILABLE = HAS_LIEF
        if HAS_LIEF:
            return lief
        error_msg = "LIEF not available"
        logger.error(error_msg)
        raise ImportError(error_msg)
    except ImportError:
        logger.warning("lief not available - using fallback", exc_info=True)
        LIEF_AVAILABLE = False
        return create_lief_fallback()


def safe_import_pyelftools() -> bool:
    """Safely import pyelftools with fallback.

    Returns:
        bool: True if pyelftools is available, False otherwise.

    """
    global PYELFTOOLS_AVAILABLE
    try:
        from intellicrack.handlers.pyelftools_handler import HAS_PYELFTOOLS, ELFFile, bytes2str

        if not HAS_PYELFTOOLS:
            error_msg = "pyelftools not available"
            logger.error(error_msg)
            raise ImportError(error_msg)

        test_bytes = b"test"
        test_str = bytes2str(test_bytes)

        logger.debug("pyelftools available - bytes2str: %s, ELFFile: %s", test_str, ELFFile)

        PYELFTOOLS_AVAILABLE = True
        return True
    except ImportError:
        logger.warning("pyelftools not available - using fallback", exc_info=True)
        PYELFTOOLS_AVAILABLE = False
        return False


# Fallback implementations
def _create_randn_fallback(shape: tuple[int, ...]) -> object:
    """Generate random normal distribution for given shape.

    Args:
        shape: Tuple specifying the shape of the array to generate.

    Returns:
        Nested list representing random normal distributed values.

    Raises:
        ValueError: If shape has more than 4 dimensions.

    """
    import random

    if not shape:
        return random.gauss(0, 1)
    if len(shape) == 1:
        return [random.gauss(0, 1) for _ in range(shape[0])]
    if len(shape) == 2:
        return [[random.gauss(0, 1) for _ in range(shape[1])] for _ in range(shape[0])]
    if len(shape) == 3:
        return [[[random.gauss(0, 1) for _ in range(shape[2])] for _ in range(shape[1])] for _ in range(shape[0])]
    if len(shape) == 4:
        return [
            [[[random.gauss(0, 1) for _ in range(shape[3])] for _ in range(shape[2])] for _ in range(shape[1])] for _ in range(shape[0])
        ]
    error_msg = "Too many dimensions for fallback randn"
    logger.error(error_msg)
    raise ValueError(error_msg)


def _create_rand_fallback(shape: tuple[int, ...]) -> object:
    """Generate random uniform distribution [0, 1) for given shape.

    Args:
        shape: Tuple specifying the shape of the array to generate.

    Returns:
        Nested list representing random uniform distributed values.

    Raises:
        ValueError: If shape has more than 2 dimensions.

    """
    import random

    if not shape:
        return random.random()  # noqa: S311
    if len(shape) == 1:
        return [random.random() for _ in range(shape[0])]  # noqa: S311
    if len(shape) == 2:
        return [[random.random() for _ in range(shape[1])] for _ in range(shape[0])]  # noqa: S311
    error_msg = "Too many dimensions for fallback rand"
    logger.error(error_msg)
    raise ValueError(error_msg)


def _create_random_int_fallback(low: int, high: int, size: int | None) -> int | list[int]:
    """Generate random integers.

    Args:
        low: Lower bound (inclusive).
        high: Upper bound (exclusive).
        size: Number of random integers to generate, or None for single value.

    Returns:
        Single integer or list of random integers.

    """
    import random

    if size is None:
        return random.randint(low, high - 1)  # noqa: S311
    return [random.randint(low, high - 1) for _ in range(size)]  # noqa: S311


def _create_random_uniform_fallback(low: float, high: float, size: int | None) -> float | list[float]:
    """Generate uniform random values.

    Args:
        low: Lower bound (inclusive).
        high: Upper bound (inclusive).
        size: Number of values to generate, or None for single value.

    Returns:
        Single float or list of uniform random values.

    """
    import random

    if size is None:
        return random.uniform(low, high)  # noqa: S311
    return [random.uniform(low, high) for _ in range(size)]  # noqa: S311


def _create_random_normal_fallback(loc: float, scale: float, size: int | None) -> float | list[float]:
    """Generate normal distribution.

    Args:
        loc: Mean of the distribution.
        scale: Standard deviation of the distribution.
        size: Number of values to generate, or None for single value.

    Returns:
        Single float or list of normally distributed values.

    """
    import random

    if size is None:
        return random.gauss(loc, scale)
    return [random.gauss(loc, scale) for _ in range(size)]


def _create_random_choice_fallback(a: list[Any], size: int | None, p: list[float] | None) -> Any | list[Any]:
    """Random choice from array.

    Args:
        a: Array-like to choose from.
        size: Number of choices to make, or None for single choice.
        p: Probabilities for weighted sampling, or None for uniform.

    Returns:
        Single element or list of randomly chosen elements.

    """
    import random

    if p is not None:
        # Weighted choice
        if size is None:
            return random.choices(a, weights=p, k=1)[0]  # noqa: S311
        return random.choices(a, weights=p, k=size)  # noqa: S311
    if size is None:
        return random.choice(a)  # noqa: S311
    return [random.choice(a) for _ in range(size)]  # noqa: S311


def _create_random_float_fallback(size: int | None) -> float | list[float]:
    """Generate random floats [0, 1).

    Args:
        size: Number of floats to generate, or None for single value.

    Returns:
        Single float or list of random floats in [0, 1).

    """
    import random

    if size is None:
        return random.random()  # noqa: S311
    return [random.random() for _ in range(size)]  # noqa: S311


def create_numpy_fallback() -> Any:
    """Create a minimal numpy fallback.

    Returns:
        A minimal numpy replacement module.

    """

    class NumpyFallback:
        """Minimal numpy replacement for when numpy is unavailable."""

        __version__ = "fallback-1.0.0"

        # Define ndarray as the list type for compatibility
        ndarray = list

        @staticmethod
        def array(data: Any) -> list[Any]:
            """Convert data to array-like structure.

            Args:
                data: Input data to convert.

            Returns:
                Array-like list representation.

            """
            if isinstance(data, list):
                return data
            return list(data) if hasattr(data, "__iter__") else [data]

        @staticmethod
        def zeros(shape: int | tuple[int, ...]) -> list[int] | list[list[int]]:
            """Create array of zeros with given shape.

            Args:
                shape: Integer or tuple specifying shape.

            Returns:
                Array of zeros with specified shape.

            """
            if isinstance(shape, int):
                return [0] * shape
            if isinstance(shape, tuple) and len(shape) == 2:
                return [[0] * shape[1] for _ in range(shape[0])]
            return []

        @staticmethod
        def mean(data: Sequence[float]) -> float:
            """Calculate mean of data.

            Args:
                data: List of numeric values.

            Returns:
                Mean value.

            """
            if not data:
                return 0.0
            return float(sum(data)) / len(data)

        @staticmethod
        def sum(data: Sequence[float]) -> float:
            """Calculate sum of data.

            Args:
                data: List of numeric values.

            Returns:
                Sum of values.

            """
            import builtins

            return float(builtins.sum(data)) if data else 0.0

        @staticmethod
        def where(condition: Sequence[bool]) -> list[int]:
            """Return indices where condition is true.

            Args:
                condition: List of boolean values.

            Returns:
                Indices where condition is True.

            """
            return [i for i, val in enumerate(condition) if val]

        class Random:
            """Random number generation fallback."""

            @staticmethod
            def randn(*shape: int) -> object:
                """Generate random normal distribution.

                Args:
                    *shape: Variable-length shape arguments.

                Returns:
                    Normally distributed random values.

                """
                return _create_randn_fallback(shape)

            @staticmethod
            def rand(*shape: int) -> object:
                """Generate random uniform distribution [0, 1).

                Args:
                    *shape: Variable-length shape arguments.

                Returns:
                    Uniformly distributed random values.

                """
                return _create_rand_fallback(shape)

            @staticmethod
            def randint(low: int, high: int, size: int | None = None) -> int | list[int]:
                """Generate random integers.

                Args:
                    low: Lower bound (inclusive).
                    high: Upper bound (exclusive).
                    size: Number of values, or None for single value.

                Returns:
                    Random integer or list of integers.

                """
                return _create_random_int_fallback(low, high, size)

            @staticmethod
            def uniform(low: float, high: float, size: int | None = None) -> float | list[float]:
                """Generate uniform random values.

                Args:
                    low: Lower bound (inclusive).
                    high: Upper bound (inclusive).
                    size: Number of values, or None for single value.

                Returns:
                    Random float or list of floats.

                """
                return _create_random_uniform_fallback(low, high, size)

            @staticmethod
            def normal(loc: float = 0.0, scale: float = 1.0, size: int | None = None) -> float | list[float]:
                """Generate normal distribution.

                Args:
                    loc: Mean of the distribution.
                    scale: Standard deviation.
                    size: Number of values, or None for single value.

                Returns:
                    Normally distributed random value(s).

                """
                return _create_random_normal_fallback(loc, scale, size)

            @staticmethod
            def choice(a: list[Any], size: int | None = None, p: list[float] | None = None) -> Any | list[Any]:
                """Random choice from array.

                Args:
                    a: Array-like to choose from.
                    size: Number of choices, or None for single.
                    p: Probabilities for weighted sampling.

                Returns:
                    Randomly chosen element(s).

                """
                return _create_random_choice_fallback(a, size, p)

            @staticmethod
            def random(size: int | None = None) -> float | list[float]:
                """Generate random floats [0, 1).

                Args:
                    size: Number of floats, or None for single.

                Returns:
                    Random float(s) in [0, 1).

                """
                return _create_random_float_fallback(size)

    return NumpyFallback()


def create_pandas_fallback() -> Any:
    """Create a minimal pandas fallback.

    Returns:
        A minimal pandas replacement module.

    """

    class DataFrameFallback:
        """Minimal DataFrame replacement for when pandas is unavailable."""

        def __init__(self, data: dict[str, Any] | list[Any] | None = None) -> None:
            """Initialize DataFrame fallback.

            Args:
                data: Dictionary, list, or None to initialize with.

            """
            if isinstance(data, dict):
                self.data: dict[str, Any] = data
            elif isinstance(data, list):
                self.data = {"column_0": data}
            else:
                self.data = {}

        def to_dict(self) -> dict[str, Any]:
            """Convert DataFrame to dictionary.

            Returns:
                Dictionary representation of data.

            """
            return self.data

        def __len__(self) -> int:
            """Get length of DataFrame.

            Returns:
                Number of rows.

            """
            return len(next(iter(self.data.values()))) if self.data else 0

    class PandasFallback:
        """Minimal pandas replacement for when pandas is unavailable."""

        __version__ = "fallback-1.0.0"
        DataFrame = DataFrameFallback

    return PandasFallback()


def create_sklearn_fallback() -> Any:
    """Create a minimal sklearn fallback.

    Returns:
        A minimal sklearn replacement module.

    """

    class RandomForestFallback:
        """Minimal RandomForest replacement for when sklearn is unavailable."""

        def __init__(self, n_estimators: int = 100) -> None:
            """Initialize RandomForest fallback.

            Args:
                n_estimators: Number of estimators (unused in fallback).

            """
            self.n_estimators = n_estimators

        def fit(self, X: list[Any], y: list[Any]) -> "RandomForestFallback":
            """Fit the model (fallback does nothing).

            Args:
                X: Training features.
                y: Training labels.

            Returns:
                Self for chaining.

            """
            logger.debug("RandomForest fallback fit called with %s samples and %s labels", len(X), len(y))
            return self

        def predict(self, X: list[Any]) -> list[int]:
            """Predict labels (fallback returns zeros).

            Args:
                X: Features to predict on.

            Returns:
                Predicted labels (all zeros).

            """
            return [0] * len(X)

        def predict_proba(self, X: list[Any]) -> list[list[float]]:
            """Predict probabilities (fallback returns 50/50).

            Args:
                X: Features to predict on.

            Returns:
                Predicted probabilities (50/50 for two classes).

            """
            return [[0.5, 0.5] for _ in X]

    class DBSCANFallback:
        """Minimal DBSCAN replacement for when sklearn is unavailable."""

        def __init__(self, eps: float = 0.5, min_samples: int = 5) -> None:
            """Initialize DBSCAN fallback.

            Args:
                eps: Epsilon parameter (unused in fallback).
                min_samples: Minimum samples parameter (unused in fallback).

            """
            self.eps = eps
            self.min_samples = min_samples

        def fit_predict(self, X: list[Any]) -> list[int]:
            """Fit and predict clusters (fallback returns zeros).

            Args:
                X: Features to cluster.

            Returns:
                Cluster labels (all zeros).

            """
            return [0] * len(X)

    class StandardScalerFallback:
        """Minimal StandardScaler replacement for when sklearn is unavailable."""

        def fit(self, X: list[Any]) -> "StandardScalerFallback":
            """Fit the scaler (fallback does nothing).

            Args:
                X: Data to fit.

            Returns:
                Self for chaining.

            """
            logger.debug("StandardScaler fallback fit called with %s samples", len(X))
            return self

        def transform(self, X: list[Any]) -> list[Any]:
            """Transform data (fallback returns unchanged).

            Args:
                X: Data to transform.

            Returns:
                Unchanged data.

            """
            return X

        def fit_transform(self, X: list[Any]) -> list[Any]:
            """Fit and transform data (fallback returns unchanged).

            Args:
                X: Data to fit and transform.

            Returns:
                Unchanged data.

            """
            return X

    class ClusterModule:
        """Sklearn cluster module fallback."""

        DBSCAN = DBSCANFallback

    class EnsembleModule:
        """Sklearn ensemble module fallback."""

        RandomForestClassifier = RandomForestFallback

    class PreprocessingModule:
        """Sklearn preprocessing module fallback."""

        StandardScaler = StandardScalerFallback

    class SklearnFallback:
        """Minimal sklearn replacement for when sklearn is unavailable."""

        __version__ = "fallback-1.0.0"
        cluster = ClusterModule()
        ensemble = EnsembleModule()
        preprocessing = PreprocessingModule()

    return SklearnFallback()


def create_lief_fallback() -> Any:
    """Create a minimal lief fallback.

    Returns:
        A minimal lief replacement module.

    """

    class LiefFallback:
        """Minimal lief replacement for when lief is unavailable."""

        __version__ = "fallback-1.0.0"

        class ELF:
            """ELF parsing fallback."""

            @staticmethod
            def parse(filename: str) -> None:
                """Parse ELF file (fallback returns None).

                Args:
                    filename: Path to ELF file.

                Returns:
                    None.

                """
                logger.debug("ELF fallback parse called for: %s", filename)

        @staticmethod
        def parse(filename: str) -> None:
            """Parse binary file (fallback returns None).

            Args:
                filename: Path to binary file.

            Returns:
                None.

            """
            logger.debug("Lief fallback parse called for: %s", filename)

    return LiefFallback()


# Safe module replacer
class SafeModuleReplacer:
    """Replaces problematic modules with safe fallbacks."""

    def __init__(self) -> None:
        """Initialize safe module replacer with empty tracking state."""
        self.original_modules: dict[str, Any] = {}
        self.replaced_modules: set[str] = set()

    def replace_module(self, module_name: str, fallback_factory: Callable[[], Any]) -> None:
        """Replace a module with a fallback implementation.

        Args:
            module_name: Name of module to replace.
            fallback_factory: Callable that returns fallback module instance.

        """
        if module_name in sys.modules and module_name not in self.replaced_modules:
            self.original_modules[module_name] = sys.modules[module_name]

        sys.modules[module_name] = fallback_factory()
        self.replaced_modules.add(module_name)
        logger.info("Replaced %s with fallback implementation", module_name)

    def restore_module(self, module_name: str) -> None:
        """Restore original module if available.

        Args:
            module_name: Name of module to restore.

        """
        if module_name in self.original_modules:
            sys.modules[module_name] = self.original_modules[module_name]
            self.replaced_modules.discard(module_name)
            logger.info("Restored original %s", module_name)


# Global replacer instance
_module_replacer: SafeModuleReplacer = SafeModuleReplacer()


def initialize_safe_imports() -> None:
    """Initialize safe imports by testing and replacing problematic modules.

    Tests whether critical dependencies (numpy, pandas, sklearn) are working
    correctly, and replaces them with fallback implementations if they fail.
    """
    logger.info("Initializing safe dependency imports...")

    # Test and replace numpy if needed
    try:
        import numpy as np

        test_array = np.array([1, 2, 3])
        logger.info("numpy working correctly - test array shape: %s", test_array.shape)
    except Exception as e:
        logger.warning("numpy issue detected: %s", e, exc_info=True)
        _module_replacer.replace_module("numpy", create_numpy_fallback)

    # Test and replace pandas if needed
    try:
        import pandas as pd

        test_df = pd.DataFrame({"test": [1, 2, 3]})
        logger.info("pandas working correctly - test df shape: %s", test_df.shape)
    except Exception as e:
        logger.warning("pandas issue detected: %s", e, exc_info=True)
        _module_replacer.replace_module("pandas", create_pandas_fallback)

    try:
        logger.info("sklearn working correctly")
    except Exception as e:
        logger.warning("sklearn issue detected: %s", e, exc_info=True)
        _module_replacer.replace_module("sklearn", create_sklearn_fallback)

        def sklearn_ensemble_factory() -> Any:
            sklearn_obj = create_sklearn_fallback()
            return sklearn_obj.ensemble

        def sklearn_cluster_factory() -> Any:
            sklearn_obj = create_sklearn_fallback()
            return sklearn_obj.cluster

        def sklearn_preprocessing_factory() -> Any:
            sklearn_obj = create_sklearn_fallback()
            return sklearn_obj.preprocessing

        _module_replacer.replace_module("sklearn.ensemble", sklearn_ensemble_factory)
        _module_replacer.replace_module("sklearn.cluster", sklearn_cluster_factory)
        _module_replacer.replace_module("sklearn.preprocessing", sklearn_preprocessing_factory)

    logger.info("Safe import initialization complete")


def get_dependency_status() -> dict[str, bool]:
    """Get status of all dependencies.

    Returns:
        Dictionary mapping dependency names to availability status.

    """
    status = {
        "numpy": NUMPY_AVAILABLE,
        "pandas": PANDAS_AVAILABLE,
        "sklearn": SKLEARN_AVAILABLE,
        "lief": LIEF_AVAILABLE,
        "pyelftools": PYELFTOOLS_AVAILABLE,
    }

    working_deps = sum(status.values())
    total_deps = len(status)

    logger.info("Dependency status: %s/%s working", working_deps, total_deps)
    for dep, available in status.items():
        status_text = "OK" if available else "WARNING"
        logger.info("  [%s] %s", status_text, dep)

    return status


# Auto-initialize when module is imported
try:
    initialize_safe_imports()
except Exception as e:
    logger.exception("Failed to initialize safe imports: %s", e)
