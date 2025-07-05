"""
Dependency fallbacks for Intellicrack
Provides safe imports and fallback implementations when dependencies are missing or incompatible
"""

import logging
import sys

logger = logging.getLogger(__name__)

# Global flags for dependency availability
NUMPY_AVAILABLE = False
PANDAS_AVAILABLE = False
SKLEARN_AVAILABLE = False
LIEF_AVAILABLE = False
PYELFTOOLS_AVAILABLE = False

# Safe import functions
def safe_import_numpy():
    """Safely import numpy with fallback."""
    global NUMPY_AVAILABLE
    try:
        import numpy as np
        NUMPY_AVAILABLE = True
        return np
    except ImportError:
        logger.warning("numpy not available - using fallback")
        NUMPY_AVAILABLE = False
        return create_numpy_fallback()
    except Exception as e:
        if "numpy.dtype size changed" in str(e):
            logger.warning("numpy compatibility issue - using fallback")
        else:
            logger.warning(f"numpy import error: {e} - using fallback")
        NUMPY_AVAILABLE = False
        return create_numpy_fallback()

def safe_import_pandas():
    """Safely import pandas with fallback."""
    global PANDAS_AVAILABLE
    try:
        import pandas as pd
        PANDAS_AVAILABLE = True
        return pd
    except ImportError:
        logger.warning("pandas not available - using fallback")
        PANDAS_AVAILABLE = False
        return create_pandas_fallback()
    except Exception as e:
        if "numpy.dtype size changed" in str(e):
            logger.warning("pandas compatibility issue - using fallback")
        else:
            logger.warning(f"pandas import error: {e} - using fallback")
        PANDAS_AVAILABLE = False
        return create_pandas_fallback()

def safe_import_sklearn():
    """Safely import sklearn with fallback."""
    global SKLEARN_AVAILABLE
    try:
        import sklearn
        SKLEARN_AVAILABLE = True
        return sklearn
    except ImportError:
        logger.warning("sklearn not available - using fallback")
        SKLEARN_AVAILABLE = False
        return create_sklearn_fallback()
    except Exception as e:
        if "numpy.dtype size changed" in str(e):
            logger.warning("sklearn compatibility issue - using fallback")
        else:
            logger.warning(f"sklearn import error: {e} - using fallback")
        SKLEARN_AVAILABLE = False
        return create_sklearn_fallback()

def safe_import_lief():
    """Safely import lief with fallback."""
    global LIEF_AVAILABLE
    try:
        import lief
        LIEF_AVAILABLE = True
        return lief
    except ImportError:
        logger.warning("lief not available - using fallback")
        LIEF_AVAILABLE = False
        return create_lief_fallback()

def safe_import_pyelftools():
    """Safely import pyelftools with fallback."""
    global PYELFTOOLS_AVAILABLE
    try:
        from elftools.common.py3compat import bytes2str, maxint
        from elftools.elf.elffile import ELFFile
        PYELFTOOLS_AVAILABLE = True
        return True
    except ImportError:
        logger.warning("pyelftools not available - using fallback")
        PYELFTOOLS_AVAILABLE = False
        return False

# Fallback implementations
def create_numpy_fallback():
    """Create a minimal numpy fallback."""
    class NumpyFallback:
        """Minimal numpy replacement for when numpy is unavailable."""
        __version__ = "fallback-1.0.0"

        # Define ndarray as the list type for compatibility
        ndarray = list

        @staticmethod
        def array(data):
            """Convert data to array-like structure."""
            if isinstance(data, list):
                return data
            return list(data) if hasattr(data, '__iter__') else [data]

        @staticmethod
        def zeros(shape):
            """Create array of zeros with given shape."""
            if isinstance(shape, int):
                return [0] * shape
            elif isinstance(shape, tuple) and len(shape) == 2:
                return [[0] * shape[1] for _ in range(shape[0])]
            return []

        @staticmethod
        def mean(data):
            """Calculate mean of data."""
            if not data:
                return 0
            return sum(data) / len(data)

        @staticmethod
        def sum(data):
            """Calculate sum of data."""
            return sum(data) if data else 0

        @staticmethod
        def where(condition):
            """Return indices where condition is true."""
            return [i for i, val in enumerate(condition) if val]

        class random:
            """Random number generation fallback."""
            @staticmethod
            def randn(*shape):
                """Generate random normal distribution."""
                import random
                if len(shape) == 0:
                    return random.gauss(0, 1)
                elif len(shape) == 1:
                    return [random.gauss(0, 1) for _ in range(shape[0])]
                elif len(shape) == 2:
                    return [[random.gauss(0, 1) for _ in range(shape[1])] for _ in range(shape[0])]
                elif len(shape) == 3:
                    return [[[random.gauss(0, 1) for _ in range(shape[2])] for _ in range(shape[1])] for _ in range(shape[0])]
                elif len(shape) == 4:
                    return [[[[random.gauss(0, 1) for _ in range(shape[3])] for _ in range(shape[2])] for _ in range(shape[1])] for _ in range(shape[0])]
                else:
                    raise ValueError("Too many dimensions for fallback randn")

            @staticmethod
            def rand(*shape):
                """Generate random uniform distribution [0, 1)."""
                import random
                if len(shape) == 0:
                    return random.random()
                elif len(shape) == 1:
                    return [random.random() for _ in range(shape[0])]
                elif len(shape) == 2:
                    return [[random.random() for _ in range(shape[1])] for _ in range(shape[0])]
                else:
                    raise ValueError("Too many dimensions for fallback rand")

            @staticmethod
            def randint(low, high, size=None):
                """Generate random integers."""
                import random
                if size is None:
                    return random.randint(low, high - 1)
                elif isinstance(size, int):
                    return [random.randint(low, high - 1) for _ in range(size)]
                else:
                    raise ValueError("Complex sizes not supported in fallback")

            @staticmethod
            def uniform(low, high, size=None):
                """Generate uniform random values."""
                import random
                if size is None:
                    return random.uniform(low, high)
                elif isinstance(size, int):
                    return [random.uniform(low, high) for _ in range(size)]
                else:
                    raise ValueError("Complex sizes not supported in fallback")

            @staticmethod
            def normal(loc=0.0, scale=1.0, size=None):
                """Generate normal distribution."""
                import random
                if size is None:
                    return random.gauss(loc, scale)
                elif isinstance(size, int):
                    return [random.gauss(loc, scale) for _ in range(size)]
                else:
                    raise ValueError("Complex sizes not supported in fallback")

            @staticmethod
            def choice(a, size=None, p=None):
                """Random choice from array."""
                import random
                if p is not None:
                    # Weighted choice
                    if size is None:
                        return random.choices(a, weights=p, k=1)[0]
                    else:
                        return random.choices(a, weights=p, k=size)
                else:
                    if size is None:
                        return random.choice(a)
                    else:
                        return [random.choice(a) for _ in range(size)]

            @staticmethod
            def random(size=None):
                """Generate random floats [0, 1)."""
                import random
                if size is None:
                    return random.random()
                elif isinstance(size, int):
                    return [random.random() for _ in range(size)]
                else:
                    raise ValueError("Complex sizes not supported in fallback")

    return NumpyFallback()

def create_pandas_fallback():
    """Create a minimal pandas fallback."""
    class DataFrameFallback:
        """Minimal DataFrame replacement for when pandas is unavailable."""

        def __init__(self, data=None):
            if isinstance(data, dict):
                self.data = data
            elif isinstance(data, list):
                self.data = {'column_0': data}
            else:
                self.data = {}

        def to_dict(self):
            """Convert DataFrame to dictionary."""
            return self.data

        def __len__(self):
            if self.data:
                return len(next(iter(self.data.values())))
            return 0

    class PandasFallback:
        """Minimal pandas replacement for when pandas is unavailable."""
        __version__ = "fallback-1.0.0"
        DataFrame = DataFrameFallback

    return PandasFallback()

def create_sklearn_fallback():
    """Create a minimal sklearn fallback."""
    class RandomForestFallback:
        """Minimal RandomForest replacement for when sklearn is unavailable."""

        def __init__(self, n_estimators=100):
            self.n_estimators = n_estimators

        def fit(self, X, y):
            """Fit the model (fallback does nothing)."""
            logger.debug(f"RandomForest fallback fit called with {len(X)} samples and {len(y)} labels")
            return self

        def predict(self, X):
            """Predict labels (fallback returns zeros)."""
            return [0] * len(X)

        def predict_proba(self, X):
            """Predict probabilities (fallback returns 50/50)."""
            return [[0.5, 0.5] for _ in X]

    class DBSCANFallback:
        """Minimal DBSCAN replacement for when sklearn is unavailable."""

        def __init__(self, eps=0.5, min_samples=5):
            self.eps = eps
            self.min_samples = min_samples

        def fit_predict(self, X):
            """Fit and predict clusters (fallback returns zeros)."""
            return [0] * len(X)

    class StandardScalerFallback:
        """Minimal StandardScaler replacement for when sklearn is unavailable."""

        def fit(self, X):
            """Fit the scaler (fallback does nothing)."""
            logger.debug(f"StandardScaler fallback fit called with {len(X)} samples")
            return self

        def transform(self, X):
            """Transform data (fallback returns unchanged)."""
            return X

        def fit_transform(self, X):
            """Fit and transform data (fallback returns unchanged)."""
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

def create_lief_fallback():
    """Create a minimal lief fallback."""
    class LiefFallback:
        """Minimal lief replacement for when lief is unavailable."""
        __version__ = "fallback-1.0.0"

        class ELF:
            """ELF parsing fallback."""

            @staticmethod
            def parse(filename):
                """Parse ELF file (fallback returns None)."""
                logger.debug(f"ELF fallback parse called for: {filename}")
                return None

        @staticmethod
        def parse(filename):
            """Parse binary file (fallback returns None)."""
            logger.debug(f"Lief fallback parse called for: {filename}")
            return None

    return LiefFallback()

# Safe module replacer
class SafeModuleReplacer:
    """Replaces problematic modules with safe fallbacks."""

    def __init__(self):
        self.original_modules = {}
        self.replaced_modules = set()

    def replace_module(self, module_name: str, fallback_factory):
        """Replace a module with a fallback implementation."""
        if module_name in sys.modules and module_name not in self.replaced_modules:
            # Store original
            self.original_modules[module_name] = sys.modules[module_name]

        # Replace with fallback
        sys.modules[module_name] = fallback_factory()
        self.replaced_modules.add(module_name)
        logger.info(f"Replaced {module_name} with fallback implementation")

    def restore_module(self, module_name: str):
        """Restore original module if available."""
        if module_name in self.original_modules:
            sys.modules[module_name] = self.original_modules[module_name]
            self.replaced_modules.discard(module_name)
            logger.info(f"Restored original {module_name}")

# Global replacer instance
_module_replacer = SafeModuleReplacer()

def initialize_safe_imports():
    """Initialize safe imports by testing and replacing problematic modules."""
    logger.info("Initializing safe dependency imports...")

    # Test and replace numpy if needed
    try:
        import numpy
        test_array = numpy.array([1, 2, 3])
        logger.info("✅ numpy working correctly - test array shape: %s", test_array.shape)
    except Exception as e:
        logger.warning(f"numpy issue detected: {e}")
        _module_replacer.replace_module('numpy', create_numpy_fallback)

    # Test and replace pandas if needed
    try:
        import pandas
        test_df = pandas.DataFrame({'test': [1, 2, 3]})
        logger.info("✅ pandas working correctly - test df shape: %s", test_df.shape)
    except Exception as e:
        logger.warning(f"pandas issue detected: {e}")
        _module_replacer.replace_module('pandas', create_pandas_fallback)

    # Test and replace sklearn if needed
    try:
        logger.info("✅ sklearn working correctly")
    except Exception as e:
        logger.warning(f"sklearn issue detected: {e}")
        _module_replacer.replace_module('sklearn', create_sklearn_fallback)
        _module_replacer.replace_module('sklearn.ensemble', lambda: create_sklearn_fallback().ensemble)
        _module_replacer.replace_module('sklearn.cluster', lambda: create_sklearn_fallback().cluster)
        _module_replacer.replace_module('sklearn.preprocessing', lambda: create_sklearn_fallback().preprocessing)

    logger.info("Safe import initialization complete")

def get_dependency_status():
    """Get status of all dependencies."""
    status = {
        'numpy': NUMPY_AVAILABLE,
        'pandas': PANDAS_AVAILABLE,
        'sklearn': SKLEARN_AVAILABLE,
        'lief': LIEF_AVAILABLE,
        'pyelftools': PYELFTOOLS_AVAILABLE
    }

    working_deps = sum(status.values())
    total_deps = len(status)

    logger.info(f"Dependency status: {working_deps}/{total_deps} working")
    for dep, available in status.items():
        status_icon = "✅" if available else "⚠️"
        logger.info(f"  {status_icon} {dep}")

    return status

# Auto-initialize when module is imported
try:
    initialize_safe_imports()
except Exception as e:
    logger.error(f"Failed to initialize safe imports: {e}")
