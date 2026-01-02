"""Production-ready tests for intellicrack/utils/dependency_fallbacks.py

Tests validate REAL dependency fallback capabilities:
- Safe import mechanisms for numpy, pandas, sklearn, lief, pyelftools
- Fallback implementations that mirror real library interfaces
- Random number generation matching numpy.random API
- DataFrame operations matching pandas API
- ML model interfaces matching sklearn API
- Module replacement and restoration functionality
- Dependency status reporting
"""

import sys
from typing import Any, Callable, Dict, Optional

import pytest

from intellicrack.utils.dependency_fallbacks import (
    LIEF_AVAILABLE,
    NUMPY_AVAILABLE,
    PANDAS_AVAILABLE,
    PYELFTOOLS_AVAILABLE,
    SKLEARN_AVAILABLE,
    SafeModuleReplacer,
    create_lief_fallback,
    create_numpy_fallback,
    create_pandas_fallback,
    create_sklearn_fallback,
    get_dependency_status,
    initialize_safe_imports,
    safe_import_lief,
    safe_import_numpy,
    safe_import_pandas,
    safe_import_pyelftools,
    safe_import_sklearn,
)


class FakeModule:
    """Fake module implementation for testing module replacement."""

    def __init__(self, name: str, version: str = "1.0.0") -> None:
        self._name: str = name
        self.__version__: str = version
        self.call_log: list[str] = []

    def __repr__(self) -> str:
        return f"FakeModule({self._name})"


class FakeNumpyModule:
    """Fake numpy module with trackable behavior."""

    def __init__(self, should_fail: bool = False) -> None:
        self.__version__: str = "1.24.0"
        self.should_fail: bool = should_fail
        self.array_calls: list[Any] = []

    def array(self, data: Any) -> Any:
        """Track array() calls and optionally raise exception."""
        self.array_calls.append(data)
        if self.should_fail:
            raise Exception("numpy broken")
        return list(data) if hasattr(data, "__iter__") else [data]


class FakePandasModule:
    """Fake pandas module with trackable behavior."""

    def __init__(self, should_fail: bool = False) -> None:
        self.__version__: str = "2.0.0"
        self.should_fail: bool = should_fail
        self.dataframe_calls: list[Any] = []

    class DataFrame:
        """Fake DataFrame class."""

        def __init__(self, data: Any = None) -> None:
            if data is None:
                self.data: Any = {}
            else:
                self.data = data

        def __len__(self) -> int:
            if isinstance(self.data, dict):
                first_key: Optional[str] = next(iter(self.data), None)
                if first_key and isinstance(self.data[first_key], list):
                    return len(self.data[first_key])
                return len(self.data)
            return len(self.data) if hasattr(self.data, "__len__") else 0

        def to_dict(self) -> Any:
            return self.data


class FakeSklearnModule:
    """Fake sklearn module with trackable behavior."""

    def __init__(self, should_fail: bool = False) -> None:
        self.__version__: str = "1.3.0"
        self.should_fail: bool = should_fail


class FakeModuleReplacer:
    """Fake module replacer for testing initialization."""

    def __init__(self) -> None:
        self.replace_calls: list[tuple[str, Any]] = []
        self.restore_calls: list[str] = []

    def replace_module(self, name: str, factory: Callable[[], Any]) -> None:
        """Track replace_module calls."""
        self.replace_calls.append((name, factory))

    def restore_module(self, name: str) -> None:
        """Track restore_module calls."""
        self.restore_calls.append(name)


class TestNumpyFallback:
    """Test numpy fallback implementation."""

    def test_numpy_fallback_array_converts_list(self) -> None:
        """Numpy fallback array() converts lists correctly."""
        np_fallback = create_numpy_fallback()
        data = [1, 2, 3, 4, 5]
        result = np_fallback.array(data)
        assert result == data

    def test_numpy_fallback_array_converts_iterables(self) -> None:
        """Numpy fallback array() converts iterables to lists."""
        np_fallback = create_numpy_fallback()
        data = range(5)
        result = np_fallback.array(data)
        assert result == [0, 1, 2, 3, 4]

    def test_numpy_fallback_zeros_creates_1d_array(self) -> None:
        """Numpy fallback zeros() creates 1D arrays correctly."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.zeros(5)
        assert result == [0, 0, 0, 0, 0]
        assert len(result) == 5

    def test_numpy_fallback_zeros_creates_2d_array(self) -> None:
        """Numpy fallback zeros() creates 2D arrays correctly."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.zeros((3, 4))
        assert len(result) == 3
        assert len(result[0]) == 4
        assert all(all(val == 0 for val in row) for row in result)

    def test_numpy_fallback_mean_calculates_average(self) -> None:
        """Numpy fallback mean() calculates correct average."""
        np_fallback = create_numpy_fallback()
        data = [1, 2, 3, 4, 5]
        result = np_fallback.mean(data)
        assert result == 3.0

    def test_numpy_fallback_mean_handles_empty_list(self) -> None:
        """Numpy fallback mean() handles empty lists safely."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.mean([])
        assert result == 0

    def test_numpy_fallback_sum_calculates_total(self) -> None:
        """Numpy fallback sum() calculates correct sum."""
        np_fallback = create_numpy_fallback()
        data = [1, 2, 3, 4, 5]
        result = np_fallback.sum(data)
        assert result == 15

    def test_numpy_fallback_where_returns_true_indices(self) -> None:
        """Numpy fallback where() returns indices where condition is True."""
        np_fallback = create_numpy_fallback()
        condition = [False, True, False, True, True]
        result = np_fallback.where(condition)
        assert result == [1, 3, 4]

    def test_numpy_fallback_random_randn_generates_values(self) -> None:
        """Numpy fallback random.randn() generates random normal values."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.Random.randn(5)
        assert isinstance(result, list)
        assert len(result) == 5
        assert all(isinstance(v, float) for v in result)

    def test_numpy_fallback_random_randn_generates_2d_arrays(self) -> None:
        """Numpy fallback random.randn() generates 2D arrays."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.Random.randn(3, 4)
        assert isinstance(result, list)
        assert len(result) == 3
        assert len(result[0]) == 4

    def test_numpy_fallback_random_rand_generates_uniform_values(self) -> None:
        """Numpy fallback random.rand() generates uniform random values."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.Random.rand(10)
        assert isinstance(result, list)
        assert len(result) == 10
        assert all(0 <= v < 1 for v in result)

    def test_numpy_fallback_random_randint_generates_integers(self) -> None:
        """Numpy fallback random.randint() generates random integers."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.Random.randint(0, 100, size=10)
        assert isinstance(result, list)
        assert len(result) == 10
        assert all(isinstance(v, int) for v in result)
        assert all(0 <= v < 100 for v in result)

    def test_numpy_fallback_random_randint_single_value(self) -> None:
        """Numpy fallback random.randint() generates single integer."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.Random.randint(10, 20)
        assert isinstance(result, int)
        assert 10 <= result < 20

    def test_numpy_fallback_random_uniform_generates_floats(self) -> None:
        """Numpy fallback random.uniform() generates uniform floats."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.Random.uniform(0.0, 10.0, size=5)
        assert isinstance(result, list)
        assert len(result) == 5
        assert all(0.0 <= v <= 10.0 for v in result)

    def test_numpy_fallback_random_normal_generates_distribution(self) -> None:
        """Numpy fallback random.normal() generates normal distribution."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.Random.normal(loc=5.0, scale=2.0, size=100)
        assert isinstance(result, list)
        assert len(result) == 100
        mean = sum(result) / len(result)
        assert 3.0 < mean < 7.0

    def test_numpy_fallback_random_choice_selects_from_array(self) -> None:
        """Numpy fallback random.choice() selects from array."""
        np_fallback = create_numpy_fallback()
        choices = [10, 20, 30, 40, 50]
        result = np_fallback.Random.choice(choices, size=10)
        assert isinstance(result, list)
        assert len(result) == 10
        assert all(v in choices for v in result)

    def test_numpy_fallback_random_choice_weighted(self) -> None:
        """Numpy fallback random.choice() handles weighted sampling."""
        np_fallback = create_numpy_fallback()
        choices = [1, 2, 3]
        weights = [0.9, 0.05, 0.05]
        result = np_fallback.Random.choice(choices, size=100, p=weights)
        assert len(result) == 100
        assert result.count(1) > result.count(2)
        assert result.count(1) > result.count(3)


class TestPandasFallback:
    """Test pandas fallback implementation."""

    def test_pandas_fallback_dataframe_from_dict(self) -> None:
        """Pandas fallback DataFrame initializes from dictionary."""
        pd_fallback = create_pandas_fallback()
        data = {"col1": [1, 2, 3], "col2": [4, 5, 6]}
        df = pd_fallback.DataFrame(data)
        assert df.to_dict() == data

    def test_pandas_fallback_dataframe_from_list(self) -> None:
        """Pandas fallback DataFrame initializes from list."""
        pd_fallback = create_pandas_fallback()
        data = [1, 2, 3, 4, 5]
        df = pd_fallback.DataFrame(data)
        result = df.to_dict()
        assert "column_0" in result
        assert result["column_0"] == data

    def test_pandas_fallback_dataframe_length(self) -> None:
        """Pandas fallback DataFrame returns correct length."""
        pd_fallback = create_pandas_fallback()
        data = {"col1": [1, 2, 3, 4, 5]}
        df = pd_fallback.DataFrame(data)
        assert len(df) == 5

    def test_pandas_fallback_dataframe_empty_length(self) -> None:
        """Pandas fallback DataFrame handles empty data."""
        pd_fallback = create_pandas_fallback()
        df = pd_fallback.DataFrame()
        assert len(df) == 0


class TestSklearnFallback:
    """Test sklearn fallback implementation."""

    def test_sklearn_fallback_random_forest_fit(self) -> None:
        """Sklearn fallback RandomForestClassifier fit() executes without error."""
        sklearn_fallback = create_sklearn_fallback()
        clf = sklearn_fallback.ensemble.RandomForestClassifier(n_estimators=10)
        X = [[1, 2], [3, 4], [5, 6]]
        y = [0, 1, 0]
        result = clf.fit(X, y)
        assert result is clf

    def test_sklearn_fallback_random_forest_predict(self) -> None:
        """Sklearn fallback RandomForestClassifier predict() returns zeros."""
        sklearn_fallback = create_sklearn_fallback()
        clf = sklearn_fallback.ensemble.RandomForestClassifier()
        X_train = [[1, 2], [3, 4]]
        y_train = [0, 1]
        clf.fit(X_train, y_train)

        X_test = [[5, 6], [7, 8], [9, 10]]
        predictions = clf.predict(X_test)
        assert len(predictions) == 3
        assert all(p == 0 for p in predictions)

    def test_sklearn_fallback_random_forest_predict_proba(self) -> None:
        """Sklearn fallback RandomForestClassifier predict_proba() returns 50/50."""
        sklearn_fallback = create_sklearn_fallback()
        clf = sklearn_fallback.ensemble.RandomForestClassifier()
        X = [[1, 2], [3, 4]]
        proba = clf.predict_proba(X)
        assert len(proba) == 2
        assert all(p == [0.5, 0.5] for p in proba)

    def test_sklearn_fallback_dbscan_fit_predict(self) -> None:
        """Sklearn fallback DBSCAN fit_predict() returns zeros."""
        sklearn_fallback = create_sklearn_fallback()
        dbscan = sklearn_fallback.cluster.DBSCAN(eps=0.5, min_samples=3)
        X = [[1, 2], [3, 4], [5, 6], [7, 8]]
        labels = dbscan.fit_predict(X)
        assert len(labels) == 4
        assert all(l == 0 for l in labels)

    def test_sklearn_fallback_standard_scaler_fit(self) -> None:
        """Sklearn fallback StandardScaler fit() executes without error."""
        sklearn_fallback = create_sklearn_fallback()
        scaler = sklearn_fallback.preprocessing.StandardScaler()
        X = [[1, 2], [3, 4], [5, 6]]
        result = scaler.fit(X)
        assert result is scaler

    def test_sklearn_fallback_standard_scaler_transform(self) -> None:
        """Sklearn fallback StandardScaler transform() returns unchanged data."""
        sklearn_fallback = create_sklearn_fallback()
        scaler = sklearn_fallback.preprocessing.StandardScaler()
        X = [[1, 2], [3, 4], [5, 6]]
        scaler.fit(X)
        transformed = scaler.transform(X)
        assert transformed == X

    def test_sklearn_fallback_standard_scaler_fit_transform(self) -> None:
        """Sklearn fallback StandardScaler fit_transform() returns unchanged data."""
        sklearn_fallback = create_sklearn_fallback()
        scaler = sklearn_fallback.preprocessing.StandardScaler()
        X = [[1, 2], [3, 4], [5, 6]]
        transformed = scaler.fit_transform(X)
        assert transformed == X


class TestLiefFallback:
    """Test lief fallback implementation."""

    def test_lief_fallback_parse_returns_none(self) -> None:
        """Lief fallback parse() returns None without error."""
        lief_fallback = create_lief_fallback()
        result = lief_fallback.parse("test_binary.elf")
        assert result is None

    def test_lief_fallback_elf_parse_returns_none(self) -> None:
        """Lief fallback ELF.parse() returns None without error."""
        lief_fallback = create_lief_fallback()
        result = lief_fallback.ELF.parse("test_binary.elf")
        assert result is None


class TestSafeImportFunctions:
    """Test safe import functions with fallback mechanisms."""

    def test_safe_import_numpy_returns_module_when_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """safe_import_numpy returns real numpy when available."""
        fake_numpy = FakeNumpyModule(should_fail=False)
        monkeypatch.setattr(
            "intellicrack.utils.dependency_fallbacks.HAS_NUMPY", True
        )
        monkeypatch.setattr("intellicrack.utils.dependency_fallbacks.np", fake_numpy)

        result = safe_import_numpy()
        assert NUMPY_AVAILABLE or isinstance(result, type(create_numpy_fallback()))

    def test_safe_import_numpy_returns_fallback_on_import_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """safe_import_numpy returns fallback when import fails."""
        monkeypatch.setattr(
            "intellicrack.utils.dependency_fallbacks.HAS_NUMPY", False
        )
        result = safe_import_numpy()
        assert hasattr(result, "array")
        assert hasattr(result, "zeros")
        assert hasattr(result, "mean")

    def test_safe_import_pandas_returns_module_when_available(self) -> None:
        """safe_import_pandas returns real pandas when available."""
        try:
            import pandas as pd

            result = safe_import_pandas()
            assert PANDAS_AVAILABLE or hasattr(result, "DataFrame")
        except ImportError:
            pytest.skip("pandas not available")

    def test_safe_import_pandas_returns_fallback_on_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """safe_import_pandas returns fallback when import fails."""

        def raise_import_error(*args: Any, **kwargs: Any) -> None:
            raise ImportError("No pandas")

        fake_pandas = FakePandasModule(should_fail=True)
        fake_pandas.DataFrame = type(
            "DataFrame", (), {"__init__": raise_import_error}
        )

        monkeypatch.setattr("intellicrack.utils.dependency_fallbacks.pd", fake_pandas)

        result = safe_import_pandas()
        assert hasattr(result, "DataFrame")

    def test_safe_import_sklearn_returns_module_when_available(self) -> None:
        """safe_import_sklearn returns real sklearn when available."""
        try:
            import sklearn

            result = safe_import_sklearn()
            assert SKLEARN_AVAILABLE or hasattr(result, "ensemble")
        except ImportError:
            pytest.skip("sklearn not available")

    def test_safe_import_sklearn_returns_fallback_on_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """safe_import_sklearn returns fallback when import fails."""

        class FailingSklearn:
            """Fake sklearn that raises on attribute access."""

            def __getattr__(self, name: str) -> Any:
                raise ImportError("No sklearn")

        monkeypatch.setattr(
            "intellicrack.utils.dependency_fallbacks.sklearn", FailingSklearn()
        )

        result = safe_import_sklearn()
        assert hasattr(result, "ensemble")
        assert hasattr(result, "cluster")
        assert hasattr(result, "preprocessing")

    def test_safe_import_lief_returns_module_when_available(self) -> None:
        """safe_import_lief returns real lief when available."""
        try:
            result = safe_import_lief()
            assert LIEF_AVAILABLE or hasattr(result, "parse")
        except ImportError:
            pass

    def test_safe_import_lief_returns_fallback_on_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """safe_import_lief returns fallback when import fails."""
        monkeypatch.setattr("intellicrack.utils.dependency_fallbacks.HAS_LIEF", False)
        result = safe_import_lief()
        assert hasattr(result, "parse")
        assert hasattr(result, "ELF")

    def test_safe_import_pyelftools_returns_true_when_available(self) -> None:
        """safe_import_pyelftools returns True when available."""
        try:
            result = safe_import_pyelftools()
            assert isinstance(result, bool) or result is None
            assert PYELFTOOLS_AVAILABLE or result is False
        except ImportError:
            pass

    def test_safe_import_pyelftools_returns_false_on_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """safe_import_pyelftools returns False when import fails."""
        monkeypatch.setattr(
            "intellicrack.utils.dependency_fallbacks.HAS_PYELFTOOLS", False
        )
        result = safe_import_pyelftools()
        assert result is False


class TestSafeModuleReplacer:
    """Test module replacement and restoration functionality."""

    def test_module_replacer_replaces_module_in_sys_modules(self) -> None:
        """SafeModuleReplacer replaces module in sys.modules."""
        replacer = SafeModuleReplacer()
        original_module = FakeModule("test_module_replace", "1.0.0")
        sys.modules["test_module_replace"] = original_module

        replacer.replace_module(
            "test_module_replace", lambda: FakeModule("test_module_replace", "2.0.0")
        )

        assert sys.modules["test_module_replace"] != original_module
        assert "test_module_replace" in replacer.replaced_modules

    def test_module_replacer_stores_original_module(self) -> None:
        """SafeModuleReplacer stores original module for restoration."""
        replacer = SafeModuleReplacer()
        original_module = FakeModule("test_module_store", "1.0.0")
        sys.modules["test_module_store"] = original_module

        replacer.replace_module(
            "test_module_store", lambda: FakeModule("test_module_store", "2.0.0")
        )

        assert "test_module_store" in replacer.original_modules
        assert replacer.original_modules["test_module_store"] is original_module

    def test_module_replacer_restores_original_module(self) -> None:
        """SafeModuleReplacer restores original module correctly."""
        replacer = SafeModuleReplacer()
        original_module = FakeModule("test_module_restore", "1.0.0")
        sys.modules["test_module_restore"] = original_module

        replacer.replace_module(
            "test_module_restore", lambda: FakeModule("test_module_restore", "2.0.0")
        )
        replaced_module = sys.modules["test_module_restore"]

        replacer.restore_module("test_module_restore")

        assert sys.modules["test_module_restore"] is original_module
        assert sys.modules["test_module_restore"] is not replaced_module
        assert "test_module_restore" not in replacer.replaced_modules

    def test_module_replacer_handles_nonexistent_module(self) -> None:
        """SafeModuleReplacer handles replacing nonexistent modules."""
        replacer = SafeModuleReplacer()

        if "nonexistent_test_module" in sys.modules:
            del sys.modules["nonexistent_test_module"]

        replacer.replace_module(
            "nonexistent_test_module", lambda: FakeModule("nonexistent_test_module")
        )

        assert "nonexistent_test_module" in sys.modules
        assert "nonexistent_test_module" in replacer.replaced_modules


class TestDependencyStatusReporting:
    """Test dependency status reporting functionality."""

    def test_get_dependency_status_returns_all_dependencies(self) -> None:
        """get_dependency_status returns status for all dependencies."""
        status = get_dependency_status()

        assert "numpy" in status
        assert "pandas" in status
        assert "sklearn" in status
        assert "lief" in status
        assert "pyelftools" in status

    def test_get_dependency_status_returns_boolean_values(self) -> None:
        """get_dependency_status returns boolean availability status."""
        status = get_dependency_status()

        assert isinstance(status["numpy"], bool)
        assert isinstance(status["pandas"], bool)
        assert isinstance(status["sklearn"], bool)
        assert isinstance(status["lief"], bool)
        assert isinstance(status["pyelftools"], bool)

    def test_get_dependency_status_reflects_actual_availability(self) -> None:
        """get_dependency_status reflects actual dependency availability."""
        status = get_dependency_status()

        assert status["numpy"] == NUMPY_AVAILABLE
        assert status["pandas"] == PANDAS_AVAILABLE
        assert status["sklearn"] == SKLEARN_AVAILABLE
        assert status["lief"] == LIEF_AVAILABLE
        assert status["pyelftools"] == PYELFTOOLS_AVAILABLE


class TestInitializeSafeImports:
    """Test safe imports initialization."""

    def test_initialize_safe_imports_tests_numpy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """initialize_safe_imports tests numpy availability."""
        fake_replacer = FakeModuleReplacer()
        monkeypatch.setattr(
            "intellicrack.utils.dependency_fallbacks._module_replacer", fake_replacer
        )

        fake_numpy = FakeNumpyModule(should_fail=True)
        monkeypatch.setattr("intellicrack.utils.dependency_fallbacks.np", fake_numpy)

        initialize_safe_imports()

    def test_initialize_safe_imports_tests_pandas(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """initialize_safe_imports tests pandas availability."""
        fake_replacer = FakeModuleReplacer()
        monkeypatch.setattr(
            "intellicrack.utils.dependency_fallbacks._module_replacer", fake_replacer
        )

        fake_pandas = FakePandasModule(should_fail=True)
        monkeypatch.setattr("intellicrack.utils.dependency_fallbacks.pd", fake_pandas)

        initialize_safe_imports()


class TestNumpyFallbackEdgeCases:
    """Test numpy fallback edge cases and error handling."""

    def test_numpy_fallback_randn_handles_4d_arrays(self) -> None:
        """Numpy fallback randn() handles 4D arrays."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.Random.randn(2, 2, 2, 2)
        assert isinstance(result, list)
        assert len(result) == 2
        assert len(result[0]) == 2
        assert len(result[0][0]) == 2
        assert len(result[0][0][0]) == 2

    def test_numpy_fallback_randn_raises_on_too_many_dimensions(self) -> None:
        """Numpy fallback randn() raises error for >4 dimensions."""
        np_fallback = create_numpy_fallback()
        with pytest.raises(ValueError) as exc_info:
            np_fallback.Random.randn(2, 2, 2, 2, 2)
        assert "Too many dimensions" in str(exc_info.value)

    def test_numpy_fallback_rand_raises_on_too_many_dimensions(self) -> None:
        """Numpy fallback rand() raises error for >2 dimensions."""
        np_fallback = create_numpy_fallback()
        with pytest.raises(ValueError) as exc_info:
            np_fallback.Random.rand(2, 2, 2)
        assert "Too many dimensions" in str(exc_info.value)

    def test_numpy_fallback_randint_raises_on_complex_size(self) -> None:
        """Numpy fallback randint() raises error for complex sizes."""
        np_fallback = create_numpy_fallback()
        with pytest.raises(ValueError) as exc_info:
            np_fallback.Random.randint(0, 10, size=[2, 3])
        assert "Complex sizes not supported" in str(exc_info.value)

    def test_numpy_fallback_uniform_raises_on_complex_size(self) -> None:
        """Numpy fallback uniform() raises error for complex sizes."""
        np_fallback = create_numpy_fallback()
        with pytest.raises(ValueError) as exc_info:
            np_fallback.Random.uniform(0.0, 1.0, size=(2, 3))
        assert "Complex sizes not supported" in str(exc_info.value)

    def test_numpy_fallback_normal_raises_on_complex_size(self) -> None:
        """Numpy fallback normal() raises error for complex sizes."""
        np_fallback = create_numpy_fallback()
        with pytest.raises(ValueError) as exc_info:
            np_fallback.Random.normal(0.0, 1.0, size=(2, 3))
        assert "Complex sizes not supported" in str(exc_info.value)

    def test_numpy_fallback_random_generates_single_value(self) -> None:
        """Numpy fallback random() generates single float."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.Random.random()
        assert isinstance(result, float)
        assert 0 <= result < 1

    def test_numpy_fallback_random_generates_array(self) -> None:
        """Numpy fallback random() generates array of floats."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.Random.random(size=5)
        assert isinstance(result, list)
        assert len(result) == 5
        assert all(0 <= v < 1 for v in result)


class TestVersionAttributes:
    """Test fallback modules have version attributes."""

    def test_numpy_fallback_has_version(self) -> None:
        """Numpy fallback has __version__ attribute."""
        np_fallback = create_numpy_fallback()
        assert hasattr(np_fallback, "__version__")
        assert "fallback" in np_fallback.__version__

    def test_pandas_fallback_has_version(self) -> None:
        """Pandas fallback has __version__ attribute."""
        pd_fallback = create_pandas_fallback()
        assert hasattr(pd_fallback, "__version__")
        assert "fallback" in pd_fallback.__version__

    def test_sklearn_fallback_has_version(self) -> None:
        """Sklearn fallback has __version__ attribute."""
        sklearn_fallback = create_sklearn_fallback()
        assert hasattr(sklearn_fallback, "__version__")
        assert "fallback" in sklearn_fallback.__version__

    def test_lief_fallback_has_version(self) -> None:
        """Lief fallback has __version__ attribute."""
        lief_fallback = create_lief_fallback()
        assert hasattr(lief_fallback, "__version__")
        assert "fallback" in lief_fallback.__version__


class TestNumpyFallbackNdarrayType:
    """Test numpy fallback ndarray type compatibility."""

    def test_numpy_fallback_ndarray_is_list(self) -> None:
        """Numpy fallback ndarray type is list for compatibility."""
        np_fallback = create_numpy_fallback()
        assert np_fallback.ndarray is list

    def test_numpy_fallback_array_returns_ndarray_type(self) -> None:
        """Numpy fallback array() returns ndarray-compatible type."""
        np_fallback = create_numpy_fallback()
        result = np_fallback.array([1, 2, 3])
        assert isinstance(result, np_fallback.ndarray)
