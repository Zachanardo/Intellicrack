"""
Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ImportChecker:
    """
    Utility class for checking and managing optional imports.
    """

    def __init__(self):
        """Initialize the import checker with empty caches."""
        self._import_cache = {}
        self._failed_imports = set()

    def check_import(self, module_name: str, package_name: Optional[str] = None) -> bool:
        """
        Check if a module can be imported.

        Args:
            module_name: Name of the module to import
            package_name: Optional package name for relative imports

        Returns:
            True if module can be imported, False otherwise
        """
        cache_key = f"{package_name}.{module_name}" if package_name else module_name

        if cache_key in self._import_cache:
            return self._import_cache[cache_key]

        if cache_key in self._failed_imports:
            return False

        try:
            if package_name:
                __import__(f"{package_name}.{module_name}")
            else:
                __import__(module_name)

            self._import_cache[cache_key] = True
            return True

        except (ImportError, ModuleNotFoundError) as e:
            logger.debug(f"Import check failed for {cache_key}: {e}")
            self._failed_imports.add(cache_key)
            self._import_cache[cache_key] = False
            return False

    def safe_import(self, module_name: str,
                   fallback: Optional[Any] = None,
                   package_name: Optional[str] = None) -> Tuple[bool, Any]:
        """
        Safely import a module with fallback.

        Args:
            module_name: Name of the module to import
            fallback: Fallback value if import fails
            package_name: Optional package name

        Returns:
            Tuple of (success, module_or_fallback)
        """
        try:
            if package_name:
                module = __import__(f"{package_name}.{module_name}", fromlist=[module_name])
            else:
                module = __import__(module_name)

            return True, module

        except (ImportError, ModuleNotFoundError) as e:
            logger.debug(f"Safe import failed for {module_name}: {e}")
            return False, fallback

    def get_available_imports(self, module_list: List[str]) -> Dict[str, bool]:
        """
        Check availability of multiple modules.

        Args:
            module_list: List of module names to check

        Returns:
            Dictionary mapping module names to availability
        """
        results = {}
        for module in module_list:
            results[module] = self.check_import(module)
        return results

    def clear_cache(self):
        """Clear the import cache."""
        self._import_cache.clear()
        self._failed_imports.clear()


# Global import checker instance
_import_checker = ImportChecker()

# Convenience functions using global instance
def check_import(module_name: str, package_name: Optional[str] = None) -> bool:
    """Check if a module can be imported."""
    return _import_checker.check_import(module_name, package_name)

def safe_import(module_name: str,
               fallback: Optional[Any] = None,
               package_name: Optional[str] = None) -> Tuple[bool, Any]:
    """Safely import a module with fallback."""
    return _import_checker.safe_import(module_name, fallback, package_name)

def get_available_imports(module_list: List[str]) -> Dict[str, bool]:
    """Check availability of multiple modules."""
    return _import_checker.get_available_imports(module_list)


# Common import checks for frequently used modules
NUMPY_AVAILABLE = check_import("numpy")
PANDAS_AVAILABLE = check_import("pandas")
SKLEARN_AVAILABLE = check_import("sklearn")
MATPLOTLIB_AVAILABLE = check_import("matplotlib")
PILLOW_AVAILABLE = check_import("PIL")
REQUESTS_AVAILABLE = check_import("requests")
PSUTIL_AVAILABLE = check_import("psutil")
LIEF_AVAILABLE = check_import("lief")
PEFILE_AVAILABLE = check_import("pefile")
CAPSTONE_AVAILABLE = check_import("capstone")
UNICORN_AVAILABLE = check_import("unicorn")
ANGR_AVAILABLE = check_import("angr")
RADARE2_AVAILABLE = check_import("r2pipe")
GHIDRA_AVAILABLE = check_import("ghidra_bridge")
FRIDA_AVAILABLE = check_import("frida")
SCAPY_AVAILABLE = check_import("scapy")
TENSORFLOW_AVAILABLE = check_import("tensorflow")
TORCH_AVAILABLE = check_import("torch")
KERAS_AVAILABLE = check_import("keras")

# PyQt availability check
PYQT5_AVAILABLE = check_import("PyQt5")
PYQT6_AVAILABLE = check_import("PyQt6")
PYSIDE2_AVAILABLE = check_import("PySide2")
PYSIDE6_AVAILABLE = check_import("PySide6")

# Determine which Qt library is available
QT_AVAILABLE = any([PYQT5_AVAILABLE, PYQT6_AVAILABLE, PYSIDE2_AVAILABLE, PYSIDE6_AVAILABLE])
PREFERRED_QT = None
if PYQT6_AVAILABLE:
    PREFERRED_QT = "PyQt6"
elif PYQT5_AVAILABLE:
    PREFERRED_QT = "PyQt5"
elif PYSIDE6_AVAILABLE:
    PREFERRED_QT = "PySide6"
elif PYSIDE2_AVAILABLE:
    PREFERRED_QT = "PySide2"

# Cryptography libraries
CRYPTODOME_AVAILABLE = check_import("Cryptodome")
CRYPTOGRAPHY_AVAILABLE = check_import("cryptography")
CRYPTO_AVAILABLE = CRYPTODOME_AVAILABLE or CRYPTOGRAPHY_AVAILABLE

# Network libraries
SOCKET_AVAILABLE = check_import("socket")
SSL_AVAILABLE = check_import("ssl")
HTTP_CLIENT_AVAILABLE = check_import("http.client")

# System libraries
OS_AVAILABLE = check_import("os")
SYS_AVAILABLE = check_import("sys")
SUBPROCESS_AVAILABLE = check_import("subprocess")
THREADING_AVAILABLE = check_import("threading")
MULTIPROCESSING_AVAILABLE = check_import("multiprocessing")

# Specialized security libraries
VOLATILITY_AVAILABLE = check_import("volatility")
VOLATILITY3_AVAILABLE = check_import("volatility3")
BINWALK_AVAILABLE = check_import("binwalk")
YARA_AVAILABLE = check_import("yara")
YARA_PYTHON_AVAILABLE = check_import("yara")  # yara-python installs as 'yara'
PYNACL_AVAILABLE = check_import("nacl")

# Database libraries
SQLITE3_AVAILABLE = check_import("sqlite3")
SQLALCHEMY_AVAILABLE = check_import("sqlalchemy")

# Compression libraries
ZLIB_AVAILABLE = check_import("zlib")
GZIP_AVAILABLE = check_import("gzip")
BROTLI_AVAILABLE = check_import("brotli")

# Data format libraries
JSON_AVAILABLE = check_import("json")
YAML_AVAILABLE = check_import("yaml")
XML_AVAILABLE = check_import("xml")
TOML_AVAILABLE = check_import("toml")

# Virtualization and emulation
QEMU_AVAILABLE = check_import("qemu")
DOCKER_AVAILABLE = check_import("docker")
VIRTUALBOX_AVAILABLE = check_import("virtualbox")


def get_import_summary() -> Dict[str, Any]:
    """
    Get a summary of all import availability checks.

    Returns:
        Dictionary with categorized import availability
    """
    return {
        "data_science": {
            "numpy": NUMPY_AVAILABLE,
            "pandas": PANDAS_AVAILABLE,
            "sklearn": SKLEARN_AVAILABLE,
            "matplotlib": MATPLOTLIB_AVAILABLE
        },
        "machine_learning": {
            "tensorflow": TENSORFLOW_AVAILABLE,
            "torch": TORCH_AVAILABLE,
            "keras": KERAS_AVAILABLE
        },
        "gui_frameworks": {
            "pyqt5": PYQT5_AVAILABLE,
            "pyqt6": PYQT6_AVAILABLE,
            "pyside2": PYSIDE2_AVAILABLE,
            "pyside6": PYSIDE6_AVAILABLE,
            "preferred_qt": PREFERRED_QT
        },
        "security_tools": {
            "lief": LIEF_AVAILABLE,
            "pefile": PEFILE_AVAILABLE,
            "capstone": CAPSTONE_AVAILABLE,
            "unicorn": UNICORN_AVAILABLE,
            "angr": ANGR_AVAILABLE,
            "radare2": RADARE2_AVAILABLE,
            "ghidra": GHIDRA_AVAILABLE,
            "frida": FRIDA_AVAILABLE,
            "yara": YARA_AVAILABLE,
            "yara_python": YARA_PYTHON_AVAILABLE,
            "volatility": VOLATILITY_AVAILABLE,
            "volatility3": VOLATILITY3_AVAILABLE,
            "binwalk": BINWALK_AVAILABLE
        },
        "cryptography": {
            "cryptodome": CRYPTODOME_AVAILABLE,
            "cryptography": CRYPTOGRAPHY_AVAILABLE,
            "pynacl": PYNACL_AVAILABLE,
            "crypto_available": CRYPTO_AVAILABLE
        },
        "network": {
            "scapy": SCAPY_AVAILABLE,
            "requests": REQUESTS_AVAILABLE,
            "socket": SOCKET_AVAILABLE,
            "ssl": SSL_AVAILABLE,
            "http_client": HTTP_CLIENT_AVAILABLE
        },
        "system": {
            "psutil": PSUTIL_AVAILABLE,
            "os": OS_AVAILABLE,
            "sys": SYS_AVAILABLE,
            "subprocess": SUBPROCESS_AVAILABLE,
            "threading": THREADING_AVAILABLE,
            "multiprocessing": MULTIPROCESSING_AVAILABLE
        },
        "data_formats": {
            "json": JSON_AVAILABLE,
            "yaml": YAML_AVAILABLE,
            "xml": XML_AVAILABLE,
            "toml": TOML_AVAILABLE
        },
        "virtualization": {
            "docker": DOCKER_AVAILABLE,
            "qemu": QEMU_AVAILABLE,
            "virtualbox": VIRTUALBOX_AVAILABLE
        }
    }


def check_required_imports(required_modules: List[str]) -> Tuple[bool, List[str]]:
    """
    Check if all required modules are available.

    Args:
        required_modules: List of required module names

    Returns:
        Tuple of (all_available, missing_modules)
    """
    missing = []
    for module in required_modules:
        if not check_import(module):
            missing.append(module)

    return len(missing) == 0, missing


def get_fallback_implementations() -> Dict[str, Any]:
    """
    Get fallback implementations for common missing modules.

    Returns:
        Dictionary of fallback implementations
    """
    fallbacks = {}

    # Simple numpy-like operations
    if not NUMPY_AVAILABLE:
        class NumpyFallback:
            """Fallback numpy-like operations when numpy is not available."""
            # Define ndarray as the list type for compatibility
            ndarray = list

            class random:
                """Random number generation fallback."""
                @staticmethod
                def uniform(low, high):
                    """Generate uniform random value."""
                    import random
                    return random.uniform(low, high)  # noqa: S311

                @staticmethod
                def normal(loc=0.0, scale=1.0):
                    """Generate normal distribution value."""
                    import random
                    return random.gauss(loc, scale)

                @staticmethod
                def choice(a, p=None):
                    """Random choice from array."""
                    import random
                    if p is not None:
                        return random.choices(a, weights=p, k=1)[0]  # noqa: S311
                    return random.choice(a)  # noqa: S311
            @staticmethod
            def array(data):
                """Convert data to array-like structure."""
                return list(data) if hasattr(data, "__iter__") else [data]

            @staticmethod
            def mean(data):
                """Calculate mean of data."""
                return sum(data) / len(data) if data else 0

            @staticmethod
            def std(data):
                """Calculate standard deviation of data."""
                if not data:
                    return 0
                mean_val = sum(data) / len(data)
                variance = sum((x - mean_val) ** 2 for x in data) / len(data)
                return variance ** 0.5

        fallbacks["numpy"] = NumpyFallback()

    # Simple requests-like functionality
    if not REQUESTS_AVAILABLE:
        import urllib.parse
        import urllib.request

        class RequestsFallback:
            """Fallback HTTP requests implementation when requests module is not available."""
            @staticmethod
            def get(url, **kwargs):
                """Perform HTTP GET request using urllib."""
                logger.debug(f"Fallback HTTP GET to {url} with {len(kwargs)} kwargs: {list(kwargs.keys())}")
                try:
                    response = urllib.request.urlopen(url)
                    return type("Response", (), {
                        "status_code": response.getcode(),
                        "text": response.read().decode("utf-8"),
                        "content": response.read()
                    })()
                except Exception as e:
                    logger.error("Exception in import_checks: %s", e)
                    return type("Response", (), {
                        "status_code": 500,
                        "text": str(e),
                        "content": b""
                    })()

        fallbacks["requests"] = RequestsFallback()

    return fallbacks


def log_import_status():
    """Log the status of important imports."""
    summary = get_import_summary()

    logger.info("Import availability summary:")
    for category, modules in summary.items():
        available_count = sum(1 for v in modules.values() if v is True)
        total_count = len([v for v in modules.values() if isinstance(v, bool)])

        if total_count > 0:
            logger.info(f"  {category}: {available_count}/{total_count} available")

    # Log missing critical modules
    critical_modules = ["os", "sys", "json"]
    all_critical, missing_critical = check_required_imports(critical_modules)

    if not all_critical:
        logger.warning(f"Missing critical modules: {missing_critical}")
    else:
        logger.info("All critical modules available")


# Export commonly used functions and constants
__all__ = [
    "ImportChecker",
    "check_import",
    "safe_import",
    "get_available_imports",
    "get_import_summary",
    "check_required_imports",
    "get_fallback_implementations",
    "log_import_status",
    # Common availability flags
    "NUMPY_AVAILABLE",
    "PANDAS_AVAILABLE",
    "SKLEARN_AVAILABLE",
    "TENSORFLOW_AVAILABLE",
    "TORCH_AVAILABLE",
    "PYQT5_AVAILABLE",
    "PYQT6_AVAILABLE",
    "QT_AVAILABLE",
    "PREFERRED_QT",
    "LIEF_AVAILABLE",
    "PEFILE_AVAILABLE",
    "CAPSTONE_AVAILABLE",
    "UNICORN_AVAILABLE",
    "ANGR_AVAILABLE",
    "FRIDA_AVAILABLE",
    "SCAPY_AVAILABLE",
    "REQUESTS_AVAILABLE",
    "CRYPTO_AVAILABLE",
    "VOLATILITY3_AVAILABLE",
    "YARA_PYTHON_AVAILABLE",
    "BINWALK_AVAILABLE"
]
