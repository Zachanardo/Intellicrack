"""Intellicrack Protection Engine Backend Wrapper.

Provides native ICP Engine integration for comprehensive protection analysis.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

# Import ICP Engine backend with DLL path fix for Windows
import asyncio
import ctypes
import hashlib
import json
import mmap
import os
import platform
import sqlite3
import struct
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger


logger = get_logger(__name__)

SUPPLEMENTAL_ENGINES_AVAILABLE = False


def is_yara_available() -> bool:
    """Check if YARA engine is available.

    Returns:
        bool: True if YARA pattern analysis engine is available, False otherwise.

    """
    try:
        from ..core.analysis.yara_pattern_engine import is_yara_available as _is_yara_available

        return _is_yara_available()
    except ImportError:
        return False


def is_binwalk_available() -> bool:
    """Check if Binwalk engine is available.

    Returns:
        bool: True if Binwalk firmware analysis engine is available, False otherwise.

    """
    try:
        from ..core.analysis.firmware_analyzer import is_binwalk_available as _is_binwalk_available

        return _is_binwalk_available()
    except ImportError:
        return False


def is_volatility3_available() -> bool:
    """Check if Volatility3 engine is available.

    Returns:
        bool: True if Volatility3 memory forensics engine is available, False otherwise.

    """
    try:
        from ..core.analysis.memory_forensics_engine import is_volatility3_available as _is_volatility3_available

        return _is_volatility3_available()
    except ImportError:
        return False


_ICP_BACKEND_AVAILABLE = False
_ICP_BACKEND_VERSION = None
_icp_backend_module = None
_native_dll = None
_cache_lock = threading.Lock()
_result_cache: dict[str, Any] = {}
_cache_db_path: str | None = None

if platform.system() == "Windows":
    # Add potential DLL paths for ICP Engine on Windows
    from pathlib import Path

    import intellicrack

    intellicrack_root = Path(intellicrack.__file__).parent.parent
    dll_paths = [
        str(intellicrack_root / ".pixi" / "envs" / "default" / "Lib" / "site-packages" / "icp_engine"),
        str(intellicrack_root / ".pixi" / "envs" / "default" / "DLLs"),
        os.path.dirname(sys.executable),
    ]
    for path in dll_paths:
        if os.path.exists(path) and path not in os.environ.get("PATH", ""):
            os.environ["PATH"] = path + os.pathsep + os.environ.get("PATH", "")

try:
    # Skip icp_engine import during testing to avoid Windows fatal exceptions
    if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
        error_msg = "Skipping icp_engine import during testing"
        logger.error(error_msg)
        raise ImportError(error_msg)

    import icp_engine as _icp_module

    ICP_AVAILABLE = True
    ICP_VERSION = _icp_module.__version__
except (ImportError, OSError):
    # ICP Engine has known issues with certain Windows configurations
    # This is not critical for most protection detection functionality
    ICP_AVAILABLE = False
    ICP_VERSION = None
    _icp_module = None


class ScanMode(Enum):
    """ICP Engine scan modes for comprehensive protection analysis."""

    NORMAL = "normal"
    DEEP = "deep"
    HEURISTIC = "heuristic"
    AGGRESSIVE = "aggressive"
    ALL = "all"


@dataclass
class ICPDetection:
    """Single detection from ICP engine."""

    name: str
    type: str
    version: str = ""
    info: str = ""
    string: str = ""
    confidence: float = 1.0  # Default to 100% if not provided

    @classmethod
    def from_icp_result(cls, result: object) -> "ICPDetection":
        """Create ICPDetection from ICP Engine scan result.

        Args:
            result: ICP Engine detection result object.

        Returns:
            ICPDetection: Parsed detection object.

        """
        return cls(
            name=getattr(result, "name", "Unknown"),
            type=getattr(result, "type", "Unknown"),
            version=getattr(result, "version", ""),
            info=getattr(result, "info", ""),
            string=getattr(result, "string", ""),
            confidence=1.0,  # ICP Engine provides reliable detections with high confidence
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ICPDetection":
        """Create ICPDetection from dictionary (legacy compatibility).

        Args:
            data: Dictionary containing detection data from ICP engine JSON.

        Returns:
            ICPDetection: Parsed detection object.

        """
        return cls(
            name=data.get("name", "Unknown"),
            type=data.get("type", "Unknown"),
            version=data.get("version", ""),
            info=data.get("info", ""),
            string=data.get("string", ""),
        )


@dataclass
class ICPFileInfo:
    """File information from ICP engine."""

    filetype: str
    size: str
    offset: str = "0"
    parentfilepart: str = ""
    detections: list[ICPDetection] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ICPFileInfo":
        """Create ICPFileInfo from dictionary (legacy compatibility).

        Args:
            data: Dictionary containing file info from ICP engine JSON output.

        Returns:
            ICPFileInfo: Parsed file information object.

        """
        obj = cls(
            filetype=data.get("filetype", "Unknown"),
            size=data.get("size", "0"),
            offset=data.get("offset", "0"),
            parentfilepart=data.get("parentfilepart", ""),
        )

        # Parse detections
        for value in data.get("values", []):
            obj.detections.append(ICPDetection.from_dict(value))

        return obj


@dataclass
class ICPScanResult:
    """Complete scan result from ICP engine."""

    file_path: str
    file_infos: list[ICPFileInfo] = field(default_factory=list)
    error: str | None = None
    raw_json: dict[str, Any] | None = None
    supplemental_data: dict[str, Any] = field(default_factory=dict)

    @property
    def is_packed(self) -> bool:
        """Check if file is packed.

        Returns:
            bool: True if packer detection found, False otherwise.

        """
        packer_types = ["Packer", "Protector", "Cryptor"]
        for info in self.file_infos:
            for detection in info.detections:
                if detection.type in packer_types:
                    return True
        return False

    @property
    def is_protected(self) -> bool:
        """Check if file has protections.

        Returns:
            bool: True if protection detection found, False otherwise.

        """
        protection_types = ["Protector", "License", "DRM", "Dongle", "Anti-Debug"]
        for info in self.file_infos:
            for detection in info.detections:
                if detection.type in protection_types:
                    return True
        return False

    @property
    def all_detections(self) -> list[ICPDetection]:
        """Get all detections from all file infos.

        Returns:
            list[ICPDetection]: List of all detection objects.

        """
        detections = []
        for info in self.file_infos:
            detections.extend(info.detections)
        return detections

    @classmethod
    def from_json(cls, file_path: str, json_data: dict[str, Any]) -> "ICPScanResult":
        """Create ICPScanResult from ICP engine JSON output (legacy compatibility).

        Args:
            file_path: Path to analyzed file.
            json_data: JSON data from ICP engine scan.

        Returns:
            ICPScanResult: Parsed scan result object.

        """
        obj = cls(file_path=file_path, raw_json=json_data)

        # Parse detects array
        for detect in json_data.get("detects", []):
            obj.file_infos.append(ICPFileInfo.from_dict(detect))

        return obj

    @classmethod
    def from_icp_results(cls, file_path: str, icp_results: list[Any]) -> "ICPScanResult":
        """Create ICPScanResult from ICP Engine scan results.

        Args:
            file_path: Path to analyzed file.
            icp_results: List of ICP Engine detection results.

        Returns:
            ICPScanResult: Parsed scan result object.

        """
        obj = cls(file_path=file_path)

        if not icp_results:
            # Create a basic file info with no detections
            file_info = ICPFileInfo(
                filetype="Binary",
                size=str(Path(file_path).stat().st_size if Path(file_path).exists() else 0),
            )
            obj.file_infos.append(file_info)
            return obj

        # Create file info with detections
        file_info = ICPFileInfo(
            filetype="Binary",  # ICP Engine doesn't provide file type info directly
            size=str(Path(file_path).stat().st_size if Path(file_path).exists() else 0),
        )

        # Convert ICP Engine results to our detection format
        for result in icp_results:
            detection = ICPDetection.from_icp_result(result)
            file_info.detections.append(detection)

        obj.file_infos.append(file_info)
        return obj

    @classmethod
    def from_icp_text(cls, file_path: str, icp_text: str) -> "ICPScanResult":
        r"""Create from ICP Engine text output.

        Args:
            file_path: Path to the analyzed file
            icp_text: Text output from ICP Engine scan.
                Example format: "PE64\\n    Unknown: Unknown\\n    Packer: UPX"

        Returns:
            ICPScanResult with parsed detections

        """
        obj = cls(file_path=file_path)

        if not icp_text or not icp_text.strip():
            # Create a basic file info with no detections
            file_info = ICPFileInfo(
                filetype="Binary",
                size=str(Path(file_path).stat().st_size if Path(file_path).exists() else 0),
            )
            obj.file_infos.append(file_info)
            return obj

        lines = icp_text.strip().split("\n")
        if not lines:
            return obj

        # First line is the file type (e.g., "PE64", "ELF64")
        filetype = lines[0].strip() if lines else "Binary"

        # Create file info
        file_info = ICPFileInfo(
            filetype=filetype,
            size=str(Path(file_path).stat().st_size if Path(file_path).exists() else 0),
        )

        # Parse detection lines (indented lines after the first)
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue

            # Parse "Type: Name" format
            if ":" in line:
                type_part, name_part = line.split(":", 1)
                detection_type = type_part.strip()
                detection_name = name_part.strip()

                # Create detection with parsed info
                detection = ICPDetection(
                    name=detection_name,
                    type=detection_type,
                    version="",  # ICP Engine text format doesn't include version
                    info="",  # ICP Engine text format doesn't include detailed info
                    string=line,  # Store original line
                    confidence=1.0,  # Default confidence
                )

            else:
                # Handle lines without colons (unusual case)
                detection = ICPDetection(
                    name=line,
                    type="Unknown",
                    version="",
                    info="",
                    string=line,
                    confidence=1.0,
                )
            file_info.detections.append(detection)
        obj.file_infos.append(file_info)
        return obj


class ICPEngineError(Exception):
    """ICP Engine specific errors."""


class NativeICPLibrary:
    """Direct native library interface for ICP Engine."""

    def __init__(self, library_path: str | None = None) -> None:
        """Initialize native library interface.

        Args:
            library_path: Optional path to native ICP library.

        """
        self.lib = None
        self.functions: dict[str, Any] = {}

        # Try to load native library
        if platform.system() == "Windows":
            lib_names = ["die.dll", "diec.dll", "die_core.dll"]
            lib_paths = [
                Path(library_path) if library_path else None,
                Path(sys.prefix) / "Lib" / "site-packages" / "die",
                Path("die"),
                Path(os.environ.get("INTELLICRACK_ROOT", ".")) / "bin",
            ]
        else:
            lib_names = ["libdie.so", "libdiec.so", "die.so"]
            lib_paths = [
                Path(library_path) if library_path else None,
                Path("/usr/local/lib"),
                Path("/usr/lib"),
                Path("die"),
            ]

        # Attempt to load library
        for path in lib_paths:
            if not path:
                continue
            for name in lib_names:
                try:
                    lib_file = path / name if path else Path(name)
                    if lib_file.exists():
                        self.lib = ctypes.CDLL(str(lib_file))
                        self._setup_functions()
                        logger.info("Loaded native ICP library from %s", lib_file)
                        return
                except Exception as e:
                    logger.debug("Failed to load %s: %s", lib_file, e, exc_info=True)

        # Fallback to Python module if available
        if _icp_module:
            self.lib = _icp_module
            logger.info("Using Python ICP module as native interface")

    def _setup_functions(self) -> None:
        """Configure function prototypes for native library.

        Sets up ctypes function prototypes for native ICP library functions
        including scan, entropy calculation, and memory management routines.

        """
        if not self.lib or isinstance(self.lib, type(_icp_module)):
            return

        # Define function signatures
        try:
            # Initialize function
            self.functions["init"] = self.lib.die_init
            self.functions["init"].argtypes = []
            self.functions["init"].restype = ctypes.c_int

            # Scan file function
            self.functions["scan"] = self.lib.die_scan_file
            self.functions["scan"].argtypes = [ctypes.c_char_p, ctypes.c_int]
            self.functions["scan"].restype = ctypes.c_char_p

            # Get entropy function
            self.functions["entropy"] = self.lib.die_get_entropy
            self.functions["entropy"].argtypes = [ctypes.c_char_p, ctypes.c_int]
            self.functions["entropy"].restype = ctypes.c_double

            # Get file type function
            self.functions["filetype"] = self.lib.die_get_filetype
            self.functions["filetype"].argtypes = [ctypes.c_char_p]
            self.functions["filetype"].restype = ctypes.c_char_p

            # Extract strings function
            self.functions["strings"] = self.lib.die_extract_strings
            self.functions["strings"].argtypes = [ctypes.c_char_p, ctypes.c_int]
            self.functions["strings"].restype = ctypes.POINTER(ctypes.c_char_p)

            # Free memory function
            self.functions["free"] = self.lib.die_free_memory
            self.functions["free"].argtypes = [ctypes.c_void_p]
            self.functions["free"].restype = None

            # Initialize the library
            self.functions["init"]()

        except AttributeError as e:
            logger.warning("Some native functions not available: %s", e, exc_info=True)

    def scan_file_native(self, file_path: str, flags: int = 0) -> str:
        """Scan file using native library call.

        Args:
            file_path: Path to file to scan.
            flags: Scan mode flags.

        Returns:
            str: Text output from native scan operation.

        Raises:
            RuntimeError: If native scan function is not available.

        """
        if isinstance(self.lib, type(_icp_module)):
            # Use Python module
            result = self.lib.scan_file(file_path, flags)
            return str(result) if result else ""
        if "scan" in self.functions:
            # Use native function
            result = self.functions["scan"](file_path.encode("utf-8"), flags)
            return result.decode("utf-8") if result else ""
        error_msg = "Native scan function not available"
        logger.error(error_msg)
        raise RuntimeError(error_msg)

    def get_entropy_native(self, file_path: str, max_bytes: int = 0) -> float:
        """Get file entropy using native library call.

        Args:
            file_path: Path to file to analyze.
            max_bytes: Maximum bytes to read (0 = all).

        Returns:
            float: Shannon entropy value between 0.0 and 8.0.

        """
        if isinstance(self.lib, type(_icp_module)):
            # Calculate entropy using Python module or manual calculation
            return self._calculate_entropy_python(file_path, max_bytes)
        if "entropy" in self.functions:
            # Use native function
            result = self.functions["entropy"](file_path.encode("utf-8"), max_bytes)
            return float(result) if result is not None else 0.0
        return self._calculate_entropy_python(file_path, max_bytes)

    def _calculate_entropy_python(self, file_path: str, max_bytes: int = 0) -> float:
        """Calculate Shannon entropy in Python.

        Args:
            file_path: Path to file to analyze.
            max_bytes: Maximum bytes to read (0 = all).

        Returns:
            float: Shannon entropy value between 0.0 and 8.0.

        """
        import math

        with open(file_path, "rb") as f:
            data = f.read(max_bytes) if max_bytes > 0 else f.read()
            if not data:
                return 0.0

            # Calculate byte frequency
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)

            return entropy


class ResultCache:
    """SQLite-based result caching system with invalidation."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        """Initialize cache system.

        Args:
            cache_dir: Directory to store cache database (defaults to ~/.intellicrack/cache).

        """
        if cache_dir is None:
            cache_dir = Path.home() / ".intellicrack" / "cache"

        cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = cache_dir / "icp_cache.db"
        self.memory_cache: dict[str, dict[str, Any]] = {}
        self.cache_stats: dict[str, int] = {"hits": 0, "misses": 0, "evictions": 0}

        # Initialize database
        self._init_database()

        # Start cache cleanup thread
        self._start_cleanup_thread()

    def _init_database(self) -> None:
        """Initialize SQLite cache database.

        Creates cache table with file hash, metadata, and scan results.

        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    file_hash TEXT PRIMARY KEY,
                    file_path TEXT,
                    file_size INTEGER,
                    file_mtime REAL,
                    scan_mode TEXT,
                    result_json TEXT,
                    created_at REAL,
                    accessed_at REAL,
                    access_count INTEGER DEFAULT 1
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_accessed_at
                ON cache(accessed_at)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_file_path
                ON cache(file_path)
            """)

    def _start_cleanup_thread(self) -> None:
        """Start background thread for cache cleanup.

        Spawns daemon thread that evicts old cache entries every hour.

        """

        def cleanup_worker() -> None:
            while True:
                time.sleep(3600)  # Run every hour
                self._cleanup_old_entries()

        thread = threading.Thread(target=cleanup_worker, daemon=True)
        thread.start()

    def _cleanup_old_entries(self, max_age_days: int = 7) -> None:
        """Remove old cache entries.

        Args:
            max_age_days: Age threshold in days for cache eviction.

        """
        cutoff_time = time.time() - (max_age_days * 86400)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM cache WHERE accessed_at < ?", (cutoff_time,))

            if cursor.rowcount > 0:
                self.cache_stats["evictions"] += cursor.rowcount
                logger.info("Evicted %s old cache entries", cursor.rowcount)

    def get_file_hash(self, file_path: str) -> str:
        """Calculate file hash for cache key.

        Args:
            file_path: Path to file to hash.

        Returns:
            str: SHA256 hash hexdigest of file contents.

        """
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            # Read file in chunks for memory efficiency
            for chunk in iter(lambda: f.read(65536), b""):
                sha256_hash.update(chunk)

        return sha256_hash.hexdigest()

    def get(self, file_path: str, scan_mode: str) -> dict[str, Any] | None:
        """Get cached result if valid.

        Args:
            file_path: Path to analyzed file.
            scan_mode: Scan mode used for analysis.

        Returns:
            dict[str, Any] | None: Cached result if found and valid, None otherwise.

        """
        try:
            # Check memory cache first
            cache_key = f"{file_path}:{scan_mode}"
            if cache_key in self.memory_cache:
                self.cache_stats["hits"] += 1
                return self.memory_cache[cache_key]

            # Get file info
            stat = Path(file_path).stat()
            file_hash = self.get_file_hash(file_path)

            # Check database cache
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    """
                    SELECT result_json, file_size, file_mtime
                    FROM cache
                    WHERE file_hash = ? AND scan_mode = ?
                    """,
                    (file_hash, scan_mode),
                )

                if row := cursor.fetchone():
                    result_json, cached_size, cached_mtime = row

                    # Validate cache entry
                    if cached_size == stat.st_size and abs(cached_mtime - stat.st_mtime) < 1:
                        # Update access time and count
                        conn.execute(
                            """
                            UPDATE cache
                            SET accessed_at = ?, access_count = access_count + 1
                            WHERE file_hash = ? AND scan_mode = ?
                            """,
                            (time.time(), file_hash, scan_mode),
                        )

                        result: dict[str, Any] = json.loads(result_json)

                        # Store in memory cache
                        self.memory_cache[cache_key] = result

                        self.cache_stats["hits"] += 1
                        return result

            self.cache_stats["misses"] += 1
            return None

        except Exception as e:
            logger.debug("Cache get error: %s", e, exc_info=True)
            return None

    def put(self, file_path: str, scan_mode: str, result: dict[str, Any]) -> None:
        """Store result in cache.

        Args:
            file_path: Path to analyzed file.
            scan_mode: Scan mode used for analysis.
            result: Scan result dictionary to cache.

        """
        try:
            # Store in memory cache
            cache_key = f"{file_path}:{scan_mode}"
            self.memory_cache[cache_key] = result

            # Limit memory cache size
            if len(self.memory_cache) > 100:
                # Remove oldest entries
                for key in list(self.memory_cache)[:20]:
                    del self.memory_cache[key]

            # Get file info
            stat = Path(file_path).stat()
            file_hash = self.get_file_hash(file_path)

            # Store in database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cache
                    (file_hash, file_path, file_size, file_mtime, scan_mode,
                     result_json, created_at, accessed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        file_hash,
                        file_path,
                        stat.st_size,
                        stat.st_mtime,
                        scan_mode,
                        json.dumps(result),
                        time.time(),
                        time.time(),
                    ),
                )

        except Exception as e:
            logger.debug("Cache put error: %s", e, exc_info=True)

    def invalidate(self, file_path: str) -> None:
        """Invalidate cache entries for a file.

        Args:
            file_path: Path to file whose cache should be invalidated.

        """
        try:
            # Remove from memory cache
            keys_to_remove = [k for k in self.memory_cache if k.startswith(f"{file_path}:")]
            for key in keys_to_remove:
                del self.memory_cache[key]

            # Remove from database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM cache WHERE file_path = ?", (file_path,))

        except Exception as e:
            logger.debug("Cache invalidate error: %s", e, exc_info=True)

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics.

        Returns:
            dict[str, Any]: Cache statistics including hits, misses, and hit rate.

        """
        stats: dict[str, Any] = self.cache_stats.copy()

        # Add database stats
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM cache")
                stats["db_entries"] = cursor.fetchone()[0]

                cursor = conn.execute("SELECT SUM(access_count) FROM cache")
                total_accesses = cursor.fetchone()[0]
                stats["total_accesses"] = total_accesses or 0

        except Exception:
            stats["db_entries"] = 0
            stats["total_accesses"] = 0

        stats["memory_entries"] = len(self.memory_cache)
        hit_rate: float = (
            self.cache_stats["hits"] / (self.cache_stats["hits"] + self.cache_stats["misses"])
            if self.cache_stats["hits"] + self.cache_stats["misses"] > 0
            else 0.0
        )
        stats["hit_rate"] = hit_rate

        return stats


class ParallelScanner:
    """Parallel scanning coordinator for batch analysis."""

    def __init__(self, max_workers: int = 4) -> None:
        """Initialize parallel scanner.

        Args:
            max_workers: Maximum number of concurrent scan threads.

        """
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.native_lib = NativeICPLibrary()
        self.scan_queue: asyncio.Queue[str] = asyncio.Queue()
        self.results: dict[str, ICPScanResult] = {}
        self.active_scans: set[str] = set()

    async def scan_files_parallel(
        self,
        file_paths: list[str],
        scan_mode: ScanMode,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> dict[str, ICPScanResult]:
        """Scan multiple files in parallel with progress tracking.

        Args:
            file_paths: List of file paths to scan.
            scan_mode: Scan mode to use for all files.
            progress_callback: Optional callback for progress updates.

        Returns:
            dict[str, ICPScanResult]: Dictionary mapping file paths to scan results.

        """
        results = {}
        total_files = len(file_paths)
        completed = 0

        # Create scan tasks
        scan_tasks = []
        for file_path in file_paths:
            task = asyncio.create_task(self._scan_single_file(file_path, scan_mode))
            scan_tasks.append((file_path, task))

        # Process results as they complete
        for file_path, task in scan_tasks:
            try:
                result = await task
                results[file_path] = result
                completed += 1

                if progress_callback:
                    progress_callback(completed, total_files, file_path)

            except Exception as e:
                logger.error("Parallel scan error for %s: %s", file_path, e, exc_info=True)
                results[file_path] = ICPScanResult(file_path=file_path, error=str(e))

        return results

    async def _scan_single_file(self, file_path: str, scan_mode: ScanMode) -> ICPScanResult:
        """Scan a single file asynchronously.

        Args:
            file_path: Path to file to scan.
            scan_mode: Scan mode to use.

        Returns:
            ICPScanResult: Scan result for the file.

        """
        loop = asyncio.get_event_loop()

        # Run native scan in thread pool
        def do_scan() -> ICPScanResult:
            try:
                # Memory map file for efficient access
                with open(file_path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ):
                    # Perform native scan
                    scan_flags = self._get_scan_flags(scan_mode)
                    result_text = self.native_lib.scan_file_native(file_path, scan_flags)

                    # Get additional data
                    entropy = self.native_lib.get_entropy_native(file_path)

                    # Parse result
                    scan_result = ICPScanResult.from_icp_text(file_path, result_text)

                    # Add entropy to supplemental data
                    if not scan_result.supplemental_data:
                        scan_result.supplemental_data = {}
                    scan_result.supplemental_data["entropy"] = entropy
                    scan_result.supplemental_data["entropy_high"] = entropy > 7.5

                    return scan_result

            except Exception as e:
                logger.error("Native scan error: %s", e, exc_info=True)
                raise

        result = await loop.run_in_executor(self.executor, do_scan)
        return result

    def _get_scan_flags(self, scan_mode: ScanMode) -> int:
        """Convert scan mode to native scan flags.

        Args:
            scan_mode: Scan mode enum value.

        Returns:
            int: Native scan flags for the mode.

        """
        # Define scan flags based on mode
        flags = {
            ScanMode.NORMAL: 0x0000,
            ScanMode.DEEP: 0x0001 | 0x0002,  # Deep scan + version info
            ScanMode.HEURISTIC: 0x0004 | 0x0008,  # Heuristic + suspicious
            ScanMode.AGGRESSIVE: 0x000F,  # All basic flags
            ScanMode.ALL: 0xFFFF,  # All possible flags
        }

        return flags.get(scan_mode, 0)

    def shutdown(self) -> None:
        """Shutdown the parallel scanner.

        Cleanly shuts down ThreadPoolExecutor and waits for pending tasks.

        """
        self.executor.shutdown(wait=True)


class ICPBackend:
    """Native ICP Engine wrapper providing comprehensive protection analysis functionality.

    This class serves as the core backend for Intellicrack's protection analysis,
    offering advanced native integration for comprehensive binary analysis.
    It provides all the functionality required for sophisticated protection detection
    with enhanced performance, reliability, and seamless integration.

    Core Capabilities:
    - Native library integration without subprocess calls
    - Memory-mapped file access for performance
    - Result caching with SQLite persistence
    - Parallel scanning with asyncio coordination
    - Robust error handling and recovery
    - File type detection and analysis
    - Packer and protector identification
    - Shannon entropy calculation and analysis
    - String extraction with offset mapping
    - PE section analysis with detailed metadata
    - Comprehensive binary analysis reports

    The backend supports multiple scan modes from quick analysis to deep
    investigation, and can process files asynchronously to maintain UI
    responsiveness in GUI applications.

    Example:
        .. code-block:: python

            backend = ICPBackend()
            result = await backend.analyze_file(
                "target.exe",
                ScanMode.DEEP,
            )
            if result.is_packed:
                print(
                    f"File is packed with: {', '.join(result.all_detections)}"
                )

            # Or use synchronous detailed analysis
            analysis = backend.get_detailed_analysis(
                "target.exe"
            )
            print(
                f"Entropy: {analysis['entropy']:.4f}"
            )
            print(
                f"Strings found: {len(analysis['strings'])}"
            )

    """

    def __init__(self, engine_path: str | None = None, enable_cache: bool = True) -> None:
        """Initialize ICP backend with native integration.

        Args:
            engine_path: Optional path to native ICP library
            enable_cache: Enable result caching for performance

        Raises:
            ICPEngineError: If native library initialization fails

        """
        self.engine_path = engine_path

        # Initialize native library interface
        self.native_lib = NativeICPLibrary(engine_path)

        # Initialize result cache
        self.cache = ResultCache() if enable_cache else None

        # Initialize parallel scanner
        self.parallel_scanner = ParallelScanner(max_workers=4)

        # Use pre-imported module as fallback
        if not self.native_lib.lib and _icp_module:
            self.icp_module = _icp_module
            logger.info("ICP Backend initialized with Python module v%s", ICP_VERSION)
        elif self.native_lib.lib:
            self.icp_module = self.native_lib
            logger.info("ICP Backend initialized with native library")
        else:
            error_msg = "No ICP Engine implementation available"
            logger.error(error_msg)
            raise ICPEngineError(error_msg)

        # Error recovery state
        self.last_error: str | None = None
        self.error_count: int = 0
        self.max_retries: int = 3

        # Timeout configuration
        self.default_scan_timeout: float = 30.0  # Default timeout for scan operations

    def _get_icp_scan_flags(self, scan_mode: ScanMode) -> int:
        """Convert scan mode to ICP Engine scan flags.

        Args:
            scan_mode: Scan mode enum value.

        Returns:
            int: ICP Engine scan flags for the mode.

        """
        # Use native flags or module flags
        if hasattr(self.icp_module, "ScanFlags"):
            flag_map = {
                ScanMode.NORMAL: 0,  # Default scanning
                ScanMode.DEEP: self.icp_module.ScanFlags.DEEP_SCAN,
                ScanMode.HEURISTIC: self.icp_module.ScanFlags.HEURISTIC_SCAN,
                ScanMode.AGGRESSIVE: self.icp_module.ScanFlags.DEEP_SCAN | self.icp_module.ScanFlags.HEURISTIC_SCAN,
                ScanMode.ALL: (
                    self.icp_module.ScanFlags.DEEP_SCAN
                    | self.icp_module.ScanFlags.HEURISTIC_SCAN
                    | self.icp_module.ScanFlags.ALL_TYPES_SCAN
                ),
            }
        else:
            # Use numeric flags for native library
            flag_map = {
                ScanMode.NORMAL: 0x0000,
                ScanMode.DEEP: 0x0003,  # DEEP_SCAN | SHOW_VERSION
                ScanMode.HEURISTIC: 0x000C,  # HEURISTIC_SCAN | SHOW_SUSPICIOUS
                ScanMode.AGGRESSIVE: 0x000F,  # All basic flags
                ScanMode.ALL: 0x00FF,  # All extended flags
            }

        return int(flag_map.get(scan_mode, 0))

    async def analyze_file(
        self,
        file_path: str,
        scan_mode: ScanMode = ScanMode.DEEP,
        show_entropy: bool = True,
        show_info: bool = True,
        include_supplemental: bool = True,
    ) -> ICPScanResult:
        """Analyze a file asynchronously using ICP Engine with optional supplemental analysis.

        Args:
            file_path: Path to file to analyze
            scan_mode: Scan mode to use
            show_entropy: Include entropy analysis (ignored, kept for compatibility)
            show_info: Include file info (ignored, kept for compatibility)
            include_supplemental: Include supplemental analysis from YARA, Binwalk, and Volatility3

        Returns:
            ICPScanResult with analysis data and optional supplemental data

        """
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            return ICPScanResult(
                file_path=file_path,
                error=f"File not found: {file_path}",
            )

        # Get scan flags
        scan_flags = self._get_icp_scan_flags(scan_mode)

        # Apply additional flags based on parameters
        if show_entropy:
            # Add entropy calculation flag if available
            scan_flags |= 0x0100  # ICP_SHOWERRORS flag can include entropy info

        if not show_info:
            # If info is not requested, use a faster scan mode
            scan_flags &= ~0x0002  # Remove ICP_SHOWVERSION flag

        # Check cache first if enabled
        if self.cache:
            cached_result = self.cache.get(file_path, scan_mode.value)
            if cached_result:
                logger.debug("Cache hit for %s with mode %s", file_path, scan_mode.value)
                # Convert cached dict back to ICPScanResult
                return ICPScanResult.from_json(file_path, cached_result)

        # Implement retry logic for robustness
        retry_count = 0
        last_error = None

        while retry_count < self.max_retries:
            try:
                # Use native scanning with memory-mapped file access
                async with asyncio.timeout(self.default_scan_timeout):
                    result = await self._perform_native_scan(file_path_obj, scan_flags)

                if result and not result.error:
                    # Cache successful result
                    if self.cache:
                        cache_data = {
                            "detects": [
                                {
                                    "filetype": info.filetype,
                                    "size": info.size,
                                    "offset": info.offset,
                                    "values": [
                                        {
                                            "name": d.name,
                                            "type": d.type,
                                            "version": d.version,
                                            "info": d.info,
                                            "string": d.string,
                                        }
                                        for d in info.detections
                                    ],
                                }
                                for info in result.file_infos
                            ],
                        }
                        self.cache.put(str(file_path), scan_mode.value, cache_data)

                    # Reset error state on success
                    self.error_count = 0
                    self.last_error = None

                    break  # Success, exit retry loop

                retry_count += 1
                last_error = result.error if result else "Unknown error"

            except TimeoutError:
                logger.error("Analysis timed out after %s seconds for %s", self.default_scan_timeout, file_path, exc_info=True)
                result = ICPScanResult(
                    file_path=str(file_path),
                    error=f"Analysis timed out after {self.default_scan_timeout} seconds",
                )
                break
            except Exception as e:
                retry_count += 1
                last_error = str(e)
                logger.warning("Scan attempt %s failed: %s", retry_count, e, exc_info=True)

                if retry_count < self.max_retries:
                    # Exponential backoff
                    await asyncio.sleep(0.5 * (2**retry_count))

        # Handle persistent failure
        if retry_count >= self.max_retries:
            self.error_count += 1
            self.last_error = str(last_error) if last_error else None
            logger.error("Analysis failed after %s retries: %s", self.max_retries, last_error)
            return ICPScanResult(
                file_path=str(file_path),
                error=f"Analysis failed after {self.max_retries} retries: {last_error}",
            )

        try:
            # scan_result contains the result from native scan
            scan_result = result

            # Run supplemental analysis if requested
            if include_supplemental and SUPPLEMENTAL_ENGINES_AVAILABLE:
                try:
                    supplemental_data = await self._run_supplemental_analysis(str(file_path))
                    scan_result.supplemental_data = supplemental_data
                except Exception as e:
                    logger.warning("Supplemental analysis failed: %s", e, exc_info=True)

            # Add entropy information if requested
            if show_entropy and os.path.exists(file_path):
                try:
                    # Calculate file entropy
                    import math

                    def _calc_entropy() -> tuple[float, bool] | None:
                        with open(file_path, "rb") as f:
                            data = f.read(1024 * 1024)  # Read first MB for entropy
                            if data:
                                # Calculate entropy
                                byte_counts = [0] * 256
                                for byte in data:
                                    byte_counts[byte] += 1

                                entropy = 0.0
                                data_len = len(data)
                                for count in byte_counts:
                                    if count > 0:
                                        probability = count / data_len
                                        entropy -= probability * math.log2(probability)

                                return round(entropy, 4), entropy > 7.5
                        return None

                    entropy_result = await asyncio.to_thread(_calc_entropy)
                    if entropy_result:
                        # Add entropy to scan result
                        if not scan_result.supplemental_data:
                            scan_result.supplemental_data = {}
                        scan_result.supplemental_data["entropy"] = entropy_result[0]
                        scan_result.supplemental_data["entropy_high"] = entropy_result[1]
                except Exception as e:
                    logger.debug("Could not calculate entropy: %s", e, exc_info=True)

            # Add file info if requested
            if show_info and os.path.exists(file_path):
                try:
                    stat_info = Path(file_path).stat()
                    if not scan_result.supplemental_data:
                        scan_result.supplemental_data = {}
                    scan_result.supplemental_data["file_info"] = {
                        "size": stat_info.st_size,
                        "modified": stat_info.st_mtime,
                        "created": getattr(stat_info, "st_birthtime", stat_info.st_ctime),
                        "permissions": oct(stat_info.st_mode),
                    }
                except Exception as e:
                    logger.debug("Could not get file info: %s", e, exc_info=True)

            logger.info("Analysis complete: %s detections found", len(scan_result.all_detections))
            return scan_result

        except Exception as e:
            logger.error("ICP analysis error: %s", e, exc_info=True)
            return ICPScanResult(
                file_path=str(file_path),
                error=str(e),
            )

    async def batch_analyze(
        self,
        file_paths: list[str],
        scan_mode: ScanMode = ScanMode.NORMAL,
        max_concurrent: int = 4,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> dict[str, ICPScanResult]:
        """Analyze multiple files concurrently with native parallel scanning.

        Args:
            file_paths: List of file paths to analyze
            scan_mode: Scan mode to use for all files
            max_concurrent: Maximum concurrent analyses
            progress_callback: Optional callback for progress updates

        Returns:
            Dictionary mapping file paths to results

        """
        # Update parallel scanner worker count if different
        if self.parallel_scanner.max_workers != max_concurrent:
            self.parallel_scanner.shutdown()
            self.parallel_scanner = ParallelScanner(max_workers=max_concurrent)

        # Use native parallel scanning
        results = await self.parallel_scanner.scan_files_parallel(file_paths, scan_mode, progress_callback)

        # Add supplemental data if enabled
        if SUPPLEMENTAL_ENGINES_AVAILABLE:
            for file_path, result in results.items():
                if not result.error:
                    try:
                        supplemental = await self._run_supplemental_analysis(file_path)
                        result.supplemental_data = supplemental
                    except Exception as e:
                        logger.warning("Failed to add supplemental data for %s: %s", file_path, e, exc_info=True)

        return results

    async def _perform_native_scan(self, file_path: Path, scan_flags: int) -> ICPScanResult:
        """Perform native scan with error handling.

        Args:
            file_path: Path to file to scan.
            scan_flags: Scan mode flags.

        Returns:
            ICPScanResult: Scan result from native analysis.

        """
        loop = asyncio.get_event_loop()

        def native_scan() -> ICPScanResult:
            try:
                # Use memory-mapped file for efficiency
                with open(file_path, "rb") as f:
                    # Check if file is too large for memory mapping
                    file_size = os.path.getsize(file_path)
                    if file_size > 2 * 1024 * 1024 * 1024:  # 2GB limit
                        # Use streaming scan for large files
                        return self._scan_large_file(file_path, scan_flags)

                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ):
                        # Perform native scan
                        if isinstance(self.icp_module, NativeICPLibrary):
                            result_text = self.icp_module.scan_file_native(str(file_path), scan_flags)
                        else:
                            result_text = self.icp_module.scan_file(str(file_path), scan_flags)

                        return ICPScanResult.from_icp_text(str(file_path), result_text)

            except Exception as e:
                logger.error("Native scan error: %s", e, exc_info=True)
                return ICPScanResult(file_path=str(file_path), error=str(e))

        result = await loop.run_in_executor(None, native_scan)
        return result

    def _scan_large_file(self, file_path: Path, scan_flags: int) -> ICPScanResult:
        """Scan large files that can't be memory-mapped.

        Args:
            file_path: Path to large file to scan.
            scan_flags: Scan mode flags.

        Returns:
            ICPScanResult: Scan result from chunked analysis.

        """
        try:
            # For large files, scan in chunks
            chunk_size = 100 * 1024 * 1024  # 100MB chunks
            detections = []
            file_type = "Unknown"

            with open(file_path, "rb") as f:
                chunk_num = 0
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    # Analyze chunk
                    if chunk_num == 0:
                        # First chunk contains file type info
                        if isinstance(self.icp_module, NativeICPLibrary):
                            file_type = self._detect_file_type_from_bytes(chunk)
                        else:
                            # Use module's file type detection
                            temp_path = Path.home() / ".intellicrack" / "temp" / f"chunk_{chunk_num}.bin"
                            temp_path.parent.mkdir(parents=True, exist_ok=True)
                            temp_path.write_bytes(chunk[:4096])  # Write header only
                            file_type = self.get_file_type(str(temp_path))
                            temp_path.unlink()

                    # Look for protection signatures in chunk
                    chunk_detections = self._scan_chunk_for_protections(chunk, chunk_num * chunk_size)
                    detections.extend(chunk_detections)

                    chunk_num += 1

            # Create result
            file_info = ICPFileInfo(filetype=file_type, size=str(os.path.getsize(file_path)), detections=detections)

            result = ICPScanResult(file_path=str(file_path))
            result.file_infos.append(file_info)

            return result

        except Exception as e:
            return ICPScanResult(file_path=str(file_path), error=f"Large file scan error: {e}")

    def _detect_file_type_from_bytes(self, data: bytes) -> str:
        """Detect file type from first bytes.

        Args:
            data: First bytes of file to analyze.

        Returns:
            str: Detected file type (e.g., "PE64", "ELF32", "Unknown").

        """
        if len(data) < 4:
            return "Unknown"

        # Check common file signatures
        if data[:2] == b"MZ":
            # PE file - check if 32 or 64 bit
            if len(data) > 0x3C + 4:
                pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
                if len(data) > pe_offset + 6:
                    machine = struct.unpack("<H", data[pe_offset + 4 : pe_offset + 6])[0]
                    if machine == 0x8664:
                        return "PE64"
                    if machine == 0x014C:
                        return "PE32"
            return "PE"
        if data[:4] == b"\x7fELF":
            if len(data) > 4:
                if data[4] == 2:
                    return "ELF64"
                if data[4] == 1:
                    return "ELF32"
            return "ELF"
        if data[:4] == b"\xca\xfe\xba\xbe":
            return "Mach-O"
        if data[:4] in [b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"]:
            return "Mach-O64"
        if data[:2] == b"PK":
            return "ZIP/JAR"
        if data[:4] == b"Rar!":
            return "RAR"
        return "7Z" if data[:6] == b"7z\xbc\xaf\x27\x1c" else "Binary"

    def _scan_chunk_for_protections(self, chunk: bytes, offset: int) -> list[ICPDetection]:
        """Scan a chunk of data for protection signatures.

        Args:
            chunk: Binary data chunk to scan.
            offset: Offset of chunk in file.

        Returns:
            list[ICPDetection]: List of detections found in chunk.

        """
        detections = []

        # Define protection signatures to search for
        signatures = [
            # Packers
            (b"UPX0", "Packer", "UPX"),
            (b"UPX1", "Packer", "UPX"),
            (b"UPX!", "Packer", "UPX"),
            (b"ASPack", "Packer", "ASPack"),
            (b"aPLib", "Packer", "aPLib"),
            (b"PEC2", "Packer", "PECompact"),
            (b"PEtite", "Packer", "PEtite"),
            (b"NSPack", "Packer", "NSPack"),
            # Protectors
            (b"VMProtect", "Protector", "VMProtect"),
            (b".vmp0", "Protector", "VMProtect"),
            (b".vmp1", "Protector", "VMProtect"),
            (b"Themida", "Protector", "Themida"),
            (b"WinLicense", "Protector", "WinLicense"),
            (b"Obsidium", "Protector", "Obsidium"),
            (b"ASProtect", "Protector", "ASProtect"),
            (b"Enigma", "Protector", "Enigma Protector"),
            (b"MPRESS", "Protector", "MPRESS"),
            (b"Armadillo", "Protector", "Armadillo"),
            (b"SecuROM", "Protector", "SecuROM"),
            # License systems
            (b"FLEXlm", "License", "FlexLM"),
            (b"FLEXnet", "License", "FlexNet"),
            (b"Sentinel", "License", "Sentinel HASP"),
            (b"HASP", "License", "HASP"),
            (b"CodeMeter", "License", "CodeMeter"),
            (b"iLok", "License", "iLok"),
            (b"Steam API", "DRM", "Steam DRM"),
            (b"steam_api", "DRM", "Steam DRM"),
            (b"Denuvo", "DRM", "Denuvo"),
            (b"Origin", "DRM", "Origin DRM"),
            (b"Uplay", "DRM", "Uplay DRM"),
        ]

        # Search for signatures in chunk
        for signature, detection_type, name in signatures:
            pos = chunk.find(signature)
            if pos != -1:
                detection = ICPDetection(
                    name=name,
                    type=detection_type,
                    version="",
                    info=f"Found at offset 0x{offset + pos:08X}",
                    string=signature.decode("utf-8", errors="ignore"),
                    confidence=0.9,
                )
                detections.append(detection)

        return detections

    def get_engine_version(self) -> str:
        """Get ICP engine version.

        Returns:
            str: Version string of loaded ICP Engine.

        """
        try:
            if isinstance(self.icp_module, NativeICPLibrary):
                return "ICP Native Library v1.0.0"
            if hasattr(self.icp_module, "__version__"):
                version = self.icp_module.__version__
                if hasattr(self.icp_module, "die_version"):
                    return f"ICP Engine {version} (Core {self.icp_module.die_version})"
                return f"ICP Engine {version}"
            return "ICP Engine (version unknown)"
        except Exception as e:
            logger.error("Failed to get engine version: %s", e, exc_info=True)
            return "Unknown"

    def get_available_scan_modes(self) -> list[str]:
        """Get list of available scan modes.

        Returns:
            list[str]: List of available scan mode strings.

        """
        return [mode.value for mode in ScanMode]

    def is_icp_available(self) -> bool:
        """Check if ICP Engine is available and working.

        Returns:
            bool: True if ICP Engine is available, False otherwise.

        """
        try:
            if hasattr(self, "icp_module") and self.icp_module is not None:
                # Test with a simple operation
                if isinstance(self.icp_module, NativeICPLibrary):
                    return self.icp_module.lib is not None
                return True
            return False
        except Exception:
            return False

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics.

        Returns:
            dict[str, Any]: Cache statistics including hits, misses, and rates.

        """
        return self.cache.get_stats() if self.cache else {"cache_enabled": False}

    def invalidate_cache(self, file_path: str) -> None:
        """Invalidate cache for a specific file.

        Args:
            file_path: Path to file whose cache entries should be invalidated.

        """
        if self.cache:
            self.cache.invalidate(file_path)

    def get_error_stats(self) -> dict[str, Any]:
        """Get error recovery statistics.

        Returns:
            dict[str, Any]: Error statistics including last error and retry count.

        """
        return {
            "last_error": self.last_error,
            "error_count": self.error_count,
            "max_retries": self.max_retries,
        }

    def reset_error_state(self) -> None:
        """Reset error tracking state.

        Clears last error and resets error counter for fresh analysis.

        """
        self.last_error = None
        self.error_count = 0

    def get_file_type(self, file_path: str) -> str:
        """Get file type using native ICP Engine analysis.

        Args:
            file_path: Path to the file to analyze

        Returns:
            str: File type (e.g., "PE64", "ELF64", "Unknown")

        """
        try:
            result = self.icp_module.scan_file(file_path, 0)
            lines = result.strip().split("\n")
            return lines[0] if lines else "Unknown"
        except Exception as e:
            logger.error("Error getting file type: %s", e, exc_info=True)
            return "Unknown"

    def get_file_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of file contents.

        Entropy is a measure of randomness/unpredictability in data.
        High entropy (>7.5) often indicates encryption or compression.
        Low entropy (<4.0) indicates normal code/text.

        Args:
            file_path: Path to the file to analyze

        Returns:
            float: Entropy value between 0.0 and 8.0

        """
        try:
            import math

            with open(file_path, "rb") as f:
                data = f.read()
                if not data:
                    return 0.0

                # Calculate entropy
                byte_counts = [0] * 256
                for byte in data:
                    byte_counts[byte] += 1

                entropy = 0.0
                data_len = len(data)
                for count in byte_counts:
                    if count > 0:
                        probability = count / data_len
                        entropy -= probability * math.log2(probability)

                return entropy
        except Exception as e:
            logger.error("Error calculating entropy: %s", e, exc_info=True)
            return 0.0

    def extract_strings(self, file_path: str, min_length: int = 4) -> list[dict[str, Any]]:
        """Extract printable ASCII strings from binary file.

        Searches for sequences of printable ASCII characters that could
        indicate hardcoded strings, API names, error messages, etc.

        Args:
            file_path: Path to the file to analyze
            min_length: Minimum string length to extract (default: 4)

        Returns:
            List[Dict]: List of dictionaries containing:
                - offset: File offset where string was found
                - string: The extracted string
                - length: Length of the string
                - type: String type ("ASCII")

        """
        try:
            strings = []
            with open(file_path, "rb") as f:
                data = f.read()

            # Extract ASCII strings
            current_string = ""
            current_offset = 0

            for i, byte in enumerate(data):
                if 32 <= byte <= 126:  # Printable ASCII
                    if not current_string:
                        current_offset = i
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append(
                            {
                                "offset": current_offset,
                                "string": current_string,
                                "length": len(current_string),
                                "type": "ASCII",
                            },
                        )
                    current_string = ""

            # Don't forget the last string
            if len(current_string) >= min_length:
                strings.append(
                    {
                        "offset": current_offset,
                        "string": current_string,
                        "length": len(current_string),
                        "type": "ASCII",
                    },
                )

            return strings
        except Exception as e:
            logger.error("Error extracting strings: %s", e, exc_info=True)
            return []

    def get_file_sections(self, file_path: str) -> list[dict[str, Any]]:
        """Extract file sections with detailed information.

        Attempts to parse PE file sections using pefile if available,
        otherwise provides basic file information as a single section.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List[Dict]: List of section dictionaries containing:
                - name: Section name
                - virtual_address: Virtual address in memory
                - virtual_size: Size in memory
                - raw_size: Size on disk
                - raw_offset: Offset in file
                - characteristics: Section characteristics flags
                - entropy: Section entropy (calculated if needed)

        """
        try:
            sections = []

            # Try to get sections from PE analysis
            from intellicrack.handlers.pefile_handler import pefile

            try:
                pe = pefile.PE(file_path)
                for section in pe.sections:
                    section_info = {
                        "name": section.Name.decode("utf-8").rstrip("\x00"),
                        "virtual_address": section.VirtualAddress,
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "raw_offset": section.PointerToRawData,
                        "characteristics": section.Characteristics,
                        "entropy": 0.0,  # Will calculate if needed
                    }
                    sections.append(section_info)
            except Exception as e:
                logger.debug("Error parsing PE sections: %s", e, exc_info=True)

            # Fallback to basic file analysis
            if not sections:
                file_size = os.path.getsize(file_path)
                sections.append(
                    {
                        "name": ".data",
                        "virtual_address": 0,
                        "virtual_size": file_size,
                        "raw_size": file_size,
                        "raw_offset": 0,
                        "characteristics": 0,
                        "entropy": self.get_file_entropy(file_path),
                    },
                )

            return sections
        except Exception as e:
            logger.error("Error getting file sections: %s", e, exc_info=True)
            return []

    def detect_packers(self, file_path: str) -> list[str]:
        """Detect packers and protectors using native ICP Engine analysis.

        Scans the file and extracts any detections that are classified
        as packers or protectors based on the detection type.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List[str]: List of detected packer/protector names

        """
        try:
            result = self.icp_module.scan_file(file_path, 0)
            lines = result.strip().split("\n")

            packers = []
            for line in lines[1:]:  # Skip file type line
                line = line.strip()
                if ":" in line:
                    type_part, name_part = line.split(":", 1)
                    type_part = type_part.strip()
                    name_part = name_part.strip()

                    if "pack" in type_part.lower():
                        packers.append(name_part)

            return packers
        except Exception as e:
            logger.error("Error detecting packers: %s", e, exc_info=True)
            return []

    def add_supplemental_data(self, scan_result: ICPScanResult, supplemental_data: dict[str, Any]) -> ICPScanResult:
        """Add supplemental analysis data to an ICP scan result.

        Args:
            scan_result: Existing ICP scan result
            supplemental_data: Additional analysis data from external engines

        Returns:
            Updated ICPScanResult with merged supplemental data

        """
        if supplemental_data:
            scan_result.supplemental_data.update(supplemental_data)

            # Enhance detections with supplemental findings
            self._merge_supplemental_detections(scan_result, supplemental_data)

        return scan_result

    def _merge_supplemental_detections(self, scan_result: ICPScanResult, supplemental_data: dict[str, Any]) -> None:
        """Merge supplemental analysis findings into ICP detections.

        Args:
            scan_result: ICP scan result to enhance.
            supplemental_data: Supplemental analysis data to merge.

        """
        try:
            # Process YARA pattern findings
            if "yara_analysis" in supplemental_data:
                yara_data = supplemental_data["yara_analysis"]
                for pattern in yara_data.get("pattern_matches", []):
                    # Create detection for YARA match
                    detection = ICPDetection(
                        name=pattern.get("rule_name", "YARA Pattern"),
                        type="Pattern",
                        version="",
                        info=f"YARA: {pattern.get('category', 'Unknown')}",
                        string=pattern.get("description", ""),
                        confidence=pattern.get("confidence", 0.8),
                    )

                    # Add to first file info or create new one
                    if scan_result.file_infos:
                        scan_result.file_infos[0].detections.append(detection)
                    else:
                        file_info = ICPFileInfo(
                            filetype="Binary",
                            size=str(Path(scan_result.file_path).stat().st_size if Path(scan_result.file_path).exists() else 0),
                        )
                        file_info.detections.append(detection)
                        scan_result.file_infos.append(file_info)

            # Process firmware analysis findings
            if "firmware_analysis" in supplemental_data:
                firmware_data = supplemental_data["firmware_analysis"]
                for component in firmware_data.get("embedded_components", []):
                    if component.get("is_executable") or component.get("is_filesystem"):
                        detection = ICPDetection(
                            name=component.get("name", "Embedded Component"),
                            type="Firmware",
                            version="",
                            info=f"Firmware: {component.get('type', 'Unknown')} at offset {component.get('offset', 0)}",
                            string=f"Size: {component.get('size', 0)} bytes",
                            confidence=component.get("confidence", 0.9),
                        )

                        if scan_result.file_infos:
                            scan_result.file_infos[0].detections.append(detection)
                        else:
                            file_info = ICPFileInfo(
                                filetype="Firmware",
                                size=str(Path(scan_result.file_path).stat().st_size if Path(scan_result.file_path).exists() else 0),
                            )
                            file_info.detections.append(detection)
                            scan_result.file_infos.append(file_info)

            # Process memory forensics findings
            if "memory_forensics" in supplemental_data:
                memory_data = supplemental_data["memory_forensics"]
                for indicator in memory_data.get("process_indicators", []):
                    if indicator.get("is_hidden") or indicator.get("indicators"):
                        detection = ICPDetection(
                            name=f"Process {indicator.get('name', 'Unknown')}",
                            type="Memory",
                            version="",
                            info=f"Memory: PID {indicator.get('pid', 0)} - {', '.join(indicator.get('indicators', []))}",
                            string=f"Hidden: {indicator.get('is_hidden', False)}",
                            confidence=0.7,
                        )

                        if scan_result.file_infos:
                            scan_result.file_infos[0].detections.append(detection)
                        else:
                            file_info = ICPFileInfo(
                                filetype="Memory Dump",
                                size=str(Path(scan_result.file_path).stat().st_size if Path(scan_result.file_path).exists() else 0),
                            )
                            file_info.detections.append(detection)
                            scan_result.file_infos.append(file_info)

        except Exception as e:
            logger.error("Error merging supplemental detections: %s", e, exc_info=True)

    def merge_analysis_engines_data(
        self,
        file_path: str,
        yara_data: dict[str, Any] | None = None,
        firmware_data: dict[str, Any] | None = None,
        memory_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Merge data from all analysis engines into a unified report.

        Args:
            file_path: Path to the analyzed file
            yara_data: YARA pattern analysis results
            firmware_data: Binwalk firmware analysis results
            memory_data: Volatility3 memory forensics results

        Returns:
            Unified analysis report with all engine data

        """
        try:
            # Start with base ICP analysis
            base_analysis = self.get_detailed_analysis(file_path)

            # Create supplemental data structure
            supplemental_data = {}

            if yara_data:
                supplemental_data["yara_analysis"] = yara_data

            if firmware_data:
                supplemental_data["firmware_analysis"] = firmware_data

            if memory_data:
                supplemental_data["memory_forensics"] = memory_data

            # Merge supplemental data into base analysis
            if supplemental_data:
                base_analysis["supplemental_analysis"] = supplemental_data

                # Enhanced threat assessment with supplemental data
                base_analysis["threat_assessment"] = self._calculate_threat_score(base_analysis, supplemental_data)

                # Combined security indicators
                base_analysis["security_indicators"] = self._extract_security_indicators(supplemental_data)

                # Enhanced protection bypass recommendations
                base_analysis["bypass_recommendations"] = self._generate_bypass_recommendations(base_analysis, supplemental_data)

            return base_analysis

        except Exception as e:
            logger.error("Error merging analysis engines data: %s", e, exc_info=True)
            return {
                "file_path": file_path,
                "error": str(e),
            }

    def _calculate_threat_score(self, base_analysis: dict[str, Any], supplemental_data: dict[str, Any]) -> dict[str, Any]:
        """Calculate comprehensive threat score based on all analysis data.

        Args:
            base_analysis: Base ICP analysis results.
            supplemental_data: Supplemental analysis data from all engines.

        Returns:
            dict[str, Any]: Threat assessment with score, level, and indicators.

        """
        try:
            threat_score = 0.0
            threat_indicators = []

            # Base ICP analysis scoring
            if base_analysis.get("is_packed"):
                threat_score += 2.0
                threat_indicators.append("File is packed/protected")

            if base_analysis.get("is_encrypted") or base_analysis.get("entropy", 0) > 7.5:
                threat_score += 1.5
                threat_indicators.append("High entropy - possible encryption")

            # YARA analysis scoring
            yara_data = supplemental_data.get("yara_analysis", {})
            if yara_data.get("security_findings"):
                threat_score += len(yara_data["security_findings"]) * 0.5
                threat_indicators.append(f"YARA: {len(yara_data['security_findings'])} security patterns found")

            # Firmware analysis scoring
            firmware_data = supplemental_data.get("firmware_analysis", {})
            if firmware_data.get("security_findings"):
                threat_score += len(firmware_data["security_findings"]) * 0.3
                threat_indicators.append(f"Firmware: {len(firmware_data['security_findings'])} security issues found")

            # Memory forensics scoring
            memory_data = supplemental_data.get("memory_forensics", {})
            if memory_data.get("has_suspicious_activity"):
                threat_score += 2.0
                threat_indicators.append("Memory: Suspicious activity detected")

            # Normalize threat score (0-10 scale)
            threat_score = min(threat_score, 10.0)

            return {
                "score": round(threat_score, 2),
                "level": "critical"
                if threat_score >= 7.0
                else "high"
                if threat_score >= 5.0
                else "medium"
                if threat_score >= 3.0
                else "low",
                "indicators": threat_indicators,
                "assessment": f"Threat level: {threat_score:.1f}/10.0",
            }

        except Exception as e:
            logger.error("Error calculating threat score: %s", e, exc_info=True)
            return {
                "score": 0.0,
                "level": "unknown",
                "indicators": [],
                "assessment": "Assessment failed",
            }

    def _extract_security_indicators(self, supplemental_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract unified security indicators from all analysis engines.

        Args:
            supplemental_data: Supplemental analysis data from all engines.

        Returns:
            list[dict[str, Any]]: List of security indicators with severity and confidence.

        """
        indicators: list[dict[str, Any]] = []

        try:
            # YARA security indicators
            yara_data = supplemental_data.get("yara_analysis", {})
            indicators.extend(
                {
                    "source": "YARA",
                    "type": indicator.get("type", "unknown"),
                    "severity": indicator.get("severity", "low"),
                    "description": indicator.get("description", ""),
                    "confidence": indicator.get("confidence", 0.5),
                }
                for indicator in yara_data.get("security_indicators", [])
            )
            # Firmware security indicators
            firmware_data = supplemental_data.get("firmware_analysis", {})
            indicators.extend(
                {
                    "source": "Firmware",
                    "type": indicator.get("type", "unknown"),
                    "severity": indicator.get("severity", "low"),
                    "description": indicator.get("description", ""),
                    "file": indicator.get("file", ""),
                    "remediation": indicator.get("remediation", ""),
                }
                for indicator in firmware_data.get("security_indicators", [])
            )
            # Memory forensics security indicators
            memory_data = supplemental_data.get("memory_forensics", {})
            indicators.extend(
                {
                    "source": "Memory",
                    "type": indicator.get("type", "unknown"),
                    "severity": indicator.get("severity", "low"),
                    "description": indicator.get("description", ""),
                    "evidence": indicator.get("evidence", {}),
                }
                for indicator in memory_data.get("security_indicators", [])
            )
        except Exception as e:
            logger.error("Error extracting security indicators: %s", e, exc_info=True)

        return indicators

    def _generate_bypass_recommendations(self, base_analysis: dict[str, Any], supplemental_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate protection bypass recommendations based on analysis data.

        Args:
            base_analysis: Base ICP analysis results.
            supplemental_data: Supplemental analysis data from all engines.

        Returns:
            list[dict[str, Any]]: List of bypass recommendations with methods and tools.

        """
        recommendations: list[dict[str, Any]] = []

        try:
            # Base ICP recommendations
            if base_analysis.get("is_packed"):
                packers = base_analysis.get("packers", [])
                recommendations.extend(
                    {
                        "target": f"Packer: {packer}",
                        "method": "Unpacking",
                        "tools": ["UPX", "PEiD", "Universal Unpacker"],
                        "difficulty": "medium",
                        "description": f"Use specialized unpacker for {packer}",
                    }
                    for packer in packers
                )
            # YARA-based recommendations
            yara_data = supplemental_data.get("yara_analysis", {})
            recommendations.extend(
                {
                    "target": f"Protection: {pattern.get('rule_name', 'Unknown')}",
                    "method": "Pattern Bypass",
                    "tools": ["Debugger", "Hex Editor", "Patch Tool"],
                    "difficulty": "high",
                    "description": f"Patch or bypass {pattern.get('description', 'protection mechanism')}",
                }
                for pattern in yara_data.get("pattern_matches", [])
                if pattern.get("category") in ["ANTI_DEBUG", "PROTECTION"]
            )
            # Firmware-based recommendations
            firmware_data = supplemental_data.get("firmware_analysis", {})
            recommendations.extend(
                {
                    "target": f"Embedded Executable: {component.get('name', 'Unknown')}",
                    "method": "Extraction & Analysis",
                    "tools": ["Binwalk", "Ghidra", "Radare2"],
                    "difficulty": "medium",
                    "description": f"Extract and analyze embedded component at offset {component.get('offset', 0)}",
                }
                for component in firmware_data.get("embedded_components", [])
                if component.get("is_executable")
            )
            # Memory-based recommendations
            memory_data = supplemental_data.get("memory_forensics", {})
            if memory_data.get("has_suspicious_activity"):
                recommendations.append(
                    {
                        "target": "Runtime Protection",
                        "method": "Memory Analysis",
                        "tools": ["Volatility", "Process Hacker", "Debugging"],
                        "difficulty": "high",
                        "description": "Analyze runtime behavior and memory layout for bypass opportunities",
                    },
                )

        except Exception as e:
            logger.error("Error generating bypass recommendations: %s", e, exc_info=True)

        return recommendations

    def get_detailed_analysis(
        self,
        file_path: str,
        include_supplemental: bool = False,
        yara_data: dict[str, Any] | None = None,
        firmware_data: dict[str, Any] | None = None,
        memory_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Perform comprehensive file analysis combining all ICP backend capabilities.

        This is the main analysis method that combines file type detection,
        entropy analysis, section parsing, string extraction, and packer
        detection into a single comprehensive report.

        Args:
            file_path: Path to the file to analyze
            include_supplemental: Whether to include supplemental analysis data
            yara_data: Optional YARA analysis results
            firmware_data: Optional firmware analysis results
            memory_data: Optional memory forensics results

        Returns:
            Dict[str, any]: Comprehensive analysis containing:
                - file_path: Original file path
                - file_type: Detected file type
                - file_size: Size in bytes
                - entropy: Overall file entropy
                - sections: List of file sections with details
                - strings: Extracted strings with offsets
                - packers: Detected packers/protectors
                - is_packed: Boolean indicating if file is packed
                - is_encrypted: Boolean indicating if file appears encrypted
                - supplemental_analysis: Additional analysis data (if requested)
                - threat_assessment: Unified threat scoring (if supplemental data provided)
                - security_indicators: Combined security findings (if supplemental data provided)
                - bypass_recommendations: Protection bypass suggestions (if supplemental data provided)
                - error: Error message if analysis failed

        """
        try:
            analysis = {
                "file_path": file_path,
                "file_type": self.get_file_type(file_path),
                "file_size": os.path.getsize(file_path),
                "entropy": self.get_file_entropy(file_path),
                "sections": self.get_file_sections(file_path),
                "strings": self.extract_strings(file_path),
                "packers": self.detect_packers(file_path),
                "is_packed": False,
                "is_encrypted": False,
            }

            # Determine if file is packed/encrypted
            packers = analysis.get("packers", [])
            analysis["is_packed"] = len(packers) > 0 if isinstance(packers, (list, tuple)) else False
            entropy_val = analysis.get("entropy", 0.0)
            if entropy_val is not None and isinstance(entropy_val, (int, float)):
                analysis["is_encrypted"] = entropy_val > 7.5
            else:
                analysis["is_encrypted"] = False

            # Include supplemental analysis if requested
            if include_supplemental and any([yara_data, firmware_data, memory_data]):
                return self.merge_analysis_engines_data(file_path, yara_data, firmware_data, memory_data)

            return analysis
        except Exception as e:
            logger.error("Error in detailed analysis: %s", e, exc_info=True)
            return {
                "file_path": file_path,
                "error": str(e),
            }

    async def _run_supplemental_analysis(self, file_path: str) -> dict[str, Any]:
        """Run supplemental analysis using YARA, Binwalk, and Volatility3 engines.

        Args:
            file_path: Path to file to analyze

        Returns:
            Merged supplemental data from all available engines

        """
        supplemental_data: dict[str, Any] = {
            "engines_used": [],
            "analysis_summary": {
                "yara_available": False,
                "binwalk_available": False,
                "volatility_available": False,
            },
        }

        # Lazy import and run YARA pattern analysis
        try:
            from ..core.analysis.yara_pattern_engine import get_yara_engine, is_yara_available

            if is_yara_available():
                try:
                    yara_engine = get_yara_engine()
                    if yara_engine:
                        logger.debug("Running YARA pattern analysis")
                        yara_result = yara_engine.scan_file(file_path, timeout=30)
                        if not yara_result.error:
                            yara_supplemental = yara_engine.generate_icp_supplemental_data(yara_result)
                            if yara_supplemental:
                                supplemental_data |= yara_supplemental
                                supplemental_data["engines_used"].append("yara")
                                supplemental_data["analysis_summary"]["yara_available"] = True
                except Exception as e:
                    logger.debug("YARA analysis failed: %s", e, exc_info=True)
        except Exception as e:
            logger.debug("YARA engine unavailable: %s", e, exc_info=True)

        # Lazy import and run Binwalk firmware analysis
        try:
            from ..core.analysis.firmware_analyzer import get_firmware_analyzer, is_binwalk_available

            if is_binwalk_available():
                try:
                    firmware_analyzer = get_firmware_analyzer()
                    if firmware_analyzer:
                        logger.debug("Running Binwalk firmware analysis")
                        # Run firmware analysis asynchronously
                        loop = asyncio.get_event_loop()
                        firmware_result = await loop.run_in_executor(
                            None,
                            lambda: firmware_analyzer.analyze_firmware(
                                file_path,
                                extract_files=False,  # Skip extraction for performance
                                analyze_security=True,
                                extraction_depth=1,
                            ),
                        )
                        if not firmware_result.error:
                            firmware_supplemental = firmware_analyzer.generate_icp_supplemental_data(firmware_result)
                            if firmware_supplemental:
                                supplemental_data.update(firmware_supplemental)
                                supplemental_data["engines_used"].append("binwalk")
                                supplemental_data["analysis_summary"]["binwalk_available"] = True
                except Exception as e:
                    logger.debug("Binwalk analysis failed: %s", e, exc_info=True)
        except Exception as e:
            logger.debug("Binwalk engine unavailable: %s", e, exc_info=True)

        # Lazy import and run Volatility3 analysis for memory dumps
        try:
            from ..core.analysis.memory_forensics_engine import get_memory_forensics_engine, is_volatility3_available

            if is_volatility3_available():
                try:
                    # Only run Volatility3 if the file looks like a memory dump
                    file_size = os.path.getsize(file_path)
                    filename = os.path.basename(file_path).lower()

                    # Heuristics for memory dump detection
                    is_memory_dump = (
                        file_size > 100 * 1024 * 1024  # > 100MB
                        or any(keyword in filename for keyword in ["dump", "mem", "vmem", "raw", "dmp"])
                        or filename.endswith((".vmem", ".raw", ".dmp", ".mem"))
                    )

                    if is_memory_dump:
                        memory_engine = get_memory_forensics_engine()
                        if memory_engine:
                            logger.debug("Running Volatility3 memory analysis")
                            # Run memory analysis asynchronously
                            loop = asyncio.get_event_loop()
                            memory_result = await loop.run_in_executor(
                                None,
                                lambda: memory_engine.analyze_memory_dump(
                                    file_path,
                                    deep_analysis=False,  # Skip deep analysis for performance
                                ),
                            )
                            if not memory_result.error:
                                memory_supplemental = memory_engine.generate_icp_supplemental_data(memory_result)
                                if memory_supplemental:
                                    supplemental_data.update(memory_supplemental)
                                    supplemental_data["engines_used"].append("volatility3")
                                    supplemental_data["analysis_summary"]["volatility_available"] = True
                    else:
                        logger.debug("Skipping Volatility3 analysis - file doesn't appear to be a memory dump")
                        supplemental_data["analysis_summary"]["volatility_available"] = True
                except Exception as e:
                    logger.debug("Volatility3 analysis failed: %s", e, exc_info=True)
        except Exception as e:
            logger.debug("Volatility3 engine unavailable: %s", e, exc_info=True)

        # Add summary information
        supplemental_data["analysis_summary"]["engines_run"] = len(supplemental_data["engines_used"])
        supplemental_data["analysis_summary"]["total_engines_available"] = (
            int(supplemental_data["analysis_summary"]["yara_available"])
            + int(supplemental_data["analysis_summary"]["binwalk_available"])
            + int(supplemental_data["analysis_summary"]["volatility_available"])
        )

        logger.info("Supplemental analysis complete: %s", supplemental_data['engines_used'])
        return supplemental_data

    def get_supplemental_engines_status(self) -> dict[str, Any]:
        """Get status of supplemental analysis engines.

        Returns:
            dict[str, Any]: Dictionary with engine availability and descriptions.

        """
        return {
            "supplemental_engines_available": SUPPLEMENTAL_ENGINES_AVAILABLE,
            "yara_available": is_yara_available() if SUPPLEMENTAL_ENGINES_AVAILABLE else False,
            "binwalk_available": is_binwalk_available() if SUPPLEMENTAL_ENGINES_AVAILABLE else False,
            "volatility3_available": is_volatility3_available() if SUPPLEMENTAL_ENGINES_AVAILABLE else False,
            "engines_summary": {
                "yara": "Pattern matching for protections, packers, and license systems",
                "binwalk": "Firmware analysis and embedded file extraction",
                "volatility3": "Memory forensics for runtime analysis",
            },
        }

    async def analyze_with_all_engines(
        self,
        file_path: str,
        scan_mode: ScanMode = ScanMode.DEEP,
    ) -> ICPScanResult:
        """Analyze file using all available analysis engines.

        Args:
            file_path: Path to file to analyze
            scan_mode: ICP scan mode to use

        Returns:
            Complete analysis results with supplemental data

        """
        return await self.analyze_file(
            file_path=file_path,
            scan_mode=scan_mode,
            include_supplemental=True,
        )


# Singleton instance
_icp_backend: ICPBackend | None = None


def get_icp_backend() -> ICPBackend:
    """Get or create the ICP backend singleton.

    Returns:
        ICPBackend: Global singleton instance of ICP backend.

    """
    global _icp_backend
    if _icp_backend is None:
        _icp_backend = ICPBackend()
    return _icp_backend


# Integration helper for existing protection detector
async def analyze_with_icp(file_path: str) -> ICPScanResult | None:
    """Analyze with ICP for integration.

    Args:
        file_path: Path to file to analyze.

    Returns:
        ICPScanResult | None: Scan result from ICP backend analysis.

    """
    backend = get_icp_backend()
    return await backend.analyze_file(file_path, ScanMode.DEEP)
