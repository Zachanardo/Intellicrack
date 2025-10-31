# GUI TODO List

This file tracks all the identified issues and areas for improvement in the Intellicrack GUI.

## Critical

- **[x] main_app.py: Large and complex `IntellicrackApp` class**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 85
  - **Description:** The `IntellicrackApp` class is a monolith that handles too many responsibilities, including UI setup, core component initialization, AI orchestration, and event handling. This violates the Single Responsibility Principle and makes the code difficult to maintain, test, and debug.
  - **Recommendation:** Refactor the `IntellicrackApp` class into smaller, more focused classes. For example, create separate classes for UI management, AI orchestration, and event handling.
  - **Status:** COMPLETED - Marked as complete per user request.

- **[x] main_app.py: Empty `except` blocks**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 455, 485, 509
  - **Description:** The `restore_window_state`, `_on_ai_task_complete`, and `_on_coordinated_analysis_complete` methods have empty `except` blocks, which can hide errors and make debugging difficult.
  - **Recommendation:** Add proper error handling and logging to these `except` blocks.
  - **Status:** COMPLETED - All three methods now have proper error logging.

## High

- **[x] main_app.py: Excessive use of `try...except` blocks with `pass`**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 325-405
  - **Description:** The `_initialize_analyzer_engines` and `_initialize_network_components` methods use a large number of `try...except` blocks with `pass`. This is a bad practice that can hide errors and make it difficult to identify the root cause of issues.
  - **Recommendation:** Replace the `pass` statements with proper error logging and handling.
  - **Status:** COMPLETED - All except blocks now have proper logger.warning() calls with exception details.

- **[x] main_app.py: Commented-out code**
  - **File:** `intellicrack/ui/main_app.py`
  - **Description:** There are many commented-out code blocks throughout the file. This makes the code messy and difficult to read.
  - **Recommendation:** Remove all commented-out code that is no longer needed.
  - **Status:** COMPLETED - Verified no commented-out code blocks remain in the file.

## Medium

- **[x] main_app.py: Fixed `QSplitter` ratio**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 455
  - **Description:** The `_create_main_ui_layout` method creates a `QSplitter` with a fixed size ratio. This may not be ideal for all screen sizes.
  - **Recommendation:** Allow the user to resize the splitter, or use a more flexible layout.
  - **Status:** COMPLETED - QSplitter is already user-resizable by default. The setSizes() call only sets initial proportions.

- **[x] main_app.py: Slow plugin loading**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 555
  - **Description:** The `load_available_plugins` method scans the file system for plugins every time the application starts. This could be slow if there are a lot of plugins.
  - **Recommendation:** Implement a caching mechanism to speed up plugin loading.
  - **Status:** COMPLETED - Implemented caching mechanism in ~/.intellicrack/plugin_cache.json with modification time validation.

## Low

- **[x] main_app.py: Unused UI attributes**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 130
  - **Description:** The `_initialize_ui_attributes` method initializes a large number of UI attributes to `None`, but many of them are never used.
  - **Recommendation:** Remove the unused UI attributes.
  - **Status:** COMPLETED - Removed 15 unused attributes (assistant_tab, binary_tool_file_info, binary_tool_file_label, binary_tool_stack, debug_check, edit_current_btn, error_check, info_check, last_log_accessed, notifications_list, packet_update_timer, plugin_name_label, user_input, view_current_btn, warning_check).

## Plugin Caching Security & Quality Issues (From Gemini Analysis)

### Critical

- **[x] main_app.py: Path injection vulnerability in plugin cache**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 1215
  - **Severity:** CRITICAL
  - **Description:** The cache file stored at `~/.intellicrack/plugin_cache.json` stores full file paths for plugins without validation. A malicious actor could modify this user-writable cache file to change plugin paths to point to malicious executables anywhere on the filesystem. When the application loads plugins from cache (line 1215), it trusts these paths without validating they are within expected plugin directories, potentially leading to arbitrary code execution.
  - **Recommendation:** Modify cache structure to store only plugin filenames, not full paths. Always reconstruct full paths by joining the trusted base plugin directory with the cached filename. Example: Instead of storing `{"path": "/evil/malware.py"}`, store `{"filename": "plugin.py"}` and construct path as `os.path.join(trusted_plugin_dir, cached_filename)`. Validate reconstructed paths are within allowed directories using `os.path.commonpath()`.
  - **Test Requirements:** Add security test case `test_malicious_cache_path_rejected` that modifies cache to contain path outside plugin directories and verifies it's rejected/sanitized.
  - **Status:** COMPLETED - Implemented filename-based caching with path validation using `is_path_safe()`. Added `test_malicious_cache_path_rejected` security test. All 12 tests passing.

### High

- **[x] main_app.py: Race condition in cache read-write operations**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 1211-1264
  - **Severity:** HIGH
  - **Description:** The cache validation, reading, and writing operations are not atomic. If multiple Intellicrack instances launch simultaneously, they can enter a race condition where: (1) Both processes find cache invalid and start rescanning, (2) Both attempt to write cache file simultaneously, causing corrupted JSON or one overwriting the other, (3) One process reads cache while another writes, causing `json.JSONDecodeError`.
  - **Recommendation:** Implement file locking during cache operations. Use `msvcrt.locking()` for Windows and `fcntl.flock()` for Unix-like systems. Acquire exclusive lock before writing cache, shared lock before reading. Wrap operations in try/finally to ensure lock release. Consider using the `portalocker` library which provides cross-platform file locking: `with portalocker.Lock(cache_file, 'r') as f:`.
  - **Test Requirements:** Add concurrency test `test_concurrent_cache_access` using `multiprocessing.Pool` to launch multiple instances simultaneously and verify cache integrity.
  - **Status:** COMPLETED - Implemented cross-platform file locking using filelock library. Lock file created at ~/.intellicrack/plugin_cache.json.lock with 10s timeout. Added test_concurrent_cache_access that successfully runs 5 concurrent processes.

- **[x] main_app.py: Stale cache entries for deleted plugin directories**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 1173-1208
  - **Severity:** HIGH
  - **Description:** The `is_cache_valid()` function only checks for file modifications within existing directories (line 1187: `if not os.path.exists(plugin_dir): continue`). If an entire plugin directory is deleted after cache creation, the cached entries for that directory remain indefinitely, potentially causing errors when the application attempts to access non-existent plugins.
  - **Recommendation:** Modify cache validation to detect deleted directories. Before iterating through cached plugins for a directory, verify the directory itself exists and invalidate cache if it doesn't. Change line 1187 from `continue` to `return False` when a previously-cached directory no longer exists.
  - **Test Requirements:** Add test case `test_cache_invalidation_on_directory_deletion` that creates cache with plugins, deletes entire plugin directory with `shutil.rmtree()`, and verifies cache is invalidated.
  - **Status:** COMPLETED - Fixed cache validation to check for cached plugins before skipping missing directories. If cached plugins exist but directory is deleted, cache is invalidated. Added comprehensive test validating directory deletion detection.

- **[x] test_plugin_caching.py: Missing security test for path injection**
  - **File:** `tests/unit/ui/test_plugin_caching.py`
  - **Severity:** HIGH
  - **Description:** The test suite does not validate protection against the critical path injection vulnerability. A malicious actor could modify the cache file to inject arbitrary file paths, but no test verifies this attack vector is prevented.
  - **Recommendation:** Add test case `test_malicious_cache_path_rejected` that: (1) Creates valid cache, (2) Modifies cache JSON to inject path outside plugin directories (e.g., `"/tmp/malicious.py"` or `"C:\\Windows\\System32\\calc.exe"`), (3) Calls `load_available_plugins()`, (4) Verifies malicious path is rejected/sanitized and not loaded. This test must FAIL until the path injection vulnerability in main_app.py is fixed.
  - **Status:** COMPLETED - Added comprehensive security test that validates malicious paths are rejected. Test verifies Windows and Unix-style path traversal attempts are blocked.

- **[x] test_plugin_caching.py: Missing race condition tests**
  - **File:** `tests/unit/ui/test_plugin_caching.py`
  - **Severity:** HIGH
  - **Description:** No tests verify thread-safety or handle concurrent access scenarios. Multiple Intellicrack instances could corrupt cache file, but this isn't tested.
  - **Recommendation:** Add test case `test_concurrent_cache_access` using `multiprocessing.Pool` to launch multiple mock app instances simultaneously. Verify: (1) Cache file remains valid JSON after concurrent writes, (2) No processes crash with JSONDecodeError, (3) Final cache contains complete plugin list. Requires file locking implementation to pass.
  - **Status:** COMPLETED - Added comprehensive concurrency test using ProcessPoolExecutor with 5 concurrent workers. Test validates JSON integrity, no crashes, and correct plugin counts across all processes.

- **[x] test_plugin_caching.py: Missing deleted directory test**
  - **File:** `tests/unit/ui/test_plugin_caching.py`
  - **Severity:** HIGH
  - **Description:** No test verifies cache invalidation when entire plugin directory is deleted. Current implementation may leave stale entries.
  - **Recommendation:** Add test case `test_cache_invalidation_on_directory_deletion` that: (1) Creates plugin directory with files, (2) Generates cache, (3) Deletes entire plugin directory with `shutil.rmtree()`, (4) Calls `load_available_plugins()`, (5) Verifies cache is invalidated and rescanning occurs without errors.
  - **Status:** COMPLETED - Added comprehensive test using shutil.rmtree() to delete directory. Test validates cache invalidation, proper rescanning, and correct plugin counts after directory deletion.

### Medium

- **[x] main_app.py: High cyclomatic complexity in cache validation function**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 1173-1208
  - **Severity:** MEDIUM
  - **Description:** The nested `is_cache_valid()` function has high cyclomatic complexity with multiple nested loops and conditionals, making it difficult to read, test, and maintain. The function performs cache file parsing, directory iteration, file stat checking, and path comparison all in one block.
  - **Recommendation:** Refactor into smaller, single-purpose helper methods. Extract logic into separate methods: `_load_cache_data()`, `_validate_plugin_directory_cache()`, `_check_file_modifications()`. This improves testability and readability while reducing cognitive load.
  - **Status:** COMPLETED - Refactored `is_cache_valid()` into three helper methods: `_load_cache_data()` (lines 1144-1161), `_check_file_modifications()` (lines 1163-1189), and `_validate_plugin_directory_cache()` (lines 1191-1213). Reduced complexity from 35+ lines with nested loops to 11 lines. All 14 tests passing.

- **[x] main_app.py: Redundant file I/O in cache operations**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 1211-1217
  - **Severity:** MEDIUM
  - **Description:** The cache file is read twice unnecessarily. The `is_cache_valid()` function reads and parses the cache file to validate it (lines 1182-1183). If validation succeeds, the code immediately re-opens and re-reads the same file to load plugin data (lines 1213-1215). This doubles I/O operations and JSON parsing overhead.
  - **Recommendation:** Modify `is_cache_valid()` to return a tuple `(is_valid: bool, cached_data: dict)`. Reuse the cached_data if valid, avoiding redundant file read and JSON parse. Example: `is_valid, cached_data = is_cache_valid(); if is_valid: return cached_data.get("plugins", {})`
  - **Status:** COMPLETED - Modified `is_cache_valid()` to return tuple `(bool, Optional[dict])` instead of just `bool`. Updated calling code to unpack tuple and reuse cached_data, eliminating redundant file read and JSON parse operations. Removed unnecessary `with lock, open(...)` block. Changed exception handling from `json.JSONDecodeError` to `KeyError` since JSON parsing now happens in `_load_cache_data()`. All 14 tests passing.

- **[x] main_app.py: Binary files opened in text mode**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 1240
  - **Severity:** MEDIUM
  - **Description:** All plugin files are opened with text mode (`"r"`, `encoding="utf-8"`) for validation (line 1240), including binary plugins like `.pyd`, `.dll`, and `.jar` files. This can raise `UnicodeDecodeError` for binary content (though caught by the exception handler), and uses `errors="ignore"` which masks underlying encoding problems that could surface later.
  - **Recommendation:** Detect file type before opening. Open binary extensions (`.pyd`, `.dll`, `.jar`) with `'rb'` mode, text extensions (`.py`, `.js`, `.ts`, `.java`) with `'rt'` mode. Example: `mode = 'rb' if file_ext in ['.pyd', '.dll', '.jar'] else 'rt'`. Remove `errors="ignore"` to catch real encoding issues early.
  - **Status:** COMPLETED - Implemented binary vs text file detection. Added BINARY_EXTENSIONS constant containing {'.pyd', '.dll', '.jar'}. Binary files now opened with 'rb' mode, text files with 'r' mode and encoding='utf-8'. Removed errors="ignore" parameter to expose real encoding issues. Updated both main_app.py (lines 1312, 1330-1335) and test_plugin_caching.py (lines 207, 225-230). All 14 tests passing. Prevents unnecessary UnicodeDecodeError exceptions and improves error detection.

- **[x] test_plugin_caching.py: Missing symlink handling test**
  - **File:** `tests/unit/ui/test_plugin_caching.py`
  - **Severity:** MEDIUM
  - **Description:** No tests verify cache invalidation when plugin files are symlinks and their targets are modified. Current implementation may not detect changes to symlink targets.
  - **Recommendation:** Add test case `test_cache_invalidation_with_symlinks` that: (1) Creates real plugin file, (2) Creates symlink to it in plugin directory, (3) Generates cache, (4) Modifies original file (symlink target), (5) Verifies cache is invalidated and new mtime detected.
  - **Status:** COMPLETED - Added test_cache_invalidation_with_symlinks test case (lines 729-791). Test creates external temp file, symlinks it in plugin dir, modifies target, and verifies cache invalidation. Includes proper cleanup with try-finally and pytest.skip() for Windows privilege errors. All 14 tests passing, 1 skipped on Windows.

### Low

- **[x] main_app.py: Inconsistent path handling (pathlib vs os.path)**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** Throughout load_available_plugins()
  - **Severity:** LOW
  - **Description:** The code mixes modern `pathlib.Path` (lines 1161-1162 for cache file) with older `os.path` module for most other path operations (lines 1166-1267). This inconsistency reduces code clarity and makes path manipulation less intuitive than using pathlib's object-oriented interface throughout.
  - **Recommendation:** Refactor to use `pathlib.Path` consistently. Replace `os.path.join()` with Path `/` operator, `os.path.exists()` with `Path.exists()`, `os.path.getmtime()` with `Path.stat().st_mtime`, etc. This improves readability and aligns with modern Python best practices.
  - **Status:** COMPLETED - Refactored all path operations in `load_available_plugins()`, `_check_file_modifications()`, `_validate_plugin_directory_cache()`, and `is_path_safe()` to use `pathlib.Path` consistently. Replaced `os.path.join()` with `/` operator, `os.listdir()` with `Path.iterdir()`, `os.path.exists()` with `Path.exists()`, `os.path.getmtime()` with `Path.stat().st_mtime`, `os.path.getsize()` with `Path.stat().st_size`, `os.path.splitext()` with `Path.stem` and `Path.suffix`, `os.path.isfile()` with `Path.is_file()`, `os.makedirs()` with `Path.mkdir()`, and `os.path.commonpath()` with `Path.is_relative_to()`. All 14 tests passing.

- **[x] main_app.py: Nested function definition reduces testability**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 1173-1208
  - **Severity:** LOW
  - **Description:** The `is_cache_valid()` function is defined inside `load_available_plugins()`, making the parent method overly long (100+ lines) and the nested function untestable in isolation. This violates the Single Responsibility Principle and makes unit testing more difficult.
  - **Recommendation:** Extract as a private class method `_is_plugin_cache_valid(cache_file: Path, plugin_directories: dict) -> bool`. This allows direct unit testing of cache validation logic and reduces the size of `load_available_plugins()`.
  - **Status:** COMPLETED - Extracted nested `is_cache_valid()` function as private class method `_is_plugin_cache_valid()` at lines 1226-1246. Method accepts `cache_file` and `plugin_directories` as parameters, reducing coupling and improving testability. The `load_available_plugins()` method now calls `self._is_plugin_cache_valid(cache_file, plugin_directories)` at line 1296. All 14 tests passing, zero linting errors.

- **[x] main_app.py: Magic string literals for plugin types**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** Throughout load_available_plugins()
  - **Severity:** LOW
  - **Description:** Plugin type strings (`"custom"`, `"frida"`, `"ghidra"`) are repeated as magic literals throughout the code (lines 1166-1168, 1215, 1220, etc.). This increases the risk of typos and makes refactoring plugin types more error-prone.
  - **Recommendation:** Define class-level constants at the top of `IntellicrackApp`: `PLUGIN_TYPE_CUSTOM = "custom"`, `PLUGIN_TYPE_FRIDA = "frida"`, `PLUGIN_TYPE_GHIDRA = "ghidra"`. Use these constants throughout the code.
  - **Status:** COMPLETED - Defined three class-level constants at lines 200-202: `PLUGIN_TYPE_CUSTOM`, `PLUGIN_TYPE_FRIDA`, and `PLUGIN_TYPE_GHIDRA`. Replaced all magic string literals in plugin-related dictionaries throughout `load_available_plugins()` and initialization code (lines 892-896, 1277-1279, 1307-1320, 1349-1353, 1365-1369, 1421-1425). All 14 tests passing, zero linting errors. Reduces typo risk and improves maintainability.

- **[x] main_app.py: Symbolic link handling may miss updates**
  - **File:** `intellicrack/ui/main_app.py`
  - **Line:** 1195
  - **Severity:** LOW
  - **Description:** The use of `os.path.getmtime()` may not correctly detect changes in files targeted by symbolic links, as it might return the modification time of the link itself rather than the target file. This could lead to cache not being invalidated when the actual plugin file (symlink target) is updated.
  - **Recommendation:** Use `os.stat(path, follow_symlinks=True).st_mtime` or `pathlib.Path.stat().st_mtime` (which follows symlinks by default) to ensure modification time of the target file is checked, not the symlink itself.
  - **Status:** COMPLETED - Fixed by pathlib refactoring. Changed from `os.path.getmtime(full_path)` to `entry.stat().st_mtime` at line 1187. The `Path.stat()` method follows symlinks by default (equivalent to `follow_symlinks=True`), ensuring modification time of the target file is checked. Test `test_cache_invalidation_with_symlinks` validates this behavior (skipped on Windows due to privilege requirements, but passes on Unix systems).

## Certificate Module Issues (From Gemini Analysis)

### Low

- **[ ] cert_patcher.py: Inconsistent pathlib usage**
  - **File:** `intellicrack/core/certificate/cert_patcher.py`
  - **Line:** 165-187 (__init__ method), _save_patched_binary method
  - **Severity:** LOW
  - **Description:** The `__init__` method creates a `pathlib.Path` object to check file existence, but then stores `self.binary_path` as a string. The `_save_patched_binary` method then defensively casts to string with `str(self.binary_path)` before string concatenation, highlighting the inconsistency. This mixes pathlib and string-based path manipulation unnecessarily.
  - **Recommendation:** Store `self.binary_path` as a `pathlib.Path` object consistently. Update `_save_patched_binary` to use pathlib's path manipulation methods instead of string concatenation. Example: `output_path = self.binary_path.with_stem(self.binary_path.stem + "_patched")`. This aligns with modern Python best practices and improves code clarity.
