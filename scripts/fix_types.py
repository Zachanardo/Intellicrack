#!/usr/bin/env python3
"""Claude Type Error Auto-Fixer with AGENTIC Processing.

Uses Claude CLI with full tool access (Read, Edit, Bash) for true agentic control.
Claude reads files, makes edits, and verifies fixes - exactly like Claude Code.

Usage:
    # Test mode (3 files max)
    pixi run python fix_types.py --test

    # Full run with 5 parallel workers
    pixi run python fix_types.py --max-workers 5

    # Process specific directory
    pixi run python fix_types.py --target-dir intellicrack/utils
"""

import argparse
import contextlib
import logging
import os
import re
import secrets
import shutil
import subprocess  # noqa: S404
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("WARNING: 'rich' not installed. Install with: pip install rich")


def setup_logging(*, verbose: bool = False) -> logging.Logger:
    """Configure console logging with timestamps and levels."""
    logger = logging.getLogger("typefix")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    handler: logging.Handler
    if RICH_AVAILABLE:
        handler = RichHandler(
            show_time=True,
            show_path=False,
            rich_tracebacks=True,
            markup=True,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)-7s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ),
        )

    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(handler)
    return logger


def get_project_root(file_path: str) -> Path:
    """Find project root by looking for pyproject.toml or .git."""
    current = Path(file_path).resolve().parent
    while current != current.parent:
        if (current / "pyproject.toml").exists() or (current / ".git").exists():
            return current
        current = current.parent
    return Path.cwd()


LOG = setup_logging()
PROJECT_ROOT = get_project_root(__file__)
ERROR_PAYLOAD_DIR = PROJECT_ROOT / "temp"


def rollback_file(file_path: str, original_content: str | None, cwd: str) -> bool:
    """Rollback file changes with multiple fallback strategies."""
    result = subprocess.run(
        ["git", "checkout", "--", file_path],
        cwd=cwd,
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        return True

    if original_content is not None:
        try:
            with Path(file_path).open("w", encoding="utf-8") as f:
                f.write(original_content)
            return True
        except OSError:
            pass

    return False


def validate_model(model: str, claude_profile: str | None = None) -> bool:
    """Test model with trivial prompt at startup."""
    LOG.info("Validating model '%s'...", model)
    start_time = time.time()
    try:
        cmd = ["claude", "-p", "--model", model, "--max-turns", "1"]
        if claude_profile:
            cmd.extend(["--profile", claude_profile])
        result = subprocess.run(
            cmd,
            input="Say OK",
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        elapsed = time.time() - start_time
        if result.returncode == 0:
            LOG.info("Model validation OK (%.1fs)", elapsed)
            return True
        LOG.error("Model validation FAILED (exit code %d)", result.returncode)
        return False
    except subprocess.TimeoutExpired:
        LOG.warning("Model validation TIMEOUT after 30s")
        return False
    except FileNotFoundError:
        LOG.warning("Model validation FAILED - claude CLI not found in PATH")
        return False


def validate_errors_per_file(value: str) -> int:
    """Validate errors-per-file is within acceptable range or allow unlimited."""
    normalized = value.strip().lower()
    if normalized in {"0", "all", "unlimited"}:
        return 0
    ivalue = int(value)
    if not MIN_ERRORS_PER_FILE <= ivalue <= MAX_ERRORS_PER_FILE_LIMIT:
        raise argparse.ArgumentTypeError(f"Must be 10-500, got {ivalue}")
    return ivalue


def create_error_payload(file_path: str, errors: list[str]) -> Path:
    """Persist a truncated list of mypy errors to reduce CLI prompt size."""
    ERROR_PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe_stem = re.sub(r"[^A-Za-z0-9_-]", "_", Path(file_path).stem)
    payload_name = f"errors_{safe_stem}_{secrets.token_hex(4)}.txt"
    payload_path = ERROR_PAYLOAD_DIR / payload_name
    payload_path.write_text("\n".join(errors), encoding="utf-8")
    return payload_path


class BatchFailureTracker:
    """Track batch failures for adaptive backoff."""

    def __init__(self, worker_timeout: int) -> None:
        """Initialize the tracker with a worker timeout value."""
        self.worker_timeout = worker_timeout
        self.batch_results: list[bool] = []
        self.lock = threading.Lock()

    def record_result(self, *, success: bool, transient_error: bool = False) -> None:
        """Record a result. Only tracks transient errors (rate-limit, auth, CLI crash)."""
        with self.lock:
            self.batch_results.append(success or not transient_error)

    def should_pause_dispatcher(self) -> tuple[bool, int]:
        """Check if >=50% of last batch had transient failures."""
        with self.lock:
            if len(self.batch_results) < MIN_BATCH_SIZE:
                return False, 0
            failure_rate = self.batch_results.count(False) / len(self.batch_results)
            if failure_rate >= FAILURE_RATE_THRESHOLD:
                pause_time = min(self.worker_timeout, 120)
                self.batch_results.clear()
                return True, pause_time
            return False, 0

    def is_healthy(self) -> bool:
        """Check if success rate >= 70% (can resume normal cadence)."""
        with self.lock:
            if len(self.batch_results) < MIN_HEALTHY_BATCH_SIZE:
                return True
            success_rate = self.batch_results.count(True) / len(self.batch_results)
            if success_rate >= SUCCESS_RATE_THRESHOLD:
                self.batch_results.clear()
                return True
            return False


SYSTEM_PROMPT = """You are an elite Python type annotation specialist with deep expertise in mypy strict mode, PEP 484 (type hints), PEP 526 (variable annotations), PEP 604 (union syntax), and PEP 585 (generic types).

Your singular mission is to achieve zero mypy errors by fixing all type annotation issues - both missing annotations and type mismatches - while preserving all existing functionality.

## Core Responsibilities

1. **Fix Type Mismatches**: Resolve incompatible type errors by:
   - Correcting return type annotations to match actual return values
   - Fixing parameter type hints to accept the values actually passed
   - Widening types with unions where `None` or multiple types are valid
   - Adding type narrowing (isinstance, assert, if-checks) where needed

2. **Add Missing Annotations**: Achieve mypy strict compliance by adding:
   - Return type annotations to all functions and methods
   - Parameter type hints to all function arguments
   - Class attribute and instance variable annotations
   - Module-level variable type annotations

3. **Resolve Complex Type Issues**: Handle advanced typing scenarios:
   - Fix `[union-attr]` errors with proper None-checking or assertions
   - Resolve `[override]` errors by matching parent class signatures exactly
   - Fix `[arg-type]` errors with casts, type guards, or annotation corrections
   - Handle forward references with `from __future__ import annotations`

## Mypy Error Code Reference

**[no-untyped-def]** - Function missing type annotations
```python
# Before:
def process(data, offset):
    return data[offset:]
# After:
def process(data: bytes, offset: int) -> bytes:
    return data[offset:]
```

**[arg-type]** - Argument has incompatible type
```python
# Before (param expects str, got str | None):
name: str | None = get_name()
process_name(name)  # error: Argument 1 has incompatible type "str | None"; expected "str"
# After:
name: str | None = get_name()
if name is not None:
    process_name(name)
```

**[return-value]** - Incompatible return value type
```python
# Before:
def get_id(self) -> int:
    return self._id  # _id is int | None, error!
# After (Option 1 - widen return type):
def get_id(self) -> int | None:
    return self._id
# After (Option 2 - assert non-None):
def get_id(self) -> int:
    assert self._id is not None
    return self._id
```

**[union-attr]** - Item of union has no attribute X
```python
# Before:
result: str | None = fetch()
length = result.upper()  # error: Item "None" has no attribute "upper"
# After:
result: str | None = fetch()
length = result.upper() if result is not None else ""
```

**[assignment]** - Incompatible types in assignment
```python
# Before:
self._cache: dict[str, int] = None  # error: incompatible type "None"
# After:
self._cache: dict[str, int] | None = None
```

**[override]** - Signature incompatible with superclass
```python
# Before:
def process(self, data: bytes) -> None:  # parent has -> bool
# After:
def process(self, data: bytes) -> bool:  # match parent exactly
```

**[type-arg]** - Invalid type argument
```python
# Before:
items: list[str | int] = []
result: dict[items] = {}  # error: invalid type
# After:
items: list[str | int] = []
result: dict[str, Any] = {}
```

**[import]** / **[name-defined]** - Import or forward reference issues
```python
# Fix: Add at file top:
from __future__ import annotations
# Or use TYPE_CHECKING:
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from some_module import SomeClass
```

## Type Syntax Standards (Python 3.10+)

**REQUIRED syntax:**
- `X | None` not `Optional[X]`
- `list[str]` not `List[str]`
- `dict[str, int]` not `Dict[str, int]`
- `tuple[int, ...]` not `Tuple[int, ...]`
- `type[MyClass]` not `Type[MyClass]`

**Import from typing only for:**
- `Any`, `Callable`, `TypeVar`, `Protocol`, `Literal`, `Final`
- `cast`, `overload`, `TYPE_CHECKING`
- `Sequence`, `Mapping`, `Iterable` (abstract types)

## What You CAN Modify

- Function/method parameter type hints
- Function/method return type annotations
- Variable and attribute type annotations
- Import statements (add typing imports)
- Add `from __future__ import annotations` at file top
- Add `cast()` calls for type narrowing
- Add `assert` statements for None-checking
- Add `isinstance()` checks as type guards
- Add `if x is not None:` narrowing blocks

## What You CANNOT Modify

- Function logic or algorithms
- Variable values or computations
- String contents, f-strings, log messages
- Class inheritance or structure
- Method names or signatures (except types)
- Delete any existing code or methods

## ABSOLUTELY FORBIDDEN

- `# type: ignore` comments - NEVER ADD THESE
- `# noqa` comments - NEVER ADD THESE
- Changing actual program behavior
- Removing or stubbing out code
- Adding TODO or placeholder comments

If you add ANY `# type: ignore` comment, your work is INVALID and will be reverted.

## Fix Strategy

1. **Read all errors first** - Understand the full scope before editing
2. **Fix imports first** - Add `from __future__ import annotations` if forward refs exist
3. **Fix class attributes** - Annotate class-level variables before methods
4. **Fix methods top-to-bottom** - Work through the file systematically
5. **Handle dependencies** - Some errors resolve when others are fixed
6. **Verify each section** - After a batch of fixes, mentally verify before continuing

## Validation

After fixing, the file must pass:
```bash
mypy --strict <file_path> --show-error-codes --no-error-summary
```

Zero errors = success. Any remaining errors = continue fixing.

You have up to 100 turns. Use as many as needed. DO NOT STOP until every mypy error is resolved."""

MAX_ERRORS_PER_FILE = 100
MAX_ITERATIONS = 50
STALL_THRESHOLD = 3
MIN_ERRORS_PER_FILE = 10
MAX_ERRORS_PER_FILE_LIMIT = 500
MIN_BATCH_SIZE = 2
MIN_HEALTHY_BATCH_SIZE = 3
FAILURE_RATE_THRESHOLD = 0.5
SUCCESS_RATE_THRESHOLD = 0.7
STAGGER_DELAY_SECONDS = 3


class GlobalTypecheckState:
    """Serialized project-wide type checking to catch cross-file regressions."""

    def __init__(self, checker: str, target_dir: str, cwd: str, timeout: int = 600) -> None:
        """Initialize GlobalTypecheckState."""
        self.checker = checker
        self.target_dir = target_dir
        self.cwd = cwd
        self.timeout = timeout
        self._lock = threading.Lock()
        self._current_errors: int | None = None

    def initialize(self, errors: int) -> None:
        """Set the current error count baseline."""
        with self._lock:
            self._current_errors = errors

    def _run_type_checker(self) -> tuple[int, str] | tuple[None, str]:
        """Execute the configured type checker against the entire target directory."""
        if self.checker == "mypy":
            cmd = [
                sys.executable,
                "-m",
                "mypy",
                self.target_dir,
                "--show-column-numbers",
                "--show-error-codes",
                "--no-error-summary",
            ]
        else:
            cmd = [
                sys.executable,
                "-m",
                "pyright",
                self.target_dir,
            ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.cwd,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return None, f"Global type check failed: {exc}"

        output = (result.stdout or "") + (result.stderr or "")
        error_count = sum(
            1
            for line in output.splitlines()
            if "error:" in line.lower() or line.lower().startswith("error")
        )
        return error_count, output

    def validate_project(self) -> tuple[bool, int | None, str]:
        """Run a serialized project-wide check, rejecting any regression."""
        with self._lock:
            run_result = self._run_type_checker()
            if run_result[0] is None:
                return False, self._current_errors, run_result[1]

            error_count, output = run_result
            if self._current_errors is None or error_count <= self._current_errors:
                self._current_errors = error_count
                return True, error_count, output

            return False, error_count, output


def fix_file_agentically(  # noqa: PLR0914
    file_path: str,
    errors: list[str],
    cwd: str,
    model: str = "claude-3-5-haiku-20241022",
    timeout: int = 600,
    *,
    claude_profile: str | None = None,
    global_state: GlobalTypecheckState | None = None,
    errors_per_file: int = 0,
) -> dict[str, Any]:
    """Fix type errors in a single file using Claude CLI with full tool access."""
    thread_id = threading.current_thread().name
    file_name = Path(file_path).name
    start_time = time.time()
    LOG.info("[%s] START %s (%d errors)", thread_id, file_name, len(errors))

    original_content: str | None = None
    try:
        with Path(file_path).open(encoding="utf-8") as f:
            original_content = f.read()
    except OSError:
        pass

    claude_path = shutil.which("claude")
    if not claude_path:
        return {
            "file": file_path,
            "success": False,
            "error": "Claude CLI not found in PATH",
            "errors_count": len(errors),
            "git_diff": "",
            "mypy_before": 0,
            "mypy_after": 0,
            "errors_fixed": 0,
            "model": model,
            "transient_error": True,
        }

    payload_path: Path | None = None
    payload_errors = errors if errors_per_file == 0 else errors[:errors_per_file]
    try:
        payload_path = create_error_payload(file_path, payload_errors)
        LOG.debug("[%s] Created error payload: %s (%d errors)", thread_id, payload_path, len(payload_errors))
    except OSError as e:
        LOG.warning("[%s] Failed to create error payload for %s: %s", thread_id, file_name, e)
        payload_path = None

    omitted_count = max(0, len(errors) - len(payload_errors))
    if payload_path:
        if omitted_count:
            payload_instructions = f"The first {len(payload_errors)} mypy errors are recorded in {payload_path}."
        else:
            payload_instructions = f"All {len(payload_errors)} mypy errors are recorded in {payload_path}."
    else:
        if omitted_count:
            payload_instructions = f"The first {len(payload_errors)} mypy errors (shown below) must be fixed."
        else:
            payload_instructions = f"All {len(payload_errors)} mypy errors (shown below) must be fixed."
    if omitted_count:
        payload_instructions += f" There are {omitted_count} additional errors not listed; rerun mypy after applying the fixes."

    inline_errors = ""
    if not payload_path:
        inline_errors = "\n".join(f"  - {e}" for e in payload_errors)

    payload_ref = str(payload_path) if payload_path else "the errors listed above"
    prompt = f"""FIX ALL {len(payload_errors)} MYPY STRICT MODE ERRORS in {file_path}.

## Your Task

You must achieve ZERO mypy errors in this file. All {len(payload_errors)} errors must be fixed.

## Error Payload

{payload_instructions}
{inline_errors}

## Required Workflow

**Step 1: Read the errors**
Read {payload_ref} to see every mypy error with line numbers and error codes.

**Step 2: Read the source file**
Read {file_path} to understand the code structure and existing types.

**Step 3: Fix systematically**
Work through errors from first to last:
- Each error format: `file:line:col: error: [description] [error-code]`
- The error code in brackets (e.g., `[arg-type]`, `[return-value]`) tells you the fix category
- Fix all errors for one function/class before moving to the next

**Step 4: Continue until done**
After fixing all listed errors, you are done. Do not run mypy yourself - the orchestrator will verify.

## Error Codes Quick Reference

- `[no-untyped-def]` -> Add parameter types and return type to the function
- `[arg-type]` -> Add None-check, cast, or widen the parameter's type annotation
- `[return-value]` -> Change return annotation or add assertion before return
- `[union-attr]` -> Add `if x is not None:` or `assert x is not None`
- `[assignment]` -> Widen variable annotation (usually add `| None`)
- `[override]` -> Match parent class method signature exactly
- `[name-defined]` -> Add import or use `from __future__ import annotations`

## Rules

- Fix types, NOT logic - never change what the code actually does
- NO `# type: ignore` - fix properly or your work is reverted
- Use modern syntax: `X | None`, `list[str]`, `dict[str, int]`
- Add imports at file top if needed: `from typing import Any, Callable, cast`

## Begin Now

1. First: Read the error payload file at {payload_ref}
2. Then: Read {file_path}
3. Then: Start fixing with the Edit tool - make as many edits as needed
4. Continue until ALL {len(payload_errors)} errors are addressed

START NOW. Read the payload file first."""

    try:
        mypy_before = subprocess.run(
            [sys.executable, "-m", "mypy", file_path, "--show-error-codes", "--no-error-summary"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=cwd,
            check=False,
        )
        errors_before = len([line for line in mypy_before.stdout.split("\n") if "error:" in line.lower()])
    except (subprocess.TimeoutExpired, OSError):
        errors_before = len(errors)

    try:
        claude_cmd = [
            claude_path,
            "-p",
            "--model",
            model,
            "--system-prompt",
            SYSTEM_PROMPT,
            "--allowedTools",
            "Read,Edit,Bash",
            "--dangerously-skip-permissions",
            "--output-format",
            "text",
            "--max-turns",
            "100",
        ]
        if claude_profile:
            claude_cmd.extend(["--profile", claude_profile])

        LOG.debug("[%s] Sending prompt via stdin (%d chars)", thread_id, len(prompt))
        result = subprocess.run(
            claude_cmd,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )

        if result.returncode != 0:
            rollback_file(file_path, original_content, cwd)
            return {
                "file": file_path,
                "success": False,
                "error": f"Claude CLI failed: {result.stderr[:200] if result.stderr else 'unknown'}",
                "errors_count": len(errors),
                "git_diff": "",
                "mypy_before": errors_before,
                "mypy_after": errors_before,
                "errors_fixed": 0,
                "model": model,
                "transient_error": True,
            }

        syntax_check = subprocess.run(
            [sys.executable, "-c", f"import ast; ast.parse(open(r'{file_path}', encoding='utf-8').read())"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=cwd,
            check=False,
        )
        if syntax_check.returncode != 0:
            rollback_file(file_path, original_content, cwd)
            return {
                "file": file_path,
                "success": False,
                "error": f"Syntax error after edit - reverted: {syntax_check.stderr[:100]}",
                "errors_count": len(errors),
                "git_diff": "",
                "mypy_before": errors_before,
                "mypy_after": errors_before,
                "errors_fixed": 0,
                "model": model,
                "transient_error": False,
            }

        color_flag = "--color=always" if RICH_AVAILABLE else "--color=never"
        git_diff = subprocess.run(
            ["git", "diff", color_flag, file_path],
            capture_output=True,
            text=True,
            cwd=cwd,
            check=False,
        )

        mypy_after = subprocess.run(
            [sys.executable, "-m", "mypy", file_path, "--show-error-codes", "--no-error-summary"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=cwd,
            check=False,
        )
        errors_after = len([line for line in mypy_after.stdout.split("\n") if "error:" in line.lower()])

        if errors_after > errors_before + 2 or errors_after >= errors_before * 1.25:
            rollback_file(file_path, original_content, cwd)
            elapsed = time.time() - start_time
            LOG.warning("[%s] REGRESSION %s: %d -> %d errors (%.1fs)", thread_id, file_name, errors_before, errors_after, elapsed)
            return {
                "file": file_path,
                "success": False,
                "error": f"Regression: {errors_before} -> {errors_after} errors",
                "errors_count": len(errors),
                "git_diff": "",
                "mypy_before": errors_before,
                "mypy_after": errors_before,
                "errors_fixed": 0,
                "model": model,
                "transient_error": False,
            }

        if global_state:
            project_ok, project_errors, project_output = global_state.validate_project()
            if not project_ok:
                rollback_file(file_path, original_content, cwd)
                msg = "cross-file regression detected"
                if project_errors is not None:
                    msg += f" (project errors => {project_errors})"
                return {
                    "file": file_path,
                    "success": False,
                    "error": f"Project-level validation failed: {project_output[:200]} | {msg}",
                    "errors_count": len(errors),
                    "git_diff": "",
                    "mypy_before": errors_before,
                    "mypy_after": errors_before,
                    "errors_fixed": 0,
                    "model": model,
                    "transient_error": False,
                }

        elapsed = time.time() - start_time
        fixed_count = max(0, errors_before - errors_after)
        if fixed_count == 0:
            LOG.warning("[%s] NO CHANGES %s: %d -> %d (0 fixed) in %.1fs", thread_id, file_name, errors_before, errors_after, elapsed)
            LOG.debug("[%s] Claude output (first 500 chars): %s", thread_id, (result.stdout or "")[:500])
        else:
            LOG.info("[%s] DONE %s: %d -> %d (%d fixed) in %.1fs", thread_id, file_name, errors_before, errors_after, fixed_count, elapsed)
        return {
            "file": file_path,
            "success": True,
            "output": result.stdout[:2000] if result.stdout else "",
            "error": "",
            "errors_count": len(errors),
            "git_diff": git_diff.stdout if git_diff.returncode == 0 else "",
            "mypy_before": errors_before,
            "mypy_after": errors_after,
            "errors_fixed": max(0, errors_before - errors_after),
            "model": model,
            "transient_error": False,
        }
    except subprocess.TimeoutExpired:
        rollback_file(file_path, original_content, cwd)
        elapsed = time.time() - start_time
        LOG.warning("[%s] TIMEOUT %s after %.1fs", thread_id, file_name, elapsed)
        return {
            "file": file_path,
            "success": False,
            "error": f"Claude CLI timed out after {timeout}s",
            "errors_count": len(errors),
            "git_diff": "",
            "mypy_before": errors_before,
            "mypy_after": errors_before,
            "errors_fixed": 0,
            "model": model,
            "transient_error": True,
        }
    except Exception as e:
        rollback_file(file_path, original_content, cwd)
        return {
            "file": file_path,
            "success": False,
            "error": str(e)[:200],
            "errors_count": len(errors),
            "git_diff": "",
            "mypy_before": errors_before if "errors_before" in dir() else 0,
            "mypy_after": errors_before if "errors_before" in dir() else 0,
            "errors_fixed": 0,
            "model": model,
            "transient_error": True,
        }
    finally:
        if payload_path and payload_path.exists():
            with contextlib.suppress(OSError):
                payload_path.unlink()


class AgenticTypeFixer:
    """Agentic type error fixer - Claude uses tools directly to fix errors."""

    def __init__(
        self,
        checker: str = "mypy",
        target_dir: str = "intellicrack",
        max_workers: int = 3,
        max_files: int | None = None,
        model: str = "claude-3-5-haiku-20241022",
        timeout: int = 1200,
        *,
        show_diff: bool = True,
        claude_profile: str | None = None,
        max_iterations: int = 50,
        stall_threshold: int = 3,
        errors_per_file: int = 0,
        skip_global_check: bool = False,
    ) -> None:
        """Initialize the AgenticTypeFixer.

        Args:
            checker: Type checker to use ('mypy' or 'ruff').
            target_dir: Directory to scan for Python files.
            max_workers: Maximum concurrent workers for parallel processing.
            max_files: Maximum number of files to process (None for all).
            model: Claude model to use for fixes.
            timeout: Timeout in seconds for each file processing.
            show_diff: Whether to display git diffs after fixes.
            claude_profile: Claude CLI profile or credential alias.
            max_iterations: Maximum iterations before stopping.
            stall_threshold: Stop after N iterations with no progress.
            errors_per_file: Maximum errors to show Claude per file.
            skip_global_check: Skip per-file global typecheck for faster processing.

        """
        self.checker = checker
        self.target_dir = target_dir
        self.max_workers = max_workers
        self.max_files = max_files
        self.model = model
        self.show_diff = show_diff
        self.timeout = timeout
        self.cwd = os.getcwd()
        self.failure_tracker = BatchFailureTracker(timeout)
        self.claude_profile = claude_profile
        self.max_iterations = max_iterations
        self.stall_threshold = stall_threshold
        self.errors_per_file = errors_per_file
        self.skip_global_check = skip_global_check
        self.global_state: GlobalTypecheckState | None = None if skip_global_check else GlobalTypecheckState(
            checker=self.checker,
            target_dir=self.target_dir,
            cwd=self.cwd,
            timeout=max(180, min(self.timeout, 900)),
        )

        self.console: Console | None
        if RICH_AVAILABLE:
            self.console = Console()
        else:
            self.console = None

    def log(self, message: str, style: str = "") -> None:
        """Log a message."""
        if self.console and RICH_AVAILABLE:
            self.console.print(message, style=style)
        else:
            clean_msg = re.sub(r"\[/?[^\]]+\]", "", message)
            print(clean_msg)

    def run_type_checker(self) -> str:
        """Run type checker and return output."""
        self.log(f"\n[bold cyan]Running {self.checker} on {self.target_dir}...[/bold cyan]")

        try:
            if self.checker == "mypy":
                result = subprocess.run(
                    [sys.executable, "-m", "mypy", self.target_dir,
                     "--show-column-numbers", "--show-error-codes", "--no-error-summary"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
            else:
                result = subprocess.run(
                    [sys.executable, "-m", "pyright", self.target_dir],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            self.log("[red]Type checker timed out![/red]")
            return ""
        except FileNotFoundError:
            self.log(f"[red]{self.checker} not found. Is it installed?[/red]")
            return ""

    @staticmethod
    def group_errors_by_file(output: str) -> dict[str, list[str]]:
        """Group type errors by file path."""
        errors_by_file: dict[str, list[str]] = defaultdict(list)

        for line in output.split("\n"):
            line = line.strip()
            if "error:" in line.lower() and line:
                match = re.match(r"(.+?):(\d+)", line)
                if match:
                    filepath = match.group(1).strip()
                    if Path(filepath).exists():
                        errors_by_file[filepath].append(line)

        return dict(errors_by_file)

    def _process_files_batch(
        self,
        files_to_process: list[tuple[str, list[str]]],
    ) -> list[dict[str, Any]]:
        """Process a batch of files with the thread pool."""
        results: list[dict[str, Any]] = []

        if RICH_AVAILABLE:  # noqa: PLR1702
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Fixing files...", total=len(files_to_process))

                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures: dict[Any, str] = {}
                    for idx, (file_path, errors) in enumerate(files_to_process):
                        if idx > 0 and idx < self.max_workers:
                            time.sleep(STAGGER_DELAY_SECONDS)
                        future = executor.submit(
                            fix_file_agentically,
                            file_path,
                            errors,
                            self.cwd,
                            self.model,
                            self.timeout,
                            claude_profile=self.claude_profile,
                            global_state=self.global_state,
                            errors_per_file=self.errors_per_file,
                        )
                        futures[future] = file_path

                    for future in as_completed(futures):
                        file_path = futures[future]
                        try:
                            result = future.result()
                            results.append(result)
                            self.failure_tracker.record_result(
                                success=result.get("success", False),
                                transient_error=result.get("transient_error", False),
                            )
                            fixed = result.get("errors_fixed", 0)
                            before = result.get("mypy_before", 0)
                            after = result.get("mypy_after", 0)
                            status = "[green]OK[/green]" if result["success"] else "[red]FAIL[/red]"
                            progress.update(task, advance=1, description=f"{status} {Path(file_path).name}")

                            should_pause, pause_time = self.failure_tracker.should_pause_dispatcher()
                            if should_pause:
                                progress.stop()
                                self.log(f"[yellow]High failure rate detected. Pausing for {pause_time}s...[/yellow]")
                                time.sleep(pause_time)
                                progress.start()

                            if self.show_diff and result.get("git_diff"):
                                progress.stop()
                                self.log(f"\n[bold cyan]{'=' * 60}[/bold cyan]")
                                self.log(f"[bold]File: {file_path}[/bold]")
                                self.log(f"[cyan]Model: {result.get('model', self.model)}[/cyan]")
                                self.log(f"[yellow]Mypy errors: {before} -> {after} ({fixed} fixed)[/yellow]")
                                self.log("[bold cyan]Git Diff:[/bold cyan]")
                                print(result["git_diff"])
                                self.log(f"[bold cyan]{'=' * 60}[/bold cyan]\n")
                                progress.start()
                        except Exception as e:
                            results.append({
                                "file": file_path,
                                "success": False,
                                "error": str(e),
                                "transient_error": True,
                            })
                            self.failure_tracker.record_result(success=False, transient_error=True)
                            progress.update(task, advance=1)
        else:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                pending_futures: dict[Any, str] = {}
                for submit_idx, (file_path, errors) in enumerate(files_to_process):
                    if submit_idx > 0 and submit_idx < self.max_workers:
                        time.sleep(STAGGER_DELAY_SECONDS)
                    future = executor.submit(
                        fix_file_agentically,
                        file_path,
                        errors,
                        self.cwd,
                        self.model,
                        self.timeout,
                        claude_profile=self.claude_profile,
                        global_state=self.global_state,
                        errors_per_file=self.errors_per_file,
                    )
                    pending_futures[future] = file_path

                for idx, future in enumerate(as_completed(pending_futures), 1):
                    file_path = pending_futures[future]
                    try:
                        result = future.result()
                        results.append(result)
                        self.failure_tracker.record_result(
                            success=result.get("success", False),
                            transient_error=result.get("transient_error", False),
                        )
                        fixed = result.get("errors_fixed", 0)
                        before = result.get("mypy_before", 0)
                        after = result.get("mypy_after", 0)
                        status = "OK" if result["success"] else "FAIL"
                        LOG.info("[%d/%d] %s: %s (%d -> %d, %d fixed)", idx, len(files_to_process), status, Path(file_path).name, before, after, fixed)

                        should_pause, pause_time = self.failure_tracker.should_pause_dispatcher()
                        if should_pause:
                            LOG.warning("High failure rate detected. Pausing for %ds...", pause_time)
                            time.sleep(pause_time)

                        if self.show_diff and result.get("git_diff"):
                            LOG.info("Git Diff for %s:", file_path)
                            print(result["git_diff"])
                    except Exception:
                        results.append({
                            "file": file_path,
                            "success": False,
                            "error": "Unexpected exception",
                            "transient_error": True,
                        })
                        self.failure_tracker.record_result(success=False, transient_error=True)
                        LOG.exception("[%d/%d] ERROR: %s", idx, len(files_to_process), file_path)

        return results

    def run(self) -> dict[str, Any]:  # noqa: PLR0914
        """Run the agentic type fixer with iteration until all errors are fixed."""
        self.log("\n[bold green]Claude Agentic Type Fixer[/bold green]")
        self.log("[cyan]Claude uses Read/Edit/Bash tools directly.[/cyan]")
        self.log(f"[cyan]Model: {self.model}[/cyan]")
        self.log(f"[cyan]Type Checker: {self.checker}[/cyan]")
        self.log(f"[cyan]Target: {self.target_dir}[/cyan]")
        self.log(f"[cyan]Parallel Workers: {self.max_workers}[/cyan]")
        self.log(f"[cyan]Timeout per file: {self.timeout}s[/cyan]")
        self.log(f"[cyan]Max Iterations: {self.max_iterations}[/cyan]")
        if self.max_files:
            self.log(f"[cyan]Max Files per iteration: {self.max_files}[/cyan]")
        self.log("")

        iteration = 0
        total_fixed_all_iterations = 0
        total_files_processed = 0
        stall_count = 0
        previous_error_count = float("inf")
        error_history: list[int] = []

        while iteration < self.max_iterations:
            iteration += 1
            self.log(f"\n[bold magenta]{'=' * 60}[/bold magenta]")
            self.log(f"[bold magenta]  ITERATION {iteration} / {self.max_iterations}[/bold magenta]")
            self.log(f"[bold magenta]{'=' * 60}[/bold magenta]\n")

            output = self.run_type_checker()
            errors_by_file = self.group_errors_by_file(output)

            if not errors_by_file:
                self.log("[bold green]SUCCESS! No type errors remaining![/bold green]")
                break

            total_errors = sum(len(errs) for errs in errors_by_file.values())
            error_history.append(total_errors)
            self.log(f"[bold yellow]Found {total_errors} errors in {len(errors_by_file)} files[/bold yellow]")
            if self.global_state is not None:
                self.global_state.initialize(total_errors)

            if total_errors >= previous_error_count:
                stall_count += 1
                self.log(f"[yellow]No progress detected (stall count: {stall_count}/{self.stall_threshold})[/yellow]")
                if stall_count >= self.stall_threshold:
                    self.log(f"[red]Stopping: No progress for {self.stall_threshold} iterations[/red]")
                    break
            else:
                stall_count = 0
                reduction = previous_error_count - total_errors
                if previous_error_count != float("inf"):
                    pct = reduction / previous_error_count * 100
                    self.log(f"[green]Progress: Reduced by {reduction} errors ({pct:.1f}%)[/green]")

            previous_error_count = total_errors

            files_to_process = sorted(
                errors_by_file.items(),
                key=lambda x: len(x[1]),
                reverse=True,
            )

            if self.max_files:
                files_to_process = files_to_process[:self.max_files]
                self.log(f"[cyan]Processing {len(files_to_process)} of {len(errors_by_file)} files this iteration[/cyan]\n")
            else:
                self.log(f"[cyan]Processing all {len(files_to_process)} files[/cyan]\n")

            results = self._process_files_batch(files_to_process)

            successful = sum(1 for r in results if r.get("success"))
            failed = len(results) - successful
            iteration_fixed = sum(r.get("errors_fixed", 0) for r in results)
            total_fixed_all_iterations += iteration_fixed
            total_files_processed += len(files_to_process)

            self.log(f"\n[bold cyan]Iteration {iteration} Summary:[/bold cyan]")
            self.log(f"  Files processed: {successful}/{len(files_to_process)}")
            self.log(f"  Errors fixed this iteration: {iteration_fixed}")
            self.log(f"  Total errors fixed so far: {total_fixed_all_iterations}")

            if failed > 0:
                self.log("\n[yellow]Failed files this iteration:[/yellow]")
                for r in results:
                    if not r.get("success"):
                        self.log(f"  - {r.get('file')}: {r.get('error', 'Unknown error')[:80]}")

        self.log(f"\n[bold green]{'=' * 60}[/bold green]")
        self.log("[bold green]  FINAL RESULTS[/bold green]")
        self.log(f"[bold green]{'=' * 60}[/bold green]\n")

        final_output = self.run_type_checker()
        final_errors_by_file = self.group_errors_by_file(final_output)
        final_error_count = sum(len(errs) for errs in final_errors_by_file.values())

        if RICH_AVAILABLE and self.console:
            table = Table(title="Final Results Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Model Used", self.model)
            table.add_row("Total Iterations", str(iteration))
            table.add_row("Total Files Processed", str(total_files_processed))
            table.add_row("Total Errors Fixed", str(total_fixed_all_iterations))
            table.add_row("Remaining Errors", str(final_error_count))
            if error_history:
                table.add_row("Starting Errors", str(error_history[0]))
                if error_history[0] > 0:
                    reduction_pct = (1 - final_error_count / error_history[0]) * 100
                    table.add_row("Reduction", f"{reduction_pct:.1f}%")
            self.console.print(table)

            if error_history:
                self.log("\n[bold cyan]Error History:[/bold cyan]")
                for i, count in enumerate(error_history, 1):
                    self.log(f"  Iteration {i}: {count} errors")
                self.log(f"  Final: {final_error_count} errors")
        else:
            LOG.info("Model: %s", self.model)
            LOG.info("Iterations: %d", iteration)
            LOG.info("Files Processed: %d", total_files_processed)
            LOG.info("Errors Fixed: %d", total_fixed_all_iterations)
            LOG.info("Remaining Errors: %d", final_error_count)

        return {
            "total_iterations": iteration,
            "total_files_processed": total_files_processed,
            "total_errors_fixed": total_fixed_all_iterations,
            "remaining_errors": final_error_count,
            "error_history": error_history,
            "model": self.model,
        }


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Claude Agentic Type Error Fixer - Claude uses tools directly",
    )

    parser.add_argument(
        "--test", action="store_true",
        help="Test mode: process only 3 files",
    )
    parser.add_argument(
        "--checker", choices=["mypy", "pyright"], default="mypy",
        help="Type checker to use (default: mypy)",
    )
    parser.add_argument(
        "--target-dir", default="intellicrack",
        help="Directory to check (default: intellicrack)",
    )
    parser.add_argument(
        "--max-workers", type=int, default=3,
        help="Parallel Claude CLI instances (default: 3)",
    )
    parser.add_argument(
        "--max-files", type=int, default=None,
        help="Maximum files to process (default: all)",
    )
    parser.add_argument(
        "--model", default="claude-3-5-haiku-20241022",
        help="Claude model to use (default: claude-3-5-haiku-20241022)",
    )
    parser.add_argument(
        "--claude-profile",
        default=None,
        help="Claude CLI profile or credential alias to use",
    )
    parser.add_argument(
        "--no-diff", action="store_true",
        help="Disable live git diff output",
    )
    parser.add_argument(
        "--timeout", type=int, default=1200,
        help="Timeout per file in seconds (default: 1200 = 20 minutes)",
    )
    parser.add_argument(
        "--max-iterations", type=int, default=50,
        help="Maximum iterations before stopping (default: 50)",
    )
    parser.add_argument(
        "--stall-threshold", type=int, default=3,
        help="Stop after N iterations with no progress (default: 3)",
    )
    parser.add_argument(
        "--errors-per-file",
        type=validate_errors_per_file,
        default=0,
        metavar="10-500|all",
        help="Maximum errors to record per file (use 10-500 or 'all'/0 for every error; default: all)",
    )
    parser.add_argument(
        "--skip-global-check", action="store_true",
        help="Skip per-file global typecheck (faster but may miss cross-file regressions)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose (DEBUG level) logging output",
    )

    args = parser.parse_args()

    global LOG  # noqa: PLW0603
    LOG = setup_logging(verbose=args.verbose)

    LOG.info("Checking Claude CLI availability...")
    claude_check = subprocess.run(
        ["claude", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if claude_check.returncode != 0:
        LOG.error("Claude CLI not found!")
        LOG.error("Install: npm install -g @anthropic-ai/claude-code")
        LOG.error("Then authenticate: claude auth login")
        sys.exit(1)
    LOG.info("Claude CLI version: %s", claude_check.stdout.strip().split("\n")[0] if claude_check.stdout else "unknown")

    if not validate_model(args.model, args.claude_profile):
        LOG.error("Model '%s' is invalid or unavailable", args.model)
        LOG.error("Valid models: sonnet, opus, haiku, or full slugs like claude-3-5-haiku-20241022")
        sys.exit(1)

    if args.test:
        args.max_files = 3
        args.max_workers = 2
        LOG.info("TEST MODE: Processing 3 files max with 2 workers")

    fixer = AgenticTypeFixer(
        checker=args.checker,
        target_dir=args.target_dir,
        max_workers=args.max_workers,
        max_files=args.max_files,
        model=args.model,
        show_diff=not args.no_diff,
        timeout=args.timeout,
        claude_profile=args.claude_profile,
        max_iterations=args.max_iterations,
        stall_threshold=args.stall_threshold,
        errors_per_file=args.errors_per_file,
        skip_global_check=args.skip_global_check,
    )

    run_start = time.time()
    results = fixer.run()
    run_elapsed = time.time() - run_start

    LOG.info("Total run time: %.1f seconds (%.1f minutes)", run_elapsed, run_elapsed / 60)
    if results.get("remaining_errors", 0) == 0:
        LOG.info("SUCCESS: All type errors have been fixed!")
    else:
        LOG.info("%d errors remaining after %d iterations", results.get("remaining_errors", 0), results.get("total_iterations", 0))
        LOG.info("Total errors fixed: %d", results.get("total_errors_fixed", 0))


if __name__ == "__main__":
    main()
