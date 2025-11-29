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
import os
import re
import shutil
import subprocess  # noqa: S404
import sys
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


try:
    from rich.console import Console
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("WARNING: 'rich' not installed. Install with: pip install rich")


def get_project_root(file_path: str) -> Path:
    """Find project root by looking for pyproject.toml or .git."""
    current = Path(file_path).resolve().parent
    while current != current.parent:
        if (current / "pyproject.toml").exists() or (current / ".git").exists():
            return current
        current = current.parent
    return Path.cwd()


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
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(original_content)
            return True
        except OSError:
            pass

    return False


def validate_model(model: str, claude_profile: str | None = None) -> bool:
    """Test model with trivial prompt at startup."""
    print(f"Validating model '{model}'...", end=" ", flush=True)
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
        if result.returncode == 0:
            print("OK")
            return True
        print("FAILED")
        return False
    except subprocess.TimeoutExpired:
        print("TIMEOUT")
        return False
    except FileNotFoundError:
        print("FAILED (claude not found)")
        return False


def validate_errors_per_file(value: str) -> int:
    """Validate errors-per-file is within acceptable range (10-500)."""
    ivalue = int(value)
    if not MIN_ERRORS_PER_FILE <= ivalue <= MAX_ERRORS_PER_FILE_LIMIT:
        raise argparse.ArgumentTypeError(f"Must be 10-500, got {ivalue}")
    return ivalue


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


SYSTEM_PROMPT = """You are a Python type annotation expert. Your ONLY task is to add/fix TYPE ANNOTATIONS.

SCOPE - READ CAREFULLY:
- You may ONLY modify type hints and type-related imports
- DO NOT touch logging statements, f-strings, variable names, logic, or anything else
- DO NOT refactor, clean up, or "improve" code in any way
- If you see other issues (logging, style, etc.) - IGNORE THEM COMPLETELY

WHAT YOU CAN CHANGE:
- Function parameter type hints: `def foo(x: int) -> str:`
- Variable annotations: `my_var: list[str] = []`
- Import statements for types: `from typing import ...`
- `from __future__ import annotations` for forward refs

WHAT YOU CANNOT CHANGE:
- Logging calls (leave f-strings in logging ALONE)
- Function logic or implementation
- Variable names or values
- Comments (except adding type-related ones)
- Anything not directly related to type annotations

TYPE SYNTAX (Python 3.10+):
- `X | None` for Optional
- `list[str]` not `List[str]`
- `dict[str, int]` not `Dict[str, int]`
- `collections.abc.Callable[[Args], Return]` for callables

FORBIDDEN:
- `# type: ignore` - NEVER USE
- `# noqa` - NEVER USE
- `typing.Any` as lazy fix
- Changing ANYTHING except type annotations

Fix ONLY the specific mypy errors listed. Nothing else."""

MAX_ERRORS_PER_FILE = 100
MAX_ITERATIONS = 50
STALL_THRESHOLD = 3
MIN_ERRORS_PER_FILE = 10
MAX_ERRORS_PER_FILE_LIMIT = 500
MIN_BATCH_SIZE = 2
MIN_HEALTHY_BATCH_SIZE = 3
FAILURE_RATE_THRESHOLD = 0.5
SUCCESS_RATE_THRESHOLD = 0.7


class GlobalTypecheckState:
    """Serialized project-wide type checking to catch cross-file regressions."""

    def __init__(self, checker: str, target_dir: str, cwd: str, timeout: int = 600) -> None:
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


def fix_file_agentically(
    file_path: str,
    errors: list[str],
    cwd: str,
    model: str = "claude-sonnet-4-5-20250929",
    timeout: int = 600,
    *,
    claude_profile: str | None = None,
    global_state: GlobalTypecheckState | None = None,
) -> dict[str, Any]:
    """Fix type errors in a single file using Claude CLI with full tool access."""
    thread_id = threading.current_thread().name
    print(f"[{thread_id}] STARTING: {Path(file_path).name}", flush=True)

    original_content: str | None = None
    try:
        with open(file_path, encoding="utf-8") as f:
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

    errors_text = "\n".join(f"  - {e}" for e in errors[:MAX_ERRORS_PER_FILE])
    if len(errors) > MAX_ERRORS_PER_FILE:
        errors_text += f"\n  ... and {len(errors) - MAX_ERRORS_PER_FILE} more errors"

    prompt = f"""Fix ONLY these specific type errors in {file_path}:

{errors_text}

CRITICAL INSTRUCTIONS:
1. ONLY fix the type errors listed above - nothing else
2. DO NOT change logging statements, f-strings, or any other code
3. DO NOT refactor or "improve" anything
4. ONLY add/modify type annotations to resolve the listed mypy errors
5. Each error shows: file:line:col: error: [description] [error-code]

Use Read to see the file, then Edit to add type hints at the specific lines listed."""

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
            prompt,
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

        result = subprocess.run(
            claude_cmd,
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
            print(f"[{thread_id}] REGRESSION: {Path(file_path).name} ({errors_before} -> {errors_after})", flush=True)
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

        print(f"[{thread_id}] FINISHED: {Path(file_path).name} (fixed {max(0, errors_before - errors_after)})", flush=True)
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
        print(f"[{thread_id}] TIMEOUT: {Path(file_path).name}", flush=True)
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


class AgenticTypeFixer:
    """Agentic type error fixer - Claude uses tools directly to fix errors."""

    def __init__(
        self,
        checker: str = "mypy",
        target_dir: str = "intellicrack",
        max_workers: int = 3,
        max_files: int | None = None,
        model: str = "claude-sonnet-4-5-20250929",
        timeout: int = 1200,
        *,
        show_diff: bool = True,
        claude_profile: str | None = None,
    ) -> None:
        """Initialize the AgenticTypeFixer.

        Args:
            checker: Type checker to use ('mypy' or 'ruff').
            target_dir: Directory to scan for Python files.
            max_workers: Maximum concurrent workers for parallel processing.
            max_files: Maximum number of files to process (None for all).
            model: Claude model to use for fixes.
            show_diff: Whether to display git diffs after fixes.
            timeout: Timeout in seconds for each file processing.

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
        self.global_state = GlobalTypecheckState(
            checker=self.checker,
            target_dir=self.target_dir,
            cwd=self.cwd,
            timeout=max(180, min(self.timeout, 900)),
        )

        if RICH_AVAILABLE:
            self.console = Console()
        else:
            self.console = None

    def log(self, message: str, style: str = "") -> None:
        """Log a message."""
        if self.console and RICH_AVAILABLE:
            self.console.print(message, style=style)
        else:
            clean_msg = re.sub(r'\[/?[^\]]+\]', '', message)
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
                    futures = {
                        executor.submit(
                            fix_file_agentically,
                            file_path,
                            errors,
                            self.cwd,
                            self.model,
                            self.timeout,
                            claude_profile=self.claude_profile,
                            global_state=self.global_state,
                        ): file_path
                        for file_path, errors in files_to_process
                    }

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
                                import time
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
                futures = {
                    executor.submit(
                        fix_file_agentically,
                        file_path,
                        errors,
                        self.cwd,
                        self.model,
                        self.timeout,
                        claude_profile=self.claude_profile,
                        global_state=self.global_state,
                    ): file_path
                    for file_path, errors in files_to_process
                }

                for idx, future in enumerate(as_completed(futures), 1):
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
                        status = "OK" if result["success"] else "FAIL"
                        print(f"[{idx}/{len(files_to_process)}] {status}: {file_path}")
                        print(f"    Model: {result.get('model', self.model)}")
                        print(f"    Mypy: {before} -> {after} ({fixed} fixed)")

                        should_pause, pause_time = self.failure_tracker.should_pause_dispatcher()
                        if should_pause:
                            print(f"High failure rate detected. Pausing for {pause_time}s...")
                            import time
                            time.sleep(pause_time)

                        if self.show_diff and result.get("git_diff"):
                            print(f"\n{'=' * 60}")
                            print(f"Git Diff for {file_path}:")
                            print(result["git_diff"])
                            print(f"{'=' * 60}\n")
                    except Exception as e:
                        results.append({
                            "file": file_path,
                            "success": False,
                            "error": str(e),
                            "transient_error": True,
                        })
                        self.failure_tracker.record_result(success=False, transient_error=True)
                        print(f"[{idx}/{len(files_to_process)}] ERROR: {file_path}")

        return results

    def run(self) -> dict[str, Any]:  # noqa: PLR0914
        """Run the agentic type fixer with iteration until all errors are fixed."""
        self.log("\n[bold green]Claude Agentic Type Fixer[/bold green]")
        self.log("[cyan]Mode: AGENTIC (Claude uses Read/Edit/Bash tools directly)[/cyan]")
        self.log(f"[cyan]Model: {self.model}[/cyan]")
        self.log(f"[cyan]Type Checker: {self.checker}[/cyan]")
        self.log(f"[cyan]Target: {self.target_dir}[/cyan]")
        self.log(f"[cyan]Parallel Workers: {self.max_workers}[/cyan]")
        self.log(f"[cyan]Timeout per file: {self.timeout}s[/cyan]")
        self.log(f"[cyan]Max Iterations: {MAX_ITERATIONS}[/cyan]")
        if self.max_files:
            self.log(f"[cyan]Max Files per iteration: {self.max_files}[/cyan]")
        self.log("")

        iteration = 0
        total_fixed_all_iterations = 0
        total_files_processed = 0
        stall_count = 0
        previous_error_count = float('inf')
        error_history: list[int] = []

        while iteration < MAX_ITERATIONS:
            iteration += 1
            self.log(f"\n[bold magenta]{'=' * 60}[/bold magenta]")
            self.log(f"[bold magenta]  ITERATION {iteration} / {MAX_ITERATIONS}[/bold magenta]")
            self.log(f"[bold magenta]{'=' * 60}[/bold magenta]\n")

            output = self.run_type_checker()
            errors_by_file = self.group_errors_by_file(output)

            if not errors_by_file:
                self.log("[bold green]SUCCESS! No type errors remaining![/bold green]")
                break

            total_errors = sum(len(errs) for errs in errors_by_file.values())
            error_history.append(total_errors)
            self.log(f"[bold yellow]Found {total_errors} errors in {len(errors_by_file)} files[/bold yellow]")
            self.global_state.initialize(total_errors)

            if total_errors >= previous_error_count:
                stall_count += 1
                self.log(f"[yellow]No progress detected (stall count: {stall_count}/{STALL_THRESHOLD})[/yellow]")
                if stall_count >= STALL_THRESHOLD:
                    self.log(f"[red]Stopping: No progress for {STALL_THRESHOLD} iterations[/red]")
                    break
            else:
                stall_count = 0
                reduction = previous_error_count - total_errors
                if previous_error_count != float('inf'):
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
            print(f"\nModel: {self.model}")
            print(f"Iterations: {iteration}")
            print(f"Files Processed: {total_files_processed}")
            print(f"Errors Fixed: {total_fixed_all_iterations}")
            print(f"Remaining Errors: {final_error_count}")

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
        help="Test mode: process only 3 files"
    )
    parser.add_argument(
        "--checker", choices=["mypy", "pyright"], default="mypy",
        help="Type checker to use (default: mypy)"
    )
    parser.add_argument(
        "--target-dir", default="intellicrack",
        help="Directory to check (default: intellicrack)"
    )
    parser.add_argument(
        "--max-workers", type=int, default=3,
        help="Parallel Claude CLI instances (default: 3)"
    )
    parser.add_argument(
        "--max-files", type=int, default=None,
        help="Maximum files to process (default: all)"
    )
    parser.add_argument(
        "--model", default="claude-sonnet-4-5-20250929",
        help="Claude model to use (default: claude-sonnet-4-5-20250929)"
    )
    parser.add_argument(
        "--claude-profile",
        default=None,
        help="Claude CLI profile or credential alias to use",
    )
    parser.add_argument(
        "--no-diff", action="store_true",
        help="Disable live git diff output"
    )
    parser.add_argument(
        "--timeout", type=int, default=1200,
        help="Timeout per file in seconds (default: 1200 = 20 minutes)"
    )
    parser.add_argument(
        "--max-iterations", type=int, default=50,
        help="Maximum iterations before stopping (default: 50)"
    )
    parser.add_argument(
        "--stall-threshold", type=int, default=3,
        help="Stop after N iterations with no progress (default: 3)"
    )
    parser.add_argument(
        "--errors-per-file", type=validate_errors_per_file, default=100,
        metavar="10-500",
        help="Maximum errors to show Claude per file (10-500, default: 100)"
    )

    args = parser.parse_args()

    claude_check = subprocess.run(
        ["claude", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if claude_check.returncode != 0:
        print("ERROR: Claude CLI not found!")
        print("")
        print("Install Claude CLI:")
        print("  npm install -g @anthropic-ai/claude-code")
        print("")
        print("Then authenticate:")
        print("  claude auth login")
        sys.exit(1)

    if not validate_model(args.model, args.claude_profile):
        print(f"ERROR: Model '{args.model}' is invalid or unavailable")
        print("Valid models: sonnet, opus, haiku, or full slugs like claude-sonnet-4-5-20250929")
        sys.exit(1)

    if args.test:
        args.max_files = 3
        args.max_workers = 2
        print("TEST MODE: Processing 3 files max with 2 workers\n")

    fixer = AgenticTypeFixer(
        checker=args.checker,
        target_dir=args.target_dir,
        max_workers=args.max_workers,
        max_files=args.max_files,
        model=args.model,
        show_diff=not args.no_diff,
        timeout=args.timeout,
        claude_profile=args.claude_profile,
    )

    results = fixer.run()

    if results.get("remaining_errors", 0) == 0:
        print("\n[SUCCESS] All type errors have been fixed!")
    else:
        print(f"\n[INFO] {results.get('remaining_errors', 0)} errors remaining after {results.get('total_iterations', 0)} iterations")
        print(f"[INFO] Total errors fixed: {results.get('total_errors_fixed', 0)}")


if __name__ == "__main__":
    main()
