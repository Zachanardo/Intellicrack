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
import subprocess
import sys
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


def fix_file_agentically(
    file_path: str,
    errors: list[str],
    cwd: str,
    model: str = "claude-sonnet-4-5-20250929",
    timeout: int = 600,
) -> dict[str, Any]:
    """Fix all type errors in a single file using Claude CLI with full tool access.

    This function runs in a thread and gives Claude agentic control
    via Read, Edit, and Bash tools - exactly like Claude Code.

    Returns dict with: file, success, output, error, errors_count, git_diff,
                       mypy_before, mypy_after, errors_fixed
    """
    import threading
    thread_id = threading.current_thread().name
    print(f"[{thread_id}] STARTING: {Path(file_path).name}", flush=True)

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
        )
        errors_before = len([line for line in mypy_before.stdout.split("\n") if "error:" in line.lower()])
    except Exception:
        errors_before = len(errors)

    try:
        result = subprocess.run(
            [
                claude_path,
                "-p", prompt,
                "--model", model,
                "--system-prompt", SYSTEM_PROMPT,
                "--allowedTools", "Read,Edit,Bash",
                "--dangerously-skip-permissions",
                "--output-format", "text",
                "--max-turns", "100",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )

        syntax_check = subprocess.run(
            [sys.executable, "-c", f"import ast; ast.parse(open(r'{file_path}', encoding='utf-8').read())"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=cwd,
        )
        if syntax_check.returncode != 0:
            subprocess.run(["git", "checkout", file_path], cwd=cwd, capture_output=True)
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
            }

        git_diff = subprocess.run(
            ["git", "diff", "--color=always", file_path],
            capture_output=True,
            text=True,
            cwd=cwd,
        )

        mypy_after = subprocess.run(
            [sys.executable, "-m", "mypy", file_path, "--show-error-codes", "--no-error-summary"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=cwd,
        )
        errors_after = len([line for line in mypy_after.stdout.split("\n") if "error:" in line.lower()])

        print(f"[{thread_id}] FINISHED: {Path(file_path).name} (fixed {max(0, errors_before - errors_after)})", flush=True)
        return {
            "file": file_path,
            "success": result.returncode == 0,
            "output": result.stdout[:2000] if result.stdout else "",
            "error": result.stderr[:500] if result.returncode != 0 else "",
            "errors_count": len(errors),
            "git_diff": git_diff.stdout if git_diff.returncode == 0 else "",
            "mypy_before": errors_before,
            "mypy_after": errors_after,
            "errors_fixed": max(0, errors_before - errors_after),
            "model": model,
        }
    except subprocess.TimeoutExpired:
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
        }
    except Exception as e:
        return {
            "file": file_path,
            "success": False,
            "error": str(e)[:200],
            "errors_count": len(errors),
            "git_diff": "",
            "mypy_before": errors_before if 'errors_before' in locals() else 0,
            "mypy_after": errors_before if 'errors_before' in locals() else 0,
            "errors_fixed": 0,
            "model": model,
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
        show_diff: bool = True,
        timeout: int = 1200,
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
                )
            else:
                result = subprocess.run(
                    [sys.executable, "-m", "pyright", self.target_dir],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            self.log("[red]Type checker timed out![/red]")
            return ""
        except FileNotFoundError:
            self.log(f"[red]{self.checker} not found. Is it installed?[/red]")
            return ""

    def group_errors_by_file(self, output: str) -> dict[str, list[str]]:
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

        if RICH_AVAILABLE:
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
                        ): file_path
                        for file_path, errors in files_to_process
                    }

                    for future in as_completed(futures):
                        file_path = futures[future]
                        try:
                            result = future.result()
                            results.append(result)
                            fixed = result.get("errors_fixed", 0)
                            before = result.get("mypy_before", 0)
                            after = result.get("mypy_after", 0)
                            status = "[green]OK[/green]" if result["success"] else "[red]FAIL[/red]"
                            progress.update(task, advance=1, description=f"{status} {Path(file_path).name}")

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
                            })
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
                    ): file_path
                    for file_path, errors in files_to_process
                }

                for idx, future in enumerate(as_completed(futures), 1):
                    file_path = futures[future]
                    try:
                        result = future.result()
                        results.append(result)
                        fixed = result.get("errors_fixed", 0)
                        before = result.get("mypy_before", 0)
                        after = result.get("mypy_after", 0)
                        status = "OK" if result["success"] else "FAIL"
                        print(f"[{idx}/{len(files_to_process)}] {status}: {file_path}")
                        print(f"    Model: {result.get('model', self.model)}")
                        print(f"    Mypy: {before} -> {after} ({fixed} fixed)")

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
                        })
                        print(f"[{idx}/{len(files_to_process)}] ERROR: {file_path}")

        return results

    def run(self) -> dict[str, Any]:
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
                    self.log(f"[green]Progress: Reduced by {reduction} errors ({reduction/previous_error_count*100:.1f}%)[/green]")

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
                self.log(f"\n[yellow]Failed files this iteration:[/yellow]")
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
        "--errors-per-file", type=int, default=100,
        help="Maximum errors to show Claude per file (default: 100)"
    )

    args = parser.parse_args()

    global MAX_ITERATIONS, STALL_THRESHOLD, MAX_ERRORS_PER_FILE
    MAX_ITERATIONS = args.max_iterations
    STALL_THRESHOLD = args.stall_threshold
    MAX_ERRORS_PER_FILE = args.errors_per_file

    claude_check = subprocess.run(
        ["claude", "--version"],
        capture_output=True,
        text=True,
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
    )

    results = fixer.run()

    if results.get("remaining_errors", 0) == 0:
        print("\n[SUCCESS] All type errors have been fixed!")
    else:
        print(f"\n[INFO] {results.get('remaining_errors', 0)} errors remaining after {results.get('total_iterations', 0)} iterations")
        print(f"[INFO] Total errors fixed: {results.get('total_errors_fixed', 0)}")


if __name__ == "__main__":
    main()
