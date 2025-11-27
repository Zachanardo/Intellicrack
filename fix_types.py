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
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("WARNING: 'rich' not installed. Install with: pip install rich")


def fix_file_agentically(
    file_path: str,
    errors: list[str],
    cwd: str,
    model: str = "claude-sonnet-4-5-20250929",
) -> dict[str, Any]:
    """Fix all type errors in a single file using Claude CLI with full tool access.

    This function runs in a separate process and gives Claude agentic control
    via Read, Edit, and Bash tools - exactly like Claude Code.

    Returns dict with: file, success, output, error, errors_count, git_diff,
                       mypy_before, mypy_after, errors_fixed
    """
    system_prompt = """You are a Python type checking expert with FULL TOOL ACCESS.
You have Read, Edit, and Bash tools - use them directly to fix type errors.

WORKFLOW:
1. Read the file to understand the code
2. Use Edit tool to make precise type fixes
3. Optionally run mypy to verify your fixes

FIXING RULES:
- Add proper type hints using modern Python 3.12+ syntax (list[str], dict[str, Any])
- Fix type mismatches with correct types
- Use TYPE_CHECKING imports for forward references
- Be minimally invasive - only change what's necessary

ABSOLUTE PROHIBITIONS:
- NEVER use # type: ignore comments
- NEVER use # mypy: ignore or # pyright: ignore
- NEVER use # noqa comments for type errors
- NEVER suppress errors - FIX them with proper type hints

If you cannot properly fix an error, skip it. Do not suppress it.
After fixing, briefly report what you changed."""

    errors_text = "\n".join(f"  - {e}" for e in errors)
    prompt = f"""Fix these type errors in {file_path}:

{errors_text}

Use your Read tool to see the file, then use Edit tool to fix each error.
Add proper type hints - NEVER use type: ignore or any suppression comments."""

    mypy_before = subprocess.run(
        [sys.executable, "-m", "mypy", file_path, "--show-error-codes", "--no-error-summary"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=cwd,
    )
    errors_before = len([l for l in mypy_before.stdout.split("\n") if "error:" in l.lower()])

    try:
        result = subprocess.run(
            [
                "claude",
                "-p", prompt,
                "--model", model,
                "--allowedTools", "Read,Edit,Bash",
                "--dangerously-skip-permissions",
                "--output-format", "text",
                "--max-turns", "10",
            ],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=cwd,
            env={**os.environ, "CLAUDE_CODE_ENTRYPOINT": "cli"},
        )

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
            timeout=60,
            cwd=cwd,
        )
        errors_after = len([l for l in mypy_after.stdout.split("\n") if "error:" in l.lower()])

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
        return {
            "file": file_path,
            "success": False,
            "error": "Claude CLI timed out after 300s",
            "errors_count": len(errors),
            "git_diff": "",
            "mypy_before": errors_before,
            "mypy_after": errors_before,
            "errors_fixed": 0,
            "model": model,
        }
    except FileNotFoundError:
        return {
            "file": file_path,
            "success": False,
            "error": "Claude CLI not found. Install with: npm install -g @anthropic-ai/claude-code",
            "errors_count": len(errors),
            "git_diff": "",
            "mypy_before": 0,
            "mypy_after": 0,
            "errors_fixed": 0,
            "model": model,
        }
    except Exception as e:
        return {
            "file": file_path,
            "success": False,
            "error": str(e),
            "errors_count": len(errors),
            "git_diff": "",
            "mypy_before": 0,
            "mypy_after": 0,
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
    ) -> None:
        self.checker = checker
        self.target_dir = target_dir
        self.max_workers = max_workers
        self.max_files = max_files
        self.model = model
        self.show_diff = show_diff
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

    def run(self) -> dict[str, Any]:
        """Run the agentic type fixer."""
        self.log("\n[bold green]Claude Agentic Type Fixer[/bold green]")
        self.log("[cyan]Mode: AGENTIC (Claude uses Read/Edit/Bash tools directly)[/cyan]")
        self.log(f"[cyan]Model: {self.model}[/cyan]")
        self.log(f"[cyan]Type Checker: {self.checker}[/cyan]")
        self.log(f"[cyan]Target: {self.target_dir}[/cyan]")
        self.log(f"[cyan]Parallel Workers: {self.max_workers}[/cyan]")
        if self.max_files:
            self.log(f"[cyan]Max Files: {self.max_files} (TEST MODE)[/cyan]")
        self.log("")

        output = self.run_type_checker()
        errors_by_file = self.group_errors_by_file(output)

        if not errors_by_file:
            self.log("[bold green]No type errors found![/bold green]")
            return {"total_errors": 0, "files_processed": 0}

        total_errors = sum(len(errs) for errs in errors_by_file.values())
        self.log(f"[bold yellow]Found {total_errors} errors in {len(errors_by_file)} files[/bold yellow]\n")

        files_to_process = list(errors_by_file.items())
        if self.max_files:
            files_to_process = files_to_process[:self.max_files]
            self.log(f"[cyan]Processing {len(files_to_process)} files (test mode limit)[/cyan]\n")

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

                with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = {
                        executor.submit(
                            fix_file_agentically,
                            file_path,
                            errors,
                            self.cwd,
                            self.model,
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
                                self.log(f"\n[bold cyan]{'='*60}[/bold cyan]")
                                self.log(f"[bold]File: {file_path}[/bold]")
                                self.log(f"[cyan]Model: {result.get('model', self.model)}[/cyan]")
                                self.log(f"[yellow]Mypy errors: {before} -> {after} ({fixed} fixed)[/yellow]")
                                self.log("[bold cyan]Git Diff:[/bold cyan]")
                                print(result["git_diff"])
                                self.log(f"[bold cyan]{'='*60}[/bold cyan]\n")
                                progress.start()
                        except Exception as e:
                            results.append({
                                "file": file_path,
                                "success": False,
                                "error": str(e),
                            })
                            progress.update(task, advance=1)
        else:
            with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(
                        fix_file_agentically,
                        file_path,
                        errors,
                        self.cwd,
                        self.model,
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
                            print(f"\n{'='*60}")
                            print(f"Git Diff for {file_path}:")
                            print(result["git_diff"])
                            print(f"{'='*60}\n")
                    except Exception as e:
                        results.append({
                            "file": file_path,
                            "success": False,
                            "error": str(e),
                        })
                        print(f"[{idx}/{len(files_to_process)}] ERROR: {file_path}")

        successful = sum(1 for r in results if r.get("success"))
        failed = len(results) - successful
        total_fixed = sum(r.get("errors_fixed", 0) for r in results)
        errors_addressed = sum(r.get("errors_count", 0) for r in results if r.get("success"))

        self.log("\n[bold green]Processing Complete![/bold green]")

        if RICH_AVAILABLE and self.console:
            table = Table(title="Results Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Model Used", self.model)
            table.add_row("Total Errors Found", str(total_errors))
            table.add_row("Files Processed", f"{successful}/{len(files_to_process)}")
            table.add_row("Files Successful", str(successful))
            table.add_row("Files Failed", str(failed))
            table.add_row("Errors Addressed", str(errors_addressed))
            table.add_row("Errors Actually Fixed (verified)", str(total_fixed))
            self.console.print(table)
        else:
            print(f"\nModel: {self.model}")
            print(f"Total Errors: {total_errors}")
            print(f"Files: {successful}/{len(files_to_process)} successful")
            print(f"Errors Addressed: {errors_addressed}")
            print(f"Errors Fixed (verified): {total_fixed}")

        if failed > 0:
            self.log("\n[yellow]Failed files:[/yellow]")
            for r in results:
                if not r.get("success"):
                    self.log(f"  - {r.get('file')}: {r.get('error', 'Unknown error')[:80]}")

        return {
            "total_errors": total_errors,
            "files_processed": len(files_to_process),
            "files_successful": successful,
            "files_failed": failed,
            "errors_addressed": errors_addressed,
            "errors_fixed_verified": total_fixed,
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

    args = parser.parse_args()

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
    )

    results = fixer.run()

    if results.get("files_successful", 0) > 0:
        success_rate = results["files_successful"] / max(results["files_processed"], 1) * 100
        print(f"\nSuccess rate: {success_rate:.1f}%")

    verified = results.get("errors_fixed_verified", 0)
    addressed = results.get("errors_addressed", 0)
    if addressed > 0:
        fix_rate = verified / addressed * 100
        print(f"Verified fix rate: {fix_rate:.1f}% ({verified}/{addressed} errors actually fixed)")


if __name__ == "__main__":
    main()
