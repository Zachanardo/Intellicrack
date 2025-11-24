#!/usr/bin/env python3
"""Claude Type Error Auto-Fixer with PARALLEL Processing.

Divides type errors into batches of 50 and processes them SIMULTANEOUSLY
with multiple Claude API calls for maximum speed.

Usage:
    # With OAuth (FREE for Max/Pro users)
    export CLAUDE_ACCESS_TOKEN="your-token"
    python tools/claude_type_fixer_parallel.py

    # With API key
    export ANTHROPIC_API_KEY="your-key"
    python tools/claude_type_fixer_parallel.py

    # Configure parallelism
    python tools/claude_type_fixer_parallel.py --max-workers 5 --batch-size 50
"""

import argparse
import asyncio
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import anthropic


try:
    from rich.console import Console
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.layout import Layout

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  Install 'rich' for better visualizations: pip install rich")


class ParallelTypeFixer:
    """Parallel type error fixer using multiple Claude instances."""

    def __init__(
        self,
        api_key: str | None = None,
        oauth_token: str | None = None,
        checker: str = "mypy",
        target_dir: str = "src",
        max_workers: int = 5,
        batch_size: int = 50,
    ) -> None:
        """Initialize parallel type error fixer.

        Args:
            api_key: Anthropic API key (fallback)
            oauth_token: Claude OAuth token (primary, FREE)
            checker: Type checker (mypy or pyright)
            target_dir: Directory to check
            max_workers: Number of parallel Claude instances
            batch_size: Errors per batch
        """
        if oauth_token:
            self.client = anthropic.Anthropic(api_key=oauth_token)
            self.auth_method = "OAuth (FREE)"
        elif api_key:
            self.client = anthropic.Anthropic(api_key=api_key)
            self.auth_method = "API Key"
        else:
            raise ValueError("Either oauth_token or api_key required")

        self.checker = checker
        self.target_dir = target_dir
        self.max_workers = max_workers
        self.batch_size = batch_size

        if RICH_AVAILABLE:
            self.console = Console()
        else:
            self.console = None

    def log(self, message: str, style: str = "") -> None:
        """Log message with optional styling."""
        if self.console:
            self.console.print(message, style=style)
        else:
            print(message)

    def run_type_checker(self) -> str:
        """Run type checker and return output."""
        self.log(f"\n[bold cyan]Running {self.checker} on {self.target_dir}...[/bold cyan]")

        if self.checker == "mypy":
            result = subprocess.run(
                [
                    "pixi",
                    "run",
                    "python",
                    "-m",
                    "mypy",
                    self.target_dir,
                    "--show-column-numbers",
                    "--show-error-codes",
                    "--no-error-summary",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        else:
            result = subprocess.run(
                ["pixi", "run", "pyright", self.target_dir],
                capture_output=True,
                text=True,
                check=False,
            )

        return result.stdout + result.stderr

    def extract_errors(self, output: str) -> list[str]:
        """Extract error lines from type checker output."""
        return [line.strip() for line in output.split("\n") if "error:" in line.lower()]

    def split_into_batches(self, errors: list[str]) -> list[list[str]]:
        """Split errors into batches of specified size."""
        batches = []
        for i in range(0, len(errors), self.batch_size):
            batches.append(errors[i : i + self.batch_size])
        return batches

    def fix_batch(self, batch: list[str], batch_id: int) -> dict[str, Any]:
        """Fix a single batch of errors (runs in parallel thread).

        Args:
            batch: List of error lines
            batch_id: Batch identifier

        Returns:
            Results dictionary with fixes and metadata
        """
        prompt = f"""Fix the following type errors in the Intellicrack Python codebase.

For each error:
1. Read the relevant file
2. Understand the context and existing code patterns
3. Apply the MINIMAL fix needed (add type hints, fix incorrect types, etc.)
4. Use proper type hints with modern Python 3.12+ syntax
5. Use TYPE_CHECKING imports for forward references to avoid circular imports

CRITICAL RULES - FOLLOW STRICTLY:
- Add proper type hints using typing module or modern syntax (list[str], dict[str, int])
- Fix actual type mismatches with correct types
- NEVER use # type: ignore, # noqa, # pragma, or any disable comments
- FORBIDDEN: Any form of error suppression (type: ignore, mypy: ignore, pyright: ignore)
- REQUIRED: Add actual type hints - function signatures, variable annotations, return types
- Use TYPE_CHECKING for imports only needed for type checking
- Maintain existing functionality - DO NOT change logic
- If you cannot fix an error properly, skip it - DO NOT suppress it

Type errors to fix:

{chr(10).join(batch)}

Provide your fixes in this EXACT format for each file:

FILE: path/to/file.py
OPERATION: edit
OLD:
```python
# exact old code that needs fixing (including surrounding context)
```
NEW:
```python
# exact new code with type fix applied
```
---

You can provide multiple edits for the same file. Make sure OLD code matches EXACTLY what's in the file."""

        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=16000,
                temperature=0,
                system="""You are a Python type checking expert. Fix type errors by:
1. Adding proper type hints with correct imports from typing module
2. Fixing type mismatches with correct types
3. Using modern Python 3.12+ syntax (list[str], dict[str, Any], etc.)
4. Using TYPE_CHECKING imports to avoid circular dependencies
5. Being minimally invasive - only change what's necessary

ABSOLUTE PROHIBITIONS:
- NEVER use # type: ignore comments
- NEVER use # mypy: ignore comments
- NEVER use # pyright: ignore comments
- NEVER use # noqa comments for type errors
- NEVER suppress errors - FIX them with proper type hints

If you cannot properly fix an error, skip it. Do not suppress it.

Output edits in the exact format requested.""",
                messages=[{"role": "user", "content": prompt}],
            )

            response_text = message.content[0].text
            tokens_used = message.usage.input_tokens + message.usage.output_tokens

            return {
                "batch_id": batch_id,
                "success": True,
                "response": response_text,
                "tokens": tokens_used,
                "errors_in_batch": len(batch),
            }

        except Exception as e:
            return {
                "batch_id": batch_id,
                "success": False,
                "error": str(e),
                "errors_in_batch": len(batch),
            }

    def apply_fixes(self, responses: list[dict[str, Any]]) -> tuple[int, int]:
        """Apply fixes from all batch responses.

        Args:
            responses: List of batch response dictionaries

        Returns:
            Tuple of (applied_count, failed_count)
        """
        edit_pattern = re.compile(
            r"FILE:\s*(.+?)\n"
            r"OPERATION:\s*(\w+)\n"
            r"OLD:\s*\n```python\n(.*?)\n```\s*\n"
            r"NEW:\s*\n```python\n(.*?)\n```",
            re.DOTALL | re.MULTILINE,
        )

        applied_count = 0
        failed_count = 0

        for response in responses:
            if not response["success"]:
                continue

            edits = edit_pattern.findall(response["response"])

            for file_path, operation, old_code, new_code in edits:
                file_path = file_path.strip()
                old_code = old_code.strip()
                new_code = new_code.strip()

                try:
                    path = Path(file_path)

                    if not path.exists():
                        self.log(f"[yellow]⚠️  File not found: {file_path}[/yellow]")
                        failed_count += 1
                        continue

                    content = path.read_text(encoding="utf-8")

                    if old_code not in content:
                        self.log(
                            f"[yellow]⚠️  Old code not found in {file_path}[/yellow]"
                        )
                        failed_count += 1
                        continue

                    new_content = content.replace(old_code, new_code, 1)
                    path.write_text(new_content, encoding="utf-8")

                    applied_count += 1

                except Exception as e:
                    self.log(
                        f"[red]❌ Error applying fix to {file_path}: {e}[/red]"
                    )
                    failed_count += 1

        return applied_count, failed_count

    def run_parallel(self) -> dict[str, Any]:
        """Run parallel type fixing with visual progress.

        Returns:
            Results dictionary
        """
        self.log("\n[bold green]🚀 Claude Parallel Type Fixer[/bold green]")
        self.log(f"[cyan]Authentication: {self.auth_method}[/cyan]")
        self.log(f"[cyan]Type Checker: {self.checker}[/cyan]")
        self.log(f"[cyan]Max Workers: {self.max_workers}[/cyan]")
        self.log(f"[cyan]Batch Size: {self.batch_size}[/cyan]\n")

        output = self.run_type_checker()
        all_errors = self.extract_errors(output)

        if not all_errors:
            self.log("[bold green]✅ No type errors found![/bold green]")
            return {"total_errors": 0}

        self.log(
            f"[bold yellow]📊 Found {len(all_errors)} type errors[/bold yellow]\n"
        )

        batches = self.split_into_batches(all_errors)
        self.log(
            f"[bold cyan]📦 Split into {len(batches)} batches of {self.batch_size}[/bold cyan]\n"
        )

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=self.console,
            ) as progress:
                task = progress.add_task(
                    "[cyan]Processing batches...", total=len(batches)
                )

                responses = []

                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = {
                        executor.submit(self.fix_batch, batch, idx): idx
                        for idx, batch in enumerate(batches)
                    }

                    for future in as_completed(futures):
                        batch_id = futures[future]
                        result = future.result()
                        responses.append(result)

                        if result["success"]:
                            progress.update(
                                task,
                                advance=1,
                                description=f"[green]Batch {batch_id + 1}/{len(batches)} completed[/green]",
                            )
                        else:
                            progress.update(
                                task,
                                advance=1,
                                description=f"[red]Batch {batch_id + 1}/{len(batches)} failed[/red]",
                            )
        else:
            responses = []
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(self.fix_batch, batch, idx): idx
                    for idx, batch in enumerate(batches)
                }

                for idx, future in enumerate(as_completed(futures), 1):
                    result = future.result()
                    responses.append(result)
                    print(f"[{idx}/{len(batches)}] Batch completed")

        self.log("\n[bold cyan]📝 Applying fixes to files...[/bold cyan]\n")

        applied_count, failed_count = self.apply_fixes(responses)

        total_tokens = sum(r.get("tokens", 0) for r in responses if r["success"])
        successful_batches = sum(1 for r in responses if r["success"])

        self.log("\n[bold green]✅ Processing Complete![/bold green]\n")

        if RICH_AVAILABLE:
            table = Table(title="Results Summary", show_header=True)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Total Errors Found", str(len(all_errors)))
            table.add_row("Batches Processed", f"{successful_batches}/{len(batches)}")
            table.add_row("Fixes Applied", str(applied_count))
            table.add_row("Fixes Failed", str(failed_count))
            table.add_row("Total Tokens Used", f"{total_tokens:,}")
            table.add_row("Authentication", self.auth_method)

            self.console.print(table)
        else:
            print(f"\nTotal Errors: {len(all_errors)}")
            print(f"Batches: {successful_batches}/{len(batches)}")
            print(f"Applied: {applied_count}")
            print(f"Failed: {failed_count}")
            print(f"Tokens: {total_tokens:,}")

        return {
            "total_errors": len(all_errors),
            "batches_processed": successful_batches,
            "applied_count": applied_count,
            "failed_count": failed_count,
            "total_tokens": total_tokens,
        }


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Parallel Claude Type Error Auto-Fixer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--checker",
        choices=["mypy", "pyright"],
        default="mypy",
        help="Type checker to use",
    )

    parser.add_argument(
        "--target-dir", default="src", help="Directory to check for type errors"
    )

    parser.add_argument(
        "--max-workers",
        type=int,
        default=5,
        help="Number of parallel Claude instances (default: 5)",
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Errors per batch (default: 50)",
    )

    parser.add_argument(
        "--oauth-token",
        help="Claude OAuth access token (or set CLAUDE_ACCESS_TOKEN env var)",
    )

    parser.add_argument(
        "--api-key",
        help="Anthropic API key (or set ANTHROPIC_API_KEY env var)",
    )

    args = parser.parse_args()

    oauth_token = args.oauth_token or os.environ.get("CLAUDE_ACCESS_TOKEN")
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")

    if not oauth_token and not api_key:
        print("❌ Error: Authentication required")
        print()
        print("Option 1 (Recommended - FREE for Max/Pro users):")
        print("  export CLAUDE_ACCESS_TOKEN='your-token'")
        print("  Get from: ~/.claude/.credentials.json")
        print()
        print("Option 2 (Fallback - pay-per-token):")
        print("  export ANTHROPIC_API_KEY='your-key'")
        print("  Get from: https://console.anthropic.com/")
        sys.exit(1)

    fixer = ParallelTypeFixer(
        oauth_token=oauth_token,
        api_key=api_key,
        checker=args.checker,
        target_dir=args.target_dir,
        max_workers=args.max_workers,
        batch_size=args.batch_size,
    )

    results = fixer.run_parallel()

    if results.get("total_errors", 0) > 0:
        fix_rate = (
            results["applied_count"] / results["total_errors"] * 100
            if results["total_errors"] > 0
            else 0
        )
        print(f"\n📊 Fix Rate: {fix_rate:.1f}%")


if __name__ == "__main__":
    main()
