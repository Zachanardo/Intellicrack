#!/usr/bin/env python3
"""Claude Type Error Auto-Fixer with PARALLEL Processing and Live Diff.

Uses httpx for direct API calls (avoids anthropic library dependency issues).
Shows live diff updates as changes are applied.

Usage:
    # Activate venv first
    source .venv_typefixer/bin/activate  # or .venv_typefixer\\Scripts\\activate on Windows

    # Test mode (3 batches of 5 errors)
    python fix_types.py --test

    # Full run
    python fix_types.py --max-workers 5 --batch-size 50
"""

import argparse
import difflib
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Any

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.layout import Layout
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("WARNING: 'rich' not installed. Install with: pip install rich")


CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
USE_CLAUDE_CLI = True


class LiveDiffDisplay:
    """Manages live diff display during type fixing."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self.diffs: list[tuple[str, str]] = []  # (filename, diff_text)
        self.lock = Lock()
        self.batch_status: dict[int, str] = {}
        self.total_batches = 0
        self.completed_batches = 0
        self.applied_fixes = 0
        self.failed_fixes = 0

    def add_diff(self, filename: str, old_content: str, new_content: str) -> None:
        """Add a diff to the display."""
        diff = difflib.unified_diff(
            old_content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm=""
        )
        diff_text = "".join(diff)
        if diff_text:
            with self.lock:
                self.diffs.append((filename, diff_text))

    def update_batch_status(self, batch_id: int, status: str) -> None:
        """Update status for a batch."""
        with self.lock:
            self.batch_status[batch_id] = status

    def get_display(self) -> Panel:
        """Generate the current display panel."""
        layout = Layout()

        # Progress section
        progress_text = Text()
        progress_text.append(f"Batches: {self.completed_batches}/{self.total_batches}\n", style="cyan")
        progress_text.append(f"Fixes Applied: {self.applied_fixes}\n", style="green")
        progress_text.append(f"Fixes Failed: {self.failed_fixes}\n", style="red")
        progress_text.append("\nBatch Status:\n", style="bold")

        for batch_id, status in sorted(self.batch_status.items()):
            if "completed" in status.lower():
                progress_text.append(f"  Batch {batch_id}: {status}\n", style="green")
            elif "running" in status.lower():
                progress_text.append(f"  Batch {batch_id}: {status}\n", style="yellow")
            elif "failed" in status.lower():
                progress_text.append(f"  Batch {batch_id}: {status}\n", style="red")
            else:
                progress_text.append(f"  Batch {batch_id}: {status}\n")

        # Diff section
        diff_text = Text()
        if self.diffs:
            # Show last 3 diffs
            for filename, diff in self.diffs[-3:]:
                diff_text.append(f"\n--- {filename} ---\n", style="bold cyan")
                for line in diff.split("\n")[:20]:  # Limit lines
                    if line.startswith("+") and not line.startswith("+++"):
                        diff_text.append(line + "\n", style="green")
                    elif line.startswith("-") and not line.startswith("---"):
                        diff_text.append(line + "\n", style="red")
                    elif line.startswith("@@"):
                        diff_text.append(line + "\n", style="cyan")
                    else:
                        diff_text.append(line + "\n")
                if len(diff.split("\n")) > 20:
                    diff_text.append("... (truncated)\n", style="dim")
        else:
            diff_text.append("No changes yet...", style="dim")

        content = Text()
        content.append("=== Progress ===\n\n", style="bold yellow")
        content.append_text(progress_text)
        content.append("\n=== Live Diff ===\n", style="bold yellow")
        content.append_text(diff_text)

        return Panel(content, title="[bold blue]Claude Type Fixer[/bold blue]", border_style="blue")


class ParallelTypeFixer:
    """Parallel type error fixer using Claude API or CLI."""

    def __init__(
        self,
        api_key: str | None = None,
        checker: str = "mypy",
        target_dir: str = "intellicrack",
        max_workers: int = 3,
        batch_size: int = 5,
        max_batches: int | None = None,
        use_cli: bool = False,
    ) -> None:
        self.api_key = api_key or ""
        self.checker = checker
        self.target_dir = target_dir
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.max_batches = max_batches
        self.use_cli = use_cli
        self.file_snapshots: dict[str, str] = {}

        if RICH_AVAILABLE:
            self.console = Console()
            self.live_display = LiveDiffDisplay(self.console)
        else:
            self.console = None
            self.live_display = None

    def log(self, message: str, style: str = "") -> None:
        """Log a message."""
        if self.console and RICH_AVAILABLE:
            self.console.print(message, style=style)
        else:
            print(message)

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

    def extract_errors(self, output: str) -> list[str]:
        """Extract error lines from type checker output."""
        return [line.strip() for line in output.split("\n") if "error:" in line.lower() and line.strip()]

    def split_into_batches(self, errors: list[str]) -> list[list[str]]:
        """Split errors into batches."""
        batches = []
        for i in range(0, len(errors), self.batch_size):
            batch = errors[i:i + self.batch_size]
            batches.append(batch)
            if self.max_batches and len(batches) >= self.max_batches:
                break
        return batches

    def snapshot_files(self, errors: list[str]) -> None:
        """Take snapshots of files that will be modified."""
        for error in errors:
            match = re.match(r"(.+?):(\d+)", error)
            if match:
                filepath = match.group(1).strip()
                if filepath not in self.file_snapshots:
                    try:
                        path = Path(filepath)
                        if path.exists():
                            self.file_snapshots[filepath] = path.read_text(encoding="utf-8")
                    except Exception:
                        pass

    def call_claude_cli(self, prompt: str, system_prompt: str) -> dict[str, Any]:
        """Call Claude via CLI (uses OAuth authentication)."""
        try:
            result = subprocess.run(
                ["claude", "-p", prompt, "--output-format", "text", "--system-prompt", system_prompt],
                capture_output=True,
                text=True,
                timeout=180,
                cwd=os.getcwd(),
            )

            if result.returncode != 0:
                return {"error": f"Claude CLI error: {result.stderr[:200]}"}

            return {
                "content": [{"text": result.stdout}],
                "usage": {"input_tokens": 0, "output_tokens": 0},
            }
        except subprocess.TimeoutExpired:
            return {"error": "Claude CLI timed out after 180s"}
        except FileNotFoundError:
            return {"error": "Claude CLI not found. Install with: npm install -g @anthropic-ai/claude-code"}
        except Exception as e:
            return {"error": str(e)}

    def call_claude_api(self, prompt: str, system_prompt: str) -> dict[str, Any]:
        """Call Claude API directly using httpx."""
        if not HTTPX_AVAILABLE:
            return {"error": "httpx not installed. Use --use-cli or install httpx: pip install httpx"}

        headers = {
            "x-api-key": self.api_key,
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
        }

        payload = {
            "model": "claude-sonnet-4-5-20250929",
            "max_tokens": 16000,
            "temperature": 0,
            "system": system_prompt,
            "messages": [{"role": "user", "content": prompt}],
        }

        try:
            with httpx.Client(timeout=120.0) as client:
                response = client.post(CLAUDE_API_URL, headers=headers, json=payload)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as e:
            return {"error": f"HTTP {e.response.status_code}: {e.response.text}"}
        except Exception as e:
            return {"error": str(e)}

    def fix_batch(self, batch: list[str], batch_id: int) -> dict[str, Any]:
        """Fix a single batch of errors."""
        if self.live_display:
            self.live_display.update_batch_status(batch_id, "Running...")

        system_prompt = """You are a Python type checking expert. Fix type errors by:
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

Output edits in the exact format requested."""

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

        if self.use_cli:
            result = self.call_claude_cli(prompt, system_prompt)
        else:
            result = self.call_claude_api(prompt, system_prompt)

        if "error" in result:
            if self.live_display:
                self.live_display.update_batch_status(batch_id, f"Failed: {result['error'][:50]}")
            return {
                "batch_id": batch_id,
                "success": False,
                "error": result["error"],
                "errors_in_batch": len(batch),
            }

        try:
            response_text = result["content"][0]["text"]
            tokens_used = result.get("usage", {}).get("input_tokens", 0) + result.get("usage", {}).get("output_tokens", 0)

            if self.live_display:
                self.live_display.update_batch_status(batch_id, f"Completed ({tokens_used} tokens)")

            return {
                "batch_id": batch_id,
                "success": True,
                "response": response_text,
                "tokens": tokens_used,
                "errors_in_batch": len(batch),
            }
        except (KeyError, IndexError) as e:
            if self.live_display:
                self.live_display.update_batch_status(batch_id, f"Parse error: {e}")
            return {
                "batch_id": batch_id,
                "success": False,
                "error": f"Response parse error: {e}",
                "errors_in_batch": len(batch),
            }

    def apply_fixes(self, responses: list[dict[str, Any]]) -> tuple[int, int]:
        """Apply fixes from all batch responses."""
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
            if not response.get("success"):
                continue

            edits = edit_pattern.findall(response.get("response", ""))

            for file_path, operation, old_code, new_code in edits:
                file_path = file_path.strip()
                old_code = old_code.strip()
                new_code = new_code.strip()

                try:
                    path = Path(file_path)

                    if not path.exists():
                        self.log(f"[yellow]File not found: {file_path}[/yellow]")
                        failed_count += 1
                        continue

                    content = path.read_text(encoding="utf-8")
                    old_content = content

                    if old_code not in content:
                        self.log(f"[yellow]Old code not found in {file_path}[/yellow]")
                        failed_count += 1
                        continue

                    new_content = content.replace(old_code, new_code, 1)
                    path.write_text(new_content, encoding="utf-8")

                    # Update live diff display
                    if self.live_display:
                        self.live_display.add_diff(file_path, old_content, new_content)
                        self.live_display.applied_fixes += 1

                    applied_count += 1

                except Exception as e:
                    self.log(f"[red]Error applying fix to {file_path}: {e}[/red]")
                    failed_count += 1
                    if self.live_display:
                        self.live_display.failed_fixes += 1

        return applied_count, failed_count

    def run(self) -> dict[str, Any]:
        """Run the type fixer with visual progress."""
        self.log("\n[bold green]Claude Type Fixer - Parallel Processing with Live Diff[/bold green]")
        self.log(f"[cyan]Type Checker: {self.checker}[/cyan]")
        self.log(f"[cyan]Target: {self.target_dir}[/cyan]")
        self.log(f"[cyan]Workers: {self.max_workers}[/cyan]")
        self.log(f"[cyan]Batch Size: {self.batch_size}[/cyan]")
        auth_mode = "Claude CLI (OAuth)" if self.use_cli else "API Key"
        self.log(f"[cyan]Auth Mode: {auth_mode}[/cyan]")
        if self.max_batches:
            self.log(f"[cyan]Max Batches: {self.max_batches} (TEST MODE)[/cyan]")
        self.log("")

        # Run type checker
        output = self.run_type_checker()
        all_errors = self.extract_errors(output)

        if not all_errors:
            self.log("[bold green]No type errors found![/bold green]")
            return {"total_errors": 0}

        self.log(f"[bold yellow]Found {len(all_errors)} type errors[/bold yellow]")

        # Split into batches
        batches = self.split_into_batches(all_errors)
        self.log(f"[bold cyan]Split into {len(batches)} batches of {self.batch_size}[/bold cyan]\n")

        # Snapshot files
        for batch in batches:
            self.snapshot_files(batch)

        # Initialize live display
        if self.live_display:
            self.live_display.total_batches = len(batches)

        responses = []

        if RICH_AVAILABLE and self.live_display:
            with Live(self.live_display.get_display(), console=self.console, refresh_per_second=4) as live:
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = {
                        executor.submit(self.fix_batch, batch, idx + 1): idx + 1
                        for idx, batch in enumerate(batches)
                    }

                    for future in as_completed(futures):
                        batch_id = futures[future]
                        result = future.result()
                        responses.append(result)
                        self.live_display.completed_batches += 1
                        live.update(self.live_display.get_display())

                # Apply fixes
                self.log("\n[bold cyan]Applying fixes...[/bold cyan]")
                applied, failed = self.apply_fixes(responses)
                live.update(self.live_display.get_display())
        else:
            # Non-rich fallback
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(self.fix_batch, batch, idx + 1): idx + 1
                    for idx, batch in enumerate(batches)
                }

                for idx, future in enumerate(as_completed(futures), 1):
                    result = future.result()
                    responses.append(result)
                    status = "OK" if result.get("success") else "FAILED"
                    print(f"[{idx}/{len(batches)}] Batch {futures[future]}: {status}")

            applied, failed = self.apply_fixes(responses)

        # Summary
        total_tokens = sum(r.get("tokens", 0) for r in responses if r.get("success"))
        successful_batches = sum(1 for r in responses if r.get("success"))

        self.log("\n[bold green]Processing Complete![/bold green]")

        if RICH_AVAILABLE:
            table = Table(title="Results Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Total Errors Found", str(len(all_errors)))
            table.add_row("Batches Processed", f"{successful_batches}/{len(batches)}")
            table.add_row("Fixes Applied", str(applied))
            table.add_row("Fixes Failed", str(failed))
            table.add_row("Total Tokens", f"{total_tokens:,}")
            self.console.print(table)
        else:
            print(f"\nTotal Errors: {len(all_errors)}")
            print(f"Batches: {successful_batches}/{len(batches)}")
            print(f"Applied: {applied}, Failed: {failed}")
            print(f"Tokens: {total_tokens:,}")

        # Show final diff summary
        if self.live_display and self.live_display.diffs:
            self.log("\n[bold yellow]Files Modified:[/bold yellow]")
            for filename, _ in self.live_display.diffs:
                self.log(f"  - {filename}")

        return {
            "total_errors": len(all_errors),
            "batches_processed": successful_batches,
            "applied_count": applied,
            "failed_count": failed,
            "total_tokens": total_tokens,
        }


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Claude Type Error Auto-Fixer with Parallel Processing and Live Diff",
    )

    parser.add_argument(
        "--test", action="store_true",
        help="Test mode: 3 batches of 5 errors (proves it works)"
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
        help="Parallel Claude instances (default: 3)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=50,
        help="Errors per batch (default: 50, test mode: 5)"
    )
    parser.add_argument(
        "--max-batches", type=int, default=None,
        help="Maximum batches to process (default: all)"
    )
    parser.add_argument(
        "--api-key",
        help="Anthropic API key (or set ANTHROPIC_API_KEY env var)"
    )
    parser.add_argument(
        "--use-cli", action="store_true",
        help="Use Claude CLI instead of API (uses OAuth from Claude Code)"
    )

    args = parser.parse_args()

    use_cli = args.use_cli
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")

    if not use_cli and not api_key:
        print("ERROR: Authentication required!")
        print("")
        print("Option 1 - Use Claude CLI (recommended, uses your Claude Code login):")
        print("  python fix_types.py --use-cli --test")
        print("")
        print("Option 2 - Use API key from console.anthropic.com:")
        print("  export ANTHROPIC_API_KEY='sk-ant-api03-...'")
        print("  python fix_types.py --test")
        sys.exit(1)

    if not use_cli and api_key and api_key.startswith("sk-ant-oat"):
        print("ERROR: OAuth token detected (sk-ant-oat-...)")
        print("For OAuth authentication, use --use-cli flag instead.")
        print("")
        print("  python fix_types.py --use-cli --test")
        sys.exit(1)

    # Test mode overrides
    if args.test:
        args.batch_size = 5
        args.max_batches = 3
        args.max_workers = 3
        print("TEST MODE: 3 batches of 5 errors")

    fixer = ParallelTypeFixer(
        api_key=api_key,
        checker=args.checker,
        target_dir=args.target_dir,
        max_workers=args.max_workers,
        batch_size=args.batch_size,
        max_batches=args.max_batches,
        use_cli=use_cli,
    )

    results = fixer.run()

    if results.get("applied_count", 0) > 0:
        print(f"\nFix rate: {results['applied_count'] / max(results['total_errors'], 1) * 100:.1f}%")


if __name__ == "__main__":
    main()
