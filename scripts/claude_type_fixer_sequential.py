#!/usr/bin/env python3
"""Claude Type Error Auto-Fixer.

A production-ready tool to automatically fix Python type errors using Claude AI.
Supports both Claude OAuth (FREE for Max/Pro subscribers) and Anthropic API key.

Usage:
    # With Claude OAuth (RECOMMENDED - FREE for Max/Pro users)
    export CLAUDE_ACCESS_TOKEN="your-oauth-access-token-from-credentials.json"
    python tools/claude_type_fixer.py --mode batch --max-errors 50

    # With Anthropic API Key (fallback - pay-per-token)
    export ANTHROPIC_API_KEY="your-anthropic-api-key"
    python tools/claude_type_fixer.py --mode batch --max-errors 50

    # Individual mode (one error at a time)
    python tools/claude_type_fixer.py --mode individual --max-iterations 10

    # Different type checker
    python tools/claude_type_fixer.py --checker pyright --mode batch

    # Verbose output
    python tools/claude_type_fixer.py --mode batch --verbose
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import anthropic


class TypeErrorFixer:
    """Automated type error fixer using Claude AI."""

    def __init__(
        self,
        api_key: str | None = None,
        oauth_token: str | None = None,
        checker: str = "mypy",
        target_dir: str = "src",
        verbose: bool = False,
    ) -> None:
        """Initialize the type error fixer.

        Args:
            api_key: Anthropic API key (fallback)
            oauth_token: Claude OAuth access token (primary, FREE for Max/Pro)
            checker: Type checker to use (mypy or pyright)
            target_dir: Directory to check for type errors
            verbose: Enable verbose logging
        """
        if oauth_token:
            self.client = anthropic.Anthropic(api_key=oauth_token)
            self.auth_method = "oauth"
            self.log("🔐 Using Claude OAuth authentication (FREE)", force=True)
        elif api_key:
            self.client = anthropic.Anthropic(api_key=api_key)
            self.auth_method = "api_key"
            self.log("🔐 Using Anthropic API key authentication (pay-per-token)", force=True)
        else:
            raise ValueError("Either api_key or oauth_token must be provided")

        self.checker = checker
        self.target_dir = target_dir
        self.verbose = verbose

    def log(self, message: str, force: bool = False) -> None:
        """Log a message if verbose mode is enabled."""
        if self.verbose or force:
            print(message)

    def run_type_checker(self) -> str:
        """Run the configured type checker and return output.

        Returns:
            Type checker output as string
        """
        self.log(f"Running {self.checker} on {self.target_dir}...")

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

        output = result.stdout + result.stderr
        self.log(f"Type checker output:\n{output[:500]}...")

        return output

    def extract_errors(self, output: str, max_errors: int | None = None) -> list[str]:
        """Extract error lines from type checker output.

        Args:
            output: Type checker output
            max_errors: Maximum number of errors to extract

        Returns:
            List of error lines
        """
        error_lines = [line for line in output.split("\n") if "error:" in line.lower()]

        if max_errors:
            error_lines = error_lines[:max_errors]

        self.log(f"Extracted {len(error_lines)} errors")

        return error_lines

    def fix_batch(self, max_errors: int = 50) -> tuple[int, int]:
        """Fix type errors in batch mode.

        Args:
            max_errors: Maximum number of errors to process

        Returns:
            Tuple of (fixed_count, remaining_count)
        """
        self.log("Starting batch fix mode...", force=True)

        output = self.run_type_checker()
        error_lines = self.extract_errors(output, max_errors)

        if not error_lines:
            self.log("No type errors found!", force=True)
            return 0, 0

        original_count = len(error_lines)
        self.log(f"Processing {original_count} type errors", force=True)

        prompt = self._build_batch_prompt(error_lines)

        self.log("Sending to Claude API...")

        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=16000,
                temperature=0,
                system=self._get_system_prompt(),
                messages=[{"role": "user", "content": prompt}],
            )

            response_text = message.content[0].text
            self.log(f"Received response from Claude ({len(response_text)} chars)")

            fixed_count = self._apply_batch_fixes(response_text)

            new_output = self.run_type_checker()
            new_error_lines = self.extract_errors(new_output)
            remaining_count = len(new_error_lines)

            self.log(f"✅ Fixed: {fixed_count} errors", force=True)
            self.log(f"⚠️  Remaining: {remaining_count} errors", force=True)

            return fixed_count, remaining_count

        except Exception as e:
            self.log(f"❌ Error during batch processing: {e}", force=True)
            return 0, original_count

    def fix_individual(self, max_iterations: int = 10) -> int:
        """Fix type errors one at a time.

        Args:
            max_iterations: Maximum number of errors to fix

        Returns:
            Number of errors fixed
        """
        self.log("Starting individual fix mode...", force=True)

        fixed_count = 0

        for iteration in range(max_iterations):
            self.log(f"\n{'='*60}", force=True)
            self.log(f"Iteration {iteration + 1}/{max_iterations}", force=True)
            self.log(f"{'='*60}", force=True)

            output = self.run_type_checker()
            error_lines = self.extract_errors(output)

            if not error_lines:
                self.log("✅ No more type errors found!", force=True)
                break

            first_error = error_lines[0]
            self.log(f"Processing: {first_error}", force=True)

            if self._fix_single_error(first_error):
                fixed_count += 1
            else:
                self.log("⚠️  Failed to fix error, skipping", force=True)

        self.log(f"\nTotal fixed: {fixed_count} errors", force=True)

        return fixed_count

    def _fix_single_error(self, error_line: str) -> bool:
        """Fix a single type error.

        Args:
            error_line: Error line from type checker

        Returns:
            True if fix was successful
        """
        match = re.match(r"(.+?):(\d+):.*?error:(.+)", error_line)

        if not match:
            self.log(f"Could not parse error: {error_line}")
            return False

        file_path, line_num, error_msg = match.groups()
        file_path = file_path.strip()
        line_num = int(line_num.strip())
        error_msg = error_msg.strip()

        try:
            file_content = Path(file_path).read_text(encoding="utf-8")
        except Exception as e:
            self.log(f"Could not read {file_path}: {e}")
            return False

        prompt = self._build_single_error_prompt(
            file_path, line_num, error_msg, file_content
        )

        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=8000,
                temperature=0,
                system=self._get_system_prompt(),
                messages=[{"role": "user", "content": prompt}],
            )

            response = message.content[0].text

            code_match = re.search(r"```python\n(.*?)\n```", response, re.DOTALL)

            if code_match:
                fixed_code = code_match.group(1)
            else:
                fixed_code = response.strip()

            Path(file_path).write_text(fixed_code, encoding="utf-8")

            self.log(f"✅ Applied fix to {file_path}", force=True)

            return True

        except Exception as e:
            self.log(f"Error fixing {file_path}: {e}")
            return False

    def _build_batch_prompt(self, error_lines: list[str]) -> str:
        """Build prompt for batch fixing."""
        errors_text = "\n".join(error_lines)

        return f"""Fix the following type errors in the Intellicrack codebase.

For each error:
1. Read the relevant file
2. Understand the context
3. Apply the minimal fix needed
4. Use proper type hints with modern Python 3.12+ syntax
5. Use TYPE_CHECKING imports for forward references

Type errors to fix:

{errors_text}

Provide your fixes in this format:

FILE: path/to/file.py
OPERATION: edit
OLD:
```python
# exact old code
```
NEW:
```python
# exact new code with type fix
```
---

You can provide multiple edits for the same file."""

    def _build_single_error_prompt(
        self, file_path: str, line_num: int, error_msg: str, file_content: str
    ) -> str:
        """Build prompt for single error fixing."""
        lines = file_content.split("\n")
        start = max(0, line_num - 20)
        end = min(len(lines), line_num + 20)
        context = "\n".join(f"{i+1:4d}: {lines[i]}" for i in range(start, end))

        return f"""Fix this type error in {file_path}:

Error at line {line_num}: {error_msg}

Context (lines {start+1}-{end}):
```python
{context}
```

Full file content:
```python
{file_content}
```

Provide the complete corrected file content.
Use proper type hints, modern Python 3.12+ syntax, and TYPE_CHECKING imports where needed.
Be minimally invasive - only fix what's broken.

Output ONLY the corrected Python code wrapped in ```python blocks."""

    def _get_system_prompt(self) -> str:
        """Get the system prompt for Claude."""
        return """You are a Python type checking expert specializing in fixing type errors.

Fix type errors by:
1. Adding proper type hints with correct imports from typing module
2. Fixing type mismatches with correct types
3. Using modern Python 3.12+ syntax (list[str] instead of List[str] where possible)
4. Using TYPE_CHECKING imports to avoid circular dependencies
5. Being minimally invasive - only change what's necessary to fix the error

For batch mode, output edits in the specified format.
For single file mode, output only the corrected Python code."""

    def _apply_batch_fixes(self, response: str) -> int:
        """Apply batch fixes from Claude response.

        Args:
            response: Claude's response containing fixes

        Returns:
            Number of fixes applied
        """
        edit_pattern = re.compile(
            r"FILE:\s*(.+?)\n"
            r"OPERATION:\s*(\w+)\n"
            r"OLD:\s*\n```python\n(.*?)\n```\s*\n"
            r"NEW:\s*\n```python\n(.*?)\n```",
            re.DOTALL | re.MULTILINE,
        )

        edits = edit_pattern.findall(response)

        if not edits:
            self.log("No structured edits found in response")
            self.log(f"Response:\n{response[:500]}...")
            return 0

        self.log(f"Found {len(edits)} edit operations")

        applied_count = 0

        for file_path, operation, old_code, new_code in edits:
            file_path = file_path.strip()
            old_code = old_code.strip()
            new_code = new_code.strip()

            self.log(f"\nApplying {operation} to {file_path}")

            try:
                path = Path(file_path)

                if not path.exists():
                    self.log(f"  WARNING: File not found: {file_path}")
                    continue

                content = path.read_text(encoding="utf-8")

                if old_code not in content:
                    self.log(f"  WARNING: Old code not found in {file_path}")
                    continue

                new_content = content.replace(old_code, new_code, 1)
                path.write_text(new_content, encoding="utf-8")

                self.log(f"  ✅ Applied edit to {file_path}")
                applied_count += 1

            except Exception as e:
                self.log(f"  ❌ Error applying edit to {file_path}: {e}")

        return applied_count


def main() -> None:
    """Main entry point for the type error fixer."""
    parser = argparse.ArgumentParser(
        description="Automatically fix Python type errors using Claude AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--mode",
        choices=["batch", "individual"],
        default="batch",
        help="Fixing mode: batch (all at once) or individual (one at a time)",
    )

    parser.add_argument(
        "--checker",
        choices=["mypy", "pyright"],
        default="mypy",
        help="Type checker to use",
    )

    parser.add_argument(
        "--target-dir",
        default="src",
        help="Directory to check for type errors",
    )

    parser.add_argument(
        "--max-errors",
        type=int,
        default=50,
        help="Maximum errors to process in batch mode",
    )

    parser.add_argument(
        "--max-iterations",
        type=int,
        default=10,
        help="Maximum iterations in individual mode",
    )

    parser.add_argument(
        "--api-key",
        help="Anthropic API key (fallback - or set ANTHROPIC_API_KEY env var)",
    )

    parser.add_argument(
        "--oauth-token",
        help="Claude OAuth access token (primary, FREE - or set CLAUDE_ACCESS_TOKEN env var)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    oauth_token = args.oauth_token or os.environ.get("CLAUDE_ACCESS_TOKEN")
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")

    if not oauth_token and not api_key:
        print("❌ Error: Authentication required")
        print()
        print("Option 1 (Recommended - FREE for Max/Pro users):")
        print("  Set CLAUDE_ACCESS_TOKEN environment variable or use --oauth-token")
        print("  Get token from: ~/.claude/.credentials.json")
        print()
        print("Option 2 (Fallback - pay-per-token):")
        print("  Set ANTHROPIC_API_KEY environment variable or use --api-key")
        print("  Get API key from: https://console.anthropic.com/")
        sys.exit(1)

    fixer = TypeErrorFixer(
        oauth_token=oauth_token,
        api_key=api_key,
        checker=args.checker,
        target_dir=args.target_dir,
        verbose=args.verbose,
    )

    print(f"🤖 Claude Type Error Fixer")
    print(f"Mode: {args.mode}")
    print(f"Checker: {args.checker}")
    print(f"Target: {args.target_dir}")
    print()

    if args.mode == "batch":
        fixed, remaining = fixer.fix_batch(max_errors=args.max_errors)
        print(f"\n{'='*60}")
        print(f"Batch Fix Results:")
        print(f"  ✅ Fixed: {fixed}")
        print(f"  ⚠️  Remaining: {remaining}")
        print(f"{'='*60}")
    else:
        fixed = fixer.fix_individual(max_iterations=args.max_iterations)
        print(f"\n{'='*60}")
        print(f"Individual Fix Results:")
        print(f"  ✅ Fixed: {fixed}")
        print(f"{'='*60}")


if __name__ == "__main__":
    main()
