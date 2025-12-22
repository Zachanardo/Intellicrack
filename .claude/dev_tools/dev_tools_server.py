"""
MCP Dev-Tools Server for Intellicrack.

Exposes development tools (linting, testing, building, VCS, security)
to Claude Code agents via the Model Context Protocol.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .config import LONG_TIMEOUT, TIMEOUT, WORKING_DIR

mcp = FastMCP("dev-tools")

LOG_FILE = WORKING_DIR / ".claude" / "dev_tools" / "mcp_tool_invocations.log"


def log_tool_invocation(
    tool_name: str,
    args: list[str],
    result: dict[str, Any],
) -> None:
    """Log every MCP tool invocation to a file for verification."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool_name,
        "command": args,
        "return_code": result.get("return_code", -1),
        "success": result.get("success", False),
        "has_findings": result.get("has_findings", False),
        "stdout_length": len(result.get("stdout", "")),
        "stderr_length": len(result.get("stderr", "")),
    }

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")


def run_command(
    args: list[str],
    cwd: Path | None = None,
    timeout: int | None = None,
    capture_output: bool = True,
    tool_name: str | None = None,
) -> dict[str, Any]:
    """
    Execute a subprocess command with proper error handling.

    Args:
        args: Command and arguments to execute.
        cwd: Working directory for the command.
        timeout: Timeout in seconds.
        capture_output: Whether to capture stdout/stderr.
        tool_name: Optional tool name for logging (auto-detected if not provided).

    Returns:
        Dict with success, stdout, stderr, and return_code.
    """
    effective_timeout = timeout or TIMEOUT
    effective_cwd = cwd or WORKING_DIR

    detected_tool = tool_name
    if not detected_tool and args:
        for arg in args:
            if arg in ("ruff", "mypy", "pyright", "bandit", "flake8", "vulture",
                       "pytest", "coverage", "git", "cargo", "rustfmt", "clippy",
                       "eslint", "biome", "knip", "prettier", "markdownlint",
                       "yamllint", "shellcheck", "radon", "xenon", "dead",
                       "uncalled", "deadcode", "pydocstyle", "darglint"):
                detected_tool = arg
                break
            if "pmd" in arg.lower():
                detected_tool = "pmd"
                break
            if "checkstyle" in arg.lower():
                detected_tool = "checkstyle"
                break

    try:
        result = subprocess.run(
            args,
            cwd=effective_cwd,
            capture_output=capture_output,
            text=True,
            timeout=effective_timeout,
            shell=False,
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""

        if len(stdout) > 100000:
            stdout = stdout[:100000] + "\n... (output truncated)"
        if len(stderr) > 50000:
            stderr = stderr[:50000] + "\n... (output truncated)"

        output = {
            "success": result.returncode in (0, 1),
            "stdout": stdout,
            "stderr": stderr,
            "return_code": result.returncode,
            "has_findings": result.returncode == 1,
        }

        log_tool_invocation(detected_tool or "unknown", args, output)
        return output

    except subprocess.TimeoutExpired:
        output = {
            "success": False,
            "stdout": "",
            "stderr": f"Command timed out after {effective_timeout} seconds",
            "return_code": -1,
        }
        log_tool_invocation(detected_tool or "unknown", args, output)
        return output
    except FileNotFoundError as e:
        output = {
            "success": False,
            "stdout": "",
            "stderr": f"Command not found: {e}",
            "return_code": -1,
        }
        log_tool_invocation(detected_tool or "unknown", args, output)
        return output
    except PermissionError as e:
        output = {
            "success": False,
            "stdout": "",
            "stderr": f"Permission denied: {e}",
            "return_code": -1,
        }
        log_tool_invocation(detected_tool or "unknown", args, output)
        return output
    except OSError as e:
        output = {
            "success": False,
            "stdout": "",
            "stderr": f"OS error: {e}",
            "return_code": -1,
        }
        log_tool_invocation(detected_tool or "unknown", args, output)
        return output


def error_result(message: str) -> dict[str, Any]:
    """Create a standardized error result."""
    return {
        "success": False,
        "stdout": "",
        "stderr": message,
        "return_code": -1,
    }


from .tools.config_linters import register_config_linter_tools
from .tools.formatters import register_formatter_tools
from .tools.java_tools import register_java_tools
from .tools.js_tools import register_js_tools
from .tools.python_complexity import register_complexity_tools
from .tools.python_dead_code import register_dead_code_tools
from .tools.python_linting import register_python_linting_tools
from .tools.rust_tools import register_rust_tools
from .tools.testing import register_testing_tools
from .tools.vcs import register_vcs_tools

register_python_linting_tools(mcp, run_command, error_result)
register_formatter_tools(mcp, run_command, error_result)
register_rust_tools(mcp, run_command, error_result)
register_js_tools(mcp, run_command, error_result)
register_java_tools(mcp, run_command, error_result)
register_config_linter_tools(mcp, run_command, error_result)
register_complexity_tools(mcp, run_command, error_result)
register_dead_code_tools(mcp, run_command, error_result)
register_testing_tools(mcp, run_command, error_result)
register_vcs_tools(mcp, run_command, error_result)


if __name__ == "__main__":
    mcp.run()
