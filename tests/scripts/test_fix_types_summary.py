"""Tests for the fix_types_summary harness."""

from __future__ import annotations

import itertools
import json
from dataclasses import dataclass
from pathlib import Path  # noqa: TC003

import pytest

from scripts import fix_types_summary as summary


@dataclass(slots=True)
class FakeCompletedProcess:
    """Minimal stand-in for subprocess.CompletedProcess."""

    args: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""


MAX_PARALLEL_WORKERS = 50


def _create_synthetic_project(root: Path, file_count: int) -> Path:
    project_dir = root / "synthetic_project"
    project_dir.mkdir()
    for index in range(file_count):
        file_path = project_dir / f"module_{index}.py"
        file_path.write_text(
            "def produce(value: int) -> int:\n"
            "    return value\n"
            f"BAD_{index}: str = produce(42)\n",
            encoding="utf-8",
        )
    return project_dir


def test_summary_harness_handles_max_parallelism(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Ensure the harness accepts the maximum configuration without touching real files."""
    file_count = 5
    project_dir = _create_synthetic_project(tmp_path, file_count)
    summary_dir = tmp_path / "tmp_summaries"
    summary_dir.mkdir()

    fake_claude_path = str(tmp_path / "bin" / "claude.exe")
    monkeypatch.setattr(summary.shutil, "which", lambda _: fake_claude_path)

    session_counter = itertools.count(1)
    claude_invocations: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> FakeCompletedProcess:
        del kwargs
        if cmd[:2] == ["claude", "--version"]:
            return FakeCompletedProcess(cmd, 0, stdout="Claude CLI 1.0\n")
        if cmd and cmd[0] == "claude" and "--output-format" not in cmd:
            return FakeCompletedProcess(cmd, 0, stdout="OK\n")
        if cmd and cmd[0] == fake_claude_path:
            claude_invocations.append(list(cmd))
            session_id = f"sess-{next(session_counter)}"
            timestamp = f"20250101T01010{len(claude_invocations)}.1234"
            embedded = {
                "session_id": session_id,
                "summary": f"Synthetic summary {session_id}",
                "timestamp": timestamp,
            }
            stdout = json.dumps(
                {
                    "type": "result",
                    "subtype": "success",
                    "result": f"Responding with JSON:\\n```json\\n{json.dumps(embedded)}\\n```",
                    "session_id": f"cli-{session_id}",
                    "metadata": {"timestamp": timestamp},
                }
            )
            return FakeCompletedProcess(cmd, 0, stdout=stdout)
        pytest.fail(f"Unexpected command: {cmd}")

    monkeypatch.setattr(summary, "secure_run", fake_run)

    cli_args = [
        "--checker",
        "mypy",
        "--target-dir",
        str(project_dir),
        "--max-workers",
        str(MAX_PARALLEL_WORKERS),
        "--max-files",
        str(file_count),
        "--timeout",
        "7200",
        "--max-iterations",
        "500",
        "--stall-threshold",
        "20",
        "--errors-per-file",
        "500",
        "--tmp-dir",
        str(summary_dir),
        "--model",
        "haiku",
        "--synthetic-files",
        str(file_count),
    ]
    result = summary.run_cli(cli_args)

    assert result.processed_files == file_count
    assert result.summaries_written == file_count
    assert result.max_workers == MAX_PARALLEL_WORKERS
    assert not result.failures
    assert len(result.session_ids) == file_count
    assert len(result.timestamps) == file_count
    assert len(result.summary_paths) == file_count
    assert all(path.exists() for path in result.summary_paths)
    assert all(session_id is not None for session_id in result.session_ids)
    assert all(ts is not None for ts in result.timestamps)

    written_files = sorted(summary_dir.glob("mypy*.txt"))
    assert len(written_files) == file_count
    expected_names = {f"mypy{timestamp}.txt" for timestamp in result.timestamps}
    assert {path.name for path in written_files} == expected_names
    for path in written_files:
        content = path.read_text(encoding="utf-8")
        assert content.startswith("Synthetic summary")

    assert len(claude_invocations) == file_count
    for cmd in claude_invocations:
        assert "--allowedTools" in cmd
        allowed_index = cmd.index("--allowedTools")
        assert cmd[allowed_index + 1] == "Read,Write,Bash"
        assert "--output-format" in cmd
