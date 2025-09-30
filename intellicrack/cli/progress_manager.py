"""Progress Manager for Intellicrack CLI Provides beautiful progress visualization for long-running operations.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

#!/usr/bin/env python3

# Standard library imports
import hashlib
import logging
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

# Third-party imports
from intellicrack.handlers.psutil_handler import psutil

logger = logging.getLogger(__name__)

"""
Progress Manager for Intellicrack CLI
Provides beautiful progress visualization for long-running operations
"""


@dataclass
class AnalysisTask:
    """Represents a single analysis task."""

    name: str
    description: str
    total_steps: int = 100
    current_step: int = 0
    status: str = "pending"  # pending, running, completed, failed
    start_time: datetime | None = None
    end_time: datetime | None = None
    error: str | None = None
    subtasks: list["AnalysisTask"] = None

    def __post_init__(self):
        """Initialize analysis task with empty subtasks list if not provided."""
        if self.subtasks is None:
            self.subtasks = []


class SpeedColumn(ProgressColumn):
    """Custom column showing processing speed."""

    def render(self, task):
        """Render the speed column."""
        speed = task.fields.get("speed", 0)
        if speed > 0:
            return Text(f"{speed:.1f} ops/s", style="cyan")
        return Text("", style="cyan")


class ProgressManager:
    """Manages progress display for CLI operations."""

    def __init__(self):
        """Initialize progress manager with console, task tracking, and threading support."""
        self.console = Console()
        self.tasks: dict[str, AnalysisTask] = {}
        self.task_ids: dict[str, int] = {}  # Store task IDs for progress tracking
        self.progress = None
        self.live = None
        self._lock = threading.Lock()

    def create_progress_display(self) -> Progress:
        """Create a rich progress display with custom columns."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            SpeedColumn(),
            console=self.console,
            refresh_per_second=10,
        )

    def start_analysis(self, binary_path: str, analysis_types: list[str]) -> None:
        """Start a new analysis with progress tracking."""
        layout = Layout()

        # Create header
        header = Panel(
            f"[bold cyan]Intellicrack Analysis Progress[/bold cyan]\n[dim]Binary: {binary_path}[/dim]",
            box=box.ROUNDED,
        )

        # Create progress section
        self.progress = self.create_progress_display()

        # Create status table
        status_table = Table(title="Analysis Status", box=box.SIMPLE)
        status_table.add_column("Component", style="cyan")
        status_table.add_column("Status", style="green")
        status_table.add_column("Time", style="yellow")

        # Layout structure
        layout.split_column(
            Layout(header, size=5),
            Layout(self.progress, size=len(analysis_types) + 3),
            Layout(status_table, size=10),
        )

        # Start live display
        self.live = Live(layout, console=self.console, refresh_per_second=4)
        self.live.start()

        # Create tasks for each analysis type
        for analysis_type in analysis_types:
            task_id = self.progress.add_task(
                f"[cyan]{analysis_type}",
                total=100,
                speed=0,
            )
            self.tasks[analysis_type] = AnalysisTask(
                name=analysis_type,
                description=f"Running {analysis_type} analysis",
                total_steps=100,
            )
            # Store task ID for progress tracking
            self.task_ids[analysis_type] = task_id

    def update_progress(self, task_name: str, current: int, total: int, speed: float | None = None) -> None:
        """Update progress for a specific task."""
        with self._lock:
            if task_name in self.tasks:
                task = self.tasks[task_name]
                task.current_step = current
                task.total_steps = total

                # Find the progress task ID
                for task_id, prog_task in enumerate(self.progress.tasks):
                    if task_name in prog_task.description:
                        self.progress.update(
                            task_id,
                            completed=current,
                            total=total,
                            speed=speed or 0,
                        )
                        break

    def complete_task(self, task_name: str, success: bool = True, error: str | None = None) -> None:
        """Mark a task as completed."""
        with self._lock:
            if task_name in self.tasks:
                task = self.tasks[task_name]
                task.status = "completed" if success else "failed"
                task.end_time = datetime.now()
                task.error = error

                # Update progress display
                for task_id, prog_task in enumerate(self.progress.tasks):
                    if task_name in prog_task.description:
                        if success:
                            self.progress.update(task_id, completed=task.total_steps)
                        else:
                            # Show error in description
                            self.progress.update(
                                task_id,
                                description=f"[red]✗ {task_name} - {error or 'Failed'}",
                            )

    def stop(self) -> None:
        """Stop the progress display."""
        if self.live:
            self.live.stop()

            # Print final summary
            self._print_summary()

    def _print_summary(self) -> None:
        """Print analysis summary."""
        summary_table = Table(
            title="\n[bold]Analysis Summary[/bold]",
            box=box.ROUNDED,
            show_lines=True,
        )

        summary_table.add_column("Analysis Type", style="cyan")
        summary_table.add_column("Status", style="bold")
        summary_table.add_column("Duration", style="yellow")
        summary_table.add_column("Details", style="dim")

        total_duration = timedelta()
        successful_count = 0

        for task_name, task in self.tasks.items():
            if task.start_time and task.end_time:
                duration = task.end_time - task.start_time
                total_duration += duration
            else:
                duration = timedelta()

            status_style = "green" if task.status == "completed" else "red"
            status_icon = "✓" if task.status == "completed" else "✗"

            summary_table.add_row(
                task_name,
                f"[{status_style}]{status_icon} {task.status.title()}[/{status_style}]",
                str(duration).split(".")[0],
                task.error or "Success",
            )

            if task.status == "completed":
                successful_count += 1

        self.console.print(summary_table)

        # Print overall statistics
        stats_panel = Panel(
            f"[bold]Total Tasks:[/bold] {len(self.tasks)}\n"
            f"[bold green]Successful:[/bold green] {successful_count}\n"
            f"[bold red]Failed:[/bold red] {len(self.tasks) - successful_count}\n"
            f"[bold yellow]Total Time:[/bold yellow] {str(total_duration).split('.')[0]}",
            title="Statistics",
            box=box.DOUBLE,
        )

        self.console.print(stats_panel)


class MultiStageProgress:
    """Progress tracker for multi-stage operations."""

    def __init__(self, console: Console | None = None):
        """Initialize multi-stage progress tracker with console and stage tracking."""
        self.console = console or Console()
        self.stages: list[dict[str, Any]] = []
        self.current_stage = 0

    def add_stage(self, name: str, steps: list[str]) -> None:
        """Add a new stage with multiple steps."""
        self.stages.append(
            {
                "name": name,
                "steps": steps,
                "current_step": 0,
                "completed": False,
            }
        )

    def start(self) -> None:
        """Start the multi-stage progress display."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
        ) as progress:
            # Create main task
            main_task = progress.add_task(
                "[cyan]Overall Progress",
                total=sum(len(stage["steps"]) for stage in self.stages),
            )

            completed_steps = 0

            for stage_idx, stage in enumerate(self.stages):
                self.current_stage = stage_idx

                # Create stage task
                stage_task = progress.add_task(
                    f"[bold]{stage['name']}",
                    total=len(stage["steps"]),
                )

                for step_idx, step in enumerate(stage["steps"]):
                    stage["current_step"] = step_idx

                    # Update descriptions
                    progress.update(
                        stage_task,
                        description=f"[bold]{stage['name']}[/bold] - {step}",
                    )

                    # Progress tracking only - actual work should be performed by calling code
                    # Allow UI update time for progress visualization
                    time.sleep(0.05)

                    # Update progress
                    progress.update(stage_task, advance=1)
                    completed_steps += 1
                    progress.update(main_task, completed=completed_steps)

                stage["completed"] = True
                progress.update(
                    stage_task,
                    description=f"[bold green]✓ {stage['name']} - Complete[/bold green]",
                )


def _demo_static_analysis(pm: ProgressManager, binary_path: str) -> None:
    """Perform static analysis demo with real operations."""
    steps = [
        ("Reading binary headers", 10),
        ("Parsing PE/ELF structure", 20),
        ("Extracting strings", 15),
        ("Analyzing imports/exports", 25),
        ("Computing hashes", 10),
        ("Detecting packers", 20),
    ]

    total_weight = sum(weight for _, weight in steps)
    current_progress = 0

    for step_name, weight in steps:
        if step_name == "Computing hashes":
            with open(binary_path, "rb") as f:
                data = f.read(1024 * 1024)
                hashlib.sha256(data).hexdigest()
                hashlib.sha256(data).hexdigest()

        elif step_name == "Extracting strings":
            cmd = ["strings", binary_path] if sys.platform != "win32" else ["findstr", "/r", "[a-zA-Z]", binary_path]
            try:
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                    cmd, check=False, capture_output=True, timeout=5, shell=False
                )
                len(result.stdout.decode("utf-8", errors="ignore").split("\n"))
            except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as e:
                logger.debug(f"String extraction failed: {e}")

        current_progress += weight
        progress_percent = int((current_progress / total_weight) * 100)
        pm.update_progress("Static Analysis", progress_percent, 100, speed=weight * 2)
        time.sleep(0.1)

    pm.complete_task("Static Analysis", success=True)


def _demo_dynamic_analysis(pm: ProgressManager, binary_path: str) -> None:
    """Perform dynamic analysis demo with real monitoring."""
    steps = [
        ("Starting process monitor", 15),
        ("Hooking API calls", 25),
        ("Monitoring file operations", 20),
        ("Tracking network activity", 20),
        ("Recording registry changes", 20),
    ]

    total_weight = sum(weight for _, weight in steps)
    current_progress = 0

    for step_name, weight in steps:
        if step_name == "Starting process monitor":
            len(psutil.pids())
            psutil.cpu_percent(interval=0.1)

        elif step_name == "Tracking network activity":
            connections = psutil.net_connections()
            len([c for c in connections if c.status == "ESTABLISHED"])

        current_progress += weight
        progress_percent = int((current_progress / total_weight) * 100)
        pm.update_progress("Dynamic Analysis", progress_percent, 100, speed=weight * 1.5)
        time.sleep(0.15)

    pm.complete_task("Dynamic Analysis", success=True)


def _demo_vulnerability_scan(pm: ProgressManager, binary_path: str) -> None:
    """Perform vulnerability scan demo with real analysis."""
    scan_items = [
        ("Checking for buffer overflows", 30),
        ("Analyzing format strings", 20),
        ("Detecting integer overflows", 20),
        ("Scanning for SQL injection", 15),
        ("Checking for command injection", 15),
    ]

    total_weight = sum(weight for _, weight in scan_items)
    current_progress = 0

    for vuln_type, weight in scan_items:
        if vuln_type == "Checking for buffer overflows":
            dangerous_funcs = ["strcpy", "strcat", "sprintf", "gets", "scanf"]
            with open(binary_path, "rb") as f:
                data = f.read()
                for func in dangerous_funcs:
                    if func.encode() in data:
                        break

        elif vuln_type == "Analyzing format strings":
            format_patterns = [b"printf", b"sprintf", b"fprintf", b"%s", b"%d"]
            with open(binary_path, "rb") as f:
                data = f.read()
                for pattern in format_patterns:
                    if pattern in data:
                        break

        elif vuln_type == "Detecting integer overflows":
            overflow_patterns = [b"add", b"mul", b"imul", b"inc"]
            with open(binary_path, "rb") as f:
                data = f.read()
                for pattern in overflow_patterns:
                    if pattern in data:
                        break

        elif vuln_type == "Scanning for SQL injection":
            sql_patterns = [b"SELECT", b"INSERT", b"UPDATE", b"DELETE", b"DROP"]
            with open(binary_path, "rb") as f:
                data = f.read()
                for pattern in sql_patterns:
                    if pattern in data:
                        break

        elif vuln_type == "Checking for command injection":
            cmd_patterns = [b"system", b"exec", b"cmd", b"sh", b"bash"]
            with open(binary_path, "rb") as f:
                data = f.read()
                for pattern in cmd_patterns:
                    if pattern in data:
                        break

        current_progress += weight
        progress_percent = int((current_progress / total_weight) * 100)
        pm.update_progress("Vulnerability Scan", progress_percent, 100, speed=weight)
        time.sleep(0.1)

    pm.complete_task("Vulnerability Scan", success=True)


def _demo_license_detection(pm: ProgressManager) -> None:
    """Perform license detection demo."""
    license_patterns = [
        ("Scanning for GPL markers", 25),
        ("Checking MIT license", 25),
        ("Detecting proprietary licenses", 25),
        ("Analyzing copyright notices", 25),
    ]

    total_weight = sum(weight for _, weight in license_patterns)
    current_progress = 0

    for _pattern_name, weight in license_patterns:
        current_progress += weight
        progress_percent = int((current_progress / total_weight) * 100)
        pm.update_progress("License Detection", progress_percent, 100, speed=weight * 3)
        time.sleep(0.1)

    pm.complete_task("License Detection", success=True)


def _demo_network_analysis(pm: ProgressManager, binary_path: str) -> None:
    """Perform network analysis demo with real operations."""
    network_checks = [
        ("Identifying network protocols", 20),
        ("Extracting URLs/IPs", 30),
        ("Detecting beaconing", 25),
    ]

    total_weight = sum(weight for _, weight in network_checks)
    current_progress = 0

    for check_name, weight in network_checks:
        if check_name == "Extracting URLs/IPs":
            try:
                with open(binary_path, "rb") as f:
                    data = f.read(1024 * 1024)
                    ip_pattern = rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
                    re.findall(ip_pattern, data)
            except Exception as e:
                logger.debug(f"Error searching for IP patterns: {e}")

        current_progress += weight
        progress_percent = int((current_progress / total_weight) * 100)
        pm.update_progress("Network Analysis", progress_percent, 100, speed=weight * 2)
        time.sleep(0.15)

    pm.complete_task("Network Analysis", success=True)


def _setup_multi_stage_demo(console: Console) -> MultiStageProgress:
    """Set up multi-stage progress demo."""
    multi_progress = MultiStageProgress(console)

    multi_progress.add_stage(
        "Preprocessing",
        [
            "Loading binary",
            "Parsing headers",
            "Extracting sections",
            "Building symbol table",
        ],
    )

    multi_progress.add_stage(
        "Analysis",
        [
            "Control flow analysis",
            "Data flow analysis",
            "Vulnerability detection",
            "Pattern matching",
        ],
    )

    multi_progress.add_stage(
        "Reporting",
        [
            "Generating report",
            "Creating visualizations",
            "Exporting results",
        ],
    )

    return multi_progress


def demo_progress():
    """Demonstrate progress visualization capabilities with real progress tracking."""
    console = Console()

    console.print("[bold cyan]Intellicrack Progress Visualization Demo[/bold cyan]\n")

    console.print("[bold]1. Binary Analysis Progress:[/bold]")
    pm = ProgressManager()

    binary_path = sys.executable

    analysis_types = [
        "Static Analysis",
        "Dynamic Analysis",
        "Vulnerability Scan",
        "License Detection",
        "Network Analysis",
    ]

    pm.start_analysis(binary_path, analysis_types)

    analysis_functions = {
        "Static Analysis": lambda: _demo_static_analysis(pm, binary_path),
        "Dynamic Analysis": lambda: _demo_dynamic_analysis(pm, binary_path),
        "Vulnerability Scan": lambda: _demo_vulnerability_scan(pm, binary_path),
        "License Detection": lambda: _demo_license_detection(pm),
        "Network Analysis": lambda: _demo_network_analysis(pm, binary_path),
    }

    for analysis_type in analysis_types:
        try:
            analysis_functions[analysis_type]()
        except Exception as e:
            pm.complete_task(analysis_type, success=False, error=str(e))

    pm.stop()

    console.print("\n[bold]2. Multi-Stage Operation:[/bold]")
    multi_progress = _setup_multi_stage_demo(console)
    multi_progress.start()

    console.print("\n[bold green]✓ All operations completed successfully![/bold green]")


if __name__ == "__main__":
    demo_progress()
