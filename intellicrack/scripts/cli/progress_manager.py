"""
Progress Manager for Intellicrack CLI Provides beautiful progress visualization for long-running operations

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

#!/usr/bin/env python3
"""
Progress Manager for Intellicrack CLI
Provides beautiful progress visualization for long-running operations
"""

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

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


@dataclass
class AnalysisTask:
    """Represents a single analysis task"""
    name: str
    description: str
    total_steps: int = 100
    current_step: int = 0
    status: str = "pending"  # pending, running, completed, failed
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error: Optional[str] = None
    subtasks: List['AnalysisTask'] = None

    def __post_init__(self):
        if self.subtasks is None:
            self.subtasks = []


class SpeedColumn(ProgressColumn):
    """Custom column showing processing speed"""
    def render(self, task):
        """Render the speed column."""
        speed = task.fields.get("speed", 0)
        if speed > 0:
            return Text(f"{speed:.1f} ops/s", style="cyan")
        return Text("", style="cyan")


class ProgressManager:
    """Manages progress display for CLI operations"""

    def __init__(self):
        self.console = Console()
        self.tasks: Dict[str, AnalysisTask] = {}
        self.progress = None
        self.live = None
        self._lock = threading.Lock()

    def create_progress_display(self) -> Progress:
        """Create a rich progress display with custom columns"""
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            SpeedColumn(),
            console=self.console,
            refresh_per_second=10
        )

    def start_analysis(self, binary_path: str, analysis_types: List[str]) -> None:
        """Start a new analysis with progress tracking"""
        layout = Layout()

        # Create header
        header = Panel(
            f"[bold cyan]Intellicrack Analysis Progress[/bold cyan]\n"
            f"[dim]Binary: {binary_path}[/dim]",
            box=box.ROUNDED
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
            Layout(status_table, size=10)
        )

        # Start live display
        self.live = Live(layout, console=self.console, refresh_per_second=4)
        self.live.start()

        # Create tasks for each analysis type
        for analysis_type in analysis_types:
            task_id = self.progress.add_task(
                f"[cyan]{analysis_type}",
                total=100,
                speed=0
            )
            self.tasks[analysis_type] = AnalysisTask(
                name=analysis_type,
                description=f"Running {analysis_type} analysis",
                total_steps=100
            )

    def update_progress(self, task_name: str, current: int, total: int,
                       speed: Optional[float] = None) -> None:
        """Update progress for a specific task"""
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
                            speed=speed or 0
                        )
                        break

    def complete_task(self, task_name: str, success: bool = True,
                     error: Optional[str] = None) -> None:
        """Mark a task as completed"""
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
                                description=f"[red]✗ {task_name} - {error or 'Failed'}"
                            )

    def stop(self) -> None:
        """Stop the progress display"""
        if self.live:
            self.live.stop()

            # Print final summary
            self._print_summary()

    def _print_summary(self) -> None:
        """Print analysis summary"""
        summary_table = Table(
            title="\n[bold]Analysis Summary[/bold]",
            box=box.ROUNDED,
            show_lines=True
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
                str(duration).split('.')[0],
                task.error or "Success"
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
            box=box.DOUBLE
        )

        self.console.print(stats_panel)


class MultiStageProgress:
    """Progress tracker for multi-stage operations"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.stages: List[Dict[str, Any]] = []
        self.current_stage = 0

    def add_stage(self, name: str, steps: List[str]) -> None:
        """Add a new stage with multiple steps"""
        self.stages.append({
            "name": name,
            "steps": steps,
            "current_step": 0,
            "completed": False
        })

    def start(self) -> None:
        """Start the multi-stage progress display"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:

            # Create main task
            main_task = progress.add_task(
                "[cyan]Overall Progress",
                total=sum(len(stage["steps"]) for stage in self.stages)
            )

            completed_steps = 0

            for stage_idx, stage in enumerate(self.stages):
                self.current_stage = stage_idx

                # Create stage task
                stage_task = progress.add_task(
                    f"[bold]{stage['name']}",
                    total=len(stage["steps"])
                )

                for step_idx, step in enumerate(stage["steps"]):
                    stage["current_step"] = step_idx

                    # Update descriptions
                    progress.update(
                        stage_task,
                        description=f"[bold]{stage['name']}[/bold] - {step}"
                    )

                    # Simulate work (replace with actual work)
                    time.sleep(0.5)

                    # Update progress
                    progress.update(stage_task, advance=1)
                    completed_steps += 1
                    progress.update(main_task, completed=completed_steps)

                stage["completed"] = True
                progress.update(
                    stage_task,
                    description=f"[bold green]✓ {stage['name']} - Complete[/bold green]"
                )


def demo_progress():
    """Demonstrate progress visualization capabilities"""
    console = Console()

    console.print("[bold cyan]Intellicrack Progress Visualization Demo[/bold cyan]\n")

    # Demo 1: Simple analysis progress
    console.print("[bold]1. Binary Analysis Progress:[/bold]")
    pm = ProgressManager()

    # Simulate analysis
    analysis_types = [
        "Static Analysis",
        "Dynamic Analysis",
        "Vulnerability Scan",
        "License Detection",
        "Network Analysis"
    ]

    pm.start_analysis("/path/to/binary.exe", analysis_types)

    # Simulate progress updates
    import random
    for i in range(100):
        for analysis in analysis_types:
            if random.random() > 0.3:  # Random progress
                current = min(100, i + random.randint(0, 10))
                speed = random.uniform(50, 200)
                pm.update_progress(analysis, current, 100, speed)

        time.sleep(0.05)

        # Randomly complete tasks
        if i > 50 and random.random() > 0.9:
            analysis = random.choice(analysis_types)
            if pm.tasks[analysis].status == "pending":
                pm.complete_task(analysis, success=random.random() > 0.2)

    # Complete remaining tasks
    for analysis in analysis_types:
        if pm.tasks[analysis].status == "pending":
            pm.complete_task(analysis)

    pm.stop()

    # Demo 2: Multi-stage progress
    console.print("\n[bold]2. Multi-Stage Operation:[/bold]")
    multi_progress = MultiStageProgress(console)

    multi_progress.add_stage("Preprocessing", [
        "Loading binary",
        "Parsing headers",
        "Extracting sections",
        "Building symbol table"
    ])

    multi_progress.add_stage("Analysis", [
        "Control flow analysis",
        "Data flow analysis",
        "Vulnerability detection",
        "Pattern matching"
    ])

    multi_progress.add_stage("Reporting", [
        "Generating report",
        "Creating visualizations",
        "Exporting results"
    ])

    multi_progress.start()

    console.print("\n[bold green]✓ All operations completed successfully![/bold green]")


if __name__ == "__main__":
    demo_progress()
