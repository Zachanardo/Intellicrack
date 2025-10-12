#!/usr/bin/env python3
"""Interactive Tutorial System - Step-by-step CLI guidance for Intellicrack.

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

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Optional imports for enhanced tutorials
try:
    from rich.align import Align
    from rich.columns import Columns
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.prompt import Confirm, IntPrompt, Prompt
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


@dataclass
class TutorialStep:
    """Represents a single tutorial step."""

    title: str
    description: str
    commands: list[str] = field(default_factory=list)
    explanation: str = ""
    expected_output: str | None = None
    validation: Callable | None = None
    hints: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    skip_allowed: bool = True


@dataclass
class Tutorial:
    """Represents a complete tutorial."""

    name: str
    title: str
    description: str
    difficulty: str = "beginner"  # beginner, intermediate, advanced
    estimated_time: int = 10  # minutes
    steps: list[TutorialStep] = field(default_factory=list)
    completion_message: str = ""
    prerequisites: list[str] = field(default_factory=list)


class TutorialSystem:
    """Interactive tutorial system for Intellicrack CLI."""

    def __init__(self, cli_instance=None):
        """Initialize tutorial system.

        Args:
            cli_instance: Reference to CLI instance for command execution

        """
        self.console = Console() if RICH_AVAILABLE else None
        self.cli_instance = cli_instance

        # Tutorial state
        self.current_tutorial = None
        self.current_step = 0
        self.tutorial_progress = {}
        self.tutorial_history = []

        # Initialize tutorials
        self.tutorials = {}
        self._init_tutorials()

    def _init_tutorials(self):
        """Initialize all available tutorials."""
        # Beginner Tutorial: Getting Started
        getting_started = Tutorial(
            name="getting_started",
            title="Getting Started with Intellicrack",
            description="Learn the basics of binary analysis with Intellicrack CLI",
            difficulty="beginner",
            estimated_time=15,
            steps=[
                TutorialStep(
                    title="Welcome to Intellicrack",
                    description="Let's start by exploring the help system to understand available commands.",
                    commands=["help"],
                    explanation="The help command shows all available commands in Intellicrack CLI. This is your starting point for any analysis session.",
                    hints=[
                        "Type 'help' and press Enter",
                        "Look for commands related to loading and analyzing binaries",
                    ],
                ),
                TutorialStep(
                    title="Loading a Binary",
                    description="Learn how to load a binary file for analysis.",
                    commands=["load <binary_path>"],
                    explanation="Before analyzing, you need to load a binary file. Use 'load' followed by the path to your binary.",
                    hints=[
                        "Use 'load /path/to/your/binary.exe'",
                        "If you don't have a binary, you can skip this step",
                    ],
                ),
                TutorialStep(
                    title="Quick Analysis",
                    description="Perform a quick analysis to get an overview of the binary.",
                    commands=["analyze --quick"],
                    explanation="Quick analysis provides basic information about the binary including file type, protections, and strings.",
                    hints=[
                        "Make sure you have loaded a binary first",
                        "This will show basic binary information",
                    ],
                ),
                TutorialStep(
                    title="Viewing Results",
                    description="Learn how to view analysis results in different ways.",
                    commands=["show summary", "show protections", "show imports"],
                    explanation="The 'show' command displays analysis results in various formats. Try different categories to explore the data.",
                    hints=[
                        "Start with 'show summary' for an overview",
                        "Try 'show protections' to see security features",
                    ],
                ),
                TutorialStep(
                    title="Exporting Results",
                    description="Save your analysis results to a file.",
                    commands=["export json results.json"],
                    explanation="Export functionality allows you to save analysis results in various formats for later use or reporting.",
                    hints=[
                        "Try different formats: json, html, markdown",
                        "The file will be saved in the current directory",
                    ],
                ),
            ],
            completion_message="🎉 Congratulations! You've completed the Getting Started tutorial. You now know the basics of loading, analyzing, and exporting binary analysis results.",
        )

        # Intermediate Tutorial: Advanced Analysis
        advanced_analysis = Tutorial(
            name="advanced_analysis",
            title="Advanced Binary Analysis Techniques",
            description="Explore advanced analysis features including vulnerability scanning and symbolic execution",
            difficulty="intermediate",
            estimated_time=25,
            prerequisites=["getting_started"],
            steps=[
                TutorialStep(
                    title="Comprehensive Analysis",
                    description="Run a full comprehensive analysis with all features enabled.",
                    commands=["analyze --full"],
                    explanation="Comprehensive analysis performs deep inspection including vulnerability scanning, symbolic execution, and advanced pattern matching.",
                    hints=[
                        "This may take longer than quick analysis",
                        "You'll get much more detailed results",
                    ],
                ),
                TutorialStep(
                    title="Vulnerability Scanning",
                    description="Focus specifically on vulnerability detection.",
                    commands=["analyze --vuln"],
                    explanation="Vulnerability scanning looks for common security issues like buffer overflows, format string bugs, and unsafe function usage.",
                    hints=[
                        "This focuses only on security vulnerabilities",
                        "Results will show severity levels",
                    ],
                ),
                TutorialStep(
                    title="Exploring Vulnerabilities",
                    description="Learn how to examine vulnerability findings in detail.",
                    commands=["show vulnerabilities"],
                    explanation="Understanding vulnerability details helps prioritize security fixes and understand attack vectors.",
                    hints=[
                        "Look for HIGH severity vulnerabilities first",
                        "Each vulnerability includes location and description",
                    ],
                ),
                TutorialStep(
                    title="Interactive Hex Viewer",
                    description="Use the built-in hex viewer to examine binary data.",
                    commands=["hex"],
                    explanation="The hex viewer allows you to inspect raw binary data, make modifications, and understand file structure.",
                    hints=[
                        "Press 'q' to exit the hex viewer",
                        "Use arrow keys to navigate",
                        "Press F1 for help inside the viewer",
                    ],
                    skip_allowed=True,
                ),
                TutorialStep(
                    title="AI-Assisted Analysis",
                    description="Use AI to get insights about your analysis results.",
                    commands=["ai What vulnerabilities were found?"],
                    explanation="The AI assistant can help interpret results, suggest remediation steps, and answer questions about your analysis.",
                    hints=[
                        "Try asking specific questions about vulnerabilities",
                        "AI can explain technical details in plain language",
                    ],
                ),
            ],
            completion_message="🎉 Excellent work! You've mastered advanced analysis techniques. You can now perform comprehensive security assessments.",
        )

        # Project Management Tutorial
        project_management = Tutorial(
            name="project_management",
            title="Project Management and Workflow",
            description="Learn to organize your work with projects, configurations, and collaboration features",
            difficulty="intermediate",
            estimated_time=20,
            steps=[
                TutorialStep(
                    title="Creating a Project",
                    description="Organize your analysis work by creating a project.",
                    commands=['project create MyFirstProject "Learning project management"'],
                    explanation="Projects help organize multiple binaries, analysis results, and collaboration. They provide persistence across sessions.",
                    hints=[
                        "Use descriptive project names",
                        "Projects are stored in ~/.intellicrack/projects/",
                    ],
                ),
                TutorialStep(
                    title="Adding Binaries to Project",
                    description="Add binaries to your project for organized analysis.",
                    commands=["project add-binary"],
                    explanation="Projects can contain multiple binaries. Each binary's analysis results are automatically saved to the project.",
                    hints=[
                        "Load a binary first, then add it to the project",
                        "Or specify a path directly",
                    ],
                ),
                TutorialStep(
                    title="Project Information",
                    description="View detailed information about your project.",
                    commands=["project show"],
                    explanation="Project information shows statistics, contained binaries, analysis results, and project metadata.",
                    hints=[
                        "This shows all project details",
                        "Note the statistics about binaries and analysis results",
                    ],
                ),
                TutorialStep(
                    title="Configuration Management",
                    description="Customize Intellicrack settings for your workflow.",
                    commands=["config list", "config categories"],
                    explanation="Configuration system allows customizing analysis behavior, UI preferences, and performance settings.",
                    hints=[
                        "Try 'config get theme' to see current theme",
                        "Use 'config set' to change settings",
                    ],
                ),
                TutorialStep(
                    title="Exporting Projects",
                    description="Learn to export projects for sharing or backup.",
                    commands=["project export MyFirstProject myproject_backup.zip"],
                    explanation="Project export creates a complete archive including binaries, results, and metadata for sharing or backup.",
                    hints=[
                        "Exported projects can be imported on other systems",
                        "This includes all project data",
                    ],
                ),
            ],
            completion_message="🎉 Great job! You now know how to manage projects efficiently and customize Intellicrack for your workflow.",
        )

        # Dashboard and Monitoring Tutorial
        monitoring_tutorial = Tutorial(
            name="monitoring_dashboard",
            title="Monitoring and Dashboard Features",
            description="Master the monitoring tools, dashboard, and system oversight features",
            difficulty="intermediate",
            estimated_time=15,
            steps=[
                TutorialStep(
                    title="System Status Overview",
                    description="Check current system status and resource usage.",
                    commands=["status"],
                    explanation="The status command provides a quick overview of system health, session statistics, and analysis progress.",
                    hints=[
                        "This shows CPU, memory, and session info",
                        "Great for checking system load",
                    ],
                ),
                TutorialStep(
                    title="Interactive Dashboard",
                    description="Launch the full interactive dashboard.",
                    commands=["dashboard 10"],
                    explanation="The dashboard provides real-time monitoring of system metrics, analysis progress, and session activity.",
                    hints=[
                        "Press Ctrl+C to exit the dashboard",
                        "The number specifies display duration in seconds",
                        "Try 'dashboard --basic' for simple mode",
                    ],
                    skip_allowed=True,
                ),
                TutorialStep(
                    title="Specific Monitoring",
                    description="Monitor specific system metrics in real-time.",
                    commands=["monitor cpu 5"],
                    explanation="Targeted monitoring allows tracking specific metrics like CPU usage, memory consumption, or analysis statistics.",
                    hints=[
                        "Try 'monitor memory 5' for memory usage",
                        "Numbers specify duration in seconds",
                    ],
                ),
                TutorialStep(
                    title="Workspace Management",
                    description="Manage your workspace and clean up temporary files.",
                    commands=["workspace info", "workspace clean"],
                    explanation="Workspace commands help maintain your Intellicrack environment and manage storage usage.",
                    hints=[
                        "This shows workspace location and project count",
                        "Clean removes temporary files",
                    ],
                ),
                TutorialStep(
                    title="Session Statistics",
                    description="View detailed statistics about your analysis session.",
                    commands=["stats"],
                    explanation="Session statistics provide insights into your analysis work including charts and performance metrics.",
                    hints=[
                        "This creates visual charts of your analysis data",
                        "Great for understanding patterns",
                    ],
                ),
            ],
            completion_message="🎉 Perfect! You now have full control over monitoring and can track your analysis work effectively.",
        )

        # Store tutorials
        self.tutorials = {
            "getting_started": getting_started,
            "advanced_analysis": advanced_analysis,
            "project_management": project_management,
            "monitoring_dashboard": monitoring_tutorial,
        }

    def list_tutorials(self) -> None:
        """Display available tutorials."""
        if not self.console:
            self._list_tutorials_basic()
            return

        table = Table(title="📚 Available Tutorials")
        table.add_column("Name", style="cyan")
        table.add_column("Title", style="yellow")
        table.add_column("Difficulty", style="green")
        table.add_column("Time", style="blue")
        table.add_column("Progress", style="magenta")

        for name, tutorial in self.tutorials.items():
            progress = self.tutorial_progress.get(name, 0)
            total_steps = len(tutorial.steps)
            progress_str = f"{progress}/{total_steps}"

            # Difficulty color coding
            if tutorial.difficulty == "beginner":
                difficulty = "[green]Beginner[/green]"
            elif tutorial.difficulty == "intermediate":
                difficulty = "[yellow]Intermediate[/yellow]"
            else:
                difficulty = "[red]Advanced[/red]"

            table.add_row(
                name,
                tutorial.title,
                difficulty,
                f"{tutorial.estimated_time} min",
                progress_str,
            )

        self.console.print(table)

        # Show recommendations
        if not any(self.tutorial_progress.values()):
            self.console.print("\n💡 [bold yellow]Recommendation:[/bold yellow] Start with 'getting_started' if you're new to Intellicrack")

    def _list_tutorials_basic(self):
        """List tutorials in basic text format."""
        print("\nAvailable Tutorials:")
        print("=" * 50)

        for name, tutorial in self.tutorials.items():
            progress = self.tutorial_progress.get(name, 0)
            total_steps = len(tutorial.steps)

            print(f"\n{name}:")
            print(f"  Title: {tutorial.title}")
            print(f"  Difficulty: {tutorial.difficulty}")
            print(f"  Estimated Time: {tutorial.estimated_time} minutes")
            print(f"  Progress: {progress}/{total_steps}")
            print(f"  Description: {tutorial.description}")

        print("\nTo start a tutorial, use: tutorial start <name>")

    def start_tutorial(self, tutorial_name: str) -> bool:
        """Start a tutorial.

        Args:
            tutorial_name: Name of tutorial to start

        Returns:
            True if tutorial started successfully

        """
        if tutorial_name not in self.tutorials:
            return False

        tutorial = self.tutorials[tutorial_name]

        # Check prerequisites
        if tutorial.prerequisites:
            missing_prereqs = []
            for prereq in tutorial.prerequisites:
                if self.tutorial_progress.get(prereq, 0) < len(self.tutorials[prereq].steps):
                    missing_prereqs.append(prereq)

            if missing_prereqs:
                if self.console:
                    self.console.print(f"[red]Prerequisites not met:[/red] {', '.join(missing_prereqs)}")
                else:
                    print(f"Prerequisites not met: {', '.join(missing_prereqs)}")
                return False

        self.current_tutorial = tutorial
        self.current_step = self.tutorial_progress.get(tutorial_name, 0)

        self._show_tutorial_intro()
        return True

    def _show_tutorial_intro(self):
        """Show tutorial introduction."""
        tutorial = self.current_tutorial

        if self.console:
            intro_content = f"""[bold cyan]{tutorial.title}[/bold cyan]

{tutorial.description}

[yellow]Difficulty:[/yellow] {tutorial.difficulty.title()}
[yellow]Estimated Time:[/yellow] {tutorial.estimated_time} minutes
[yellow]Steps:[/yellow] {len(tutorial.steps)}

[dim]You can type 'tutorial help' at any time for navigation commands.[/dim]"""

            intro_panel = Panel(
                intro_content,
                title="📚 Tutorial Introduction",
                border_style="blue",
            )
            self.console.print(intro_panel)
        else:
            print(f"\n{tutorial.title}")
            print("=" * len(tutorial.title))
            print(f"\n{tutorial.description}")
            print(f"\nDifficulty: {tutorial.difficulty}")
            print(f"Estimated Time: {tutorial.estimated_time} minutes")
            print(f"Steps: {len(tutorial.steps)}")
            print("\nType 'tutorial help' for navigation commands.")

        # Start first step
        self._show_current_step()

    def _show_current_step(self):
        """Show current tutorial step."""
        if not self.current_tutorial:
            return

        if self.current_step >= len(self.current_tutorial.steps):
            self._complete_tutorial()
            return

        step = self.current_tutorial.steps[self.current_step]
        step_num = self.current_step + 1
        total_steps = len(self.current_tutorial.steps)

        if self.console:
            # Create step panel
            step_content = f"""[bold yellow]Step {step_num}/{total_steps}: {step.title}[/bold yellow]

{step.description}

[bold green]Commands to try:[/bold green]"""

            for cmd in step.commands:
                step_content += f"\n  [cyan]{cmd}[/cyan]"

            if step.explanation:
                step_content += f"\n\n[bold blue]Explanation:[/bold blue]\n{step.explanation}"

            if step.hints:
                step_content += "\n\n[bold magenta]Hints:[/bold magenta]"
                for hint in step.hints:
                    step_content += f"\n  💡 {hint}"

            step_panel = Panel(
                step_content,
                title=f"📝 Tutorial Step {step_num}",
                border_style="green",
            )
            self.console.print(step_panel)

            # Navigation help
            nav_text = "[dim]Commands: 'tutorial next' | 'tutorial prev' | 'tutorial skip' | 'tutorial quit'[/dim]"
            self.console.print(nav_text)
        else:
            print(f"\n--- Step {step_num}/{total_steps}: {step.title} ---")
            print(f"\n{step.description}")
            print("\nCommands to try:")
            for cmd in step.commands:
                print(f"  {cmd}")

            if step.explanation:
                print(f"\nExplanation: {step.explanation}")

            if step.hints:
                print("\nHints:")
                for hint in step.hints:
                    print(f"  💡 {hint}")

            print("\nNavigation: 'tutorial next' | 'tutorial prev' | 'tutorial skip' | 'tutorial quit'")

        # Prompt for command execution
        self._prompt_for_command()

    def _prompt_for_command(self):
        """Prompt user to execute the tutorial command interactively."""
        if not self.current_tutorial or self.current_step >= len(self.current_tutorial.steps):
            return

        step = self.current_tutorial.steps[self.current_step]

        # Interactive prompt loop
        while True:
            try:
                # Get user input
                if self.console and RICH_AVAILABLE:
                    user_input = Prompt.ask("\n[bold cyan]Tutorial>[/bold cyan]")
                else:
                    user_input = input("\nTutorial> ").strip()

                if not user_input:
                    continue

                # Check for navigation commands
                if user_input.lower() in ["next", "tutorial next"]:
                    self.next_step()
                    break
                elif user_input.lower() in ["prev", "tutorial prev"]:
                    self.prev_step()
                    break
                elif user_input.lower() in ["skip", "tutorial skip"]:
                    if self.skip_step():
                        break
                elif user_input.lower() in ["quit", "tutorial quit", "exit"]:
                    self.quit_tutorial()
                    break
                elif user_input.lower() in ["help", "tutorial help"]:
                    self.show_help()
                    continue
                elif user_input.lower() == "hint":
                    if step.hints:
                        if self.console:
                            for hint in step.hints:
                                self.console.print(f"[yellow]💡 {hint}[/yellow]")
                        else:
                            for hint in step.hints:
                                print(f"💡 {hint}")
                    else:
                        print("No hints available for this step.")
                    continue
                else:
                    # Try to execute as a tutorial command
                    success, message = self.execute_step(user_input)

                    if self.console:
                        if success:
                            self.console.print(f"[green]{message}[/green]")
                            # Auto-advance to next step on success
                            self.next_step()
                            break
                        else:
                            self.console.print(f"[yellow]{message}[/yellow]")
                    else:
                        print(message)
                        if success:
                            # Auto-advance to next step on success
                            self.next_step()
                            break

            except KeyboardInterrupt:
                print("\nUse 'quit' to exit the tutorial")
                continue
            except EOFError:
                self.quit_tutorial()
                break

    def execute_step(self, user_command: str) -> tuple[bool, str]:
        """Execute and validate a tutorial step command.

        Args:
            user_command: Command entered by the user

        Returns:
            Tuple of (success, message)

        """
        if not self.current_tutorial or self.current_step >= len(self.current_tutorial.steps):
            return False, "No active tutorial step"

        step = self.current_tutorial.steps[self.current_step]

        # Check if command matches expected commands
        command_matched = False
        for expected_cmd in step.commands:
            # Handle placeholder commands (e.g., <binary_path>)
            if "<" in expected_cmd and ">" in expected_cmd:
                # Extract the base command
                base_cmd = expected_cmd.split("<")[0].strip()
                if user_command.startswith(base_cmd):
                    command_matched = True
                    break
            elif user_command.strip() == expected_cmd.strip():
                command_matched = True
                break

        if not command_matched:
            # Provide helpful feedback
            hint_msg = "That's not quite right. Expected one of:\n"
            for cmd in step.commands:
                hint_msg += f"  • {cmd}\n"
            if step.hints:
                hint_msg += "\nHints:\n"
                for hint in step.hints:
                    hint_msg += f"  • {hint}\n"
            return False, hint_msg

        # Execute the command if CLI instance is available
        result_output = ""
        if self.cli_instance:
            try:
                import subprocess
                import sys

                # Execute command through CLI
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                    [sys.executable, "-m", "intellicrack.cli.cli"] + user_command.split(),
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False,  # Explicitly secure - using list format prevents shell injection
                )
                result_output = result.stdout + result.stderr

            except Exception as e:
                result_output = f"Command execution error: {e}"

        # Run custom validation if provided
        if step.validation:
            try:
                validation_result = step.validation(user_command, result_output)
                if not validation_result:
                    return (
                        False,
                        "Command executed but validation failed. Check the output and try again.",
                    )
            except Exception as e:
                # Validation function error - continue anyway
                if hasattr(self, "debug") and self.debug:
                    print(f"Debug: Validation function error: {e}")

        # Check expected output if provided
        if step.expected_output:
            if step.expected_output not in result_output:
                return (
                    False,
                    f"Command executed but output doesn't match expected result.\nExpected to see: {step.expected_output}",
                )

        # Success! Mark step as completed
        success_msg = "✅ Step completed successfully!"
        if step.explanation:
            success_msg += f"\n\n{step.explanation}"

        return True, success_msg

    def next_step(self):
        """Move to next tutorial step."""
        if not self.current_tutorial:
            return False

        self.current_step += 1

        # Update progress
        tutorial_name = self.current_tutorial.name
        self.tutorial_progress[tutorial_name] = max(
            self.tutorial_progress.get(tutorial_name, 0),
            self.current_step,
        )

        self._show_current_step()
        return True

    def prev_step(self):
        """Move to previous tutorial step."""
        if not self.current_tutorial or self.current_step <= 0:
            return False

        self.current_step -= 1
        self._show_current_step()
        return True

    def skip_step(self):
        """Skip current tutorial step."""
        if not self.current_tutorial:
            return False

        step = self.current_tutorial.steps[self.current_step]
        if not step.skip_allowed:
            if self.console:
                self.console.print("[red]This step cannot be skipped[/red]")
            else:
                print("This step cannot be skipped")
            return False

        return self.next_step()

    def quit_tutorial(self):
        """Quit current tutorial."""
        if not self.current_tutorial:
            return False

        # Save progress
        tutorial_name = self.current_tutorial.name
        self.tutorial_progress[tutorial_name] = max(
            self.tutorial_progress.get(tutorial_name, 0),
            self.current_step,
        )

        # Add to history
        self.tutorial_history.append(
            {
                "name": tutorial_name,
                "completed_steps": self.current_step,
                "total_steps": len(self.current_tutorial.steps),
                "quit_time": datetime.now(),
            }
        )

        if self.console:
            self.console.print(f"[yellow]Tutorial '{tutorial_name}' paused at step {self.current_step + 1}[/yellow]")
            self.console.print("[dim]You can resume later with 'tutorial resume'[/dim]")
        else:
            print(f"Tutorial '{tutorial_name}' paused at step {self.current_step + 1}")
            print("You can resume later with 'tutorial resume'")

        self.current_tutorial = None
        self.current_step = 0
        return True

    def _complete_tutorial(self):
        """Complete current tutorial."""
        if not self.current_tutorial:
            return

        tutorial_name = self.current_tutorial.name
        tutorial = self.current_tutorial

        # Mark as completed
        self.tutorial_progress[tutorial_name] = len(tutorial.steps)

        # Add to history
        self.tutorial_history.append(
            {
                "name": tutorial_name,
                "completed_steps": len(tutorial.steps),
                "total_steps": len(tutorial.steps),
                "completion_time": datetime.now(),
            }
        )

        # Show completion message
        if self.console:
            completion_panel = Panel(
                tutorial.completion_message,
                title="🎉 Tutorial Completed!",
                border_style="green",
            )
            self.console.print(completion_panel)

            # Show next recommendations
            self._show_next_recommendations()
        else:
            print("\n🎉 Tutorial Completed!")
            print("=" * 30)
            print(tutorial.completion_message)
            self._show_next_recommendations()

        self.current_tutorial = None
        self.current_step = 0

    def _show_next_recommendations(self):
        """Show recommended next tutorials."""
        completed = set(name for name, progress in self.tutorial_progress.items() if progress >= len(self.tutorials[name].steps))

        recommendations = []

        if "getting_started" in completed and "advanced_analysis" not in completed:
            recommendations.append("advanced_analysis")

        if "getting_started" in completed and "project_management" not in completed:
            recommendations.append("project_management")

        if len(completed) >= 2 and "monitoring_dashboard" not in completed:
            recommendations.append("monitoring_dashboard")

        if recommendations:
            if self.console:
                rec_text = "Consider trying these tutorials next:\n"
                for rec in recommendations:
                    tutorial = self.tutorials[rec]
                    rec_text += f"  • [cyan]{rec}[/cyan] - {tutorial.title}\n"

                rec_panel = Panel(rec_text.strip(), title="📖 Next Steps", border_style="blue")
                self.console.print(rec_panel)
            else:
                print("\nRecommended next tutorials:")
                for rec in recommendations:
                    tutorial = self.tutorials[rec]
                    print(f"  • {rec} - {tutorial.title}")

    def resume_tutorial(self) -> bool:
        """Resume the most recent tutorial."""
        if not self.tutorial_history:
            return False

        # Find most recent incomplete tutorial
        for entry in reversed(self.tutorial_history):
            if entry["completed_steps"] < entry["total_steps"]:
                tutorial_name = entry["name"]
                if tutorial_name in self.tutorials:
                    return self.start_tutorial(tutorial_name)

        return False

    def show_progress(self):
        """Show tutorial progress summary."""
        if not self.console:
            self._show_progress_basic()
            return

        # Create progress table
        progress_table = Table(title="📊 Tutorial Progress")
        progress_table.add_column("Tutorial", style="cyan")
        progress_table.add_column("Progress", style="yellow")
        progress_table.add_column("Status", style="green")

        for name, tutorial in self.tutorials.items():
            completed_steps = self.tutorial_progress.get(name, 0)
            total_steps = len(tutorial.steps)

            progress_bar = f"{completed_steps}/{total_steps}"

            if completed_steps == 0:
                status = "[dim]Not Started[/dim]"
            elif completed_steps < total_steps:
                status = "[yellow]In Progress[/yellow]"
            else:
                status = "[green]Completed OK[/green]"

            progress_table.add_row(tutorial.title, progress_bar, status)

        self.console.print(progress_table)

    def _show_progress_basic(self):
        """Show progress in basic text format."""
        print("\nTutorial Progress:")
        print("=" * 40)

        for name, tutorial in self.tutorials.items():
            completed_steps = self.tutorial_progress.get(name, 0)
            total_steps = len(tutorial.steps)

            status = "Not Started"
            if completed_steps > 0:
                status = "In Progress" if completed_steps < total_steps else "Completed OK"

            print(f"\n{tutorial.title}")
            print(f"  Progress: {completed_steps}/{total_steps}")
            print(f"  Status: {status}")

    def show_help(self):
        """Show tutorial system help."""
        if self.console:
            help_content = """[bold cyan]Tutorial System Commands[/bold cyan]

[bold yellow]General Commands:[/bold yellow]
  [cyan]tutorial list[/cyan]              - List available tutorials
  [cyan]tutorial start <name>[/cyan]      - Start a specific tutorial
  [cyan]tutorial progress[/cyan]          - Show completion progress
  [cyan]tutorial resume[/cyan]            - Resume most recent tutorial

[bold yellow]During Tutorial:[/bold yellow]
  [cyan]tutorial next[/cyan]              - Move to next step
  [cyan]tutorial prev[/cyan]              - Go to previous step
  [cyan]tutorial skip[/cyan]              - Skip current step (if allowed)
  [cyan]tutorial quit[/cyan]              - Quit current tutorial
  [cyan]tutorial help[/cyan]              - Show this help

[bold green]Tips:[/bold green]
  • Follow the commands exactly as shown
  • Read explanations to understand concepts
  • Use hints if you get stuck
  • Take your time - tutorials are self-paced"""

            help_panel = Panel(help_content, title="📚 Tutorial Help", border_style="blue")
            self.console.print(help_panel)
        else:
            print("\nTutorial System Commands:")
            print("=" * 30)
            print("\nGeneral Commands:")
            print("  tutorial list     - List available tutorials")
            print("  tutorial start <name> - Start a specific tutorial")
            print("  tutorial progress - Show completion progress")
            print("  tutorial resume   - Resume most recent tutorial")
            print("\nDuring Tutorial:")
            print("  tutorial next     - Move to next step")
            print("  tutorial prev     - Go to previous step")
            print("  tutorial skip     - Skip current step")
            print("  tutorial quit     - Quit current tutorial")
            print("  tutorial help     - Show this help")

    def display_tutorial_cards(self) -> None:
        """Display available tutorials as cards using Columns."""
        if not RICH_AVAILABLE or not self.console:
            return

        # Create tutorial cards
        cards = []
        for tutorial in self.tutorials.values():
            # Determine difficulty color
            diff_colors = {
                "beginner": "green",
                "intermediate": "yellow",
                "advanced": "red",
            }
            diff_color = diff_colors.get(tutorial.difficulty, "white")

            # Create card content
            card_content = f"[bold {diff_color}]{tutorial.difficulty.title()}[/bold {diff_color}]\n"
            card_content += f"⏱️ {tutorial.estimated_time} min\n"
            card_content += f"📚 {len(tutorial.steps)} steps\n\n"
            card_content += (
                f"[dim]{tutorial.description[:50]}...[/dim]" if len(tutorial.description) > 50 else f"[dim]{tutorial.description}[/dim]"
            )

            # Check completion status
            completion = self.tutorial_progress.get(tutorial.name, {"completed": False, "progress": 0})
            if completion["completed"]:
                border_style = "green"
                title_prefix = "✅ "
            elif completion["progress"] > 0:
                border_style = "yellow"
                title_prefix = "🔄 "
            else:
                border_style = "blue"
                title_prefix = "📖 "

            card = Panel(
                card_content,
                title=f"{title_prefix}{tutorial.title}",
                border_style=border_style,
                width=25,
            )
            cards.append(card)

        # Display cards in columns
        if cards:
            columns = Columns(cards, equal=True, expand=False)
            self.console.print(columns)

    def display_centered_tutorial_header(self, tutorial: Tutorial) -> None:
        """Display tutorial header with centered alignment using Align."""
        if not RICH_AVAILABLE or not self.console:
            return

        # Create header content
        header_text = Text()
        header_text.append(f"📚 {tutorial.title}\n", style="bold blue")
        header_text.append(f"Difficulty: {tutorial.difficulty.title()} | ", style="cyan")
        header_text.append(f"Estimated time: {tutorial.estimated_time} minutes\n", style="cyan")
        header_text.append(f"{tutorial.description}", style="dim")

        # Center the header using Align
        centered_header = Align.center(header_text)

        # Wrap in a panel and display
        header_panel = Panel(
            centered_header,
            title="🎓 Tutorial Information",
            border_style="blue",
            padding=(1, 2),
        )

        self.console.print(header_panel)

    def show_tutorial_progress_bar(self, tutorial_name: str) -> None:
        """Show tutorial progress using Progress bar."""
        if not RICH_AVAILABLE or not self.console:
            return

        tutorial = self.tutorials.get(tutorial_name)
        if not tutorial:
            return

        progress_data = self.tutorial_progress.get(tutorial_name, {"progress": 0})
        current_step = progress_data.get("progress", 0)
        total_steps = len(tutorial.steps)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console,
        ) as progress:
            task = progress.add_task(f"Tutorial: {tutorial.title}", total=total_steps)
            progress.update(task, completed=current_step)

    def display_step_with_syntax(self, step: TutorialStep) -> None:
        """Display tutorial step with syntax highlighting using Syntax."""
        if not RICH_AVAILABLE or not self.console:
            return

        # Display step title and description
        step_panel = Panel(
            f"[bold cyan]{step.title}[/bold cyan]\n\n{step.description}",
            title="📖 Tutorial Step",
            border_style="blue",
        )
        self.console.print(step_panel)

        # Display commands with syntax highlighting
        if step.commands:
            for cmd in step.commands:
                syntax = Syntax(cmd, "bash", theme="monokai", line_numbers=False)
                cmd_panel = Panel(
                    syntax,
                    title="💻 Command to Run",
                    border_style="green",
                )
                self.console.print(cmd_panel)

        # Display explanation if available
        if step.explanation:
            explanation_panel = Panel(
                step.explanation,
                title="💡 Explanation",
                border_style="yellow",
            )
            self.console.print(explanation_panel)

    def interactive_tutorial_selection(self) -> str | None:
        """Interactive tutorial selection using Prompt."""
        if not RICH_AVAILABLE or not self.console:
            return None

        tutorial_names = list(self.tutorials.keys())
        if not tutorial_names:
            return None

        # Show available tutorials
        self.console.print("[bold cyan]Available Tutorials:[/bold cyan]")
        for i, name in enumerate(tutorial_names, 1):
            tutorial = self.tutorials[name]
            self.console.print(f"  {i}. {tutorial.title} ({tutorial.difficulty})")

        # Get user selection
        try:
            selection = IntPrompt.ask(
                "Select tutorial number",
                choices=[str(i) for i in range(1, len(tutorial_names) + 1)],
            )
            return tutorial_names[selection - 1]
        except (KeyboardInterrupt, ValueError):
            return None

    def confirm_tutorial_reset(self, tutorial_name: str) -> bool:
        """Confirm tutorial reset using Confirm."""
        if not RICH_AVAILABLE or not self.console:
            return False

        tutorial = self.tutorials.get(tutorial_name)
        if not tutorial:
            return False

        return Confirm.ask(
            f"[yellow]Reset progress for tutorial '{tutorial.title}'?[/yellow]",
            default=False,
        )

    def get_custom_tutorial_settings(self) -> dict[str, Any]:
        """Get custom tutorial settings using Prompt."""
        if not RICH_AVAILABLE or not self.console:
            return {}

        settings = {}

        # Get custom settings from user
        settings["auto_advance"] = Confirm.ask("Enable auto-advance to next step?", default=False)
        settings["show_hints"] = Confirm.ask("Show hints automatically?", default=True)

        if Confirm.ask("Set custom step timeout?", default=False):
            settings["step_timeout"] = IntPrompt.ask("Step timeout (seconds)", default=30)

        difficulty_filter = Prompt.ask(
            "Filter tutorials by difficulty",
            choices=["all", "beginner", "intermediate", "advanced"],
            default="all",
        )
        settings["difficulty_filter"] = difficulty_filter

        return settings

    def display_tutorials_table(self) -> None:
        """Display tutorials in a formatted table using Table."""
        if not RICH_AVAILABLE or not self.console:
            return

        table = Table(title="📚 Available Tutorials", show_header=True, header_style="bold magenta")
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Title", style="blue")
        table.add_column("Difficulty", style="yellow")
        table.add_column("Duration", style="green", justify="right")
        table.add_column("Steps", style="white", justify="center")
        table.add_column("Status", style="magenta")

        for name, tutorial in self.tutorials.items():
            # Get completion status
            progress_data = self.tutorial_progress.get(name, {"completed": False, "progress": 0})
            if progress_data["completed"]:
                status = "✅ Complete"
            elif progress_data["progress"] > 0:
                status = f"🔄 {progress_data['progress']}/{len(tutorial.steps)}"
            else:
                status = "📖 Not Started"

            table.add_row(
                name,
                tutorial.title,
                tutorial.difficulty.title(),
                f"{tutorial.estimated_time} min",
                str(len(tutorial.steps)),
                status,
            )

        self.console.print(table)

    def display_tutorial_structure_tree(self, tutorial_name: str) -> None:
        """Display tutorial structure as a tree using Tree."""
        if not RICH_AVAILABLE or not self.console:
            return

        tutorial = self.tutorials.get(tutorial_name)
        if not tutorial:
            return

        # Create main tutorial tree
        tree = Tree(f"📚 [bold blue]{tutorial.title}[/bold blue]")

        # Add tutorial metadata
        info_node = tree.add("ℹ️ [bold cyan]Tutorial Information[/bold cyan]")
        info_node.add(f"📊 Difficulty: {tutorial.difficulty.title()}")
        info_node.add(f"⏱️ Estimated Time: {tutorial.estimated_time} minutes")
        info_node.add(f"📝 Description: {tutorial.description}")

        # Add tutorial steps
        steps_node = tree.add(f"📋 [bold yellow]Tutorial Steps ({len(tutorial.steps)})[/bold yellow]")

        for i, step in enumerate(tutorial.steps, 1):
            step_icon = "✅" if i <= self.tutorial_progress.get(tutorial_name, {}).get("progress", 0) else "📖"
            step_node = steps_node.add(f"{step_icon} [cyan]Step {i}: {step.title}[/cyan]")

            # Add step details
            if step.commands:
                commands_node = step_node.add("💻 Commands")
                for cmd in step.commands[:3]:  # Limit to first 3 commands
                    commands_node.add(f"▶️ {cmd}")
                if len(step.commands) > 3:
                    commands_node.add(f"... and {len(step.commands) - 3} more")

            if step.hints:
                hints_node = step_node.add("💡 Hints Available")
                for hint in step.hints[:2]:  # Limit to first 2 hints
                    hints_node.add(f"💭 {hint}")
                if len(step.hints) > 2:
                    hints_node.add(f"... and {len(step.hints) - 2} more")

        self.console.print(tree)


def create_tutorial_system(cli_instance=None) -> TutorialSystem:
    """Create tutorial system instance."""
    return TutorialSystem(cli_instance)


def run_interactive_tutorial(cli_instance=None):
    """Run the interactive tutorial system."""
    tutorial_system = TutorialSystem(cli_instance)

    # Show welcome message
    if tutorial_system.console:
        welcome = Panel(
            """Welcome to the Intellicrack Interactive Tutorial System!

This system will guide you through learning Intellicrack's features
step by step with hands-on exercises.

Start with 'getting_started' if you're new to Intellicrack.""",
            title="🎓 Tutorial System",
            border_style="cyan",
        )
        tutorial_system.console.print(welcome)
    else:
        print("\n" + "=" * 60)
        print("Welcome to the Intellicrack Interactive Tutorial System!")
        print("=" * 60)
        print("\nThis system will guide you through learning Intellicrack's features")
        print("step by step with hands-on exercises.")
        print("\nStart with 'getting_started' if you're new to Intellicrack.")

    # List available tutorials
    tutorial_system.list_tutorials()

    # Interactive loop
    while True:
        try:
            if tutorial_system.console and RICH_AVAILABLE:
                command = Prompt.ask("\n[bold cyan]Tutorial System>[/bold cyan]")
            else:
                command = input("\nTutorial System> ").strip()

            if not command:
                continue

            parts = command.lower().split()

            if parts[0] in ["exit", "quit"]:
                print("Goodbye!")
                break
            elif parts[0] == "list":
                tutorial_system.list_tutorials()
            elif parts[0] == "start" and len(parts) > 1:
                tutorial_name = parts[1]
                if tutorial_system.start_tutorial(tutorial_name):
                    # Tutorial will handle its own interactive loop
                    pass
                else:
                    print(f"Tutorial '{tutorial_name}' not found. Use 'list' to see available tutorials.")
            elif parts[0] == "resume":
                if not tutorial_system.resume_tutorial():
                    print("No tutorial to resume.")
            elif parts[0] == "progress":
                tutorial_system.show_progress()
            elif parts[0] == "help":
                tutorial_system.show_help()
            else:
                print("Unknown command. Type 'help' for available commands.")

        except KeyboardInterrupt:
            print("\nUse 'exit' to quit the tutorial system.")
            continue
        except EOFError:
            break

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(run_interactive_tutorial())
