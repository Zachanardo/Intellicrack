"""Comprehensive tests for tutorial system.

Tests validate tutorial state management, workflow completion tracking,
user progression, command validation, and interactive features.
"""

from typing import Any

import pytest

from intellicrack.cli.tutorial_system import (
    Tutorial,
    TutorialStep,
    TutorialSystem,
)


class TestTutorialStep:
    """Test tutorial step data structure."""

    def test_tutorial_step_creation_with_all_fields(self) -> None:
        """Test creating tutorial step with complete data."""
        step = TutorialStep(
            title="Test Step",
            description="This is a test step",
            commands=["help", "analyze --quick"],
            explanation="This demonstrates basic commands",
            expected_output="Analysis complete",
            validation=lambda cmd, output: "complete" in output,
            hints=["Try help first", "Use --quick flag"],
            prerequisites=["previous_step"],
            skip_allowed=False
        )

        assert step.title == "Test Step"
        assert len(step.commands) == 2
        assert len(step.hints) == 2
        assert step.skip_allowed is False

    def test_tutorial_step_minimal_fields(self) -> None:
        """Test tutorial step with only required fields."""
        step = TutorialStep(
            title="Minimal Step",
            description="Basic step"
        )

        assert step.title == "Minimal Step"
        assert len(step.commands) == 0
        assert step.skip_allowed is True


class TestTutorial:
    """Test tutorial data structure."""

    def test_tutorial_creation_complete(self) -> None:
        """Test creating complete tutorial."""
        steps = [
            TutorialStep(title="Step 1", description="First step"),
            TutorialStep(title="Step 2", description="Second step"),
        ]

        tutorial = Tutorial(
            name="test_tutorial",
            title="Test Tutorial",
            description="A tutorial for testing",
            difficulty="beginner",
            estimated_time=10,
            steps=steps,
            completion_message="Well done!",
            prerequisites=[]
        )

        assert tutorial.name == "test_tutorial"
        assert tutorial.difficulty == "beginner"
        assert len(tutorial.steps) == 2
        assert tutorial.estimated_time == 10

    def test_tutorial_difficulty_levels(self) -> None:
        """Test tutorial supports different difficulty levels."""
        for difficulty in ["beginner", "intermediate", "advanced"]:
            tutorial = Tutorial(
                name="test",
                title="Test",
                description="Test",
                difficulty=difficulty
            )

            assert tutorial.difficulty == difficulty


class TestTutorialSystem:
    """Test tutorial system functionality."""

    def test_tutorial_system_initialization(self) -> None:
        """Test tutorial system initializes with tutorials."""
        system = TutorialSystem()

        assert len(system.tutorials) > 0
        assert "getting_started" in system.tutorials
        assert system.current_tutorial is None
        assert system.current_step == 0

    def test_all_tutorials_have_required_fields(self) -> None:
        """Test all initialized tutorials have required fields."""
        system = TutorialSystem()

        for name, tutorial in system.tutorials.items():
            assert tutorial.name == name
            assert tutorial.title
            assert tutorial.description
            assert tutorial.difficulty in ["beginner", "intermediate", "advanced"]
            assert tutorial.estimated_time > 0
            assert len(tutorial.steps) > 0

    def test_start_tutorial_sets_current_tutorial(self) -> None:
        """Test starting a tutorial sets it as current."""
        system = TutorialSystem()

        success = system.start_tutorial("getting_started")

        assert success is True
        assert system.current_tutorial is not None
        assert system.current_tutorial.name == "getting_started"

    def test_start_nonexistent_tutorial_returns_false(self) -> None:
        """Test starting nonexistent tutorial returns False."""
        system = TutorialSystem()

        success = system.start_tutorial("nonexistent")

        assert success is False
        assert system.current_tutorial is None

    def test_start_tutorial_with_missing_prerequisites(self) -> None:
        """Test starting tutorial with missing prerequisites."""
        system = TutorialSystem()

        tutorial_with_prereqs = None
        for tutorial in system.tutorials.values():
            if tutorial.prerequisites:
                tutorial_with_prereqs = tutorial.name
                break

        if tutorial_with_prereqs:
            success = system.start_tutorial(tutorial_with_prereqs)

            assert success is False

    def test_next_step_advances_progress(self) -> None:
        """Test next_step advances to next tutorial step."""
        system = TutorialSystem()
        system.start_tutorial("getting_started")

        initial_step = system.current_step

        system.next_step()

        assert system.current_step == initial_step + 1

    def test_prev_step_goes_backwards(self) -> None:
        """Test prev_step goes to previous step."""
        system = TutorialSystem()
        system.start_tutorial("getting_started")

        system.next_step()
        system.next_step()
        system.prev_step()

        assert system.current_step == 1

    def test_prev_step_at_start_returns_false(self) -> None:
        """Test prev_step at beginning returns False."""
        system = TutorialSystem()
        system.start_tutorial("getting_started")

        result = system.prev_step()

        assert result is False
        assert system.current_step == 0

    def test_skip_step_allowed_when_permitted(self) -> None:
        """Test skipping step when skip_allowed is True."""
        system = TutorialSystem()
        system.start_tutorial("getting_started")

        initial_step = system.current_step

        if system.current_tutorial and system.current_step < len(system.current_tutorial.steps):
            step = system.current_tutorial.steps[system.current_step]
            if step.skip_allowed:
                result = system.skip_step()
                assert result is True
                assert system.current_step == initial_step + 1

    def test_skip_step_not_allowed_when_prohibited(self) -> None:
        """Test skipping step is denied when skip_allowed is False."""
        system = TutorialSystem()

        tutorial = Tutorial(
            name="no_skip",
            title="No Skip Tutorial",
            description="Test",
            steps=[
                TutorialStep(
                    title="Mandatory",
                    description="Cannot skip",
                    skip_allowed=False
                )
            ]
        )

        system.tutorials["no_skip"] = tutorial
        system.start_tutorial("no_skip")

        result = system.skip_step()

        assert result is False

    def test_quit_tutorial_saves_progress(self) -> None:
        """Test quitting tutorial saves current progress."""
        system = TutorialSystem()
        system.start_tutorial("getting_started")

        system.next_step()
        system.next_step()

        progress_before = system.current_step

        system.quit_tutorial()

        assert system.current_tutorial is None
        assert system.tutorial_progress["getting_started"] == progress_before

    def test_resume_tutorial_continues_from_saved_progress(self) -> None:
        """Test resuming tutorial starts from saved progress."""
        system = TutorialSystem()

        system.start_tutorial("getting_started")
        system.next_step()
        system.quit_tutorial()

        success = system.resume_tutorial()

        assert success is True
        assert system.current_tutorial is not None

    def test_execute_step_validates_command(self) -> None:
        """Test execute_step validates user commands."""
        system = TutorialSystem()
        system.start_tutorial("getting_started")

        if system.current_tutorial and system.current_step < len(system.current_tutorial.steps):
            step = system.current_tutorial.steps[system.current_step]
            if step.commands:
                expected_command = step.commands[0]

                success, message = system.execute_step(expected_command)

                assert isinstance(success, bool)
                assert isinstance(message, str)

    def test_execute_step_handles_parameterized_commands(self) -> None:
        """Test execute_step handles commands with parameters."""
        system = TutorialSystem()

        tutorial = Tutorial(
            name="param_test",
            title="Parameter Test",
            description="Test",
            steps=[
                TutorialStep(
                    title="Load Binary",
                    description="Load a binary",
                    commands=["load <binary_path>"]
                )
            ]
        )

        system.tutorials["param_test"] = tutorial
        system.start_tutorial("param_test")

        success, message = system.execute_step("load /path/to/binary.exe")

        assert isinstance(success, bool)
        assert isinstance(message, str)

    def test_execute_step_wrong_command_provides_hints(self) -> None:
        """Test execute_step provides hints for wrong commands."""
        system = TutorialSystem()
        system.start_tutorial("getting_started")

        success, message = system.execute_step("wrong_command")

        assert success is False
        assert "Expected" in message or "not quite right" in message

    def test_tutorial_progress_tracking(self) -> None:
        """Test tutorial progress is tracked correctly."""
        system = TutorialSystem()

        system.start_tutorial("getting_started")

        assert "getting_started" in system.tutorial_progress
        assert system.tutorial_progress["getting_started"] >= 0

        system.next_step()

        assert system.tutorial_progress["getting_started"] > 0

    def test_tutorial_history_records_completions(self) -> None:
        """Test tutorial history records completion attempts."""
        system = TutorialSystem()

        system.start_tutorial("getting_started")
        system.quit_tutorial()

        assert len(system.tutorial_history) > 0
        assert system.tutorial_history[-1]["name"] == "getting_started"

    def test_tutorial_completion_updates_progress(self) -> None:
        """Test completing tutorial updates progress to max."""
        system = TutorialSystem()

        tutorial = Tutorial(
            name="short_tutorial",
            title="Short Tutorial",
            description="Test",
            steps=[
                TutorialStep(title="Step 1", description="First"),
                TutorialStep(title="Step 2", description="Second"),
            ]
        )

        system.tutorials["short_tutorial"] = tutorial
        system.start_tutorial("short_tutorial")

        for _ in range(len(tutorial.steps)):
            system.next_step()

        assert system.tutorial_progress["short_tutorial"] == len(tutorial.steps)

    def test_get_custom_tutorial_settings_without_rich(self) -> None:
        """Test getting tutorial settings when rich is not available."""
        system = TutorialSystem()

        settings = system.get_custom_tutorial_settings()

        assert isinstance(settings, dict)

    def test_confirm_tutorial_reset_without_rich(self) -> None:
        """Test tutorial reset confirmation without rich."""
        system = TutorialSystem()

        result = system.confirm_tutorial_reset("getting_started")

        assert isinstance(result, bool)

    def test_interactive_tutorial_selection_without_rich(self) -> None:
        """Test interactive tutorial selection without rich."""
        system = TutorialSystem()

        result = system.interactive_tutorial_selection()

        assert result is None or isinstance(result, str)


class TestTutorialStepValidation:
    """Test tutorial step validation functionality."""

    def test_step_validation_function_success(self) -> None:
        """Test step validation function evaluates correctly."""
        def always_valid(command: str, output: str) -> bool:
            return True

        step = TutorialStep(
            title="Test",
            description="Test",
            validation=always_valid
        )

        assert step.validation is not None
        assert step.validation("test", "output") is True

    def test_step_validation_function_failure(self) -> None:
        """Test step validation function can fail."""
        def always_invalid(command: str, output: str) -> bool:
            return False

        step = TutorialStep(
            title="Test",
            description="Test",
            validation=always_invalid
        )

        assert step.validation is not None
        assert step.validation("test", "output") is False

    def test_step_expected_output_matching(self) -> None:
        """Test step expected output validation."""
        step = TutorialStep(
            title="Test",
            description="Test",
            expected_output="Success"
        )

        assert step.expected_output == "Success"


class TestTutorialSystemEdgeCases:
    """Test edge cases and error handling."""

    def test_start_tutorial_without_steps(self) -> None:
        """Test starting tutorial with no steps."""
        system = TutorialSystem()

        tutorial = Tutorial(
            name="empty",
            title="Empty",
            description="No steps",
            steps=[]
        )

        system.tutorials["empty"] = tutorial

        success = system.start_tutorial("empty")

        assert success is True

    def test_next_step_at_end_of_tutorial(self) -> None:
        """Test next_step at end of tutorial."""
        system = TutorialSystem()

        tutorial = Tutorial(
            name="one_step",
            title="One Step",
            description="Test",
            steps=[TutorialStep(title="Only", description="One step")]
        )

        system.tutorials["one_step"] = tutorial
        system.start_tutorial("one_step")

        system.next_step()
        system.next_step()

        assert system.current_tutorial is None

    def test_quit_tutorial_without_active_tutorial(self) -> None:
        """Test quitting when no tutorial is active."""
        system = TutorialSystem()

        result = system.quit_tutorial()

        assert result is False

    def test_resume_tutorial_without_history(self) -> None:
        """Test resuming when no tutorial history exists."""
        system = TutorialSystem()

        result = system.resume_tutorial()

        assert result is False

    def test_execute_step_without_active_tutorial(self) -> None:
        """Test executing step with no active tutorial."""
        system = TutorialSystem()

        success, message = system.execute_step("test command")

        assert success is False

    def test_skip_step_without_active_tutorial(self) -> None:
        """Test skipping step with no active tutorial."""
        system = TutorialSystem()

        result = system.skip_step()

        assert result is False

    def test_prev_step_without_active_tutorial(self) -> None:
        """Test going to previous step with no active tutorial."""
        system = TutorialSystem()

        result = system.prev_step()

        assert result is False


class TestTutorialRecommendations:
    """Test tutorial recommendation system."""

    def test_recommendations_after_getting_started(self) -> None:
        """Test recommendations shown after completing getting started."""
        system = TutorialSystem()

        system.tutorial_progress["getting_started"] = len(
            system.tutorials["getting_started"].steps
        )

        system.current_tutorial = system.tutorials["getting_started"]

        system._show_next_recommendations()

    def test_recommendations_after_multiple_completions(self) -> None:
        """Test recommendations adapt to completed tutorials."""
        system = TutorialSystem()

        system.tutorial_progress["getting_started"] = len(
            system.tutorials["getting_started"].steps
        )
        system.tutorial_progress["advanced_analysis"] = len(
            system.tutorials["advanced_analysis"].steps
        )

        system.current_tutorial = system.tutorials["advanced_analysis"]

        system._show_next_recommendations()


class TestTutorialDisplay:
    """Test tutorial display and formatting."""

    def test_list_tutorials_shows_all(self) -> None:
        """Test list_tutorials displays all available tutorials."""
        system = TutorialSystem()

        system.list_tutorials()

    def test_show_progress_displays_completion(self) -> None:
        """Test show_progress displays completion status."""
        system = TutorialSystem()

        system.tutorial_progress["getting_started"] = 2

        system.show_progress()

    def test_show_help_displays_commands(self) -> None:
        """Test show_help displays available commands."""
        system = TutorialSystem()

        system.show_help()

    def test_display_tutorial_cards_without_rich(self) -> None:
        """Test displaying tutorial cards when rich unavailable."""
        system = TutorialSystem()

        system.display_tutorial_cards()

    def test_display_tutorials_table_without_rich(self) -> None:
        """Test displaying tutorials table when rich unavailable."""
        system = TutorialSystem()

        system.display_tutorials_table()

    def test_display_tutorial_structure_tree(self) -> None:
        """Test displaying tutorial structure as tree."""
        system = TutorialSystem()

        system.display_tutorial_structure_tree("getting_started")

    def test_display_step_with_syntax(self) -> None:
        """Test displaying step with syntax highlighting."""
        system = TutorialSystem()

        step = TutorialStep(
            title="Test Step",
            description="Test description",
            commands=["help", "analyze"],
            explanation="This is a test"
        )

        system.display_step_with_syntax(step)

    def test_display_centered_tutorial_header(self) -> None:
        """Test displaying centered tutorial header."""
        system = TutorialSystem()

        tutorial = system.tutorials["getting_started"]

        system.display_centered_tutorial_header(tutorial)

    def test_show_tutorial_progress_bar(self) -> None:
        """Test showing tutorial progress bar."""
        system = TutorialSystem()

        system.tutorial_progress["getting_started"] = 3

        system.show_tutorial_progress_bar("getting_started")


class TestTutorialContentValidation:
    """Test tutorial content validation."""

    def test_all_steps_have_valid_commands(self) -> None:
        """Test all tutorial steps have valid command formats."""
        system = TutorialSystem()

        for tutorial in system.tutorials.values():
            for step in tutorial.steps:
                assert step.title
                assert step.description

                for command in step.commands:
                    assert isinstance(command, str)
                    assert len(command) > 0

    def test_all_tutorials_have_completion_messages(self) -> None:
        """Test all tutorials have completion messages."""
        system = TutorialSystem()

        for tutorial in system.tutorials.values():
            assert tutorial.completion_message or len(tutorial.steps) == 0

    def test_tutorial_prerequisites_exist(self) -> None:
        """Test tutorial prerequisites reference existing tutorials."""
        system = TutorialSystem()

        for tutorial in system.tutorials.values():
            for prereq in tutorial.prerequisites:
                assert prereq in system.tutorials

    def test_step_prerequisites_are_valid(self) -> None:
        """Test step prerequisites are valid."""
        system = TutorialSystem()

        for tutorial in system.tutorials.values():
            for step in tutorial.steps:
                assert isinstance(step.prerequisites, list)


class TestTutorialWorkflow:
    """Test complete tutorial workflows."""

    def test_complete_tutorial_workflow(self) -> None:
        """Test completing an entire tutorial workflow."""
        system = TutorialSystem()

        tutorial = Tutorial(
            name="workflow_test",
            title="Workflow Test",
            description="Complete workflow test",
            steps=[
                TutorialStep(title="Step 1", description="First", commands=["cmd1"]),
                TutorialStep(title="Step 2", description="Second", commands=["cmd2"]),
                TutorialStep(title="Step 3", description="Third", commands=["cmd3"]),
            ]
        )

        system.tutorials["workflow_test"] = tutorial

        assert system.start_tutorial("workflow_test") is True

        for i in range(len(tutorial.steps)):
            assert system.current_step == i
            system.next_step()

        assert system.current_tutorial is None
        assert system.tutorial_progress["workflow_test"] == len(tutorial.steps)

    def test_tutorial_with_navigation(self) -> None:
        """Test tutorial navigation (next/prev/skip)."""
        system = TutorialSystem()

        tutorial = Tutorial(
            name="nav_test",
            title="Navigation Test",
            description="Test navigation",
            steps=[
                TutorialStep(title=f"Step {i}", description=f"Step {i}")
                for i in range(5)
            ]
        )

        system.tutorials["nav_test"] = tutorial
        system.start_tutorial("nav_test")

        system.next_step()
        assert system.current_step == 1

        system.next_step()
        assert system.current_step == 2

        system.prev_step()
        assert system.current_step == 1

        if system.current_tutorial and system.current_tutorial.steps[system.current_step].skip_allowed:
            system.skip_step()
            assert system.current_step == 2
