"""Integration tests for Frida Stalker with frida_analyzer.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import tempfile
from collections.abc import Generator
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, cast

if TYPE_CHECKING:
    from intellicrack.ui.main_app import IntellicrackApp

import pytest


class FakeUpdateOutput:
    """Fake output emitter for testing."""

    def __init__(self) -> None:
        self.emitted_messages: List[str] = []
        self.call_count: int = 0

    def emit(self, message: str) -> None:
        self.emitted_messages.append(message)
        self.call_count += 1

    @property
    def call_args_list(self) -> List[tuple[tuple[str, ...], Dict[str, Any]]]:
        return [((msg,), {}) for msg in self.emitted_messages]


class FakeMainApp:
    """Fake main application for testing."""

    def __init__(self) -> None:
        self.current_binary: Optional[str] = None
        self.update_output: FakeUpdateOutput = FakeUpdateOutput()
        self.messages: List[str] = []

    def set_binary(self, path: str) -> None:
        self.current_binary = path

    def emit_message(self, msg: str) -> None:
        self.messages.append(msg)
        self.update_output.emit(msg)


class FakeStalkerStats:
    """Fake Stalker statistics object."""

    def __init__(
        self,
        total_instructions: int = 1000,
        unique_blocks: int = 50,
        coverage_entries: int = 25,
        licensing_routines: int = 5,
        api_calls: int = 100,
    ) -> None:
        self.total_instructions: int = total_instructions
        self.unique_blocks: int = unique_blocks
        self.coverage_entries: int = coverage_entries
        self.licensing_routines: int = licensing_routines
        self.api_calls: int = api_calls


class FakeStalkerSessionInstance:
    """Fake StalkerSession instance for testing."""

    def __init__(
        self,
        binary_path: str,
        output_dir: Optional[str] = None,
        message_callback: Optional[Callable[[str], None]] = None,
        start_succeeds: bool = True,
        stop_succeeds: bool = True,
        trace_succeeds: bool = True,
        coverage_succeeds: bool = True,
    ) -> None:
        self.binary_path: str = binary_path
        self.output_dir: Optional[str] = output_dir
        self.message_callback: Optional[Callable[[str], None]] = message_callback
        self.start_succeeds: bool = start_succeeds
        self.stop_succeeds: bool = stop_succeeds
        self.trace_succeeds: bool = trace_succeeds
        self.coverage_succeeds: bool = coverage_succeeds

        self.start_called: bool = False
        self.stop_called: bool = False
        self.trace_calls: List[tuple[str, str]] = []
        self.coverage_calls: List[str] = []
        self.stats: FakeStalkerStats = FakeStalkerStats()
        self.licensing_routines: List[str] = ["app.exe:0x1000", "license.dll:0x2000"]

    def start(self) -> bool:
        self.start_called = True
        return self.start_succeeds

    def stop_stalking(self) -> bool:
        self.stop_called = True
        return self.stop_succeeds

    def trace_function(self, module: str, function: str) -> bool:
        self.trace_calls.append((module, function))
        return self.trace_succeeds

    def collect_module_coverage(self, module: str) -> bool:
        self.coverage_calls.append(module)
        return self.coverage_succeeds

    def get_stats(self) -> FakeStalkerStats:
        return self.stats

    def get_licensing_routines(self) -> List[str]:
        return self.licensing_routines


class FakeStalkerSession:
    """Fake StalkerSession class for testing."""

    def __init__(
        self,
        start_succeeds: bool = True,
        stop_succeeds: bool = True,
        trace_succeeds: bool = True,
        coverage_succeeds: bool = True,
    ) -> None:
        self.start_succeeds: bool = start_succeeds
        self.stop_succeeds: bool = stop_succeeds
        self.trace_succeeds: bool = trace_succeeds
        self.coverage_succeeds: bool = coverage_succeeds

        self.call_count: int = 0
        self.call_args_list: List[tuple[tuple[Any, ...], Dict[str, Any]]] = []
        self.instances: List[FakeStalkerSessionInstance] = []

    def __call__(
        self,
        binary_path: str,
        output_dir: Optional[str] = None,
        message_callback: Optional[Callable[[str], None]] = None,
    ) -> FakeStalkerSessionInstance:
        self.call_count += 1
        self.call_args_list.append(
            (
                (),
                {
                    "binary_path": binary_path,
                    "output_dir": output_dir,
                    "message_callback": message_callback,
                },
            )
        )

        instance = FakeStalkerSessionInstance(
            binary_path=binary_path,
            output_dir=output_dir,
            message_callback=message_callback,
            start_succeeds=self.start_succeeds,
            stop_succeeds=self.stop_succeeds,
            trace_succeeds=self.trace_succeeds,
            coverage_succeeds=self.coverage_succeeds,
        )
        self.instances.append(instance)
        return instance

    @property
    def return_value(self) -> Optional[FakeStalkerSessionInstance]:
        return self.instances[-1] if self.instances else None

    @property
    def call_args(self) -> Optional[tuple[tuple[Any, ...], Dict[str, Any]]]:
        return self.call_args_list[-1] if self.call_args_list else None

    def assert_called_once(self) -> None:
        assert self.call_count == 1, f"Expected 1 call, got {self.call_count}"

    @property
    def called(self) -> bool:
        return self.call_count > 0


@pytest.fixture
def fake_main_app() -> "IntellicrackApp":
    """Create fake main app."""
    return cast("IntellicrackApp", FakeMainApp())


@pytest.fixture
def temp_binary() -> Generator[str, None, None]:
    """Create temporary binary file for testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(b"MZ\x90\x00")
        temp_path = f.name
    yield temp_path
    import os

    try:
        os.unlink(temp_path)
    except Exception:
        pass


@pytest.fixture
def fake_stalker_session(monkeypatch: pytest.MonkeyPatch) -> Generator[FakeStalkerSession, None, None]:
    """Create fake StalkerSession."""
    import intellicrack.core.analysis.frida_analyzer

    fake_class = FakeStalkerSession()
    monkeypatch.setattr(
        intellicrack.core.analysis.frida_analyzer, "StalkerSession", fake_class
    )

    yield fake_class


class TestStalkerIntegration:
    """Test Stalker integration with frida_analyzer."""

    def test_start_stalker_session_success(
        self, fake_main_app: "IntellicrackApp", temp_binary: str, fake_stalker_session: FakeStalkerSession
    ) -> None:
        """Test starting Stalker session successfully."""
        from intellicrack.core.analysis.frida_analyzer import start_stalker_session

        fake_main_app.set_binary(temp_binary)
        result = start_stalker_session(fake_main_app)

        assert result is True
        fake_stalker_session.assert_called_once()
        assert fake_stalker_session.return_value is not None
        assert fake_stalker_session.return_value.start_called

    def test_start_stalker_session_no_binary(self, fake_main_app: "IntellicrackApp") -> None:
        """Test starting Stalker session without binary."""
        from intellicrack.core.analysis.frida_analyzer import start_stalker_session

        result = start_stalker_session(fake_main_app)

        assert result is False
        assert fake_main_app.update_output.call_count > 0
        assert any(
            "No binary loaded" in str(call)
            for call in fake_main_app.update_output.call_args_list
        )

    def test_start_stalker_session_module_not_available(
        self, fake_main_app: "IntellicrackApp", temp_binary: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test starting Stalker session when module not available."""
        import intellicrack.core.analysis.frida_analyzer

        monkeypatch.setattr(
            intellicrack.core.analysis.frida_analyzer, "StalkerSession", None
        )
        from intellicrack.core.analysis.frida_analyzer import start_stalker_session

        fake_main_app.set_binary(temp_binary)
        result = start_stalker_session(fake_main_app)

        assert result is False
        assert any(
            "not available" in str(call)
            for call in fake_main_app.update_output.call_args_list
        )

    def test_start_stalker_session_with_custom_output_dir(
        self, fake_main_app: "IntellicrackApp", temp_binary: str, fake_stalker_session: FakeStalkerSession
    ) -> None:
        """Test starting Stalker session with custom output directory."""
        from intellicrack.core.analysis.frida_analyzer import start_stalker_session

        fake_main_app.set_binary(temp_binary)
        custom_dir = "/custom/output"
        result = start_stalker_session(fake_main_app, output_dir=custom_dir)

        assert result is True
        call_args = fake_stalker_session.call_args
        assert call_args is not None
        assert call_args[1]["binary_path"] == temp_binary
        assert call_args[1]["output_dir"] == custom_dir
        assert "message_callback" in call_args[1]

    def test_start_stalker_session_start_failure(
        self, fake_main_app: "IntellicrackApp", temp_binary: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test starting Stalker session when start fails."""
        import intellicrack.core.analysis.frida_analyzer

        failing_stalker = FakeStalkerSession(start_succeeds=False)
        monkeypatch.setattr(
            intellicrack.core.analysis.frida_analyzer, "StalkerSession", failing_stalker
        )

        from intellicrack.core.analysis.frida_analyzer import start_stalker_session

        fake_main_app.set_binary(temp_binary)
        result = start_stalker_session(fake_main_app)

        assert result is False

    def test_stop_stalker_session_success(
        self, fake_main_app: "IntellicrackApp", temp_binary: str, fake_stalker_session: FakeStalkerSession
    ) -> None:
        """Test stopping Stalker session successfully."""
        from intellicrack.core.analysis.frida_analyzer import (
            start_stalker_session,
            stop_stalker_session,
        )

        fake_main_app.set_binary(temp_binary)
        start_result = start_stalker_session(fake_main_app)
        assert start_result is True

        result = stop_stalker_session(fake_main_app)

        assert result is True
        assert fake_stalker_session.return_value is not None
        assert fake_stalker_session.return_value.stop_called

    def test_stop_stalker_session_no_binary(self, fake_main_app: "IntellicrackApp") -> None:
        """Test stopping Stalker session without binary."""
        from intellicrack.core.analysis.frida_analyzer import stop_stalker_session

        result = stop_stalker_session(fake_main_app)

        assert result is False
        assert any(
            "No binary loaded" in str(call)
            for call in fake_main_app.update_output.call_args_list
        )

    def test_stop_stalker_session_no_active_session(
        self, fake_main_app: "IntellicrackApp", temp_binary: str
    ) -> None:
        """Test stopping Stalker session when no active session."""
        from intellicrack.core.analysis.frida_analyzer import stop_stalker_session

        fake_main_app.set_binary(temp_binary)
        result = stop_stalker_session(fake_main_app)

        assert result is False
        calls_str = " ".join(
            str(call) for call in fake_main_app.update_output.call_args_list
        )
        assert "No active" in calls_str or "not found" in calls_str

    def test_trace_function_stalker_success(
        self, fake_main_app: "IntellicrackApp", temp_binary: str, fake_stalker_session: FakeStalkerSession
    ) -> None:
        """Test tracing function with Stalker successfully."""
        from intellicrack.core.analysis.frida_analyzer import (
            start_stalker_session,
            trace_function_stalker,
        )

        fake_main_app.set_binary(temp_binary)
        start_stalker_session(fake_main_app)
        result = trace_function_stalker(fake_main_app, "app.exe", "ValidateLicense")

        assert result is True
        assert fake_stalker_session.return_value is not None
        assert ("app.exe", "ValidateLicense") in fake_stalker_session.return_value.trace_calls

    def test_trace_function_stalker_no_binary(self, fake_main_app: "IntellicrackApp") -> None:
        """Test tracing function without binary."""
        from intellicrack.core.analysis.frida_analyzer import trace_function_stalker

        result = trace_function_stalker(fake_main_app, "app.exe", "ValidateLicense")

        assert result is False
        assert any(
            "No binary loaded" in str(call)
            for call in fake_main_app.update_output.call_args_list
        )

    def test_trace_function_stalker_no_active_session(
        self, fake_main_app: "IntellicrackApp", temp_binary: str
    ) -> None:
        """Test tracing function when no active session."""
        from intellicrack.core.analysis.frida_analyzer import trace_function_stalker

        fake_main_app.set_binary(temp_binary)
        result = trace_function_stalker(fake_main_app, "app.exe", "ValidateLicense")

        assert result is False

    def test_collect_module_coverage_stalker_success(
        self, fake_main_app: "IntellicrackApp", temp_binary: str, fake_stalker_session: FakeStalkerSession
    ) -> None:
        """Test collecting module coverage with Stalker successfully."""
        from intellicrack.core.analysis.frida_analyzer import (
            collect_module_coverage_stalker,
            start_stalker_session,
        )

        fake_main_app.set_binary(temp_binary)
        start_stalker_session(fake_main_app)
        result = collect_module_coverage_stalker(fake_main_app, "license.dll")

        assert result is True
        assert fake_stalker_session.return_value is not None
        assert "license.dll" in fake_stalker_session.return_value.coverage_calls

    def test_collect_module_coverage_stalker_no_binary(
        self, fake_main_app: "IntellicrackApp"
    ) -> None:
        """Test collecting module coverage without binary."""
        from intellicrack.core.analysis.frida_analyzer import (
            collect_module_coverage_stalker,
        )

        result = collect_module_coverage_stalker(fake_main_app, "license.dll")

        assert result is False

    def test_get_stalker_stats_success(
        self, fake_main_app: "IntellicrackApp", temp_binary: str, fake_stalker_session: FakeStalkerSession
    ) -> None:
        """Test getting Stalker stats successfully."""
        from intellicrack.core.analysis.frida_analyzer import (
            get_stalker_stats,
            start_stalker_session,
        )

        fake_main_app.set_binary(temp_binary)
        start_stalker_session(fake_main_app)
        stats = get_stalker_stats(fake_main_app)

        assert stats is not None
        assert stats["total_instructions"] == 1000
        assert stats["unique_blocks"] == 50
        assert stats["coverage_entries"] == 25
        assert stats["licensing_routines"] == 5
        assert stats["api_calls"] == 100

    def test_get_stalker_stats_no_binary(self, fake_main_app: "IntellicrackApp") -> None:
        """Test getting Stalker stats without binary."""
        from intellicrack.core.analysis.frida_analyzer import get_stalker_stats

        stats = get_stalker_stats(fake_main_app)

        assert stats is None

    def test_get_stalker_stats_no_active_session(
        self, fake_main_app: "IntellicrackApp", temp_binary: str
    ) -> None:
        """Test getting Stalker stats when no active session."""
        from intellicrack.core.analysis.frida_analyzer import get_stalker_stats

        fake_main_app.set_binary(temp_binary)
        stats = get_stalker_stats(fake_main_app)

        assert stats is None

    def test_get_licensing_routines_stalker_success(
        self, fake_main_app: "IntellicrackApp", temp_binary: str, fake_stalker_session: FakeStalkerSession
    ) -> None:
        """Test getting licensing routines successfully."""
        from intellicrack.core.analysis.frida_analyzer import (
            get_licensing_routines_stalker,
            start_stalker_session,
        )

        fake_main_app.set_binary(temp_binary)
        start_stalker_session(fake_main_app)
        routines = get_licensing_routines_stalker(fake_main_app)

        assert routines is not None
        assert len(routines) == 2
        assert "app.exe:0x1000" in routines
        assert "license.dll:0x2000" in routines

    def test_get_licensing_routines_stalker_no_binary(
        self, fake_main_app: "IntellicrackApp"
    ) -> None:
        """Test getting licensing routines without binary."""
        from intellicrack.core.analysis.frida_analyzer import (
            get_licensing_routines_stalker,
        )

        routines = get_licensing_routines_stalker(fake_main_app)

        assert routines is None

    def test_get_licensing_routines_stalker_no_active_session(
        self, fake_main_app: "IntellicrackApp", temp_binary: str
    ) -> None:
        """Test getting licensing routines when no active session."""
        from intellicrack.core.analysis.frida_analyzer import (
            get_licensing_routines_stalker,
        )

        fake_main_app.set_binary(temp_binary)
        routines = get_licensing_routines_stalker(fake_main_app)

        assert routines is None

    def test_full_workflow(
        self, fake_main_app: "IntellicrackApp", temp_binary: str, fake_stalker_session: FakeStalkerSession
    ) -> None:
        """Test complete Stalker workflow."""
        from intellicrack.core.analysis.frida_analyzer import (
            collect_module_coverage_stalker,
            get_licensing_routines_stalker,
            get_stalker_stats,
            start_stalker_session,
            stop_stalker_session,
            trace_function_stalker,
        )

        fake_main_app.set_binary(temp_binary)

        result = start_stalker_session(fake_main_app)
        assert result is True

        result = trace_function_stalker(fake_main_app, "app.exe", "CheckLicense")
        assert result is True

        result = collect_module_coverage_stalker(fake_main_app, "license.dll")
        assert result is True

        stats = get_stalker_stats(fake_main_app)
        assert stats is not None
        assert stats["total_instructions"] > 0

        routines = get_licensing_routines_stalker(fake_main_app)
        assert routines is not None
        assert len(routines) > 0

        result = stop_stalker_session(fake_main_app)
        assert result is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
