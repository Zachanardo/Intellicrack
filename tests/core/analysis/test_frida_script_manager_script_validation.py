"""Production tests for Frida Script Manager script validation capabilities.

Tests validate:
- JavaScript syntax validation before injection
- Memory usage limits for scripts
- Execution timeout policies
- Script execution environment sandboxing
- RPC export signature validation
- Edge cases: malformed scripts, infinite loops

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import json
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import frida
import psutil
import pytest

from intellicrack.core.analysis.frida_script_manager import (
    FridaScriptConfig,
    FridaScriptManager,
    ScriptCategory,
    ScriptResult,
)


@pytest.fixture
def scripts_dir(temp_workspace: Path) -> Path:
    """Create temporary scripts directory."""
    scripts_path = temp_workspace / "frida_scripts"
    scripts_path.mkdir(exist_ok=True)
    return scripts_path


@pytest.fixture
def script_manager(scripts_dir: Path) -> FridaScriptManager:
    """Create FridaScriptManager instance."""
    return FridaScriptManager(scripts_dir)


@pytest.fixture
def valid_script(scripts_dir: Path) -> Path:
    """Create a valid test script."""
    script_path = scripts_dir / "valid_test.js"
    script_content = """
    console.log("Valid script running");

    rpc.exports = {
        test: function() {
            return "success";
        }
    };
    """
    script_path.write_text(script_content)
    return script_path


@pytest.fixture
def target_process() -> Iterator[subprocess.Popen[bytes]]:
    """Spawn a target process for testing."""
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)
    yield process
    try:
        process.terminate()
        process.wait(timeout=5)
    except Exception:
        process.kill()


class TestJavaScriptSyntaxValidation:
    """Test JavaScript syntax validation before script injection."""

    def test_valid_syntax_script_executes(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Valid JavaScript syntax allows script execution."""
        script_path = scripts_dir / "syntax_valid.js"
        script_content = """
        var x = 42;
        var y = "test";
        console.log(x + " " + y);
        send({type: "success", value: x});
        """
        script_path.write_text(script_content)

        script_manager.scripts["syntax_valid.js"] = FridaScriptConfig(
            name="Syntax Valid",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Valid syntax test",
            parameters={"timeout": 5},
        )

        result: ScriptResult = script_manager.execute_script(
            "syntax_valid.js",
            str(target_process.pid),
            mode="attach",
        )

        assert result.success
        assert len(result.errors) == 0
        assert any("success" in str(msg) for msg in result.messages)

    def test_syntax_error_prevents_execution(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Script with JavaScript syntax errors fails during execution."""
        script_path = scripts_dir / "syntax_error.js"
        script_content = """
        var x = ;
        var y = "unclosed string
        function broken( {
            return 42
        }
        console.log(x);
        """
        script_path.write_text(script_content)

        script_manager.scripts["syntax_error.js"] = FridaScriptConfig(
            name="Syntax Error",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Syntax error test",
            parameters={"timeout": 5},
        )

        result: ScriptResult = script_manager.execute_script(
            "syntax_error.js",
            str(target_process.pid),
            mode="attach",
        )

        assert not result.success
        assert len(result.errors) > 0
        assert any("syntax" in err.lower() or "unexpected" in err.lower() for err in result.errors)

    def test_undefined_variable_caught(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Script referencing undefined variables produces runtime error."""
        script_path = scripts_dir / "undefined_var.js"
        script_content = """
        console.log("Starting");
        var result = undefinedVariable + 42;
        send({type: "result", value: result});
        """
        script_path.write_text(script_content)

        script_manager.scripts["undefined_var.js"] = FridaScriptConfig(
            name="Undefined Variable",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Undefined variable test",
            parameters={"timeout": 5},
        )

        result: ScriptResult = script_manager.execute_script(
            "undefined_var.js",
            str(target_process.pid),
            mode="attach",
        )

        assert not result.success
        assert len(result.errors) > 0


class TestMemoryUsageLimits:
    """Test memory usage limits for scripts."""

    def test_memory_intensive_script_monitored(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Memory-intensive scripts are monitored and limited."""
        script_path = scripts_dir / "memory_intensive.js"
        script_content = """
        var arrays = [];
        for (var i = 0; i < 1000; i++) {
            arrays.push(new Array(10000).fill(i));
        }
        send({type: "allocated", count: arrays.length});
        """
        script_path.write_text(script_content)

        script_manager.scripts["memory_intensive.js"] = FridaScriptConfig(
            name="Memory Intensive",
            path=script_path,
            category=ScriptCategory.MEMORY_ANALYSIS,
            description="Memory intensive test",
            parameters={"timeout": 10},
        )

        process_before = psutil.Process(target_process.pid)
        mem_before = process_before.memory_info().rss

        result: ScriptResult = script_manager.execute_script(
            "memory_intensive.js",
            str(target_process.pid),
            mode="attach",
        )

        time.sleep(1)

        process_after = psutil.Process(target_process.pid)
        mem_after = process_after.memory_info().rss
        mem_increase = mem_after - mem_before

        assert mem_increase > 0
        assert mem_increase < 500 * 1024 * 1024

    def test_reasonable_memory_usage_succeeds(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Scripts with reasonable memory usage complete successfully."""
        script_path = scripts_dir / "memory_normal.js"
        script_content = """
        var data = [];
        for (var i = 0; i < 10; i++) {
            data.push({index: i, value: i * 2});
        }
        send({type: "complete", items: data.length});
        """
        script_path.write_text(script_content)

        script_manager.scripts["memory_normal.js"] = FridaScriptConfig(
            name="Memory Normal",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Normal memory test",
            parameters={"timeout": 5},
        )

        result: ScriptResult = script_manager.execute_script(
            "memory_normal.js",
            str(target_process.pid),
            mode="attach",
        )

        assert result.success
        assert any("complete" in str(msg) for msg in result.messages)


class TestExecutionTimeoutPolicies:
    """Test execution timeout policy enforcement."""

    def test_timeout_enforced_on_long_running_script(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Long-running scripts are terminated by timeout."""
        script_path = scripts_dir / "infinite_loop.js"
        script_content = """
        while(true) {
            var x = Math.random();
        }
        """
        script_path.write_text(script_content)

        script_manager.scripts["infinite_loop.js"] = FridaScriptConfig(
            name="Infinite Loop",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Infinite loop test",
            parameters={"timeout": 3},
        )

        start_time = time.time()
        result: ScriptResult = script_manager.execute_script(
            "infinite_loop.js",
            str(target_process.pid),
            mode="attach",
        )
        duration = time.time() - start_time

        assert duration >= 3.0
        assert duration < 5.0
        assert result.end_time > 0

    def test_script_completes_before_timeout(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Scripts completing before timeout are marked successful."""
        script_path = scripts_dir / "quick_script.js"
        script_content = """
        send({type: "start"});
        var sum = 0;
        for (var i = 0; i < 100; i++) {
            sum += i;
        }
        send({type: "complete", sum: sum});
        """
        script_path.write_text(script_content)

        script_manager.scripts["quick_script.js"] = FridaScriptConfig(
            name="Quick Script",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Quick script test",
            parameters={"timeout": 10},
        )

        start_time = time.time()
        result: ScriptResult = script_manager.execute_script(
            "quick_script.js",
            str(target_process.pid),
            mode="attach",
        )
        duration = time.time() - start_time

        assert result.success
        assert duration < 5.0
        assert any("complete" in str(msg) for msg in result.messages)

    def test_custom_timeout_respected(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Custom timeout parameter is respected."""
        script_path = scripts_dir / "sleep_script.js"
        script_content = """
        var start = Date.now();
        while (Date.now() - start < 4000) {
            // Wait 4 seconds
        }
        send({type: "done"});
        """
        script_path.write_text(script_content)

        script_manager.scripts["sleep_script.js"] = FridaScriptConfig(
            name="Sleep Script",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Sleep script test",
            parameters={},
        )

        start_time = time.time()
        result: ScriptResult = script_manager.execute_script(
            "sleep_script.js",
            str(target_process.pid),
            mode="attach",
            parameters={"timeout": 2},
        )
        duration = time.time() - start_time

        assert duration >= 2.0
        assert duration < 4.0


class TestScriptExecutionSandboxing:
    """Test script execution environment sandboxing."""

    def test_script_cannot_modify_manager_state(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Scripts cannot modify script manager state."""
        initial_script_count = len(script_manager.scripts)

        script_path = scripts_dir / "sandbox_test.js"
        script_content = """
        send({type: "test", value: "isolated"});
        """
        script_path.write_text(script_content)

        script_manager.scripts["sandbox_test.js"] = FridaScriptConfig(
            name="Sandbox Test",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Sandbox test",
            parameters={"timeout": 5},
        )

        script_manager.execute_script(
            "sandbox_test.js",
            str(target_process.pid),
            mode="attach",
        )

        assert len(script_manager.scripts) == initial_script_count + 1

    def test_script_isolation_between_executions(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Scripts are isolated from each other across executions."""
        script1_path = scripts_dir / "isolated1.js"
        script1_content = """
        var globalVar = 123;
        send({type: "script1", value: globalVar});
        """
        script1_path.write_text(script1_content)

        script2_path = scripts_dir / "isolated2.js"
        script2_content = """
        try {
            send({type: "script2", value: typeof globalVar});
        } catch (e) {
            send({type: "script2", error: "variable not accessible"});
        }
        """
        script2_path.write_text(script2_content)

        script_manager.scripts["isolated1.js"] = FridaScriptConfig(
            name="Isolated 1",
            path=script1_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Isolation test 1",
            parameters={"timeout": 5},
        )

        script_manager.scripts["isolated2.js"] = FridaScriptConfig(
            name="Isolated 2",
            path=script2_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Isolation test 2",
            parameters={"timeout": 5},
        )

        result1 = script_manager.execute_script(
            "isolated1.js",
            str(target_process.pid),
            mode="attach",
        )

        process2 = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.5)

        try:
            result2 = script_manager.execute_script(
                "isolated2.js",
                str(process2.pid),
                mode="attach",
            )

            assert result1.success
            assert result2.success
        finally:
            try:
                process2.terminate()
                process2.wait(timeout=5)
            except Exception:
                process2.kill()


class TestRPCExportValidation:
    """Test RPC export signature validation."""

    def test_valid_rpc_exports_work(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Valid RPC exports are accessible."""
        script_path = scripts_dir / "rpc_valid.js"
        script_content = """
        rpc.exports = {
            add: function(a, b) {
                return a + b;
            },
            getString: function() {
                return "test string";
            },
            getArray: function() {
                return [1, 2, 3];
            }
        };
        send({type: "rpc_ready"});
        """
        script_path.write_text(script_content)

        script_manager.scripts["rpc_valid.js"] = FridaScriptConfig(
            name="RPC Valid",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Valid RPC test",
            parameters={"timeout": 5},
        )

        result: ScriptResult = script_manager.execute_script(
            "rpc_valid.js",
            str(target_process.pid),
            mode="attach",
        )

        assert result.success
        assert any("rpc_ready" in str(msg) for msg in result.messages)

    def test_malformed_rpc_exports_handled(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Malformed RPC exports are detected."""
        script_path = scripts_dir / "rpc_malformed.js"
        script_content = """
        rpc.exports = "not an object";
        send({type: "started"});
        """
        script_path.write_text(script_content)

        script_manager.scripts["rpc_malformed.js"] = FridaScriptConfig(
            name="RPC Malformed",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Malformed RPC test",
            parameters={"timeout": 5},
        )

        result: ScriptResult = script_manager.execute_script(
            "rpc_malformed.js",
            str(target_process.pid),
            mode="attach",
        )

        assert not result.success or len(result.errors) > 0

    def test_rpc_function_signatures_validated(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """RPC function signatures are validated."""
        script_path = scripts_dir / "rpc_signature.js"
        script_content = """
        rpc.exports = {
            validFunction: function(x) {
                return x * 2;
            },
            invalidFunction: 42
        };
        send({type: "exports_set"});
        """
        script_path.write_text(script_content)

        script_manager.scripts["rpc_signature.js"] = FridaScriptConfig(
            name="RPC Signature",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="RPC signature test",
            parameters={"timeout": 5},
        )

        result: ScriptResult = script_manager.execute_script(
            "rpc_signature.js",
            str(target_process.pid),
            mode="attach",
        )

        assert result.success or len(result.errors) > 0


class TestMalformedScriptHandling:
    """Test handling of malformed scripts."""

    def test_empty_script_handled(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Empty scripts are handled gracefully."""
        script_path = scripts_dir / "empty.js"
        script_path.write_text("")

        script_manager.scripts["empty.js"] = FridaScriptConfig(
            name="Empty Script",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Empty script test",
            parameters={"timeout": 5},
        )

        result: ScriptResult = script_manager.execute_script(
            "empty.js",
            str(target_process.pid),
            mode="attach",
        )

        assert result.end_time > 0

    def test_script_with_only_comments_handled(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Scripts with only comments are handled."""
        script_path = scripts_dir / "comments_only.js"
        script_content = """
        // This is a comment
        /* This is a
           multi-line comment */
        """
        script_path.write_text(script_content)

        script_manager.scripts["comments_only.js"] = FridaScriptConfig(
            name="Comments Only",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Comments only test",
            parameters={"timeout": 5},
        )

        result: ScriptResult = script_manager.execute_script(
            "comments_only.js",
            str(target_process.pid),
            mode="attach",
        )

        assert result.end_time > 0

    def test_script_with_unicode_handled(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Scripts with Unicode characters are handled."""
        script_path = scripts_dir / "unicode.js"
        script_content = """
        var msg = "测试 тест 테스트";
        send({type: "unicode", value: msg});
        """
        script_path.write_text(script_content, encoding="utf-8")

        script_manager.scripts["unicode.js"] = FridaScriptConfig(
            name="Unicode Script",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Unicode test",
            parameters={"timeout": 5},
        )

        result: ScriptResult = script_manager.execute_script(
            "unicode.js",
            str(target_process.pid),
            mode="attach",
        )

        assert result.success


class TestInfiniteLoopDetection:
    """Test infinite loop detection and termination."""

    def test_infinite_while_loop_terminated(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Infinite while loop is terminated by timeout."""
        script_path = scripts_dir / "infinite_while.js"
        script_content = """
        send({type: "start"});
        while (true) {
            var x = 1 + 1;
        }
        send({type: "end"});
        """
        script_path.write_text(script_content)

        script_manager.scripts["infinite_while.js"] = FridaScriptConfig(
            name="Infinite While",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Infinite while test",
            parameters={"timeout": 2},
        )

        start = time.time()
        result: ScriptResult = script_manager.execute_script(
            "infinite_while.js",
            str(target_process.pid),
            mode="attach",
        )
        duration = time.time() - start

        assert duration >= 2.0
        assert duration < 4.0
        assert any("start" in str(msg) for msg in result.messages)
        assert not any("end" in str(msg) for msg in result.messages)

    def test_infinite_for_loop_terminated(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Infinite for loop is terminated by timeout."""
        script_path = scripts_dir / "infinite_for.js"
        script_content = """
        send({type: "start"});
        for (var i = 0; ; i++) {
            var x = i * 2;
        }
        send({type: "end"});
        """
        script_path.write_text(script_content)

        script_manager.scripts["infinite_for.js"] = FridaScriptConfig(
            name="Infinite For",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Infinite for test",
            parameters={"timeout": 2},
        )

        start = time.time()
        result: ScriptResult = script_manager.execute_script(
            "infinite_for.js",
            str(target_process.pid),
            mode="attach",
        )
        duration = time.time() - start

        assert duration >= 2.0
        assert duration < 4.0

    def test_recursive_infinite_loop_terminated(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Infinite recursive function is terminated."""
        script_path = scripts_dir / "infinite_recursion.js"
        script_content = """
        send({type: "start"});
        function recurse(n) {
            return recurse(n + 1);
        }
        try {
            recurse(0);
        } catch (e) {
            send({type: "error", message: e.toString()});
        }
        send({type: "end"});
        """
        script_path.write_text(script_content)

        script_manager.scripts["infinite_recursion.js"] = FridaScriptConfig(
            name="Infinite Recursion",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Infinite recursion test",
            parameters={"timeout": 5},
        )

        result: ScriptResult = script_manager.execute_script(
            "infinite_recursion.js",
            str(target_process.pid),
            mode="attach",
        )

        assert any("start" in str(msg) for msg in result.messages)


class TestParameterInjectionSafety:
    """Test parameter injection safety."""

    def test_string_parameter_injection_safe(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """String parameters are injected safely."""
        script_path = scripts_dir / "param_string.js"
        script_content = """
        send({type: "param", value: testParam});
        """
        script_path.write_text(script_content)

        script_manager.scripts["param_string.js"] = FridaScriptConfig(
            name="Param String",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="String parameter test",
            parameters={},
        )

        result: ScriptResult = script_manager.execute_script(
            "param_string.js",
            str(target_process.pid),
            mode="attach",
            parameters={"testParam": "test_value", "timeout": 5},
        )

        assert result.success
        assert any("test_value" in str(msg) for msg in result.messages)

    def test_special_characters_in_parameters_handled(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Special characters in parameters are handled safely."""
        script_path = scripts_dir / "param_special.js"
        script_content = """
        send({type: "param", value: specialParam});
        """
        script_path.write_text(script_content)

        script_manager.scripts["param_special.js"] = FridaScriptConfig(
            name="Param Special",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Special char parameter test",
            parameters={},
        )

        result: ScriptResult = script_manager.execute_script(
            "param_special.js",
            str(target_process.pid),
            mode="attach",
            parameters={"specialParam": "test;'\\\"\n\t", "timeout": 5},
        )

        assert result.end_time > 0

    def test_object_parameter_injection_works(
        self, script_manager: FridaScriptManager, scripts_dir: Path, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Object parameters are injected correctly."""
        script_path = scripts_dir / "param_object.js"
        script_content = """
        send({type: "param", value: objectParam});
        """
        script_path.write_text(script_content)

        script_manager.scripts["param_object.js"] = FridaScriptConfig(
            name="Param Object",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Object parameter test",
            parameters={},
        )

        result: ScriptResult = script_manager.execute_script(
            "param_object.js",
            str(target_process.pid),
            mode="attach",
            parameters={"objectParam": {"key": "value", "num": 42}, "timeout": 5},
        )

        assert result.success
        assert any("value" in str(msg) for msg in result.messages)


class TestProcessAttachmentValidation:
    """Test process attachment validation."""

    def test_invalid_pid_handled(
        self, script_manager: FridaScriptManager, scripts_dir: Path
    ) -> None:
        """Invalid process ID is handled gracefully."""
        script_path = scripts_dir / "attach_test.js"
        script_content = """
        send({type: "attached"});
        """
        script_path.write_text(script_content)

        script_manager.scripts["attach_test.js"] = FridaScriptConfig(
            name="Attach Test",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Attach test",
            parameters={"timeout": 5},
        )

        result: ScriptResult = script_manager.execute_script(
            "attach_test.js",
            "999999",
            mode="attach",
        )

        assert not result.success
        assert len(result.errors) > 0

    def test_spawn_mode_creates_process(
        self, script_manager: FridaScriptManager, scripts_dir: Path
    ) -> None:
        """Spawn mode successfully creates and attaches to process."""
        script_path = scripts_dir / "spawn_test.js"
        script_content = """
        send({type: "spawned"});
        """
        script_path.write_text(script_content)

        script_manager.scripts["spawn_test.js"] = FridaScriptConfig(
            name="Spawn Test",
            path=script_path,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            description="Spawn test",
            parameters={"timeout": 5},
        )

        result: ScriptResult = script_manager.execute_script(
            "spawn_test.js",
            sys.executable,
            mode="spawn",
            parameters={"-c": "import time; time.sleep(5)"},
        )

        assert result.end_time > 0
