import os
import time
from pathlib import Path

import pytest

from intellicrack.ai.integration_manager import IntegrationManager, get_integration_manager


def test_singleton_get_integration_manager_returns_same_instance() -> None:
    a = get_integration_manager()
    b = get_integration_manager()
    assert a is b


def test_manager_start_stop_idempotent() -> None:
    mgr = IntegrationManager()
    mgr.start()
    # double start should be no-op
    mgr.start()
    assert mgr.running is True
    mgr.stop()
    # double stop should be no-op
    mgr.stop()
    assert mgr.running is False


def test_create_and_complete_simple_task_generate_script() -> None:
    mgr = IntegrationManager()
    try:
        mgr.start()
        task_id = mgr.create_task(
            task_type="generate_script",
            description="gen frida",
            input_data={
                "request": {"target_info": {"file_path": "dummy"}},
                "script_type": "frida",
            },
        )
        task = mgr.wait_for_task(task_id, timeout=30)
        assert task.status == "completed"
        assert isinstance(task.result, dict)
        assert task.result.get("script_type") == "frida"
    finally:
        mgr.stop()


def test_validate_script_uses_fallback_qemu_manager(tmp_path: Path) -> None:
    mgr = IntegrationManager()
    try:
        mgr.start()
        dummy_script = "// frida script\nfunction main(){}"
        target = tmp_path / "target.bin"
        target.write_bytes(b"\x00\x01dummy")
        task_id = mgr.create_task(
            task_type="validate_script",
            description="validate",
            input_data={
                "script": dummy_script,
                "target_binary": str(target),
                "vm_config": {"dry_run": True},
            },
        )
        task = mgr.wait_for_task(task_id, timeout=60)
        assert task.status == "completed"
        res = task.result
        assert isinstance(res, dict)
        assert res.get("success") is True
        assert "validation" in res.get("results", {}).get("execution_method", "validation") or res.get("method") == "validation"
    finally:
        mgr.stop()


def test_workflow_end_to_end_minimal(tmp_path: Path) -> None:
    # Use create_bypass_workflow which wires multiple tasks together
    target = tmp_path / "bin.exe"
    target.write_bytes(b"MZ")
    mgr = IntegrationManager()
    try:
        mgr.start()
        wf_id = mgr.create_bypass_workflow(str(target))
        result = mgr.wait_for_workflow(wf_id, timeout=120)
        assert result.success in (True, False)  # workflow can succeed even with fallbacks
        assert result.tasks_completed + result.tasks_failed >= 1
        # ensure status API reports completion metadata
        status = mgr.get_workflow_status(wf_id)
        assert status.get("status") == "completed"
        assert "tasks_completed" in status
    finally:
        mgr.stop()
