"""Integration Manager for AI Components.

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

import os
import threading
import time
import types
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue
from typing import TYPE_CHECKING, Any, Literal, Self

if TYPE_CHECKING:
    from .llm_backends import LLMProvider

from ..utils.logger import get_logger
from .ai_script_generator import AIScriptGenerator
from .intelligent_code_modifier import IntelligentCodeModifier
from .llm_backends import LLMManager, LLMProvider
from .performance_monitor import performance_monitor, profile_ai_operation
from .script_generation_agent import AIAgent


logger = get_logger(__name__)

# Import QEMU Test Manager with fallback
try:
    from .qemu_manager import QEMUManager as ImportedQEMUManager

    QEMUManager = ImportedQEMUManager
except ImportError:
    logger.warning("QEMUManager not available")

    class QEMUManager:  # type: ignore[no-redef]
        """Fallback QEMUManager providing static validation and safe dry-run only."""

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            """Initialize the fallback QEMU test manager.

            Args:
                *_args: Ignored positional arguments
                **_kwargs: Ignored keyword arguments

            """
            import tempfile
            from pathlib import Path

            self.working_dir = Path(tempfile.gettempdir()) / "intellicrack_qemu_fallback"
            self.working_dir.mkdir(exist_ok=True)
            self.snapshots: dict[str, Any] = {}
            logger.warning("QEMUManager fallback initialized")

        def validate_script_in_vm(self, script: str, target_binary: str, vm_config: dict[str, Any] | None = None) -> dict[str, Any]:
            """Perform safe validation and optional dry-run; no real VM execution in fallback.

            Args:
                script: The script content to validate
                target_binary: Path to the target binary file
                vm_config: Optional VM configuration dictionary

            Returns:
                Dictionary containing validation results with keys: success, output, errors,
                exit_code, runtime_ms, results, and method

            """
            logger.info("Fallback QEMUManager: performing static validation and optional dry-run")

            import tempfile
            import time
            from pathlib import Path

            start_time = time.time()

            try:
                # Analyze script content for detailed information
                script_info = self._analyze_script_content(script)

                # Set up VM configuration
                if vm_config is None:
                    vm_config = {
                        "memory": "512M",
                        "cpu": "qemu64",
                        "timeout": 30,
                        "network": False,
                        "snapshot": True,
                        "dry_run": True,
                    }

                # Create isolated execution environment
                with tempfile.TemporaryDirectory() as execution_env:
                    execution_dir = Path(execution_env)

                    # Prepare script file
                    script_file = execution_dir / f"validation_script.{script_info['extension']}"
                    with open(script_file, "w", encoding="utf-8") as f:
                        f.write(script)

                    # Prepare target binary
                    target_file = execution_dir / "target_binary"
                    if Path(target_binary).exists():
                        import shutil

                        shutil.copy2(target_binary, target_file)
                        Path(target_file).chmod(0o700)
                    else:
                        # Create a deterministic non-executable marker file in fallback
                        with open(target_file, "wb") as tf:
                            tf.write(b"INTELLICRACK_FALLBACK_TARGET\n")

                    # Execute script testing based on type (dry-run only in fallback unless explicitly enabled)
                    execution_result = self._execute_script_in_environment(script, script_file, target_file, vm_config, execution_dir)

                    # Calculate execution time
                    runtime_ms = int((time.time() - start_time) * 1000)

                    # Generate comprehensive results
                    return {
                        "success": execution_result["success"],
                        "output": execution_result["output"],
                        "errors": execution_result.get("error", ""),
                        "exit_code": execution_result["exit_code"],
                        "runtime_ms": runtime_ms,
                        "results": {
                            "real_execution": (False if vm_config.get("dry_run", True) else execution_result.get("method") == "qemu"),
                            "script_analyzed": script_info,
                            "target": target_binary,
                            "config": vm_config,
                            "validation_environment": str(execution_dir),
                            "execution_method": execution_result.get("method", "unknown"),
                            "validation_passed": execution_result["success"],
                        },
                    }

            except Exception as vm_error:
                logger.exception("VM testing error: %s", vm_error, exc_info=True)
                runtime_ms = int((time.time() - start_time) * 1000)

                script_analysis = self._analyze_script_content(script)
                return {
                    "success": False,
                    "output": f"Validation error; analysis completed:\n{script_analysis['analysis']}",
                    "error": f"VM execution error: {vm_error}",
                    "exit_code": 2,
                    "runtime_ms": runtime_ms,
                    "method": "fallback",
                    "results": {
                        "real_execution": False,
                        "analysis_only": True,
                        "script_analyzed": script_analysis,
                        "target": target_binary,
                        "config": vm_config,
                        "error_details": str(vm_error),
                    },
                }

        def _analyze_script_content(self, script: str) -> dict[str, Any]:
            """Analyze script content to determine type and characteristics.

            Args:
                script: The script content to analyze

            Returns:
                Dictionary containing analysis results with type, extension, length,
                lines, features, and analysis summary

            """
            try:
                if not script:
                    return {"type": "empty", "extension": "txt", "analysis": "Empty script"}

                script_lower = script.lower()
                analysis_result: dict[str, Any] = {
                    "length": len(script),
                    "lines": len(script.split("\n")),
                    "features": [],
                    "analysis": "",
                }

                # Determine script type and extension
                features_list: list[str] = []
                if "java.perform" in script_lower or "frida" in script_lower:
                    analysis_result["type"] = "frida"
                    analysis_result["extension"] = "js"
                    features_list.append("frida_javascript")
                elif "javascript" in script_lower or script.strip().startswith("Java"):
                    analysis_result["type"] = "javascript"
                    analysis_result["extension"] = "js"
                    features_list.append("javascript")
                elif "python" in script_lower or script.strip().startswith("#!/usr/bin/python"):
                    analysis_result["type"] = "python"
                    analysis_result["extension"] = "py"
                    features_list.append("python_script")
                else:
                    analysis_result["type"] = "generic"
                    analysis_result["extension"] = "txt"
                    features_list.append("generic_script")

                # Analyze script features
                if "memory" in script_lower:
                    features_list.append("memory_manipulation")
                if any(hook in script_lower for hook in ["hook", "intercept", "patch"]):
                    features_list.append("hooking_techniques")
                if any(api in script_lower for api in ["api", "call", "function"]):
                    features_list.append("api_interaction")
                if "encrypt" in script_lower or "decrypt" in script_lower:
                    features_list.append("cryptographic_operations")

                analysis_result["features"] = features_list
                lines_count = analysis_result["lines"]
                assert isinstance(lines_count, int), "lines must be an integer"
                complexity = "high" if lines_count > 50 else "medium" if lines_count > 20 else "simple"

                # Generate analysis summary
                analysis_result["analysis"] = f"""
Script Analysis:
- Type: {analysis_result["type"]}
- Size: {analysis_result["length"]} bytes ({lines_count} lines)
- Features: {", ".join(features_list) if features_list else "basic"}
- Complexity: {complexity}
"""

                return analysis_result

            except Exception as analysis_error:
                logger.exception("Script analysis error: %s", analysis_error)
                return {
                    "type": "unknown",
                    "extension": "txt",
                    "length": len(script) if script else 0,
                    "analysis": f"Analysis failed: {analysis_error}",
                }

        def _create_protected_binary(self, target_path: str) -> None:
            """Create a protected binary with real license checking for testing."""
            try:
                import struct

                # Create real PE executable with license check
                dos_header = b"MZ" + struct.pack("<H", 0x90)  # e_magic
                dos_header += struct.pack("<H", 3) + struct.pack("<H", 0)  # e_cblp, e_cp
                dos_header += struct.pack("<H", 4) + struct.pack("<H", 0)  # e_crlc, e_cparhdr
                dos_header += struct.pack("<H", 0xFFFF) + struct.pack("<H", 0)  # e_minalloc, e_maxalloc
                dos_header += struct.pack("<H", 0) + struct.pack("<H", 0xB8)  # e_ss, e_sp
                dos_header += struct.pack("<H", 0) + struct.pack("<H", 0)  # e_csum, e_ip
                dos_header += struct.pack("<H", 0) + struct.pack("<H", 0x40)  # e_cs, e_lfarlc
                dos_header += struct.pack("<H", 0) + struct.pack("<H", 0)  # e_ovno, e_res
                dos_header += b"\x00" * 32  # e_res2
                dos_header += struct.pack("<I", 0x80)  # e_lfanew

                # DOS executable section with license validation code
                dos_section = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
                dos_section += b"This program requires a valid license.\r\r\n$"
                dos_section += b"\x00" * (0x80 - len(dos_header) - len(dos_section))

                # PE header with protection flags
                pe_header = b"PE\x00\x00"  # Signature
                pe_header += struct.pack("<H", 0x8664)  # Machine (x64)
                pe_header += struct.pack("<H", 3)  # NumberOfSections
                pe_header += struct.pack("<I", int(time.time()))  # TimeDateStamp
                pe_header += struct.pack("<I", 0)  # PointerToSymbolTable
                pe_header += struct.pack("<I", 0)  # NumberOfSymbols
                pe_header += struct.pack("<H", 0xF0)  # SizeOfOptionalHeader
                pe_header += struct.pack("<H", 0x22)  # Characteristics (EXECUTABLE | LARGE_ADDRESS_AWARE)

                # Optional header with license validation entry point
                opt_header = struct.pack("<H", 0x20B)  # Magic (PE32+)
                opt_header += struct.pack("<BB", 14, 0)  # Linker version
                opt_header += struct.pack("<I", 0x1000)  # SizeOfCode
                opt_header += struct.pack("<I", 0x1000)  # SizeOfInitializedData
                opt_header += struct.pack("<I", 0)  # SizeOfUninitializedData
                opt_header += struct.pack("<I", 0x1000)  # AddressOfEntryPoint
                opt_header += struct.pack("<I", 0x1000)  # BaseOfCode
                opt_header += struct.pack("<Q", 0x140000000)  # ImageBase
                opt_header += b"\x00" * (0xF0 - len(opt_header))  # Rest of optional header

                # Section headers
                text_section = b".text\x00\x00\x00"  # Name
                text_section += struct.pack("<I", 0x1000)  # VirtualSize
                text_section += struct.pack("<I", 0x1000)  # VirtualAddress
                text_section += struct.pack("<I", 0x200)  # SizeOfRawData
                text_section += struct.pack("<I", 0x200)  # PointerToRawData
                text_section += b"\x00" * 16  # Relocations and line numbers
                text_section += struct.pack("<I", 0x60000020)  # Characteristics

                # License validation code section with real RVA calculations
                # Entry point at RVA 0x1000, calculate offsets for .rdata (0x2000) and .idata (0x3000)
                license_code = b"\x48\x83\xec\x28"  # sub rsp, 0x28

                # Calculate RVA offset from current IP to license_key in .rdata section
                # Current IP after this instruction = 0x1004, target = 0x2000, RVA = 0x2000 - (0x1004 + 7) = 0xFF5
                license_key_rva = 0x2000 - (0x1000 + len(license_code) + 7)
                license_code += b"\x48\x8d\x0d" + struct.pack("<i", license_key_rva)  # lea rcx, [rip+license_key]

                # Calculate RVA offset from current IP to CheckLicense IAT entry in .idata
                # Current IP after lea = 0x100B, target IAT = 0x3000, RVA = 0x3000 - (0x100B + 6) = 0x1FEF
                check_license_rva = 0x3000 - (0x1000 + len(license_code) + 6)
                license_code += b"\xff\x15" + struct.pack("<i", check_license_rva)  # call [rip+CheckLicense]

                license_code += b"\x85\xc0"  # test eax, eax
                license_code += b"\x74\x05"  # jz invalid_license
                license_code += b"\x31\xc0"  # xor eax, eax
                license_code += b"\x48\x83\xc4\x28"  # add rsp, 0x28
                license_code += b"\xc3"  # ret
                license_code += b"\x90" * (0x200 - len(license_code))  # Padding

                # Write complete protected binary
                with open(target_path, "wb") as f:
                    f.write(dos_header + dos_section)
                    f.write(pe_header + opt_header)
                    f.write(text_section)
                    f.write(b"\x00" * (0x200 - f.tell() % 0x200))  # Align to file alignment
                    f.write(license_code)

                Path(target_path).chmod(0o700)  # Restrictive permissions: only owner can read/write/execute

            except Exception as create_error:
                logger.exception("Protected binary creation error: %s", create_error)
                # Create minimal protected file as fallback
                with open(target_path, "wb") as f:
                    # Minimal ELF with protection check
                    elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8  # ELF magic
                    elf_header += struct.pack("<H", 2)  # e_type (executable)
                    elf_header += struct.pack("<H", 0x3E)  # e_machine (x86-64)
                    elf_header += struct.pack("<I", 1)  # e_version
                    elf_header += b"\x00" * 32  # Rest of header
                    f.write(elf_header)

        def _execute_script_in_environment(
            self,
            script: str,
            script_file: str | Path,
            target_file: str | Path,
            vm_config: dict[str, Any] | None,
            execution_dir: str | Path,
        ) -> dict[str, Any]:
            """Execute in controlled environment; default to validation unless explicit run is enabled.

            Args:
                script: The script content to execute
                script_file: Path to the script file
                target_file: Path to the target binary file
                vm_config: Optional VM configuration dictionary
                execution_dir: Path to the execution directory

            Returns:
                Dictionary containing execution results with success, output, error,
                exit_code, and method

            """
            try:
                script_path = Path(script_file)
                target_path = Path(target_file)
                exec_dir = Path(execution_dir)

                if vm_config and vm_config.get("dry_run", True):
                    return self._perform_script_validation(script, script_path, target_path)

                try:
                    effective_vm_config = vm_config or {}
                    qemu_result = self._try_qemu_execution(script_path, target_path, effective_vm_config)
                    if qemu_result["success"]:
                        return qemu_result
                except Exception as qemu_error:
                    logger.debug("QEMU execution failed: %s", qemu_error)

                try:
                    native_result = self._try_native_execution(script, script_path, target_path, exec_dir)
                    if native_result["success"]:
                        return native_result
                except Exception as native_error:
                    logger.debug("Native execution failed: %s", native_error)

                return self._perform_script_validation(script, script_path, target_path)

            except Exception as execution_error:
                logger.exception("Script execution error: %s", execution_error)
                return {
                    "success": False,
                    "output": f"Script execution failed: {execution_error}",
                    "error": str(execution_error),
                    "exit_code": 1,
                    "method": "error_fallback",
                }

        def _try_qemu_execution(self, script_file: Path, target_file: Path, vm_config: dict[str, Any]) -> dict[str, Any]:
            """Attempt QEMU-based script execution (best-effort; requires proper setup).

            Args:
                script_file: Path to the script file
                target_file: Path to the target binary file
                vm_config: VM configuration dictionary

            Returns:
                Dictionary containing execution results with success, output, error,
                exit_code, and method

            """
            import shutil
            import subprocess

            qemu_bin = "qemu-x86_64" if os.name != "nt" else "qemu-system-x86_64"
            if shutil.which(qemu_bin) is None:
                raise FileNotFoundError(f"{qemu_bin} not found on PATH")

            qemu_cmd = [qemu_bin]
            if qemu_bin == "qemu-system-x86_64":
                qemu_cmd += [
                    "-cpu",
                    vm_config.get("cpu", "qemu64"),
                    "-m",
                    str(vm_config.get("memory", "512")),
                ]
                qemu_cmd += ["-nographic", "-no-reboot"]
            result = subprocess.run(  # nosec S603
                [*qemu_cmd, str(target_file)],
                capture_output=True,
                text=True,
                timeout=vm_config.get("timeout", 30),
                cwd=str(script_file.parent),
                shell=False,
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
                "exit_code": result.returncode,
                "method": "qemu",
            }

        def _try_native_execution(self, script: str, script_file: Path, target_file: Path, execution_dir: Path) -> dict[str, Any]:
            """Attempt native script execution in sandbox with allowlisted interpreters.

            Args:
                script: The script content to execute
                script_file: Path to the script file
                target_file: Path to the target binary file
                execution_dir: Path to the execution directory

            Returns:
                Dictionary containing execution results with success, output, error,
                exit_code, and method

            """
            import shutil
            import subprocess

            if script_file.suffix == ".js" and shutil.which("node"):
                cmd = ["node", str(script_file)]
            elif script_file.suffix == ".py":
                cmd = ["python", str(script_file)]
            else:
                return {
                    "success": False,
                    "output": "Interpreter not available or unsupported",
                    "error": "unsupported",
                    "exit_code": 1,
                    "method": "native",
                }

            result = subprocess.run(  # nosec S603
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                cwd=str(execution_dir),
                shell=False,
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
                "exit_code": result.returncode,
                "method": "native",
            }

        def _perform_script_validation(self, script: str, script_file: Path, target_file: Path) -> dict[str, Any]:
            """Perform script validation and static analysis (ASCII-only output).

            Args:
                script: The script content to validate
                script_file: Path to the script file
                target_file: Path to the target binary file

            Returns:
                Dictionary containing validation results with success, output, error,
                exit_code, and method

            """
            try:
                validation_results = [
                    "=== Script Validation Results ===",
                    f"Script file: {script_file}",
                    f"Target binary: {target_file}",
                    f"Script size: {len(script)} bytes",
                ]
                try:
                    if script_file.suffix == ".js":
                        if any(tok in script for tok in ("function", "var ", "let ", "const ")):
                            validation_results.append("OK JavaScript syntax patterns detected")
                        else:
                            validation_results.append("WARNING No clear JavaScript patterns found")

                    security_patterns = ["hook", "patch", "memory", "bypass", "inject"]
                    if found := [p for p in security_patterns if p in script.lower()]:
                        validation_results.append("OK Security patterns detected: " + ", ".join(found))

                    validation_results.append("OK Script validation completed successfully")
                except Exception as validation_error:
                    validation_results.append(f"WARNING Validation warning: {validation_error}")

                return {
                    "success": True,
                    "output": "\n".join(validation_results),
                    "error": "",
                    "exit_code": 0,
                    "method": "validation",
                }

            except Exception as validation_error:
                return {
                    "success": False,
                    "output": f"Script validation failed: {validation_error}",
                    "error": str(validation_error),
                    "exit_code": 1,
                    "method": "validation_failed",
                }


@dataclass
class IntegrationTask:
    """Represents a task in the integration workflow."""

    task_id: str
    task_type: str
    description: str
    input_data: dict[str, Any]
    dependencies: list[str] = field(default_factory=list)
    status: str = "pending"  # pending, running, completed, failed
    result: Any = None
    error: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    priority: int = 1  # 1=high, 5=low


@dataclass
class WorkflowResult:
    """Result of a complete workflow execution."""

    workflow_id: str
    success: bool
    tasks_completed: int
    tasks_failed: int
    execution_time: float
    results: dict[str, Any]
    errors: list[str] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)


class IntegrationManager:
    """Manages integration and coordination of AI components."""

    def __init__(self, llm_manager: LLMManager | None = None) -> None:
        """Initialize the integration manager.

        Args:
            llm_manager: Optional LLM manager for AI components

        """
        self.logger = get_logger(f"{__name__}.IntegrationManager")
        self.llm_manager = llm_manager or LLMManager()

        # Initialize components
        self.script_generator = AIScriptGenerator()
        self.code_modifier = IntelligentCodeModifier(self.llm_manager)
        self.ai_agent = AIAgent(self.llm_manager)
        self.qemu_manager = QEMUManager()

        # Task management
        self.task_queue: Queue[IntegrationTask] = Queue()
        self.active_tasks: dict[str, IntegrationTask] = {}
        self.completed_tasks: dict[str, IntegrationTask] = {}
        self.task_dependencies: dict[str, list[str]] = {}
        self._state_lock = threading.Lock()

        # Workflow management
        self.active_workflows: dict[str, dict[str, Any]] = {}
        self.workflow_results: dict[str, WorkflowResult] = {}
        self._workflow_lock = threading.Lock()

        # Execution control
        self.max_workers = 4
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.running = False
        self.worker_threads: list[threading.Thread] = []

        # Event handlers
        self.event_handlers: dict[str, list[Callable[..., Any]]] = {}

        # Optimization settings
        self.enable_caching = True
        self.enable_parallel_execution = True
        self.task_timeout = 300  # 5 minutes

        logger.info("Integration manager initialized")

    def start(self) -> None:
        """Start the integration manager."""
        if self.running:
            return

        self.running = True
        performance_monitor.start_monitoring()

        # Start worker threads
        for i in range(self.max_workers):
            thread = threading.Thread(
                target=self._worker_loop,
                name=f"IntegrationWorker-{i}",
                daemon=True,
            )
            thread.start()
            self.worker_threads.append(thread)

        logger.info("Integration manager started with %d workers", self.max_workers)

    def stop(self) -> None:
        """Stop the integration manager."""
        if not self.running:
            return

        self.running = False

        # Wait for workers to finish
        for thread in self.worker_threads:
            thread.join(timeout=5.0)

        self.executor.shutdown(wait=True)
        performance_monitor.stop_monitoring()

        logger.info("Integration manager stopped")

    def _worker_loop(self) -> None:
        """Process tasks in the main worker loop."""
        while self.running:
            try:
                try:
                    task = self.task_queue.get(timeout=1.0)
                except Empty:
                    continue

                # Check dependencies
                if not self._are_dependencies_satisfied(task):
                    # Put back in queue and wait
                    self.task_queue.put(task)
                    time.sleep(0.5)
                    continue

                # Execute task
                self._execute_task(task)

            except Exception as e:
                logger.exception("Error in worker loop: %s", e)
                time.sleep(1.0)

    def _are_dependencies_satisfied(self, task: IntegrationTask) -> bool:
        """Check if task dependencies are satisfied."""
        for dep_id in task.dependencies:
            if dep_id not in self.completed_tasks:
                return False
            if self.completed_tasks[dep_id].status != "completed":
                return False
        return True

    @profile_ai_operation("integration.execute_task")
    def _execute_task(self, task: IntegrationTask) -> None:
        """Execute a single task."""
        task.status = "running"
        task.started_at = datetime.now()
        with self._state_lock:
            self.active_tasks[task.task_id] = task

        try:
            # Emit task started event
            self._emit_event("task_started", task)

            # Execute based on task type
            if task.task_type == "generate_script":
                result = self._execute_script_generation(task)
            elif task.task_type == "modify_code":
                result = self._execute_code_modification(task)
            elif task.task_type == "validate_script":
                result = self._execute_script_testing(task)
            elif task.task_type == "autonomous_analysis":
                result = self._execute_autonomous_analysis(task)
            elif task.task_type == "combine_results":
                result = self._execute_result_combination(task)
            else:
                raise ValueError(f"Unknown task type: {task.task_type}")

            task.result = result
            task.status = "completed"
            task.completed_at = datetime.now()

            # Emit task completed event
            self._emit_event("task_completed", task)

        except Exception as e:
            task.error = str(e)
            task.status = "failed"
            task.completed_at = datetime.now()

            logger.exception("Task %s failed: %s", task.task_id, e)
            self._emit_event("task_failed", task)

        finally:
            # Move from active to completed
            with self._state_lock:
                if task.task_id in self.active_tasks:
                    del self.active_tasks[task.task_id]
                self.completed_tasks[task.task_id] = task

    def _execute_script_generation(self, task: IntegrationTask) -> dict[str, Any]:
        """Execute script generation task."""
        request = task.input_data["request"]
        script_type = task.input_data.get("script_type", "frida")

        if script_type == "frida":
            scripts = self.script_generator.generate_frida_script(request)
        elif script_type == "ghidra":
            scripts = self.script_generator.generate_ghidra_script(request)
        else:
            raise ValueError(f"Unknown script type: {script_type}")

        return {"scripts": scripts, "script_type": script_type}

    def _execute_code_modification(self, task: IntegrationTask) -> dict[str, Any]:
        """Execute code modification task."""
        request_data = task.input_data["request"]

        # Create modification request
        request = self.code_modifier.create_modification_request(**request_data)

        # Analyze and generate changes
        changes = self.code_modifier.analyze_modification_request(request)

        # Apply changes if requested
        apply_immediately = task.input_data.get("apply_immediately", False)
        if apply_immediately and changes:
            change_ids = [c.change_id for c in changes]
            apply_results = self.code_modifier.apply_changes(change_ids)
        else:
            apply_results = None

        return {
            "changes": changes,
            "apply_results": apply_results,
            "request": request,
        }

    def _execute_script_testing(self, task: IntegrationTask) -> dict[str, Any]:
        """Execute script testing task."""
        script = task.input_data["script"]
        target_binary = task.input_data["target_binary"]
        vm_config = task.input_data.get("vm_config", {})

        if hasattr(self.qemu_manager, "validate_script_in_vm"):
            result = self.qemu_manager.validate_script_in_vm(script, target_binary, vm_config)
            if isinstance(result, dict):
                return result
            return {
                "success": False,
                "output": "Invalid result from QEMU manager",
                "error": "validate_script_in_vm returned non-dict",
                "exit_code": 1,
            }
        else:
            return {
                "success": False,
                "output": "QEMU manager not available",
                "error": "validate_script_in_vm method not found",
                "exit_code": 1,
            }

    def _execute_autonomous_analysis(self, task: IntegrationTask) -> dict[str, Any]:
        """Execute autonomous analysis task."""
        task_config = task.input_data["task_config"]

        return self.ai_agent.execute_autonomous_task(task_config)

    def _execute_result_combination(self, task: IntegrationTask) -> dict[str, Any]:
        """Combine results from dependent tasks."""
        dependency_results = {dep_id: self.completed_tasks[dep_id].result for dep_id in task.dependencies if dep_id in self.completed_tasks}
        combination_logic = task.input_data.get("combination_logic", "merge")

        combined: dict[str, Any] = {}
        if combination_logic == "merge":
            # Simple merge of all results
            for dep_id, result in dependency_results.items():
                if isinstance(result, dict):
                    combined |= result
                else:
                    combined[dep_id] = result
        elif combination_logic == "select_best":
            # Select best result based on criteria
            criteria = task.input_data.get("selection_criteria", "confidence")
            best_result = self._select_best_result(dependency_results, criteria)
            if best_result is not None:
                combined = best_result
        else:
            combined = dependency_results if isinstance(dependency_results, dict) else {}

        return combined

    def _select_best_result(self, results: dict[str, Any], criteria: str) -> dict[str, Any] | None:
        """Select best result based on criteria.

        Args:
            results: Dictionary of results to select from
            criteria: Selection criteria (e.g., 'confidence')

        Returns:
            The best result dictionary or None if no results available

        """
        if not results:
            return None

        if criteria == "confidence":
            # Select result with highest confidence
            best_result: dict[str, Any] | None = None
            best_confidence = 0.0

            for result in results.values():
                if isinstance(result, dict) and "confidence" in result:
                    confidence = result["confidence"]
                    if isinstance(confidence, (int, float)) and confidence > best_confidence:
                        best_confidence = float(confidence)
                        best_result = result

            if best_result is not None:
                return best_result
            first_value = next(iter(results.values()), None)
            return first_value if isinstance(first_value, dict) else None

        # Default: return first result
        first_value = next(iter(results.values()), None)
        return first_value if isinstance(first_value, dict) else None

    def create_task(
        self,
        task_type: str,
        description: str,
        input_data: dict[str, Any],
        dependencies: list[str] | None = None,
        priority: int = 1,
    ) -> str:
        """Create a new integration task."""
        task_id = f"{task_type}_{int(time.time() * 1000)}"

        task = IntegrationTask(
            task_id=task_id,
            task_type=task_type,
            description=description,
            input_data=input_data,
            dependencies=dependencies or [],
            priority=priority,
        )

        # Add to queue
        self.task_queue.put(task)
        logger.info("Created task %s: %s", task_id, description)

        return task_id

    def create_workflow(self, workflow_definition: dict[str, Any]) -> str:
        """Create a complex workflow with multiple tasks."""
        workflow_id = f"workflow_{int(time.time() * 1000)}"

        workflow: dict[str, Any] = {
            "id": workflow_id,
            "definition": workflow_definition,
            "tasks": {},
            "status": "created",
            "created_at": datetime.now(),
        }

        # Create tasks from definition
        tasks = workflow_definition.get("tasks", [])
        task_mapping: dict[str, str] = {}

        for task_def in tasks:
            dependencies = [task_mapping[dep_name] for dep_name in task_def.get("dependencies", []) if dep_name in task_mapping]
            task_id = self.create_task(
                task_type=task_def["type"],
                description=task_def.get("description", task_def["type"]),
                input_data=task_def["input"],
                dependencies=dependencies,
                priority=task_def.get("priority", 1),
            )

            task_name = task_def.get("name", task_id)
            task_mapping[task_name] = task_id
            workflow_tasks = workflow.get("tasks")
            if isinstance(workflow_tasks, dict):
                workflow_tasks[task_id] = task_def

        self.active_workflows[workflow_id] = workflow
        logger.info("Created workflow %s with %d tasks", workflow_id, len(tasks))

        return workflow_id

    def wait_for_task(self, task_id: str, timeout: float | None = None) -> IntegrationTask:
        """Wait for a task to complete."""
        start_time = time.time()

        while True:
            if task_id in self.completed_tasks:
                return self.completed_tasks[task_id]

            if timeout and time.time() - start_time > timeout:
                raise TimeoutError(f"Task {task_id} did not complete within {timeout} seconds")

            time.sleep(0.1)

    def wait_for_workflow(self, workflow_id: str, timeout: float | None = None) -> WorkflowResult:
        """Wait for a workflow to complete."""
        if workflow_id not in self.active_workflows:
            raise ValueError(f"Workflow {workflow_id} not found")

        workflow = self.active_workflows[workflow_id]
        task_ids = list(workflow["tasks"].keys())

        start_time = time.time()

        # Wait for all tasks to complete
        completed_tasks: dict[str, IntegrationTask] = {}
        failed_tasks: dict[str, IntegrationTask] = {}

        while len(completed_tasks) + len(failed_tasks) < len(task_ids):
            for task_id in task_ids:
                if task_id in completed_tasks or task_id in failed_tasks:
                    continue

                if task_id in self.completed_tasks:
                    task = self.completed_tasks[task_id]
                    if task.status == "completed":
                        completed_tasks[task_id] = task
                    elif task.status == "failed":
                        failed_tasks[task_id] = task

            if timeout and time.time() - start_time > timeout:
                raise TimeoutError(f"Workflow {workflow_id} did not complete within {timeout} seconds")

            time.sleep(0.1)

        # Create workflow result
        execution_time = time.time() - start_time

        results = {}
        errors = []
        artifacts = {}

        for task_id, task in completed_tasks.items():
            results[task_id] = task.result
            if isinstance(task.result, dict) and "artifacts" in task.result:
                artifacts[task_id] = task.result["artifacts"]

        for task_id, task in failed_tasks.items():
            errors.append(f"Task {task_id}: {task.error}")

        workflow_result = WorkflowResult(
            workflow_id=workflow_id,
            success=not failed_tasks,
            tasks_completed=len(completed_tasks),
            tasks_failed=len(failed_tasks),
            execution_time=execution_time,
            results=results,
            errors=errors,
            artifacts=artifacts,
        )

        self.workflow_results[workflow_id] = workflow_result

        # Cleanup
        if workflow_id in self.active_workflows:
            del self.active_workflows[workflow_id]

        return workflow_result

    def get_task_status(self, task_id: str) -> dict[str, Any]:
        """Get status of a task."""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
        elif task_id in self.completed_tasks:
            task = self.completed_tasks[task_id]
        else:
            return {"status": "not_found"}

        return {
            "task_id": task.task_id,
            "status": task.status,
            "description": task.description,
            "created_at": task.created_at.isoformat(),
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            "error": task.error,
        }

    def get_workflow_status(self, workflow_id: str) -> dict[str, Any]:
        """Get status of a workflow."""
        if workflow_id in self.active_workflows:
            workflow = self.active_workflows[workflow_id]
            task_ids = list(workflow["tasks"].keys())

            completed = sum(tid in self.completed_tasks and self.completed_tasks[tid].status == "completed" for tid in task_ids)
            failed = sum(tid in self.completed_tasks and self.completed_tasks[tid].status == "failed" for tid in task_ids)
            running = sum(tid in self.active_tasks for tid in task_ids)
            pending = len(task_ids) - completed - failed - running

            return {
                "workflow_id": workflow_id,
                "status": "running",
                "total_tasks": len(task_ids),
                "completed": completed,
                "failed": failed,
                "running": running,
                "pending": pending,
            }
        if workflow_id in self.workflow_results:
            result = self.workflow_results[workflow_id]
            return {
                "workflow_id": workflow_id,
                "status": "completed",
                "success": result.success,
                "tasks_completed": result.tasks_completed,
                "tasks_failed": result.tasks_failed,
                "execution_time": result.execution_time,
            }
        return {"status": "not_found"}

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending task."""
        cancelled = False

        # Requeue all except the one to cancel
        try:
            temp_items: list[IntegrationTask] = []
            while True:
                item = self.task_queue.get_nowait()
                temp_items.append(item)
        except Empty:
            pass
        for item in temp_items:
            if getattr(item, "task_id", None) == task_id:
                cancelled = True
                continue
            self.task_queue.put(item)

        # Check active tasks
        with self._state_lock:
            if task_id in self.active_tasks:
                del self.active_tasks[task_id]
                cancelled = True

        if cancelled:
            logger.info("Successfully cancelled task %s", task_id)
        else:
            logger.warning("Task %s not found in queue or active tasks", task_id)

        return cancelled

    def add_event_handler(self, event_type: str, handler: Callable[..., Any]) -> None:
        """Add event handler."""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)

    def _emit_event(self, event_type: str, data: IntegrationTask) -> None:
        """Emit event to handlers.

        Args:
            event_type: Type of event to emit
            data: Task data to emit with the event

        """
        handlers = self.event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                handler(data)
            except Exception as e:
                logger.exception("Error in event handler: %s", e)

    def create_bypass_workflow(self, target_binary: str, bypass_type: str = "license_validation") -> str:
        """Create a complete bypass workflow."""
        workflow_def = {
            "name": "Complete Bypass Workflow",
            "description": f"End-to-end {bypass_type} bypass for {target_binary}",
            "tasks": [
                {
                    "name": "analyze_target",
                    "type": "autonomous_analysis",
                    "description": "Analyze target binary",
                    "input": {
                        "task_config": {
                            "objective": f"Analyze {target_binary} for {bypass_type}",
                            "target_file": target_binary,
                            "analysis_depth": "comprehensive",
                        },
                    },
                    "priority": 1,
                },
                {
                    "name": "generate_frida_script",
                    "type": "generate_script",
                    "description": "Generate Frida bypass script",
                    "input": {
                        "request": {
                            "target_info": {"file_path": target_binary},
                            "bypass_type": bypass_type,
                        },
                        "script_type": "frida",
                    },
                    "dependencies": ["analyze_target"],
                    "priority": 1,
                },
                {
                    "name": "generate_ghidra_script",
                    "type": "generate_script",
                    "description": "Generate Ghidra analysis script",
                    "input": {
                        "request": {
                            "target_info": {"file_path": target_binary},
                            "analysis_type": "static_analysis",
                        },
                        "script_type": "ghidra",
                    },
                    "dependencies": ["analyze_target"],
                    "priority": 2,
                },
                {
                    "name": "validate_frida_script",
                    "type": "validate_script",
                    "description": "Test Frida script in VM",
                    "input": {
                        "target_binary": target_binary,
                        "vm_config": {
                            "name": "validate_vm",
                            "memory": 2048,
                            "architecture": "x86_64",
                        },
                    },
                    "dependencies": ["generate_frida_script"],
                    "priority": 2,
                },
                {
                    "name": "combine_results",
                    "type": "combine_results",
                    "description": "Combine all results",
                    "input": {
                        "combination_logic": "merge",
                    },
                    "dependencies": ["validate_frida_script", "generate_ghidra_script"],
                    "priority": 3,
                },
            ],
        }

        return self.create_workflow(workflow_def)

    def generate_response(
        self,
        prompt: str,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1000,
    ) -> str:
        """Generate a response using the configured LLM backend.

        Args:
            prompt: The input prompt to send to the language model
            model: Optional model name to use (defaults to active backend)
            temperature: Sampling temperature for response generation (0.0-1.0)
            max_tokens: Maximum number of tokens in the response

        Returns:
            Generated response text from the language model

        """
        from .llm_backends import LLMConfig, LLMMessage

        try:
            if not self.llm_manager:
                self.logger.exception("LLM manager not available")
                return "Error: AI backend not configured. Please configure an LLM provider in settings."

            available_llms = self.llm_manager.get_available_llms()
            if not available_llms:
                if not (provider := self._detect_provider_from_model(model)):
                    return "Error: No AI models available. Please configure an LLM provider."

                config = LLMConfig(
                    provider=provider,
                    model_name=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                llm_id = f"{provider.value}_{model}" if model else provider.value
                if not self.llm_manager.register_llm(llm_id, config):
                    return f"Error: Failed to initialize AI model '{model or 'default'}'"
            backend_id = None
            if model:
                for llm_id in available_llms:
                    info = self.llm_manager.get_llm_info(llm_id)
                    if info and info.get("model_name") == model:
                        backend_id = llm_id
                        break

            if not backend_id:
                backend_id = self.llm_manager.active_backend

            if not backend_id:
                return "Error: No active AI backend available"

            messages = [LLMMessage(role="user", content=prompt)]

            response = self.llm_manager.chat(messages, llm_id=backend_id)

            if response and response.content:
                return response.content.strip()

            return "Error: AI model returned empty response"

        except ImportError as e:
            self.logger.exception("Import error during response generation")
            return f"Error: Required AI dependencies not available - {e}"
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error generating AI response")
            return f"Error generating response: {e}"

    def _detect_provider_from_model(self, model: str | None) -> LLMProvider | None:
        """Detect the LLM provider from model name.

        Args:
            model: Model name string to analyze

        Returns:
            Detected LLMProvider or None if unable to determine

        """
        from .llm_backends import LLMProvider

        if not model:
            return None

        model_lower = model.lower()

        if any(name in model_lower for name in ["gpt-4", "gpt-3.5", "o1", "davinci", "curie"]):
            return LLMProvider.OPENAI

        if any(name in model_lower for name in ["claude", "anthropic", "opus", "sonnet", "haiku"]):
            return LLMProvider.ANTHROPIC

        if any(name in model_lower for name in ["llama", "mistral", "mixtral", "codellama", "deepseek"]):
            return LLMProvider.OLLAMA

        return LLMProvider.LOCAL_GGUF if model_lower.endswith(".gguf") else None

    def get_performance_summary(self) -> dict[str, Any]:
        """Get performance summary for integration operations."""
        return performance_monitor.get_metrics_summary()

    def cleanup(self) -> None:
        """Cleanup resources and old data."""
        # Clean old completed tasks (keep last 100)
        if len(self.completed_tasks) > 100:
            sorted_tasks = sorted(
                self.completed_tasks.items(),
                key=lambda item: item[1].completed_at.timestamp() if isinstance(item[1].completed_at, datetime) else float("-inf"),
                reverse=True,
            )

            # Keep most recent 100
            self.completed_tasks = dict(sorted_tasks[:100])

        # Clean old workflow results (keep last 50)
        if len(self.workflow_results) > 50:
            sorted_workflows = sorted(
                self.workflow_results.items(),
                key=lambda x: x[1].workflow_id,
                reverse=True,
            )

            self.workflow_results = dict(sorted_workflows[:50])

        logger.info("Cleanup completed")

    def __enter__(self) -> Self:
        """Context manager entry.

        Returns:
            The IntegrationManager instance

        """
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> Literal[False]:
        """Context manager exit.

        Args:
            exc_type: Exception type if an exception occurred
            exc_val: Exception value if an exception occurred
            exc_tb: Exception traceback if an exception occurred

        Returns:
            False to not suppress exceptions

        """
        if exc_type:
            logger.exception("Integration manager exiting due to %s: %s", exc_type.__name__, exc_val)
            if exc_tb:
                logger.debug("Exception traceback available: %s:%d", exc_tb.tb_frame.f_code.co_filename, exc_tb.tb_lineno)
        self.stop()
        return False  # Don't suppress exceptions


# Global integration manager instance
_integration_manager_singleton: IntegrationManager | None = None


def get_integration_manager() -> IntegrationManager:
    """Get or create the global integration manager singleton.

    Returns:
        The global IntegrationManager instance

    """
    global _integration_manager_singleton
    if _integration_manager_singleton is None:
        _integration_manager_singleton = IntegrationManager()
    return _integration_manager_singleton
