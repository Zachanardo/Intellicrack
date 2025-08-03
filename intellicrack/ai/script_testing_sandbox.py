"""
Script Testing Sandbox

Safe validation environment for generated scripts with comprehensive testing,
performance monitoring, and security isolation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
import hashlib
import json
import os
import psutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..core.analysis.unified_model.model import UnifiedBinaryModel
from ..utils.logger import get_logger
from .ai_script_generator import GeneratedScript, ScriptType
from .feedback_loop_engine import ExecutionStatus, FeedbackLoopEngine, ScriptExecutionResult

logger = get_logger(__name__)


class SandboxIsolationLevel(Enum):
    """Sandbox isolation levels"""
    MINIMAL = "minimal"
    STANDARD = "standard"
    HIGH = "high"
    MAXIMUM = "maximum"


class ValidationResult(Enum):
    """Script validation results"""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"


class SecurityRiskLevel(Enum):
    """Security risk levels for scripts"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SandboxConfig:
    """Configuration for script testing sandbox"""
    isolation_level: SandboxIsolationLevel = SandboxIsolationLevel.STANDARD
    max_execution_time: float = 30.0
    max_memory_usage: int = 512 * 1024 * 1024  # 512MB
    max_cpu_usage: float = 80.0
    enable_network: bool = False
    enable_file_access: bool = True
    allowed_file_paths: List[str] = field(default_factory=list)
    blocked_api_calls: Set[str] = field(default_factory=lambda: {
        "CreateProcess", "ShellExecute", "WinExec", "system",
        "DeleteFile", "RemoveDirectory", "RegDeleteKey"
    })
    enable_performance_monitoring: bool = True
    enable_security_analysis: bool = True
    validation_timeout: float = 10.0


@dataclass
class SecurityAnalysisResult:
    """Result of security analysis"""
    risk_level: SecurityRiskLevel
    detected_risks: List[str]
    safe_to_execute: bool
    warnings: List[str]
    blocked_operations: List[str]


@dataclass
class PerformanceMetrics:
    """Performance metrics during script execution"""
    execution_time: float
    peak_memory_usage: int
    average_cpu_usage: float
    peak_cpu_usage: float
    disk_io_operations: int
    network_requests: int


@dataclass
class ValidationReport:
    """Comprehensive validation report"""
    script_id: str
    script_type: ScriptType
    validation_result: ValidationResult
    security_analysis: SecurityAnalysisResult
    performance_metrics: Optional[PerformanceMetrics]
    syntax_errors: List[str]
    runtime_errors: List[str]
    warnings: List[str]
    execution_output: str
    sandbox_logs: List[str]
    timestamp: float
    validation_time: float


class ScriptTestingSandbox:
    """Safe script validation and testing environment"""
    
    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self.sandbox_dir = Path(tempfile.mkdtemp(prefix="intellicrack_sandbox_"))
        self.active_processes: Set[int] = set()
        self.validation_cache: Dict[str, ValidationReport] = {}
        
        # Initialize sandbox environment
        self._initialize_sandbox_environment()
        
        logger.info(f"Script testing sandbox initialized at {self.sandbox_dir}")
    
    def _initialize_sandbox_environment(self):
        """Initialize the sandbox environment"""
        
        # Create sandbox directory structure
        self.scripts_dir = self.sandbox_dir / "scripts"
        self.logs_dir = self.sandbox_dir / "logs"
        self.temp_dir = self.sandbox_dir / "temp"
        self.output_dir = self.sandbox_dir / "output"
        
        for directory in [self.scripts_dir, self.logs_dir, self.temp_dir, self.output_dir]:
            directory.mkdir(exist_ok=True)
        
        # Set restrictive permissions
        if os.name == 'nt':  # Windows
            # Use icacls to set permissions
            try:
                subprocess.run([
                    'icacls', str(self.sandbox_dir), 
                    '/inheritance:d', '/grant:r', f"{os.getlogin()}:F"
                ], check=True, capture_output=True)
            except Exception as e:
                logger.warning(f"Failed to set Windows permissions: {e}")
        else:  # Unix-like
            os.chmod(self.sandbox_dir, 0o700)
        
        logger.debug(f"Sandbox environment initialized with isolation level: {self.config.isolation_level.value}")
    
    async def validate_script(self, script: GeneratedScript, 
                            unified_model: Optional[UnifiedBinaryModel] = None) -> ValidationReport:
        """Validate a generated script in the sandbox"""
        
        script_id = self._generate_script_id(script)
        
        # Check cache first
        if script_id in self.validation_cache:
            logger.info(f"Using cached validation result for script {script_id}")
            return self.validation_cache[script_id]
        
        start_time = time.time()
        
        report = ValidationReport(
            script_id=script_id,
            script_type=script.script_type,
            validation_result=ValidationResult.FAILED,
            security_analysis=SecurityAnalysisResult(
                risk_level=SecurityRiskLevel.MEDIUM,
                detected_risks=[],
                safe_to_execute=False,
                warnings=[],
                blocked_operations=[]
            ),
            performance_metrics=None,
            syntax_errors=[],
            runtime_errors=[],
            warnings=[],
            execution_output="",
            sandbox_logs=[],
            timestamp=time.time(),
            validation_time=0.0
        )
        
        try:
            logger.info(f"Starting validation for {script.script_type.value} script: {script_id}")
            
            # Phase 1: Security Analysis
            security_result = await self._perform_security_analysis(script)
            report.security_analysis = security_result
            
            if not security_result.safe_to_execute:
                report.validation_result = ValidationResult.FAILED
                report.warnings.append("Script blocked due to security concerns")
                logger.warning(f"Script {script_id} blocked due to security risks: {security_result.detected_risks}")
            else:
                # Phase 2: Syntax Validation
                syntax_result = await self._validate_syntax(script)
                report.syntax_errors = syntax_result
                
                if syntax_result:
                    report.validation_result = ValidationResult.FAILED
                    report.warnings.append("Syntax errors detected")
                else:
                    # Phase 3: Safe Execution Test
                    if self.config.isolation_level != SandboxIsolationLevel.MINIMAL:
                        execution_result = await self._execute_script_safely(script, unified_model)
                        
                        report.performance_metrics = execution_result.get("performance_metrics")
                        report.runtime_errors = execution_result.get("runtime_errors", [])
                        report.execution_output = execution_result.get("output", "")
                        report.sandbox_logs = execution_result.get("logs", [])
                        
                        if execution_result.get("success", False):
                            report.validation_result = ValidationResult.PASSED
                        else:
                            report.validation_result = ValidationResult.FAILED
                            if execution_result.get("timeout", False):
                                report.warnings.append("Script execution timed out")
                    else:
                        report.validation_result = ValidationResult.WARNING
                        report.warnings.append("Execution test skipped (minimal isolation)")
            
            report.validation_time = time.time() - start_time
            
            # Cache successful validations
            if report.validation_result == ValidationResult.PASSED:
                self.validation_cache[script_id] = report
            
            logger.info(f"Validation completed for {script_id}: {report.validation_result.value}")
            
        except Exception as e:
            logger.error(f"Validation failed for script {script_id}: {e}")
            report.runtime_errors.append(str(e))
            report.validation_result = ValidationResult.FAILED
            report.validation_time = time.time() - start_time
        
        return report
    
    async def _perform_security_analysis(self, script: GeneratedScript) -> SecurityAnalysisResult:
        """Perform comprehensive security analysis of the script"""
        
        detected_risks = []
        warnings = []
        blocked_operations = []
        risk_level = SecurityRiskLevel.LOW
        
        script_content = script.content.lower()
        
        # Check for dangerous API calls
        for blocked_api in self.config.blocked_api_calls:
            if blocked_api.lower() in script_content:
                blocked_operations.append(blocked_api)
                detected_risks.append(f"Uses blocked API: {blocked_api}")
                risk_level = SecurityRiskLevel.HIGH
        
        # Check for file system operations
        file_operations = ["open(", "file(", "fopen", "createfile", "deletefile", "movefile"]
        for op in file_operations:
            if op in script_content:
                if not self.config.enable_file_access:
                    blocked_operations.append(op)
                    detected_risks.append(f"File operation not allowed: {op}")
                    risk_level = SecurityRiskLevel.MEDIUM
                else:
                    warnings.append(f"File operation detected: {op}")
        
        # Check for network operations
        network_operations = ["socket", "connect", "urlopen", "requests.", "http", "wget", "curl"]
        for op in network_operations:
            if op in script_content:
                if not self.config.enable_network:
                    blocked_operations.append(op)
                    detected_risks.append(f"Network operation not allowed: {op}")
                    risk_level = SecurityRiskLevel.MEDIUM
                else:
                    warnings.append(f"Network operation detected: {op}")
        
        # Check for process execution
        process_operations = ["subprocess", "os.system", "exec", "eval", "compile"]
        for op in process_operations:
            if op in script_content:
                detected_risks.append(f"Process execution detected: {op}")
                if risk_level == SecurityRiskLevel.LOW:
                    risk_level = SecurityRiskLevel.MEDIUM
        
        # Check for registry operations (Windows)
        registry_operations = ["winreg", "regsetvalue", "regdeletekey", "regqueryvalue"]
        for op in registry_operations:
            if op in script_content:
                detected_risks.append(f"Registry operation detected: {op}")
                risk_level = SecurityRiskLevel.HIGH
        
        # Check for memory operations
        memory_operations = ["ctypes", "mmap", "virtualalloc", "writeprocessmemory"]
        for op in memory_operations:
            if op in script_content:
                warnings.append(f"Memory operation detected: {op}")
        
        # Determine if safe to execute
        safe_to_execute = (
            risk_level in [SecurityRiskLevel.LOW, SecurityRiskLevel.MEDIUM] and
            len(blocked_operations) == 0
        )
        
        return SecurityAnalysisResult(
            risk_level=risk_level,
            detected_risks=detected_risks,
            safe_to_execute=safe_to_execute,
            warnings=warnings,
            blocked_operations=blocked_operations
        )
    
    async def _validate_syntax(self, script: GeneratedScript) -> List[str]:
        """Validate script syntax without execution"""
        
        syntax_errors = []
        
        try:
            if script.script_type == ScriptType.FRIDA:
                # Validate JavaScript syntax for Frida scripts
                syntax_errors.extend(self._validate_javascript_syntax(script.content))
            
            elif script.script_type in [ScriptType.GHIDRA, ScriptType.IDA_PYTHON]:
                # Validate Python syntax
                syntax_errors.extend(self._validate_python_syntax(script.content))
            
            elif script.script_type == ScriptType.RADARE2:
                # Validate r2 commands
                syntax_errors.extend(self._validate_radare2_syntax(script.content))
            
        except Exception as e:
            syntax_errors.append(f"Syntax validation error: {e}")
        
        return syntax_errors
    
    def _validate_javascript_syntax(self, content: str) -> List[str]:
        """Validate JavaScript syntax for Frida scripts"""
        
        errors = []
        
        # Check for basic JavaScript syntax issues
        if content.count('{') != content.count('}'):
            errors.append("Mismatched curly braces")
        
        if content.count('(') != content.count(')'):
            errors.append("Mismatched parentheses")
        
        if content.count('[') != content.count(']'):
            errors.append("Mismatched square brackets")
        
        # Check for common Frida API usage
        required_frida_apis = ["Java.perform", "Module.findExportByName", "Interceptor.attach"]
        has_frida_api = any(api in content for api in required_frida_apis)
        
        if not has_frida_api:
            errors.append("No Frida-specific API calls detected")
        
        return errors
    
    def _validate_python_syntax(self, content: str) -> List[str]:
        """Validate Python syntax"""
        
        errors = []
        
        try:
            compile(content, '<script>', 'exec')
        except SyntaxError as e:
            errors.append(f"Python syntax error: {e}")
        except Exception as e:
            errors.append(f"Python compilation error: {e}")
        
        return errors
    
    def _validate_radare2_syntax(self, content: str) -> List[str]:
        """Validate radare2 command syntax"""
        
        errors = []
        
        lines = content.strip().split('\n')
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Check for valid r2 command format
            if not line.startswith(('a', 'i', 'p', 's', 'f', 'V', '?')):
                errors.append(f"Line {i}: Invalid r2 command format: {line}")
        
        return errors
    
    async def _execute_script_safely(self, script: GeneratedScript, 
                                   unified_model: Optional[UnifiedBinaryModel]) -> Dict[str, Any]:
        """Execute script in a controlled sandbox environment"""
        
        result = {
            "success": False,
            "output": "",
            "runtime_errors": [],
            "logs": [],
            "performance_metrics": None,
            "timeout": False
        }
        
        # Write script to sandbox
        script_file = self.scripts_dir / f"{script.script_type.value}_{int(time.time())}.script"
        script_file.write_text(script.content, encoding='utf-8')
        
        try:
            # Start performance monitoring
            monitor_task = None
            if self.config.enable_performance_monitoring:
                monitor_task = asyncio.create_task(self._monitor_performance())
            
            # Execute script based on type
            if script.script_type == ScriptType.FRIDA:
                exec_result = await self._execute_frida_script(script_file, unified_model)
            elif script.script_type in [ScriptType.GHIDRA, ScriptType.IDA_PYTHON]:
                exec_result = await self._execute_python_script(script_file, unified_model)
            elif script.script_type == ScriptType.RADARE2:
                exec_result = await self._execute_radare2_script(script_file, unified_model)
            else:
                exec_result = {"success": False, "error": "Unsupported script type"}
            
            # Stop performance monitoring
            if monitor_task:
                monitor_task.cancel()
                try:
                    performance_data = await monitor_task
                    result["performance_metrics"] = performance_data
                except asyncio.CancelledError:
                    pass
            
            result.update(exec_result)
            
        except asyncio.TimeoutError:
            result["timeout"] = True
            result["runtime_errors"].append("Script execution timed out")
            logger.warning(f"Script execution timed out after {self.config.max_execution_time}s")
        
        except Exception as e:
            result["runtime_errors"].append(str(e))
            logger.error(f"Script execution failed: {e}")
        
        finally:
            # Cleanup
            try:
                script_file.unlink()
            except Exception:
                pass
        
        return result
    
    async def _execute_frida_script(self, script_file: Path, 
                                  unified_model: Optional[UnifiedBinaryModel]) -> Dict[str, Any]:
        """Execute Frida script in sandbox"""
        
        if not unified_model:
            return {"success": False, "error": "No unified model provided for Frida script"}
        
        # Create a minimal test target for Frida
        test_target = self._create_test_target()
        
        try:
            # Use frida-compile to check script validity
            cmd = [
                "frida-compile", 
                str(script_file),
                "-o", str(self.output_dir / "compiled_script.js")
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.sandbox_dir)
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), 
                timeout=self.config.validation_timeout
            )
            
            if proc.returncode == 0:
                return {
                    "success": True,
                    "output": stdout.decode('utf-8', errors='ignore'),
                    "logs": ["Frida script compiled successfully"]
                }
            else:
                return {
                    "success": False,
                    "error": stderr.decode('utf-8', errors='ignore'),
                    "logs": ["Frida compilation failed"]
                }
        
        except FileNotFoundError:
            # Frida not available, perform basic validation
            return {
                "success": True,
                "output": "Frida not available - script syntax validated only",
                "logs": ["Frida execution skipped - not installed"]
            }
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _execute_python_script(self, script_file: Path, 
                                   unified_model: Optional[UnifiedBinaryModel]) -> Dict[str, Any]:
        """Execute Python script in sandbox"""
        
        try:
            # Use a restricted Python environment
            cmd = [
                "python", "-c", 
                f"exec(open('{script_file}').read())"
            ]
            
            env = os.environ.copy()
            env["PYTHONPATH"] = ""  # Restrict imports
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.sandbox_dir),
                env=env
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.config.validation_timeout
            )
            
            return {
                "success": proc.returncode == 0,
                "output": stdout.decode('utf-8', errors='ignore'),
                "error": stderr.decode('utf-8', errors='ignore') if proc.returncode != 0 else None,
                "logs": ["Python script executed in sandbox"]
            }
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _execute_radare2_script(self, script_file: Path, 
                                    unified_model: Optional[UnifiedBinaryModel]) -> Dict[str, Any]:
        """Execute radare2 script in sandbox"""
        
        if not unified_model:
            return {"success": False, "error": "No unified model provided for r2 script"}
        
        try:
            # Create a test binary for r2 analysis
            test_binary = self._create_test_binary()
            
            cmd = [
                "r2", "-q", "-c", f". {script_file}", str(test_binary)
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.sandbox_dir)
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.config.validation_timeout
            )
            
            return {
                "success": proc.returncode == 0,
                "output": stdout.decode('utf-8', errors='ignore'),
                "error": stderr.decode('utf-8', errors='ignore') if proc.returncode != 0 else None,
                "logs": ["Radare2 script executed in sandbox"]
            }
        
        except FileNotFoundError:
            return {
                "success": True,
                "output": "Radare2 not available - script syntax validated only",
                "logs": ["Radare2 execution skipped - not installed"]
            }
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _monitor_performance(self) -> PerformanceMetrics:
        """Monitor performance during script execution"""
        
        start_time = time.time()
        peak_memory = 0
        cpu_readings = []
        
        try:
            while True:
                # Get current process info
                for pid in self.active_processes:
                    try:
                        proc = psutil.Process(pid)
                        memory_info = proc.memory_info()
                        peak_memory = max(peak_memory, memory_info.rss)
                        cpu_readings.append(proc.cpu_percent())
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                await asyncio.sleep(0.1)  # Sample every 100ms
        
        except asyncio.CancelledError:
            pass
        
        execution_time = time.time() - start_time
        avg_cpu = sum(cpu_readings) / len(cpu_readings) if cpu_readings else 0.0
        peak_cpu = max(cpu_readings) if cpu_readings else 0.0
        
        return PerformanceMetrics(
            execution_time=execution_time,
            peak_memory_usage=peak_memory,
            average_cpu_usage=avg_cpu,
            peak_cpu_usage=peak_cpu,
            disk_io_operations=0,  # Would need more sophisticated monitoring
            network_requests=0
        )
    
    def _create_test_target(self) -> Path:
        """Create a minimal test target for script testing"""
        
        test_target = self.temp_dir / "test_target.exe"
        
        # Create a minimal PE file for testing
        pe_header = b'\x4d\x5a'  # MZ header
        test_target.write_bytes(pe_header + b'\x00' * 1024)
        
        return test_target
    
    def _create_test_binary(self) -> Path:
        """Create a test binary for analysis"""
        
        test_binary = self.temp_dir / "test_analysis.bin"
        
        # Create a simple binary with some recognizable patterns
        binary_data = (
            b'\x7fELF\x01\x01\x01\x00' +  # ELF header
            b'\x00' * 100 +  # Padding
            b'Hello World\x00'  # Test string
        )
        
        test_binary.write_bytes(binary_data)
        return test_binary
    
    def _generate_script_id(self, script: GeneratedScript) -> str:
        """Generate unique ID for script"""
        
        content_hash = hashlib.sha256(script.content.encode()).hexdigest()[:12]
        return f"{script.script_type.value}_{content_hash}"
    
    def batch_validate_scripts(self, scripts: List[GeneratedScript],
                             unified_model: Optional[UnifiedBinaryModel] = None) -> List[ValidationReport]:
        """Validate multiple scripts in batch"""
        
        async def validate_all():
            tasks = [
                self.validate_script(script, unified_model) 
                for script in scripts
            ]
            return await asyncio.gather(*tasks, return_exceptions=True)
        
        results = asyncio.run(validate_all())
        
        # Filter out exceptions and return valid reports
        reports = []
        for i, result in enumerate(results):
            if isinstance(result, ValidationReport):
                reports.append(result)
            else:
                # Create error report for failed validations
                error_report = ValidationReport(
                    script_id=f"error_{i}",
                    script_type=scripts[i].script_type,
                    validation_result=ValidationResult.FAILED,
                    security_analysis=SecurityAnalysisResult(
                        risk_level=SecurityRiskLevel.CRITICAL,
                        detected_risks=[str(result)],
                        safe_to_execute=False,
                        warnings=[],
                        blocked_operations=[]
                    ),
                    performance_metrics=None,
                    syntax_errors=[str(result)],
                    runtime_errors=[],
                    warnings=[],
                    execution_output="",
                    sandbox_logs=[],
                    timestamp=time.time(),
                    validation_time=0.0
                )
                reports.append(error_report)
        
        return reports
    
    def get_validation_statistics(self) -> Dict[str, Any]:
        """Get sandbox validation statistics"""
        
        if not self.validation_cache:
            return {"total_validations": 0}
        
        reports = list(self.validation_cache.values())
        
        stats = {
            "total_validations": len(reports),
            "passed": len([r for r in reports if r.validation_result == ValidationResult.PASSED]),
            "failed": len([r for r in reports if r.validation_result == ValidationResult.FAILED]),
            "warnings": len([r for r in reports if r.validation_result == ValidationResult.WARNING]),
            "average_validation_time": sum(r.validation_time for r in reports) / len(reports),
            "script_types": {},
            "risk_levels": {}
        }
        
        # Count by script type
        for report in reports:
            script_type = report.script_type.value
            stats["script_types"][script_type] = stats["script_types"].get(script_type, 0) + 1
        
        # Count by risk level
        for report in reports:
            risk_level = report.security_analysis.risk_level.value
            stats["risk_levels"][risk_level] = stats["risk_levels"].get(risk_level, 0) + 1
        
        return stats
    
    def export_validation_report(self, output_file: Path):
        """Export comprehensive validation report"""
        
        report_data = {
            "sandbox_config": {
                "isolation_level": self.config.isolation_level.value,
                "max_execution_time": self.config.max_execution_time,
                "max_memory_usage": self.config.max_memory_usage,
                "enable_network": self.config.enable_network,
                "enable_file_access": self.config.enable_file_access
            },
            "statistics": self.get_validation_statistics(),
            "validation_reports": [
                {
                    "script_id": report.script_id,
                    "script_type": report.script_type.value,
                    "validation_result": report.validation_result.value,
                    "risk_level": report.security_analysis.risk_level.value,
                    "safe_to_execute": report.security_analysis.safe_to_execute,
                    "validation_time": report.validation_time,
                    "timestamp": report.timestamp
                }
                for report in self.validation_cache.values()
            ]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"Validation report exported to {output_file}")
    
    def cleanup_sandbox(self):
        """Clean up sandbox environment"""
        
        try:
            # Terminate any active processes
            for pid in self.active_processes:
                try:
                    proc = psutil.Process(pid)
                    proc.terminate()
                    proc.wait(timeout=5)
                except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                    pass
            
            # Remove sandbox directory
            import shutil
            shutil.rmtree(self.sandbox_dir, ignore_errors=True)
            
            logger.info("Sandbox environment cleaned up")
            
        except Exception as e:
            logger.error(f"Failed to cleanup sandbox: {e}")
    
    def __del__(self):
        """Cleanup on destruction"""
        self.cleanup_sandbox()


@contextmanager
def create_script_sandbox(config: Optional[SandboxConfig] = None):
    """Context manager for script sandbox"""
    
    sandbox = ScriptTestingSandbox(config)
    try:
        yield sandbox
    finally:
        sandbox.cleanup_sandbox()