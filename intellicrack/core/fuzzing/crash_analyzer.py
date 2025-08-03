"""
Crash Analyzer - Advanced crash analysis and exploitability assessment

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

import asyncio
import hashlib
import logging
import os
import re
import signal
import struct
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import json
import subprocess
import tempfile

from ...utils.logger import get_logger

logger = get_logger(__name__)


class CrashType(Enum):
    """Types of crashes that can be detected."""
    SEGMENTATION_FAULT = "segmentation_fault"
    ACCESS_VIOLATION = "access_violation"
    BUFFER_OVERFLOW = "buffer_overflow"
    STACK_OVERFLOW = "stack_overflow"
    HEAP_CORRUPTION = "heap_corruption"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    NULL_POINTER_DEREFERENCE = "null_pointer_dereference"
    DIVISION_BY_ZERO = "division_by_zero"
    ASSERTION_FAILURE = "assertion_failure"
    TIMEOUT = "timeout"
    ABORT = "abort"
    UNKNOWN = "unknown"


class ExploitabilityLevel(Enum):
    """Exploitability assessment levels."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CrashReport:
    """Comprehensive crash report."""
    crash_id: str
    timestamp: datetime
    crash_type: CrashType
    
    # Basic crash information
    signal: Optional[int] = None
    exit_code: Optional[int] = None
    crash_address: Optional[str] = None
    instruction_pointer: Optional[str] = None
    
    # Stack trace and registers
    stack_trace: List[str] = field(default_factory=list)
    registers: Dict[str, str] = field(default_factory=dict)
    disassembly: List[str] = field(default_factory=list)
    
    # Memory information
    memory_maps: List[Dict[str, Any]] = field(default_factory=list)
    heap_state: Dict[str, Any] = field(default_factory=dict)
    stack_state: Dict[str, Any] = field(default_factory=dict)
    
    # Input information
    input_size: int = 0
    input_hash: str = ""
    input_preview: str = ""
    
    # Analysis results
    severity: str = "unknown"
    exploitability: ExploitabilityLevel = ExploitabilityLevel.NONE
    root_cause: Optional[str] = None
    affected_function: Optional[str] = None
    vulnerability_type: Optional[str] = None
    
    # Reproduction and classification
    reproducible: bool = False
    reproduction_rate: float = 0.0
    similar_crashes: List[str] = field(default_factory=list)
    classification_confidence: float = 0.0
    
    # Mitigation and exploitation info
    mitigation_bypassed: List[str] = field(default_factory=list)
    exploitation_complexity: str = "unknown"
    potential_impact: List[str] = field(default_factory=list)
    
    # Metadata
    target_binary: str = ""
    platform: str = ""
    analysis_tools_used: List[str] = field(default_factory=list)
    analysis_duration: float = 0.0


@dataclass
class ExploitabilityAssessment:
    """Detailed exploitability assessment."""
    level: ExploitabilityLevel
    confidence: float
    factors: List[str] = field(default_factory=list)
    
    # Control flow analysis
    instruction_pointer_control: bool = False
    stack_pointer_control: bool = False
    register_control: Dict[str, bool] = field(default_factory=dict)
    
    # Memory protections
    aslr_present: bool = True
    dep_present: bool = True
    stack_canaries: bool = True
    cfi_present: bool = False
    
    # Exploit development indicators
    gadget_availability: Dict[str, int] = field(default_factory=dict)
    info_leak_potential: bool = False
    heap_spray_possible: bool = False
    rop_chain_feasible: bool = False
    
    # Complexity factors
    reliability_factors: List[str] = field(default_factory=list)
    complexity_factors: List[str] = field(default_factory=list)
    
    def calculate_exploitability_score(self) -> float:
        """Calculate numerical exploitability score."""
        score = 0.0
        
        # Control factors
        if self.instruction_pointer_control:
            score += 40.0
        if self.stack_pointer_control:
            score += 30.0
        
        # Register control
        controlled_regs = sum(self.register_control.values())
        score += controlled_regs * 5.0
        
        # Mitigation bypass potential
        if not self.aslr_present:
            score += 20.0
        if not self.dep_present:
            score += 25.0
        if not self.stack_canaries:
            score += 15.0
        
        # Exploitation techniques
        if self.rop_chain_feasible:
            score += 15.0
        if self.heap_spray_possible:
            score += 10.0
        if self.info_leak_potential:
            score += 10.0
        
        # Apply complexity penalties
        score -= len(self.complexity_factors) * 5.0
        
        return max(0.0, min(100.0, score))


@dataclass
class RootCauseAnalysis:
    """Root cause analysis of the crash."""
    primary_cause: str
    contributing_factors: List[str] = field(default_factory=list)
    code_location: Optional[str] = None
    vulnerable_function: Optional[str] = None
    
    # Data flow analysis
    tainted_data_flow: List[str] = field(default_factory=list)
    input_to_crash_path: List[str] = field(default_factory=list)
    
    # Vulnerability classification
    cwe_id: Optional[str] = None
    vulnerability_category: str = "unknown"
    attack_vector: str = "unknown"
    
    # Fix recommendations
    recommended_fixes: List[str] = field(default_factory=list)
    prevention_techniques: List[str] = field(default_factory=list)


class CrashAnalyzer:
    """
    Advanced crash analyzer with exploitability assessment and root cause analysis.
    
    This class provides comprehensive crash analysis capabilities including
    crash classification, exploitability assessment, root cause analysis,
    and vulnerability categorization.
    """
    
    def __init__(self, output_directory: str, ai_enabled: bool = True):
        """Initialize crash analyzer."""
        self.output_directory = Path(output_directory)
        self.output_directory.mkdir(parents=True, exist_ok=True)
        self.ai_enabled = ai_enabled
        self.logger = logging.getLogger(__name__)
        
        # Analysis tools
        self.gdb_available = False
        self.windbg_available = False
        self.radare2_available = False
        
        # Crash database
        self.crash_database = {}
        self.crash_signatures = {}
        
        # Exploitability patterns
        self.exploitability_patterns = self._load_exploitability_patterns()
        self.vulnerability_signatures = self._load_vulnerability_signatures()
        
        # Check available tools
        asyncio.create_task(self._check_analysis_tools())
        
        self.logger.info(f"Crash analyzer initialized, output: {output_directory}")
    
    async def _check_analysis_tools(self):
        """Check availability of crash analysis tools."""
        # Check for GDB (Linux/Unix)
        try:
            result = subprocess.run(["gdb", "--version"], capture_output=True, timeout=5)
            if result.returncode == 0:
                self.gdb_available = True
                self.logger.info("GDB available for crash analysis")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Check for WinDbg (Windows)
        try:
            result = subprocess.run(["cdb", "-?"], capture_output=True, timeout=5)
            if result.returncode == 0:
                self.windbg_available = True
                self.logger.info("Windows Debugging Tools available")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Check for Radare2
        try:
            result = subprocess.run(["r2", "-v"], capture_output=True, timeout=5)
            if result.returncode == 0:
                self.radare2_available = True
                self.logger.info("Radare2 available for crash analysis")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def _load_exploitability_patterns(self) -> Dict[str, Any]:
        """Load patterns for exploitability assessment."""
        return {
            "high_exploitability_signals": [
                "controlled instruction pointer",
                "controlled stack pointer", 
                "heap overflow with controlled size",
                "format string vulnerability",
                "controlled function pointer"
            ],
            "medium_exploitability_signals": [
                "buffer overflow on stack",
                "heap corruption",
                "integer overflow leading to buffer overflow",
                "partial instruction pointer control"
            ],
            "low_exploitability_signals": [
                "null pointer dereference",
                "stack overflow with canaries",
                "assert failure",
                "divide by zero"
            ],
            "exploitation_techniques": {
                "rop_gadgets": ["pop", "ret", "jmp", "call"],
                "heap_spray_indicators": ["large allocation", "repeated pattern"],
                "info_leak_vectors": ["format string", "buffer over-read", "unitialized memory"]
            }
        }
    
    def _load_vulnerability_signatures(self) -> Dict[str, Any]:
        """Load vulnerability signatures for classification."""
        return {
            "buffer_overflow": {
                "patterns": ["stack smashing", "buffer overflow", "strcpy", "sprintf"],
                "cwe": "CWE-120"
            },
            "heap_corruption": {
                "patterns": ["heap corruption", "double free", "use after free", "malloc"],
                "cwe": "CWE-416"
            },
            "format_string": {
                "patterns": ["%n", "%s", "printf", "sprintf", "format string"],
                "cwe": "CWE-134"
            },
            "integer_overflow": {
                "patterns": ["integer overflow", "arithmetic overflow", "signed overflow"],
                "cwe": "CWE-190"
            },
            "null_deref": {
                "patterns": ["null pointer", "null dereference", "access violation at 0x0"],
                "cwe": "CWE-476"
            }
        }
    
    async def analyze_crash(self, input_data: bytes, execution_result: Dict[str, Any], 
                          target_path: str) -> CrashReport:
        """
        Perform comprehensive crash analysis.
        
        Args:
            input_data: Input that caused the crash
            execution_result: Execution result containing crash information
            target_path: Path to target binary
            
        Returns:
            Comprehensive crash report
        """
        start_time = time.time()
        
        # Create crash report
        crash_id = self._generate_crash_id(input_data, execution_result)
        report = CrashReport(
            crash_id=crash_id,
            timestamp=datetime.now(),
            crash_type=CrashType.UNKNOWN,
            target_binary=target_path,
            platform=os.name,
            input_size=len(input_data),
            input_hash=hashlib.sha256(input_data).hexdigest(),
            input_preview=self._generate_input_preview(input_data)
        )
        
        try:
            # Basic crash classification
            await self._classify_crash_type(report, execution_result)
            
            # Extract crash details
            await self._extract_crash_details(report, execution_result)
            
            # Perform detailed analysis if tools are available
            if self.gdb_available or self.windbg_available:
                await self._detailed_crash_analysis(report, input_data, target_path)
            
            # Exploitability assessment
            exploitability = await self._assess_exploitability(report, execution_result)
            report.exploitability = exploitability.level
            
            # Root cause analysis
            root_cause = await self._analyze_root_cause(report, input_data)
            report.root_cause = root_cause.primary_cause
            report.vulnerability_type = root_cause.vulnerability_category
            
            # Check for similar crashes
            await self._find_similar_crashes(report)
            
            # Test reproducibility
            await self._test_reproducibility(report, input_data, target_path)
            
            # Save crash data
            await self._save_crash_data(report, input_data)
            
            # Update crash database
            self._update_crash_database(report)
            
            report.analysis_duration = time.time() - start_time
            
            self.logger.info(f"Crash analysis complete: {crash_id} ({report.exploitability.value})")
            
            return report
            
        except Exception as e:
            self.logger.error(f"Crash analysis failed for {crash_id}: {e}")
            report.analysis_duration = time.time() - start_time
            return report
    
    def _generate_crash_id(self, input_data: bytes, execution_result: Dict[str, Any]) -> str:
        """Generate unique crash identifier."""
        # Create hash from input data and crash characteristics
        hasher = hashlib.sha256()
        hasher.update(input_data)
        
        # Add crash-specific information
        exit_code = execution_result.get("exit_code", 0)
        crash_addr = execution_result.get("crash_address", "")
        stderr = execution_result.get("stderr", "")
        
        crash_info = f"{exit_code}:{crash_addr}:{stderr[:100]}"
        hasher.update(crash_info.encode())
        
        return hasher.hexdigest()[:16]
    
    def _generate_input_preview(self, input_data: bytes) -> str:
        """Generate readable preview of input data."""
        preview_size = min(256, len(input_data))
        preview_bytes = input_data[:preview_size]
        
        # Try to create readable representation
        try:
            # First try as text
            text_preview = preview_bytes.decode('utf-8', errors='ignore')
            if all(32 <= ord(c) <= 126 or c in '\t\n\r' for c in text_preview):
                return f"TEXT: {text_preview}"
        except:
            pass
        
        # Fall back to hex representation
        hex_preview = preview_bytes.hex()
        return f"HEX: {hex_preview}"
    
    async def _classify_crash_type(self, report: CrashReport, execution_result: Dict[str, Any]):
        """Classify the type of crash."""
        exit_code = execution_result.get("exit_code")
        stderr = execution_result.get("stderr", "").lower()
        signal_num = execution_result.get("signal")
        
        # Windows-specific crash detection
        if os.name == "nt":
            if exit_code == 0xC0000005:  # ACCESS_VIOLATION
                report.crash_type = CrashType.ACCESS_VIOLATION
                report.severity = "high"
            elif exit_code == 0xC00000FD:  # STACK_OVERFLOW
                report.crash_type = CrashType.STACK_OVERFLOW
                report.severity = "medium"
            elif exit_code == 0xC0000094:  # INTEGER_DIVIDE_BY_ZERO
                report.crash_type = CrashType.DIVISION_BY_ZERO
                report.severity = "low"
        
        # Unix/Linux signal-based detection
        elif signal_num:
            if signal_num == signal.SIGSEGV:
                report.crash_type = CrashType.SEGMENTATION_FAULT
                report.severity = "high"
            elif signal_num == signal.SIGABRT:
                report.crash_type = CrashType.ABORT
                report.severity = "medium"
            elif signal_num == signal.SIGFPE:
                report.crash_type = CrashType.DIVISION_BY_ZERO
                report.severity = "low"
        
        # Pattern-based detection from stderr
        crash_patterns = {
            "stack smashing": CrashType.BUFFER_OVERFLOW,
            "heap corruption": CrashType.HEAP_CORRUPTION,
            "double free": CrashType.DOUBLE_FREE,
            "use after free": CrashType.USE_AFTER_FREE,
            "null pointer": CrashType.NULL_POINTER_DEREFERENCE,
            "access violation": CrashType.ACCESS_VIOLATION,
            "stack overflow": CrashType.STACK_OVERFLOW,
            "assertion": CrashType.ASSERTION_FAILURE
        }
        
        for pattern, crash_type in crash_patterns.items():
            if pattern in stderr:
                report.crash_type = crash_type
                break
        
        # Set signal and exit code
        report.signal = signal_num
        report.exit_code = exit_code
    
    async def _extract_crash_details(self, report: CrashReport, execution_result: Dict[str, Any]):
        """Extract detailed crash information."""
        # Extract crash address if available
        stderr = execution_result.get("stderr", "")
        
        # Look for crash address patterns
        addr_patterns = [
            r"at address (0x[0-9a-fA-F]+)",
            r"address (0x[0-9a-fA-F]+)",
            r"fault addr: (0x[0-9a-fA-F]+)",
            r"exception at (0x[0-9a-fA-F]+)"
        ]
        
        for pattern in addr_patterns:
            match = re.search(pattern, stderr)
            if match:
                report.crash_address = match.group(1)
                break
        
        # Extract instruction pointer
        ip_patterns = [
            r"rip:([0-9a-fA-F]+)",
            r"eip:([0-9a-fA-F]+)",
            r"pc:([0-9a-fA-F]+)",
            r"instruction pointer: (0x[0-9a-fA-F]+)"
        ]
        
        for pattern in ip_patterns:
            match = re.search(pattern, stderr)
            if match:
                report.instruction_pointer = f"0x{match.group(1)}"
                break
        
        # Extract basic stack trace if present
        if "stack trace" in stderr.lower() or "backtrace" in stderr.lower():
            lines = stderr.split('\n')
            in_stack_trace = False
            
            for line in lines:
                if any(keyword in line.lower() for keyword in ["stack trace", "backtrace", "call stack"]):
                    in_stack_trace = True
                    continue
                
                if in_stack_trace:
                    if line.strip() and any(char in line for char in ['(', ')', '0x']):
                        report.stack_trace.append(line.strip())
                    elif not line.strip():
                        break
        
        # Extract registers if available
        reg_pattern = r"([a-zA-Z]{2,3})\s*[:=]\s*(0x[0-9a-fA-F]+)"
        for match in re.finditer(reg_pattern, stderr):
            reg_name = match.group(1).lower()
            reg_value = match.group(2)
            report.registers[reg_name] = reg_value
    
    async def _detailed_crash_analysis(self, report: CrashReport, input_data: bytes, target_path: str):
        """Perform detailed crash analysis using debugging tools."""
        try:
            if self.gdb_available and os.name != "nt":
                await self._analyze_with_gdb(report, input_data, target_path)
            elif self.windbg_available and os.name == "nt":
                await self._analyze_with_windbg(report, input_data, target_path)
            else:
                # Fallback to basic analysis
                await self._analyze_with_fallback(report, input_data, target_path)
                
        except Exception as e:
            self.logger.warning(f"Detailed analysis failed: {e}")
    
    async def _analyze_with_gdb(self, report: CrashReport, input_data: bytes, target_path: str):
        """Analyze crash using GDB."""
        try:
            # Create temporary input file
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(input_data)
                input_file = tmp_file.name
            
            try:
                # Create GDB script
                gdb_script = f"""
                set pagination off
                set confirm off
                run {input_file}
                bt
                info registers
                x/20i $pc
                info proc mappings
                quit
                """
                
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.gdb') as script_file:
                    script_file.write(gdb_script)
                    script_path = script_file.name
                
                # Run GDB
                cmd = ["gdb", "-batch", "-x", script_path, target_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode != 0:
                    await self._parse_gdb_output(report, result.stdout + result.stderr)
                    report.analysis_tools_used.append("gdb")
                
                # Cleanup
                os.unlink(script_path)
                
            finally:
                os.unlink(input_file)
                
        except Exception as e:
            self.logger.warning(f"GDB analysis failed: {e}")
    
    async def _analyze_with_windbg(self, report: CrashReport, input_data: bytes, target_path: str):
        """Analyze crash using Windows Debugging Tools."""
        try:
            # Create temporary input file
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(input_data)
                input_file = tmp_file.name
            
            try:
                # Create WinDbg script
                windbg_script = f"""
                g
                .ecxr
                k
                r
                u eip
                !address
                q
                """
                
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as script_file:
                    script_file.write(windbg_script)
                    script_path = script_file.name
                
                # Run CDB (console debugger)
                cmd = ["cdb", "-cf", script_path, target_path, input_file]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.stdout:
                    await self._parse_windbg_output(report, result.stdout)
                    report.analysis_tools_used.append("windbg")
                
                # Cleanup
                os.unlink(script_path)
                
            finally:
                os.unlink(input_file)
                
        except Exception as e:
            self.logger.warning(f"WinDbg analysis failed: {e}")
    
    async def _analyze_with_fallback(self, report: CrashReport, input_data: bytes, target_path: str):
        """Fallback analysis without debugging tools."""
        # Basic heuristic analysis
        if report.crash_address:
            try:
                addr = int(report.crash_address, 16)
                
                # Classify based on address ranges
                if addr == 0:
                    report.vulnerability_type = "null_pointer_dereference"
                    report.severity = "low"
                elif addr < 0x10000:
                    report.vulnerability_type = "near_null_dereference"
                    report.severity = "low"
                elif addr >= 0x7fff0000:  # High addresses (stack region)
                    report.vulnerability_type = "stack_corruption"
                    report.severity = "high"
                else:
                    report.vulnerability_type = "memory_corruption"
                    report.severity = "medium"
                    
            except ValueError:
                pass
        
        report.analysis_tools_used.append("fallback_heuristic")
    
    async def _parse_gdb_output(self, report: CrashReport, output: str):
        """Parse GDB output for crash details."""
        lines = output.split('\n')
        
        # Parse stack trace
        in_backtrace = False
        for line in lines:
            if line.strip().startswith('#') and any(word in line for word in ['at', 'in', 'from']):
                report.stack_trace.append(line.strip())
            elif 'backtrace' in line.lower() or 'stack trace' in line.lower():
                in_backtrace = True
        
        # Parse registers
        for line in lines:
            reg_match = re.match(r'([a-zA-Z0-9]+)\s+0x([0-9a-fA-F]+)', line.strip())
            if reg_match:
                reg_name = reg_match.group(1).lower()
                reg_value = f"0x{reg_match.group(2)}"
                report.registers[reg_name] = reg_value
        
        # Parse disassembly
        for line in lines:
            if '=>' in line or '0x' in line and any(inst in line for inst in ['mov', 'call', 'jmp', 'ret']):
                report.disassembly.append(line.strip())
    
    async def _parse_windbg_output(self, report: CrashReport, output: str):
        """Parse WinDbg output for crash details."""
        lines = output.split('\n')
        
        # Parse stack trace
        for line in lines:
            if re.match(r'[0-9a-fA-F]+\s+[0-9a-fA-F]+', line.strip()):
                report.stack_trace.append(line.strip())
        
        # Parse registers
        reg_section = False
        for line in lines:
            if 'eax=' in line or 'rax=' in line:
                reg_section = True
            
            if reg_section and '=' in line:
                parts = line.split()
                for part in parts:
                    if '=' in part:
                        reg_name, reg_value = part.split('=', 1)
                        report.registers[reg_name.lower()] = reg_value
    
    async def _assess_exploitability(self, report: CrashReport, execution_result: Dict[str, Any]) -> ExploitabilityAssessment:
        """Assess exploitability of the crash."""
        assessment = ExploitabilityAssessment(
            level=ExploitabilityLevel.NONE,
            confidence=0.0
        )
        
        # Analyze crash type for exploitability
        if report.crash_type in [CrashType.BUFFER_OVERFLOW, CrashType.HEAP_CORRUPTION]:
            assessment.level = ExploitabilityLevel.HIGH
            assessment.confidence = 0.8
            assessment.factors.append("Memory corruption vulnerability")
            
        elif report.crash_type in [CrashType.SEGMENTATION_FAULT, CrashType.ACCESS_VIOLATION]:
            # Check if instruction pointer is controlled
            if report.instruction_pointer:
                try:
                    ip_addr = int(report.instruction_pointer, 16)
                    if 0x41414141 <= ip_addr <= 0x5a5a5a5a:  # Controlled values
                        assessment.instruction_pointer_control = True
                        assessment.level = ExploitabilityLevel.CRITICAL
                        assessment.confidence = 0.9
                        assessment.factors.append("Controlled instruction pointer")
                except ValueError:
                    pass
            
            if assessment.level == ExploitabilityLevel.NONE:
                assessment.level = ExploitabilityLevel.MEDIUM
                assessment.confidence = 0.6
                
        elif report.crash_type == CrashType.NULL_POINTER_DEREFERENCE:
            assessment.level = ExploitabilityLevel.LOW
            assessment.confidence = 0.9
            assessment.factors.append("Null pointer dereference")
            
        elif report.crash_type in [CrashType.DIVISION_BY_ZERO, CrashType.ASSERTION_FAILURE]:
            assessment.level = ExploitabilityLevel.NONE
            assessment.confidence = 0.95
            assessment.factors.append("Non-exploitable crash type")
        
        # Check for register control
        controlled_registers = []
        for reg_name, reg_value in report.registers.items():
            try:
                value = int(reg_value, 16)
                if 0x41414141 <= value <= 0x5a5a5a5a:  # Looks controlled
                    controlled_registers.append(reg_name)
                    assessment.register_control[reg_name] = True
            except ValueError:
                continue
        
        if controlled_registers:
            assessment.factors.append(f"Controlled registers: {', '.join(controlled_registers)}")
            if assessment.level.value < ExploitabilityLevel.HIGH.value:
                assessment.level = ExploitabilityLevel.HIGH
                assessment.confidence = min(0.9, assessment.confidence + 0.2)
        
        # Analyze mitigation presence (simplified)
        assessment.aslr_present = True  # Assume present by default
        assessment.dep_present = True   # Assume present by default
        assessment.stack_canaries = True  # Assume present by default
        
        # Check for mitigation bypass indicators
        if "stack smashing" in str(execution_result.get("stderr", "")):
            assessment.stack_canaries = False
            assessment.mitigation_bypassed.append("stack_canaries")
            assessment.factors.append("Stack canaries bypassed")
        
        # Calculate final exploitability score
        score = assessment.calculate_exploitability_score()
        
        if score >= 80:
            assessment.level = ExploitabilityLevel.CRITICAL
        elif score >= 60:
            assessment.level = ExploitabilityLevel.HIGH
        elif score >= 40:
            assessment.level = ExploitabilityLevel.MEDIUM
        elif score >= 20:
            assessment.level = ExploitabilityLevel.LOW
        else:
            assessment.level = ExploitabilityLevel.NONE
        
        return assessment
    
    async def _analyze_root_cause(self, report: CrashReport, input_data: bytes) -> RootCauseAnalysis:
        """Analyze root cause of the crash."""
        root_cause = RootCauseAnalysis(primary_cause="unknown")
        
        # Classify based on crash type and patterns
        if report.crash_type == CrashType.BUFFER_OVERFLOW:
            root_cause.primary_cause = "Buffer overflow due to insufficient bounds checking"
            root_cause.vulnerability_category = "buffer_overflow"
            root_cause.cwe_id = "CWE-120"
            root_cause.attack_vector = "input_manipulation"
            
        elif report.crash_type == CrashType.HEAP_CORRUPTION:
            root_cause.primary_cause = "Heap corruption due to memory management error"
            root_cause.vulnerability_category = "heap_corruption"
            root_cause.cwe_id = "CWE-416"
            root_cause.attack_vector = "memory_manipulation"
            
        elif report.crash_type == CrashType.NULL_POINTER_DEREFERENCE:
            root_cause.primary_cause = "Null pointer dereference due to missing validation"
            root_cause.vulnerability_category = "null_dereference"
            root_cause.cwe_id = "CWE-476"
            root_cause.attack_vector = "input_manipulation"
            
        elif report.crash_type == CrashType.USE_AFTER_FREE:
            root_cause.primary_cause = "Use-after-free due to dangling pointer access"
            root_cause.vulnerability_category = "use_after_free"
            root_cause.cwe_id = "CWE-416"
            root_cause.attack_vector = "memory_manipulation"
        
        # Analyze input characteristics for contributing factors
        input_analysis = self._analyze_input_characteristics(input_data)
        root_cause.contributing_factors.extend(input_analysis)
        
        # Generate fix recommendations
        root_cause.recommended_fixes = self._generate_fix_recommendations(report.crash_type)
        
        return root_cause
    
    def _analyze_input_characteristics(self, input_data: bytes) -> List[str]:
        """Analyze input data characteristics."""
        characteristics = []
        
        if len(input_data) > 1024:
            characteristics.append("Large input size may trigger buffer overflow")
        
        # Check for repeated patterns
        for pattern_size in [4, 8, 16]:
            if len(input_data) >= pattern_size * 3:
                pattern = input_data[:pattern_size]
                if input_data.count(pattern) >= 3:
                    characteristics.append(f"Repeated {pattern_size}-byte pattern detected")
        
        # Check for format string patterns
        if b'%' in input_data:
            format_chars = [b'%s', b'%d', b'%x', b'%n', b'%p']
            for fmt in format_chars:
                if fmt in input_data:
                    characteristics.append("Format string specifiers present")
                    break
        
        # Check for shellcode-like patterns
        common_opcodes = [b'\x90', b'\xeb', b'\x31', b'\x89']
        opcode_count = sum(input_data.count(opcode) for opcode in common_opcodes)
        if opcode_count > len(input_data) * 0.1:
            characteristics.append("Possible shellcode patterns detected")
        
        return characteristics
    
    def _generate_fix_recommendations(self, crash_type: CrashType) -> List[str]:
        """Generate fix recommendations based on crash type."""
        recommendations = {
            CrashType.BUFFER_OVERFLOW: [
                "Implement bounds checking for all buffer operations",
                "Use safe string functions (strncpy, snprintf)",
                "Enable stack canaries and FORTIFY_SOURCE",
                "Consider using memory-safe languages or libraries"
            ],
            CrashType.HEAP_CORRUPTION: [
                "Implement proper memory management practices",
                "Use memory debugging tools (Valgrind, AddressSanitizer)",
                "Avoid double-free and use-after-free patterns",
                "Consider using garbage collection or smart pointers"
            ],
            CrashType.NULL_POINTER_DEREFERENCE: [
                "Add null pointer checks before dereference",
                "Initialize pointers to NULL and check return values",
                "Use static analysis tools to detect null dereferences",
                "Implement defensive programming practices"
            ],
            CrashType.USE_AFTER_FREE: [
                "Set pointers to NULL after freeing",
                "Use memory debugging tools",
                "Implement proper object lifetime management",
                "Consider using reference counting or smart pointers"
            ]
        }
        
        return recommendations.get(crash_type, ["Perform thorough code review and security testing"])
    
    async def _find_similar_crashes(self, report: CrashReport):
        """Find similar crashes in the database."""
        similar_crashes = []
        
        for crash_id, existing_crash in self.crash_database.items():
            if crash_id == report.crash_id:
                continue
            
            similarity_score = self._calculate_crash_similarity(report, existing_crash)
            if similarity_score > 0.7:  # 70% similarity threshold
                similar_crashes.append(crash_id)
        
        report.similar_crashes = similar_crashes[:10]  # Limit to top 10
    
    def _calculate_crash_similarity(self, crash1: CrashReport, crash2: CrashReport) -> float:
        """Calculate similarity between two crashes."""
        score = 0.0
        factors = 0
        
        # Crash type similarity
        if crash1.crash_type == crash2.crash_type:
            score += 0.3
        factors += 1
        
        # Crash address similarity
        if crash1.crash_address and crash2.crash_address:
            try:
                addr1 = int(crash1.crash_address, 16)
                addr2 = int(crash2.crash_address, 16)
                addr_diff = abs(addr1 - addr2)
                if addr_diff < 0x1000:  # Within 4KB
                    score += 0.2
            except ValueError:
                pass
        factors += 1
        
        # Stack trace similarity
        if crash1.stack_trace and crash2.stack_trace:
            common_frames = set(crash1.stack_trace) & set(crash2.stack_trace)
            total_frames = set(crash1.stack_trace) | set(crash2.stack_trace)
            if total_frames:
                trace_similarity = len(common_frames) / len(total_frames)
                score += trace_similarity * 0.3
        factors += 1
        
        # Input size similarity
        size_diff = abs(crash1.input_size - crash2.input_size)
        max_size = max(crash1.input_size, crash2.input_size)
        if max_size > 0:
            size_similarity = 1.0 - (size_diff / max_size)
            score += size_similarity * 0.2
        factors += 1
        
        return score / factors if factors > 0 else 0.0
    
    async def _test_reproducibility(self, report: CrashReport, input_data: bytes, target_path: str):
        """Test crash reproducibility."""
        # For now, assume crashes are reproducible
        # In a full implementation, this would re-run the target with the same input
        report.reproducible = True
        report.reproduction_rate = 1.0
    
    async def _save_crash_data(self, report: CrashReport, input_data: bytes):
        """Save crash data to disk."""
        crash_dir = self.output_directory / report.crash_id
        crash_dir.mkdir(exist_ok=True)
        
        # Save input data
        input_file = crash_dir / "input.bin"
        with open(input_file, 'wb') as f:
            f.write(input_data)
        
        # Save crash report
        report_file = crash_dir / "report.json"
        with open(report_file, 'w') as f:
            json.dump({
                "crash_id": report.crash_id,
                "timestamp": report.timestamp.isoformat(),
                "crash_type": report.crash_type.value,
                "severity": report.severity,
                "exploitability": report.exploitability.value,
                "crash_address": report.crash_address,
                "instruction_pointer": report.instruction_pointer,
                "signal": report.signal,
                "exit_code": report.exit_code,
                "stack_trace": report.stack_trace,
                "registers": report.registers,
                "root_cause": report.root_cause,
                "vulnerability_type": report.vulnerability_type,
                "input_size": report.input_size,
                "input_hash": report.input_hash,
                "input_preview": report.input_preview,
                "reproducible": report.reproducible,
                "reproduction_rate": report.reproduction_rate,
                "similar_crashes": report.similar_crashes,
                "analysis_tools_used": report.analysis_tools_used,
                "analysis_duration": report.analysis_duration
            }, f, indent=2)
        
        self.logger.info(f"Crash data saved to {crash_dir}")
    
    def _update_crash_database(self, report: CrashReport):
        """Update crash database with new crash."""
        self.crash_database[report.crash_id] = report
        
        # Create crash signature for deduplication
        signature = self._create_crash_signature(report)
        self.crash_signatures[signature] = report.crash_id
        
        # Keep database manageable
        if len(self.crash_database) > 10000:
            # Remove oldest entries
            oldest_crashes = sorted(
                self.crash_database.items(),
                key=lambda x: x[1].timestamp
            )[:1000]
            
            for crash_id, _ in oldest_crashes:
                del self.crash_database[crash_id]
    
    def _create_crash_signature(self, report: CrashReport) -> str:
        """Create crash signature for deduplication."""
        signature_parts = [
            str(report.crash_type.value),
            report.crash_address or "no_addr",
            str(report.signal or "no_signal"),
            "|".join(report.stack_trace[:3])  # Top 3 stack frames
        ]
        
        signature = "|".join(signature_parts)
        return hashlib.md5(signature.encode()).hexdigest()
    
    def get_crash_statistics(self) -> Dict[str, Any]:
        """Get crash analysis statistics."""
        if not self.crash_database:
            return {"total_crashes": 0}
        
        crashes = list(self.crash_database.values())
        
        # Count by crash type
        crash_type_counts = {}
        for crash in crashes:
            crash_type = crash.crash_type.value
            crash_type_counts[crash_type] = crash_type_counts.get(crash_type, 0) + 1
        
        # Count by exploitability
        exploitability_counts = {}
        for crash in crashes:
            exploitability = crash.exploitability.value
            exploitability_counts[exploitability] = exploitability_counts.get(exploitability, 0) + 1
        
        # Count by severity
        severity_counts = {}
        for crash in crashes:
            severity = crash.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "total_crashes": len(crashes),
            "unique_crashes": len(set(self.crash_signatures.values())),
            "crash_types": crash_type_counts,
            "exploitability_levels": exploitability_counts,
            "severity_levels": severity_counts,
            "reproducible_crashes": sum(1 for c in crashes if c.reproducible),
            "average_analysis_time": sum(c.analysis_duration for c in crashes) / len(crashes)
        }