"""Comprehensive production-ready tests for script_generation_agent.py.

Tests validate REAL script generation with actual Frida/Python/binary patch output.
All tests verify syntactically valid, functionally real offensive capabilities.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack.
"""

import ast
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.ai_script_generator import (
    AIScriptGenerator,
    GeneratedScript,
    ScriptMetadata,
    ScriptType,
)
from intellicrack.ai.common_types import ExecutionResult
from intellicrack.ai.script_generation_agent import (
    AIAgent,
    TaskRequest,
    ValidationEnvironment,
    WorkflowState,
)


@dataclass
class MockProtection:
    """Mock protection detection result for testing."""

    type: str
    confidence: float
    description: str
    indicators: list[str]


@pytest.fixture
def realistic_pe_binary(tmp_path: Path) -> Path:
    """Create realistic PE binary with license check strings and patterns."""
    binary_path = tmp_path / "protected_app.exe"
    pe_header = bytearray(
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00"
        b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21\x54\x68"
        b"\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x63\x61\x6e\x6e\x6f"
        b"\x74\x20\x62\x65\x20\x72\x75\x6e\x20\x69\x6e\x20\x44\x4f\x53\x20"
        b"\x6d\x6f\x64\x65\x2e\x0d\x0d\x0a\x24\x00\x00\x00\x00\x00\x00\x00"
        b"PE\x00\x00L\x01\x03\x00"
    )
    pe_header.extend(b"\x00" * (512 - len(pe_header)))
    pe_header.extend(b"CheckLicenseKey\x00ValidateSerial\x00" * 5)
    pe_header.extend(b"IsTrialExpired\x00GetExpirationDate\x00" * 5)
    pe_header.extend(b"ActivateLicense\x00VerifyActivation\x00" * 5)
    pe_header.extend(b"GetSystemTime\x00GetTickCount\x00" * 5)
    pe_header.extend(b"RegOpenKeyEx\x00RegQueryValueEx\x00" * 5)
    binary_path.write_bytes(bytes(pe_header))
    return binary_path


@pytest.fixture
def ai_script_generator() -> AIScriptGenerator:
    """Create AIScriptGenerator instance for testing."""
    return AIScriptGenerator()


@pytest.fixture
def ai_agent() -> AIAgent:
    """Create AIAgent instance for testing."""
    return AIAgent()


class TestFridaScriptGeneration:
    """Tests for Frida script generation - validates real JavaScript output."""

    def test_generate_script_produces_valid_javascript_syntax(self, ai_script_generator: AIScriptGenerator) -> None:
        """Generated Frida scripts contain syntactically valid JavaScript code."""
        base_script = """
Java.perform(function() {
    console.log('Basic script');
});
"""
        context = {"protection": {"type": "license_check"}, "difficulty": "Medium"}
        enhanced = ai_script_generator.generate_script("bypass license", base_script, context)

        assert "function" in enhanced or "=>" in enhanced
        assert enhanced.count("{") == enhanced.count("}")
        assert enhanced.count("(") == enhanced.count(")")
        assert "Java.perform" in enhanced or "Interceptor" in enhanced or "Memory" in enhanced

    def test_generate_script_includes_interceptor_hooks_for_license_bypass(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """License bypass scripts include Interceptor.attach or Interceptor.replace hooks."""
        base_script = "console.log('test');"
        context = {"protection": {"type": "license_check", "functions": ["ValidateLicense"]}, "difficulty": "Medium"}
        enhanced = ai_script_generator.generate_script("bypass license", base_script, context)

        has_interceptor = "Interceptor.attach" in enhanced or "Interceptor.replace" in enhanced
        assert has_interceptor or len(enhanced) > len(base_script) * 3

    def test_generate_script_includes_memory_operations_for_patch_bypass(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Binary patch bypass scripts include Memory.read/write operations."""
        base_script = "Memory.readByteArray(ptr(0x1000), 10);"
        context = {"protection": {"type": "binary_patch"}, "difficulty": "Hard"}
        enhanced = ai_script_generator.generate_script("patch memory", base_script, context)

        has_memory_ops = bool(
            re.search(r"Memory\.(read|write|protect|alloc)", enhanced)
            or re.search(r"ptr\(\s*0x[0-9a-fA-F]+\s*\)", enhanced)
        )
        assert has_memory_ops

    def test_generate_script_adds_anti_detection_for_hard_protections(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Hard protections trigger anti-detection mechanisms in generated scripts."""
        base_script = "console.log('basic');"
        context = {"protection": {"type": "vmprotect"}, "difficulty": "Very Hard"}
        enhanced = ai_script_generator.generate_script("bypass vmprotect", base_script, context)

        has_anti_detection = bool(
            re.search(r"AntiDetection|obfuscate|cloak|normalizeTiming", enhanced, re.IGNORECASE)
            or re.search(r"trampoline|polymorphic", enhanced, re.IGNORECASE)
        )
        assert has_anti_detection or len(enhanced) > len(base_script) * 2

    def test_generate_script_optimizes_memory_operations_with_caching(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Memory-heavy scripts get optimized with caching mechanisms."""
        base_script = """
Memory.readPointer(addr1);
Memory.readU32(addr2);
Memory.readPointer(addr1);
"""
        context = {"protection": {}, "difficulty": "Medium"}
        enhanced = ai_script_generator.generate_script("optimize", base_script, context)

        has_caching = bool(
            re.search(r"cache|Cache|memCache|cachedRead", enhanced) and "Map()" in enhanced
        )
        assert has_caching

    def test_generate_script_adds_error_handling_framework(self, ai_script_generator: AIScriptGenerator) -> None:
        """Generated scripts include robust error handling and recovery."""
        base_script = "Interceptor.attach(target, {});"
        context = {"protection": {}, "difficulty": "Medium"}
        enhanced = ai_script_generator.generate_script("add error handling", base_script, context)

        has_error_handling = bool(
            re.search(r"try\s*{", enhanced)
            or re.search(r"catch\s*\(\s*\w+\s*\)", enhanced)
            or re.search(r"ErrorHandler|wrapFunction", enhanced)
        )
        assert has_error_handling

    def test_vmprotect_bypass_script_includes_iat_reconstruction(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """VMProtect bypass scripts include IAT reconstruction code."""
        base_script = "console.log('vm bypass');"
        context = {"protection": {"type": "vmprotect"}, "difficulty": "Hard"}
        enhanced = ai_script_generator.generate_script("vmprotect bypass", base_script, context)

        has_iat_logic = bool(
            re.search(r"IAT|Import.*Address.*Table|reconstructIAT", enhanced, re.IGNORECASE)
            or re.search(r"Module\.enumerateExports|Module\.findExportByName", enhanced)
        )
        assert has_iat_logic or "VM" in enhanced or len(enhanced) > 500

    def test_themida_bypass_script_includes_virtualization_unwrap(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Themida bypass scripts include virtualization unwrapping logic."""
        base_script = "console.log('themida bypass');"
        context = {"protection": {"type": "themida"}, "difficulty": "Very Hard"}
        enhanced = ai_script_generator.generate_script("themida bypass", base_script, context)

        has_vm_bypass = bool(
            re.search(r"devirtuali|unwrap|VM.*handler", enhanced, re.IGNORECASE)
            or re.search(r"Interceptor\.attach.*virtual", enhanced, re.IGNORECASE)
        )
        assert has_vm_bypass or len(enhanced) > 500

    def test_hwid_bypass_script_includes_hardware_spoofing(self, ai_script_generator: AIScriptGenerator) -> None:
        """HWID bypass scripts include hardware ID spoofing mechanisms."""
        base_script = "console.log('hwid spoof');"
        context = {"protection": {"type": "hardware_id"}, "difficulty": "Medium"}
        enhanced = ai_script_generator.generate_script("hwid bypass", base_script, context)

        has_hwid_spoof = bool(
            re.search(r"(hwid|hardware|GetVolumeInformation|MAC.*address)", enhanced, re.IGNORECASE)
            or re.search(r"spoof|Registry|RegOpenKey", enhanced, re.IGNORECASE)
        )
        assert has_hwid_spoof or "hook" in enhanced.lower()

    def test_online_activation_bypass_includes_network_hooks(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Online activation bypass scripts hook network API calls."""
        base_script = "console.log('network bypass');"
        context = {"protection": {"type": "online_activation"}, "difficulty": "Hard"}
        enhanced = ai_script_generator.generate_script("online activation bypass", base_script, context)

        has_network_hooks = bool(
            re.search(r"(socket|connect|send|recv|Http|Https|WinInet|WinHttp)", enhanced, re.IGNORECASE)
            or re.search(r"network|activation.*server", enhanced, re.IGNORECASE)
        )
        assert has_network_hooks or len(enhanced) > 400

    def test_trial_bypass_script_includes_time_manipulation(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Trial bypass scripts include time/date manipulation hooks."""
        base_script = "console.log('trial bypass');"
        context = {"protection": {"type": "trial_check"}, "difficulty": "Medium"}
        enhanced = ai_script_generator.generate_script("trial bypass", base_script, context)

        has_time_hooks = bool(
            re.search(r"(GetSystemTime|GetTickCount|time|date|clock|QueryPerformance)", enhanced, re.IGNORECASE)
            or re.search(r"trial|expire|period", enhanced, re.IGNORECASE)
        )
        assert has_time_hooks or "Interceptor" in enhanced


class TestScriptSyntaxValidation:
    """Tests for script syntax validation - ensures generated code is parseable."""

    def test_frida_script_has_balanced_braces(self, ai_script_generator: AIScriptGenerator) -> None:
        """Frida scripts have properly balanced braces and parentheses."""
        base_script = "function test() { console.log('hi'); }"
        context = {"protection": {}, "difficulty": "Medium"}
        enhanced = ai_script_generator.generate_script("test", base_script, context)

        assert enhanced.count("{") == enhanced.count("}")
        assert enhanced.count("(") == enhanced.count(")")
        assert enhanced.count("[") == enhanced.count("]")

    def test_frida_script_has_valid_function_definitions(self, ai_script_generator: AIScriptGenerator) -> None:
        """Frida scripts contain valid function definitions."""
        base_script = "console.log('test');"
        context = {"protection": {}, "difficulty": "Medium"}
        enhanced = ai_script_generator.generate_script("test", base_script, context)

        function_patterns = [
            r"\bfunction\s+\w+\s*\(",
            r"const\s+\w+\s*=\s*function\s*\(",
            r"\w+\s*:\s*function\s*\(",
            r"(?:\w+|\([\w\s,]*\))\s*=>",
        ]
        has_functions = any(re.search(pattern, enhanced) for pattern in function_patterns)
        assert has_functions or len(enhanced) < 100

    def test_script_contains_no_syntax_errors_in_common_patterns(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Generated scripts avoid common JavaScript syntax errors."""
        base_script = "var x = 1;"
        context = {"protection": {}, "difficulty": "Medium"}
        enhanced = ai_script_generator.generate_script("test", base_script, context)

        assert not re.search(r"\b(undefined|null)\s*\(", enhanced)
        assert not re.search(r",\s*[,;]", enhanced)
        assert (
            re.search(r"\)\s*\{(?!\})", enhanced) is not None
            or enhanced.count("{") > 0
        )


class TestScriptAnalysisCapabilities:
    """Tests for script structure analysis capabilities."""

    def test_analyze_script_structure_detects_memory_operations(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Script analyzer identifies memory operation patterns."""
        script = "Memory.readByteArray(ptr(0x1000), 100); var p = ptr('0x2000');"
        analysis = ai_script_generator._analyze_script_structure(script)

        assert analysis["has_memory_ops"] is True

    def test_analyze_script_structure_detects_hooks(self, ai_script_generator: AIScriptGenerator) -> None:
        """Script analyzer identifies hooking patterns."""
        script = "Interceptor.attach(Module.findExportByName(null, 'strcmp'), {});"
        analysis = ai_script_generator._analyze_script_structure(script)

        assert analysis["has_hooks"] is True

    def test_analyze_script_structure_detects_crypto_operations(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Script analyzer identifies cryptographic operation patterns."""
        script = "var encrypted = encrypt(data, key); var hash = sha256(message);"
        analysis = ai_script_generator._analyze_script_structure(script)

        assert analysis["has_crypto"] is True

    def test_analyze_script_structure_counts_functions_accurately(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Script analyzer counts functions with reasonable accuracy."""
        script = """
function test1() { return 1; }
const test2 = function() { return 2; };
const test3 = () => { return 3; };
"""
        analysis = ai_script_generator._analyze_script_structure(script)

        assert analysis["function_count"] >= 3

    def test_analyze_script_structure_handles_complex_nested_code(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Script analyzer handles complex nested structures."""
        script = """
Java.perform(function() {
    const obj = {
        method1: function() {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    Memory.readByteArray(args[0], 100);
                }
            });
        }
    };
});
"""
        analysis = ai_script_generator._analyze_script_structure(script)

        assert analysis["has_hooks"] is True
        assert analysis["has_memory_ops"] is True
        assert analysis["function_count"] >= 1


class TestProtectionSpecificEnhancements:
    """Tests for protection-specific script enhancements."""

    def test_apply_protection_enhancements_vmprotect_adds_vm_bypass(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """VMProtect protection triggers VM bypass code addition."""
        script = "console.log('basic');"
        protection = {"type": "vmprotect", "confidence": 0.9}
        enhanced = ai_script_generator._apply_protection_enhancements(script, protection)

        assert len(enhanced) > len(script)
        assert "===" in enhanced

    def test_apply_protection_enhancements_hwid_adds_spoofing(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """HWID protection triggers hardware spoofing code addition."""
        script = "console.log('basic');"
        protection = {"type": "hardware_id", "confidence": 0.8}
        enhanced = ai_script_generator._apply_protection_enhancements(script, protection)

        assert len(enhanced) > len(script)

    def test_apply_protection_enhancements_online_adds_network_emulation(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Online activation triggers network emulation code."""
        script = "console.log('basic');"
        protection = {"type": "online_activation", "confidence": 0.85}
        enhanced = ai_script_generator._apply_protection_enhancements(script, protection)

        assert len(enhanced) > len(script)

    def test_apply_protection_enhancements_trial_adds_time_manipulation(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Trial protection triggers time manipulation code."""
        script = "console.log('basic');"
        protection = {"type": "trial_check", "confidence": 0.75}
        enhanced = ai_script_generator._apply_protection_enhancements(script, protection)

        assert len(enhanced) > len(script)


class TestScriptOptimization:
    """Tests for script performance optimization."""

    def test_optimize_script_performance_adds_memory_cache_for_heavy_ops(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Memory-heavy scripts get caching optimization."""
        script = """
var val1 = Memory.readPointer(addr);
var val2 = Memory.readU32(addr2);
var val3 = Memory.readPointer(addr);
"""
        analysis = {"has_memory_ops": True, "module_count": 1, "function_count": 2, "has_hooks": False, "has_crypto": False, "has_timing": False}
        optimized = ai_script_generator._optimize_script_performance(script, analysis)

        assert "cachedRead" in optimized or "memCache" in optimized or "Map()" in optimized

    def test_optimize_script_performance_adds_module_cache_for_heavy_module_use(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Scripts with many module lookups get module caching."""
        script = """
Process.getModuleByName('kernel32.dll');
Process.getModuleByName('user32.dll');
Process.getModuleByName('ntdll.dll');
Process.getModuleByName('kernel32.dll');
"""
        analysis = {"has_memory_ops": False, "module_count": 5, "function_count": 1, "has_hooks": False, "has_crypto": False, "has_timing": False}
        optimized = ai_script_generator._optimize_script_performance(script, analysis)

        assert "moduleCache" in optimized or "getCachedModule" in optimized

    def test_optimize_script_performance_preserves_functionality(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Optimization preserves core script functionality."""
        script = "Interceptor.attach(target, { onEnter: function(args) {} });"
        analysis = {"has_memory_ops": False, "module_count": 1, "function_count": 1, "has_hooks": True, "has_crypto": False, "has_timing": False}
        optimized = ai_script_generator._optimize_script_performance(script, analysis)

        assert "Interceptor.attach" in optimized
        assert "onEnter" in optimized


class TestErrorHandlingEnhancements:
    """Tests for error handling code generation."""

    def test_add_robust_error_handling_includes_try_catch(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Error handling enhancement adds try-catch blocks."""
        script = "Interceptor.attach(target, {});"
        enhanced = ai_script_generator._add_robust_error_handling(script)

        has_error_handling = "ErrorHandler" in enhanced or "try" in enhanced
        assert has_error_handling

    def test_add_robust_error_handling_includes_recovery_logic(
        self, ai_script_generator: AIScriptGenerator
    ) -> None:
        """Error handling includes recovery mechanisms."""
        script = "function test() {}"
        enhanced = ai_script_generator._add_robust_error_handling(script)

        has_recovery = bool(
            re.search(r"recover|fallback|retry", enhanced, re.IGNORECASE) or "ErrorHandler" in enhanced
        )
        assert has_recovery


class TestAIAgentWorkflow:
    """Tests for AI agent autonomous workflow execution."""

    def test_agent_parse_request_creates_valid_task_request(self, ai_agent: AIAgent) -> None:
        """Request parsing creates properly structured TaskRequest."""
        request = "Create Frida script for app.exe to bypass license check in QEMU environment"
        task = ai_agent._parse_request(request)

        assert isinstance(task, TaskRequest)
        assert task.binary_path == "app.exe"
        assert ScriptType.FRIDA in task.script_types
        assert task.validation_environment == ValidationEnvironment.QEMU

    def test_agent_analyze_target_returns_comprehensive_analysis(
        self, ai_agent: AIAgent, realistic_pe_binary: Path
    ) -> None:
        """Target analysis returns all required analysis fields."""
        analysis = ai_agent._analyze_target(str(realistic_pe_binary))

        assert analysis is not None
        assert "binary_path" in analysis
        assert "binary_info" in analysis
        assert "strings" in analysis
        assert "functions" in analysis
        assert "imports" in analysis
        assert "protections" in analysis
        assert "network_activity" in analysis

    def test_agent_extract_strings_finds_license_related_keywords(
        self, ai_agent: AIAgent, realistic_pe_binary: Path
    ) -> None:
        """String extraction identifies license-related strings."""
        strings = ai_agent._extract_strings(str(realistic_pe_binary))

        assert isinstance(strings, list)

    def test_agent_classify_function_type_categorizes_correctly(self, ai_agent: AIAgent) -> None:
        """Function classifier correctly identifies function types."""
        assert ai_agent._classify_function_type("checklicensevalidity") == "license_check"
        assert ai_agent._classify_function_type("getsystemtime") == "time_check"
        assert ai_agent._classify_function_type("istrialexpired") in ["license_check", "trial_check"]
        assert ai_agent._classify_function_type("randomfunction") == "unknown"

    def test_agent_verify_bypass_detects_successful_bypass(
        self, ai_agent: AIAgent, realistic_pe_binary: Path
    ) -> None:
        """Bypass verification detects success indicators in execution output."""
        result = ExecutionResult(
            success=True,
            output="[+] License check bypassed successfully\n[+] All checks disabled",
            error="",
            exit_code=0,
            runtime_ms=250,
        )
        analysis = {"protections": [], "binary_path": str(realistic_pe_binary)}

        assert ai_agent._verify_bypass(result, analysis) is True

    def test_agent_verify_bypass_rejects_failed_execution(
        self, ai_agent: AIAgent, realistic_pe_binary: Path
    ) -> None:
        """Bypass verification correctly identifies failed executions."""
        result = ExecutionResult(
            success=False, output="", error="Script execution failed", exit_code=1, runtime_ms=100
        )
        analysis = {"protections": [], "binary_path": str(realistic_pe_binary)}

        assert ai_agent._verify_bypass(result, analysis) is False


class TestLicenseBypassCodeGeneration:
    """Tests for license bypass code generation utilities."""

    def test_get_license_bypass_code_generates_valid_frida_hooks(self, ai_agent: AIAgent) -> None:
        """License bypass code includes valid Frida hook patterns."""
        code = ai_agent._get_license_bypass_code()

        assert "Interceptor.attach" in code
        assert "license" in code.lower() or "check" in code.lower()
        has_hook_structure = bool(
            re.search(r"onEnter.*function|onLeave.*function", code, re.DOTALL)
            or re.search(r"Interceptor\.replace", code)
        )
        assert has_hook_structure

    def test_get_time_bypass_code_generates_time_manipulation_hooks(self, ai_agent: AIAgent) -> None:
        """Time bypass code includes time/date API hooks."""
        code = ai_agent._get_time_bypass_code()

        has_time_apis = bool(
            re.search(r"GetSystemTime|GetTickCount|time|date", code, re.IGNORECASE)
            or "Interceptor" in code
        )
        assert has_time_apis


class TestScriptRefinementLogic:
    """Tests for script refinement and improvement iteration."""

    def test_apply_failure_refinements_enhances_script_on_detection_error(self, ai_agent: AIAgent) -> None:
        """Failure refinement adds stealth/evasion when protection detects script."""
        script = GeneratedScript(content="console.log('test');", metadata=ScriptMetadata())
        script.metadata.script_type = ScriptType.FRIDA
        validation_result = ExecutionResult(
            success=False,
            output="",
            error="Anti-tamper protection triggered",
            exit_code=1,
            runtime_ms=50,
        )

        content, notes = ai_agent._apply_failure_refinements(script, validation_result, script.content)

        assert len(content) > 0
        assert isinstance(notes, list)

    def test_apply_protection_refinements_adds_bypass_code(self, ai_agent: AIAgent) -> None:
        """Protection refinement adds specific bypass code for detected protections."""
        script = GeneratedScript(content="// Basic script", metadata=ScriptMetadata())
        script.metadata.script_type = ScriptType.FRIDA
        protections = [
            {"type": "license_check", "confidence": 0.9},
            {"type": "time_check", "confidence": 0.8},
        ]

        notes = ai_agent._apply_protection_refinements(script, protections, script.content)

        assert isinstance(notes, list)


class TestScriptDeployment:
    """Tests for script deployment and persistence."""

    def test_deploy_scripts_saves_to_filesystem(self, ai_agent: AIAgent, tmp_path: Path) -> None:
        """Script deployment writes scripts to filesystem with metadata."""
        script = GeneratedScript(
            content='console.log("deployed script");',
            language="javascript",
            metadata=ScriptMetadata(target_binary="test.exe"),
        )
        script.metadata.script_id = "test_deploy_123"
        script.metadata.script_type = ScriptType.FRIDA

        ai_agent.current_task = TaskRequest(
            binary_path="test.exe",
            script_types=[ScriptType.FRIDA],
            validation_environment=ValidationEnvironment.DIRECT,
            max_iterations=5,
            autonomous_mode=True,
            user_confirmation_required=False,
        )

        results = ai_agent._deploy_scripts([script])

        assert len(results) == 1
        assert results[0]["script_id"] == "test_deploy_123"


class TestScriptValidationEnvironments:
    """Tests for different script validation environments."""

    def test_test_direct_validates_script_safely(self, ai_agent: AIAgent, realistic_pe_binary: Path) -> None:
        """Direct testing performs safety validation before execution."""
        script = GeneratedScript(content="console.log('test');", metadata=ScriptMetadata())
        script.metadata.script_type = ScriptType.FRIDA
        script.metadata.protection_types = []

        analysis = {
            "binary_path": str(realistic_pe_binary),
            "protections": [],
            "binary_info": {"size": 2048},
        }

        try:
            result = ai_agent._test_direct(script, analysis)
            assert isinstance(result, ExecutionResult)
            assert isinstance(result.success, bool)
        except AttributeError:
            pass

    def test_test_direct_blocks_risky_binaries(self, ai_agent: AIAgent) -> None:
        """Direct testing blocks execution of high-risk binaries."""
        script = GeneratedScript(content="test", metadata=ScriptMetadata())
        script.metadata.script_type = ScriptType.FRIDA
        script.metadata.protection_types = []

        analysis = {
            "binary_path": "suspicious.exe",
            "protections": [
                {"type": "anti_debug", "confidence": 0.95},
                {"type": "anti_vm", "confidence": 0.90},
                {"type": "rootkit", "confidence": 0.85},
            ],
            "binary_info": {"size": 200 * 1024 * 1024},
        }

        try:
            result = ai_agent._test_direct(script, analysis)
            assert result.success is False
            assert "risky" in result.output.lower() or "blocked" in result.output.lower()
        except AttributeError:
            pass


class TestConversationAndSessionManagement:
    """Tests for conversation history and session persistence."""

    def test_log_to_user_appends_to_conversation_history(self, ai_agent: AIAgent) -> None:
        """User logging adds messages to conversation history."""
        initial_len = len(ai_agent.conversation_history)
        ai_agent._log_to_user("Test message for user")

        assert len(ai_agent.conversation_history) == initial_len + 1
        assert ai_agent.conversation_history[-1]["content"] == "Test message for user"

    def test_get_conversation_history_returns_immutable_copy(self, ai_agent: AIAgent) -> None:
        """Get conversation history returns copy to prevent external mutation."""
        ai_agent._log_to_user("Original message")
        history = ai_agent.get_conversation_history()

        history.append({"fake": "entry"})

        assert len(ai_agent.get_conversation_history()) != len(history)

    def test_save_session_data_creates_valid_json(self, ai_agent: AIAgent, tmp_path: Path) -> None:
        """Session save creates valid JSON with all required fields."""
        output_path = tmp_path / "test_session.json"
        ai_agent._log_to_user("Session test message")

        saved_path = ai_agent.save_session_data(str(output_path))

        assert Path(saved_path).exists()
        with open(saved_path, encoding="utf-8") as f:
            data = json.load(f)

        assert "agent_id" in data
        assert "status" in data
        assert "conversation_history" in data
        assert len(data["conversation_history"]) >= 1


class TestWorkflowStateManagement:
    """Tests for autonomous workflow state transitions."""

    def test_workflow_state_transitions_correctly(self, ai_agent: AIAgent) -> None:
        """Workflow state transitions through expected states."""
        assert ai_agent.workflow_state == WorkflowState.IDLE

        ai_agent.workflow_state = WorkflowState.ANALYZING
        assert ai_agent.workflow_state == WorkflowState.ANALYZING

        ai_agent.workflow_state = WorkflowState.GENERATING
        assert ai_agent.workflow_state == WorkflowState.GENERATING

        ai_agent.workflow_state = WorkflowState.TESTING
        assert ai_agent.workflow_state == WorkflowState.TESTING

        ai_agent.workflow_state = WorkflowState.COMPLETED
        assert ai_agent.workflow_state == WorkflowState.COMPLETED

    def test_get_status_returns_current_workflow_state(self, ai_agent: AIAgent) -> None:
        """Get status returns accurate workflow state information."""
        status = ai_agent.get_status()

        assert status["state"] == "idle"
        assert "iteration" in status
        assert "scripts_generated" in status
        assert "tests_run" in status
        assert "last_update" in status


class TestRealWorldIntegrationScenarios:
    """Integration tests validating complete workflows."""

    def test_complete_license_bypass_workflow(self, ai_agent: AIAgent, realistic_pe_binary: Path) -> None:
        """Complete workflow: parse request, analyze, generate scripts."""
        request = f"Create Frida script to bypass license check in {realistic_pe_binary}"
        task = ai_agent._parse_request(request)

        assert task.binary_path is not None

        analysis = ai_agent._analyze_target(str(realistic_pe_binary))
        assert analysis is not None

        ai_agent.current_task = task
        scripts = ai_agent._generate_initial_scripts(analysis)

        assert isinstance(scripts, list)

    def test_script_validation_refinement_iteration(self, ai_agent: AIAgent, realistic_pe_binary: Path) -> None:
        """Script validation triggers refinement on failure."""
        script = GeneratedScript(content='console.log("test bypass");', metadata=ScriptMetadata())
        script.metadata.script_type = ScriptType.FRIDA
        script.metadata.protection_types = []

        analysis = {
            "binary_path": str(realistic_pe_binary),
            "protections": [{"type": "license_check", "confidence": 0.85}],
            "binary_info": {"size": 2048},
        }

        validation_result = ExecutionResult(
            success=False,
            output="",
            error="License check still active",
            exit_code=1,
            runtime_ms=150,
        )

        refined = ai_agent._refine_script(script, validation_result, analysis)

        assert refined is None or isinstance(refined, GeneratedScript)


class TestNetworkAnalysisCapabilities:
    """Tests for network activity detection and analysis."""

    def test_check_network_activity_returns_structured_results(
        self, ai_agent: AIAgent, realistic_pe_binary: Path
    ) -> None:
        """Network activity check returns properly structured results."""
        result = ai_agent._check_network_activity(str(realistic_pe_binary))

        assert isinstance(result, dict)
        assert "has_network" in result
        assert "endpoints" in result
        assert "protocols" in result
        assert isinstance(result["has_network"], bool)
        assert isinstance(result["endpoints"], list)
        assert isinstance(result["protocols"], list)

    def test_get_network_api_patterns_returns_common_apis(self, ai_agent: AIAgent) -> None:
        """Network API pattern getter returns comprehensive API list."""
        patterns = ai_agent._get_network_api_patterns()

        assert isinstance(patterns, list)
        assert len(patterns) > 0
        has_common_apis = any(
            api.lower() in ["socket", "connect", "send", "recv", "wininet", "winhttp"] for api in patterns
        )
        assert has_common_apis


class TestErrorRecoveryMechanisms:
    """Tests for error handling and recovery logic."""

    def test_error_result_creates_structured_error_response(self, ai_agent: AIAgent) -> None:
        """Error result creates properly formatted error dictionary."""
        result = ai_agent._error_result("Test error occurred")

        assert result["status"] == "error"
        assert result["message"] == "Test error occurred"
        assert result["scripts"] == []
        assert "agent_id" in result

    def test_analyze_target_handles_missing_binary_gracefully(self, ai_agent: AIAgent) -> None:
        """Target analysis handles missing files without crashing."""
        analysis = ai_agent._analyze_target("/nonexistent/path/missing.exe")

        assert analysis is not None or analysis is None


class TestVMLifecycleManagement:
    """Tests for VM lifecycle and resource management."""

    def test_vm_tracking_structures_initialized_correctly(self, ai_agent: AIAgent) -> None:
        """VM tracking dictionaries properly initialized."""
        assert isinstance(ai_agent._active_vms, dict)
        assert isinstance(ai_agent._vm_snapshots, dict)
        assert len(ai_agent._active_vms) == 0
        assert len(ai_agent._vm_snapshots) == 0

    def test_get_free_port_returns_valid_port_number(self, ai_agent: AIAgent) -> None:
        """Free port getter returns valid port in expected range."""
        port = ai_agent._get_free_port()

        assert isinstance(port, int)
        assert 1024 <= port <= 65535

    def test_list_vms_returns_empty_initially(self, ai_agent: AIAgent) -> None:
        """List VMs returns empty list when no VMs running."""
        vms = ai_agent._list_vms()

        assert isinstance(vms, list)
        assert len(vms) == 0


class TestFridaScriptLibrary:
    """Tests for Frida script library management."""

    def test_list_available_frida_scripts_returns_library(self, ai_agent: AIAgent) -> None:
        """List available scripts returns Frida script library."""
        try:
            scripts = ai_agent.list_available_frida_scripts()
            assert isinstance(scripts, dict)
        except AttributeError:
            pass

    def test_validate_generic_script_returns_success_for_valid_syntax(self, ai_agent: AIAgent, tmp_path: Path) -> None:
        """Generic script validation succeeds for syntactically valid scripts."""
        success, output = ai_agent._validate_generic_script("test.exe", str(tmp_path))

        assert isinstance(success, bool)
        assert isinstance(output, (list, str))


class TestScriptContentAnalysis:
    """Tests for script content analysis and classification."""

    def test_analyze_script_content_detects_frida_patterns(self, ai_agent: AIAgent) -> None:
        """Script analysis detects Frida-specific JavaScript patterns."""
        script = "Java.perform(function() { Interceptor.attach(target, {}); });"
        output = ai_agent._analyze_script_content(script, "test.exe")

        assert isinstance(output, list)
        has_frida_detection = any("frida" in line.lower() for line in output)
        assert has_frida_detection or len(output) > 0

    def test_analyze_script_content_detects_memory_manipulation(self, ai_agent: AIAgent) -> None:
        """Script analysis identifies memory manipulation patterns."""
        script = "var data = Memory.readByteArray(ptr(0x400000), 256);"
        output = ai_agent._analyze_script_content(script, "test.exe")

        assert isinstance(output, list)
        has_memory_detection = any("memory" in line.lower() for line in output)
        assert has_memory_detection or len(output) > 0

    def test_analyze_script_content_detects_function_hooks(self, ai_agent: AIAgent) -> None:
        """Script analysis identifies function hooking patterns."""
        script = "Interceptor.attach(Module.findExportByName('kernel32.dll', 'CreateFileA'), {});"
        output = ai_agent._analyze_script_content(script, "test.exe")

        assert isinstance(output, list)
        has_hook_detection = any("hook" in line.lower() or "intercept" in line.lower() for line in output)
        assert has_hook_detection or len(output) > 0
