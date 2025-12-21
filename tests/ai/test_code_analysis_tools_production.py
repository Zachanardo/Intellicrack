"""Production tests for code_analysis_tools.py - Real code analysis on diverse binaries.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.code_analysis_tools import AIAssistant, CodeAnalyzer, analyze_with_ai, explain_code, get_ai_suggestions


class TestAIAssistantProductionAnalysis:
    """Production tests for AIAssistant analyzing real code patterns."""

    @pytest.fixture
    def assistant(self) -> AIAssistant:
        """Create AIAssistant instance for testing."""
        return AIAssistant()

    @pytest.fixture
    def vulnerable_c_code(self) -> str:
        """Real vulnerable C code with buffer overflow."""
        return """
#include <stdio.h>
#include <string.h>

int authenticate(char *username, char *password) {
    char buffer[8];
    strcpy(buffer, password);  // Buffer overflow vulnerability

    if (strcmp(buffer, "admin123") == 0) {
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <username> <password>\\n", argv[0]);
        return 1;
    }

    if (authenticate(argv[1], argv[2])) {
        printf("Access granted\\n");
    } else {
        printf("Access denied\\n");
    }
    return 0;
}
"""

    @pytest.fixture
    def license_validation_assembly(self) -> str:
        """Real assembly code for license validation from disassembly."""
        return """
sub_401000:
    push    ebp
    mov     ebp, esp
    sub     esp, 0x10
    mov     eax, [ebp+0x8]      ; Load license key
    call    validate_checksum    ; Validate checksum
    test    eax, eax            ; Check result
    jz      license_invalid      ; Jump if zero (invalid)

license_valid:
    mov     eax, 1              ; Return 1 (valid)
    jmp     cleanup

license_invalid:
    mov     eax, 0              ; Return 0 (invalid)

cleanup:
    mov     esp, ebp
    pop     ebp
    ret
"""

    def test_analyze_code_detects_real_buffer_overflow(self, assistant: AIAssistant, vulnerable_c_code: str) -> None:
        """AIAssistant detects genuine buffer overflow in real C code."""
        result: dict[str, Any] = assistant.analyze_code(vulnerable_c_code, language="c")

        assert result["status"] == "success", "Analysis must succeed"
        assert result["language"] == "c", "Must detect C language"

        security_issues: list[str] = result.get("security_issues", [])
        assert security_issues, "Must detect buffer overflow security issue"

        assert any(
            "strcpy" in issue.lower() or "unsafe" in issue.lower() or "buffer" in issue.lower()
            for issue in security_issues
        ), "Must identify strcpy as unsafe"

        suggestions: list[str] = result.get("suggestions", [])
        assert any(
            "strncpy" in suggestion.lower() or "safe" in suggestion.lower()
            for suggestion in suggestions
        ), "Must suggest safer alternatives"

    def test_analyze_code_detects_assembly_patterns(self, assistant: AIAssistant, license_validation_assembly: str) -> None:
        """AIAssistant analyzes real assembly license validation code."""
        result: dict[str, Any] = assistant.analyze_code(license_validation_assembly, language="assembly")

        assert result["status"] == "success", "Analysis must succeed"
        assert result["language"] == "assembly", "Must detect assembly language"

        patterns: list[str] = result.get("patterns", [])
        assert patterns, "Must detect assembly patterns"

        assert any(
            "control flow" in pattern.lower() or "jump" in pattern.lower()
            for pattern in patterns
        ), "Must identify control flow patterns in license validation"

    def test_analyze_code_with_python_eval_vulnerability(self, assistant: AIAssistant) -> None:
        """AIAssistant detects eval() vulnerability in Python code."""
        python_code: str = """
import os

def execute_command(user_input):
    # Dangerous: executing user input
    result = eval(user_input)
    return result

def process_data(data):
    # Execute user-provided code
    exec(data)
"""

        result: dict[str, Any] = assistant.analyze_code(python_code, language="python")

        assert result["status"] == "success"
        assert result["language"] == "python"

        security_issues: list[str] = result.get("security_issues", [])
        assert security_issues, "Must detect eval/exec vulnerabilities"

        assert any(
            "eval" in issue.lower() or "exec" in issue.lower()
            for issue in security_issues
        ), "Must specifically identify eval/exec risks"


class TestCodeAnalyzerBinaryAnalysis:
    """Production tests for CodeAnalyzer analyzing real binary files."""

    @pytest.fixture
    def analyzer(self) -> CodeAnalyzer:
        """Create CodeAnalyzer instance for testing."""
        return CodeAnalyzer()

    @pytest.fixture
    def real_pe_binary(self, tmp_path: Path) -> str:
        """Create a minimal valid PE binary for analysis."""
        pe_path: Path = tmp_path / "test_binary.exe"

        dos_header: bytes = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)

        pe_signature: bytes = b"PE\x00\x00"

        coff_header: bytes = struct.pack(
            "<HHIIIHH",
            0x14C,
            1,
            0,
            0,
            0,
            0xE0,
            0x10B
        )

        optional_header: bytes = b"\x00" * 0xE0

        section_header: bytes = (
            b".text\x00\x00\x00"
            + struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0x60000020)
        )

        binary_content: bytes = (
            dos_header
            + b"\x00" * (0x80 - len(dos_header))
            + pe_signature
            + coff_header
            + optional_header
            + section_header
            + b"\x90" * 512
        )

        pe_path.write_bytes(binary_content)
        return str(pe_path)

    @pytest.fixture
    def real_elf_binary(self, tmp_path: Path) -> str:
        """Create a minimal valid ELF binary for analysis."""
        elf_path: Path = tmp_path / "test_binary.elf"

        elf_header: bytes = (
            b"\x7fELF"
            + bytes([2, 1, 1, 0])
            + b"\x00" * 8
            + struct.pack("<HHI", 2, 0x3E, 1)
            + struct.pack("<QQQIHHHHHH", 0x400000, 0x40, 0, 0, 0, 64, 0, 0, 0, 0)
        )

        elf_content: bytes = elf_header + b"\x00" * (512 - len(elf_header))

        elf_path.write_bytes(elf_content)
        return str(elf_path)

    def test_analyze_binary_detects_pe_format(self, analyzer: CodeAnalyzer, real_pe_binary: str) -> None:
        """CodeAnalyzer detects and analyzes real PE binary format."""
        result: dict[str, Any] = analyzer.analyze_binary(real_pe_binary)

        assert "error" not in result, "Analysis must not error on valid PE"
        assert result["file_path"] == real_pe_binary
        assert result["analysis_type"] == "binary"

        metadata: dict[str, Any] = result.get("metadata", {})
        assert metadata.get("format") == "PE", "Must detect PE format from real binary"

        findings: list[str] = result.get("findings", [])
        assert any("PE" in finding or "Portable Executable" in finding for finding in findings), "Must report PE detection"

    def test_analyze_binary_detects_elf_format(self, analyzer: CodeAnalyzer, real_elf_binary: str) -> None:
        """CodeAnalyzer detects and analyzes real ELF binary format."""
        result: dict[str, Any] = analyzer.analyze_binary(real_elf_binary)

        assert "error" not in result
        assert result["file_path"] == real_elf_binary
        assert result["analysis_type"] == "binary"

        metadata: dict[str, Any] = result.get("metadata", {})
        assert metadata.get("format") == "ELF", "Must detect ELF format from real binary"

        findings: list[str] = result.get("findings", [])
        assert any("ELF" in finding for finding in findings), "Must report ELF detection"

    def test_analyze_binary_with_license_strings(self, analyzer: CodeAnalyzer, tmp_path: Path) -> None:
        """CodeAnalyzer detects license-related strings in binary."""
        binary_path: Path = tmp_path / "licensed_app.exe"

        pe_data: bytes = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_data += b"\x00" * (0x80 - len(pe_data))

        license_strings: bytes = b"LICENSE_KEY_VALIDATION\x00TRIAL_EXPIRATION\x00ACTIVATION_CODE\x00"
        pe_data += license_strings
        pe_data += b"\x00" * (2048 - len(pe_data))

        binary_path.write_bytes(pe_data)

        result: dict[str, Any] = analyzer.analyze_binary(str(binary_path))

        findings: list[str] = result.get("findings", [])
        assert any(
            "license" in finding.lower() or "trial" in finding.lower() or "activation" in finding.lower()
            for finding in findings
        ), "Must detect license-related strings embedded in binary"


class TestCodeAnalyzerAssemblyAnalysis:
    """Production tests for assembly code analysis against real patterns."""

    @pytest.fixture
    def analyzer(self) -> CodeAnalyzer:
        """Create CodeAnalyzer instance."""
        return CodeAnalyzer()

    @pytest.fixture
    def real_license_check_assembly(self) -> str:
        """Real assembly from a license check routine."""
        return """
check_license_key:
    push    ebx
    push    esi
    push    edi
    mov     esi, [esp+0x10]     ; Load key pointer

validate_checksum:
    xor     eax, eax
    xor     ecx, ecx

checksum_loop:
    movzx   edx, byte [esi+ecx]
    test    edx, edx
    jz      checksum_complete
    add     eax, edx
    inc     ecx
    cmp     ecx, 16
    jl      checksum_loop

checksum_complete:
    mov     edx, [esi+16]
    cmp     eax, edx
    jne     invalid_key

valid_key:
    mov     eax, 1
    jmp     cleanup

invalid_key:
    mov     eax, 0

cleanup:
    pop     edi
    pop     esi
    pop     ebx
    ret
"""

    def test_analyze_assembly_detects_license_validation(self, analyzer: CodeAnalyzer, real_license_check_assembly: str) -> None:
        """CodeAnalyzer analyzes real license validation assembly code."""
        result: dict[str, Any] = analyzer.analyze_assembly(real_license_check_assembly)

        assert "error" not in result
        assert result["code_type"] == "assembly"
        assert result["instruction_count"] > 20, "Must count real instructions"

        patterns: list[str] = result.get("patterns", [])
        assert patterns, "Must detect assembly patterns"

        control_flow: list[str] = result.get("control_flow", [])
        assert control_flow, "Must detect control flow in license check"

        assert any(
            "jmp" in cf.lower() or "jne" in cf.lower() or "jz" in cf.lower()
            for cf in control_flow
        ), "Must identify conditional jumps in validation logic"

    def test_analyze_assembly_detects_stack_operations(self, analyzer: CodeAnalyzer, real_license_check_assembly: str) -> None:
        """CodeAnalyzer detects stack operations in real assembly."""
        result: dict[str, Any] = analyzer.analyze_assembly(real_license_check_assembly)

        patterns: list[str] = result.get("patterns", [])
        assert any("stack" in pattern.lower() for pattern in patterns), "Must detect stack manipulation"

        data_operations: list[str] = result.get("data_operations", [])
        assert data_operations, "Must detect data movement operations"


class TestAnalyzeWithAIFunctions:
    """Production tests for module-level analysis functions."""

    def test_analyze_with_ai_binary_analysis(self, tmp_path: Path) -> None:
        """analyze_with_ai performs real binary analysis."""
        binary_path: Path = tmp_path / "target.exe"
        binary_content: bytes = b"MZ" + b"\x90" * 100
        binary_path.write_bytes(binary_content)

        result: dict[str, Any] = analyze_with_ai(str(binary_path), analysis_type="binary")

        assert result["status"] == "analyzed" or "analysis_type" in result
        assert result["type"] == "binary" or result.get("analysis_type") == "binary"

    def test_analyze_with_ai_assembly_analysis(self) -> None:
        """analyze_with_ai performs real assembly analysis."""
        assembly_code: str = """
    mov eax, [ebp+8]
    call validate_license
    test eax, eax
    jz invalid_license
    mov eax, 1
    ret
"""

        result: dict[str, Any] = analyze_with_ai(assembly_code, analysis_type="assembly")

        assert result["status"] == "analyzed" or "analysis_type" in result
        assert result["type"] == "assembly" or result.get("analysis_type") == "assembly"

    def test_get_ai_suggestions_for_license_context(self) -> None:
        """get_ai_suggestions provides relevant suggestions for license analysis."""
        context: str = "analyzing license validation routine in binary"
        suggestions: list[str] = get_ai_suggestions(context, domain="reverse_engineering")

        assert suggestions, "Must provide suggestions for license analysis"
        assert any("license" in s.lower() or "validation" in s.lower() for s in suggestions), "Suggestions must be relevant to license analysis"

    def test_explain_code_with_real_vulnerable_function(self) -> None:
        """explain_code provides explanation for real vulnerable C function."""
        vulnerable_code: str = """
void process_input(char *user_data) {
    char buffer[128];
    sprintf(buffer, user_data);  // Format string vulnerability
    execute_command(buffer);
}
"""

        explanation: str = explain_code(vulnerable_code, language="c", detail_level="high")

        assert explanation != "", "Must generate explanation"
        assert "c" in explanation.lower() or "code" in explanation.lower()
        assert "line" in explanation.lower() or "analysis" in explanation.lower()


class TestProductionCodeAnalysisEndToEnd:
    """End-to-end production tests simulating real analysis workflows."""

    @pytest.fixture
    def analyzer(self) -> CodeAnalyzer:
        """Create analyzer for E2E tests."""
        return CodeAnalyzer()

    def test_complete_license_crack_workflow(self, analyzer: CodeAnalyzer, tmp_path: Path) -> None:
        """Complete workflow: analyze binary, detect license check, analyze assembly."""
        binary_path: Path = tmp_path / "protected_app.exe"

        pe_header: bytes = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_header += b"\x00" * (0x80 - len(pe_header))

        license_code: bytes = b"CHECK_LICENSE\x00ACTIVATION_REQUIRED\x00"

        binary_content: bytes = pe_header + license_code + b"\x00" * 1024
        binary_path.write_bytes(binary_content)

        binary_result: dict[str, Any] = analyzer.analyze_binary(str(binary_path))

        assert "error" not in binary_result
        assert any(
            "license" in finding.lower() or "activation" in finding.lower()
            for finding in binary_result.get("findings", [])
        ), "Step 1: Must detect license indicators in binary"

        assembly_code: str = """
    cmp     dword [license_valid], 1
    jne     show_trial_expired
    jmp     run_application
"""

        asm_result: dict[str, Any] = analyzer.analyze_assembly(assembly_code)

        assert "error" not in asm_result
        assert len(asm_result.get("control_flow", [])) > 0, "Step 2: Must analyze control flow for bypass"

        suggestions: list[str] = analyzer.get_analysis_suggestions(binary_result)

        assert suggestions, "Step 3: Must provide actionable suggestions"

    def test_large_binary_analysis_performance(self, analyzer: CodeAnalyzer, tmp_path: Path) -> None:
        """Analyzer handles large binary files efficiently."""
        large_binary_path: Path = tmp_path / "large_app.exe"

        pe_header: bytes = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_header += b"\x00" * (0x80 - len(pe_header))

        large_content: bytes = pe_header + os.urandom(5 * 1024 * 1024)
        large_binary_path.write_bytes(large_content)

        result: dict[str, Any] = analyzer.analyze_binary(str(large_binary_path))

        assert "error" not in result, "Must handle large binaries without error"
        assert result.get("file_size", 0) > 5000000, "Must report correct file size for large binary"

    def test_multi_platform_binary_detection(self, analyzer: CodeAnalyzer, tmp_path: Path) -> None:
        """Analyzer distinguishes between PE, ELF, and Mach-O formats."""
        pe_binary: Path = tmp_path / "windows.exe"
        pe_binary.write_bytes(b"MZ" + b"\x90" * 100)

        elf_binary: Path = tmp_path / "linux.elf"
        elf_binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        macho_binary: Path = tmp_path / "macos.dylib"
        macho_binary.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)

        pe_result: dict[str, Any] = analyzer.analyze_binary(str(pe_binary))
        elf_result: dict[str, Any] = analyzer.analyze_binary(str(elf_binary))
        macho_result: dict[str, Any] = analyzer.analyze_binary(str(macho_binary))

        assert pe_result["metadata"]["format"] == "PE"
        assert elf_result["metadata"]["format"] == "ELF"
        assert macho_result["metadata"]["format"] == "Mach-O"
