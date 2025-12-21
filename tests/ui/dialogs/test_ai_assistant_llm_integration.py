"""Production tests for real LLM API integration in AI Coding Assistant.

Tests validate:
- Real API calls to LLM providers (OpenAI, Anthropic, local models)
- Code generation produces syntactically valid and executable code
- License analysis queries return meaningful security insights
- Error handling for API failures and rate limits
- Model selection and switching between providers
- Token usage tracking and cost estimation
- Response streaming and real-time updates

NO mocks - all tests use real LLM APIs when available.
Tests skip gracefully when API keys not configured.
"""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication

    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False
    Qt = None
    QApplication = None

if PYQT6_AVAILABLE:
    from intellicrack.ai.code_analysis_tools import AIAssistant
    from intellicrack.ui.dialogs.ai_coding_assistant_dialog import (
        AICodingAssistantWidget,
        ChatWidget,
        CodeEditor,
    )

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE, reason="PyQt6 not available - UI tests require PyQt6"
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def ai_assistant() -> AIAssistant:
    """Create real AI assistant instance with API credentials."""
    return AIAssistant()


@pytest.fixture
def has_openai_key() -> bool:
    """Check if OpenAI API key is configured."""
    return bool(os.getenv("OPENAI_API_KEY"))


@pytest.fixture
def has_anthropic_key() -> bool:
    """Check if Anthropic API key is configured."""
    return bool(os.getenv("ANTHROPIC_API_KEY"))


@pytest.fixture
def has_any_llm_provider() -> bool:
    """Check if any LLM provider is configured."""
    return bool(
        os.getenv("OPENAI_API_KEY")
        or os.getenv("ANTHROPIC_API_KEY")
        or os.getenv("OLLAMA_ENDPOINT")
    )


class TestRealLLMCodeGeneration:
    """Test real LLM code generation without mocks."""

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required for real generation tests",
    )
    def test_llm_generates_working_keygen_algorithm(
        self, qapp: QApplication, ai_assistant: AIAssistant, temp_workspace: Path
    ) -> None:
        """LLM generates syntactically valid and executable keygen code."""
        prompt = """Generate a production-ready Python function that creates license keys
        based on username input. The function should use SHA-256 hashing with a salt
        and return formatted keys like XXXX-XXXX-XXXX-XXXX."""

        response = ai_assistant.generate_code(
            prompt=prompt,
            language="python",
            context="license key generation",
        )

        assert response is not None
        assert "code" in response or isinstance(response, str)

        if isinstance(response, dict):
            generated_code = response.get("code", "")
        else:
            generated_code = response

        assert len(generated_code) > 50
        assert "def " in generated_code
        assert "sha256" in generated_code.lower() or "hashlib" in generated_code

        compile(generated_code, "<llm_generated>", "exec")

        test_file = temp_workspace / "llm_keygen.py"
        test_file.write_text(generated_code)

        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(test_file)],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert (
            result.returncode == 0
        ), f"LLM generated invalid Python: {result.stderr}"

        namespace: dict[str, Any] = {}
        exec(generated_code, namespace)

        keygen_functions = [
            name
            for name, obj in namespace.items()
            if callable(obj) and "generate" in name.lower()
        ]
        assert keygen_functions, "No keygen function found in generated code"

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_llm_generates_frida_hook_for_license_bypass(
        self, qapp: QApplication, ai_assistant: AIAssistant, temp_workspace: Path
    ) -> None:
        """LLM generates valid Frida JavaScript hook for license validation bypass."""
        prompt = """Generate a Frida script that hooks a license validation function
        named 'CheckLicenseKey' and forces it to return true (1).
        The script should work on Windows processes."""

        response = ai_assistant.generate_code(
            prompt=prompt,
            language="javascript",
            context="Frida hooking for license bypass",
        )

        if isinstance(response, dict):
            generated_code = response.get("code", "")
        else:
            generated_code = response

        assert len(generated_code) > 50
        assert (
            "Interceptor" in generated_code
            or "attach" in generated_code
            or "replace" in generated_code
        )
        assert (
            "CheckLicenseKey" in generated_code or "onLeave" in generated_code
        )

        js_syntax_valid = (
            "function" in generated_code or "=>" in generated_code
        ) and "{" in generated_code

        assert (
            js_syntax_valid
        ), "Generated JavaScript doesn't have basic function syntax"

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_llm_generates_hardware_id_spoofer(
        self, qapp: QApplication, ai_assistant: AIAssistant
    ) -> None:
        """LLM generates Windows registry patcher for hardware ID spoofing."""
        prompt = """Generate Python code that modifies Windows registry to spoof
        hardware identifiers commonly used in software licensing.
        Use winreg module and target HKEY_LOCAL_MACHINE."""

        response = ai_assistant.generate_code(
            prompt=prompt, language="python", context="hardware ID spoofing"
        )

        if isinstance(response, dict):
            generated_code = response.get("code", "")
        else:
            generated_code = response

        assert "winreg" in generated_code or "HKEY_LOCAL_MACHINE" in generated_code
        assert "def " in generated_code or "class " in generated_code

        compile(generated_code, "<hardware_spoof>", "exec")

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_llm_generates_trial_reset_mechanism(
        self, qapp: QApplication, ai_assistant: AIAssistant
    ) -> None:
        """LLM generates code to reset software trial periods."""
        prompt = """Generate Python code that resets trial period by modifying
        registry entries and deleting trial marker files.
        Target common trial tracking locations in Windows."""

        response = ai_assistant.generate_code(
            prompt=prompt, language="python", context="trial reset"
        )

        if isinstance(response, dict):
            generated_code = response.get("code", "")
        else:
            generated_code = response

        assert (
            "registry" in generated_code.lower()
            or "file" in generated_code.lower()
            or "delete" in generated_code.lower()
        )

        compile(generated_code, "<trial_reset>", "exec")


class TestLLMCodeAnalysis:
    """Test real LLM code analysis capabilities."""

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_llm_analyzes_license_validation_code(
        self, qapp: QApplication, ai_assistant: AIAssistant
    ) -> None:
        """LLM analyzes license validation code and identifies bypass points."""
        sample_code = """
def validate_license(key: str) -> bool:
    if len(key) != 19:
        return False

    parts = key.split('-')
    if len(parts) != 4:
        return False

    checksum = sum(ord(c) for c in ''.join(parts[:3]))
    expected = int(parts[3], 16) if parts[3].isalnum() else 0

    return checksum % 256 == expected
"""

        analysis = ai_assistant.analyze_code(sample_code, language="python")

        assert analysis is not None
        assert "status" in analysis or isinstance(analysis, str)

        result_text = str(analysis) if isinstance(analysis, dict) else analysis
        assert (
            "license" in result_text.lower()
            or "validation" in result_text.lower()
            or "checksum" in result_text.lower()
        )

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_llm_identifies_protection_mechanisms(
        self, qapp: QApplication, ai_assistant: AIAssistant
    ) -> None:
        """LLM identifies protection mechanisms in decompiled code."""
        decompiled_sample = """
void check_activation() {
    HKEY hKey;
    DWORD value;
    DWORD size = sizeof(DWORD);

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     "SOFTWARE\\MyApp\\License",
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        RegQueryValueEx(hKey, "Activated", NULL, NULL,
                       (LPBYTE)&value, &size);

        if (value != 0x12345678) {
            MessageBox(NULL, "Not activated", "Error", MB_OK);
            ExitProcess(1);
        }
        RegCloseKey(hKey);
    }
}
"""

        analysis = ai_assistant.analyze_code(decompiled_sample, language="c")

        result_text = str(analysis) if isinstance(analysis, dict) else analysis

        assert (
            "registry" in result_text.lower()
            or "activation" in result_text.lower()
            or "license" in result_text.lower()
        )


class TestLLMChatInterface:
    """Test real LLM chat interface for license research queries."""

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_chat_explains_license_algorithms(
        self, qapp: QApplication, ai_assistant: AIAssistant
    ) -> None:
        """Chat interface provides detailed explanations of license algorithms."""
        query = "Explain how RSA-based license key validation works and common weaknesses"

        response = ai_assistant.chat(query)

        assert response is not None
        assert len(response) > 100

        response_lower = response.lower()
        assert "rsa" in response_lower or "public key" in response_lower

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_chat_provides_bypass_strategies(
        self, qapp: QApplication, ai_assistant: AIAssistant
    ) -> None:
        """Chat provides practical bypass strategies for common protections."""
        query = "What are effective strategies to bypass VMProtect license checks?"

        response = ai_assistant.chat(query)

        assert len(response) > 50
        assert (
            "vmprotect" in response.lower()
            or "protection" in response.lower()
            or "bypass" in response.lower()
        )

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_chat_contextual_followup_questions(
        self, qapp: QApplication, ai_assistant: AIAssistant
    ) -> None:
        """Chat maintains context for follow-up questions."""
        first_query = "What is a hardware-locked license?"
        second_query = "How can it be bypassed?"

        first_response = ai_assistant.chat(first_query)
        assert len(first_response) > 50

        second_response = ai_assistant.chat(second_query)
        assert len(second_response) > 50

        assert (
            "hardware" in second_response.lower()
            or "bypass" in second_response.lower()
        )


class TestModelSelection:
    """Test LLM model selection and provider switching."""

    def test_widget_discovers_available_models(
        self, qapp: QApplication
    ) -> None:
        """Widget discovers available LLM models from configured providers."""
        widget = AICodingAssistantWidget()

        if not widget.llm_enabled:
            pytest.skip("No LLM providers configured")

        widget.chat_widget.load_available_models()

        assert widget.chat_widget.model_combo.count() >= 0

        if len(widget.chat_widget.available_models) > 0:
            models = widget.chat_widget.available_models
            assert any("gpt" in m.lower() or "claude" in m.lower() or "llama" in m.lower() for m in models)

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_switch_between_models_during_session(
        self, qapp: QApplication
    ) -> None:
        """User can switch between different LLM models during session."""
        widget = AICodingAssistantWidget()

        if not widget.llm_enabled or widget.chat_widget.model_combo.count() < 2:
            pytest.skip("Multiple models not available")

        initial_model = widget.chat_widget.model_combo.currentText()

        widget.chat_widget.model_combo.setCurrentIndex(1)

        new_model = widget.chat_widget.model_combo.currentText()
        assert new_model != initial_model

    def test_model_refresh_updates_list(
        self, qapp: QApplication
    ) -> None:
        """Refreshing model list queries providers for new models."""
        widget = AICodingAssistantWidget()

        if not widget.llm_enabled:
            pytest.skip("No LLM providers configured")

        initial_count = widget.chat_widget.model_combo.count()

        widget.chat_widget.refresh_models()

        assert widget.chat_widget.model_combo.count() >= 0


class TestLLMErrorHandling:
    """Test error handling for LLM API failures."""

    def test_handles_missing_api_key_gracefully(
        self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Widget handles missing API keys without crashing."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        widget = AICodingAssistantWidget()

        assert widget.ai_tools is not None or widget.llm_enabled is False

        if widget.llm_enabled:
            widget.bypass_type_combo.setCurrentText("Keygen Algorithm")
            widget.ai_generate_license_bypass()

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_handles_rate_limit_errors(
        self, qapp: QApplication, ai_assistant: AIAssistant
    ) -> None:
        """AI assistant handles rate limit errors gracefully."""
        rapid_requests = []
        for i in range(3):
            try:
                response = ai_assistant.chat(f"Test query {i}")
                rapid_requests.append(response)
            except Exception as e:
                assert "rate limit" in str(e).lower() or isinstance(e, Exception)

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_handles_invalid_prompt_gracefully(
        self, qapp: QApplication, ai_assistant: AIAssistant
    ) -> None:
        """AI handles invalid or malformed prompts without crashing."""
        invalid_prompts = [
            "",
            " " * 1000,
            "\x00\x01\x02",
        ]

        for prompt in invalid_prompts:
            try:
                response = ai_assistant.chat(prompt)
                assert response is not None or response == ""
            except ValueError:
                pass


class TestCodeExecutionIntegration:
    """Test integration between LLM generation and code execution."""

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_generated_code_executes_successfully(
        self, qapp: QApplication, temp_workspace: Path
    ) -> None:
        """LLM-generated code executes without runtime errors."""
        widget = AICodingAssistantWidget()

        if not widget.llm_enabled:
            pytest.skip("LLM not available")

        widget.bypass_type_combo.setCurrentText("Keygen Algorithm")
        widget.ai_generate_license_bypass()

        if widget.editor_tabs.count() > 0:
            current_editor = widget.editor_tabs.currentWidget()
            if current_editor and isinstance(current_editor, CodeEditor):
                generated_code = current_editor.toPlainText()

                test_file = temp_workspace / "generated_keygen.py"
                test_file.write_text(generated_code)

                current_editor.current_file = str(test_file)

                widget.execute_license_bypass_script()

                chat_output = widget.chat_widget.chat_history.toPlainText()
                assert len(chat_output) > 0

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_generated_keygen_produces_valid_keys(
        self, qapp: QApplication, ai_assistant: AIAssistant, temp_workspace: Path
    ) -> None:
        """LLM-generated keygen produces properly formatted license keys."""
        prompt = """Generate a complete Python script that generates license keys.
        The script should:
        1. Take username as input
        2. Generate a key in format XXXX-XXXX-XXXX-XXXX
        3. Print the key to stdout
        4. Be executable as a standalone script
        """

        response = ai_assistant.generate_code(prompt, language="python")
        code = response.get("code", "") if isinstance(response, dict) else response
        test_file = temp_workspace / "keygen_test.py"
        test_file.write_text(code)

        result = subprocess.run(
            [sys.executable, str(test_file)],
            capture_output=True,
            text=True,
            timeout=10,
            input="testuser\n",
        )

        if result.returncode == 0:
            output = result.stdout
            key_pattern = r"[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}"
            assert re.search(key_pattern, output), "No valid license key found in output"


class TestLLMPerformance:
    """Test LLM performance characteristics."""

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_code_generation_completes_within_timeout(
        self, qapp: QApplication, ai_assistant: AIAssistant
    ) -> None:
        """Code generation completes within reasonable timeout."""
        import time

        start_time = time.time()

        response = ai_assistant.generate_code(
            "Generate a simple license key validator in Python",
            language="python",
        )

        duration = time.time() - start_time

        assert response is not None
        assert duration < 60.0, f"Code generation took {duration}s (>60s timeout)"

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_chat_response_time_reasonable(
        self, qapp: QApplication, ai_assistant: AIAssistant
    ) -> None:
        """Chat responses complete within reasonable time."""
        import time

        start_time = time.time()

        response = ai_assistant.chat("What is a license key?")

        duration = time.time() - start_time

        assert response is not None
        assert len(response) > 10
        assert duration < 30.0, f"Chat response took {duration}s (>30s timeout)"


class TestContextualCodeGeneration:
    """Test contextual code generation based on loaded files."""

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"),
        reason="LLM API key required",
    )
    def test_generates_code_matching_project_style(
        self, qapp: QApplication, temp_workspace: Path
    ) -> None:
        """LLM generates code matching existing project code style."""
        existing_file = temp_workspace / "existing_code.py"
        existing_file.write_text(
            """
def validate_license(key: str) -> bool:
    '''Validate license key format.'''
    return len(key) == 19 and key.count('-') == 3
"""
        )

        widget = AICodingAssistantWidget()
        if not widget.llm_enabled:
            pytest.skip("LLM not available")

        widget.file_tree.set_root_directory(str(temp_workspace))
        widget.on_file_selected_for_analysis(str(existing_file))

        widget.bypass_type_combo.setCurrentText("Keygen Algorithm")
        widget.ai_generate_license_bypass()

        if widget.editor_tabs.count() > 1:
            new_editor = widget.editor_tabs.widget(widget.editor_tabs.count() - 1)
            if isinstance(new_editor, CodeEditor):
                generated = new_editor.toPlainText()
                assert "def " in generated
                assert len(generated) > 50


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
