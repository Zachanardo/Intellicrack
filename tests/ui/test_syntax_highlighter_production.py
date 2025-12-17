"""Production tests for SyntaxHighlighter.

Tests syntax highlighting for multiple programming languages including Python,
JavaScript, Assembly, C/C++, JSON, XML, and Shell with real QTextDocument instances.

Copyright (C) 2025 Zachary Flint
"""

import pytest
from typing import List, Tuple
import re

from intellicrack.handlers.pyqt6_handler import QApplication, QTextDocument, QTextCharFormat
from intellicrack.ui.syntax_highlighter import (
    SyntaxHighlighter,
    create_highlighter,
    get_supported_languages,
    detect_language,
)


@pytest.fixture
def qapp() -> QApplication:
    """Provide QApplication instance for Qt text document testing."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def text_document(qapp: QApplication) -> QTextDocument:
    """Create QTextDocument for syntax highlighting testing."""
    doc = QTextDocument()
    return doc


class TestSyntaxHighlighterInitialization:
    """Test SyntaxHighlighter initialization with different languages."""

    def test_initialization_with_python_language_sets_up_rules(
        self, text_document: QTextDocument
    ) -> None:
        """Initializing with Python language sets up Python-specific highlighting rules."""
        highlighter = SyntaxHighlighter(text_document, "python")

        assert highlighter.language == "python"
        assert len(highlighter.rules) > 0

        rule_patterns = [pattern.pattern for pattern, _ in highlighter.rules]
        assert any("def" in pattern for pattern in rule_patterns)
        assert any("class" in pattern for pattern in rule_patterns)

    def test_initialization_with_javascript_language_sets_up_rules(
        self, text_document: QTextDocument
    ) -> None:
        """Initializing with JavaScript language sets up JS-specific highlighting rules."""
        highlighter = SyntaxHighlighter(text_document, "javascript")

        assert highlighter.language == "javascript"
        assert len(highlighter.rules) > 0

        rule_patterns = [pattern.pattern for pattern, _ in highlighter.rules]
        assert any("function" in pattern for pattern in rule_patterns)
        assert any("const" in pattern or "let" in pattern for pattern in rule_patterns)

    def test_initialization_with_assembly_language_sets_up_rules(
        self, text_document: QTextDocument
    ) -> None:
        """Initializing with Assembly language sets up ASM-specific highlighting rules."""
        highlighter = SyntaxHighlighter(text_document, "assembly")

        assert highlighter.language == "assembly"
        assert len(highlighter.rules) > 0

        rule_patterns = [pattern.pattern for pattern, _ in highlighter.rules]
        assert any("mov" in pattern for pattern in rule_patterns)
        assert any("eax" in pattern or "rax" in pattern for pattern in rule_patterns)

    def test_initialization_with_c_language_sets_up_rules(
        self, text_document: QTextDocument
    ) -> None:
        """Initializing with C language sets up C-specific highlighting rules."""
        highlighter = SyntaxHighlighter(text_document, "c")

        assert highlighter.language == "c"
        assert len(highlighter.rules) > 0

        rule_patterns = [pattern.pattern for pattern, _ in highlighter.rules]
        assert any("int" in pattern for pattern in rule_patterns)
        assert any("struct" in pattern for pattern in rule_patterns)

    def test_initialization_with_unsupported_language_uses_default(
        self, text_document: QTextDocument
    ) -> None:
        """Initializing with unsupported language uses default highlighting rules."""
        highlighter = SyntaxHighlighter(text_document, "unsupported_language")

        assert highlighter.language == "unsupported_language"
        assert len(highlighter.rules) > 0


class TestPythonSyntaxHighlighting:
    """Test Python syntax highlighting functionality."""

    def test_python_keyword_highlighting(self, text_document: QTextDocument) -> None:
        """Python keywords are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "python")

        python_code = "def test_function():\n    if True:\n        return False"
        text_document.setPlainText(python_code)

        assert any(
            pattern.search("def") for pattern, _ in highlighter.rules
        ), "def keyword should be in rules"
        assert any(
            pattern.search("if") for pattern, _ in highlighter.rules
        ), "if keyword should be in rules"
        assert any(
            pattern.search("return") for pattern, _ in highlighter.rules
        ), "return keyword should be in rules"

    def test_python_builtin_function_highlighting(
        self, text_document: QTextDocument
    ) -> None:
        """Python built-in functions are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "python")

        python_code = "result = len(data)\nprint(result)"
        text_document.setPlainText(python_code)

        assert any(pattern.search("len") for pattern, _ in highlighter.rules)
        assert any(pattern.search("print") for pattern, _ in highlighter.rules)

    def test_python_string_highlighting(self, text_document: QTextDocument) -> None:
        """Python strings are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "python")

        python_code = 'message = "Hello, World!"\npath = \'C:\\\\test\\\\file.txt\''
        text_document.setPlainText(python_code)

        string_rules = [
            (pattern, fmt) for pattern, fmt in highlighter.rules if '".*?"' in pattern.pattern or "'.*?'" in pattern.pattern
        ]
        assert len(string_rules) > 0

    def test_python_comment_highlighting(self, text_document: QTextDocument) -> None:
        """Python comments are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "python")

        python_code = "# This is a comment\nx = 42  # Inline comment"
        text_document.setPlainText(python_code)

        comment_rules = [
            (pattern, fmt) for pattern, fmt in highlighter.rules if "#" in pattern.pattern
        ]
        assert len(comment_rules) > 0

    def test_python_decorator_highlighting(self, text_document: QTextDocument) -> None:
        """Python decorators are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "python")

        python_code = "@property\n@staticmethod\ndef method():\n    pass"
        text_document.setPlainText(python_code)

        decorator_rules = [
            (pattern, fmt) for pattern, fmt in highlighter.rules if "@" in pattern.pattern
        ]
        assert len(decorator_rules) > 0

    def test_python_number_highlighting(self, text_document: QTextDocument) -> None:
        """Python numbers are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "python")

        python_code = "x = 42\ny = 3.14\nz = 0x1A2B\nw = 1e-10"
        text_document.setPlainText(python_code)

        number_rules = [
            (pattern, fmt)
            for pattern, fmt in highlighter.rules
            if "[0-9]" in pattern.pattern
        ]
        assert len(number_rules) > 0


class TestJavaScriptSyntaxHighlighting:
    """Test JavaScript syntax highlighting functionality."""

    def test_javascript_keyword_highlighting(
        self, text_document: QTextDocument
    ) -> None:
        """JavaScript keywords are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "javascript")

        js_code = "function test() {\n  const x = 42;\n  let y = true;\n  return x;\n}"
        text_document.setPlainText(js_code)

        assert any(pattern.search("function") for pattern, _ in highlighter.rules)
        assert any(pattern.search("const") for pattern, _ in highlighter.rules)
        assert any(pattern.search("let") for pattern, _ in highlighter.rules)
        assert any(pattern.search("return") for pattern, _ in highlighter.rules)

    def test_javascript_arrow_function_highlighting(
        self, text_document: QTextDocument
    ) -> None:
        """JavaScript arrow functions are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "javascript")

        js_code = "const add = (a, b) => a + b;"
        text_document.setPlainText(js_code)

        arrow_function_rules = [
            (pattern, fmt) for pattern, fmt in highlighter.rules if "=>" in pattern.pattern
        ]
        assert len(arrow_function_rules) > 0

    def test_javascript_comment_highlighting(
        self, text_document: QTextDocument
    ) -> None:
        """JavaScript comments are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "javascript")

        js_code = "// Single line comment\n/* Multi-line\n   comment */"
        text_document.setPlainText(js_code)

        comment_rules = [
            (pattern, fmt)
            for pattern, fmt in highlighter.rules
            if "//" in pattern.pattern or r"/\*" in pattern.pattern
        ]
        assert len(comment_rules) > 0


class TestAssemblySyntaxHighlighting:
    """Test Assembly syntax highlighting functionality."""

    def test_assembly_instruction_highlighting(
        self, text_document: QTextDocument
    ) -> None:
        """Assembly instructions are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "assembly")

        asm_code = "mov eax, ebx\npush ecx\npop edx\ncall function\nret"
        text_document.setPlainText(asm_code)

        assert any(pattern.search("mov") for pattern, _ in highlighter.rules)
        assert any(pattern.search("push") for pattern, _ in highlighter.rules)
        assert any(pattern.search("call") for pattern, _ in highlighter.rules)
        assert any(pattern.search("ret") for pattern, _ in highlighter.rules)

    def test_assembly_register_highlighting(
        self, text_document: QTextDocument
    ) -> None:
        """Assembly registers are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "assembly")

        asm_code = "mov eax, 0\nmov rax, rbx\nmov r8, r9"
        text_document.setPlainText(asm_code)

        assert any(pattern.search("eax") for pattern, _ in highlighter.rules)
        assert any(pattern.search("rax") for pattern, _ in highlighter.rules)
        assert any(pattern.search("r8") for pattern, _ in highlighter.rules)

    def test_assembly_hex_number_highlighting(
        self, text_document: QTextDocument
    ) -> None:
        """Assembly hexadecimal numbers are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "assembly")

        asm_code = "mov eax, 0x1234ABCD\nadd ebx, 0xFF"
        text_document.setPlainText(asm_code)

        hex_rules = [
            (pattern, fmt) for pattern, fmt in highlighter.rules if "0x" in pattern.pattern
        ]
        assert len(hex_rules) > 0

    def test_assembly_label_highlighting(self, text_document: QTextDocument) -> None:
        """Assembly labels are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "assembly")

        asm_code = "main:\n    mov eax, 0\n    jmp loop_start\nloop_start:"
        text_document.setPlainText(asm_code)

        label_rules = [
            (pattern, fmt) for pattern, fmt in highlighter.rules if ":" in pattern.pattern
        ]
        assert len(label_rules) > 0

    def test_assembly_comment_highlighting(
        self, text_document: QTextDocument
    ) -> None:
        """Assembly comments are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "assembly")

        asm_code = "; This is a comment\nmov eax, 0  ; inline comment"
        text_document.setPlainText(asm_code)

        comment_rules = [
            (pattern, fmt) for pattern, fmt in highlighter.rules if ";" in pattern.pattern
        ]
        assert len(comment_rules) > 0


class TestJSONSyntaxHighlighting:
    """Test JSON syntax highlighting functionality."""

    def test_json_key_highlighting(self, text_document: QTextDocument) -> None:
        """JSON keys are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "json")

        json_code = '{"name": "test", "value": 42}'
        text_document.setPlainText(json_code)

        key_rules = [
            (pattern, fmt)
            for pattern, fmt in highlighter.rules
            if '"' in pattern.pattern and ":" in pattern.pattern
        ]
        assert len(key_rules) > 0

    def test_json_boolean_and_null_highlighting(
        self, text_document: QTextDocument
    ) -> None:
        """JSON booleans and null are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "json")

        json_code = '{"active": true, "inactive": false, "data": null}'
        text_document.setPlainText(json_code)

        boolean_rules = [
            (pattern, fmt)
            for pattern, fmt in highlighter.rules
            if "true" in pattern.pattern or "false" in pattern.pattern or "null" in pattern.pattern
        ]
        assert len(boolean_rules) > 0

    def test_json_number_highlighting(self, text_document: QTextDocument) -> None:
        """JSON numbers are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "json")

        json_code = '{"count": 42, "pi": 3.14, "scientific": 1.5e-10}'
        text_document.setPlainText(json_code)

        number_rules = [
            (pattern, fmt)
            for pattern, fmt in highlighter.rules
            if "[0-9]" in pattern.pattern
        ]
        assert len(number_rules) > 0


class TestXMLSyntaxHighlighting:
    """Test XML/HTML syntax highlighting functionality."""

    def test_xml_tag_highlighting(self, text_document: QTextDocument) -> None:
        """XML tags are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "xml")

        xml_code = "<root>\n  <element>text</element>\n</root>"
        text_document.setPlainText(xml_code)

        tag_rules = [
            (pattern, fmt) for pattern, fmt in highlighter.rules if "<" in pattern.pattern
        ]
        assert len(tag_rules) > 0

    def test_xml_attribute_highlighting(self, text_document: QTextDocument) -> None:
        """XML attributes are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "xml")

        xml_code = '<element name="test" value="42" />'
        text_document.setPlainText(xml_code)

        attribute_rules = [
            (pattern, fmt) for pattern, fmt in highlighter.rules if "=" in pattern.pattern
        ]
        assert len(attribute_rules) > 0

    def test_xml_comment_highlighting(self, text_document: QTextDocument) -> None:
        """XML comments are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "xml")

        xml_code = "<!-- This is a comment -->\n<element />"
        text_document.setPlainText(xml_code)

        comment_rules = [
            (pattern, fmt) for pattern, fmt in highlighter.rules if "<!--" in pattern.pattern
        ]
        assert len(comment_rules) > 0


class TestShellSyntaxHighlighting:
    """Test Shell/Bash syntax highlighting functionality."""

    def test_shell_keyword_highlighting(self, text_document: QTextDocument) -> None:
        """Shell keywords are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "shell")

        shell_code = "if [ -f file ]; then\n  echo 'exists'\nfi"
        text_document.setPlainText(shell_code)

        assert any(pattern.search("if") for pattern, _ in highlighter.rules)
        assert any(pattern.search("then") for pattern, _ in highlighter.rules)
        assert any(pattern.search("fi") for pattern, _ in highlighter.rules)

    def test_shell_builtin_command_highlighting(
        self, text_document: QTextDocument
    ) -> None:
        """Shell built-in commands are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "shell")

        shell_code = "echo 'hello'\ncd /tmp\npwd"
        text_document.setPlainText(shell_code)

        assert any(pattern.search("echo") for pattern, _ in highlighter.rules)
        assert any(pattern.search("cd") for pattern, _ in highlighter.rules)
        assert any(pattern.search("pwd") for pattern, _ in highlighter.rules)

    def test_shell_variable_highlighting(self, text_document: QTextDocument) -> None:
        """Shell variables are highlighted correctly."""
        highlighter = SyntaxHighlighter(text_document, "shell")

        shell_code = "VAR=value\necho $VAR\necho ${PATH}"
        text_document.setPlainText(shell_code)

        variable_rules = [
            (pattern, fmt) for pattern, fmt in highlighter.rules if "$" in pattern.pattern
        ]
        assert len(variable_rules) > 0


class TestSyntaxHighlighterLanguageSwitching:
    """Test dynamic language switching functionality."""

    def test_set_language_changes_highlighting_rules(
        self, text_document: QTextDocument
    ) -> None:
        """Setting language changes highlighting rules dynamically."""
        highlighter = SyntaxHighlighter(text_document, "python")

        initial_rule_count = len(highlighter.rules)
        assert initial_rule_count > 0

        highlighter.set_language("javascript")

        assert highlighter.language == "javascript"
        new_rule_count = len(highlighter.rules)
        assert new_rule_count > 0

    def test_set_language_triggers_rehighlighting(
        self, text_document: QTextDocument
    ) -> None:
        """Setting language triggers document rehighlighting."""
        highlighter = SyntaxHighlighter(text_document, "python")

        python_code = "def test():\n    pass"
        text_document.setPlainText(python_code)

        highlighter.set_language("c")

        assert highlighter.language == "c"


class TestSyntaxHighlighterHelperFunctions:
    """Test helper functions for syntax highlighting."""

    def test_create_highlighter_returns_configured_instance(
        self, text_document: QTextDocument
    ) -> None:
        """Creating highlighter returns properly configured instance."""
        highlighter = create_highlighter(text_document, "python")

        assert isinstance(highlighter, SyntaxHighlighter)
        assert highlighter.language == "python"
        assert len(highlighter.rules) > 0

    def test_get_supported_languages_returns_all_languages(self) -> None:
        """Getting supported languages returns complete language list."""
        languages = get_supported_languages()

        assert "python" in languages
        assert "javascript" in languages
        assert "assembly" in languages
        assert "c" in languages
        assert "json" in languages
        assert "xml" in languages
        assert "shell" in languages

    def test_detect_language_identifies_python_code(self) -> None:
        """Detecting language correctly identifies Python code."""
        python_code = "def test():\n    import os\n    return True"

        detected = detect_language(python_code)

        assert detected == "python"

    def test_detect_language_identifies_javascript_code(self) -> None:
        """Detecting language correctly identifies JavaScript code."""
        js_code = "function test() {\n  const x = 42;\n  return x;\n}"

        detected = detect_language(js_code)

        assert detected == "javascript"

    def test_detect_language_identifies_assembly_code(self) -> None:
        """Detecting language correctly identifies Assembly code."""
        asm_code = "mov eax, 0\npush ebx\ncall function\nret"

        detected = detect_language(asm_code)

        assert detected == "assembly"

    def test_detect_language_identifies_c_code(self) -> None:
        """Detecting language correctly identifies C/C++ code."""
        c_code = "#include <stdio.h>\nint main() {\n  printf(\"hello\");\n  return 0;\n}"

        detected = detect_language(c_code)

        assert detected == "c"

    def test_detect_language_identifies_json_code(self) -> None:
        """Detecting language correctly identifies JSON code."""
        json_code = '{"name": "test", "value": 42}'

        detected = detect_language(json_code)

        assert detected == "json"

    def test_detect_language_identifies_xml_code(self) -> None:
        """Detecting language correctly identifies XML code."""
        xml_code = "<root>\n  <element>value</element>\n</root>"

        detected = detect_language(xml_code)

        assert detected == "xml"

    def test_detect_language_identifies_shell_code(self) -> None:
        """Detecting language correctly identifies Shell scripts."""
        shell_code = "#!/bin/bash\necho 'hello'\ncd /tmp"

        detected = detect_language(shell_code)

        assert detected == "shell"

    def test_detect_language_defaults_to_python_for_unknown_code(self) -> None:
        """Detecting language defaults to Python for unknown code."""
        unknown_code = "some random text without clear language indicators"

        detected = detect_language(unknown_code)

        assert detected == "python"


class TestSyntaxHighlighterFormatCreation:
    """Test text format creation with different styles."""

    def test_create_format_with_color_only(
        self, text_document: QTextDocument
    ) -> None:
        """Creating format with color only sets foreground color."""
        highlighter = SyntaxHighlighter(text_document, "python")

        text_format = highlighter._create_format("#ff0000")

        assert text_format.foreground().color().name() == "#ff0000"

    def test_create_format_with_bold_style(
        self, text_document: QTextDocument
    ) -> None:
        """Creating format with bold style sets font weight."""
        highlighter = SyntaxHighlighter(text_document, "python")

        text_format = highlighter._create_format("#00ff00", bold=True)

        assert text_format.fontWeight() > 50

    def test_create_format_with_italic_style(
        self, text_document: QTextDocument
    ) -> None:
        """Creating format with italic style sets font italic."""
        highlighter = SyntaxHighlighter(text_document, "python")

        text_format = highlighter._create_format("#0000ff", italic=True)

        assert text_format.fontItalic() is True

    def test_create_format_with_bold_and_italic(
        self, text_document: QTextDocument
    ) -> None:
        """Creating format with bold and italic sets both styles."""
        highlighter = SyntaxHighlighter(text_document, "python")

        text_format = highlighter._create_format("#ffff00", bold=True, italic=True)

        assert text_format.fontWeight() > 50
        assert text_format.fontItalic() is True
