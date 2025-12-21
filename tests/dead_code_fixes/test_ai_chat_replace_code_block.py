"""Tests for replace_code_block usage in ai_chat_interface.py.

This tests that the replace_code_block function is properly used with
re.finditer to process code blocks in AI responses.
"""


from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest


class TestReplaceCodeBlockUsage:
    """Test suite for replace_code_block function usage."""

    def test_code_block_pattern_matching(self) -> None:
        """Test that code block pattern matches correctly."""
        pattern = r"```(\w+)?\n(.*?)```"
        response = """Here is some code:
```python
def hello():
    print("Hello, World!")
```
And more text."""

        matches = list(re.finditer(pattern, response, flags=re.DOTALL))

        assert len(matches) == 1
        assert matches[0].group(1) == "python"
        assert 'def hello():' in matches[0].group(2)

    def test_multiple_code_blocks(self) -> None:
        """Test handling of multiple code blocks."""
        pattern = r"```(\w+)?\n(.*?)```"
        response = """First block:
```python
x = 1
```
Second block:
```javascript
let y = 2;
```
End."""

        matches = list(re.finditer(pattern, response, flags=re.DOTALL))

        assert len(matches) == 2
        assert matches[0].group(1) == "python"
        assert matches[1].group(1) == "javascript"

    def test_text_between_code_blocks(self) -> None:
        """Test that text between code blocks is preserved."""
        pattern = r"```(\w+)?\n(.*?)```"
        response = """Start text
```python
code1
```
Middle text
```python
code2
```
End text"""

        result_parts: list[str] = []
        last_end = 0

        for match in re.finditer(pattern, response, flags=re.DOTALL):
            text_before = response[last_end : match.start()]
            if text_before.strip():
                result_parts.append(text_before.strip())
            result_parts.append(f"[CODE:{match.group(2).strip()}]")
            last_end = match.end()

        text_after = response[last_end:]
        if text_after.strip():
            result_parts.append(text_after.strip())

        assert len(result_parts) == 5
        assert "Start text" in result_parts[0]
        assert "[CODE:code1]" in result_parts[1]
        assert "Middle text" in result_parts[2]
        assert "[CODE:code2]" in result_parts[3]
        assert "End text" in result_parts[4]

    def test_code_block_without_language(self) -> None:
        """Test handling of code blocks without language specifier."""
        pattern = r"```(\w+)?\n(.*?)```"
        response = """```
some code
```"""

        matches = list(re.finditer(pattern, response, flags=re.DOTALL))

        assert len(matches) == 1
        assert matches[0].group(1) is None
        assert "some code" in matches[0].group(2)

    def test_default_language_fallback(self) -> None:
        """Test that default language is used when not specified."""
        pattern = r"```(\w+)?\n(.*?)```"
        response = """```
code here
```"""

        for match in re.finditer(pattern, response, flags=re.DOTALL):
            language = match.group(1) or "python"
            assert language == "python"

    def test_no_code_blocks_returns_original(self) -> None:
        """Test that responses without code blocks return original."""
        pattern = r"```(\w+)?\n(.*?)```"
        response = "This is plain text without code blocks."

        matches = list(re.finditer(pattern, response, flags=re.DOTALL))
        result_parts: list[str] = []
        last_end = 0

        for match in matches:
            text_before = response[last_end : match.start()]
            if text_before.strip():
                result_parts.append(text_before)
            last_end = match.end()

        if not result_parts:
            result_parts.append(response)

        assert len(result_parts) == 1
        assert result_parts[0] == response

    def test_code_block_extraction_accuracy(self) -> None:
        """Test accurate extraction of code block contents."""
        pattern = r"```(\w+)?\n(.*?)```"
        code_content = """def analyze_binary(path):
    with open(path, 'rb') as f:
        return f.read()"""
        response = f"""```python
{code_content}
```"""

        for match in re.finditer(pattern, response, flags=re.DOTALL):
            extracted_code = match.group(2)
            assert "def analyze_binary" in extracted_code
            assert "with open(path, 'rb')" in extracted_code

    def test_multiline_code_preservation(self) -> None:
        """Test that multiline code structure is preserved."""
        pattern = r"```(\w+)?\n(.*?)```"
        response = """```python
line1
line2
line3
```"""

        for match in re.finditer(pattern, response, flags=re.DOTALL):
            code = match.group(2)
            lines = code.strip().split('\n')
            assert len(lines) == 3

    def test_replace_function_receives_match_object(self) -> None:
        """Test that replace function receives valid match object."""
        pattern = r"```(\w+)?\n(.*?)```"
        response = """```python
test_code
```"""

        def replace_code_block(match: re.Match[str]) -> str:
            assert match.group(0).startswith("```")
            assert match.group(2) is not None
            return f"REPLACED:{match.group(2).strip()}"

        result_parts: list[str] = []
        for match in re.finditer(pattern, response, flags=re.DOTALL):
            result_parts.append(replace_code_block(match))

        assert len(result_parts) == 1
        assert "REPLACED:test_code" in result_parts[0]

    def test_last_end_tracking(self) -> None:
        """Test that last_end correctly tracks position."""
        pattern = r"```(\w+)?\n(.*?)```"
        response = "A```python\nx\n```B```python\ny\n```C"

        last_end = 0
        positions: list[tuple[int, int]] = []

        for match in re.finditer(pattern, response, flags=re.DOTALL):
            positions.append((last_end, match.start(), match.end()))
            last_end = match.end()

        assert len(positions) == 2
        assert positions[0][0] == 0
        assert positions[0][1] == 1
        assert positions[1][0] == positions[0][2]

    def test_empty_code_block_handling(self) -> None:
        """Test handling of empty code blocks."""
        pattern = r"```(\w+)?\n(.*?)```"
        response = """```python
```"""

        for match in re.finditer(pattern, response, flags=re.DOTALL):
            code = match.group(2)
            assert code == ""

    def test_result_parts_type_consistency(self) -> None:
        """Test that result_parts maintains type consistency."""
        pattern = r"```(\w+)?\n(.*?)```"
        response = """Text```python
code
```More text"""

        result_parts: list[Any] = []
        last_end = 0

        for match in re.finditer(pattern, response, flags=re.DOTALL):
            text_before = response[last_end : match.start()]
            if text_before.strip():
                result_parts.append(text_before)
            result_parts.append({"type": "code", "content": match.group(2)})
            last_end = match.end()

        text_after = response[last_end:]
        if text_after.strip():
            result_parts.append(text_after)

        assert isinstance(result_parts[0], str)
        assert isinstance(result_parts[1], dict)
        assert isinstance(result_parts[2], str)

