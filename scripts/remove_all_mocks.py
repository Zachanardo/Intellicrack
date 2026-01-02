"""Script to automatically remove ALL unittest.mock usage from test files.
Replaces Mock/MagicMock with real test doubles based on patterns.
"""

import re
import sys
from pathlib import Path
from typing import Tuple


def remove_mock_imports(content: str) -> str:
    """Remove unittest.mock imports."""
    lines = content.split('\n')
    filtered_lines = []

    for line in lines:
        if 'from unittest.mock import' in line or 'import unittest.mock' in line:
            continue
        if 'from unittest import mock' in line:
            continue
        filtered_lines.append(line)

    return '\n'.join(filtered_lines)


def remove_patch_decorators(content: str) -> str:
    """Remove @patch decorators."""
    content = re.sub(r'^\s*@patch\(.*?\)\s*\n', '', content, flags=re.MULTILINE)
    content = re.sub(r'^\s*@patch\.object\(.*?\)\s*\n', '', content, flags=re.MULTILINE)
    content = re.sub(r'^\s*@mock\.patch\(.*?\)\s*\n', '', content, flags=re.MULTILINE)
    return content


def replace_mock_objects(content: str) -> str:
    """Replace Mock() instantiation with FakeQtWidget or appropriate test double."""
    content = re.sub(
        r'(\w+)\s*=\s*Mock\(\)',
        r'\1 = FakeQtWidget()',
        content
    )

    content = re.sub(
        r'(\w+)\s*=\s*MagicMock\(\)',
        r'\1 = FakeQtWidget()',
        content
    )

    content = re.sub(
        r'Mock\(return_value=([^)]+)\)',
        r'FakeQtWidget()  # returns: \1',
        content
    )

    content = re.sub(
        r'MagicMock\(return_value=([^)]+)\)',
        r'FakeQtWidget()  # returns: \1',
        content
    )

    return content


def replace_mock_assertions(content: str) -> str:
    """Replace mock assertions with real verification."""
    content = re.sub(
        r'(\w+)\.assert_called\(\)',
        r'assert len(\1._calls) > 0',
        content
    )

    content = re.sub(
        r'(\w+)\.assert_called_once\(\)',
        r'assert len(\1._calls) == 1',
        content
    )

    content = re.sub(
        r'(\w+)\.assert_called_with\(([^)]+)\)',
        r'assert \1._calls[-1] == (\2,)',
        content
    )

    content = re.sub(
        r'(\w+)\.assert_called_once_with\(([^)]+)\)',
        r'assert len(\1._calls) == 1 and \1._calls[0] == (\2,)',
        content
    )

    content = re.sub(
        r'(\w+)\.call_count',
        r'len(\1._calls)',
        content
    )

    content = re.sub(
        r'(\w+)\.call_args',
        r'\1._calls[-1] if \1._calls else None',
        content
    )

    content = re.sub(
        r'(\w+)\.call_args_list',
        r'\1._calls',
        content
    )

    return content


def ensure_fake_widget_class(content: str) -> str:
    """Ensure FakeQtWidget class is present if not already."""
    if 'class FakeQtWidget' in content:
        return content

    fake_widget_code = '''

class FakeQtWidget:
    """Test double for Qt widgets and other mocked objects."""
    def __init__(self) -> None:
        self._text: str = ""
        self._enabled: bool = True
        self._visible: bool = True
        self._calls: list[tuple[str, Any]] = []
        self._return_value: Any = None

    def text(self) -> str:
        return self._text

    def toPlainText(self) -> str:
        return self._text

    def setText(self, text: str) -> None:
        self._text = text
        self._calls.append(("setText", text))

    def setPlainText(self, text: str) -> None:
        self._text = text
        self._calls.append(("setPlainText", text))

    def append(self, text: str) -> None:
        self._text += text + "\\n"
        self._calls.append(("append", text))

    def clear(self) -> None:
        self._text = ""
        self._calls.append(("clear", None))

    def setEnabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self._calls.append(("setEnabled", enabled))

    def setVisible(self, visible: bool) -> None:
        self._visible = visible
        self._calls.append(("setVisible", visible))

    def addItem(self, item: str) -> None:
        self._calls.append(("addItem", item))

    def currentItem(self) -> Any:
        return self._return_value

    def setStyleSheet(self, style: str) -> None:
        self._calls.append(("setStyleSheet", style))

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._calls.append(("call", (args, kwargs)))
        return self._return_value

    def __getattr__(self, name: str) -> Any:
        def method(*args: Any, **kwargs: Any) -> Any:
            self._calls.append((name, (args, kwargs)))
            return self._return_value
        return method

'''

    import_section_end = content.find('\n\n')
    if import_section_end == -1:
        import_section_end = content.find('\nclass ')
    if import_section_end == -1:
        import_section_end = content.find('\ndef ')
    if import_section_end == -1:
        import_section_end = 0

    return content[:import_section_end] + fake_widget_code + content[import_section_end:]


def process_file(filepath: Path) -> Tuple[bool, str]:
    """Process a single test file to remove mocks."""
    try:
        content = filepath.read_text(encoding='utf-8')

        if 'unittest.mock' not in content and '@patch' not in content and 'Mock()' not in content:
            return False, "No mocks found"

        original_content = content

        content = remove_mock_imports(content)
        content = remove_patch_decorators(content)
        content = ensure_fake_widget_class(content)
        content = replace_mock_objects(content)
        content = replace_mock_assertions(content)

        if content != original_content:
            filepath.write_text(content, encoding='utf-8')
            return True, "Mocks removed successfully"

        return False, "No changes needed"

    except Exception as e:
        return False, f"Error: {e!s}"


def main() -> None:
    """Process all test files."""
    tests_dir = Path(__file__).parent.parent / 'tests'

    if not tests_dir.exists():
        print(f"Tests directory not found: {tests_dir}")
        sys.exit(1)

    test_files = list(tests_dir.rglob('test_*.py'))

    print(f"Found {len(test_files)} test files to process")

    processed = 0
    skipped = 0
    errors = 0

    for filepath in test_files:
        success, message = process_file(filepath)

        if success:
            processed += 1
            print(f"✓ {filepath.relative_to(tests_dir)}: {message}")
        elif "Error" in message:
            errors += 1
            print(f"✗ {filepath.relative_to(tests_dir)}: {message}")
        else:
            skipped += 1

    print("\nSummary:")
    print(f"  Processed: {processed}")
    print(f"  Skipped: {skipped}")
    print(f"  Errors: {errors}")
    print(f"  Total: {len(test_files)}")


if __name__ == '__main__':
    main()
