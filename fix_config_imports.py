#!/usr/bin/env python3
"""Script to convert top-level config_manager imports to lazy imports."""
import re
import subprocess
from pathlib import Path


def find_files_with_top_level_config_imports():
    """Find all files with top-level config_manager imports."""
    result = subprocess.run(
        ['rg', '--files-with-matches', r'^from intellicrack\.core\.config_manager import', 'intellicrack/'],
        capture_output=True,
        text=True,
        check=False,
        cwd='D:\\Intellicrack',
    )

    if result.returncode != 0:
        return []

    files = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
    return [Path('D:\\Intellicrack') / f for f in files]

def convert_to_lazy_import(file_path) -> bool | None:
    """Convert top-level config_manager imports to lazy imports in a file."""
    try:
        content = file_path.read_text(encoding='utf-8')
        original_content = content

        import_pattern = r'^from intellicrack\.core\.config_manager import (.+)$'

        matches = list(re.finditer(import_pattern, content, re.MULTILINE))
        if not matches:
            return False

        imported_items = []
        for match in matches:
            items = match.group(1).split(',')
            imported_items.extend([item.strip() for item in items])

        content = re.sub(import_pattern, '', content, flags=re.MULTILINE)

        if 'TYPE_CHECKING' not in content:
            content = content.replace(
                'from typing import',
                'from typing import TYPE_CHECKING,',
                1,
            )

            if 'TYPE_CHECKING' not in content:
                import_section_end = content.find('\n\n')
                if import_section_end != -1:
                    content = content[:import_section_end] + '\nfrom typing import TYPE_CHECKING\n' + content[import_section_end:]

        type_check_import = f'\nif TYPE_CHECKING:\n    from intellicrack.core.config_manager import {", ".join(imported_items)}\n'

        import_section_end = content.find('\n\nlogger =')
        if import_section_end == -1:
            import_section_end = content.find('\n\nclass ')
        if import_section_end == -1:
            import_section_end = content.find('\n\ndef ')

        if import_section_end != -1:
            content = content[:import_section_end] + type_check_import + content[import_section_end:]

        for item in imported_items:
            usage_pattern = rf'\b{item}\('
            usage_matches = list(re.finditer(usage_pattern, content))

            if usage_matches:
                for usage_match in usage_matches:
                    func_start = content.rfind('def ', 0, usage_match.start())
                    if func_start != -1:
                        next_def = content.find('\ndef ', func_start + 4)
                        func_body_start = content.find(':\n', func_start) + 2

                        if next_def == -1 or usage_match.start() < next_def:
                            indent_match = re.search(r'\n(\s+)', content[func_body_start:func_body_start+50])
                            indent = indent_match.group(1) if indent_match else '    '

                            lazy_import = f'{indent}from intellicrack.core.config_manager import {item}\n'

                            if lazy_import not in content[func_body_start:func_body_start+200]:
                                content = content[:func_body_start] + lazy_import + content[func_body_start:]

        if content != original_content:
            file_path.write_text(content, encoding='utf-8')
            return True

        return False

    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False


def main() -> None:
    """Run the config import refactoring workflow."""
    files = find_files_with_top_level_config_imports()

    print(f"Found {len(files)} files with top-level config_manager imports")

    converted = 0
    for file_path in files:
        if convert_to_lazy_import(file_path):
            print(f"Converted: {file_path}")
            converted += 1
        else:
            print(f"Skipped: {file_path}")

    print(f"\nConverted {converted} files")

if __name__ == '__main__':
    main()
