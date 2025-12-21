#!/usr/bin/env python3
"""
Fix remaining Phase 1 linting errors.
Targets the 101 remaining errors after initial fixes.
"""

import re
from pathlib import Path


def fix_module_imports_not_at_top(filepath: Path) -> bool:
    """Fix E402 - Module imports not at top of file."""
    content = filepath.read_text()
    lines = content.split('\n')

    # Find all import lines that come after non-import lines
    imports = []
    non_imports = []
    docstring_complete = False
    in_docstring = False
    docstring_quote = None

    for line in lines:
        stripped = line.strip()

        # Handle docstrings
        if not docstring_complete:
            if not in_docstring:
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    docstring_quote = '"""' if stripped.startswith('"""') else "'''"
                    in_docstring = True
                    non_imports.append(line)
                    if stripped.count(docstring_quote) >= 2:
                        in_docstring = False
                        docstring_complete = True
                    continue
            else:
                non_imports.append(line)
                if docstring_quote in stripped:
                    in_docstring = False
                    docstring_complete = True
                continue

        # After docstring, collect imports
        if stripped.startswith('import ') or stripped.startswith('from '):
            imports.append(line)
        elif stripped == '' or stripped.startswith('#'):
            # Empty lines and comments between imports are OK
            if imports and not any(l.strip() and not l.strip().startswith('#') and not l.strip().startswith('import') and not l.strip().startswith('from') for l in non_imports[len(non_imports)-10:] if non_imports):
                imports.append(line)
            else:
                non_imports.append(line)
        else:
            non_imports.append(line)

    # If we found imports mixed with non-imports, reorganize
    if imports and any(not line.strip().startswith('#') and line.strip() != '' and not line.strip().startswith('import') and not line.strip().startswith('from') for line in non_imports[2:]):
        # Reconstruct file with imports at top
        new_content = []

        # Add initial docstring/comments
        for line in non_imports[:2]:  # Keep first lines (shebang, docstring start)
            if line.strip().startswith('#!') or '"""' in line or "'''" in line:
                new_content.append(line)

        # Add the rest of docstring
        docstring_end = -1
        for i, line in enumerate(non_imports[2:], 2):
            if '"""' in line or "'''" in line:
                new_content.extend(non_imports[2:i+1])
                docstring_end = i
                break

        # Add blank line after docstring
        new_content.append('')

        # Add all imports
        if 'import logging' not in '\n'.join(imports) and 'logger.' in content:
            imports.insert(0, 'import logging')
            imports.insert(1, '')
            imports.insert(2, 'logger = logging.getLogger(__name__)')

        new_content.extend(imports)

        # Add blank line after imports
        new_content.append('')

        # Add the rest of the file
        start_idx = docstring_end + 1 if docstring_end > 0 else 0
        for line in non_imports[start_idx:]:
            if not (line.strip().startswith('import ') or line.strip().startswith('from ')):
                new_content.append(line)

        # Write back
        filepath.write_text('\n'.join(new_content))
        return True

    return False


def fix_undefined_process_basic_information(filepath: Path) -> bool:
    """Fix F821 - Undefined name 'PROCESS_BASIC_INFORMATION'."""
    content = filepath.read_text()

    # Add the class definition before it's used
    if 'PROCESS_BASIC_INFORMATION' in content and 'class PROCESS_BASIC_INFORMATION' not in content and 'class ProcessBasicInformation' not in content:
        # Find where to insert the class
        lines = content.split('\n')
        insert_idx = -1

        # Look for the line before first usage
        for i, line in enumerate(lines):
            if 'PROCESS_BASIC_INFORMATION()' in line:
                # Find the function/method this is in
                for j in range(i-1, -1, -1):
                    if line[j].strip().startswith('def '):
                        insert_idx = j
                        break
                break

        if insert_idx > 0:
            # Insert the class definition
            pbi_class = """
class ProcessBasicInformation(ctypes.Structure):
    \"\"\"Windows PROCESS_BASIC_INFORMATION structure.\"\"\"
    _fields_ = [
        ('Reserved1', ctypes.c_void_p),
        ('PebBaseAddress', ctypes.c_void_p),
        ('Reserved2', ctypes.c_void_p * 2),
        ('UniqueProcessId', ctypes.c_void_p),
        ('Reserved3', ctypes.c_void_p)
    ]
"""
            lines.insert(insert_idx, pbi_class)

            # Also fix the usage
            content = '\n'.join(lines)
            content = content.replace('PROCESS_BASIC_INFORMATION()', 'ProcessBasicInformation()')

            filepath.write_text(content)
            return True

    return False


def fix_subprocess_security(filepath: Path) -> bool:
    """Fix S603/S607 - Subprocess security issues."""
    content = filepath.read_text()
    original = content

    # Fix shell=True to shell=False (already done mostly)
    content = content.replace('shell=True', 'shell=False')

    # Fix partial paths - add full paths for common Windows executables
    replacements = [
        ("'ipconfig'", "'C:\\\\Windows\\\\System32\\\\ipconfig.exe'"),
        ('"ipconfig"', '"C:\\\\Windows\\\\System32\\\\ipconfig.exe"'),
        ("'msiexec'", "'C:\\\\Windows\\\\System32\\\\msiexec.exe'"),
        ('"msiexec"', '"C:\\\\Windows\\\\System32\\\\msiexec.exe"'),
        ("'wmic'", "'C:\\\\Windows\\\\System32\\\\wbem\\\\wmic.exe'"),
        ('"wmic"', '"C:\\\\Windows\\\\System32\\\\wbem\\\\wmic.exe"'),
        ("'cmd'", "'C:\\\\Windows\\\\System32\\\\cmd.exe'"),
        ('"cmd"', '"C:\\\\Windows\\\\System32\\\\cmd.exe"'),
        ("'powershell'", "'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe'"),
        ('"powershell"', '"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"'),
    ]

    for old_cmd, new_cmd in replacements:
        content = content.replace(old_cmd, new_cmd)

    if content != original:
        filepath.write_text(content)
        return True

    return False


def fix_try_except_pass(filepath: Path) -> bool:
    """Fix S110 - Try-except-pass patterns."""
    content = filepath.read_text()
    original = content

    # Pattern 1: except: pass
    content = re.sub(
        r'except:\s*\n\s*pass',
        'except Exception as e:\n                logger.debug(f"Suppressed exception: {e}")',
        content
    )

    # Pattern 2: except Exception: pass
    content = re.sub(
        r'except Exception:\s*\n\s*pass',
        'except Exception as e:\n                logger.debug(f"Suppressed exception: {e}")',
        content
    )

    # Pattern 3: except [SpecificError]: pass
    content = re.sub(
        r'except (\w+):\s*\n\s*pass',
        r'except \1 as e:\n                logger.debug(f"Suppressed \1: {e}")',
        content
    )

    # Add logging import if needed
    if content != original and 'import logging' not in content:
        lines = content.split('\n')
        # Find where to add import
        for i, line in enumerate(lines):
            if line.strip().startswith('import ') or line.strip().startswith('from '):
                continue
            lines.insert(i, 'import logging')
            lines.insert(i+1, '')
            lines.insert(i+2, 'logger = logging.getLogger(__name__)')
            break
        content = '\n'.join(lines)

    if content != original:
        filepath.write_text(content)
        return True

    return False


def fix_random_security(filepath: Path) -> bool:
    """Fix S311 - Non-cryptographic random for security."""
    content = filepath.read_text()
    original = content

    # Add secrets import if using random for security
    if 'random.randint' in content or 'random.random' in content or 'random.uniform' in content:
        if 'import secrets' not in content:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'import random' in line:
                    lines.insert(i+1, 'import secrets')
                    content = '\n'.join(lines)
                    break

        # Replace random calls with secrets
        content = re.sub(
            r'random\.randint\((\d+),\s*(\d+)\)',
            r'secrets.randbelow(\2 - \1 + 1) + \1',
            content
        )

        content = re.sub(
            r'random\.random\(\)',
            r'secrets.SystemRandom().random()',
            content
        )

        content = re.sub(
            r'random\.uniform\(([\d.]+),\s*([\d.]+)\)',
            r'secrets.SystemRandom().uniform(\1, \2)',
            content
        )

    if content != original:
        filepath.write_text(content)
        return True

    return False


def fix_hashlib_security(filepath: Path) -> bool:
    """Fix S324 - Insecure hash function."""
    content = filepath.read_text()
    original = content

    # Replace MD5 and SHA1 with SHA256 for non-legacy use
    content = re.sub(
        r'hashlib\.md5\(',
        'hashlib.sha256(',
        content
    )

    content = re.sub(
        r'hashlib\.sha1\(',
        'hashlib.sha256(',
        content
    )

    if content != original:
        filepath.write_text(content)
        return True

    return False


def main():
    """Fix all remaining Phase 1 errors."""
    print("=== Fixing Remaining Phase 1 Errors ===\n")

    files = [
        Path(r"D:\Intellicrack\tests\validation_system\environment_validator.py"),
        Path(r"D:\Intellicrack\tests\validation_system\multi_environment_tester.py"),
        Path(r"D:\Intellicrack\tests\validation_system\anti_detection_verifier.py"),
        Path(r"D:\Intellicrack\tests\validation_system\fingerprint_randomizer.py"),
        Path(r"D:\Intellicrack\tests\validation_system\certified_ground_truth_profile.py"),
        Path(r"D:\Intellicrack\tests\validation_system\runner.py"),
        Path(r"D:\Intellicrack\tests\validation_system\commercial_binary_manager.py")
    ]

    for filepath in files:
        if not filepath.exists():
            print(f"Skipping {filepath.name} (not found)")
            continue

        print(f"Processing {filepath.name}...")
        fixes_made = False

        # Apply fixes in order
        if fix_module_imports_not_at_top(filepath):
            print("  Fixed module import order")
            fixes_made = True

        if fix_undefined_process_basic_information(filepath):
            print("  Fixed undefined PROCESS_BASIC_INFORMATION")
            fixes_made = True

        if fix_subprocess_security(filepath):
            print("  Fixed subprocess security issues")
            fixes_made = True

        if fix_try_except_pass(filepath):
            print("  Fixed try-except-pass patterns")
            fixes_made = True

        if fix_random_security(filepath):
            print("  Fixed non-cryptographic random usage")
            fixes_made = True

        if fix_hashlib_security(filepath):
            print("  Fixed insecure hash functions")
            fixes_made = True

        if not fixes_made:
            print("  No fixes needed")

    print("\n[+] Fixes completed")
    print("[!] Run 'ruff check' to verify remaining issues")


if __name__ == "__main__":
    main()
