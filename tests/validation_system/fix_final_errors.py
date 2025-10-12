#!/usr/bin/env python3
"""
Fix the final remaining errors in Phase 1 files.
"""

import re
from pathlib import Path


def fix_environment_validator():
    """Fix syntax errors in environment_validator.py."""
    filepath = Path(r"D:\Intellicrack\tests\validation_system\environment_validator.py")

    content = filepath.read_text()

    # Remove the broken indented import line
    content = re.sub(r'^\s+import time\n', '', content, flags=re.MULTILINE)

    # Remove extra blank lines before logger
    content = re.sub(r'(\n)+logger = logging\.getLogger\(__name__\)', r'\n\nlogger = logging.getLogger(__name__)', content)

    # Ensure winreg import is present for UUID manipulation
    if 'import winreg' not in content:
        content = content.replace('import uuid', 'import uuid\nimport winreg')

    filepath.write_text(content)
    print(f"Fixed {filepath.name}")


def fix_fingerprint_randomizer():
    """Fix syntax errors in fingerprint_randomizer.py."""
    filepath = Path(r"D:\Intellicrack\tests\validation_system\fingerprint_randomizer.py")

    content = filepath.read_text()

    # Fix the nested exception handling syntax error
    # Look for the problematic pattern and fix it
    problem_pattern = r'except Exception as e:\s*\n\s*logger\.debug\(f"Suppressed exception: \{e\}"\)\s*\n\s+except Exception:'

    # Replace with proper indentation
    content = re.sub(
        problem_pattern,
        'except Exception as e:\n                    logger.debug(f"Suppressed exception: {e}")\n            except Exception:',
        content,
        flags=re.MULTILINE | re.DOTALL
    )

    # Also fix any remaining indentation issues with logger.debug
    content = re.sub(
        r'except Exception as e:\s*\nlogger\.debug',
        'except Exception as e:\n                    logger.debug',
        content
    )

    filepath.write_text(content)
    print(f"Fixed {filepath.name}")


def fix_anti_detection_undefined_names():
    """Fix undefined PROCESS_BASIC_INFORMATION in anti_detection_verifier.py."""
    filepath = Path(r"D:\Intellicrack\tests\validation_system\anti_detection_verifier.py")

    content = filepath.read_text()

    # Add the ProcessBasicInformation class definition
    if 'class ProcessBasicInformation' not in content:
        class_def = """

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
        # Insert before the AntiDetectionBypass class
        insertion_point = content.find('class AntiDetectionBypass:')
        if insertion_point > 0:
            content = content[:insertion_point] + class_def + content[insertion_point:]

    # Replace PROCESS_BASIC_INFORMATION with ProcessBasicInformation
    content = content.replace('PROCESS_BASIC_INFORMATION()', 'ProcessBasicInformation()')

    filepath.write_text(content)
    print(f"Fixed {filepath.name}")


def fix_runner_undefined_names():
    """Fix undefined winreg and math imports in runner.py."""
    filepath = Path(r"D:\Intellicrack\tests\validation_system\runner.py")

    content = filepath.read_text()

    # Add missing imports at the top
    lines = content.split('\n')

    # Find where to insert imports (after existing imports)
    import_end_idx = 0
    for i, line in enumerate(lines):
        if line.strip().startswith('import ') or line.strip().startswith('from '):
            import_end_idx = i
        elif line.strip() and not line.strip().startswith('#'):
            break

    # Insert missing imports
    missing_imports = []
    if 'import math' not in content:
        missing_imports.append('import math')
    if 'import winreg' not in content:
        missing_imports.append('import winreg')

    for imp in reversed(missing_imports):
        lines.insert(import_end_idx + 1, imp)

    content = '\n'.join(lines)
    filepath.write_text(content)
    print(f"Fixed {filepath.name}")


def fix_commercial_binary_manager():
    """Fix security issues in commercial_binary_manager.py."""
    filepath = Path(r"D:\Intellicrack\tests\validation_system\commercial_binary_manager.py")

    content = filepath.read_text()

    # Add safe extraction for tarfile and zipfile
    # Replace tarfile.extractall with safe extraction
    safe_extract_code = '''def safe_extract(archive, path):
        """Safely extract archive avoiding path traversal."""
        for member in archive.getmembers() if hasattr(archive, 'getmembers') else archive.infolist():
            name = member.name if hasattr(member, 'name') else member.filename
            if '..' in name or name.startswith('/') or ':' in name:
                continue
            archive.extract(member, path)'''

    # Insert the safe extraction function
    if 'def safe_extract' not in content:
        # Find a good place to insert (before first method)
        class_start = content.find('class')
        if class_start > 0:
            method_start = content.find('    def', class_start)
            if method_start > 0:
                content = content[:method_start] + safe_extract_code + '\n\n    ' + content[method_start+4:]

    # Replace unsafe extraction calls
    content = content.replace('zip_ref.extractall(temp_dir)', 'safe_extract(zip_ref, temp_dir)')
    content = content.replace('tar_ref.extractall(temp_dir)', 'safe_extract(tar_ref, temp_dir)')

    # Fix try-except-continue to add logging
    content = re.sub(
        r'except Exception:\s*\n\s*continue',
        'except Exception as e:\n                        logger.debug(f"Extraction attempt failed: {e}")\n                        continue',
        content
    )

    filepath.write_text(content)
    print(f"Fixed {filepath.name}")


def main():
    """Fix all final errors."""
    print("=== Fixing Final Errors ===\n")

    fixes = [
        fix_environment_validator,
        fix_fingerprint_randomizer,
        fix_anti_detection_undefined_names,
        fix_runner_undefined_names,
        fix_commercial_binary_manager
    ]

    for fix_func in fixes:
        try:
            fix_func()
        except Exception as e:
            print(f"Error in {fix_func.__name__}: {e}")

    print("\n[+] Final fixes completed")


if __name__ == "__main__":
    main()
