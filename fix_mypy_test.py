#!/usr/bin/env python3
"""Script to fix mypy --strict errors in test_keygen_iteration_limits_production.py"""

import re
from pathlib import Path

def fix_mypy_errors() -> None:
    """Fix all mypy --strict errors in the test file."""
    file_path = Path(__file__).parent / "tests" / "core" / "license" / "test_keygen_iteration_limits_production.py"

    content = file_path.read_text(encoding="utf-8")

    # Fix 1: Add json import and remove unused imports
    content = re.sub(
        r'import hashlib\nimport multiprocessing\nimport time\nfrom collections\.abc import Callable\nfrom pathlib import Path\nfrom typing import Any\nfrom unittest\.mock import MagicMock, Mock, patch',
        'import hashlib\nimport json\nimport multiprocessing\nimport time\nfrom pathlib import Path\nfrom typing import Any\nfrom unittest.mock import MagicMock, patch',
        content
    )

    # Fix 2: Remove unused SerialConstraints import
    content = re.sub(
        r'from intellicrack\.core\.serial_generator import \(\n    GeneratedSerial,\n    SerialConstraints,\n    SerialFormat,\n\)',
        'from intellicrack.core.serial_generator import (\n    GeneratedSerial,\n    SerialFormat,\n)',
        content
    )

    # Fix 3: Add type annotations for checksum variables
    content = re.sub(
        r'(\s+)checksum = sum\(ord\(c\) for c in key\) % 256',
        r'\1checksum: int = sum(ord(c) for c in key) % 256',
        content
    )

    # Fix 4: Add type annotations for hash_val variables
    content = re.sub(
        r'(\s+)hash_val = hashlib\.(sha256|md5)\(key\.encode\(\)\)\.hexdigest\(\)',
        r'\1hash_val: str = hashlib.\2(key.encode()).hexdigest()',
        content
    )

    # Fix 5: Add type annotations for hash_check variables
    content = re.sub(
        r'(\s+)hash_check = hashlib\.sha256\(key\.encode\(\)\)\.hexdigest\(\)',
        r'\1hash_check: str = hashlib.sha256(key.encode()).hexdigest()',
        content
    )

    # Fix 6: Fix lambda with mutable default argument in test_exponential_keyspace_growth_handling
    content = re.sub(
        r'validation_function=lambda k, l=length: len\(k\) == l,',
        'validation_function=length_validator,',
        content
    )

    # Fix 7: Add proper length_validator function before lambda usage
    old_pattern = r'(        for length in keyspace_sizes:\n)'
    new_pattern = r'''\1            def length_validator(k: str, required_len: int = length) -> bool:
                return len(k) == required_len

'''
    content = re.sub(old_pattern, new_pattern, content)

    # Fix 8: Add type annotations for all result variables
    content = re.sub(
        r'(\s+)result = keygen_engine\.synthesize_key\(',
        r'\1result: GeneratedSerial = keygen_engine.synthesize_key(',
        content
    )

    # Fix 9: Add type annotations for algorithm variables
    content = re.sub(
        r'(\s+)algorithm = ExtractedAlgorithm\(',
        r'\1algorithm: ExtractedAlgorithm = ExtractedAlgorithm(',
        content
    )

    # Fix 10: Add type annotations for time variables
    content = re.sub(
        r'(\s+)start_time = time\.time\(\)',
        r'\1start_time: float = time.time()',
        content
    )

    content = re.sub(
        r'(\s+)elapsed = time\.time\(\) - start_time',
        r'\1elapsed: float = time.time() - start_time',
        content
    )

    # Fix 11: Add type annotations for batch variables
    content = re.sub(
        r'(\s+)batch = keygen_engine\.synthesize_batch\(',
        r'\1batch: list[GeneratedSerial] = keygen_engine.synthesize_batch(',
        content
    )

    # Fix 12: Add type annotations for checkpoint_file
    content = re.sub(
        r'(\s+)checkpoint_file = tmp_path / "keygen_checkpoint\.json"',
        r'\1checkpoint_file: Path = tmp_path / "keygen_checkpoint.json"',
        content
    )

    content = re.sub(
        r'(\s+)corrupted_checkpoint = tmp_path / "corrupted\.json"',
        r'\1corrupted_checkpoint: Path = tmp_path / "corrupted.json"',
        content
    )

    # Fix 13: Add type annotations for mock_file
    content = re.sub(
        r'(\s+)mock_file = MagicMock\(\)',
        r'\1mock_file: MagicMock = MagicMock()',
        content
    )

    # Fix 14: Add type annotations for int variables
    content = re.sub(
        r'(\s+)cpu_count = multiprocessing\.cpu_count\(\)',
        r'\1cpu_count: int = multiprocessing.cpu_count()',
        content
    )

    content = re.sub(
        r'(\s+)batch_size = cpu_count \* 10',
        r'\1batch_size: int = cpu_count * 10',
        content
    )

    content = re.sub(
        r'(\s+)batch_size = 100',
        r'\1batch_size: int = 100',
        content
    )

    content = re.sub(
        r'(\s+)batch_size = 50',
        r'\1batch_size: int = 50',
        content
    )

    # Fix 15: Add type annotations for call_count, attempts, etc.
    content = re.sub(
        r'(\s+)call_count = 0',
        r'\1call_count: int = 0',
        content
    )

    content = re.sub(
        r'(\s+)attempts = 0',
        r'\1attempts: int = 0',
        content
    )

    content = re.sub(
        r'(\s+)simple_calls = 0',
        r'\1simple_calls: int = 0',
        content
    )

    content = re.sub(
        r'(\s+)complex_calls = 0',
        r'\1complex_calls: int = 0',
        content
    )

    content = re.sub(
        r'(\s+)resume_calls = 0',
        r'\1resume_calls: int = 0',
        content
    )

    content = re.sub(
        r'(\s+)calls = 0',
        r'\1calls: int = 0',
        content
    )

    # Fix 16: Add type annotations for candidate string
    content = re.sub(
        r'(\s+)candidate = f"X\{\'A\' \* 18\}Z"',
        r'\1candidate: str = f"X{\'A\' * 18}Z"',
        content
    )

    # Fix 17: Add type annotations for simple_attempt_count and complex_attempt_count
    content = re.sub(
        r'(\s+)simple_attempt_count = simple_calls',
        r'\1simple_attempt_count: int = simple_calls',
        content
    )

    content = re.sub(
        r'(\s+)complex_attempt_count = complex_calls',
        r'\1complex_attempt_count: int = complex_calls',
        content
    )

    # Fix 18: Add type annotations for parallel_time and expected_sequential_time
    content = re.sub(
        r'(\s+)parallel_time = time\.time\(\) - start_time',
        r'\1parallel_time: float = time.time() - start_time',
        content
    )

    content = re.sub(
        r'(\s+)expected_sequential_time = parallel_time \* cpu_count \* 0\.7',
        r'\1expected_sequential_time: float = parallel_time * cpu_count * 0.7',
        content
    )

    # Fix 19: Add type annotations for simple_constraints_algo and complex_constraints_algo
    content = re.sub(
        r'(\s+)simple_constraints_algo = ExtractedAlgorithm\(',
        r'\1simple_constraints_algo: ExtractedAlgorithm = ExtractedAlgorithm(',
        content
    )

    content = re.sub(
        r'(\s+)complex_constraints_algo = ExtractedAlgorithm\(',
        r'\1complex_constraints_algo: ExtractedAlgorithm = ExtractedAlgorithm(',
        content
    )

    content = re.sub(
        r'(\s+)conflicting_algo = ExtractedAlgorithm\(',
        r'\1conflicting_algo: ExtractedAlgorithm = ExtractedAlgorithm(',
        content
    )

    content = re.sub(
        r'(\s+)impossible_algo = ExtractedAlgorithm\(',
        r'\1impossible_algo: ExtractedAlgorithm = ExtractedAlgorithm(',
        content
    )

    # Fix 20: Add type annotations for start and elapsed in loop
    content = re.sub(
        r'(\s+)start = time\.time\(\)',
        r'\1start: float = time.time()',
        content
    )

    # Fix 21: Add type annotations for sum_check and xor_check
    content = re.sub(
        r'(\s+)sum_check = sum\(ord\(c\) for c in key\) % 100 == 42',
        r'\1sum_check: bool = sum(ord(c) for c in key) % 100 == 42',
        content
    )

    content = re.sub(
        r'(\s+)xor_check = \(\n(\s+)sum\(ord\(c\) \^ \(i \* 7\) for i, c in enumerate\(key\)\) % 256 == 128\n(\s+)\)',
        r'\1xor_check: bool = (\n\2sum(ord(c) ^ (i * 7) for i, c in enumerate(key)) % 256 == 128\n\3)',
        content
    )

    # Fix 22: Add type annotations for checksum_val in complex_validator
    content = re.sub(
        r'return \(\n(\s+)len\(k\) == 10 and k\.isalnum\(\) and sum\(ord\(c\) for c in k\) % 100 == 7\n(\s+)\)',
        r'checksum_val: int = sum(ord(c) for c in k) % 100\n\1return (\n\1len(k) == 10 and k.isalnum() and checksum_val == 7\n\2)',
        content
    )

    # Fix 23: Add type annotations for checksum_val in learning_validator
    content = re.sub(
        r'(\s+)if sum\(ord\(c\) for c in key\) % 97 != 13:',
        r'\1checksum_val: int = sum(ord(c) for c in key) % 97\n\1if checksum_val != 13:',
        content
    )

    # Fix 24: Fix checkpoint_data.get() calls to handle Any type properly
    content = re.sub(
        r'(\s+)seed = kwargs\.get\("seed", 0\)\n(\s+)if isinstance\(seed, int\) and seed > checkpoint_data\.get\("attempts", 0\):',
        r'\1seed: Any = kwargs.get("seed", 0)\n\2attempts_val: Any = checkpoint_data.get("attempts", 0)\n\2if isinstance(seed, int) and isinstance(attempts_val, int) and seed > attempts_val:',
        content
    )

    # Fix 25: Remove duplicate import json statement if it exists in the function
    content = re.sub(
        r'\n\s+import json\n\n\s+checkpoint_file\.write_text',
        r'\n        checkpoint_file.write_text',
        content
    )

    file_path.write_text(content, encoding="utf-8")
    print(f"Fixed mypy errors in {file_path}")

if __name__ == "__main__":
    fix_mypy_errors()
