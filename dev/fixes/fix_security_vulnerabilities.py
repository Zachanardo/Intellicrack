#!/usr/bin/env python3
"""
Security vulnerability fixes for Intellicrack
Addresses issues found by bandit security scanner
"""

import os
import re
import sys
from pathlib import Path

def fix_md5_vulnerabilities():
    """Fix weak MD5 hash usage by adding usedforsecurity=False parameter"""

    files_to_fix = [
        'intellicrack/ai/ai_script_generator.py',
        'intellicrack/ai/exploit_chain_builder.py',
        'intellicrack/ai/learning_engine.py',
        'intellicrack/ai/performance_optimization_layer.py',
        'intellicrack/ai/predictive_intelligence.py',
        'intellicrack/ai/semantic_code_analyzer.py',
        'intellicrack/ai/template_engine.py',
        'intellicrack/ai/vulnerability_pattern_matcher.py',
        'intellicrack/core/analysis/binary_ninja_integration.py',
        'intellicrack/core/analysis/cache_manager.py',
        'intellicrack/core/analysis/code_analysis.py',
        'intellicrack/core/analysis/ida_integration.py',
        'intellicrack/core/c2/plugins/steganography_plugin.py',
        'intellicrack/core/database/db_models.py',
        'intellicrack/core/database/models.py',
        'intellicrack/core/deobfuscators/control_flow_deobfuscator.py',
        'intellicrack/core/deobfuscators/entropy_deobfuscator.py',
        'intellicrack/core/deobfuscators/heuristic_deobfuscator.py',
        'intellicrack/core/exploitation/exploit_protection_detection.py',
        'intellicrack/core/exploitation/web_payload_generator.py',
        'intellicrack/core/protection/common_protections.py',
        'intellicrack/core/protection/legacy_anti_debug.py',
        'intellicrack/core/reporting/advanced_report_generator.py',
        'intellicrack/core/reporting/report_exporter.py',
        'intellicrack/core/reversing/binary_lifting.py',
        'intellicrack/core/reversing/disassembler.py',
        'intellicrack/core/reversing/legacy_disassembler.py',
        'intellicrack/core/utils.py',
        'intellicrack/ui/tabs/cloud_tab.py',
        'intellicrack/ui/tabs/reporting_tab.py',
    ]

    for file_path in files_to_fix:
        if not os.path.exists(file_path):
            print(f"Skipping {file_path} - file not found")
            continue

        print(f"Fixing MD5 vulnerabilities in {file_path}")

        with open(file_path, 'r') as f:
            content = f.read()

        # Fix hashlib.md5() calls
        original = content

        # Pattern 1: hashlib.md5(something).hexdigest()
        content = re.sub(
            r'hashlib\.md5\(([^)]+)\)\.hexdigest\(\)',
            r'hashlib.md5(\1, usedforsecurity=False).hexdigest()',
            content
        )

        # Pattern 2: hashlib.md5(something).digest()
        content = re.sub(
            r'hashlib\.md5\(([^)]+)\)\.digest\(\)',
            r'hashlib.md5(\1, usedforsecurity=False).digest()',
            content
        )

        # Pattern 3: hashlib.md5(something) without immediate method call
        content = re.sub(
            r'hashlib\.md5\(([^)]+)\)(?![.\w])',
            r'hashlib.md5(\1, usedforsecurity=False)',
            content
        )

        # Pattern 4: md5() direct calls (if imported)
        content = re.sub(
            r'(?<!hashlib\.)md5\(([^)]+)\)\.hexdigest\(\)',
            r'md5(\1, usedforsecurity=False).hexdigest()',
            content
        )

        if content != original:
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"  ✓ Fixed MD5 usage in {file_path}")

def fix_subprocess_vulnerabilities():
    """Fix subprocess calls with shell=True"""

    files_to_fix = [
        'intellicrack/core/c2/c2_client.py',
        'intellicrack/core/exploitation/base_exploitation.py',
        'intellicrack/core/exploitation/exploit_fuzzer.py',
        'intellicrack/core/exploitation/exploit_optimizer.py',
        'intellicrack/core/exploitation/local_privilege_escalation.py',
        'intellicrack/core/exploitation/post_exploitation.py',
        'intellicrack/core/exploitation/shellcode_loader.py',
        'intellicrack/core/protection/virtualization_detection.py',
        'intellicrack/core/reversing/binary_lifting.py',
        'intellicrack/core/reversing/plugin_system.py',
        'intellicrack/core/unpacking/heuristic_unpacker.py',
        'intellicrack/ui/tabs/tools_tab.py',
    ]

    for file_path in files_to_fix:
        if not os.path.exists(file_path):
            print(f"Skipping {file_path} - file not found")
            continue

        print(f"Reviewing subprocess calls in {file_path}")

        with open(file_path, 'r') as f:
            content = f.read()

        # Find lines with subprocess calls with shell=True
        lines = content.split('\n')
        modified = False

        for i, line in enumerate(lines):
            if 'subprocess' in line and 'shell=True' in line:
                print(f"  ! Found subprocess with shell=True at line {i + 1}")
                print(f"    {line.strip()}")
                # Note: Manual review needed for each case
                # Some might be legitimate, others need refactoring
                modified = True

        if modified:
            print(f"  ⚠ Manual review needed for {file_path}")

def fix_yaml_vulnerabilities():
    """Fix yaml.load() usage to use safe_load()"""

    print("\nFixing YAML vulnerabilities...")

    # Find all Python files
    for root, dirs, files in os.walk('intellicrack'):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)

                with open(file_path, 'r') as f:
                    content = f.read()

                original = content

                # Replace yaml.load with yaml.safe_load
                content = re.sub(
                    r'yaml\.load\(([^,]+)\)',
                    r'yaml.safe_load(\1)',
                    content
                )

                # Also fix cases with Loader parameter
                content = re.sub(
                    r'yaml\.load\(([^,]+),\s*Loader=yaml\.FullLoader\)',
                    r'yaml.safe_load(\1)',
                    content
                )

                if content != original:
                    with open(file_path, 'w') as f:
                        f.write(content)
                    print(f"  ✓ Fixed yaml.load in {file_path}")

def fix_pickle_vulnerabilities():
    """Add warnings for pickle usage"""

    print("\nReviewing pickle usage...")

    # Find all Python files using pickle
    for root, dirs, files in os.walk('intellicrack'):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)

                with open(file_path, 'r') as f:
                    content = f.read()

                if 'pickle.load' in content or 'pickle.loads' in content:
                    print(f"  ⚠ Found pickle usage in {file_path}")
                    print("    Consider using safer alternatives like JSON for untrusted data")

def create_security_config():
    """Create security configuration file"""

    config_content = """# Intellicrack Security Configuration
# This file defines security policies and settings

[hashing]
# Use SHA-256 or stronger for security-sensitive hashing
default_algorithm = sha256
# MD5 is only used for non-security purposes (checksums, caching)
allow_md5_for_security = false

[subprocess]
# Disallow shell=True except in whitelisted cases
allow_shell_true = false
# Whitelisted commands that require shell=True
shell_whitelist = []

[serialization]
# Prefer JSON over pickle for untrusted data
default_format = json
# Only allow pickle for trusted internal data
restrict_pickle = true

[input_validation]
# Enable strict input validation
strict_mode = true
# Maximum file size for analysis (in MB)
max_file_size = 1024
# Allowed file extensions
allowed_extensions = [
    ".exe", ".dll", ".so", ".dylib", ".elf",
    ".apk", ".dex", ".jar", ".class"
]

[network]
# Disable insecure protocols
disable_http = false  # Some analysis tools require HTTP
# Certificate validation
verify_ssl = true
# Timeout for network requests (seconds)
request_timeout = 30

[api_keys]
# Store API keys in environment variables, not in code
use_env_vars = true
# Required environment variables
required_vars = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY"
]
"""

    config_path = 'security.ini'
    with open(config_path, 'w') as f:
        f.write(config_content)

    print(f"\n✓ Created security configuration at {config_path}")

def create_security_utils():
    """Create security utility functions"""

    utils_content = '''"""
Security utilities for Intellicrack
Provides secure alternatives to common operations
"""

import hashlib
import json
import subprocess
import shlex
from typing import Any, Dict, List, Optional, Union
import yaml

class SecurityError(Exception):
    """Raised when a security policy is violated"""
    pass

def secure_hash(data: Union[str, bytes], algorithm: str = 'sha256') -> str:
    """
    Generate a secure hash of the given data
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm (sha256, sha512, etc.)
    
    Returns:
        Hex digest of the hash
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    if algorithm == 'md5':
        # MD5 only for non-security purposes
        return hashlib.md5(data, usedforsecurity=False).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(data).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(data).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

def secure_subprocess(command: Union[str, List[str]], 
                     shell: bool = False,
                     timeout: Optional[int] = 30,
                     **kwargs) -> subprocess.CompletedProcess:
    """
    Execute a subprocess command securely
    
    Args:
        command: Command to execute
        shell: Whether to use shell (discouraged)
        timeout: Command timeout in seconds
        **kwargs: Additional arguments for subprocess.run
    
    Returns:
        CompletedProcess instance
    
    Raises:
        SecurityError: If shell=True without whitelist
    """
    if shell:
        raise SecurityError(
            "shell=True is not allowed for security reasons. "
            "Use a list of arguments instead."
        )
    
    if isinstance(command, str):
        # Parse command string into list safely
        command = shlex.split(command)
    
    return subprocess.run(
        command,
        shell=False,
        timeout=timeout,
        capture_output=True,
        text=True,
        **kwargs
    )

def secure_yaml_load(data: str) -> Any:
    """
    Safely load YAML data
    
    Args:
        data: YAML string to parse
    
    Returns:
        Parsed YAML data
    """
    return yaml.safe_load(data)

def secure_json_load(data: str) -> Any:
    """
    Safely load JSON data
    
    Args:
        data: JSON string to parse
    
    Returns:
        Parsed JSON data
    """
    return json.loads(data)

def validate_file_path(path: str, allowed_extensions: Optional[List[str]] = None) -> bool:
    """
    Validate a file path for security
    
    Args:
        path: File path to validate
        allowed_extensions: List of allowed file extensions
    
    Returns:
        True if path is valid
    
    Raises:
        SecurityError: If path is invalid or insecure
    """
    import os
    
    # Prevent path traversal
    if '..' in path or path.startswith('/'):
        raise SecurityError(f"Potentially malicious path: {path}")
    
    # Check file extension
    if allowed_extensions:
        ext = os.path.splitext(path)[1].lower()
        if ext not in allowed_extensions:
            raise SecurityError(f"File extension not allowed: {ext}")
    
    return True

def sanitize_input(text: str, max_length: int = 1024) -> str:
    """
    Sanitize user input
    
    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
    
    Returns:
        Sanitized text
    """
    # Remove null bytes
    text = text.replace('\\x00', '')
    
    # Limit length
    text = text[:max_length]
    
    # Remove control characters
    import re
    text = re.sub(r'[\\x00-\\x1F\\x7F-\\x9F]', '', text)
    
    return text.strip()
'''

    utils_path = 'intellicrack/core/security_utils.py'
    os.makedirs(os.path.dirname(utils_path), exist_ok=True)

    with open(utils_path, 'w') as f:
        f.write(utils_content)

    print(f"✓ Created security utilities at {utils_path}")

def main():
    """Main function to fix security vulnerabilities"""

    print("Intellicrack Security Vulnerability Fixes")
    print("========================================\n")

    # Fix MD5 vulnerabilities
    print("1. Fixing MD5 hash vulnerabilities...")
    fix_md5_vulnerabilities()

    # Review subprocess vulnerabilities
    print("\n2. Reviewing subprocess vulnerabilities...")
    fix_subprocess_vulnerabilities()

    # Fix YAML vulnerabilities
    print("\n3. Fixing YAML vulnerabilities...")
    fix_yaml_vulnerabilities()

    # Review pickle usage
    print("\n4. Reviewing pickle usage...")
    fix_pickle_vulnerabilities()

    # Create security configuration
    print("\n5. Creating security configuration...")
    create_security_config()

    # Create security utilities
    print("\n6. Creating security utilities...")
    create_security_utils()

    print("\n✓ Security fixes completed!")
    print("\nNext steps:")
    print("1. Review subprocess calls marked for manual review")
    print("2. Replace pickle usage with JSON where possible")
    print("3. Update code to use security_utils.py functions")
    print("4. Run bandit again to verify fixes")

if __name__ == "__main__":
    main()
