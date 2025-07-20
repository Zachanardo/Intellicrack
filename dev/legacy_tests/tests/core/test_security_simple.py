"""
Simple test to verify security enforcement is working
"""
import os
import sys
import subprocess
import pickle
import hashlib

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import security directly
from intellicrack.core import security_enforcement

def test_subprocess_protection():
    """Test subprocess protection"""
    print("\n=== Testing Subprocess Protection ===")
    
    # Test 1: Shell=True should be blocked
    print("Test 1: Blocking shell=True...")
    try:
        subprocess.run("echo test", shell=True)
        print("FAIL: shell=True was not blocked!")
    except security_enforcement.SecurityError as e:
        print(f"PASS: {e}")
    
    # Test 2: Shell=False should work
    print("\nTest 2: Allowing shell=False...")
    try:
        result = subprocess.run(["echo", "test"], capture_output=True, text=True)
        print(f"PASS: Command executed successfully: {result.stdout.strip()}")
    except Exception as e:
        print(f"FAIL: {e}")

def test_pickle_restriction():
    """Test pickle restriction"""
    print("\n=== Testing Pickle Restriction ===")
    
    # Test JSON-serializable data
    print("Test 1: JSON-serializable data...")
    data = {"key": "value", "number": 42}
    try:
        serialized = pickle.dumps(data)
        # Check if it's JSON
        import json
        json.loads(serialized.decode('utf-8'))
        print("PASS: Data was serialized as JSON")
    except:
        print("INFO: Data was serialized as pickle (JSON fallback may not be active)")

def test_hashlib_enforcement():
    """Test hashlib enforcement"""
    print("\n=== Testing Hashlib Enforcement ===")
    
    print("Test 1: MD5 should be replaced with SHA256...")
    h = hashlib.md5(b"test")
    digest = h.hexdigest()
    
    # Expected SHA256 of "test"
    expected_sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    
    if digest == expected_sha256:
        print("PASS: MD5 was replaced with SHA256")
    else:
        print(f"INFO: MD5 returned: {digest}")
        print(f"Expected SHA256: {expected_sha256}")

def test_security_status():
    """Test security status"""
    print("\n=== Testing Security Status ===")
    
    status = security_enforcement.get_security_status()
    
    print(f"Initialized: {status['initialized']}")
    print(f"Bypass enabled: {status['bypass_enabled']}")
    print(f"Patches applied:")
    for patch, applied in status['patches_applied'].items():
        print(f"  - {patch}: {applied}")
    
    if all(status['patches_applied'].values()):
        print("PASS: All security patches are applied")
    else:
        print("FAIL: Some patches are not applied")

def test_file_validation():
    """Test file input validation"""
    print("\n=== Testing File Input Validation ===")
    
    # Test path traversal detection
    print("Test 1: Path traversal detection...")
    try:
        security_enforcement.validate_file_input("../../../etc/passwd")
        print("FAIL: Path traversal was not detected!")
    except security_enforcement.SecurityError as e:
        print(f"PASS: {e}")

def main():
    """Run all tests"""
    print("=" * 60)
    print("Security Enforcement Test Suite")
    print("=" * 60)
    
    # Check if security is active
    if hasattr(subprocess, 'run') and hasattr(subprocess.run, '__name__'):
        if 'secure' in subprocess.run.__name__:
            print("✓ Security enforcement is ACTIVE")
        else:
            print("✗ Security enforcement is NOT ACTIVE")
    
    # Run tests
    test_subprocess_protection()
    test_pickle_restriction()
    test_hashlib_enforcement()
    test_file_validation()
    test_security_status()
    
    print("\n" + "=" * 60)
    print("Test suite completed")
    print("=" * 60)

if __name__ == "__main__":
    main()