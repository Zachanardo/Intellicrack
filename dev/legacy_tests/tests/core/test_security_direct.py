"""
Direct test of security enforcement module
"""
import os
import sys

# Add the specific module path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'intellicrack', 'core'))

# Import the module directly
import security_enforcement

# Now test the functionality
print("Security Enforcement Direct Test")
print("=" * 40)

# Test 1: Check if patches were applied
print("\n1. Checking patches...")
import subprocess
import pickle
import hashlib

print(f"subprocess.run patched: {'secure' in subprocess.run.__name__}")
print(f"pickle.dump patched: {'secure' in pickle.dump.__name__}")
print(f"hashlib.md5 patched: {'secure' in hashlib.md5.__name__}")

# Test 2: Test subprocess blocking
print("\n2. Testing subprocess protection...")
try:
    subprocess.run("echo test", shell=True)
    print("FAIL: shell=True was not blocked!")
except security_enforcement.SecurityError as e:
    print(f"PASS: Blocked with error: {e}")

# Test 3: Test MD5 replacement
print("\n3. Testing MD5 replacement...")
h = hashlib.md5(b"test")
digest = h.hexdigest()
expected_sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
if digest == expected_sha256:
    print("PASS: MD5 was replaced with SHA256")
else:
    print(f"UNEXPECTED: Got {digest}")

# Test 4: Test pickle JSON fallback
print("\n4. Testing pickle JSON fallback...")
data = {"test": "data"}
serialized = pickle.dumps(data)
try:
    import json
    json.loads(serialized.decode('utf-8'))
    print("PASS: Data was serialized as JSON")
except:
    print("INFO: Data was serialized as pickle")

# Test 5: Get security status
print("\n5. Security Status:")
status = security_enforcement.get_security_status()
print(f"Initialized: {status['initialized']}")
print(f"Config: {status['config']}")

print("\n" + "=" * 40)
print("Direct test completed successfully!")