"""
Comprehensive test suite for security enforcement module
"""
import json
import os
import pickle
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from intellicrack.core.security_enforcement import (
    SecurityEnforcement, SecurityError, validate_file_input,
    secure_open, get_security_status, _security
)

class TestSecurityEnforcement(unittest.TestCase):
    """Test security enforcement functionality"""

    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, 'w') as f:
            f.write("test content")

        # Save original config
        self.original_config = _security.security_config.copy()

    def tearDown(self):
        """Clean up test environment"""
        # Restore original config
        _security.security_config = self.original_config
        _security._bypass_security = False

        # Clean up temp files
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_subprocess_protection_shell_true_blocked(self):
        """Test that subprocess with shell=True is blocked"""
        _security.security_config['subprocess']['allow_shell_true'] = False

        with self.assertRaises(SecurityError) as cm:
            subprocess.run("echo test", shell=True)

        self.assertIn("shell=True is disabled", str(cm.exception))

    def test_subprocess_protection_shell_true_allowed(self):
        """Test that subprocess with shell=True works when allowed"""
        _security.security_config['subprocess']['allow_shell_true'] = True
        _security.security_config['subprocess']['shell_whitelist'] = []

        # Should not raise an exception
        result = subprocess.run("echo test", shell=True, capture_output=True, text=True)
        self.assertIn("test", result.stdout)

    def test_subprocess_whitelist(self):
        """Test subprocess whitelist functionality"""
        _security.security_config['subprocess']['allow_shell_true'] = True
        _security.security_config['subprocess']['shell_whitelist'] = ['echo', 'dir']

        # Allowed command
        result = subprocess.run("echo test", shell=True, capture_output=True, text=True)
        self.assertIn("test", result.stdout)

        # Disallowed command
        with self.assertRaises(SecurityError) as cm:
            subprocess.run("whoami", shell=True)

        self.assertIn("not in shell whitelist", str(cm.exception))

    def test_pickle_restriction(self):
        """Test pickle restriction and JSON fallback"""
        _security.security_config['serialization']['restrict_pickle'] = True

        # Test with JSON-serializable data
        data = {"key": "value", "number": 42}

        # Test pickle.dumps - should use JSON
        result = pickle.dumps(data)
        # Result should be JSON-encoded bytes
        self.assertEqual(json.loads(result.decode('utf-8')), data)

        # Test with non-JSON-serializable data
        class CustomObject:
            def __init__(self):
                self.value = "test"

        obj = CustomObject()
        # Should fall back to pickle for non-JSON data
        result = pickle.dumps(obj)
        loaded = pickle.loads(result)
        self.assertEqual(loaded.value, "test")

    def test_pickle_allowed(self):
        """Test pickle when not restricted"""
        _security.security_config['serialization']['restrict_pickle'] = False

        data = {"key": "value"}
        result = pickle.dumps(data)

        # Should use actual pickle format
        loaded = pickle.loads(result)
        self.assertEqual(loaded, data)

    def test_hashlib_md5_blocked(self):
        """Test MD5 blocking when not allowed"""
        _security.security_config['hashing']['allow_md5_for_security'] = False
        _security.security_config['hashing']['default_algorithm'] = 'sha256'

        # Direct MD5 call should return SHA256
        import hashlib
        h = hashlib.md5(b"test")
        # Should be SHA256 hash of "test"
        expected_sha256 = hashlib.sha256(b"test").hexdigest()
        self.assertEqual(h.hexdigest(), expected_sha256)

        # Using hashlib.new
        h2 = hashlib.new('md5', b"test")
        self.assertEqual(h2.hexdigest(), expected_sha256)

    def test_hashlib_md5_allowed(self):
        """Test MD5 when allowed"""
        _security.security_config['hashing']['allow_md5_for_security'] = True

        import hashlib
        h = hashlib.md5(b"test")
        # Should be actual MD5 hash
        expected_md5 = "098f6bcd4621d373cade4e832627b4f6"
        self.assertEqual(h.hexdigest(), expected_md5)

    def test_file_validation_size(self):
        """Test file size validation"""
        _security.security_config['input_validation']['strict_mode'] = True
        _security.security_config['input_validation']['max_file_size'] = 10  # 10 bytes

        # Write content larger than limit
        large_file = os.path.join(self.temp_dir, "large.txt")
        with open(large_file, 'w') as f:
            f.write("x" * 20)  # 20 bytes

        with self.assertRaises(SecurityError) as cm:
            validate_file_input(large_file)

        self.assertIn("exceeds maximum size", str(cm.exception))

    def test_file_validation_extension(self):
        """Test file extension validation"""
        _security.security_config['input_validation']['strict_mode'] = True
        _security.security_config['input_validation']['allowed_extensions'] = ['.txt', '.py']

        # Allowed extension
        self.assertTrue(validate_file_input(self.test_file))

        # Disallowed extension
        exe_file = os.path.join(self.temp_dir, "test.exe")
        with open(exe_file, 'w') as f:
            f.write("test")

        with self.assertRaises(SecurityError) as cm:
            validate_file_input(exe_file)

        self.assertIn("not allowed", str(cm.exception))

    def test_path_traversal_detection(self):
        """Test path traversal detection"""
        _security.security_config['input_validation']['strict_mode'] = True

        # Path with .. should be detected
        traversal_path = os.path.join(self.temp_dir, "..", "sensitive.txt")

        with self.assertRaises(SecurityError) as cm:
            validate_file_input(traversal_path)

        self.assertIn("Path traversal", str(cm.exception))

    def test_secure_open(self):
        """Test secure_open wrapper"""
        _security.security_config['input_validation']['strict_mode'] = True
        _security.security_config['input_validation']['allowed_extensions'] = ['.txt']

        # Should work for allowed file
        with secure_open(self.test_file, 'r') as f:
            content = f.read()
            self.assertEqual(content, "test content")

        # Should fail for disallowed extension
        bad_file = os.path.join(self.temp_dir, "bad.exe")
        with open(bad_file, 'w') as f:
            f.write("bad")

        with self.assertRaises(SecurityError):
            with secure_open(bad_file, 'r') as f:
                pass

    def test_bypass_mode(self):
        """Test security bypass functionality"""
        _security.security_config['subprocess']['allow_shell_true'] = False

        # Enable bypass
        _security.enable_bypass()

        # Should work with bypass enabled
        result = subprocess.run("echo bypass test", shell=True, capture_output=True, text=True)
        self.assertIn("bypass test", result.stdout)

        # Disable bypass
        _security.disable_bypass()

        # Should be blocked again
        with self.assertRaises(SecurityError):
            subprocess.run("echo test", shell=True)

    def test_security_status(self):
        """Test get_security_status function"""
        status = get_security_status()

        self.assertIn('initialized', status)
        self.assertIn('bypass_enabled', status)
        self.assertIn('config', status)
        self.assertIn('patches_applied', status)

        # Check patches are applied
        self.assertTrue(status['patches_applied']['subprocess'])
        self.assertTrue(status['patches_applied']['pickle'])
        self.assertTrue(status['patches_applied']['hashlib'])

    def test_config_loading(self):
        """Test configuration loading"""
        security = SecurityEnforcement()

        # Should have loaded config
        self.assertIsInstance(security.security_config, dict)
        self.assertIn('subprocess', security.security_config)
        self.assertIn('serialization', security.security_config)
        self.assertIn('hashing', security.security_config)

    def test_subprocess_popen(self):
        """Test subprocess.Popen protection"""
        _security.security_config['subprocess']['allow_shell_true'] = False

        with self.assertRaises(SecurityError):
            subprocess.Popen("echo test", shell=True)

        # Should work without shell
        proc = subprocess.Popen(["echo", "test"], stdout=subprocess.PIPE, text=True)
        stdout, _ = proc.communicate()
        self.assertIn("test", stdout)

    def test_subprocess_call_variants(self):
        """Test other subprocess variants"""
        _security.security_config['subprocess']['allow_shell_true'] = False

        # Test subprocess.call
        with self.assertRaises(SecurityError):
            subprocess.call("echo test", shell=True)

        # Test subprocess.check_call
        with self.assertRaises(SecurityError):
            subprocess.check_call("echo test", shell=True)

        # Test subprocess.check_output
        with self.assertRaises(SecurityError):
            subprocess.check_output("echo test", shell=True)

    def test_pickle_file_operations(self):
        """Test pickle dump/load with files"""
        _security.security_config['serialization']['restrict_pickle'] = True

        data = {"test": "data", "number": 123}
        pickle_file = os.path.join(self.temp_dir, "test.pkl")

        # Test dump
        with open(pickle_file, 'wb') as f:
            pickle.dump(data, f)

        # Test load
        with open(pickle_file, 'rb') as f:
            loaded = pickle.load(f)

        self.assertEqual(loaded, data)

    def test_environment_variables(self):
        """Test security-related environment variables"""
        _security.security_config['sandbox_analysis'] = True
        _security.security_config['allow_network_access'] = False

        # Re-initialize to set env vars
        from intellicrack.core.security_enforcement import initialize_security
        initialize_security()

        self.assertEqual(os.environ.get('INTELLICRACK_SANDBOX'), '1')
        self.assertEqual(os.environ.get('INTELLICRACK_NO_NETWORK'), '1')


class TestSecurityIntegration(unittest.TestCase):
    """Test security integration with real Intellicrack components"""

    def test_import_order(self):
        """Test that security is imported early in main modules"""
        # Check main.py imports security
        main_path = Path(__file__).parent.parent / "intellicrack" / "main.py"
        if main_path.exists():
            with open(main_path, 'r') as f:
                content = f.read()
                self.assertIn("security_enforcement", content)

        # Check __main__.py imports security
        main_module_path = Path(__file__).parent.parent / "intellicrack" / "__main__.py"
        if main_module_path.exists():
            with open(main_module_path, 'r') as f:
                content = f.read()
                self.assertIn("security_enforcement", content)

    def test_monkey_patches_active(self):
        """Test that monkey patches are active"""
        # Test subprocess
        self.assertNotEqual(subprocess.run.__name__, 'run')
        self.assertIn('secure', subprocess.run.__name__)

        # Test pickle
        self.assertNotEqual(pickle.dump.__name__, 'dump')
        self.assertIn('secure', pickle.dump.__name__)

        # Test hashlib
        import hashlib
        self.assertNotEqual(hashlib.md5.__name__, 'md5')
        self.assertIn('secure', hashlib.md5.__name__)


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
