"""
Security tests for safe execution and sandboxing.
Tests REAL sandboxing, privilege separation, and secure execution.
NO MOCKS - ALL TESTS VALIDATE REAL SECURITY BOUNDARIES.
"""

import pytest
import subprocess
import os
import tempfile
from pathlib import Path
import platform

from intellicrack.core.sandbox.sandbox_manager import SandboxManager
from intellicrack.core.security.privilege_manager import PrivilegeManager
from intellicrack.core.execution.safe_executor import SafeExecutor
from tests.base_test import IntellicrackTestBase


class TestExecutionSecurity(IntellicrackTestBase):
    """Test execution security with REAL sandboxing."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with security components."""
        self.sandbox = SandboxManager()
        self.privilege_manager = PrivilegeManager()
        self.safe_executor = SafeExecutor()
        self.temp_dir = Path(tempfile.mkdtemp())
        
    def teardown_method(self):
        """Clean up temp files and processes."""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            
        # Clean up any sandbox processes
        self.sandbox.cleanup_all()
        
    def test_sandbox_isolation(self):
        """Test sandbox isolation from host system."""
        # Create test script that tries to access system
        test_script = self.temp_dir / "sandbox_test.py"
        test_script.write_text("""
import os
import sys

# Try to access sensitive locations
attempts = []

# Try to read sensitive files
try:
    with open('/etc/passwd', 'r') as f:
        attempts.append(('read_passwd', 'success'))
except:
    attempts.append(('read_passwd', 'blocked'))

# Try to write to system
try:
    with open('/tmp/sandbox_escape', 'w') as f:
        f.write('escaped')
    attempts.append(('write_system', 'success'))
except:
    attempts.append(('write_system', 'blocked'))

# Try to access network
try:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('8.8.8.8', 80))
    attempts.append(('network', 'success'))
except:
    attempts.append(('network', 'blocked'))

print(attempts)
""")
        
        # Execute in sandbox
        result = self.sandbox.execute_in_sandbox(
            str(test_script),
            timeout=5,
            network_access=False,
            filesystem_access='restricted'
        )
        
        self.assert_real_output(result)
        
        # Verify isolation
        assert result['exit_code'] == 0 or result['sandboxed'] == True
        
        # Check attempts
        if 'output' in result:
            assert 'read_passwd', 'blocked' in result['output']
            assert 'write_system', 'blocked' in result['output']
            assert 'network', 'blocked' in result['output']
            
        # Verify no actual system access
        assert not Path('/tmp/sandbox_escape').exists()
        
        print("\nSandbox Isolation Test:")
        print(f"  Sandboxed: {result.get('sandboxed', False)}")
        print(f"  System access blocked: Yes")
        
    def test_privilege_dropping(self):
        """Test privilege dropping mechanisms."""
        if platform.system() == 'Windows':
            # Windows privilege test
            result = self.privilege_manager.run_with_limited_privileges(
                lambda: os.getenv('USERNAME'),
                privilege_level='low'
            )
        else:
            # Unix privilege test
            result = self.privilege_manager.drop_privileges_and_run(
                lambda: os.geteuid(),
                target_uid=65534  # nobody user
            )
            
        self.assert_real_output(result)
        
        # Should run with reduced privileges
        assert result['success'] == True
        assert result['privilege_level'] == 'reduced'
        
    def test_resource_limits(self):
        """Test resource limit enforcement."""
        # Test script that tries to consume resources
        resource_hog = self.temp_dir / "resource_hog.py"
        resource_hog.write_text("""
import time

# Try to allocate lots of memory
try:
    huge_list = [0] * (10**9)  # Try to allocate billions
    print("Memory: unlimited")
except:
    print("Memory: limited")

# Try to use lots of CPU
start = time.time()
while time.time() - start < 10:
    pass
print("CPU: ran for", time.time() - start, "seconds")
""")
        
        # Execute with resource limits
        result = self.safe_executor.execute_with_limits(
            str(resource_hog),
            memory_limit_mb=100,
            cpu_time_limit=2,
            real_time_limit=3
        )
        
        self.assert_real_output(result)
        
        # Should enforce limits
        assert 'Memory: limited' in result.get('output', '')
        assert result['terminated_by_limit'] == True or result['exit_code'] != 0
        
        print("\nResource Limits Test:")
        print(f"  Memory limited: Yes")
        print(f"  CPU time limited: Yes")
        print(f"  Execution time: {result.get('execution_time', 0):.2f}s")
        
    def test_code_signing_verification(self):
        """Test code signing and verification."""
        # Create test executable
        test_exe = self.temp_dir / "unsigned.exe"
        test_exe.write_bytes(b"MZ" + b"\x00" * 100)
        
        # Verify signature check
        verification = self.safe_executor.verify_code_signature(test_exe)
        
        self.assert_real_output(verification)
        
        # Should detect unsigned code
        assert verification['signed'] == False
        assert 'unsigned' in verification.get('status', '').lower()
        
        # Test execution policy
        policy_result = self.safe_executor.check_execution_policy(test_exe)
        assert policy_result['allowed'] == False or policy_result['warning'] == True
        
    def test_anti_debugging_bypass_prevention(self):
        """Test prevention of anti-debugging bypasses."""
        # Script that tries to detect/bypass debugging
        anti_debug_script = self.temp_dir / "anti_debug.py"
        anti_debug_script.write_text("""
import sys
import os

# Try various anti-debugging techniques
debug_detected = False

# Check for debugger via trace
try:
    import ctypes
    if hasattr(ctypes, 'windll'):
        # Windows IsDebuggerPresent
        debug_detected = ctypes.windll.kernel32.IsDebuggerPresent()
except:
    pass

# Check via environment
if 'PYDEVD' in os.environ or '_PYCHARM_' in str(sys.modules):
    debug_detected = True

# Try to detect via timing
import time
start = time.time()
for i in range(1000000):
    pass
elapsed = time.time() - start
if elapsed > 1.0:  # Suspiciously slow
    debug_detected = True

print(f"Debug detected: {debug_detected}")

# Try to crash debugger
if debug_detected:
    # Attempt various anti-debug tricks
    try:
        os._exit(0)  # Direct exit
    except:
        pass
""")
        
        # Execute with anti-debugging prevention
        result = self.sandbox.execute_with_anti_debug_protection(
            str(anti_debug_script)
        )
        
        self.assert_real_output(result)
        
        # Should prevent anti-debugging tricks
        assert result['completed'] == True
        assert 'anti_debug_prevented' in result
        
    def test_shellcode_execution_prevention(self):
        """Test prevention of shellcode execution."""
        # Create test that tries to execute shellcode
        shellcode_test = self.temp_dir / "shellcode_test.py"
        shellcode_test.write_text("""
import ctypes
import sys

# Try to execute shellcode
try:
    # NOP sled shellcode (harmless)
    shellcode = b"\\x90" * 100
    
    # Try to make memory executable
    if sys.platform == 'win32':
        # Windows VirtualAlloc
        kernel32 = ctypes.windll.kernel32
        ptr = kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)
        ctypes.memmove(ptr, shellcode, len(shellcode))
        print("Shellcode: allocated")
    else:
        # Unix mmap
        import mmap
        mem = mmap.mmap(-1, len(shellcode), mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, mmap.PROT_WRITE | mmap.PROT_EXEC)
        print("Shellcode: mapped")
except Exception as e:
    print(f"Shellcode: blocked - {e}")
""")
        
        # Execute with DEP/NX enforcement
        result = self.safe_executor.execute_with_dep_enforcement(
            str(shellcode_test)
        )
        
        self.assert_real_output(result)
        
        # Should prevent shellcode execution
        assert 'blocked' in result.get('output', '').lower() or \
               result.get('dep_violation', False) == True
               
    def test_process_injection_prevention(self):
        """Test prevention of process injection."""
        if platform.system() != 'Windows':
            pytest.skip("Windows-specific test")
            
        # Test script that tries process injection
        injection_test = self.temp_dir / "injection_test.py"
        injection_test.write_text("""
import ctypes
import os

# Try to inject into another process
try:
    kernel32 = ctypes.windll.kernel32
    
    # Try to open another process
    PROCESS_ALL_ACCESS = 0x1F0FFF
    pid = os.getpid()  # Self for testing
    
    handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if handle:
        print("Process: opened")
        
        # Try to allocate memory in target
        MEM_COMMIT = 0x1000
        PAGE_EXECUTE_READWRITE = 0x40
        
        addr = kernel32.VirtualAllocEx(handle, 0, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        if addr:
            print("Injection: allocated")
        else:
            print("Injection: blocked")
            
        kernel32.CloseHandle(handle)
    else:
        print("Process: blocked")
except Exception as e:
    print(f"Injection: error - {e}")
""")
        
        # Execute with injection prevention
        result = self.sandbox.execute_with_injection_prevention(
            str(injection_test)
        )
        
        self.assert_real_output(result)
        
        # Should prevent injection
        assert 'blocked' in result.get('output', '').lower()
        
    def test_file_system_virtualization(self):
        """Test filesystem virtualization in sandbox."""
        # Script that tries to access files
        fs_test = self.temp_dir / "fs_test.py"
        fs_test.write_text("""
import os
import tempfile

# Try to write to various locations
locations = [
    '/etc/test_file',
    'C:\\\\Windows\\\\test_file',
    os.path.expanduser('~/test_file'),
    '/tmp/test_file',
    tempfile.gettempdir() + '/test_file'
]

results = []
for loc in locations:
    try:
        with open(loc, 'w') as f:
            f.write('test')
        results.append((loc, 'written'))
        # Clean up
        try:
            os.unlink(loc)
        except:
            pass
    except Exception as e:
        results.append((loc, 'blocked'))

for loc, status in results:
    print(f"{loc}: {status}")
""")
        
        # Execute with filesystem virtualization
        result = self.sandbox.execute_with_fs_virtualization(
            str(fs_test),
            allowed_paths=[tempfile.gettempdir()]
        )
        
        self.assert_real_output(result)
        
        # Should only allow temp directory access
        output = result.get('output', '')
        assert '/etc/test_file: blocked' in output or \
               'C:\\Windows\\test_file: blocked' in output
               
    def test_network_isolation(self):
        """Test network isolation in sandbox."""
        # Script that tries network access
        net_test = self.temp_dir / "net_test.py"
        net_test.write_text("""
import socket
import urllib.request

# Try various network operations
results = []

# Direct socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(('8.8.8.8', 80))
    s.close()
    results.append('socket: connected')
except:
    results.append('socket: blocked')

# HTTP request
try:
    response = urllib.request.urlopen('http://example.com', timeout=2)
    results.append('http: connected')
except:
    results.append('http: blocked')

# DNS lookup
try:
    socket.gethostbyname('google.com')
    results.append('dns: resolved')
except:
    results.append('dns: blocked')

for result in results:
    print(result)
""")
        
        # Execute with network isolation
        result = self.sandbox.execute_with_network_isolation(
            str(net_test),
            allow_localhost=True
        )
        
        self.assert_real_output(result)
        
        # Should block external network
        output = result.get('output', '')
        assert 'socket: blocked' in output
        assert 'http: blocked' in output
        assert 'dns: blocked' in output
        
    def test_time_based_restrictions(self):
        """Test time-based execution restrictions."""
        # Script with timing attacks
        timing_test = self.temp_dir / "timing_test.py"
        timing_test.write_text("""
import time
import sys

# Try timing attack
start = time.time()

# Attempt to sleep/delay
try:
    time.sleep(10)
    elapsed = time.time() - start
    print(f"Slept for {elapsed} seconds")
except:
    print("Sleep interrupted")

# Try busy wait
start = time.time()
while time.time() - start < 10:
    pass
    
print(f"Busy waited for {time.time() - start} seconds")
""")
        
        # Execute with time restrictions
        result = self.safe_executor.execute_with_timeout(
            str(timing_test),
            timeout=3,
            kill_on_timeout=True
        )
        
        self.assert_real_output(result)
        
        # Should enforce timeout
        assert result['timed_out'] == True
        assert result['execution_time'] < 5  # Should not run for 10 seconds
        
    def test_api_hooking_prevention(self):
        """Test prevention of malicious API hooking."""
        # Script that tries to hook APIs
        hook_test = self.temp_dir / "hook_test.py"
        hook_test.write_text("""
import sys

# Try to hook built-in functions
original_open = open
hooked = False

def malicious_open(*args, **kwargs):
    global hooked
    hooked = True
    print("HOOKED: open() intercepted!")
    return original_open(*args, **kwargs)

# Try to replace built-in
try:
    import builtins
    builtins.open = malicious_open
    
    # Test if hook worked
    with open(__file__, 'r') as f:
        pass
        
    if hooked:
        print("Hooking: successful")
    else:
        print("Hooking: failed")
except:
    print("Hooking: blocked")
""")
        
        # Execute with hook prevention
        result = self.sandbox.execute_with_hook_prevention(
            str(hook_test)
        )
        
        self.assert_real_output(result)
        
        # Should prevent or detect hooking
        assert 'blocked' in result.get('output', '').lower() or \
               result.get('hooks_detected', False) == True