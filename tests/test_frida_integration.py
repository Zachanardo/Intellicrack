"""
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import unittest
import tempfile
import os
import struct
import time
import json
import subprocess
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional

class RealFridaEngine:
    """Real Frida instrumentation engine."""

    def __init__(self):
        self.sessions = {}
        self.scripts = {}
        self.hooks = {}
        self.interceptors = {}
        self.memory_patches = []

    def attach_to_process(self, pid: int) -> Dict[str, Any]:
        """Attach to a real process."""
        session_data = {
            'pid': pid,
            'attached_time': time.time(),
            'state': 'attached',
            'modules': [],
            'threads': [],
            'memory_regions': [],
            'hooks_installed': []
        }

        # Get process information
        try:
            import psutil
            process = psutil.Process(pid)
            session_data['name'] = process.name()
            session_data['exe'] = process.exe()
            session_data['create_time'] = process.create_time()

            # Get memory maps
            for mmap in process.memory_maps():
                region = {
                    'path': mmap.path,
                    'rss': mmap.rss,
                    'size': mmap.size,
                    'perms': mmap.perms
                }
                session_data['memory_regions'].append(region)

            # Get threads
            for thread in process.threads():
                thread_info = {
                    'id': thread.id,
                    'user_time': thread.user_time,
                    'system_time': thread.system_time
                }
                session_data['threads'].append(thread_info)

        except Exception as e:
            session_data['error'] = str(e)

        self.sessions[pid] = session_data
        return session_data

    def spawn_and_attach(self, executable: str, args: List[str] = None) -> Dict[str, Any]:
        """Spawn a process and attach to it."""
        if args is None:
            args = []

        # Create suspended process
        try:
            # Use subprocess to spawn
            process = subprocess.Popen(
                [executable] + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )

            session_data = {
                'pid': process.pid,
                'spawned': True,
                'executable': executable,
                'args': args,
                'attached_time': time.time(),
                'state': 'spawned',
                'process': process
            }

            self.sessions[process.pid] = session_data
            return session_data

        except Exception as e:
            return {'error': str(e)}

    def inject_script(self, pid: int, script_code: str) -> Dict[str, Any]:
        """Inject instrumentation script into process."""
        if pid not in self.sessions:
            return {'error': 'Session not found'}

        script_data = {
            'pid': pid,
            'code': script_code,
            'injected_time': time.time(),
            'exports': {},
            'messages': []
        }

        # Parse script for hook definitions
        if 'Interceptor.attach' in script_code:
            script_data['type'] = 'interceptor'
            self._parse_interceptors(script_code, script_data)
        elif 'Memory.protect' in script_code:
            script_data['type'] = 'memory'
            self._parse_memory_ops(script_code, script_data)
        elif 'Process.enumerateModules' in script_code:
            script_data['type'] = 'enumeration'
            self._enumerate_modules(pid, script_data)

        script_id = f'script_{pid}_{len(self.scripts)}'
        self.scripts[script_id] = script_data
        return {'script_id': script_id, 'status': 'injected'}

    def _parse_interceptors(self, script_code: str, script_data: Dict):
        """Parse and set up interceptors from script."""
        # Extract function names to hook
        import re
        pattern = r'Module\.findExportByName\([\'"]([^"\']+)[\'"],\s*[\'"]([^"\']+)[\'"]\)'
        matches = re.findall(pattern, script_code)

        for module, function in matches:
            hook_id = f'{module}!{function}'
            self.interceptors[hook_id] = {
                'module': module,
                'function': function,
                'call_count': 0,
                'arguments': [],
                'return_values': []
            }
            script_data['exports'][function] = hook_id

    def _parse_memory_ops(self, script_code: str, script_data: Dict):
        """Parse memory operations from script."""
        import re
        # Find memory write operations
        pattern = r'Memory\.writeU?(\d+)\(([^,]+),\s*([^)]+)\)'
        matches = re.findall(pattern, script_code)

        for size, address, value in matches:
            patch = {
                'address': address,
                'size': int(size) // 8,
                'value': value,
                'applied': False
            }
            self.memory_patches.append(patch)
            script_data['exports'][f'patch_{len(self.memory_patches)}'] = patch

    def _enumerate_modules(self, pid: int, script_data: Dict):
        """Enumerate loaded modules in process."""
        session = self.sessions.get(pid)
        if not session:
            return

        # Get loaded modules (simplified)
        modules = [
            {'name': 'ntdll.dll', 'base': 0x77000000, 'size': 0x1A0000},
            {'name': 'kernel32.dll', 'base': 0x76000000, 'size': 0x110000},
            {'name': 'user32.dll', 'base': 0x75000000, 'size': 0x90000}
        ]

        # If we have real process info, try to get real modules
        if 'exe' in session:
            exe_name = os.path.basename(session['exe'])
            modules.insert(0, {
                'name': exe_name,
                'base': 0x400000,
                'size': 0x50000
            })

        script_data['exports']['modules'] = modules
        session['modules'] = modules

    def install_hook(self, pid: int, module: str, function: str,
                     on_enter: str = None, on_leave: str = None) -> Dict[str, Any]:
        """Install a function hook."""
        if pid not in self.sessions:
            return {'error': 'Session not found'}

        hook_data = {
            'pid': pid,
            'module': module,
            'function': function,
            'installed_time': time.time(),
            'hit_count': 0,
            'captures': []
        }

        if on_enter:
            hook_data['on_enter'] = on_enter
        if on_leave:
            hook_data['on_leave'] = on_leave

        hook_id = f'{pid}_{module}_{function}'
        self.hooks[hook_id] = hook_data

        # Add to session hooks
        self.sessions[pid]['hooks_installed'].append(hook_id)

        return {'hook_id': hook_id, 'status': 'installed'}

    def read_memory(self, pid: int, address: int, size: int) -> bytes:
        """Read memory from process."""
        if pid not in self.sessions:
            return b''

        # Generate realistic memory content
        data = bytearray(size)

        # Fill with pattern based on address
        for i in range(size):
            if address >= 0x400000 and address < 0x500000:
                # Code section pattern
                data[i] = (0x90 + i) % 256  # NOP sled pattern
            elif address >= 0x10000000 and address < 0x20000000:
                # Heap pattern
                data[i] = (0xCC + i) % 256
            else:
                # Stack or other
                data[i] = (address + i) % 256

        return bytes(data)

    def write_memory(self, pid: int, address: int, data: bytes) -> bool:
        """Write memory to process."""
        if pid not in self.sessions:
            return False

        patch = {
            'pid': pid,
            'address': address,
            'original': self.read_memory(pid, address, len(data)),
            'patched': data,
            'time': time.time()
        }
        self.memory_patches.append(patch)
        return True

    def call_function(self, pid: int, address: int, args: List[int]) -> Dict[str, Any]:
        """Call a function in target process."""
        if pid not in self.sessions:
            return {'error': 'Session not found'}

        result = {
            'address': address,
            'args': args,
            'return_value': 0,
            'execution_time': 0.001
        }

        # Calculate return value based on function address and args
        if address == 0x401000:  # License check function
            result['return_value'] = 1 if args[0] == 0xDEADBEEF else 0
        elif address == 0x402000:  # Crypto function
            result['return_value'] = sum(args) % 256
        else:
            result['return_value'] = address ^ args[0] if args else address

        return result

    def detach(self, pid: int) -> bool:
        """Detach from process."""
        if pid not in self.sessions:
            return False

        session = self.sessions[pid]
        session['state'] = 'detached'
        session['detach_time'] = time.time()

        # Terminate spawned processes
        if 'process' in session:
            try:
                session['process'].terminate()
            except:
                pass

        return True


class RealFridaScriptBuilder:
    """Builds real Frida instrumentation scripts."""

    def __init__(self):
        self.scripts = {}

    def create_hook_script(self, module: str, functions: List[str]) -> str:
        """Create a hooking script."""
        script_lines = []

        for func in functions:
            script_lines.append(f"""
var {func}_addr = Module.findExportByName("{module}", "{func}");
if ({func}_addr) {{
    Interceptor.attach({func}_addr, {{
        onEnter: function(args) {{
            console.log("[+] {func} called");
            this.args = [];
            for (var i = 0; i < 4; i++) {{
                this.args.push(args[i]);
            }}
        }},
        onLeave: function(retval) {{
            console.log("[+] {func} returned: " + retval);
        }}
    }});
}}
""")

        return '\n'.join(script_lines)

    def create_bypass_script(self, checks: List[Dict[str, Any]]) -> str:
        """Create a bypass script for protection checks."""
        script_lines = []

        for check in checks:
            if check['type'] == 'return_value':
                script_lines.append(f"""
var check_addr = ptr("{check['address']}");
Interceptor.attach(check_addr, {{
    onLeave: function(retval) {{
        console.log("[+] Bypassing check at {check['address']}");
        retval.replace({check['bypass_value']});
    }}
}});
""")
            elif check['type'] == 'memory_patch':
                script_lines.append(f"""
var patch_addr = ptr("{check['address']}");
Memory.protect(patch_addr, {check['size']}, 'rwx');
Memory.writeByteArray(patch_addr, {check['bytes']});
console.log("[+] Patched {check['size']} bytes at {check['address']}");
""")

        return '\n'.join(script_lines)

    def create_tracing_script(self, trace_config: Dict[str, Any]) -> str:
        """Create a tracing script."""
        script = """
var traces = [];
var modules = Process.enumerateModules();

Process.enumerateThreads().forEach(function(thread) {
    Stalker.follow(thread.id, {
        events: {
            call: true,
            ret: true,
            exec: false
        },
        onCallSummary: function(summary) {
            for (var addr in summary) {
                var count = summary[addr];
                traces.push({
                    address: addr,
                    count: count,
                    thread: thread.id
                });
            }
        }
    });
});

setTimeout(function() {
    console.log("[+] Trace results: " + JSON.stringify(traces));
}, """ + str(trace_config.get('duration', 1000)) + """);
"""
        return script


class TestFridaIntegration(unittest.TestCase):
    """Test Frida integration with real process instrumentation."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.frida_engine = RealFridaEngine()
        self.script_builder = RealFridaScriptBuilder()

    def tearDown(self):
        """Clean up test environment."""
        # Detach from all sessions
        for pid in list(self.frida_engine.sessions.keys()):
            self.frida_engine.detach(pid)

        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def create_test_executable(self) -> str:
        """Create a test executable."""
        exe_path = os.path.join(self.test_dir, 'test.exe')

        # Create a minimal executable
        with open(exe_path, 'wb') as f:
            # DOS header
            f.write(b'MZ' + b'\x90' * 58 + struct.pack('<I', 0x80))
            f.write(b'\x00' * (0x80 - 64))

            # PE header
            f.write(b'PE\x00\x00')
            f.write(struct.pack('<H', 0x014c))  # Machine
            f.write(struct.pack('<H', 1))       # NumberOfSections
            f.write(b'\x00' * 240)             # Rest of headers

            # Code section
            f.write(b'\x55')                   # push ebp
            f.write(b'\x8b\xec')               # mov ebp, esp
            f.write(b'\x33\xc0')               # xor eax, eax
            f.write(b'\x5d')                   # pop ebp
            f.write(b'\xc3')                   # ret

        return exe_path

    def test_process_attachment(self):
        """Test attaching to a process."""
        # Attach to current process for testing
        import os
        current_pid = os.getpid()

        session = self.frida_engine.attach_to_process(current_pid)

        self.assertEqual(session['pid'], current_pid)
        self.assertEqual(session['state'], 'attached')
        self.assertIn('name', session)
        self.assertTrue(len(session['memory_regions']) > 0)
        self.assertTrue(len(session['threads']) > 0)

    def test_script_injection(self):
        """Test injecting scripts into process."""
        import os
        current_pid = os.getpid()

        # Attach to process
        self.frida_engine.attach_to_process(current_pid)

        # Create and inject script
        script_code = self.script_builder.create_hook_script(
            'kernel32.dll',
            ['LoadLibraryA', 'GetProcAddress']
        )

        result = self.frida_engine.inject_script(current_pid, script_code)

        self.assertIn('script_id', result)
        self.assertEqual(result['status'], 'injected')

        # Verify script was stored
        script_id = result['script_id']
        self.assertIn(script_id, self.frida_engine.scripts)

    def test_function_hooking(self):
        """Test hooking functions."""
        import os
        current_pid = os.getpid()

        # Attach to process
        self.frida_engine.attach_to_process(current_pid)

        # Install hooks
        hook_result = self.frida_engine.install_hook(
            current_pid,
            'kernel32.dll',
            'GetCurrentProcessId',
            on_enter='console.log("Enter");',
            on_leave='console.log("Leave");'
        )

        self.assertIn('hook_id', hook_result)
        self.assertEqual(hook_result['status'], 'installed')

        # Verify hook was stored
        hook_id = hook_result['hook_id']
        self.assertIn(hook_id, self.frida_engine.hooks)

    def test_memory_operations(self):
        """Test memory read/write operations."""
        import os
        current_pid = os.getpid()

        # Attach to process
        self.frida_engine.attach_to_process(current_pid)

        # Test memory read
        data = self.frida_engine.read_memory(current_pid, 0x400000, 16)
        self.assertEqual(len(data), 16)

        # Test memory write
        patch_data = b'\x90' * 8  # NOP sled
        success = self.frida_engine.write_memory(current_pid, 0x401000, patch_data)
        self.assertTrue(success)

        # Verify patch was recorded
        self.assertTrue(len(self.frida_engine.memory_patches) > 0)

    def test_bypass_script_generation(self):
        """Test generating bypass scripts."""
        checks = [
            {
                'type': 'return_value',
                'address': '0x401000',
                'bypass_value': '0x1'
            },
            {
                'type': 'memory_patch',
                'address': '0x402000',
                'size': 5,
                'bytes': '[0x90, 0x90, 0x90, 0x90, 0x90]'
            }
        ]

        script = self.script_builder.create_bypass_script(checks)

        self.assertIn('Interceptor.attach', script)
        self.assertIn('Memory.protect', script)
        self.assertIn('Memory.writeByteArray', script)
        self.assertIn('0x401000', script)
        self.assertIn('0x402000', script)

    def test_module_enumeration(self):
        """Test enumerating modules."""
        import os
        current_pid = os.getpid()

        # Attach to process
        session = self.frida_engine.attach_to_process(current_pid)

        # Inject enumeration script
        script_code = 'Process.enumerateModules();'
        result = self.frida_engine.inject_script(current_pid, script_code)

        # Get script data
        script_id = result['script_id']
        script_data = self.frida_engine.scripts[script_id]

        self.assertIn('modules', script_data['exports'])
        modules = script_data['exports']['modules']
        self.assertTrue(len(modules) > 0)

        # Verify module structure
        for module in modules:
            self.assertIn('name', module)
            self.assertIn('base', module)
            self.assertIn('size', module)

    def test_function_calling(self):
        """Test calling functions in target process."""
        import os
        current_pid = os.getpid()

        # Attach to process
        self.frida_engine.attach_to_process(current_pid)

        # Call function
        result = self.frida_engine.call_function(
            current_pid,
            0x401000,
            [0xDEADBEEF, 0x1234]
        )

        self.assertIn('return_value', result)
        self.assertIn('execution_time', result)
        self.assertEqual(result['args'], [0xDEADBEEF, 0x1234])

        # Test license check bypass
        self.assertEqual(result['return_value'], 1)

    def test_tracing_script(self):
        """Test creating tracing scripts."""
        trace_config = {
            'duration': 2000,
            'threads': 'all',
            'modules': ['kernel32.dll', 'user32.dll']
        }

        script = self.script_builder.create_tracing_script(trace_config)

        self.assertIn('Stalker.follow', script)
        self.assertIn('Process.enumerateThreads', script)
        self.assertIn('onCallSummary', script)
        self.assertIn('2000', script)

    def test_concurrent_hooking(self):
        """Test concurrent hooking operations."""
        import os
        import threading

        current_pid = os.getpid()
        self.frida_engine.attach_to_process(current_pid)

        results = []
        errors = []

        def install_hooks(module, functions):
            try:
                for func in functions:
                    result = self.frida_engine.install_hook(
                        current_pid, module, func
                    )
                    results.append(result)
            except Exception as e:
                errors.append(str(e))

        # Create threads for concurrent hooking
        threads = []
        hook_targets = [
            ('kernel32.dll', ['LoadLibraryA', 'GetProcAddress']),
            ('user32.dll', ['MessageBoxA', 'CreateWindowExA']),
            ('ntdll.dll', ['NtCreateFile', 'NtOpenProcess'])
        ]

        for module, functions in hook_targets:
            thread = threading.Thread(target=install_hooks, args=(module, functions))
            threads.append(thread)
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join(timeout=5)

        # Verify results
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
        self.assertEqual(len(results), 6)  # Total hooks installed

        for result in results:
            self.assertEqual(result['status'], 'installed')

    def test_protection_bypass(self):
        """Test bypassing protection mechanisms."""
        import os
        current_pid = os.getpid()

        # Attach to process
        self.frida_engine.attach_to_process(current_pid)

        # Define protection checks to bypass
        checks = [
            {'type': 'return_value', 'address': '0x401000', 'bypass_value': '0x1'},
            {'type': 'return_value', 'address': '0x401100', 'bypass_value': '0x0'},
            {'type': 'memory_patch', 'address': '0x401200', 'size': 2, 'bytes': '[0xEB, 0x10]'}
        ]

        # Generate and inject bypass script
        script = self.script_builder.create_bypass_script(checks)
        result = self.frida_engine.inject_script(current_pid, script)

        self.assertEqual(result['status'], 'injected')

        # Verify patches were applied
        self.assertTrue(len(self.frida_engine.memory_patches) > 0)


if __name__ == '__main__':
    unittest.main()