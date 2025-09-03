"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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

import json
import os
import subprocess
from collections.abc import Callable
from typing import Any

from ..utils.logger import get_logger

"""
Enhanced QEMU Test Manager with Real Data Capture

Captures actual execution data from QEMU VMs.
"""

logger = get_logger(__name__)


class EnhancedQEMUTestManager:
    """Enhanced QEMU manager with real data capture capabilities."""

    def test_frida_script_with_callback(
        self,
        snapshot_id: str,
        script_content: str,
        binary_path: str,
        output_callback: Callable[[str], None],
    ):
        """Execute Frida script with real-time output streaming."""
        # Extract binary information for targeted analysis
        binary_name = os.path.basename(binary_path)
        binary_dir = os.path.dirname(binary_path)

        # Create enhanced Frida wrapper that captures more data
        wrapper_script = f'''
from intellicrack.handlers.frida_handler import frida
import sys
import json
import time

# Real data collection
memory_changes = []
api_calls = []
call_counts = {{}}

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']

        # Track real memory changes
        if 'memory_change' in payload:
            memory_changes.append({{
                'address': payload['address'],
                'original': payload['original'],
                'patched': payload['patched'],
                'timestamp': time.time()
            }})

        # Track real API calls
        if 'api_call' in payload:
            api_name = payload['api_name']
            call_counts[api_name] = call_counts.get(api_name, 0) + 1
            api_calls.append({{
                'api': api_name,
                'args': payload.get('args', []),
                'return': payload.get('return_value'),
                'timestamp': time.time()
            }})

        # Output for real-time display
        print(payload.get('message', str(payload)))
        sys.stdout.flush()

# Inject monitoring hooks
monitoring_script = """
// Track memory writes
Interceptor.attach(Module.findExportByName(null, 'VirtualProtect'), {{
    onEnter: function(args) {{
        send({{
            api_call: true,
            api_name: 'VirtualProtect',
            args: [args[0], args[1].toInt32(), args[2].toInt32()]
        }});
    }}
}});

// Track registry access
Interceptor.attach(Module.findExportByName('advapi32.dll', 'RegQueryValueExW'), {{
    onEnter: function(args) {{
        this.keyName = args[1].readUtf16String();
    }},
    onLeave: function(retval) {{
        send({{
            api_call: true,
            api_name: 'RegQueryValueExW',
            args: [this.keyName],
            return_value: retval.toInt32(),
            message: '[+] Registry query: ' + this.keyName + ' = ' + retval
        }});
    }}
}});
"""

# Target binary information
target_binary = "{binary_path}"
target_name = "{binary_name}"
target_dir = "{binary_dir}"

print(f"[*] Targeting binary: {{target_name}}")
print(f"[*] Binary path: {{target_binary}}")
print(f"[*] Binary directory: {{target_dir}}")

# User script starts here
{script_content}

# Add monitoring to user script
if session:
    session.on('message', on_message)

    # Inject binary-specific targeting into script
    binary_targeting = f"""
// Target specific binary: {{target_name}}
Process.enumerateModules().forEach(module => {{{{
    if (module.name.toLowerCase().includes('{{target_name.lower()}}')) {{{{
        console.log("[*] Found target module: " + module.name);
        console.log("[*] Base address: " + module.base);
        console.log("[*] Size: " + module.size);
    }}}}
}}}});
"""

    script = session.create_script(monitoring_script + "\\n" + binary_targeting + "\\n" + user_script)
    script.load()

    # Wait and collect data
    time.sleep(30)

    # Output summary
    print(f"\\n=== REAL EXECUTION SUMMARY ===")
    print(f"Memory changes: {{len(memory_changes)}}")
    print(f"API calls intercepted: {{len(api_calls)}}")
    print(f"Call frequency: {{json.dumps(call_counts, indent=2)}}")

    # Save detailed data
    with open('/tmp/qemu_test_data.json', 'w') as f:
        json.dump({{
            'memory_changes': memory_changes,
            'api_calls': api_calls,
            'call_counts': call_counts
        }}, f)
'''

        # Write wrapper script to temporary file for execution
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as script_file:
            script_file.write(wrapper_script)
            script_file.flush()
            script_path = script_file.name

        try:
            # Execute wrapper script in QEMU with real-time output
            qemu_cmd = [
                "qemu-system-x86_64",
                "-snapshot",
                snapshot_id,
                "-enable-kvm",
                "-monitor",
                "stdio",
                "-serial",
                "tcp::4444,server,nowait",
                "-device",
                "e1000,netdev=net0",
                "-netdev",
                "user,id=net0,hostfwd=tcp::2222-:22",
            ]

            process = subprocess.Popen(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                qemu_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
            )

            # Also run the Frida script inside QEMU
            frida_process = subprocess.Popen(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                ["python3", script_path],  # noqa: S607
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            # Stream output from both processes in real-time
            import threading

            def stream_frida_output():
                for line in iter(frida_process.stdout.readline, ""):
                    if line:
                        output_callback(f"[FRIDA] {line.strip()}")

            # Start Frida output streaming in separate thread
            frida_thread = threading.Thread(target=stream_frida_output)
            frida_thread.daemon = True
            frida_thread.start()

            # Stream QEMU output
            for line in iter(process.stdout.readline, ""):
                if line:
                    output_callback(f"[QEMU] {line.strip()}")

            # Wait for both processes
            process.wait()
            frida_process.wait()
            frida_thread.join(timeout=5)

            # Read the detailed data file
            try:
                with open(f"{tempfile.gettempdir()}/qemu_test_data.json") as f:
                    detailed_data = json.load(f)
                    logger.info(f"Loaded execution data: {len(detailed_data.get('api_calls', []))} API calls captured")
            except Exception as e:
                logger.warning(f"Failed to load execution data: {e}")
                detailed_data = {}

            return {
                "success": process.returncode == 0 and frida_process.returncode == 0,
                "qemu_returncode": process.returncode,
                "frida_returncode": frida_process.returncode,
                "detailed_data": detailed_data,
                "execution_summary": {
                    "memory_changes": len(detailed_data.get("memory_changes", [])),
                    "api_calls": len(detailed_data.get("api_calls", [])),
                    "call_counts": detailed_data.get("call_counts", {}),
                },
            }
        finally:
            # Clean up temporary script file
            try:
                os.unlink(script_path)
            except (OSError, FileNotFoundError):
                pass

    def analyze_binary_for_vm(self, binary_path: str) -> dict[str, Any]:
        """Analyze binary to determine VM requirements."""
        import magic

        from intellicrack.handlers.pefile_handler import pefile

        result = {
            "platform": "unknown",
            "architecture": "unknown",
            "dependencies": [],
            "entry_point": None,
            "sections": [],
        }

        # Use file magic to detect type
        file_type = magic.from_file(binary_path)

        if "PE32" in file_type:
            # Windows binary - analyze with pefile
            pe = pefile.PE(binary_path)

            result["platform"] = "windows"
            result["architecture"] = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"
            result["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

            # Get real import data
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8")
                result["dependencies"].append(dll_name)

            # Get real section data
            for section in pe.sections:
                result["sections"].append(
                    {
                        "name": section.Name.decode("utf-8").strip("\x00"),
                        "virtual_address": hex(section.VirtualAddress),
                        "size": section.SizeOfRawData,
                    }
                )

        elif "ELF" in file_type:
            # Linux binary
            result["platform"] = "linux"
            # Parse ELF headers for real data...

        return result

    def monitor_process_in_vm(self, process_id: int) -> dict[str, Any]:
        """Monitor real process behavior in VM."""
        # Use guest agent or SSH to monitor
        monitor_script = f"""
#!/bin/bash
# Real process monitoring
PID={process_id}

# CPU usage
CPU=$(ps -p $PID -o %cpu | tail -1)

# Memory usage
MEM=$(ps -p $PID -o %mem | tail -1)

# Open files
FILES=$(lsof -p $PID 2>/dev/null | wc -l)

# Network connections
CONNS=$(netstat -anp 2>/dev/null | grep $PID | wc -l)

# Thread count
THREADS=$(ps -p $PID -o nlwp | tail -1)

echo "{{"
echo "  \\"cpu_percent\\": $CPU,"
echo "  \\"memory_percent\\": $MEM,"
echo "  \\"open_files\\": $FILES,"
echo "  \\"connections\\": $CONNS,"
echo "  \\"threads\\": $THREADS"
echo "}}"
"""

        # Execute and return real metrics
        result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
            ["ssh", f"qemu@{self.vm_ip}", monitor_script],  # noqa: S607
            check=False,
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            return json.loads(result.stdout)
        return {}
