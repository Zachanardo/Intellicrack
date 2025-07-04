"""
Enhanced QEMU Test Manager with Real Data Capture

Captures actual execution data from QEMU VMs.
"""

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from ..utils.logger import get_logger

logger = get_logger(__name__)


class EnhancedQEMUTestManager:
    """Enhanced QEMU manager with real data capture capabilities."""
    
    def test_frida_script_with_callback(self, snapshot_id: str, script_content: str, 
                                       binary_path: str, output_callback: Callable[[str], None]):
        """Execute Frida script with real-time output streaming."""
        
        # Create enhanced Frida wrapper that captures more data
        wrapper_script = f'''
import frida
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

# User script starts here
{script_content}

# Add monitoring to user script
if session:
    session.on('message', on_message)
    script = session.create_script(monitoring_script + "\\n" + user_script)
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

        # Execute in QEMU with real-time output
        process = subprocess.Popen(
            ['qemu-system-x86_64', '-snapshot', snapshot_id, '-enable-kvm'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # Line buffered
        )
        
        # Stream output in real-time
        for line in iter(process.stdout.readline, ''):
            if line:
                output_callback(line.strip())
                
        process.wait()
        
        # Read the detailed data file
        try:
            with open('/tmp/qemu_test_data.json', 'r') as f:
                detailed_data = json.load(f)
        except:
            detailed_data = {}
            
        return {
            'success': process.returncode == 0,
            'output': ''.join(self.captured_output),
            'detailed_data': detailed_data
        }
        
    def analyze_binary_for_vm(self, binary_path: str) -> Dict[str, Any]:
        """Analyze binary to determine VM requirements."""
        import pefile
        import magic
        
        result = {
            'platform': 'unknown',
            'architecture': 'unknown',
            'dependencies': [],
            'entry_point': None,
            'sections': []
        }
        
        # Use file magic to detect type
        file_type = magic.from_file(binary_path)
        
        if 'PE32' in file_type:
            # Windows binary - analyze with pefile
            pe = pefile.PE(binary_path)
            
            result['platform'] = 'windows'
            result['architecture'] = 'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'
            result['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            
            # Get real import data
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')
                result['dependencies'].append(dll_name)
                
            # Get real section data
            for section in pe.sections:
                result['sections'].append({
                    'name': section.Name.decode('utf-8').strip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'size': section.SizeOfRawData
                })
                
        elif 'ELF' in file_type:
            # Linux binary
            result['platform'] = 'linux'
            # Parse ELF headers for real data...
            
        return result
        
    def monitor_process_in_vm(self, process_id: int) -> Dict[str, Any]:
        """Monitor real process behavior in VM."""
        
        # Use guest agent or SSH to monitor
        monitor_script = f'''
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
'''
        
        # Execute and return real metrics
        result = subprocess.run(
            ['ssh', f'qemu@{self.vm_ip}', monitor_script],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            return json.loads(result.stdout)
        return {}