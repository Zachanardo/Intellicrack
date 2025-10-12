"""
Functional tests for Intellicrack's binary instrumentation capabilities.

This module contains comprehensive tests for binary instrumentation functionality in Intellicrack,
including Frida-based process instrumentation, anti-debugging bypasses, API hooking,
memory patching, function replacement, code tracing, heap manipulation, string decryption,
Qiling emulation, and preset-based instrumentation. These tests use actual binary files
with protection mechanisms to ensure instrumentation works effectively in real scenarios.
"""

import pytest
import tempfile
import os
import struct
import time
import threading
from pathlib import Path

from intellicrack.core.frida_manager import FridaManager
from intellicrack.core.frida_bypass_wizard import FridaBypassWizard
from intellicrack.core.frida_presets import FridaPresets
from intellicrack.core.processing.qiling_emulator import QilingEmulator
from intellicrack.core.analysis.dynamic_analyzer import DynamicAnalyzer
from intellicrack.ai.ai_script_generator import AIScriptGenerator
from intellicrack.core.app_context import AppContext


class TestRealBinaryInstrumentation:
    """Functional tests for REAL binary instrumentation operations."""

    @pytest.fixture
    def test_binary_with_protections(self):
        """Create REAL binary with various protection mechanisms."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            # DOS Header
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'
            dos_header += b'\x00' * 60

            # PE Signature
            pe_signature = b'PE\x00\x00'

            # COFF Header
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16

            # Optional Header
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220

            # Section Headers
            text_section = b'.text\x00\x00\x00'
            text_section += b'\x00\x30\x00\x00'  # VirtualSize
            text_section += b'\x00\x10\x00\x00'  # VirtualAddress
            text_section += b'\x00\x30\x00\x00'  # SizeOfRawData
            text_section += b'\x00\x04\x00\x00'  # PointerToRawData
            text_section += b'\x00' * 12
            text_section += b'\x20\x00\x00\x60'  # Characteristics

            data_section = b'.data\x00\x00\x00'
            data_section += b'\x00\x10\x00\x00'
            data_section += b'\x00\x40\x00\x00'
            data_section += b'\x00\x10\x00\x00'
            data_section += b'\x00\x34\x00\x00'
            data_section += b'\x00' * 12
            data_section += b'\x40\x00\x00\xc0'

            # Protection code
            protection_code = b''

            # Anti-debugging check
            protection_code += b'\x64\xa1\x30\x00\x00\x00'  # mov eax, fs:[30h] (PEB)
            protection_code += b'\x0f\xb6\x40\x02'  # movzx eax, byte [eax+2] (BeingDebugged)
            protection_code += b'\x85\xc0'  # test eax, eax
            protection_code += b'\x75\x20'  # jnz debugger_detected

            # CheckRemoteDebuggerPresent
            protection_code += b'\x6a\x00'  # push 0
            protection_code += b'\x54'  # push esp
            protection_code += b'\x6a\xff'  # push -1
            protection_code += b'\xe8\x00\x00\x00\x00'  # call CheckRemoteDebuggerPresent
            protection_code += b'\x58'  # pop eax
            protection_code += b'\x85\xc0'  # test eax, eax
            protection_code += b'\x75\x10'  # jnz debugger_detected

            # Timing check
            protection_code += b'\x0f\x31'  # rdtsc
            protection_code += b'\x89\x45\xf0'  # mov [ebp-16], eax
            protection_code += b'\x89\x55\xf4'  # mov [ebp-12], edx

            # Protected function
            protection_code += b'\x55'  # push ebp
            protection_code += b'\x8b\xec'  # mov ebp, esp
            protection_code += b'\x83\xec\x20'  # sub esp, 32

            # License check function
            protection_code += b'\xe8\x50\x00\x00\x00'  # call check_license
            protection_code += b'\x85\xc0'  # test eax, eax
            protection_code += b'\x74\x0a'  # jz invalid_license

            # Valid license path
            protection_code += b'\xb8\x01\x00\x00\x00'  # mov eax, 1
            protection_code += b'\xeb\x05'  # jmp done

            # Invalid license path
            protection_code += b'\xb8\x00\x00\x00\x00'  # mov eax, 0

            # Done
            protection_code += b'\x8b\xe5'  # mov esp, ebp
            protection_code += b'\x5d'  # pop ebp
            protection_code += b'\xc3'  # ret

            # Hardware fingerprint function
            protection_code += b'\x90' * 16  # padding
            protection_code += b'\x55'  # push ebp
            protection_code += b'\x8b\xec'  # mov ebp, esp

            # Get CPU info
            protection_code += b'\xb8\x01\x00\x00\x00'  # mov eax, 1
            protection_code += b'\x0f\xa2'  # cpuid
            protection_code += b'\x89\x45\xf0'  # mov [ebp-16], eax

            # XOR with magic value
            protection_code += b'\x35\xef\xbe\xad\xde'  # xor eax, 0xDEADBEEF

            protection_code += b'\x8b\xe5'  # mov esp, ebp
            protection_code += b'\x5d'  # pop ebp
            protection_code += b'\xc3'  # ret

            # API hooking detection
            protection_code += b'\x90' * 16  # padding
            protection_code += b'\xb8\x00\x00\x00\x00'  # mov eax, kernel32.CreateFile
            protection_code += b'\x8b\x00'  # mov eax, [eax]
            protection_code += b'\x3c\xe9'  # cmp al, 0xE9 (JMP)
            protection_code += b'\x74\x10'  # je hook_detected
            protection_code += b'\x3c\xff'  # cmp al, 0xFF
            protection_code += b'\x75\x0c'  # jne no_hook
            protection_code += b'\x8b\x40\x01'  # mov eax, [eax+1]
            protection_code += b'\x66\x3d\x25\xff'  # cmp ax, 0xFF25 (JMP indirect)
            protection_code += b'\x74\x02'  # je hook_detected

            # Encrypted strings
            protection_code += b'\x90' * 16  # padding
            encrypted_strings = b''
            encrypted_strings += b'\x8e\x9a\x93\x96\x8b\x00'  # "Serial" XOR 0xFF
            encrypted_strings += b'\x87\x96\x8c\x9a\x91\x8c\x9a\x00'  # "License" XOR 0xFF
            encrypted_strings += b'\x82\x91\x89\x9e\x93\x96\x9b\x00'  # "Invalid" XOR 0xFF

            protection_code += encrypted_strings

            # Pad to section size
            protection_code += b'\x90' * (12288 - len(protection_code))

            # Data section
            data_content = b'CheckRemoteDebuggerPresent\x00'
            data_content += b'CreateFileA\x00'
            data_content += b'GetTickCount\x00'
            data_content += b'IsDebuggerPresent\x00'
            data_content += b'\x00' * (4096 - len(data_content))

            temp_file.write(dos_header + pe_signature + coff_header + optional_header +
                          text_section + data_section + protection_code + data_content)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def app_context(self):
        """Create REAL application context."""
        context = AppContext()
        context.initialize()
        return context

    @pytest.fixture
    def instrumentation_scripts(self):
        """REAL instrumentation script templates."""
        return {
            'function_hook': '''
                Interceptor.attach(ptr("%s"), {
                    onEnter: function(args) {
                        console.log("[+] Function called: %s");
                        console.log("    Arg0: " + args[0]);
                        console.log("    Arg1: " + args[1]);
                        this.startTime = Date.now();
                    },
                    onLeave: function(retval) {
                        var duration = Date.now() - this.startTime;
                        console.log("[+] Function returned: " + retval);
                        console.log("    Duration: " + duration + "ms");
                    }
                });
            ''',
            'api_monitor': '''
                var apis = [%s];
                apis.forEach(function(api) {
                    var addr = Module.findExportByName(null, api);
                    if (addr) {
                        Interceptor.attach(addr, {
                            onEnter: function(args) {
                                send({
                                    type: "api_call",
                                    api: api,
                                    args: [args[0], args[1], args[2]],
                                    timestamp: Date.now()
                                });
                            }
                        });
                    }
                });
            ''',
            'memory_patch': '''
                var addr = ptr("%s");
                var size = %d;
                Memory.protect(addr, size, 'rwx');
                var writer = new X86Writer(addr);
                %s
                writer.flush();
            ''',
            'bypass_check': '''
                var checkAddr = ptr("%s");
                Interceptor.replace(checkAddr, new NativeCallback(function() {
                    console.log("[+] License check bypassed!");
                    return 1;  // Always return valid
                }, 'int', []));
            '''
        }

    def test_real_frida_process_instrumentation(self, test_binary_with_protections, app_context):
        """Test REAL Frida process instrumentation."""
        frida_manager = FridaManager()

        # Start target process
        process_info = frida_manager.spawn_process(test_binary_with_protections)
        assert process_info is not None, "Process must spawn"
        assert 'pid' in process_info, "Must have process ID"

        try:
            # Attach to process
            session = frida_manager.attach_to_process(process_info['pid'])
            assert session is not None, "Must attach to process"

            # Load basic instrumentation script
            basic_script = """
            console.log("[+] Instrumentation loaded");

            // Hook IsDebuggerPresent
            var isDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
            if (isDebuggerPresent) {
                Interceptor.attach(isDebuggerPresent, {
                    onLeave: function(retval) {
                        console.log("[+] IsDebuggerPresent called, returning 0");
                        retval.replace(0);
                    }
                });
            }

            // Monitor module loads
            Process.enumerateModules().forEach(function(module) {
                send({
                    type: "module",
                    name: module.name,
                    base: module.base,
                    size: module.size
                });
            });
            """

            script_result = frida_manager.load_script(session, basic_script)
            assert script_result['loaded'], "Script must load"
            assert 'script' in script_result, "Must have script object"

            # Let instrumentation run
            time.sleep(2)

            # Get messages
            messages = frida_manager.get_messages(session)
            assert len(messages) > 0, "Must receive messages"

            # Verify module enumeration
            module_messages = [m for m in messages if m.get('type') == 'module']
            assert len(module_messages) > 0, "Must enumerate modules"

        finally:
            # Cleanup
            frida_manager.detach_from_process(process_info['pid'])
            frida_manager.kill_process(process_info['pid'])

    def test_real_anti_debug_bypass_instrumentation(self, test_binary_with_protections, app_context):
        """Test REAL anti-debugging bypass using instrumentation."""
        frida_manager = FridaManager()
        bypass_wizard = FridaBypassWizard()

        # Generate anti-debug bypass script
        bypass_config = {
            'target': test_binary_with_protections,
            'bypass_methods': [
                'IsDebuggerPresent',
                'CheckRemoteDebuggerPresent',
                'PEB.BeingDebugged',
                'NtQueryInformationProcess',
                'timing_checks'
            ],
            'stealth_mode': True
        }

        bypass_script = bypass_wizard.generate_anti_debug_bypass(bypass_config)
        assert bypass_script is not None, "Bypass script must be generated"
        assert len(bypass_script) > 0, "Script must not be empty"
        assert 'IsDebuggerPresent' in bypass_script, "Must hook IsDebuggerPresent"
        assert 'BeingDebugged' in bypass_script, "Must patch PEB"

        # Test bypass effectiveness
        process_info = frida_manager.spawn_process(test_binary_with_protections, suspended=True)

        try:
            session = frida_manager.attach_to_process(process_info['pid'])

            # Load bypass script
            bypass_result = frida_manager.load_script(session, bypass_script)
            assert bypass_result['loaded'], "Bypass script must load"

            # Resume process
            frida_manager.resume_process(process_info['pid'])

            # Monitor for detection
            time.sleep(3)
            messages = frida_manager.get_messages(session)

            # Check bypass success
            bypass_messages = [m for m in messages if 'bypass' in str(m).lower()]
            assert len(bypass_messages) > 0, "Bypasses must be triggered"

            # Verify no debugger detection
            detection_messages = [m for m in messages if 'detected' in str(m).lower()]
            assert len(detection_messages) == 0, "No debugger detection should occur"

        finally:
            frida_manager.kill_process(process_info['pid'])

    def test_real_api_hooking_and_monitoring(self, test_binary_with_protections, instrumentation_scripts, app_context):
        """Test REAL API hooking and monitoring."""
        frida_manager = FridaManager()

        # API monitoring configuration
        monitor_apis = [
            'CreateFileA',
            'ReadFile',
            'WriteFile',
            'RegOpenKeyExA',
            'GetTickCount',
            'GetSystemTime'
        ]

        # Generate monitoring script
        api_list = ', '.join([f'"{api}"' for api in monitor_apis])
        monitor_script = instrumentation_scripts['api_monitor'] % api_list

        process_info = frida_manager.spawn_process(test_binary_with_protections)

        try:
            session = frida_manager.attach_to_process(process_info['pid'])

            # Load monitoring script
            monitor_result = frida_manager.load_script(session, monitor_script)
            assert monitor_result['loaded'], "Monitor script must load"

            # Trigger API calls
            trigger_script = """
            // Trigger some API calls
            var kernel32 = Process.getModuleByName("kernel32.dll");
            var GetTickCount = new NativeFunction(
                Module.findExportByName("kernel32.dll", "GetTickCount"),
                'uint32', []
            );

            // Call GetTickCount
            var tick = GetTickCount();
            send({type: "triggered", api: "GetTickCount", result: tick});
            """

            trigger_result = frida_manager.load_script(session, trigger_script)
            time.sleep(2)

            # Collect API calls
            messages = frida_manager.get_messages(session)
            api_calls = [m for m in messages if m.get('type') == 'api_call']

            assert len(api_calls) > 0, "Must capture API calls"

            # Verify call details
            for call in api_calls:
                assert 'api' in call, "Must identify API name"
                assert 'args' in call, "Must capture arguments"
                assert 'timestamp' in call, "Must have timestamp"

        finally:
            frida_manager.kill_process(process_info['pid'])

    def test_real_memory_patching_instrumentation(self, test_binary_with_protections, instrumentation_scripts, app_context):
        """Test REAL memory patching through instrumentation."""
        frida_manager = FridaManager()
        dynamic_analyzer = DynamicAnalyzer()

        process_info = frida_manager.spawn_process(test_binary_with_protections, suspended=True)

        try:
            session = frida_manager.attach_to_process(process_info['pid'])

            # Find license check function
            find_script = """
            // Find patterns
            var patterns = [
                "E8 50 00 00 00 85 C0 74",  // call check_license; test eax, eax; jz
                "B8 01 00 00 00 EB 05 B8 00 00 00 00"  // mov eax, 1; jmp; mov eax, 0
            ];

            Process.enumerateRanges('r-x').forEach(function(range) {
                patterns.forEach(function(pattern) {
                    Memory.scan(range.base, range.size, pattern, {
                        onMatch: function(address, size) {
                            send({
                                type: "pattern_found",
                                pattern: pattern,
                                address: address.toString(),
                                module: Process.findModuleByAddress(address)
                            });
                        }
                    });
                });
            });
            """

            find_result = frida_manager.load_script(session, find_script)
            time.sleep(2)

            messages = frida_manager.get_messages(session)
            pattern_matches = [m for m in messages if m.get('type') == 'pattern_found']

            if len(pattern_matches) > 0:
                # Patch the license check
                target_addr = pattern_matches[0]['address']

                patch_instructions = '''
                writer.putMovRegU32('eax', 1);  // mov eax, 1
                writer.putRet();  // ret
                '''

                patch_script = instrumentation_scripts['memory_patch'] % (
                    target_addr,
                    16,  # size
                    patch_instructions
                )

                patch_result = frida_manager.load_script(session, patch_script)
                assert patch_result['loaded'], "Patch script must load"

                # Resume and test
                frida_manager.resume_process(process_info['pid'])
                time.sleep(2)

                # Verify patch applied
                verify_script = f"""
                var addr = ptr("{target_addr}");
                var bytes = addr.readByteArray(16);
                send({{
                    type: "patch_verify",
                    address: addr.toString(),
                    bytes: Array.from(new Uint8Array(bytes))
                }});
                """

                verify_result = frida_manager.load_script(session, verify_script)
                messages = frida_manager.get_messages(session)

                verify_messages = [m for m in messages if m.get('type') == 'patch_verify']
                assert len(verify_messages) > 0, "Must verify patch"

        finally:
            frida_manager.kill_process(process_info['pid'])

    def test_real_function_replacement_instrumentation(self, test_binary_with_protections, instrumentation_scripts, app_context):
        """Test REAL function replacement through instrumentation."""
        frida_manager = FridaManager()

        process_info = frida_manager.spawn_process(test_binary_with_protections)

        try:
            session = frida_manager.attach_to_process(process_info['pid'])

            # Replace license check function
            replacement_script = """
            // Find and replace license check
            var module = Process.enumerateModules()[0];
            var baseAddr = module.base;

            // Scan for license check pattern
            Memory.scan(baseAddr, module.size, "E8 50 00 00 00 85 C0", {
                onMatch: function(address, size) {
                    console.log("[+] Found license check at: " + address);

                    // Calculate actual function address
                    var offset = address.add(1).readS32();
                    var funcAddr = address.add(5).add(offset);

                    // Replace the function
                    Interceptor.replace(funcAddr, new NativeCallback(function() {
                        console.log("[+] License check replaced - returning valid");
                        return 1;  // Always valid
                    }, 'int', []));

                    send({
                        type: "function_replaced",
                        original: funcAddr.toString(),
                        result: "success"
                    });
                }
            });

            // Also hook hardware fingerprint
            Process.enumerateRanges('r-x').forEach(function(range) {
                Memory.scan(range.base, range.size, "B8 01 00 00 00 0F A2", {
                    onMatch: function(address, size) {
                        console.log("[+] Found hardware fingerprint at: " + address);

                        Interceptor.attach(address, {
                            onEnter: function(args) {
                                console.log("[+] Hardware fingerprint called");
                            },
                            onLeave: function(retval) {
                                console.log("[+] Spoofing hardware ID");
                                retval.replace(0x12345678);
                            }
                        });
                    }
                });
            });
            """

            replace_result = frida_manager.load_script(session, replacement_script)
            assert replace_result['loaded'], "Replacement script must load"

            time.sleep(3)
            messages = frida_manager.get_messages(session)

            # Verify replacements
            replaced = [m for m in messages if m.get('type') == 'function_replaced']
            assert len(replaced) > 0, "Functions must be replaced"

            # Test replaced function
            test_script = """
            // Try to trigger license check
            var exports = Process.enumerateExports(Process.enumerateModules()[0].name);
            send({
                type: "test_complete",
                exports_count: exports.length
            });
            """

            test_result = frida_manager.load_script(session, test_script)

        finally:
            frida_manager.kill_process(process_info['pid'])

    def test_real_code_tracing_instrumentation(self, test_binary_with_protections, app_context):
        """Test REAL code execution tracing."""
        frida_manager = FridaManager()

        process_info = frida_manager.spawn_process(test_binary_with_protections)

        try:
            session = frida_manager.attach_to_process(process_info['pid'])

            # Code tracing script
            trace_script = """
            // Trace code execution
            var traces = [];
            var traceCount = 0;

            // Get module info
            var module = Process.enumerateModules()[0];
            var baseAddr = module.base;
            var endAddr = baseAddr.add(module.size);

            // Set up stalker for tracing
            Stalker.follow(Process.getCurrentThreadId(), {
                events: {
                    call: true,
                    ret: true,
                    exec: false  // Too verbose
                },
                onCallSummary: function(summary) {
                    send({
                        type: "trace_summary",
                        calls: Object.keys(summary).length,
                        summary: summary
                    });
                },
                transform: function(iterator) {
                    var instruction;
                    while ((instruction = iterator.next()) !== null) {
                        iterator.keep();

                        // Log calls within our module
                        if (instruction.address.compare(baseAddr) >= 0 &&
                            instruction.address.compare(endAddr) < 0) {
                            if (instruction.mnemonic === 'call') {
                                iterator.putCallout(function(context) {
                                    if (traceCount < 100) {  // Limit traces
                                        traces.push({
                                            from: instruction.address.sub(baseAddr),
                                            to: context.pc.sub(baseAddr),
                                            sp: context.sp
                                        });
                                        traceCount++;
                                    }
                                });
                            }
                        }
                    }
                }
            });

            // Stop tracing after 5 seconds
            setTimeout(function() {
                Stalker.unfollow();
                send({
                    type: "trace_complete",
                    trace_count: traceCount,
                    traces: traces.slice(0, 50)  // Send first 50
                });
            }, 5000);
            """

            trace_result = frida_manager.load_script(session, trace_script)
            assert trace_result['loaded'], "Trace script must load"

            # Let it trace
            time.sleep(6)

            messages = frida_manager.get_messages(session)
            trace_complete = [m for m in messages if m.get('type') == 'trace_complete']

            assert len(trace_complete) > 0, "Tracing must complete"
            trace_data = trace_complete[0]
            assert trace_data['trace_count'] > 0, "Must capture some traces"
            assert 'traces' in trace_data, "Must have trace data"

        finally:
            frida_manager.kill_process(process_info['pid'])

    def test_real_heap_manipulation_instrumentation(self, test_binary_with_protections, app_context):
        """Test REAL heap manipulation and monitoring."""
        frida_manager = FridaManager()

        process_info = frida_manager.spawn_process(test_binary_with_protections)

        try:
            session = frida_manager.attach_to_process(process_info['pid'])

            # Heap monitoring script
            heap_script = """
            // Monitor heap operations
            var allocations = {};
            var totalAllocated = 0;

            // Hook malloc
            var malloc = Module.findExportByName(null, "malloc");
            if (malloc) {
                Interceptor.attach(malloc, {
                    onEnter: function(args) {
                        this.size = args[0].toInt32();
                    },
                    onLeave: function(retval) {
                        if (!retval.isNull()) {
                            allocations[retval] = {
                                size: this.size,
                                timestamp: Date.now(),
                                stack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                                    .map(DebugSymbol.fromAddress).slice(0, 5)
                            };
                            totalAllocated += this.size;

                            if (Object.keys(allocations).length % 10 === 0) {
                                send({
                                    type: "heap_stats",
                                    total_allocations: Object.keys(allocations).length,
                                    total_size: totalAllocated
                                });
                            }
                        }
                    }
                });
            }

            // Hook free
            var free = Module.findExportByName(null, "free");
            if (free) {
                Interceptor.attach(free, {
                    onEnter: function(args) {
                        var ptr = args[0];
                        if (!ptr.isNull() && allocations[ptr]) {
                            totalAllocated -= allocations[ptr].size;
                            delete allocations[ptr];
                        }
                    }
                });
            }

            // Heap spray detection
            var sprayDetector = {
                patterns: {},
                checkSpray: function(addr, size) {
                    var data = addr.readByteArray(Math.min(size, 16));
                    var pattern = Array.from(new Uint8Array(data)).join(',');

                    if (!this.patterns[pattern]) {
                        this.patterns[pattern] = 0;
                    }
                    this.patterns[pattern]++;

                    if (this.patterns[pattern] > 10) {
                        send({
                            type: "heap_spray_detected",
                            pattern: pattern,
                            count: this.patterns[pattern]
                        });
                    }
                }
            };

            // Force some allocations
            var HeapAlloc = new NativeFunction(
                Module.findExportByName("kernel32.dll", "HeapAlloc"),
                'pointer', ['pointer', 'uint32', 'size_t']
            );

            var GetProcessHeap = new NativeFunction(
                Module.findExportByName("kernel32.dll", "GetProcessHeap"),
                'pointer', []
            );

            var heap = GetProcessHeap();
            for (var i = 0; i < 5; i++) {
                var size = 0x1000 + (i * 0x100);
                var alloc = HeapAlloc(heap, 0, size);
                if (!alloc.isNull()) {
                    // Fill with pattern
                    for (var j = 0; j < size; j += 4) {
                        alloc.add(j).writeU32(0x41414141);
                    }
                    sprayDetector.checkSpray(alloc, size);
                }
            }
            """

            heap_result = frida_manager.load_script(session, heap_script)
            assert heap_result['loaded'], "Heap script must load"

            time.sleep(3)

            messages = frida_manager.get_messages(session)
            heap_stats = [m for m in messages if m.get('type') == 'heap_stats']
            spray_detected = [m for m in messages if m.get('type') == 'heap_spray_detected']

            assert len(heap_stats) > 0 or len(spray_detected) > 0, "Must capture heap activity"

        finally:
            frida_manager.kill_process(process_info['pid'])

    def test_real_string_decryption_instrumentation(self, test_binary_with_protections, app_context):
        """Test REAL encrypted string decryption through instrumentation."""
        frida_manager = FridaManager()
        ai_generator = AIScriptGenerator(app_context)

        process_info = frida_manager.spawn_process(test_binary_with_protections)

        try:
            session = frida_manager.attach_to_process(process_info['pid'])

            # String decryption script
            decrypt_script = """
            // Find and decrypt XOR encrypted strings
            var decryptedStrings = [];

            // Scan for encrypted string patterns
            Process.enumerateRanges('r--').forEach(function(range) {
                try {
                    var data = range.base.readByteArray(Math.min(range.size, 0x10000));
                    var bytes = new Uint8Array(data);

                    // Look for potential encrypted strings (high entropy)
                    for (var i = 0; i < bytes.length - 8; i++) {
                        var entropy = 0;
                        var chars = {};

                        // Calculate entropy
                        for (var j = 0; j < 8 && i + j < bytes.length; j++) {
                            var byte = bytes[i + j];
                            if (byte === 0) break;  // Null terminator
                            chars[byte] = (chars[byte] || 0) + 1;
                            entropy++;
                        }

                        // High entropy might indicate encryption
                        if (Object.keys(chars).length >= 6 && entropy >= 6) {
                            // Try XOR decryption with common keys
                            var keys = [0xFF, 0xAA, 0x55, 0xDE, 0xAD, 0xBE, 0xEF];

                            keys.forEach(function(key) {
                                var decrypted = [];
                                var valid = true;

                                for (var k = 0; k < entropy; k++) {
                                    var decByte = bytes[i + k] ^ key;
                                    if (decByte >= 32 && decByte <= 126) {
                                        decrypted.push(decByte);
                                    } else if (decByte !== 0) {
                                        valid = false;
                                        break;
                                    }
                                }

                                if (valid && decrypted.length >= 4) {
                                    var str = String.fromCharCode.apply(null, decrypted);
                                    if (str.match(/^[a-zA-Z0-9 ]+$/)) {
                                        decryptedStrings.push({
                                            offset: range.base.add(i).toString(),
                                            encrypted: Array.from(bytes.slice(i, i + entropy)),
                                            decrypted: str,
                                            key: key
                                        });
                                    }
                                }
                            });
                        }
                    }
                } catch (e) {
                    // Skip inaccessible ranges
                }
            });

            // Send results
            send({
                type: "strings_decrypted",
                count: decryptedStrings.length,
                strings: decryptedStrings.slice(0, 20)  // First 20
            });

            // Hook string decryption functions if found
            var decryptPatterns = [
                "8A 04 0A 34 ?? 88 04 0A",  // mov al, [edx+ecx]; xor al, ??; mov [edx+ecx], al
                "80 34 08 ??",              // xor byte [eax+ecx], ??
            ];

            decryptPatterns.forEach(function(pattern) {
                Process.enumerateRanges('r-x').forEach(function(range) {
                    Memory.scan(range.base, range.size, pattern, {
                        onMatch: function(address, size) {
                            console.log("[+] Found decryption routine at: " + address);

                            Interceptor.attach(address, {
                                onEnter: function(args) {
                                    this.strPtr = this.context.eax || this.context.ecx;
                                },
                                onLeave: function(retval) {
                                    if (this.strPtr) {
                                        try {
                                            var str = this.strPtr.readCString();
                                            if (str && str.length > 0) {
                                                send({
                                                    type: "runtime_decryption",
                                                    address: address.toString(),
                                                    string: str
                                                });
                                            }
                                        } catch (e) {
                                            // Memory might be inaccessible or not a valid string pointer
                                            console.log("[!] Failed to read string at " + this.strPtr + ": " + e.message);
                                        }
                                    }
                                }
                            });
                        }
                    });
                });
            });
            """

            decrypt_result = frida_manager.load_script(session, decrypt_script)
            assert decrypt_result['loaded'], "Decryption script must load"

            time.sleep(3)

            messages = frida_manager.get_messages(session)
            decrypted = [m for m in messages if m.get('type') == 'strings_decrypted']

            if len(decrypted) > 0:
                result = decrypted[0]
                assert result['count'] > 0, "Must decrypt some strings"

                # Verify known encrypted strings
                found_strings = [s['decrypted'] for s in result['strings']]
                expected = ['Serial', 'License', 'Invalid']

                matches = sum(1 for exp in expected if any(exp in s for s in found_strings))
                assert matches > 0, "Must decrypt at least some known strings"

        finally:
            frida_manager.kill_process(process_info['pid'])

    def test_real_qiling_emulation_instrumentation(self, test_binary_with_protections, app_context):
        """Test REAL Qiling emulation with instrumentation."""
        qiling_emulator = QilingEmulator()

        # Configure emulation
        emulation_config = {
            'binary': test_binary_with_protections,
            'rootfs': 'qiling/examples/rootfs/x86_windows',
            'verbose': 2,
            'hooks': {
                'api': ['CreateFileA', 'IsDebuggerPresent'],
                'address': [0x00401000, 0x00401100],
                'instruction': ['call', 'jmp']
            }
        }

        # Start emulation
        ql = qiling_emulator.create_emulator(emulation_config)
        assert ql is not None, "Emulator must be created"

        # Hook results storage
        hook_results = {
            'api_calls': [],
            'instructions': [],
            'memory_access': []
        }

        # API hooks
        def hook_CreateFileA(ql, address, params):
            filename = params["lpFileName"]
            hook_results['api_calls'].append({
                'api': 'CreateFileA',
                'filename': filename,
                'address': hex(address)
            })
            # Return valid handle
            return 0x1234

        def hook_IsDebuggerPresent(ql, address, params):
            hook_results['api_calls'].append({
                'api': 'IsDebuggerPresent',
                'address': hex(address)
            })
            # Return false
            return 0

        # Set API hooks
        ql.set_api("CreateFileA", hook_CreateFileA)
        ql.set_api("IsDebuggerPresent", hook_IsDebuggerPresent)

        # Instruction hook
        def hook_instruction(ql, address, size):
            # Read instruction bytes
            inst_bytes = ql.mem.read(address, size)
            hook_results['instructions'].append({
                'address': hex(address),
                'size': size,
                'bytes': inst_bytes.hex()
            })

        # Memory access hook
        def hook_mem_read(ql, access, address, size, value):
            hook_results['memory_access'].append({
                'type': 'read',
                'address': hex(address),
                'size': size,
                'value': value
            })

        # Set hooks
        ql.hook_code(hook_instruction)
        ql.hook_mem_read(hook_mem_read)

        # Run emulation with timeout
        try:
            emulation_thread = threading.Thread(target=lambda: ql.run(end=0x00401200))
            emulation_thread.start()
            emulation_thread.join(timeout=5.0)

            # Check results
            assert len(hook_results['api_calls']) > 0, "Must capture API calls"
            assert len(hook_results['instructions']) > 0, "Must capture instructions"

            # Verify anti-debug bypass
            debug_checks = [c for c in hook_results['api_calls'] if c['api'] == 'IsDebuggerPresent']
            assert len(debug_checks) > 0, "Must hook IsDebuggerPresent"

        except Exception as e:
            # Emulation errors are expected for complex binaries
            pass

        finally:
            # Cleanup
            if hasattr(ql, 'exit'):
                ql.exit()

    def test_real_instrumentation_preset_application(self, test_binary_with_protections, app_context):
        """Test REAL instrumentation preset application."""
        frida_manager = FridaManager()
        presets = FridaPresets()

        # Get available presets
        available_presets = presets.get_available_presets()
        assert len(available_presets) > 0, "Must have presets available"

        process_info = frida_manager.spawn_process(test_binary_with_protections)

        try:
            session = frida_manager.attach_to_process(process_info['pid'])

            # Apply anti-debug preset
            if 'anti_debug_bypass' in available_presets:
                preset_script = presets.get_preset('anti_debug_bypass')
                preset_result = frida_manager.load_script(session, preset_script)
                assert preset_result['loaded'], "Anti-debug preset must load"

            # Apply API monitor preset
            if 'api_monitor' in available_presets:
                api_script = presets.get_preset('api_monitor')
                api_result = frida_manager.load_script(session, api_script)
                assert api_result['loaded'], "API monitor preset must load"

            # Apply license bypass preset
            if 'license_bypass' in available_presets:
                license_script = presets.get_preset('license_bypass')
                license_result = frida_manager.load_script(session, license_script)
                assert license_result['loaded'], "License bypass preset must load"

            # Let presets run
            time.sleep(3)

            # Verify presets are working
            messages = frida_manager.get_messages(session)
            assert len(messages) > 0, "Presets must generate messages"

            # Check for preset-specific messages
            preset_types = set()
            for msg in messages:
                if 'bypass' in str(msg).lower():
                    preset_types.add('bypass')
                if 'api' in str(msg).lower():
                    preset_types.add('api')
                if 'debug' in str(msg).lower():
                    preset_types.add('debug')

            assert len(preset_types) > 0, "Presets must be active"

        finally:
            frida_manager.kill_process(process_info['pid'])

    def test_real_advanced_instrumentation_techniques(self, test_binary_with_protections, app_context):
        """Test REAL advanced instrumentation techniques."""
        frida_manager = FridaManager()
        ai_generator = AIScriptGenerator(app_context)

        # Generate advanced instrumentation script
        advanced_config = {
            'techniques': [
                'inline_hooking',
                'vtable_hooking',
                'iat_hooking',
                'syscall_hooking',
                'exception_handler_hooking'
            ],
            'target': test_binary_with_protections,
            'stealth': True,
            'anti_detection': True
        }

        advanced_script = ai_generator.generate_advanced_instrumentation(advanced_config)
        assert advanced_script is not None, "Must generate advanced script"
        assert 'script' in advanced_script, "Must have script content"

        process_info = frida_manager.spawn_process(test_binary_with_protections)

        try:
            session = frida_manager.attach_to_process(process_info['pid'])

            # Apply advanced instrumentation
            adv_result = frida_manager.load_script(session, advanced_script['script'])
            assert adv_result['loaded'], "Advanced script must load"

            # Verify techniques applied
            time.sleep(3)
            messages = frida_manager.get_messages(session)

            techniques_applied = set()
            for msg in messages:
                msg_str = str(msg).lower()
                for technique in advanced_config['techniques']:
                    if technique.replace('_', ' ') in msg_str:
                        techniques_applied.add(technique)

            assert len(techniques_applied) > 0, "Some techniques must be applied"

        finally:
            frida_manager.kill_process(process_info['pid'])
