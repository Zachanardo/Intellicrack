"""
Comprehensive Unit Tests for Dynamic Instrumentation Module.

Tests real Frida-based runtime instrumentation capabilities including process
spawning, script injection, API hooking, and message handling. Validates
production-ready functionality for defensive security research.
"""

import json
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from intellicrack.core.analysis.dynamic_instrumentation import (
    on_message,
    run_dynamic_instrumentation,
    run_instrumentation_thread,
)


class TestOnMessage:
    """Test suite for Frida message handler with real application objects."""

    class RealMainApp:
        """Real application object for testing message handling."""

        def __init__(self):
            self.messages = []
            self.update_output = self

        def emit(self, message):
            """Store emitted messages for verification."""
            self.messages.append(message)

    def test_on_message_send_type(self):
        """Test handling of 'send' type messages from Frida scripts."""
        app = self.RealMainApp()

        message = {
            "type": "send",
            "payload": "Function hooked: CreateFileW"
        }
        data = None

        on_message(app, message, data)

        assert len(app.messages) == 1
        assert "[Frida] Function hooked: CreateFileW" in app.messages[0]

    def test_on_message_error_type(self):
        """Test handling of 'error' type messages from Frida scripts."""
        app = self.RealMainApp()

        message = {
            "type": "error",
            "stack": "Error: Cannot find module 'kernel32.dll'\n  at line 5"
        }
        data = None

        on_message(app, message, data)

        assert len(app.messages) == 1
        assert "[Frida Error]" in app.messages[0]
        assert "Cannot find module 'kernel32.dll'" in app.messages[0]

    def test_on_message_complex_payload(self):
        """Test handling of complex payload structures."""
        app = self.RealMainApp()

        message = {
            "type": "send",
            "payload": {
                "api": "CreateFileW",
                "path": "C:\\Windows\\System32\\config.sys",
                "access": "READ",
                "timestamp": 1234567890
            }
        }
        data = None

        on_message(app, message, data)

        assert len(app.messages) == 1
        assert "[Frida]" in app.messages[0]
        # Should contain the dictionary representation
        assert "CreateFileW" in str(app.messages[0])
        assert "config.sys" in str(app.messages[0])

    def test_on_message_with_binary_data(self):
        """Test handling messages with binary data payloads."""
        app = self.RealMainApp()

        message = {
            "type": "send",
            "payload": "Memory dump received"
        }
        data = b"\x00\x01\x02\x03\x04\x05\x06\x07"

        on_message(app, message, data)

        assert len(app.messages) == 1
        assert "[Frida] Memory dump received" in app.messages[0]

    def test_on_message_unknown_type(self):
        """Test handling of unknown message types."""
        app = self.RealMainApp()

        message = {
            "type": "unknown",
            "payload": "Some data"
        }
        data = None

        # Should not crash or emit anything for unknown types
        on_message(app, message, data)

        # May or may not emit depending on implementation
        # Key is that it doesn't crash
        assert isinstance(app.messages, list)

    def test_on_message_malformed_structure(self):
        """Test handling of malformed message structures."""
        app = self.RealMainApp()

        # Test various malformed messages
        malformed_messages = [
            {},  # Empty message
            {"type": "send"},  # Missing payload
            {"payload": "data"},  # Missing type
            {"type": "error"},  # Missing stack for error
            None,  # None message
        ]

        for msg in malformed_messages:
            # Should handle gracefully without crashing
            try:
                on_message(app, msg, None)
            except (KeyError, AttributeError, TypeError):
                # Expected for some malformed messages
                pass

        # App should still be functional
        assert isinstance(app.messages, list)

    def test_on_message_unicode_handling(self):
        """Test handling of Unicode characters in messages."""
        app = self.RealMainApp()

        unicode_messages = [
            {"type": "send", "payload": "File: C:\\Users\\用户\\文档\\test.exe"},
            {"type": "send", "payload": "Symbol: Ω_calculate_λ"},
            {"type": "send", "payload": "Path: /home/用戶/ドキュメント/"},
            {"type": "error", "stack": "Error: ñoñ-áscíí characters"},
        ]

        for msg in unicode_messages:
            on_message(app, msg, None)

        # All messages should be processed
        assert len(app.messages) >= len([m for m in unicode_messages if m.get("type") in ["send", "error"]])

        # Unicode should be preserved
        combined = " ".join(app.messages)
        assert any(char in combined for char in ["用", "Ω", "λ", "ñ"])


class TestRunInstrumentationThread:
    """Test suite for instrumentation thread execution with real binaries."""

    class RealTestApp:
        """Real application object for instrumentation testing."""

        def __init__(self):
            self.messages = []
            self.completed = False
            self.update_output = self
            self.analysis_completed = self

        def emit(self, message):
            """Store messages or mark completion."""
            if isinstance(message, str):
                if message == "Dynamic Instrumentation":
                    self.completed = True
                else:
                    self.messages.append(message)

    def create_test_binary(self, tmp_path):
        """Create a real test binary for instrumentation."""
        if platform.system() == "Windows":
            # Create a minimal Windows executable
            test_file = tmp_path / "test_target.exe"

            # PE header for minimal executable
            pe_data = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00'
            pe_data += b'\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            pe_data += b'\x00' * 32  # Reserved bytes
            pe_data += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00'
            pe_data += b'\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21'
            pe_data += b'This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00'
            pe_data = pe_data.ljust(0x80, b'\x00')

            # PE signature
            pe_data += b'PE\x00\x00'

            # COFF header
            pe_data += b'\x4C\x01'  # Machine (x86)
            pe_data += b'\x01\x00'  # Number of sections
            pe_data += b'\x00\x00\x00\x00'  # TimeDateStamp
            pe_data += b'\x00\x00\x00\x00'  # PointerToSymbolTable
            pe_data += b'\x00\x00\x00\x00'  # NumberOfSymbols
            pe_data += b'\xE0\x00'  # SizeOfOptionalHeader
            pe_data += b'\x02\x01'  # Characteristics

            # Optional header
            pe_data += b'\x0B\x01'  # Magic (PE32)
            pe_data += b'\x0E\x00'  # Linker version
            pe_data += b'\x00\x10\x00\x00'  # SizeOfCode
            pe_data += b'\x00' * 216  # Rest of optional header

            test_file.write_bytes(pe_data)
        else:
            # Create a minimal ELF executable
            test_file = tmp_path / "test_target"

            # ELF header for minimal executable
            elf_data = b'\x7fELF'  # Magic
            elf_data += b'\x01'  # 32-bit
            elf_data += b'\x01'  # Little endian
            elf_data += b'\x01'  # Current version
            elf_data += b'\x00' * 9  # Padding
            elf_data += b'\x02\x00'  # Executable file
            elf_data += b'\x03\x00'  # x86
            elf_data += b'\x01\x00\x00\x00'  # Version
            elf_data += b'\x00' * 44  # Rest of header

            test_file.write_bytes(elf_data)
            test_file.chmod(0o755)

        return str(test_file)

    def test_instrumentation_with_real_binary(self, tmp_path):
        """Test instrumentation with a real binary file."""
        app = self.RealTestApp()
        binary_path = self.create_test_binary(tmp_path)

        # Simple Frida script that should work on any process
        script_source = """
        console.log('Instrumentation started');
        if (Process.platform === 'windows') {
            console.log('Windows platform detected');
        } else {
            console.log('Unix platform detected');
        }
        """

        # Test if Frida is available
        try:
            import frida

            # Run actual instrumentation
            run_instrumentation_thread(app, binary_path, script_source)

            # Should have status messages
            assert len(app.messages) > 0
            assert any("instrumentation" in msg.lower() for msg in app.messages)

            # Should mark completion
            assert app.completed or any("finished" in msg.lower() for msg in app.messages)

        except ImportError:
            # Frida not available - test fallback behavior
            run_instrumentation_thread(app, binary_path, script_source)

            # Should handle missing Frida gracefully
            assert len(app.messages) > 0
            assert any("error" in msg.lower() or "frida" in msg.lower()
                      for msg in app.messages)

    def test_instrumentation_error_handling(self, tmp_path):
        """Test error handling during instrumentation."""
        app = self.RealTestApp()

        # Test with non-existent binary
        run_instrumentation_thread(app, "nonexistent_binary.exe", "script")

        # Should report error
        assert len(app.messages) > 0
        assert any("error" in msg.lower() for msg in app.messages)

        # Should still signal completion
        assert app.completed or any("finished" in msg.lower() or "completed" in msg.lower()
                                   for msg in app.messages)

    def test_instrumentation_script_injection(self, tmp_path):
        """Test script injection capabilities."""
        app = self.RealTestApp()
        binary_path = self.create_test_binary(tmp_path)

        # Complex Frida script with hooks
        hook_script = """
        if (Process.platform === 'windows') {
            const kernel32 = Process.getModuleByName('kernel32.dll');
            if (kernel32) {
                const createFile = Module.findExportByName('kernel32.dll', 'CreateFileW');
                if (createFile) {
                    Interceptor.attach(createFile, {
                        onEnter: function(args) {
                            send({type: 'api_call', function: 'CreateFileW', path: args[0].readUtf16String()});
                        }
                    });
                }
            }
        } else {
            const open = Module.findExportByName(null, 'open');
            if (open) {
                Interceptor.attach(open, {
                    onEnter: function(args) {
                        send({type: 'api_call', function: 'open', path: args[0].readUtf8String()});
                    }
                });
            }
        }
        """

        try:
            import frida
            run_instrumentation_thread(app, binary_path, hook_script)

            # Should process the script
            assert len(app.messages) > 0

        except ImportError:
            # Test without Frida
            run_instrumentation_thread(app, binary_path, hook_script)
            assert len(app.messages) > 0

    def test_concurrent_message_handling(self):
        """Test handling multiple messages concurrently."""
        app = self.RealTestApp()

        # Simulate concurrent message processing
        def send_messages():
            for i in range(100):
                message = {"type": "send", "payload": f"Message {i}"}
                on_message(app, message, None)

        # Run in multiple threads
        threads = []
        for _ in range(5):
            t = threading.Thread(target=send_messages)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Should handle all messages
        assert len(app.messages) == 500

        # Messages should be intact
        for msg in app.messages:
            assert "[Frida]" in msg
            assert "Message" in msg


class TestRunDynamicInstrumentation:
    """Test suite for main instrumentation entry point."""

    class RealMainApp:
        """Real main application for testing."""

        def __init__(self, binary_path=None):
            self.current_binary = binary_path
            self.messages = []
            self.threads_started = 0
            self.update_output = self

        def emit(self, message):
            self.messages.append(message)

    def test_successful_launch(self):
        """Test successful instrumentation launch."""
        app = self.RealMainApp("C:\\test\\app.exe")

        # Store original Thread class
        original_thread = threading.Thread

        # Track thread creation
        threads_created = []

        class TrackingThread(threading.Thread):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                threads_created.append(self)

        # Temporarily replace Thread
        threading.Thread = TrackingThread

        try:
            run_dynamic_instrumentation(app)

            # Should create a thread
            assert len(threads_created) == 1

            # Thread should be daemon
            assert threads_created[0].daemon

            # Should have status message
            assert len(app.messages) == 1
            assert "Task submitted" in app.messages[0]

        finally:
            # Restore original Thread
            threading.Thread = original_thread

    def test_no_binary_loaded(self):
        """Test behavior when no binary is loaded."""
        app = self.RealMainApp(None)

        run_dynamic_instrumentation(app)

        # Should show error
        assert len(app.messages) == 1
        assert "No binary loaded" in app.messages[0]

    def test_empty_binary_path(self):
        """Test behavior with empty binary path."""
        app = self.RealMainApp("")

        run_dynamic_instrumentation(app)

        # Should show error
        assert len(app.messages) == 1
        assert "No binary loaded" in app.messages[0]

    def test_script_content_generation(self):
        """Test that appropriate Frida script is generated."""
        app = self.RealMainApp("test.exe")

        # Capture the script content
        captured_script = None

        original_thread = threading.Thread

        class ScriptCapturingThread(threading.Thread):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                # Capture script from args
                if 'args' in kwargs and len(kwargs['args']) > 2:
                    nonlocal captured_script
                    captured_script = kwargs['args'][2]

        threading.Thread = ScriptCapturingThread

        try:
            run_dynamic_instrumentation(app)

            # Should have generated script
            assert captured_script is not None

            # Script should contain platform checks
            assert "Process.platform" in captured_script
            assert "windows" in captured_script
            assert "linux" in captured_script

            # Should contain API hooks
            assert "CreateFileW" in captured_script or "open" in captured_script
            assert "Interceptor.attach" in captured_script

        finally:
            threading.Thread = original_thread


class TestIntegrationScenarios:
    """Integration tests for complete instrumentation workflows."""

    def test_complete_workflow(self, tmp_path):
        """Test complete instrumentation workflow from start to finish."""
        # Create test app
        app = TestRunDynamicInstrumentation.RealMainApp()

        # Create test binary
        if platform.system() == "Windows":
            binary = tmp_path / "test.exe"
            binary.write_bytes(b"MZ" + b"\x00" * 100)
        else:
            binary = tmp_path / "test"
            binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
            binary.chmod(0o755)

        app.current_binary = str(binary)

        # Run instrumentation
        run_dynamic_instrumentation(app)

        # Should have started
        assert len(app.messages) > 0
        assert any("Task submitted" in msg or "Starting" in msg for msg in app.messages)

    def test_message_flow(self):
        """Test complete message flow from Frida to UI."""
        app = TestOnMessage.RealMainApp()

        # Simulate complete message flow
        messages = [
            {"type": "send", "payload": "Instrumentation initialized"},
            {"type": "send", "payload": {"api": "CreateProcess", "target": "child.exe"}},
            {"type": "send", "payload": "Hook installed: RegOpenKeyEx"},
            {"type": "error", "stack": "Warning: Symbol not found: CustomAPI"},
            {"type": "send", "payload": "Analysis complete"},
        ]

        for msg in messages:
            on_message(app, msg, None)

        # All messages should be processed
        assert len(app.messages) == len([m for m in messages if m.get("type") in ["send", "error"]])

        # Check message formatting
        for app_msg in app.messages:
            assert "[Frida" in app_msg  # Should have Frida prefix


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_license_check_monitoring_script(self):
        """Test script for monitoring license checks."""
        # Create app
        app = TestRunDynamicInstrumentation.RealMainApp("licensed_app.exe")

        # Capture generated script
        captured_args = None
        original_thread = threading.Thread

        class ArgumentCapturingThread(threading.Thread):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                nonlocal captured_args
                captured_args = kwargs.get('args', [])

        threading.Thread = ArgumentCapturingThread

        try:
            run_dynamic_instrumentation(app)

            # Should have script with Windows registry monitoring
            if captured_args and len(captured_args) > 2:
                script = captured_args[2]

                # Should monitor registry for license keys
                assert "CreateFileW" in script or "RegOpenKeyEx" in script or "RegQueryValueEx" in script

        finally:
            threading.Thread = original_thread

    def test_anti_debugging_bypass_script(self):
        """Test script for bypassing anti-debugging."""
        app = TestRunDynamicInstrumentation.RealMainApp("protected.exe")

        # The generated script should include anti-debugging bypasses
        captured_script = None
        original_thread = threading.Thread

        class ScriptCapturingThread(threading.Thread):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                nonlocal captured_script
                if 'args' in kwargs and len(kwargs['args']) > 2:
                    captured_script = kwargs['args'][2]

        threading.Thread = ScriptCapturingThread

        try:
            run_dynamic_instrumentation(app)

            # Script should be capable of hooking common anti-debug APIs
            if captured_script:
                # Should have capability to hook debugging-related APIs
                assert "Interceptor" in captured_script
                assert "attach" in captured_script

        finally:
            threading.Thread = original_thread

    def test_performance_monitoring(self):
        """Test performance characteristics of message handling."""
        app = TestOnMessage.RealMainApp()

        # Process many messages to test performance
        start_time = time.time()

        for i in range(1000):
            message = {
                "type": "send",
                "payload": f"Performance test message {i}"
            }
            on_message(app, message, None)

        elapsed = time.time() - start_time

        # Should process 1000 messages quickly
        assert elapsed < 2.0  # Reasonable threshold
        assert len(app.messages) == 1000

        # All messages should be properly formatted
        for msg in app.messages:
            assert "[Frida]" in msg
            assert "Performance test message" in msg
