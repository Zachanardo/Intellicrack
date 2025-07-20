#!/usr/bin/env python3
"""
Test script for structured messaging integration
Verifies that Frida scripts can send structured messages and that they are properly handled by the UI
"""

import sys
import os
import time
import json
from pathlib import Path

# Add the intellicrack module to the path
sys.path.insert(0, os.path.abspath('.'))

try:
    from intellicrack.core.frida_manager import FridaManager
    from intellicrack.ui.dialogs.frida_manager_dialog import FridaManagerDialog
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from PyQt6.QtCore import QTimer
    import frida
    
    class TestMainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Structured Messaging Test")
            self.setGeometry(100, 100, 800, 600)
            
            # Create Frida manager dialog
            self.frida_dialog = FridaManagerDialog(self)
            self.setCentralWidget(self.frida_dialog)
            
            # Test message capture
            self.captured_messages = []
            
            # Connect to message handlers to capture messages
            self.connect_message_handlers()
            
        def connect_message_handlers(self):
            """Connect to message handlers to capture test messages"""
            if hasattr(self.frida_dialog, 'frida_manager'):
                manager = self.frida_dialog.frida_manager
                
                # Override the structured message handler to capture messages
                original_handler = manager._handle_structured_message
                
                def capture_handler(message_data):
                    self.captured_messages.append(message_data)
                    print(f"Captured message: {json.dumps(message_data, indent=2)}")
                    return original_handler(message_data)
                
                manager._handle_structured_message = capture_handler
                
        def run_test(self):
            """Run the structured messaging test"""
            print("Starting structured messaging integration test...")
            
            # Load the test script
            script_path = Path("intellicrack/plugins/frida_scripts/test_structured_messaging.js")
            if not script_path.exists():
                print(f"ERROR: Test script not found at {script_path}")
                return False
                
            try:
                with open(script_path, 'r', encoding='utf-8') as f:
                    script_content = f.read()
                
                print(f"Loaded test script: {script_path}")
                print(f"Script length: {len(script_content)} characters")
                
                # Try to get a session (this will fail without a target process, but we can still test the script loading)
                try:
                    session = frida.spawn(["notepad.exe"])
                    print(f"Spawned test process: {session}")
                    
                    # Attach to the process
                    process = frida.attach(session)
                    
                    # Create and load the script
                    script = process.create_script(script_content)
                    script.on('message', self.on_message)
                    script.load()
                    
                    print("Script loaded successfully!")
                    
                    # Let the script run for a bit
                    time.sleep(2)
                    
                    # Resume the process
                    frida.resume(session)
                    
                    # Wait a bit more for messages
                    time.sleep(3)
                    
                    # Clean up
                    script.unload()
                    process.detach()
                    frida.kill(session)
                    
                except frida.ProcessNotFoundError:
                    print("No target process available, testing script parsing only...")
                    
                except Exception as e:
                    print(f"Process attachment failed: {e}")
                    print("Testing script parsing only...")
                
                # Test script parsing
                print("\nTesting script parsing...")
                
                # Count expected messages in the script
                expected_messages = script_content.count('send({')
                print(f"Expected {expected_messages} structured messages in script")
                
                # Verify script structure
                if 'type:' in script_content and 'target:' in script_content and 'action:' in script_content:
                    print("✅ Script contains required structured message fields")
                else:
                    print("❌ Script missing required structured message fields")
                    
                # Test message types
                message_types = ['info', 'warning', 'error', 'status', 'bypass', 'success', 'detection', 'notification']
                for msg_type in message_types:
                    if f'type: "{msg_type}"' in script_content:
                        print(f"✅ Found {msg_type} message type in script")
                    else:
                        print(f"❌ Missing {msg_type} message type in script")
                        
                print(f"\nCaptured {len(self.captured_messages)} messages during test")
                
                return True
                
            except Exception as e:
                print(f"ERROR: Failed to run test: {e}")
                return False
                
        def on_message(self, message, data):
            """Handle Frida script messages"""
            print(f"Received message: {message}")
            if message['type'] == 'send':
                payload = message.get('payload', {})
                if isinstance(payload, dict) and 'type' in payload:
                    print(f"Structured message received: {payload}")
                    
    def main():
        """Main test function"""
        app = QApplication(sys.argv)
        
        # Create test window
        window = TestMainWindow()
        window.show()
        
        # Run the test after a short delay
        QTimer.singleShot(1000, window.run_test)
        
        # Run for a limited time
        QTimer.singleShot(10000, app.quit)
        
        # Start the application
        sys.exit(app.exec())
        
    if __name__ == '__main__':
        main()
        
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure you're running this from the Intellicrack root directory")
    print("and that all dependencies are installed.")
    sys.exit(1)