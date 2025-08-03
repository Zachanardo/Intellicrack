"""
This file is part of Intellicrack.
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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""Integration tests for optional QEMU testing feature."""

import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QSettings

# Create QApplication if it doesn't exist
if not QApplication.instance():
    app = QApplication(sys.argv)

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from intellicrack.core.execution import ScriptExecutionManager


class TestQEMUOptionalTestingIntegration(unittest.TestCase):
    """Integration tests for QEMU optional testing workflow."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.temp_dir, "test.exe")

        # Create a simple test binary
        with open(self.test_binary, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)  # Minimal PE header

        # Clear settings
        self.settings = QSettings("Intellicrack", "Preferences")
        self.settings.clear()

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        self.settings.clear()

    def test_frida_script_with_qemu_preference_always(self):
        """Test Frida script execution with QEMU preference set to always."""
        # Set preference to always test in QEMU
        self.settings.setValue("execution/qemu_preference", "always")

        # Create manager
        parent = Mock()
        manager = ScriptExecutionManager(parent)

        # Mock QEMU test to succeed
        with patch.object(manager, '_run_qemu_test') as mock_qemu:
            mock_qemu.return_value = {
                'success': True,
                'output': 'QEMU test passed',
                'memory_changes': [],
                'api_calls': ['CreateFileA', 'ReadFile']
            }

            # Mock host execution
            with patch.object(manager, '_execute_on_host') as mock_host:
                mock_host.return_value = {'success': True, 'output': 'Executed on host'}

                # Execute script
                result = manager.execute_script(
                    script_type='frida',
                    script_content='console.log("Hello from Frida");',
                    target_binary=self.test_binary
                )

                # Verify QEMU test was called
                mock_qemu.assert_called_once()

                # Verify host execution was called after QEMU success
                mock_host.assert_called_once()

                # Verify result
                self.assertTrue(result['success'])

    def test_ghidra_script_with_qemu_preference_never(self):
        """Test Ghidra script execution with QEMU preference set to never."""
        # Set preference to never test in QEMU
        self.settings.setValue("execution/qemu_preference", "never")

        # Create manager
        parent = Mock()
        manager = ScriptExecutionManager(parent)

        # Mock host execution
        with patch.object(manager, '_execute_on_host') as mock_host:
            mock_host.return_value = {'success': True, 'output': 'Executed on host'}

            # Mock QEMU test (should not be called)
            with patch.object(manager, '_run_qemu_test') as mock_qemu:
                # Execute script
                result = manager.execute_script(
                    script_type='ghidra',
                    script_content='// Ghidra analysis script',
                    target_binary=self.test_binary
                )

                # Verify QEMU test was NOT called
                mock_qemu.assert_not_called()

                # Verify host execution was called directly
                mock_host.assert_called_once()

                # Verify result
                self.assertTrue(result['success'])

    def test_script_execution_with_dialog_interaction(self):
        """Test script execution with user dialog interaction."""
        # Set preference to ask
        self.settings.setValue("execution/qemu_preference", "ask")

        # Create manager
        parent = Mock()
        manager = ScriptExecutionManager(parent)

        # Mock dialog to return "test_qemu"
        with patch.object(manager, '_show_qemu_test_dialog') as mock_dialog:
            mock_dialog.return_value = 'test_qemu'

            # Mock QEMU test
            with patch.object(manager, '_run_qemu_test') as mock_qemu:
                mock_qemu.return_value = {'success': True, 'output': 'QEMU test output'}

                # Mock results confirmation
                with patch.object(manager, '_show_qemu_results_and_confirm') as mock_confirm:
                    mock_confirm.return_value = True

                    # Mock host execution
                    with patch.object(manager, '_execute_on_host') as mock_host:
                        mock_host.return_value = {'success': True}

                        # Execute script
                        result = manager.execute_script(
                            script_type='frida',
                            script_content='console.log("test");',
                            target_binary=self.test_binary
                        )

                        # Verify dialog was shown
                        mock_dialog.assert_called_once()

                        # Verify QEMU test was run
                        mock_qemu.assert_called_once()

                        # Verify results were shown
                        mock_confirm.assert_called_once()

                        # Verify host execution
                        mock_host.assert_called_once()

                        # Verify success
                        self.assertTrue(result['success'])

    def test_qemu_test_failure_handling(self):
        """Test handling of QEMU test failures."""
        # Create manager
        parent = Mock()
        manager = ScriptExecutionManager(parent)

        # Force QEMU test
        with patch.object(manager, '_should_ask_qemu_testing', return_value=False):
            with patch.object(manager, '_should_auto_test_qemu', return_value=True):
                # Mock QEMU test to fail
                with patch.object(manager, '_run_qemu_test') as mock_qemu:
                    mock_qemu.return_value = {
                        'success': False,
                        'error': 'QEMU initialization failed'
                    }

                    # Execute script
                    result = manager.execute_script(
                        script_type='frida',
                        script_content='console.log("test");',
                        target_binary=self.test_binary
                    )

                    # Verify failure
                    self.assertFalse(result['success'])
                    self.assertTrue(result['qemu_failed'])
                    self.assertEqual(result['results']['error'], 'QEMU initialization failed')


if __name__ == '__main__':
    unittest.main()
