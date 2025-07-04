"""Tests for the ScriptExecutionManager."""

import unittest
from unittest.mock import Mock, patch, MagicMock
from PyQt5.QtWidgets import QApplication, QDialog
from PyQt5.QtCore import QSettings
import sys

# Create QApplication if it doesn't exist
if not QApplication.instance():
    app = QApplication(sys.argv)

from intellicrack.core.execution import ScriptExecutionManager
from intellicrack.ui.dialogs.qemu_test_dialog import QEMUTestDialog


class TestScriptExecutionManager(unittest.TestCase):
    """Test cases for ScriptExecutionManager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parent = Mock()
        self.manager = ScriptExecutionManager(self.parent)
        
        # Clear any existing settings
        self.settings = QSettings("Intellicrack", "Preferences")
        self.settings.clear()
        
    def tearDown(self):
        """Clean up after tests."""
        self.settings.clear()
        
    def test_initialization(self):
        """Test ScriptExecutionManager initialization."""
        self.assertIsNotNone(self.manager)
        self.assertEqual(self.manager.parent, self.parent)
        self.assertIsInstance(self.manager.settings, QSettings)
        
    def test_should_ask_qemu_testing_with_force_option(self):
        """Test QEMU testing decision with force option."""
        # Force option should override everything
        result = self.manager._should_ask_qemu_testing(
            'frida', '/path/to/binary', {'force_qemu_test': True}
        )
        self.assertFalse(result)
        
        result = self.manager._should_ask_qemu_testing(
            'frida', '/path/to/binary', {'force_qemu_test': False}
        )
        self.assertFalse(result)
        
    def test_should_ask_qemu_testing_with_general_preference(self):
        """Test QEMU testing decision with general preferences."""
        # Set general preference to always
        self.settings.setValue("execution/qemu_preference", "always")
        result = self.manager._should_ask_qemu_testing(
            'frida', '/path/to/binary', {}
        )
        self.assertFalse(result)  # Don't ask, automatically test
        
        # Set general preference to never
        self.settings.setValue("execution/qemu_preference", "never")
        result = self.manager._should_ask_qemu_testing(
            'frida', '/path/to/binary', {}
        )
        self.assertFalse(result)  # Don't ask, skip testing
        
        # Set general preference to ask
        self.settings.setValue("execution/qemu_preference", "ask")
        result = self.manager._should_ask_qemu_testing(
            'frida', '/path/to/binary', {}
        )
        self.assertTrue(result)  # Ask the user
        
    def test_should_auto_test_qemu(self):
        """Test automatic QEMU testing decision."""
        # Test with force option
        result = self.manager._should_auto_test_qemu('frida', {'force_qemu_test': True})
        self.assertTrue(result)
        
        # Test with general preference
        self.settings.setValue("execution/qemu_preference", "always")
        result = self.manager._should_auto_test_qemu('frida', {})
        self.assertTrue(result)
        
        self.settings.setValue("execution/qemu_preference", "never")
        result = self.manager._should_auto_test_qemu('frida', {})
        self.assertFalse(result)
        
    @patch('intellicrack.core.execution.script_execution_manager.QEMUTestDialog')
    def test_show_qemu_test_dialog(self, mock_dialog_class):
        """Test showing QEMU test dialog."""
        # Mock dialog instance
        mock_dialog = Mock()
        mock_dialog.exec_.return_value = QDialog.Accepted
        mock_dialog.user_choice = 'test_qemu'
        mock_dialog_class.return_value = mock_dialog
        
        result = self.manager._show_qemu_test_dialog(
            'frida', '/path/to/binary', 'console.log("test");'
        )
        
        self.assertEqual(result, 'test_qemu')
        mock_dialog_class.assert_called_once()
        mock_dialog.exec_.assert_called_once()
        
    @patch('intellicrack.core.execution.script_execution_manager.QEMUTestManager')
    def test_run_qemu_test(self, mock_qemu_class):
        """Test running QEMU test."""
        # Mock QEMU manager
        mock_qemu = Mock()
        mock_qemu.test_frida_script.return_value = {
            'success': True,
            'output': 'Script executed successfully',
            'memory_changes': [],
            'api_calls': []
        }
        mock_qemu_class.return_value = mock_qemu
        
        result = self.manager._run_qemu_test(
            'frida', 'console.log("test");', '/path/to/binary', {}
        )
        
        self.assertTrue(result['success'])
        self.assertEqual(result['output'], 'Script executed successfully')
        
    def test_execute_script_with_cancelled_dialog(self):
        """Test script execution when user cancels dialog."""
        with patch.object(self.manager, '_should_ask_qemu_testing', return_value=True):
            with patch.object(self.manager, '_show_qemu_test_dialog', return_value='cancelled'):
                result = self.manager.execute_script(
                    'frida', 'console.log("test");', '/path/to/binary'
                )
                
                self.assertFalse(result['success'])
                self.assertTrue(result['cancelled'])
                
    def test_execute_script_with_qemu_test_success(self):
        """Test script execution with successful QEMU test."""
        with patch.object(self.manager, '_should_ask_qemu_testing', return_value=True):
            with patch.object(self.manager, '_show_qemu_test_dialog', return_value='test_qemu'):
                with patch.object(self.manager, '_run_qemu_test') as mock_run:
                    mock_run.return_value = {'success': True, 'output': 'Test output'}
                    
                    with patch.object(self.manager, '_show_qemu_results_and_confirm', return_value=True):
                        with patch.object(self.manager, '_execute_on_host') as mock_exec:
                            mock_exec.return_value = {'success': True}
                            
                            result = self.manager.execute_script(
                                'frida', 'console.log("test");', '/path/to/binary'
                            )
                            
                            self.assertTrue(result['success'])
                            mock_run.assert_called_once()
                            mock_exec.assert_called_once()
                            
    def test_save_qemu_preference(self):
        """Test saving QEMU preferences."""
        self.manager._save_qemu_preference('always', 'frida')
        
        saved_value = self.settings.value('qemu_preference_frida')
        self.assertEqual(saved_value, 'always')
        
    def test_get_qemu_timeout(self):
        """Test getting QEMU timeout from settings."""
        # Default timeout
        timeout = self.manager._get_qemu_timeout()
        self.assertEqual(timeout, 60)
        
        # Custom timeout
        self.settings.setValue("execution/qemu_timeout", 120)
        timeout = self.manager._get_qemu_timeout()
        self.assertEqual(timeout, 120)


if __name__ == '__main__':
    unittest.main()