"""Central script execution manager with QEMU testing options."""

import os
import json
import subprocess
import logging
from typing import Dict, Any, Optional, Callable, Tuple, List
from pathlib import Path
import hashlib
import datetime

from PyQt5.QtCore import QObject, pyqtSignal, QSettings
from PyQt5.QtWidgets import QDialog, QMessageBox

logger = logging.getLogger(__name__)


class ScriptExecutionManager(QObject):
    """Central manager for all script executions with optional QEMU testing."""
    
    # Signals
    execution_started = pyqtSignal(str, str)  # script_type, target_binary
    execution_completed = pyqtSignal(str, bool, dict)  # script_type, success, results
    qemu_test_started = pyqtSignal(str, str)  # script_type, target_binary
    qemu_test_completed = pyqtSignal(str, bool, dict)  # script_type, success, results
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = QSettings('Intellicrack', 'ScriptExecution')        self.qemu_manager = None
        self.qemu_test_dialog = None
        self.qemu_results_dialog = None
        self._initialize_managers()
        
    def _initialize_managers(self):
        """Initialize QEMU and dialog managers."""
        try:
            from intellicrack.ai.qemu_test_manager_enhanced import EnhancedQEMUTestManager
            from intellicrack.ui.dialogs.qemu_test_dialog import QEMUTestDialog
            from intellicrack.ui.dialogs.qemu_test_results_dialog import QEMUTestResultsDialog
            
            self.qemu_manager = EnhancedQEMUTestManager()
            self.QEMUTestDialog = QEMUTestDialog
            self.QEMUTestResultsDialog = QEMUTestResultsDialog
        except ImportError as e:
            logger.warning(f"Could not initialize QEMU components: {e}")
            self.qemu_manager = None
            
    def execute_script(self, script_type: str, script_content: str, 
                      target_binary: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a script with optional QEMU testing.
        
        Args:
            script_type: Type of script ('frida', 'ghidra', 'ida', etc.)
            script_content: The actual script content
            target_binary: Path to the target binary
            options: Additional execution options            
        Returns:
            Execution results dictionary
        """
        options = options or {}
        
        # Check if we should ask about QEMU testing
        if self._should_ask_qemu_testing(script_type, target_binary, options):
            user_choice = self._show_qemu_test_dialog(script_type, target_binary, script_content)
            
            if user_choice == 'test_qemu':
                # Run QEMU test first
                qemu_results = self._run_qemu_test(script_type, script_content, target_binary, options)
                
                if qemu_results and qemu_results.get('success'):
                    # Show results and ask if they want to proceed with host execution
                    if self._show_qemu_results_and_confirm(qemu_results):
                        return self._execute_on_host(script_type, script_content, target_binary, options)
                    else:
                        return {'success': False, 'cancelled': True, 'message': 'User cancelled after QEMU test'}
                else:
                    # QEMU test failed
                    return {'success': False, 'qemu_failed': True, 'results': qemu_results}
                    
            elif user_choice == 'run_host':
                # Skip QEMU, run directly on host
                return self._execute_on_host(script_type, script_content, target_binary, options)                
            elif user_choice == 'always_test':
                # Save preference and run QEMU test
                self._save_qemu_preference('always', script_type)
                qemu_results = self._run_qemu_test(script_type, script_content, target_binary, options)
                
                if qemu_results and qemu_results.get('success'):
                    if self._show_qemu_results_and_confirm(qemu_results):
                        return self._execute_on_host(script_type, script_content, target_binary, options)
                    else:
                        return {'success': False, 'cancelled': True}
                else:
                    return {'success': False, 'qemu_failed': True, 'results': qemu_results}
                    
            elif user_choice == 'never_test':
                # Save preference and run on host
                self._save_qemu_preference('never', script_type)
                return self._execute_on_host(script_type, script_content, target_binary, options)
                
            else:  # cancelled
                return {'success': False, 'cancelled': True, 'message': 'User cancelled execution'}
                
        else:
            # Based on saved preferences or options, either test or execute directly
            if self._should_auto_test_qemu(script_type, options):
                qemu_results = self._run_qemu_test(script_type, script_content, target_binary, options)                if qemu_results and qemu_results.get('success'):
                    return self._execute_on_host(script_type, script_content, target_binary, options)
                else:
                    return {'success': False, 'qemu_failed': True, 'results': qemu_results}
            else:
                return self._execute_on_host(script_type, script_content, target_binary, options)
                
    def _should_ask_qemu_testing(self, script_type: str, target_binary: str, 
                                options: Dict[str, Any]) -> bool:
        """Determine if we should ask the user about QEMU testing."""
        # Check if force option is set
        if options.get('force_qemu_test') is not None:
            return False  # Don't ask, use the forced option
            
        # Check saved preferences
        # First check general preference from preferences dialog
        general_pref = self.settings.value("execution/qemu_preference", "ask")
        if general_pref in ['always', 'never']:
            return False  # Don't ask, use general preference
            
        # Then check script-specific preference
        pref_key = f"qemu_preference_{script_type}"
        saved_pref = self.settings.value(pref_key, 'ask')
        
        if saved_pref in ['always', 'never']:
            return False  # Don't ask, use saved preference
            
        # Check if binary is trusted
        if self._is_trusted_binary(target_binary):
            return False  # Don't ask for trusted binaries
            
        return True  # Ask the user
        
    def _should_auto_test_qemu(self, script_type: str, options: Dict[str, Any]) -> bool:
        """Check if we should automatically test in QEMU."""
        if options.get('force_qemu_test'):
            return True
            
        # Check general preference first
        general_pref = self.settings.value("execution/qemu_preference", "ask")
        if general_pref == 'always':
            return True
        elif general_pref == 'never':
            return False
            
        # Then check script-specific preference
        pref_key = f"qemu_preference_{script_type}"
        saved_pref = self.settings.value(pref_key, 'ask')
        
        return saved_pref == 'always'
        
    def _is_trusted_binary(self, binary_path: str) -> bool:
        """Check if a binary is in the trusted list."""
        trusted_list_key = "trusted_binaries"
        trusted_binaries = self.settings.value(trusted_list_key, [])
        
        if not isinstance(trusted_binaries, list):
            trusted_binaries = []
            
        # Normalize path
        binary_path = os.path.abspath(binary_path)
        
        return binary_path in trusted_binaries
        
    def _show_qemu_test_dialog(self, script_type: str, target_binary: str, 
                              script_content: str) -> str:
        """Show QEMU test dialog and return user choice."""
        if not self.QEMUTestDialog:
            logger.warning("QEMUTestDialog not available, defaulting to host execution")
            return 'run_host'            
        dialog = self.QEMUTestDialog(
            script_type=script_type,
            target_binary=target_binary,
            script_preview=script_content[:500],  # Show first 500 chars
            parent=self.parent()
        )
        
        result = dialog.exec_()
        
        if result == QDialog.Accepted:
            return dialog.get_user_choice()
        else:
            return 'cancelled'
            
    def _run_qemu_test(self, script_type: str, script_content: str, 
                      target_binary: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run script in QEMU environment."""
        if not self.qemu_manager:
            logger.error("QEMU manager not available")
            return {'success': False, 'error': 'QEMU testing not available'}
            
        self.qemu_test_started.emit(script_type, target_binary)
        
        try:
            # Create snapshot for testing
            snapshot_id = self._create_qemu_snapshot(target_binary, options)
            
            if not snapshot_id:                return {'success': False, 'error': 'Failed to create QEMU snapshot'}
                
            # Run the appropriate test based on script type
            if script_type == 'frida':
                results = self.qemu_manager.test_frida_script_enhanced(
                    snapshot_id, script_content, target_binary
                )
            elif script_type == 'ghidra':
                results = self.qemu_manager.test_ghidra_script_enhanced(
                    snapshot_id, script_content, target_binary
                )
            else:
                results = {'success': False, 'error': f'Unsupported script type: {script_type}'}
                
            self.qemu_test_completed.emit(script_type, results.get('success', False), results)
            return results
            
        except Exception as e:
            logger.exception(f"Error during QEMU test: {e}")
            error_results = {'success': False, 'error': str(e)}
            self.qemu_test_completed.emit(script_type, False, error_results)
            return error_results
            
    def _create_qemu_snapshot(self, target_binary: str, options: Dict[str, Any]) -> Optional[str]:
        """Create QEMU snapshot for testing."""
        if not self.qemu_manager:
            return None            
        try:
            # Generate unique snapshot ID
            snapshot_id = f"test_{hashlib.md5(target_binary.encode()).hexdigest()[:8]}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            # Create snapshot with binary
            success = self.qemu_manager.create_snapshot(
                snapshot_id=snapshot_id,
                binary_path=target_binary,
                os_type=options.get('os_type', 'windows'),
                architecture=options.get('architecture', 'x64')
            )
            
            return snapshot_id if success else None
            
        except Exception as e:
            logger.exception(f"Error creating QEMU snapshot: {e}")
            return None
            
    def _show_qemu_results_and_confirm(self, qemu_results: Dict[str, Any]) -> bool:
        """Show QEMU test results and ask for confirmation to proceed."""
        if not self.QEMUTestResultsDialog:
            # Fallback to simple message box
            msg = QMessageBox(self.parent())
            msg.setWindowTitle("QEMU Test Results")
            msg.setText("QEMU test completed successfully.\nProceed with host execution?")
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)            return msg.exec_() == QMessageBox.Yes
            
        dialog = self.QEMUTestResultsDialog(
            test_results=qemu_results,
            parent=self.parent()
        )
        
        dialog.add_action_button("Deploy to Host", "deploy")
        dialog.add_action_button("Cancel Deployment", "cancel")
        
        result = dialog.exec_()
        user_action = dialog.get_user_action()
        
        return user_action == "deploy"
        
    def _execute_on_host(self, script_type: str, script_content: str, 
                        target_binary: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute script on the host system."""
        self.execution_started.emit(script_type, target_binary)
        
        try:
            if script_type == 'frida':
                results = self._execute_frida_host(script_content, target_binary, options)
            elif script_type == 'ghidra':
                results = self._execute_ghidra_host(script_content, target_binary, options)
            elif script_type == 'ida':
                results = self._execute_ida_host(script_content, target_binary, options)            else:
                results = {'success': False, 'error': f'Unsupported script type: {script_type}'}
                
            self.execution_completed.emit(script_type, results.get('success', False), results)
            return results
            
        except Exception as e:
            logger.exception(f"Error during host execution: {e}")
            error_results = {'success': False, 'error': str(e)}
            self.execution_completed.emit(script_type, False, error_results)
            return error_results
            
    def _execute_frida_host(self, script_content: str, target_binary: str, 
                           options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Frida script on host."""
        try:
            import frida
            import tempfile
            
            # Save script to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(script_content)
                script_path = f.name
                
            # Prepare Frida command
            cmd = ['frida', '-f', target_binary, '-l', script_path]
            
            if options.get('no_pause'):                cmd.append('--no-pause')
                
            # Execute
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Clean up
            os.unlink(script_path)
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
    def _execute_ghidra_host(self, script_content: str, target_binary: str, 
                            options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Ghidra script on host."""
        try:
            import tempfile
            
            # Find Ghidra installation
            ghidra_path = self._find_ghidra_installation()
            if not ghidra_path:
                return {'success': False, 'error': 'Ghidra installation not found'}
                            # Save script to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(script_content)
                script_path = f.name
                
            # Prepare Ghidra command
            analyze_headless = os.path.join(ghidra_path, 'support', 'analyzeHeadless')
            project_path = tempfile.mkdtemp()
            project_name = 'temp_project'
            
            cmd = [
                analyze_headless,
                project_path,
                project_name,
                '-import', target_binary,
                '-postScript', script_path
            ]
            
            # Execute
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Clean up
            os.unlink(script_path)
            import shutil
            shutil.rmtree(project_path, ignore_errors=True)
            
            return {
                'success': result.returncode == 0,                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
    def _execute_ida_host(self, script_content: str, target_binary: str, 
                         options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute IDA script on host."""
        # Implementation would be similar to Ghidra
        return {'success': False, 'error': 'IDA execution not yet implemented'}
        
    def _find_ghidra_installation(self) -> Optional[str]:
        """Find Ghidra installation path."""
        # Check common locations
        possible_paths = [
            os.environ.get('GHIDRA_HOME'),
            os.path.expanduser('~/ghidra'),
            '/opt/ghidra',
            'C:\\ghidra',
            'C:\\Program Files\\ghidra'
        ]
        
        for path in possible_paths:
            if path and os.path.exists(path):
                return path                
        return None
        
    def _save_qemu_preference(self, preference: str, script_type: str):
        """Save QEMU testing preference."""
        pref_key = f"qemu_preference_{script_type}"
        self.settings.setValue(pref_key, preference)
        self.settings.sync()
        
    def add_trusted_binary(self, binary_path: str):
        """Add binary to trusted list."""
        binary_path = os.path.abspath(binary_path)
        trusted_list_key = "trusted_binaries"
        trusted_binaries = self.settings.value(trusted_list_key, [])
        
        if not isinstance(trusted_binaries, list):
            trusted_binaries = []
            
        if binary_path not in trusted_binaries:
            trusted_binaries.append(binary_path)
            self.settings.setValue(trusted_list_key, trusted_binaries)
            self.settings.sync()
            
    def remove_trusted_binary(self, binary_path: str):
        """Remove binary from trusted list."""
        binary_path = os.path.abspath(binary_path)
        trusted_list_key = "trusted_binaries"        trusted_binaries = self.settings.value(trusted_list_key, [])
        
        if not isinstance(trusted_binaries, list):
            trusted_binaries = []
            
        if binary_path in trusted_binaries:
            trusted_binaries.remove(binary_path)
            self.settings.setValue(trusted_list_key, trusted_binaries)
            self.settings.sync()
            
    def get_execution_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent execution history."""
        history_key = "execution_history"
        history = self.settings.value(history_key, [])
        
        if not isinstance(history, list):
            history = []
            
        return history[:limit]
        
    def _add_to_history(self, script_type: str, target_binary: str, 
                       success: bool, timestamp: datetime.datetime):
        """Add execution to history."""
        history_key = "execution_history"
        history = self.settings.value(history_key, [])
        
        if not isinstance(history, list):            history = []
            
        entry = {
            'script_type': script_type,
            'target_binary': target_binary,
            'success': success,
            'timestamp': timestamp.isoformat()
        }
        
        history.insert(0, entry)  # Add to beginning
        
        # Keep only last 100 entries
        history = history[:100]
        
        self.settings.setValue(history_key, history)
        self.settings.sync()