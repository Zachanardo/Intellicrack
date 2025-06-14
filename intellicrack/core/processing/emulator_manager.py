"""
Emulator Manager for automatic emulator lifecycle management.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import threading
from typing import Optional, Dict, Any, Callable
try:
    from PyQt5.QtCore import QObject, pyqtSignal
except ImportError:
    from PyQt6.QtCore import QObject, pyqtSignal

try:
    from .qemu_emulator import QemuEmulator
    QEMU_AVAILABLE = True
except ImportError:
    QEMU_AVAILABLE = False
    QemuEmulator = None

try:
    from .qiling_emulator import QilingEmulator, QILING_AVAILABLE
except ImportError:
    QILING_AVAILABLE = False
    QilingEmulator = None


class EmulatorManager(QObject):
    """
    Manages automatic launching and lifecycle of emulators.
    
    This class ensures that required emulators are started automatically
    when features need them, and provides status tracking.
    """
    
    # Signals for UI updates
    emulator_status_changed = pyqtSignal(str, bool, str)  # emulator_type, is_running, message
    emulator_error = pyqtSignal(str, str)  # emulator_type, error_message
    
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        
        # Emulator instances
        self.qemu_instance: Optional[QemuEmulator] = None
        self.qiling_instances: Dict[str, QilingEmulator] = {}
        
        # Status tracking
        self.qemu_running = False
        self.qemu_starting = False
        
        # Thread safety
        self.lock = threading.Lock()
        
    def ensure_qemu_running(self, binary_path: str, config: Optional[Dict[str, Any]] = None) -> bool:
        """
        Ensure QEMU is running for the given binary.
        
        Args:
            binary_path: Path to binary that needs QEMU
            config: Optional QEMU configuration
            
        Returns:
            True if QEMU is running or successfully started
        """
        if not QEMU_AVAILABLE:
            self.emulator_error.emit("QEMU", "QEMU is not installed. Please install QEMU first.")
            return False
            
        with self.lock:
            # Check if already running
            if self.qemu_running and self.qemu_instance:
                return True
                
            # Check if already starting
            if self.qemu_starting:
                self.emulator_status_changed.emit("QEMU", False, "QEMU is already starting...")
                return False
                
            self.qemu_starting = True
            
        try:
            self.emulator_status_changed.emit("QEMU", False, "Starting QEMU emulator...")
            
            # Create QEMU instance if needed
            if not self.qemu_instance:
                self.qemu_instance = QemuEmulator(config=config)
                
            # Start the system
            self.qemu_instance.start_system()
            
            with self.lock:
                self.qemu_running = True
                self.qemu_starting = False
                
            self.emulator_status_changed.emit("QEMU", True, "QEMU emulator started successfully")
            return True
            
        except Exception as e:
            with self.lock:
                self.qemu_running = False
                self.qemu_starting = False
                
            error_msg = f"Failed to start QEMU: {str(e)}"
            self.logger.error(error_msg)
            self.emulator_error.emit("QEMU", error_msg)
            self.emulator_status_changed.emit("QEMU", False, "QEMU failed to start")
            return False
            
    def ensure_qiling_ready(self, binary_path: str) -> Optional[QilingEmulator]:
        """
        Ensure Qiling is ready for the given binary.
        
        Args:
            binary_path: Path to binary to emulate
            
        Returns:
            QilingEmulator instance if successful, None otherwise
        """
        if not QILING_AVAILABLE:
            self.emulator_error.emit("Qiling", "Qiling framework not installed. Run: pip install qiling")
            return None
            
        try:
            self.emulator_status_changed.emit("Qiling", True, "Initializing Qiling emulator...")
            
            # Create Qiling instance for this binary
            if binary_path not in self.qiling_instances:
                self.qiling_instances[binary_path] = QilingEmulator(binary_path)
                
            self.emulator_status_changed.emit("Qiling", True, "Qiling emulator ready")
            return self.qiling_instances[binary_path]
            
        except Exception as e:
            error_msg = f"Failed to initialize Qiling: {str(e)}"
            self.logger.error(error_msg)
            self.emulator_error.emit("Qiling", error_msg)
            self.emulator_status_changed.emit("Qiling", False, "Qiling initialization failed")
            return None
            
    def stop_qemu(self):
        """Stop QEMU emulator if running."""
        if self.qemu_instance and self.qemu_running:
            try:
                self.qemu_instance.stop_system()
                with self.lock:
                    self.qemu_running = False
                self.emulator_status_changed.emit("QEMU", False, "QEMU emulator stopped")
            except Exception as e:
                self.logger.error(f"Error stopping QEMU: {e}")
                
    def cleanup(self):
        """Clean up all emulator resources."""
        self.stop_qemu()
        self.qiling_instances.clear()
        

# Global emulator manager instance
_emulator_manager: Optional[EmulatorManager] = None


def get_emulator_manager() -> EmulatorManager:
    """Get or create the global emulator manager instance."""
    global _emulator_manager
    if _emulator_manager is None:
        _emulator_manager = EmulatorManager()
    return _emulator_manager


def run_with_qemu(binary_path: str, analysis_func: Callable, 
                  config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run an analysis function with QEMU automatically started.
    
    Args:
        binary_path: Binary to analyze
        analysis_func: Function to run once QEMU is ready
        config: Optional QEMU configuration
        
    Returns:
        Analysis results or error dictionary
    """
    manager = get_emulator_manager()
    
    if not manager.ensure_qemu_running(binary_path, config):
        return {
            "status": "error",
            "error": "Failed to start QEMU emulator",
            "suggestion": "Check QEMU installation and system requirements"
        }
        
    try:
        return analysis_func()
    except Exception as e:
        return {
            "status": "error", 
            "error": f"Analysis failed: {str(e)}"
        }


def run_with_qiling(binary_path: str, analysis_func: Callable) -> Dict[str, Any]:
    """
    Run an analysis function with Qiling automatically initialized.
    
    Args:
        binary_path: Binary to analyze
        analysis_func: Function to run with Qiling instance
        
    Returns:
        Analysis results or error dictionary
    """
    manager = get_emulator_manager()
    
    qiling_instance = manager.ensure_qiling_ready(binary_path)
    if not qiling_instance:
        return {
            "status": "error",
            "error": "Failed to initialize Qiling emulator",
            "suggestion": "Install Qiling with: pip install qiling"
        }
        
    try:
        return analysis_func(qiling_instance)
    except Exception as e:
        return {
            "status": "error",
            "error": f"Analysis failed: {str(e)}"
        }