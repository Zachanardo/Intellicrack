"""
Common UI helper functions to reduce code duplication.

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


def check_binary_path_and_warn(app_instance):
    """Check if binary path exists and show warning if not.
    
    Args:
        app_instance: Application instance with binary_path and QMessageBox access
        
    Returns:
        bool: True if binary path exists, False if missing
    """
    if not hasattr(app_instance, 'binary_path') or not app_instance.binary_path:
        try:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(app_instance, "No File Selected",
                              "Please select a program first.")
        except ImportError:
            pass
        return False
    return True

def emit_log_message(app_instance, message):
    """Emit log message if app instance supports it.
    
    Args:
        app_instance: Application instance
        message: Message to log
    """
    if hasattr(app_instance, 'update_output') and hasattr(app_instance.update_output, 'emit'):
        try:
            from ..utils.logger import log_message
            app_instance.update_output.emit(log_message(message))
        except ImportError:
            app_instance.update_output.emit(message)
    elif hasattr(app_instance, 'update_output'):
        app_instance.update_output.emit(message)

def show_file_dialog(parent, title, file_filter="HTML Files (*.html);;All Files (*)"):
    """Show file save dialog and return filename.
    
    Args:
        parent: Parent widget
        title: Dialog title
        file_filter: File filter string
        
    Returns:
        str: Selected filename or empty string if cancelled
    """
    try:
        from PyQt5.QtWidgets import QFileDialog
        filename, _ = QFileDialog.getSaveFileName(parent, title, "", file_filter)
        return filename if filename else ""
    except ImportError:
        return ""

def ask_yes_no_question(parent, title, question):
    """Show yes/no question dialog.
    
    Args:
        parent: Parent widget
        title: Dialog title
        question: Question text
        
    Returns:
        bool: True if Yes clicked, False otherwise
    """
    try:
        from PyQt5.QtWidgets import QMessageBox
        return QMessageBox.question(
            parent, title, question,
            QMessageBox.Yes | QMessageBox.No
        ) == QMessageBox.Yes
    except ImportError:
        return False

def generate_exploit_payload_common(payload_type, target_path="target_software"):
    """Generate exploit payload of specified type.
    
    This is the common implementation extracted from duplicate code
    in main_app.py and missing_methods.py.
    
    Args:
        payload_type: Type of payload to generate ("License Bypass", "Function Hijack", "Buffer Overflow")
        target_path: Target path for license bypass payload
        
    Returns:
        dict: Payload result with fields like 'method', 'payload_bytes', 'description', or 'error'
    """
    try:
        from ..core.patching.payload_generator import generate_advanced_payload
        from ..exploitation import generate_exploit, generate_license_bypass_payload

        if payload_type == "License Bypass":
            payload_result = generate_license_bypass_payload(target_path, "patch")
        elif payload_type == "Function Hijack":
            strategy = {"strategy": "function_hijacking", "target": "license_check"}
            payload_bytes = generate_advanced_payload(strategy)
            payload_result = {
                "method": "function_hijacking",
                "payload_bytes": payload_bytes.hex() if payload_bytes else "Generation failed",
                "description": "Function hijacking payload for license bypass"
            }
        elif payload_type == "Buffer Overflow":
            payload_result = generate_exploit("buffer_overflow", "x86", "shellcode")
        else:
            payload_result = {"error": f"Unknown payload type: {payload_type}"}

        return payload_result

    except (OSError, ValueError, RuntimeError) as e:
        return {"error": str(e)}

def generate_exploit_strategy_common(binary_path, vulnerability_type="buffer_overflow"):
    """Generate exploit strategy for given binary and vulnerability type.
    
    This is the common implementation extracted from duplicate code.
    
    Args:
        binary_path: Path to binary file
        vulnerability_type: Type of vulnerability to exploit
        
    Returns:
        dict: Strategy result with 'strategy', 'automation_script' fields or 'error'
    """
    try:
        from ..exploitation import generate_exploit_strategy
        
        strategy = generate_exploit_strategy(binary_path, vulnerability_type)
        return strategy

    except (OSError, ValueError, RuntimeError) as e:
        return {"error": str(e)}
